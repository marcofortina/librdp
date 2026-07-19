/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * Module: authenticated managed X11 session supervision.
 * Invariants: the authentication handle outlives every user process, all
 * session children share one process group and only one broker controls the
 * agent at a time.
 * Ownership: the supervisor owns broker/agent sockets, the control listener,
 * authentication session and process group until orderly teardown.
 * Threading: one event loop handles IPC, signals, deadlines and child state.
 * Trust boundary: the bootstrap broker and recovery connections are checked
 * with kernel credentials; every command also carries the session token.
 */

#include "x11_managed_supervisor.h"

#include "x11_managed_ipc.h"
#include "x11_managed_process.h"

#include <openssl/crypto.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef LIBRDP_X11_SESSION_AGENT_PATH
#define LIBRDP_X11_SESSION_AGENT_PATH \
    "/usr/libexec/librdp/librdp-session-agent"
#endif

typedef struct x11_managed_supervisor
{
    const x11_managed_supervisor_config* config;
    x11_managed_auth_session* auth_session;
    x11_managed_process_group process_group;
    x11_managed_ipc_message session;
    int broker_fd;
    int listener_fd;
    int agent_fd;
    int signal_read_fd;
    int signal_write_fd;
    pid_t agent_pid;
    uint64_t last_activity_ns;
    int detached;
    int stop_requested;
    int child_failed;
    int recovery_query_allowed;
    char authority_path[X11_MANAGED_IPC_PATH_BYTES];
} x11_managed_supervisor;

static volatile sig_atomic_t x11_managed_supervisor_cancelled = 0;
static int x11_managed_supervisor_signal_fd = -1;

static uint64_t x11_managed_supervisor_now_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0u;
    return (uint64_t)now.tv_sec * 1000000000u +
           (uint64_t)now.tv_nsec;
}

static void x11_managed_supervisor_signal(int signal_number)
{
    unsigned char value = (unsigned char)signal_number;

    if (signal_number != SIGCHLD)
        x11_managed_supervisor_cancelled = 1;
    if (x11_managed_supervisor_signal_fd >= 0)
        (void)write(x11_managed_supervisor_signal_fd, &value, 1u);
}

static int x11_managed_supervisor_set_fd_flags(int descriptor,
                                               int nonblocking)
{
    int descriptor_flags = fcntl(descriptor, F_GETFD);
    int status_flags = fcntl(descriptor, F_GETFL);

    if (descriptor_flags < 0 || status_flags < 0 ||
        fcntl(descriptor,
              F_SETFD,
              descriptor_flags | FD_CLOEXEC) != 0)
        return 0;
    if (nonblocking &&
        fcntl(descriptor,
              F_SETFL,
              status_flags | O_NONBLOCK) != 0)
        return 0;
    return 1;
}

static int x11_managed_supervisor_install_signals(
    x11_managed_supervisor* supervisor)
{
    struct sigaction action;
    int descriptors[2] = {-1, -1};

    if (!supervisor || pipe(descriptors) != 0)
        return 0;
    if (!x11_managed_supervisor_set_fd_flags(descriptors[0], 1) ||
        !x11_managed_supervisor_set_fd_flags(descriptors[1], 1))
    {
        close(descriptors[0]);
        close(descriptors[1]);
        return 0;
    }
    supervisor->signal_read_fd = descriptors[0];
    supervisor->signal_write_fd = descriptors[1];
    x11_managed_supervisor_signal_fd = descriptors[1];
    x11_managed_supervisor_cancelled = 0;
    memset(&action, 0, sizeof(action));
    action.sa_handler = x11_managed_supervisor_signal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;
    return sigaction(SIGCHLD, &action, NULL) == 0 &&
           sigaction(SIGINT, &action, NULL) == 0 &&
           sigaction(SIGTERM, &action, NULL) == 0 &&
           sigaction(SIGHUP, &action, NULL) == 0;
}

static int x11_managed_supervisor_auth_cancelled(void* user_data)
{
    (void)user_data;
    return x11_managed_supervisor_cancelled != 0;
}

static int x11_managed_supervisor_copy(char* output,
                                       size_t capacity,
                                       const char* input)
{
    size_t length = input ? strlen(input) : 0u;

    if (!output || capacity == 0u || !input || length >= capacity)
        return 0;
    memcpy(output, input, length + 1u);
    return 1;
}

void x11_managed_supervisor_config_init(
    x11_managed_supervisor_config* config)
{
    if (!config)
        return;
    memset(config, 0, sizeof(*config));
    config->version = X11_MANAGED_SUPERVISOR_VERSION;
    config->size = sizeof(*config);
    x11_managed_auth_config_init(&config->authentication);
    config->agent_path = LIBRDP_X11_SESSION_AGENT_PATH;
    config->authentication_timeout_ms = 30000;
    config->startup_timeout_ms = 30000;
    config->command_timeout_ms = 5000;
    config->shutdown_timeout_ms = 5000;
}

static int x11_managed_supervisor_config_valid(
    const x11_managed_supervisor_config* config)
{
    return config &&
           config->version == X11_MANAGED_SUPERVISOR_VERSION &&
           config->size >= sizeof(*config) &&
           config->authentication.version == X11_MANAGED_AUTH_VERSION &&
           config->authentication.size >=
               sizeof(config->authentication) &&
           config->agent_path && config->agent_path[0] == '/' &&
           strnlen(config->agent_path, 4096u) < 4096u &&
           config->authentication_timeout_ms > 0 &&
           config->authentication_timeout_ms <= 120000 &&
           config->startup_timeout_ms > 0 &&
           config->startup_timeout_ms <= 120000 &&
           config->command_timeout_ms > 0 &&
           config->command_timeout_ms <= 120000 &&
           config->shutdown_timeout_ms >= 0 &&
           config->shutdown_timeout_ms <= 120000;
}

static void x11_managed_supervisor_send_error(
    int descriptor,
    uint64_t request_id,
    uint64_t session_id,
    librdp_status status,
    x11_managed_auth_outcome outcome,
    int timeout_ms)
{
    x11_managed_ipc_message response;

    if (descriptor < 0 || request_id == 0u)
        return;
    x11_managed_ipc_message_init(&response);
    response.type = X11_MANAGED_IPC_ERROR;
    response.request_id = request_id;
    response.session_id = session_id;
    response.status = status == LIBRDP_STATUS_OK
                          ? LIBRDP_STATUS_STATE
                          : status;
    response.auth_outcome = (uint32_t)outcome;
    (void)x11_managed_ipc_send(descriptor, &response, timeout_ms);
    x11_managed_ipc_message_clear(&response);
}

static librdp_status x11_managed_supervisor_authenticate(
    x11_managed_supervisor* supervisor,
    const x11_managed_ipc_message* request,
    x11_managed_auth_outcome* auth_outcome)
{
    x11_managed_ipc_message response;
    const x11_managed_auth_identity* identity = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    status = x11_managed_auth_session_open(
        &supervisor->config->authentication,
        request->username,
        request->password,
        x11_managed_supervisor_auth_cancelled,
        NULL,
        auth_outcome,
        &supervisor->auth_session);
    if (status != LIBRDP_STATUS_OK ||
        *auth_outcome != X11_MANAGED_AUTH_AUTHENTICATED ||
        !supervisor->auth_session)
        return status == LIBRDP_STATUS_OK
                   ? LIBRDP_STATUS_STATE
                   : status;
    identity = x11_managed_auth_session_identity(
        supervisor->auth_session);
    if (!identity)
        return LIBRDP_STATUS_STATE;
    x11_managed_ipc_message_init(&response);
    response.type = X11_MANAGED_IPC_AUTHENTICATED;
    response.request_id = request->request_id;
    response.uid = (uint32_t)identity->uid;
    response.gid = (uint32_t)identity->gid;
    response.auth_outcome =
        (uint32_t)X11_MANAGED_AUTH_AUTHENTICATED;
    if (!x11_managed_supervisor_copy(response.username,
                                     sizeof(response.username),
                                     identity->username))
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_ipc_send(
            supervisor->broker_fd,
            &response,
            supervisor->config->command_timeout_ms);
    }
    x11_managed_ipc_message_clear(&response);
    return status;
}

static int x11_managed_supervisor_start_valid(
    const x11_managed_supervisor* supervisor,
    const x11_managed_ipc_message* initial,
    const x11_managed_ipc_message* request)
{
    const x11_managed_auth_identity* identity =
        x11_managed_auth_session_identity(supervisor->auth_session);

    return identity && initial && request &&
           request->type == X11_MANAGED_IPC_START &&
           request->session_id != 0u &&
           request->uid == (uint32_t)identity->uid &&
           request->gid == (uint32_t)identity->gid &&
           strcmp(request->username, identity->username) == 0 &&
           request->display_name[0] == ':' &&
           request->runtime_directory[0] == '/' &&
           request->control_socket[0] == '/' &&
           request->desktop_command[0] == '/' &&
           request->xserver_command[0] == '/' &&
           request->width == initial->width &&
           request->height == initial->height &&
           request->security_mode >= LIBRDP_SECURITY_STANDARD &&
           request->security_mode <= LIBRDP_SECURITY_NLA &&
           strnlen(request->reconnect_token,
                   sizeof(request->reconnect_token)) ==
               X11_MANAGED_IPC_TOKEN_BYTES - 1u;
}

static librdp_status x11_managed_supervisor_create_listener(
    const char* path,
    int* output)
{
    struct sockaddr_un address;
    mode_t previous_mask = 0;
    int descriptor = -1;
    int bind_error = 0;
    size_t length = path ? strlen(path) : 0u;

    if (!path || !output || path[0] != '/' ||
        length == 0u || length >= sizeof(address.sun_path))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *output = -1;
    descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0 ||
        !x11_managed_supervisor_set_fd_flags(descriptor, 0))
    {
        if (descriptor >= 0)
            close(descriptor);
        return LIBRDP_STATUS_IO_ERROR;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, length + 1u);
    previous_mask = umask(0177);
    if (bind(descriptor,
             (const struct sockaddr*)&address,
             sizeof(address)) != 0)
    {
        bind_error = errno;
        (void)umask(previous_mask);
        close(descriptor);
        return bind_error == EADDRINUSE || bind_error == EEXIST
                   ? LIBRDP_STATUS_STATE
                   : LIBRDP_STATUS_IO_ERROR;
    }
    (void)umask(previous_mask);
    if (listen(descriptor, 4) != 0)
    {
        close(descriptor);
        (void)unlink(path);
        return LIBRDP_STATUS_IO_ERROR;
    }
    *output = descriptor;
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_managed_supervisor_process_config(
    x11_managed_supervisor* supervisor,
    const x11_managed_ipc_message* request,
    x11_managed_process_config* process,
    const char** environment)
{
    const x11_managed_auth_identity* identity =
        x11_managed_auth_session_identity(supervisor->auth_session);
    size_t count = x11_managed_auth_session_environment_count(
        supervisor->auth_session);
    size_t index = 0u;
    int length = 0;

    if (!identity || !process || !environment ||
        count > X11_MANAGED_AUTH_MAX_ENVIRONMENT)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    length = snprintf(supervisor->authority_path,
                      sizeof(supervisor->authority_path),
                      "%s/Xauthority",
                      request->runtime_directory);
    if (length < 0 ||
        (size_t)length >= sizeof(supervisor->authority_path))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    for (index = 0u; index < count; index++)
    {
        environment[index] =
            x11_managed_auth_session_environment_at(
                supervisor->auth_session, index);
        if (!environment[index])
            return LIBRDP_STATUS_STATE;
    }
    x11_managed_process_config_init(process);
    process->identity = identity;
    process->login_environment = environment;
    process->login_environment_count = count;
    process->environment_allowlist =
        request->environment_allowlist;
    process->display_name = request->display_name;
    process->authority_path = supervisor->authority_path;
    process->runtime_directory = request->runtime_directory;
    process->xserver_path = request->xserver_command;
    process->desktop_command = request->desktop_command;
    process->width = request->width;
    process->height = request->height;
    process->use_xvfb =
        (request->flags & X11_MANAGED_IPC_TEST_XVFB) != 0u;
    process->startup_timeout_ms =
        supervisor->config->startup_timeout_ms;
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_managed_supervisor_start_agent(
    x11_managed_supervisor* supervisor,
    const x11_managed_process_config* process,
    x11_managed_ipc_message* request,
    const x11_managed_ipc_message* initial,
    x11_managed_ipc_message* ready)
{
    int sockets[2] = {-1, -1};
    char descriptor[32];
    char* arguments[4];
    int length = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (x11_managed_ipc_connected_pair(sockets) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_IO_ERROR;
    length = snprintf(descriptor,
                      sizeof(descriptor),
                      "%d",
                      sockets[1]);
    if (length < 0 || (size_t)length >= sizeof(descriptor))
    {
        close(sockets[0]);
        close(sockets[1]);
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    arguments[0] = (char*)supervisor->config->agent_path;
    arguments[1] = (char*)"--control-fd";
    arguments[2] = descriptor;
    arguments[3] = NULL;
    status = x11_managed_process_join(
        process,
        &supervisor->process_group,
        supervisor->config->agent_path,
        arguments,
        sockets[1],
        &supervisor->agent_pid);
    close(sockets[1]);
    if (status != LIBRDP_STATUS_OK)
    {
        close(sockets[0]);
        return status;
    }
    supervisor->agent_fd = sockets[0];
    request->supervisor_pid = (uint64_t)getpid();
    request->agent_pid = (uint64_t)supervisor->agent_pid;
    request->xserver_pid =
        (uint64_t)supervisor->process_group.xserver_pid;
    request->desktop_pid =
        (uint64_t)supervisor->process_group.desktop_pid;
    if (!x11_managed_supervisor_copy(request->password,
                                     sizeof(request->password),
                                     initial->password) ||
        !x11_managed_supervisor_copy(request->domain,
                                     sizeof(request->domain),
                                     initial->domain))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    status = x11_managed_ipc_send(
        supervisor->agent_fd,
        request,
        supervisor->config->startup_timeout_ms);
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_ipc_receive(
            supervisor->agent_fd,
            ready,
            supervisor->config->startup_timeout_ms);
    }
    OPENSSL_cleanse(request->password,
                    sizeof(request->password));
    return status;
}

static void x11_managed_supervisor_ready(
    const x11_managed_supervisor* supervisor,
    uint64_t request_id,
    x11_managed_ipc_message* response)
{
    x11_managed_ipc_message_init(response);
    response->type = X11_MANAGED_IPC_READY;
    response->request_id = request_id;
    response->session_id = supervisor->session.session_id;
    response->created_ns = supervisor->session.created_ns;
    response->idle_timeout_ns =
        supervisor->session.idle_timeout_ns;
    response->max_duration_ns =
        supervisor->session.max_duration_ns;
    response->supervisor_pid = (uint64_t)getpid();
    response->agent_pid = (uint64_t)supervisor->agent_pid;
    response->xserver_pid =
        (uint64_t)supervisor->process_group.xserver_pid;
    response->desktop_pid =
        (uint64_t)supervisor->process_group.desktop_pid;
    response->flags = supervisor->session.flags;
    response->uid = supervisor->session.uid;
    response->gid = supervisor->session.gid;
    response->width = supervisor->session.width;
    response->height = supervisor->session.height;
    response->port = supervisor->session.port;
    response->security_mode = supervisor->session.security_mode;
    response->max_peers = supervisor->session.max_peers;
    response->session_state = supervisor->session.session_state;
    response->attachment_count =
        supervisor->session.attachment_count;
    (void)x11_managed_supervisor_copy(
        response->username,
        sizeof(response->username),
        supervisor->session.username);
    (void)x11_managed_supervisor_copy(
        response->reconnect_token,
        sizeof(response->reconnect_token),
        supervisor->session.reconnect_token);
    (void)x11_managed_supervisor_copy(
        response->display_name,
        sizeof(response->display_name),
        supervisor->session.display_name);
    (void)x11_managed_supervisor_copy(
        response->bind_address,
        sizeof(response->bind_address),
        supervisor->session.bind_address);
    (void)x11_managed_supervisor_copy(
        response->runtime_directory,
        sizeof(response->runtime_directory),
        supervisor->session.runtime_directory);
    (void)x11_managed_supervisor_copy(
        response->control_socket,
        sizeof(response->control_socket),
        supervisor->session.control_socket);
}

static int x11_managed_supervisor_command_valid(
    const x11_managed_supervisor* supervisor,
    const x11_managed_ipc_message* command,
    int recovery_query)
{
    if (!supervisor || !command ||
        command->session_id != supervisor->session.session_id)
        return 0;
    if (recovery_query &&
        command->type == X11_MANAGED_IPC_QUERY)
        return 1;
    if (!x11_managed_ipc_token_equal(
            supervisor->session.reconnect_token,
            command->reconnect_token))
        return 0;
    return command->type == X11_MANAGED_IPC_ATTACH ||
           command->type == X11_MANAGED_IPC_DETACH ||
           command->type == X11_MANAGED_IPC_RESIZE ||
           command->type == X11_MANAGED_IPC_TERMINATE ||
           command->type == X11_MANAGED_IPC_QUERY ||
           command->type == X11_MANAGED_IPC_PING ||
           command->type == X11_MANAGED_IPC_STOP;
}

static librdp_status x11_managed_supervisor_forward(
    x11_managed_supervisor* supervisor,
    const x11_managed_ipc_message* command,
    x11_managed_ipc_message* response)
{
    librdp_status status = x11_managed_ipc_send(
        supervisor->agent_fd,
        command,
        supervisor->config->command_timeout_ms);

    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_ipc_receive(
            supervisor->agent_fd,
            response,
            supervisor->config->command_timeout_ms);
    }
    if (status == LIBRDP_STATUS_OK &&
        (response->request_id != command->request_id ||
         response->session_id != command->session_id ||
         (response->type != X11_MANAGED_IPC_READY &&
          response->type != X11_MANAGED_IPC_ERROR)))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    return status;
}

/*
 * Receive, authorize, forward, and correlate one broker command against the
 * active supervised session. State changes commit only after a successful
 * agent response; malformed or recovery-ineligible commands receive an error
 * and are never forwarded.
 */
static librdp_status x11_managed_supervisor_handle_command(
    x11_managed_supervisor* supervisor,
    int descriptor,
    int recovery_query)
{
    x11_managed_ipc_message command;
    x11_managed_ipc_message response;
    librdp_status status = LIBRDP_STATUS_OK;
    uint64_t now_ns = x11_managed_supervisor_now_ns();

    x11_managed_ipc_message_init(&command);
    x11_managed_ipc_message_init(&response);
    status = x11_managed_ipc_receive(
        descriptor,
        &command,
        supervisor->config->command_timeout_ms);
    if (status != LIBRDP_STATUS_OK ||
        !x11_managed_supervisor_command_valid(
            supervisor, &command, recovery_query))
    {
        x11_managed_supervisor_send_error(
            descriptor,
            command.request_id != 0u ? command.request_id : 1u,
            supervisor->session.session_id,
            status == LIBRDP_STATUS_OK
                ? LIBRDP_STATUS_INVALID_ARGUMENT
                : status,
            X11_MANAGED_AUTH_UNAVAILABLE,
            supervisor->config->command_timeout_ms);
        x11_managed_ipc_message_clear(&command);
        x11_managed_ipc_message_clear(&response);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (command.type == X11_MANAGED_IPC_QUERY ||
        command.type == X11_MANAGED_IPC_PING)
    {
        x11_managed_supervisor_ready(supervisor,
                                     command.request_id,
                                     &response);
    }
    else
    {
        status = x11_managed_supervisor_forward(supervisor,
                                                &command,
                                                &response);
        if (status == LIBRDP_STATUS_OK &&
            response.status == LIBRDP_STATUS_OK)
        {
            if (command.type == X11_MANAGED_IPC_RESIZE)
            {
                supervisor->session.width = command.width;
                supervisor->session.height = command.height;
            }
            else if (command.type == X11_MANAGED_IPC_DETACH)
            {
                supervisor->detached = 1;
                supervisor->session.session_state =
                    X11_MANAGED_SESSION_DETACHED;
                supervisor->session.attachment_count = 0u;
            }
            else if (command.type == X11_MANAGED_IPC_ATTACH)
            {
                supervisor->detached = 0;
                supervisor->session.session_state =
                    X11_MANAGED_SESSION_ACTIVE;
                supervisor->session.attachment_count = 1u;
            }
            else if (command.type == X11_MANAGED_IPC_STOP ||
                     command.type == X11_MANAGED_IPC_TERMINATE)
            {
                supervisor->stop_requested = 1;
            }
        }
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_ipc_send(
            descriptor,
            &response,
            supervisor->config->command_timeout_ms);
    }
    if (now_ns != 0u)
        supervisor->last_activity_ns = now_ns;
    x11_managed_ipc_message_clear(&command);
    x11_managed_ipc_message_clear(&response);
    return status;
}

static int x11_managed_supervisor_accept_broker(
    x11_managed_supervisor* supervisor)
{
    x11_managed_ipc_identity identity;
    int descriptor = accept(supervisor->listener_fd, NULL, NULL);

    if (descriptor < 0)
        return errno == EINTR || errno == EAGAIN;
    if (!x11_managed_supervisor_set_fd_flags(descriptor, 0) ||
        x11_managed_ipc_peer_identity(descriptor, &identity) !=
            LIBRDP_STATUS_OK ||
        (identity.uid != 0u && identity.uid != geteuid()))
    {
        close(descriptor);
        return 1;
    }
    if (supervisor->broker_fd >= 0)
        close(supervisor->broker_fd);
    supervisor->broker_fd = descriptor;
    supervisor->recovery_query_allowed = 1;
    return 1;
}

static int x11_managed_supervisor_child_exited(pid_t* child)
{
    int status = 0;
    pid_t result = 0;

    if (!child || *child <= 0)
        return 0;
    result = waitpid(*child, &status, WNOHANG);
    if (result == *child)
    {
        *child = -1;
        return 1;
    }
    return result < 0 && errno == ECHILD;
}

static void x11_managed_supervisor_drain_signals(
    x11_managed_supervisor* supervisor)
{
    unsigned char values[64];

    while (read(supervisor->signal_read_fd,
                values,
                sizeof(values)) > 0)
    {
    }
    if (x11_managed_supervisor_cancelled)
        supervisor->stop_requested = 1;
    if (x11_managed_supervisor_child_exited(
            &supervisor->agent_pid) ||
        x11_managed_supervisor_child_exited(
            &supervisor->process_group.xserver_pid) ||
        x11_managed_supervisor_child_exited(
            &supervisor->process_group.desktop_pid))
    {
        supervisor->child_failed = 1;
        supervisor->stop_requested = 1;
    }
}

static int x11_managed_supervisor_timeout(
    const x11_managed_supervisor* supervisor,
    uint64_t now_ns)
{
    uint64_t deadline = UINT64_MAX;
    uint64_t remaining_ns = 0u;

    if (supervisor->session.max_duration_ns != 0u &&
        supervisor->session.created_ns <=
            UINT64_MAX - supervisor->session.max_duration_ns)
    {
        deadline = supervisor->session.created_ns +
                   supervisor->session.max_duration_ns;
    }
    if (supervisor->detached &&
        supervisor->session.idle_timeout_ns != 0u &&
        supervisor->last_activity_ns <=
            UINT64_MAX - supervisor->session.idle_timeout_ns &&
        supervisor->last_activity_ns +
                supervisor->session.idle_timeout_ns <
            deadline)
    {
        deadline = supervisor->last_activity_ns +
                   supervisor->session.idle_timeout_ns;
    }
    if (deadline == UINT64_MAX)
        return -1;
    if (now_ns >= deadline)
        return 0;
    remaining_ns = deadline - now_ns;
    if (remaining_ns / 1000000u > (uint64_t)INT_MAX)
        return INT_MAX;
    return (int)((remaining_ns + 999999u) / 1000000u);
}

static librdp_status x11_managed_supervisor_loop(
    x11_managed_supervisor* supervisor)
{
    while (!supervisor->stop_requested)
    {
        struct pollfd descriptors[3];
        nfds_t count = 0u;
        int listener_index = -1;
        int broker_index = -1;
        int signal_index = -1;
        uint64_t now_ns = x11_managed_supervisor_now_ns();
        int timeout_ms =
            x11_managed_supervisor_timeout(supervisor, now_ns);
        int ready = 0;

        memset(descriptors, 0, sizeof(descriptors));
        listener_index = (int)count;
        descriptors[count].fd = supervisor->listener_fd;
        descriptors[count].events = POLLIN;
        count++;
        if (supervisor->broker_fd >= 0)
        {
            broker_index = (int)count;
            descriptors[count].fd = supervisor->broker_fd;
            descriptors[count].events = POLLIN;
            count++;
        }
        signal_index = (int)count;
        descriptors[count].fd = supervisor->signal_read_fd;
        descriptors[count].events = POLLIN;
        count++;
        ready = poll(descriptors, count, timeout_ms);
        if (ready < 0)
        {
            if (errno == EINTR)
                continue;
            return LIBRDP_STATUS_IO_ERROR;
        }
        if (ready == 0)
        {
            supervisor->stop_requested = 1;
            break;
        }
        if ((descriptors[signal_index].revents &
             (POLLIN | POLLERR | POLLHUP)) != 0)
            x11_managed_supervisor_drain_signals(supervisor);
        if ((descriptors[listener_index].revents & POLLIN) != 0)
            (void)x11_managed_supervisor_accept_broker(supervisor);
        if (broker_index >= 0 &&
            (descriptors[broker_index].revents & POLLIN) != 0)
        {
            if (x11_managed_supervisor_handle_command(
                    supervisor,
                    supervisor->broker_fd,
                    supervisor->recovery_query_allowed) !=
                LIBRDP_STATUS_OK)
            {
                close(supervisor->broker_fd);
                supervisor->broker_fd = -1;
            }
            else
            {
                supervisor->recovery_query_allowed = 0;
            }
        }
        else if (broker_index >= 0 &&
                 (descriptors[broker_index].revents &
                  (POLLERR | POLLHUP | POLLNVAL)) != 0)
        {
            close(supervisor->broker_fd);
            supervisor->broker_fd = -1;
        }
    }
    return supervisor->child_failed
               ? LIBRDP_STATUS_CLOSED
               : LIBRDP_STATUS_OK;
}

static void x11_managed_supervisor_cleanup(
    x11_managed_supervisor* supervisor)
{
    if (!supervisor)
        return;
    if (supervisor->agent_fd >= 0)
    {
        x11_managed_ipc_message stop;
        x11_managed_ipc_message response;

        x11_managed_ipc_message_init(&stop);
        stop.type = X11_MANAGED_IPC_STOP;
        stop.request_id = 1u;
        stop.session_id = supervisor->session.session_id;
        (void)x11_managed_supervisor_copy(
            stop.reconnect_token,
            sizeof(stop.reconnect_token),
            supervisor->session.reconnect_token);
        x11_managed_ipc_message_init(&response);
        (void)x11_managed_ipc_send(
            supervisor->agent_fd, &stop, 500);
        (void)x11_managed_ipc_receive(
            supervisor->agent_fd, &response, 500);
        x11_managed_ipc_message_clear(&stop);
        x11_managed_ipc_message_clear(&response);
    }
    (void)x11_managed_process_stop(
        &supervisor->process_group,
        supervisor->config
            ? supervisor->config->shutdown_timeout_ms
            : 0);
    if (supervisor->agent_pid > 0)
        (void)waitpid(supervisor->agent_pid, NULL, 0);
    if (supervisor->broker_fd >= 0)
        close(supervisor->broker_fd);
    if (supervisor->agent_fd >= 0)
        close(supervisor->agent_fd);
    if (supervisor->listener_fd >= 0)
        close(supervisor->listener_fd);
    if (supervisor->session.control_socket[0] != '\0')
        (void)unlink(supervisor->session.control_socket);
    if (supervisor->signal_read_fd >= 0)
        close(supervisor->signal_read_fd);
    if (supervisor->signal_write_fd >= 0)
        close(supervisor->signal_write_fd);
    x11_managed_supervisor_signal_fd = -1;
    x11_managed_auth_session_close(supervisor->auth_session);
    supervisor->auth_session = NULL;
    x11_managed_ipc_message_clear(&supervisor->session);
}

/*
 * Own the authenticated managed-session lifecycle from broker handshake
 * through X server, desktop, and agent startup to command-loop teardown.
 * Failure policy sends one correlated startup error, clears credentials, and
 * releases every descriptor, process, socket, and authentication session.
 */
librdp_status x11_managed_supervisor_run(
    int broker_descriptor,
    const x11_managed_supervisor_config* config)
{
    x11_managed_supervisor supervisor;
    x11_managed_ipc_identity broker_identity;
    x11_managed_ipc_message initial;
    x11_managed_ipc_message request;
    x11_managed_ipc_message agent_ready;
    x11_managed_ipc_message broker_ready;
    x11_managed_process_config process;
    const char* environment[X11_MANAGED_AUTH_MAX_ENVIRONMENT];
    librdp_status status = LIBRDP_STATUS_OK;
    x11_managed_auth_outcome auth_outcome =
        X11_MANAGED_AUTH_UNAVAILABLE;

    if (broker_descriptor < 0 ||
        !x11_managed_supervisor_config_valid(config))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&supervisor, 0, sizeof(supervisor));
    supervisor.config = config;
    supervisor.broker_fd = broker_descriptor;
    supervisor.listener_fd = -1;
    supervisor.agent_fd = -1;
    supervisor.signal_read_fd = -1;
    supervisor.signal_write_fd = -1;
    supervisor.agent_pid = -1;
    x11_managed_process_group_init(&supervisor.process_group);
    x11_managed_ipc_message_init(&supervisor.session);
    x11_managed_ipc_message_init(&initial);
    x11_managed_ipc_message_init(&request);
    x11_managed_ipc_message_init(&agent_ready);
    x11_managed_ipc_message_init(&broker_ready);
    memset(environment, 0, sizeof(environment));
    memset(&process, 0, sizeof(process));
    if (!x11_managed_supervisor_install_signals(&supervisor) ||
        x11_managed_ipc_peer_identity(
            broker_descriptor, &broker_identity) != LIBRDP_STATUS_OK ||
        (broker_identity.uid != 0u &&
         broker_identity.uid != geteuid()))
    {
        status = LIBRDP_STATUS_STATE;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_ipc_receive(
            broker_descriptor,
            &initial,
            config->authentication_timeout_ms);
    }
    if (status == LIBRDP_STATUS_OK &&
        initial.type != X11_MANAGED_IPC_START)
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
    if (status == LIBRDP_STATUS_OK)
        status = x11_managed_supervisor_authenticate(
            &supervisor, &initial, &auth_outcome);
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_ipc_receive(
            broker_descriptor,
            &request,
            config->startup_timeout_ms);
    }
    if (status == LIBRDP_STATUS_OK &&
        !x11_managed_supervisor_start_valid(
            &supervisor, &initial, &request))
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_supervisor_create_listener(
            request.control_socket,
            &supervisor.listener_fd);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_supervisor_process_config(
            &supervisor, &request, &process, environment);
    }
    if (status == LIBRDP_STATUS_OK)
        status = x11_managed_process_start(
            &process, &supervisor.process_group);
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_supervisor_start_agent(
            &supervisor,
            &process,
            &request,
            &initial,
            &agent_ready);
    }
    OPENSSL_cleanse(initial.password, sizeof(initial.password));
    if (status == LIBRDP_STATUS_OK &&
        agent_ready.type != X11_MANAGED_IPC_READY)
        status = agent_ready.status != LIBRDP_STATUS_OK
                     ? agent_ready.status
                     : LIBRDP_STATUS_STATE;
    if (status == LIBRDP_STATUS_OK)
    {
        supervisor.session = request;
        x11_managed_ipc_message_init(&request);
        supervisor.session.port = agent_ready.port;
        supervisor.session.session_state =
            X11_MANAGED_SESSION_ACTIVE;
        supervisor.session.attachment_count = 1u;
        supervisor.session.agent_pid =
            (uint64_t)supervisor.agent_pid;
        supervisor.session.xserver_pid =
            (uint64_t)supervisor.process_group.xserver_pid;
        supervisor.session.desktop_pid =
            (uint64_t)supervisor.process_group.desktop_pid;
        supervisor.last_activity_ns =
            x11_managed_supervisor_now_ns();
        x11_managed_supervisor_ready(
            &supervisor,
            initial.request_id,
            &broker_ready);
        status = x11_managed_ipc_send(
            broker_descriptor,
            &broker_ready,
            config->command_timeout_ms);
    }
    if (status != LIBRDP_STATUS_OK)
    {
        x11_managed_supervisor_send_error(
            broker_descriptor,
            initial.request_id != 0u ? initial.request_id : 1u,
            request.session_id,
            status,
            auth_outcome,
            config->command_timeout_ms);
    }
    else
    {
        status = x11_managed_supervisor_loop(&supervisor);
    }
    x11_managed_ipc_message_clear(&initial);
    x11_managed_ipc_message_clear(&request);
    x11_managed_ipc_message_clear(&agent_ready);
    x11_managed_ipc_message_clear(&broker_ready);
    x11_managed_supervisor_cleanup(&supervisor);
    return status;
}
