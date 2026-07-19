/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: unprivileged managed X11 session agent.
 * Invariants: X11 and server-host work stays on the owner thread; the control
 * thread only validates, queues and wakes that thread.
 * Ownership: the agent owns its runtime and control thread, while Xorg and the
 * desktop remain children of the external session supervisor.
 * Threading: one owner thread drives librdp/X11 and one reader thread handles a
 * single authenticated Unix socket.
 * Trust boundary: the inherited peer is kernel-authenticated, every command is
 * correlated to one session/token and credential fields are cleansed after the
 * server constructor copies them.
 */

#include "server_managed_ipc.h"
#include "server_managed_process.h"
#include "x11_runtime.h"

#include "server_host.h"

#include <openssl/crypto.h>

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct x11_session_agent
{
    int control_fd;
    uint64_t session_id;
    char reconnect_token[X11_MANAGED_IPC_TOKEN_BYTES];
    x11_server_runtime* runtime;
    x11_managed_process_group display;
    pthread_t control_thread;
    pthread_mutex_t lock;
    x11_managed_ipc_message command;
    int command_pending;
    atomic_int control_closed;
    atomic_int stop_requested;
} x11_session_agent;

static x11_session_agent* x11_session_agent_signal_context = NULL;

static void x11_session_agent_signal(int signal_number)
{
    (void)signal_number;
    if (x11_session_agent_signal_context &&
        x11_session_agent_signal_context->runtime)
        (void)x11_server_runtime_cancel(
            x11_session_agent_signal_context->runtime);
}

static int x11_session_agent_parse_fd(const char* value,
                                      int* descriptor)
{
    char* end = NULL;
    long parsed = 0;

    if (!value || !descriptor || value[0] == '\0')
        return 0;
    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' ||
        parsed < 3 || parsed > INT32_MAX)
        return 0;
    *descriptor = (int)parsed;
    return 1;
}

static int x11_session_agent_install_signals(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = x11_session_agent_signal;
    sigemptyset(&action.sa_mask);
    return sigaction(SIGINT, &action, NULL) == 0 &&
           sigaction(SIGTERM, &action, NULL) == 0 &&
           sigaction(SIGHUP, &action, NULL) == 0;
}

static int x11_session_agent_command_valid(
    const x11_session_agent* agent,
    const x11_managed_ipc_message* command)
{
    if (!agent || !command ||
        command->session_id != agent->session_id)
        return 0;
    if (!x11_managed_ipc_token_equal(agent->reconnect_token,
                                     command->reconnect_token))
        return 0;
    return command->type == X11_MANAGED_IPC_ATTACH ||
           command->type == X11_MANAGED_IPC_DETACH ||
           command->type == X11_MANAGED_IPC_RESIZE ||
           command->type == X11_MANAGED_IPC_QUERY ||
           command->type == X11_MANAGED_IPC_PING ||
           command->type == X11_MANAGED_IPC_STOP ||
           command->type == X11_MANAGED_IPC_TERMINATE;
}

/*
 * Read exactly one command at a time. The supervisor waits for each response,
 * so a pending command is a protocol violation rather than an unbounded queue.
 */
static void* x11_session_agent_control_main(void* user_data)
{
    x11_session_agent* agent = (x11_session_agent*)user_data;

    while (agent)
    {
        x11_managed_ipc_message incoming;
        librdp_status status = LIBRDP_STATUS_OK;

        x11_managed_ipc_message_init(&incoming);
        status = x11_managed_ipc_receive(agent->control_fd,
                                         &incoming,
                                         -1);
        if (status != LIBRDP_STATUS_OK)
        {
            pthread_mutex_lock(&agent->lock);
            atomic_store(&agent->control_closed, 1);
            atomic_store(&agent->stop_requested, 1);
            pthread_mutex_unlock(&agent->lock);
            (void)x11_server_runtime_wakeup(agent->runtime);
            x11_managed_ipc_message_clear(&incoming);
            break;
        }
        pthread_mutex_lock(&agent->lock);
        if (agent->command_pending ||
            !x11_session_agent_command_valid(agent, &incoming))
        {
            atomic_store(&agent->control_closed, 1);
            atomic_store(&agent->stop_requested, 1);
        }
        else
        {
            agent->command = incoming;
            agent->command_pending = 1;
            memset(&incoming, 0, sizeof(incoming));
        }
        pthread_mutex_unlock(&agent->lock);
        (void)x11_server_runtime_wakeup(agent->runtime);
        x11_managed_ipc_message_clear(&incoming);
        if (atomic_load(&agent->control_closed))
            break;
    }
    return NULL;
}

static void x11_session_agent_response(
    const x11_session_agent* agent,
    const x11_managed_ipc_message* command,
    librdp_status status,
    x11_managed_ipc_message* response)
{
    x11_managed_ipc_message_init(response);
    response->type = status == LIBRDP_STATUS_OK
                         ? X11_MANAGED_IPC_READY
                         : X11_MANAGED_IPC_ERROR;
    response->request_id = command->request_id;
    response->session_id = agent->session_id;
    response->status = status;
    response->width = x11_server_runtime_width(agent->runtime);
    response->height = x11_server_runtime_height(agent->runtime);
    response->port = x11_server_runtime_local_port(agent->runtime);
    response->agent_pid = (uint64_t)getpid();
    response->xserver_pid = (uint64_t)agent->display.xserver_pid;
    response->desktop_pid = (uint64_t)agent->display.desktop_pid;
    memcpy(response->reconnect_token,
           agent->reconnect_token,
           sizeof(response->reconnect_token));
    memcpy(response->display_name,
           agent->display.display_name,
           strlen(agent->display.display_name) + 1u);
}

static void x11_session_agent_send_startup_error(
    int descriptor,
    const x11_managed_ipc_message* request,
    librdp_status status)
{
    x11_managed_ipc_message response;

    if (!request || request->request_id == 0u)
        return;
    x11_managed_ipc_message_init(&response);
    response.type = X11_MANAGED_IPC_ERROR;
    response.request_id = request->request_id;
    response.session_id = request->session_id;
    response.status = status != LIBRDP_STATUS_OK
                          ? status
                          : LIBRDP_STATUS_STATE;
    (void)x11_managed_ipc_send(descriptor, &response, 1000);
    x11_managed_ipc_message_clear(&response);
}

static librdp_status x11_session_agent_dispatch_command(
    x11_session_agent* agent,
    const x11_managed_ipc_message* command)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (command->type == X11_MANAGED_IPC_RESIZE)
        status = x11_managed_process_resize(&agent->display,
                                            command->width,
                                            command->height);
    else if (command->type == X11_MANAGED_IPC_STOP ||
             command->type == X11_MANAGED_IPC_TERMINATE)
        atomic_store(&agent->stop_requested, 1);
    return status;
}

static librdp_status x11_session_agent_process_pending(
    x11_session_agent* agent)
{
    x11_managed_ipc_message command;
    x11_managed_ipc_message response;
    librdp_status status = LIBRDP_STATUS_OK;
    int pending = 0;

    x11_managed_ipc_message_init(&command);
    pthread_mutex_lock(&agent->lock);
    if (agent->command_pending)
    {
        command = agent->command;
        x11_managed_ipc_message_init(&agent->command);
        agent->command_pending = 0;
        pending = 1;
    }
    pthread_mutex_unlock(&agent->lock);
    if (!pending)
        return LIBRDP_STATUS_OK;
    status = x11_session_agent_dispatch_command(agent, &command);
    x11_session_agent_response(agent, &command, status, &response);
    if (x11_managed_ipc_send(agent->control_fd,
                             &response,
                             5000) != LIBRDP_STATUS_OK)
    {
        atomic_store(&agent->stop_requested, 1);
        status = LIBRDP_STATUS_CLOSED;
    }
    x11_managed_ipc_message_clear(&response);
    x11_managed_ipc_message_clear(&command);
    return status;
}

static int x11_session_agent_configure(
    const x11_managed_ipc_message* request,
    x11_server_options* options,
    x11_managed_process_group* display)
{
    int authority_length = 0;

    if (!request || !options || !display ||
        request->type != X11_MANAGED_IPC_START ||
        request->session_id == 0u ||
        request->uid != (uint32_t)geteuid() ||
        request->gid != (uint32_t)getegid() ||
        request->display_name[0] != ':' ||
        request->runtime_directory[0] != '/' ||
        request->port > UINT16_MAX ||
        request->max_peers > SERVER_HOST_MAX_PEERS ||
        (request->security_mode != LIBRDP_SECURITY_STANDARD &&
         request->security_mode != LIBRDP_SECURITY_TLS &&
         request->security_mode != LIBRDP_SECURITY_NLA) ||
        ((request->security_mode == LIBRDP_SECURITY_TLS ||
          request->security_mode == LIBRDP_SECURITY_NLA) &&
         (request->tls_certificate[0] != '/' ||
          request->tls_private_key[0] != '/')) ||
        (request->security_mode == LIBRDP_SECURITY_NLA &&
         (request->username[0] == '\0' ||
          request->password[0] == '\0')) ||
        ((request->flags & X11_MANAGED_IPC_ALLOW_DRIVE) != 0u &&
         request->drive_mount[0] != '/') ||
        (request->flags & X11_MANAGED_IPC_ALLOW_CAPTURE) == 0u)
        return 0;
    x11_server_options_init(options);
    options->session_mode = X11_SERVER_SESSION_SHADOW;
    options->display_name = request->display_name;
    options->source_kind = X11_SERVER_SOURCE_ROOT;
    options->bind_address = request->bind_address[0] != '\0'
                                ? request->bind_address
                                : "127.0.0.1";
    options->port = (uint16_t)request->port;
    options->max_peers =
        request->max_peers != 0u ? request->max_peers : 1u;
    options->security_mode =
        (librdp_security_mode)request->security_mode;
    options->tls_certificate = request->tls_certificate;
    options->tls_private_key = request->tls_private_key;
    options->nla_username = request->username;
    options->nla_domain = request->domain;
    options->nla_password = request->password;
    options->allow_capture = 1;
    options->allow_input =
        (request->flags & X11_MANAGED_IPC_ALLOW_INPUT) != 0u;
    options->allow_clipboard =
        (request->flags & X11_MANAGED_IPC_ALLOW_CLIPBOARD) != 0u;
    options->allow_drive =
        (request->flags & X11_MANAGED_IPC_ALLOW_DRIVE) != 0u;
    options->drive_read_only =
        (request->flags & X11_MANAGED_IPC_DRIVE_READ_ONLY) != 0u;
    options->drive_mount = request->drive_mount;
    x11_managed_process_group_init(display);
    display->process_group = (pid_t)request->xserver_pid;
    display->xserver_pid = (pid_t)request->xserver_pid;
    display->desktop_pid = (pid_t)request->desktop_pid;
    if (strnlen(request->reconnect_token,
                sizeof(request->reconnect_token)) !=
            X11_MANAGED_IPC_TOKEN_BYTES - 1u ||
        request->xserver_pid == 0u ||
        request->xserver_pid > (uint64_t)INT32_MAX ||
        request->desktop_pid == 0u ||
        request->desktop_pid > (uint64_t)INT32_MAX ||
        strlen(request->display_name) >=
            sizeof(display->display_name) ||
        strlen(request->runtime_directory) + sizeof("/Xauthority") >
            sizeof(display->authority_path))
        return 0;
    memcpy(display->display_name,
           request->display_name,
           strlen(request->display_name) + 1u);
    authority_length = snprintf(display->authority_path,
                                sizeof(display->authority_path),
                                "%s/Xauthority",
                                request->runtime_directory);
    if (authority_length < 0 ||
        (size_t)authority_length >=
            sizeof(display->authority_path))
        return 0;
    return 1;
}

static int x11_session_agent_run(int descriptor)
{
    x11_session_agent agent;
    x11_managed_ipc_identity peer_identity;
    x11_managed_ipc_message request;
    x11_managed_ipc_message ready;
    x11_server_options options;
    librdp_status status = LIBRDP_STATUS_OK;
    int result = 1;
    int control_started = 0;
    int request_accepted = 0;
    int ready_sent = 0;
    uint64_t start_request_id = 0u;

    memset(&agent, 0, sizeof(agent));
    agent.control_fd = descriptor;
    atomic_init(&agent.control_closed, 0);
    atomic_init(&agent.stop_requested, 0);
    x11_managed_ipc_message_init(&agent.command);
    if (pthread_mutex_init(&agent.lock, NULL) != 0)
        return 1;
    x11_managed_ipc_message_init(&request);
    status = x11_managed_ipc_peer_identity(descriptor,
                                           &peer_identity);
    if (status != LIBRDP_STATUS_OK ||
        (peer_identity.uid != 0u &&
         peer_identity.uid != geteuid()))
        goto cleanup;
    status = x11_managed_ipc_receive(descriptor, &request, 30000);
    if (status != LIBRDP_STATUS_OK ||
        !x11_session_agent_configure(&request,
                                     &options,
                                     &agent.display))
    {
        if (status == LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        goto cleanup;
    }
    request_accepted = 1;
    start_request_id = request.request_id;
    agent.session_id = request.session_id;
    memcpy(agent.reconnect_token,
           request.reconnect_token,
           sizeof(agent.reconnect_token));
    agent.runtime = x11_server_runtime_new(&options, &status);
    options.nla_password = NULL;
    x11_managed_ipc_message_clear(&request);
    if (!agent.runtime || status != LIBRDP_STATUS_OK)
        goto cleanup;
    status = x11_server_runtime_start(agent.runtime);
    if (status != LIBRDP_STATUS_OK)
        goto cleanup;
    x11_managed_ipc_message_init(&request);
    request.type = X11_MANAGED_IPC_START;
    request.request_id = start_request_id;
    x11_session_agent_response(&agent,
                               &request,
                               LIBRDP_STATUS_OK,
                               &ready);
    if (x11_managed_ipc_send(descriptor, &ready, 5000) !=
        LIBRDP_STATUS_OK)
    {
        x11_managed_ipc_message_clear(&ready);
        goto cleanup;
    }
    ready_sent = 1;
    x11_managed_ipc_message_clear(&ready);
    if (pthread_create(&agent.control_thread,
                       NULL,
                       x11_session_agent_control_main,
                       &agent) != 0)
        goto cleanup;
    control_started = 1;
    x11_session_agent_signal_context = &agent;
    if (!x11_session_agent_install_signals())
        goto cleanup;
    while (!atomic_load(&agent.stop_requested))
    {
        status = x11_server_runtime_run_once(agent.runtime, -1);
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT &&
            status != LIBRDP_STATUS_AGAIN)
        {
            if (status == LIBRDP_STATUS_CANCELLED)
                result = 0;
            break;
        }
        status = x11_session_agent_process_pending(&agent);
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_UNSUPPORTED)
            break;
    }
    if (atomic_load(&agent.stop_requested))
        result = 0;

cleanup:
    x11_session_agent_signal_context = NULL;
    if (request_accepted && !ready_sent)
    {
        x11_managed_ipc_message error_request;

        x11_managed_ipc_message_init(&error_request);
        error_request.request_id = start_request_id;
        error_request.session_id = agent.session_id;
        x11_session_agent_send_startup_error(descriptor,
                                             &error_request,
                                             status);
        x11_managed_ipc_message_clear(&error_request);
    }
    if (agent.runtime)
        (void)x11_server_runtime_cancel(agent.runtime);
    if (control_started)
    {
        (void)shutdown(descriptor, SHUT_RDWR);
        (void)pthread_join(agent.control_thread, NULL);
    }
    x11_server_runtime_free(agent.runtime);
    x11_managed_ipc_message_clear(&request);
    x11_managed_ipc_message_clear(&agent.command);
    OPENSSL_cleanse(agent.reconnect_token,
                    sizeof(agent.reconnect_token));
    pthread_mutex_destroy(&agent.lock);
    close(descriptor);
    return result;
}

int main(int argc, char** argv)
{
    int descriptor = -1;

    if (argc == 2 &&
        (strcmp(argv[1], "--help") == 0 ||
         strcmp(argv[1], "-h") == 0))
    {
        fprintf(stdout,
                "usage: %s --control-fd descriptor\n",
                argv[0]);
        return 0;
    }
    if (argc != 3 || strcmp(argv[1], "--control-fd") != 0 ||
        !x11_session_agent_parse_fd(argv[2], &descriptor))
    {
        fprintf(stderr,
                "usage: %s --control-fd descriptor\n",
                argv[0]);
        return 2;
    }
    return x11_session_agent_run(descriptor);
}
