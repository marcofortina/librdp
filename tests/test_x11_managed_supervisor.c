/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * Module: managed X11 supervisor integration tests.
 * Coverage: mock authentication, Xvfb/desktop startup, agent handoff, broker
 * disconnect and recovery, resize forwarding and orderly process cleanup.
 * Bug classes: retained credentials, unauthenticated recovery, orphaned
 * process groups, stale control sockets and request-correlation failures.
 * Determinism: the test executable doubles as a protocol-correct fake agent;
 * no network peer, desktop manager or host authentication database is used.
 */

#include "x11_managed_supervisor.h"

#include "x11_managed_ipc.h"

#include <openssl/crypto.h>

#include <errno.h>
#include <grp.h>
#include <pwd.h>
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

#define CHECK(condition)                                                        \
    do                                                                          \
    {                                                                           \
        if (!(condition))                                                       \
        {                                                                       \
            fprintf(stderr,                                                     \
                    "check failed %s:%d: %s\n",                                 \
                    __FILE__,                                                   \
                    __LINE__,                                                   \
                    #condition);                                                \
            return 1;                                                           \
        }                                                                       \
    } while (0)

static uint64_t test_now_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0u;
    return (uint64_t)now.tv_sec * 1000000000u +
           (uint64_t)now.tv_nsec;
}

static int test_identity(x11_managed_auth_identity* identity)
{
    struct passwd* account = getpwuid(geteuid());
    int group_count = (int)X11_MANAGED_AUTH_MAX_GROUPS;

    if (!account)
        return 0;
    x11_managed_auth_identity_init(identity);
    identity->uid = account->pw_uid;
    identity->gid = account->pw_gid;
    if (strlen(account->pw_name) >= sizeof(identity->username) ||
        strlen(account->pw_dir) >= sizeof(identity->home) ||
        strlen(account->pw_shell) >= sizeof(identity->shell))
        return 0;
    memcpy(identity->username,
           account->pw_name,
           strlen(account->pw_name) + 1u);
    memcpy(identity->home,
           account->pw_dir,
           strlen(account->pw_dir) + 1u);
    memcpy(identity->shell,
           account->pw_shell,
           strlen(account->pw_shell) + 1u);
    if (getgrouplist(account->pw_name,
                     account->pw_gid,
                     identity->groups,
                     &group_count) < 0 ||
        group_count <= 0)
        return 0;
    identity->group_count = (size_t)group_count;
    return 1;
}

static librdp_status test_auth_provider(
    const char* username,
    const char* password,
    x11_managed_auth_cancel_callback cancelled,
    void* cancel_user_data,
    x11_managed_auth_outcome* outcome,
    x11_managed_auth_identity* identity,
    void* provider_user_data)
{
    (void)provider_user_data;
    if (!username || !password || !outcome || !identity ||
        strcmp(username, "managed-request") != 0 ||
        strcmp(password, "ephemeral-test-secret") != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (cancelled && cancelled(cancel_user_data))
    {
        *outcome = X11_MANAGED_AUTH_CANCELLED;
        return LIBRDP_STATUS_CANCELLED;
    }
    if (!test_identity(identity))
        return LIBRDP_STATUS_STATE;
    *outcome = X11_MANAGED_AUTH_AUTHENTICATED;
    return LIBRDP_STATUS_OK;
}

static int test_parse_descriptor(const char* value)
{
    char* end = NULL;
    long descriptor = 0;

    if (!value)
        return -1;
    errno = 0;
    descriptor = strtol(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' ||
        descriptor < 3 || descriptor > INT32_MAX)
        return -1;
    return (int)descriptor;
}

static void test_agent_ready(const x11_managed_ipc_message* session,
                             const x11_managed_ipc_message* request,
                             x11_managed_ipc_message* response)
{
    x11_managed_ipc_message_init(response);
    response->type = X11_MANAGED_IPC_READY;
    response->request_id = request->request_id;
    response->session_id = session->session_id;
    response->port = 33991u;
    response->width =
        request->width != 0u ? request->width : session->width;
    response->height =
        request->height != 0u ? request->height : session->height;
    memcpy(response->reconnect_token,
           session->reconnect_token,
           sizeof(response->reconnect_token));
    memcpy(response->display_name,
           session->display_name,
           strlen(session->display_name) + 1u);
}

/*
 * Behave like the unprivileged agent at the IPC boundary. The supervisor test
 * is interested in ownership and orchestration, while server-runtime behavior
 * has its own X11 integration suite.
 */
static int test_fake_agent(int descriptor)
{
    x11_managed_ipc_message request;
    x11_managed_ipc_message response;
    x11_managed_ipc_message session;
    int done = 0;

    x11_managed_ipc_message_init(&request);
    x11_managed_ipc_message_init(&session);
    CHECK(x11_managed_ipc_receive(descriptor, &request, 5000) ==
          LIBRDP_STATUS_OK);
    CHECK(request.type == X11_MANAGED_IPC_START);
    CHECK(strcmp(request.password, "ephemeral-test-secret") == 0);
    session = request;
    x11_managed_ipc_message_init(&request);
    OPENSSL_cleanse(session.password, sizeof(session.password));
    test_agent_ready(&session, &session, &response);
    CHECK(x11_managed_ipc_send(descriptor, &response, 5000) ==
          LIBRDP_STATUS_OK);
    x11_managed_ipc_message_clear(&response);
    while (!done)
    {
        x11_managed_ipc_message_init(&request);
        CHECK(x11_managed_ipc_receive(descriptor,
                                     &request,
                                     5000) == LIBRDP_STATUS_OK);
        test_agent_ready(&session, &request, &response);
        CHECK(x11_managed_ipc_send(descriptor,
                                  &response,
                                  5000) == LIBRDP_STATUS_OK);
        done = request.type == X11_MANAGED_IPC_STOP ||
               request.type == X11_MANAGED_IPC_TERMINATE;
        x11_managed_ipc_message_clear(&response);
        x11_managed_ipc_message_clear(&request);
    }
    x11_managed_ipc_message_clear(&session);
    close(descriptor);
    return 0;
}

static int test_connect_control(const char* path)
{
    struct sockaddr_un address;
    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    size_t length = strlen(path);

    if (descriptor < 0 || length >= sizeof(address.sun_path))
    {
        if (descriptor >= 0)
            close(descriptor);
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, length + 1u);
    if (connect(descriptor,
                (const struct sockaddr*)&address,
                sizeof(address)) != 0)
    {
        close(descriptor);
        return -1;
    }
    return descriptor;
}

/*
 * Drive a full two-stage start and then discard the bootstrap channel. A
 * kernel-authenticated recovery connection must query the live session before
 * token-authorized resize and stop commands can cross to the fake agent.
 * Every generated process and filesystem object must be gone on return.
 */
static int test_managed_lifecycle(void)
{
    char root[] = "/tmp/librdp-managed-supervisor-XXXXXX";
    char runtime[4096];
    char control[4096];
    char display[64];
    int bootstrap[2] = {-1, -1};
    int control_fd = -1;
    int length = 0;
    int child_status = 0;
    pid_t supervisor_pid = -1;
    x11_managed_ipc_message initial;
    x11_managed_ipc_message authenticated;
    x11_managed_ipc_message start;
    x11_managed_ipc_message ready;
    x11_managed_ipc_message command;
    x11_managed_supervisor_config config;

    CHECK(mkdtemp(root) != NULL);
    length = snprintf(runtime, sizeof(runtime), "%s/runtime", root);
    CHECK(length > 0 && (size_t)length < sizeof(runtime));
    CHECK(mkdir(runtime, 0700) == 0);
    length = snprintf(control, sizeof(control), "%s/control.sock", root);
    CHECK(length > 0 && (size_t)length < sizeof(control));
    length = snprintf(display,
                      sizeof(display),
                      ":%d",
                      820 + (int)(getpid() % 100));
    CHECK(length > 0 && (size_t)length < sizeof(display));
    CHECK(x11_managed_ipc_connected_pair(bootstrap) ==
          LIBRDP_STATUS_OK);
    x11_managed_supervisor_config_init(&config);
    CHECK(strcmp(config.agent_path,
                 LIBRDP_X11_SESSION_AGENT_PATH) == 0);
    config.authentication.provider = test_auth_provider;
    config.agent_path = LIBRDP_TEST_MANAGED_SUPERVISOR_PATH;
    config.startup_timeout_ms = 10000;
    supervisor_pid = fork();
    CHECK(supervisor_pid >= 0);
    if (supervisor_pid == 0)
    {
        librdp_status status = LIBRDP_STATUS_OK;

        close(bootstrap[0]);
        status = x11_managed_supervisor_run(bootstrap[1], &config);
        _exit(status == LIBRDP_STATUS_OK ? 0 : 1);
    }
    close(bootstrap[1]);
    x11_managed_ipc_message_init(&initial);
    initial.type = X11_MANAGED_IPC_START;
    initial.request_id = 10u;
    initial.width = 800u;
    initial.height = 600u;
    memcpy(initial.username,
           "managed-request",
           sizeof("managed-request"));
    memcpy(initial.password,
           "ephemeral-test-secret",
           sizeof("ephemeral-test-secret"));
    CHECK(x11_managed_ipc_send(bootstrap[0], &initial, 5000) ==
          LIBRDP_STATUS_OK);
    x11_managed_ipc_message_init(&authenticated);
    CHECK(x11_managed_ipc_receive(bootstrap[0],
                                 &authenticated,
                                 5000) == LIBRDP_STATUS_OK);
    CHECK(authenticated.type == X11_MANAGED_IPC_AUTHENTICATED);
    x11_managed_ipc_message_init(&start);
    start.type = X11_MANAGED_IPC_START;
    start.request_id = 11u;
    start.session_id = 0x12345678u;
    start.created_ns = test_now_ns();
    start.idle_timeout_ns = 60000000000u;
    start.max_duration_ns = 60000000000u;
    start.flags = X11_MANAGED_IPC_ALLOW_CAPTURE |
                  X11_MANAGED_IPC_ALLOW_INPUT |
                  X11_MANAGED_IPC_TEST_XVFB |
                  X11_MANAGED_IPC_PERSISTENT |
                  X11_MANAGED_IPC_RECONNECT;
    start.uid = authenticated.uid;
    start.gid = authenticated.gid;
    start.width = initial.width;
    start.height = initial.height;
    start.security_mode = LIBRDP_SECURITY_STANDARD;
    start.max_peers = 1u;
    memcpy(start.username,
           authenticated.username,
           strlen(authenticated.username) + 1u);
    memcpy(start.reconnect_token,
           "0123456789abcdef0123456789abcdef"
           "0123456789abcdef0123456789abcdef",
           X11_MANAGED_IPC_TOKEN_BYTES);
    memcpy(start.display_name, display, strlen(display) + 1u);
    memcpy(start.runtime_directory,
           runtime,
           strlen(runtime) + 1u);
    memcpy(start.control_socket, control, strlen(control) + 1u);
    memcpy(start.desktop_command,
           "/bin/sleep 30",
           sizeof("/bin/sleep 30"));
    memcpy(start.xserver_command,
           LIBRDP_TEST_XVFB_PATH,
           sizeof(LIBRDP_TEST_XVFB_PATH));
    CHECK(x11_managed_ipc_send(bootstrap[0], &start, 5000) ==
          LIBRDP_STATUS_OK);
    x11_managed_ipc_message_init(&ready);
    CHECK(x11_managed_ipc_receive(bootstrap[0], &ready, 10000) ==
          LIBRDP_STATUS_OK);
    CHECK(ready.type == X11_MANAGED_IPC_READY &&
          ready.port == 33991u &&
          ready.supervisor_pid == (uint64_t)supervisor_pid);
    x11_managed_ipc_message_clear(&ready);
    CHECK(close(bootstrap[0]) == 0);
    bootstrap[0] = -1;
    control_fd = test_connect_control(control);
    CHECK(control_fd >= 0);
    x11_managed_ipc_message_init(&command);
    command.type = X11_MANAGED_IPC_QUERY;
    command.request_id = 12u;
    command.session_id = start.session_id;
    CHECK(x11_managed_ipc_send(control_fd, &command, 5000) ==
          LIBRDP_STATUS_OK);
    CHECK(x11_managed_ipc_receive(control_fd, &ready, 5000) ==
          LIBRDP_STATUS_OK);
    CHECK(ready.type == X11_MANAGED_IPC_READY &&
          ready.session_id == start.session_id);
    x11_managed_ipc_message_clear(&command);
    x11_managed_ipc_message_init(&command);
    command.type = X11_MANAGED_IPC_RESIZE;
    command.request_id = 13u;
    command.session_id = start.session_id;
    command.width = 1024u;
    command.height = 768u;
    memcpy(command.reconnect_token,
           ready.reconnect_token,
           sizeof(command.reconnect_token));
    x11_managed_ipc_message_clear(&ready);
    CHECK(x11_managed_ipc_send(control_fd, &command, 5000) ==
          LIBRDP_STATUS_OK);
    CHECK(x11_managed_ipc_receive(control_fd, &ready, 5000) ==
          LIBRDP_STATUS_OK);
    CHECK(ready.request_id == command.request_id);
    x11_managed_ipc_message_clear(&command);
    x11_managed_ipc_message_init(&command);
    command.type = X11_MANAGED_IPC_STOP;
    command.request_id = 14u;
    command.session_id = start.session_id;
    memcpy(command.reconnect_token,
           start.reconnect_token,
           sizeof(command.reconnect_token));
    CHECK(x11_managed_ipc_send(control_fd, &command, 5000) ==
          LIBRDP_STATUS_OK);
    CHECK(x11_managed_ipc_receive(control_fd, &ready, 5000) ==
          LIBRDP_STATUS_OK);
    close(control_fd);
    CHECK(waitpid(supervisor_pid, &child_status, 0) ==
          supervisor_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    CHECK(lstat(control, &(struct stat){0}) != 0);
    CHECK(rmdir(runtime) == 0);
    CHECK(rmdir(root) == 0);
    x11_managed_ipc_message_clear(&initial);
    x11_managed_ipc_message_clear(&authenticated);
    x11_managed_ipc_message_clear(&start);
    x11_managed_ipc_message_clear(&ready);
    x11_managed_ipc_message_clear(&command);
    return 0;
}

int main(int argc, char** argv)
{
    if (argc == 3 && strcmp(argv[1], "--control-fd") == 0)
    {
        int descriptor = test_parse_descriptor(argv[2]);

        return descriptor >= 0 ? test_fake_agent(descriptor) : 2;
    }
    return test_managed_lifecycle();
}
