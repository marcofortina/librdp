/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/*
 * Module: managed X11 broker lifecycle tests.
 * Coverage: two-stage authentication, policy filtering, session allocation,
 * detach/attach, resize, termination and registry recovery after broker restart.
 * Bug classes: retained credentials, confused-deputy authorization, unbounded
 * workers, stale resources and cross-session reconnect token acceptance.
 * Determinism: this executable doubles as a supervisor process; no X server,
 * host authentication database or RDP network peer is required.
 */

#include "server_managed_broker.h"

#include "server_managed_ipc.h"

#include <openssl/crypto.h>

#include <errno.h>
#include <pthread.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
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

typedef struct test_broker_thread
{
    x11_managed_broker* broker;
    librdp_status status;
} test_broker_thread;

static int test_copy(char* output,
                     size_t capacity,
                     const char* input)
{
    size_t length = input ? strlen(input) : 0u;

    if (!output || !input || capacity == 0u || length >= capacity)
        return 0;
    memcpy(output, input, length + 1u);
    return 1;
}

static int test_parse_descriptor(const char* value)
{
    char* end = NULL;
    long parsed = 0;

    if (!value)
        return -1;
    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' ||
        parsed < 3 || parsed > INT32_MAX)
        return -1;
    return (int)parsed;
}

static int test_connect(const char* path)
{
    struct sockaddr_un address;
    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    size_t length = path ? strlen(path) : 0u;

    if (descriptor < 0 || !path ||
        length >= sizeof(address.sun_path))
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

static int test_wait_path(const char* path,
                          int should_exist,
                          int timeout_ms)
{
    int elapsed = 0;

    while (elapsed < timeout_ms)
    {
        struct stat info;
        int exists = lstat(path, &info) == 0;

        if (exists == should_exist)
            return 1;
        (void)poll(NULL, 0u, 10);
        elapsed += 10;
    }
    return 0;
}

static void test_ready(const x11_managed_ipc_message* session,
                       uint64_t request_id,
                       x11_managed_ipc_message* response)
{
    x11_managed_ipc_message_init(response);
    response->type = X11_MANAGED_IPC_READY;
    response->request_id = request_id;
    response->session_id = session->session_id;
    response->created_ns = session->created_ns;
    response->idle_timeout_ns = session->idle_timeout_ns;
    response->max_duration_ns = session->max_duration_ns;
    response->supervisor_pid = (uint64_t)getpid();
    response->agent_pid = (uint64_t)getpid();
    response->xserver_pid = (uint64_t)getpid();
    response->desktop_pid = (uint64_t)getpid();
    response->flags = session->flags;
    response->uid = session->uid;
    response->gid = session->gid;
    response->width = session->width;
    response->height = session->height;
    response->port = 33990u;
    response->security_mode = session->security_mode;
    response->max_peers = 1u;
    response->session_state = session->session_state;
    response->attachment_count = session->attachment_count;
    (void)test_copy(response->username,
                    sizeof(response->username),
                    session->username);
    (void)test_copy(response->reconnect_token,
                    sizeof(response->reconnect_token),
                    session->reconnect_token);
    (void)test_copy(response->display_name,
                    sizeof(response->display_name),
                    session->display_name);
    (void)test_copy(response->runtime_directory,
                    sizeof(response->runtime_directory),
                    session->runtime_directory);
    (void)test_copy(response->control_socket,
                    sizeof(response->control_socket),
                    session->control_socket);
}

static int test_create_control_listener(const char* path)
{
    struct sockaddr_un address;
    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    size_t length = path ? strlen(path) : 0u;

    if (descriptor < 0 || !path ||
        length >= sizeof(address.sun_path))
    {
        if (descriptor >= 0)
            close(descriptor);
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, length + 1u);
    if (bind(descriptor,
             (const struct sockaddr*)&address,
             sizeof(address)) != 0 ||
        chmod(path, 0600) != 0 ||
        listen(descriptor, 4) != 0)
    {
        close(descriptor);
        unlink(path);
        return -1;
    }
    return descriptor;
}

/*
 * Emulate the supervisor boundary, including a persistent root-owned control
 * socket. Password bytes are accepted only in the first message and must be
 * absent from the policy-derived start message.
 */
static int test_fake_supervisor(int descriptor)
{
    struct passwd* account = getpwuid(geteuid());
    x11_managed_ipc_message initial;
    x11_managed_ipc_message authenticated;
    x11_managed_ipc_message session;
    x11_managed_ipc_message response;
    int listener = -1;
    int done = 0;

    CHECK(account != NULL);
    x11_managed_ipc_message_init(&initial);
    CHECK(x11_managed_ipc_receive(descriptor, &initial, 5000) ==
          LIBRDP_STATUS_OK);
    CHECK(initial.type == X11_MANAGED_IPC_START);
    CHECK(strcmp(initial.password, "transient-broker-secret") == 0);
    x11_managed_ipc_message_init(&authenticated);
    authenticated.type = X11_MANAGED_IPC_AUTHENTICATED;
    authenticated.request_id = initial.request_id;
    authenticated.uid = (uint32_t)account->pw_uid;
    authenticated.gid = (uint32_t)account->pw_gid;
    authenticated.auth_outcome = 1u;
    CHECK(test_copy(authenticated.username,
                    sizeof(authenticated.username),
                    account->pw_name));
    CHECK(x11_managed_ipc_send(
              descriptor, &authenticated, 5000) ==
          LIBRDP_STATUS_OK);
    x11_managed_ipc_message_init(&session);
    CHECK(x11_managed_ipc_receive(descriptor, &session, 5000) ==
          LIBRDP_STATUS_OK);
    CHECK(session.type == X11_MANAGED_IPC_START);
    CHECK(session.password[0] == '\0');
    CHECK((session.flags & X11_MANAGED_IPC_ALLOW_INPUT) != 0u);
    CHECK((session.flags & X11_MANAGED_IPC_ALLOW_CLIPBOARD) == 0u);
    listener = test_create_control_listener(
        session.control_socket);
    CHECK(listener >= 0);
    session.session_state = X11_MANAGED_SESSION_ACTIVE;
    session.attachment_count = 1u;
    test_ready(&session, initial.request_id, &response);
    CHECK(x11_managed_ipc_send(descriptor, &response, 5000) ==
          LIBRDP_STATUS_OK);
    close(descriptor);
    x11_managed_ipc_message_clear(&response);
    OPENSSL_cleanse(initial.password, sizeof(initial.password));
    while (!done)
    {
        int control = accept(listener, NULL, NULL);
        x11_managed_ipc_message command;

        CHECK(control >= 0);
        x11_managed_ipc_message_init(&command);
        CHECK(x11_managed_ipc_receive(control, &command, 5000) ==
              LIBRDP_STATUS_OK);
        CHECK(command.session_id == session.session_id);
        CHECK(command.type == X11_MANAGED_IPC_QUERY ||
              x11_managed_ipc_token_equal(
                  command.reconnect_token,
                  session.reconnect_token));
        if (command.type == X11_MANAGED_IPC_RESIZE)
        {
            session.width = command.width;
            session.height = command.height;
        }
        else if (command.type == X11_MANAGED_IPC_DETACH)
        {
            session.session_state =
                X11_MANAGED_SESSION_DETACHED;
            session.attachment_count = 0u;
        }
        else if (command.type == X11_MANAGED_IPC_ATTACH)
        {
            session.session_state =
                X11_MANAGED_SESSION_ACTIVE;
            session.attachment_count = 1u;
        }
        done = command.type == X11_MANAGED_IPC_STOP ||
               command.type == X11_MANAGED_IPC_TERMINATE;
        test_ready(&session, command.request_id, &response);
        CHECK(x11_managed_ipc_send(control, &response, 5000) ==
              LIBRDP_STATUS_OK);
        x11_managed_ipc_message_clear(&command);
        x11_managed_ipc_message_clear(&response);
        close(control);
    }
    close(listener);
    unlink(session.control_socket);
    x11_managed_ipc_message_clear(&initial);
    x11_managed_ipc_message_clear(&authenticated);
    x11_managed_ipc_message_clear(&session);
    return 0;
}

static void* test_broker_main(void* user_data)
{
    test_broker_thread* thread =
        (test_broker_thread*)user_data;

    thread->status = x11_managed_broker_run(thread->broker);
    return NULL;
}

static int test_start_broker(const x11_managed_policy* policy,
                             test_broker_thread* context,
                             pthread_t* thread)
{
    librdp_status status = LIBRDP_STATUS_OK;

    memset(context, 0, sizeof(*context));
    context->broker = x11_managed_broker_new(policy, &status);
    if (!context->broker || status != LIBRDP_STATUS_OK ||
        pthread_create(thread, NULL, test_broker_main, context) != 0)
        return 0;
    return test_wait_path(policy->socket_path, 1, 3000);
}

static int test_stop_broker(test_broker_thread* context,
                            pthread_t thread)
{
    int result = 1;

    if (x11_managed_broker_cancel(context->broker) !=
            LIBRDP_STATUS_OK ||
        pthread_join(thread, NULL) != 0 ||
        context->status != LIBRDP_STATUS_OK)
        result = 0;
    x11_managed_broker_free(context->broker);
    context->broker = NULL;
    return result;
}

static int test_request(const char* socket_path,
                        x11_managed_ipc_message* request,
                        x11_managed_ipc_message* response)
{
    int descriptor = test_connect(socket_path);
    librdp_status status = LIBRDP_STATUS_OK;

    if (descriptor < 0)
        return 0;
    status = x11_managed_ipc_send(descriptor, request, 5000);
    if (status == LIBRDP_STATUS_OK)
        status = x11_managed_ipc_receive(
            descriptor, response, 10000);
    close(descriptor);
    if (status != LIBRDP_STATUS_OK ||
        response->type != X11_MANAGED_IPC_READY)
    {
        fprintf(stderr,
                "broker request failed transport=%s type=%u status=%s\n",
                librdp_status_name(status),
                (unsigned int)response->type,
                librdp_status_name(response->status));
    }
    return status == LIBRDP_STATUS_OK &&
           response->type == X11_MANAGED_IPC_READY;
}

/*
 * Start one persistent session, exercise its control lifecycle, replace the
 * broker process view, recover from the supervisor socket and terminate it.
 */
static int test_broker_lifecycle(void)
{
    char root[] = "/tmp/librdp-managed-broker-XXXXXX";
    char socket_path[4096];
    char runtime_root[4096];
    char runtime_path[4096];
    struct passwd* account = getpwuid(geteuid());
    x11_managed_policy policy;
    test_broker_thread first;
    test_broker_thread second;
    pthread_t first_thread;
    pthread_t second_thread;
    x11_managed_ipc_message request;
    x11_managed_ipc_message response;
    uint64_t session_id = 0u;
    char token[X11_MANAGED_IPC_TOKEN_BYTES];
    int length = 0;

    CHECK(account != NULL);
    CHECK(mkdtemp(root) != NULL);
    length = snprintf(
        socket_path, sizeof(socket_path), "%s/broker.sock", root);
    CHECK(length > 0 && (size_t)length < sizeof(socket_path));
    length = snprintf(
        runtime_root, sizeof(runtime_root), "%s/sessions", root);
    CHECK(length > 0 && (size_t)length < sizeof(runtime_root));
    x11_managed_policy_init(&policy);
    CHECK(test_copy(policy.socket_path,
                    sizeof(policy.socket_path),
                    socket_path));
    CHECK(test_copy(policy.runtime_root,
                    sizeof(policy.runtime_root),
                    runtime_root));
    CHECK(test_copy(policy.supervisor_path,
                    sizeof(policy.supervisor_path),
                    LIBRDP_TEST_MANAGED_BROKER_PATH));
    CHECK(test_copy(policy.agent_path,
                    sizeof(policy.agent_path),
                    LIBRDP_TEST_MANAGED_BROKER_PATH));
    CHECK(test_copy(policy.xserver_path,
                    sizeof(policy.xserver_path),
                    "/bin/true"));
    CHECK(test_copy(policy.desktop_command,
                    sizeof(policy.desktop_command),
                    "/bin/true"));
    policy.security_mode = LIBRDP_SECURITY_STANDARD;
    policy.allow_standard_security = 1;
    policy.allow_input = 1;
    policy.allow_clipboard = 0;
    policy.allow_drive = 1;
    policy.max_sessions = 2u;
    policy.max_sessions_per_user = 1u;
    policy.first_display =
        700u + (uint32_t)(getpid() % 100);
    policy.last_display = policy.first_display + 1u;
    CHECK(x11_managed_policy_valid(&policy));
    CHECK(test_start_broker(
        &policy, &first, &first_thread));
    x11_managed_ipc_message_init(&request);
    request.type = X11_MANAGED_IPC_START;
    request.request_id = 100u;
    request.width = 800u;
    request.height = 600u;
    request.flags = X11_MANAGED_IPC_ALLOW_CAPTURE |
                    X11_MANAGED_IPC_ALLOW_INPUT |
                    X11_MANAGED_IPC_ALLOW_CLIPBOARD |
                    X11_MANAGED_IPC_ALLOW_DRIVE |
                    X11_MANAGED_IPC_PERSISTENT |
                    X11_MANAGED_IPC_RECONNECT;
    CHECK(test_copy(request.username,
                    sizeof(request.username),
                    account->pw_name));
    CHECK(test_copy(request.password,
                    sizeof(request.password),
                    "transient-broker-secret"));
    x11_managed_ipc_message_init(&response);
    CHECK(test_request(socket_path, &request, &response));
    CHECK(response.session_id != 0u &&
          response.port == 33990u &&
          (response.flags & X11_MANAGED_IPC_ALLOW_INPUT) != 0u &&
          (response.flags &
           X11_MANAGED_IPC_ALLOW_CLIPBOARD) == 0u);
    session_id = response.session_id;
    memcpy(token, response.reconnect_token, sizeof(token));
    length = snprintf(runtime_path,
                      sizeof(runtime_path),
                      "%s/session-%016llx",
                      runtime_root,
                      (unsigned long long)session_id);
    CHECK(length > 0 && (size_t)length < sizeof(runtime_path));
    x11_managed_ipc_message_clear(&request);
    x11_managed_ipc_message_init(&request);
    request.type = X11_MANAGED_IPC_DETACH;
    request.request_id = 101u;
    request.session_id = session_id;
    memcpy(request.reconnect_token, token, sizeof(token));
    x11_managed_ipc_message_clear(&response);
    CHECK(test_request(socket_path, &request, &response));
    CHECK(response.session_state == X11_MANAGED_SESSION_DETACHED);
    x11_managed_ipc_message_clear(&request);
    x11_managed_ipc_message_init(&request);
    request.type = X11_MANAGED_IPC_ATTACH;
    request.request_id = 102u;
    request.session_id = session_id;
    memcpy(request.reconnect_token, token, sizeof(token));
    x11_managed_ipc_message_clear(&response);
    CHECK(test_request(socket_path, &request, &response));
    CHECK(response.session_state == X11_MANAGED_SESSION_ACTIVE);
    x11_managed_ipc_message_clear(&request);
    x11_managed_ipc_message_init(&request);
    request.type = X11_MANAGED_IPC_RESIZE;
    request.request_id = 103u;
    request.session_id = session_id;
    request.width = 1280u;
    request.height = 720u;
    memcpy(request.reconnect_token, token, sizeof(token));
    x11_managed_ipc_message_clear(&response);
    CHECK(test_request(socket_path, &request, &response));
    CHECK(response.width == 1280u && response.height == 720u);
    CHECK(test_stop_broker(&first, first_thread));
    CHECK(test_wait_path(runtime_path, 1, 1000));
    CHECK(test_start_broker(
        &policy, &second, &second_thread));
    x11_managed_ipc_message_clear(&request);
    x11_managed_ipc_message_init(&request);
    request.type = X11_MANAGED_IPC_QUERY;
    request.request_id = 104u;
    request.session_id = session_id;
    memcpy(request.reconnect_token, token, sizeof(token));
    x11_managed_ipc_message_clear(&response);
    CHECK(test_request(socket_path, &request, &response));
    CHECK(response.width == 1280u &&
          response.height == 720u &&
          response.session_id == session_id);
    x11_managed_ipc_message_clear(&request);
    x11_managed_ipc_message_init(&request);
    request.type = X11_MANAGED_IPC_TERMINATE;
    request.request_id = 105u;
    request.session_id = session_id;
    memcpy(request.reconnect_token, token, sizeof(token));
    x11_managed_ipc_message_clear(&response);
    CHECK(test_request(socket_path, &request, &response));
    CHECK(test_wait_path(runtime_path, 0, 4000));
    CHECK(test_stop_broker(&second, second_thread));
    CHECK(rmdir(runtime_root) == 0);
    CHECK(rmdir(root) == 0);
    x11_managed_ipc_message_clear(&request);
    x11_managed_ipc_message_clear(&response);
    OPENSSL_cleanse(token, sizeof(token));
    return 0;
}

int main(int argc, char** argv)
{
    int index = 0;
    int descriptor = -1;

    if (argc > 1 && strcmp(argv[1], "--control-fd") == 0)
    {
        for (index = 1; index + 1 < argc; index++)
        {
            if (strcmp(argv[index], "--control-fd") == 0)
                descriptor =
                    test_parse_descriptor(argv[index + 1]);
        }
        return descriptor >= 0
                   ? test_fake_supervisor(descriptor)
                   : 2;
    }
    return test_broker_lifecycle();
}
