/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * Module: managed X11 command-client tests.
 * Coverage: CLI request construction, environment-only secret handling,
 * response correlation and stable START/ATTACH output.
 * Bug classes: credential exposure through argv/output, missing reconnect
 * tokens, malformed broker replies and action-to-message mapping errors.
 * Determinism: a local broker fixture serves synthetic IPC responses; no X
 * server, authentication backend or network listener is used.
 */

#include "x11_managed_client.h"

#include "x11_managed_ipc.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
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

typedef struct test_managed_client_broker
{
    int listener;
    int result;
} test_managed_client_broker;

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

static int test_listener(const char* path)
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
        listen(descriptor, 2) != 0)
    {
        close(descriptor);
        unlink(path);
        return -1;
    }
    return descriptor;
}

static int test_reply(int descriptor,
                      const x11_managed_ipc_message* request)
{
    x11_managed_ipc_message response;

    x11_managed_ipc_message_init(&response);
    response.type = X11_MANAGED_IPC_READY;
    response.request_id = request->request_id;
    response.session_id = 0x1234u;
    response.port = 33991u;
    response.width = request->width;
    response.height = request->height;
    response.session_state = X11_MANAGED_SESSION_ACTIVE;
    response.attachment_count = 1u;
    CHECK(test_copy(
        response.reconnect_token,
        sizeof(response.reconnect_token),
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef"));
    CHECK(test_copy(response.display_name,
                    sizeof(response.display_name),
                    ":42"));
    CHECK(test_copy(response.bind_address,
                    sizeof(response.bind_address),
                    "127.0.0.1"));
    CHECK(x11_managed_ipc_send(descriptor, &response, 1000) ==
          LIBRDP_STATUS_OK);
    x11_managed_ipc_message_clear(&response);
    return 0;
}

/*
 * Serve one START followed by one ATTACH. This validates the exact secrets on
 * the wire while ensuring the command client does not print either secret.
 */
static void* test_broker_main(void* user_data)
{
    test_managed_client_broker* broker =
        (test_managed_client_broker*)user_data;
    size_t index = 0u;

    broker->result = 1;
    for (index = 0u; index < 2u; index++)
    {
        x11_managed_ipc_message request;
        int descriptor = accept(broker->listener, NULL, NULL);

        if (descriptor < 0)
            return NULL;
        x11_managed_ipc_message_init(&request);
        if (x11_managed_ipc_receive(descriptor,
                                    &request,
                                    1000) != LIBRDP_STATUS_OK)
        {
            close(descriptor);
            return NULL;
        }
        if (index == 0u)
        {
            if (request.type != X11_MANAGED_IPC_START ||
                strcmp(request.password,
                       "ephemeral-managed-secret") != 0 ||
                strcmp(request.username, "test-account") != 0)
            {
                close(descriptor);
                x11_managed_ipc_message_clear(&request);
                return NULL;
            }
        }
        else if (request.type != X11_MANAGED_IPC_ATTACH ||
                 request.session_id != 0x1234u ||
                 strcmp(request.reconnect_token,
                        "0123456789abcdef0123456789abcdef"
                        "0123456789abcdef0123456789abcdef") != 0)
        {
            close(descriptor);
            x11_managed_ipc_message_clear(&request);
            return NULL;
        }
        if (test_reply(descriptor, &request) != 0)
        {
            close(descriptor);
            x11_managed_ipc_message_clear(&request);
            return NULL;
        }
        close(descriptor);
        x11_managed_ipc_message_clear(&request);
    }
    broker->result = 0;
    return NULL;
}

static int test_stream_contains(FILE* stream, const char* needle)
{
    char buffer[2048];
    size_t length = 0u;

    if (fflush(stream) != 0 || fseek(stream, 0, SEEK_SET) != 0)
        return 0;
    length = fread(buffer, 1u, sizeof(buffer) - 1u, stream);
    buffer[length] = '\0';
    return strstr(buffer, needle) != NULL;
}

static int test_managed_client(void)
{
    char root[] = "/tmp/librdp-managed-client-XXXXXX";
    char socket_path[4096];
    x11_server_options options;
    test_managed_client_broker broker;
    pthread_t thread;
    FILE* output = NULL;
    FILE* error = NULL;
    int length = 0;

    CHECK(mkdtemp(root) != NULL);
    length = snprintf(socket_path,
                      sizeof(socket_path),
                      "%s/broker.sock",
                      root);
    CHECK(length > 0 && (size_t)length < sizeof(socket_path));
    memset(&broker, 0, sizeof(broker));
    broker.listener = test_listener(socket_path);
    CHECK(broker.listener >= 0);
    CHECK(pthread_create(
              &thread, NULL, test_broker_main, &broker) == 0);
    CHECK(setenv("LIBRDP_TEST_MANAGED_PASSWORD",
                 "ephemeral-managed-secret",
                 1) == 0);
    CHECK(setenv(
              "LIBRDP_TEST_MANAGED_TOKEN",
              "0123456789abcdef0123456789abcdef"
              "0123456789abcdef0123456789abcdef",
              1) == 0);
    output = tmpfile();
    error = tmpfile();
    CHECK(output != NULL && error != NULL);
    x11_server_options_init(&options);
    options.session_mode = X11_SERVER_SESSION_MANAGED;
    options.managed_action = X11_SERVER_MANAGED_START;
    options.broker_socket = socket_path;
    options.nla_username = "test-account";
    options.password_environment =
        "LIBRDP_TEST_MANAGED_PASSWORD";
    options.allow_capture = 1;
    options.allow_input = 1;
    options.persistent_session = 1;
    options.reconnect_session = 1;
    CHECK(x11_server_run_managed(
              &options, output, error) == 0);
    CHECK(test_stream_contains(output, "session_id=4660"));
    CHECK(!test_stream_contains(
        output, "ephemeral-managed-secret"));
    CHECK(fclose(output) == 0);
    output = tmpfile();
    CHECK(output != NULL);
    options.managed_action = X11_SERVER_MANAGED_ATTACH;
    options.managed_session_id = 0x1234u;
    options.reconnect_token_environment =
        "LIBRDP_TEST_MANAGED_TOKEN";
    CHECK(x11_server_run_managed(
              &options, output, error) == 0);
    CHECK(test_stream_contains(output, "port=33991"));
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(broker.result == 0);
    close(broker.listener);
    fclose(output);
    fclose(error);
    CHECK(unsetenv("LIBRDP_TEST_MANAGED_PASSWORD") == 0);
    CHECK(unsetenv("LIBRDP_TEST_MANAGED_TOKEN") == 0);
    CHECK(unlink(socket_path) == 0);
    CHECK(rmdir(root) == 0);
    return 0;
}

int main(void)
{
    return test_managed_client();
}
