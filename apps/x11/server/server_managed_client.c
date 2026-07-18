/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: bounded managed-session broker client.
 * Invariants: each connection carries exactly one correlated request/response,
 * secrets never enter argv output or diagnostics and response IDs must match.
 * Ownership: request and response storage is stack-owned and securely cleared.
 * Threading: synchronous and caller-owned.
 * Trust boundary: the configured Unix socket and all broker response fields
 * remain untrusted until the IPC decoder and correlation checks succeed.
 */

#include "server_managed_client.h"

#include "server_managed_ipc.h"

#include <openssl/crypto.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int x11_managed_client_copy(char* output,
                                   size_t capacity,
                                   const char* input)
{
    size_t length = input ? strlen(input) : 0u;

    if (!output || !input || capacity == 0u || length >= capacity)
        return 0;
    memcpy(output, input, length + 1u);
    return 1;
}

static int x11_managed_client_connect(const char* path)
{
    struct sockaddr_un address;
    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    size_t length = path ? strlen(path) : 0u;

    if (descriptor < 0 || !path || path[0] != '/' ||
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

static x11_managed_ipc_type x11_managed_client_type(
    x11_server_managed_action action)
{
    switch (action)
    {
        case X11_SERVER_MANAGED_START:
            return X11_MANAGED_IPC_START;
        case X11_SERVER_MANAGED_ATTACH:
            return X11_MANAGED_IPC_ATTACH;
        case X11_SERVER_MANAGED_QUERY:
            return X11_MANAGED_IPC_QUERY;
        case X11_SERVER_MANAGED_RESIZE:
            return X11_MANAGED_IPC_RESIZE;
        case X11_SERVER_MANAGED_DETACH:
            return X11_MANAGED_IPC_DETACH;
        case X11_SERVER_MANAGED_TERMINATE:
            return X11_MANAGED_IPC_TERMINATE;
        default:
            return 0;
    }
}

static librdp_status x11_managed_client_request(
    const x11_server_options* options,
    x11_managed_ipc_message* request)
{
    const char* password = NULL;
    const char* token = NULL;

    x11_managed_ipc_message_init(request);
    request->type =
        x11_managed_client_type(options->managed_action);
    if (request->type == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    request->request_id =
        ((uint64_t)getpid() << 32u) ^
        (uint64_t)(unsigned int)options->managed_action;
    if (request->request_id == 0u)
        request->request_id = 1u;
    request->session_id = options->managed_session_id;
    request->width = options->width;
    request->height = options->height;
    if (options->managed_action == X11_SERVER_MANAGED_START)
    {
        password = getenv(options->password_environment);
        if (!password || password[0] == '\0' ||
            !x11_managed_client_copy(
                request->username,
                sizeof(request->username),
                options->nla_username) ||
            !x11_managed_client_copy(
                request->domain,
                sizeof(request->domain),
                options->nla_domain ? options->nla_domain : "") ||
            !x11_managed_client_copy(
                request->password,
                sizeof(request->password),
                password))
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        request->flags = X11_MANAGED_IPC_ALLOW_CAPTURE;
        if (options->allow_input)
            request->flags |= X11_MANAGED_IPC_ALLOW_INPUT;
        if (options->allow_clipboard)
            request->flags |= X11_MANAGED_IPC_ALLOW_CLIPBOARD;
        if (options->allow_drive)
        {
            request->flags |= X11_MANAGED_IPC_ALLOW_DRIVE;
            if (options->drive_read_only)
                request->flags |=
                    X11_MANAGED_IPC_DRIVE_READ_ONLY;
        }
        if (options->persistent_session)
            request->flags |= X11_MANAGED_IPC_PERSISTENT;
        if (options->reconnect_session)
            request->flags |= X11_MANAGED_IPC_RECONNECT;
    }
    else if (options->reconnect_token_environment)
    {
        token = getenv(options->reconnect_token_environment);
        if (token && token[0] != '\0' &&
            !x11_managed_client_copy(
                request->reconnect_token,
                sizeof(request->reconnect_token),
                token))
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    return x11_managed_ipc_message_validate(request);
}

static void x11_managed_client_print(
    FILE* output,
    const x11_managed_ipc_message* response)
{
    fprintf(output,
            "status=ok session_id=%llu address=%s port=%u "
            "display=%s width=%u height=%u state=%u token=%s\n",
            (unsigned long long)response->session_id,
            response->bind_address[0] != '\0'
                ? response->bind_address
                : "127.0.0.1",
            response->port,
            response->display_name,
            response->width,
            response->height,
            response->session_state,
            response->reconnect_token);
}

int x11_server_run_managed(const x11_server_options* options,
                           FILE* output,
                           FILE* error)
{
    x11_managed_ipc_message request;
    x11_managed_ipc_message response;
    librdp_status status = LIBRDP_STATUS_OK;
    int descriptor = -1;
    int result = 1;

    if (!options || !output || !error)
        return 2;
    x11_managed_ipc_message_init(&request);
    x11_managed_ipc_message_init(&response);
    status = x11_managed_client_request(options, &request);
    if (status == LIBRDP_STATUS_OK)
    {
        descriptor = x11_managed_client_connect(
            options->broker_socket);
        if (descriptor < 0)
            status = LIBRDP_STATUS_IO_ERROR;
    }
    if (status == LIBRDP_STATUS_OK)
        status = x11_managed_ipc_send(descriptor, &request, 10000);
    OPENSSL_cleanse(request.password, sizeof(request.password));
    if (status == LIBRDP_STATUS_OK)
        status = x11_managed_ipc_receive(
            descriptor, &response, 30000);
    if (status == LIBRDP_STATUS_OK &&
        (response.request_id != request.request_id ||
         response.type != X11_MANAGED_IPC_READY))
    {
        status = response.type == X11_MANAGED_IPC_ERROR &&
                         response.status != LIBRDP_STATUS_OK
                     ? response.status
                     : LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        x11_managed_client_print(output, &response);
        result = 0;
    }
    else
    {
        fprintf(error,
                "error=managed_session status=%s\n",
                librdp_status_name(status));
    }
    if (descriptor >= 0)
        close(descriptor);
    x11_managed_ipc_message_clear(&request);
    x11_managed_ipc_message_clear(&response);
    return result;
}
