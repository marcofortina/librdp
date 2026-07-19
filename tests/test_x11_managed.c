/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic managed-session IPC contract tests.
 * Coverage: bounds, malformed and truncated frames, deadlines, peer credential
 * authentication, random reconnect tokens and sensitive-field cleansing.
 * Bug classes: over-read, oversized allocation, version confusion, stale
 * token acceptance, partial-frame commit and credential lifetime leaks.
 * Determinism: local Unix sockets, bounded deadlines and kernel credentials
 * avoid network, desktop and external service dependencies.
 */

#include "x11_managed_ipc.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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

static void test_message_start(x11_managed_ipc_message* message)
{
    x11_managed_ipc_message_init(message);
    message->type = X11_MANAGED_IPC_START;
    message->request_id = 7u;
    message->width = 1280u;
    message->height = 720u;
    message->supervisor_pid = 101u;
    message->xserver_pid = 102u;
    message->desktop_pid = 103u;
    message->flags = X11_MANAGED_IPC_ALLOW_INPUT |
                     X11_MANAGED_IPC_ALLOW_CLIPBOARD |
                     X11_MANAGED_IPC_DRIVE_READ_ONLY;
    memcpy(message->username, "test-user", sizeof("test-user"));
    memcpy(message->domain, "test-domain", sizeof("test-domain"));
    memcpy(message->password, "test-secret", sizeof("test-secret"));
    memcpy(message->desktop_command,
           "/usr/bin/test-desktop",
           sizeof("/usr/bin/test-desktop"));
    memcpy(message->xserver_command,
           "/usr/bin/Xorg",
           sizeof("/usr/bin/Xorg"));
    memcpy(message->runtime_directory,
           "/tmp/librdp-managed-test",
           sizeof("/tmp/librdp-managed-test"));
    memcpy(message->control_socket,
           "/tmp/librdp-managed-test.sock",
           sizeof("/tmp/librdp-managed-test.sock"));
}

static int test_roundtrip(void)
{
    x11_managed_ipc_message sent;
    x11_managed_ipc_message received;
    int sockets[2] = {-1, -1};

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    test_message_start(&sent);
    x11_managed_ipc_message_init(&received);
    CHECK(x11_managed_ipc_send(sockets[0], &sent, 1000) ==
          LIBRDP_STATUS_OK);
    CHECK(close(sockets[0]) == 0);
    sockets[0] = -1;
    CHECK(x11_managed_ipc_receive(sockets[1], &received, 1000) ==
          LIBRDP_STATUS_OK);
    CHECK(received.type == sent.type);
    CHECK(received.request_id == sent.request_id);
    CHECK(received.width == sent.width &&
          received.height == sent.height);
    CHECK(received.flags == sent.flags);
    CHECK(received.supervisor_pid == sent.supervisor_pid);
    CHECK(received.xserver_pid == sent.xserver_pid);
    CHECK(received.desktop_pid == sent.desktop_pid);
    CHECK(strcmp(received.username, sent.username) == 0);
    CHECK(strcmp(received.domain, sent.domain) == 0);
    CHECK(strcmp(received.password, sent.password) == 0);
    CHECK(strcmp(received.control_socket, sent.control_socket) == 0);
    x11_managed_ipc_message_clear(&sent);
    x11_managed_ipc_message_clear(&received);
    CHECK(close(sockets[1]) == 0);
    return 0;
}

static int test_validation_and_cleansing(void)
{
    x11_managed_ipc_message message;
    size_t index = 0u;

    test_message_start(&message);
    CHECK(x11_managed_ipc_message_validate(&message) ==
          LIBRDP_STATUS_OK);
    message.flags |= X11_MANAGED_IPC_RECONNECT;
    CHECK(x11_managed_ipc_message_validate(&message) ==
          LIBRDP_STATUS_OK);
    message.session_id = 1u;
    CHECK(x11_managed_ipc_message_validate(&message) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    memcpy(message.reconnect_token,
           "0123456789abcdef0123456789abcdef"
           "0123456789abcdef0123456789abcdef",
           X11_MANAGED_IPC_TOKEN_BYTES);
    CHECK(x11_managed_ipc_message_validate(&message) ==
          LIBRDP_STATUS_OK);
    message.width = 0u;
    CHECK(x11_managed_ipc_message_validate(&message) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    message.width = 1280u;
    memset(message.username, 'x', sizeof(message.username));
    CHECK(x11_managed_ipc_message_validate(&message) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    test_message_start(&message);
    x11_managed_ipc_message_clear(&message);
    for (index = 0u; index < sizeof(message); index++)
        CHECK(((const uint8_t*)&message)[index] == 0u);
    return 0;
}

static int test_malformed_and_timeout(void)
{
    static const uint8_t bad_header[24] = {
        0x4cu, 0x52u, 0x4du, 0x53u, 0x02u, 0x00u,
    };
    x11_managed_ipc_message message;
    int sockets[2] = {-1, -1};

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    x11_managed_ipc_message_init(&message);
    CHECK(x11_managed_ipc_receive(sockets[0], &message, 10) ==
          LIBRDP_STATUS_TIMEOUT);
    CHECK(write(sockets[1], bad_header, sizeof(bad_header)) ==
          (ssize_t)sizeof(bad_header));
    CHECK(x11_managed_ipc_receive(sockets[0], &message, 1000) ==
          LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(message.version == X11_MANAGED_IPC_VERSION);
    CHECK(message.password[0] == '\0');
    CHECK(close(sockets[0]) == 0);
    CHECK(close(sockets[1]) == 0);
    return 0;
}

static int test_peer_identity_and_token(void)
{
    x11_managed_ipc_identity identity;
    char first[X11_MANAGED_IPC_TOKEN_BYTES];
    char second[X11_MANAGED_IPC_TOKEN_BYTES];
    int sockets[2] = {-1, -1};

    CHECK(x11_managed_ipc_connected_pair(sockets) ==
          LIBRDP_STATUS_OK);
    CHECK(x11_managed_ipc_peer_identity(sockets[0], &identity) ==
          LIBRDP_STATUS_OK);
    CHECK(identity.uid == geteuid());
    CHECK(identity.gid == getegid());
    CHECK(x11_managed_ipc_generate_token(first) == LIBRDP_STATUS_OK);
    CHECK(x11_managed_ipc_generate_token(second) == LIBRDP_STATUS_OK);
    CHECK(strlen(first) == X11_MANAGED_IPC_TOKEN_BYTES - 1u);
    CHECK(x11_managed_ipc_token_equal(first, first));
    CHECK(!x11_managed_ipc_token_equal(first, second));
    second[0] = '\0';
    CHECK(!x11_managed_ipc_token_equal(first, second));
    CHECK(close(sockets[0]) == 0);
    CHECK(close(sockets[1]) == 0);
    return 0;
}

int main(void)
{
    if (test_roundtrip() != 0)
        return 1;
    if (test_validation_and_cleansing() != 0)
        return 1;
    if (test_malformed_and_timeout() != 0)
        return 1;
    if (test_peer_identity_and_token() != 0)
        return 1;
    return 0;
}
