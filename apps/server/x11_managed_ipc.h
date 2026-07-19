/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: versioned local IPC contract for managed X11 sessions.
 * Invariants: every frame is length-prefixed and bounded, identifiers are
 * non-zero, and reconnect tokens are compared in constant time.
 * Ownership: messages are caller-owned values; send and receive retain no
 * pointers or file descriptors.
 * Threading: one reader and one writer may use a connected socket concurrently.
 * Trust boundary: kernel peer credentials and every decoded field are
 * validated before a broker or agent acts on a request.
 */

#ifndef LIBRDP_X11_SERVER_MANAGED_IPC_H
#define LIBRDP_X11_SERVER_MANAGED_IPC_H

#include <librdp/librdp.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define X11_MANAGED_IPC_VERSION 5u
#define X11_MANAGED_IPC_MAX_FRAME_BYTES 32768u
#define X11_MANAGED_IPC_USERNAME_BYTES 256u
#define X11_MANAGED_IPC_DOMAIN_BYTES 256u
#define X11_MANAGED_IPC_PASSWORD_BYTES 1024u
#define X11_MANAGED_IPC_TOKEN_BYTES 65u
#define X11_MANAGED_IPC_DISPLAY_BYTES 64u
#define X11_MANAGED_IPC_ADDRESS_BYTES 256u
#define X11_MANAGED_IPC_PATH_BYTES 4096u
#define X11_MANAGED_IPC_COMMAND_BYTES 4096u
#define X11_MANAGED_IPC_ENVIRONMENT_BYTES 2048u

typedef enum x11_managed_ipc_type
{
    X11_MANAGED_IPC_START = 1,
    X11_MANAGED_IPC_ATTACH = 2,
    X11_MANAGED_IPC_RESIZE = 3,
    X11_MANAGED_IPC_DETACH = 4,
    X11_MANAGED_IPC_TERMINATE = 5,
    X11_MANAGED_IPC_QUERY = 6,
    X11_MANAGED_IPC_READY = 7,
    X11_MANAGED_IPC_ERROR = 8,
    X11_MANAGED_IPC_PING = 9,
    X11_MANAGED_IPC_STOP = 10,
    X11_MANAGED_IPC_AUTHENTICATED = 11
} x11_managed_ipc_type;

typedef enum x11_managed_ipc_flag
{
    X11_MANAGED_IPC_ALLOW_INPUT = 1u << 0,
    X11_MANAGED_IPC_ALLOW_CLIPBOARD = 1u << 1,
    X11_MANAGED_IPC_ALLOW_DRIVE = 1u << 2,
    X11_MANAGED_IPC_DRIVE_READ_ONLY = 1u << 3,
    X11_MANAGED_IPC_TEST_XVFB = 1u << 4,
    X11_MANAGED_IPC_PERSISTENT = 1u << 5,
    X11_MANAGED_IPC_RECONNECT = 1u << 6,
    X11_MANAGED_IPC_ALLOW_CAPTURE = 1u << 7
} x11_managed_ipc_flag;

typedef enum x11_managed_session_state
{
    X11_MANAGED_SESSION_RESERVED = 1,
    X11_MANAGED_SESSION_STARTING = 2,
    X11_MANAGED_SESSION_ACTIVE = 3,
    X11_MANAGED_SESSION_DETACHED = 4,
    X11_MANAGED_SESSION_TERMINATING = 5,
    X11_MANAGED_SESSION_FAILED = 6
} x11_managed_session_state;

typedef struct x11_managed_ipc_identity
{
    uid_t uid;
    gid_t gid;
    pid_t pid;
} x11_managed_ipc_identity;

typedef struct x11_managed_ipc_message
{
    uint32_t version;
    size_t size;
    x11_managed_ipc_type type;
    uint64_t request_id;
    uint64_t session_id;
    uint64_t created_ns;
    uint64_t idle_timeout_ns;
    uint64_t max_duration_ns;
    uint64_t supervisor_pid;
    uint64_t agent_pid;
    uint64_t xserver_pid;
    uint64_t desktop_pid;
    uint32_t flags;
    uint32_t uid;
    uint32_t gid;
    uint32_t width;
    uint32_t height;
    uint32_t port;
    uint32_t security_mode;
    uint32_t max_peers;
    uint32_t auth_outcome;
    uint32_t session_state;
    uint32_t attachment_count;
    librdp_status status;
    char username[X11_MANAGED_IPC_USERNAME_BYTES];
    char domain[X11_MANAGED_IPC_DOMAIN_BYTES];
    char password[X11_MANAGED_IPC_PASSWORD_BYTES];
    char reconnect_token[X11_MANAGED_IPC_TOKEN_BYTES];
    char display_name[X11_MANAGED_IPC_DISPLAY_BYTES];
    char bind_address[X11_MANAGED_IPC_ADDRESS_BYTES];
    char runtime_directory[X11_MANAGED_IPC_PATH_BYTES];
    char control_socket[X11_MANAGED_IPC_PATH_BYTES];
    char environment_allowlist[X11_MANAGED_IPC_ENVIRONMENT_BYTES];
    char desktop_command[X11_MANAGED_IPC_COMMAND_BYTES];
    char xserver_command[X11_MANAGED_IPC_COMMAND_BYTES];
    char tls_certificate[X11_MANAGED_IPC_PATH_BYTES];
    char tls_private_key[X11_MANAGED_IPC_PATH_BYTES];
    char drive_mount[X11_MANAGED_IPC_PATH_BYTES];
} x11_managed_ipc_message;

void x11_managed_ipc_message_init(x11_managed_ipc_message* message);
void x11_managed_ipc_message_clear(x11_managed_ipc_message* message);
librdp_status x11_managed_ipc_message_validate(
    const x11_managed_ipc_message* message);
librdp_status x11_managed_ipc_send(
    int descriptor,
    const x11_managed_ipc_message* message,
    int timeout_ms);
librdp_status x11_managed_ipc_receive(
    int descriptor,
    x11_managed_ipc_message* message,
    int timeout_ms);
/* Create connected endpoints that support kernel peer credential queries. */
librdp_status x11_managed_ipc_connected_pair(int descriptors[2]);
librdp_status x11_managed_ipc_peer_identity(
    int descriptor,
    x11_managed_ipc_identity* identity);
librdp_status x11_managed_ipc_generate_token(
    char token[X11_MANAGED_IPC_TOKEN_BYTES]);
int x11_managed_ipc_token_equal(const char* left, const char* right);

#endif
