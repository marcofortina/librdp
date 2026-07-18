/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: broker-owned managed-session registry and resource reservation.
 * Invariants: session IDs, display numbers and reconnect tokens are unique
 * within one registry; every reserved display is protected by an exclusive
 * lock file held until release.
 * Ownership: the registry owns entries, lock descriptors and runtime
 * directories; returned entry pointers remain valid until that entry is
 * released or the registry is freed.
 * Threading: calls are serialized by the broker owner thread.
 * Trust boundary: usernames and request dimensions are validated before they
 * influence filesystem names, limits or process configuration.
 */

#ifndef LIBRDP_X11_SERVER_MANAGED_REGISTRY_H
#define LIBRDP_X11_SERVER_MANAGED_REGISTRY_H

#include "server_managed_ipc.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define X11_MANAGED_REGISTRY_MAX_SESSIONS 128u
#define X11_MANAGED_REGISTRY_MAX_PER_USER 16u
#define X11_MANAGED_REGISTRY_MIN_DISPLAY 20u
#define X11_MANAGED_REGISTRY_MAX_DISPLAY 999u

typedef struct x11_managed_registry_config
{
    uint32_t version;
    size_t size;
    const char* runtime_root;
    uint32_t max_sessions;
    uint32_t max_sessions_per_user;
    uint32_t first_display;
    uint32_t last_display;
    uint64_t idle_timeout_ns;
    uint64_t max_duration_ns;
    int allow_reconnect;
} x11_managed_registry_config;

typedef struct x11_managed_session_entry
{
    uint64_t session_id;
    uint64_t created_ns;
    uint64_t last_activity_ns;
    uint64_t idle_timeout_ns;
    uint64_t max_duration_ns;
    uid_t uid;
    gid_t gid;
    pid_t supervisor_pid;
    pid_t agent_pid;
    pid_t xserver_pid;
    pid_t desktop_pid;
    uint32_t display_number;
    uint32_t width;
    uint32_t height;
    uint32_t port;
    uint32_t attachment_count;
    uint32_t flags;
    x11_managed_session_state state;
    char username[X11_MANAGED_IPC_USERNAME_BYTES];
    char reconnect_token[X11_MANAGED_IPC_TOKEN_BYTES];
    char display_name[X11_MANAGED_IPC_DISPLAY_BYTES];
    char runtime_directory[X11_MANAGED_IPC_PATH_BYTES];
    char authority_path[X11_MANAGED_IPC_PATH_BYTES];
    char agent_socket_path[X11_MANAGED_IPC_PATH_BYTES];
    char drive_mount[X11_MANAGED_IPC_PATH_BYTES];
} x11_managed_session_entry;

typedef struct x11_managed_registry x11_managed_registry;

void x11_managed_registry_config_init(
    x11_managed_registry_config* config);
x11_managed_registry* x11_managed_registry_new(
    const x11_managed_registry_config* config);
void x11_managed_registry_free(x11_managed_registry* registry);
size_t x11_managed_registry_count(
    const x11_managed_registry* registry);
size_t x11_managed_registry_capacity(
    const x11_managed_registry* registry);
const x11_managed_session_entry* x11_managed_registry_entry_at(
    const x11_managed_registry* registry,
    size_t index);
librdp_status x11_managed_registry_reserve(
    x11_managed_registry* registry,
    const x11_managed_ipc_message* request,
    uid_t uid,
    gid_t gid,
    uint64_t now_ns,
    x11_managed_session_entry** entry);
x11_managed_session_entry* x11_managed_registry_find(
    x11_managed_registry* registry,
    uint64_t session_id,
    uid_t uid);
x11_managed_session_entry* x11_managed_registry_find_any(
    x11_managed_registry* registry,
    uint64_t session_id);
x11_managed_session_entry* x11_managed_registry_find_token(
    x11_managed_registry* registry,
    const char* token,
    uid_t uid);
librdp_status x11_managed_registry_adopt(
    x11_managed_registry* registry,
    const x11_managed_ipc_message* state,
    uint64_t now_ns,
    x11_managed_session_entry** entry);
librdp_status x11_managed_registry_mark_starting(
    x11_managed_registry* registry,
    uint64_t session_id,
    pid_t supervisor_pid);
librdp_status x11_managed_registry_mark_active(
    x11_managed_registry* registry,
    uint64_t session_id,
    pid_t agent_pid,
    pid_t xserver_pid,
    pid_t desktop_pid,
    uint32_t port,
    uint64_t now_ns);
librdp_status x11_managed_registry_attach(
    x11_managed_registry* registry,
    uint64_t session_id,
    uint64_t now_ns);
librdp_status x11_managed_registry_detach(
    x11_managed_registry* registry,
    uint64_t session_id,
    uint64_t now_ns);
librdp_status x11_managed_registry_resize(
    x11_managed_registry* registry,
    uint64_t session_id,
    uint32_t width,
    uint32_t height,
    uint64_t now_ns);
int x11_managed_registry_expired(
    const x11_managed_session_entry* entry,
    uint64_t now_ns);
librdp_status x11_managed_registry_release(
    x11_managed_registry* registry,
    uint64_t session_id);

#endif
