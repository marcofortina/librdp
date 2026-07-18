/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: managed X11 broker policy contract.
 * Invariants: executable and filesystem paths are absolute, Standard Security
 * is disabled by default and requested providers are intersected with policy.
 * Ownership: policy values are fixed-size copies owned by the structure.
 * Threading: policy is immutable after broker startup and may be read by every
 * request worker.
 * Trust boundary: authenticated account data and untrusted client requests are
 * converted into a bounded supervisor request without carrying credentials.
 */

#ifndef LIBRDP_X11_SERVER_MANAGED_POLICY_H
#define LIBRDP_X11_SERVER_MANAGED_POLICY_H

#include "server_managed_registry.h"

#include <librdp/librdp.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define X11_MANAGED_POLICY_VERSION 1u
#define X11_MANAGED_POLICY_MAX_IDENTITIES 64u
#define X11_MANAGED_POLICY_MAX_ENVIRONMENT 64u
#define X11_MANAGED_POLICY_NAME_BYTES 256u

typedef struct x11_managed_policy
{
    uint32_t version;
    size_t size;
    char socket_path[X11_MANAGED_IPC_PATH_BYTES];
    char runtime_root[X11_MANAGED_IPC_PATH_BYTES];
    char supervisor_path[X11_MANAGED_IPC_PATH_BYTES];
    char agent_path[X11_MANAGED_IPC_PATH_BYTES];
    char xserver_path[X11_MANAGED_IPC_PATH_BYTES];
    char authentication_service[X11_MANAGED_POLICY_NAME_BYTES];
    char desktop_command[X11_MANAGED_IPC_COMMAND_BYTES];
    char bind_address[X11_MANAGED_IPC_ADDRESS_BYTES];
    char tls_certificate[X11_MANAGED_IPC_PATH_BYTES];
    char tls_private_key[X11_MANAGED_IPC_PATH_BYTES];
    char allowed_users[X11_MANAGED_POLICY_MAX_IDENTITIES]
                      [X11_MANAGED_POLICY_NAME_BYTES];
    gid_t allowed_groups[X11_MANAGED_POLICY_MAX_IDENTITIES];
    char environment[X11_MANAGED_POLICY_MAX_ENVIRONMENT]
                    [X11_MANAGED_POLICY_NAME_BYTES];
    size_t allowed_user_count;
    size_t allowed_group_count;
    size_t environment_count;
    librdp_security_mode security_mode;
    uint32_t max_sessions;
    uint32_t max_sessions_per_user;
    uint32_t first_display;
    uint32_t last_display;
    uint64_t idle_timeout_ns;
    uint64_t max_duration_ns;
    mode_t socket_mode;
    gid_t socket_group;
    int socket_group_set;
    int allow_user_switch;
    int allow_standard_security;
    int allow_capture;
    int allow_input;
    int allow_clipboard;
    int allow_drive;
    int drive_read_only;
    int allow_reconnect;
    int persistent_sessions;
    int use_xvfb;
} x11_managed_policy;

void x11_managed_policy_init(x11_managed_policy* policy);
int x11_managed_policy_valid(const x11_managed_policy* policy);
librdp_status x11_managed_policy_add_user(
    x11_managed_policy* policy,
    const char* username);
librdp_status x11_managed_policy_add_group(
    x11_managed_policy* policy,
    const char* group_name);
librdp_status x11_managed_policy_add_environment(
    x11_managed_policy* policy,
    const char* name);
int x11_managed_policy_authorize(
    const x11_managed_policy* policy,
    uid_t peer_uid,
    const x11_managed_ipc_message* authenticated);
librdp_status x11_managed_policy_filter_request(
    const x11_managed_policy* policy,
    const x11_managed_ipc_message* initial,
    const x11_managed_ipc_message* authenticated,
    x11_managed_ipc_message* filtered);
librdp_status x11_managed_policy_prepare_start(
    const x11_managed_policy* policy,
    const x11_managed_ipc_message* filtered,
    const x11_managed_session_entry* entry,
    x11_managed_ipc_message* request);

#endif
