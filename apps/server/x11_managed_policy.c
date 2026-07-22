/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * Module: secure policy evaluation for managed X11 sessions.
 * Invariants: authorization is evaluated after host authentication, provider
 * flags can only be removed by filtering and administrator commands cannot be
 * replaced by a client request.
 * Ownership: all accepted values are copied into bounded policy/message fields.
 * Threading: mutation helpers are startup-only; validation and request
 * preparation are read-only and safe across broker workers.
 * Trust boundary: NSS group membership, local peer credentials and IPC fields
 * are checked before display, process or listener resources are allocated.
 */

#include "x11_managed_policy.h"

#include "x11_managed_auth.h"

#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef LIBRDP_X11_SESSION_SUPERVISOR_PATH
#define LIBRDP_X11_SESSION_SUPERVISOR_PATH \
    "/usr/libexec/librdp/librdp-session-supervisor"
#endif

#ifndef LIBRDP_X11_SESSION_AGENT_PATH
#define LIBRDP_X11_SESSION_AGENT_PATH \
    "/usr/libexec/librdp/librdp-session-agent"
#endif

static int x11_managed_policy_copy(char* output,
                                   size_t capacity,
                                   const char* input)
{
    size_t length = input ? strlen(input) : 0u;

    if (!output || capacity == 0u || !input || length >= capacity)
        return 0;
    memcpy(output, input, length + 1u);
    return 1;
}

static int x11_managed_policy_name_valid(const char* value)
{
    size_t index = 0u;
    size_t length =
        value ? strnlen(value, X11_MANAGED_POLICY_NAME_BYTES) : 0u;

    if (length == 0u ||
        length >= X11_MANAGED_POLICY_NAME_BYTES)
        return 0;
    for (index = 0u; index < length; index++)
    {
        unsigned char character = (unsigned char)value[index];

        if (!(isalnum(character) || character == '_' ||
              character == '-' || character == '.'))
            return 0;
    }
    return 1;
}

static int x11_managed_policy_environment_valid(const char* value)
{
    size_t index = 0u;
    size_t length =
        value ? strnlen(value, X11_MANAGED_POLICY_NAME_BYTES) : 0u;

    if (length == 0u ||
        length >= X11_MANAGED_POLICY_NAME_BYTES ||
        !(isalpha((unsigned char)value[0]) || value[0] == '_'))
        return 0;
    for (index = 1u; index < length; index++)
    {
        if (!(isalnum((unsigned char)value[index]) ||
              value[index] == '_'))
            return 0;
    }
    return 1;
}

void x11_managed_policy_init(x11_managed_policy* policy)
{
    static const char* environment[] = {
        "LANG",
        "LANGUAGE",
        "LC_ADDRESS",
        "LC_ALL",
        "LC_COLLATE",
        "LC_CTYPE",
        "LC_IDENTIFICATION",
        "LC_MEASUREMENT",
        "LC_MESSAGES",
        "LC_MONETARY",
        "LC_NAME",
        "LC_NUMERIC",
        "LC_PAPER",
        "LC_TELEPHONE",
        "LC_TIME",
    };
    size_t index = 0u;

    if (!policy)
        return;
    memset(policy, 0, sizeof(*policy));
    policy->version = X11_MANAGED_POLICY_VERSION;
    policy->size = sizeof(*policy);
    (void)x11_managed_policy_copy(
        policy->socket_path,
        sizeof(policy->socket_path),
        "/run/librdp/session-broker.sock");
    (void)x11_managed_policy_copy(
        policy->runtime_root,
        sizeof(policy->runtime_root),
        "/run/librdp/sessions");
    (void)x11_managed_policy_copy(
        policy->supervisor_path,
        sizeof(policy->supervisor_path),
        LIBRDP_X11_SESSION_SUPERVISOR_PATH);
    (void)x11_managed_policy_copy(
        policy->agent_path,
        sizeof(policy->agent_path),
        LIBRDP_X11_SESSION_AGENT_PATH);
    (void)x11_managed_policy_copy(
        policy->xserver_path,
        sizeof(policy->xserver_path),
        "/usr/bin/Xorg");
    (void)x11_managed_policy_copy(
        policy->bind_address,
        sizeof(policy->bind_address),
        "127.0.0.1");
    (void)x11_managed_policy_copy(
        policy->authentication_service,
        sizeof(policy->authentication_service),
        "librdp");
    policy->security_mode = LIBRDP_SECURITY_NLA;
    policy->max_sessions = 32u;
    policy->max_sessions_per_user = 2u;
    policy->first_display = X11_MANAGED_REGISTRY_MIN_DISPLAY;
    policy->last_display = 199u;
    policy->idle_timeout_ns = X11_MANAGED_DEFAULT_IDLE_TIMEOUT_NS;
    policy->max_duration_ns = X11_MANAGED_DEFAULT_MAX_DURATION_NS;
    policy->socket_mode = 0600;
    policy->allow_capture = 1;
    policy->drive_read_only = 1;
    policy->allow_reconnect = 1;
    policy->persistent_sessions = 1;
    for (index = 0u;
         index < sizeof(environment) / sizeof(environment[0]);
         index++)
        (void)x11_managed_policy_add_environment(
            policy, environment[index]);
}

static int x11_managed_policy_absolute(const char* value,
                                       size_t capacity)
{
    return value && value[0] == '/' &&
           strnlen(value, capacity) < capacity;
}

/*
 * Validate the complete administrative policy before it can authorize a
 * request. Paths, identity lists, permissions, security prerequisites, and
 * resource ranges must form one internally consistent configuration.
 */
int x11_managed_policy_valid(const x11_managed_policy* policy)
{
    size_t index = 0u;

    if (!policy ||
        policy->version != X11_MANAGED_POLICY_VERSION ||
        policy->size < sizeof(*policy) ||
        !x11_managed_policy_absolute(
            policy->socket_path, sizeof(policy->socket_path)) ||
        !x11_managed_policy_absolute(
            policy->runtime_root, sizeof(policy->runtime_root)) ||
        !x11_managed_policy_absolute(
            policy->supervisor_path,
            sizeof(policy->supervisor_path)) ||
        !x11_managed_policy_absolute(
            policy->agent_path, sizeof(policy->agent_path)) ||
        !x11_managed_policy_absolute(
            policy->xserver_path, sizeof(policy->xserver_path)) ||
        !x11_managed_policy_absolute(
            policy->desktop_command,
            sizeof(policy->desktop_command)) ||
        !x11_managed_policy_name_valid(
            policy->authentication_service) ||
        policy->bind_address[0] == '\0' ||
        strnlen(policy->bind_address,
                sizeof(policy->bind_address)) >=
            sizeof(policy->bind_address) ||
        policy->max_sessions == 0u ||
        policy->max_sessions > X11_MANAGED_REGISTRY_MAX_SESSIONS ||
        policy->max_sessions_per_user == 0u ||
        policy->max_sessions_per_user >
            X11_MANAGED_REGISTRY_MAX_PER_USER ||
        policy->max_sessions_per_user > policy->max_sessions ||
        policy->first_display < X11_MANAGED_REGISTRY_MIN_DISPLAY ||
        policy->last_display > X11_MANAGED_REGISTRY_MAX_DISPLAY ||
        policy->first_display > policy->last_display ||
        (policy->socket_mode & 0007u) != 0u ||
        (policy->socket_mode & ~0770u) != 0u ||
        !policy->allow_capture ||
        policy->security_mode < LIBRDP_SECURITY_STANDARD ||
        policy->security_mode > LIBRDP_SECURITY_NLA ||
        (policy->security_mode == LIBRDP_SECURITY_STANDARD &&
         !policy->allow_standard_security) ||
        ((policy->security_mode == LIBRDP_SECURITY_TLS ||
          policy->security_mode == LIBRDP_SECURITY_NLA) &&
         (!x11_managed_policy_absolute(
              policy->tls_certificate,
              sizeof(policy->tls_certificate)) ||
          !x11_managed_policy_absolute(
              policy->tls_private_key,
              sizeof(policy->tls_private_key)))) ||
        policy->allowed_user_count >
            X11_MANAGED_POLICY_MAX_IDENTITIES ||
        policy->allowed_group_count >
            X11_MANAGED_POLICY_MAX_IDENTITIES ||
        policy->environment_count >
            X11_MANAGED_POLICY_MAX_ENVIRONMENT)
        return 0;
    for (index = 0u; index < policy->allowed_user_count; index++)
    {
        if (!x11_managed_policy_name_valid(
                policy->allowed_users[index]))
            return 0;
    }
    for (index = 0u; index < policy->environment_count; index++)
    {
        if (!x11_managed_policy_environment_valid(
                policy->environment[index]))
            return 0;
    }
    return 1;
}

librdp_status x11_managed_policy_add_user(
    x11_managed_policy* policy,
    const char* username)
{
    size_t index = 0u;

    if (!policy || !x11_managed_policy_name_valid(username))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (index = 0u; index < policy->allowed_user_count; index++)
    {
        if (strcmp(policy->allowed_users[index], username) == 0)
            return LIBRDP_STATUS_OK;
    }
    if (policy->allowed_user_count >=
        X11_MANAGED_POLICY_MAX_IDENTITIES)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (!x11_managed_policy_copy(
            policy->allowed_users[policy->allowed_user_count],
            sizeof(policy->allowed_users[0]),
            username))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    policy->allowed_user_count++;
    return LIBRDP_STATUS_OK;
}

librdp_status x11_managed_policy_add_group(
    x11_managed_policy* policy,
    const char* group_name)
{
    struct group group;
    struct group* result = NULL;
    char buffer[16384];
    size_t index = 0u;
    int lookup = 0;

    if (!policy || !x11_managed_policy_name_valid(group_name))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&group, 0, sizeof(group));
    lookup = getgrnam_r(group_name,
                        &group,
                        buffer,
                        sizeof(buffer),
                        &result);
    if (lookup != 0 || !result)
        return LIBRDP_STATUS_STATE;
    for (index = 0u; index < policy->allowed_group_count; index++)
    {
        if (policy->allowed_groups[index] == group.gr_gid)
            return LIBRDP_STATUS_OK;
    }
    if (policy->allowed_group_count >=
        X11_MANAGED_POLICY_MAX_IDENTITIES)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    policy->allowed_groups[policy->allowed_group_count++] =
        group.gr_gid;
    return LIBRDP_STATUS_OK;
}

librdp_status x11_managed_policy_add_environment(
    x11_managed_policy* policy,
    const char* name)
{
    size_t index = 0u;

    if (!policy || !x11_managed_policy_environment_valid(name))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (index = 0u; index < policy->environment_count; index++)
    {
        if (strcmp(policy->environment[index], name) == 0)
            return LIBRDP_STATUS_OK;
    }
    if (policy->environment_count >=
        X11_MANAGED_POLICY_MAX_ENVIRONMENT)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (!x11_managed_policy_copy(
            policy->environment[policy->environment_count],
            sizeof(policy->environment[0]),
            name))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    policy->environment_count++;
    return LIBRDP_STATUS_OK;
}

static int x11_managed_policy_user_allowed(
    const x11_managed_policy* policy,
    const char* username)
{
    size_t index = 0u;

    for (index = 0u; index < policy->allowed_user_count; index++)
    {
        if (strcmp(policy->allowed_users[index], username) == 0)
            return 1;
    }
    return 0;
}

static int x11_managed_policy_group_allowed(
    const x11_managed_policy* policy,
    const x11_managed_ipc_message* authenticated)
{
    gid_t groups[X11_MANAGED_AUTH_MAX_GROUPS];
    int count = (int)X11_MANAGED_AUTH_MAX_GROUPS;
    size_t allowed_index = 0u;
    int group_index = 0;

    if (getgrouplist(authenticated->username,
                     (gid_t)authenticated->gid,
                     groups,
                     &count) < 0 ||
        count < 0 ||
        count > (int)X11_MANAGED_AUTH_MAX_GROUPS)
        return 0;
    for (allowed_index = 0u;
         allowed_index < policy->allowed_group_count;
         allowed_index++)
    {
        for (group_index = 0; group_index < count; group_index++)
        {
            if (groups[group_index] ==
                policy->allowed_groups[allowed_index])
                return 1;
        }
    }
    return 0;
}

int x11_managed_policy_authorize(
    const x11_managed_policy* policy,
    uid_t peer_uid,
    const x11_managed_ipc_message* authenticated)
{
    uid_t target_uid = 0;
    int has_allowlist = 0;

    if (!x11_managed_policy_valid(policy) || !authenticated ||
        authenticated->type != X11_MANAGED_IPC_AUTHENTICATED ||
        authenticated->auth_outcome !=
            X11_MANAGED_AUTH_AUTHENTICATED ||
        (uint32_t)(uid_t)authenticated->uid !=
            authenticated->uid)
        return 0;
    target_uid = (uid_t)authenticated->uid;
    if (!policy->allow_user_switch &&
        peer_uid != 0u && peer_uid != target_uid)
        return 0;
    has_allowlist = policy->allowed_user_count > 0u ||
                    policy->allowed_group_count > 0u;
    if (!has_allowlist)
        return 1;
    return x11_managed_policy_user_allowed(
               policy, authenticated->username) ||
           x11_managed_policy_group_allowed(
               policy, authenticated);
}

static uint64_t x11_managed_policy_limit_duration(
    uint64_t requested,
    uint64_t maximum)
{
    if (requested == 0u || requested > maximum)
        return maximum;
    return requested;
}

librdp_status x11_managed_policy_filter_request(
    const x11_managed_policy* policy,
    const x11_managed_ipc_message* initial,
    const x11_managed_ipc_message* authenticated,
    x11_managed_ipc_message* filtered)
{
    if (!x11_managed_policy_valid(policy) || !initial ||
        !authenticated || !filtered ||
        initial->type != X11_MANAGED_IPC_START ||
        authenticated->type != X11_MANAGED_IPC_AUTHENTICATED ||
        (initial->flags & X11_MANAGED_IPC_ALLOW_CAPTURE) == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    x11_managed_ipc_message_init(filtered);
    filtered->type = X11_MANAGED_IPC_START;
    filtered->request_id = initial->request_id;
    filtered->uid = authenticated->uid;
    filtered->gid = authenticated->gid;
    filtered->width = initial->width;
    filtered->height = initial->height;
    filtered->security_mode = (uint32_t)policy->security_mode;
    filtered->max_peers = 1u;
    filtered->idle_timeout_ns =
        x11_managed_policy_limit_duration(
            initial->idle_timeout_ns,
            policy->idle_timeout_ns);
    filtered->max_duration_ns =
        x11_managed_policy_limit_duration(
            initial->max_duration_ns,
            policy->max_duration_ns);
    filtered->flags = X11_MANAGED_IPC_ALLOW_CAPTURE;
    if (policy->allow_input &&
        (initial->flags & X11_MANAGED_IPC_ALLOW_INPUT) != 0u)
        filtered->flags |= X11_MANAGED_IPC_ALLOW_INPUT;
    if (policy->allow_clipboard &&
        (initial->flags & X11_MANAGED_IPC_ALLOW_CLIPBOARD) != 0u)
        filtered->flags |= X11_MANAGED_IPC_ALLOW_CLIPBOARD;
    if (policy->allow_drive &&
        (initial->flags & X11_MANAGED_IPC_ALLOW_DRIVE) != 0u)
    {
        filtered->flags |= X11_MANAGED_IPC_ALLOW_DRIVE;
        if (policy->drive_read_only ||
            (initial->flags &
             X11_MANAGED_IPC_DRIVE_READ_ONLY) != 0u)
            filtered->flags |= X11_MANAGED_IPC_DRIVE_READ_ONLY;
    }
    if (policy->use_xvfb)
        filtered->flags |= X11_MANAGED_IPC_TEST_XVFB;
    if (policy->persistent_sessions &&
        (initial->flags & X11_MANAGED_IPC_PERSISTENT) != 0u)
        filtered->flags |= X11_MANAGED_IPC_PERSISTENT;
    if (policy->allow_reconnect &&
        (initial->flags & X11_MANAGED_IPC_RECONNECT) != 0u)
        filtered->flags |= X11_MANAGED_IPC_RECONNECT;
    if (!x11_managed_policy_copy(
            filtered->username,
            sizeof(filtered->username),
            authenticated->username) ||
        !x11_managed_policy_copy(
            filtered->domain,
            sizeof(filtered->domain),
            initial->domain))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    return LIBRDP_STATUS_OK;
}

static int x11_managed_policy_environment_string(
    const x11_managed_policy* policy,
    char* output,
    size_t capacity)
{
    size_t offset = 0u;
    size_t index = 0u;

    if (!policy || !output || capacity == 0u)
        return 0;
    output[0] = '\0';
    for (index = 0u; index < policy->environment_count; index++)
    {
        size_t length = strlen(policy->environment[index]);

        if (offset + length + (index != 0u ? 1u : 0u) >= capacity)
            return 0;
        if (index != 0u)
            output[offset++] = ',';
        memcpy(output + offset, policy->environment[index], length);
        offset += length;
        output[offset] = '\0';
    }
    return 1;
}

librdp_status x11_managed_policy_prepare_start(
    const x11_managed_policy* policy,
    const x11_managed_ipc_message* filtered,
    const x11_managed_session_entry* entry,
    x11_managed_ipc_message* request)
{
    if (!x11_managed_policy_valid(policy) || !filtered || !entry ||
        !request || filtered->type != X11_MANAGED_IPC_START ||
        entry->session_id == 0u ||
        entry->uid != (uid_t)filtered->uid ||
        entry->gid != (gid_t)filtered->gid ||
        entry->flags != filtered->flags)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *request = *filtered;
    request->session_id = entry->session_id;
    request->created_ns = entry->created_ns;
    request->idle_timeout_ns = entry->idle_timeout_ns;
    request->max_duration_ns = entry->max_duration_ns;
    request->session_state = X11_MANAGED_SESSION_STARTING;
    if (!x11_managed_policy_copy(
            request->reconnect_token,
            sizeof(request->reconnect_token),
            entry->reconnect_token) ||
        !x11_managed_policy_copy(
            request->display_name,
            sizeof(request->display_name),
            entry->display_name) ||
        !x11_managed_policy_copy(
            request->runtime_directory,
            sizeof(request->runtime_directory),
            entry->runtime_directory) ||
        !x11_managed_policy_copy(
            request->control_socket,
            sizeof(request->control_socket),
            entry->agent_socket_path) ||
        !x11_managed_policy_copy(
            request->bind_address,
            sizeof(request->bind_address),
            policy->bind_address) ||
        !x11_managed_policy_copy(
            request->desktop_command,
            sizeof(request->desktop_command),
            policy->desktop_command) ||
        !x11_managed_policy_copy(
            request->xserver_command,
            sizeof(request->xserver_command),
            policy->xserver_path) ||
        !x11_managed_policy_copy(
            request->tls_certificate,
            sizeof(request->tls_certificate),
            policy->tls_certificate) ||
        !x11_managed_policy_copy(
            request->tls_private_key,
            sizeof(request->tls_private_key),
            policy->tls_private_key) ||
        !x11_managed_policy_environment_string(
            policy,
            request->environment_allowlist,
            sizeof(request->environment_allowlist)))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    if ((request->flags & X11_MANAGED_IPC_ALLOW_DRIVE) != 0u &&
        !x11_managed_policy_copy(
            request->drive_mount,
            sizeof(request->drive_mount),
            entry->drive_mount))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    return LIBRDP_STATUS_OK;
}
