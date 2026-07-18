/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: native host authentication contract for managed X11 sessions.
 * Invariants: authentication outcomes are distinct from backend failures and
 * successful identities contain bounded account metadata resolved locally.
 * Ownership: auth sessions own native handles and copied environment strings;
 * callers close them with x11_managed_auth_session_close().
 * Threading: one worker process owns each session; callbacks run synchronously
 * on that worker.
 * Trust boundary: passwords are borrowed only during open, never retained in
 * the returned session and never exposed through diagnostics.
 */

#ifndef LIBRDP_X11_SERVER_MANAGED_AUTH_H
#define LIBRDP_X11_SERVER_MANAGED_AUTH_H

#include <librdp/librdp.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define X11_MANAGED_AUTH_VERSION 1u
#define X11_MANAGED_AUTH_MAX_GROUPS 128u
#define X11_MANAGED_AUTH_MAX_ENVIRONMENT 128u
#define X11_MANAGED_AUTH_NAME_BYTES 256u
#define X11_MANAGED_AUTH_PATH_BYTES 4096u

typedef enum x11_managed_auth_outcome
{
    X11_MANAGED_AUTH_AUTHENTICATED = 1,
    X11_MANAGED_AUTH_DENIED = 2,
    X11_MANAGED_AUTH_ACCOUNT_RESTRICTED = 3,
    X11_MANAGED_AUTH_CANCELLED = 4,
    X11_MANAGED_AUTH_UNAVAILABLE = 5
} x11_managed_auth_outcome;

typedef int (*x11_managed_auth_cancel_callback)(void* user_data);

typedef struct x11_managed_auth_identity
{
    uint32_t version;
    size_t size;
    uid_t uid;
    gid_t gid;
    size_t group_count;
    gid_t groups[X11_MANAGED_AUTH_MAX_GROUPS];
    char username[X11_MANAGED_AUTH_NAME_BYTES];
    char home[X11_MANAGED_AUTH_PATH_BYTES];
    char shell[X11_MANAGED_AUTH_PATH_BYTES];
} x11_managed_auth_identity;

typedef librdp_status (*x11_managed_auth_provider_callback)(
    const char* username,
    const char* password,
    x11_managed_auth_cancel_callback cancelled,
    void* cancel_user_data,
    x11_managed_auth_outcome* outcome,
    x11_managed_auth_identity* identity,
    void* provider_user_data);

typedef struct x11_managed_auth_config
{
    uint32_t version;
    size_t size;
    const char* service_name;
    x11_managed_auth_provider_callback provider;
    void* provider_user_data;
} x11_managed_auth_config;

typedef struct x11_managed_auth_session x11_managed_auth_session;

void x11_managed_auth_config_init(x11_managed_auth_config* config);
void x11_managed_auth_identity_init(x11_managed_auth_identity* identity);
librdp_status x11_managed_auth_session_open(
    const x11_managed_auth_config* config,
    const char* username,
    const char* password,
    x11_managed_auth_cancel_callback cancelled,
    void* cancel_user_data,
    x11_managed_auth_outcome* outcome,
    x11_managed_auth_session** session);
void x11_managed_auth_session_close(x11_managed_auth_session* session);
const x11_managed_auth_identity* x11_managed_auth_session_identity(
    const x11_managed_auth_session* session);
size_t x11_managed_auth_session_environment_count(
    const x11_managed_auth_session* session);
const char* x11_managed_auth_session_environment_at(
    const x11_managed_auth_session* session,
    size_t index);

#endif
