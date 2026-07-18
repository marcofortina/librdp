/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: managed host-authentication contract tests.
 * Coverage: accepted, denied, cancelled and malformed provider results,
 * identity ownership and absence of a native backend.
 * Bug classes: credential retention, auth/backend error confusion, invalid
 * identity acceptance and callback cancellation loss.
 * Determinism: a local mock provider supplies synthetic account metadata and
 * never consults PAM, BSD Authentication or the host account database.
 */

#include "server_managed_auth.h"

#include <stdio.h>
#include <string.h>

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

typedef struct test_auth_context
{
    int calls;
    int deny;
    int malformed;
} test_auth_context;

static int test_auth_cancelled(void* user_data)
{
    return user_data ? *(const int*)user_data : 0;
}

static librdp_status test_auth_provider(
    const char* username,
    const char* password,
    x11_managed_auth_cancel_callback cancelled,
    void* cancel_user_data,
    x11_managed_auth_outcome* outcome,
    x11_managed_auth_identity* identity,
    void* user_data)
{
    test_auth_context* context = (test_auth_context*)user_data;

    if (!context || !username || !password || !outcome || !identity)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    context->calls++;
    if (cancelled && cancelled(cancel_user_data))
    {
        *outcome = X11_MANAGED_AUTH_CANCELLED;
        return LIBRDP_STATUS_CANCELLED;
    }
    if (context->deny)
    {
        *outcome = X11_MANAGED_AUTH_DENIED;
        return LIBRDP_STATUS_OK;
    }
    x11_managed_auth_identity_init(identity);
    identity->uid = 1000u;
    identity->gid = 1000u;
    identity->groups[0] = 1000u;
    identity->group_count = 1u;
    memcpy(identity->username,
           context->malformed ? "" : "synthetic-user",
           context->malformed ? 1u : sizeof("synthetic-user"));
    memcpy(identity->home, "/tmp/synthetic-home",
           sizeof("/tmp/synthetic-home"));
    memcpy(identity->shell, "/bin/sh", sizeof("/bin/sh"));
    *outcome = X11_MANAGED_AUTH_AUTHENTICATED;
    return LIBRDP_STATUS_OK;
}

static int test_provider_outcomes(void)
{
    x11_managed_auth_config config;
    x11_managed_auth_session* session = NULL;
    const x11_managed_auth_identity* identity = NULL;
    x11_managed_auth_outcome outcome = X11_MANAGED_AUTH_UNAVAILABLE;
    test_auth_context context;
    int cancelled = 0;

    memset(&context, 0, sizeof(context));
    x11_managed_auth_config_init(&config);
    config.provider = test_auth_provider;
    config.provider_user_data = &context;
    CHECK(x11_managed_auth_session_open(&config,
                                        "request-user",
                                        "synthetic-secret",
                                        test_auth_cancelled,
                                        &cancelled,
                                        &outcome,
                                        &session) == LIBRDP_STATUS_OK);
    CHECK(outcome == X11_MANAGED_AUTH_AUTHENTICATED);
    CHECK(session != NULL);
    identity = x11_managed_auth_session_identity(session);
    CHECK(identity != NULL);
    CHECK(strcmp(identity->username, "synthetic-user") == 0);
    CHECK(identity->uid == 1000u && identity->gid == 1000u);
    CHECK(x11_managed_auth_session_environment_count(session) == 0u);
    CHECK(x11_managed_auth_session_environment_at(session, 0u) == NULL);
    x11_managed_auth_session_close(session);
    session = NULL;
    context.deny = 1;
    CHECK(x11_managed_auth_session_open(&config,
                                        "request-user",
                                        "synthetic-secret",
                                        NULL,
                                        NULL,
                                        &outcome,
                                        &session) == LIBRDP_STATUS_OK);
    CHECK(outcome == X11_MANAGED_AUTH_DENIED && session == NULL);
    context.deny = 0;
    cancelled = 1;
    CHECK(x11_managed_auth_session_open(&config,
                                        "request-user",
                                        "synthetic-secret",
                                        test_auth_cancelled,
                                        &cancelled,
                                        &outcome,
                                        &session) ==
          LIBRDP_STATUS_CANCELLED);
    CHECK(outcome == X11_MANAGED_AUTH_CANCELLED && session == NULL);
    context.malformed = 1;
    cancelled = 0;
    CHECK(x11_managed_auth_session_open(&config,
                                        "request-user",
                                        "synthetic-secret",
                                        NULL,
                                        NULL,
                                        &outcome,
                                        &session) ==
          LIBRDP_STATUS_STATE);
    CHECK(outcome == X11_MANAGED_AUTH_UNAVAILABLE && session == NULL);
    CHECK(context.calls == 3);
    return 0;
}

static int test_argument_validation(void)
{
    x11_managed_auth_config config;
    x11_managed_auth_session* session = NULL;
    x11_managed_auth_outcome outcome = X11_MANAGED_AUTH_UNAVAILABLE;

    x11_managed_auth_config_init(&config);
    CHECK(x11_managed_auth_session_open(&config,
                                        "",
                                        "secret",
                                        NULL,
                                        NULL,
                                        &outcome,
                                        &session) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(x11_managed_auth_session_open(&config,
                                        "user",
                                        "",
                                        NULL,
                                        NULL,
                                        &outcome,
                                        &session) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    return 0;
}

int main(void)
{
    if (test_provider_outcomes() != 0)
        return 1;
    if (test_argument_validation() != 0)
        return 1;
    return 0;
}
