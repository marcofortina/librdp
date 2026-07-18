/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: application-level TLS certificate decision policy.
 * Invariants: strict mode never overrides library verification, and an
 * interactive or automatic exception applies only to the current connection.
 * Ownership: streams and certificate fields remain caller-owned; the context
 * stores no certificate data after a decision.
 * Threading: callbacks execute synchronously on the session-driving thread.
 * Trust boundary: certificate metadata is remote input and is rendered as
 * bounded fields without exposing credentials or protocol payloads.
 */

#ifndef LIBRDP_APP_CLIENT_TLS_H
#define LIBRDP_APP_CLIENT_TLS_H

#include <librdp/librdp.h>

#include <stdio.h>

typedef enum client_tls_decision_mode
{
    CLIENT_TLS_DECISION_STRICT = 0,
    CLIENT_TLS_DECISION_PROMPT = 1,
    CLIENT_TLS_DECISION_ACCEPT_ONCE = 2
} client_tls_decision_mode;

typedef struct client_tls_context
{
    client_tls_decision_mode mode;
    FILE* input;
    FILE* output;
} client_tls_context;

void client_tls_context_init(client_tls_context* context);
librdp_status client_tls_apply(librdp_settings* settings, client_tls_context* context);
librdp_tls_certificate_decision client_tls_certificate_callback(
    const librdp_tls_certificate_info* certificate,
    void* user_data);

#endif
