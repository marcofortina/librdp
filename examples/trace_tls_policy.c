/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>

#include <librdp/librdp.h>

static librdp_tls_certificate_decision certificate_prompt(const librdp_tls_certificate_info* certificate,
                                                         void* user_data)
{
    (void)user_data;
    if (!certificate)
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;

    printf("host=%s fingerprint=%s subject=%s\n",
           certificate->host,
           certificate->sha256_fingerprint,
           certificate->subject ? certificate->subject : "");
    return LIBRDP_TLS_CERTIFICATE_DECISION_DEFAULT;
}

static void trace_record(librdp_session* session, const librdp_trace_record* record, void* user_data)
{
    (void)session;
    (void)user_data;
    if (record && record->event)
        printf("trace event=%s level=%s\n", record->event, record->level ? record->level : "");
}

int main(void)
{
    librdp_settings* settings = librdp_settings_new();
    librdp_session* session = NULL;
    librdp_tls_policy tls_policy;
    librdp_trace_policy trace_policy;
    librdp_status status;

    if (!settings)
        return 1;

    if (librdp_tls_policy_init(&tls_policy) != LIBRDP_STATUS_OK ||
        librdp_trace_policy_init(&trace_policy) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return 1;
    }

    tls_policy.mode = LIBRDP_TLS_POLICY_TOFU;
    tls_policy.certificate_callback = certificate_prompt;
    status = librdp_settings_set_tls_policy(settings, &tls_policy);
    if (status != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return 1;
    }

    session = librdp_session_new(settings);
    librdp_settings_free(settings);
    if (!session)
        return 1;

    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_CLIENT | LIBRDP_TRACE_CATEGORY_TRANSPORT;
    trace_policy.level = LIBRDP_TRACE_LEVEL_INFO;
    trace_policy.callback = trace_record;

    status = librdp_session_set_trace_policy(session, &trace_policy);
    printf("trace_policy=%s\n", librdp_status_string(status));

    librdp_session_free(session);
    return status == LIBRDP_STATUS_OK ? 0 : 1;
}
