/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: application-level TLS certificate decision implementation.
 * Invariants: strict mode leaves the default verifier untouched, while prompt
 * and accept-once modes install one session-scoped TOFU callback.
 * Ownership: input and output streams are borrowed for the context lifetime;
 * certificate strings are used only during the synchronous callback.
 * Threading: initialization is caller-local and decisions run on the client
 * session thread without shared global state.
 * Trust boundary: peer certificate metadata is untrusted and never used as a
 * format string or retained beyond the callback.
 */

#include "client_tls.h"

#include <string.h>

void client_tls_context_init(client_tls_context* context)
{
    if (!context)
        return;
    memset(context, 0, sizeof(*context));
    context->mode = CLIENT_TLS_DECISION_STRICT;
    context->input = stdin;
    context->output = stderr;
}

/*
 * Render the failed verification result and apply the local operator's
 * connection-scoped decision. A missing context, stream, or certificate fails
 * closed, and only an explicit leading y/Y accepts an interactive prompt.
 */
librdp_tls_certificate_decision client_tls_certificate_callback(
    const librdp_tls_certificate_info* certificate,
    void* user_data)
{
    client_tls_context* context = (client_tls_context*)user_data;
    FILE* output = NULL;
    char answer[16];

    if (!certificate || !context)
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
    output = context->output;
    if (!output)
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;

    fprintf(output, "tls_certificate host=\"%s\"\n", certificate->host ? certificate->host : "");
    fprintf(output,
            "tls_certificate subject=\"%s\"\n",
            certificate->subject ? certificate->subject : "");
    fprintf(output, "tls_certificate issuer=\"%s\"\n", certificate->issuer ? certificate->issuer : "");
    fprintf(output, "tls_certificate sha256=%s\n", certificate->sha256_fingerprint);
    fprintf(output,
            "tls_certificate verify_status=%s native_verify_result=%ld\n",
            librdp_status_name(certificate->verify_status),
            certificate->native_verify_result);

    if (context->mode == CLIENT_TLS_DECISION_ACCEPT_ONCE)
    {
        fprintf(output, "tls_certificate decision=accepted mode=auto\n");
        return LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT;
    }
    if (context->mode != CLIENT_TLS_DECISION_PROMPT || !context->input)
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;

    fputs("Accept this TLS certificate for this connection? [y/N] ", output);
    fflush(output);
    if (!fgets(answer, sizeof(answer), context->input))
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
    if (answer[0] == 'y' || answer[0] == 'Y')
    {
        fprintf(output, "tls_certificate decision=accepted mode=prompt\n");
        return LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT;
    }
    fprintf(output, "tls_certificate decision=rejected mode=prompt\n");
    return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
}

librdp_status client_tls_apply(librdp_settings* settings, client_tls_context* context)
{
    librdp_tls_policy policy;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!settings || !context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (context->mode == CLIENT_TLS_DECISION_STRICT)
        return LIBRDP_STATUS_OK;
    if (context->mode != CLIENT_TLS_DECISION_PROMPT &&
        context->mode != CLIENT_TLS_DECISION_ACCEPT_ONCE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = librdp_tls_policy_init(&policy);
    if (status != LIBRDP_STATUS_OK)
        return status;
    policy.mode = LIBRDP_TLS_POLICY_TOFU;
    policy.use_system_store = 1;
    policy.certificate_callback = client_tls_certificate_callback;
    policy.certificate_callback_user_data = context;
    return librdp_settings_set_tls_policy(settings, &policy);
}
