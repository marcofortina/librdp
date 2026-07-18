/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: secure credential transfer into public client settings.
 * Invariants: every initialized transient credential object reaches clear,
 * including setter and allocation failures.
 * Ownership: all strings are borrowed on entry and copied by librdp; provider
 * pointers remain application-owned for every derived session lifetime.
 * Threading: the function is startup-only and requires serialized settings
 * access.
 * Trust boundary: credentials are sensitive local input and never enter trace
 * or diagnostic output through this module.
 */

#include "client_credentials.h"

#include <string.h>

void client_credentials_input_init(client_credentials_input* input)
{
    if (!input)
        return;
    memset(input, 0, sizeof(*input));
}

librdp_status client_credentials_apply(librdp_settings* settings,
                                       const client_credentials_input* input)
{
    librdp_credentials credentials;
    librdp_status status = LIBRDP_STATUS_OK;
    int has_static_values = 0;

    if (!settings || !input)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    has_static_values = input->username || input->password || input->domain;
    if (has_static_values)
    {
        status = librdp_credentials_init(&credentials);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = librdp_credentials_set(&credentials,
                                        input->username,
                                        input->password,
                                        input->domain);
        if (status == LIBRDP_STATUS_OK)
            status = librdp_settings_set_credentials(settings, &credentials);
        librdp_credentials_clear(&credentials);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (input->provider)
    {
        status = librdp_settings_set_credentials_provider(settings,
                                                          input->provider,
                                                          input->provider_user_data);
    }
    return status;
}
