/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: application credential handoff.
 * Invariants: transient credential objects are always cleared and a
 * just-in-time provider is installed only through the public settings API.
 * Ownership: input strings and provider state are borrowed; settings copy
 * static values and retain only the provider function and opaque user data.
 * Threading: static setup runs before session creation; providers follow the
 * synchronous connection-thread contract of librdp_credentials_provider.
 * Trust boundary: plaintext credentials are never logged, persisted, or
 * retained by this layer after settings population.
 */

#ifndef LIBRDP_APP_CLIENT_CREDENTIALS_H
#define LIBRDP_APP_CLIENT_CREDENTIALS_H

#include <librdp/librdp.h>

typedef struct client_credentials_input
{
    const char* username;
    const char* password;
    const char* domain;
    librdp_credentials_provider provider;
    void* provider_user_data;
} client_credentials_input;

void client_credentials_input_init(client_credentials_input* input);
librdp_status client_credentials_apply(librdp_settings* settings,
                                       const client_credentials_input* input);

#endif
