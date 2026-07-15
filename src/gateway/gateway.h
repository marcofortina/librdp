/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal gateway transport provider.
 * Invariants: gateway setup either commits a connected transport or leaves the
 * caller-owned transport closed.
 * Ownership: successful connection transfers the libcurl easy handle to
 * rdp_transport for cleanup.
 * Threading: setup runs on the caller's connection thread.
 * Trust boundary: gateway URLs and credentials originate from application
 * settings and are validated before reaching libcurl.
 */

#ifndef RDP_GATEWAY_GATEWAY_H
#define RDP_GATEWAY_GATEWAY_H

#include <librdp/error.h>
#include <librdp/settings.h>

#include <stdint.h>

typedef struct rdp_transport rdp_transport;

typedef struct rdp_gateway_connect_config
{
    const char* gateway_url;
    const char* target_host;
    uint16_t target_port;
    const char* username;
    const char* password;
    const char* domain;
    uint32_t timeout_ms;
    librdp_gateway_mode mode;
} rdp_gateway_connect_config;

librdp_status rdp_gateway_connect_transport(rdp_transport* transport,
                                            const rdp_gateway_connect_config* config);
librdp_status rdp_gateway_user_name(const char* domain, const char* username, char** out);

#endif
