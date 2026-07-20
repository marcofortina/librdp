/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef TEST_SERVER_CLIENT_CLIPBOARD_H
#define TEST_SERVER_CLIENT_CLIPBOARD_H

#include "server_platform.h"

#include <stddef.h>
#include <stdint.h>

typedef struct server_client_clipboard_profile
{
    uint32_t format_id;
    const char* format_name;
    const char* mime_type;
    const uint8_t* client_data;
    size_t client_data_len;
    const uint8_t* client_decoded_sha256;
    const uint8_t* server_data;
    size_t server_data_len;
    const uint8_t* server_decoded_sha256;
    const char* sensitive_canary;
} server_client_clipboard_profile;

typedef struct server_client_clipboard_provider
    server_client_clipboard_provider;

const server_client_clipboard_profile*
server_client_clipboard_profile_by_name(const char* name);

int server_client_clipboard_profile_validate_server_data(
    const server_client_clipboard_profile* profile,
    const uint8_t* data,
    size_t data_len);

server_client_clipboard_provider* server_client_clipboard_provider_new(
    const server_client_clipboard_profile* profile);

void server_client_clipboard_provider_free(
    server_client_clipboard_provider* provider);

const server_platform_clipboard_vtable*
server_client_clipboard_provider_vtable(void);

int server_client_clipboard_provider_has_offer(
    const server_client_clipboard_provider* provider);

int server_client_clipboard_provider_complete(
    const server_client_clipboard_provider* provider);

#endif
