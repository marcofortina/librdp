/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef TEST_SERVER_CLIENT_CLIPBOARD_H
#define TEST_SERVER_CLIENT_CLIPBOARD_H

#include "server_platform.h"

#include <librdp/event.h>
#include <librdp/session.h>

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
    int file_transfer;
} server_client_clipboard_profile;

typedef struct server_client_clipboard_provider
    server_client_clipboard_provider;

const server_client_clipboard_profile*
server_client_clipboard_profile_by_name(const char* name);

int server_client_clipboard_profile_validate_server_data(
    const server_client_clipboard_profile* profile,
    const uint8_t* data,
    size_t data_len);

int server_client_clipboard_profile_is_file_transfer(
    const server_client_clipboard_profile* profile);

server_client_clipboard_provider* server_client_clipboard_provider_new(
    const server_client_clipboard_profile* profile);

void server_client_clipboard_provider_free(
    server_client_clipboard_provider* provider);

const server_platform_clipboard_vtable*
server_client_clipboard_provider_vtable(void);

int server_client_clipboard_provider_has_offer(
    const server_client_clipboard_provider* provider);

/*
 * Publish the profile's client-owned data through the public session API.
 * File profiles retain their temporary files until provider_free().
 */
librdp_status server_client_clipboard_provider_publish_client(
    server_client_clipboard_provider* provider,
    librdp_session* session);

/*
 * Consume client-side clipboard events for file-transfer profiles. The return
 * value is non-zero only when the event belonged to this provider.
 */
int server_client_clipboard_provider_handle_client_event(
    server_client_clipboard_provider* provider,
    librdp_session* session,
    const librdp_event* event);

int server_client_clipboard_provider_complete(
    const server_client_clipboard_provider* provider);

#endif
