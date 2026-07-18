/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: bounded application-level server clipboard runtime.
 * Invariants: peer and request identifiers are generation-scoped, each request
 * reaches one terminal response, and clipboard content never enters trace.
 * Ownership: the runtime copies retained format metadata and data chunks;
 * protocol and platform contexts remain borrowed until peer removal or free.
 * Threading: all operations run on the serialized server-host thread.
 * Trust boundary: protocol and native clipboard payloads are bounded and
 * correlated before crossing between the platform and public server APIs.
 */

#ifndef LIBRDP_APP_SERVER_CLIPBOARD_H
#define LIBRDP_APP_SERVER_CLIPBOARD_H

#include "server_platform.h"

#include <librdp/librdp.h>

#include <stddef.h>
#include <stdint.h>

#define SERVER_CLIPBOARD_CONFIG_VERSION 1u
#define SERVER_CLIPBOARD_DEFAULT_MAX_FORMATS 32u
#define SERVER_CLIPBOARD_DEFAULT_MAX_PENDING 16u
#define SERVER_CLIPBOARD_DEFAULT_MAX_DATA_BYTES (16u * 1024u * 1024u)
#define SERVER_CLIPBOARD_DEFAULT_MAX_FILE_RANGE_BYTES (1024u * 1024u)

typedef enum server_clipboard_format_class
{
    SERVER_CLIPBOARD_FORMAT_TEXT = 0x01u,
    SERVER_CLIPBOARD_FORMAT_HTML = 0x02u,
    SERVER_CLIPBOARD_FORMAT_PNG = 0x04u,
    SERVER_CLIPBOARD_FORMAT_URI_LIST = 0x08u
} server_clipboard_format_class;

typedef struct server_clipboard_config
{
    uint32_t version;
    size_t size;
    uint32_t max_peers;
    uint32_t max_formats;
    uint32_t max_pending_requests;
    size_t max_data_bytes;
    uint32_t max_file_range_bytes;
    uint32_t allowed_formats;
} server_clipboard_config;

typedef struct server_clipboard_protocol_vtable
{
    librdp_status (*send_monitor_ready)(void* context, uint16_t channel_id);
    librdp_status (*send_capabilities)(void* context,
                                      uint16_t channel_id,
                                      uint32_t flags);
    librdp_status (*send_format_list)(
        void* context,
        uint16_t channel_id,
        const librdp_server_clipboard_format* formats,
        uint32_t format_count,
        int long_names);
    librdp_status (*send_format_list_response)(void* context,
                                              uint16_t channel_id,
                                              int ok);
    librdp_status (*send_format_data_request)(void* context,
                                             uint16_t channel_id,
                                             uint32_t format_id);
    librdp_status (*send_format_data_response)(void* context,
                                              uint16_t channel_id,
                                              int ok,
                                              const void* data,
                                              size_t data_len);
    librdp_status (*send_file_request)(
        void* context,
        uint16_t channel_id,
        uint32_t stream_id,
        int32_t file_index,
        uint32_t flags,
        uint64_t position,
        uint32_t requested_bytes,
        const uint32_t* clip_data_id);
    librdp_status (*send_file_response)(void* context,
                                       uint16_t channel_id,
                                       int ok,
                                       uint32_t stream_id,
                                       const void* data,
                                       size_t data_len);
    librdp_status (*cancel_requests)(void* context);
} server_clipboard_protocol_vtable;

typedef struct server_clipboard_runtime server_clipboard_runtime;

void server_clipboard_config_init(server_clipboard_config* config);
librdp_status server_clipboard_config_validate(
    const server_clipboard_config* config);
server_clipboard_runtime* server_clipboard_runtime_new(
    const server_clipboard_config* config,
    const server_platform_clipboard_vtable* platform,
    void* platform_context);
void server_clipboard_runtime_free(server_clipboard_runtime* runtime);
librdp_status server_clipboard_runtime_add_peer(
    server_clipboard_runtime* runtime,
    uint32_t peer_id,
    uint32_t generation,
    const server_clipboard_protocol_vtable* protocol,
    void* protocol_context);
void server_clipboard_runtime_remove_peer(server_clipboard_runtime* runtime,
                                          uint32_t peer_id,
                                          uint32_t generation);
librdp_status server_clipboard_runtime_channel_ready(
    server_clipboard_runtime* runtime,
    uint32_t peer_id,
    uint32_t generation,
    uint16_t channel_id);
librdp_status server_clipboard_runtime_protocol_event(
    server_clipboard_runtime* runtime,
    uint32_t peer_id,
    uint32_t generation,
    const librdp_server_clipboard_event* event);
librdp_status server_clipboard_runtime_platform_formats(
    server_clipboard_runtime* runtime,
    const server_platform_clipboard_format* formats,
    size_t format_count,
    uint64_t generation);
librdp_status server_clipboard_runtime_platform_data(
    server_clipboard_runtime* runtime,
    const server_platform_clipboard_data* data);
librdp_status server_clipboard_runtime_platform_request(
    server_clipboard_runtime* runtime,
    const server_platform_clipboard_request* request);
librdp_status server_clipboard_runtime_platform_file_request(
    server_clipboard_runtime* runtime,
    const server_platform_clipboard_file_request* request);
void server_clipboard_runtime_revoke(server_clipboard_runtime* runtime);

#endif
