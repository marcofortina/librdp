/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: bounded clipboard ownership and request state for desktop servers.
 * Invariants: retained data is capped by policy, one peer generation owns each
 * protocol request, and platform publication generations suppress feedback.
 * Ownership: format names and chunk buffers are runtime-owned; callbacks borrow
 * their arguments only for the duration of each call.
 * Threading: all entry points are confined to the shared host owner thread.
 * Trust boundary: remote formats and payloads are allowlisted before native
 * providers receive them, and local content is never emitted to diagnostics.
 */

#include "server_clipboard.h"

#include <stdlib.h>
#include <string.h>

typedef struct server_clipboard_format_entry
{
    uint32_t format_id;
    uint32_t format_class;
    const char* mime_type;
    uint8_t* wire_name;
    size_t wire_name_len;
} server_clipboard_format_entry;

typedef enum server_clipboard_pending_kind
{
    SERVER_CLIPBOARD_PENDING_NONE = 0,
    SERVER_CLIPBOARD_PENDING_LOCAL_DATA = 1,
    SERVER_CLIPBOARD_PENDING_LOCAL_FILE = 2,
    SERVER_CLIPBOARD_PENDING_REMOTE_DATA = 3,
    SERVER_CLIPBOARD_PENDING_REMOTE_FILE = 4
} server_clipboard_pending_kind;

typedef struct server_clipboard_pending
{
    server_clipboard_pending_kind kind;
    uint64_t request_id;
    uint32_t format_id;
    uint32_t stream_id;
    size_t max_bytes;
    uint8_t* data;
    size_t data_len;
} server_clipboard_pending;

typedef struct server_clipboard_peer
{
    uint32_t peer_id;
    uint32_t generation;
    uint16_t channel_id;
    const server_clipboard_protocol_vtable* protocol;
    void* protocol_context;
    server_clipboard_format_entry* remote_formats;
    size_t remote_format_count;
    uint64_t ownership_generation;
    server_clipboard_pending local_data;
    server_clipboard_pending local_file;
    server_clipboard_pending remote_data;
    server_clipboard_pending remote_file;
    int occupied;
    int channel_ready;
} server_clipboard_peer;

struct server_clipboard_runtime
{
    server_clipboard_config config;
    const server_platform_clipboard_vtable* platform;
    void* platform_context;
    server_clipboard_peer* peers;
    server_clipboard_format_entry* local_formats;
    size_t local_format_count;
    uint64_t local_generation;
    uint64_t published_generation;
    uint64_t next_ownership_generation;
    uint64_t next_request_id;
    uint32_t pending_count;
};

static const char server_clipboard_mime_text[] =
    "text/plain;charset=utf-8";
static const char server_clipboard_mime_html[] = "text/html";
static const char server_clipboard_mime_png[] = "image/png";
static const char server_clipboard_mime_uri_list[] = "text/uri-list";

void server_clipboard_config_init(server_clipboard_config* config)
{
    if (!config)
        return;
    memset(config, 0, sizeof(*config));
    config->version = SERVER_CLIPBOARD_CONFIG_VERSION;
    config->size = sizeof(*config);
    config->max_peers = 4u;
    config->max_formats = SERVER_CLIPBOARD_DEFAULT_MAX_FORMATS;
    config->max_pending_requests = SERVER_CLIPBOARD_DEFAULT_MAX_PENDING;
    config->max_data_bytes = SERVER_CLIPBOARD_DEFAULT_MAX_DATA_BYTES;
    config->max_file_range_bytes =
        SERVER_CLIPBOARD_DEFAULT_MAX_FILE_RANGE_BYTES;
    config->allowed_formats = SERVER_CLIPBOARD_FORMAT_TEXT |
                              SERVER_CLIPBOARD_FORMAT_HTML |
                              SERVER_CLIPBOARD_FORMAT_PNG |
                              SERVER_CLIPBOARD_FORMAT_URI_LIST;
}

librdp_status server_clipboard_config_validate(
    const server_clipboard_config* config)
{
    const uint32_t known_formats = SERVER_CLIPBOARD_FORMAT_TEXT |
                                   SERVER_CLIPBOARD_FORMAT_HTML |
                                   SERVER_CLIPBOARD_FORMAT_PNG |
                                   SERVER_CLIPBOARD_FORMAT_URI_LIST;

    if (!config || config->version != SERVER_CLIPBOARD_CONFIG_VERSION ||
        config->size < sizeof(*config) || config->max_peers == 0u ||
        config->max_formats == 0u || config->max_pending_requests == 0u ||
        config->max_data_bytes == 0u ||
        config->max_file_range_bytes == 0u ||
        (config->allowed_formats & ~known_formats) != 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return LIBRDP_STATUS_OK;
}

static int server_clipboard_protocol_valid(
    const server_clipboard_protocol_vtable* protocol)
{
    return protocol && protocol->send_monitor_ready &&
           protocol->send_capabilities && protocol->send_format_list &&
           protocol->send_format_list_response &&
           protocol->send_format_data_request &&
           protocol->send_format_data_response &&
           protocol->send_file_request && protocol->send_file_response &&
           protocol->cancel_requests;
}

static int server_clipboard_platform_valid(
    const server_platform_clipboard_vtable* platform)
{
    return platform && platform->version == SERVER_PLATFORM_CLIPBOARD_VERSION &&
           platform->size >= sizeof(*platform) && platform->publish_formats &&
           platform->request_data && platform->request_file &&
           platform->write_data && platform->cancel_peer &&
           platform->release_ownership;
}

static void server_clipboard_format_entries_free(
    server_clipboard_format_entry* formats,
    size_t count)
{
    size_t index = 0;

    if (!formats)
        return;
    for (index = 0; index < count; index++)
        free(formats[index].wire_name);
    free(formats);
}

static void server_clipboard_pending_clear(server_clipboard_runtime* runtime,
                                           server_clipboard_pending* pending)
{
    if (!pending || pending->kind == SERVER_CLIPBOARD_PENDING_NONE)
        return;
    free(pending->data);
    memset(pending, 0, sizeof(*pending));
    if (runtime && runtime->pending_count > 0u)
        runtime->pending_count--;
}

static void server_clipboard_peer_clear(server_clipboard_runtime* runtime,
                                        server_clipboard_peer* peer)
{
    if (!peer)
        return;
    server_clipboard_pending_clear(runtime, &peer->local_data);
    server_clipboard_pending_clear(runtime, &peer->local_file);
    server_clipboard_pending_clear(runtime, &peer->remote_data);
    server_clipboard_pending_clear(runtime, &peer->remote_file);
    server_clipboard_format_entries_free(peer->remote_formats,
                                         peer->remote_format_count);
    memset(peer, 0, sizeof(*peer));
}

server_clipboard_runtime* server_clipboard_runtime_new(
    const server_clipboard_config* config,
    const server_platform_clipboard_vtable* platform,
    void* platform_context)
{
    server_clipboard_runtime* runtime = NULL;

    if (server_clipboard_config_validate(config) != LIBRDP_STATUS_OK ||
        !server_clipboard_platform_valid(platform))
        return NULL;
    runtime = (server_clipboard_runtime*)calloc(1u, sizeof(*runtime));
    if (!runtime)
        return NULL;
    runtime->peers = (server_clipboard_peer*)calloc(
        config->max_peers,
        sizeof(*runtime->peers));
    if (!runtime->peers)
    {
        free(runtime);
        return NULL;
    }
    runtime->config = *config;
    runtime->platform = platform;
    runtime->platform_context = platform_context;
    runtime->next_ownership_generation = 1u;
    runtime->next_request_id = 1u;
    return runtime;
}

void server_clipboard_runtime_free(server_clipboard_runtime* runtime)
{
    uint32_t index = 0;

    if (!runtime)
        return;
    for (index = 0; index < runtime->config.max_peers; index++)
    {
        server_clipboard_peer* peer = &runtime->peers[index];

        if (peer->occupied)
        {
            peer->protocol->cancel_requests(peer->protocol_context);
            runtime->platform->cancel_peer(runtime->platform_context,
                                           peer->peer_id,
                                           peer->generation);
        }
        server_clipboard_peer_clear(runtime, peer);
    }
    server_clipboard_format_entries_free(runtime->local_formats,
                                         runtime->local_format_count);
    free(runtime->peers);
    memset(runtime, 0, sizeof(*runtime));
    free(runtime);
}

static server_clipboard_peer* server_clipboard_find_peer(
    server_clipboard_runtime* runtime,
    uint32_t peer_id,
    uint32_t generation)
{
    uint32_t index = 0;

    if (!runtime || peer_id == 0u || generation == 0u)
        return NULL;
    for (index = 0; index < runtime->config.max_peers; index++)
    {
        server_clipboard_peer* peer = &runtime->peers[index];

        if (peer->occupied && peer->peer_id == peer_id &&
            peer->generation == generation)
            return peer;
    }
    return NULL;
}

librdp_status server_clipboard_runtime_add_peer(
    server_clipboard_runtime* runtime,
    uint32_t peer_id,
    uint32_t generation,
    const server_clipboard_protocol_vtable* protocol,
    void* protocol_context)
{
    uint32_t index = 0;

    if (!runtime || peer_id == 0u || generation == 0u ||
        !server_clipboard_protocol_valid(protocol) ||
        server_clipboard_find_peer(runtime, peer_id, generation))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (index = 0; index < runtime->config.max_peers; index++)
    {
        server_clipboard_peer* peer = &runtime->peers[index];

        if (peer->occupied)
            continue;
        peer->peer_id = peer_id;
        peer->generation = generation;
        peer->protocol = protocol;
        peer->protocol_context = protocol_context;
        peer->occupied = 1;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_LIMIT_EXCEEDED;
}

void server_clipboard_runtime_remove_peer(server_clipboard_runtime* runtime,
                                          uint32_t peer_id,
                                          uint32_t generation)
{
    server_clipboard_peer* peer =
        server_clipboard_find_peer(runtime, peer_id, generation);

    if (!peer)
        return;
    peer->protocol->cancel_requests(peer->protocol_context);
    runtime->platform->cancel_peer(runtime->platform_context,
                                   peer->peer_id,
                                   peer->generation);
    if (peer->ownership_generation != 0u &&
        runtime->published_generation == peer->ownership_generation)
    {
        runtime->platform->release_ownership(runtime->platform_context,
                                             peer->ownership_generation);
        runtime->published_generation = 0u;
    }
    server_clipboard_peer_clear(runtime, peer);
}

static uint32_t server_clipboard_format_class_from_mime(const char* mime_type)
{
    if (!mime_type)
        return 0u;
    if (strcmp(mime_type, server_clipboard_mime_text) == 0 ||
        strcmp(mime_type, "text/plain") == 0)
        return SERVER_CLIPBOARD_FORMAT_TEXT;
    if (strcmp(mime_type, server_clipboard_mime_html) == 0)
        return SERVER_CLIPBOARD_FORMAT_HTML;
    if (strcmp(mime_type, server_clipboard_mime_png) == 0)
        return SERVER_CLIPBOARD_FORMAT_PNG;
    if (strcmp(mime_type, server_clipboard_mime_uri_list) == 0)
        return SERVER_CLIPBOARD_FORMAT_URI_LIST;
    return 0u;
}

static const char* server_clipboard_mime_from_class(uint32_t format_class)
{
    switch (format_class)
    {
        case SERVER_CLIPBOARD_FORMAT_TEXT:
            return server_clipboard_mime_text;
        case SERVER_CLIPBOARD_FORMAT_HTML:
            return server_clipboard_mime_html;
        case SERVER_CLIPBOARD_FORMAT_PNG:
            return server_clipboard_mime_png;
        case SERVER_CLIPBOARD_FORMAT_URI_LIST:
            return server_clipboard_mime_uri_list;
        default:
            return NULL;
    }
}

static uint32_t server_clipboard_default_format_id(uint32_t format_class)
{
    switch (format_class)
    {
        case SERVER_CLIPBOARD_FORMAT_TEXT:
            return LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT;
        case SERVER_CLIPBOARD_FORMAT_HTML:
            return LIBRDP_CLIPBOARD_FORMAT_HTML;
        case SERVER_CLIPBOARD_FORMAT_PNG:
            return LIBRDP_CLIPBOARD_FORMAT_PNG;
        case SERVER_CLIPBOARD_FORMAT_URI_LIST:
            return LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW;
        default:
            return 0u;
    }
}

static const char* server_clipboard_wire_name(uint32_t format_class)
{
    switch (format_class)
    {
        case SERVER_CLIPBOARD_FORMAT_HTML:
            return LIBRDP_CLIPBOARD_FORMAT_NAME_HTML;
        case SERVER_CLIPBOARD_FORMAT_PNG:
            return LIBRDP_CLIPBOARD_FORMAT_NAME_PNG;
        case SERVER_CLIPBOARD_FORMAT_URI_LIST:
            return LIBRDP_CLIPBOARD_FORMAT_NAME_FILEGROUPDESCRIPTORW;
        case SERVER_CLIPBOARD_FORMAT_TEXT:
        default:
            return NULL;
    }
}

static librdp_status server_clipboard_copy_wire_name(
    server_clipboard_format_entry* destination,
    const char* ascii_name)
{
    size_t index = 0;
    size_t length = ascii_name ? strlen(ascii_name) : 0u;

    if (!destination)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length == 0u)
        return LIBRDP_STATUS_OK;
    if (length > SIZE_MAX / 2u)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    destination->wire_name = (uint8_t*)calloc(length, 2u);
    if (!destination->wire_name)
        return LIBRDP_STATUS_NO_MEMORY;
    for (index = 0; index < length; index++)
        destination->wire_name[index * 2u] = (uint8_t)ascii_name[index];
    destination->wire_name_len = length * 2u;
    return LIBRDP_STATUS_OK;
}

static int server_clipboard_format_id_exists(
    const server_clipboard_format_entry* formats,
    size_t count,
    uint32_t format_id)
{
    size_t index = 0;

    for (index = 0; index < count; index++)
    {
        if (formats[index].format_id == format_id)
            return 1;
    }
    return 0;
}

static librdp_status server_clipboard_build_local_formats(
    server_clipboard_runtime* runtime,
    const server_platform_clipboard_format* formats,
    size_t format_count,
    server_clipboard_format_entry** output,
    size_t* output_count)
{
    server_clipboard_format_entry* copied = NULL;
    size_t copied_count = 0;
    size_t index = 0;

    if (!runtime || !output || !output_count ||
        (format_count > 0u && !formats) ||
        format_count > runtime->config.max_formats)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (format_count > 0u)
    {
        copied = (server_clipboard_format_entry*)calloc(format_count,
                                                        sizeof(*copied));
        if (!copied)
            return LIBRDP_STATUS_NO_MEMORY;
    }
    for (index = 0; index < format_count; index++)
    {
        uint32_t format_class =
            server_clipboard_format_class_from_mime(formats[index].mime_type);
        uint32_t format_id = formats[index].id;
        librdp_status status = LIBRDP_STATUS_OK;

        if (format_class == 0u ||
            (runtime->config.allowed_formats & format_class) == 0u)
            continue;
        if (format_id == 0u)
            format_id = server_clipboard_default_format_id(format_class);
        if (format_id == 0u ||
            server_clipboard_format_id_exists(copied,
                                              copied_count,
                                              format_id))
        {
            server_clipboard_format_entries_free(copied, copied_count);
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        }
        copied[copied_count].format_id = format_id;
        copied[copied_count].format_class = format_class;
        copied[copied_count].mime_type =
            server_clipboard_mime_from_class(format_class);
        status = server_clipboard_copy_wire_name(
            &copied[copied_count],
            server_clipboard_wire_name(format_class));
        if (status != LIBRDP_STATUS_OK)
        {
            server_clipboard_format_entries_free(copied, copied_count + 1u);
            return status;
        }
        copied_count++;
    }
    *output = copied;
    *output_count = copied_count;
    return LIBRDP_STATUS_OK;
}

static librdp_status server_clipboard_send_local_formats(
    const server_clipboard_runtime* runtime,
    server_clipboard_peer* peer)
{
    librdp_server_clipboard_format* formats = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t index = 0;

    if (!runtime || !peer || !peer->channel_ready)
        return LIBRDP_STATUS_STATE;
    if (runtime->local_format_count > 0u)
    {
        formats = (librdp_server_clipboard_format*)calloc(
            runtime->local_format_count,
            sizeof(*formats));
        if (!formats)
            return LIBRDP_STATUS_NO_MEMORY;
    }
    for (index = 0; index < runtime->local_format_count; index++)
    {
        formats[index].format_id = runtime->local_formats[index].format_id;
        formats[index].name = runtime->local_formats[index].wire_name;
        formats[index].name_len = runtime->local_formats[index].wire_name_len;
    }
    status = peer->protocol->send_format_list(
        peer->protocol_context,
        peer->channel_id,
        formats,
        (uint32_t)runtime->local_format_count,
        1);
    free(formats);
    return status;
}

static void server_clipboard_cancel_remote_pending(
    server_clipboard_runtime* runtime,
    server_clipboard_peer* peer)
{
    server_platform_clipboard_data data;
    int had_pending = 0;

    if (!runtime || !peer)
        return;
    memset(&data, 0, sizeof(data));
    data.peer_id = peer->peer_id;
    data.generation = peer->generation;
    data.ownership_generation = peer->ownership_generation;
    data.status = LIBRDP_STATUS_CANCELLED;
    data.final_chunk = 1;
    if (peer->remote_data.kind == SERVER_CLIPBOARD_PENDING_REMOTE_DATA)
    {
        data.request_id = peer->remote_data.request_id;
        data.format_id = peer->remote_data.format_id;
        (void)runtime->platform->write_data(runtime->platform_context, &data);
        had_pending = 1;
    }
    if (peer->remote_file.kind == SERVER_CLIPBOARD_PENDING_REMOTE_FILE)
    {
        data.request_id = peer->remote_file.request_id;
        data.format_id = 0u;
        data.stream_id = peer->remote_file.stream_id;
        (void)runtime->platform->write_data(runtime->platform_context, &data);
        had_pending = 1;
    }
    if (had_pending)
        (void)peer->protocol->cancel_requests(peer->protocol_context);
    server_clipboard_pending_clear(runtime, &peer->remote_data);
    server_clipboard_pending_clear(runtime, &peer->remote_file);
}

static void server_clipboard_cancel_local_pending(
    server_clipboard_runtime* runtime,
    server_clipboard_peer* peer)
{
    if (!runtime || !peer)
        return;
    if (peer->local_data.kind == SERVER_CLIPBOARD_PENDING_LOCAL_DATA)
    {
        (void)peer->protocol->send_format_data_response(
            peer->protocol_context,
            peer->channel_id,
            0,
            NULL,
            0u);
    }
    if (peer->local_file.kind == SERVER_CLIPBOARD_PENDING_LOCAL_FILE)
    {
        (void)peer->protocol->send_file_response(
            peer->protocol_context,
            peer->channel_id,
            0,
            peer->local_file.stream_id,
            NULL,
            0u);
    }
    server_clipboard_pending_clear(runtime, &peer->local_data);
    server_clipboard_pending_clear(runtime, &peer->local_file);
}

librdp_status server_clipboard_runtime_channel_ready(
    server_clipboard_runtime* runtime,
    uint32_t peer_id,
    uint32_t generation,
    uint16_t channel_id)
{
    server_clipboard_peer* peer =
        server_clipboard_find_peer(runtime, peer_id, generation);
    uint32_t flags = LIBRDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || channel_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((runtime->config.allowed_formats &
         SERVER_CLIPBOARD_FORMAT_URI_LIST) != 0u)
    {
        flags |= LIBRDP_CLIPBOARD_CAP_STREAM_FILECLIP_ENABLED |
                 LIBRDP_CLIPBOARD_CAP_FILECLIP_NO_FILE_PATHS |
                 LIBRDP_CLIPBOARD_CAP_CAN_LOCK_CLIPDATA |
                 LIBRDP_CLIPBOARD_CAP_HUGE_FILE_SUPPORT;
    }
    status = peer->protocol->send_monitor_ready(peer->protocol_context,
                                               channel_id);
    if (status == LIBRDP_STATUS_OK)
    {
        status = peer->protocol->send_capabilities(peer->protocol_context,
                                                  channel_id,
                                                  flags);
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    peer->channel_id = channel_id;
    peer->channel_ready = 1;
    return server_clipboard_send_local_formats(runtime, peer);
}

librdp_status server_clipboard_runtime_platform_formats(
    server_clipboard_runtime* runtime,
    const server_platform_clipboard_format* formats,
    size_t format_count,
    uint64_t generation)
{
    server_clipboard_format_entry* copied = NULL;
    size_t copied_count = 0;
    uint32_t index = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!runtime || (format_count > 0u && !formats))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (generation != 0u && generation == runtime->published_generation)
        return LIBRDP_STATUS_OK;
    status = server_clipboard_build_local_formats(runtime,
                                                  formats,
                                                  format_count,
                                                  &copied,
                                                  &copied_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (index = 0; index < runtime->config.max_peers; index++)
    {
        server_clipboard_peer* peer = &runtime->peers[index];

        if (!peer->occupied)
            continue;
        server_clipboard_cancel_local_pending(runtime, peer);
        server_clipboard_cancel_remote_pending(runtime, peer);
        peer->ownership_generation = 0u;
    }
    runtime->published_generation = 0u;
    server_clipboard_format_entries_free(runtime->local_formats,
                                         runtime->local_format_count);
    runtime->local_formats = copied;
    runtime->local_format_count = copied_count;
    runtime->local_generation = generation;
    for (index = 0; index < runtime->config.max_peers; index++)
    {
        server_clipboard_peer* peer = &runtime->peers[index];

        if (!peer->occupied || !peer->channel_ready)
            continue;
        status = server_clipboard_send_local_formats(runtime, peer);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static int server_clipboard_name_equals_ascii(const void* name,
                                              size_t name_len,
                                              int long_names,
                                              const char* expected)
{
    const uint8_t* bytes = (const uint8_t*)name;
    size_t expected_len = expected ? strlen(expected) : 0u;
    size_t index = 0;

    if (!name || !expected)
        return 0;
    if (!long_names)
        return name_len == expected_len &&
               memcmp(name, expected, expected_len) == 0;
    if (name_len != expected_len * 2u)
        return 0;
    for (index = 0; index < expected_len; index++)
    {
        if (bytes[index * 2u] != (uint8_t)expected[index] ||
            bytes[index * 2u + 1u] != 0u)
            return 0;
    }
    return 1;
}

static uint32_t server_clipboard_remote_format_class(
    const librdp_server_clipboard_format* format,
    int long_names)
{
    if (!format)
        return 0u;
    if (format->format_id == LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT)
        return SERVER_CLIPBOARD_FORMAT_TEXT;
    if (format->format_id == LIBRDP_CLIPBOARD_FORMAT_HTML ||
        server_clipboard_name_equals_ascii(
            format->name,
            format->name_len,
            long_names,
            LIBRDP_CLIPBOARD_FORMAT_NAME_HTML))
        return SERVER_CLIPBOARD_FORMAT_HTML;
    if (format->format_id == LIBRDP_CLIPBOARD_FORMAT_PNG ||
        server_clipboard_name_equals_ascii(
            format->name,
            format->name_len,
            long_names,
            LIBRDP_CLIPBOARD_FORMAT_NAME_PNG))
        return SERVER_CLIPBOARD_FORMAT_PNG;
    if (format->format_id == LIBRDP_CLIPBOARD_FORMAT_HDROP ||
        format->format_id == LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW ||
        server_clipboard_name_equals_ascii(
            format->name,
            format->name_len,
            long_names,
            LIBRDP_CLIPBOARD_FORMAT_NAME_FILEGROUPDESCRIPTORW))
        return SERVER_CLIPBOARD_FORMAT_URI_LIST;
    return 0u;
}

/*
 * Replace the single platform-visible remote ownership generation only after
 * the native provider accepts the filtered format set. Duplicate identifiers
 * fail closed, and prior peer ownership and pending reads are invalidated
 * atomically so stale responses cannot cross peer or reconnect boundaries.
 */
static librdp_status server_clipboard_publish_remote_formats(
    server_clipboard_runtime* runtime,
    server_clipboard_peer* peer,
    const librdp_server_clipboard_event* event)
{
    server_clipboard_format_entry* copied = NULL;
    server_platform_clipboard_format* published = NULL;
    server_platform_clipboard_offer offer;
    size_t copied_count = 0;
    size_t index = 0;
    uint32_t peer_index = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (event->format_count > runtime->config.max_formats ||
        (event->format_count > 0u && !event->formats))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (event->format_count > 0u)
    {
        copied = (server_clipboard_format_entry*)calloc(
            event->format_count,
            sizeof(*copied));
        published = (server_platform_clipboard_format*)calloc(
            event->format_count,
            sizeof(*published));
        if (!copied || !published)
        {
            free(copied);
            free(published);
            return LIBRDP_STATUS_NO_MEMORY;
        }
    }
    for (index = 0; index < event->format_count; index++)
    {
        uint32_t format_class = server_clipboard_remote_format_class(
            &event->formats[index],
            event->long_format_names);

        if (format_class == 0u ||
            (runtime->config.allowed_formats & format_class) == 0u)
            continue;
        if (server_clipboard_format_id_exists(
                copied,
                copied_count,
                event->formats[index].format_id))
        {
            server_clipboard_format_entries_free(copied, copied_count);
            free(published);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        copied[copied_count].format_id = event->formats[index].format_id;
        copied[copied_count].format_class = format_class;
        copied[copied_count].mime_type =
            server_clipboard_mime_from_class(format_class);
        published[copied_count].id = copied[copied_count].format_id;
        published[copied_count].mime_type = copied[copied_count].mime_type;
        copied_count++;
    }
    runtime->next_ownership_generation++;
    if (runtime->next_ownership_generation == 0u)
        runtime->next_ownership_generation = 1u;
    memset(&offer, 0, sizeof(offer));
    offer.peer_id = peer->peer_id;
    offer.generation = peer->generation;
    offer.ownership_generation = runtime->next_ownership_generation;
    offer.formats = published;
    offer.format_count = copied_count;
    status = runtime->platform->publish_formats(runtime->platform_context,
                                                &offer);
    free(published);
    if (status != LIBRDP_STATUS_OK)
    {
        server_clipboard_format_entries_free(copied, copied_count);
        return status;
    }
    for (peer_index = 0;
         peer_index < runtime->config.max_peers;
         peer_index++)
    {
        server_clipboard_peer* previous = &runtime->peers[peer_index];

        if (!previous->occupied)
            continue;
        server_clipboard_cancel_remote_pending(runtime, previous);
        server_clipboard_format_entries_free(previous->remote_formats,
                                             previous->remote_format_count);
        previous->remote_formats = NULL;
        previous->remote_format_count = 0u;
        previous->ownership_generation = 0u;
    }
    peer->remote_formats = copied;
    peer->remote_format_count = copied_count;
    peer->ownership_generation = runtime->next_ownership_generation;
    runtime->published_generation = peer->ownership_generation;
    return LIBRDP_STATUS_OK;
}

static server_clipboard_format_entry* server_clipboard_find_format(
    server_clipboard_format_entry* formats,
    size_t count,
    uint32_t format_id)
{
    size_t index = 0;

    for (index = 0; index < count; index++)
    {
        if (formats[index].format_id == format_id)
            return &formats[index];
    }
    return NULL;
}

static int server_clipboard_has_format_class(
    const server_clipboard_format_entry* formats,
    size_t count,
    uint32_t format_class)
{
    size_t index = 0;

    for (index = 0; index < count; index++)
    {
        if (formats[index].format_class == format_class)
            return 1;
    }
    return 0;
}

static uint64_t server_clipboard_next_request_id(
    server_clipboard_runtime* runtime)
{
    uint64_t request_id = runtime->next_request_id++;

    if (request_id == 0u)
        request_id = runtime->next_request_id++;
    return request_id;
}

static librdp_status server_clipboard_pending_begin(
    server_clipboard_runtime* runtime,
    server_clipboard_pending* pending,
    server_clipboard_pending_kind kind,
    uint64_t request_id,
    uint32_t format_id,
    uint32_t stream_id,
    size_t max_bytes)
{
    if (!runtime || !pending || pending->kind != SERVER_CLIPBOARD_PENDING_NONE)
        return LIBRDP_STATUS_STATE;
    if (runtime->pending_count >= runtime->config.max_pending_requests)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    pending->kind = kind;
    pending->request_id = request_id;
    pending->format_id = format_id;
    pending->stream_id = stream_id;
    pending->max_bytes = max_bytes;
    runtime->pending_count++;
    return LIBRDP_STATUS_OK;
}

static librdp_status server_clipboard_request_local_data(
    server_clipboard_runtime* runtime,
    server_clipboard_peer* peer,
    const librdp_server_clipboard_event* event)
{
    uint64_t request_id = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!server_clipboard_find_format(runtime->local_formats,
                                      runtime->local_format_count,
                                      event->format_id))
    {
        return peer->protocol->send_format_data_response(
            peer->protocol_context,
            peer->channel_id,
            0,
            NULL,
            0u);
    }
    request_id = server_clipboard_next_request_id(runtime);
    status = server_clipboard_pending_begin(runtime,
                                            &peer->local_data,
                                            SERVER_CLIPBOARD_PENDING_LOCAL_DATA,
                                            request_id,
                                            event->format_id,
                                            0u,
                                            runtime->config.max_data_bytes);
    if (status == LIBRDP_STATUS_OK)
    {
        status = runtime->platform->request_data(runtime->platform_context,
                                                 request_id,
                                                 event->format_id);
    }
    if (status != LIBRDP_STATUS_OK)
    {
        server_clipboard_pending_clear(runtime, &peer->local_data);
        (void)peer->protocol->send_format_data_response(
            peer->protocol_context,
            peer->channel_id,
            0,
            NULL,
            0u);
    }
    return status;
}

static librdp_status server_clipboard_request_local_file(
    server_clipboard_runtime* runtime,
    server_clipboard_peer* peer,
    const librdp_server_clipboard_event* event)
{
    server_platform_clipboard_file_request request;
    uint64_t request_id = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if ((event->file_flags &
         ~(LIBRDP_CLIPBOARD_FILECONTENTS_SIZE |
           LIBRDP_CLIPBOARD_FILECONTENTS_RANGE)) != 0u ||
        (event->file_flags &
         (LIBRDP_CLIPBOARD_FILECONTENTS_SIZE |
          LIBRDP_CLIPBOARD_FILECONTENTS_RANGE)) == 0u ||
        event->requested_bytes > runtime->config.max_file_range_bytes ||
        !server_clipboard_has_format_class(
            runtime->local_formats,
            runtime->local_format_count,
            SERVER_CLIPBOARD_FORMAT_URI_LIST))
    {
        return peer->protocol->send_file_response(peer->protocol_context,
                                                 peer->channel_id,
                                                 0,
                                                 event->stream_id,
                                                 NULL,
                                                 0u);
    }
    request_id = server_clipboard_next_request_id(runtime);
    status = server_clipboard_pending_begin(runtime,
                                            &peer->local_file,
                                            SERVER_CLIPBOARD_PENDING_LOCAL_FILE,
                                            request_id,
                                            0u,
                                            event->stream_id,
                                            event->requested_bytes > 0u
                                                ? event->requested_bytes
                                                : runtime->config
                                                      .max_file_range_bytes);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(&request, 0, sizeof(request));
    request.peer_id = peer->peer_id;
    request.generation = peer->generation;
    request.ownership_generation = runtime->local_generation;
    request.request_id = request_id;
    request.stream_id = event->stream_id;
    request.file_index = event->file_index;
    request.flags = event->file_flags;
    request.position = event->position;
    request.requested_bytes = event->requested_bytes;
    request.has_clip_data_id = event->has_clip_data_id;
    request.clip_data_id = event->clip_data_id;
    status = runtime->platform->request_file(runtime->platform_context,
                                             &request);
    if (status != LIBRDP_STATUS_OK)
    {
        server_clipboard_pending_clear(runtime, &peer->local_file);
        (void)peer->protocol->send_file_response(peer->protocol_context,
                                                 peer->channel_id,
                                                 0,
                                                 event->stream_id,
                                                 NULL,
                                                 0u);
    }
    return status;
}

static librdp_status server_clipboard_deliver_remote_data(
    server_clipboard_runtime* runtime,
    server_clipboard_peer* peer,
    server_clipboard_pending* pending,
    const librdp_server_clipboard_event* event)
{
    server_platform_clipboard_data data;
    librdp_status status = LIBRDP_STATUS_OK;

    if (event->data_len > pending->max_bytes)
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    memset(&data, 0, sizeof(data));
    data.peer_id = peer->peer_id;
    data.generation = peer->generation;
    data.ownership_generation = peer->ownership_generation;
    data.request_id = pending->request_id;
    data.format_id = pending->format_id;
    data.stream_id = event->stream_id;
    data.status = status == LIBRDP_STATUS_OK && event->success
                      ? LIBRDP_STATUS_OK
                      : LIBRDP_STATUS_PROTOCOL_ERROR;
    data.data = data.status == LIBRDP_STATUS_OK ? event->data : NULL;
    data.data_len = data.status == LIBRDP_STATUS_OK ? event->data_len : 0u;
    data.final_chunk = 1;
    if (status == LIBRDP_STATUS_OK)
        status = runtime->platform->write_data(runtime->platform_context,
                                               &data);
    server_clipboard_pending_clear(runtime, pending);
    return status;
}

/*
 * Apply one validated client clipboard event transactionally. State is
 * committed only after the platform or wire operation succeeds; failed
 * requests receive an explicit negative response and release correlation.
 */
librdp_status server_clipboard_runtime_protocol_event(
    server_clipboard_runtime* runtime,
    uint32_t peer_id,
    uint32_t generation,
    const librdp_server_clipboard_event* event)
{
    server_clipboard_peer* peer =
        server_clipboard_find_peer(runtime, peer_id, generation);
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !event ||
        event->version != LIBRDP_SERVER_CLIPBOARD_EVENT_VERSION ||
        event->size < sizeof(*event) || !peer->channel_ready ||
        (event->type != LIBRDP_SERVER_CLIPBOARD_CANCELLED &&
         event->channel_id != peer->channel_id))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (event->type)
    {
        case LIBRDP_SERVER_CLIPBOARD_MONITOR_READY:
        case LIBRDP_SERVER_CLIPBOARD_CAPABILITIES:
            return LIBRDP_STATUS_OK;
        case LIBRDP_SERVER_CLIPBOARD_FORMAT_LIST:
            status = server_clipboard_publish_remote_formats(runtime,
                                                             peer,
                                                             event);
            if (peer->protocol->send_format_list_response(
                    peer->protocol_context,
                    peer->channel_id,
                    status == LIBRDP_STATUS_OK) != LIBRDP_STATUS_OK &&
                status == LIBRDP_STATUS_OK)
                status = LIBRDP_STATUS_IO_ERROR;
            return status;
        case LIBRDP_SERVER_CLIPBOARD_FORMAT_LIST_RESPONSE:
            return event->success ? LIBRDP_STATUS_OK
                                  : LIBRDP_STATUS_PROTOCOL_ERROR;
        case LIBRDP_SERVER_CLIPBOARD_FORMAT_DATA_REQUEST:
            return server_clipboard_request_local_data(runtime, peer, event);
        case LIBRDP_SERVER_CLIPBOARD_FORMAT_DATA_RESPONSE:
            if (peer->remote_data.kind !=
                SERVER_CLIPBOARD_PENDING_REMOTE_DATA)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            return server_clipboard_deliver_remote_data(runtime,
                                                        peer,
                                                        &peer->remote_data,
                                                        event);
        case LIBRDP_SERVER_CLIPBOARD_FILE_CONTENTS_REQUEST:
            return server_clipboard_request_local_file(runtime, peer, event);
        case LIBRDP_SERVER_CLIPBOARD_FILE_CONTENTS_RESPONSE:
            if (peer->remote_file.kind !=
                    SERVER_CLIPBOARD_PENDING_REMOTE_FILE ||
                peer->remote_file.stream_id != event->stream_id)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            return server_clipboard_deliver_remote_data(runtime,
                                                        peer,
                                                        &peer->remote_file,
                                                        event);
        case LIBRDP_SERVER_CLIPBOARD_LOCK:
        case LIBRDP_SERVER_CLIPBOARD_UNLOCK:
            return LIBRDP_STATUS_OK;
        case LIBRDP_SERVER_CLIPBOARD_CANCELLED:
            if (event->related_type ==
                LIBRDP_SERVER_CLIPBOARD_FORMAT_DATA_RESPONSE)
                server_clipboard_pending_clear(runtime, &peer->remote_data);
            else if (event->related_type ==
                     LIBRDP_SERVER_CLIPBOARD_FILE_CONTENTS_RESPONSE)
                server_clipboard_pending_clear(runtime, &peer->remote_file);
            return LIBRDP_STATUS_CANCELLED;
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

static librdp_status server_clipboard_pending_append(
    server_clipboard_runtime* runtime,
    server_clipboard_pending* pending,
    const uint8_t* data,
    size_t data_len)
{
    uint8_t* resized = NULL;

    if (!runtime || !pending || (!data && data_len > 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (pending->data_len > pending->max_bytes ||
        data_len > pending->max_bytes - pending->data_len)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (data_len == 0u)
        return LIBRDP_STATUS_OK;
    resized = (uint8_t*)realloc(pending->data,
                                pending->data_len + data_len);
    if (!resized)
        return LIBRDP_STATUS_NO_MEMORY;
    memcpy(resized + pending->data_len, data, data_len);
    pending->data = resized;
    pending->data_len += data_len;
    return LIBRDP_STATUS_OK;
}

/*
 * Accumulate bounded platform chunks for one client-originated request. The
 * protocol sees exactly one terminal response, including empty data and
 * provider failures, regardless of the native provider's chunk boundaries.
 */
librdp_status server_clipboard_runtime_platform_data(
    server_clipboard_runtime* runtime,
    const server_platform_clipboard_data* data)
{
    server_clipboard_peer* peer = NULL;
    server_clipboard_pending* pending = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!runtime || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer = server_clipboard_find_peer(runtime,
                                      data->peer_id,
                                      data->generation);
    if (!peer)
        return LIBRDP_STATUS_STATE;
    if (peer->local_data.request_id == data->request_id &&
        peer->local_data.kind == SERVER_CLIPBOARD_PENDING_LOCAL_DATA)
        pending = &peer->local_data;
    else if (peer->local_file.request_id == data->request_id &&
             peer->local_file.kind == SERVER_CLIPBOARD_PENDING_LOCAL_FILE)
        pending = &peer->local_file;
    if (!pending || pending->format_id != data->format_id ||
        (pending->kind == SERVER_CLIPBOARD_PENDING_LOCAL_FILE &&
         pending->stream_id != data->stream_id) ||
        (data->ownership_generation != 0u &&
         data->ownership_generation != runtime->local_generation))
        return LIBRDP_STATUS_STATE;
    if (data->status == LIBRDP_STATUS_OK)
        status = server_clipboard_pending_append(runtime,
                                                 pending,
                                                 data->data,
                                                 data->data_len);
    else
        status = data->status;
    if (status != LIBRDP_STATUS_OK || data->final_chunk)
    {
        librdp_status send_status = LIBRDP_STATUS_OK;

        if (pending->kind == SERVER_CLIPBOARD_PENDING_LOCAL_DATA)
        {
            send_status = peer->protocol->send_format_data_response(
                peer->protocol_context,
                peer->channel_id,
                status == LIBRDP_STATUS_OK,
                status == LIBRDP_STATUS_OK ? pending->data : NULL,
                status == LIBRDP_STATUS_OK ? pending->data_len : 0u);
        }
        else
        {
            send_status = peer->protocol->send_file_response(
                peer->protocol_context,
                peer->channel_id,
                status == LIBRDP_STATUS_OK,
                pending->stream_id,
                status == LIBRDP_STATUS_OK ? pending->data : NULL,
                status == LIBRDP_STATUS_OK ? pending->data_len : 0u);
        }
        server_clipboard_pending_clear(runtime, pending);
        if (status == LIBRDP_STATUS_OK)
            status = send_status;
    }
    return status;
}

librdp_status server_clipboard_runtime_platform_request(
    server_clipboard_runtime* runtime,
    const server_platform_clipboard_request* request)
{
    server_clipboard_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!runtime || !request || request->request_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer = server_clipboard_find_peer(runtime,
                                      request->peer_id,
                                      request->generation);
    if (!peer ||
        request->ownership_generation != runtime->published_generation ||
        request->ownership_generation != peer->ownership_generation ||
        !server_clipboard_find_format(peer->remote_formats,
                                      peer->remote_format_count,
                                      request->format_id))
        return LIBRDP_STATUS_STATE;
    status = server_clipboard_pending_begin(
        runtime,
        &peer->remote_data,
        SERVER_CLIPBOARD_PENDING_REMOTE_DATA,
        request->request_id,
        request->format_id,
        0u,
        runtime->config.max_data_bytes);
    if (status == LIBRDP_STATUS_OK)
    {
        status = peer->protocol->send_format_data_request(
            peer->protocol_context,
            peer->channel_id,
            request->format_id);
    }
    if (status != LIBRDP_STATUS_OK)
        server_clipboard_pending_clear(runtime, &peer->remote_data);
    return status;
}

librdp_status server_clipboard_runtime_platform_file_request(
    server_clipboard_runtime* runtime,
    const server_platform_clipboard_file_request* request)
{
    server_clipboard_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    const uint32_t* clip_data_id = NULL;

    if (!runtime || !request || request->request_id == 0u ||
        request->stream_id == 0u ||
        request->requested_bytes > runtime->config.max_file_range_bytes ||
        (request->flags &
         ~(LIBRDP_CLIPBOARD_FILECONTENTS_SIZE |
           LIBRDP_CLIPBOARD_FILECONTENTS_RANGE)) != 0u ||
        (request->flags &
         (LIBRDP_CLIPBOARD_FILECONTENTS_SIZE |
          LIBRDP_CLIPBOARD_FILECONTENTS_RANGE)) == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer = server_clipboard_find_peer(runtime,
                                      request->peer_id,
                                      request->generation);
    if (!peer ||
        request->ownership_generation != runtime->published_generation ||
        request->ownership_generation != peer->ownership_generation ||
        !server_clipboard_has_format_class(peer->remote_formats,
                                           peer->remote_format_count,
                                           SERVER_CLIPBOARD_FORMAT_URI_LIST))
        return LIBRDP_STATUS_STATE;
    status = server_clipboard_pending_begin(
        runtime,
        &peer->remote_file,
        SERVER_CLIPBOARD_PENDING_REMOTE_FILE,
        request->request_id,
        0u,
        request->stream_id,
        request->requested_bytes > 0u
            ? request->requested_bytes
            : runtime->config.max_file_range_bytes);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (request->has_clip_data_id)
        clip_data_id = &request->clip_data_id;
    status = peer->protocol->send_file_request(
        peer->protocol_context,
        peer->channel_id,
        request->stream_id,
        request->file_index,
        request->flags,
        request->position,
        request->requested_bytes,
        clip_data_id);
    if (status != LIBRDP_STATUS_OK)
        server_clipboard_pending_clear(runtime, &peer->remote_file);
    return status;
}

librdp_status server_clipboard_runtime_platform_cancel(
    server_clipboard_runtime* runtime,
    uint32_t peer_id,
    uint32_t generation,
    uint64_t ownership_generation,
    uint64_t request_id)
{
    server_clipboard_peer* peer = NULL;
    server_clipboard_pending* pending = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!runtime || peer_id == 0u || generation == 0u ||
        ownership_generation == 0u || request_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer = server_clipboard_find_peer(runtime, peer_id, generation);
    if (!peer || ownership_generation != runtime->published_generation ||
        ownership_generation != peer->ownership_generation)
        return LIBRDP_STATUS_STATE;
    if (peer->remote_data.kind == SERVER_CLIPBOARD_PENDING_REMOTE_DATA &&
        peer->remote_data.request_id == request_id)
        pending = &peer->remote_data;
    else if (peer->remote_file.kind ==
                 SERVER_CLIPBOARD_PENDING_REMOTE_FILE &&
             peer->remote_file.request_id == request_id)
        pending = &peer->remote_file;
    if (!pending)
        return LIBRDP_STATUS_STATE;
    status = peer->protocol->cancel_requests(peer->protocol_context);
    server_clipboard_pending_clear(runtime, pending);
    return status;
}

void server_clipboard_runtime_revoke(server_clipboard_runtime* runtime)
{
    uint32_t index = 0;

    if (!runtime)
        return;
    for (index = 0; index < runtime->config.max_peers; index++)
    {
        server_clipboard_peer* peer = &runtime->peers[index];

        if (!peer->occupied)
            continue;
        peer->protocol->cancel_requests(peer->protocol_context);
        runtime->platform->cancel_peer(runtime->platform_context,
                                       peer->peer_id,
                                       peer->generation);
        server_clipboard_pending_clear(runtime, &peer->local_data);
        server_clipboard_pending_clear(runtime, &peer->local_file);
        server_clipboard_pending_clear(runtime, &peer->remote_data);
        server_clipboard_pending_clear(runtime, &peer->remote_file);
        peer->channel_ready = 0;
        peer->channel_id = 0u;
    }
    if (runtime->published_generation != 0u)
    {
        runtime->platform->release_ownership(runtime->platform_context,
                                             runtime->published_generation);
        runtime->published_generation = 0u;
    }
}
