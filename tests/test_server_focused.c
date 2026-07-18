/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: focused server peer lifecycle, channel, and graphics tests.
 * Coverage: accepted-peer ownership, pre-activation state gates, surface
 * storage, provider state, and idempotent shutdown.
 * Bug classes: invalid state, stale channel state, framebuffer bounds, and
 * resource cleanup.
 * Determinism: every peer uses an ephemeral loopback listener.
 */

#include "test_server_support.h"
#include "test_server_suites.h"
#include "server/server_channels.h"

#include <string.h>
#include <unistd.h>

typedef struct test_server_peer_fixture
{
    librdp_server* server;
    librdp_server_peer* peer;
    int client_fd;
} test_server_peer_fixture;

typedef struct test_server_clipboard_context
{
    uint32_t counts[LIBRDP_SERVER_CLIPBOARD_CANCELLED + 1u];
    uint32_t format_id;
    uint32_t stream_id;
    uint32_t clip_data_id;
    uint32_t general_flags;
    uint8_t format_name[32];
    size_t format_name_len;
    uint8_t data[32];
    size_t data_len;
    int valid;
} test_server_clipboard_context;

static void test_server_clipboard_callback(
    librdp_server_peer* peer,
    const librdp_server_clipboard_event* event,
    void* user_data)
{
    test_server_clipboard_context* context =
        (test_server_clipboard_context*)user_data;

    if (!peer || !event || !context ||
        event->version != LIBRDP_SERVER_CLIPBOARD_EVENT_VERSION ||
        event->size < sizeof(*event) ||
        event->type < LIBRDP_SERVER_CLIPBOARD_MONITOR_READY ||
        event->type > LIBRDP_SERVER_CLIPBOARD_CANCELLED)
    {
        if (context)
            context->valid = 0;
        return;
    }
    context->counts[event->type]++;
    if (event->format_id != 0u)
        context->format_id = event->format_id;
    if (event->stream_id != 0u)
        context->stream_id = event->stream_id;
    if (event->has_clip_data_id)
        context->clip_data_id = event->clip_data_id;
    if (event->type == LIBRDP_SERVER_CLIPBOARD_CAPABILITIES)
        context->general_flags = event->general_flags;
    if (event->format_count > 0u && event->formats &&
        event->formats[0].name_len <= sizeof(context->format_name))
    {
        context->format_name_len = event->formats[0].name_len;
        memcpy(context->format_name,
               event->formats[0].name,
               context->format_name_len);
    }
    if (event->data_len > 0u && event->data &&
        event->data_len <= sizeof(context->data))
    {
        context->data_len = event->data_len;
        memcpy(context->data, event->data, event->data_len);
    }
    else if (event->data_len > 0u)
        context->valid = 0;
}

static int test_server_peer_fixture_open(test_server_peer_fixture* fixture)
{
    librdp_server_config config;
    uint16_t port = 0;

    if (!fixture)
        return 0;
    memset(fixture, 0, sizeof(*fixture));
    fixture->client_fd = -1;
    if (librdp_server_config_init(&config) != LIBRDP_STATUS_OK)
        return 0;
    config.bind_address = "127.0.0.1";
    fixture->server = librdp_server_new(&config);
    if (!fixture->server || librdp_server_listen(fixture->server) != LIBRDP_STATUS_OK)
        return 0;
    port = librdp_server_local_port(fixture->server);
    fixture->client_fd = test_server_connect_loopback(port);
    if (fixture->client_fd < 0 ||
        librdp_server_accept(fixture->server, 1000, &fixture->peer) != LIBRDP_STATUS_OK)
        return 0;
    return 1;
}

static void test_server_peer_fixture_close(test_server_peer_fixture* fixture)
{
    if (!fixture)
        return;
    librdp_server_peer_free(fixture->peer);
    if (fixture->client_fd >= 0)
        close(fixture->client_fd);
    librdp_server_close(fixture->server);
    librdp_server_free(fixture->server);
    memset(fixture, 0, sizeof(*fixture));
    fixture->client_fd = -1;
}

int test_server_lifecycle_focused(void)
{
    test_server_peer_fixture fixture;
    struct pollfd pollfd;
    size_t count = 0;

    SCHECK(test_server_peer_fixture_open(&fixture));
    SCHECK(librdp_server_peer_get_state(fixture.peer) == LIBRDP_SERVER_PEER_NEW);
    SCHECK(librdp_server_peer_get_pollfds(fixture.peer, NULL, 0, &count) == LIBRDP_STATUS_OK);
    SCHECK(count == 1);
    SCHECK(librdp_server_peer_get_pollfds(fixture.peer, &pollfd, 1, &count) == LIBRDP_STATUS_OK);
    SCHECK(count == 1);
    SCHECK(pollfd.fd >= 0);
    SCHECK(librdp_server_peer_close(fixture.peer) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(fixture.peer) == LIBRDP_SERVER_PEER_CLOSED);
    SCHECK(librdp_server_peer_close(fixture.peer) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_pollfds(fixture.peer, NULL, 0, &count) == LIBRDP_STATUS_STATE);
    test_server_peer_fixture_close(&fixture);
    return 0;
}

int test_server_channels_focused(void)
{
    test_server_peer_fixture fixture;
    test_server_clipboard_context clipboard;
    librdp_server_dynamic_channel_info channel_info;
    librdp_server_clipboard_event initialized_event;
    rdp_clipboard_format_entry entry;
    rdp_buffer packet;
    int provider_enabled = 0;
    static const uint8_t payload[] = { 0x11, 0x22 };
    static const uint8_t format_name[] = {'T', 0, 'E', 0, 'S', 0, 'T', 0};

    SCHECK(!rdp_server_channel_allowed(NULL, RDP_MCS_GLOBAL_CHANNEL_ID));
    SCHECK(test_server_peer_fixture_open(&fixture));
    memset(&clipboard, 0, sizeof(clipboard));
    clipboard.valid = 1;
    rdp_buffer_init(&packet);
    SCHECK(librdp_server_clipboard_event_init(NULL) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_clipboard_event_init(&initialized_event) ==
           LIBRDP_STATUS_OK);
    SCHECK(initialized_event.version ==
               LIBRDP_SERVER_CLIPBOARD_EVENT_VERSION &&
           initialized_event.size == sizeof(initialized_event));
    SCHECK(librdp_server_peer_set_clipboard_callback(
               NULL,
               test_server_clipboard_callback,
               &clipboard) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_set_clipboard_callback(
               fixture.peer,
               test_server_clipboard_callback,
               &clipboard) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_set_channel_callback(fixture.peer, test_server_channel_callback, NULL) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_set_dynamic_channel_accept_callback(
               fixture.peer, test_server_dynamic_channel_accept_callback, NULL) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_dynamic_channel_count(fixture.peer) == 0);
    SCHECK(librdp_server_peer_dynamic_channel_at(fixture.peer, 0, &channel_info) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_send_channel_data(fixture.peer, 1003, payload, sizeof(payload)) ==
           LIBRDP_STATUS_STATE);
    SCHECK(librdp_server_peer_open_dynamic_channel(fixture.peer, 1, 0, "test") ==
           LIBRDP_STATUS_STATE);
    SCHECK(librdp_server_peer_enable_extension_provider(
               fixture.peer, LIBRDP_SERVER_EXTENSION_CLIPBOARD, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_extension_provider_status(
               fixture.peer, LIBRDP_SERVER_EXTENSION_CLIPBOARD, &provider_enabled) == LIBRDP_STATUS_OK);
    SCHECK(provider_enabled == 1);
    SCHECK(librdp_server_peer_enable_extension_provider(
               fixture.peer, LIBRDP_SERVER_EXTENSION_CLIPBOARD, 0) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_extension_provider_status(
               fixture.peer, LIBRDP_SERVER_EXTENSION_CLIPBOARD, &provider_enabled) == LIBRDP_STATUS_OK);
    SCHECK(provider_enabled == 0);

    SCHECK(rdp_clipboard_write_monitor_ready(&packet) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_capabilities(
               &packet,
               RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    memset(&entry, 0, sizeof(entry));
    entry.format_id = RDP_CLIPBOARD_FORMAT_UNICODETEXT;
    entry.name = format_name;
    entry.name_len = sizeof(format_name);
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_format_list(&packet, &entry, 1u, 1) ==
           LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    fixture.peer->clipboard_formats_sent = 1u;
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_format_list_response(&packet, 1) ==
           LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_format_data_request(
               &packet,
               RDP_CLIPBOARD_FORMAT_UNICODETEXT) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    fixture.peer->clipboard_pending_format = 1u;
    fixture.peer->clipboard_pending_format_id =
        RDP_CLIPBOARD_FORMAT_UNICODETEXT;
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_format_data_response(
               &packet,
               1,
               payload,
               sizeof(payload)) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_file_contents_request(
               &packet,
               41u,
               2,
               RDP_CLIPBOARD_FILECONTENTS_RANGE,
               7u,
               11u,
               NULL) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    fixture.peer->clipboard_pending_file = 1u;
    fixture.peer->clipboard_pending_file_stream_id = 43u;
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_file_contents_response(
               &packet,
               1,
               43u,
               payload,
               sizeof(payload)) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_lock(&packet, 47u) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_unlock(&packet, 47u) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    fixture.peer->clipboard_pending_format = 1u;
    fixture.peer->clipboard_pending_format_id = 53u;
    fixture.peer->clipboard_pending_file = 1u;
    fixture.peer->clipboard_pending_file_stream_id = 59u;
    SCHECK(librdp_server_peer_cancel_clipboard_requests(fixture.peer) ==
           LIBRDP_STATUS_OK);
    SCHECK(clipboard.valid);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_MONITOR_READY] == 1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_CAPABILITIES] == 1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_FORMAT_LIST] == 1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_FORMAT_LIST_RESPONSE] ==
           1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_FORMAT_DATA_REQUEST] ==
           1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_FORMAT_DATA_RESPONSE] ==
           1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_FILE_CONTENTS_REQUEST] ==
           1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_FILE_CONTENTS_RESPONSE] ==
           1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_LOCK] == 1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_UNLOCK] == 1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_CANCELLED] == 2u);
    SCHECK(clipboard.general_flags ==
           RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES);
    SCHECK(clipboard.format_name_len == sizeof(format_name) &&
           memcmp(clipboard.format_name,
                  format_name,
                  sizeof(format_name)) == 0);
    SCHECK(clipboard.data_len == sizeof(payload) &&
           memcmp(clipboard.data, payload, sizeof(payload)) == 0);
    SCHECK(clipboard.stream_id == 59u);
    SCHECK(librdp_server_peer_set_clipboard_callback(
               fixture.peer,
               NULL,
               NULL) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&packet);
    test_server_peer_fixture_close(&fixture);
    return 0;
}

int test_server_graphics_focused(void)
{
    test_server_peer_fixture fixture;
    static const uint8_t pixels[] = {
        0x10, 0x20, 0x30, 0xff, 0x40, 0x50, 0x60, 0xff,
        0x70, 0x80, 0x90, 0xff, 0xa0, 0xb0, 0xc0, 0xff,
    };

    SCHECK(test_server_peer_fixture_open(&fixture));
    SCHECK(librdp_server_peer_desktop_width(fixture.peer) == 1024);
    SCHECK(librdp_server_peer_desktop_height(fixture.peer) == 768);
    SCHECK(librdp_server_peer_surface_resize(fixture.peer, 8, 6) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_desktop_width(fixture.peer) == 8);
    SCHECK(librdp_server_peer_desktop_height(fixture.peer) == 6);
    SCHECK(librdp_server_peer_surface_blit_bgra32(
               fixture.peer, 2, 1, 2, 2, 8, pixels) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_surface_blit_bgra32(
               fixture.peer, 7, 5, 2, 2, 8, pixels) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_surface_present(fixture.peer, 2, 1, 2, 2) ==
           LIBRDP_STATUS_STATE);
    SCHECK(librdp_server_peer_set_graphics_frame_queue_limit(fixture.peer, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_set_graphics_frame_queue_limit(fixture.peer, 4) ==
           LIBRDP_STATUS_OK);
    test_server_peer_fixture_close(&fixture);
    return 0;
}
