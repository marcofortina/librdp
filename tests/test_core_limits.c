/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: public client limit boundary smoke tests.
 * Coverage: policy maxima, PDU and fast-path framing, static and dynamic
 * channels, clipboard data/files/ranges, DVC count and graphics surfaces.
 * Bug classes: off-by-one acceptance, silent truncation, stale partial state,
 * incorrect status mapping and missing rejection metrics.
 * Determinism: all wire reads use local socket pairs and synthetic payloads.
 */

#include "test_core_support.h"
#include "test_core_suites.h"

#include "channels/graphics_pipeline.h"
#include "client/session_channels.h"
#include "client/session_clipboard.h"
#include "client/session_graphics_pipeline.h"
#include "client/session_protocol_io.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

typedef struct limit_field
{
    size_t offset;
} limit_field;

#define LIMIT_FIELD(member) {offsetof(librdp_limits, member)}

static const limit_field public_limit_fields[] = {
    LIMIT_FIELD(pdu_buffer_bytes),
    LIMIT_FIELD(channel_buffer_bytes),
    LIMIT_FIELD(dynamic_channel_count),
    LIMIT_FIELD(dynamic_channel_message_bytes),
    LIMIT_FIELD(clipboard_formats),
    LIMIT_FIELD(clipboard_files),
    LIMIT_FIELD(clipboard_file_range_bytes),
    LIMIT_FIELD(file_handles),
    LIMIT_FIELD(file_io_bytes),
    LIMIT_FIELD(device_io_bytes),
    LIMIT_FIELD(surface_count),
    LIMIT_FIELD(surface_max_dimension),
    LIMIT_FIELD(frame_bytes),
    LIMIT_FIELD(pending_requests)
};

static uint32_t* limit_value(librdp_limits* limits,
                             const limit_field* field)
{
    return (uint32_t*)((uint8_t*)limits + field->offset);
}

/*
 * Every maximum returned by the initializer is accepted. One greater and zero
 * are rejected transactionally for each field without changing the installed
 * policy.
 */
static int test_limit_policy_values(void)
{
    librdp_settings* settings = NULL;
    librdp_limits defaults;
    librdp_limits candidate;
    librdp_limits observed;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_desktop_size(
              settings,
              LIBRDP_DESKTOP_MIN_DIMENSION,
              LIBRDP_DESKTOP_MIN_DIMENSION) == LIBRDP_STATUS_OK);
    CHECK(librdp_limits_init(&defaults) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_limits(settings, &defaults) ==
          LIBRDP_STATUS_OK);

    for (size_t index = 0u;
         index < sizeof(public_limit_fields) / sizeof(public_limit_fields[0]);
         index++)
    {
        uint32_t maximum = 0u;

        candidate = defaults;
        maximum = *limit_value(&candidate, &public_limit_fields[index]);
        CHECK(maximum < UINT32_MAX);
        *limit_value(&candidate, &public_limit_fields[index]) = maximum + 1u;
        CHECK(librdp_settings_set_limits(settings, &candidate) ==
              LIBRDP_STATUS_INVALID_ARGUMENT);
        CHECK(librdp_settings_get_limits(settings, &observed) ==
              LIBRDP_STATUS_OK);
        CHECK(memcmp(&observed, &defaults, sizeof(defaults)) == 0);

        candidate = defaults;
        *limit_value(&candidate, &public_limit_fields[index]) = 0u;
        CHECK(librdp_settings_set_limits(settings, &candidate) ==
              LIBRDP_STATUS_INVALID_ARGUMENT);
        CHECK(librdp_settings_get_limits(settings, &observed) ==
              LIBRDP_STATUS_OK);
        CHECK(memcmp(&observed, &defaults, sizeof(defaults)) == 0);
    }

    librdp_settings_free(settings);
    return 0;
}

static int write_socket_packet(int fd,
                               const uint8_t* data,
                               size_t data_len)
{
    size_t offset = 0u;

    while (offset < data_len)
    {
        ssize_t written = write(fd, data + offset, data_len - offset);

        if (written <= 0)
            return 0;
        offset += (size_t)written;
    }
    return 1;
}

/*
 * Read complete TPKT and fast-path records at the configured byte caps, then
 * reject records one byte larger before parser or payload allocation commits.
 */
static int test_wire_buffer_limits(void)
{
    static const uint8_t tpkt_exact[] = {
        0x03u, 0x00u, 0x00u, 0x08u, 0x02u, 0xf0u, 0x80u, 0x55u
    };
    static const uint8_t tpkt_over[] = {
        0x03u, 0x00u, 0x00u, 0x09u, 0x02u, 0xf0u, 0x80u, 0x55u, 0x66u
    };
    static const uint8_t fastpath_exact[] = {
        0x00u, 0x04u, 0x55u, 0x66u
    };
    static const uint8_t fastpath_over[] = {
        0x00u, 0x05u, 0x55u, 0x66u, 0x77u
    };
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_limits limits;
    librdp_metrics metrics;
    rdp_buffer packet;
    const uint8_t* pdu = NULL;
    size_t pdu_len = 0u;
    int sockets[2] = {-1, -1};

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_limits_init(&limits) == LIBRDP_STATUS_OK);
    limits.pdu_buffer_bytes = sizeof(tpkt_exact);
    limits.frame_bytes = sizeof(fastpath_exact);
    CHECK(librdp_settings_set_limits(settings, &limits) ==
          LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    rdp_transport_attach_fd(&session->transport, sockets[0], 1);
    sockets[0] = -1;
    rdp_buffer_init(&packet);

    CHECK(write_socket_packet(sockets[1], tpkt_exact, sizeof(tpkt_exact)));
    CHECK(rdp_session_read_mcs_pdu(session,
                                   &packet,
                                   &pdu,
                                   &pdu_len,
                                   "test.limit.tpkt") == LIBRDP_STATUS_OK);
    CHECK(pdu_len == 1u && pdu && pdu[0] == 0x55u);
    CHECK(write_socket_packet(sockets[1], tpkt_over, sizeof(tpkt_over)));
    CHECK(rdp_session_read_mcs_pdu(session,
                                   &packet,
                                   &pdu,
                                   &pdu_len,
                                   "test.limit.tpkt") ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);

    CHECK(write_socket_packet(sockets[1],
                              fastpath_exact,
                              sizeof(fastpath_exact)));
    CHECK(rdp_session_read_fastpath_packet(session, &packet) ==
          LIBRDP_STATUS_OK);
    CHECK(packet.length == sizeof(fastpath_exact));
    CHECK(write_socket_packet(sockets[1],
                              fastpath_over,
                              sizeof(fastpath_over)));
    CHECK(rdp_session_read_fastpath_packet(session, &packet) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(metrics.limits_rejected == 2u);

    rdp_buffer_free(&packet);
    CHECK(close(sockets[1]) == 0);
    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}

/*
 * Exercise low configured caps through public clipboard/channel APIs and the
 * internal DVC allocator. Exact-size calls proceed to normal state handling;
 * one-byte/count-over calls stop at the policy boundary and update metrics.
 */
static int test_channel_clipboard_limits(void)
{
    static const uint8_t exact[4] = {1u, 2u, 3u, 4u};
    static const uint8_t over[5] = {1u, 2u, 3u, 4u, 5u};
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_limits limits;
    librdp_metrics metrics;
    librdp_clipboard_file files[2];
    rdp_dynamic_channel_create_request request;
    char path[] = "/tmp/librdp-limit-XXXXXX";
    int fd = -1;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_limits_init(&limits) == LIBRDP_STATUS_OK);
    limits.channel_buffer_bytes = sizeof(exact);
    limits.dynamic_channel_count = 1u;
    limits.dynamic_channel_message_bytes = sizeof(exact);
    limits.clipboard_files = 1u;
    limits.clipboard_file_range_bytes = sizeof(exact);
    CHECK(librdp_settings_set_limits(settings, &limits) ==
          LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_static_channel_send(session,
                                             "TEST",
                                             exact,
                                             sizeof(exact)) ==
          LIBRDP_STATUS_STATE);
    CHECK(librdp_session_static_channel_send(session,
                                             "TEST",
                                             over,
                                             sizeof(over)) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(librdp_session_channel_send(session,
                                     1u,
                                     exact,
                                     sizeof(exact)) ==
          LIBRDP_STATUS_STATE);
    CHECK(librdp_session_channel_send(session,
                                     1u,
                                     over,
                                     sizeof(over)) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(librdp_session_clipboard_set_data(
              session,
              LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT,
              exact,
              sizeof(exact)) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_clipboard_set_data(
              session,
              LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT,
              over,
              sizeof(over)) == LIBRDP_STATUS_LIMIT_EXCEEDED);

    fd = mkstemp(path);
    CHECK(fd >= 0);
    CHECK(write(fd, exact, sizeof(exact)) == (ssize_t)sizeof(exact));
    CHECK(close(fd) == 0);
    fd = -1;
    memset(files, 0, sizeof(files));
    files[0].path = path;
    files[0].name = "one.bin";
    files[1].path = path;
    files[1].name = "two.bin";
    CHECK(librdp_session_clipboard_set_files(session, files, 1u) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_session_clipboard_set_files(session, files, 2u) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(librdp_session_clipboard_request_file_range(
              session,
              1u,
              0,
              0u,
              sizeof(exact)) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_clipboard_request_file_range(
              session,
              1u,
              0,
              0u,
              sizeof(over)) == LIBRDP_STATUS_LIMIT_EXCEEDED);

    memset(&request, 0, sizeof(request));
    request.channel_id = 1u;
    request.channel_id_bytes = 1u;
    request.name = "LIMIT1";
    request.name_len = strlen(request.name);
    CHECK(rdp_session_dynamic_channel_add(session, &request) ==
          LIBRDP_STATUS_OK);
    request.channel_id = 2u;
    request.name = "LIMIT2";
    request.name_len = strlen(request.name);
    CHECK(rdp_session_dynamic_channel_add(session, &request) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);

    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(metrics.limits_rejected == 6u);
    CHECK(unlink(path) == 0);
    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}

/*
 * Clamp an incoming clipboard format list to the configured remembered count
 * and reject a second graphics surface without mutating the first one.
 */
static int test_remote_format_and_surface_limits(void)
{
    rdp_clipboard_format_entry format_entries[2];
    librdp_clipboard_format formats[2];
    rdp_clipboard_packet packet;
    rdp_clipboard_format_list list;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_limits limits;
    librdp_metrics metrics;
    rdp_buffer encoded;
    rdp_buffer segmented;
    uint32_t stored = 0u;
    uint32_t total = 0u;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_limits_init(&limits) == LIBRDP_STATUS_OK);
    limits.clipboard_formats = 1u;
    limits.surface_count = 1u;
    CHECK(librdp_settings_set_limits(settings, &limits) ==
          LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    memset(format_entries, 0, sizeof(format_entries));
    memset(formats, 0, sizeof(formats));
    format_entries[0].format_id = LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT;
    format_entries[1].format_id = LIBRDP_CLIPBOARD_FORMAT_HTML;
    rdp_buffer_init(&encoded);
    CHECK(rdp_clipboard_write_format_list(&encoded,
                                          format_entries,
                                          1u,
                                          0) == LIBRDP_STATUS_OK);
    CHECK(rdp_clipboard_parse_packet(encoded.data,
                                     encoded.length,
                                     &packet) == LIBRDP_STATUS_OK);
    CHECK(rdp_clipboard_parse_format_list(&packet, &list) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_clipboard_store_remote_formats(
              session,
              &list,
              0,
              formats,
              2u,
              &stored,
              &total) == LIBRDP_STATUS_OK);
    CHECK(stored == 1u && total == 1u);
    CHECK(session->clipboard_remote_format_count == 1u);

    encoded.length = 0u;
    CHECK(rdp_clipboard_write_format_list(&encoded,
                                          format_entries,
                                          2u,
                                          0) == LIBRDP_STATUS_OK);
    CHECK(rdp_clipboard_parse_packet(encoded.data,
                                     encoded.length,
                                     &packet) == LIBRDP_STATUS_OK);
    CHECK(rdp_clipboard_parse_format_list(&packet, &list) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_clipboard_store_remote_formats(
              session,
              &list,
              0,
              formats,
              2u,
              &stored,
              &total) == LIBRDP_STATUS_OK);
    CHECK(stored == 1u && total == 2u);
    CHECK(session->clipboard_remote_format_count == 1u);
    CHECK(session->clipboard_remote_formats[0] ==
          LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT);

    rdp_buffer_init(&segmented);
    encoded.length = 0u;
    CHECK(rdp_graphics_write_create_surface(
              &encoded,
              1u,
              1u,
              1u,
              RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888) == LIBRDP_STATUS_OK);
    CHECK(rdp_graphics_write_segmented_uncompressed(
              &segmented,
              encoded.data,
              encoded.length) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_graphics_message(
              session,
              7u,
              segmented.data,
              segmented.length) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_graphics_surface_find(session, 1u) != NULL);

    segmented.length = 0u;
    encoded.length = 0u;
    CHECK(rdp_graphics_write_create_surface(
              &encoded,
              2u,
              1u,
              1u,
              RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888) == LIBRDP_STATUS_OK);
    CHECK(rdp_graphics_write_segmented_uncompressed(
              &segmented,
              encoded.data,
              encoded.length) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_graphics_message(
              session,
              7u,
              segmented.data,
              segmented.length) == LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(rdp_session_graphics_surface_find(session, 1u) != NULL);
    CHECK(rdp_session_graphics_surface_find(session, 2u) == NULL);

    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(metrics.limits_rejected == 2u);
    rdp_buffer_free(&segmented);
    rdp_buffer_free(&encoded);
    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}

int test_public_limit_boundaries(void)
{
    if (test_limit_policy_values() != 0 ||
        test_wire_buffer_limits() != 0 ||
        test_channel_clipboard_limits() != 0)
        return 1;
    return test_remote_format_and_surface_limits();
}
