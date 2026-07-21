/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic redirected and optimized video runtime smoke.
 * Coverage: TSMF capability/format/stream/sample/flush/close sequencing,
 * RDPEGT mapping lifecycle, optimized presentation sequencing, bounded media
 * delivery, packet-loss recovery and reconnect reset.
 * Bug classes: unbounded media writes, stale presentation state, late sample
 * acceptance, false geometry bindings and missing recovery notification.
 * Determinism: an in-memory transport and bounded temporary-file sink replace
 * network and decoder backends.
 */

#include <librdp/librdp.h>

#include "channels/dynamic_channel.h"
#include "channels/geometry_tracking.h"
#include "channels/video_optimized.h"
#include "channels/video_redirection.h"
#include "client/session_internal.h"
#include "client/session_video.h"
#include "common/buffer.h"
#include "transport/transport.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expr)                                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

#define TEST_VIDEO_DYNAMIC_STATIC_ID 1008u
#define TEST_VIDEO_TSMF_ID 20u
#define TEST_VIDEO_CONTROL_ID 21u
#define TEST_VIDEO_DATA_ID 22u
#define TEST_VIDEO_GEOMETRY_ID 23u
#define TEST_VIDEO_USER_ID 1005u
#define TEST_VIDEO_SINK_LIMIT 12u

typedef struct test_video_capture
{
    rdp_buffer wire;
    FILE* sink;
    size_t sink_limit;
    size_t sink_bytes;
    size_t sink_dropped;
    uint64_t sink_hash;
    uint32_t writes;
    uint32_t opens;
    uint32_t closes;
    uint32_t data_events;
} test_video_capture;

static uint64_t test_video_hash_update(uint64_t hash,
                                       const uint8_t* data,
                                       size_t data_len)
{
    size_t i = 0;

    for (i = 0; i < data_len; i++)
    {
        hash ^= data[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static librdp_status test_video_capture_write(void* context,
                                              const void* data,
                                              size_t length,
                                              size_t* written_len)
{
    test_video_capture* capture = (test_video_capture*)context;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!capture || (!data && length > 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append(&capture->wire, data, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    capture->writes++;
    if (written_len)
        *written_len = length;
    return LIBRDP_STATUS_OK;
}

static const rdp_transport_backend_ops TEST_VIDEO_TRANSPORT_OPS = {
    NULL,
    NULL,
    NULL,
    NULL,
    test_video_capture_write,
    NULL,
};

static int test_video_name_contains(const char* name,
                                    size_t name_len,
                                    const char* needle)
{
    size_t needle_len = 0;
    size_t i = 0;

    if (!name || !needle)
        return 0;
    needle_len = strlen(needle);
    if (needle_len == 0u || needle_len > name_len)
        return 0;
    for (i = 0; i + needle_len <= name_len; i++)
    {
        if (memcmp(name + i, needle, needle_len) == 0)
            return 1;
    }
    return 0;
}

/*
 * Model the application file sink through public channel events. The sink
 * drops complete samples once its byte quota is exhausted and hashes exactly
 * the bytes committed to the temporary file.
 */
static void test_video_event(librdp_session* session,
                             const librdp_event* event,
                             void* user_data)
{
    test_video_capture* capture = (test_video_capture*)user_data;

    (void)session;
    if (!capture || !event)
        return;
    if (event->type == LIBRDP_EVENT_CHANNEL_OPEN)
    {
        const librdp_channel_open_event* open = &event->data.channel_open;

        if (test_video_name_contains(open->name, open->name_len, "Video") ||
            test_video_name_contains(open->name, open->name_len, "TSMF"))
            capture->opens++;
    }
    else if (event->type == LIBRDP_EVENT_CHANNEL_DATA)
    {
        const librdp_channel_data_event* channel = &event->data.channel_data;

        if (!test_video_name_contains(channel->name, channel->name_len, "Video") &&
            !test_video_name_contains(channel->name, channel->name_len, "TSMF"))
            return;
        capture->data_events++;
        if (channel->data_len > capture->sink_limit - capture->sink_bytes)
        {
            capture->sink_dropped += channel->data_len;
            return;
        }
        if (channel->data_len > 0u)
        {
            size_t written = fwrite(channel->data,
                                    1u,
                                    channel->data_len,
                                    capture->sink);

            if (written != channel->data_len)
            {
                capture->sink_dropped += channel->data_len;
                return;
            }
            capture->sink_hash = test_video_hash_update(capture->sink_hash,
                                                        channel->data,
                                                        channel->data_len);
            capture->sink_bytes += channel->data_len;
            (void)fflush(capture->sink);
        }
    }
    else if (event->type == LIBRDP_EVENT_CHANNEL_CLOSE)
    {
        const librdp_channel_close_event* close = &event->data.channel_close;

        if (test_video_name_contains(close->name, close->name_len, "Video") ||
            test_video_name_contains(close->name, close->name_len, "TSMF"))
            capture->closes++;
    }
}

static void test_video_channel_init(rdp_session_dynamic_channel* channel,
                                    uint32_t channel_id,
                                    const char* name)
{
    memset(channel, 0, sizeof(*channel));
    channel->channel_id = channel_id;
    channel->channel_id_bytes =
        rdp_dynamic_channel_select_channel_id_bytes(channel_id);
    channel->active = 1u;
    (void)snprintf(channel->name, sizeof(channel->name), "%s", name);
    rdp_buffer_init(&channel->fragment);
}

static int test_video_sink_matches(const test_video_capture* capture,
                                   const uint8_t* expected,
                                   size_t expected_len)
{
    uint8_t actual[TEST_VIDEO_SINK_LIMIT];
    uint64_t expected_hash = UINT64_C(1469598103934665603);

    if (!capture || !capture->sink || !expected ||
        expected_len > sizeof(actual) ||
        capture->sink_bytes != expected_len)
        return 0;
    expected_hash = test_video_hash_update(expected_hash, expected, expected_len);
    if (capture->sink_hash != expected_hash ||
        fflush(capture->sink) != 0 ||
        fseek(capture->sink, 0, SEEK_SET) != 0 ||
        fread(actual, 1u, expected_len, capture->sink) != expected_len)
        return 0;
    return memcmp(actual, expected, expected_len) == 0;
}

static librdp_status test_video_tsmf_dispatch(librdp_session* session,
                                               rdp_session_dynamic_channel* channel,
                                               const rdp_buffer* packet)
{
    return rdp_session_handle_video_redirection_message(session,
                                                        channel,
                                                        TEST_VIDEO_TSMF_ID,
                                                        packet->data,
                                                        packet->length);
}

/*
 * Exercise the media lifecycle through the session handlers rather than the
 * standalone parsers. State and wire assertions are made after every control
 * transition so malformed or late traffic cannot partially commit.
 */
static int test_video_virtual_lifecycle(void)
{
    static const uint8_t presentation_id[16] = {
        0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
        0x18u, 0x19u, 0x1au, 0x1bu, 0x1cu, 0x1du, 0x1eu, 0x1fu
    };
    static const uint8_t format_guid[16] = {
        0x21u, 0x22u, 0x23u, 0x24u, 0x25u, 0x26u, 0x27u, 0x28u,
        0x29u, 0x2au, 0x2bu, 0x2cu, 0x2du, 0x2eu, 0x2fu, 0x30u
    };
    static const uint8_t protocol_version[4] = {
        RDP_VIDEO_REDIRECTION_PROTOCOL_VERSION_2, 0u, 0u, 0u
    };
    static const uint8_t tsmf_sample[] = {
        0x31u, 0x32u, 0x33u, 0x34u
    };
    static const uint8_t optimized_sample[] = {
        0x41u, 0x42u, 0x43u, 0x44u
    };
    static const uint8_t oversized_sample[TEST_VIDEO_SINK_LIMIT + 1u] = {
        0x51u, 0x52u, 0x53u, 0x54u, 0x55u, 0x56u, 0x57u,
        0x58u, 0x59u, 0x5au, 0x5bu, 0x5cu, 0x5du
    };
    static const uint8_t expected_sink[] = {
        0x31u, 0x32u, 0x33u, 0x34u,
        0x41u, 0x42u, 0x43u, 0x44u,
        0x41u, 0x42u, 0x43u, 0x44u
    };
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_limits limits;
    test_video_capture capture;
    rdp_session_dynamic_channel tsmf;
    rdp_session_dynamic_channel optimized_data;
    rdp_buffer packet;
    rdp_buffer nested;
    rdp_buffer visible;
    rdp_buffer media_type;
    rdp_video_redirection_capability capability;
    rdp_video_redirection_geometry_info geometry;
    rdp_geometry_tracking_rect mapping_bounds;
    rdp_geometry_tracking_rect mapping_rect;
    librdp_metrics metrics;
    uint32_t writes_before = 0u;

    memset(&capture, 0, sizeof(capture));
    memset(&capability, 0, sizeof(capability));
    memset(&geometry, 0, sizeof(geometry));
    rdp_buffer_init(&capture.wire);
    rdp_buffer_init(&packet);
    rdp_buffer_init(&nested);
    rdp_buffer_init(&visible);
    rdp_buffer_init(&media_type);
    capture.sink = tmpfile();
    capture.sink_limit = TEST_VIDEO_SINK_LIMIT;
    capture.sink_hash = UINT64_C(1469598103934665603);
    CHECK(capture.sink != NULL);

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_video_output_path(settings,
                                                "/tmp/librdp-test-video.bin") ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings,
                                         LIBRDP_FEATURE_VIDEO,
                                         1) == LIBRDP_STATUS_OK);
    CHECK(librdp_limits_init(&limits) == LIBRDP_STATUS_OK);
    limits.frame_bytes = TEST_VIDEO_SINK_LIMIT;
    CHECK(librdp_settings_set_limits(settings, &limits) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    session->mcs_user_id = TEST_VIDEO_USER_ID;
    session->dynamic_channel_id = TEST_VIDEO_DYNAMIC_STATIC_ID;
    session->video_redirection_channel_id = TEST_VIDEO_TSMF_ID;
    session->video_redirection_channel_id_bytes =
        rdp_dynamic_channel_select_channel_id_bytes(TEST_VIDEO_TSMF_ID);
    session->video_optimized_control_channel_id = TEST_VIDEO_CONTROL_ID;
    session->video_optimized_control_channel_id_bytes =
        rdp_dynamic_channel_select_channel_id_bytes(TEST_VIDEO_CONTROL_ID);
    session->video_optimized_data_channel_id = TEST_VIDEO_DATA_ID;
    session->video_optimized_data_channel_id_bytes =
        rdp_dynamic_channel_select_channel_id_bytes(TEST_VIDEO_DATA_ID);
    session->geometry_tracking_channel_id = TEST_VIDEO_GEOMETRY_ID;
    session->geometry_tracking_channel_id_bytes =
        rdp_dynamic_channel_select_channel_id_bytes(TEST_VIDEO_GEOMETRY_ID);
    rdp_transport_attach_backend(&session->transport,
                                 &capture,
                                 &TEST_VIDEO_TRANSPORT_OPS);
    librdp_session_set_event_callback(session, test_video_event, &capture);
    test_video_channel_init(&tsmf,
                            TEST_VIDEO_TSMF_ID,
                            RDP_VIDEO_REDIRECTION_CHANNEL_NAME);
    test_video_channel_init(&optimized_data,
                            TEST_VIDEO_DATA_ID,
                            RDP_VIDEO_OPTIMIZED_DATA_CHANNEL);
    rdp_session_emit_channel_open(session, &tsmf);
    rdp_session_emit_channel_open(session, &optimized_data);
    CHECK(capture.opens == 2u);

    capability.type = RDP_VIDEO_REDIRECTION_CAPABILITY_PROTOCOL_VERSION;
    capability.length = sizeof(protocol_version);
    capability.data = protocol_version;
    capability.data_len = sizeof(protocol_version);
    CHECK(rdp_video_redirection_write_exchange_capabilities_request(
               &packet,
               1u,
               &capability,
               1u) == LIBRDP_STATUS_OK);
    CHECK(test_video_tsmf_dispatch(session, &tsmf, &packet) ==
          LIBRDP_STATUS_OK);
    CHECK(session->video_redirection_ready);
    CHECK(session->video_redirection_capabilities_sent);

    packet.length = 0u;
    CHECK(rdp_video_redirection_write_media_type(&media_type,
                                                 format_guid,
                                                 format_guid,
                                                 0u,
                                                 1u,
                                                 4096u,
                                                 format_guid,
                                                 NULL,
                                                 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_video_redirection_write_header(
               &packet,
               RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
               RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
               2u,
               1u,
               RDP_VIDEO_REDIRECTION_FUNC_CHECK_FORMAT_SUPPORT_REQ) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(
               &packet,
               RDP_VIDEO_REDIRECTION_PLATFORM_COOKIE_MF) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&packet, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&packet, 1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append(&packet,
                            media_type.data,
                            media_type.length) == LIBRDP_STATUS_OK);
    writes_before = capture.writes;
    CHECK(test_video_tsmf_dispatch(session, &tsmf, &packet) ==
          LIBRDP_STATUS_OK);
    CHECK(capture.writes == writes_before + 1u);

    packet.length = 0u;
    CHECK(rdp_video_redirection_write_new_presentation(
               &packet,
               3u,
               presentation_id,
               RDP_VIDEO_REDIRECTION_PLATFORM_COOKIE_MF) ==
          LIBRDP_STATUS_OK);
    CHECK(test_video_tsmf_dispatch(session, &tsmf, &packet) ==
          LIBRDP_STATUS_OK);
    packet.length = 0u;
    CHECK(rdp_video_redirection_write_add_stream(&packet,
                                                 4u,
                                                 presentation_id,
                                                 7u,
                                                 media_type.data,
                                                 (uint32_t)media_type.length) ==
          LIBRDP_STATUS_OK);
    CHECK(test_video_tsmf_dispatch(session, &tsmf, &packet) ==
          LIBRDP_STATUS_OK);
    CHECK(session->video_streams[0].active);

    packet.length = 0u;
    nested.length = 0u;
    CHECK(rdp_video_redirection_write_data_sample(&nested,
                                                  100u,
                                                  133u,
                                                  0u,
                                                  1u,
                                                  0u,
                                                  tsmf_sample,
                                                  sizeof(tsmf_sample)) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_video_redirection_write_sample_message(
               &packet,
               5u,
               presentation_id,
               7u,
               nested.data,
               (uint32_t)nested.length) == LIBRDP_STATUS_OK);
    writes_before = capture.writes;
    CHECK(test_video_tsmf_dispatch(session, &tsmf, &packet) ==
          LIBRDP_STATUS_OK);
    CHECK(capture.data_events == 1u);
    CHECK(capture.sink_bytes == sizeof(tsmf_sample));
    CHECK(capture.writes == writes_before + 1u);
    CHECK(session->video_streams[0].sample_count == 1u);
    CHECK(session->video_streams[0].last_sample_start == 100u);
    CHECK(session->video_streams[0].last_sample_end == 133u);

    packet.length = 0u;
    CHECK(rdp_video_redirection_write_stream_only(
               &packet,
               6u,
               RDP_VIDEO_REDIRECTION_FUNC_ON_FLUSH,
               presentation_id,
               7u) == LIBRDP_STATUS_OK);
    CHECK(test_video_tsmf_dispatch(session, &tsmf, &packet) ==
          LIBRDP_STATUS_OK);
    CHECK(session->video_streams[0].flush_count == 1u);

    geometry.video_window_id = UINT64_C(0x1020304050607080);
    geometry.window_state = RDP_VIDEO_REDIRECTION_WINDOW_NEW |
                            RDP_VIDEO_REDIRECTION_WINDOW_VISRGN;
    geometry.width = 200u;
    geometry.height = 100u;
    geometry.left = 100u;
    geometry.top = 100u;
    geometry.client_left = 100u;
    geometry.client_top = 100u;
    nested.length = 0u;
    CHECK(rdp_video_redirection_write_geometry_info(&nested,
                                                    &geometry) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_video_redirection_write_rect(&visible,
                                           90u,
                                           90u,
                                           210u,
                                           310u) == LIBRDP_STATUS_OK);
    CHECK(rdp_video_redirection_write_rect(&visible,
                                           300u,
                                           400u,
                                           340u,
                                           450u) == LIBRDP_STATUS_OK);
    packet.length = 0u;
    CHECK(rdp_video_redirection_write_geometry_update(
               &packet,
               7u,
               presentation_id,
               nested.data,
               (uint32_t)nested.length,
               visible.data,
               (uint32_t)visible.length) == LIBRDP_STATUS_OK);
    CHECK(test_video_tsmf_dispatch(session, &tsmf, &packet) ==
          LIBRDP_STATUS_OK);
    CHECK(session->video_geometry_active_count == 1u);
    CHECK(session->video_geometry_clipped_count == 2u);
    CHECK(session->video_geometries[0].visible_rect_count == 1u);
    CHECK(session->video_geometries[0].visible_rects[0].top == 100u &&
          session->video_geometries[0].visible_rects[0].left == 100u &&
          session->video_geometries[0].visible_rects[0].bottom == 200u &&
          session->video_geometries[0].visible_rects[0].right == 300u);

    geometry.window_state = RDP_VIDEO_REDIRECTION_WINDOW_VISRGN;
    nested.length = 0u;
    visible.length = 0u;
    CHECK(rdp_video_redirection_write_geometry_info(&nested,
                                                    &geometry) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_video_redirection_write_rect(&visible,
                                           120u,
                                           130u,
                                           180u,
                                           250u) == LIBRDP_STATUS_OK);
    packet.length = 0u;
    CHECK(rdp_video_redirection_write_geometry_update(
              &packet,
              8u,
              presentation_id,
              nested.data,
              (uint32_t)nested.length,
              visible.data,
              (uint32_t)visible.length) == LIBRDP_STATUS_OK);
    CHECK(test_video_tsmf_dispatch(session, &tsmf, &packet) ==
          LIBRDP_STATUS_OK);
    CHECK(session->video_geometries[0].visible_rect_count == 1u);
    CHECK(session->video_geometries[0].visible_rects[0].top == 120u &&
          session->video_geometries[0].visible_rects[0].left == 130u &&
          session->video_geometries[0].visible_rects[0].bottom == 180u &&
          session->video_geometries[0].visible_rects[0].right == 250u);

    mapping_bounds.left = 20;
    mapping_bounds.top = 30;
    mapping_bounds.right = 660;
    mapping_bounds.bottom = 390;
    mapping_rect = mapping_bounds;
    packet.length = 0u;
    CHECK(rdp_geometry_tracking_write_update(
              &packet,
              geometry.video_window_id,
              UINT64_C(0x8877665544332211),
              &mapping_bounds,
              &mapping_bounds,
              &mapping_bounds,
              &mapping_rect,
              1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_geometry_tracking_message(
              session,
              TEST_VIDEO_GEOMETRY_ID,
              packet.data,
              packet.length) == LIBRDP_STATUS_OK);
    CHECK(session->geometry_tracking_active_count == 1u);
    CHECK(rdp_session_geometry_mapping_available(session,
                                                 geometry.video_window_id));

    packet.length = 0u;
    CHECK(rdp_video_optimized_write_presentation_start_request(
               &packet,
               9u,
               30u,
               2500u,
               640u,
               360u,
               640u,
               360u,
               1000u,
               geometry.video_window_id,
               rdp_video_optimized_h264_subtype_guid(),
               NULL,
               0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_video_optimized_control_message(
               session,
               TEST_VIDEO_CONTROL_ID,
               packet.data,
               packet.length) == LIBRDP_STATUS_OK);
    CHECK(session->video_optimized_presentations[0].active);

    packet.length = 0u;
    CHECK(rdp_video_optimized_write_video_data(
               &packet,
               9u,
               RDP_VIDEO_OPTIMIZED_DATA_FLAG_HAS_TIMESTAMPS |
                   RDP_VIDEO_OPTIMIZED_DATA_FLAG_KEYFRAME,
               1100u,
               33u,
               1u,
               1u,
               1u,
               optimized_sample,
               sizeof(optimized_sample)) == LIBRDP_STATUS_OK);
    writes_before = capture.writes;
    CHECK(rdp_session_handle_video_optimized_data_message(
               session,
               &optimized_data,
               TEST_VIDEO_DATA_ID,
               packet.data,
               packet.length) == LIBRDP_STATUS_OK);
    CHECK(capture.data_events == 2u);
    CHECK(capture.writes == writes_before);
    CHECK(session->video_optimized_presentations[0].sample_count == 1u);

    packet.length = 0u;
    CHECK(rdp_video_optimized_write_video_data(
               &packet,
               9u,
               RDP_VIDEO_OPTIMIZED_DATA_FLAG_HAS_TIMESTAMPS,
               1099u,
               33u,
               1u,
               1u,
               2u,
               optimized_sample,
               sizeof(optimized_sample)) == LIBRDP_STATUS_OK);
    writes_before = capture.writes;
    CHECK(rdp_session_handle_video_optimized_data_message(
               session,
               &optimized_data,
               TEST_VIDEO_DATA_ID,
               packet.data,
               packet.length) == LIBRDP_STATUS_OK);
    CHECK(capture.data_events == 2u);
    CHECK(capture.writes == writes_before + 1u);
    CHECK(session->video_optimized_presentations[0].sample_count == 1u);
    CHECK(session->video_optimized_presentations[0].recovery_notified);

    packet.length = 0u;
    CHECK(rdp_video_optimized_write_video_data(
              &packet,
              9u,
              RDP_VIDEO_OPTIMIZED_DATA_FLAG_HAS_TIMESTAMPS |
                  RDP_VIDEO_OPTIMIZED_DATA_FLAG_KEYFRAME,
              1200u,
              33u,
              1u,
              1u,
              2u,
              optimized_sample,
              sizeof(optimized_sample)) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_video_optimized_data_message(
              session,
              &optimized_data,
              TEST_VIDEO_DATA_ID,
              packet.data,
              packet.length) == LIBRDP_STATUS_OK);
    CHECK(capture.data_events == 3u);
    CHECK(session->video_optimized_presentations[0].sample_count == 2u);
    CHECK(!session->video_optimized_presentations[0].recovery_notified);

    packet.length = 0u;
    CHECK(rdp_video_optimized_write_video_data(
              &packet,
              9u,
              RDP_VIDEO_OPTIMIZED_DATA_FLAG_HAS_TIMESTAMPS,
              1233u,
              33u,
              1u,
              1u,
              3u,
              optimized_sample,
              sizeof(optimized_sample)) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_video_optimized_data_message(
              session,
              &optimized_data,
              TEST_VIDEO_DATA_ID,
              packet.data,
              packet.length) == LIBRDP_STATUS_OK);
    CHECK(capture.data_events == 4u);
    CHECK(capture.sink_bytes == TEST_VIDEO_SINK_LIMIT);
    CHECK(capture.sink_dropped == sizeof(optimized_sample));
    CHECK(session->video_optimized_presentations[0].sample_count == 3u);

    geometry.window_state = RDP_VIDEO_REDIRECTION_WINDOW_DELETED;
    nested.length = 0u;
    CHECK(rdp_video_redirection_write_geometry_info(&nested,
                                                    &geometry) ==
          LIBRDP_STATUS_OK);
    packet.length = 0u;
    CHECK(rdp_video_redirection_write_geometry_update(
               &packet,
               9u,
               presentation_id,
               nested.data,
               (uint32_t)nested.length,
               NULL,
               0u) == LIBRDP_STATUS_OK);
    CHECK(test_video_tsmf_dispatch(session, &tsmf, &packet) ==
          LIBRDP_STATUS_OK);
    CHECK(session->video_geometry_active_count == 0u);
    geometry.window_state = RDP_VIDEO_REDIRECTION_WINDOW_VISRGN;
    nested.length = 0u;
    CHECK(rdp_video_redirection_write_geometry_info(&nested,
                                                    &geometry) ==
          LIBRDP_STATUS_OK);
    packet.length = 0u;
    CHECK(rdp_video_redirection_write_geometry_update(
              &packet,
              10u,
              presentation_id,
              nested.data,
              (uint32_t)nested.length,
              visible.data,
              (uint32_t)visible.length) == LIBRDP_STATUS_OK);
    CHECK(test_video_tsmf_dispatch(session, &tsmf, &packet) ==
          LIBRDP_STATUS_OK);
    CHECK(session->video_geometry_active_count == 0u);
    CHECK(session->video_geometry_stale_count == 1u);
    packet.length = 0u;
    CHECK(rdp_geometry_tracking_write_clear(
              &packet,
              geometry.video_window_id) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_geometry_tracking_message(
              session,
              TEST_VIDEO_GEOMETRY_ID,
              packet.data,
              packet.length) == LIBRDP_STATUS_OK);
    CHECK(session->geometry_tracking_active_count == 0u);
    CHECK(!rdp_session_geometry_mapping_available(session,
                                                  geometry.video_window_id));
    packet.length = 0u;
    CHECK(rdp_video_optimized_write_video_data(
               &packet,
               9u,
               RDP_VIDEO_OPTIMIZED_DATA_FLAG_HAS_TIMESTAMPS,
               1200u,
               33u,
               1u,
               1u,
               4u,
               optimized_sample,
               sizeof(optimized_sample)) == LIBRDP_STATUS_OK);
    writes_before = capture.writes;
    CHECK(rdp_session_handle_video_optimized_data_message(
               session,
               &optimized_data,
               TEST_VIDEO_DATA_ID,
               packet.data,
               packet.length) == LIBRDP_STATUS_OK);
    CHECK(capture.data_events == 4u);
    CHECK(capture.writes == writes_before);
    CHECK(!session->video_optimized_presentations[0].recovery_notified);

    packet.length = 0u;
    CHECK(rdp_video_optimized_write_presentation_stop_request(
               &packet,
               9u) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_video_optimized_control_message(
               session,
               TEST_VIDEO_CONTROL_ID,
               packet.data,
               packet.length) == LIBRDP_STATUS_OK);
    CHECK(!session->video_optimized_presentations[0].active);

    packet.length = 0u;
    CHECK(rdp_video_optimized_write_presentation_start_request(
               &packet,
               10u,
               30u,
               2500u,
               640u,
               360u,
               640u,
               360u,
               1000u,
               geometry.video_window_id,
               rdp_video_optimized_h264_subtype_guid(),
               NULL,
               0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_video_optimized_control_message(
               session,
               TEST_VIDEO_CONTROL_ID,
               packet.data,
               packet.length) == LIBRDP_STATUS_OK);
    CHECK(!session->video_optimized_presentations[0].active);
    packet.length = 0u;
    CHECK(rdp_geometry_tracking_write_update(
              &packet,
              geometry.video_window_id,
              UINT64_C(0x8877665544332211),
              &mapping_bounds,
              &mapping_bounds,
              &mapping_bounds,
              &mapping_rect,
              1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_geometry_tracking_message(
              session,
              TEST_VIDEO_GEOMETRY_ID,
              packet.data,
              packet.length) == LIBRDP_STATUS_OK);
    packet.length = 0u;
    CHECK(rdp_video_optimized_write_presentation_start_request(
              &packet,
              10u,
              30u,
              2500u,
              640u,
              360u,
              640u,
              360u,
              1000u,
              geometry.video_window_id,
              rdp_video_optimized_h264_subtype_guid(),
              NULL,
              0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_video_optimized_control_message(
              session,
              TEST_VIDEO_CONTROL_ID,
              packet.data,
              packet.length) == LIBRDP_STATUS_OK);
    CHECK(session->video_optimized_presentations[0].active);
    packet.length = 0u;
    CHECK(rdp_video_optimized_write_video_data(
               &packet,
               10u,
               RDP_VIDEO_OPTIMIZED_DATA_FLAG_HAS_TIMESTAMPS,
               1300u,
               33u,
               1u,
               1u,
               1u,
               oversized_sample,
               sizeof(oversized_sample)) == LIBRDP_STATUS_OK);
    writes_before = capture.writes;
    CHECK(rdp_session_handle_video_optimized_data_message(
               session,
               &optimized_data,
               TEST_VIDEO_DATA_ID,
               packet.data,
               packet.length) == LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(capture.writes == writes_before);
    CHECK(capture.data_events == 4u);
    CHECK(session->video_optimized_presentations[0].sample_count == 0u);

    packet.length = 0u;
    CHECK(rdp_video_redirection_write_stream_only(
               &packet,
               11u,
               RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_STOPPED,
               presentation_id,
               7u) == LIBRDP_STATUS_OK);
    CHECK(test_video_tsmf_dispatch(session, &tsmf, &packet) ==
          LIBRDP_STATUS_OK);
    CHECK(!session->video_streams[0].active);
    rdp_session_emit_channel_close(session, &optimized_data);
    rdp_session_emit_channel_close(session, &tsmf);
    CHECK(capture.closes == 2u);
    CHECK(test_video_sink_matches(&capture,
                                  expected_sink,
                                  sizeof(expected_sink)));

    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(metrics.channel_out >= 7u);
    CHECK(metrics.limits_rejected == 1u);
    rdp_session_video_redirection_reset(session);
    rdp_session_video_optimized_reset(session);
    rdp_session_geometry_tracking_reset(session);
    CHECK(!rdp_session_video_runtime_active(session));
    CHECK(session->video_geometry_active_count == 0u);
    CHECK(session->geometry_tracking_active_count == 0u);

    session->video_optimized_control_channel_id = TEST_VIDEO_CONTROL_ID;
    session->video_optimized_control_channel_id_bytes =
        rdp_dynamic_channel_select_channel_id_bytes(TEST_VIDEO_CONTROL_ID);
    session->geometry_tracking_channel_id = TEST_VIDEO_GEOMETRY_ID;
    session->geometry_tracking_channel_id_bytes =
        rdp_dynamic_channel_select_channel_id_bytes(TEST_VIDEO_GEOMETRY_ID);
    packet.length = 0u;
    CHECK(rdp_geometry_tracking_write_update(
              &packet,
              geometry.video_window_id,
              UINT64_C(0x8877665544332211),
              &mapping_bounds,
              &mapping_bounds,
              &mapping_bounds,
              &mapping_rect,
              1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_geometry_tracking_message(
              session,
              TEST_VIDEO_GEOMETRY_ID,
              packet.data,
              packet.length) == LIBRDP_STATUS_OK);
    packet.length = 0u;
    CHECK(rdp_video_optimized_write_presentation_start_request(
              &packet,
              11u,
              30u,
              2500u,
              640u,
              360u,
              640u,
              360u,
              1000u,
              geometry.video_window_id,
              rdp_video_optimized_h264_subtype_guid(),
              NULL,
              0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_video_optimized_control_message(
              session,
              TEST_VIDEO_CONTROL_ID,
              packet.data,
              packet.length) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_video_runtime_active(session));
    rdp_session_video_optimized_reset(session);
    rdp_session_geometry_tracking_reset(session);
    CHECK(!rdp_session_video_runtime_active(session));

    rdp_buffer_free(&media_type);
    rdp_buffer_free(&visible);
    rdp_buffer_free(&nested);
    rdp_buffer_free(&packet);
    rdp_buffer_free(&tsmf.fragment);
    rdp_buffer_free(&optimized_data.fragment);
    librdp_session_free(session);
    librdp_settings_free(settings);
    rdp_buffer_free(&capture.wire);
    CHECK(fclose(capture.sink) == 0);
    return 0;
}

int main(void)
{
    return test_video_virtual_lifecycle();
}
