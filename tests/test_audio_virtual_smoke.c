/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic client audio-output runtime smoke.
 * Coverage: format negotiation, Wave2 and split-wave delivery, exactly-once
 * confirmation, UDP fragment ordering, close, late-data rejection and restart.
 * Bug classes: duplicate acknowledgements, stale fragment state, data delivery
 * after close, malformed tail lockup and reconnect-state leakage.
 * Determinism: an in-memory transport captures client channel responses and no
 * network or host audio device is used.
 */

#include <librdp/librdp.h>

#include "channels/audio_format.h"
#include "channels/audio_output.h"
#include "channels/virtual_channel.h"
#include "client/session_audio.h"
#include "client/session_internal.h"
#include "common/buffer.h"
#include "protocol/mcs.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
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

#define TEST_AUDIO_CHANNEL_ID 1007u
#define TEST_AUDIO_USER_ID 1005u

typedef struct test_audio_capture
{
    rdp_buffer bytes;
    uint32_t writes;
    uint32_t format_events;
    uint32_t data_events;
    uint32_t close_events;
    uint16_t last_timestamp;
    uint16_t last_format_no;
    uint8_t last_block_no;
    uint32_t last_audio_timestamp;
    uint8_t last_data[64];
    size_t last_data_len;
} test_audio_capture;

static librdp_status test_audio_capture_write(void* context,
                                              const void* data,
                                              size_t length,
                                              size_t* written_len)
{
    test_audio_capture* capture = (test_audio_capture*)context;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!capture || (!data && length > 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append(&capture->bytes, data, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    capture->writes++;
    if (written_len)
        *written_len = length;
    return LIBRDP_STATUS_OK;
}

static const rdp_transport_backend_ops TEST_AUDIO_TRANSPORT_OPS = {
    NULL,
    NULL,
    NULL,
    NULL,
    test_audio_capture_write,
    NULL,
};

static void test_audio_event(librdp_session* session,
                             const librdp_event* event,
                             void* user_data)
{
    test_audio_capture* capture = (test_audio_capture*)user_data;

    (void)session;
    if (!capture || !event)
        return;
    if (event->type == LIBRDP_EVENT_AUDIO_OUTPUT_FORMATS)
    {
        capture->format_events++;
    }
    else if (event->type == LIBRDP_EVENT_AUDIO_OUTPUT_DATA)
    {
        size_t copy_len = event->data.audio_output_data.data_len;

        if (copy_len > sizeof(capture->last_data))
            copy_len = sizeof(capture->last_data);
        capture->data_events++;
        capture->last_timestamp = event->data.audio_output_data.timestamp;
        capture->last_format_no = event->data.audio_output_data.format_no;
        capture->last_block_no = event->data.audio_output_data.block_no;
        capture->last_audio_timestamp =
            event->data.audio_output_data.audio_timestamp;
        capture->last_data_len = copy_len;
        if (copy_len > 0u)
            memcpy(capture->last_data,
                   event->data.audio_output_data.data,
                   copy_len);
    }
    else if (event->type == LIBRDP_EVENT_AUDIO_OUTPUT_CLOSE)
    {
        capture->close_events++;
    }
}

static void test_audio_wire_reset(test_audio_capture* capture)
{
    if (!capture)
        return;
    capture->bytes.length = 0u;
    capture->writes = 0u;
}

/*
 * Unwrap the sole static-channel response and validate that it is the expected
 * WaveConfirm. This catches duplicate confirms as well as responses emitted on
 * the wrong MCS channel.
 */
static int test_audio_parse_confirm(const test_audio_capture* capture,
                                    uint16_t expected_timestamp,
                                    uint8_t expected_block)
{
    rdp_tpkt tpkt;
    rdp_mcs_send_data_indication request;
    rdp_virtual_channel_packet packet;
    const uint8_t* x224_payload = NULL;
    size_t x224_payload_len = 0u;
    uint16_t timestamp = 0u;
    uint8_t block = 0u;

    if (!capture || capture->writes != 1u)
        return 0;
    if (rdp_tpkt_parse(capture->bytes.data,
                       capture->bytes.length,
                       &tpkt) != LIBRDP_STATUS_OK ||
        tpkt.total_len != capture->bytes.length ||
        rdp_x224_parse_data(tpkt.payload,
                            tpkt.payload_len,
                            &x224_payload,
                            &x224_payload_len) != LIBRDP_STATUS_OK ||
        rdp_mcs_parse_send_data_request(x224_payload,
                                        x224_payload_len,
                                        &request) != LIBRDP_STATUS_OK ||
        request.channel_id != TEST_AUDIO_CHANNEL_ID ||
        rdp_virtual_channel_parse_packet(request.payload,
                                         request.payload_len,
                                         &packet) != LIBRDP_STATUS_OK ||
        packet.length != packet.payload_len ||
        rdp_audio_output_parse_wave_confirm(packet.payload,
                                            packet.payload_len,
                                            &timestamp,
                                            &block) != LIBRDP_STATUS_OK)
        return 0;
    return timestamp == expected_timestamp && block == expected_block;
}

/*
 * Exercise one negotiated stream across valid data, malformed split framing,
 * UDP reorder rejection, close and a fresh negotiation epoch. Every state
 * transition is paired with event and wire-response assertions.
 */
static int test_audio_virtual_lifecycle(void)
{
    static const uint8_t wave_data[] = {
        0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u
    };
    static const uint8_t first_data[4] = {
        0x61u, 0x62u, 0x63u, 0x64u
    };
    static const uint8_t malformed_tail[] = {
        0x71u, 0x72u
    };
    static const uint8_t fragment_a[] = {
        0x81u, 0x82u
    };
    static const uint8_t fragment_b[] = {
        0x83u, 0x84u
    };
    static const uint8_t fragment_c[] = {
        0x85u, 0x86u
    };
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    test_audio_capture capture;
    rdp_audio_format pcm;
    rdp_buffer packet;
    librdp_metrics metrics;
    uint32_t data_events = 0u;

    memset(&capture, 0, sizeof(capture));
    memset(&pcm, 0, sizeof(pcm));
    rdp_buffer_init(&capture.bytes);
    rdp_buffer_init(&packet);
    pcm.format_tag = RDP_AUDIO_FORMAT_PCM;
    pcm.channels = 2u;
    pcm.samples_per_sec = 48000u;
    pcm.avg_bytes_per_sec = 192000u;
    pcm.block_align = 4u;
    pcm.bits_per_sample = 16u;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_enable_feature(settings,
                                         LIBRDP_FEATURE_AUDIO_OUTPUT,
                                         1) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    session->mcs_user_id = TEST_AUDIO_USER_ID;
    session->audio_output_channel_id = TEST_AUDIO_CHANNEL_ID;
    rdp_transport_attach_backend(&session->transport,
                                 &capture,
                                 &TEST_AUDIO_TRANSPORT_OPS);
    librdp_session_set_event_callback(session, test_audio_event, &capture);

    CHECK(rdp_audio_output_write_client_formats(&packet,
                                                RDP_AUDIO_OUTPUT_CAP_ALIVE,
                                                0xffffffffu,
                                                0x00010000u,
                                                0u,
                                                0u,
                                                6u,
                                                &pcm,
                                                1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_audio_output_message(session,
                                                  packet.data,
                                                  packet.length) ==
          LIBRDP_STATUS_OK);
    CHECK(session->audio_output_ready);
    CHECK(session->audio_output_selected_format_count == 1u);
    CHECK(capture.format_events == 1u);
    CHECK(capture.writes == 2u);

    packet.length = 0u;
    test_audio_wire_reset(&capture);
    CHECK(rdp_audio_output_write_wave2(&packet,
                                       17u,
                                       0u,
                                       3u,
                                       700u,
                                       wave_data,
                                       (uint16_t)sizeof(wave_data)) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_audio_output_message(session,
                                                  packet.data,
                                                  packet.length) ==
          LIBRDP_STATUS_OK);
    CHECK(capture.data_events == 1u);
    CHECK(capture.last_timestamp == 17u);
    CHECK(capture.last_format_no == 0u);
    CHECK(capture.last_block_no == 3u);
    CHECK(capture.last_audio_timestamp == 700u);
    CHECK(capture.last_data_len == sizeof(wave_data));
    CHECK(memcmp(capture.last_data, wave_data, sizeof(wave_data)) == 0);
    CHECK(test_audio_parse_confirm(&capture, 17u, 3u));

    packet.length = 0u;
    test_audio_wire_reset(&capture);
    CHECK(rdp_audio_output_write_wave_info(&packet,
                                           18u,
                                           0u,
                                           4u,
                                           first_data,
                                           3u) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_audio_output_message(session,
                                                  packet.data,
                                                  packet.length) ==
          LIBRDP_STATUS_OK);
    CHECK(session->audio_output_pending_wave);
    packet.length = 0u;
    CHECK(rdp_audio_output_write_wave_data(&packet,
                                           malformed_tail,
                                           sizeof(malformed_tail)) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_audio_output_message(session,
                                                  packet.data,
                                                  packet.length) ==
          LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(!session->audio_output_pending_wave);
    CHECK(session->audio_output_pending_data.length == 0u);
    CHECK(capture.writes == 0u);

    packet.length = 0u;
    CHECK(rdp_audio_output_write_udp_wave(&packet,
                                          5u,
                                          0u,
                                          fragment_a,
                                          sizeof(fragment_a)) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_audio_output_message(session,
                                                  packet.data,
                                                  packet.length) ==
          LIBRDP_STATUS_OK);
    CHECK(session->audio_output_udp_active);
    packet.length = 0u;
    CHECK(rdp_audio_output_write_udp_wave(&packet,
                                          5u,
                                          2u,
                                          fragment_b,
                                          sizeof(fragment_b)) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_audio_output_message(session,
                                                  packet.data,
                                                  packet.length) ==
          LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(!session->audio_output_udp_active);
    CHECK(session->audio_output_udp_data.length == 0u);

    packet.length = 0u;
    test_audio_wire_reset(&capture);
    data_events = capture.data_events;
    CHECK(rdp_audio_output_write_udp_wave(&packet,
                                          6u,
                                          0u,
                                          fragment_a,
                                          sizeof(fragment_a)) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_audio_output_message(session,
                                                  packet.data,
                                                  packet.length) ==
          LIBRDP_STATUS_OK);
    packet.length = 0u;
    CHECK(rdp_audio_output_write_udp_wave(&packet,
                                          6u,
                                          1u,
                                          fragment_b,
                                          sizeof(fragment_b)) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_audio_output_message(session,
                                                  packet.data,
                                                  packet.length) ==
          LIBRDP_STATUS_OK);
    packet.length = 0u;
    CHECK(rdp_audio_output_write_udp_wave_last(&packet,
                                               6u,
                                               19u,
                                               0u,
                                               6u,
                                               fragment_c,
                                               sizeof(fragment_c)) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_audio_output_message(session,
                                                  packet.data,
                                                  packet.length) ==
          LIBRDP_STATUS_OK);
    CHECK(capture.data_events == data_events + 1u);
    CHECK(capture.last_data_len == 6u);
    CHECK(memcmp(capture.last_data, fragment_a, sizeof(fragment_a)) == 0);
    CHECK(memcmp(capture.last_data + sizeof(fragment_a),
                 fragment_b,
                 sizeof(fragment_b)) == 0);
    CHECK(memcmp(capture.last_data + sizeof(fragment_a) +
                     sizeof(fragment_b),
                 fragment_c,
                 sizeof(fragment_c)) == 0);
    CHECK(test_audio_parse_confirm(&capture, 19u, 6u));
    CHECK(!session->audio_output_udp_active);

    packet.length = 0u;
    test_audio_wire_reset(&capture);
    data_events = capture.data_events;
    CHECK(rdp_audio_output_write_udp_wave_last(&packet,
                                               4u,
                                               20u,
                                               0u,
                                               7u,
                                               fragment_c,
                                               sizeof(fragment_c)) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_audio_output_message(session,
                                                  packet.data,
                                                  packet.length) ==
          LIBRDP_STATUS_OK);
    CHECK(capture.data_events == data_events + 1u);
    CHECK(capture.last_data_len == sizeof(fragment_c));
    CHECK(test_audio_parse_confirm(&capture, 20u, 7u));

    packet.length = 0u;
    test_audio_wire_reset(&capture);
    CHECK(rdp_audio_output_write_close(&packet) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_audio_output_message(session,
                                                  packet.data,
                                                  packet.length) ==
          LIBRDP_STATUS_OK);
    CHECK(!session->audio_output_ready);
    CHECK(session->audio_output_selected_format_count == 0u);
    CHECK(capture.close_events == 1u);
    CHECK(capture.writes == 0u);

    packet.length = 0u;
    data_events = capture.data_events;
    CHECK(rdp_audio_output_write_wave2(&packet,
                                       21u,
                                       0u,
                                       8u,
                                       800u,
                                       wave_data,
                                       (uint16_t)sizeof(wave_data)) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_audio_output_message(session,
                                                  packet.data,
                                                  packet.length) ==
          LIBRDP_STATUS_STATE);
    CHECK(capture.data_events == data_events);
    CHECK(capture.writes == 0u);

    packet.length = 0u;
    CHECK(rdp_audio_output_write_client_formats(&packet,
                                                RDP_AUDIO_OUTPUT_CAP_ALIVE,
                                                0xffffffffu,
                                                0x00010000u,
                                                0u,
                                                0u,
                                                6u,
                                                &pcm,
                                                1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_audio_output_message(session,
                                                  packet.data,
                                                  packet.length) ==
          LIBRDP_STATUS_OK);
    CHECK(session->audio_output_ready);
    CHECK(capture.format_events == 2u);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(metrics.channel_out >= 6u);

    rdp_buffer_free(&packet);
    librdp_session_free(session);
    rdp_buffer_free(&capture.bytes);
    librdp_settings_free(settings);
    return 0;
}

int main(void)
{
    return test_audio_virtual_lifecycle();
}
