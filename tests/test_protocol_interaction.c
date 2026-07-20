/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: focused protocol conformance suite.
 * Coverage: virtual channels, dynamic channels, pointer channels, input, and display-control conformance vectors.
 * Bug classes: fragmentation, malformed channel state, contact lifetime, coordinate overflow, and layout validation.
 * Determinism: all vectors and state are synthetic and remain local to this suite.
 */

#include "channels/core_input.h"
#include "channels/display_control.h"
#include "channels/dynamic_channel.h"
#include "channels/input_channel.h"
#include "channels/mouse_cursor.h"
#include "channels/virtual_channel.h"
#include "common/buffer.h"
#include "protocol/pointer.h"

#include <librdp/session.h>

#include <stdio.h>
#include <string.h>

#define PCHECK(expr)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

static uint16_t test_read_u16_le(const uint8_t* data)
{
    return (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
}
static uint32_t test_read_u32_le(const uint8_t* data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

/*
 * Runs virtual channels, dynamic channels, pointer channels, input, and display-control conformance vectors.
 */
int test_protocol_interaction_vectors(void)
{
    const uint8_t mouse_cursor_caps_confirm[] = {
        0x02, 0x00, 0x00, 0x00,
        0x43, 0x41, 0x50, 0x53,
        0x01, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x00, 0x00
    };
    const uint8_t mouse_cursor_hidden[] = {0x03, 0x05, 0x00, 0x00};
    const uint8_t mouse_cursor_default[] = {0x03, 0x06, 0x00, 0x00};
    const uint8_t mouse_cursor_position[] = {
        0x03, 0x08, 0x00, 0x00,
        0x22, 0x00,
        0x33, 0x00
    };
    const uint8_t mouse_cursor_cached[] = {
        0x03, 0x0a, 0x00, 0x00,
        0x05, 0x00
    };
    const uint8_t mouse_cursor_unknown[] = {0x03, 0xff, 0x00, 0x00};
    const uint8_t mouse_cursor_shape_32[] = {
        0x03, 0x0b, 0x00, 0x00,
        0x20, 0x00,
        0x05, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0x10, 0x00,
        0xff, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        0x00, 0xff, 0x00, 0xff,
        0x40, 0x00,
        0x00, 0x00
    };
    const uint8_t mouse_cursor_shape_bad_width[] = {
        0x03, 0x0b, 0x00, 0x00,
        0x20, 0x00,
        0x05, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x01, 0x02,
        0x02, 0x00,
        0x04, 0x00,
        0x10, 0x00,
        0xff, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        0x00, 0xff, 0x00, 0xff,
        0x40, 0x00,
        0x00, 0x00
    };
    const uint8_t mouse_cursor_shape_bad_hotspot[] = {
        0x03, 0x0b, 0x00, 0x00,
        0x20, 0x00,
        0x05, 0x00,
        0x02, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0x10, 0x00,
        0xff, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        0x00, 0xff, 0x00, 0xff,
        0x40, 0x00,
        0x00, 0x00
    };
    const uint8_t mouse_cursor_large_32[] = {
        0x03, 0x0c, 0x00, 0x00,
        0x20, 0x00,
        0x05, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0xff, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        0x00, 0xff, 0x00, 0xff,
        0x40, 0x00,
        0x00, 0x00
    };
    const uint8_t channel[] = {3, 0, 0, 0, 0x10, 0, 0, 0, 1, 2, 3};
    const uint8_t channel_fragment[] = {8, 0, 0, 0, RDP_VIRTUAL_CHANNEL_FLAG_FIRST, 0, 0, 0, 1, 2, 3};
    const uint8_t dyn_caps[] = {
        0x50, 0x00, 0x03, 0x00,
        0xa8, 0x03, 0xcc, 0x0c,
        0x92, 0x24, 0x55, 0x55
    };
    const uint8_t dyn_caps_zero[] = {0x50, 0x00, 0x00, 0x00};
    const uint8_t dyn_create[] = {0x18, 0x07, 'E', 'C', 'H', 'O', 0};
    const uint8_t dyn_data[] = {0x30, 0x07, 0xaa, 0xbb, 0xcc};
    const uint8_t dyn_data_first[] = {0x24, 0x07, 0x2c, 0x01, 0xaa, 0xbb, 0xcc};
    const uint8_t dyn_close[] = {0x40, 0x07};
    const uint8_t dyn_data_compressed[] = {0x70, 0x07, 0xe0, 0x06, 0xaa};
    const uint8_t dyn_data_first_compressed[] = {0x64, 0x07, 0x2c, 0x01, 0xe0, 0x06, 0xaa};
    const uint8_t dyn_soft_sync_request[] = {
        0x80, 0x00,
        0x16, 0x00, 0x00, 0x00,
        0x03, 0x00,
        0x01, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x34, 0x12, 0x00, 0x00
    };
    const uint8_t dyn_soft_sync_empty_request[] = {
        0x80, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x01, 0x00,
        0x00, 0x00
    };
    const uint8_t dyn_bad_header[] = {0x33};
    const uint8_t display_caps[] = {
        5, 0, 0, 0,
        20, 0, 0, 0,
        16, 0, 0, 0,
        0, 32, 0, 0,
        0, 32, 0, 0
    };
    const uint8_t core_response[] = {
        3, 2, 0, 0,
        0, 1, 0, 1,
        0, 0, 0, 0,
        0, 0, 0, 0
    };
    const uint8_t input_sc_ready_v300[] = {
        0x01, 0x00,
        0x0e, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00,
        0x01, 0x00, 0x00, 0x00
    };
    const uint8_t input_sc_ready_v300_no_pen[] = {
        0x01, 0x00,
        0x0e, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    const uint8_t input_sc_ready_v200[] = {
        0x01, 0x00,
        0x0a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00
    };
    const uint16_t dyn_priority_charge[4] = {
        RDP_DYNAMIC_CHANNEL_PRIORITY_CHARGE_0,
        RDP_DYNAMIC_CHANNEL_PRIORITY_CHARGE_1,
        RDP_DYNAMIC_CHANNEL_PRIORITY_CHARGE_2,
        RDP_DYNAMIC_CHANNEL_PRIORITY_CHARGE_3
    };
    rdp_pointer_update pointer_update;
    rdp_virtual_channel_packet vc;
    rdp_dynamic_channel_header dyn_header;
    rdp_dynamic_channel_capabilities dyn_parsed_caps;
    rdp_dynamic_channel_create_request dyn_create_request;
    rdp_dynamic_channel_create_response dyn_create_response;
    rdp_dynamic_channel_data_pdu dyn_data_pdu;
    rdp_dynamic_channel_data_first_pdu dyn_first_pdu;
    rdp_dynamic_channel_close_pdu dyn_close_pdu;
    rdp_dynamic_channel_compressed_data_pdu dyn_compressed_pdu;
    rdp_dynamic_channel_compressed_data_first_pdu dyn_first_compressed_pdu;
    rdp_dynamic_channel_soft_sync_request dyn_soft_sync;
    rdp_dynamic_channel_soft_sync_channel_list dyn_soft_sync_list;
    rdp_dynamic_channel_soft_sync_response dyn_soft_sync_response;
    rdp_mouse_cursor_header mouse_cursor_header;
    rdp_mouse_cursor_capset mouse_cursor_capset;
    rdp_core_input_header core_header;
    rdp_core_input_init_response core_init_response;
    rdp_core_input_negotiation core_negotiation;
    rdp_core_input_event core_events[8];
    uint8_t core_event_count = 0;
    rdp_input_channel_header input_header;
    rdp_input_channel_sc_ready input_sc_ready;
    rdp_input_channel_cs_ready input_cs_ready;
    rdp_input_channel_cs_ready valid_input_cs_ready;
    rdp_input_channel_negotiation input_negotiation;
    rdp_input_channel_touch_contact input_touch_contact;
    rdp_input_channel_touch_frame input_touch_frame;
    rdp_input_channel_touch_event input_touch_event;
    rdp_input_channel_touch_event valid_input_touch_event;
    rdp_input_channel_pen_contact input_pen_contact;
    rdp_input_channel_pen_frame input_pen_frame;
    rdp_input_channel_pen_event input_pen_event;
    rdp_input_channel_pen_event valid_input_pen_event;
    uint8_t input_contact_id = 0;
    rdp_display_control_caps display_parsed_caps;
    rdp_display_control_monitor display_monitor;
    rdp_display_control_monitor display_monitors[2];
    uint8_t display_mutated[96];
    uint8_t display_bad_caps[20];
    uint32_t display_monitor_count = 0;
    rdp_buffer decoded_pointer;
    rdp_buffer channel_packet;
    rdp_buffer dyn_response;
    uint32_t error_info = 0;
    size_t pointer_stride = 0;

    rdp_buffer_init(&decoded_pointer);
    rdp_buffer_init(&channel_packet);
    rdp_buffer_init(&dyn_response);

    PCHECK(rdp_virtual_channel_parse_packet(channel, sizeof(channel), &vc) == LIBRDP_STATUS_OK);
    PCHECK(vc.length == 3 && vc.flags == 0x10 && vc.payload[2] == 3);
    PCHECK(rdp_virtual_channel_parse_packet(channel_fragment, sizeof(channel_fragment), &vc) == LIBRDP_STATUS_OK);
    PCHECK(vc.length == 8 && vc.flags == RDP_VIRTUAL_CHANNEL_FLAG_FIRST && vc.payload_len == 3 && vc.payload[2] == 3);
    PCHECK(rdp_virtual_channel_write_packet(&channel_packet, dyn_create, sizeof(dyn_create), 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_virtual_channel_parse_packet(channel_packet.data, channel_packet.length, &vc) == LIBRDP_STATUS_OK);
    PCHECK(vc.length == sizeof(dyn_create) && vc.flags == 3 && memcmp(vc.payload, dyn_create, sizeof(dyn_create)) == 0);
    channel_packet.length = 0;
    PCHECK(rdp_virtual_channel_write_fragment(
               &channel_packet,
               dyn_create,
               2,
               sizeof(dyn_create),
               RDP_VIRTUAL_CHANNEL_FLAG_FIRST) == LIBRDP_STATUS_OK);
    PCHECK(rdp_virtual_channel_parse_packet(channel_packet.data,
                                            channel_packet.length,
                                            &vc) == LIBRDP_STATUS_OK);
    PCHECK(vc.length == sizeof(dyn_create) && vc.payload_len == 2 &&
           (vc.flags & RDP_VIRTUAL_CHANNEL_FLAG_FIRST) != 0);
    PCHECK(rdp_virtual_channel_write_fragment(
               NULL,
               dyn_create,
               2,
               sizeof(dyn_create),
               RDP_VIRTUAL_CHANNEL_FLAG_FIRST) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_virtual_channel_write_fragment(
               &channel_packet,
               dyn_create,
               2,
               1,
               RDP_VIRTUAL_CHANNEL_FLAG_LAST) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_parse_header(dyn_caps, sizeof(dyn_caps), &dyn_header) == LIBRDP_STATUS_OK);
    PCHECK(dyn_header.command == RDP_DYNAMIC_CHANNEL_CMD_CAPABILITIES && dyn_header.channel_id_bytes == 1);
    {
        rdp_dynamic_channel_header valid_dyn_header = dyn_header;

        PCHECK(rdp_dynamic_channel_parse_header(dyn_bad_header, sizeof(dyn_bad_header), &dyn_header) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_header, &valid_dyn_header, sizeof(dyn_header)) == 0);
    }
    PCHECK(rdp_dynamic_channel_parse_capabilities(dyn_caps, sizeof(dyn_caps), &dyn_parsed_caps) ==
           LIBRDP_STATUS_OK);
    PCHECK(dyn_parsed_caps.version == 3 &&
           dyn_parsed_caps.has_priority_charges &&
           dyn_parsed_caps.priority_charge[0] == 936 &&
           dyn_parsed_caps.priority_charge[1] == 3276 &&
           dyn_parsed_caps.priority_charge[2] == 9362 &&
           dyn_parsed_caps.priority_charge[3] == 21845);
    {
        rdp_dynamic_channel_capabilities valid_dyn_caps = dyn_parsed_caps;

        PCHECK(rdp_dynamic_channel_parse_capabilities(dyn_caps_zero,
                                                      sizeof(dyn_caps_zero),
                                                      &dyn_parsed_caps) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_parsed_caps, &valid_dyn_caps, sizeof(dyn_parsed_caps)) == 0);
    }
    PCHECK(rdp_dynamic_channel_select_version(0) == 0 &&
           rdp_dynamic_channel_select_version(1) == 1 &&
           rdp_dynamic_channel_select_version(2) == 2 &&
           rdp_dynamic_channel_select_version(3) == 3 &&
           rdp_dynamic_channel_select_version(4) == 3);
    PCHECK(rdp_dynamic_channel_select_channel_id_bytes(0xffu) == 1 &&
           rdp_dynamic_channel_select_channel_id_bytes(0x100u) == 2 &&
           rdp_dynamic_channel_select_channel_id_bytes(0x10000u) == 4);
    PCHECK(rdp_dynamic_channel_data_pdu_header_size(1) == 2 &&
           rdp_dynamic_channel_data_pdu_header_size(2) == 3 &&
           rdp_dynamic_channel_data_pdu_header_size(3) == 0 &&
           rdp_dynamic_channel_data_first_pdu_header_size(1, 0xffu) == 3 &&
           rdp_dynamic_channel_data_first_pdu_header_size(1, 0x100u) == 4 &&
           rdp_dynamic_channel_data_first_pdu_header_size(1, 0x10000u) == 6);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_capabilities_request(
               &dyn_response,
               3u,
               dyn_priority_charge) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 12u &&
           dyn_response.data[0] == 0x50u);
    PCHECK(rdp_dynamic_channel_parse_capabilities(
               dyn_response.data,
               dyn_response.length,
               &dyn_parsed_caps) == LIBRDP_STATUS_OK);
    PCHECK(dyn_parsed_caps.version == 3u &&
           dyn_parsed_caps.has_priority_charges &&
           memcmp(dyn_parsed_caps.priority_charge,
                  dyn_priority_charge,
                  sizeof(dyn_priority_charge)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_capabilities_request(
               &dyn_response,
               1u,
               NULL) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 4u);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_capabilities_request(
               &dyn_response,
               2u,
               NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_write_capabilities_response(&dyn_response, 1) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 4 && dyn_response.data[0] == 0x50 && dyn_response.data[2] == 1);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_capabilities_response(&dyn_response, 2) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 4 && dyn_response.data[0] == 0x50 && dyn_response.data[2] == 2);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_capabilities_response(&dyn_response, 3) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 4 && dyn_response.data[0] == 0x50 && dyn_response.data[2] == 3);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_capabilities_response(&dyn_response, 4) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_parse_create_request(dyn_create,
                                                    sizeof(dyn_create),
                                                    &dyn_create_request) == LIBRDP_STATUS_OK);
    PCHECK(dyn_create_request.channel_id == 7 && dyn_create_request.channel_id_bytes == 1 &&
           dyn_create_request.priority == 2 &&
           dyn_create_request.name_len == 4 && memcmp(dyn_create_request.name, "ECHO", 4) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_create_request(&dyn_response,
                                                    0x1234u,
                                                    2,
                                                    2,
                                                    "APP",
                                                    3) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 7 && dyn_response.data[0] == 0x19 &&
           test_read_u16_le(dyn_response.data + 1) == 0x1234u &&
           memcmp(dyn_response.data + 3, "APP", 4) == 0);
    PCHECK(rdp_dynamic_channel_parse_create_request(dyn_response.data,
                                                    dyn_response.length,
                                                    &dyn_create_request) == LIBRDP_STATUS_OK);
    PCHECK(dyn_create_request.channel_id == 0x1234u && dyn_create_request.channel_id_bytes == 2 &&
           dyn_create_request.priority == 2 &&
           dyn_create_request.name_len == 3 && memcmp(dyn_create_request.name, "APP", 3) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_create_request(&dyn_response,
                                                    15,
                                                    1,
                                                    3,
                                                    "Microsoft::Windows::RDS::Notify",
                                                    sizeof("Microsoft::Windows::RDS::Notify") - 1u) ==
           LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof("Microsoft::Windows::RDS::Notify") + 2u &&
           dyn_response.data[0] == 0x1c && dyn_response.data[1] == 15);
    PCHECK(rdp_dynamic_channel_parse_create_request(dyn_response.data,
                                                    dyn_response.length,
                                                    &dyn_create_request) == LIBRDP_STATUS_OK);
    PCHECK(dyn_create_request.channel_id == 15 && dyn_create_request.channel_id_bytes == 1 &&
           dyn_create_request.priority == 3 &&
           dyn_create_request.name_len == sizeof("Microsoft::Windows::RDS::Notify") - 1u &&
           memcmp(dyn_create_request.name,
                  "Microsoft::Windows::RDS::Notify",
                  sizeof("Microsoft::Windows::RDS::Notify") - 1u) == 0);
    PCHECK(rdp_dynamic_channel_write_create_request(&dyn_response,
                                                    1,
                                                    1,
                                                    0,
                                                    NULL,
                                                    0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    {
        rdp_dynamic_channel_create_request valid_dyn_create_request = dyn_create_request;

        PCHECK(rdp_dynamic_channel_parse_create_request(dyn_data,
                                                        sizeof(dyn_data),
                                                        &dyn_create_request) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_create_request,
                      &valid_dyn_create_request,
                      sizeof(dyn_create_request)) == 0);
    }
    PCHECK(rdp_dynamic_channel_write_create_response(&dyn_response,
                                                     7,
                                                     1,
                                                     RDP_DYNAMIC_CHANNEL_STATUS_OK) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 6 && dyn_response.data[0] == 0x10 && dyn_response.data[1] == 7 &&
           test_read_u32_le(dyn_response.data + 2) == 0);
    PCHECK(rdp_dynamic_channel_parse_create_response(dyn_response.data,
                                                     dyn_response.length,
                                                     &dyn_create_response) == LIBRDP_STATUS_OK);
    PCHECK(dyn_create_response.channel_id == 7 &&
           dyn_create_response.channel_id_bytes == 1 &&
           dyn_create_response.status_code == RDP_DYNAMIC_CHANNEL_STATUS_OK);
    {
        rdp_dynamic_channel_create_response valid_dyn_create_response = dyn_create_response;

        PCHECK(rdp_dynamic_channel_parse_create_response(dyn_response.data,
                                                         dyn_response.length - 1u,
                                                         &dyn_create_response) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_create_response,
                      &valid_dyn_create_response,
                      sizeof(dyn_create_response)) == 0);
        PCHECK(rdp_dynamic_channel_parse_create_request(dyn_response.data,
                                                        dyn_response.length,
                                                        &dyn_create_request) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_create_response,
                      &valid_dyn_create_response,
                      sizeof(dyn_create_response)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_parse_data(dyn_data, sizeof(dyn_data), &dyn_data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_data_pdu.channel_id == 7 && dyn_data_pdu.data_len == 3 && dyn_data_pdu.data[0] == 0xaa);
    {
        rdp_dynamic_channel_data_pdu valid_dyn_data_pdu = dyn_data_pdu;
        uint8_t high_dyn_data_priority[sizeof(dyn_data)];

        memcpy(high_dyn_data_priority, dyn_data, sizeof(high_dyn_data_priority));
        high_dyn_data_priority[0] = 0x3cu;
        PCHECK(rdp_dynamic_channel_parse_data(high_dyn_data_priority,
                                              sizeof(high_dyn_data_priority),
                                              &dyn_data_pdu) == LIBRDP_STATUS_OK);
        PCHECK(dyn_data_pdu.channel_id == valid_dyn_data_pdu.channel_id &&
               dyn_data_pdu.channel_id_bytes == valid_dyn_data_pdu.channel_id_bytes &&
               dyn_data_pdu.data_len == valid_dyn_data_pdu.data_len &&
               memcmp(dyn_data_pdu.data, valid_dyn_data_pdu.data, dyn_data_pdu.data_len) == 0);
        valid_dyn_data_pdu = dyn_data_pdu;
        PCHECK(rdp_dynamic_channel_parse_data(dyn_create,
                                              sizeof(dyn_create),
                                              &dyn_data_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_data_pdu, &valid_dyn_data_pdu, sizeof(dyn_data_pdu)) == 0);
    }
    PCHECK(rdp_dynamic_channel_parse_data(dyn_data, sizeof(dyn_data), &dyn_data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(rdp_dynamic_channel_write_data(&dyn_response,
                                          dyn_data_pdu.channel_id,
                                          dyn_data_pdu.channel_id_bytes,
                                          dyn_data_pdu.data,
                                          dyn_data_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(dyn_data) && memcmp(dyn_response.data, dyn_data, sizeof(dyn_data)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_data(&dyn_response,
                                          0x00123456u,
                                          4,
                                          dyn_data_pdu.data,
                                          dyn_data_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 8 && dyn_response.data[0] == 0x32 &&
           test_read_u32_le(dyn_response.data + 1) == 0x00123456u &&
           memcmp(dyn_response.data + 5, dyn_data_pdu.data, dyn_data_pdu.data_len) == 0);
    PCHECK(rdp_dynamic_channel_parse_data(dyn_response.data, dyn_response.length, &dyn_data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_data_pdu.channel_id == 0x00123456u &&
           dyn_data_pdu.channel_id_bytes == 4 &&
           dyn_data_pdu.data_len == 3);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_data_ex(&dyn_response,
                                             7,
                                             1,
                                             2,
                                             dyn_data_pdu.data,
                                             dyn_data_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 5 && dyn_response.data[0] == 0x38 && dyn_response.data[1] == 7);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_data_ex(&dyn_response,
                                             7,
                                             1,
                                             3,
                                             dyn_data_pdu.data,
                                             dyn_data_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 5 && dyn_response.data[0] == 0x3c && dyn_response.data[1] == 7);
    PCHECK(rdp_dynamic_channel_parse_data(dyn_response.data, dyn_response.length, &dyn_data_pdu) ==
           LIBRDP_STATUS_OK);
    PCHECK(dyn_data_pdu.channel_id == 7 && dyn_data_pdu.channel_id_bytes == 1 &&
           dyn_data_pdu.data_len == 3);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_data(&dyn_response, 0x100u, 1, dyn_data, sizeof(dyn_data)) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_parse_data_first(dyn_data_first,
                                                sizeof(dyn_data_first),
                                                &dyn_first_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_first_pdu.channel_id == 7 &&
           dyn_first_pdu.channel_id_bytes == 1 &&
           dyn_first_pdu.total_length == 300 &&
           dyn_first_pdu.data_len == 3 &&
           dyn_first_pdu.data[2] == 0xcc);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_write_data_first(&dyn_response,
                                                dyn_first_pdu.channel_id,
                                                dyn_first_pdu.channel_id_bytes,
                                                dyn_first_pdu.total_length,
                                                dyn_first_pdu.data,
                                                dyn_first_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(dyn_data_first) &&
           memcmp(dyn_response.data, dyn_data_first, sizeof(dyn_data_first)) == 0);
    PCHECK(rdp_dynamic_channel_parse_data_first(dyn_data_first,
                                                sizeof(dyn_data_first) - 1u,
                                                &dyn_first_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_first_pdu.data_len == 2);
    {
        uint8_t bad_dyn_data_first[sizeof(dyn_data_first)];
        rdp_dynamic_channel_data_first_pdu valid_dyn_first_pdu = dyn_first_pdu;

        memcpy(bad_dyn_data_first, dyn_data_first, sizeof(bad_dyn_data_first));
        bad_dyn_data_first[2] = 2u;
        bad_dyn_data_first[3] = 0u;
        PCHECK(rdp_dynamic_channel_parse_data_first(bad_dyn_data_first,
                                                    sizeof(bad_dyn_data_first),
                                                    &dyn_first_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_first_pdu, &valid_dyn_first_pdu, sizeof(dyn_first_pdu)) == 0);
        PCHECK(rdp_dynamic_channel_parse_data_first((const uint8_t[]){0x20, 0x07, 0x00},
                                                    3,
                                                    &dyn_first_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_first_pdu, &valid_dyn_first_pdu, sizeof(dyn_first_pdu)) == 0);
    }
    PCHECK(rdp_dynamic_channel_write_data_first(&dyn_response, 7, 1, 0, NULL, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_write_data_first(&dyn_response,
                                                7,
                                                1,
                                                300,
                                                dyn_data_first,
                                                RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_parse_close(dyn_close, sizeof(dyn_close), &dyn_close_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_close_pdu.channel_id == 7 && dyn_close_pdu.channel_id_bytes == 1);
    {
        rdp_dynamic_channel_close_pdu valid_dyn_close_pdu = dyn_close_pdu;

        PCHECK(rdp_dynamic_channel_parse_close(dyn_data,
                                               sizeof(dyn_data),
                                               &dyn_close_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_close_pdu, &valid_dyn_close_pdu, sizeof(dyn_close_pdu)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_write_close(&dyn_response, 0x1234u, 2) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 3 && dyn_response.data[0] == 0x41 &&
           test_read_u16_le(dyn_response.data + 1) == 0x1234u);
    PCHECK(rdp_dynamic_channel_parse_close(dyn_response.data, dyn_response.length, &dyn_close_pdu) ==
           LIBRDP_STATUS_OK);
    PCHECK(dyn_close_pdu.channel_id == 0x1234u && dyn_close_pdu.channel_id_bytes == 2);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_close(&dyn_response, 0x10000u, 2) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_parse_compressed_data(dyn_data_compressed,
                                                     sizeof(dyn_data_compressed),
                                                     &dyn_compressed_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_compressed_pdu.channel_id == 7 &&
           dyn_compressed_pdu.channel_id_bytes == 1 &&
           dyn_compressed_pdu.data_len == 3 &&
           dyn_compressed_pdu.data[0] == 0xe0);
    {
        rdp_dynamic_channel_compressed_data_pdu valid_dyn_compressed_pdu = dyn_compressed_pdu;
        uint8_t high_dyn_compressed_priority[sizeof(dyn_data_compressed)];

        memcpy(high_dyn_compressed_priority, dyn_data_compressed, sizeof(high_dyn_compressed_priority));
        high_dyn_compressed_priority[0] = 0x7cu;
        PCHECK(rdp_dynamic_channel_parse_compressed_data(high_dyn_compressed_priority,
                                                         sizeof(high_dyn_compressed_priority),
                                                         &dyn_compressed_pdu) == LIBRDP_STATUS_OK);
        PCHECK(dyn_compressed_pdu.channel_id == valid_dyn_compressed_pdu.channel_id &&
               dyn_compressed_pdu.channel_id_bytes == valid_dyn_compressed_pdu.channel_id_bytes &&
               dyn_compressed_pdu.data_len == valid_dyn_compressed_pdu.data_len &&
               memcmp(dyn_compressed_pdu.data,
                      valid_dyn_compressed_pdu.data,
                      dyn_compressed_pdu.data_len) == 0);
        valid_dyn_compressed_pdu = dyn_compressed_pdu;
        PCHECK(rdp_dynamic_channel_parse_compressed_data(dyn_data,
                                                         sizeof(dyn_data),
                                                         &dyn_compressed_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_compressed_pdu,
                      &valid_dyn_compressed_pdu,
                      sizeof(dyn_compressed_pdu)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_parse_compressed_data(dyn_data_compressed,
                                                     sizeof(dyn_data_compressed),
                                                     &dyn_compressed_pdu) == LIBRDP_STATUS_OK);
    PCHECK(rdp_dynamic_channel_write_compressed_data(&dyn_response,
                                                     dyn_compressed_pdu.channel_id,
                                                     dyn_compressed_pdu.channel_id_bytes,
                                                     dyn_compressed_pdu.data,
                                                     dyn_compressed_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(dyn_data_compressed) &&
           memcmp(dyn_response.data, dyn_data_compressed, sizeof(dyn_data_compressed)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_compressed_data(&dyn_response,
                                                     7,
                                                     1,
                                                     dyn_compressed_pdu.data,
                                                     1u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_parse_compressed_data_first(dyn_data_first_compressed,
                                                           sizeof(dyn_data_first_compressed),
                                                           &dyn_first_compressed_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_first_compressed_pdu.channel_id == 7 &&
           dyn_first_compressed_pdu.total_length == 300 &&
           dyn_first_compressed_pdu.data_len == 3 &&
           dyn_first_compressed_pdu.data[1] == 0x06);
    {
        uint8_t bad_dyn_first_compressed[sizeof(dyn_data_first_compressed)];
        rdp_dynamic_channel_compressed_data_first_pdu valid_dyn_first_compressed_pdu =
            dyn_first_compressed_pdu;

        memcpy(bad_dyn_first_compressed,
               dyn_data_first_compressed,
               sizeof(bad_dyn_first_compressed));
        bad_dyn_first_compressed[2] = 0u;
        bad_dyn_first_compressed[3] = 0u;
        PCHECK(rdp_dynamic_channel_parse_compressed_data_first(
                   bad_dyn_first_compressed,
                   sizeof(bad_dyn_first_compressed),
                   &dyn_first_compressed_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_first_compressed_pdu,
                      &valid_dyn_first_compressed_pdu,
                      sizeof(dyn_first_compressed_pdu)) == 0);
        bad_dyn_first_compressed[2] = 2u;
        bad_dyn_first_compressed[3] = 0u;
        PCHECK(rdp_dynamic_channel_parse_compressed_data_first(
                   bad_dyn_first_compressed,
                   sizeof(bad_dyn_first_compressed),
                   &dyn_first_compressed_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_first_compressed_pdu,
                      &valid_dyn_first_compressed_pdu,
                      sizeof(dyn_first_compressed_pdu)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_write_compressed_data_first(&dyn_response,
                                                           dyn_first_compressed_pdu.channel_id,
                                                           dyn_first_compressed_pdu.channel_id_bytes,
                                                           dyn_first_compressed_pdu.total_length,
                                                           dyn_first_compressed_pdu.data,
                                                           dyn_first_compressed_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(dyn_data_first_compressed) &&
           memcmp(dyn_response.data, dyn_data_first_compressed, sizeof(dyn_data_first_compressed)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_compressed_data_first(&dyn_response,
                                                           7,
                                                           1,
                                                           1,
                                                           dyn_first_compressed_pdu.data,
                                                           dyn_first_compressed_pdu.data_len) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_parse_soft_sync_request(dyn_soft_sync_request,
                                                       sizeof(dyn_soft_sync_request),
                                                       &dyn_soft_sync) == LIBRDP_STATUS_OK);
    PCHECK(dyn_soft_sync.length == 22 &&
           dyn_soft_sync.flags == (RDP_DYNAMIC_CHANNEL_SOFT_SYNC_TCP_FLUSHED |
                                   RDP_DYNAMIC_CHANNEL_SOFT_SYNC_CHANNEL_LIST_PRESENT) &&
           dyn_soft_sync.tunnel_count == 1);
    {
        uint8_t bad_dyn_soft_sync_request[sizeof(dyn_soft_sync_request)];
        rdp_dynamic_channel_soft_sync_request valid_dyn_soft_sync = dyn_soft_sync;

        memcpy(bad_dyn_soft_sync_request,
               dyn_soft_sync_request,
               sizeof(bad_dyn_soft_sync_request));
        bad_dyn_soft_sync_request[6] = 0u;
        bad_dyn_soft_sync_request[7] = 0u;
        PCHECK(rdp_dynamic_channel_parse_soft_sync_request(
                   bad_dyn_soft_sync_request,
                   sizeof(bad_dyn_soft_sync_request),
                   &dyn_soft_sync) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_soft_sync, &valid_dyn_soft_sync, sizeof(dyn_soft_sync)) == 0);
    }
    PCHECK(rdp_dynamic_channel_soft_sync_request_get_list(&dyn_soft_sync,
                                                          0,
                                                          &dyn_soft_sync_list) == LIBRDP_STATUS_OK);
    PCHECK(dyn_soft_sync_list.tunnel_type == RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE &&
           dyn_soft_sync_list.channel_count == 2);
    {
        uint8_t bad_list[14];
        rdp_dynamic_channel_soft_sync_request bad_soft_sync = dyn_soft_sync;
        rdp_dynamic_channel_soft_sync_channel_list valid_dyn_soft_sync_list =
            dyn_soft_sync_list;

        PCHECK(dyn_soft_sync.lists_len == sizeof(bad_list));
        memcpy(bad_list, dyn_soft_sync.lists, sizeof(bad_list));
        bad_list[0] = 0xffu;
        bad_soft_sync.lists = bad_list;
        PCHECK(rdp_dynamic_channel_soft_sync_request_get_list(&bad_soft_sync,
                                                              0,
                                                              &dyn_soft_sync_list) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_soft_sync_list,
                      &valid_dyn_soft_sync_list,
                      sizeof(dyn_soft_sync_list)) == 0);
        PCHECK(rdp_dynamic_channel_soft_sync_request_get_list(&dyn_soft_sync,
                                                              1,
                                                              &dyn_soft_sync_list) ==
               LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(memcmp(&dyn_soft_sync_list,
                      &valid_dyn_soft_sync_list,
                      sizeof(dyn_soft_sync_list)) == 0);
    }
    PCHECK(rdp_dynamic_channel_soft_sync_channel_list_get_id(&dyn_soft_sync_list,
                                                             0,
                                                             &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 7);
    PCHECK(rdp_dynamic_channel_soft_sync_channel_list_get_id(&dyn_soft_sync_list,
                                                             1,
                                                             &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 0x1234u);
    PCHECK(rdp_dynamic_channel_parse_soft_sync_request(dyn_soft_sync_empty_request,
                                                       sizeof(dyn_soft_sync_empty_request),
                                                       &dyn_soft_sync) == LIBRDP_STATUS_OK);
    PCHECK(dyn_soft_sync.length == 8 &&
           dyn_soft_sync.flags == RDP_DYNAMIC_CHANNEL_SOFT_SYNC_TCP_FLUSHED &&
           dyn_soft_sync.tunnel_count == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_soft_sync_response(&dyn_response, NULL, 0) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 6 &&
           dyn_response.data[0] == (uint8_t)(RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_RESPONSE << 4) &&
           test_read_u32_le(dyn_response.data + 2) == 0);
    PCHECK(rdp_dynamic_channel_parse_soft_sync_response(dyn_response.data,
                                                        dyn_response.length,
                                                        &dyn_soft_sync_response) == LIBRDP_STATUS_OK);
    PCHECK(dyn_soft_sync_response.tunnel_count == 0);
    dyn_response.length = 0;
    error_info = RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY;
    PCHECK(rdp_dynamic_channel_write_soft_sync_response(&dyn_response, &error_info, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_dynamic_channel_parse_soft_sync_response(dyn_response.data,
                                                        dyn_response.length,
                                                        &dyn_soft_sync_response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_dynamic_channel_soft_sync_response_get_tunnel(&dyn_soft_sync_response,
                                                             0,
                                                             &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY);
    {
        uint32_t valid_error_info = error_info;
        rdp_dynamic_channel_soft_sync_response valid_response = dyn_soft_sync_response;

        dyn_response.data[6] = 0xffu;
        PCHECK(rdp_dynamic_channel_parse_soft_sync_response(dyn_response.data,
                                                            dyn_response.length,
                                                            &dyn_soft_sync_response) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_soft_sync_response,
                      &valid_response,
                      sizeof(dyn_soft_sync_response)) == 0);
        PCHECK(rdp_dynamic_channel_soft_sync_response_get_tunnel(&dyn_soft_sync_response,
                                                                 0,
                                                                 &error_info) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(error_info == valid_error_info);
        dyn_response.data[6] = RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY;
    }
    {
        uint32_t invalid_tunnel = 0x12345678u;

        dyn_response.length = 0;
        PCHECK(rdp_buffer_append_u8(&dyn_response, 0xa5u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_dynamic_channel_write_soft_sync_response(&dyn_response,
                                                            &invalid_tunnel,
                                                            1) == LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(dyn_response.length == 1u && dyn_response.data[0] == 0xa5u);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_mouse_cursor_write_caps_advertise(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 16 &&
           dyn_response.data[0] == RDP_MOUSE_CURSOR_PDU_CS_CAPS_ADVERTISE &&
           dyn_response.data[1] == 0 &&
           test_read_u16_le(dyn_response.data + 2) == 0 &&
           test_read_u32_le(dyn_response.data + 4) == RDP_MOUSE_CURSOR_CAPSET_SIGNATURE &&
           test_read_u32_le(dyn_response.data + 8) == RDP_MOUSE_CURSOR_CAPSET_VERSION1 &&
           test_read_u32_le(dyn_response.data + 12) == RDP_MOUSE_CURSOR_CAPSET_SIZE_VERSION1);
    PCHECK(rdp_mouse_cursor_parse_header(dyn_response.data,
                                         dyn_response.length,
                                         &mouse_cursor_header) == LIBRDP_STATUS_OK);
    PCHECK(mouse_cursor_header.pdu_type == RDP_MOUSE_CURSOR_PDU_CS_CAPS_ADVERTISE &&
           mouse_cursor_header.update_type == 0);
    PCHECK(rdp_mouse_cursor_parse_caps_confirm(mouse_cursor_caps_confirm,
                                               sizeof(mouse_cursor_caps_confirm),
                                               &mouse_cursor_capset) == LIBRDP_STATUS_OK);
    PCHECK(mouse_cursor_capset.signature == RDP_MOUSE_CURSOR_CAPSET_SIGNATURE &&
           mouse_cursor_capset.version == RDP_MOUSE_CURSOR_CAPSET_VERSION1 &&
           mouse_cursor_capset.size == RDP_MOUSE_CURSOR_CAPSET_SIZE_VERSION1);
    {
        rdp_mouse_cursor_capset valid_mouse_cursor_capset = mouse_cursor_capset;

        PCHECK(rdp_mouse_cursor_parse_caps_confirm(mouse_cursor_caps_confirm,
                                                   sizeof(mouse_cursor_caps_confirm) - 1u,
                                                   &mouse_cursor_capset) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&mouse_cursor_capset,
                      &valid_mouse_cursor_capset,
                      sizeof(mouse_cursor_capset)) == 0);
    }
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_hidden,
                                         sizeof(mouse_cursor_hidden),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_NULL);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_default,
                                         sizeof(mouse_cursor_default),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_DEFAULT);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_position,
                                         sizeof(mouse_cursor_position),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_POSITION &&
           pointer_update.x == 0x22 && pointer_update.y == 0x33);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_cached,
                                         sizeof(mouse_cursor_cached),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_CACHED && pointer_update.cache_index == 5);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_shape_32,
                                         sizeof(mouse_cursor_shape_32),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.cache_index == 5 &&
           pointer_update.hot_x == 1 &&
           pointer_update.hot_y == 0 &&
           pointer_update.width == 2 &&
           pointer_update.height == 2 &&
           pointer_update.xor_bpp == 32);
    rdp_buffer_free(&decoded_pointer);
    rdp_buffer_init(&decoded_pointer);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 8 && decoded_pointer.length == 16 && decoded_pointer.data[15] == 0x00);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_large_32,
                                         sizeof(mouse_cursor_large_32),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.cache_index == 5 &&
           pointer_update.width == 2 &&
           pointer_update.height == 2 &&
           pointer_update.xor_bpp == 32);
    {
        rdp_pointer_update valid_mouse_cursor_update = pointer_update;

        PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_shape_32,
                                             sizeof(mouse_cursor_shape_32) - 1u,
                                             &pointer_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&pointer_update,
                      &valid_mouse_cursor_update,
                      sizeof(pointer_update)) == 0);
        PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_shape_bad_width,
                                             sizeof(mouse_cursor_shape_bad_width),
                                             &pointer_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&pointer_update,
                      &valid_mouse_cursor_update,
                      sizeof(pointer_update)) == 0);
        PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_shape_bad_hotspot,
                                             sizeof(mouse_cursor_shape_bad_hotspot),
                                             &pointer_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&pointer_update,
                      &valid_mouse_cursor_update,
                      sizeof(pointer_update)) == 0);
        PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_unknown,
                                             sizeof(mouse_cursor_unknown),
                                             &pointer_update) == LIBRDP_STATUS_UNSUPPORTED);
        PCHECK(memcmp(&pointer_update,
                      &valid_mouse_cursor_update,
                      sizeof(pointer_update)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_init_request(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 16 &&
           dyn_response.data[0] == RDP_CORE_INPUT_SIGNATURE &&
           dyn_response.data[1] == RDP_CORE_INPUT_PDU_CS_INIT_REQUEST &&
           test_read_u16_le(dyn_response.data + 4) == RDP_CORE_INPUT_PROTOCOL_VERSION_100 &&
           test_read_u16_le(dyn_response.data + 6) == RDP_CORE_INPUT_PROTOCOL_VERSION_100);
    PCHECK(rdp_core_input_parse_header(dyn_response.data, dyn_response.length, &core_header) == LIBRDP_STATUS_OK);
    PCHECK(core_header.pdu_type == RDP_CORE_INPUT_PDU_CS_INIT_REQUEST && core_header.event_count == 0);
    {
        rdp_core_input_init_request request;

        PCHECK(rdp_core_input_parse_init_request(
                   dyn_response.data,
                   dyn_response.length,
                   &request) == LIBRDP_STATUS_OK);
        PCHECK(request.protocol_version_min ==
                   RDP_CORE_INPUT_PROTOCOL_VERSION_100 &&
               request.protocol_version_max ==
                   RDP_CORE_INPUT_PROTOCOL_VERSION_100);
        dyn_response.data[8] = 1u;
        PCHECK(rdp_core_input_parse_init_request(
                   dyn_response.data,
                   dyn_response.length,
                   &request) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        dyn_response.data[8] = 0u;
    }
    {
        rdp_core_input_header valid_core_header = core_header;

        dyn_response.data[3] = 1;
        PCHECK(rdp_core_input_parse_header(dyn_response.data, dyn_response.length, &core_header) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&core_header, &valid_core_header, sizeof(core_header)) == 0);
        dyn_response.data[3] = 0;
    }
    PCHECK(rdp_core_input_parse_init_response(core_response,
                                              sizeof(core_response),
                                              &core_init_response) == LIBRDP_STATUS_OK);
    PCHECK(core_init_response.selected_protocol_version == RDP_CORE_INPUT_PROTOCOL_VERSION_100 &&
           core_init_response.protocol_version_max == RDP_CORE_INPUT_PROTOCOL_VERSION_100);
    PCHECK(rdp_core_input_negotiate(&core_init_response, &core_negotiation) == LIBRDP_STATUS_OK);
    PCHECK(core_negotiation.selected_protocol_version == RDP_CORE_INPUT_PROTOCOL_VERSION_100 &&
           core_negotiation.supports_relative_mouse &&
           core_negotiation.supports_qoe_timestamp);
    dyn_response.length = 0;
    PCHECK(rdp_core_input_write_init_response(
               &dyn_response,
               RDP_CORE_INPUT_PROTOCOL_VERSION_100,
               RDP_CORE_INPUT_PROTOCOL_VERSION_100) ==
           LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(core_response) &&
           memcmp(dyn_response.data,
                  core_response,
                  sizeof(core_response)) == 0);
    PCHECK(rdp_core_input_write_init_response(
               NULL,
               RDP_CORE_INPUT_PROTOCOL_VERSION_100,
               RDP_CORE_INPUT_PROTOCOL_VERSION_100) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_core_input_write_init_response(
               &dyn_response,
               RDP_CORE_INPUT_PROTOCOL_VERSION_100,
               0u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    {
        rdp_core_input_init_response valid_core_init_response = core_init_response;

        PCHECK(rdp_core_input_parse_init_response(core_response,
                                                  sizeof(core_response) - 1u,
                                                  &core_init_response) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&core_init_response,
                      &valid_core_init_response,
                      sizeof(core_init_response)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_keyboard_event(&dyn_response, 0x1e, 0) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 6 &&
           dyn_response.data[1] == RDP_CORE_INPUT_PDU_CS_KEYBOARD_AND_MOUSE &&
           dyn_response.data[2] == 1 &&
           dyn_response.data[4] == 0 &&
           dyn_response.data[5] == 0x1e);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_keyboard_event(&dyn_response, 0x1e, 1) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.data[4] == RDP_CORE_INPUT_KBDFLAGS_RELEASE);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_mouse_event(&dyn_response, 0x8800u, 10, 11) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 11 &&
           dyn_response.data[4] == (uint8_t)(RDP_CORE_INPUT_EVENT_MOUSE << 5) &&
           test_read_u16_le(dyn_response.data + 5) == 0x8800u &&
           test_read_u16_le(dyn_response.data + 7) == 10 &&
           test_read_u16_le(dyn_response.data + 9) == 11);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_event_count == 1 &&
           core_events[0].type == RDP_CORE_INPUT_EVENT_MOUSE &&
           core_events[0].pointer_flags == 0x8800u &&
           core_events[0].x == 10 &&
           core_events[0].y == 11);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_keyboard_event_ex(&dyn_response,
                                                  0x1d,
                                                  RDP_CORE_INPUT_KBDFLAGS_EXTENDED |
                                                  RDP_CORE_INPUT_KBDFLAGS_RELEASE) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_event_count == 1 &&
           core_events[0].type == RDP_CORE_INPUT_EVENT_SCANCODE &&
           core_events[0].flags == (RDP_CORE_INPUT_KBDFLAGS_EXTENDED |
                                    RDP_CORE_INPUT_KBDFLAGS_RELEASE) &&
           core_events[0].scancode == 0x1d);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_unicode_event(&dyn_response, 0x20ac, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_event_count == 1 &&
           core_events[0].type == RDP_CORE_INPUT_EVENT_UNICODE &&
           core_events[0].unicode_code == 0x20ac);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_sync_event(&dyn_response,
                                           RDP_CORE_INPUT_SYNC_NUM_LOCK |
                                           RDP_CORE_INPUT_SYNC_CAPS_LOCK) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_event_count == 1 &&
           core_events[0].type == RDP_CORE_INPUT_EVENT_SYNC &&
           core_events[0].flags == (RDP_CORE_INPUT_SYNC_NUM_LOCK | RDP_CORE_INPUT_SYNC_CAPS_LOCK));
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_extended_mouse_event(&dyn_response, 0x8001u, 12, 13) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_events[0].type == RDP_CORE_INPUT_EVENT_MOUSEX &&
           core_events[0].pointer_flags == 0x8001u &&
           core_events[0].x == 12 &&
           core_events[0].y == 13);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_relative_mouse_event(&dyn_response, 0x0800u, -3, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_events[0].type == RDP_CORE_INPUT_EVENT_RELMOUSE &&
           core_events[0].pointer_flags == 0x0800u &&
           core_events[0].dx == -3 &&
           core_events[0].dy == 4);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    core_events[0].type = RDP_CORE_INPUT_EVENT_SCANCODE;
    core_events[0].flags = 0;
    core_events[0].scancode = 0x1e;
    core_events[1].type = RDP_CORE_INPUT_EVENT_QOE_TIMESTAMP;
    core_events[1].flags = 0;
    core_events[1].timestamp = 0x12345678u;
    PCHECK(rdp_core_input_write_events(&dyn_response, core_events, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_event_count == 2 &&
           core_events[0].scancode == 0x1e &&
           core_events[1].type == RDP_CORE_INPUT_EVENT_QOE_TIMESTAMP &&
           core_events[1].timestamp == 0x12345678u);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_buffer_append_u8(&dyn_response, 0xa5u) == LIBRDP_STATUS_OK);
    core_events[0].type = RDP_CORE_INPUT_EVENT_SCANCODE;
    core_events[0].flags = 0;
    core_events[0].scancode = 0x1e;
    core_events[1].type = RDP_CORE_INPUT_EVENT_QOE_TIMESTAMP;
    core_events[1].flags = 1;
    core_events[1].timestamp = 0x12345678u;
    PCHECK(rdp_core_input_write_events(&dyn_response,
                                       core_events,
                                       2) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(dyn_response.length == 1 && dyn_response.data[0] == 0xa5u);
    {
        const uint8_t invalid_second_event[] = {
            RDP_CORE_INPUT_SIGNATURE,
            RDP_CORE_INPUT_PDU_CS_KEYBOARD_AND_MOUSE,
            2,
            0,
            0,
            0x1e,
            (uint8_t)((RDP_CORE_INPUT_EVENT_QOE_TIMESTAMP << 5) | 1u),
            0x78,
            0x56,
            0x34,
            0x12
        };

        memset(core_events, 0x5a, sizeof(core_events));
        core_event_count = 77;
        PCHECK(rdp_core_input_parse_events(invalid_second_event,
                                           sizeof(invalid_second_event),
                                           core_events,
                                           8,
                                           &core_event_count) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(core_event_count == 77 && core_events[0].type == 0x5a && core_events[0].scancode == 0x5a);
    }
    PCHECK(rdp_input_channel_parse_header(input_sc_ready_v300,
                                          sizeof(input_sc_ready_v300),
                                          &input_header) == LIBRDP_STATUS_OK);
    PCHECK(input_header.event_id == RDP_INPUT_CHANNEL_EVENT_SC_READY &&
           input_header.pdu_length == sizeof(input_sc_ready_v300));
    {
        rdp_input_channel_header valid_input_header = input_header;

        PCHECK(rdp_input_channel_parse_header(input_sc_ready_v300,
                                              sizeof(input_sc_ready_v300) - 1u,
                                              &input_header) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&input_header, &valid_input_header, sizeof(input_header)) == 0);
    }
    PCHECK(rdp_input_channel_write_header(&dyn_response, 0xffffu, 6) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_input_channel_parse_sc_ready(input_sc_ready_v300,
                                            sizeof(input_sc_ready_v300),
                                            &input_sc_ready) == LIBRDP_STATUS_OK);
    PCHECK(input_sc_ready.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V300 &&
           input_sc_ready.has_supported_features &&
           input_sc_ready.supported_features == RDP_INPUT_CHANNEL_SC_READY_MULTIPEN);
    {
        rdp_input_channel_sc_ready valid_input_sc_ready = input_sc_ready;

        PCHECK(rdp_input_channel_parse_sc_ready(input_sc_ready_v300,
                                                sizeof(input_sc_ready_v300) - 1u,
                                                &input_sc_ready) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&input_sc_ready, &valid_input_sc_ready, sizeof(input_sc_ready)) == 0);
    }
    PCHECK(rdp_input_channel_negotiate_client_ready(&input_sc_ready,
                                                    10,
                                                    0,
                                                    &input_negotiation) == LIBRDP_STATUS_OK);
    PCHECK(input_negotiation.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V300 &&
           input_negotiation.supports_touch &&
           input_negotiation.supports_pen &&
           input_negotiation.disables_timestamp_injection &&
           input_negotiation.max_touch_contacts == 10);
    PCHECK(rdp_input_channel_parse_sc_ready(input_sc_ready_v300_no_pen,
                                            sizeof(input_sc_ready_v300_no_pen),
                                            &input_sc_ready) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_negotiate_client_ready(&input_sc_ready,
                                                    10,
                                                    0,
                                                    &input_negotiation) == LIBRDP_STATUS_OK);
    PCHECK(input_negotiation.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V300 &&
           input_negotiation.supports_touch &&
           !input_negotiation.supports_pen &&
           (input_negotiation.flags & RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN) == 0);
    PCHECK(rdp_input_channel_parse_sc_ready(input_sc_ready_v200,
                                            sizeof(input_sc_ready_v200),
                                            &input_sc_ready) == LIBRDP_STATUS_OK);
    PCHECK(input_sc_ready.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V200 &&
           !input_sc_ready.has_supported_features);
    PCHECK(rdp_input_channel_negotiate_client_ready(&input_sc_ready,
                                                    10,
                                                    0,
                                                    &input_negotiation) == LIBRDP_STATUS_OK);
    PCHECK(input_negotiation.supports_touch &&
           !input_negotiation.supports_pen &&
           (input_negotiation.flags & RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN) == 0);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_input_channel_write_sc_ready(&dyn_response,
                                            RDP_INPUT_CHANNEL_PROTOCOL_V300,
                                            RDP_INPUT_CHANNEL_SC_READY_MULTIPEN,
                                            1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_sc_ready(dyn_response.data,
                                            dyn_response.length,
                                            &input_sc_ready) == LIBRDP_STATUS_OK);
    PCHECK(input_sc_ready.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V300 &&
           input_sc_ready.has_supported_features &&
           input_sc_ready.supported_features == RDP_INPUT_CHANNEL_SC_READY_MULTIPEN);
    PCHECK(rdp_input_channel_write_sc_ready(&dyn_response,
                                            RDP_INPUT_CHANNEL_PROTOCOL_V300,
                                            0,
                                            0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_input_channel_write_cs_ready(&dyn_response,
                                            RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION |
                                            RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN,
                                            RDP_INPUT_CHANNEL_PROTOCOL_V300,
                                            10) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 16 &&
           test_read_u16_le(dyn_response.data) == RDP_INPUT_CHANNEL_EVENT_CS_READY &&
           test_read_u32_le(dyn_response.data + 2) == 16 &&
           test_read_u32_le(dyn_response.data + 6) ==
               (RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION | RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN));
    PCHECK(rdp_input_channel_parse_cs_ready(dyn_response.data,
                                            dyn_response.length,
                                            &input_cs_ready) == LIBRDP_STATUS_OK);
    PCHECK(input_cs_ready.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V300 &&
           input_cs_ready.max_touch_contacts == 10);
    valid_input_cs_ready = input_cs_ready;
    PCHECK(rdp_input_channel_write_cs_ready(&dyn_response,
                                            RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN,
                                            RDP_INPUT_CHANNEL_PROTOCOL_V101,
                                            1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    dyn_response.length = 0;
    PCHECK(rdp_input_channel_write_header(&dyn_response, RDP_INPUT_CHANNEL_EVENT_CS_READY, 16) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&dyn_response,
                                    RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&dyn_response, RDP_INPUT_CHANNEL_PROTOCOL_V100) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&dyn_response, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_cs_ready(dyn_response.data,
                                            dyn_response.length,
                                            &input_cs_ready) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(memcmp(&input_cs_ready, &valid_input_cs_ready, sizeof(input_cs_ready)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_input_channel_write_header(&dyn_response, RDP_INPUT_CHANNEL_EVENT_CS_READY, 16) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&dyn_response, RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&dyn_response, RDP_INPUT_CHANNEL_PROTOCOL_V101) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&dyn_response, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_cs_ready(dyn_response.data,
                                            dyn_response.length,
                                            &input_cs_ready) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(memcmp(&input_cs_ready, &valid_input_cs_ready, sizeof(input_cs_ready)) == 0);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_input_channel_write_suspend(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_empty(dyn_response.data,
                                         dyn_response.length,
                                         RDP_INPUT_CHANNEL_EVENT_SUSPEND_INPUT) == LIBRDP_STATUS_OK);
    dyn_response.length = 0;
    PCHECK(rdp_input_channel_write_resume(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_empty(dyn_response.data,
                                         dyn_response.length,
                                         RDP_INPUT_CHANNEL_EVENT_RESUME_INPUT) == LIBRDP_STATUS_OK);
    dyn_response.length = 0;
    PCHECK(rdp_input_channel_write_dismiss_hovering(&dyn_response, 9) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_dismiss_hovering(dyn_response.data,
                                                    dyn_response.length,
                                                    &input_contact_id) == LIBRDP_STATUS_OK);
    PCHECK(input_contact_id == 9);
    PCHECK(rdp_input_channel_parse_dismiss_hovering(dyn_response.data,
                                                    dyn_response.length - 1u,
                                                    &input_contact_id) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(input_contact_id == 9);
    dyn_response.length = 0;
    memset(&input_touch_contact, 0, sizeof(input_touch_contact));
    input_touch_contact.contact_id = 1;
    input_touch_contact.fields_present = RDP_INPUT_CHANNEL_TOUCH_CONTACTRECT_PRESENT |
                                         RDP_INPUT_CHANNEL_TOUCH_ORIENTATION_PRESENT |
                                         RDP_INPUT_CHANNEL_TOUCH_PRESSURE_PRESENT;
    input_touch_contact.x = 100;
    input_touch_contact.y = 200;
    input_touch_contact.contact_flags = RDP_INPUT_CHANNEL_CONTACT_DOWN |
                                        RDP_INPUT_CHANNEL_CONTACT_INRANGE |
                                        RDP_INPUT_CHANNEL_CONTACT_INCONTACT;
    input_touch_contact.contact_rect_left = -2;
    input_touch_contact.contact_rect_top = -3;
    input_touch_contact.contact_rect_right = 2;
    input_touch_contact.contact_rect_bottom = 3;
    input_touch_contact.orientation = 90;
    input_touch_contact.pressure = 512;
    PCHECK(rdp_input_channel_validate_touch_contact(&input_touch_contact) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_write_touch_contact(&dyn_response, &input_touch_contact) == LIBRDP_STATUS_OK);
    {
        rdp_input_channel_touch_contact touch_contacts[2];

        touch_contacts[0] = input_touch_contact;
        touch_contacts[1] = input_touch_contact;
        channel_packet.length = 0;
        PCHECK(rdp_buffer_append_u8(&channel_packet, 0xa5u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_input_channel_write_touch_frame(&channel_packet,
                                                   0x0102030405060708ull,
                                                   touch_contacts,
                                                   2) == LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(channel_packet.length == 1 && channel_packet.data[0] == 0xa5u);
        touch_contacts[1].contact_id = 2;
        touch_contacts[1].pressure = 1025;
        PCHECK(rdp_input_channel_write_touch_frame(&channel_packet,
                                                   0x0102030405060708ull,
                                                   touch_contacts,
                                                   2) == LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(channel_packet.length == 1 && channel_packet.data[0] == 0xa5u);
    }
    memset(&input_touch_frame, 0, sizeof(input_touch_frame));
    input_touch_frame.contact_count = 1;
    input_touch_frame.frame_offset = 0x0102030405060708ull;
    input_touch_frame.contacts = dyn_response.data;
    input_touch_frame.contacts_len = dyn_response.length;
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_touch_event(&channel_packet, 0x11223344u, &input_touch_frame, 1) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_touch_event(channel_packet.data,
                                               channel_packet.length,
                                               &input_touch_event) == LIBRDP_STATUS_OK);
    PCHECK(input_touch_event.encode_time == 0x11223344u && input_touch_event.frame_count == 1);
    PCHECK(rdp_input_channel_touch_event_get_frame(&input_touch_event,
                                                   0,
                                                   &input_touch_frame) == LIBRDP_STATUS_OK);
    PCHECK(input_touch_frame.contact_count == 1 &&
           input_touch_frame.frame_offset == 0x0102030405060708ull);
    {
        rdp_input_channel_touch_event invalid_touch_event = input_touch_event;
        rdp_input_channel_touch_frame valid_touch_frame = input_touch_frame;

        invalid_touch_event.frames_len--;
        PCHECK(rdp_input_channel_touch_event_get_frame(&invalid_touch_event,
                                                       0,
                                                       &input_touch_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&input_touch_frame, &valid_touch_frame, sizeof(input_touch_frame)) == 0);
    }
    PCHECK(rdp_input_channel_touch_frame_get_contact(&input_touch_frame,
                                                     0,
                                                     &input_touch_contact) == LIBRDP_STATUS_OK);
    PCHECK(input_touch_contact.contact_id == 1 &&
           input_touch_contact.x == 100 &&
           input_touch_contact.y == 200 &&
           input_touch_contact.contact_rect_top == -3 &&
           input_touch_contact.orientation == 90 &&
           input_touch_contact.pressure == 512);
    {
        rdp_input_channel_touch_frame invalid_touch_frame = input_touch_frame;
        rdp_input_channel_touch_contact valid_touch_contact = input_touch_contact;

        invalid_touch_frame.contacts_len--;
        PCHECK(rdp_input_channel_touch_frame_get_contact(&invalid_touch_frame,
                                                         0,
                                                         &input_touch_contact) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&input_touch_contact,
                      &valid_touch_contact,
                      sizeof(input_touch_contact)) == 0);
    }
    {
        rdp_buffer second_contact;
        rdp_input_channel_touch_frame frames[2];

        rdp_buffer_init(&second_contact);
        input_touch_contact.contact_id = 2;
        input_touch_contact.x = 300;
        input_touch_contact.y = 400;
        input_touch_contact.contact_flags = RDP_INPUT_CHANNEL_CONTACT_UPDATE |
                                            RDP_INPUT_CHANNEL_CONTACT_INRANGE |
                                            RDP_INPUT_CHANNEL_CONTACT_INCONTACT;
        input_touch_contact.orientation = 180;
        input_touch_contact.pressure = 900;
        PCHECK(rdp_input_channel_write_touch_contact(&second_contact, &input_touch_contact) ==
               LIBRDP_STATUS_OK);
        memset(frames, 0, sizeof(frames));
        frames[0].contact_count = 1;
        frames[0].frame_offset = 0x0102030405060708ull;
        frames[0].contacts = dyn_response.data;
        frames[0].contacts_len = dyn_response.length;
        frames[1].contact_count = 1;
        frames[1].frame_offset = 0x1112131415161718ull;
        frames[1].contacts = second_contact.data;
        frames[1].contacts_len = second_contact.length;
        channel_packet.length = 0;
        PCHECK(rdp_input_channel_write_touch_event(&channel_packet, 0x11223344u, frames, 2) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_input_channel_parse_touch_event(channel_packet.data,
                                                   channel_packet.length,
                                                   &input_touch_event) == LIBRDP_STATUS_OK);
        PCHECK(input_touch_event.frame_count == 2);
        PCHECK(rdp_input_channel_touch_event_get_frame(&input_touch_event,
                                                       1,
                                                       &input_touch_frame) == LIBRDP_STATUS_OK);
        PCHECK(input_touch_frame.contact_count == 1 &&
               input_touch_frame.frame_offset == 0x1112131415161718ull);
        PCHECK(rdp_input_channel_touch_frame_get_contact(&input_touch_frame,
                                                         0,
                                                         &input_touch_contact) == LIBRDP_STATUS_OK);
        PCHECK(input_touch_contact.contact_id == 2 &&
               input_touch_contact.x == 300 &&
               input_touch_contact.y == 400 &&
               input_touch_contact.orientation == 180 &&
               input_touch_contact.pressure == 900);
        valid_input_touch_event = input_touch_event;
        rdp_buffer_free(&second_contact);
    }
    input_touch_contact.contact_id = 1;
    input_touch_contact.x = 100;
    input_touch_contact.y = 200;
    input_touch_contact.contact_flags = RDP_INPUT_CHANNEL_CONTACT_DOWN |
                                        RDP_INPUT_CHANNEL_CONTACT_INRANGE |
                                        RDP_INPUT_CHANNEL_CONTACT_INCONTACT;
    input_touch_contact.orientation = 90;
    input_touch_contact.pressure = 512;
    {
        rdp_buffer duplicate_contacts;

        rdp_buffer_init(&duplicate_contacts);
        PCHECK(rdp_buffer_append(&duplicate_contacts,
                                 dyn_response.data,
                                 dyn_response.length) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append(&duplicate_contacts,
                                 dyn_response.data,
                                 dyn_response.length) == LIBRDP_STATUS_OK);
        channel_packet.length = 0;
        PCHECK(rdp_input_channel_write_header(&channel_packet,
                                              RDP_INPUT_CHANNEL_EVENT_TOUCH,
                                              (uint32_t)(6u + 4u + 2u + 2u + 8u +
                                                         duplicate_contacts.length)) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0x11223344u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u16_le(&channel_packet, 1) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u16_le(&channel_packet, 2) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0x05060708u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0x01020304u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append(&channel_packet,
                                 duplicate_contacts.data,
                                 duplicate_contacts.length) == LIBRDP_STATUS_OK);
        PCHECK(rdp_input_channel_parse_touch_event(channel_packet.data,
                                                   channel_packet.length,
                                                   &input_touch_event) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&input_touch_event,
                      &valid_input_touch_event,
                      sizeof(input_touch_event)) == 0);
        input_touch_frame.contact_count = 2;
        input_touch_frame.contacts = duplicate_contacts.data;
        input_touch_frame.contacts_len = duplicate_contacts.length;
        channel_packet.length = 0;
        PCHECK(rdp_buffer_append_u8(&channel_packet, 0xa5u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_input_channel_write_touch_event(&channel_packet, 0, &input_touch_frame, 1) ==
               LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(channel_packet.length == 1 && channel_packet.data[0] == 0xa5u);
        rdp_buffer_free(&duplicate_contacts);
    }
    input_touch_frame.contact_count = 2;
    input_touch_frame.contacts = dyn_response.data;
    input_touch_frame.contacts_len = dyn_response.length;
    channel_packet.length = 0;
    PCHECK(rdp_buffer_append_u8(&channel_packet, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_write_touch_event(&channel_packet, 0, &input_touch_frame, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(channel_packet.length == 1 && channel_packet.data[0] == 0xa5u);
    input_touch_frame.contact_count = 1;
    input_touch_frame.contacts = dyn_response.data;
    input_touch_frame.contacts_len = dyn_response.length;
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_touch_event(&channel_packet, 0x11223344u, &input_touch_frame, 1) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&channel_packet, 0xaa) == LIBRDP_STATUS_OK);
    channel_packet.data[2] = (uint8_t)(channel_packet.length & 0xffu);
    channel_packet.data[3] = (uint8_t)((channel_packet.length >> 8) & 0xffu);
    channel_packet.data[4] = (uint8_t)((channel_packet.length >> 16) & 0xffu);
    channel_packet.data[5] = (uint8_t)((channel_packet.length >> 24) & 0xffu);
    PCHECK(rdp_input_channel_parse_touch_event(channel_packet.data,
                                               channel_packet.length,
                                               &input_touch_event) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(memcmp(&input_touch_event,
                  &valid_input_touch_event,
                  sizeof(input_touch_event)) == 0);
    PCHECK(rdp_input_channel_write_touch_event(&channel_packet, 0, NULL, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    memset(&input_touch_frame, 0, sizeof(input_touch_frame));
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_touch_event(&channel_packet, 0, &input_touch_frame, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_header(&channel_packet, RDP_INPUT_CHANNEL_EVENT_TOUCH, 22) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&channel_packet, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_touch_event(channel_packet.data,
                                               channel_packet.length,
                                               &input_touch_event) == LIBRDP_STATUS_PROTOCOL_ERROR);
    input_touch_contact.contact_rect_left = 5;
    input_touch_contact.contact_rect_right = 2;
    PCHECK(rdp_input_channel_write_touch_contact(&dyn_response, &input_touch_contact) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    input_touch_contact.contact_rect_left = -2;
    input_touch_contact.contact_rect_right = 2;
    input_touch_contact.pressure = 1025;
    PCHECK(rdp_input_channel_write_touch_contact(&dyn_response, &input_touch_contact) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    input_touch_contact.pressure = 512;
    input_touch_contact.contact_flags = RDP_INPUT_CHANNEL_CONTACT_DOWN;
    PCHECK(rdp_input_channel_write_touch_contact(&dyn_response, &input_touch_contact) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    dyn_response.length = 0;
    memset(&input_pen_contact, 0, sizeof(input_pen_contact));
    input_pen_contact.device_id = 2;
    input_pen_contact.fields_present = RDP_INPUT_CHANNEL_PEN_FLAGS_PRESENT |
                                       RDP_INPUT_CHANNEL_PEN_PRESSURE_PRESENT |
                                       RDP_INPUT_CHANNEL_PEN_ROTATION_PRESENT |
                                       RDP_INPUT_CHANNEL_PEN_TILTX_PRESENT |
                                       RDP_INPUT_CHANNEL_PEN_TILTY_PRESENT;
    input_pen_contact.x = -20;
    input_pen_contact.y = 30;
    input_pen_contact.contact_flags = RDP_INPUT_CHANNEL_CONTACT_UPDATE |
                                      RDP_INPUT_CHANNEL_CONTACT_INRANGE |
                                      RDP_INPUT_CHANNEL_CONTACT_INCONTACT;
    input_pen_contact.pen_flags = RDP_INPUT_CHANNEL_PEN_BARREL_PRESSED;
    input_pen_contact.pressure = 700;
    input_pen_contact.rotation = 45;
    input_pen_contact.tilt_x = -10;
    input_pen_contact.tilt_y = 20;
    PCHECK(rdp_input_channel_validate_pen_contact(&input_pen_contact) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_write_pen_contact(&dyn_response, &input_pen_contact) == LIBRDP_STATUS_OK);
    {
        rdp_input_channel_pen_contact pen_contacts[2];

        pen_contacts[0] = input_pen_contact;
        pen_contacts[1] = input_pen_contact;
        channel_packet.length = 0;
        PCHECK(rdp_buffer_append_u8(&channel_packet, 0xa5u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_input_channel_write_pen_frame(&channel_packet,
                                                 7,
                                                 pen_contacts,
                                                 2) == LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(channel_packet.length == 1 && channel_packet.data[0] == 0xa5u);
        pen_contacts[1].device_id = 3;
        pen_contacts[1].rotation = 360;
        PCHECK(rdp_input_channel_write_pen_frame(&channel_packet,
                                                 7,
                                                 pen_contacts,
                                                 2) == LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(channel_packet.length == 1 && channel_packet.data[0] == 0xa5u);
    }
    memset(&input_pen_frame, 0, sizeof(input_pen_frame));
    input_pen_frame.contact_count = 1;
    input_pen_frame.frame_offset = 7;
    input_pen_frame.contacts = dyn_response.data;
    input_pen_frame.contacts_len = dyn_response.length;
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_pen_event(&channel_packet, 0x55667788u, &input_pen_frame, 1) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_pen_event(channel_packet.data,
                                             channel_packet.length,
                                             &input_pen_event) == LIBRDP_STATUS_OK);
    PCHECK(input_pen_event.encode_time == 0x55667788u && input_pen_event.frame_count == 1);
    PCHECK(rdp_input_channel_pen_event_get_frame(&input_pen_event,
                                                 0,
                                                 &input_pen_frame) == LIBRDP_STATUS_OK);
    PCHECK(input_pen_frame.contact_count == 1 && input_pen_frame.frame_offset == 7);
    {
        rdp_input_channel_pen_event invalid_pen_event = input_pen_event;
        rdp_input_channel_pen_frame valid_pen_frame = input_pen_frame;

        invalid_pen_event.frames_len--;
        PCHECK(rdp_input_channel_pen_event_get_frame(&invalid_pen_event,
                                                     0,
                                                     &input_pen_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&input_pen_frame, &valid_pen_frame, sizeof(input_pen_frame)) == 0);
    }
    PCHECK(rdp_input_channel_pen_frame_get_contact(&input_pen_frame,
                                                   0,
                                                   &input_pen_contact) == LIBRDP_STATUS_OK);
    PCHECK(input_pen_contact.device_id == 2 &&
           input_pen_contact.x == -20 &&
           input_pen_contact.pen_flags == RDP_INPUT_CHANNEL_PEN_BARREL_PRESSED &&
           input_pen_contact.pressure == 700 &&
           input_pen_contact.rotation == 45 &&
           input_pen_contact.tilt_x == -10 &&
           input_pen_contact.tilt_y == 20);
    {
        rdp_input_channel_pen_frame invalid_pen_frame = input_pen_frame;
        rdp_input_channel_pen_contact valid_pen_contact = input_pen_contact;

        invalid_pen_frame.contacts_len--;
        PCHECK(rdp_input_channel_pen_frame_get_contact(&invalid_pen_frame,
                                                       0,
                                                       &input_pen_contact) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&input_pen_contact,
                      &valid_pen_contact,
                      sizeof(input_pen_contact)) == 0);
    }
    {
        rdp_buffer second_contact;
        rdp_input_channel_pen_frame frames[2];

        rdp_buffer_init(&second_contact);
        input_pen_contact.device_id = 3;
        input_pen_contact.x = 40;
        input_pen_contact.y = 50;
        input_pen_contact.pen_flags = RDP_INPUT_CHANNEL_PEN_ERASER_PRESSED;
        input_pen_contact.pressure = 300;
        input_pen_contact.rotation = 270;
        input_pen_contact.tilt_x = 15;
        input_pen_contact.tilt_y = -25;
        PCHECK(rdp_input_channel_write_pen_contact(&second_contact, &input_pen_contact) ==
               LIBRDP_STATUS_OK);
        memset(frames, 0, sizeof(frames));
        frames[0].contact_count = 1;
        frames[0].frame_offset = 7;
        frames[0].contacts = dyn_response.data;
        frames[0].contacts_len = dyn_response.length;
        frames[1].contact_count = 1;
        frames[1].frame_offset = 11;
        frames[1].contacts = second_contact.data;
        frames[1].contacts_len = second_contact.length;
        channel_packet.length = 0;
        PCHECK(rdp_input_channel_write_pen_event(&channel_packet, 0x55667788u, frames, 2) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_input_channel_parse_pen_event(channel_packet.data,
                                                 channel_packet.length,
                                                 &input_pen_event) == LIBRDP_STATUS_OK);
        PCHECK(input_pen_event.frame_count == 2);
        PCHECK(rdp_input_channel_pen_event_get_frame(&input_pen_event,
                                                     1,
                                                     &input_pen_frame) == LIBRDP_STATUS_OK);
        PCHECK(input_pen_frame.contact_count == 1 && input_pen_frame.frame_offset == 11);
        PCHECK(rdp_input_channel_pen_frame_get_contact(&input_pen_frame,
                                                       0,
                                                       &input_pen_contact) == LIBRDP_STATUS_OK);
        PCHECK(input_pen_contact.device_id == 3 &&
               input_pen_contact.x == 40 &&
               input_pen_contact.y == 50 &&
               input_pen_contact.pen_flags == RDP_INPUT_CHANNEL_PEN_ERASER_PRESSED &&
               input_pen_contact.pressure == 300 &&
               input_pen_contact.rotation == 270 &&
               input_pen_contact.tilt_x == 15 &&
               input_pen_contact.tilt_y == -25);
        valid_input_pen_event = input_pen_event;
        rdp_buffer_free(&second_contact);
    }
    input_pen_contact.device_id = 2;
    input_pen_contact.x = -20;
    input_pen_contact.y = 30;
    input_pen_contact.pen_flags = RDP_INPUT_CHANNEL_PEN_BARREL_PRESSED;
    input_pen_contact.pressure = 700;
    input_pen_contact.rotation = 45;
    input_pen_contact.tilt_x = -10;
    input_pen_contact.tilt_y = 20;
    {
        rdp_buffer duplicate_contacts;

        rdp_buffer_init(&duplicate_contacts);
        PCHECK(rdp_buffer_append(&duplicate_contacts,
                                 dyn_response.data,
                                 dyn_response.length) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append(&duplicate_contacts,
                                 dyn_response.data,
                                 dyn_response.length) == LIBRDP_STATUS_OK);
        channel_packet.length = 0;
        PCHECK(rdp_input_channel_write_header(&channel_packet,
                                              RDP_INPUT_CHANNEL_EVENT_PEN,
                                              (uint32_t)(6u + 4u + 2u + 2u + 8u +
                                                         duplicate_contacts.length)) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0x55667788u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u16_le(&channel_packet, 1) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u16_le(&channel_packet, 2) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u32_le(&channel_packet, 7) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append(&channel_packet,
                                 duplicate_contacts.data,
                                 duplicate_contacts.length) == LIBRDP_STATUS_OK);
        PCHECK(rdp_input_channel_parse_pen_event(channel_packet.data,
                                                 channel_packet.length,
                                                 &input_pen_event) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&input_pen_event,
                      &valid_input_pen_event,
                      sizeof(input_pen_event)) == 0);
        input_pen_frame.contact_count = 2;
        input_pen_frame.contacts = duplicate_contacts.data;
        input_pen_frame.contacts_len = duplicate_contacts.length;
        channel_packet.length = 0;
        PCHECK(rdp_buffer_append_u8(&channel_packet, 0xa5u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_input_channel_write_pen_event(&channel_packet, 0, &input_pen_frame, 1) ==
               LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(channel_packet.length == 1 && channel_packet.data[0] == 0xa5u);
        rdp_buffer_free(&duplicate_contacts);
    }
    input_pen_frame.contact_count = 2;
    input_pen_frame.contacts = dyn_response.data;
    input_pen_frame.contacts_len = dyn_response.length;
    channel_packet.length = 0;
    PCHECK(rdp_buffer_append_u8(&channel_packet, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_write_pen_event(&channel_packet, 0, &input_pen_frame, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(channel_packet.length == 1 && channel_packet.data[0] == 0xa5u);
    input_pen_frame.contact_count = 1;
    input_pen_frame.contacts = dyn_response.data;
    input_pen_frame.contacts_len = dyn_response.length;
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_pen_event(&channel_packet, 0x55667788u, &input_pen_frame, 1) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&channel_packet, 0xbb) == LIBRDP_STATUS_OK);
    channel_packet.data[2] = (uint8_t)(channel_packet.length & 0xffu);
    channel_packet.data[3] = (uint8_t)((channel_packet.length >> 8) & 0xffu);
    channel_packet.data[4] = (uint8_t)((channel_packet.length >> 16) & 0xffu);
    channel_packet.data[5] = (uint8_t)((channel_packet.length >> 24) & 0xffu);
    PCHECK(rdp_input_channel_parse_pen_event(channel_packet.data,
                                             channel_packet.length,
                                             &input_pen_event) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(memcmp(&input_pen_event,
                  &valid_input_pen_event,
                  sizeof(input_pen_event)) == 0);
    PCHECK(rdp_input_channel_write_pen_event(&channel_packet, 0, NULL, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    memset(&input_pen_frame, 0, sizeof(input_pen_frame));
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_pen_event(&channel_packet, 0, &input_pen_frame, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_header(&channel_packet, RDP_INPUT_CHANNEL_EVENT_PEN, 22) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&channel_packet, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_pen_event(channel_packet.data,
                                             channel_packet.length,
                                             &input_pen_event) == LIBRDP_STATUS_PROTOCOL_ERROR);
    input_pen_contact.tilt_y = 91;
    PCHECK(rdp_input_channel_write_pen_contact(&dyn_response, &input_pen_contact) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_display_control_parse_caps(display_caps,
                                          sizeof(display_caps),
                                          &display_parsed_caps) == LIBRDP_STATUS_OK);
    PCHECK(display_parsed_caps.max_num_monitors == 16 &&
           display_parsed_caps.max_monitor_area_factor_a == 8192 &&
           display_parsed_caps.max_monitor_area_factor_b == 8192);
    {
        rdp_display_control_caps valid_caps = display_parsed_caps;

        memcpy(display_bad_caps, display_caps, sizeof(display_bad_caps));
        display_bad_caps[8] = 0;
        PCHECK(rdp_display_control_parse_caps(display_bad_caps,
                                              sizeof(display_bad_caps),
                                              &display_parsed_caps) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&display_parsed_caps, &valid_caps, sizeof(display_parsed_caps)) == 0);
        memcpy(display_bad_caps, display_caps, sizeof(display_bad_caps));
        display_bad_caps[8] = 17;
        PCHECK(rdp_display_control_parse_caps(display_bad_caps,
                                              sizeof(display_bad_caps),
                                              &display_parsed_caps) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&display_parsed_caps, &valid_caps, sizeof(display_parsed_caps)) == 0);
        memcpy(display_bad_caps, display_caps, sizeof(display_bad_caps));
        display_bad_caps[12] = 0;
        display_bad_caps[13] = 0;
        PCHECK(rdp_display_control_parse_caps(display_bad_caps,
                                              sizeof(display_bad_caps),
                                              &display_parsed_caps) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&display_parsed_caps, &valid_caps, sizeof(display_parsed_caps)) == 0);
        PCHECK(rdp_display_control_parse_caps(display_caps,
                                              sizeof(display_caps) - 1u,
                                              &display_parsed_caps) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&display_parsed_caps, &valid_caps, sizeof(display_parsed_caps)) == 0);
    }
    PCHECK(rdp_display_control_parse_caps(display_caps,
                                          sizeof(display_caps),
                                          &display_parsed_caps) == LIBRDP_STATUS_OK);
    PCHECK(rdp_display_control_make_single_monitor(&display_monitor, 801, 199) == LIBRDP_STATUS_OK);
    PCHECK(display_monitor.flags == RDP_DISPLAY_CONTROL_MONITOR_PRIMARY &&
           display_monitor.width == 800 &&
           display_monitor.height == 200 &&
           display_monitor.desktop_scale_factor == 100);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, &display_monitor, 1) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 56 &&
           test_read_u32_le(dyn_response.data) == RDP_DISPLAY_CONTROL_PDU_MONITOR_LAYOUT &&
           test_read_u32_le(dyn_response.data + 4) == 56 &&
           test_read_u32_le(dyn_response.data + 8) == RDP_DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE &&
           test_read_u32_le(dyn_response.data + 12) == 1 &&
           test_read_u32_le(dyn_response.data + 16) == RDP_DISPLAY_CONTROL_MONITOR_PRIMARY &&
           test_read_u32_le(dyn_response.data + 28) == 800 &&
           test_read_u32_le(dyn_response.data + 32) == 200);
    PCHECK(rdp_display_control_parse_monitor_layout(dyn_response.data,
                                                    dyn_response.length,
                                                    display_monitors,
                                                    2,
                                                    &display_monitor_count) == LIBRDP_STATUS_OK);
    PCHECK(display_monitor_count == 1 &&
           display_monitors[0].flags == RDP_DISPLAY_CONTROL_MONITOR_PRIMARY &&
           display_monitors[0].width == 800 &&
           display_monitors[0].height == 200);
    memset(display_monitors, 0xa5, sizeof(display_monitors));
    display_monitor_count = 99;
    PCHECK(rdp_display_control_parse_monitor_layout(dyn_response.data,
                                                    dyn_response.length,
                                                    display_monitors,
                                                    LIBRDP_DISPLAY_MAX_MONITORS + 1u,
                                                    &display_monitor_count) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(display_monitor_count == 99 &&
           display_monitors[0].flags == 0xa5a5a5a5u &&
           display_monitors[1].flags == 0xa5a5a5a5u);
    PCHECK(dyn_response.length <= sizeof(display_mutated));
    memcpy(display_mutated, dyn_response.data, dyn_response.length);
    display_mutated[36] = 9;
    memset(display_monitors, 0xa5, sizeof(display_monitors));
    display_monitor_count = 99;
    PCHECK(rdp_display_control_parse_monitor_layout(display_mutated,
                                                    dyn_response.length,
                                                    display_monitors,
                                                    2,
                                                    &display_monitor_count) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(display_monitor_count == 0 &&
           display_monitors[0].flags == 0 &&
           display_monitors[0].width == 0 &&
           display_monitors[1].flags == 0);
    display_monitors[0] = display_monitor;
    display_monitors[1] = display_monitor;
    display_monitors[1].flags = 0;
    display_monitors[1].left = 800;
    display_monitors[1].width = 640;
    display_monitors[1].height = 480;
    display_monitors[1].physical_width = 169;
    display_monitors[1].physical_height = 127;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout_with_caps(&dyn_response,
                                                              display_monitors,
                                                              2,
                                                              &display_parsed_caps) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 96 &&
           test_read_u32_le(dyn_response.data + 12) == 2 &&
           test_read_u32_le(dyn_response.data + 56) == 0 &&
           test_read_u32_le(dyn_response.data + 68) == 640);
    PCHECK(rdp_display_control_parse_monitor_layout_with_caps(dyn_response.data,
                                                              dyn_response.length,
                                                              display_monitors,
                                                              2,
                                                              &display_monitor_count,
                                                              &display_parsed_caps) == LIBRDP_STATUS_OK);
    PCHECK(display_monitor_count == 2 &&
           display_monitors[1].left == 800 &&
           display_monitors[1].width == 640);
    PCHECK(dyn_response.length <= sizeof(display_mutated));
    memcpy(display_mutated, dyn_response.data, dyn_response.length);
    display_mutated[56] = RDP_DISPLAY_CONTROL_MONITOR_PRIMARY;
    PCHECK(rdp_display_control_parse_monitor_layout_with_caps(display_mutated,
                                                              dyn_response.length,
                                                              display_monitors,
                                                              2,
                                                              &display_monitor_count,
                                                              &display_parsed_caps) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    memcpy(display_mutated, dyn_response.data, dyn_response.length);
    display_mutated[60] = 0xbc;
    display_mutated[61] = 0x02;
    display_mutated[62] = 0;
    display_mutated[63] = 0;
    PCHECK(rdp_display_control_parse_monitor_layout_with_caps(display_mutated,
                                                              dyn_response.length,
                                                              display_monitors,
                                                              2,
                                                              &display_monitor_count,
                                                              &display_parsed_caps) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    memcpy(display_mutated, dyn_response.data, dyn_response.length);
    display_mutated[60] = 0xf0u;
    display_mutated[61] = 0xffu;
    display_mutated[62] = 0xffu;
    display_mutated[63] = 0x7fu;
    memset(display_monitors, 0xa5, sizeof(display_monitors));
    display_monitor_count = 99;
    PCHECK(rdp_display_control_parse_monitor_layout_with_caps(display_mutated,
                                                              dyn_response.length,
                                                              display_monitors,
                                                              2,
                                                              &display_monitor_count,
                                                              &display_parsed_caps) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(display_monitor_count == 0 &&
           display_monitors[0].flags == 0 &&
           display_monitors[1].width == 0);
    display_monitors[1].left = 700;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, display_monitors, 2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_monitors[1].left = 800;
    display_monitors[1].left = INT32_MAX - 100;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, display_monitors, 2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_monitors[1].left = 800;
    display_parsed_caps.max_num_monitors = 1;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout_with_caps(&dyn_response,
                                                              display_monitors,
                                                              2,
                                                              &display_parsed_caps) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_parsed_caps.max_num_monitors = 1;
    display_parsed_caps.max_monitor_area_factor_a = 200;
    display_parsed_caps.max_monitor_area_factor_b = 200;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout_with_caps(&dyn_response,
                                                              &display_monitor,
                                                              1,
                                                              &display_parsed_caps) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_parsed_caps.max_monitor_area_factor_a = 8192;
    display_parsed_caps.max_monitor_area_factor_b = 8192;
    display_monitor.left = 1;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, &display_monitor, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_monitor.left = 0;
    display_monitor.device_scale_factor = 120;
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, &display_monitor, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_monitor.device_scale_factor = 100;
    display_monitor.physical_width = 9;
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, &display_monitor, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_monitor.physical_width = 210;
    display_monitor.width = 801;
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, &display_monitor, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&dyn_response);

    rdp_buffer_free(&dyn_response);
    rdp_buffer_free(&channel_packet);
    rdp_buffer_free(&decoded_pointer);
    return 0;
}
