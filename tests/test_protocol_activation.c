/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: focused protocol conformance suite.
 * Coverage: capability, activation, input synchronization, and output-control conformance vectors.
 * Bug classes: capability length, duplicate state, activation sequencing, coordinate bounds, and malformed payloads.
 * Determinism: all vectors and state are synthetic and remain local to this suite.
 */

#include "common/buffer.h"
#include "graphics/bitmap.h"
#include "graphics/gdi_orders.h"
#include "graphics/nscodec.h"
#include "protocol/capabilities.h"
#include "protocol/slowpath.h"

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
 * Runs capability, activation, input synchronization, and output-control conformance vectors.
 */
int test_protocol_activation_vectors(void)
{
    const uint8_t bitmap_data_pdu[] = {
        0x38, 0x00, 0x17, 0x00, 0xec, 0x03, 0x78, 0x56, 0x34, 0x12,
        0x00, 0x01, 0x26, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x10, 0x00,
        1,    2,    3,    4,    5,    6,    7,    8,
        9,    10,   11,   12,   13,   14,   15,   16
    };
    const uint8_t nscodec_guid[RDP_NSCODEC_GUID_LENGTH] = RDP_NSCODEC_GUID_BYTES;
    rdp_slowpath_share_control_header slow_header;
    rdp_slowpath_data_pdu data_pdu;
    rdp_slowpath_font_map font_map;
    rdp_slowpath_save_session_info save_info;
    rdp_bitmap_update bitmap_update;
    rdp_buffer confirm_active;
    rdp_buffer client_sync;
    rdp_buffer client_control;
    rdp_buffer client_persistent_keys;
    rdp_buffer client_font_list;
    rdp_buffer client_keyboard_input;
    rdp_buffer client_mouse_input;
    rdp_buffer client_refresh_rect;
    rdp_buffer client_suppress_output;
    rdp_buffer deactivate_all;
    rdp_capability_list confirm_caps;
    const rdp_capability_set* confirm_bitmap_set = NULL;
    const rdp_capability_set* confirm_set = NULL;
    rdp_capability_general confirm_general;
    rdp_capability_bitmap confirm_bitmap;
    rdp_capability_order confirm_order;
    rdp_capability_bitmap_cache_v2 confirm_bitmap_cache;
    rdp_capability_pointer confirm_pointer;
    rdp_capability_large_pointer confirm_large_pointer;
    rdp_capability_input confirm_input;
    rdp_capability_brush confirm_brush;
    rdp_capability_glyph_cache confirm_glyph;
    rdp_capability_virtual_channel confirm_virtual_channel;
    rdp_capability_sound confirm_sound;
    rdp_capability_share confirm_share;
    rdp_capability_font confirm_font;
    rdp_capability_control confirm_control;
    rdp_capability_color_cache confirm_color_cache;
    rdp_capability_activation confirm_activation;
    rdp_capability_bitmap_codecs confirm_bitmap_codecs;
    rdp_nscodec_capability confirm_nscodec;
    rdp_slowpath_confirm_active parsed_confirm;
    rdp_slowpath_deactivate_all parsed_deactivate;
    rdp_capability_set virtual_channel_minimal_set;
    uint32_t error_info = 0;
    size_t i = 0;
    uint16_t confirm_source_len = 0;
    uint16_t confirm_caps_len = 0;
    const uint16_t expected_confirm_types[] = {
        RDP_CAPABILITY_TYPE_GENERAL,
        RDP_CAPABILITY_TYPE_BITMAP,
        RDP_CAPABILITY_TYPE_ORDER,
        RDP_CAPABILITY_TYPE_BITMAP_CACHE_V2,
        RDP_CAPABILITY_TYPE_POINTER,
        RDP_CAPABILITY_TYPE_LARGE_POINTER,
        RDP_CAPABILITY_TYPE_INPUT,
        RDP_CAPABILITY_TYPE_BRUSH,
        RDP_CAPABILITY_TYPE_GLYPH_CACHE,
        RDP_CAPABILITY_TYPE_VIRTUAL_CHANNEL,
        RDP_CAPABILITY_TYPE_SOUND,
        RDP_CAPABILITY_TYPE_SHARE,
        RDP_CAPABILITY_TYPE_FONT,
        RDP_CAPABILITY_TYPE_CONTROL,
        RDP_CAPABILITY_TYPE_COLOR_CACHE,
        RDP_GDI_CAPSTYPE_DRAW_NINEGRID_CACHE,
        RDP_CAPABILITY_TYPE_ACTIVATION,
        RDP_CAPABILITY_TYPE_BITMAP_CODECS
    };
    const uint16_t expected_confirm_lengths[] = {
        24, 28, 88, 40, 10, 6, 88, 8, 52, 12, 8, 8, 8, 12, 8, 12, 12, 27
    };
    const uint8_t virtual_channel_minimal_data[] = {1, 0, 0, 0};
    const uint8_t font_map_payload[] = {1, 0, 2, 0, 3, 0, 4, 0};
    const uint8_t set_error_info_payload[] = {0x34, 0x12, 0, 0};
    const uint8_t save_session_info_payload[] = {1, 0, 0, 0, 0xaa, 0x55};
    const uint8_t orders_update_payload[] = {0, 0, 0, 0};

    rdp_buffer_init(&confirm_active);
    rdp_buffer_init(&client_sync);
    rdp_buffer_init(&client_control);
    rdp_buffer_init(&client_persistent_keys);
    rdp_buffer_init(&client_font_list);
    rdp_buffer_init(&client_keyboard_input);
    rdp_buffer_init(&client_mouse_input);
    rdp_buffer_init(&client_refresh_rect);
    rdp_buffer_init(&client_suppress_output);
    rdp_buffer_init(&deactivate_all);

    PCHECK(rdp_slowpath_parse_data_pdu(bitmap_data_pdu, sizeof(bitmap_data_pdu), &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len - 1u, &bitmap_update) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_bitmap_parse_update(orders_update_payload, sizeof(orders_update_payload), &bitmap_update) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    memset(&virtual_channel_minimal_set, 0, sizeof(virtual_channel_minimal_set));
    virtual_channel_minimal_set.type = RDP_CAPABILITY_TYPE_VIRTUAL_CHANNEL;
    virtual_channel_minimal_set.length = 8;
    virtual_channel_minimal_set.data = virtual_channel_minimal_data;
    virtual_channel_minimal_set.data_len = sizeof(virtual_channel_minimal_data);
    PCHECK(rdp_slowpath_write_confirm_active(&confirm_active, 0x12345678u, 1004, 800, 600, "librdp") ==
           LIBRDP_STATUS_OK);
    memset(&parsed_confirm, 0, sizeof(parsed_confirm));
    PCHECK(rdp_slowpath_parse_confirm_active(
               confirm_active.data,
               confirm_active.length,
               &parsed_confirm) == LIBRDP_STATUS_OK);
    PCHECK(parsed_confirm.share_id == 0x12345678u);
    PCHECK(parsed_confirm.originator_id == 1002u);
    PCHECK(parsed_confirm.header.channel_id == 1004u);
    PCHECK(parsed_confirm.source_descriptor_len == 6u);
    PCHECK(memcmp(parsed_confirm.source_descriptor, "librdp", 6u) == 0);
    PCHECK(parsed_confirm.capabilities.count == 18u);
    PCHECK(rdp_slowpath_parse_confirm_active(
               confirm_active.data,
               confirm_active.length - 1u,
               &parsed_confirm) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(parsed_confirm.share_id == 0x12345678u);
    PCHECK(rdp_slowpath_parse_share_control_header(confirm_active.data, confirm_active.length, &slow_header) ==
           LIBRDP_STATUS_OK);
    PCHECK(slow_header.total_length == confirm_active.length);
    PCHECK((slow_header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE);
    PCHECK(slow_header.channel_id == 1004);
    PCHECK(confirm_active.data[6] == 0x78 && confirm_active.data[10] == 0xea);
    confirm_source_len = (uint16_t)(confirm_active.data[12] | ((uint16_t)confirm_active.data[13] << 8));
    confirm_caps_len = (uint16_t)(confirm_active.data[14] | ((uint16_t)confirm_active.data[15] << 8));
    PCHECK(confirm_source_len == 6);
    PCHECK(rdp_capabilities_parse(confirm_active.data + 16u + confirm_source_len,
                                  confirm_caps_len,
                                  &confirm_caps) == LIBRDP_STATUS_OK);
    PCHECK(confirm_caps.count == sizeof(expected_confirm_types) / sizeof(expected_confirm_types[0]));
    PCHECK(confirm_caps_len == 455);
    PCHECK(rdp_slowpath_write_deactivate_all(&deactivate_all,
                                             0x12345678u,
                                             1004u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_deactivate_all(deactivate_all.data,
                                             deactivate_all.length,
                                             &parsed_deactivate) ==
           LIBRDP_STATUS_OK);
    PCHECK(parsed_deactivate.has_share_id == 1u);
    PCHECK(parsed_deactivate.share_id == 0x12345678u);
    PCHECK(parsed_deactivate.source_descriptor_len == 1u);
    PCHECK(parsed_deactivate.source_descriptor[0] == 0u);
    {
        static const uint8_t legacy_deactivate[] = {
            0x06, 0x00, 0x16, 0x00, 0xec, 0x03
        };
        const rdp_slowpath_deactivate_all complete = parsed_deactivate;

        PCHECK(rdp_slowpath_parse_deactivate_all(
                   legacy_deactivate,
                   sizeof(legacy_deactivate),
                   &parsed_deactivate) == LIBRDP_STATUS_OK);
        PCHECK(parsed_deactivate.has_share_id == 0u);
        parsed_deactivate = complete;
        PCHECK(rdp_slowpath_parse_deactivate_all(
                   deactivate_all.data,
                   deactivate_all.length - 1u,
                   &parsed_deactivate) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(parsed_deactivate.share_id == complete.share_id);
        deactivate_all.data[10] = 2u;
        PCHECK(rdp_slowpath_parse_deactivate_all(
                   deactivate_all.data,
                   deactivate_all.length,
                   &parsed_deactivate) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(parsed_deactivate.share_id == complete.share_id);
        deactivate_all.data[10] = 1u;
    }
    for (i = 0; i < sizeof(expected_confirm_types) / sizeof(expected_confirm_types[0]); i++)
    {
        PCHECK(confirm_caps.sets[i].type == expected_confirm_types[i]);
        PCHECK(confirm_caps.sets[i].length == expected_confirm_lengths[i]);
    }
    {
        const size_t capabilities_offset = 16u + confirm_source_len;
        const size_t second_type_offset =
            capabilities_offset + 4u + expected_confirm_lengths[0];
        const uint8_t saved_type_low = confirm_active.data[second_type_offset];
        const uint8_t saved_type_high = confirm_active.data[second_type_offset + 1u];

        confirm_active.data[second_type_offset] =
            confirm_active.data[capabilities_offset + 4u];
        confirm_active.data[second_type_offset + 1u] =
            confirm_active.data[capabilities_offset + 5u];
        PCHECK(rdp_slowpath_parse_confirm_active(
                   confirm_active.data,
                   confirm_active.length,
                   &parsed_confirm) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(parsed_confirm.share_id == 0x12345678u);
        confirm_active.data[second_type_offset] = saved_type_low;
        confirm_active.data[second_type_offset + 1u] = saved_type_high;
    }
    confirm_bitmap_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_BITMAP);
    PCHECK(confirm_bitmap_set != NULL);
    PCHECK(rdp_capability_parse_bitmap(confirm_bitmap_set, &confirm_bitmap) == LIBRDP_STATUS_OK);
    PCHECK(confirm_bitmap.preferred_bits_per_pixel == 32 &&
           confirm_bitmap.desktop_width == 800 &&
           confirm_bitmap.desktop_height == 600 &&
           confirm_bitmap.desktop_resize_flag == 1 &&
           confirm_bitmap.bitmap_compression_flag == 1 &&
           confirm_bitmap.multiple_rectangle_support == 1);
    {
        const rdp_capability_bitmap valid_bitmap = confirm_bitmap;
        rdp_capability_set invalid_bitmap_set = *confirm_bitmap_set;
        uint8_t invalid_bitmap_data[24];

        PCHECK(rdp_capability_parse_bitmap(confirm_caps.sets, &confirm_bitmap) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&confirm_bitmap, &valid_bitmap, sizeof(confirm_bitmap)) == 0);
        memcpy(invalid_bitmap_data, confirm_bitmap_set->data, sizeof(invalid_bitmap_data));
        invalid_bitmap_data[0] = 0;
        invalid_bitmap_data[1] = 0;
        invalid_bitmap_set.data = invalid_bitmap_data;
        PCHECK(rdp_capability_parse_bitmap(&invalid_bitmap_set, &confirm_bitmap) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&confirm_bitmap, &valid_bitmap, sizeof(confirm_bitmap)) == 0);
    }
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_GENERAL);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_general(confirm_set, &confirm_general) == LIBRDP_STATUS_OK);
    PCHECK(confirm_general.os_major_type == 1 &&
           confirm_general.os_minor_type == 3 &&
           confirm_general.protocol_version == 0x0200u &&
           confirm_general.extra_flags == 0x0404u &&
           confirm_general.refresh_rect_support == 1 &&
           confirm_general.suppress_output_support == 1);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_ORDER);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_order(confirm_set, &confirm_order) == LIBRDP_STATUS_OK);
    PCHECK(confirm_order.desktop_save_x_granularity == 1 &&
           confirm_order.desktop_save_y_granularity == 20 &&
           confirm_order.maximum_order_level == 1 &&
           confirm_order.order_flags == 0x002au &&
           confirm_order.desktop_save_size == 230400u &&
           confirm_order.text_ansi_code_page == 65001u);
    {
        size_t supported_orders = 0;
        size_t unsupported_orders = 0;

        for (i = 0; i < sizeof(confirm_order.order_support); i++)
        {
            uint8_t field_bytes = 0;
            const uint8_t expected =
                rdp_gdi_primary_order_field_bytes((uint8_t)i, &field_bytes) ? 1u : 0u;

            PCHECK(confirm_order.order_support[i] == expected);
            supported_orders += expected != 0u ? 1u : 0u;
            unsupported_orders += expected == 0u ? 1u : 0u;
        }
        PCHECK(supported_orders > 0u && unsupported_orders > 0u);
    }
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_BITMAP_CACHE_V2);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_bitmap_cache_v2(confirm_set, &confirm_bitmap_cache) == LIBRDP_STATUS_OK);
    PCHECK(confirm_bitmap_cache.cache_flags == 2 &&
           confirm_bitmap_cache.num_cell_caches == 5 &&
           confirm_bitmap_cache.cell_info[0] == 600 &&
           confirm_bitmap_cache.cell_info[1] == 600 &&
           confirm_bitmap_cache.cell_info[2] == 2048 &&
           confirm_bitmap_cache.cell_info[3] == 4096 &&
           confirm_bitmap_cache.cell_info[4] == 2048);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_POINTER);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_pointer(confirm_set, &confirm_pointer) == LIBRDP_STATUS_OK);
    PCHECK(confirm_pointer.color_pointer_flag == 1 &&
           confirm_pointer.color_pointer_cache_size == 128 &&
           confirm_pointer.pointer_cache_size == 128);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_LARGE_POINTER);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_large_pointer(confirm_set, &confirm_large_pointer) == LIBRDP_STATUS_OK);
    PCHECK(confirm_large_pointer.support_flags == 1);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_INPUT);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_input(confirm_set, &confirm_input) == LIBRDP_STATUS_OK);
    PCHECK(confirm_input.input_flags == 0x0115u &&
           confirm_input.keyboard_layout == 0x00000409u &&
           confirm_input.keyboard_type == 4 &&
           confirm_input.keyboard_subtype == 0 &&
           confirm_input.keyboard_function_key == 12);
    {
        const rdp_capability_input valid_input = confirm_input;
        rdp_capability_set invalid_input_set = *confirm_set;
        uint8_t invalid_input_data[84];

        memcpy(invalid_input_data, confirm_set->data, sizeof(invalid_input_data));
        memset(invalid_input_data + 8u, 0, 4u);
        invalid_input_set.data = invalid_input_data;
        PCHECK(rdp_capability_parse_input(&invalid_input_set, &confirm_input) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&confirm_input, &valid_input, sizeof(confirm_input)) == 0);
    }
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_BRUSH);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_brush(confirm_set, &confirm_brush) == LIBRDP_STATUS_OK);
    PCHECK(confirm_brush.support_level == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_GLYPH_CACHE);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_glyph_cache(confirm_set, &confirm_glyph) == LIBRDP_STATUS_OK);
    PCHECK(confirm_glyph.glyph_cache[0].cache_entries == 254 &&
           confirm_glyph.glyph_cache[0].maximum_cell_size == 4 &&
           confirm_glyph.glyph_cache[9].cache_entries == 254 &&
           confirm_glyph.glyph_cache[9].maximum_cell_size == 256 &&
           confirm_glyph.frag_cache_entries == 256 &&
           confirm_glyph.frag_cache_maximum_cell_size == 256 &&
           confirm_glyph.glyph_support_level == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_VIRTUAL_CHANNEL);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_virtual_channel(confirm_set, &confirm_virtual_channel) == LIBRDP_STATUS_OK);
    PCHECK(confirm_virtual_channel.flags == 0 &&
           confirm_virtual_channel.has_chunk_size == 1 &&
           confirm_virtual_channel.chunk_size == 1600);
    PCHECK(rdp_capability_parse_virtual_channel(&virtual_channel_minimal_set, &confirm_virtual_channel) ==
           LIBRDP_STATUS_OK);
    PCHECK(confirm_virtual_channel.flags == 1 &&
           confirm_virtual_channel.has_chunk_size == 0 &&
           confirm_virtual_channel.chunk_size == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_SOUND);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_sound(confirm_set, &confirm_sound) == LIBRDP_STATUS_OK);
    PCHECK(confirm_sound.flags == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_SHARE);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_share(confirm_set, &confirm_share) == LIBRDP_STATUS_OK);
    PCHECK(confirm_share.node_id == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_FONT);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_font(confirm_set, &confirm_font) == LIBRDP_STATUS_OK);
    PCHECK(confirm_font.support_flags == 1);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_CONTROL);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_control(confirm_set, &confirm_control) == LIBRDP_STATUS_OK);
    PCHECK(confirm_control.control_flags == 0 &&
           confirm_control.remote_detach_flag == 0 &&
           confirm_control.control_interest == 2 &&
           confirm_control.detach_interest == 2);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_COLOR_CACHE);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_color_cache(confirm_set, &confirm_color_cache) == LIBRDP_STATUS_OK);
    PCHECK(confirm_color_cache.cache_size == 6);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_GDI_CAPSTYPE_DRAW_NINEGRID_CACHE);
    PCHECK(confirm_set != NULL);
    PCHECK(confirm_set->data_len == 8 &&
           test_read_u32_le(confirm_set->data) == RDP_GDI_NINEGRID_SUPPORT_SUPPORTED_REV2 &&
           test_read_u16_le(confirm_set->data + 4u) == 2560 &&
           test_read_u16_le(confirm_set->data + 6u) == 256);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_GDI_CAPSTYPE_DRAW_GDIPLUS);
    PCHECK(confirm_set == NULL);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_ACTIVATION);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_activation(confirm_set, &confirm_activation) == LIBRDP_STATUS_OK);
    PCHECK(confirm_activation.help_key_flag == 0 &&
           confirm_activation.help_key_index_flag == 0 &&
           confirm_activation.help_extended_key_flag == 0 &&
           confirm_activation.window_manager_key_flag == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_BITMAP_CODECS);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_bitmap_codecs(confirm_set, &confirm_bitmap_codecs) == LIBRDP_STATUS_OK);
    PCHECK(confirm_bitmap_codecs.count == 1 &&
           confirm_bitmap_codecs.codecs[0].codec_id == RDP_NSCODEC_BITMAP_CODEC_ID &&
           confirm_bitmap_codecs.codecs[0].properties_len == RDP_NSCODEC_CAPABILITY_LENGTH &&
           memcmp(confirm_bitmap_codecs.codecs[0].guid, nscodec_guid, sizeof(nscodec_guid)) == 0);
    {
        const rdp_capability_bitmap_codecs valid_codecs = confirm_bitmap_codecs;
        rdp_capability_set invalid_codecs_set = *confirm_set;

        invalid_codecs_set.data_len--;
        invalid_codecs_set.length--;
        PCHECK(rdp_capability_parse_bitmap_codecs(&invalid_codecs_set, &confirm_bitmap_codecs) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&confirm_bitmap_codecs, &valid_codecs, sizeof(confirm_bitmap_codecs)) == 0);
    }
    PCHECK(rdp_nscodec_parse_capability(confirm_bitmap_codecs.codecs[0].properties,
                                        confirm_bitmap_codecs.codecs[0].properties_len,
                                        &confirm_nscodec) == LIBRDP_STATUS_OK);
    PCHECK(confirm_nscodec.allow_dynamic_fidelity == 1 &&
           confirm_nscodec.allow_subsampling == 1 &&
           confirm_nscodec.color_loss_level == 7);
    {
        const rdp_capability_general valid_general = confirm_general;

        PCHECK(rdp_capability_parse_general(confirm_bitmap_set, &confirm_general) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&confirm_general, &valid_general, sizeof(confirm_general)) == 0);
    }
    PCHECK(confirm_caps.sets[0].data[0] == 1 && confirm_caps.sets[0].data[2] == 3 &&
           confirm_caps.sets[0].data[4] == 0x00 && confirm_caps.sets[0].data[5] == 0x02);
    PCHECK(confirm_caps.sets[1].data[0] == 32 && confirm_caps.sets[1].data[8] == 0x20 &&
           confirm_caps.sets[1].data[9] == 0x03 && confirm_caps.sets[1].data[10] == 0x58 &&
           confirm_caps.sets[1].data[11] == 0x02);
    PCHECK(confirm_caps.sets[2].data[30] == 0x2a && confirm_caps.sets[2].data[31] == 0x00);
    PCHECK(confirm_caps.sets[5].data[0] == 1 && confirm_caps.sets[5].data[1] == 0);
    PCHECK(confirm_caps.sets[6].data[0] == 0x15 && confirm_caps.sets[6].data[1] == 0x01 &&
           confirm_caps.sets[6].data[4] == 0x09 && confirm_caps.sets[6].data[5] == 0x04);
    PCHECK(rdp_slowpath_write_client_synchronize(&client_sync, 0x12345678u, 1004) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_sync.data, client_sync.length, &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.share_id == 0x12345678u &&
           data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SYNCHRONIZE &&
           data_pdu.payload_len == 4);
    PCHECK(test_read_u16_le(data_pdu.payload) == 1 && test_read_u16_le(data_pdu.payload + 2) == 1004);
    PCHECK(rdp_slowpath_write_client_control(&client_control, 0x12345678u, 1004, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_control.data, client_control.length, &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL &&
           data_pdu.payload_len == 8 &&
           test_read_u16_le(data_pdu.payload) == 4 &&
           test_read_u16_le(data_pdu.payload + 2) == 0 &&
           test_read_u32_le(data_pdu.payload + 4) == 0);
    client_control.length = 0;
    PCHECK(rdp_slowpath_write_client_control(&client_control, 0x12345678u, 1004, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_control.data, client_control.length, &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL &&
           test_read_u16_le(data_pdu.payload) == 1);
    PCHECK(rdp_slowpath_write_client_control(&client_control, 0x12345678u, 1004, 2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_write_client_persistent_key_list(&client_persistent_keys, 0x12345678u, 1004) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_persistent_keys.data,
                                       client_persistent_keys.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_BITMAP_CACHE_PERSISTENT_LIST &&
           data_pdu.payload_len == 24 &&
           data_pdu.payload[20] == 3);
    for (i = 0; i < 20; i++)
        PCHECK(data_pdu.payload[i] == 0);
    PCHECK(data_pdu.payload[21] == 0 && data_pdu.payload[22] == 0 && data_pdu.payload[23] == 0);
    PCHECK(rdp_slowpath_write_client_font_list(&client_font_list, 0x12345678u, 1004) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_font_list.data, client_font_list.length, &data_pdu) ==
           LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_LIST &&
           data_pdu.payload_len == 8 &&
           test_read_u16_le(data_pdu.payload + 4) == 3 &&
           test_read_u16_le(data_pdu.payload + 6) == 50);
    PCHECK(rdp_slowpath_write_client_keyboard_input(&client_keyboard_input,
                                                    0x12345678u,
                                                    1004,
                                                    0x8000u,
                                                    30) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_keyboard_input.data,
                                       client_keyboard_input.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_INPUT &&
           data_pdu.payload_len == 16 &&
           test_read_u16_le(data_pdu.payload) == 1 &&
           test_read_u16_le(data_pdu.payload + 8) == 4 &&
           test_read_u16_le(data_pdu.payload + 10) == 0x8000u &&
           test_read_u16_le(data_pdu.payload + 12) == 30);
    PCHECK(rdp_slowpath_write_client_keyboard_input(&client_keyboard_input,
                                                    0x12345678u,
                                                    1004,
                                                    0,
                                                    256) == LIBRDP_STATUS_INVALID_ARGUMENT);
    client_keyboard_input.length = 0;
    PCHECK(rdp_slowpath_write_client_unicode_keyboard_input(&client_keyboard_input,
                                                            0x12345678u,
                                                            1004,
                                                            0x8000u,
                                                            0x20acu) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_keyboard_input.data,
                                       client_keyboard_input.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_INPUT &&
           data_pdu.payload_len == 16 &&
           test_read_u16_le(data_pdu.payload + 8) == 5 &&
           test_read_u16_le(data_pdu.payload + 10) == 0x8000u &&
           test_read_u16_le(data_pdu.payload + 12) == 0x20acu);
    PCHECK(rdp_slowpath_write_client_mouse_input(&client_mouse_input,
                                                 0x12345678u,
                                                 1004,
                                                 0x9000u,
                                                 10,
                                                 11) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_mouse_input.data,
                                       client_mouse_input.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_INPUT &&
           data_pdu.payload_len == 16 &&
           test_read_u16_le(data_pdu.payload + 8) == 0x8001u &&
           test_read_u16_le(data_pdu.payload + 10) == 0x9000u &&
           test_read_u16_le(data_pdu.payload + 12) == 10 &&
           test_read_u16_le(data_pdu.payload + 14) == 11);
    client_mouse_input.length = 0;
    PCHECK(rdp_slowpath_write_client_extended_mouse_input(&client_mouse_input,
                                                          0x12345678u,
                                                          1004,
                                                          0x8001u,
                                                          10,
                                                          11) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_mouse_input.data,
                                       client_mouse_input.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_INPUT &&
           data_pdu.payload_len == 16 &&
           test_read_u16_le(data_pdu.payload + 8) == 0x8002u &&
           test_read_u16_le(data_pdu.payload + 10) == 0x8001u &&
           test_read_u16_le(data_pdu.payload + 12) == 10 &&
           test_read_u16_le(data_pdu.payload + 14) == 11);
    PCHECK(rdp_slowpath_write_client_refresh_rect(&client_refresh_rect,
                                                  0x12345678u,
                                                  1004,
                                                  2,
                                                  3,
                                                  800,
                                                  600) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_refresh_rect.data,
                                       client_refresh_rect.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_REFRESH_RECT &&
           data_pdu.payload_len == 12 &&
           data_pdu.payload[0] == 1 &&
           test_read_u16_le(data_pdu.payload + 4) == 2 &&
           test_read_u16_le(data_pdu.payload + 6) == 3 &&
           test_read_u16_le(data_pdu.payload + 8) == 801 &&
           test_read_u16_le(data_pdu.payload + 10) == 602);
    PCHECK(rdp_slowpath_write_client_refresh_rect(&client_refresh_rect,
                                                  0x12345678u,
                                                  1004,
                                                  0xffffu,
                                                  0,
                                                  2,
                                                  1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_write_client_suppress_output(&client_suppress_output,
                                                     0x12345678u,
                                                     1004,
                                                     1,
                                                     2,
                                                     3,
                                                     800,
                                                     600) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_suppress_output.data,
                                       client_suppress_output.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SUPPRESS_OUTPUT &&
           data_pdu.payload_len == 12 &&
           data_pdu.payload[0] == 1 &&
           test_read_u16_le(data_pdu.payload + 4) == 2 &&
           test_read_u16_le(data_pdu.payload + 6) == 3 &&
           test_read_u16_le(data_pdu.payload + 8) == 801 &&
           test_read_u16_le(data_pdu.payload + 10) == 602);
    client_suppress_output.length = 0;
    PCHECK(rdp_slowpath_write_client_suppress_output(&client_suppress_output,
                                                     0x12345678u,
                                                     1004,
                                                     0,
                                                     0,
                                                     0,
                                                     0,
                                                     0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_suppress_output.data,
                                       client_suppress_output.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SUPPRESS_OUTPUT &&
           data_pdu.payload_len == 4 &&
           data_pdu.payload[0] == 0);
    PCHECK(rdp_slowpath_write_client_suppress_output(&client_suppress_output,
                                                     0x12345678u,
                                                     1004,
                                                     1,
                                                     0xffffu,
                                                     0,
                                                     2,
                                                     1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_parse_font_map(font_map_payload, sizeof(font_map_payload), &font_map) == LIBRDP_STATUS_OK);
    PCHECK(font_map.number_entries == 1 && font_map.total_entries == 2 && font_map.map_flags == 3 &&
           font_map.entry_size == 4);
    {
        const rdp_slowpath_font_map valid_font_map = font_map;

        PCHECK(rdp_slowpath_parse_font_map(font_map_payload, sizeof(font_map_payload) - 1u, &font_map) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&font_map, &valid_font_map, sizeof(font_map)) == 0);
    }
    PCHECK(rdp_slowpath_parse_set_error_info(set_error_info_payload,
                                             sizeof(set_error_info_payload),
                                             &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 0x1234u);
    {
        const uint32_t valid_error_info = error_info;

        PCHECK(rdp_slowpath_parse_set_error_info(set_error_info_payload,
                                                 sizeof(set_error_info_payload) - 1u,
                                                 &error_info) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(error_info == valid_error_info);
    }
    PCHECK(rdp_slowpath_parse_save_session_info(save_session_info_payload,
                                                sizeof(save_session_info_payload),
                                                &save_info) == LIBRDP_STATUS_OK);
    PCHECK(save_info.info_type == 1 && save_info.data_len == 2 && save_info.data[0] == 0xaa &&
           save_info.data[1] == 0x55);
    {
        const rdp_slowpath_save_session_info valid_save_info = save_info;

        PCHECK(rdp_slowpath_parse_save_session_info(save_session_info_payload, 3, &save_info) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&save_info, &valid_save_info, sizeof(save_info)) == 0);
    }


    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_free(&client_suppress_output);
    rdp_buffer_free(&deactivate_all);
    rdp_buffer_free(&client_mouse_input);
    rdp_buffer_free(&client_keyboard_input);
    rdp_buffer_free(&client_font_list);
    rdp_buffer_free(&client_persistent_keys);
    rdp_buffer_free(&client_control);
    rdp_buffer_free(&client_sync);
    rdp_buffer_free(&confirm_active);
    return 0;
}
