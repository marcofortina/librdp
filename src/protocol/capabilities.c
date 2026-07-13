/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: capability set parsing and serialization support.
 * Invariants: wire lengths, tags, and stream offsets stay consistent across
 * every parse and write path.
 * Ownership: serialized buffers are caller-owned and parsed views never
 * outlive the input stream.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: all protocol bytes are untrusted network input until parsed
 * successfully.
 */


#include "protocol/capabilities.h"

#include "common/stream.h"

#include <string.h>

librdp_status rdp_capabilities_parse(const void* data, size_t length, rdp_capability_list* list)
{
    rdp_stream stream;
    rdp_capability_list parsed;
    uint16_t count = 0;
    uint16_t pad = 0;
    uint16_t i = 0;

    if (!data || !list)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pad) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    (void)pad;

    if (count > RDP_CAPABILITY_MAX_SETS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    for (i = 0; i < count; i++)
    {
        rdp_capability_set* set = &parsed.sets[i];
        uint16_t j = 0;

        if (rdp_stream_read_u16_le(&stream, &set->type) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &set->length) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (set->length < 4 || rdp_stream_remaining(&stream) < (size_t)set->length - 4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (j = 0; j < i; j++)
        {
            if (parsed.sets[j].type == set->type)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        set->data_len = (size_t)set->length - 4u;
        if (rdp_stream_read_bytes(&stream, &set->data, set->data_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }

    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.count = count;
    *list = parsed;
    return LIBRDP_STATUS_OK;
}

const rdp_capability_set* rdp_capabilities_find(const rdp_capability_list* list, uint16_t type)
{
    uint16_t i = 0;

    if (!list)
        return NULL;
    for (i = 0; i < list->count; i++)
    {
        if (list->sets[i].type == type)
            return &list->sets[i];
    }
    return NULL;
}

static librdp_status rdp_capability_stream(const rdp_capability_set* set,
                                           uint16_t type,
                                           size_t min_len,
                                           size_t max_len,
                                           rdp_stream* stream)
{
    if (!set || !stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (set->type != type || !set->data || set->data_len < min_len || set->data_len > max_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(stream, set->data, set->data_len);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_capability_read_pad_u16(rdp_stream* stream)
{
    uint16_t pad = 0;
    return rdp_stream_read_u16_le(stream, &pad);
}

librdp_status rdp_capability_parse_general(const rdp_capability_set* set, rdp_capability_general* general)
{
    rdp_stream stream;
    rdp_capability_general parsed;

    if (!general)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_GENERAL, 20u, 20u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_stream_read_u16_le(&stream, &parsed.os_major_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.os_minor_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.protocol_version) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.compression_types) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.extra_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.update_capability_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.remote_unshare_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.compression_level) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.refresh_rect_support) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.suppress_output_support) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.protocol_version == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *general = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_bitmap(const rdp_capability_set* set, rdp_capability_bitmap* bitmap)
{
    rdp_stream stream;
    rdp_capability_bitmap parsed;
    uint16_t pad = 0;

    if (!set || !bitmap)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_BITMAP, 24u, 24u, &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_stream_read_u16_le(&stream, &parsed.preferred_bits_per_pixel) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.receive_1_bit_per_pixel) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.receive_4_bits_per_pixel) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.receive_8_bits_per_pixel) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.desktop_width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.desktop_height) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pad) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.desktop_resize_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.bitmap_compression_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.high_color_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.drawing_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.multiple_rectangle_support) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pad) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) != 0 ||
        parsed.preferred_bits_per_pixel == 0 ||
        parsed.desktop_width == 0 ||
        parsed.desktop_height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *bitmap = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_order(const rdp_capability_set* set, rdp_capability_order* order)
{
    rdp_stream stream;
    rdp_capability_order parsed;
    const uint8_t* terminal_descriptor = NULL;
    const uint8_t* order_support = NULL;

    if (!order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_ORDER, 84u, 84u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_stream_read_bytes(&stream, &terminal_descriptor, sizeof(parsed.terminal_descriptor)) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 4u) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.desktop_save_x_granularity) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.desktop_save_y_granularity) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.maximum_order_level) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.number_fonts) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.order_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &order_support, sizeof(parsed.order_support)) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.text_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.order_support_ex_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 4u) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.desktop_save_size) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.text_ansi_code_page) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(parsed.terminal_descriptor, terminal_descriptor, sizeof(parsed.terminal_descriptor));
    memcpy(parsed.order_support, order_support, sizeof(parsed.order_support));
    *order = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_bitmap_cache_v2(const rdp_capability_set* set,
                                                   rdp_capability_bitmap_cache_v2* cache)
{
    rdp_stream stream;
    rdp_capability_bitmap_cache_v2 parsed;
    uint8_t pad = 0;
    size_t i = 0;

    if (!cache)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_BITMAP_CACHE_V2, 36u, 36u, &stream) !=
        LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_stream_read_u16_le(&stream, &parsed.cache_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &pad) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.num_cell_caches) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    (void)pad;
    for (i = 0; i < 5u; i++)
    {
        if (rdp_stream_read_u32_le(&stream, &parsed.cell_info[i]) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (rdp_stream_skip(&stream, 12u) != LIBRDP_STATUS_OK || rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.num_cell_caches > 5u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *cache = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_pointer(const rdp_capability_set* set, rdp_capability_pointer* pointer)
{
    rdp_stream stream;
    rdp_capability_pointer parsed;

    if (!pointer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_POINTER, 6u, 6u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_stream_read_u16_le(&stream, &parsed.color_pointer_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.color_pointer_cache_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.pointer_cache_size) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *pointer = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_large_pointer(const rdp_capability_set* set,
                                                 rdp_capability_large_pointer* pointer)
{
    rdp_stream stream;
    rdp_capability_large_pointer parsed;

    if (!pointer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_LARGE_POINTER, 2u, 2u, &stream) !=
        LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_stream_read_u16_le(&stream, &parsed.support_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *pointer = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_input(const rdp_capability_set* set, rdp_capability_input* input)
{
    rdp_stream stream;
    rdp_capability_input parsed;
    const uint8_t* ime = NULL;

    if (!input)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_INPUT, 84u, 84u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_stream_read_u16_le(&stream, &parsed.input_flags) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.keyboard_layout) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.keyboard_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.keyboard_subtype) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.keyboard_function_key) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &ime, sizeof(parsed.ime_file_name)) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(parsed.ime_file_name, ime, sizeof(parsed.ime_file_name));
    if (parsed.keyboard_type == 0 || parsed.keyboard_function_key == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *input = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_brush(const rdp_capability_set* set, rdp_capability_brush* brush)
{
    rdp_stream stream;
    rdp_capability_brush parsed;

    if (!brush)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_BRUSH, 4u, 4u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_stream_read_u32_le(&stream, &parsed.support_level) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *brush = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_glyph_cache(const rdp_capability_set* set,
                                               rdp_capability_glyph_cache* glyph)
{
    rdp_stream stream;
    rdp_capability_glyph_cache parsed;
    size_t i = 0;

    if (!glyph)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_GLYPH_CACHE, 48u, 48u, &stream) !=
        LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    for (i = 0; i < 10u; i++)
    {
        if (rdp_stream_read_u16_le(&stream, &parsed.glyph_cache[i].cache_entries) !=
                LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &parsed.glyph_cache[i].maximum_cell_size) !=
                LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (rdp_stream_read_u16_le(&stream, &parsed.frag_cache_entries) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.frag_cache_maximum_cell_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.glyph_support_level) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *glyph = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_virtual_channel(const rdp_capability_set* set,
                                                   rdp_capability_virtual_channel* channel)
{
    rdp_stream stream;
    rdp_capability_virtual_channel parsed;

    if (!channel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_VIRTUAL_CHANNEL, 4u, 8u, &stream) !=
        LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_stream_read_u32_le(&stream, &parsed.flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) == 4u)
    {
        if (rdp_stream_read_u32_le(&stream, &parsed.chunk_size) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        parsed.has_chunk_size = 1;
    }
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *channel = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_sound(const rdp_capability_set* set, rdp_capability_sound* sound)
{
    rdp_stream stream;
    rdp_capability_sound parsed;

    if (!sound)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_SOUND, 4u, 4u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_stream_read_u16_le(&stream, &parsed.flags) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *sound = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_share(const rdp_capability_set* set, rdp_capability_share* share)
{
    rdp_stream stream;
    rdp_capability_share parsed;

    if (!share)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_SHARE, 4u, 4u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_stream_read_u16_le(&stream, &parsed.node_id) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *share = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_font(const rdp_capability_set* set, rdp_capability_font* font)
{
    rdp_stream stream;
    rdp_capability_font parsed;

    if (!font)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_FONT, 4u, 4u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_stream_read_u16_le(&stream, &parsed.support_flags) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *font = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_control(const rdp_capability_set* set, rdp_capability_control* control)
{
    rdp_stream stream;
    rdp_capability_control parsed;

    if (!control)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_CONTROL, 8u, 8u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_stream_read_u16_le(&stream, &parsed.control_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.remote_detach_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.control_interest) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.detach_interest) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *control = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_color_cache(const rdp_capability_set* set,
                                               rdp_capability_color_cache* color_cache)
{
    rdp_stream stream;
    rdp_capability_color_cache parsed;

    if (!color_cache)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_COLOR_CACHE, 4u, 4u, &stream) !=
        LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_stream_read_u16_le(&stream, &parsed.cache_size) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *color_cache = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_activation(const rdp_capability_set* set,
                                              rdp_capability_activation* activation)
{
    rdp_stream stream;
    rdp_capability_activation parsed;

    if (!activation)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_ACTIVATION, 8u, 8u, &stream) !=
        LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_stream_read_u16_le(&stream, &parsed.help_key_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.help_key_index_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.help_extended_key_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.window_manager_key_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *activation = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_bitmap_codecs(const rdp_capability_set* set,
                                                 rdp_capability_bitmap_codecs* codecs)
{
    rdp_stream stream;
    rdp_capability_bitmap_codecs parsed;
    uint8_t count = 0;
    uint8_t i = 0;

    if (!codecs)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_BITMAP_CODECS, 1u, (size_t)-1, &stream) !=
        LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_stream_read_u8(&stream, &count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (count > RDP_CAPABILITY_BITMAP_CODECS_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < count; i++)
    {
        rdp_capability_bitmap_codec* codec = &parsed.codecs[i];
        const uint8_t* guid = NULL;

        if (rdp_stream_read_bytes(&stream, &guid, sizeof(codec->guid)) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &codec->codec_id) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &codec->properties_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        memcpy(codec->guid, guid, sizeof(codec->guid));
        if (codec->properties_len > rdp_stream_remaining(&stream))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (codec->properties_len > 0 &&
            rdp_stream_read_bytes(&stream, &codec->properties, codec->properties_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.count = count;
    *codecs = parsed;
    return LIBRDP_STATUS_OK;
}
