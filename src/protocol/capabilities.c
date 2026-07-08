#include "protocol/capabilities.h"

#include "common/stream.h"

#include <string.h>

librdp_status rdp_capabilities_parse(const void* data, size_t length, rdp_capability_list* list)
{
    rdp_stream stream;
    uint16_t count = 0;
    uint16_t pad = 0;
    uint16_t i = 0;

    if (!data || !list)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(list, 0, sizeof(*list));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pad) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    (void)pad;

    if (count > RDP_CAPABILITY_MAX_SETS)
        return LIBRDP_STATUS_UNSUPPORTED;

    for (i = 0; i < count; i++)
    {
        rdp_capability_set* set = &list->sets[i];
        if (rdp_stream_read_u16_le(&stream, &set->type) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &set->length) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (set->length < 4 || rdp_stream_remaining(&stream) < (size_t)set->length - 4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        set->data_len = (size_t)set->length - 4u;
        if (rdp_stream_read_bytes(&stream, &set->data, set->data_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }

    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    list->count = count;
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

    if (!general)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_GENERAL, 20u, 20u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(general, 0, sizeof(*general));
    if (rdp_stream_read_u16_le(&stream, &general->os_major_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &general->os_minor_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &general->protocol_version) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &general->compression_types) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &general->extra_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &general->update_capability_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &general->remote_unshare_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &general->compression_level) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &general->refresh_rect_support) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &general->suppress_output_support) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (general->protocol_version == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_bitmap(const rdp_capability_set* set, rdp_capability_bitmap* bitmap)
{
    rdp_stream stream;
    uint16_t pad = 0;

    if (!set || !bitmap)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_BITMAP, 24u, 24u, &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(bitmap, 0, sizeof(*bitmap));
    if (rdp_stream_read_u16_le(&stream, &bitmap->preferred_bits_per_pixel) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &bitmap->receive_1_bit_per_pixel) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &bitmap->receive_4_bits_per_pixel) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &bitmap->receive_8_bits_per_pixel) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &bitmap->desktop_width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &bitmap->desktop_height) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pad) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &bitmap->desktop_resize_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &bitmap->bitmap_compression_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &bitmap->high_color_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &bitmap->drawing_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &bitmap->multiple_rectangle_support) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pad) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) != 0 ||
        bitmap->preferred_bits_per_pixel == 0 ||
        bitmap->desktop_width == 0 ||
        bitmap->desktop_height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_order(const rdp_capability_set* set, rdp_capability_order* order)
{
    rdp_stream stream;
    const uint8_t* terminal_descriptor = NULL;
    const uint8_t* order_support = NULL;

    if (!order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_ORDER, 84u, 84u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(order, 0, sizeof(*order));
    if (rdp_stream_read_bytes(&stream, &terminal_descriptor, sizeof(order->terminal_descriptor)) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 4u) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->desktop_save_x_granularity) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->desktop_save_y_granularity) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->maximum_order_level) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->number_fonts) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->order_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &order_support, sizeof(order->order_support)) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->text_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->order_support_ex_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 4u) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->desktop_save_size) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->text_ansi_code_page) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(order->terminal_descriptor, terminal_descriptor, sizeof(order->terminal_descriptor));
    memcpy(order->order_support, order_support, sizeof(order->order_support));
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_bitmap_cache_v2(const rdp_capability_set* set,
                                                   rdp_capability_bitmap_cache_v2* cache)
{
    rdp_stream stream;
    uint8_t pad = 0;
    size_t i = 0;

    if (!cache)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_BITMAP_CACHE_V2, 36u, 36u, &stream) !=
        LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(cache, 0, sizeof(*cache));
    if (rdp_stream_read_u16_le(&stream, &cache->cache_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &pad) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &cache->num_cell_caches) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    (void)pad;
    for (i = 0; i < 5u; i++)
    {
        if (rdp_stream_read_u32_le(&stream, &cache->cell_info[i]) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (rdp_stream_skip(&stream, 12u) != LIBRDP_STATUS_OK || rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (cache->num_cell_caches > 5u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_pointer(const rdp_capability_set* set, rdp_capability_pointer* pointer)
{
    rdp_stream stream;

    if (!pointer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_POINTER, 6u, 6u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(pointer, 0, sizeof(*pointer));
    if (rdp_stream_read_u16_le(&stream, &pointer->color_pointer_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pointer->color_pointer_cache_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pointer->pointer_cache_size) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_large_pointer(const rdp_capability_set* set,
                                                 rdp_capability_large_pointer* pointer)
{
    rdp_stream stream;

    if (!pointer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_LARGE_POINTER, 2u, 2u, &stream) !=
        LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(pointer, 0, sizeof(*pointer));
    if (rdp_stream_read_u16_le(&stream, &pointer->support_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_input(const rdp_capability_set* set, rdp_capability_input* input)
{
    rdp_stream stream;
    const uint8_t* ime = NULL;

    if (!input)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_INPUT, 84u, 84u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(input, 0, sizeof(*input));
    if (rdp_stream_read_u16_le(&stream, &input->input_flags) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &input->keyboard_layout) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &input->keyboard_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &input->keyboard_subtype) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &input->keyboard_function_key) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &ime, sizeof(input->ime_file_name)) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(input->ime_file_name, ime, sizeof(input->ime_file_name));
    if (input->keyboard_type == 0 || input->keyboard_function_key == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_brush(const rdp_capability_set* set, rdp_capability_brush* brush)
{
    rdp_stream stream;

    if (!brush)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_BRUSH, 4u, 4u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(brush, 0, sizeof(*brush));
    if (rdp_stream_read_u32_le(&stream, &brush->support_level) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_glyph_cache(const rdp_capability_set* set,
                                               rdp_capability_glyph_cache* glyph)
{
    rdp_stream stream;
    size_t i = 0;

    if (!glyph)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_GLYPH_CACHE, 48u, 48u, &stream) !=
        LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(glyph, 0, sizeof(*glyph));
    for (i = 0; i < 10u; i++)
    {
        if (rdp_stream_read_u16_le(&stream, &glyph->glyph_cache[i].cache_entries) !=
                LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &glyph->glyph_cache[i].maximum_cell_size) !=
                LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (rdp_stream_read_u16_le(&stream, &glyph->frag_cache_entries) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &glyph->frag_cache_maximum_cell_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &glyph->glyph_support_level) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_virtual_channel(const rdp_capability_set* set,
                                                   rdp_capability_virtual_channel* channel)
{
    rdp_stream stream;

    if (!channel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_VIRTUAL_CHANNEL, 4u, 8u, &stream) !=
        LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(channel, 0, sizeof(*channel));
    if (rdp_stream_read_u32_le(&stream, &channel->flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) == 4u)
    {
        if (rdp_stream_read_u32_le(&stream, &channel->chunk_size) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        channel->has_chunk_size = 1;
    }
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_sound(const rdp_capability_set* set, rdp_capability_sound* sound)
{
    rdp_stream stream;

    if (!sound)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_SOUND, 4u, 4u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(sound, 0, sizeof(*sound));
    if (rdp_stream_read_u16_le(&stream, &sound->flags) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_share(const rdp_capability_set* set, rdp_capability_share* share)
{
    rdp_stream stream;

    if (!share)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_SHARE, 4u, 4u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(share, 0, sizeof(*share));
    if (rdp_stream_read_u16_le(&stream, &share->node_id) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_font(const rdp_capability_set* set, rdp_capability_font* font)
{
    rdp_stream stream;

    if (!font)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_FONT, 4u, 4u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(font, 0, sizeof(*font));
    if (rdp_stream_read_u16_le(&stream, &font->support_flags) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_control(const rdp_capability_set* set, rdp_capability_control* control)
{
    rdp_stream stream;

    if (!control)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_CONTROL, 8u, 8u, &stream) != LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(control, 0, sizeof(*control));
    if (rdp_stream_read_u16_le(&stream, &control->control_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &control->remote_detach_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &control->control_interest) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &control->detach_interest) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_color_cache(const rdp_capability_set* set,
                                               rdp_capability_color_cache* color_cache)
{
    rdp_stream stream;

    if (!color_cache)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_COLOR_CACHE, 4u, 4u, &stream) !=
        LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(color_cache, 0, sizeof(*color_cache));
    if (rdp_stream_read_u16_le(&stream, &color_cache->cache_size) != LIBRDP_STATUS_OK ||
        rdp_capability_read_pad_u16(&stream) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_activation(const rdp_capability_set* set,
                                              rdp_capability_activation* activation)
{
    rdp_stream stream;

    if (!activation)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_ACTIVATION, 8u, 8u, &stream) !=
        LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(activation, 0, sizeof(*activation));
    if (rdp_stream_read_u16_le(&stream, &activation->help_key_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &activation->help_key_index_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &activation->help_extended_key_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &activation->window_manager_key_flag) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_capability_parse_bitmap_codecs(const rdp_capability_set* set,
                                                 rdp_capability_bitmap_codecs* codecs)
{
    rdp_stream stream;
    uint8_t count = 0;
    uint8_t i = 0;

    if (!codecs)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_capability_stream(set, RDP_CAPABILITY_TYPE_BITMAP_CODECS, 1u, (size_t)-1, &stream) !=
        LIBRDP_STATUS_OK)
        return set ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(codecs, 0, sizeof(*codecs));
    if (rdp_stream_read_u8(&stream, &count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (count > RDP_CAPABILITY_BITMAP_CODECS_MAX)
        return LIBRDP_STATUS_UNSUPPORTED;
    for (i = 0; i < count; i++)
    {
        rdp_capability_bitmap_codec* codec = &codecs->codecs[i];
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
    codecs->count = count;
    return LIBRDP_STATUS_OK;
}
