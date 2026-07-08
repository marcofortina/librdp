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

librdp_status rdp_capability_parse_bitmap(const rdp_capability_set* set, rdp_capability_bitmap* bitmap)
{
    rdp_stream stream;
    uint16_t pad = 0;

    if (!set || !bitmap)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (set->type != RDP_CAPABILITY_TYPE_BITMAP || !set->data || set->data_len != 24u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(bitmap, 0, sizeof(*bitmap));
    rdp_stream_init(&stream, set->data, set->data_len);
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
