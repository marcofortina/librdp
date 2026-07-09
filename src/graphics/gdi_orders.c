#include "graphics/gdi_orders.h"

#include "common/stream.h"

#include <limits.h>
#include <string.h>

static int rdp_gdi_primary_order_field_bytes(uint8_t order_type, uint8_t* bytes)
{
    switch (order_type)
    {
        case RDP_GDI_ORDER_DSTBLT:
        case RDP_GDI_ORDER_SCRBLT:
        case RDP_GDI_ORDER_DRAWNINEGRID:
        case RDP_GDI_ORDER_MULTI_DRAWNINEGRID:
        case RDP_GDI_ORDER_OPAQUERECT:
        case RDP_GDI_ORDER_SAVEBITMAP:
        case RDP_GDI_ORDER_MULTIDSTBLT:
        case RDP_GDI_ORDER_MULTISCRBLT:
        case RDP_GDI_ORDER_MULTIOPAQUERECT:
        case RDP_GDI_ORDER_POLYGON_SC:
        case RDP_GDI_ORDER_POLYLINE:
        case RDP_GDI_ORDER_ELLIPSE_SC:
            *bytes = 1;
            return 1;
        case RDP_GDI_ORDER_PATBLT:
        case RDP_GDI_ORDER_LINETO:
        case RDP_GDI_ORDER_MEMBLT:
        case RDP_GDI_ORDER_MEM3BLT:
        case RDP_GDI_ORDER_MULTIPATBLT:
        case RDP_GDI_ORDER_FAST_INDEX:
        case RDP_GDI_ORDER_POLYGON_CB:
        case RDP_GDI_ORDER_FAST_GLYPH:
        case RDP_GDI_ORDER_ELLIPSE_CB:
            *bytes = 2;
            return 1;
        case RDP_GDI_ORDER_GLYPH_INDEX:
            *bytes = 3;
            return 1;
        default:
            return 0;
    }
}

static int rdp_gdi_secondary_order_type_valid(uint8_t order_type)
{
    return order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED ||
           order_type == RDP_GDI_SECONDARY_CACHE_COLOR_TABLE ||
           order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED ||
           order_type == RDP_GDI_SECONDARY_CACHE_GLYPH ||
           order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED_REV2 ||
           order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV2 ||
           order_type == RDP_GDI_SECONDARY_CACHE_BRUSH ||
           order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV3;
}

static int rdp_gdi_altsec_order_type_valid(uint8_t order_type)
{
    return order_type <= RDP_GDI_ALTSEC_FRAME_MARKER;
}

static librdp_status rdp_gdi_parse_bounds(rdp_stream* stream, rdp_gdi_primary_order_header* header)
{
    uint8_t flags = 0;
    size_t start = stream->position;
    size_t i = 0;

    if (rdp_stream_read_u8(stream, &flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < 4u; i++)
    {
        uint8_t absolute = (uint8_t)(1u << i);
        uint8_t delta = (uint8_t)(0x10u << i);

        if ((flags & absolute) && (flags & delta))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (flags & absolute)
        {
            if (rdp_stream_skip(stream, 2u) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (flags & delta)
        {
            if (rdp_stream_skip(stream, 1u) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
    }
    header->bounds_flags = flags;
    header->bounds_len = stream->position - start;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_read_capability_header(rdp_stream* stream,
                                                    uint16_t expected_type,
                                                    uint16_t expected_length)
{
    uint16_t type = 0;
    uint16_t length = 0;

    if (rdp_stream_read_u16_le(stream, &type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (type != expected_type || length != expected_length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_write_capability_header(rdp_buffer* buffer,
                                                     uint16_t type,
                                                     uint16_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, type);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u16_le(buffer, length);
}

librdp_status rdp_gdi_parse_slow_orders_update_payload(const void* data,
                                                       size_t length,
                                                       rdp_gdi_orders_update* update)
{
    rdp_stream stream;
    uint16_t ignored = 0;

    if (!data || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(update, 0, sizeof(*update));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &update->update_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &ignored) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &update->number_orders) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &ignored) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (update->update_type != RDP_GDI_UPDATE_TYPE_ORDERS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    update->order_data_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &update->order_data, update->order_data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_slow_orders_update_payload(rdp_buffer* buffer,
                                                       uint16_t number_orders,
                                                       const void* order_data,
                                                       size_t order_data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!order_data && order_data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, RDP_GDI_UPDATE_TYPE_ORDERS);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, number_orders);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, order_data, order_data_len);
}

librdp_status rdp_gdi_parse_fast_orders_update_payload(const void* data,
                                                       size_t length,
                                                       rdp_gdi_orders_update* update)
{
    rdp_stream stream;

    if (!data || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(update, 0, sizeof(*update));
    rdp_stream_init(&stream, data, length);
    update->update_type = RDP_GDI_UPDATE_TYPE_ORDERS;
    if (rdp_stream_read_u16_le(&stream, &update->number_orders) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    update->order_data_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &update->order_data, update->order_data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_fast_orders_update_payload(rdp_buffer* buffer,
                                                       uint16_t number_orders,
                                                       const void* order_data,
                                                       size_t order_data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!order_data && order_data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, number_orders);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, order_data, order_data_len);
}

librdp_status rdp_gdi_parse_primary_order(const void* data,
                                          size_t length,
                                          uint8_t previous_order_type,
                                          rdp_gdi_primary_order_header* header)
{
    rdp_stream stream;
    uint8_t control_flags = 0;
    uint8_t order_type = previous_order_type;
    uint8_t field_bytes = 0;
    uint8_t zero_field_bytes = 0;
    uint8_t present_field_bytes = 0;
    uint8_t byte = 0;
    size_t i = 0;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &control_flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!(control_flags & RDP_GDI_TS_STANDARD) || (control_flags & RDP_GDI_TS_SECONDARY))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (control_flags & RDP_GDI_TS_TYPE_CHANGE)
    {
        if (rdp_stream_read_u8(&stream, &order_type) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (!rdp_gdi_primary_order_field_bytes(order_type, &field_bytes))
        return LIBRDP_STATUS_UNSUPPORTED;
    zero_field_bytes = (uint8_t)(((control_flags & RDP_GDI_TS_ZERO_FIELD_BYTE_BIT0) ? 1u : 0u) |
                                 ((control_flags & RDP_GDI_TS_ZERO_FIELD_BYTE_BIT1) ? 2u : 0u));
    if (zero_field_bytes > field_bytes)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    present_field_bytes = (uint8_t)(field_bytes - zero_field_bytes);
    for (i = 0; i < present_field_bytes; i++)
    {
        if (rdp_stream_read_u8(&stream, &byte) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        header->field_flags |= (uint32_t)byte << (8u * i);
    }
    if ((control_flags & RDP_GDI_TS_BOUNDS) &&
        !(control_flags & RDP_GDI_TS_ZERO_BOUNDS_DELTAS) &&
        rdp_gdi_parse_bounds(&stream, header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->control_flags = control_flags;
    header->order_type = order_type;
    header->field_flag_bytes = field_bytes;
    header->next_order_type = order_type;
    header->payload_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &header->payload, header->payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_parse_secondary_order(const void* data,
                                            size_t length,
                                            rdp_gdi_secondary_order_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &header->control_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->order_length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->extra_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &header->order_type) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((header->control_flags & (RDP_GDI_TS_STANDARD | RDP_GDI_TS_SECONDARY)) !=
            (RDP_GDI_TS_STANDARD | RDP_GDI_TS_SECONDARY) ||
        !rdp_gdi_secondary_order_type_valid(header->order_type))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->actual_length = (size_t)header->order_length + 13u;
    if (header->actual_length > length || header->actual_length < 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->payload_len = header->actual_length - 6u;
    if (rdp_stream_read_bytes(&stream, &header->payload, header->payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_secondary_order(rdp_buffer* buffer,
                                            uint16_t extra_flags,
                                            uint8_t order_type,
                                            const void* payload,
                                            size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_gdi_secondary_order_type_valid(order_type) ||
        (!payload && payload_len > 0) || payload_len < 7u ||
        payload_len - 7u > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, RDP_GDI_TS_STANDARD | RDP_GDI_TS_SECONDARY);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)(payload_len - 7u));
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, extra_flags);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, order_type);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, payload, payload_len);
}

librdp_status rdp_gdi_parse_altsec_order(const void* data,
                                         size_t length,
                                         rdp_gdi_altsec_order_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &header->control_flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((header->control_flags & 0x03u) != RDP_GDI_TS_SECONDARY)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->order_type = (uint8_t)(header->control_flags >> 2);
    if (!rdp_gdi_altsec_order_type_valid(header->order_type))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->payload_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &header->payload, header->payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_parse_order_list(const void* data,
                                       size_t length,
                                       uint16_t number_orders,
                                       uint8_t initial_order_type,
                                       rdp_gdi_order_list* list)
{
    const uint8_t* bytes = (const uint8_t*)data;
    size_t offset = 0;
    uint16_t index = 0;
    uint8_t current_order_type = initial_order_type;

    if ((!data && length > 0) || !list)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (number_orders > RDP_GDI_MAX_ORDERS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(list, 0, sizeof(*list));
    for (index = 0; index < number_orders; index++)
    {
        uint8_t control = 0;
        rdp_gdi_secondary_order_header secondary;
        rdp_gdi_primary_order_header primary;
        rdp_gdi_altsec_order_header altsec;

        if (offset >= length)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        control = bytes[offset];
        list->orders[index].data = bytes + offset;
        if ((control & (RDP_GDI_TS_STANDARD | RDP_GDI_TS_SECONDARY)) ==
            (RDP_GDI_TS_STANDARD | RDP_GDI_TS_SECONDARY))
        {
            if (rdp_gdi_parse_secondary_order(bytes + offset, length - offset, &secondary) !=
                LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            list->orders[index].kind = RDP_GDI_ORDER_KIND_SECONDARY;
            list->orders[index].order_type = secondary.order_type;
            list->orders[index].length = secondary.actual_length;
            offset += secondary.actual_length;
            continue;
        }
        if ((control & 0x03u) == RDP_GDI_TS_SECONDARY)
        {
            if (index + 1u != number_orders)
                return LIBRDP_STATUS_UNSUPPORTED;
            if (rdp_gdi_parse_altsec_order(bytes + offset, length - offset, &altsec) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            list->orders[index].kind = RDP_GDI_ORDER_KIND_ALTSEC;
            list->orders[index].order_type = altsec.order_type;
            list->orders[index].length = length - offset;
            offset = length;
            continue;
        }
        if (control & RDP_GDI_TS_STANDARD)
        {
            if (index + 1u != number_orders)
                return LIBRDP_STATUS_UNSUPPORTED;
            if (rdp_gdi_parse_primary_order(bytes + offset,
                                            length - offset,
                                            current_order_type,
                                            &primary) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            current_order_type = primary.next_order_type;
            list->orders[index].kind = RDP_GDI_ORDER_KIND_PRIMARY;
            list->orders[index].order_type = primary.order_type;
            list->orders[index].length = length - offset;
            offset = length;
            continue;
        }
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (offset != length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    list->count = number_orders;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_parse_bitmap_cache_error_payload(const void* data,
                                                       size_t length,
                                                       rdp_gdi_bitmap_cache_error* error)
{
    rdp_stream stream;
    uint8_t pad8 = 0;
    uint16_t pad16 = 0;
    uint16_t ignored = 0;
    size_t i = 0;

    if (!data || !error)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(error, 0, sizeof(*error));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &error->count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &pad8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pad16) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (error->count > RDP_GDI_MAX_BITMAP_CACHE_ERROR_INFO ||
        rdp_stream_remaining(&stream) != (size_t)error->count * 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < error->count; i++)
    {
        if (rdp_stream_read_u8(&stream, &error->infos[i].cache_id) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &error->infos[i].flags) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &ignored) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &error->infos[i].new_num_entries) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (error->infos[i].flags &
            ~(RDP_GDI_BITMAP_CACHE_ERROR_FLUSH_CACHE |
              RDP_GDI_BITMAP_CACHE_ERROR_NEWNUMENTRIES_VALID))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_bitmap_cache_error_payload(rdp_buffer* buffer,
                                                       const rdp_gdi_bitmap_cache_error* error)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    if (!buffer || !error || error->count > RDP_GDI_MAX_BITMAP_CACHE_ERROR_INFO)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, error->count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < error->count; i++)
    {
        if (error->infos[i].flags &
            ~(RDP_GDI_BITMAP_CACHE_ERROR_FLUSH_CACHE |
              RDP_GDI_BITMAP_CACHE_ERROR_NEWNUMENTRIES_VALID))
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        status = rdp_buffer_append_u8(buffer, error->infos[i].cache_id);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append_u8(buffer, error->infos[i].flags);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append_u16_le(buffer, 0);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append_u32_le(buffer, error->infos[i].new_num_entries);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_parse_cache_error_flags(const void* data,
                                              size_t length,
                                              uint32_t expected_flags,
                                              uint32_t* flags)
{
    rdp_stream stream;

    if (!data || !flags)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return *flags == expected_flags ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_gdi_write_cache_error_flags(rdp_buffer* buffer, uint32_t flags)
{
    if (!buffer || flags == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u32_le(buffer, flags);
}

librdp_status rdp_gdi_parse_color_cache_capability(const void* data,
                                                   size_t length,
                                                   rdp_gdi_color_cache_capability* capability)
{
    rdp_stream stream;
    uint16_t ignored = 0;

    if (!data || !capability)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != RDP_GDI_COLOR_CACHE_CAPABILITY_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(capability, 0, sizeof(*capability));
    rdp_stream_init(&stream, data, length);
    if (rdp_gdi_read_capability_header(&stream,
                                       RDP_GDI_CAPSTYPE_COLOR_CACHE,
                                       RDP_GDI_COLOR_CACHE_CAPABILITY_LENGTH) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &capability->color_table_cache_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &ignored) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_color_cache_capability(
    rdp_buffer* buffer,
    const rdp_gdi_color_cache_capability* capability)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !capability)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_gdi_write_capability_header(buffer,
                                             RDP_GDI_CAPSTYPE_COLOR_CACHE,
                                             RDP_GDI_COLOR_CACHE_CAPABILITY_LENGTH);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, capability->color_table_cache_size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u16_le(buffer, 0);
}

librdp_status rdp_gdi_parse_ninegrid_capability(const void* data,
                                                size_t length,
                                                rdp_gdi_ninegrid_capability* capability)
{
    rdp_stream stream;

    if (!data || !capability)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != RDP_GDI_DRAW_NINEGRID_CAPABILITY_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(capability, 0, sizeof(*capability));
    rdp_stream_init(&stream, data, length);
    if (rdp_gdi_read_capability_header(&stream,
                                       RDP_GDI_CAPSTYPE_DRAW_NINEGRID_CACHE,
                                       RDP_GDI_DRAW_NINEGRID_CAPABILITY_LENGTH) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &capability->support_level) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &capability->cache_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &capability->cache_entries) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (capability->support_level > RDP_GDI_NINEGRID_SUPPORT_SUPPORTED_REV2 ||
        capability->cache_size > 2560u ||
        capability->cache_entries > 256u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_ninegrid_capability(
    rdp_buffer* buffer,
    const rdp_gdi_ninegrid_capability* capability)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !capability ||
        capability->support_level > RDP_GDI_NINEGRID_SUPPORT_SUPPORTED_REV2 ||
        capability->cache_size > 2560u ||
        capability->cache_entries > 256u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_gdi_write_capability_header(buffer,
                                             RDP_GDI_CAPSTYPE_DRAW_NINEGRID_CACHE,
                                             RDP_GDI_DRAW_NINEGRID_CAPABILITY_LENGTH);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, capability->support_level);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, capability->cache_size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u16_le(buffer, capability->cache_entries);
}

librdp_status rdp_gdi_parse_gdiplus_capability(const void* data,
                                               size_t length,
                                               rdp_gdi_gdiplus_capability* capability)
{
    static const uint16_t max_entries[5] = {10u, 5u, 5u, 10u, 2u};
    static const uint16_t max_chunks[4] = {512u, 2048u, 1024u, 64u};
    static const uint16_t max_properties[3] = {4096u, 256u, 128u};
    rdp_stream stream;
    size_t i = 0;

    if (!data || !capability)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != RDP_GDI_DRAW_GDIPLUS_CAPABILITY_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(capability, 0, sizeof(*capability));
    rdp_stream_init(&stream, data, length);
    if (rdp_gdi_read_capability_header(&stream,
                                       RDP_GDI_CAPSTYPE_DRAW_GDIPLUS,
                                       RDP_GDI_DRAW_GDIPLUS_CAPABILITY_LENGTH) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &capability->support_level) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &capability->version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &capability->cache_level) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (capability->support_level > RDP_GDI_GDIPLUS_SUPPORT_SUPPORTED ||
        capability->cache_level > RDP_GDI_GDIPLUS_CACHE_LEVEL_ONE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < 5u; i++)
    {
        if (rdp_stream_read_u16_le(&stream, &capability->cache_entries[i]) != LIBRDP_STATUS_OK ||
            capability->cache_entries[i] > max_entries[i])
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    for (i = 0; i < 4u; i++)
    {
        if (rdp_stream_read_u16_le(&stream, &capability->cache_chunk_size[i]) != LIBRDP_STATUS_OK ||
            capability->cache_chunk_size[i] > max_chunks[i])
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    for (i = 0; i < 3u; i++)
    {
        if (rdp_stream_read_u16_le(&stream, &capability->image_cache_properties[i]) != LIBRDP_STATUS_OK ||
            capability->image_cache_properties[i] > max_properties[i])
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_gdi_write_gdiplus_capability(
    rdp_buffer* buffer,
    const rdp_gdi_gdiplus_capability* capability)
{
    static const uint16_t max_entries[5] = {10u, 5u, 5u, 10u, 2u};
    static const uint16_t max_chunks[4] = {512u, 2048u, 1024u, 64u};
    static const uint16_t max_properties[3] = {4096u, 256u, 128u};
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    if (!buffer || !capability ||
        capability->support_level > RDP_GDI_GDIPLUS_SUPPORT_SUPPORTED ||
        capability->cache_level > RDP_GDI_GDIPLUS_CACHE_LEVEL_ONE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < 5u; i++)
    {
        if (capability->cache_entries[i] > max_entries[i])
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    for (i = 0; i < 4u; i++)
    {
        if (capability->cache_chunk_size[i] > max_chunks[i])
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    for (i = 0; i < 3u; i++)
    {
        if (capability->image_cache_properties[i] > max_properties[i])
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    status = rdp_gdi_write_capability_header(buffer,
                                             RDP_GDI_CAPSTYPE_DRAW_GDIPLUS,
                                             RDP_GDI_DRAW_GDIPLUS_CAPABILITY_LENGTH);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, capability->support_level);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, capability->version);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, capability->cache_level);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < 5u; i++)
    {
        status = rdp_buffer_append_u16_le(buffer, capability->cache_entries[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    for (i = 0; i < 4u; i++)
    {
        status = rdp_buffer_append_u16_le(buffer, capability->cache_chunk_size[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    for (i = 0; i < 3u; i++)
    {
        status = rdp_buffer_append_u16_le(buffer, capability->image_cache_properties[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}
