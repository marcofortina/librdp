#include "graphics/gdi_orders.h"

#include "common/stream.h"
#include "graphics/gdi_render.h"
#include "graphics/surface_commands.h"

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
        case RDP_GDI_ORDER_MULTISCRBLT:
        case RDP_GDI_ORDER_MULTIOPAQUERECT:
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

static librdp_status rdp_gdi_altsec_payload_length(uint8_t order_type,
                                                   const uint8_t* payload,
                                                   size_t available,
                                                   size_t* payload_len)
{
    size_t need = available;

    if (!payload || !payload_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (order_type)
    {
        case RDP_GDI_ALTSEC_SWITCH_SURFACE:
            need = 2u;
            break;
        case RDP_GDI_ALTSEC_FRAME_MARKER:
            need = 4u;
            break;
        case RDP_GDI_ALTSEC_CREATE_NINEGRID_BITMAP:
            need = 19u;
            break;
        case RDP_GDI_ALTSEC_CREATE_OFFSCREEN_BITMAP:
            if (available < 6u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            need = 6u;
            if ((payload[1] & 0x80u) != 0)
            {
                uint16_t delete_count = 0;

                if (available < 8u)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                delete_count = (uint16_t)payload[6] | ((uint16_t)payload[7] << 8u);
                if (delete_count > RDP_GDI_MAX_OFFSCREEN_DELETE_INDICES)
                    return LIBRDP_STATUS_UNSUPPORTED;
                need = 8u + ((size_t)delete_count * 2u);
            }
            break;
        case RDP_GDI_ALTSEC_STREAM_BITMAP_FIRST:
            if (available < 12u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if ((payload[0] & RDP_GDI_STREAM_BITMAP_V2) != 0)
            {
                uint16_t block_len = 0;

                if (available < 14u)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                block_len = (uint16_t)payload[12] | ((uint16_t)payload[13] << 8u);
                need = 14u + block_len;
            }
            else
            {
                uint16_t block_len = (uint16_t)payload[10] | ((uint16_t)payload[11] << 8u);

                need = 12u + block_len;
            }
            break;
        case RDP_GDI_ALTSEC_STREAM_BITMAP_NEXT:
            if (available < 5u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            need = 5u + ((uint16_t)payload[3] | ((uint16_t)payload[4] << 8u));
            break;
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
    if (need > available)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *payload_len = need;
    return LIBRDP_STATUS_OK;
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

static int rdp_gdi_valid_bounds_blob(const void* data, size_t length)
{
    rdp_stream stream;
    rdp_gdi_primary_order_header header;

    if (!data || length == 0)
        return 0;
    memset(&header, 0, sizeof(header));
    rdp_stream_init(&stream, data, length);
    if (rdp_gdi_parse_bounds(&stream, &header) != LIBRDP_STATUS_OK)
        return 0;
    return stream.position == length;
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

static librdp_status rdp_gdi_restore_on_error(rdp_buffer* buffer,
                                              size_t start,
                                              librdp_status status)
{
    if (status != LIBRDP_STATUS_OK && buffer)
        buffer->length = start;
    return status;
}

static librdp_status rdp_gdi_read_2byte_unsigned(rdp_stream* stream, uint32_t* value)
{
    uint8_t first = 0;
    uint8_t second = 0;

    if (!stream || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u8(stream, &first) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((first & 0x80u) == 0)
    {
        *value = first & 0x7fu;
        return LIBRDP_STATUS_OK;
    }
    if (rdp_stream_read_u8(stream, &second) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = (((uint32_t)first & 0x7fu) << 8u) | second;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_read_2byte_signed(rdp_stream* stream, int32_t* value)
{
    uint8_t first = 0;
    uint8_t second = 0;
    uint32_t raw = 0;

    if (!stream || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u8(stream, &first) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((first & 0x80u) == 0)
    {
        raw = (uint32_t)(first & 0x7fu);
        if (raw & 0x40u)
            raw |= 0xffffff80u;
        *value = (int32_t)raw;
        return LIBRDP_STATUS_OK;
    }
    if (rdp_stream_read_u8(stream, &second) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    raw = (((uint32_t)first & 0x7fu) << 8u) | second;
    if (raw & 0x4000u)
        raw |= 0xffff8000u;
    *value = (int32_t)raw;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_glyph_bitmap_padded_len(uint32_t width,
                                                     uint32_t height,
                                                     uint32_t* length)
{
    uint32_t stride = 0;
    uint32_t total = 0;

    if (!length || width == 0 || height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (width > UINT32_MAX - 7u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    stride = (width + 7u) / 8u;
    if (height > UINT32_MAX / stride)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    total = stride * height;
    if (total > UINT32_MAX - 3u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    total = (total + 3u) & ~3u;
    if (total == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *length = total;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_read_4byte_unsigned(rdp_stream* stream, uint32_t* value)
{
    uint8_t first = 0;
    uint8_t byte = 0;
    uint8_t count = 0;
    uint32_t out = 0;

    if (!stream || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u8(stream, &first) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    count = (uint8_t)((first & 0xc0u) >> 6u);
    out = (uint32_t)(first & 0x3fu);
    while (count > 0)
    {
        if (rdp_stream_read_u8(stream, &byte) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        out = (out << 8u) | byte;
        count--;
    }
    *value = out;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_cbr2_bpp(uint32_t encoded, uint32_t* bits_per_pixel)
{
    if (!bits_per_pixel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (encoded)
    {
        case 3u:
            *bits_per_pixel = 8;
            return LIBRDP_STATUS_OK;
        case 4u:
            *bits_per_pixel = 16;
            return LIBRDP_STATUS_OK;
        case 5u:
            *bits_per_pixel = 24;
            return LIBRDP_STATUS_OK;
        case 6u:
            *bits_per_pixel = 32;
            return LIBRDP_STATUS_OK;
        default:
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
}

static librdp_status rdp_gdi_parse_cache_bitmap_order_rev3(rdp_stream* stream,
                                                           const rdp_gdi_secondary_order_header* header,
                                                           rdp_gdi_cache_bitmap_order* order)
{
    uint8_t bpp = 0;
    uint8_t reserved1 = 0;
    uint8_t reserved2 = 0;
    uint16_t cache_index = 0;
    uint16_t width = 0;
    uint16_t height = 0;
    uint32_t flags = 0;
    uint32_t bpp_id = 0;
    uint32_t bitmap_length = 0;
    const uint8_t* bitmap = NULL;

    if (!stream || !header || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    flags = (header->extra_flags & 0xff80u) >> 7u;
    bpp_id = (header->extra_flags & 0x0078u) >> 3u;
    order->rev3 = 1;
    order->cache_id = header->extra_flags & 0x0007u;
    if ((flags & ~(RDP_GDI_CBR3_IGNORABLE_FLAG | RDP_GDI_CBR3_DO_NOT_CACHE)) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_gdi_cbr2_bpp(bpp_id, &order->bits_per_pixel) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u16_le(stream, &cache_index) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &order->key1) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &order->key2) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &bpp) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &reserved1) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &reserved2) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &order->codec_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &height) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &bitmap_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    order->cache_index = cache_index;
    order->width = width;
    order->height = height;
    if ((flags & RDP_GDI_CBR3_DO_NOT_CACHE) != 0)
    {
        if (cache_index != RDP_GDI_BITMAP_CACHE_WAITING_LIST_INDEX)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        order->do_not_cache = 1;
    }
    if (reserved1 != 0 || reserved2 != 0 ||
        bpp != order->bits_per_pixel ||
        order->width == 0 || order->height == 0 ||
        bitmap_length == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (order->codec_id != RDP_SURFACE_CODEC_NONE &&
        order->codec_id != RDP_SURFACE_CODEC_NSCODEC &&
        order->codec_id != RDP_SURFACE_CODEC_REMOTEFX &&
        order->codec_id != RDP_SURFACE_CODEC_IMAGE_REMOTEFX)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (rdp_stream_remaining(stream) < bitmap_length ||
        rdp_stream_read_bytes(stream, &bitmap, bitmap_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    order->compressed = order->codec_id != RDP_SURFACE_CODEC_NONE;
    order->bitmap_data = bitmap;
    order->bitmap_data_len = bitmap_length;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_parse_slow_orders_update_payload(const void* data,
                                                       size_t length,
                                                       rdp_gdi_orders_update* update)
{
    rdp_gdi_orders_update parsed;
    rdp_stream stream;
    uint16_t ignored = 0;

    if (!data || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &parsed.update_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &ignored) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.number_orders) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &ignored) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.update_type != RDP_GDI_UPDATE_TYPE_ORDERS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.number_orders > RDP_GDI_MAX_ORDERS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.order_data_len = rdp_stream_remaining(&stream);
    if (parsed.number_orders == 0 && parsed.order_data_len != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &parsed.order_data, parsed.order_data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *update = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_slow_orders_update_payload(rdp_buffer* buffer,
                                                       uint16_t number_orders,
                                                       const void* order_data,
                                                       size_t order_data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || (!order_data && order_data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (number_orders > RDP_GDI_MAX_ORDERS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (number_orders == 0 && order_data_len != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u16_le(buffer, RDP_GDI_UPDATE_TYPE_ORDERS);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, number_orders);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer, order_data, order_data_len);
    return rdp_gdi_restore_on_error(buffer, start, status);
}

librdp_status rdp_gdi_parse_fast_orders_update_payload(const void* data,
                                                       size_t length,
                                                       rdp_gdi_orders_update* update)
{
    rdp_gdi_orders_update parsed;
    rdp_stream stream;

    if (!data || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    parsed.update_type = RDP_GDI_UPDATE_TYPE_ORDERS;
    if (rdp_stream_read_u16_le(&stream, &parsed.number_orders) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.number_orders > RDP_GDI_MAX_ORDERS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.order_data_len = rdp_stream_remaining(&stream);
    if (parsed.number_orders == 0 && parsed.order_data_len != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &parsed.order_data, parsed.order_data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *update = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_fast_orders_update_payload(rdp_buffer* buffer,
                                                       uint16_t number_orders,
                                                       const void* order_data,
                                                       size_t order_data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || (!order_data && order_data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (number_orders > RDP_GDI_MAX_ORDERS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (number_orders == 0 && order_data_len != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u16_le(buffer, number_orders);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer, order_data, order_data_len);
    return rdp_gdi_restore_on_error(buffer, start, status);
}

librdp_status rdp_gdi_parse_primary_order(const void* data,
                                          size_t length,
                                          uint8_t previous_order_type,
                                          rdp_gdi_primary_order_header* header)
{
    rdp_gdi_primary_order_header parsed;
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
    memset(&parsed, 0, sizeof(parsed));
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
        parsed.field_flags |= (uint32_t)byte << (8u * i);
    }
    if ((control_flags & RDP_GDI_TS_BOUNDS) &&
        !(control_flags & RDP_GDI_TS_ZERO_BOUNDS_DELTAS) &&
        rdp_gdi_parse_bounds(&stream, &parsed) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.control_flags = control_flags;
    parsed.order_type = order_type;
    parsed.field_flag_bytes = field_bytes;
    parsed.next_order_type = order_type;
    parsed.payload_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &parsed.payload, parsed.payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *header = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_primary_order(rdp_buffer* buffer,
                                          uint8_t previous_order_type,
                                          uint8_t order_type,
                                          uint8_t control_flags,
                                          uint32_t field_flags,
                                          const void* bounds,
                                          size_t bounds_len,
                                          const void* payload,
                                          size_t payload_len)
{
    uint8_t field_bytes = 0;
    uint8_t zero_field_bytes = 0;
    uint8_t present_field_bytes = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;
    size_t start = 0;

    if (!buffer || (!payload && payload_len > 0) ||
        (control_flags & RDP_GDI_TS_SECONDARY) ||
        !(control_flags & RDP_GDI_TS_STANDARD) ||
        !rdp_gdi_primary_order_field_bytes(order_type, &field_bytes))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((control_flags & RDP_GDI_TS_TYPE_CHANGE) == 0 &&
        order_type != previous_order_type)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    zero_field_bytes = (uint8_t)(((control_flags & RDP_GDI_TS_ZERO_FIELD_BYTE_BIT0) ? 1u : 0u) |
                                 ((control_flags & RDP_GDI_TS_ZERO_FIELD_BYTE_BIT1) ? 2u : 0u));
    if (zero_field_bytes > field_bytes)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    present_field_bytes = (uint8_t)(field_bytes - zero_field_bytes);
    if (present_field_bytes < 4u && (field_flags >> (8u * present_field_bytes)) != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (control_flags & RDP_GDI_TS_BOUNDS)
    {
        if (control_flags & RDP_GDI_TS_ZERO_BOUNDS_DELTAS)
        {
            if (bounds_len != 0)
                return LIBRDP_STATUS_INVALID_ARGUMENT;
        }
        else if (!rdp_gdi_valid_bounds_blob(bounds, bounds_len))
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    else if (bounds_len != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, control_flags);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    if (control_flags & RDP_GDI_TS_TYPE_CHANGE)
    {
        status = rdp_buffer_append_u8(buffer, order_type);
        if (status != LIBRDP_STATUS_OK)
            return rdp_gdi_restore_on_error(buffer, start, status);
    }
    for (i = 0; i < present_field_bytes; i++)
    {
        status = rdp_buffer_append_u8(buffer, (uint8_t)((field_flags >> (8u * i)) & 0xffu));
        if (status != LIBRDP_STATUS_OK)
            return rdp_gdi_restore_on_error(buffer, start, status);
    }
    if ((control_flags & RDP_GDI_TS_BOUNDS) &&
        !(control_flags & RDP_GDI_TS_ZERO_BOUNDS_DELTAS))
    {
        status = rdp_buffer_append(buffer, bounds, bounds_len);
        if (status != LIBRDP_STATUS_OK)
            return rdp_gdi_restore_on_error(buffer, start, status);
    }
    status = rdp_buffer_append(buffer, payload, payload_len);
    return rdp_gdi_restore_on_error(buffer, start, status);
}

librdp_status rdp_gdi_parse_secondary_order(const void* data,
                                            size_t length,
                                            rdp_gdi_secondary_order_header* header)
{
    rdp_gdi_secondary_order_header parsed;
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &parsed.control_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.order_length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.extra_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.order_type) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((parsed.control_flags & (RDP_GDI_TS_STANDARD | RDP_GDI_TS_SECONDARY)) !=
            (RDP_GDI_TS_STANDARD | RDP_GDI_TS_SECONDARY) ||
        !rdp_gdi_secondary_order_type_valid(parsed.order_type))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.actual_length = (size_t)parsed.order_length + 13u;
    if (parsed.actual_length > length || parsed.actual_length < 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.payload_len = parsed.actual_length - 6u;
    if (rdp_stream_read_bytes(&stream, &parsed.payload, parsed.payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *header = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_secondary_order(rdp_buffer* buffer,
                                            uint16_t extra_flags,
                                            uint8_t order_type,
                                            const void* payload,
                                            size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !rdp_gdi_secondary_order_type_valid(order_type) ||
        (!payload && payload_len > 0) || payload_len < 7u ||
        payload_len - 7u > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, RDP_GDI_TS_STANDARD | RDP_GDI_TS_SECONDARY);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)(payload_len - 7u));
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, extra_flags);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u8(buffer, order_type);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer, payload, payload_len);
    return rdp_gdi_restore_on_error(buffer, start, status);
}

librdp_status rdp_gdi_parse_cache_bitmap_order(const rdp_gdi_secondary_order_header* header,
                                               rdp_gdi_cache_bitmap_order* order)
{
    rdp_gdi_cache_bitmap_order parsed;
    rdp_stream stream;
    const uint8_t* bitmap = NULL;

    if (!header || !order || !header->payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->order_type != RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED &&
        header->order_type != RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED &&
        header->order_type != RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED_REV2 &&
        header->order_type != RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV2 &&
        header->order_type != RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV3)
        return LIBRDP_STATUS_UNSUPPORTED;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, header->payload, header->payload_len);
    if (header->order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED ||
        header->order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED)
    {
        uint8_t pad = 0;
        uint8_t cache_id = 0;
        uint8_t width = 0;
        uint8_t height = 0;
        uint8_t bits_per_pixel = 0;
        uint16_t bitmap_length = 0;
        uint16_t cache_index = 0;

        if (header->payload_len < 9u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        parsed.compressed = header->order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED;
        if (rdp_stream_read_u8(&stream, &cache_id) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &pad) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &width) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &height) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &bits_per_pixel) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &bitmap_length) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &cache_index) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        parsed.cache_id = cache_id;
        parsed.width = width;
        parsed.height = height;
        parsed.bits_per_pixel = bits_per_pixel;
        parsed.cache_index = cache_index;
        if (pad != 0 ||
            parsed.cache_id > 4u ||
            parsed.width == 0 ||
            parsed.height == 0 ||
            parsed.bits_per_pixel == 0 ||
            parsed.bits_per_pixel > 32u ||
            bitmap_length == 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (parsed.compressed && (header->extra_flags & RDP_GDI_NO_BITMAP_COMPRESSION_HEADER) == 0)
        {
            if (bitmap_length < 8u ||
                rdp_stream_remaining(&stream) < bitmap_length ||
                rdp_stream_read_bytes(&stream, &bitmap, bitmap_length) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            memcpy(parsed.compression_header, bitmap, sizeof(parsed.compression_header));
            parsed.has_compression_header = 1;
            parsed.bitmap_data_includes_compression_header = 1;
            parsed.bitmap_data = bitmap;
            parsed.bitmap_data_len = bitmap_length;
        }
        else
        {
            if (rdp_stream_remaining(&stream) < bitmap_length ||
                rdp_stream_read_bytes(&stream, &bitmap, bitmap_length) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            parsed.bitmap_data = bitmap;
            parsed.bitmap_data_len = bitmap_length;
        }
    }
    else if (header->order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV3)
    {
        librdp_status status = rdp_gdi_parse_cache_bitmap_order_rev3(&stream, header, &parsed);

        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    else
    {
        uint32_t flags = (header->extra_flags & 0xff80u) >> 7u;
        uint32_t bpp_id = (header->extra_flags & 0x0078u) >> 3u;
        uint32_t bitmap_length = 0;

        parsed.compressed = header->order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV2;
        parsed.cache_id = header->extra_flags & 0x0007u;
        if ((flags & ~(RDP_GDI_CBR2_HEIGHT_SAME_AS_WIDTH |
                       RDP_GDI_CBR2_PERSISTENT_KEY_PRESENT |
                       RDP_GDI_CBR2_NO_BITMAP_COMPRESSION_HEADER |
                       RDP_GDI_CBR2_DO_NOT_CACHE)) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_gdi_cbr2_bpp(bpp_id, &parsed.bits_per_pixel) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (flags & RDP_GDI_CBR2_PERSISTENT_KEY_PRESENT)
        {
            if (rdp_stream_read_u32_le(&stream, &parsed.key1) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u32_le(&stream, &parsed.key2) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (rdp_gdi_read_2byte_unsigned(&stream, &parsed.width) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (flags & RDP_GDI_CBR2_HEIGHT_SAME_AS_WIDTH)
            parsed.height = parsed.width;
        else if (rdp_gdi_read_2byte_unsigned(&stream, &parsed.height) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_gdi_read_4byte_unsigned(&stream, &bitmap_length) != LIBRDP_STATUS_OK ||
            rdp_gdi_read_2byte_unsigned(&stream, &parsed.cache_index) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (flags & RDP_GDI_CBR2_DO_NOT_CACHE)
        {
            parsed.do_not_cache = 1;
            parsed.cache_index = RDP_GDI_BITMAP_CACHE_WAITING_LIST_INDEX;
        }
        if (parsed.compressed && (flags & RDP_GDI_CBR2_NO_BITMAP_COMPRESSION_HEADER) == 0)
        {
            uint16_t first_row = 0;
            uint16_t main_body = 0;
            uint16_t scan_width = 0;
            uint16_t uncompressed = 0;

            if (rdp_stream_read_u16_le(&stream, &first_row) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u16_le(&stream, &main_body) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u16_le(&stream, &scan_width) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u16_le(&stream, &uncompressed) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            parsed.compression_header[0] = (uint8_t)(first_row & 0xffu);
            parsed.compression_header[1] = (uint8_t)(first_row >> 8u);
            parsed.compression_header[2] = (uint8_t)(main_body & 0xffu);
            parsed.compression_header[3] = (uint8_t)(main_body >> 8u);
            parsed.compression_header[4] = (uint8_t)(scan_width & 0xffu);
            parsed.compression_header[5] = (uint8_t)(scan_width >> 8u);
            parsed.compression_header[6] = (uint8_t)(uncompressed & 0xffu);
            parsed.compression_header[7] = (uint8_t)(uncompressed >> 8u);
            parsed.has_compression_header = 1;
            bitmap_length = main_body;
        }
        if (parsed.width == 0 || parsed.height == 0 || bitmap_length == 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_stream_remaining(&stream) < bitmap_length ||
            rdp_stream_read_bytes(&stream, &bitmap, bitmap_length) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        parsed.bitmap_data = bitmap;
        parsed.bitmap_data_len = bitmap_length;
    }
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *order = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_parse_cache_color_table_order(const rdp_gdi_secondary_order_header* header,
                                                    rdp_gdi_cache_color_table_order* order)
{
    rdp_gdi_cache_color_table_order parsed;
    rdp_stream stream;
    uint8_t cache_index = 0;
    uint16_t number_colors = 0;
    uint32_t i = 0;

    if (!header || !order || !header->payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->order_type != RDP_GDI_SECONDARY_CACHE_COLOR_TABLE)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (header->payload_len != 3u + (RDP_BITMAP_PALETTE_MAX_ENTRIES * 4u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, header->payload, header->payload_len);
    if (rdp_stream_read_u8(&stream, &cache_index) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &number_colors) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (number_colors != RDP_BITMAP_PALETTE_MAX_ENTRIES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.cache_index = cache_index;
    parsed.palette.count = number_colors;
    for (i = 0; i < number_colors; i++)
    {
        uint8_t blue = 0;
        uint8_t green = 0;
        uint8_t red = 0;
        uint8_t pad = 0;

        if (rdp_stream_read_u8(&stream, &blue) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &green) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &red) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &pad) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        parsed.palette.entries[i].red = red;
        parsed.palette.entries[i].green = green;
        parsed.palette.entries[i].blue = blue;
        (void)pad;
    }
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *order = parsed;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_cache_brush_format_bpp(uint32_t format, uint32_t* bits_per_pixel)
{
    if (!bits_per_pixel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (format)
    {
        case RDP_GDI_BMF_1BPP:
            *bits_per_pixel = 1;
            return LIBRDP_STATUS_OK;
        case RDP_GDI_BMF_8BPP:
            *bits_per_pixel = 8;
            return LIBRDP_STATUS_OK;
        case RDP_GDI_BMF_16BPP:
            *bits_per_pixel = 16;
            return LIBRDP_STATUS_OK;
        case RDP_GDI_BMF_24BPP:
            *bits_per_pixel = 24;
            return LIBRDP_STATUS_OK;
        case RDP_GDI_BMF_32BPP:
            *bits_per_pixel = 32;
            return LIBRDP_STATUS_OK;
        default:
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
}

static int rdp_gdi_cache_brush_compressed_length(uint32_t format, uint32_t length)
{
    return (format == RDP_GDI_BMF_8BPP && length == 20u) ||
           (format == RDP_GDI_BMF_16BPP && length == 24u) ||
           (format == RDP_GDI_BMF_24BPP && length == 28u) ||
           (format == RDP_GDI_BMF_32BPP && length == 32u);
}

librdp_status rdp_gdi_parse_cache_brush_order(const rdp_gdi_secondary_order_header* header,
                                              rdp_gdi_cache_brush_order* order)
{
    rdp_gdi_cache_brush_order parsed;
    rdp_stream stream;
    uint8_t cache_entry = 0;
    uint8_t bitmap_format = 0;
    uint8_t width = 0;
    uint8_t height = 0;
    uint8_t style = 0;
    uint8_t bytes = 0;
    uint32_t bits_per_pixel = 0;
    uint32_t raw_len = 0;
    const uint8_t* brush_data = NULL;

    if (!header || !order || !header->payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->order_type != RDP_GDI_SECONDARY_CACHE_BRUSH)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (header->payload_len < 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, header->payload, header->payload_len);
    if (rdp_stream_read_u8(&stream, &cache_entry) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &bitmap_format) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &height) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &style) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &bytes) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (cache_entry >= RDP_GDI_BRUSH_CACHE_ENTRIES ||
        width != 8u ||
        height != 8u ||
        rdp_gdi_cache_brush_format_bpp(bitmap_format, &bits_per_pixel) != LIBRDP_STATUS_OK ||
        bytes == 0 ||
        rdp_stream_remaining(&stream) != bytes)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (bits_per_pixel == 1u)
    {
        if (bytes != 8u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    else
    {
        raw_len = (uint32_t)((uint64_t)width * height * ((bits_per_pixel + 7u) / 8u));
        if (bytes != raw_len && !rdp_gdi_cache_brush_compressed_length(bitmap_format, bytes))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (rdp_stream_read_bytes(&stream, &brush_data, bytes) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    parsed.cache_entry = cache_entry;
    parsed.bitmap_format = bitmap_format;
    parsed.width = width;
    parsed.height = height;
    parsed.style = style;
    parsed.brush_data = brush_data;
    parsed.brush_data_len = bytes;
    *order = parsed;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_parse_cache_glyph_v1(const rdp_gdi_secondary_order_header* header,
                                                  rdp_gdi_cache_glyph_order* order)
{
    rdp_stream stream;
    uint8_t cache_id = 0;
    uint8_t glyph_count = 0;
    uint32_t i = 0;

    if (!header || !order || !header->payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, header->payload, header->payload_len);
    if (rdp_stream_read_u8(&stream, &cache_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &glyph_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (cache_id > 9u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    order->cache_id = cache_id;
    order->flags = header->extra_flags;
    order->version = 1;
    order->glyph_count = glyph_count;
    for (i = 0; i < glyph_count; i++)
    {
        rdp_gdi_glyph_bitmap* glyph = &order->glyphs[i];
        uint16_t raw = 0;

        if (rdp_stream_read_u16_le(&stream, &raw) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        glyph->cache_index = raw;
        if (glyph->cache_index >= RDP_GDI_MAX_CACHE_GLYPHS)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_stream_read_u16_le(&stream, &raw) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        glyph->x = (int16_t)raw;
        if (rdp_stream_read_u16_le(&stream, &raw) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        glyph->y = (int16_t)raw;
        if (rdp_stream_read_u16_le(&stream, &raw) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        glyph->width = raw;
        if (rdp_stream_read_u16_le(&stream, &raw) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        glyph->height = raw;
        if (rdp_gdi_glyph_bitmap_padded_len(glyph->width,
                                            glyph->height,
                                            &glyph->bitmap_len) != LIBRDP_STATUS_OK ||
            rdp_stream_read_bytes(&stream, &glyph->bitmap, glyph->bitmap_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if ((header->extra_flags & RDP_GDI_CACHE_GLYPH_UNICODE_PRESENT) != 0)
    {
        for (i = 0; i < glyph_count; i++)
        {
            if (rdp_stream_read_u16_le(&stream, &order->glyphs[i].unicode_codepoint) !=
                LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            order->glyphs[i].has_unicode = 1;
        }
    }
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_gdi_parse_cache_glyph_v2(const rdp_gdi_secondary_order_header* header,
                                                  rdp_gdi_cache_glyph_order* order)
{
    rdp_stream stream;
    uint32_t i = 0;

    if (!header || !order || !header->payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(order, 0, sizeof(*order));
    order->cache_id = header->extra_flags & 0x000fu;
    order->flags = (header->extra_flags & 0x00f0u) >> 4u;
    order->version = 2;
    order->glyph_count = (header->extra_flags & 0xff00u) >> 8u;
    if (order->cache_id > 9u || order->glyph_count > RDP_GDI_MAX_CACHE_GLYPHS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, header->payload, header->payload_len);
    for (i = 0; i < order->glyph_count; i++)
    {
        rdp_gdi_glyph_bitmap* glyph = &order->glyphs[i];
        uint8_t cache_index = 0;

        if (rdp_stream_read_u8(&stream, &cache_index) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        glyph->cache_index = cache_index;
        if (rdp_gdi_read_2byte_signed(&stream, &glyph->x) != LIBRDP_STATUS_OK ||
            rdp_gdi_read_2byte_signed(&stream, &glyph->y) != LIBRDP_STATUS_OK ||
            rdp_gdi_read_2byte_unsigned(&stream, &glyph->width) != LIBRDP_STATUS_OK ||
            rdp_gdi_read_2byte_unsigned(&stream, &glyph->height) != LIBRDP_STATUS_OK ||
            rdp_gdi_glyph_bitmap_padded_len(glyph->width,
                                            glyph->height,
                                            &glyph->bitmap_len) != LIBRDP_STATUS_OK ||
            rdp_stream_read_bytes(&stream, &glyph->bitmap, glyph->bitmap_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if ((header->extra_flags & RDP_GDI_CACHE_GLYPH_UNICODE_PRESENT) != 0)
    {
        for (i = 0; i < order->glyph_count; i++)
        {
            if (rdp_stream_read_u16_le(&stream, &order->glyphs[i].unicode_codepoint) !=
                LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            order->glyphs[i].has_unicode = 1;
        }
    }
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_gdi_parse_cache_glyph_order(const rdp_gdi_secondary_order_header* header,
                                              rdp_gdi_cache_glyph_order* order)
{
    rdp_gdi_cache_glyph_order parsed;
    librdp_status primary = LIBRDP_STATUS_OK;
    librdp_status fallback = LIBRDP_STATUS_OK;

    if (!header || !order || !header->payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->order_type != RDP_GDI_SECONDARY_CACHE_GLYPH)
        return LIBRDP_STATUS_UNSUPPORTED;
    if ((header->extra_flags & 0xff00u) != 0)
    {
        primary = rdp_gdi_parse_cache_glyph_v2(header, &parsed);
        if (primary == LIBRDP_STATUS_OK)
        {
            *order = parsed;
            return primary;
        }
        fallback = rdp_gdi_parse_cache_glyph_v1(header, &parsed);
        if (fallback == LIBRDP_STATUS_OK)
        {
            *order = parsed;
            return fallback;
        }
        return primary;
    }
    primary = rdp_gdi_parse_cache_glyph_v1(header, &parsed);
    if (primary == LIBRDP_STATUS_OK)
    {
        *order = parsed;
        return primary;
    }
    fallback = rdp_gdi_parse_cache_glyph_v2(header, &parsed);
    if (fallback == LIBRDP_STATUS_OK)
    {
        *order = parsed;
        return fallback;
    }
    return primary;
}

librdp_status rdp_gdi_parse_altsec_order(const void* data,
                                         size_t length,
                                         rdp_gdi_altsec_order_header* header)
{
    rdp_gdi_altsec_order_header parsed;
    rdp_stream stream;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &parsed.control_flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((parsed.control_flags & 0x03u) != RDP_GDI_TS_SECONDARY)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.order_type = (uint8_t)(parsed.control_flags >> 2);
    if (!rdp_gdi_altsec_order_type_valid(parsed.order_type))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_gdi_altsec_payload_length(parsed.order_type,
                                           stream.data + stream.position,
                                           rdp_stream_remaining(&stream),
                                           &parsed.payload_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_stream_read_bytes(&stream, &parsed.payload, parsed.payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.actual_length = stream.position;
    *header = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_altsec_order(rdp_buffer* buffer,
                                         uint8_t order_type,
                                         const void* payload,
                                         size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t control_flags = 0;
    size_t start = 0;

    if (!buffer || !rdp_gdi_altsec_order_type_valid(order_type) ||
        (!payload && payload_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    control_flags = (uint8_t)((order_type << 2u) | RDP_GDI_TS_SECONDARY);
    status = rdp_buffer_append_u8(buffer, control_flags);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer, payload, payload_len);
    return rdp_gdi_restore_on_error(buffer, start, status);
}

librdp_status rdp_gdi_parse_create_ninegrid_bitmap_order(const rdp_gdi_altsec_order_header* header,
                                                         rdp_gdi_create_ninegrid_bitmap_order* order)
{
    rdp_gdi_create_ninegrid_bitmap_order parsed;
    rdp_stream stream;
    uint8_t bits_per_pixel = 0;
    uint16_t bitmap_id = 0;
    uint16_t value16 = 0;

    if (!header || !order || !header->payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->order_type != RDP_GDI_ALTSEC_CREATE_NINEGRID_BITMAP)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (header->payload_len != 19u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, header->payload, header->payload_len);
    if (rdp_stream_read_u8(&stream, &bits_per_pixel) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &bitmap_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.info.flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &value16) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.bits_per_pixel = bits_per_pixel;
    parsed.bitmap_id = bitmap_id;
    parsed.info.left_width = value16;
    if (rdp_stream_read_u16_le(&stream, &value16) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.info.right_width = value16;
    if (rdp_stream_read_u16_le(&stream, &value16) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.info.top_height = value16;
    if (rdp_stream_read_u16_le(&stream, &value16) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.info.bottom_height = value16;
    if (rdp_stream_read_u32_le(&stream, &parsed.info.transparent_color) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.bits_per_pixel == 0 || parsed.bits_per_pixel > 32u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *order = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_create_ninegrid_bitmap_order(rdp_buffer* buffer,
                                                         const rdp_gdi_create_ninegrid_bitmap_order* order)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !order || order->bits_per_pixel == 0 || order->bits_per_pixel > 32u ||
        order->bitmap_id > UINT16_MAX || order->info.left_width > UINT16_MAX ||
        order->info.right_width > UINT16_MAX || order->info.top_height > UINT16_MAX ||
        order->info.bottom_height > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, (uint8_t)order->bits_per_pixel);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)order->bitmap_id);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, order->info.flags);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)order->info.left_width);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)order->info.right_width);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)order->info.top_height);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)order->info.bottom_height);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, order->info.transparent_color);
    return rdp_gdi_restore_on_error(buffer, start, status);
}

librdp_status rdp_gdi_parse_create_offscreen_bitmap_order(
    const rdp_gdi_altsec_order_header* header,
    rdp_gdi_create_offscreen_bitmap_order* order)
{
    rdp_gdi_create_offscreen_bitmap_order parsed;
    rdp_stream stream;
    uint16_t flags = 0;
    uint16_t width = 0;
    uint16_t height = 0;
    uint16_t delete_count = 0;
    uint32_t i = 0;

    if (!header || !order || !header->payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->order_type != RDP_GDI_ALTSEC_CREATE_OFFSCREEN_BITMAP)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (header->payload_len < 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, header->payload, header->payload_len);
    if (rdp_stream_read_u16_le(&stream, &flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &height) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.bitmap_id = flags & 0x7fffu;
    parsed.width = width;
    parsed.height = height;
    if ((flags & 0x8000u) != 0)
    {
        if (rdp_stream_read_u16_le(&stream, &delete_count) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (delete_count > RDP_GDI_MAX_OFFSCREEN_DELETE_INDICES)
            return LIBRDP_STATUS_UNSUPPORTED;
        if (rdp_stream_remaining(&stream) < (size_t)delete_count * 2u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        parsed.delete_count = delete_count;
        for (i = 0; i < parsed.delete_count; i++)
        {
            if (rdp_stream_read_u16_le(&stream, &parsed.delete_indices[i]) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
    }
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *order = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_create_offscreen_bitmap_order(
    rdp_buffer* buffer,
    const rdp_gdi_create_offscreen_bitmap_order* order)
{
    uint16_t flags = 0;
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !order || order->bitmap_id > 0x7fffu ||
        order->width == 0 || order->width > UINT16_MAX ||
        order->height == 0 || order->height > UINT16_MAX ||
        order->delete_count > RDP_GDI_MAX_OFFSCREEN_DELETE_INDICES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    flags = (uint16_t)order->bitmap_id;
    if (order->delete_count > 0)
        flags |= 0x8000u;
    status = rdp_buffer_append_u16_le(buffer, flags);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)order->width);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)order->height);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    if (order->delete_count == 0)
        return LIBRDP_STATUS_OK;
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)order->delete_count);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    for (i = 0; i < order->delete_count; i++)
    {
        status = rdp_buffer_append_u16_le(buffer, order->delete_indices[i]);
        if (status != LIBRDP_STATUS_OK)
            return rdp_gdi_restore_on_error(buffer, start, status);
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_parse_switch_surface_order(const rdp_gdi_altsec_order_header* header,
                                                 rdp_gdi_switch_surface_order* order)
{
    rdp_gdi_switch_surface_order parsed;
    rdp_stream stream;
    uint16_t bitmap_id = 0;

    if (!header || !order || !header->payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->order_type != RDP_GDI_ALTSEC_SWITCH_SURFACE)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (header->payload_len != 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, header->payload, header->payload_len);
    if (rdp_stream_read_u16_le(&stream, &bitmap_id) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.bitmap_id = bitmap_id;
    *order = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_switch_surface_order(rdp_buffer* buffer,
                                                 const rdp_gdi_switch_surface_order* order)
{
    if (!buffer || !order || order->bitmap_id > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u16_le(buffer, (uint16_t)order->bitmap_id);
}

librdp_status rdp_gdi_parse_frame_marker_order(const rdp_gdi_altsec_order_header* header,
                                               rdp_gdi_frame_marker_order* order)
{
    rdp_gdi_frame_marker_order parsed;
    rdp_stream stream;

    if (!header || !order || !header->payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->order_type != RDP_GDI_ALTSEC_FRAME_MARKER)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (header->payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, header->payload, header->payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.action) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *order = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_frame_marker_order(rdp_buffer* buffer,
                                               const rdp_gdi_frame_marker_order* order)
{
    if (!buffer || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u32_le(buffer, order->action);
}

librdp_status rdp_gdi_parse_stream_bitmap_first_order(
    const rdp_gdi_altsec_order_header* header,
    rdp_gdi_stream_bitmap_first_order* order)
{
    rdp_gdi_stream_bitmap_first_order parsed;
    rdp_stream stream;
    uint8_t flags = 0;
    uint8_t bpp = 0;
    uint16_t value16 = 0;
    uint32_t bitmap_size = 0;
    uint16_t block_len = 0;
    const uint8_t* block = NULL;

    if (!header || !order || !header->payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->order_type != RDP_GDI_ALTSEC_STREAM_BITMAP_FIRST)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (header->payload_len < 10u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, header->payload, header->payload_len);
    if (rdp_stream_read_u8(&stream, &flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &bpp) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &value16) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.bitmap_type = value16;
    if (rdp_stream_read_u16_le(&stream, &value16) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.width = value16;
    if (rdp_stream_read_u16_le(&stream, &value16) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.height = value16;
    if ((flags & RDP_GDI_STREAM_BITMAP_V2) != 0)
    {
        if (rdp_stream_read_u32_le(&stream, &bitmap_size) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    else
    {
        if (rdp_stream_read_u16_le(&stream, &value16) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        bitmap_size = value16;
    }
    if (rdp_stream_read_u16_le(&stream, &block_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) < block_len ||
        rdp_stream_read_bytes(&stream, &block, block_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) != 0 ||
        bpp == 0 || bpp > 32u ||
        parsed.width == 0 || parsed.height == 0 ||
        bitmap_size == 0 || block_len > bitmap_size)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.flags = flags;
    parsed.bits_per_pixel = bpp;
    parsed.bitmap_size = bitmap_size;
    parsed.bitmap_block = block;
    parsed.bitmap_block_len = block_len;
    *order = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_stream_bitmap_first_order(
    rdp_buffer* buffer,
    const rdp_gdi_stream_bitmap_first_order* order)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !order || (!order->bitmap_block && order->bitmap_block_len > 0) ||
        order->flags > UINT8_MAX || order->bits_per_pixel == 0 || order->bits_per_pixel > 32u ||
        order->bitmap_type > UINT16_MAX || order->width == 0 || order->width > UINT16_MAX ||
        order->height == 0 || order->height > UINT16_MAX ||
        order->bitmap_size == 0 || order->bitmap_block_len > order->bitmap_size ||
        order->bitmap_block_len > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((order->flags & RDP_GDI_STREAM_BITMAP_V2) == 0 && order->bitmap_size > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, (uint8_t)order->flags);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u8(buffer, (uint8_t)order->bits_per_pixel);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)order->bitmap_type);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)order->width);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)order->height);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    if ((order->flags & RDP_GDI_STREAM_BITMAP_V2) != 0)
        status = rdp_buffer_append_u32_le(buffer, order->bitmap_size);
    else
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)order->bitmap_size);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)order->bitmap_block_len);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer, order->bitmap_block, order->bitmap_block_len);
    return rdp_gdi_restore_on_error(buffer, start, status);
}

librdp_status rdp_gdi_parse_stream_bitmap_next_order(
    const rdp_gdi_altsec_order_header* header,
    rdp_gdi_stream_bitmap_next_order* order)
{
    rdp_gdi_stream_bitmap_next_order parsed;
    rdp_stream stream;
    uint8_t flags = 0;
    uint16_t value16 = 0;
    uint16_t block_len = 0;
    const uint8_t* block = NULL;

    if (!header || !order || !header->payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->order_type != RDP_GDI_ALTSEC_STREAM_BITMAP_NEXT)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (header->payload_len < 5u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, header->payload, header->payload_len);
    if (rdp_stream_read_u8(&stream, &flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &value16) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &block_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) < block_len ||
        rdp_stream_read_bytes(&stream, &block, block_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.flags = flags;
    parsed.bitmap_type = value16;
    parsed.bitmap_block = block;
    parsed.bitmap_block_len = block_len;
    *order = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_stream_bitmap_next_order(
    rdp_buffer* buffer,
    const rdp_gdi_stream_bitmap_next_order* order)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !order || (!order->bitmap_block && order->bitmap_block_len > 0) ||
        order->flags > UINT8_MAX || order->bitmap_type > UINT16_MAX ||
        order->bitmap_block_len > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, (uint8_t)order->flags);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)order->bitmap_type);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)order->bitmap_block_len);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer, order->bitmap_block, order->bitmap_block_len);
    return rdp_gdi_restore_on_error(buffer, start, status);
}

librdp_status rdp_gdi_parse_order_list(const void* data,
                                       size_t length,
                                       uint16_t number_orders,
                                       uint8_t initial_order_type,
                                       rdp_gdi_order_list* list)
{
    const uint8_t* bytes = (const uint8_t*)data;
    rdp_gdi_order_list parsed;
    size_t offset = 0;
    uint16_t index = 0;
    rdp_gdi_render_state render_state;

    if ((!data && length > 0) || !list)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (number_orders > RDP_GDI_MAX_ORDERS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_gdi_render_state_init(&render_state);
    render_state.current_order_type = initial_order_type;
    for (index = 0; index < number_orders; index++)
    {
        uint8_t control = 0;
        rdp_gdi_secondary_order_header secondary;
        rdp_gdi_altsec_order_header altsec;

        if (offset >= length)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        control = bytes[offset];
        parsed.orders[index].data = bytes + offset;
        if ((control & (RDP_GDI_TS_STANDARD | RDP_GDI_TS_SECONDARY)) ==
            (RDP_GDI_TS_STANDARD | RDP_GDI_TS_SECONDARY))
        {
            if (rdp_gdi_parse_secondary_order(bytes + offset, length - offset, &secondary) !=
                LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            parsed.orders[index].kind = RDP_GDI_ORDER_KIND_SECONDARY;
            parsed.orders[index].order_type = secondary.order_type;
            parsed.orders[index].length = secondary.actual_length;
            offset += secondary.actual_length;
            continue;
        }
        if ((control & 0x03u) == RDP_GDI_TS_SECONDARY)
        {
            librdp_status status = rdp_gdi_parse_altsec_order(bytes + offset, length - offset, &altsec);

            if (status != LIBRDP_STATUS_OK)
                return status;
            parsed.orders[index].kind = RDP_GDI_ORDER_KIND_ALTSEC;
            parsed.orders[index].order_type = altsec.order_type;
            parsed.orders[index].length = altsec.actual_length;
            offset += altsec.actual_length;
            continue;
        }
        if (control & RDP_GDI_TS_STANDARD)
        {
            rdp_gdi_render_op op;
            size_t consumed = 0;
            librdp_status status = rdp_gdi_decode_primary_render_order(&render_state,
                                                                       bytes + offset,
                                                                       length - offset,
                                                                       &op,
                                                                       &consumed);

            if (status != LIBRDP_STATUS_OK)
                return status;
            if (consumed == 0 || consumed > length - offset)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            parsed.orders[index].kind = RDP_GDI_ORDER_KIND_PRIMARY;
            parsed.orders[index].order_type = op.order_type;
            parsed.orders[index].length = consumed;
            offset += consumed;
            continue;
        }
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (offset != length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.count = number_orders;
    *list = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_parse_bitmap_cache_error_payload(const void* data,
                                                       size_t length,
                                                       rdp_gdi_bitmap_cache_error* error)
{
    rdp_gdi_bitmap_cache_error parsed;
    rdp_stream stream;
    uint8_t pad8 = 0;
    uint16_t pad16 = 0;
    uint16_t ignored = 0;
    size_t i = 0;

    if (!data || !error)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &parsed.count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &pad8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pad16) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.count > RDP_GDI_MAX_BITMAP_CACHE_ERROR_INFO ||
        rdp_stream_remaining(&stream) != (size_t)parsed.count * 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < parsed.count; i++)
    {
        if (rdp_stream_read_u8(&stream, &parsed.infos[i].cache_id) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &parsed.infos[i].flags) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &ignored) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &parsed.infos[i].new_num_entries) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (parsed.infos[i].flags &
            ~(RDP_GDI_BITMAP_CACHE_ERROR_FLUSH_CACHE |
              RDP_GDI_BITMAP_CACHE_ERROR_NEWNUMENTRIES_VALID))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    *error = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_bitmap_cache_error_payload(rdp_buffer* buffer,
                                                       const rdp_gdi_bitmap_cache_error* error)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;
    size_t start = 0;

    if (!buffer || !error || error->count > RDP_GDI_MAX_BITMAP_CACHE_ERROR_INFO)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < error->count; i++)
    {
        if (error->infos[i].flags &
            ~(RDP_GDI_BITMAP_CACHE_ERROR_FLUSH_CACHE |
              RDP_GDI_BITMAP_CACHE_ERROR_NEWNUMENTRIES_VALID))
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, error->count);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u8(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    for (i = 0; i < error->count; i++)
    {
        status = rdp_buffer_append_u8(buffer, error->infos[i].cache_id);
        if (status != LIBRDP_STATUS_OK)
            return rdp_gdi_restore_on_error(buffer, start, status);
        status = rdp_buffer_append_u8(buffer, error->infos[i].flags);
        if (status != LIBRDP_STATUS_OK)
            return rdp_gdi_restore_on_error(buffer, start, status);
        status = rdp_buffer_append_u16_le(buffer, 0);
        if (status != LIBRDP_STATUS_OK)
            return rdp_gdi_restore_on_error(buffer, start, status);
        status = rdp_buffer_append_u32_le(buffer, error->infos[i].new_num_entries);
        if (status != LIBRDP_STATUS_OK)
            return rdp_gdi_restore_on_error(buffer, start, status);
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
    rdp_gdi_color_cache_capability parsed;
    rdp_stream stream;
    uint16_t ignored = 0;

    if (!data || !capability)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != RDP_GDI_COLOR_CACHE_CAPABILITY_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_gdi_read_capability_header(&stream,
                                       RDP_GDI_CAPSTYPE_COLOR_CACHE,
                                       RDP_GDI_COLOR_CACHE_CAPABILITY_LENGTH) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.color_table_cache_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &ignored) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *capability = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_color_cache_capability(
    rdp_buffer* buffer,
    const rdp_gdi_color_cache_capability* capability)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !capability)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_gdi_write_capability_header(buffer,
                                             RDP_GDI_CAPSTYPE_COLOR_CACHE,
                                             RDP_GDI_COLOR_CACHE_CAPABILITY_LENGTH);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, capability->color_table_cache_size);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, 0);
    return rdp_gdi_restore_on_error(buffer, start, status);
}

librdp_status rdp_gdi_parse_ninegrid_capability(const void* data,
                                                size_t length,
                                                rdp_gdi_ninegrid_capability* capability)
{
    rdp_gdi_ninegrid_capability parsed;
    rdp_stream stream;

    if (!data || !capability)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != RDP_GDI_DRAW_NINEGRID_CAPABILITY_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_gdi_read_capability_header(&stream,
                                       RDP_GDI_CAPSTYPE_DRAW_NINEGRID_CACHE,
                                       RDP_GDI_DRAW_NINEGRID_CAPABILITY_LENGTH) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.support_level) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.cache_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.cache_entries) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.support_level > RDP_GDI_NINEGRID_SUPPORT_SUPPORTED_REV2 ||
        parsed.cache_size > 2560u ||
        parsed.cache_entries > 256u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *capability = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_ninegrid_capability(
    rdp_buffer* buffer,
    const rdp_gdi_ninegrid_capability* capability)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !capability ||
        capability->support_level > RDP_GDI_NINEGRID_SUPPORT_SUPPORTED_REV2 ||
        capability->cache_size > 2560u ||
        capability->cache_entries > 256u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_gdi_write_capability_header(buffer,
                                             RDP_GDI_CAPSTYPE_DRAW_NINEGRID_CACHE,
                                             RDP_GDI_DRAW_NINEGRID_CAPABILITY_LENGTH);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, capability->support_level);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, capability->cache_size);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, capability->cache_entries);
    return rdp_gdi_restore_on_error(buffer, start, status);
}

librdp_status rdp_gdi_parse_gdiplus_capability(const void* data,
                                               size_t length,
                                               rdp_gdi_gdiplus_capability* capability)
{
    static const uint16_t max_entries[5] = {10u, 5u, 5u, 10u, 2u};
    static const uint16_t max_chunks[4] = {512u, 2048u, 1024u, 64u};
    static const uint16_t max_properties[3] = {4096u, 256u, 128u};
    rdp_gdi_gdiplus_capability parsed;
    rdp_stream stream;
    size_t i = 0;

    if (!data || !capability)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != RDP_GDI_DRAW_GDIPLUS_CAPABILITY_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_gdi_read_capability_header(&stream,
                                       RDP_GDI_CAPSTYPE_DRAW_GDIPLUS,
                                       RDP_GDI_DRAW_GDIPLUS_CAPABILITY_LENGTH) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.support_level) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.cache_level) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.support_level > RDP_GDI_GDIPLUS_SUPPORT_SUPPORTED ||
        parsed.cache_level > RDP_GDI_GDIPLUS_CACHE_LEVEL_ONE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < 5u; i++)
    {
        if (rdp_stream_read_u16_le(&stream, &parsed.cache_entries[i]) != LIBRDP_STATUS_OK ||
            parsed.cache_entries[i] > max_entries[i])
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    for (i = 0; i < 4u; i++)
    {
        if (rdp_stream_read_u16_le(&stream, &parsed.cache_chunk_size[i]) != LIBRDP_STATUS_OK ||
            parsed.cache_chunk_size[i] > max_chunks[i])
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    for (i = 0; i < 3u; i++)
    {
        if (rdp_stream_read_u16_le(&stream, &parsed.image_cache_properties[i]) != LIBRDP_STATUS_OK ||
            parsed.image_cache_properties[i] > max_properties[i])
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *capability = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gdi_write_gdiplus_capability(
    rdp_buffer* buffer,
    const rdp_gdi_gdiplus_capability* capability)
{
    static const uint16_t max_entries[5] = {10u, 5u, 5u, 10u, 2u};
    static const uint16_t max_chunks[4] = {512u, 2048u, 1024u, 64u};
    static const uint16_t max_properties[3] = {4096u, 256u, 128u};
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;
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
    start = buffer->length;
    status = rdp_gdi_write_capability_header(buffer,
                                             RDP_GDI_CAPSTYPE_DRAW_GDIPLUS,
                                             RDP_GDI_DRAW_GDIPLUS_CAPABILITY_LENGTH);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, capability->support_level);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, capability->version);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, capability->cache_level);
    if (status != LIBRDP_STATUS_OK)
        return rdp_gdi_restore_on_error(buffer, start, status);
    for (i = 0; i < 5u; i++)
    {
        status = rdp_buffer_append_u16_le(buffer, capability->cache_entries[i]);
        if (status != LIBRDP_STATUS_OK)
            return rdp_gdi_restore_on_error(buffer, start, status);
    }
    for (i = 0; i < 4u; i++)
    {
        status = rdp_buffer_append_u16_le(buffer, capability->cache_chunk_size[i]);
        if (status != LIBRDP_STATUS_OK)
            return rdp_gdi_restore_on_error(buffer, start, status);
    }
    for (i = 0; i < 3u; i++)
    {
        status = rdp_buffer_append_u16_le(buffer, capability->image_cache_properties[i]);
        if (status != LIBRDP_STATUS_OK)
            return rdp_gdi_restore_on_error(buffer, start, status);
    }
    return LIBRDP_STATUS_OK;
}
