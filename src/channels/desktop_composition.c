#include "channels/desktop_composition.h"

#include "common/stream.h"

#include <string.h>

static librdp_status rdp_desktop_composition_read_u64(rdp_stream* stream, uint64_t* value)
{
    uint32_t low = 0;
    uint32_t high = 0;

    if (rdp_stream_read_u32_le(stream, &low) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &high) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = (uint64_t)low | ((uint64_t)high << 32);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_desktop_composition_write_u64(rdp_buffer* buffer, uint64_t value)
{
    librdp_status status = rdp_buffer_append_u32_le(buffer, (uint32_t)(value & 0xffffffffu));

    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, (uint32_t)((value >> 32) & 0xffffffffu));
}

static int rdp_desktop_composition_bool_valid(uint8_t value)
{
    return value <= 1u;
}

static int rdp_desktop_composition_event_valid(uint8_t event_type)
{
    return event_type <= RDP_DESKTOP_COMPOSITION_EVENT_DWM_DESK_LEAVE;
}

int rdp_desktop_composition_operation_valid(uint8_t operation)
{
    return operation >= RDP_DESKTOP_COMPOSITION_OP_TOGGLE &&
           operation <= RDP_DESKTOP_COMPOSITION_OP_FLUSH_COMPOSE_ONCE;
}

librdp_status rdp_desktop_composition_parse_header(const void* data,
                                                   size_t length,
                                                   rdp_desktop_composition_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u || length > UINT16_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &header->altsec_header) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &header->operation) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->size) != LIBRDP_STATUS_OK ||
        header->altsec_header != RDP_DESKTOP_COMPOSITION_ALTSEC_HEADER ||
        !rdp_desktop_composition_operation_valid(header->operation) ||
        header->size != length - 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_desktop_composition_write_header(rdp_buffer* buffer,
                                                   uint8_t operation,
                                                   uint16_t size)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_desktop_composition_operation_valid(operation))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, RDP_DESKTOP_COMPOSITION_ALTSEC_HEADER);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, operation);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u16_le(buffer, size);
}

librdp_status rdp_desktop_composition_parse_toggle(const void* data,
                                                   size_t length,
                                                   rdp_desktop_composition_toggle* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 5u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_desktop_composition_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.operation != RDP_DESKTOP_COMPOSITION_OP_TOGGLE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &order->event_type) != LIBRDP_STATUS_OK ||
        !rdp_desktop_composition_event_valid(order->event_type))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_desktop_composition_write_toggle(rdp_buffer* buffer, uint8_t event_type)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_desktop_composition_event_valid(event_type))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_desktop_composition_write_header(buffer, RDP_DESKTOP_COMPOSITION_OP_TOGGLE, 1u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, event_type);
}

librdp_status rdp_desktop_composition_parse_lsurface(const void* data,
                                                     size_t length,
                                                     rdp_desktop_composition_lsurface* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 38u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_desktop_composition_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.operation != RDP_DESKTOP_COMPOSITION_OP_LSURFACE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &order->create) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &order->flags) != LIBRDP_STATUS_OK ||
        rdp_desktop_composition_read_u64(&stream, &order->surface_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->height) != LIBRDP_STATUS_OK ||
        rdp_desktop_composition_read_u64(&stream, &order->window_id) != LIBRDP_STATUS_OK ||
        rdp_desktop_composition_read_u64(&stream, &order->luid) != LIBRDP_STATUS_OK ||
        !rdp_desktop_composition_bool_valid(order->create) ||
        (order->flags & ~(RDP_DESKTOP_COMPOSITION_LSURFACE_COMPOSE_ONCE |
                          RDP_DESKTOP_COMPOSITION_LSURFACE_REDIRECTION)) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (order->create && (order->width == 0 || order->height == 0))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_desktop_composition_write_lsurface(rdp_buffer* buffer,
                                                     uint8_t create,
                                                     uint8_t flags,
                                                     uint64_t surface_id,
                                                     uint32_t width,
                                                     uint32_t height,
                                                     uint64_t window_id,
                                                     uint64_t luid)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_desktop_composition_bool_valid(create) ||
        (flags & ~(RDP_DESKTOP_COMPOSITION_LSURFACE_COMPOSE_ONCE |
                   RDP_DESKTOP_COMPOSITION_LSURFACE_REDIRECTION)) != 0 ||
        (create && (width == 0 || height == 0)))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_desktop_composition_write_header(buffer, RDP_DESKTOP_COMPOSITION_OP_LSURFACE, 0x22u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, create);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_desktop_composition_write_u64(buffer, surface_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, width);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_desktop_composition_write_u64(buffer, window_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_desktop_composition_write_u64(buffer, luid);
    return status;
}

librdp_status rdp_desktop_composition_parse_surfobj(const void* data,
                                                    size_t length,
                                                    rdp_desktop_composition_surfobj* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 26u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_desktop_composition_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.operation != RDP_DESKTOP_COMPOSITION_OP_SURFOBJ)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->cache_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &order->surface_bpp) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &order->flags) != LIBRDP_STATUS_OK ||
        rdp_desktop_composition_read_u64(&stream, &order->surface_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->height) != LIBRDP_STATUS_OK ||
        order->flags != 0 ||
        order->width == 0 || order->height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_desktop_composition_write_surfobj(rdp_buffer* buffer,
                                                    uint32_t cache_id,
                                                    uint8_t surface_bpp,
                                                    uint64_t surface_id,
                                                    uint32_t width,
                                                    uint32_t height)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || width == 0 || height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_desktop_composition_write_header(buffer, RDP_DESKTOP_COMPOSITION_OP_SURFOBJ, 0x16u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, cache_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, surface_bpp);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_desktop_composition_write_u64(buffer, surface_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, width);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, height);
    return status;
}

librdp_status rdp_desktop_composition_parse_assoc(const void* data,
                                                  size_t length,
                                                  rdp_desktop_composition_assoc* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 21u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_desktop_composition_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.operation != RDP_DESKTOP_COMPOSITION_OP_ASSOC)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &order->associate) != LIBRDP_STATUS_OK ||
        rdp_desktop_composition_read_u64(&stream, &order->logical_surface_id) != LIBRDP_STATUS_OK ||
        rdp_desktop_composition_read_u64(&stream, &order->redirection_surface_id) != LIBRDP_STATUS_OK ||
        !rdp_desktop_composition_bool_valid(order->associate))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_desktop_composition_write_assoc(rdp_buffer* buffer,
                                                  uint8_t associate,
                                                  uint64_t logical_surface_id,
                                                  uint64_t redirection_surface_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_desktop_composition_bool_valid(associate))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_desktop_composition_write_header(buffer, RDP_DESKTOP_COMPOSITION_OP_ASSOC, 0x11u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, associate);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_desktop_composition_write_u64(buffer, logical_surface_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_desktop_composition_write_u64(buffer, redirection_surface_id);
    return status;
}

librdp_status rdp_desktop_composition_parse_compref(const void* data,
                                                    size_t length,
                                                    rdp_desktop_composition_u64_order* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_desktop_composition_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.operation != RDP_DESKTOP_COMPOSITION_OP_COMPREF)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_desktop_composition_read_u64(&stream, &order->value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_desktop_composition_write_compref(rdp_buffer* buffer, uint64_t logical_surface_id)
{
    librdp_status status = rdp_desktop_composition_write_header(buffer, RDP_DESKTOP_COMPOSITION_OP_COMPREF, 8u);

    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_desktop_composition_write_u64(buffer, logical_surface_id);
}

librdp_status rdp_desktop_composition_parse_switch_surfobj(const void* data,
                                                           size_t length,
                                                           rdp_desktop_composition_u32_order* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_desktop_composition_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.operation != RDP_DESKTOP_COMPOSITION_OP_SWITCH_SURFOBJ)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_desktop_composition_write_switch_surfobj(rdp_buffer* buffer, uint32_t cache_id)
{
    librdp_status status = rdp_desktop_composition_write_header(buffer,
                                                                RDP_DESKTOP_COMPOSITION_OP_SWITCH_SURFOBJ,
                                                                4u);

    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, cache_id);
}

librdp_status rdp_desktop_composition_parse_opaque(const void* data,
                                                   size_t length,
                                                   rdp_desktop_composition_opaque* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(order, 0, sizeof(*order));
    if (rdp_desktop_composition_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    order->payload_len = rdp_stream_remaining(&stream);
    return rdp_stream_read_bytes(&stream, &order->payload, order->payload_len);
}

librdp_status rdp_desktop_composition_write_opaque(rdp_buffer* buffer,
                                                   uint8_t operation,
                                                   const void* payload,
                                                   uint16_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!payload && payload_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_desktop_composition_write_header(buffer, operation, payload_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, payload, payload_len);
}
