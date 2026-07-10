#include "graphics/gdi_render.h"

#include "common/stream.h"
#include "graphics/gdi_orders.h"

#include <string.h>

static int rdp_gdi_render_field_bytes(uint8_t order_type, uint8_t* bytes)
{
    switch (order_type)
    {
        case RDP_GDI_ORDER_DSTBLT:
        case RDP_GDI_ORDER_SCRBLT:
        case RDP_GDI_ORDER_OPAQUERECT:
            *bytes = 1;
            return 1;
        case RDP_GDI_ORDER_PATBLT:
            *bytes = 2;
            return 1;
        default:
            return 0;
    }
}

static librdp_status rdp_gdi_render_read_i16(rdp_stream* stream, int32_t* value)
{
    uint16_t raw = 0;

    if (rdp_stream_read_u16_le(stream, &raw) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = (int16_t)raw;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_read_coord(rdp_stream* stream, int delta, int32_t* value)
{
    if (delta)
    {
        uint8_t raw = 0;

        if (rdp_stream_read_u8(stream, &raw) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *value += (int8_t)raw;
        return LIBRDP_STATUS_OK;
    }
    return rdp_gdi_render_read_i16(stream, value);
}

static librdp_status rdp_gdi_render_read_color(rdp_stream* stream, uint32_t* color)
{
    uint8_t b = 0;
    uint8_t g = 0;
    uint8_t r = 0;

    if (rdp_stream_read_u8(stream, &b) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &g) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &r) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *color = (uint32_t)b | ((uint32_t)g << 8u) | ((uint32_t)r << 16u);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_read_bounds(rdp_stream* stream,
                                                uint8_t flags,
                                                rdp_gdi_render_state* state,
                                                rdp_gdi_render_op* op)
{
    uint8_t bounds_flags = 0;
    int32_t* fields[4];
    size_t i = 0;

    op->bounds.present = 1;
    if (flags & RDP_GDI_TS_ZERO_BOUNDS_DELTAS)
        goto done;
    if (rdp_stream_read_u8(stream, &bounds_flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    fields[0] = &state->bounds_left;
    fields[1] = &state->bounds_top;
    fields[2] = &state->bounds_right;
    fields[3] = &state->bounds_bottom;
    for (i = 0; i < 4u; i++)
    {
        uint8_t absolute = (uint8_t)(1u << i);
        uint8_t delta = (uint8_t)(0x10u << i);

        if ((bounds_flags & absolute) && (bounds_flags & delta))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (bounds_flags & absolute)
        {
            librdp_status status = rdp_gdi_render_read_i16(stream, fields[i]);

            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (bounds_flags & delta)
        {
            librdp_status status = rdp_gdi_render_read_coord(stream, 1, fields[i]);

            if (status != LIBRDP_STATUS_OK)
                return status;
        }
    }

done:
    op->bounds.left = state->bounds_left;
    op->bounds.top = state->bounds_top;
    op->bounds.right = state->bounds_right;
    op->bounds.bottom = state->bounds_bottom;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_dstblt(rdp_stream* stream,
                                                  uint32_t flags,
                                                  int delta,
                                                  rdp_gdi_render_state* state,
                                                  rdp_gdi_render_op* op)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x01u)
        status = rdp_gdi_render_read_coord(stream, delta, &state->dst_left);
    if (status == LIBRDP_STATUS_OK && (flags & 0x02u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->dst_top);
    if (status == LIBRDP_STATUS_OK && (flags & 0x04u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->dst_width);
    if (status == LIBRDP_STATUS_OK && (flags & 0x08u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->dst_height);
    if (status == LIBRDP_STATUS_OK && (flags & 0x10u) &&
        rdp_stream_read_u8(stream, &state->dst_rop) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status != LIBRDP_STATUS_OK)
        return status;

    op->kind = RDP_GDI_RENDER_OP_DSTBLT;
    op->rop = state->dst_rop;
    op->rect.x = state->dst_left;
    op->rect.y = state->dst_top;
    op->rect.width = state->dst_width;
    op->rect.height = state->dst_height;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_opaque_rect(rdp_stream* stream,
                                                       uint32_t flags,
                                                       int delta,
                                                       rdp_gdi_render_state* state,
                                                       rdp_gdi_render_op* op)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x01u)
        status = rdp_gdi_render_read_coord(stream, delta, &state->opaque_left);
    if (status == LIBRDP_STATUS_OK && (flags & 0x02u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->opaque_top);
    if (status == LIBRDP_STATUS_OK && (flags & 0x04u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->opaque_width);
    if (status == LIBRDP_STATUS_OK && (flags & 0x08u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->opaque_height);
    if (status == LIBRDP_STATUS_OK && (flags & 0x10u))
        status = rdp_gdi_render_read_color(stream, &state->opaque_color);
    if (status != LIBRDP_STATUS_OK)
        return status;

    op->kind = RDP_GDI_RENDER_OP_OPAQUE_RECT;
    op->color = state->opaque_color;
    op->rect.x = state->opaque_left;
    op->rect.y = state->opaque_top;
    op->rect.width = state->opaque_width;
    op->rect.height = state->opaque_height;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_scrblt(rdp_stream* stream,
                                                  uint32_t flags,
                                                  int delta,
                                                  rdp_gdi_render_state* state,
                                                  rdp_gdi_render_op* op)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x01u)
        status = rdp_gdi_render_read_coord(stream, delta, &state->scr_left);
    if (status == LIBRDP_STATUS_OK && (flags & 0x02u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->scr_top);
    if (status == LIBRDP_STATUS_OK && (flags & 0x04u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->scr_width);
    if (status == LIBRDP_STATUS_OK && (flags & 0x08u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->scr_height);
    if (status == LIBRDP_STATUS_OK && (flags & 0x10u) &&
        rdp_stream_read_u8(stream, &state->scr_rop) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x20u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->scr_src_x);
    if (status == LIBRDP_STATUS_OK && (flags & 0x40u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->scr_src_y);
    if (status != LIBRDP_STATUS_OK)
        return status;

    op->kind = RDP_GDI_RENDER_OP_SCRBLT;
    op->rop = state->scr_rop;
    op->rect.x = state->scr_left;
    op->rect.y = state->scr_top;
    op->rect.width = state->scr_width;
    op->rect.height = state->scr_height;
    op->src_x = state->scr_src_x;
    op->src_y = state->scr_src_y;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_patblt(rdp_stream* stream,
                                                  uint32_t flags,
                                                  int delta,
                                                  rdp_gdi_render_state* state,
                                                  rdp_gdi_render_op* op)
{
    const uint8_t* extra = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x0001u)
        status = rdp_gdi_render_read_coord(stream, delta, &state->pat_left);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0002u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->pat_top);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0004u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->pat_width);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0008u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->pat_height);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0010u) &&
        rdp_stream_read_u8(stream, &state->pat_rop) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0020u))
        status = rdp_gdi_render_read_color(stream, &state->pat_back_color);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0040u))
        status = rdp_gdi_render_read_color(stream, &state->pat_fore_color);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0080u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->pat_brush_x);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0100u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->pat_brush_y);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0200u) &&
        rdp_stream_read_u8(stream, &state->pat_brush_style) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0400u) &&
        rdp_stream_read_u8(stream, &state->pat_brush_hatch) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0800u))
    {
        if (rdp_stream_read_bytes(stream, &extra, sizeof(state->pat_brush_extra)) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            memcpy(state->pat_brush_extra, extra, sizeof(state->pat_brush_extra));
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (state->pat_brush_style != 0)
        return LIBRDP_STATUS_UNSUPPORTED;

    op->kind = RDP_GDI_RENDER_OP_PATBLT;
    op->rop = state->pat_rop;
    op->color = state->pat_fore_color;
    op->rect.x = state->pat_left;
    op->rect.y = state->pat_top;
    op->rect.width = state->pat_width;
    op->rect.height = state->pat_height;
    return LIBRDP_STATUS_OK;
}

void rdp_gdi_render_state_init(rdp_gdi_render_state* state)
{
    if (!state)
        return;
    memset(state, 0, sizeof(*state));
    state->current_order_type = RDP_GDI_ORDER_DSTBLT;
    state->dst_rop = 0x00u;
    state->scr_rop = 0xccu;
    state->pat_rop = 0xf0u;
}

librdp_status rdp_gdi_decode_primary_render_order(rdp_gdi_render_state* state,
                                                  const void* data,
                                                  size_t length,
                                                  rdp_gdi_render_op* op,
                                                  size_t* consumed)
{
    rdp_stream stream;
    uint8_t control = 0;
    uint8_t order_type = 0;
    uint8_t field_bytes = 0;
    uint8_t present_field_bytes = 0;
    uint8_t zero_field_bytes = 0;
    uint32_t field_flags = 0;
    size_t i = 0;
    int delta = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!state || !data || !op || !consumed)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(op, 0, sizeof(*op));
    *consumed = 0;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &control) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!(control & RDP_GDI_TS_STANDARD) || (control & RDP_GDI_TS_SECONDARY))
        return LIBRDP_STATUS_UNSUPPORTED;
    order_type = state->current_order_type;
    if (control & RDP_GDI_TS_TYPE_CHANGE)
    {
        if (rdp_stream_read_u8(&stream, &order_type) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (!rdp_gdi_render_field_bytes(order_type, &field_bytes))
        return LIBRDP_STATUS_UNSUPPORTED;
    zero_field_bytes = (uint8_t)(((control & RDP_GDI_TS_ZERO_FIELD_BYTE_BIT0) ? 1u : 0u) |
                                 ((control & RDP_GDI_TS_ZERO_FIELD_BYTE_BIT1) ? 2u : 0u));
    if (zero_field_bytes > field_bytes)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    present_field_bytes = (uint8_t)(field_bytes - zero_field_bytes);
    for (i = 0; i < present_field_bytes; i++)
    {
        uint8_t byte = 0;

        if (rdp_stream_read_u8(&stream, &byte) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        field_flags |= (uint32_t)byte << (8u * i);
    }
    if (control & RDP_GDI_TS_BOUNDS)
    {
        status = rdp_gdi_render_read_bounds(&stream, control, state, op);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    delta = (control & RDP_GDI_TS_DELTA_COORDINATES) != 0;
    op->order_type = order_type;
    switch (order_type)
    {
        case RDP_GDI_ORDER_DSTBLT:
            status = rdp_gdi_render_decode_dstblt(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_PATBLT:
            status = rdp_gdi_render_decode_patblt(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_OPAQUERECT:
            status = rdp_gdi_render_decode_opaque_rect(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_SCRBLT:
            status = rdp_gdi_render_decode_scrblt(&stream, field_flags, delta, state, op);
            break;
        default:
            status = LIBRDP_STATUS_UNSUPPORTED;
            break;
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (op->rect.width < 0 || op->rect.height < 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    state->current_order_type = order_type;
    *consumed = stream.position;
    return LIBRDP_STATUS_OK;
}
