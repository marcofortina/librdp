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
        case RDP_GDI_ORDER_DRAWNINEGRID:
        case RDP_GDI_ORDER_MULTI_DRAWNINEGRID:
        case RDP_GDI_ORDER_OPAQUERECT:
        case RDP_GDI_ORDER_MULTIDSTBLT:
        case RDP_GDI_ORDER_POLYGON_SC:
        case RDP_GDI_ORDER_POLYLINE:
        case RDP_GDI_ORDER_ELLIPSE_SC:
        case RDP_GDI_ORDER_SAVEBITMAP:
            *bytes = 1;
            return 1;
        case RDP_GDI_ORDER_PATBLT:
        case RDP_GDI_ORDER_LINETO:
        case RDP_GDI_ORDER_MEMBLT:
        case RDP_GDI_ORDER_MULTIPATBLT:
        case RDP_GDI_ORDER_MULTISCRBLT:
        case RDP_GDI_ORDER_MULTIOPAQUERECT:
        case RDP_GDI_ORDER_FAST_INDEX:
        case RDP_GDI_ORDER_POLYGON_CB:
        case RDP_GDI_ORDER_FAST_GLYPH:
        case RDP_GDI_ORDER_ELLIPSE_CB:
            *bytes = 2;
            return 1;
        case RDP_GDI_ORDER_MEM3BLT:
        case RDP_GDI_ORDER_GLYPH_INDEX:
            *bytes = 3;
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

static librdp_status rdp_gdi_render_read_u16(rdp_stream* stream, uint32_t* value)
{
    uint16_t raw = 0;

    if (rdp_stream_read_u16_le(stream, &raw) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = raw;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_read_u32(rdp_stream* stream, uint32_t* value)
{
    if (rdp_stream_read_u32_le(stream, value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_read_2byte_unsigned(rdp_stream* stream, uint32_t* value)
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

static librdp_status rdp_gdi_render_read_2byte_signed(rdp_stream* stream, int32_t* value)
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
        raw = first & 0x7fu;
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

static librdp_status rdp_gdi_render_glyph_bitmap_padded_len(uint32_t width,
                                                            uint32_t height,
                                                            uint32_t* length)
{
    uint32_t stride = 0;
    uint32_t total = 0;

    if (!length || width == 0 || height == 0 || width > UINT32_MAX - 7u)
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

static librdp_status rdp_gdi_render_read_delta(rdp_stream* stream, int32_t* value)
{
    uint8_t first = 0;
    uint32_t raw = 0;

    if (rdp_stream_read_u8(stream, &first) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (first & 0x40u)
        raw = (uint32_t)first | 0xffffffc0u;
    else
        raw = (uint32_t)(first & 0x3fu);
    if (first & 0x80u)
    {
        uint8_t second = 0;

        if (rdp_stream_read_u8(stream, &second) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        raw = (raw << 8u) | second;
    }
    *value = (int32_t)raw;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_read_delta_points(rdp_stream* stream,
                                                      uint32_t count,
                                                      rdp_gdi_render_point* points)
{
    uint8_t zero_bits[(RDP_GDI_RENDER_MAX_POINTS + 3u) / 4u];
    size_t zero_bits_len = 0;
    uint32_t i = 0;

    if (!stream || !points || count == 0 || count > RDP_GDI_RENDER_MAX_POINTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    zero_bits_len = (size_t)((count + 3u) / 4u);
    if (rdp_stream_remaining(stream) < zero_bits_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < zero_bits_len; i++)
    {
        if (rdp_stream_read_u8(stream, &zero_bits[i]) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    memset(points, 0, sizeof(*points) * count);
    for (i = 0; i < count; i++)
    {
        uint8_t flags = zero_bits[i / 4u];

        flags = (uint8_t)(flags << ((i % 4u) * 2u));
        if ((flags & 0x80u) == 0 &&
            rdp_gdi_render_read_delta(stream, &points[i].x) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if ((flags & 0x40u) == 0 &&
            rdp_gdi_render_read_delta(stream, &points[i].y) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_read_delta_blob(rdp_stream* stream,
                                                    uint32_t count,
                                                    rdp_gdi_render_point* points)
{
    uint8_t blob_len = 0;
    const uint8_t* blob = NULL;
    rdp_stream substream;
    librdp_status status = LIBRDP_STATUS_OK;

    if (rdp_stream_read_u8(stream, &blob_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (blob_len == 0 || rdp_stream_read_bytes(stream, &blob, blob_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&substream, blob, blob_len);
    status = rdp_gdi_render_read_delta_points(&substream, count, points);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_stream_remaining(&substream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_read_delta_rects(rdp_stream* stream,
                                                     uint32_t count,
                                                     rdp_gdi_render_rect* rects)
{
    uint8_t zero_bits[(RDP_GDI_RENDER_MAX_RECTS + 1u) / 2u];
    size_t zero_bits_len = 0;
    uint32_t i = 0;

    if (!stream || !rects || count == 0 || count > RDP_GDI_RENDER_MAX_RECTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    zero_bits_len = (size_t)((count + 1u) / 2u);
    if (rdp_stream_remaining(stream) < zero_bits_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < zero_bits_len; i++)
    {
        if (rdp_stream_read_u8(stream, &zero_bits[i]) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    memset(rects, 0, sizeof(*rects) * count);
    for (i = 0; i < count; i++)
    {
        uint8_t flags = zero_bits[i / 2u];

        flags = (uint8_t)(flags << ((i % 2u) * 4u));
        if ((flags & 0x80u) == 0 &&
            rdp_gdi_render_read_delta(stream, &rects[i].x) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if ((flags & 0x40u) == 0 &&
            rdp_gdi_render_read_delta(stream, &rects[i].y) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if ((flags & 0x20u) == 0)
        {
            if (rdp_gdi_render_read_delta(stream, &rects[i].width) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (i > 0)
        {
            rects[i].width = rects[i - 1u].width;
        }
        if ((flags & 0x10u) == 0)
        {
            if (rdp_gdi_render_read_delta(stream, &rects[i].height) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (i > 0)
        {
            rects[i].height = rects[i - 1u].height;
        }
        if (i > 0)
        {
            rects[i].x += rects[i - 1u].x;
            rects[i].y += rects[i - 1u].y;
        }
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_read_rect_blob(rdp_stream* stream,
                                                   uint32_t count,
                                                   rdp_gdi_render_rect* rects)
{
    uint16_t blob_len = 0;
    const uint8_t* blob = NULL;
    rdp_stream substream;
    librdp_status status = LIBRDP_STATUS_OK;

    if (rdp_stream_read_u16_le(stream, &blob_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (blob_len == 0 || rdp_stream_read_bytes(stream, &blob, blob_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&substream, blob, blob_len);
    status = rdp_gdi_render_read_delta_rects(&substream, count, rects);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_stream_remaining(&substream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
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

    op->kind = RDP_GDI_RENDER_OP_PATBLT;
    op->rop = state->pat_rop;
    op->color = state->pat_fore_color;
    op->back_color = state->pat_back_color;
    op->rect.x = state->pat_left;
    op->rect.y = state->pat_top;
    op->rect.width = state->pat_width;
    op->rect.height = state->pat_height;
    op->brush_x = state->pat_brush_x;
    op->brush_y = state->pat_brush_y;
    op->brush_style = state->pat_brush_style;
    op->brush_hatch = state->pat_brush_hatch;
    memcpy(op->brush_extra, state->pat_brush_extra, sizeof(op->brush_extra));
    return LIBRDP_STATUS_OK;
}

static void rdp_gdi_render_split_cache_id(uint32_t packed, uint32_t* cache_id, uint32_t* color_index)
{
    if (cache_id)
        *cache_id = packed & 0xffu;
    if (color_index)
        *color_index = (packed >> 8u) & 0xffu;
}

static librdp_status rdp_gdi_render_decode_memblt(rdp_stream* stream,
                                                  uint32_t flags,
                                                  int delta,
                                                  rdp_gdi_render_state* state,
                                                  rdp_gdi_render_op* op)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x0001u)
        status = rdp_gdi_render_read_u16(stream, &state->mem_cache_id);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0002u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->mem_left);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0004u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->mem_top);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0008u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->mem_width);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0010u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->mem_height);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0020u) &&
        rdp_stream_read_u8(stream, &state->mem_rop) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0040u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->mem_src_x);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0080u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->mem_src_y);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0100u))
        status = rdp_gdi_render_read_u16(stream, &state->mem_cache_index);
    if (status != LIBRDP_STATUS_OK)
        return status;

    op->kind = RDP_GDI_RENDER_OP_MEMBLT;
    op->rop = state->mem_rop;
    op->rect.x = state->mem_left;
    op->rect.y = state->mem_top;
    op->rect.width = state->mem_width;
    op->rect.height = state->mem_height;
    op->src_x = state->mem_src_x;
    op->src_y = state->mem_src_y;
    op->cache_index = state->mem_cache_index;
    rdp_gdi_render_split_cache_id(state->mem_cache_id, &op->cache_id, &op->color_index);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_mem3blt(rdp_stream* stream,
                                                   uint32_t flags,
                                                   int delta,
                                                   rdp_gdi_render_state* state,
                                                   rdp_gdi_render_op* op)
{
    const uint8_t* extra = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x0001u)
        status = rdp_gdi_render_read_u16(stream, &state->mem3_cache_id);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0002u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->mem3_left);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0004u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->mem3_top);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0008u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->mem3_width);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0010u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->mem3_height);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0020u) &&
        rdp_stream_read_u8(stream, &state->mem3_rop) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0040u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->mem3_src_x);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0080u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->mem3_src_y);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0100u))
        status = rdp_gdi_render_read_color(stream, &state->mem3_back_color);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0200u))
        status = rdp_gdi_render_read_color(stream, &state->mem3_fore_color);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0400u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->mem3_brush_x);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0800u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->mem3_brush_y);
    if (status == LIBRDP_STATUS_OK && (flags & 0x1000u) &&
        rdp_stream_read_u8(stream, &state->mem3_brush_style) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x2000u) &&
        rdp_stream_read_u8(stream, &state->mem3_brush_hatch) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x4000u))
    {
        if (rdp_stream_read_bytes(stream, &extra, sizeof(state->mem3_brush_extra)) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            memcpy(state->mem3_brush_extra, extra, sizeof(state->mem3_brush_extra));
    }
    if (status == LIBRDP_STATUS_OK && (flags & 0x8000u))
        status = rdp_gdi_render_read_u16(stream, &state->mem3_cache_index);
    if (status != LIBRDP_STATUS_OK)
        return status;

    op->kind = RDP_GDI_RENDER_OP_MEM3BLT;
    op->rop = state->mem3_rop;
    op->color = state->mem3_fore_color;
    op->back_color = state->mem3_back_color;
    op->rect.x = state->mem3_left;
    op->rect.y = state->mem3_top;
    op->rect.width = state->mem3_width;
    op->rect.height = state->mem3_height;
    op->src_x = state->mem3_src_x;
    op->src_y = state->mem3_src_y;
    op->brush_x = state->mem3_brush_x;
    op->brush_y = state->mem3_brush_y;
    op->brush_style = state->mem3_brush_style;
    op->brush_hatch = state->mem3_brush_hatch;
    op->cache_index = state->mem3_cache_index;
    memcpy(op->brush_extra, state->mem3_brush_extra, sizeof(op->brush_extra));
    rdp_gdi_render_split_cache_id(state->mem3_cache_id, &op->cache_id, &op->color_index);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_multi_dstblt(rdp_stream* stream,
                                                        uint32_t flags,
                                                        int delta,
                                                        rdp_gdi_render_state* state,
                                                        rdp_gdi_render_op* op)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x01u)
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_dst_left);
    if (status == LIBRDP_STATUS_OK && (flags & 0x02u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_dst_top);
    if (status == LIBRDP_STATUS_OK && (flags & 0x04u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_dst_width);
    if (status == LIBRDP_STATUS_OK && (flags & 0x08u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_dst_height);
    if (status == LIBRDP_STATUS_OK && (flags & 0x10u) &&
        rdp_stream_read_u8(stream, &state->multi_dst_rop) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x20u))
    {
        uint8_t count = 0;

        if (rdp_stream_read_u8(stream, &count) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            state->multi_dst_rect_count = count;
    }
    if (status == LIBRDP_STATUS_OK && (flags & 0x40u))
    {
        if (state->multi_dst_rect_count == 0 ||
            state->multi_dst_rect_count > RDP_GDI_RENDER_MAX_RECTS)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            status = rdp_gdi_render_read_rect_blob(stream,
                                                   state->multi_dst_rect_count,
                                                   state->multi_dst_rects);
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (state->multi_dst_rect_count > RDP_GDI_RENDER_MAX_RECTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    op->kind = RDP_GDI_RENDER_OP_MULTIDSTBLT;
    op->rop = state->multi_dst_rop;
    op->rect.x = state->multi_dst_left;
    op->rect.y = state->multi_dst_top;
    op->rect.width = state->multi_dst_width;
    op->rect.height = state->multi_dst_height;
    op->rect_count = state->multi_dst_rect_count;
    memcpy(op->rects, state->multi_dst_rects, sizeof(op->rects[0]) * op->rect_count);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_multi_scrblt(rdp_stream* stream,
                                                        uint32_t flags,
                                                        int delta,
                                                        rdp_gdi_render_state* state,
                                                        rdp_gdi_render_op* op)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x001u)
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_scr_left);
    if (status == LIBRDP_STATUS_OK && (flags & 0x002u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_scr_top);
    if (status == LIBRDP_STATUS_OK && (flags & 0x004u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_scr_width);
    if (status == LIBRDP_STATUS_OK && (flags & 0x008u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_scr_height);
    if (status == LIBRDP_STATUS_OK && (flags & 0x010u) &&
        rdp_stream_read_u8(stream, &state->multi_scr_rop) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x020u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_scr_src_x);
    if (status == LIBRDP_STATUS_OK && (flags & 0x040u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_scr_src_y);
    if (status == LIBRDP_STATUS_OK && (flags & 0x080u))
    {
        uint8_t count = 0;

        if (rdp_stream_read_u8(stream, &count) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            state->multi_scr_rect_count = count;
    }
    if (status == LIBRDP_STATUS_OK && (flags & 0x100u))
    {
        if (state->multi_scr_rect_count == 0 ||
            state->multi_scr_rect_count > RDP_GDI_RENDER_MAX_RECTS)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            status = rdp_gdi_render_read_rect_blob(stream,
                                                   state->multi_scr_rect_count,
                                                   state->multi_scr_rects);
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (state->multi_scr_rect_count > RDP_GDI_RENDER_MAX_RECTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    op->kind = RDP_GDI_RENDER_OP_MULTISCRBLT;
    op->rop = state->multi_scr_rop;
    op->rect.x = state->multi_scr_left;
    op->rect.y = state->multi_scr_top;
    op->rect.width = state->multi_scr_width;
    op->rect.height = state->multi_scr_height;
    op->src_x = state->multi_scr_src_x;
    op->src_y = state->multi_scr_src_y;
    op->rect_count = state->multi_scr_rect_count;
    memcpy(op->rects, state->multi_scr_rects, sizeof(op->rects[0]) * op->rect_count);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_multi_patblt(rdp_stream* stream,
                                                        uint32_t flags,
                                                        int delta,
                                                        rdp_gdi_render_state* state,
                                                        rdp_gdi_render_op* op)
{
    const uint8_t* extra = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x0001u)
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_pat_left);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0002u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_pat_top);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0004u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_pat_width);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0008u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_pat_height);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0010u) &&
        rdp_stream_read_u8(stream, &state->multi_pat_rop) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0020u))
        status = rdp_gdi_render_read_color(stream, &state->multi_pat_back_color);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0040u))
        status = rdp_gdi_render_read_color(stream, &state->multi_pat_fore_color);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0080u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_pat_brush_x);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0100u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_pat_brush_y);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0200u) &&
        rdp_stream_read_u8(stream, &state->multi_pat_brush_style) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0400u) &&
        rdp_stream_read_u8(stream, &state->multi_pat_brush_hatch) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0800u))
    {
        if (rdp_stream_read_bytes(stream, &extra, sizeof(state->multi_pat_brush_extra)) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            memcpy(state->multi_pat_brush_extra, extra, sizeof(state->multi_pat_brush_extra));
    }
    if (status == LIBRDP_STATUS_OK && (flags & 0x1000u))
    {
        uint8_t count = 0;

        if (rdp_stream_read_u8(stream, &count) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            state->multi_pat_rect_count = count;
    }
    if (status == LIBRDP_STATUS_OK && (flags & 0x2000u))
    {
        if (state->multi_pat_rect_count == 0 ||
            state->multi_pat_rect_count > RDP_GDI_RENDER_MAX_RECTS)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            status = rdp_gdi_render_read_rect_blob(stream,
                                                   state->multi_pat_rect_count,
                                                   state->multi_pat_rects);
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (state->multi_pat_rect_count > RDP_GDI_RENDER_MAX_RECTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    op->kind = RDP_GDI_RENDER_OP_MULTIPATBLT;
    op->rop = state->multi_pat_rop;
    op->color = state->multi_pat_fore_color;
    op->back_color = state->multi_pat_back_color;
    op->rect.x = state->multi_pat_left;
    op->rect.y = state->multi_pat_top;
    op->rect.width = state->multi_pat_width;
    op->rect.height = state->multi_pat_height;
    op->brush_x = state->multi_pat_brush_x;
    op->brush_y = state->multi_pat_brush_y;
    op->brush_style = state->multi_pat_brush_style;
    op->brush_hatch = state->multi_pat_brush_hatch;
    op->rect_count = state->multi_pat_rect_count;
    memcpy(op->brush_extra, state->multi_pat_brush_extra, sizeof(op->brush_extra));
    memcpy(op->rects, state->multi_pat_rects, sizeof(op->rects[0]) * op->rect_count);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_multi_opaque_rect(rdp_stream* stream,
                                                             uint32_t flags,
                                                             int delta,
                                                             rdp_gdi_render_state* state,
                                                             rdp_gdi_render_op* op)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t byte = 0;

    if (flags & 0x001u)
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_opaque_left);
    if (status == LIBRDP_STATUS_OK && (flags & 0x002u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_opaque_top);
    if (status == LIBRDP_STATUS_OK && (flags & 0x004u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_opaque_width);
    if (status == LIBRDP_STATUS_OK && (flags & 0x008u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_opaque_height);
    if (status == LIBRDP_STATUS_OK && (flags & 0x010u))
    {
        if (rdp_stream_read_u8(stream, &byte) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            state->multi_opaque_color = (state->multi_opaque_color & 0x00ffff00u) | byte;
    }
    if (status == LIBRDP_STATUS_OK && (flags & 0x020u))
    {
        if (rdp_stream_read_u8(stream, &byte) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            state->multi_opaque_color = (state->multi_opaque_color & 0x00ff00ffu) |
                                        ((uint32_t)byte << 8u);
    }
    if (status == LIBRDP_STATUS_OK && (flags & 0x040u))
    {
        if (rdp_stream_read_u8(stream, &byte) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            state->multi_opaque_color = (state->multi_opaque_color & 0x0000ffffu) |
                                        ((uint32_t)byte << 16u);
    }
    if (status == LIBRDP_STATUS_OK && (flags & 0x080u))
    {
        uint8_t count = 0;

        if (rdp_stream_read_u8(stream, &count) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            state->multi_opaque_rect_count = count;
    }
    if (status == LIBRDP_STATUS_OK && (flags & 0x100u))
    {
        if (state->multi_opaque_rect_count == 0 ||
            state->multi_opaque_rect_count > RDP_GDI_RENDER_MAX_RECTS)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            status = rdp_gdi_render_read_rect_blob(stream,
                                                   state->multi_opaque_rect_count,
                                                   state->multi_opaque_rects);
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (state->multi_opaque_rect_count > RDP_GDI_RENDER_MAX_RECTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    op->kind = RDP_GDI_RENDER_OP_MULTIOPAQUE_RECT;
    op->color = state->multi_opaque_color;
    op->rect.x = state->multi_opaque_left;
    op->rect.y = state->multi_opaque_top;
    op->rect.width = state->multi_opaque_width;
    op->rect.height = state->multi_opaque_height;
    op->rect_count = state->multi_opaque_rect_count;
    memcpy(op->rects, state->multi_opaque_rects, sizeof(op->rects[0]) * op->rect_count);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_line(rdp_stream* stream,
                                                uint32_t flags,
                                                int delta,
                                                rdp_gdi_render_state* state,
                                                rdp_gdi_render_op* op)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x0001u)
        status = rdp_gdi_render_read_u16(stream, &state->line_back_mode);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0002u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->line_start_x);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0004u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->line_start_y);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0008u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->line_end_x);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0010u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->line_end_y);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0020u))
        status = rdp_gdi_render_read_color(stream, &state->line_back_color);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0040u) &&
        rdp_stream_read_u8(stream, &state->line_rop2) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0080u) &&
        rdp_stream_read_u8(stream, &state->line_pen_style) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0100u) &&
        rdp_stream_read_u8(stream, &state->line_pen_width) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0200u))
        status = rdp_gdi_render_read_color(stream, &state->line_pen_color);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (state->line_pen_style > 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    op->kind = RDP_GDI_RENDER_OP_LINE;
    op->rop = state->line_rop2;
    op->color = state->line_pen_color;
    op->rect.x = state->line_start_x;
    op->rect.y = state->line_start_y;
    op->end_x = state->line_end_x;
    op->end_y = state->line_end_y;
    op->pen_width = state->line_pen_width == 0 ? 1u : state->line_pen_width;
    op->pen_style = state->line_pen_style;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_polyline(rdp_stream* stream,
                                                    uint32_t flags,
                                                    int delta,
                                                    rdp_gdi_render_state* state,
                                                    rdp_gdi_render_op* op)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x01u)
        status = rdp_gdi_render_read_coord(stream, delta, &state->polyline_start_x);
    if (status == LIBRDP_STATUS_OK && (flags & 0x02u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->polyline_start_y);
    if (status == LIBRDP_STATUS_OK && (flags & 0x04u) &&
        rdp_stream_read_u8(stream, &state->polyline_rop2) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x08u))
        status = rdp_gdi_render_read_u16(stream, &state->polyline_unused);
    if (status == LIBRDP_STATUS_OK && (flags & 0x10u))
        status = rdp_gdi_render_read_color(stream, &state->polyline_pen_color);
    if (status == LIBRDP_STATUS_OK && (flags & 0x20u))
    {
        uint8_t count = 0;

        if (rdp_stream_read_u8(stream, &count) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            state->polyline_point_count = count;
    }
    if (status == LIBRDP_STATUS_OK && (flags & 0x40u))
    {
        if (state->polyline_point_count == 0 ||
            state->polyline_point_count > RDP_GDI_RENDER_MAX_POINTS)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            status = rdp_gdi_render_read_delta_blob(stream,
                                                    state->polyline_point_count,
                                                    state->polyline_points);
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (state->polyline_point_count > RDP_GDI_RENDER_MAX_POINTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    op->kind = RDP_GDI_RENDER_OP_POLYLINE;
    op->rop = state->polyline_rop2;
    op->color = state->polyline_pen_color;
    op->rect.x = state->polyline_start_x;
    op->rect.y = state->polyline_start_y;
    op->point_count = state->polyline_point_count;
    memcpy(op->points, state->polyline_points, sizeof(op->points[0]) * op->point_count);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_polygon_sc(rdp_stream* stream,
                                                      uint32_t flags,
                                                      int delta,
                                                      rdp_gdi_render_state* state,
                                                      rdp_gdi_render_op* op)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x01u)
        status = rdp_gdi_render_read_coord(stream, delta, &state->polygon_start_x);
    if (status == LIBRDP_STATUS_OK && (flags & 0x02u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->polygon_start_y);
    if (status == LIBRDP_STATUS_OK && (flags & 0x04u) &&
        rdp_stream_read_u8(stream, &state->polygon_rop2) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x08u) &&
        rdp_stream_read_u8(stream, &state->polygon_fill_mode) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x10u))
        status = rdp_gdi_render_read_color(stream, &state->polygon_color);
    if (status == LIBRDP_STATUS_OK && (flags & 0x20u))
    {
        uint8_t count = 0;

        if (rdp_stream_read_u8(stream, &count) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            state->polygon_point_count = count;
    }
    if (status == LIBRDP_STATUS_OK && (flags & 0x40u))
    {
        if (state->polygon_point_count == 0 ||
            state->polygon_point_count > RDP_GDI_RENDER_MAX_POINTS)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            status = rdp_gdi_render_read_delta_blob(stream,
                                                    state->polygon_point_count,
                                                    state->polygon_points);
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (state->polygon_point_count > RDP_GDI_RENDER_MAX_POINTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    op->kind = RDP_GDI_RENDER_OP_POLYGON_SC;
    op->rop = state->polygon_rop2;
    op->fill_mode = state->polygon_fill_mode;
    op->color = state->polygon_color;
    op->rect.x = state->polygon_start_x;
    op->rect.y = state->polygon_start_y;
    op->point_count = state->polygon_point_count;
    memcpy(op->points, state->polygon_points, sizeof(op->points[0]) * op->point_count);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_polygon_cb(rdp_stream* stream,
                                                      uint32_t flags,
                                                      int delta,
                                                      rdp_gdi_render_state* state,
                                                      rdp_gdi_render_op* op)
{
    const uint8_t* extra = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x0001u)
        status = rdp_gdi_render_read_coord(stream, delta, &state->polygon_start_x);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0002u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->polygon_start_y);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0004u) &&
        rdp_stream_read_u8(stream, &state->polygon_rop2) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0008u) &&
        rdp_stream_read_u8(stream, &state->polygon_fill_mode) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0010u))
        status = rdp_gdi_render_read_color(stream, &state->pat_back_color);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0020u))
        status = rdp_gdi_render_read_color(stream, &state->pat_fore_color);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0040u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->pat_brush_x);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0080u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->pat_brush_y);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0100u) &&
        rdp_stream_read_u8(stream, &state->pat_brush_style) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0200u) &&
        rdp_stream_read_u8(stream, &state->pat_brush_hatch) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0400u))
    {
        if (rdp_stream_read_bytes(stream, &extra, sizeof(state->pat_brush_extra)) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            memcpy(state->pat_brush_extra, extra, sizeof(state->pat_brush_extra));
    }
    if (status == LIBRDP_STATUS_OK && (flags & 0x0800u))
    {
        uint8_t count = 0;

        if (rdp_stream_read_u8(stream, &count) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            state->polygon_point_count = count;
    }
    if (status == LIBRDP_STATUS_OK && (flags & 0x1000u))
    {
        if (state->polygon_point_count == 0 ||
            state->polygon_point_count > RDP_GDI_RENDER_MAX_POINTS)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            status = rdp_gdi_render_read_delta_blob(stream,
                                                    state->polygon_point_count,
                                                    state->polygon_points);
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (state->polygon_point_count > RDP_GDI_RENDER_MAX_POINTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    op->kind = RDP_GDI_RENDER_OP_POLYGON_CB;
    op->rop = state->polygon_rop2 & 0x1fu;
    op->transparent_background = (state->polygon_rop2 & 0x80u) != 0;
    op->fill_mode = state->polygon_fill_mode;
    op->color = state->pat_fore_color;
    op->back_color = state->pat_back_color;
    op->rect.x = state->polygon_start_x;
    op->rect.y = state->polygon_start_y;
    op->brush_x = state->pat_brush_x;
    op->brush_y = state->pat_brush_y;
    op->brush_style = state->pat_brush_style;
    op->brush_hatch = state->pat_brush_hatch;
    op->point_count = state->polygon_point_count;
    memcpy(op->brush_extra, state->pat_brush_extra, sizeof(op->brush_extra));
    memcpy(op->points, state->polygon_points, sizeof(op->points[0]) * op->point_count);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_ellipse_sc(rdp_stream* stream,
                                                      uint32_t flags,
                                                      int delta,
                                                      rdp_gdi_render_state* state,
                                                      rdp_gdi_render_op* op)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x01u)
        status = rdp_gdi_render_read_coord(stream, delta, &state->ellipse_left);
    if (status == LIBRDP_STATUS_OK && (flags & 0x02u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->ellipse_top);
    if (status == LIBRDP_STATUS_OK && (flags & 0x04u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->ellipse_right);
    if (status == LIBRDP_STATUS_OK && (flags & 0x08u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->ellipse_bottom);
    if (status == LIBRDP_STATUS_OK && (flags & 0x10u) &&
        rdp_stream_read_u8(stream, &state->ellipse_rop2) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x20u) &&
        rdp_stream_read_u8(stream, &state->ellipse_fill_mode) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x40u))
        status = rdp_gdi_render_read_color(stream, &state->ellipse_color);
    if (status != LIBRDP_STATUS_OK)
        return status;

    op->kind = RDP_GDI_RENDER_OP_ELLIPSE_SC;
    op->rop = state->ellipse_rop2;
    op->fill_mode = state->ellipse_fill_mode;
    op->color = state->ellipse_color;
    op->rect.x = state->ellipse_left;
    op->rect.y = state->ellipse_top;
    op->rect.width = state->ellipse_right - state->ellipse_left + 1;
    op->rect.height = state->ellipse_bottom - state->ellipse_top + 1;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_ellipse_cb(rdp_stream* stream,
                                                      uint32_t flags,
                                                      int delta,
                                                      rdp_gdi_render_state* state,
                                                      rdp_gdi_render_op* op)
{
    const uint8_t* extra = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x0001u)
        status = rdp_gdi_render_read_coord(stream, delta, &state->ellipse_left);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0002u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->ellipse_top);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0004u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->ellipse_right);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0008u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->ellipse_bottom);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0010u) &&
        rdp_stream_read_u8(stream, &state->ellipse_rop2) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0020u) &&
        rdp_stream_read_u8(stream, &state->ellipse_fill_mode) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0040u))
        status = rdp_gdi_render_read_color(stream, &state->pat_back_color);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0080u))
        status = rdp_gdi_render_read_color(stream, &state->pat_fore_color);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0100u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->pat_brush_x);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0200u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->pat_brush_y);
    if (status == LIBRDP_STATUS_OK && (flags & 0x0400u) &&
        rdp_stream_read_u8(stream, &state->pat_brush_style) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x0800u) &&
        rdp_stream_read_u8(stream, &state->pat_brush_hatch) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && (flags & 0x1000u))
    {
        if (rdp_stream_read_bytes(stream, &extra, sizeof(state->pat_brush_extra)) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            memcpy(state->pat_brush_extra, extra, sizeof(state->pat_brush_extra));
    }
    if (status != LIBRDP_STATUS_OK)
        return status;

    op->kind = RDP_GDI_RENDER_OP_ELLIPSE_CB;
    op->rop = state->ellipse_rop2 & 0x1fu;
    op->transparent_background = (state->ellipse_rop2 & 0x80u) != 0;
    op->fill_mode = state->ellipse_fill_mode;
    op->color = state->pat_fore_color;
    op->back_color = state->pat_back_color;
    op->rect.x = state->ellipse_left;
    op->rect.y = state->ellipse_top;
    op->rect.width = state->ellipse_right - state->ellipse_left + 1;
    op->rect.height = state->ellipse_bottom - state->ellipse_top + 1;
    op->brush_x = state->pat_brush_x;
    op->brush_y = state->pat_brush_y;
    op->brush_style = state->pat_brush_style;
    op->brush_hatch = state->pat_brush_hatch;
    memcpy(op->brush_extra, state->pat_brush_extra, sizeof(op->brush_extra));
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_save_bitmap(rdp_stream* stream,
                                                       uint32_t flags,
                                                       int delta,
                                                       rdp_gdi_render_state* state,
                                                       rdp_gdi_render_op* op)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x01u)
        status = rdp_gdi_render_read_u32(stream, &state->save_bitmap_position);
    if (status == LIBRDP_STATUS_OK && (flags & 0x02u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->save_bitmap_left);
    if (status == LIBRDP_STATUS_OK && (flags & 0x04u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->save_bitmap_top);
    if (status == LIBRDP_STATUS_OK && (flags & 0x08u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->save_bitmap_right);
    if (status == LIBRDP_STATUS_OK && (flags & 0x10u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->save_bitmap_bottom);
    if (status == LIBRDP_STATUS_OK && (flags & 0x20u) &&
        rdp_stream_read_u8(stream, &state->save_bitmap_operation) != LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (state->save_bitmap_operation > 1u ||
        state->save_bitmap_right < state->save_bitmap_left ||
        state->save_bitmap_bottom < state->save_bitmap_top)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    op->kind = RDP_GDI_RENDER_OP_SAVE_BITMAP;
    op->bitmap_id = state->save_bitmap_position;
    op->operation = state->save_bitmap_operation;
    op->rect.x = state->save_bitmap_left;
    op->rect.y = state->save_bitmap_top;
    op->rect.width = state->save_bitmap_right - state->save_bitmap_left + 1;
    op->rect.height = state->save_bitmap_bottom - state->save_bitmap_top + 1;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_rect_from_bounds_or_source(const rdp_gdi_render_op* op,
                                                               int32_t src_left,
                                                               int32_t src_top,
                                                               int32_t src_right,
                                                               int32_t src_bottom,
                                                               rdp_gdi_render_rect* rect)
{
    if (!op || !rect || src_right < src_left || src_bottom < src_top)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (op->bounds.present)
    {
        if (op->bounds.right < op->bounds.left || op->bounds.bottom < op->bounds.top)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        rect->x = op->bounds.left;
        rect->y = op->bounds.top;
        rect->width = op->bounds.right - op->bounds.left + 1;
        rect->height = op->bounds.bottom - op->bounds.top + 1;
        return LIBRDP_STATUS_OK;
    }
    rect->x = src_left;
    rect->y = src_top;
    rect->width = src_right - src_left + 1;
    rect->height = src_bottom - src_top + 1;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_draw_ninegrid(rdp_stream* stream,
                                                         uint32_t flags,
                                                         int delta,
                                                         rdp_gdi_render_state* state,
                                                         rdp_gdi_render_op* op)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x01u)
        status = rdp_gdi_render_read_coord(stream, delta, &state->nine_src_left);
    if (status == LIBRDP_STATUS_OK && (flags & 0x02u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->nine_src_top);
    if (status == LIBRDP_STATUS_OK && (flags & 0x04u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->nine_src_right);
    if (status == LIBRDP_STATUS_OK && (flags & 0x08u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->nine_src_bottom);
    if (status == LIBRDP_STATUS_OK && (flags & 0x10u))
        status = rdp_gdi_render_read_u16(stream, &state->nine_bitmap_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    op->kind = RDP_GDI_RENDER_OP_DRAW_NINEGRID;
    op->bitmap_id = state->nine_bitmap_id;
    op->src_left = state->nine_src_left;
    op->src_top = state->nine_src_top;
    op->src_right = state->nine_src_right;
    op->src_bottom = state->nine_src_bottom;
    return rdp_gdi_render_rect_from_bounds_or_source(op,
                                                     state->nine_src_left,
                                                     state->nine_src_top,
                                                     state->nine_src_right,
                                                     state->nine_src_bottom,
                                                     &op->rect);
}

static librdp_status rdp_gdi_render_decode_multi_draw_ninegrid(rdp_stream* stream,
                                                               uint32_t flags,
                                                               int delta,
                                                               rdp_gdi_render_state* state,
                                                               rdp_gdi_render_op* op)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (flags & 0x01u)
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_nine_src_left);
    if (status == LIBRDP_STATUS_OK && (flags & 0x02u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_nine_src_top);
    if (status == LIBRDP_STATUS_OK && (flags & 0x04u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_nine_src_right);
    if (status == LIBRDP_STATUS_OK && (flags & 0x08u))
        status = rdp_gdi_render_read_coord(stream, delta, &state->multi_nine_src_bottom);
    if (status == LIBRDP_STATUS_OK && (flags & 0x10u))
        status = rdp_gdi_render_read_u16(stream, &state->multi_nine_bitmap_id);
    if (status == LIBRDP_STATUS_OK && (flags & 0x20u))
    {
        uint8_t count = 0;

        if (rdp_stream_read_u8(stream, &count) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            state->multi_nine_rect_count = count;
    }
    if (status == LIBRDP_STATUS_OK && (flags & 0x40u))
    {
        if (state->multi_nine_rect_count == 0 ||
            state->multi_nine_rect_count > RDP_GDI_RENDER_MAX_RECTS)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            status = rdp_gdi_render_read_rect_blob(stream,
                                                   state->multi_nine_rect_count,
                                                   state->multi_nine_rects);
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (state->multi_nine_rect_count > RDP_GDI_RENDER_MAX_RECTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    op->kind = RDP_GDI_RENDER_OP_MULTI_DRAW_NINEGRID;
    op->bitmap_id = state->multi_nine_bitmap_id;
    op->src_left = state->multi_nine_src_left;
    op->src_top = state->multi_nine_src_top;
    op->src_right = state->multi_nine_src_right;
    op->src_bottom = state->multi_nine_src_bottom;
    op->rect_count = state->multi_nine_rect_count;
    memcpy(op->rects, state->multi_nine_rects, sizeof(op->rects[0]) * op->rect_count);
    return rdp_gdi_render_rect_from_bounds_or_source(op,
                                                     state->multi_nine_src_left,
                                                     state->multi_nine_src_top,
                                                     state->multi_nine_src_right,
                                                     state->multi_nine_src_bottom,
                                                     &op->rect);
}

static void rdp_gdi_render_rect_from_edges(int32_t left,
                                           int32_t top,
                                           int32_t right,
                                           int32_t bottom,
                                           rdp_gdi_render_rect* rect)
{
    if (!rect)
        return;
    rect->x = left;
    rect->y = top;
    rect->width = right >= left ? right - left + 1 : 0;
    rect->height = bottom >= top ? bottom - top + 1 : 0;
}

static librdp_status rdp_gdi_render_read_glyph_index_data(rdp_stream* stream,
                                                          rdp_gdi_render_state* state,
                                                          rdp_gdi_render_op* op)
{
    uint8_t length = 0;
    const uint8_t* data = NULL;

    if (rdp_stream_read_u8(stream, &length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(stream, &data, length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    state->glyph_data = data;
    state->glyph_data_len = length;
    op->glyph_data = data;
    op->glyph_data_len = length;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_inline_glyph(rdp_gdi_render_op* op)
{
    rdp_stream stream;
    uint8_t cache_index = 0;
    uint32_t bitmap_len = 0;

    if (!op || !op->glyph_data || op->glyph_data_len <= 1u)
        return LIBRDP_STATUS_OK;
    rdp_stream_init(&stream, op->glyph_data, op->glyph_data_len);
    if (rdp_stream_read_u8(&stream, &cache_index) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    op->inline_glyph_cache_index = cache_index;
    if (rdp_gdi_render_read_2byte_signed(&stream, &op->inline_glyph_x) != LIBRDP_STATUS_OK ||
        rdp_gdi_render_read_2byte_signed(&stream, &op->inline_glyph_y) != LIBRDP_STATUS_OK ||
        rdp_gdi_render_read_2byte_unsigned(&stream, &op->inline_glyph_width) != LIBRDP_STATUS_OK ||
        rdp_gdi_render_read_2byte_unsigned(&stream, &op->inline_glyph_height) != LIBRDP_STATUS_OK ||
        rdp_gdi_render_glyph_bitmap_padded_len(op->inline_glyph_width,
                                               op->inline_glyph_height,
                                               &bitmap_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != bitmap_len ||
        rdp_stream_read_bytes(&stream, &op->inline_glyph_bitmap, bitmap_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    op->inline_glyph_bitmap_len = bitmap_len;
    op->inline_glyph_present = 1;
    op->glyph_data_len = 1;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_glyph_index(rdp_stream* stream,
                                                       uint32_t flags,
                                                       int delta,
                                                       rdp_gdi_render_state* state,
                                                       rdp_gdi_render_op* op)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t ignored = 0;
    const uint8_t* ignored_extra = NULL;

    (void)delta;
    if (flags & 0x000001u)
    {
        uint8_t value = 0;

        if (rdp_stream_read_u8(stream, &value) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        state->glyph_cache_id = value;
    }
    if (flags & 0x000002u)
    {
        if (rdp_stream_read_u8(stream, &ignored) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        state->glyph_flags = ignored;
    }
    if (flags & 0x000004u)
    {
        if (rdp_stream_read_u8(stream, &ignored) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        state->glyph_char_inc = ignored;
    }
    if (flags & 0x000008u)
    {
        if (rdp_stream_read_u8(stream, &ignored) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        state->glyph_opaque = ignored;
    }
    if ((flags & 0x000010u) &&
        rdp_gdi_render_read_color(stream, &state->glyph_back_color) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x000020u) &&
        rdp_gdi_render_read_color(stream, &state->glyph_fore_color) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x000040u) && rdp_gdi_render_read_i16(stream, &state->glyph_back_left) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x000080u) && rdp_gdi_render_read_i16(stream, &state->glyph_back_top) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x000100u) && rdp_gdi_render_read_i16(stream, &state->glyph_back_right) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x000200u) && rdp_gdi_render_read_i16(stream, &state->glyph_back_bottom) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x000400u) && rdp_gdi_render_read_i16(stream, &state->glyph_op_left) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x000800u) && rdp_gdi_render_read_i16(stream, &state->glyph_op_top) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x001000u) && rdp_gdi_render_read_i16(stream, &state->glyph_op_right) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x002000u) && rdp_gdi_render_read_i16(stream, &state->glyph_op_bottom) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x004000u) && rdp_stream_read_u8(stream, &ignored) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x008000u) && rdp_stream_read_u8(stream, &ignored) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x010000u) && rdp_stream_read_u8(stream, &ignored) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x020000u) && rdp_stream_read_u8(stream, &ignored) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x040000u) &&
        rdp_stream_read_bytes(stream, &ignored_extra, 7u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x080000u) && rdp_gdi_render_read_i16(stream, &state->glyph_x) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x100000u) && rdp_gdi_render_read_i16(stream, &state->glyph_y) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    op->glyph_data = state->glyph_data;
    op->glyph_data_len = state->glyph_data_len;
    if (flags & 0x200000u)
    {
        status = rdp_gdi_render_read_glyph_index_data(stream, state, op);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    op->kind = RDP_GDI_RENDER_OP_GLYPH;
    op->cache_id = state->glyph_cache_id;
    op->glyph_flags = state->glyph_flags;
    op->glyph_char_inc = state->glyph_char_inc;
    op->glyph_opaque = state->glyph_opaque != 0;
    op->back_color = state->glyph_back_color;
    op->color = state->glyph_fore_color;
    op->glyph_x = state->glyph_x;
    op->glyph_y = state->glyph_y;
    rdp_gdi_render_rect_from_edges(state->glyph_op_left,
                                   state->glyph_op_top,
                                   state->glyph_op_right,
                                   state->glyph_op_bottom,
                                   &op->rect);
    rdp_gdi_render_rect_from_edges(state->glyph_back_left,
                                   state->glyph_back_top,
                                   state->glyph_back_right,
                                   state->glyph_back_bottom,
                                   &op->glyph_back_rect);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_render_decode_fast_glyph_common(rdp_stream* stream,
                                                            uint32_t flags,
                                                            int delta,
                                                            rdp_gdi_render_state* state,
                                                            rdp_gdi_render_op* op,
                                                            int inline_glyph)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t value = 0;

    if (flags & 0x0001u)
    {
        if (rdp_stream_read_u8(stream, &value) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        state->glyph_cache_id = value;
    }
    if (flags & 0x0002u)
    {
        uint8_t char_inc = 0;
        uint8_t accel = 0;

        if (rdp_stream_read_u8(stream, &char_inc) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(stream, &accel) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        state->glyph_char_inc = char_inc;
        state->glyph_flags = accel;
    }
    if ((flags & 0x0004u) &&
        rdp_gdi_render_read_color(stream, &state->glyph_back_color) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x0008u) &&
        rdp_gdi_render_read_color(stream, &state->glyph_fore_color) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x0010u) && rdp_gdi_render_read_coord(stream, delta, &state->glyph_back_left) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x0020u) && rdp_gdi_render_read_coord(stream, delta, &state->glyph_back_top) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x0040u) && rdp_gdi_render_read_coord(stream, delta, &state->glyph_back_right) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x0080u) && rdp_gdi_render_read_coord(stream, delta, &state->glyph_back_bottom) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x0100u) && rdp_gdi_render_read_coord(stream, delta, &state->glyph_op_left) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x0200u) && rdp_gdi_render_read_coord(stream, delta, &state->glyph_op_top) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x0400u) && rdp_gdi_render_read_coord(stream, delta, &state->glyph_op_right) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x0800u) && rdp_gdi_render_read_coord(stream, delta, &state->glyph_op_bottom) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x1000u) && rdp_gdi_render_read_coord(stream, delta, &state->glyph_x) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & 0x2000u) && rdp_gdi_render_read_coord(stream, delta, &state->glyph_y) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    op->glyph_data = state->glyph_data;
    op->glyph_data_len = state->glyph_data_len;
    if (flags & 0x4000u)
    {
        status = rdp_gdi_render_read_glyph_index_data(stream, state, op);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    op->kind = RDP_GDI_RENDER_OP_GLYPH;
    op->cache_id = state->glyph_cache_id;
    op->glyph_flags = state->glyph_flags;
    op->glyph_char_inc = state->glyph_char_inc;
    op->glyph_opaque = 0;
    op->back_color = state->glyph_back_color;
    op->color = state->glyph_fore_color;
    op->glyph_x = state->glyph_x == -32768 ? state->glyph_back_left : state->glyph_x;
    op->glyph_y = state->glyph_y == -32768 ? state->glyph_back_top : state->glyph_y;
    if (state->glyph_op_bottom == -32768)
    {
        uint8_t special = (uint8_t)(state->glyph_op_top & 0x0f);

        if (special & 0x01u)
            state->glyph_op_bottom = state->glyph_back_bottom;
        if (special & 0x02u)
            state->glyph_op_right = state->glyph_back_right;
        if (special & 0x04u)
            state->glyph_op_top = state->glyph_back_top;
        if (special & 0x08u)
            state->glyph_op_left = state->glyph_back_left;
    }
    if (state->glyph_op_left == 0)
        state->glyph_op_left = state->glyph_back_left;
    if (state->glyph_op_right == 0)
        state->glyph_op_right = state->glyph_back_right;
    rdp_gdi_render_rect_from_edges(state->glyph_op_left,
                                   state->glyph_op_top,
                                   state->glyph_op_right,
                                   state->glyph_op_bottom,
                                   &op->rect);
    rdp_gdi_render_rect_from_edges(state->glyph_back_left,
                                   state->glyph_back_top,
                                   state->glyph_back_right,
                                   state->glyph_back_bottom,
                                   &op->glyph_back_rect);
    if (inline_glyph)
        return rdp_gdi_render_decode_inline_glyph(op);
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
    state->line_rop2 = 13u;
    state->line_pen_width = 1u;
    state->polyline_rop2 = 13u;
    state->polygon_rop2 = 13u;
    state->polygon_fill_mode = 1u;
    state->ellipse_rop2 = 13u;
    state->ellipse_fill_mode = 1u;
    state->multi_dst_rop = 0x00u;
    state->multi_scr_rop = 0xccu;
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
        case RDP_GDI_ORDER_MEMBLT:
            status = rdp_gdi_render_decode_memblt(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_MEM3BLT:
            status = rdp_gdi_render_decode_mem3blt(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_DRAWNINEGRID:
            status = rdp_gdi_render_decode_draw_ninegrid(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_MULTI_DRAWNINEGRID:
            status = rdp_gdi_render_decode_multi_draw_ninegrid(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_MULTIDSTBLT:
            status = rdp_gdi_render_decode_multi_dstblt(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_MULTISCRBLT:
            status = rdp_gdi_render_decode_multi_scrblt(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_MULTIPATBLT:
            status = rdp_gdi_render_decode_multi_patblt(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_MULTIOPAQUERECT:
            status = rdp_gdi_render_decode_multi_opaque_rect(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_LINETO:
            status = rdp_gdi_render_decode_line(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_POLYLINE:
            status = rdp_gdi_render_decode_polyline(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_POLYGON_SC:
            status = rdp_gdi_render_decode_polygon_sc(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_POLYGON_CB:
            status = rdp_gdi_render_decode_polygon_cb(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_ELLIPSE_SC:
            status = rdp_gdi_render_decode_ellipse_sc(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_ELLIPSE_CB:
            status = rdp_gdi_render_decode_ellipse_cb(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_OPAQUERECT:
            status = rdp_gdi_render_decode_opaque_rect(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_SCRBLT:
            status = rdp_gdi_render_decode_scrblt(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_SAVEBITMAP:
            status = rdp_gdi_render_decode_save_bitmap(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_GLYPH_INDEX:
            status = rdp_gdi_render_decode_glyph_index(&stream, field_flags, delta, state, op);
            break;
        case RDP_GDI_ORDER_FAST_INDEX:
            status = rdp_gdi_render_decode_fast_glyph_common(&stream, field_flags, delta, state, op, 0);
            break;
        case RDP_GDI_ORDER_FAST_GLYPH:
            status = rdp_gdi_render_decode_fast_glyph_common(&stream, field_flags, delta, state, op, 1);
            break;
        default:
            status = LIBRDP_STATUS_UNSUPPORTED;
            break;
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    if ((op->kind == RDP_GDI_RENDER_OP_DSTBLT || op->kind == RDP_GDI_RENDER_OP_SCRBLT ||
         op->kind == RDP_GDI_RENDER_OP_PATBLT || op->kind == RDP_GDI_RENDER_OP_OPAQUE_RECT ||
         op->kind == RDP_GDI_RENDER_OP_ELLIPSE_SC || op->kind == RDP_GDI_RENDER_OP_ELLIPSE_CB ||
         op->kind == RDP_GDI_RENDER_OP_MULTIDSTBLT ||
         op->kind == RDP_GDI_RENDER_OP_MULTIPATBLT || op->kind == RDP_GDI_RENDER_OP_MULTISCRBLT ||
         op->kind == RDP_GDI_RENDER_OP_MULTIOPAQUE_RECT ||
         op->kind == RDP_GDI_RENDER_OP_SAVE_BITMAP) &&
        (op->rect.width < 0 || op->rect.height < 0))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    state->current_order_type = order_type;
    *consumed = stream.position;
    return LIBRDP_STATUS_OK;
}
