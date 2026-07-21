/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: geometry tracking virtual-channel parser and serializer.
 * Invariants: the wire length excludes the trailing reserved byte, update
 * payloads contain complete region records, and clear payloads retain the
 * fixed wire footprint.
 * Ownership: parsed geometry and rectangle bytes borrow the input buffer;
 * callers copy data before retaining it.
 * Threading: no mutable global state is used.
 * Trust boundary: length, count, and signed coordinates are validated before
 * session state can consume a mapping.
 */

#include "channels/geometry_tracking.h"

#include "common/stream.h"

#include <limits.h>
#include <string.h>

static librdp_status rdp_geometry_tracking_read_u64(rdp_stream* stream,
                                                    uint64_t* value)
{
    uint32_t low = 0;
    uint32_t high = 0;

    if (!stream || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u32_le(stream, &low) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &high) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = ((uint64_t)high << 32u) | low;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_geometry_tracking_write_u64(rdp_buffer* buffer,
                                                     uint64_t value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, (uint32_t)value);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, (uint32_t)(value >> 32u));
    return status;
}

static int32_t rdp_geometry_tracking_decode_i32(uint32_t value)
{
    if (value <= (uint32_t)INT32_MAX)
        return (int32_t)value;
    return -((int32_t)(UINT32_MAX - value)) - 1;
}

static uint32_t rdp_geometry_tracking_encode_i32(int32_t value)
{
    if (value >= 0)
        return (uint32_t)value;
    return UINT32_MAX - (uint32_t)(-(value + 1));
}

static librdp_status rdp_geometry_tracking_read_rect(
    rdp_stream* stream,
    rdp_geometry_tracking_rect* rect)
{
    uint32_t values[4];

    if (!stream || !rect)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (size_t i = 0; i < 4u; i++)
    {
        if (rdp_stream_read_u32_le(stream, &values[i]) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    rect->left = rdp_geometry_tracking_decode_i32(values[0]);
    rect->top = rdp_geometry_tracking_decode_i32(values[1]);
    rect->right = rdp_geometry_tracking_decode_i32(values[2]);
    rect->bottom = rdp_geometry_tracking_decode_i32(values[3]);
    if (rect->right < rect->left || rect->bottom < rect->top)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_geometry_tracking_write_rect(
    rdp_buffer* buffer,
    const rdp_geometry_tracking_rect* rect)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rect || rect->right < rect->left ||
        rect->bottom < rect->top)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(
        buffer,
        rdp_geometry_tracking_encode_i32(rect->left));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(
            buffer,
            rdp_geometry_tracking_encode_i32(rect->top));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(
            buffer,
            rdp_geometry_tracking_encode_i32(rect->right));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(
            buffer,
            rdp_geometry_tracking_encode_i32(rect->bottom));
    return status;
}

/*
 * Parse the fixed mapping header and, for update messages, the nested region
 * header. The reserved trailer is present on the wire but excluded from the
 * protocol length field.
 */
librdp_status rdp_geometry_tracking_parse(const void* data,
                                          size_t length,
                                          rdp_geometry_tracking_packet* packet)
{
    rdp_geometry_tracking_packet parsed;
    rdp_stream stream;
    const uint8_t* ignored = NULL;
    const uint8_t* reserved = NULL;
    size_t expected_region_bytes = 0;

    if (!data || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_GEOMETRY_TRACKING_FIXED_SIZE + 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &parsed.declared_length) !=
            LIBRDP_STATUS_OK ||
        parsed.declared_length < RDP_GEOMETRY_TRACKING_FIXED_SIZE ||
        (size_t)parsed.declared_length + 1u != length ||
        rdp_stream_read_u32_le(&stream, &parsed.version) !=
            LIBRDP_STATUS_OK ||
        rdp_geometry_tracking_read_u64(&stream, &parsed.mapping_id) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.update_type) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.version != RDP_GEOMETRY_TRACKING_VERSION_1 ||
        (parsed.update_type != RDP_GEOMETRY_TRACKING_UPDATE &&
         parsed.update_type != RDP_GEOMETRY_TRACKING_CLEAR))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.update_type == RDP_GEOMETRY_TRACKING_CLEAR)
    {
        if (parsed.declared_length != RDP_GEOMETRY_TRACKING_FIXED_SIZE ||
            rdp_stream_read_bytes(
                &stream,
                &ignored,
                RDP_GEOMETRY_TRACKING_FIXED_SIZE - 20u) !=
                LIBRDP_STATUS_OK ||
            rdp_stream_read_bytes(&stream, &reserved, 1u) !=
                LIBRDP_STATUS_OK ||
            rdp_stream_remaining(&stream) != 0u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *packet = parsed;
        return LIBRDP_STATUS_OK;
    }
    if (rdp_stream_read_u32_le(&stream, &parsed.flags) != LIBRDP_STATUS_OK ||
        parsed.flags != 0 ||
        rdp_geometry_tracking_read_u64(&stream, &parsed.top_level_id) !=
            LIBRDP_STATUS_OK ||
        rdp_geometry_tracking_read_rect(&stream, &parsed.local_bounds) !=
            LIBRDP_STATUS_OK ||
        rdp_geometry_tracking_read_rect(&stream, &parsed.top_level_bounds) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.geometry_type) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.geometry_buffer_len) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((size_t)RDP_GEOMETRY_TRACKING_FIXED_SIZE +
            parsed.geometry_buffer_len !=
        parsed.declared_length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream,
                              &parsed.geometry_buffer,
                              parsed.geometry_buffer_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &reserved, 1u) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (parsed.geometry_type != RDP_GEOMETRY_TRACKING_TYPE_REGION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.geometry_buffer_len < RDP_GEOMETRY_TRACKING_REGION_HEADER_SIZE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream,
                    parsed.geometry_buffer,
                    parsed.geometry_buffer_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.region_header_size) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.region_type) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.rect_count) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.region_data_size) !=
            LIBRDP_STATUS_OK ||
        rdp_geometry_tracking_read_rect(&stream, &parsed.region_bounds) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.region_header_size != RDP_GEOMETRY_TRACKING_REGION_HEADER_SIZE ||
        parsed.region_type != RDP_GEOMETRY_TRACKING_REGION_TYPE_RECTANGLES ||
        parsed.rect_count >
            (UINT32_MAX - RDP_GEOMETRY_TRACKING_REGION_HEADER_SIZE) / 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    expected_region_bytes =
        RDP_GEOMETRY_TRACKING_REGION_HEADER_SIZE +
        ((size_t)parsed.rect_count * 16u);
    if (expected_region_bytes != parsed.geometry_buffer_len ||
        (parsed.region_data_size != 0 &&
         parsed.region_data_size != (uint32_t)(parsed.rect_count * 16u)) ||
        rdp_stream_read_bytes(&stream,
                              &parsed.rect_data,
                              (size_t)parsed.rect_count * 16u) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (uint32_t i = 0; i < parsed.rect_count; i++)
    {
        rdp_geometry_tracking_rect rect;

        if (rdp_geometry_tracking_get_rect(&parsed, i, &rect) !=
            LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    *packet = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_geometry_tracking_get_rect(
    const rdp_geometry_tracking_packet* packet,
    uint32_t index,
    rdp_geometry_tracking_rect* rect)
{
    rdp_stream stream;

    if (!packet || !rect)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (index >= packet->rect_count || !packet->rect_data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream,
                    packet->rect_data + ((size_t)index * 16u),
                    16u);
    return rdp_geometry_tracking_read_rect(&stream, rect);
}

static librdp_status rdp_geometry_tracking_write_fixed(
    rdp_buffer* buffer,
    uint32_t declared_length,
    uint64_t mapping_id,
    uint32_t update_type,
    uint64_t top_level_id,
    const rdp_geometry_tracking_rect* local_bounds,
    const rdp_geometry_tracking_rect* top_level_bounds,
    uint32_t geometry_type,
    uint32_t geometry_buffer_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, declared_length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(
            buffer,
            RDP_GEOMETRY_TRACKING_VERSION_1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_geometry_tracking_write_u64(buffer, mapping_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, update_type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_geometry_tracking_write_u64(buffer, top_level_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_geometry_tracking_write_rect(buffer, local_bounds);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_geometry_tracking_write_rect(buffer, top_level_bounds);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, geometry_type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, geometry_buffer_len);
    return status;
}

librdp_status rdp_geometry_tracking_write_update(
    rdp_buffer* buffer,
    uint64_t mapping_id,
    uint64_t top_level_id,
    const rdp_geometry_tracking_rect* local_bounds,
    const rdp_geometry_tracking_rect* top_level_bounds,
    const rdp_geometry_tracking_rect* region_bounds,
    const rdp_geometry_tracking_rect* rects,
    uint32_t rect_count)
{
    uint32_t geometry_buffer_len = 0;
    uint32_t declared_length = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !local_bounds || !top_level_bounds || !region_bounds ||
        (rect_count > 0 && !rects) ||
        rect_count >
            (UINT32_MAX - RDP_GEOMETRY_TRACKING_REGION_HEADER_SIZE) / 16u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    geometry_buffer_len =
        RDP_GEOMETRY_TRACKING_REGION_HEADER_SIZE + (rect_count * 16u);
    declared_length =
        RDP_GEOMETRY_TRACKING_FIXED_SIZE + geometry_buffer_len;
    status = rdp_geometry_tracking_write_fixed(
        buffer,
        declared_length,
        mapping_id,
        RDP_GEOMETRY_TRACKING_UPDATE,
        top_level_id,
        local_bounds,
        top_level_bounds,
        RDP_GEOMETRY_TRACKING_TYPE_REGION,
        geometry_buffer_len);
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_buffer_append_u32_le(
            buffer,
            RDP_GEOMETRY_TRACKING_REGION_HEADER_SIZE);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(
            buffer,
            RDP_GEOMETRY_TRACKING_REGION_TYPE_RECTANGLES);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, rect_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, rect_count * 16u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_geometry_tracking_write_rect(buffer, region_bounds);
    for (uint32_t i = 0; status == LIBRDP_STATUS_OK && i < rect_count; i++)
        status = rdp_geometry_tracking_write_rect(buffer, &rects[i]);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0u);
    return status;
}

librdp_status rdp_geometry_tracking_write_clear(rdp_buffer* buffer,
                                                uint64_t mapping_id)
{
    static const rdp_geometry_tracking_rect empty_rect = {0, 0, 0, 0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_geometry_tracking_write_fixed(
        buffer,
        RDP_GEOMETRY_TRACKING_FIXED_SIZE,
        mapping_id,
        RDP_GEOMETRY_TRACKING_CLEAR,
        0,
        &empty_rect,
        &empty_rect,
        0,
        0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0u);
    return status;
}
