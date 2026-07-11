/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "common/stream.h"

void rdp_stream_init(rdp_stream* stream, const void* data, size_t length)
{
    if (!stream)
        return;
    stream->data = (const uint8_t*)data;
    stream->length = data ? length : 0;
    stream->position = 0;
}

size_t rdp_stream_remaining(const rdp_stream* stream)
{
    if (!stream || stream->position > stream->length)
        return 0;
    return stream->length - stream->position;
}

librdp_status rdp_stream_read_u8(rdp_stream* stream, uint8_t* value)
{
    if (!stream || !value || rdp_stream_remaining(stream) < 1)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = stream->data[stream->position++];
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_stream_read_u16_le(rdp_stream* stream, uint16_t* value)
{
    const uint8_t* p = NULL;
    if (rdp_stream_read_bytes(stream, &p, 2) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_stream_read_u16_be(rdp_stream* stream, uint16_t* value)
{
    const uint8_t* p = NULL;
    if (rdp_stream_read_bytes(stream, &p, 2) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_stream_read_u32_le(rdp_stream* stream, uint32_t* value)
{
    const uint8_t* p = NULL;
    if (rdp_stream_read_bytes(stream, &p, 4) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_stream_read_u32_be(rdp_stream* stream, uint32_t* value)
{
    const uint8_t* p = NULL;
    if (rdp_stream_read_bytes(stream, &p, 4) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_stream_read_bytes(rdp_stream* stream, const uint8_t** data, size_t length)
{
    if (!stream || !data || rdp_stream_remaining(stream) < length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *data = stream->data + stream->position;
    stream->position += length;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_stream_skip(rdp_stream* stream, size_t length)
{
    if (!stream || rdp_stream_remaining(stream) < length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    stream->position += length;
    return LIBRDP_STATUS_OK;
}
