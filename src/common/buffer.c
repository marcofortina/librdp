/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: growable byte buffer utilities shared by protocol encoders and
 * channel writers.
 * Invariants: publicly observable state is updated only after local validation
 * succeeds.
 * Ownership: buffer capacity, length, and ownership stay synchronized before
 * data is exposed to callers.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: external input is treated as untrusted until validated by
 * this module or its caller.
 */


#include "common/buffer.h"

#include <stdlib.h>
#include <string.h>

void rdp_buffer_init(rdp_buffer* buffer)
{
    if (!buffer)
        return;
    buffer->data = NULL;
    buffer->length = 0;
    buffer->capacity = 0;
}

void rdp_buffer_free(rdp_buffer* buffer)
{
    if (!buffer)
        return;
    free(buffer->data);
    buffer->data = NULL;
    buffer->length = 0;
    buffer->capacity = 0;
}

librdp_status rdp_buffer_reserve(rdp_buffer* buffer, size_t capacity)
{
    uint8_t* resized = NULL;
    size_t next = 0;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (capacity <= buffer->capacity)
        return LIBRDP_STATUS_OK;

    next = buffer->capacity ? buffer->capacity : 64;
    while (next < capacity)
    {
        if (next > ((size_t)-1) / 2)
            return LIBRDP_STATUS_NO_MEMORY;
        next *= 2;
    }

    resized = (uint8_t*)realloc(buffer->data, next);
    if (!resized)
        return LIBRDP_STATUS_NO_MEMORY;

    buffer->data = resized;
    buffer->capacity = next;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_buffer_append(rdp_buffer* buffer, const void* data, size_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length > ((size_t)-1) - buffer->length)
        return LIBRDP_STATUS_NO_MEMORY;

    status = rdp_buffer_reserve(buffer, buffer->length + length);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (length > 0)
        memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_buffer_append_u8(rdp_buffer* buffer, uint8_t value)
{
    return rdp_buffer_append(buffer, &value, 1);
}

librdp_status rdp_buffer_append_u16_le(rdp_buffer* buffer, uint16_t value)
{
    uint8_t bytes[2];
    bytes[0] = (uint8_t)(value & 0xffu);
    bytes[1] = (uint8_t)((value >> 8) & 0xffu);
    return rdp_buffer_append(buffer, bytes, sizeof(bytes));
}

librdp_status rdp_buffer_append_u16_be(rdp_buffer* buffer, uint16_t value)
{
    uint8_t bytes[2];
    bytes[0] = (uint8_t)((value >> 8) & 0xffu);
    bytes[1] = (uint8_t)(value & 0xffu);
    return rdp_buffer_append(buffer, bytes, sizeof(bytes));
}

librdp_status rdp_buffer_append_u32_le(rdp_buffer* buffer, uint32_t value)
{
    uint8_t bytes[4];
    bytes[0] = (uint8_t)(value & 0xffu);
    bytes[1] = (uint8_t)((value >> 8) & 0xffu);
    bytes[2] = (uint8_t)((value >> 16) & 0xffu);
    bytes[3] = (uint8_t)((value >> 24) & 0xffu);
    return rdp_buffer_append(buffer, bytes, sizeof(bytes));
}

librdp_status rdp_buffer_append_u32_be(rdp_buffer* buffer, uint32_t value)
{
    uint8_t bytes[4];
    bytes[0] = (uint8_t)((value >> 24) & 0xffu);
    bytes[1] = (uint8_t)((value >> 16) & 0xffu);
    bytes[2] = (uint8_t)((value >> 8) & 0xffu);
    bytes[3] = (uint8_t)(value & 0xffu);
    return rdp_buffer_append(buffer, bytes, sizeof(bytes));
}

librdp_status rdp_buffer_consume(rdp_buffer* buffer, size_t length)
{
    if (!buffer || length > buffer->length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length > 0)
        memmove(buffer->data, buffer->data + length, buffer->length - length);
    buffer->length -= length;
    return LIBRDP_STATUS_OK;
}
