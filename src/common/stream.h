/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef RDP_COMMON_STREAM_H
#define RDP_COMMON_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

typedef struct rdp_stream
{
    const uint8_t* data;
    size_t length;
    size_t position;
} rdp_stream;

void rdp_stream_init(rdp_stream* stream, const void* data, size_t length);
size_t rdp_stream_remaining(const rdp_stream* stream);
librdp_status rdp_stream_read_u8(rdp_stream* stream, uint8_t* value);
librdp_status rdp_stream_read_u16_le(rdp_stream* stream, uint16_t* value);
librdp_status rdp_stream_read_u16_be(rdp_stream* stream, uint16_t* value);
librdp_status rdp_stream_read_u32_le(rdp_stream* stream, uint32_t* value);
librdp_status rdp_stream_read_u32_be(rdp_stream* stream, uint32_t* value);
librdp_status rdp_stream_read_bytes(rdp_stream* stream, const uint8_t** data, size_t length);
librdp_status rdp_stream_skip(rdp_stream* stream, size_t length);

#endif
