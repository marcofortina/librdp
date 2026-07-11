/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef RDP_COMMON_BUFFER_H
#define RDP_COMMON_BUFFER_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

typedef struct rdp_buffer
{
    uint8_t* data;
    size_t length;
    size_t capacity;
} rdp_buffer;

void rdp_buffer_init(rdp_buffer* buffer);
void rdp_buffer_free(rdp_buffer* buffer);
librdp_status rdp_buffer_reserve(rdp_buffer* buffer, size_t capacity);
librdp_status rdp_buffer_append(rdp_buffer* buffer, const void* data, size_t length);
librdp_status rdp_buffer_append_u8(rdp_buffer* buffer, uint8_t value);
librdp_status rdp_buffer_append_u16_le(rdp_buffer* buffer, uint16_t value);
librdp_status rdp_buffer_append_u16_be(rdp_buffer* buffer, uint16_t value);
librdp_status rdp_buffer_append_u32_le(rdp_buffer* buffer, uint32_t value);
librdp_status rdp_buffer_append_u32_be(rdp_buffer* buffer, uint32_t value);
librdp_status rdp_buffer_consume(rdp_buffer* buffer, size_t length);

#endif
