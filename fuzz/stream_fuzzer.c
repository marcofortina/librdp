/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "common/stream.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_stream stream;
    const uint8_t* bytes = NULL;
    uint8_t u8 = 0;
    uint16_t u16 = 0;
    uint32_t u32 = 0;
    size_t skip = size > 0 ? data[0] : 0;
    size_t read_len = size > 1 ? data[1] : 0;

    rdp_stream_init(&stream, data, size);
    (void)rdp_stream_remaining(&stream);
    (void)rdp_stream_read_u8(&stream, &u8);
    (void)rdp_stream_read_u16_le(&stream, &u16);
    (void)rdp_stream_read_u16_be(&stream, &u16);
    (void)rdp_stream_read_u32_le(&stream, &u32);
    (void)rdp_stream_read_u32_be(&stream, &u32);
    (void)rdp_stream_read_bytes(&stream, &bytes, read_len);
    (void)rdp_stream_skip(&stream, skip);

    rdp_stream_init(&stream, NULL, size);
    (void)rdp_stream_remaining(&stream);
    return 0;
}
