/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for stream reader/writer bounds and endian helper paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "common/stream.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises stream reader/writer bounds and endian helper paths
 * with one arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
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
