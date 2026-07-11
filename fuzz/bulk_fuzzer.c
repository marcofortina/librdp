/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "protocol/bulk.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static const uint8_t bulk_types[] = {
        RDP_BULK_TYPE_8K,
        RDP_BULK_TYPE_64K,
        RDP_BULK_TYPE_RDP6,
        RDP_BULK_TYPE_RDP61
    };
    rdp_bulk_decompressor decompressor;
    rdp_buffer decoded;
    size_t payload_len = size > 4096u ? 4096u : size;
    size_t i = 0;

    rdp_bulk_decompressor_init(&decompressor);
    rdp_buffer_init(&decoded);

    if (payload_len > 0)
    {
        uint8_t flags = (uint8_t)(data[0] & (RDP_BULK_TYPE_MASK | RDP_BULK_FLAGS_MASK));

        (void)rdp_bulk_decompress(&decompressor, flags, data + 1u, payload_len - 1u, &decoded);
        rdp_bulk_decompressor_reset(&decompressor);
        decoded.length = 0;
    }

    for (i = 0; i < sizeof(bulk_types) / sizeof(bulk_types[0]); i++)
    {
        uint8_t flags = (uint8_t)(bulk_types[i] | RDP_BULK_PACKET_COMPRESSED |
                                  RDP_BULK_PACKET_FLUSHED);

        (void)rdp_bulk_decompress(&decompressor, flags, data, payload_len, &decoded);
        rdp_bulk_decompressor_reset(&decompressor);
        decoded.length = 0;
        (void)rdp_bulk_decompress(&decompressor, bulk_types[i], data, payload_len, &decoded);
        rdp_bulk_decompressor_reset(&decompressor);
        decoded.length = 0;
    }

    rdp_buffer_free(&decoded);
    rdp_bulk_decompressor_free(&decompressor);
    return 0;
}
