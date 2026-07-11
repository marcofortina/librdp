/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "graphics/nscodec.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_nscodec_context context;
    rdp_nscodec_stream stream;
    rdp_nscodec_capability capability;
    rdp_buffer pixels;
    size_t stride = 0;
    uint32_t width = size > 0 ? (uint32_t)(data[0] % 32u) + 1u : 1u;
    uint32_t height = size > 1 ? (uint32_t)(data[1] % 32u) + 1u : 1u;
    uint8_t plane[64];

    rdp_nscodec_context_init(&context);
    rdp_buffer_init(&pixels);
    (void)rdp_nscodec_parse_capability(data, size, &capability);
    (void)rdp_nscodec_parse_stream(data, size, width, height, &stream);
    (void)rdp_nscodec_decode_rle_plane(data, size, plane, sizeof(plane));
    (void)rdp_nscodec_decode_bgra32(&context, data, size, width, height, &pixels, &stride);
    rdp_buffer_free(&pixels);
    rdp_nscodec_context_free(&context);
    return 0;
}
