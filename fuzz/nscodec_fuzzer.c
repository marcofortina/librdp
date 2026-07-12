/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for NSCodec planar bitmap parser and decoder paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "graphics/nscodec.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises NSCodec planar bitmap parser and decoder paths with
 * one arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
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
