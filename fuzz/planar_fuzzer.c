/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for planar bitmap decoder and RLE plane paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "graphics/planar.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises planar bitmap decoder and RLE plane paths with one
 * arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_buffer pixels;
    size_t stride = 0;
    uint32_t width = size > 0 ? (uint32_t)(data[0] % 32u) + 1u : 1u;
    uint32_t height = size > 1 ? (uint32_t)(data[1] % 32u) + 1u : 1u;

    rdp_buffer_init(&pixels);
    (void)rdp_planar_decode_argb(data, size, width, height, &pixels, &stride);
    rdp_buffer_free(&pixels);
    return 0;
}
