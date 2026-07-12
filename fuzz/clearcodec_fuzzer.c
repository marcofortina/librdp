/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for ClearCodec bitmap and subcodec decoder paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "graphics/clearcodec.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises ClearCodec bitmap and subcodec decoder paths with one
 * arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_clearcodec_stream stream;
    rdp_clearcodec_composite_payload payload;
    rdp_clearcodec_subcodec subcodec;
    rdp_clearcodec_context context;
    rdp_buffer pixels;
    size_t stride = 0;
    uint16_t width = (uint16_t)((size % 64u) + 1u);
    uint16_t height = (uint16_t)(((size / 64u) % 64u) + 1u);

    rdp_clearcodec_context_init(&context);
    rdp_buffer_init(&pixels);
    (void)rdp_clearcodec_parse_stream(data, size, &stream);
    (void)rdp_clearcodec_parse_composite_payload(data, size, &payload);
    (void)rdp_clearcodec_parse_subcodec(data, size, &subcodec);
    (void)rdp_clearcodec_decode_bitmap(&context, data, size, width, height, &pixels, &stride);
    rdp_buffer_free(&pixels);
    rdp_clearcodec_context_free(&context);
    return 0;
}
