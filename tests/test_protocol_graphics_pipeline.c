/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: focused protocol conformance suite.
 * Coverage: graphics-pipeline, AVC, progressive, surface, cache, and ClearCodec conformance vectors.
 * Bug classes: capability gating, surface bounds, codec state, cache lifetime, frame atomicity, and malformed payloads.
 * Determinism: all vectors and state are synthetic and remain local to this suite.
 */

#include "channels/graphics_pipeline.h"
#include "common/buffer.h"
#include "graphics/avc.h"
#include "graphics/clearcodec.h"
#include "graphics/nscodec.h"

#include <librdp/session.h>

#include <stdio.h>
#include <string.h>

#define PCHECK(expr)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

static uint16_t test_read_u16_le(const uint8_t* data)
{
    return (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
}
static uint32_t test_read_u32_le(const uint8_t* data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

/*
 * Runs graphics-pipeline, AVC, progressive, surface, cache, and ClearCodec conformance vectors.
 */
int test_protocol_graphics_pipeline_vectors(void)
{
    const uint8_t graphics_confirm[] = {
        0x13, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x08, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_bad_capset[] = {
        0x01, 0x00, 0x01, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_capset_v107[] = {
        0x01, 0x07, 0x0a, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_capset_unknown_flags[] = {
        0x02, 0x00, 0x0a, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00
    };
    const uint8_t graphics_capset_conflicting_avc[] = {
        0x02, 0x00, 0x0a, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x30, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_capset_trailing[] = {
        0x02, 0x00, 0x0a, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0xef, 0xbe, 0xad, 0xde
    };
    const uint8_t graphics_confirm_trailing_capset[] = {
        0x13, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x08, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0xef, 0xbe, 0xad, 0xde
    };
    const uint8_t graphics_segment_single[] = {
        0xe0, 0x04,
        0x13, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x08, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_segment_multipart[] = {
        0xe1, 0x02, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x04,
        0x13, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00,
        0x0d, 0x00, 0x00, 0x00, 0x04,
        0x04, 0x00, 0x08, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_segment_compressed_literal[] = {0xe0, 0x24, 0x24, 0x80, 0x07};
    const uint8_t graphics_segment_bad_compression_type[] = {0xe0, 0x20, 1, 2, 3};
    const uint8_t graphics_segment_multipart_bad_second[] = {
        0xe1, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x04, 0x51,
        0x04, 0x00, 0x00, 0x00, 0x20, 1, 2, 3
    };
    const uint8_t graphics_create_surface[] = {
        0x09, 0x00, 0x00, 0x00,
        0x0f, 0x00, 0x00, 0x00,
        0x34, 0x12, 0x00, 0x04,
        0x00, 0x03, 0x20
    };
    const uint8_t graphics_delete_surface[] = {
        0x0a, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00,
        0x34, 0x12
    };
    const uint8_t graphics_map_output[] = {
        0x0f, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00,
        0x34, 0x12, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_scaled_map_output[] = {
        0x17, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x00, 0x00,
        0x34, 0x12, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00,
        0x00, 0x03, 0x00, 0x00
    };
    const uint8_t graphics_solid_fill[] = {
        0x04, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x11, 0x22, 0x33, 0xff,
        0x01, 0x00,
        0x01, 0x00, 0x02, 0x00,
        0x05, 0x00, 0x06, 0x00
    };
    const uint8_t graphics_bad_rect[] = {
        0x05, 0x00, 0x02, 0x00,
        0x01, 0x00, 0x06, 0x00
    };
    const uint8_t graphics_wire_to_surface_1[] = {
        0x01, 0x00, 0x00, 0x00,
        0x29, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x00, 0x00,
        0x20,
        0x01, 0x00, 0x02, 0x00,
        0x03, 0x00, 0x04, 0x00,
        0x10, 0x00, 0x00, 0x00,
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 11, 12,
        13, 14, 15, 16
    };
    const uint8_t graphics_wire_to_surface_1_alpha[] = {
        0x01, 0x00, 0x00, 0x00,
        0x21, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x0c, 0x00,
        0x21,
        0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x02, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x4c, 0x41, 0x00, 0x00,
        0x10, 0x20, 0x30, 0xff
    };
    const uint8_t graphics_wire_to_surface_2[] = {
        0x02, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x09, 0x00,
        0x44, 0x33, 0x22, 0x11,
        0x21,
        0x03, 0x00, 0x00, 0x00,
        0xaa, 0xbb, 0xcc
    };
    const uint8_t graphics_avc420_stream[] = {
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc420_bad_rect[] = {
        0x01, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc420_empty_bits[] = {
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64
    };
    const uint8_t graphics_avc420_bad_quant[] = {
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x34, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc444_both[] = {
        0x12, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x66
    };
    const uint8_t graphics_avc444_luma[] = {
        0x12, 0x00, 0x00, 0x40,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc444_chroma[] = {
        0x12, 0x00, 0x00, 0x80,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc444_invalid_lc[] = {
        0x12, 0x00, 0x00, 0xc0,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc444_bad_split[] = {
        0x05, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x66
    };
    const uint8_t graphics_avc_red_h264[] = {
        0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xc0, 0x0a,
        0xdd, 0xec, 0x04, 0x40, 0x00, 0x00, 0x03, 0x00,
        0x40, 0x00, 0x00, 0x03, 0x00, 0xa3, 0xc4, 0x89,
        0xe0, 0x00, 0x00, 0x00, 0x01, 0x68, 0xce, 0x0f,
        0xc8, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x3a,
        0x11, 0x8a, 0x00, 0x02, 0x18, 0xf1, 0xc0, 0x00,
        0x40, 0xf6, 0x38, 0x00, 0x08, 0x79, 0x60
    };
    const uint8_t graphics_avc_rect_full_16[] = {
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00
    };
    const uint8_t graphics_avc_rect_oob[] = {
        0x00, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x10, 0x00
    };
    const uint8_t graphics_avc_quant_quality[] = {0x45, 0x64};
    const uint8_t graphics_avc_quant_bad_qp[] = {0x34, 0x64};
    const uint8_t graphics_avc_quant_bad_quality[] = {0x45, 0x65};
    const uint8_t graphics_progressive_stream[] = {
        0xc3, 0xcc, 0x0a, 0x00, 0x00, 0x00,
        0x00, 0x40, 0x00, 0x01,
        0xc1, 0xcc, 0x0c, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00,
        0xc4, 0xcc, 0x48, 0x00, 0x00, 0x00,
        0x40,
        0x01, 0x00,
        0x01,
        0x01,
        0x01,
        0x01, 0x00,
        0x19, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x40, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55,
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
        0xc5, 0xcc, 0x19, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0xaa, 0xbb, 0xcc,
        0xc2, 0xcc, 0x06, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_progressive_sync[] = {
        0xc0, 0xcc, 0x0c, 0x00, 0x00, 0x00,
        0xca, 0xac, 0xcc, 0xca,
        0x00, 0x01
    };
    const uint8_t graphics_progressive_bad_sync[] = {
        0xc0, 0xcc, 0x0c, 0x00, 0x00, 0x00,
        0xca, 0xac, 0xcc, 0x00,
        0x00, 0x01
    };
    const uint8_t graphics_progressive_tile_first[] = {
        0xc6, 0xcc, 0x1a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
        0x01, 0x00,
        0x02, 0x00,
        0x01,
        0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x11, 0x22, 0x33
    };
    const uint8_t graphics_progressive_tile_upgrade[] = {
        0xc7, 0xcc, 0x20, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
        0x03, 0x00,
        0x04, 0x00,
        0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66
    };
    const uint8_t graphics_progressive_bad_block[] = {0xc3, 0xcc, 0x05, 0x00, 0x00, 0x00};
    const uint8_t graphics_progressive_empty_region[] = {
        0xc4, 0xcc, 0x1f, 0x00, 0x00, 0x00,
        0x40,
        0x01, 0x00,
        0x01,
        0x00,
        0x01,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x0d, 0x02, 0xd8, 0x02,
        0x40, 0x00, 0x20, 0x00,
        0x66, 0x76, 0x88, 0x99, 0xa9
    };
    const uint8_t graphics_progressive_bad_region[] = {
        0xc4, 0xcc, 0x17, 0x00, 0x00, 0x00,
        0x40,
        0x01, 0x00,
        0x01,
        0x00,
        0x00,
        0x02, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x40, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55
    };
    const uint8_t graphics_progressive_region_rect[] = {
        0x80, 0x02, 0x20, 0x01,
        0x40, 0x00, 0x20, 0x00
    };
    const uint8_t graphics_progressive_region_rect_overflow[] = {
        0xff, 0xff, 0x00, 0x00,
        0x02, 0x00, 0x01, 0x00
    };
    const uint8_t graphics_surface_to_surface[] = {
        0x05, 0x00, 0x00, 0x00,
        0x1e, 0x00, 0x00, 0x00,
        0x10, 0x00,
        0x20, 0x00,
        0x01, 0x00, 0x02, 0x00,
        0x05, 0x00, 0x06, 0x00,
        0x02, 0x00,
        0x07, 0x00, 0x08, 0x00,
        0x09, 0x00, 0x0a, 0x00
    };
    const uint8_t graphics_surface_to_cache[] = {
        0x06, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x08, 0x07, 0x06, 0x05,
        0x04, 0x03, 0x02, 0x01,
        0x42, 0x00,
        0x01, 0x00, 0x02, 0x00,
        0x05, 0x00, 0x06, 0x00
    };
    const uint8_t graphics_cache_to_surface[] = {
        0x07, 0x00, 0x00, 0x00,
        0x16, 0x00, 0x00, 0x00,
        0x42, 0x00,
        0x34, 0x12,
        0x02, 0x00,
        0x07, 0x00, 0x08, 0x00,
        0x09, 0x00, 0x0a, 0x00
    };
    const uint8_t graphics_evict_cache[] = {
        0x08, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00,
        0x42, 0x00
    };
    const uint8_t graphics_delete_context_pdu[] = {
        0x03, 0x00, 0x00, 0x00,
        0x0e, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x44, 0x33, 0x22, 0x11
    };
    const uint8_t clear_residual_bitmap[] = {
        0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04
    };
    const uint8_t clear_residual_zero_run_bitmap[] = {
        0x00, 0x06,
        0x08, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04
    };
    const uint8_t clear_raw_subcodec_bitmap[] = {
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x19, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x0c, 0x00, 0x00, 0x00,
        0x00,
        1, 2, 3,
        4, 5, 6,
        7, 8, 9,
        10, 11, 12
    };
    const uint8_t clear_rlex_subcodec_bitmap[] = {
        0x00, 0x07,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x0b, 0x00, 0x00, 0x00,
        0x02,
        0x02,
        1, 2, 3,
        4, 5, 6,
        0x03, 0x00,
        0x03, 0x00
    };
    const uint8_t clear_nsc_subcodec_bitmap[] = {
        0x00, 0x08,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x25, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x01,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01,
        0x00,
        0x00, 0x00,
        10, 0, 0, 0xff
    };
    const uint8_t clear_band_miss_bitmap[] = {
        0x04, 0x02,
        0x04, 0x00, 0x00, 0x00,
        0x13, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04,
        0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x00,
        0x0a, 0x14, 0x1e,
        0x00, 0x02,
        1, 2, 3,
        4, 5, 6
    };
    const uint8_t clear_band_hit_bitmap[] = {
        0x00, 0x03,
        0x04, 0x00, 0x00, 0x00,
        0x0d, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00,
        0x0a, 0x14, 0x1e,
        0x00, 0x80
    };
    const uint8_t clear_missing_band_bitmap[] = {
        0x00, 0x04,
        0x04, 0x00, 0x00, 0x00,
        0x0d, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00,
        0x0a, 0x14, 0x1e,
        0x0a, 0x80
    };
    const uint8_t clear_glyph_store_bitmap[] = {
        0x01, 0x05,
        0x02, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        9, 8, 7, 4
    };
    const uint8_t clear_glyph_hit[] = {
        0x03, 0x03,
        0x02, 0x00
    };
    const uint8_t clear_glyph_hit_after_reset[] = {
        0x07, 0x0d,
        0x02, 0x00
    };
    const uint8_t clear_missing_glyph_hit[] = {
        0x03, 0x0a,
        0x03, 0x00
    };
    const uint8_t clear_max_glyph_hit[] = {
        0x03, 0x0e,
        0x9f, 0x0f
    };
    const uint8_t clear_bad_glyph_hit[] = {
        0x03, 0x0f,
        0xa0, 0x0f
    };
    const uint8_t clear_empty_payload[] = {
        0x00, 0x0b
    };
    const uint8_t clear_unknown_subcodec_bitmap[] = {
        0x00, 0x0c,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x19, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x0c, 0x00, 0x00, 0x00,
        0xff,
        1, 2, 3,
        4, 5, 6,
        7, 8, 9,
        10, 11, 12
    };
    const uint8_t graphics_start_frame[] = {
        0x0b, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0x04, 0x03, 0x02, 0x01,
        0x44, 0x33, 0x22, 0x11
    };
    const uint8_t graphics_end_frame[] = {
        0x0c, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x00, 0x00,
        0x44, 0x33, 0x22, 0x11
    };
    rdp_graphics_header graphics_header;
    rdp_graphics_caps_confirm graphics_caps_confirm;
    rdp_graphics_capset graphics_capset;
    rdp_graphics_capset graphics_default_capsets[RDP_GRAPHICS_DEFAULT_CAPSET_LIMIT];
    uint32_t graphics_avc_runtime_support = 0;
    uint16_t graphics_default_capset_count = 0;
    uint16_t graphics_default_capset_index = 0;
    rdp_graphics_create_surface graphics_create;
    rdp_graphics_delete_surface graphics_delete;
    rdp_graphics_reset graphics_reset;
    rdp_graphics_map_surface_to_output graphics_map;
    rdp_graphics_map_surface_to_scaled_output graphics_scaled_map;
    rdp_graphics_point16 graphics_point;
    rdp_graphics_rect16 graphics_rect;
    rdp_graphics_rect16 graphics_zero_rect;
    rdp_graphics_solid_fill graphics_solid;
    rdp_graphics_wire_to_surface_1 graphics_wire1;
    rdp_graphics_wire_to_surface_2 graphics_wire2;
    rdp_graphics_surface_to_surface graphics_surface_copy;
    rdp_graphics_surface_to_cache graphics_surface_cache;
    rdp_graphics_cache_to_surface graphics_cache_surface;
    rdp_graphics_evict_cache_entry graphics_evict;
    rdp_graphics_delete_encoding_context graphics_delete_context;
    rdp_graphics_start_frame graphics_start;
    rdp_graphics_end_frame graphics_end;
    rdp_graphics_frame_ack graphics_ack;
    rdp_graphics_point16 graphics_points[2];
    rdp_graphics_decompressor graphics_decompressor;
    rdp_graphics_progressive_block graphics_progressive_block;
    rdp_graphics_progressive_context graphics_progressive_context;
    rdp_graphics_progressive_frame_begin graphics_progressive_frame_begin;
    rdp_graphics_progressive_region graphics_progressive_region;
    rdp_graphics_progressive_tile_simple graphics_progressive_simple;
    rdp_graphics_progressive_tile_first graphics_progressive_first;
    rdp_graphics_progressive_tile_upgrade graphics_progressive_upgrade;
    rdp_graphics_rect16 graphics_progressive_rect;
    rdp_graphics_progressive_stream graphics_progressive;
    rdp_graphics_avc420_quant_quality graphics_avc_quant;
    rdp_graphics_avc420_quant_quality graphics_bad_quant;
    rdp_graphics_avc420_metablock graphics_avc_meta;
    rdp_graphics_avc420_stream graphics_avc420;
    rdp_graphics_avc420_stream graphics_avc420_edge;
    rdp_graphics_avc444_stream graphics_avc444;
    rdp_graphics_avc444_stream graphics_avc444_edge;
    rdp_graphics_avc444_stream graphics_avc444_valid;
    librdp_status graphics_avc_status;
    rdp_avc_decoder* avc_decoder;
    rdp_avc_frame avc_frame;
    rdp_clearcodec_stream clear_stream;
    rdp_clearcodec_composite_payload clear_payload;
    rdp_clearcodec_subcodec clear_subcodec;
    rdp_clearcodec_context clear_context;
    rdp_buffer graphics_decoded;
    rdp_buffer graphics_reset_pdu;
    rdp_buffer clear_pixels;
    rdp_buffer dyn_response;
    uint8_t clear_saved[16];
    size_t decoded_stride = 0;
    size_t clear_saved_len = 0;

    rdp_graphics_decompressor_init(&graphics_decompressor);
    rdp_clearcodec_context_init(&clear_context);
    rdp_graphics_decompressor_reset(&graphics_decompressor);
    rdp_clearcodec_context_reset(&clear_context);
    rdp_buffer_init(&graphics_decoded);
    rdp_buffer_init(&graphics_reset_pdu);
    rdp_buffer_init(&clear_pixels);
    rdp_buffer_init(&dyn_response);

    PCHECK(RDP_GRAPHICS_BULK_MAX_DECODED == 64u * 1024u * 1024u);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_default_caps_advertise(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_default_capsets(graphics_default_capsets,
                                        (uint16_t)(sizeof(graphics_default_capsets) /
                                                   sizeof(graphics_default_capsets[0])),
                                        &graphics_default_capset_count) == LIBRDP_STATUS_OK);
    PCHECK((dyn_response.length == 70u && graphics_default_capset_count == 5u) ||
           (dyn_response.length == 46u && graphics_default_capset_count == 3u) ||
           (dyn_response.length == 34u && graphics_default_capset_count == 2u));
    for (graphics_default_capset_index = 0;
         graphics_default_capset_index < graphics_default_capset_count;
         graphics_default_capset_index++)
    {
        PCHECK(rdp_graphics_capset_is_default_supported(
                   &graphics_default_capsets[graphics_default_capset_index]) != 0);
    }
    graphics_capset = graphics_default_capsets[graphics_default_capset_count - 1u];
    graphics_capset.flags ^= RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED;
    PCHECK(rdp_graphics_capset_is_default_supported(&graphics_capset) == 0);
    graphics_capset = graphics_default_capsets[graphics_default_capset_count - 1u];
    graphics_capset.version = RDP_GRAPHICS_CAPVERSION_106_ERR;
    PCHECK(rdp_graphics_capset_is_default_supported(&graphics_capset) == 0);
    PCHECK(rdp_graphics_default_capsets(graphics_default_capsets,
                                        (uint16_t)(graphics_default_capset_count - 1u),
                                        &graphics_default_capset_count) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(dyn_response.length == 34 || dyn_response.length == 46 || dyn_response.length == 70);
    PCHECK(test_read_u16_le(dyn_response.data) == RDP_GRAPHICS_CMDID_CAPS_ADVERTISE);
    PCHECK(test_read_u32_le(dyn_response.data + 4) == dyn_response.length);
    PCHECK(test_read_u16_le(dyn_response.data + 8) ==
           (dyn_response.length == 70 ? 5 : (dyn_response.length == 46 ? 3 : 2)));
    PCHECK(rdp_graphics_parse_capset(dyn_response.data + 10, 12, &graphics_capset) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_8 &&
           (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0);
    {
        rdp_graphics_capset valid_capset = graphics_capset;

        PCHECK(rdp_graphics_parse_capset(graphics_bad_capset,
                                         sizeof(graphics_bad_capset),
                                         &graphics_capset) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_capset, &valid_capset, sizeof(graphics_capset)) == 0);
    }
    PCHECK(rdp_graphics_parse_capset(dyn_response.data + 22, 12, &graphics_capset) ==
           LIBRDP_STATUS_OK);
    if (dyn_response.length != 34)
    {
        PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_81 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_AVC420_ENABLED) != 0);
        PCHECK(rdp_graphics_parse_capset(dyn_response.data + 34, 12, &graphics_capset) ==
               LIBRDP_STATUS_OK);
        PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_10 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) == 0);
        if (dyn_response.length == 70)
        {
            PCHECK(rdp_graphics_parse_capset(dyn_response.data + 46, 12, &graphics_capset) ==
                   LIBRDP_STATUS_OK);
            PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_106 &&
                   (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0 &&
                   (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) == 0);
            PCHECK(rdp_graphics_parse_capset(dyn_response.data + 58, 12, &graphics_capset) ==
                   LIBRDP_STATUS_OK);
            PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_107 &&
                   (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0 &&
                   (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) == 0);
        }
    }
    else
    {
        PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_10 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) != 0);
    }
    PCHECK(rdp_graphics_default_capsets_for_avc(graphics_default_capsets,
                                                (uint16_t)(sizeof(graphics_default_capsets) /
                                                           sizeof(graphics_default_capsets[0])),
                                                &graphics_default_capset_count,
                                                0) == LIBRDP_STATUS_OK);
    PCHECK(graphics_default_capset_count == 2);
    PCHECK(graphics_default_capsets[1].version == RDP_GRAPHICS_CAPVERSION_10 &&
           (graphics_default_capsets[1].flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) != 0);
    PCHECK(rdp_graphics_capset_is_supported_for_avc(&graphics_default_capsets[1], 0) != 0);
    PCHECK(rdp_graphics_default_capsets_for_avc(graphics_default_capsets,
                                                (uint16_t)(sizeof(graphics_default_capsets) /
                                                           sizeof(graphics_default_capsets[0])),
                                                &graphics_default_capset_count,
                                                RDP_GRAPHICS_AVC_SUPPORT_AVC420) == LIBRDP_STATUS_OK);
    PCHECK(graphics_default_capset_count == 3);
    PCHECK(graphics_default_capsets[1].version == RDP_GRAPHICS_CAPVERSION_81 &&
           (graphics_default_capsets[1].flags & RDP_GRAPHICS_CAPS_FLAG_AVC420_ENABLED) != 0);
    PCHECK(graphics_default_capsets[2].version == RDP_GRAPHICS_CAPVERSION_10 &&
           (graphics_default_capsets[2].flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) != 0);
    PCHECK(rdp_graphics_capset_is_supported_for_avc(&graphics_default_capsets[2],
                                                    RDP_GRAPHICS_AVC_SUPPORT_AVC420) != 0);
    graphics_capset = graphics_default_capsets[1];
    PCHECK(rdp_graphics_capset_is_supported_for_avc(&graphics_capset, 0) == 0);
    PCHECK(rdp_graphics_default_capsets_for_avc(graphics_default_capsets,
                                                (uint16_t)(sizeof(graphics_default_capsets) /
                                                           sizeof(graphics_default_capsets[0])),
                                                &graphics_default_capset_count,
                                                RDP_GRAPHICS_AVC_SUPPORT_AVC420 |
                                                    RDP_GRAPHICS_AVC_SUPPORT_AVC444) == LIBRDP_STATUS_OK);
    PCHECK(graphics_default_capset_count == 4 &&
           graphics_default_capsets[3].version == RDP_GRAPHICS_CAPVERSION_106);
    graphics_capset.version = RDP_GRAPHICS_CAPVERSION_107;
    graphics_capset.flags = RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE;
    PCHECK(rdp_graphics_capset_is_supported_for_avc(&graphics_capset,
                                                    RDP_GRAPHICS_AVC_SUPPORT_AVC420 |
                                                        RDP_GRAPHICS_AVC_SUPPORT_AVC444) == 0);
    PCHECK(rdp_graphics_default_capsets_for_avc(graphics_default_capsets,
                                                (uint16_t)(sizeof(graphics_default_capsets) /
                                                           sizeof(graphics_default_capsets[0])),
                                                &graphics_default_capset_count,
                                                RDP_GRAPHICS_AVC_SUPPORT_ALL) == LIBRDP_STATUS_OK);
    PCHECK(graphics_default_capset_count == 5 &&
           graphics_default_capsets[4].version == RDP_GRAPHICS_CAPVERSION_107 &&
           (graphics_default_capsets[4].flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) == 0);
    PCHECK(rdp_graphics_capset_is_supported_for_avc(&graphics_default_capsets[4],
                                                    RDP_GRAPHICS_AVC_SUPPORT_ALL) != 0);
    PCHECK(rdp_graphics_capset_is_supported_for_avc(&graphics_default_capsets[4],
                                                    RDP_GRAPHICS_AVC_SUPPORT_AVC420) == 0);
    PCHECK(rdp_graphics_default_capsets_for_avc(graphics_default_capsets,
                                                (uint16_t)(sizeof(graphics_default_capsets) /
                                                           sizeof(graphics_default_capsets[0])),
                                                &graphics_default_capset_count,
                                                RDP_GRAPHICS_AVC_SUPPORT_AVC444) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_default_capsets_for_avc(graphics_default_capsets,
                                                (uint16_t)(sizeof(graphics_default_capsets) /
                                                           sizeof(graphics_default_capsets[0])),
                                                &graphics_default_capset_count,
                                                RDP_GRAPHICS_AVC_SUPPORT_AVC420 |
                                                    RDP_GRAPHICS_AVC_SUPPORT_AVC444V2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    dyn_response.length = 0;
    PCHECK(rdp_graphics_write_default_caps_advertise_for_avc(&dyn_response, 0) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 34u);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_buffer_append_u8(&dyn_response, 0xa5) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_write_default_caps_advertise_for_avc(&dyn_response,
                                                             RDP_GRAPHICS_AVC_SUPPORT_ALL << 1u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(dyn_response.length == 1 && dyn_response.data[0] == 0xa5);
    graphics_avc_runtime_support = rdp_avc_runtime_support();
    PCHECK((graphics_avc_runtime_support & ~RDP_GRAPHICS_AVC_SUPPORT_ALL) == 0);
    PCHECK((graphics_avc_runtime_support &
            (RDP_GRAPHICS_AVC_SUPPORT_AVC444 | RDP_GRAPHICS_AVC_SUPPORT_AVC444V2)) == 0 ||
           (graphics_avc_runtime_support & RDP_GRAPHICS_AVC_SUPPORT_AVC420) != 0);
    PCHECK(rdp_graphics_write_default_caps_advertise_for_avc(&dyn_response,
                                                             graphics_avc_runtime_support) ==
           LIBRDP_STATUS_OK);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    graphics_capset = graphics_default_capsets[0];
    PCHECK(rdp_graphics_parse_capset(graphics_capset_v107,
                                     sizeof(graphics_capset_v107),
                                     &graphics_capset) == LIBRDP_STATUS_OK);
    PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_107 &&
           (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SCALEDMAP_DISABLE) != 0);
    PCHECK(rdp_graphics_parse_capset(graphics_capset_unknown_flags,
                                     sizeof(graphics_capset_unknown_flags),
                                     &graphics_capset) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_capset(graphics_capset_conflicting_avc,
                                     sizeof(graphics_capset_conflicting_avc),
                                     &graphics_capset) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_capset(graphics_capset_trailing,
                                     sizeof(graphics_capset_trailing),
                                     &graphics_capset) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_buffer_append_u8(&dyn_response, 0xa5) == LIBRDP_STATUS_OK);
    graphics_capset.version = RDP_GRAPHICS_CAPVERSION_10;
    graphics_capset.flags = RDP_GRAPHICS_CAPS_FLAG_AVC420_ENABLED |
                            RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED;
    PCHECK(rdp_graphics_write_caps_advertise(&dyn_response,
                                             &graphics_capset,
                                             1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(dyn_response.length == 1 && dyn_response.data[0] == 0xa5);
    PCHECK(rdp_graphics_parse_header(graphics_confirm, sizeof(graphics_confirm), &graphics_header) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_header.cmd_id == RDP_GRAPHICS_CMDID_CAPS_CONFIRM);
    {
        rdp_graphics_header valid_header = graphics_header;

        PCHECK(rdp_graphics_parse_header(graphics_confirm,
                                         sizeof(graphics_confirm) - 1u,
                                         &graphics_header) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_header, &valid_header, sizeof(graphics_header)) == 0);
    }
    PCHECK(rdp_graphics_parse_caps_confirm(graphics_confirm, sizeof(graphics_confirm), &graphics_caps_confirm) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_caps_confirm.selected.version == RDP_GRAPHICS_CAPVERSION_8);
    PCHECK((graphics_caps_confirm.selected.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0);
    {
        rdp_graphics_caps_confirm valid_confirm = graphics_caps_confirm;

        PCHECK(rdp_graphics_parse_caps_confirm(graphics_confirm_trailing_capset,
                                               sizeof(graphics_confirm_trailing_capset),
                                               &graphics_caps_confirm) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_caps_confirm, &valid_confirm, sizeof(graphics_caps_confirm)) == 0);
    }
    PCHECK(rdp_graphics_decode_segmented_data(&graphics_decompressor,
                                              graphics_segment_single,
                                              sizeof(graphics_segment_single),
                                              &graphics_decoded) == LIBRDP_STATUS_OK);
    PCHECK(graphics_decoded.length == sizeof(graphics_confirm));
    PCHECK(memcmp(graphics_decoded.data, graphics_confirm, sizeof(graphics_confirm)) == 0);
    graphics_decoded.length = 0;
    PCHECK(rdp_graphics_decode_segmented_data(&graphics_decompressor,
                                              graphics_segment_multipart,
                                              sizeof(graphics_segment_multipart),
                                              &graphics_decoded) == LIBRDP_STATUS_OK);
    PCHECK(graphics_decoded.length == sizeof(graphics_confirm));
    PCHECK(memcmp(graphics_decoded.data, graphics_confirm, sizeof(graphics_confirm)) == 0);
    graphics_decoded.length = 0;
    PCHECK(rdp_graphics_decode_segmented_data(&graphics_decompressor,
                                              graphics_segment_compressed_literal,
                                              sizeof(graphics_segment_compressed_literal),
                                              &graphics_decoded) == LIBRDP_STATUS_OK);
    PCHECK(graphics_decoded.length == 1 && graphics_decoded.data[0] == 0x49);
    graphics_decoded.length = 0;
    PCHECK(rdp_graphics_decode_segmented_data(&graphics_decompressor,
                                              graphics_segment_bad_compression_type,
                                              sizeof(graphics_segment_bad_compression_type),
                                              &graphics_decoded) == LIBRDP_STATUS_PROTOCOL_ERROR);
    {
        uint32_t graphics_history_index = graphics_decompressor.history_index;
        uint32_t graphics_history_filled = graphics_decompressor.history_filled;
        uint32_t graphics_history_last_index =
            graphics_history_index == 0 ? RDP_GRAPHICS_BULK_HISTORY_SIZE - 1u : graphics_history_index - 1u;
        uint8_t graphics_history_last = graphics_decompressor.history[graphics_history_last_index];

        graphics_decoded.length = 0;
        PCHECK(rdp_buffer_append_u8(&graphics_decoded, 0xa5u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_graphics_decode_segmented_data(&graphics_decompressor,
                                                  graphics_segment_multipart_bad_second,
                                                  sizeof(graphics_segment_multipart_bad_second),
                                                  &graphics_decoded) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(graphics_decoded.length == 1u && graphics_decoded.data[0] == 0xa5u);
        PCHECK(graphics_decompressor.history_index == graphics_history_index &&
               graphics_decompressor.history_filled == graphics_history_filled &&
               graphics_decompressor.history[graphics_history_last_index] == graphics_history_last);
    }
    PCHECK(rdp_graphics_parse_caps_confirm(graphics_confirm, sizeof(graphics_confirm) - 1u, &graphics_caps_confirm) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_create_surface(graphics_create_surface,
                                             sizeof(graphics_create_surface),
                                             &graphics_create) == LIBRDP_STATUS_OK);
    PCHECK(graphics_create.surface_id == 0x1234 &&
           graphics_create.width == 1024 &&
           graphics_create.height == 768 &&
           graphics_create.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888);
    {
        rdp_graphics_create_surface valid_create = graphics_create;

        PCHECK(rdp_graphics_parse_create_surface(graphics_create_surface,
                                                 sizeof(graphics_create_surface) - 1u,
                                                 &graphics_create) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_create, &valid_create, sizeof(graphics_create)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_create_surface(&dyn_response,
                                             graphics_create.surface_id,
                                             graphics_create.width,
                                             graphics_create.height,
                                             graphics_create.pixel_format) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_create_surface(dyn_response.data,
                                             dyn_response.length,
                                             &graphics_create) == LIBRDP_STATUS_OK);
    PCHECK(graphics_create.width == 1024 && graphics_create.height == 768);
    PCHECK(rdp_graphics_write_create_surface(&dyn_response,
                                             1,
                                             0,
                                             1,
                                             RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_parse_delete_surface(graphics_delete_surface,
                                             sizeof(graphics_delete_surface),
                                             &graphics_delete) == LIBRDP_STATUS_OK);
    PCHECK(graphics_delete.surface_id == 0x1234);
    {
        rdp_graphics_delete_surface valid_delete = graphics_delete;

        PCHECK(rdp_graphics_parse_delete_surface(graphics_delete_surface,
                                                 sizeof(graphics_delete_surface) - 1u,
                                                 &graphics_delete) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_delete, &valid_delete, sizeof(graphics_delete)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_delete_surface(&dyn_response, graphics_delete.surface_id) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_delete_surface(dyn_response.data,
                                             dyn_response.length,
                                             &graphics_delete) == LIBRDP_STATUS_OK);
    PCHECK(graphics_delete.surface_id == 0x1234);
    PCHECK(rdp_graphics_parse_map_surface_to_output(graphics_map_output,
                                                    sizeof(graphics_map_output),
                                                    &graphics_map) == LIBRDP_STATUS_OK);
    PCHECK(graphics_map.surface_id == 0x1234 &&
           graphics_map.output_origin_x == 10 &&
           graphics_map.output_origin_y == 20);
    {
        rdp_graphics_map_surface_to_output valid_map = graphics_map;
        uint8_t bad_map[20];

        memcpy(bad_map, graphics_map_output, sizeof(bad_map));
        bad_map[11] = 1u;
        PCHECK(rdp_graphics_parse_map_surface_to_output(bad_map,
                                                        sizeof(bad_map),
                                                        &graphics_map) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_map, &valid_map, sizeof(graphics_map)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_map_surface_to_output(&dyn_response,
                                                    graphics_map.surface_id,
                                                    graphics_map.output_origin_x,
                                                    graphics_map.output_origin_y) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_map_surface_to_output(dyn_response.data,
                                                    dyn_response.length,
                                                    &graphics_map) == LIBRDP_STATUS_OK);
    PCHECK(graphics_map.output_origin_x == 10 && graphics_map.output_origin_y == 20);
    PCHECK(rdp_graphics_parse_map_surface_to_scaled_output(graphics_scaled_map_output,
                                                           sizeof(graphics_scaled_map_output),
                                                           &graphics_scaled_map) == LIBRDP_STATUS_OK);
    PCHECK(graphics_scaled_map.surface_id == 0x1234 &&
           graphics_scaled_map.output_origin_x == 10 &&
           graphics_scaled_map.output_origin_y == 20 &&
           graphics_scaled_map.target_width == 1024 &&
           graphics_scaled_map.target_height == 768);
    {
        rdp_graphics_map_surface_to_scaled_output valid_map = graphics_scaled_map;
        uint8_t bad_map[28];

        memcpy(bad_map, graphics_scaled_map_output, sizeof(bad_map));
        bad_map[24] = 0u;
        bad_map[25] = 0u;
        bad_map[26] = 0u;
        bad_map[27] = 0u;
        PCHECK(rdp_graphics_parse_map_surface_to_scaled_output(bad_map,
                                                               sizeof(bad_map),
                                                               &graphics_scaled_map) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_scaled_map, &valid_map, sizeof(graphics_scaled_map)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_map_surface_to_scaled_output(&dyn_response,
                                                           graphics_scaled_map.surface_id,
                                                           graphics_scaled_map.output_origin_x,
                                                           graphics_scaled_map.output_origin_y,
                                                           graphics_scaled_map.target_width,
                                                           graphics_scaled_map.target_height) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_map_surface_to_scaled_output(dyn_response.data,
                                                           dyn_response.length,
                                                           &graphics_scaled_map) == LIBRDP_STATUS_OK);
    PCHECK(graphics_scaled_map.target_width == 1024 && graphics_scaled_map.target_height == 768);
    PCHECK(rdp_graphics_write_map_surface_to_scaled_output(&dyn_response, 1, 0, 0, 0, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_parse_solid_fill(graphics_solid_fill,
                                         sizeof(graphics_solid_fill),
                                         &graphics_solid) == LIBRDP_STATUS_OK);
    PCHECK(graphics_solid.surface_id == 0x1234 &&
           graphics_solid.fill_pixel == 0xff332211u &&
           graphics_solid.rect_count == 1 &&
           graphics_solid.rects_len == 8);
    PCHECK(rdp_graphics_parse_rect16(graphics_solid.rects,
                                     graphics_solid.rects_len,
                                     &graphics_rect) == LIBRDP_STATUS_OK);
    PCHECK(graphics_rect.left == 1 &&
           graphics_rect.top == 2 &&
           graphics_rect.right == 5 &&
           graphics_rect.bottom == 6);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_rect16(&dyn_response, &graphics_rect) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_rect16(dyn_response.data, dyn_response.length, &graphics_rect) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_rect.right == 5 && graphics_rect.bottom == 6);
    {
        rdp_graphics_rect16 valid_rect = graphics_rect;

        PCHECK(rdp_graphics_parse_rect16(graphics_bad_rect,
                                         sizeof(graphics_bad_rect),
                                         &graphics_rect) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_rect, &valid_rect, sizeof(graphics_rect)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_solid_fill(&dyn_response,
                                         graphics_solid.surface_id,
                                         graphics_solid.fill_pixel,
                                         &graphics_rect,
                                         1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_solid_fill(dyn_response.data,
                                         dyn_response.length,
                                         &graphics_solid) == LIBRDP_STATUS_OK);
    PCHECK(graphics_solid.rect_count == 1 && graphics_solid.fill_pixel == 0xff332211u);
    {
        rdp_graphics_solid_fill valid_solid = graphics_solid;

        PCHECK(rdp_graphics_parse_solid_fill(graphics_solid_fill,
                                             sizeof(graphics_solid_fill) - 1u,
                                             &graphics_solid) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_solid, &valid_solid, sizeof(graphics_solid)) == 0);
    }
    PCHECK(rdp_graphics_parse_wire_to_surface_1(graphics_wire_to_surface_1,
                                                sizeof(graphics_wire_to_surface_1),
                                                &graphics_wire1) == LIBRDP_STATUS_OK);
    PCHECK(graphics_wire1.surface_id == 0x1234 &&
           graphics_wire1.codec_id == RDP_GRAPHICS_CODECID_UNCOMPRESSED &&
           graphics_wire1.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888 &&
           graphics_wire1.dest_rect.left == 1 &&
           graphics_wire1.dest_rect.bottom == 4 &&
           graphics_wire1.bitmap_data_length == 16 &&
           graphics_wire1.bitmap_data[15] == 16);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_wire_to_surface_1(&dyn_response,
                                                graphics_wire1.surface_id,
                                                graphics_wire1.codec_id,
                                                graphics_wire1.pixel_format,
                                                &graphics_wire1.dest_rect,
                                                graphics_wire1.bitmap_data,
                                                graphics_wire1.bitmap_data_length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_wire_to_surface_1(dyn_response.data,
                                                dyn_response.length,
                                                &graphics_wire1) == LIBRDP_STATUS_OK);
    PCHECK(graphics_wire1.bitmap_data_length == 16 && graphics_wire1.bitmap_data[0] == 1);
    PCHECK(rdp_graphics_parse_wire_to_surface_1(graphics_wire_to_surface_1_alpha,
                                                sizeof(graphics_wire_to_surface_1_alpha),
                                                &graphics_wire1) == LIBRDP_STATUS_OK);
    PCHECK(graphics_wire1.codec_id == RDP_GRAPHICS_CODECID_ALPHA &&
           graphics_wire1.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_ARGB_8888 &&
           graphics_wire1.dest_rect.right == 2 &&
           graphics_wire1.dest_rect.bottom == 2 &&
           graphics_wire1.bitmap_data_length == 8 &&
           graphics_wire1.bitmap_data[4] == 0x10 &&
           graphics_wire1.bitmap_data[7] == 0xff);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_wire_to_surface_1(&dyn_response,
                                                graphics_wire1.surface_id,
                                                graphics_wire1.codec_id,
                                                graphics_wire1.pixel_format,
                                                &graphics_wire1.dest_rect,
                                                graphics_wire1.bitmap_data,
                                                graphics_wire1.bitmap_data_length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_wire_to_surface_1(dyn_response.data,
                                                dyn_response.length,
                                                &graphics_wire1) == LIBRDP_STATUS_OK);
    PCHECK(graphics_wire1.codec_id == RDP_GRAPHICS_CODECID_ALPHA &&
           graphics_wire1.bitmap_data_length == 8 &&
           graphics_wire1.bitmap_data[5] == 0x20);
    {
        rdp_graphics_wire_to_surface_1 valid_wire1 = graphics_wire1;

        PCHECK(rdp_graphics_parse_wire_to_surface_1(graphics_wire_to_surface_1,
                                                    sizeof(graphics_wire_to_surface_1) - 1u,
                                                    &graphics_wire1) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_wire1, &valid_wire1, sizeof(graphics_wire1)) == 0);
    }
    graphics_zero_rect.left = 10;
    graphics_zero_rect.top = 20;
    graphics_zero_rect.right = 10;
    graphics_zero_rect.bottom = 21;
    PCHECK(rdp_graphics_write_wire_to_surface_1(&dyn_response,
                                                graphics_wire1.surface_id,
                                                graphics_wire1.codec_id,
                                                graphics_wire1.pixel_format,
                                                &graphics_zero_rect,
                                                graphics_wire1.bitmap_data,
                                                graphics_wire1.bitmap_data_length) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_wire_to_surface_1(&dyn_response,
                                                graphics_wire1.surface_id,
                                                RDP_GRAPHICS_CODECID_CAPROGRESSIVE,
                                                graphics_wire1.pixel_format,
                                                &graphics_wire1.dest_rect,
                                                graphics_wire1.bitmap_data,
                                                graphics_wire1.bitmap_data_length) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_parse_wire_to_surface_2(graphics_wire_to_surface_2,
                                                sizeof(graphics_wire_to_surface_2),
                                                &graphics_wire2) == LIBRDP_STATUS_OK);
    PCHECK(graphics_wire2.surface_id == 0x1234 &&
           graphics_wire2.codec_id == RDP_GRAPHICS_CODECID_CAPROGRESSIVE &&
           graphics_wire2.codec_context_id == 0x11223344u &&
           graphics_wire2.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_ARGB_8888 &&
           graphics_wire2.bitmap_data_length == 3 &&
           graphics_wire2.bitmap_data[2] == 0xcc);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_wire_to_surface_2(&dyn_response,
                                                graphics_wire2.surface_id,
                                                graphics_wire2.codec_id,
                                                graphics_wire2.codec_context_id,
                                                graphics_wire2.pixel_format,
                                                graphics_wire2.bitmap_data,
                                                graphics_wire2.bitmap_data_length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_wire_to_surface_2(dyn_response.data,
                                                dyn_response.length,
                                                &graphics_wire2) == LIBRDP_STATUS_OK);
    PCHECK(graphics_wire2.codec_context_id == 0x11223344u && graphics_wire2.bitmap_data[2] == 0xcc);
    {
        rdp_graphics_wire_to_surface_2 valid_wire2 = graphics_wire2;

        PCHECK(rdp_graphics_parse_wire_to_surface_2(graphics_wire_to_surface_2,
                                                    sizeof(graphics_wire_to_surface_2) - 1u,
                                                    &graphics_wire2) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_wire2, &valid_wire2, sizeof(graphics_wire2)) == 0);
    }
    PCHECK(rdp_graphics_write_wire_to_surface_2(&dyn_response,
                                                graphics_wire2.surface_id,
                                                RDP_GRAPHICS_CODECID_CLEARCODEC,
                                                graphics_wire2.codec_context_id,
                                                graphics_wire2.pixel_format,
                                                graphics_wire2.bitmap_data,
                                                graphics_wire2.bitmap_data_length) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_parse_avc420_metablock(graphics_avc420_stream,
                                               sizeof(graphics_avc420_stream) - 4u,
                                               &graphics_avc_meta) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc_meta.rect_count == 1 &&
           graphics_avc_meta.rects_len == 8 &&
           graphics_avc_meta.quant_quality_len == 2);
    PCHECK(rdp_graphics_parse_rect16(graphics_avc_meta.rects,
                                     graphics_avc_meta.rects_len,
                                     &graphics_rect) == LIBRDP_STATUS_OK);
    PCHECK(graphics_rect.left == 0 &&
           graphics_rect.top == 0 &&
           graphics_rect.right == 16 &&
           graphics_rect.bottom == 16);
    PCHECK(rdp_graphics_parse_avc420_quant_quality(graphics_avc_meta.quant_quality,
                                                   graphics_avc_meta.quant_quality_len,
                                                   &graphics_avc_quant) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc_quant.qp_val == 0x45 &&
           graphics_avc_quant.qp == 5 &&
           graphics_avc_quant.r == 1 &&
           graphics_avc_quant.p == 0 &&
           graphics_avc_quant.quality == 100);
    graphics_bad_quant = graphics_avc_quant;
    PCHECK(rdp_graphics_parse_avc420_quant_quality(graphics_avc_quant_bad_qp,
                                                   sizeof(graphics_avc_quant_bad_qp),
                                                   &graphics_bad_quant) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(memcmp(&graphics_bad_quant, &graphics_avc_quant, sizeof(graphics_bad_quant)) == 0);
    PCHECK(rdp_graphics_parse_avc420_quant_quality(graphics_avc_quant_bad_quality,
                                                   sizeof(graphics_avc_quant_bad_quality),
                                                   &graphics_bad_quant) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(memcmp(&graphics_bad_quant, &graphics_avc_quant, sizeof(graphics_bad_quant)) == 0);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc420_quant_quality(&dyn_response,
                                                   &graphics_avc_quant) == LIBRDP_STATUS_OK);
    graphics_avc_quant.qp = 52;
    graphics_avc_quant.qp_val = 52;
    graphics_avc_quant.quality = 100;
    PCHECK(rdp_graphics_write_avc420_quant_quality(&dyn_response,
                                                   &graphics_avc_quant) == LIBRDP_STATUS_INVALID_ARGUMENT);
    graphics_avc_quant.qp = 5;
    graphics_avc_quant.qp_val = 0x45;
    graphics_avc_quant.quality = 101;
    PCHECK(rdp_graphics_write_avc420_quant_quality(&dyn_response,
                                                   &graphics_avc_quant) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(dyn_response.length == 2 &&
           memcmp(dyn_response.data, graphics_avc_meta.quant_quality, 2) == 0);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc420_metablock(&dyn_response,
                                               &graphics_avc_meta) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(graphics_avc420_stream) - 4u &&
           memcmp(dyn_response.data,
                  graphics_avc420_stream,
                  sizeof(graphics_avc420_stream) - 4u) == 0);
    PCHECK(rdp_graphics_parse_avc420_stream(graphics_avc420_stream,
                                            sizeof(graphics_avc420_stream),
                                            &graphics_avc420) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc420.meta.rect_count == 1 &&
           graphics_avc420.bitstream_len == 4 &&
           graphics_avc420.bitstream[3] == 0x65);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc420_stream(&dyn_response,
                                            &graphics_avc420) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(graphics_avc420_stream) &&
           memcmp(dyn_response.data, graphics_avc420_stream, sizeof(graphics_avc420_stream)) == 0);
    {
        rdp_graphics_avc420_stream valid_graphics_avc420 = graphics_avc420;

        PCHECK(rdp_graphics_parse_avc420_stream(graphics_avc420_bad_rect,
                                                sizeof(graphics_avc420_bad_rect),
                                                &graphics_avc420) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_avc420, &valid_graphics_avc420, sizeof(graphics_avc420)) == 0);
        PCHECK(rdp_graphics_parse_avc420_stream(graphics_avc420_empty_bits,
                                                sizeof(graphics_avc420_empty_bits),
                                                &graphics_avc420) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_avc420, &valid_graphics_avc420, sizeof(graphics_avc420)) == 0);
        PCHECK(rdp_graphics_parse_avc420_stream(graphics_avc420_bad_quant,
                                                sizeof(graphics_avc420_bad_quant),
                                                &graphics_avc420) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_avc420, &valid_graphics_avc420, sizeof(graphics_avc420)) == 0);
    }
    PCHECK(rdp_graphics_parse_avc420_stream(graphics_avc420_stream,
                                            sizeof(graphics_avc420_stream),
                                            &graphics_avc420) == LIBRDP_STATUS_OK);
    graphics_avc420_edge = graphics_avc420;
    graphics_avc420_edge.meta.quant_quality = graphics_avc_quant_bad_qp;
    graphics_avc420_edge.meta.quant_quality_len = sizeof(graphics_avc_quant_bad_qp);
    PCHECK(rdp_graphics_write_avc420_stream(&dyn_response,
                                            &graphics_avc420_edge) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_both,
                                            sizeof(graphics_avc444_both),
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc444.lc == RDP_GRAPHICS_AVC444_LC_BOTH &&
           graphics_avc444.stream1_size == sizeof(graphics_avc420_stream) &&
           graphics_avc444.has_stream1 &&
           graphics_avc444.has_stream2 &&
           graphics_avc444.stream2.bitstream[3] == 0x66);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc444_stream(&dyn_response,
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(graphics_avc444_both) &&
           memcmp(dyn_response.data, graphics_avc444_both, sizeof(graphics_avc444_both)) == 0);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_luma,
                                            sizeof(graphics_avc444_luma),
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc444.lc == RDP_GRAPHICS_AVC444_LC_LUMA &&
           graphics_avc444.has_stream1 &&
           !graphics_avc444.has_stream2);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc444_stream(&dyn_response,
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(graphics_avc444_luma) &&
           memcmp(dyn_response.data, graphics_avc444_luma, sizeof(graphics_avc444_luma)) == 0);
    graphics_avc444.has_stream2 = 1;
    PCHECK(rdp_graphics_write_avc444_stream(&dyn_response,
                                            &graphics_avc444) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_chroma,
                                            sizeof(graphics_avc444_chroma),
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc444.lc == RDP_GRAPHICS_AVC444_LC_CHROMA &&
           graphics_avc444.has_stream1 &&
           !graphics_avc444.has_stream2);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc444_stream(&dyn_response,
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(graphics_avc444_chroma) &&
           memcmp(dyn_response.data, graphics_avc444_chroma, sizeof(graphics_avc444_chroma)) == 0);
    graphics_avc444_edge = graphics_avc444;
    graphics_avc444_edge.lc = RDP_GRAPHICS_AVC444_LC_INVALID;
    PCHECK(rdp_graphics_write_avc444_stream(&dyn_response,
                                            &graphics_avc444_edge) == LIBRDP_STATUS_INVALID_ARGUMENT);
    {
        rdp_graphics_avc444_stream valid_graphics_avc444 = graphics_avc444;

        PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_invalid_lc,
                                                sizeof(graphics_avc444_invalid_lc),
                                                &graphics_avc444) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_avc444, &valid_graphics_avc444, sizeof(graphics_avc444)) == 0);
        PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_bad_split,
                                                sizeof(graphics_avc444_bad_split),
                                                &graphics_avc444) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_avc444, &valid_graphics_avc444, sizeof(graphics_avc444)) == 0);
    }
    avc_decoder = rdp_avc_decoder_new();
    PCHECK(avc_decoder != NULL);
    rdp_avc_decoder_reset(avc_decoder);
    rdp_avc_frame_init(&avc_frame);
    graphics_avc420_edge = graphics_avc420;
    graphics_avc420_edge.meta.rect_count = 0;
    PCHECK(rdp_avc_decode_420(avc_decoder,
                              &graphics_avc420_edge,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
    graphics_avc420_edge = graphics_avc420;
    graphics_avc420_edge.meta.rects = graphics_avc_rect_oob;
    graphics_avc420_edge.meta.rects_len = sizeof(graphics_avc_rect_oob);
    PCHECK(rdp_avc_decode_420(avc_decoder,
                              &graphics_avc420_edge,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_avc_decode_420(avc_decoder,
                              &graphics_avc420,
                              0,
                              16,
                              &avc_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
#if !defined(RDP_HAVE_FFMPEG_AVC) && !defined(RDP_HAVE_OPENH264_AVC)
    PCHECK(rdp_avc_decode_420(avc_decoder,
                              &graphics_avc420,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_UNSUPPORTED);
#endif
    graphics_avc_status = rdp_avc_decode_420(avc_decoder,
                                             &graphics_avc420,
                                             16,
                                             16,
                                             &avc_frame);
    if ((graphics_avc_runtime_support & RDP_GRAPHICS_AVC_SUPPORT_AVC420) != 0)
        PCHECK(graphics_avc_status != LIBRDP_STATUS_UNSUPPORTED);
    else
        PCHECK(graphics_avc_status == LIBRDP_STATUS_UNSUPPORTED);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_both,
                                            sizeof(graphics_avc444_both),
                                            &graphics_avc444_edge) == LIBRDP_STATUS_OK);
    graphics_avc444_edge.has_stream1 = 0;
    PCHECK(rdp_avc_decode_444(avc_decoder,
                              RDP_GRAPHICS_CODECID_AVC444,
                              &graphics_avc444_edge,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_both,
                                            sizeof(graphics_avc444_both),
                                            &graphics_avc444_edge) == LIBRDP_STATUS_OK);
    graphics_avc444_edge.stream2.bitstream_len = 0;
    PCHECK(rdp_avc_decode_444(avc_decoder,
                              RDP_GRAPHICS_CODECID_AVC444V2,
                              &graphics_avc444_edge,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_luma,
                                            sizeof(graphics_avc444_luma),
                                            &graphics_avc444_edge) == LIBRDP_STATUS_OK);
    graphics_avc444_edge.has_stream2 = 1;
    graphics_avc444_edge.stream2 = graphics_avc444_edge.stream1;
    PCHECK(rdp_avc_decode_444(avc_decoder,
                              RDP_GRAPHICS_CODECID_AVC444,
                              &graphics_avc444_edge,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_both,
                                            sizeof(graphics_avc444_both),
                                            &graphics_avc444_edge) == LIBRDP_STATUS_OK);
    PCHECK(rdp_avc_decode_444(avc_decoder,
                              0xffffu,
                              &graphics_avc444_edge,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_INVALID_ARGUMENT);
    memset(&graphics_avc444_valid, 0, sizeof(graphics_avc444_valid));
    graphics_avc444_valid.lc = RDP_GRAPHICS_AVC444_LC_LUMA;
    graphics_avc444_valid.has_stream1 = 1;
    graphics_avc444_valid.stream1.meta.rect_count = 1;
    graphics_avc444_valid.stream1.meta.rects = graphics_avc_rect_full_16;
    graphics_avc444_valid.stream1.meta.rects_len = sizeof(graphics_avc_rect_full_16);
    graphics_avc444_valid.stream1.meta.quant_quality = graphics_avc_quant_quality;
    graphics_avc444_valid.stream1.meta.quant_quality_len = sizeof(graphics_avc_quant_quality);
    graphics_avc444_valid.stream1.bitstream = graphics_avc_red_h264;
    graphics_avc444_valid.stream1.bitstream_len = sizeof(graphics_avc_red_h264);
    graphics_avc444_edge = graphics_avc444_valid;
    graphics_avc444_edge.stream1.meta.rect_count = 0;
    PCHECK(rdp_avc_decode_444(avc_decoder,
                              RDP_GRAPHICS_CODECID_AVC444,
                              &graphics_avc444_edge,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
    graphics_avc444_edge = graphics_avc444_valid;
    graphics_avc444_edge.stream1.meta.rects = graphics_avc_rect_oob;
    graphics_avc444_edge.stream1.meta.rects_len = sizeof(graphics_avc_rect_oob);
    PCHECK(rdp_avc_decode_444(avc_decoder,
                              RDP_GRAPHICS_CODECID_AVC444V2,
                              &graphics_avc444_edge,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
#if !defined(RDP_HAVE_FFMPEG_AVC) && !defined(RDP_HAVE_OPENH264_AVC)
    PCHECK(rdp_avc_decode_444(avc_decoder,
                              RDP_GRAPHICS_CODECID_AVC444,
                              &graphics_avc444_valid,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_UNSUPPORTED);
#endif
    graphics_avc_status = rdp_avc_decode_444(avc_decoder,
                                             RDP_GRAPHICS_CODECID_AVC444,
                                             &graphics_avc444_valid,
                                             16,
                                             16,
                                             &avc_frame);
    if ((graphics_avc_runtime_support & RDP_GRAPHICS_AVC_SUPPORT_AVC444) != 0)
        PCHECK(graphics_avc_status == LIBRDP_STATUS_OK ||
               graphics_avc_status == LIBRDP_STATUS_PROTOCOL_ERROR);
    else
        PCHECK(graphics_avc_status == LIBRDP_STATUS_UNSUPPORTED);
    if (graphics_avc_status == LIBRDP_STATUS_OK)
    {
        const uint8_t* pixel = avc_frame.pixels.data;
        int red_delta_bg = (int)pixel[2] - (int)pixel[0];
        int red_delta_gr = (int)pixel[2] - (int)pixel[1];

        PCHECK(avc_frame.width == 16 && avc_frame.height == 16 && avc_frame.stride >= 64u);
        PCHECK(red_delta_bg > 8 && red_delta_gr > 8 && pixel[3] == 0xffu);
    }
    graphics_avc_status = rdp_avc_decode_444(avc_decoder,
                                             RDP_GRAPHICS_CODECID_AVC444V2,
                                             &graphics_avc444_valid,
                                             16,
                                             16,
                                             &avc_frame);
    if ((graphics_avc_runtime_support & RDP_GRAPHICS_AVC_SUPPORT_AVC444V2) != 0)
        PCHECK(graphics_avc_status == LIBRDP_STATUS_OK ||
               graphics_avc_status == LIBRDP_STATUS_PROTOCOL_ERROR);
    else
        PCHECK(graphics_avc_status == LIBRDP_STATUS_UNSUPPORTED);
    {
        uint8_t aux_y[8u * 5u];
        uint8_t aux_u[4u * 3u];
        uint8_t aux_v[4u * 3u];
        uint8_t dst_u[8u * 5u];
        uint8_t dst_v[8u * 5u];
        size_t i = 0;
        rdp_avc_444_chroma_view chroma_view;

        for (i = 0; i < sizeof(aux_y); i++)
            aux_y[i] = (uint8_t)(0x20u + i);
        for (i = 0; i < sizeof(aux_u); i++)
            aux_u[i] = (uint8_t)(0x60u + i);
        for (i = 0; i < sizeof(aux_v); i++)
            aux_v[i] = (uint8_t)(0xa0u + i);
        memset(dst_u, 0xee, sizeof(dst_u));
        memset(dst_v, 0xdd, sizeof(dst_v));
        memset(&chroma_view, 0, sizeof(chroma_view));
        chroma_view.aux_y = aux_y;
        chroma_view.aux_y_stride = 8;
        chroma_view.aux_u = aux_u;
        chroma_view.aux_u_stride = 4;
        chroma_view.aux_v = aux_v;
        chroma_view.aux_v_stride = 4;
        chroma_view.aux_width = 8;
        chroma_view.aux_height = 5;
        chroma_view.rect.left = 0;
        chroma_view.rect.top = 0;
        chroma_view.rect.right = 5;
        chroma_view.rect.bottom = 5;
        chroma_view.dst_u = dst_u;
        chroma_view.dst_u_stride = 8;
        chroma_view.dst_v = dst_v;
        chroma_view.dst_v_stride = 8;
        chroma_view.dst_width = 8;
        chroma_view.dst_height = 5;
        PCHECK(rdp_avc_reconstruct_444_chroma(&chroma_view) == LIBRDP_STATUS_OK);
        PCHECK(dst_u[8u + 0u] == aux_y[0] && dst_u[8u + 4u] == aux_y[4]);
        PCHECK(dst_v[8u + 0u] == aux_y[4u * 8u] && dst_v[8u + 4u] == aux_y[4u * 8u + 4u]);
        PCHECK(dst_u[0u * 8u + 1u] == aux_u[0] && dst_v[0u * 8u + 1u] == aux_v[0]);
        PCHECK(dst_u[2u * 8u + 3u] == aux_u[5] && dst_v[2u * 8u + 3u] == aux_v[5]);
        PCHECK(dst_u[4u * 8u + 1u] == aux_u[8] && dst_v[4u * 8u + 1u] == aux_v[8]);
        chroma_view.aux_v_stride = 1;
        PCHECK(rdp_avc_reconstruct_444_chroma(&chroma_view) == LIBRDP_STATUS_PROTOCOL_ERROR);
        chroma_view.aux_v_stride = 4;
        chroma_view.aux_u_stride = 1;
        PCHECK(rdp_avc_reconstruct_444_chroma(&chroma_view) == LIBRDP_STATUS_PROTOCOL_ERROR);
    }
    {
        uint8_t aux_y[6u * 3u];
        uint8_t aux_u[3u * 2u];
        uint8_t aux_v[3u * 2u];
        uint8_t dst_u[6u * 3u];
        uint8_t dst_v[6u * 3u];
        size_t i = 0;
        rdp_avc_444_chroma_view chroma_view;

        for (i = 0; i < sizeof(aux_y); i++)
            aux_y[i] = (uint8_t)(0x10u + i);
        for (i = 0; i < sizeof(aux_u); i++)
            aux_u[i] = (uint8_t)(0x50u + i);
        for (i = 0; i < sizeof(aux_v); i++)
            aux_v[i] = (uint8_t)(0x90u + i);
        memset(dst_u, 0xee, sizeof(dst_u));
        memset(dst_v, 0xdd, sizeof(dst_v));
        memset(&chroma_view, 0, sizeof(chroma_view));
        chroma_view.aux_y = aux_y;
        chroma_view.aux_y_stride = 6;
        chroma_view.aux_u = aux_u;
        chroma_view.aux_u_stride = 3;
        chroma_view.aux_v = aux_v;
        chroma_view.aux_v_stride = 3;
        chroma_view.aux_width = 6;
        chroma_view.aux_height = 3;
        chroma_view.rect.left = 1;
        chroma_view.rect.top = 0;
        chroma_view.rect.right = 4;
        chroma_view.rect.bottom = 3;
        chroma_view.dst_u = dst_u;
        chroma_view.dst_u_stride = 6;
        chroma_view.dst_v = dst_v;
        chroma_view.dst_v_stride = 6;
        chroma_view.dst_width = 6;
        chroma_view.dst_height = 3;
        PCHECK(rdp_avc_reconstruct_444_chroma(&chroma_view) == LIBRDP_STATUS_OK);
        PCHECK(dst_u[1] == aux_u[0] && dst_v[1] == aux_v[0]);
        PCHECK(dst_u[3] == aux_u[1] && dst_v[3] == aux_v[1]);
        PCHECK(dst_u[2] == 0xeeu && dst_v[2] == 0xddu);
        PCHECK(dst_u[6u + 1u] == aux_y[1] && dst_u[6u + 3u] == aux_y[3]);
        PCHECK(dst_v[6u + 1u] == aux_y[12u + 1u] &&
               dst_v[6u + 3u] == aux_y[12u + 3u]);
    }
    {
        uint8_t aux_y[16u * 4u];
        uint8_t aux_u[8u * 2u];
        uint8_t aux_v[8u * 2u];
        uint8_t dst_u[16u * 4u];
        uint8_t dst_v[16u * 4u];
        size_t i = 0;
        rdp_avc_444v2_chroma_view chroma_view;

        for (i = 0; i < sizeof(aux_y); i++)
            aux_y[i] = (uint8_t)(0x20u + i);
        for (i = 0; i < sizeof(aux_u); i++)
            aux_u[i] = (uint8_t)(0x60u + i);
        for (i = 0; i < sizeof(aux_v); i++)
            aux_v[i] = (uint8_t)(0xa0u + i);
        memset(dst_u, 0xee, sizeof(dst_u));
        memset(dst_v, 0xdd, sizeof(dst_v));
        memset(&chroma_view, 0, sizeof(chroma_view));
        chroma_view.aux_y = aux_y;
        chroma_view.aux_y_stride = 16;
        chroma_view.aux_u = aux_u;
        chroma_view.aux_u_stride = 8;
        chroma_view.aux_v = aux_v;
        chroma_view.aux_v_stride = 8;
        chroma_view.aux_width = 16;
        chroma_view.aux_height = 4;
        chroma_view.rect.left = 2;
        chroma_view.rect.top = 0;
        chroma_view.rect.right = 7;
        chroma_view.rect.bottom = 3;
        chroma_view.dst_u = dst_u;
        chroma_view.dst_u_stride = 16;
        chroma_view.dst_v = dst_v;
        chroma_view.dst_v_stride = 16;
        chroma_view.dst_width = 16;
        chroma_view.dst_height = 4;
        PCHECK(rdp_avc_reconstruct_444v2_chroma(&chroma_view) == LIBRDP_STATUS_OK);
        PCHECK(dst_u[3] == aux_y[1] && dst_v[3] == aux_y[9]);
        PCHECK(dst_u[5] == aux_y[2] && dst_v[5] == aux_y[10]);
        PCHECK(dst_u[16u + 3u] == aux_y[16u + 1u] && dst_v[16u + 3u] == aux_y[16u + 9u]);
        PCHECK(dst_u[16u + 2u] == aux_v[0] && dst_v[16u + 2u] == aux_v[4]);
        PCHECK(dst_u[16u + 4u] == aux_u[1] && dst_v[16u + 4u] == aux_u[5]);
        PCHECK(dst_u[16u + 6u] == aux_v[1] && dst_v[16u + 6u] == aux_v[5]);
        PCHECK(dst_u[0] == 0xeeu && dst_v[0] == 0xddu);
        chroma_view.aux_u_stride = 4;
        PCHECK(rdp_avc_reconstruct_444v2_chroma(&chroma_view) == LIBRDP_STATUS_PROTOCOL_ERROR);
        chroma_view.aux_u_stride = 8;
        chroma_view.aux_v_stride = 4;
        PCHECK(rdp_avc_reconstruct_444v2_chroma(&chroma_view) == LIBRDP_STATUS_PROTOCOL_ERROR);
    }
    {
        uint8_t aux_y[15u * 5u];
        uint8_t aux_u[8u * 3u];
        uint8_t aux_v[8u * 3u];
        uint8_t dst_u[15u * 5u];
        uint8_t dst_v[15u * 5u];
        size_t i = 0;
        rdp_avc_444v2_chroma_view chroma_view;

        for (i = 0; i < sizeof(aux_y); i++)
            aux_y[i] = (uint8_t)(0x10u + i);
        for (i = 0; i < sizeof(aux_u); i++)
            aux_u[i] = (uint8_t)(0x50u + i);
        for (i = 0; i < sizeof(aux_v); i++)
            aux_v[i] = (uint8_t)(0x90u + i);
        memset(dst_u, 0xee, sizeof(dst_u));
        memset(dst_v, 0xdd, sizeof(dst_v));
        memset(&chroma_view, 0, sizeof(chroma_view));
        chroma_view.aux_y = aux_y;
        chroma_view.aux_y_stride = 15;
        chroma_view.aux_u = aux_u;
        chroma_view.aux_u_stride = 8;
        chroma_view.aux_v = aux_v;
        chroma_view.aux_v_stride = 8;
        chroma_view.aux_width = 15;
        chroma_view.aux_height = 5;
        chroma_view.rect.left = 1;
        chroma_view.rect.top = 0;
        chroma_view.rect.right = 8;
        chroma_view.rect.bottom = 5;
        chroma_view.dst_u = dst_u;
        chroma_view.dst_u_stride = 15;
        chroma_view.dst_v = dst_v;
        chroma_view.dst_v_stride = 15;
        chroma_view.dst_width = 15;
        chroma_view.dst_height = 5;
        PCHECK(rdp_avc_reconstruct_444v2_chroma(&chroma_view) == LIBRDP_STATUS_OK);
        PCHECK(dst_u[1] == aux_y[0] && dst_v[1] == aux_y[8]);
        PCHECK(dst_u[3] == aux_y[1] && dst_v[3] == aux_y[9]);
        PCHECK(dst_u[15u + 2u] == aux_v[0] && dst_v[15u + 2u] == aux_v[4]);
        PCHECK(dst_u[15u + 4u] == aux_u[1] && dst_v[15u + 4u] == aux_u[5]);
        PCHECK(dst_u[15u + 6u] == aux_v[1] && dst_v[15u + 6u] == aux_v[5]);
    }
    {
        uint8_t aux_y[4u * 2u] = {0};
        uint8_t aux_u[2u] = {0};
        uint8_t aux_v[2u] = {0};
        uint8_t dst_u[4u * 2u];
        uint8_t dst_v[4u * 2u];
        rdp_avc_444v2_chroma_view chroma_view;

        memset(dst_u, 0x80, sizeof(dst_u));
        memset(dst_v, 0x80, sizeof(dst_v));
        dst_u[0] = 60;
        dst_v[0] = 90;
        aux_y[0] = 10;
        aux_y[2] = 40;
        aux_y[4] = 30;
        aux_y[6] = 70;
        aux_u[0] = 20;
        aux_u[1] = 50;
        aux_v[0] = 80;
        aux_v[1] = 110;
        memset(&chroma_view, 0, sizeof(chroma_view));
        chroma_view.aux_y = aux_y;
        chroma_view.aux_y_stride = 4;
        chroma_view.aux_u = aux_u;
        chroma_view.aux_u_stride = 2;
        chroma_view.aux_v = aux_v;
        chroma_view.aux_v_stride = 2;
        chroma_view.aux_width = 4;
        chroma_view.aux_height = 2;
        chroma_view.rect.left = 0;
        chroma_view.rect.top = 0;
        chroma_view.rect.right = 4;
        chroma_view.rect.bottom = 2;
        chroma_view.dst_u = dst_u;
        chroma_view.dst_u_stride = 4;
        chroma_view.dst_v = dst_v;
        chroma_view.dst_v_stride = 4;
        chroma_view.dst_width = 4;
        chroma_view.dst_height = 2;
        PCHECK(rdp_avc_reconstruct_444v2_chroma(&chroma_view) == LIBRDP_STATUS_OK);
        PCHECK(dst_u[1] == 10 && dst_u[4] == 20 && dst_u[5] == 30 && dst_u[0] == 180);
        PCHECK(dst_v[1] == 40 && dst_v[4] == 50 && dst_v[5] == 70 && dst_v[0] == 200);
    }
    {
        uint8_t aux_y[4u * 2u] = {0};
        uint8_t aux_u[2u] = {0};
        uint8_t aux_v[2u] = {0};
        uint8_t dst_u[4u * 2u];
        uint8_t dst_v[4u * 2u];
        rdp_avc_444v2_chroma_view chroma_view;

        memset(dst_u, 0x80, sizeof(dst_u));
        memset(dst_v, 0x80, sizeof(dst_v));
        dst_u[0] = 60;
        dst_v[0] = 90;
        aux_y[0] = 61;
        aux_y[2] = 91;
        aux_y[4] = 62;
        aux_y[6] = 92;
        aux_u[0] = 63;
        aux_u[1] = 93;
        aux_v[0] = 64;
        aux_v[1] = 94;
        memset(&chroma_view, 0, sizeof(chroma_view));
        chroma_view.aux_y = aux_y;
        chroma_view.aux_y_stride = 4;
        chroma_view.aux_u = aux_u;
        chroma_view.aux_u_stride = 2;
        chroma_view.aux_v = aux_v;
        chroma_view.aux_v_stride = 2;
        chroma_view.aux_width = 4;
        chroma_view.aux_height = 2;
        chroma_view.rect.left = 0;
        chroma_view.rect.top = 0;
        chroma_view.rect.right = 4;
        chroma_view.rect.bottom = 2;
        chroma_view.dst_u = dst_u;
        chroma_view.dst_u_stride = 4;
        chroma_view.dst_v = dst_v;
        chroma_view.dst_v_stride = 4;
        chroma_view.dst_width = 4;
        chroma_view.dst_height = 2;
        PCHECK(rdp_avc_reconstruct_444v2_chroma(&chroma_view) == LIBRDP_STATUS_OK);
        PCHECK(dst_u[0] == 54 && dst_v[0] == 84);
    }
#if defined(RDP_HAVE_FFMPEG_AVC) || defined(RDP_HAVE_OPENH264_AVC)
    {
        uint8_t y_plane[4] = {128, 128, 128, 128};
        uint8_t u_plane[4] = {160, 130, 130, 130};
        uint8_t v_plane[4] = {160, 130, 130, 130};
        const uint8_t* pixel0 = NULL;
        const uint8_t* pixel1 = NULL;

        PCHECK(rdp_avc_yuv444_planes_to_bgra(y_plane,
                                             2,
                                             u_plane,
                                             2,
                                             v_plane,
                                             2,
                                             2,
                                             2,
                                             0,
                                             &avc_frame) == LIBRDP_STATUS_OK);
        pixel0 = avc_frame.pixels.data;
        PCHECK(pixel0[0] == 187 && pixel0[1] == 107 && pixel0[2] == 178 && pixel0[3] == 255);
        PCHECK(rdp_avc_yuv444_planes_to_bgra(y_plane,
                                             2,
                                             u_plane,
                                             2,
                                             v_plane,
                                             2,
                                             2,
                                             2,
                                             1,
                                             &avc_frame) == LIBRDP_STATUS_OK);
        pixel0 = avc_frame.pixels.data;
        pixel1 = avc_frame.pixels.data + 4u;
        PCHECK(pixel0[0] == 255 && pixel0[1] == 48 && pixel0[2] == 255 && pixel0[3] == 255);
        PCHECK(pixel1[0] == 131 && pixel1[1] == 127 && pixel1[2] == 131 && pixel1[3] == 255);
        {
            uint8_t saved[8];
            size_t saved_len = avc_frame.pixels.length;
            uint32_t saved_width = avc_frame.width;
            uint32_t saved_height = avc_frame.height;
            size_t saved_stride = avc_frame.stride;

            memcpy(saved, avc_frame.pixels.data, sizeof(saved));
            PCHECK(rdp_avc_yuv444_planes_to_bgra(y_plane,
                                                 1,
                                                 u_plane,
                                                 2,
                                                 v_plane,
                                                 2,
                                                 2,
                                                 2,
                                                 0,
                                                 &avc_frame) == LIBRDP_STATUS_INVALID_ARGUMENT);
            PCHECK(avc_frame.pixels.length == saved_len &&
                   avc_frame.width == saved_width &&
                   avc_frame.height == saved_height &&
                   avc_frame.stride == saved_stride &&
                   memcmp(avc_frame.pixels.data, saved, sizeof(saved)) == 0);
        }
    }
#endif
    rdp_avc_frame_free(&avc_frame);
    rdp_avc_decoder_free(avc_decoder);
    PCHECK(rdp_graphics_progressive_parse_block(graphics_progressive_stream,
                                                sizeof(graphics_progressive_stream),
                                                &graphics_progressive_block) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_CONTEXT &&
           graphics_progressive_block.length == 10 &&
           graphics_progressive_block.payload_len == 4);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_block(&dyn_response,
                                                graphics_progressive_block.type,
                                                graphics_progressive_block.payload,
                                                (uint32_t)graphics_progressive_block.payload_len) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_block(dyn_response.data,
                                                dyn_response.length,
                                                &graphics_progressive_block) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_CONTEXT &&
           graphics_progressive_block.payload_len == 4);
    {
        rdp_graphics_progressive_block valid_block = graphics_progressive_block;

        PCHECK(rdp_graphics_progressive_parse_block(graphics_progressive_bad_block,
                                                    sizeof(graphics_progressive_bad_block),
                                                    &graphics_progressive_block) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_block,
                      &valid_block,
                      sizeof(graphics_progressive_block)) == 0);
    }
    PCHECK(rdp_graphics_progressive_write_block(&dyn_response, 1, NULL, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_progressive_parse_context(graphics_progressive_stream,
                                                  sizeof(graphics_progressive_stream),
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_context.context_id == 0 &&
           graphics_progressive_context.tile_size == RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE &&
           graphics_progressive_context.flags == 1);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_context(&dyn_response,
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_context(dyn_response.data,
                                                  dyn_response.length,
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_context.flags == 1);
    {
        rdp_graphics_progressive_context valid_context = graphics_progressive_context;

        PCHECK(rdp_graphics_progressive_parse_context(graphics_progressive_stream + 10,
                                                      sizeof(graphics_progressive_stream) - 10u,
                                                      &graphics_progressive_context) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_context,
                      &valid_context,
                      sizeof(graphics_progressive_context)) == 0);
    }
    PCHECK(rdp_graphics_progressive_parse_frame_begin(graphics_progressive_stream + 10,
                                                      sizeof(graphics_progressive_stream) - 10u,
                                                      &graphics_progressive_frame_begin) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_frame_begin.frame_index == 1 &&
           graphics_progressive_frame_begin.region_count == 1);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_frame_begin(&dyn_response,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_frame_begin(dyn_response.data,
                                                      dyn_response.length,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_frame_begin.frame_index == 1);
    {
        rdp_graphics_progressive_frame_begin valid_frame_begin = graphics_progressive_frame_begin;

        PCHECK(rdp_graphics_progressive_parse_frame_begin(graphics_progressive_stream + 10,
                                                          11u,
                                                          &graphics_progressive_frame_begin) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_frame_begin,
                      &valid_frame_begin,
                      sizeof(graphics_progressive_frame_begin)) == 0);
    }
    PCHECK(rdp_graphics_progressive_parse_region(graphics_progressive_stream + 22,
                                                 sizeof(graphics_progressive_stream) - 22u,
                                                 &graphics_progressive_region) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_region.tile_size == RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE &&
           graphics_progressive_region.rect_count == 1 &&
           graphics_progressive_region.quant_count == 1 &&
           graphics_progressive_region.progressive_quant_count == 1 &&
           graphics_progressive_region.tile_count == 1 &&
           graphics_progressive_region.tile_data_size == 25 &&
           graphics_progressive_region.tiles_len == 25);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_region(&dyn_response,
                                                 &graphics_progressive_region) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_region(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_progressive_region) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_region.tiles_len == 25);
    {
        rdp_graphics_progressive_region valid_region = graphics_progressive_region;

        PCHECK(rdp_graphics_progressive_parse_region(graphics_progressive_bad_region,
                                                     sizeof(graphics_progressive_bad_region),
                                                     &graphics_progressive_region) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_region,
                      &valid_region,
                      sizeof(graphics_progressive_region)) == 0);
    }
    PCHECK(rdp_graphics_progressive_parse_region(graphics_progressive_empty_region,
                                                 sizeof(graphics_progressive_empty_region),
                                                 &graphics_progressive_region) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_region.tile_count == 0 &&
           graphics_progressive_region.tile_data_size == 0 &&
           graphics_progressive_region.tiles_len == 0);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_region(&dyn_response,
                                                 &graphics_progressive_region) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data,
                  graphics_progressive_empty_region,
                  sizeof(graphics_progressive_empty_region)) == 0);
    PCHECK(rdp_graphics_progressive_parse_region_rect(graphics_progressive_region_rect,
                                                      sizeof(graphics_progressive_region_rect),
                                                      &graphics_progressive_rect) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_rect.left == 640 &&
           graphics_progressive_rect.top == 288 &&
           graphics_progressive_rect.right == 704 &&
           graphics_progressive_rect.bottom == 320);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_region_rect(&dyn_response,
                                                      &graphics_progressive_rect) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data,
                  graphics_progressive_region_rect,
                  sizeof(graphics_progressive_region_rect)) == 0);
    {
        rdp_graphics_rect16 valid_progressive_rect = graphics_progressive_rect;

        PCHECK(rdp_graphics_progressive_parse_region_rect(graphics_progressive_region_rect_overflow,
                                                          sizeof(graphics_progressive_region_rect_overflow),
                                                          &graphics_progressive_rect) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_rect,
                      &valid_progressive_rect,
                      sizeof(graphics_progressive_rect)) == 0);
        PCHECK(rdp_graphics_progressive_parse_region_rect(graphics_progressive_region_rect,
                                                          sizeof(graphics_progressive_region_rect) - 1u,
                                                          &graphics_progressive_rect) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_rect,
                      &valid_progressive_rect,
                      sizeof(graphics_progressive_rect)) == 0);
    }
    PCHECK(rdp_graphics_progressive_parse_tile_simple(graphics_progressive_stream + 69,
                                                      sizeof(graphics_progressive_stream) - 69u,
                                                      &graphics_progressive_simple) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_simple.block_type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_SIMPLE &&
           graphics_progressive_simple.y_len == 1 &&
           graphics_progressive_simple.cb_len == 1 &&
           graphics_progressive_simple.cr_len == 1 &&
           graphics_progressive_simple.y_data[0] == 0xaa &&
           graphics_progressive_simple.cb_data[0] == 0xbb &&
           graphics_progressive_simple.cr_data[0] == 0xcc);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_tile_simple(&dyn_response,
                                                      &graphics_progressive_simple) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_tile_simple(dyn_response.data,
                                                      dyn_response.length,
                                                      &graphics_progressive_simple) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_simple.y_data[0] == 0xaa);
    {
        rdp_graphics_progressive_tile_simple valid_simple = graphics_progressive_simple;

        PCHECK(rdp_graphics_progressive_parse_tile_simple(graphics_progressive_stream + 69,
                                                          24u,
                                                          &graphics_progressive_simple) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_simple,
                      &valid_simple,
                      sizeof(graphics_progressive_simple)) == 0);
    }
    PCHECK(rdp_graphics_progressive_parse_frame_end(graphics_progressive_stream + 94,
                                                    sizeof(graphics_progressive_stream) - 94u) ==
           LIBRDP_STATUS_OK);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_frame_end(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_frame_end(dyn_response.data,
                                                    dyn_response.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_tile_first(graphics_progressive_tile_first,
                                                     sizeof(graphics_progressive_tile_first),
                                                     &graphics_progressive_first) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_first.block_type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_FIRST &&
           graphics_progressive_first.x_idx == 1 &&
           graphics_progressive_first.y_idx == 2 &&
           graphics_progressive_first.progressive_quality == 0 &&
           graphics_progressive_first.y_data[0] == 0x11 &&
           graphics_progressive_first.cb_data[0] == 0x22 &&
           graphics_progressive_first.cr_data[0] == 0x33);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_tile_first(&dyn_response,
                                                     &graphics_progressive_first) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data,
                  graphics_progressive_tile_first,
                  sizeof(graphics_progressive_tile_first)) == 0);
    {
        rdp_graphics_progressive_tile_first valid_first = graphics_progressive_first;

        PCHECK(rdp_graphics_progressive_parse_tile_first(graphics_progressive_tile_first,
                                                         sizeof(graphics_progressive_tile_first) - 1u,
                                                         &graphics_progressive_first) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_first,
                      &valid_first,
                      sizeof(graphics_progressive_first)) == 0);
    }
    PCHECK(rdp_graphics_progressive_parse_tile_upgrade(graphics_progressive_tile_upgrade,
                                                       sizeof(graphics_progressive_tile_upgrade),
                                                       &graphics_progressive_upgrade) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_upgrade.block_type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_UPGRADE &&
           graphics_progressive_upgrade.x_idx == 3 &&
           graphics_progressive_upgrade.y_idx == 4 &&
           graphics_progressive_upgrade.y_srl_data[0] == 0x11 &&
           graphics_progressive_upgrade.cr_raw_data[0] == 0x66);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_tile_upgrade(&dyn_response,
                                                       &graphics_progressive_upgrade) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data,
                  graphics_progressive_tile_upgrade,
                  sizeof(graphics_progressive_tile_upgrade)) == 0);
    {
        rdp_graphics_progressive_tile_upgrade valid_upgrade = graphics_progressive_upgrade;

        PCHECK(rdp_graphics_progressive_parse_tile_upgrade(graphics_progressive_tile_upgrade,
                                                           sizeof(graphics_progressive_tile_upgrade) - 1u,
                                                           &graphics_progressive_upgrade) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_upgrade,
                      &valid_upgrade,
                      sizeof(graphics_progressive_upgrade)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_context(&dyn_response,
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_frame_begin(&dyn_response,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_region(graphics_progressive_stream + 22,
                                                 sizeof(graphics_progressive_stream) - 22u,
                                                 &graphics_progressive_region) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_region(&dyn_response,
                                                 &graphics_progressive_region) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_frame_end(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data,
                  graphics_progressive_stream,
                  sizeof(graphics_progressive_stream)) == 0);
    PCHECK(rdp_graphics_progressive_parse_stream(graphics_progressive_stream,
                                                 sizeof(graphics_progressive_stream),
                                                 &graphics_progressive) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive.block_count == 4 &&
           graphics_progressive.known_block_count == 4 &&
           graphics_progressive.region_count == 1 &&
           graphics_progressive.tile_count == 1 &&
           graphics_progressive.simple_tile_count == 1 &&
           graphics_progressive.first_tile_count == 0 &&
           graphics_progressive.upgrade_tile_count == 0 &&
           graphics_progressive.has_sync == 0 &&
           graphics_progressive.has_context &&
           graphics_progressive.has_frame_begin &&
           graphics_progressive.has_frame_end);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_buffer_append(&dyn_response,
                             graphics_progressive_sync,
                             sizeof(graphics_progressive_sync)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&dyn_response,
                             graphics_progressive_stream,
                             sizeof(graphics_progressive_stream)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_stream(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_progressive) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive.block_count == 5 &&
           graphics_progressive.known_block_count == 5 &&
           graphics_progressive.has_sync == 1 &&
           graphics_progressive.has_context == 1 &&
           graphics_progressive.region_count == 1 &&
           graphics_progressive.tile_count == 1);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_buffer_append(&dyn_response,
                             graphics_progressive_bad_sync,
                             sizeof(graphics_progressive_bad_sync)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&dyn_response,
                             graphics_progressive_stream,
                             sizeof(graphics_progressive_stream)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_stream(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_progressive) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_buffer_append(&dyn_response,
                             graphics_progressive_stream + 10u,
                             sizeof(graphics_progressive_stream) - 10u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_stream(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_progressive) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive.block_count == 3 &&
           graphics_progressive.known_block_count == 3 &&
           graphics_progressive.has_sync == 0 &&
           graphics_progressive.has_context == 0 &&
           graphics_progressive.has_frame_begin == 1 &&
           graphics_progressive.has_frame_end == 1 &&
           graphics_progressive.region_count == 1 &&
           graphics_progressive.tile_count == 1);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_context(&dyn_response,
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_region(&dyn_response,
                                                 &graphics_progressive_region) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_frame_end(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_stream(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_progressive) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_context(&dyn_response,
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_frame_begin(&dyn_response,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_frame_begin(&dyn_response,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_stream(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_progressive) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_context(&dyn_response,
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_frame_begin(&dyn_response,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_region(&dyn_response,
                                                 &graphics_progressive_region) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_stream(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_progressive) == LIBRDP_STATUS_PROTOCOL_ERROR);
    graphics_progressive_frame_begin.region_count =
        (uint16_t)(RDP_GRAPHICS_PROGRESSIVE_MAX_REGIONS + 1u);
    PCHECK(rdp_graphics_progressive_write_frame_begin(&dyn_response,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    graphics_progressive_frame_begin.region_count = 1;
    graphics_progressive_region.rect_count =
        (uint16_t)(RDP_GRAPHICS_PROGRESSIVE_MAX_RECTS + 1u);
    PCHECK(rdp_graphics_progressive_write_region(&dyn_response,
                                                 &graphics_progressive_region) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    graphics_progressive_region.rect_count = 1;
    {
        rdp_graphics_progressive_stream graphics_progressive_before = graphics_progressive;

        PCHECK(rdp_graphics_progressive_parse_stream(graphics_progressive_stream,
                                                     sizeof(graphics_progressive_stream) - 1u,
                                                     &graphics_progressive) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive,
                      &graphics_progressive_before,
                      sizeof(graphics_progressive)) == 0);
    }
    PCHECK(rdp_graphics_parse_surface_to_surface(graphics_surface_to_surface,
                                                 sizeof(graphics_surface_to_surface),
                                                 &graphics_surface_copy) == LIBRDP_STATUS_OK);
    PCHECK(graphics_surface_copy.surface_id_src == 0x10 &&
           graphics_surface_copy.surface_id_dest == 0x20 &&
           graphics_surface_copy.rect_src.right == 5 &&
           graphics_surface_copy.dest_points_count == 2 &&
           graphics_surface_copy.dest_points_len == 8);
    PCHECK(rdp_graphics_parse_point16(graphics_surface_copy.dest_points,
                                      graphics_surface_copy.dest_points_len,
                                      &graphics_point) == LIBRDP_STATUS_OK);
    PCHECK(graphics_point.x == 7 && graphics_point.y == 8);
    graphics_points[0] = graphics_point;
    PCHECK(rdp_graphics_parse_point16(graphics_surface_copy.dest_points + 4,
                                      graphics_surface_copy.dest_points_len - 4u,
                                      &graphics_points[1]) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_point16(&dyn_response, &graphics_points[0]) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_point16(dyn_response.data, dyn_response.length, &graphics_point) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_point.x == 7 && graphics_point.y == 8);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_surface_to_surface(&dyn_response,
                                                 graphics_surface_copy.surface_id_src,
                                                 graphics_surface_copy.surface_id_dest,
                                                 &graphics_surface_copy.rect_src,
                                                 graphics_points,
                                                 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_surface_to_surface(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_surface_copy) == LIBRDP_STATUS_OK);
    PCHECK(graphics_surface_copy.dest_points_count == 2 &&
           graphics_surface_copy.rect_src.right == 5);
    {
        rdp_graphics_surface_to_surface valid_surface_copy = graphics_surface_copy;

        PCHECK(rdp_graphics_parse_surface_to_surface(graphics_surface_to_surface,
                                                     sizeof(graphics_surface_to_surface) - 1u,
                                                     &graphics_surface_copy) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_surface_copy,
                      &valid_surface_copy,
                      sizeof(graphics_surface_copy)) == 0);
    }
    PCHECK(rdp_graphics_parse_surface_to_cache(graphics_surface_to_cache,
                                               sizeof(graphics_surface_to_cache),
                                               &graphics_surface_cache) == LIBRDP_STATUS_OK);
    PCHECK(graphics_surface_cache.surface_id == 0x1234 &&
           graphics_surface_cache.cache_key == 0x0102030405060708ull &&
           graphics_surface_cache.cache_slot == 0x42 &&
           graphics_surface_cache.rect_src.left == 1);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_surface_to_cache(&dyn_response,
                                               graphics_surface_cache.surface_id,
                                               graphics_surface_cache.cache_key,
                                               graphics_surface_cache.cache_slot,
                                               &graphics_surface_cache.rect_src) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_surface_to_cache(dyn_response.data,
                                               dyn_response.length,
                                               &graphics_surface_cache) == LIBRDP_STATUS_OK);
    PCHECK(graphics_surface_cache.cache_key == 0x0102030405060708ull);
    {
        rdp_graphics_surface_to_cache valid_surface_cache = graphics_surface_cache;

        PCHECK(rdp_graphics_parse_surface_to_cache(graphics_surface_to_cache,
                                                   sizeof(graphics_surface_to_cache) - 1u,
                                                   &graphics_surface_cache) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_surface_cache,
                      &valid_surface_cache,
                      sizeof(graphics_surface_cache)) == 0);
    }
    PCHECK(rdp_graphics_parse_cache_to_surface(graphics_cache_to_surface,
                                               sizeof(graphics_cache_to_surface),
                                               &graphics_cache_surface) == LIBRDP_STATUS_OK);
    PCHECK(graphics_cache_surface.cache_slot == 0x42 &&
           graphics_cache_surface.surface_id == 0x1234 &&
           graphics_cache_surface.dest_points_count == 2 &&
           graphics_cache_surface.dest_points_len == 8);
    PCHECK(rdp_graphics_parse_point16(graphics_cache_surface.dest_points,
                                      graphics_cache_surface.dest_points_len,
                                      &graphics_points[0]) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_point16(graphics_cache_surface.dest_points + 4,
                                      graphics_cache_surface.dest_points_len - 4u,
                                      &graphics_points[1]) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_cache_to_surface(&dyn_response,
                                               graphics_cache_surface.cache_slot,
                                               graphics_cache_surface.surface_id,
                                               graphics_points,
                                               2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_cache_to_surface(dyn_response.data,
                                               dyn_response.length,
                                               &graphics_cache_surface) == LIBRDP_STATUS_OK);
    PCHECK(graphics_cache_surface.dest_points_count == 2);
    {
        rdp_graphics_cache_to_surface valid_cache_surface = graphics_cache_surface;

        PCHECK(rdp_graphics_parse_cache_to_surface(graphics_cache_to_surface,
                                                   sizeof(graphics_cache_to_surface) - 1u,
                                                   &graphics_cache_surface) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_cache_surface,
                      &valid_cache_surface,
                      sizeof(graphics_cache_surface)) == 0);
    }
    PCHECK(rdp_graphics_parse_evict_cache_entry(graphics_evict_cache,
                                                sizeof(graphics_evict_cache),
                                                &graphics_evict) == LIBRDP_STATUS_OK);
    PCHECK(graphics_evict.cache_slot == 0x42);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_evict_cache_entry(&dyn_response, graphics_evict.cache_slot) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_evict_cache_entry(dyn_response.data,
                                                dyn_response.length,
                                                &graphics_evict) == LIBRDP_STATUS_OK);
    PCHECK(graphics_evict.cache_slot == 0x42);
    {
        rdp_graphics_evict_cache_entry valid_evict = graphics_evict;

        PCHECK(rdp_graphics_parse_evict_cache_entry(graphics_evict_cache,
                                                    sizeof(graphics_evict_cache) - 1u,
                                                    &graphics_evict) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_evict, &valid_evict, sizeof(graphics_evict)) == 0);
    }
    PCHECK(rdp_graphics_parse_delete_encoding_context(graphics_delete_context_pdu,
                                                      sizeof(graphics_delete_context_pdu),
                                                      &graphics_delete_context) == LIBRDP_STATUS_OK);
    PCHECK(graphics_delete_context.surface_id == 0x1234 &&
           graphics_delete_context.codec_context_id == 0x11223344u);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_delete_encoding_context(&dyn_response,
                                                      graphics_delete_context.surface_id,
                                                      graphics_delete_context.codec_context_id) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_delete_encoding_context(dyn_response.data,
                                                      dyn_response.length,
                                                      &graphics_delete_context) == LIBRDP_STATUS_OK);
    PCHECK(graphics_delete_context.codec_context_id == 0x11223344u);
    {
        rdp_graphics_delete_encoding_context valid_delete_context = graphics_delete_context;

        PCHECK(rdp_graphics_parse_delete_encoding_context(graphics_delete_context_pdu,
                                                          sizeof(graphics_delete_context_pdu) - 1u,
                                                          &graphics_delete_context) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_delete_context,
                      &valid_delete_context,
                      sizeof(graphics_delete_context)) == 0);
    }
    PCHECK(rdp_graphics_parse_start_frame(graphics_start_frame,
                                          sizeof(graphics_start_frame),
                                          &graphics_start) == LIBRDP_STATUS_OK);
    PCHECK(graphics_start.timestamp == 0x01020304 && graphics_start.frame_id == 0x11223344);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_start_frame(&dyn_response,
                                          graphics_start.timestamp,
                                          graphics_start.frame_id) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_start_frame(dyn_response.data,
                                          dyn_response.length,
                                          &graphics_start) == LIBRDP_STATUS_OK);
    PCHECK(graphics_start.frame_id == 0x11223344);
    {
        rdp_graphics_start_frame valid_start = graphics_start;

        PCHECK(rdp_graphics_parse_start_frame(graphics_start_frame,
                                              sizeof(graphics_start_frame) - 1u,
                                              &graphics_start) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_start, &valid_start, sizeof(graphics_start)) == 0);
    }
    PCHECK(rdp_graphics_parse_end_frame(graphics_end_frame,
                                        sizeof(graphics_end_frame),
                                        &graphics_end) == LIBRDP_STATUS_OK);
    PCHECK(graphics_end.frame_id == 0x11223344);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_end_frame(&dyn_response, graphics_end.frame_id) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_end_frame(dyn_response.data,
                                        dyn_response.length,
                                        &graphics_end) == LIBRDP_STATUS_OK);
    PCHECK(graphics_end.frame_id == 0x11223344);
    {
        rdp_graphics_end_frame valid_end = graphics_end;

        PCHECK(rdp_graphics_parse_end_frame(graphics_end_frame,
                                            sizeof(graphics_end_frame) - 1u,
                                            &graphics_end) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_end, &valid_end, sizeof(graphics_end)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_frame_ack(&dyn_response,
                                        RDP_GRAPHICS_QUEUE_DEPTH_UNAVAILABLE,
                                        graphics_end.frame_id,
                                        7) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 20 &&
           test_read_u16_le(dyn_response.data) == RDP_GRAPHICS_CMDID_FRAME_ACKNOWLEDGE &&
           test_read_u32_le(dyn_response.data + 4) == 20 &&
           test_read_u32_le(dyn_response.data + 12) == graphics_end.frame_id &&
           test_read_u32_le(dyn_response.data + 16) == 7);
    PCHECK(rdp_graphics_parse_frame_ack(dyn_response.data,
                                        dyn_response.length,
                                        &graphics_ack) == LIBRDP_STATUS_OK);
    PCHECK(graphics_ack.queue_depth == RDP_GRAPHICS_QUEUE_DEPTH_UNAVAILABLE &&
           graphics_ack.frame_id == graphics_end.frame_id &&
           graphics_ack.total_frames_decoded == 7);
    {
        rdp_graphics_frame_ack valid_ack = graphics_ack;

        PCHECK(rdp_graphics_parse_frame_ack(dyn_response.data,
                                            dyn_response.length - 1u,
                                            &graphics_ack) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_ack, &valid_ack, sizeof(graphics_ack)) == 0);
    }
    PCHECK(rdp_graphics_write_reset(&graphics_reset_pdu, 1024, 768) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_reset(graphics_reset_pdu.data,
                                    graphics_reset_pdu.length,
                                    &graphics_reset) == LIBRDP_STATUS_OK);
    PCHECK(graphics_reset.width == 1024 &&
           graphics_reset.height == 768 &&
           graphics_reset.monitor_count == 0);
    PCHECK(graphics_reset_pdu.length == 340);
    {
        rdp_graphics_reset valid_reset = graphics_reset;

        PCHECK(rdp_graphics_parse_reset(graphics_reset_pdu.data,
                                        graphics_reset_pdu.length - 1u,
                                        &graphics_reset) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_reset, &valid_reset, sizeof(graphics_reset)) == 0);
        graphics_reset_pdu.data[16] = (uint8_t)((LIBRDP_DISPLAY_MAX_MONITORS + 1u) & 0xffu);
        graphics_reset_pdu.data[17] = (uint8_t)(((LIBRDP_DISPLAY_MAX_MONITORS + 1u) >> 8u) & 0xffu);
        graphics_reset_pdu.data[18] = 0;
        graphics_reset_pdu.data[19] = 0;
        PCHECK(rdp_graphics_parse_reset(graphics_reset_pdu.data,
                                        graphics_reset_pdu.length,
                                        &graphics_reset) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_reset, &valid_reset, sizeof(graphics_reset)) == 0);
    }
    PCHECK(rdp_graphics_write_reset(&graphics_reset_pdu, 0, 768) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_clearcodec_parse_stream(clear_residual_bitmap,
                                       sizeof(clear_residual_bitmap),
                                       &clear_stream) == LIBRDP_STATUS_OK);
    PCHECK(clear_stream.flags == 0 &&
           clear_stream.seq_number == 0 &&
           clear_stream.payload_len == 16);
    PCHECK(rdp_clearcodec_parse_composite_payload(clear_stream.payload,
                                                  clear_stream.payload_len,
                                                  &clear_payload) == LIBRDP_STATUS_OK);
    PCHECK(clear_payload.residual_len == 4 &&
           clear_payload.bands_len == 0 &&
           clear_payload.subcodec_len == 0);
    {
        rdp_clearcodec_composite_payload valid_clear_payload = clear_payload;

        PCHECK(rdp_clearcodec_parse_composite_payload(clear_stream.payload,
                                                      clear_stream.payload_len - 1u,
                                                      &clear_payload) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&clear_payload,
                      &valid_clear_payload,
                      sizeof(clear_payload)) == 0);
    }
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_residual_bitmap,
                                        sizeof(clear_residual_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 &&
           clear_pixels.length == 16 &&
           clear_pixels.data[0] == 1 &&
           clear_pixels.data[1] == 2 &&
           clear_pixels.data[2] == 3 &&
           clear_pixels.data[3] == 0xff &&
           clear_pixels.data[12] == 1 &&
           clear_pixels.data[15] == 0xff);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_residual_zero_run_bitmap,
                                        sizeof(clear_residual_zero_run_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 1 &&
           clear_pixels.data[1] == 2 &&
           clear_pixels.data[2] == 3 &&
           clear_pixels.data[12] == 1 &&
           clear_pixels.data[15] == 0xff);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_parse_stream(clear_raw_subcodec_bitmap,
                                       sizeof(clear_raw_subcodec_bitmap),
                                       &clear_stream) == LIBRDP_STATUS_OK);
    PCHECK(clear_stream.seq_number == 1);
    PCHECK(rdp_clearcodec_parse_composite_payload(clear_stream.payload,
                                                  clear_stream.payload_len,
                                                  &clear_payload) == LIBRDP_STATUS_OK);
    PCHECK(clear_payload.subcodec_len == 25);
    PCHECK(rdp_clearcodec_parse_subcodec(clear_payload.subcodec,
                                         clear_payload.subcodec_len,
                                         &clear_subcodec) == LIBRDP_STATUS_OK);
    PCHECK(clear_subcodec.x == 0 &&
           clear_subcodec.y == 0 &&
           clear_subcodec.width == 2 &&
           clear_subcodec.height == 2 &&
           clear_subcodec.bitmap_data_len == 12 &&
           clear_subcodec.subcodec_id == RDP_CLEARCODEC_SUBCODEC_RAW);
    {
        rdp_clearcodec_subcodec valid_clear_subcodec = clear_subcodec;

        PCHECK(rdp_clearcodec_parse_subcodec(clear_payload.subcodec,
                                             clear_payload.subcodec_len - 1u,
                                             &clear_subcodec) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&clear_subcodec,
                      &valid_clear_subcodec,
                      sizeof(clear_subcodec)) == 0);
    }
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_raw_subcodec_bitmap,
                                        sizeof(clear_raw_subcodec_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 1 &&
           clear_pixels.data[2] == 3 &&
           clear_pixels.data[4] == 4 &&
           clear_pixels.data[6] == 6 &&
           clear_pixels.data[8] == 7 &&
           clear_pixels.data[10] == 9 &&
           clear_pixels.data[12] == 10 &&
           clear_pixels.data[14] == 12);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_parse_stream(clear_rlex_subcodec_bitmap,
                                       sizeof(clear_rlex_subcodec_bitmap),
                                       &clear_stream) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clearcodec_parse_composite_payload(clear_stream.payload,
                                                  clear_stream.payload_len,
                                                  &clear_payload) == LIBRDP_STATUS_OK);
    PCHECK(clear_payload.subcodec_len == 24);
    PCHECK(rdp_clearcodec_parse_subcodec(clear_payload.subcodec,
                                         clear_payload.subcodec_len,
                                         &clear_subcodec) == LIBRDP_STATUS_OK);
    PCHECK(clear_subcodec.subcodec_id == RDP_CLEARCODEC_SUBCODEC_RLEX &&
           clear_subcodec.bitmap_data_len == 11);
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_rlex_subcodec_bitmap,
                                        sizeof(clear_rlex_subcodec_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 1 &&
           clear_pixels.data[1] == 2 &&
           clear_pixels.data[2] == 3 &&
           clear_pixels.data[4] == 4 &&
           clear_pixels.data[5] == 5 &&
           clear_pixels.data[6] == 6 &&
           clear_pixels.data[8] == 1 &&
           clear_pixels.data[12] == 4);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_nsc_subcodec_bitmap,
                                        sizeof(clear_nsc_subcodec_bitmap),
                                        1,
                                        1,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 4 &&
           clear_pixels.data[0] == 10 &&
           clear_pixels.data[1] == 10 &&
           clear_pixels.data[2] == 10 &&
           clear_pixels.data[3] == 0xff);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_band_miss_bitmap,
                                        sizeof(clear_band_miss_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[4] == 1 &&
           clear_pixels.data[5] == 2 &&
           clear_pixels.data[6] == 3 &&
           clear_pixels.data[12] == 4 &&
           clear_pixels.data[13] == 5 &&
           clear_pixels.data[14] == 6);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_band_hit_bitmap,
                                        sizeof(clear_band_hit_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 1 &&
           clear_pixels.data[1] == 2 &&
           clear_pixels.data[2] == 3 &&
           clear_pixels.data[8] == 4 &&
           clear_pixels.data[9] == 5 &&
           clear_pixels.data[10] == 6);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_missing_band_bitmap,
                                        sizeof(clear_missing_band_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.length == 16 &&
           clear_pixels.data[0] == 0 &&
           clear_pixels.data[8] == 0);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_glyph_store_bitmap,
                                        sizeof(clear_glyph_store_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 9 &&
           clear_pixels.data[1] == 8 &&
           clear_pixels.data[2] == 7 &&
           clear_pixels.data[15] == 0xff);
    PCHECK(rdp_clearcodec_parse_stream(clear_glyph_hit,
                                       sizeof(clear_glyph_hit),
                                       &clear_stream) == LIBRDP_STATUS_OK);
    PCHECK((clear_stream.flags & RDP_CLEARCODEC_FLAG_GLYPH_HIT) != 0 &&
           clear_stream.has_glyph_index &&
           clear_stream.payload_len == 0);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_glyph_hit,
                                        sizeof(clear_glyph_hit),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 9 &&
           clear_pixels.data[2] == 7 &&
           clear_pixels.data[12] == 9 &&
           clear_pixels.data[15] == 0xff);
    clear_saved_len = clear_pixels.length;
    PCHECK(clear_saved_len <= sizeof(clear_saved));
    memcpy(clear_saved, clear_pixels.data, clear_saved_len);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_glyph_hit,
                                        sizeof(clear_glyph_hit),
                                        2,
                                        1,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.length == 8 &&
           clear_pixels.data[0] == 9 &&
           clear_pixels.data[2] == 7 &&
           clear_pixels.data[7] == 0xff);
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_glyph_hit_after_reset,
                                        sizeof(clear_glyph_hit_after_reset),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_glyph_hit,
                                        sizeof(clear_glyph_hit),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.length == clear_saved_len &&
           memcmp(clear_pixels.data, clear_saved, clear_saved_len) == 0);
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_missing_glyph_hit,
                                        sizeof(clear_missing_glyph_hit),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_clearcodec_parse_stream(clear_max_glyph_hit,
                                       sizeof(clear_max_glyph_hit),
                                       &clear_stream) == LIBRDP_STATUS_OK);
    PCHECK(clear_stream.glyph_index == RDP_CLEARCODEC_GLYPH_STORAGE_ENTRIES - 1u);
    {
        rdp_clearcodec_stream valid_clear_stream = clear_stream;

        PCHECK(rdp_clearcodec_parse_stream(clear_bad_glyph_hit,
                                           sizeof(clear_bad_glyph_hit),
                                           &clear_stream) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&clear_stream, &valid_clear_stream, sizeof(clear_stream)) == 0);
    }
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_empty_payload,
                                        sizeof(clear_empty_payload),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_unknown_subcodec_bitmap,
                                        sizeof(clear_unknown_subcodec_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(clear_pixels.length == clear_saved_len &&
           memcmp(clear_pixels.data, clear_saved, clear_saved_len) == 0);

    rdp_buffer_free(&dyn_response);
    rdp_clearcodec_context_free(&clear_context);
    rdp_graphics_decompressor_free(&graphics_decompressor);
    rdp_buffer_free(&graphics_reset_pdu);
    rdp_buffer_free(&graphics_decoded);
    rdp_buffer_free(&clear_pixels);
    return 0;
}
