/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: NSCodec decoder declaration contract.
 * Invariants: rectangles, strides, codec payload lengths, and cache
 * identifiers must be validated before pixel mutation.
 * Ownership: decoded pixel buffers, cache entries, and surfaces are owned by
 * the caller selected by each API.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: codec payloads, rectangles, and cache references are
 * untrusted server data.
 */


#ifndef RDP_GRAPHICS_NSCODEC_H
#define RDP_GRAPHICS_NSCODEC_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_NSCODEC_CAPABILITY_LENGTH 3u
#define RDP_NSCODEC_BITMAP_CODEC_ID 0x01u
#define RDP_NSCODEC_STREAM_HEADER_LENGTH 20u
#define RDP_NSCODEC_GUID_LENGTH 16u
#define RDP_NSCODEC_MAX_DIMENSION 8192u
#define RDP_NSCODEC_GUID_BYTES                                                                                         \
    {                                                                                                                   \
        0xb9, 0x1b, 0x8d, 0xca, 0x0f, 0x00, 0x4f, 0x15, 0x58, 0x9f, 0xae, 0x2d, 0x1a, 0x87, 0xe2, 0xd6                \
    }

typedef struct rdp_nscodec_capability
{
    uint8_t allow_dynamic_fidelity;
    uint8_t allow_subsampling;
    uint8_t color_loss_level;
} rdp_nscodec_capability;

typedef struct rdp_nscodec_stream
{
    uint32_t luma_len;
    uint32_t orange_chroma_len;
    uint32_t green_chroma_len;
    uint32_t alpha_len;
    uint8_t color_loss_level;
    uint8_t chroma_subsampling_level;
    const uint8_t* luma;
    const uint8_t* orange_chroma;
    const uint8_t* green_chroma;
    const uint8_t* alpha;
    size_t luma_width;
    size_t luma_height;
    size_t chroma_width;
    size_t chroma_height;
    size_t alpha_width;
    size_t alpha_height;
} rdp_nscodec_stream;

typedef struct rdp_nscodec_context
{
    uint8_t* planes[4];
    size_t plane_capacity;
} rdp_nscodec_context;

void rdp_nscodec_context_init(rdp_nscodec_context* context);
void rdp_nscodec_context_reset(rdp_nscodec_context* context);
void rdp_nscodec_context_free(rdp_nscodec_context* context);
librdp_status rdp_nscodec_parse_capability(const void* data, size_t length, rdp_nscodec_capability* capability);
librdp_status rdp_nscodec_write_capability(rdp_buffer* buffer, const rdp_nscodec_capability* capability);
librdp_status rdp_nscodec_parse_stream(const void* data,
                                       size_t length,
                                       uint32_t width,
                                       uint32_t height,
                                       rdp_nscodec_stream* stream);
librdp_status rdp_nscodec_decode_rle_plane(const uint8_t* input,
                                           size_t input_len,
                                           uint8_t* output,
                                           size_t output_len);
librdp_status rdp_nscodec_decode_bgra32(rdp_nscodec_context* context,
                                        const void* data,
                                        size_t length,
                                        uint32_t width,
                                        uint32_t height,
                                        rdp_buffer* pixels,
                                        size_t* stride);
librdp_status rdp_nscodec_decode_region_bgra32(rdp_nscodec_context* context,
                                               const void* data,
                                               size_t length,
                                               uint32_t width,
                                               uint32_t height,
                                               uint8_t* dest,
                                               size_t dest_stride,
                                               uint32_t dest_x,
                                               uint32_t dest_y,
                                               uint32_t dest_width,
                                               uint32_t dest_height);

#endif
