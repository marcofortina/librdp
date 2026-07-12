/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: RemoteFX stream parser declaration contract.
 * Invariants: rectangles, strides, codec payload lengths, and cache
 * identifiers must be validated before pixel mutation.
 * Ownership: decoded pixel buffers, cache entries, and surfaces are owned by
 * the caller selected by each API.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: codec payloads, rectangles, and cache references are
 * untrusted server data.
 */


#ifndef RDP_GRAPHICS_RFX_STREAM_H
#define RDP_GRAPHICS_RFX_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "graphics/rfx_codec.h"

#define RDP_RFX_STREAM_MAX_QUANTS 64u
#define RDP_RFX_STREAM_MAX_TILES 4096u
#define RDP_RFX_STREAM_TILE_SIZE 64u

typedef struct rdp_rfx_stream_tile
{
    uint16_t x_idx;
    uint16_t y_idx;
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
    rdp_rfx_tile_pixels pixels;
} rdp_rfx_stream_tile;

typedef struct rdp_rfx_stream_summary
{
    uint32_t frame_id;
    uint16_t width;
    uint16_t height;
    uint16_t region_count;
    uint16_t rect_count;
    uint16_t tile_count;
    rdp_rfx_rlgr_mode mode;
    uint8_t sync_seen;
    uint8_t codec_versions_seen;
    uint8_t channels_seen;
    uint8_t context_seen;
    uint8_t frame_end_seen;
} rdp_rfx_stream_summary;

typedef librdp_status (*rdp_rfx_stream_tile_callback)(const rdp_rfx_stream_tile* tile, void* user);

librdp_status rdp_rfx_stream_decode(const void* data,
                                    size_t length,
                                    rdp_rfx_stream_tile_callback callback,
                                    void* user,
                                    rdp_rfx_stream_summary* summary);

#endif
