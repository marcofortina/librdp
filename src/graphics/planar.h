/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: planar bitmap decoder declaration contract.
 * Invariants: rectangles, strides, codec payload lengths, and cache
 * identifiers must be validated before pixel mutation.
 * Ownership: decoded pixel buffers, cache entries, and surfaces are owned by
 * the caller selected by each API.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: codec payloads, rectangles, and cache references are
 * untrusted server data.
 */


#ifndef RDP_GRAPHICS_PLANAR_H
#define RDP_GRAPHICS_PLANAR_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_PLANAR_FORMAT_CLL_MASK 0x07u
#define RDP_PLANAR_FORMAT_CHROMA_SUBSAMPLING 0x08u
#define RDP_PLANAR_FORMAT_RLE 0x10u
#define RDP_PLANAR_FORMAT_NO_ALPHA 0x20u
#define RDP_PLANAR_FORMAT_RESERVED_MASK 0xc0u

librdp_status rdp_planar_decode_argb(const void* data,
                                     size_t length,
                                     uint32_t width,
                                     uint32_t height,
                                     rdp_buffer* pixels,
                                     size_t* stride);

#endif
