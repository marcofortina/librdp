/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: AVC graphics codec declaration contract.
 * Invariants: rectangles, strides, codec payload lengths, and cache
 * identifiers must be validated before pixel mutation.
 * Ownership: decoded pixel buffers, cache entries, and surfaces are owned by
 * the caller selected by each API.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: codec payloads, rectangles, and cache references are
 * untrusted server data.
 */


#ifndef RDP_GRAPHICS_AVC_H
#define RDP_GRAPHICS_AVC_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "channels/graphics_pipeline.h"
#include "common/buffer.h"

typedef struct rdp_avc_decoder rdp_avc_decoder;

typedef struct rdp_avc_frame
{
    rdp_buffer pixels;
    uint32_t width;
    uint32_t height;
    size_t stride;
} rdp_avc_frame;

typedef struct rdp_avc_444_chroma_view
{
    const uint8_t* aux_y;
    size_t aux_y_stride;
    const uint8_t* aux_u;
    size_t aux_u_stride;
    const uint8_t* aux_v;
    size_t aux_v_stride;
    uint32_t aux_width;
    uint32_t aux_height;
    rdp_graphics_rect16 rect;
    uint8_t* dst_u;
    size_t dst_u_stride;
    uint8_t* dst_v;
    size_t dst_v_stride;
    uint32_t dst_width;
    uint32_t dst_height;
} rdp_avc_444_chroma_view;

typedef struct rdp_avc_444v2_chroma_view
{
    const uint8_t* aux_y;
    size_t aux_y_stride;
    const uint8_t* aux_u;
    size_t aux_u_stride;
    const uint8_t* aux_v;
    size_t aux_v_stride;
    uint32_t aux_width;
    uint32_t aux_height;
    rdp_graphics_rect16 rect;
    uint8_t* dst_u;
    size_t dst_u_stride;
    uint8_t* dst_v;
    size_t dst_v_stride;
    uint32_t dst_width;
    uint32_t dst_height;
} rdp_avc_444v2_chroma_view;

rdp_avc_decoder* rdp_avc_decoder_new(void);
void rdp_avc_decoder_reset(rdp_avc_decoder* decoder);
void rdp_avc_decoder_free(rdp_avc_decoder* decoder);
void rdp_avc_frame_init(rdp_avc_frame* frame);
void rdp_avc_frame_free(rdp_avc_frame* frame);
uint32_t rdp_avc_runtime_support(void);
librdp_status rdp_avc_reconstruct_444_chroma(const rdp_avc_444_chroma_view* view);
librdp_status rdp_avc_reconstruct_444v2_chroma(const rdp_avc_444v2_chroma_view* view);
#if defined(RDP_HAVE_FFMPEG_AVC) || defined(RDP_HAVE_OPENH264_AVC)
librdp_status rdp_avc_yuv444_planes_to_bgra(const uint8_t* y_plane,
                                            size_t y_stride,
                                            const uint8_t* u_plane,
                                            size_t u_stride,
                                            const uint8_t* v_plane,
                                            size_t v_stride,
                                            uint32_t width,
                                            uint32_t height,
                                            uint8_t avc444_correction,
                                            rdp_avc_frame* frame);
#endif
librdp_status rdp_avc_decode_420(rdp_avc_decoder* decoder,
                                 const rdp_graphics_avc420_stream* stream,
                                 uint32_t surface_width,
                                 uint32_t surface_height,
                                 rdp_avc_frame* frame);
librdp_status rdp_avc_decode_444(rdp_avc_decoder* decoder,
                                 uint16_t codec_id,
                                 const rdp_graphics_avc444_stream* stream,
                                 uint32_t surface_width,
                                 uint32_t surface_height,
                                 rdp_avc_frame* frame);

#endif
