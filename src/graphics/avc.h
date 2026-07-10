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
librdp_status rdp_avc_reconstruct_444_chroma(const rdp_avc_444_chroma_view* view);
librdp_status rdp_avc_reconstruct_444v2_chroma(const rdp_avc_444v2_chroma_view* view);
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
