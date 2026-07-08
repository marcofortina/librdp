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

rdp_avc_decoder* rdp_avc_decoder_new(void);
void rdp_avc_decoder_reset(rdp_avc_decoder* decoder);
void rdp_avc_decoder_free(rdp_avc_decoder* decoder);
void rdp_avc_frame_init(rdp_avc_frame* frame);
void rdp_avc_frame_free(rdp_avc_frame* frame);
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
