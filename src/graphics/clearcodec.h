#ifndef RDP_GRAPHICS_CLEARCODEC_H
#define RDP_GRAPHICS_CLEARCODEC_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_CLEARCODEC_FLAG_GLYPH_INDEX 0x01u
#define RDP_CLEARCODEC_FLAG_GLYPH_HIT 0x02u
#define RDP_CLEARCODEC_FLAG_CACHE_RESET 0x04u
#define RDP_CLEARCODEC_SUBCODEC_RAW 0x00u
#define RDP_CLEARCODEC_SUBCODEC_NSCODEC 0x01u
#define RDP_CLEARCODEC_SUBCODEC_RLEX 0x02u

typedef struct rdp_clearcodec_stream
{
    uint8_t flags;
    uint8_t seq_number;
    uint8_t has_glyph_index;
    uint16_t glyph_index;
    const uint8_t* payload;
    size_t payload_len;
} rdp_clearcodec_stream;

typedef struct rdp_clearcodec_composite_payload
{
    uint32_t residual_len;
    uint32_t bands_len;
    uint32_t subcodec_len;
    const uint8_t* residual;
    const uint8_t* bands;
    const uint8_t* subcodec;
} rdp_clearcodec_composite_payload;

typedef struct rdp_clearcodec_subcodec
{
    uint16_t x;
    uint16_t y;
    uint16_t width;
    uint16_t height;
    uint32_t bitmap_data_len;
    uint8_t subcodec_id;
    const uint8_t* bitmap_data;
    size_t total_len;
} rdp_clearcodec_subcodec;

librdp_status rdp_clearcodec_parse_stream(const void* data, size_t length, rdp_clearcodec_stream* stream);
librdp_status rdp_clearcodec_parse_composite_payload(const void* data,
                                                     size_t length,
                                                     rdp_clearcodec_composite_payload* payload);
librdp_status rdp_clearcodec_parse_subcodec(const void* data,
                                            size_t length,
                                            rdp_clearcodec_subcodec* subcodec);
librdp_status rdp_clearcodec_decode_bitmap(const void* data,
                                           size_t length,
                                           uint16_t width,
                                           uint16_t height,
                                           rdp_buffer* pixels,
                                           size_t* stride);

#endif
