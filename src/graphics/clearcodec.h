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
#define RDP_CLEARCODEC_VBAR_STORAGE_ENTRIES 32768u
#define RDP_CLEARCODEC_SHORT_VBAR_STORAGE_ENTRIES 16384u
#define RDP_CLEARCODEC_GLYPH_STORAGE_ENTRIES 4000u
#define RDP_CLEARCODEC_MAX_BAND_HEIGHT 52u

typedef struct rdp_clearcodec_glyph
{
    size_t pixel_count;
    rdp_buffer pixels;
} rdp_clearcodec_glyph;

typedef struct rdp_clearcodec_context
{
    uint8_t* vbar_storage;
    uint8_t* short_vbar_storage;
    uint8_t* vbar_lengths;
    uint8_t* short_vbar_lengths;
    uint16_t vbar_cursor;
    uint16_t short_vbar_cursor;
    uint8_t* nsc_planes[4];
    size_t nsc_plane_capacity;
    rdp_clearcodec_glyph glyphs[RDP_CLEARCODEC_GLYPH_STORAGE_ENTRIES];
} rdp_clearcodec_context;

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

void rdp_clearcodec_context_init(rdp_clearcodec_context* context);
void rdp_clearcodec_context_reset(rdp_clearcodec_context* context);
void rdp_clearcodec_context_free(rdp_clearcodec_context* context);
librdp_status rdp_clearcodec_parse_stream(const void* data, size_t length, rdp_clearcodec_stream* stream);
librdp_status rdp_clearcodec_parse_composite_payload(const void* data,
                                                     size_t length,
                                                     rdp_clearcodec_composite_payload* payload);
librdp_status rdp_clearcodec_parse_subcodec(const void* data,
                                            size_t length,
                                            rdp_clearcodec_subcodec* subcodec);
librdp_status rdp_clearcodec_decode_bitmap(rdp_clearcodec_context* context,
                                           const void* data,
                                           size_t length,
                                           uint16_t width,
                                           uint16_t height,
                                           rdp_buffer* pixels,
                                           size_t* stride);

#endif
