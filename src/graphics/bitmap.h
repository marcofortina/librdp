#ifndef RDP_GRAPHICS_BITMAP_H
#define RDP_GRAPHICS_BITMAP_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_BITMAP_MAX_RECTS 64u
#define RDP_UPDATE_TYPE_BITMAP 0x0001u

typedef struct rdp_bitmap_rect
{
    uint16_t dest_left;
    uint16_t dest_top;
    uint16_t dest_right;
    uint16_t dest_bottom;
    uint16_t width;
    uint16_t height;
    uint16_t bits_per_pixel;
    uint16_t flags;
    const uint8_t* data;
    uint32_t data_len;
} rdp_bitmap_rect;

typedef struct rdp_bitmap_update
{
    uint16_t count;
    rdp_bitmap_rect rects[RDP_BITMAP_MAX_RECTS];
} rdp_bitmap_update;

typedef struct rdp_bitmap_update_header
{
    uint16_t update_type;
    uint16_t count;
} rdp_bitmap_update_header;

librdp_status rdp_bitmap_parse_update_header(const void* data, size_t length, rdp_bitmap_update_header* header);
librdp_status rdp_bitmap_parse_update(const void* data, size_t length, rdp_bitmap_update* update);
librdp_status rdp_bitmap_parse_fastpath_update(const void* data, size_t length, rdp_bitmap_update* update);
librdp_status rdp_bitmap_decode_rect_bgra32(const rdp_bitmap_rect* rect, rdp_buffer* output, size_t* stride);

#endif
