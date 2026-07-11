/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef RDP_GRAPHICS_BITMAP_H
#define RDP_GRAPHICS_BITMAP_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_BITMAP_MAX_RECTS 64u
#define RDP_BITMAP_PALETTE_MAX_ENTRIES 256u
#define RDP_UPDATE_TYPE_BITMAP 0x0001u
#define RDP_UPDATE_TYPE_PALETTE 0x0002u

typedef struct rdp_palette_entry
{
    uint8_t red;
    uint8_t green;
    uint8_t blue;
} rdp_palette_entry;

typedef struct rdp_palette_update
{
    uint32_t count;
    rdp_palette_entry entries[RDP_BITMAP_PALETTE_MAX_ENTRIES];
} rdp_palette_update;

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
librdp_status rdp_bitmap_parse_palette_update(const void* data, size_t length, rdp_palette_update* palette);
librdp_status rdp_bitmap_parse_fastpath_palette_update(const void* data, size_t length, rdp_palette_update* palette);
librdp_status rdp_bitmap_write_rect(rdp_buffer* buffer, const rdp_bitmap_rect* rect);
librdp_status rdp_bitmap_write_update(rdp_buffer* buffer, const rdp_bitmap_rect* rects, uint16_t count);
librdp_status rdp_bitmap_write_fastpath_update(rdp_buffer* buffer, const rdp_bitmap_rect* rects, uint16_t count);
librdp_status rdp_bitmap_write_palette_update(rdp_buffer* buffer, const rdp_palette_update* palette);
librdp_status rdp_bitmap_write_fastpath_palette_update(rdp_buffer* buffer, const rdp_palette_update* palette);
librdp_status rdp_bitmap_decode_rect_bgra32(const rdp_bitmap_rect* rect, rdp_buffer* output, size_t* stride);
librdp_status rdp_bitmap_decode_rect_bgra32_with_palette(const rdp_bitmap_rect* rect,
                                                         const rdp_palette_update* palette,
                                                         rdp_buffer* output,
                                                         size_t* stride);

#endif
