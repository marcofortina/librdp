/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for bitmap update, palette, and RLE decoder paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "graphics/bitmap.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Fuzz target: exercises bitmap update, palette, and RLE decoder paths with
 * one arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_bitmap_update update;
    rdp_bitmap_update_header header;
    rdp_palette_update palette;
    rdp_buffer decoded;
    rdp_buffer encoded;
    rdp_bitmap_rect rect;
    size_t bounded = size < 64u ? size : 64u;
    size_t stride = 0;
    uint16_t i = 0;

    rdp_buffer_init(&decoded);
    rdp_buffer_init(&encoded);
    memset(&palette, 0, sizeof(palette));
    (void)rdp_bitmap_parse_update_header(data, size, &header);
    if (rdp_bitmap_parse_palette_update(data, size, &palette) == LIBRDP_STATUS_OK)
    {
        (void)rdp_bitmap_write_palette_update(&encoded, &palette);
        encoded.length = 0;
    }
    if (rdp_bitmap_parse_fastpath_palette_update(data, size, &palette) == LIBRDP_STATUS_OK)
    {
        (void)rdp_bitmap_write_fastpath_palette_update(&encoded, &palette);
        encoded.length = 0;
    }
    if (rdp_bitmap_parse_update(data, size, &update) == LIBRDP_STATUS_OK)
    {
        (void)rdp_bitmap_write_update(&encoded, update.rects, update.count);
        encoded.length = 0;
        (void)rdp_bitmap_write_fastpath_update(&encoded, update.rects, update.count);
        encoded.length = 0;
        if (update.count > 0)
            (void)rdp_bitmap_write_rect(&encoded, &update.rects[0]);
        encoded.length = 0;
        for (i = 0; i < update.count; i++)
        {
            (void)rdp_bitmap_decode_rect_bgra32(&update.rects[i], &decoded, &stride);
            (void)rdp_bitmap_decode_rect_bgra32_with_palette(&update.rects[i], &palette, &decoded, &stride);
        }
    }
    if (rdp_bitmap_parse_fastpath_update(data, size, &update) == LIBRDP_STATUS_OK)
    {
        for (i = 0; i < update.count; i++)
        {
            (void)rdp_bitmap_decode_rect_bgra32(&update.rects[i], &decoded, &stride);
            (void)rdp_bitmap_decode_rect_bgra32_with_palette(&update.rects[i], &palette, &decoded, &stride);
        }
    }
    palette.count = 1;
    palette.entries[0].red = 1;
    palette.entries[0].green = 2;
    palette.entries[0].blue = 3;
    rect.dest_left = 0;
    rect.dest_top = 0;
    rect.dest_right = 0;
    rect.dest_bottom = 0;
    rect.width = 1;
    rect.height = 1;
    rect.bits_per_pixel = 32;
    rect.flags = 0;
    rect.data = data;
    rect.data_len = (uint32_t)bounded;
    (void)rdp_bitmap_write_update(&encoded, &rect, 1);
    encoded.length = 0;
    (void)rdp_bitmap_write_fastpath_update(&encoded, &rect, 1);
    encoded.length = 0;
    rect.bits_per_pixel = 8;
    (void)rdp_bitmap_decode_rect_bgra32_with_palette(&rect, &palette, &decoded, &stride);
    rdp_buffer_free(&decoded);
    rdp_buffer_free(&encoded);
    return 0;
}
