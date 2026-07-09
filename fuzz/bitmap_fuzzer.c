#include "graphics/bitmap.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_bitmap_update update;
    rdp_bitmap_update_header header;
    rdp_buffer decoded;
    rdp_buffer encoded;
    rdp_bitmap_rect rect;
    size_t bounded = size < 64u ? size : 64u;
    size_t stride = 0;
    uint16_t i = 0;

    rdp_buffer_init(&decoded);
    rdp_buffer_init(&encoded);
    (void)rdp_bitmap_parse_update_header(data, size, &header);
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
            (void)rdp_bitmap_decode_rect_bgra32(&update.rects[i], &decoded, &stride);
    }
    if (rdp_bitmap_parse_fastpath_update(data, size, &update) == LIBRDP_STATUS_OK)
    {
        for (i = 0; i < update.count; i++)
            (void)rdp_bitmap_decode_rect_bgra32(&update.rects[i], &decoded, &stride);
    }
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
    rdp_buffer_free(&decoded);
    rdp_buffer_free(&encoded);
    return 0;
}
