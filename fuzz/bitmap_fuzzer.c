#include "graphics/bitmap.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_bitmap_update update;
    rdp_bitmap_update_header header;
    rdp_buffer decoded;
    size_t stride = 0;
    uint16_t i = 0;

    rdp_buffer_init(&decoded);
    (void)rdp_bitmap_parse_update_header(data, size, &header);
    if (rdp_bitmap_parse_update(data, size, &update) == LIBRDP_STATUS_OK)
    {
        for (i = 0; i < update.count; i++)
            (void)rdp_bitmap_decode_rect_bgra32(&update.rects[i], &decoded, &stride);
    }
    if (rdp_bitmap_parse_fastpath_update(data, size, &update) == LIBRDP_STATUS_OK)
    {
        for (i = 0; i < update.count; i++)
            (void)rdp_bitmap_decode_rect_bgra32(&update.rects[i], &decoded, &stride);
    }
    rdp_buffer_free(&decoded);
    return 0;
}
