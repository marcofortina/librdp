#include "graphics/bitmap.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_bitmap_update update;
    rdp_bitmap_update_header header;

    (void)rdp_bitmap_parse_update_header(data, size, &header);
    (void)rdp_bitmap_parse_update(data, size, &update);
    (void)rdp_bitmap_parse_fastpath_update(data, size, &update);
    return 0;
}
