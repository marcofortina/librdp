#include "graphics/bitmap.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_bitmap_update update;

    (void)rdp_bitmap_parse_update(data, size, &update);
    return 0;
}
