#include "graphics/planar.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_buffer pixels;
    size_t stride = 0;
    uint32_t width = size > 0 ? (uint32_t)(data[0] % 32u) + 1u : 1u;
    uint32_t height = size > 1 ? (uint32_t)(data[1] % 32u) + 1u : 1u;

    rdp_buffer_init(&pixels);
    (void)rdp_planar_decode_argb(data, size, width, height, &pixels, &stride);
    rdp_buffer_free(&pixels);
    return 0;
}
