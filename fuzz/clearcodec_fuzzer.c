#include "graphics/clearcodec.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_clearcodec_stream stream;
    rdp_clearcodec_composite_payload payload;
    rdp_clearcodec_subcodec subcodec;
    rdp_clearcodec_context context;
    rdp_buffer pixels;
    size_t stride = 0;
    uint16_t width = (uint16_t)((size % 64u) + 1u);
    uint16_t height = (uint16_t)(((size / 64u) % 64u) + 1u);

    rdp_clearcodec_context_init(&context);
    rdp_buffer_init(&pixels);
    (void)rdp_clearcodec_parse_stream(data, size, &stream);
    (void)rdp_clearcodec_parse_composite_payload(data, size, &payload);
    (void)rdp_clearcodec_parse_subcodec(data, size, &subcodec);
    (void)rdp_clearcodec_decode_bitmap(&context, data, size, width, height, &pixels, &stride);
    rdp_buffer_free(&pixels);
    rdp_clearcodec_context_free(&context);
    return 0;
}
