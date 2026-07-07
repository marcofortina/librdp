#include "channels/graphics_pipeline.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_graphics_header header;
    rdp_graphics_capset capset;
    rdp_graphics_caps_confirm confirm;
    rdp_graphics_decompressor decompressor;
    rdp_buffer output;

    rdp_graphics_decompressor_init(&decompressor);
    rdp_buffer_init(&output);
    (void)rdp_graphics_parse_header(data, size, &header);
    (void)rdp_graphics_parse_capset(data, size, &capset);
    (void)rdp_graphics_parse_caps_confirm(data, size, &confirm);
    (void)rdp_graphics_decode_segmented_data(&decompressor, data, size, &output);
    output.length = 0;
    (void)rdp_graphics_write_default_caps_advertise(&output);
    rdp_buffer_free(&output);
    rdp_graphics_decompressor_free(&decompressor);
    return 0;
}
