#include "channels/graphics_pipeline.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_graphics_header header;
    rdp_graphics_capset capset;
    rdp_graphics_caps_confirm confirm;
    rdp_graphics_create_surface create_surface;
    rdp_graphics_delete_surface delete_surface;
    rdp_graphics_reset reset;
    rdp_graphics_map_surface_to_output map;
    rdp_graphics_start_frame start_frame;
    rdp_graphics_end_frame end_frame;
    rdp_graphics_decompressor decompressor;
    rdp_buffer output;

    rdp_graphics_decompressor_init(&decompressor);
    rdp_buffer_init(&output);
    (void)rdp_graphics_parse_header(data, size, &header);
    (void)rdp_graphics_parse_capset(data, size, &capset);
    (void)rdp_graphics_parse_caps_confirm(data, size, &confirm);
    (void)rdp_graphics_parse_create_surface(data, size, &create_surface);
    (void)rdp_graphics_parse_delete_surface(data, size, &delete_surface);
    (void)rdp_graphics_parse_reset(data, size, &reset);
    (void)rdp_graphics_parse_map_surface_to_output(data, size, &map);
    (void)rdp_graphics_parse_start_frame(data, size, &start_frame);
    (void)rdp_graphics_parse_end_frame(data, size, &end_frame);
    (void)rdp_graphics_decode_segmented_data(&decompressor, data, size, &output);
    output.length = 0;
    (void)rdp_graphics_write_default_caps_advertise(&output);
    output.length = 0;
    (void)rdp_graphics_write_frame_ack(&output, RDP_GRAPHICS_QUEUE_DEPTH_UNAVAILABLE, 1, 1);
    rdp_buffer_free(&output);
    rdp_graphics_decompressor_free(&decompressor);
    return 0;
}
