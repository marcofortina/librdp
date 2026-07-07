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
    rdp_graphics_map_surface_to_scaled_output scaled_map;
    rdp_graphics_point16 point;
    rdp_graphics_rect16 rect;
    rdp_graphics_solid_fill solid_fill;
    rdp_graphics_wire_to_surface_1 wire1;
    rdp_graphics_wire_to_surface_2 wire2;
    rdp_graphics_surface_to_surface surface_to_surface;
    rdp_graphics_surface_to_cache surface_to_cache;
    rdp_graphics_cache_to_surface cache_to_surface;
    rdp_graphics_evict_cache_entry evict;
    rdp_graphics_delete_encoding_context delete_context;
    rdp_graphics_start_frame start_frame;
    rdp_graphics_end_frame end_frame;
    rdp_graphics_decompressor decompressor;
    rdp_graphics_progressive_block progressive_block;
    rdp_graphics_progressive_context progressive_context;
    rdp_graphics_progressive_frame_begin progressive_frame_begin;
    rdp_graphics_progressive_region progressive_region;
    rdp_graphics_progressive_tile_simple progressive_simple;
    rdp_graphics_progressive_tile_first progressive_first;
    rdp_graphics_progressive_tile_upgrade progressive_upgrade;
    rdp_graphics_progressive_stream progressive_stream;
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
    (void)rdp_graphics_parse_map_surface_to_scaled_output(data, size, &scaled_map);
    (void)rdp_graphics_parse_point16(data, size, &point);
    (void)rdp_graphics_parse_rect16(data, size, &rect);
    (void)rdp_graphics_parse_solid_fill(data, size, &solid_fill);
    (void)rdp_graphics_parse_wire_to_surface_1(data, size, &wire1);
    (void)rdp_graphics_parse_wire_to_surface_2(data, size, &wire2);
    (void)rdp_graphics_parse_surface_to_surface(data, size, &surface_to_surface);
    (void)rdp_graphics_parse_surface_to_cache(data, size, &surface_to_cache);
    (void)rdp_graphics_parse_cache_to_surface(data, size, &cache_to_surface);
    (void)rdp_graphics_parse_evict_cache_entry(data, size, &evict);
    (void)rdp_graphics_parse_delete_encoding_context(data, size, &delete_context);
    (void)rdp_graphics_parse_start_frame(data, size, &start_frame);
    (void)rdp_graphics_parse_end_frame(data, size, &end_frame);
    (void)rdp_graphics_progressive_parse_block(data, size, &progressive_block);
    (void)rdp_graphics_progressive_parse_context(data, size, &progressive_context);
    (void)rdp_graphics_progressive_parse_frame_begin(data, size, &progressive_frame_begin);
    (void)rdp_graphics_progressive_parse_frame_end(data, size);
    (void)rdp_graphics_progressive_parse_region(data, size, &progressive_region);
    (void)rdp_graphics_progressive_parse_tile_simple(data, size, &progressive_simple);
    (void)rdp_graphics_progressive_parse_tile_first(data, size, &progressive_first);
    (void)rdp_graphics_progressive_parse_tile_upgrade(data, size, &progressive_upgrade);
    (void)rdp_graphics_progressive_parse_stream(data, size, &progressive_stream);
    (void)rdp_graphics_decode_segmented_data(&decompressor, data, size, &output);
    output.length = 0;
    (void)rdp_graphics_write_default_caps_advertise(&output);
    output.length = 0;
    (void)rdp_graphics_write_frame_ack(&output, RDP_GRAPHICS_QUEUE_DEPTH_UNAVAILABLE, 1, 1);
    rdp_buffer_free(&output);
    rdp_graphics_decompressor_free(&decompressor);
    return 0;
}
