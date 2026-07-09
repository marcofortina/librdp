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
    rdp_graphics_frame_ack frame_ack;
    rdp_graphics_decompressor decompressor;
    rdp_graphics_progressive_block progressive_block;
    rdp_graphics_progressive_context progressive_context;
    rdp_graphics_progressive_frame_begin progressive_frame_begin;
    rdp_graphics_progressive_region progressive_region;
    rdp_graphics_progressive_tile_simple progressive_simple;
    rdp_graphics_progressive_tile_first progressive_first;
    rdp_graphics_progressive_tile_upgrade progressive_upgrade;
    rdp_graphics_progressive_stream progressive_stream;
    rdp_graphics_avc420_quant_quality avc_quant;
    rdp_graphics_avc420_metablock avc_meta;
    rdp_graphics_avc420_stream avc420;
    rdp_graphics_avc444_stream avc444;
    rdp_graphics_rect16 valid_rect = {0, 0, 16, 16};
    rdp_graphics_point16 valid_points[2] = {{0, 0}, {16, 16}};
    const uint8_t progressive_rect[] = {0, 0, 0, 0, 64, 0, 64, 0};
    const uint8_t progressive_quant[] = {0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t progressive_quality[] = {
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15
    };
    rdp_graphics_progressive_context valid_progressive_context = {
        0,
        RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE,
        0
    };
    rdp_graphics_progressive_frame_begin valid_progressive_frame = {1, 1};
    rdp_graphics_progressive_region valid_progressive_region = {
        RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE,
        1,
        1,
        1,
        0,
        0,
        0,
        progressive_rect,
        sizeof(progressive_rect),
        progressive_quant,
        sizeof(progressive_quant),
        progressive_quality,
        sizeof(progressive_quality),
        NULL,
        0
    };
    rdp_graphics_progressive_tile_simple valid_simple_tile;
    rdp_graphics_progressive_tile_first valid_first_tile;
    rdp_graphics_progressive_tile_upgrade valid_upgrade_tile;
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
    (void)rdp_graphics_parse_frame_ack(data, size, &frame_ack);
    (void)rdp_graphics_progressive_parse_block(data, size, &progressive_block);
    (void)rdp_graphics_progressive_parse_context(data, size, &progressive_context);
    (void)rdp_graphics_progressive_parse_frame_begin(data, size, &progressive_frame_begin);
    (void)rdp_graphics_progressive_parse_frame_end(data, size);
    (void)rdp_graphics_progressive_parse_region(data, size, &progressive_region);
    (void)rdp_graphics_progressive_parse_tile_simple(data, size, &progressive_simple);
    (void)rdp_graphics_progressive_parse_tile_first(data, size, &progressive_first);
    (void)rdp_graphics_progressive_parse_tile_upgrade(data, size, &progressive_upgrade);
    (void)rdp_graphics_progressive_parse_stream(data, size, &progressive_stream);
    (void)rdp_graphics_parse_avc420_quant_quality(data, size, &avc_quant);
    (void)rdp_graphics_parse_avc420_metablock(data, size, &avc_meta);
    (void)rdp_graphics_parse_avc420_stream(data, size, &avc420);
    (void)rdp_graphics_parse_avc444_stream(data, size, &avc444);
    (void)rdp_graphics_decode_segmented_data(&decompressor, data, size, &output);
    output.length = 0;
    (void)rdp_graphics_write_default_caps_advertise(&output);
    output.length = 0;
    (void)rdp_graphics_write_create_surface(&output, 1, 64, 64, RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888);
    output.length = 0;
    (void)rdp_graphics_write_delete_surface(&output, 1);
    output.length = 0;
    (void)rdp_graphics_write_reset(&output, 64, 64);
    output.length = 0;
    (void)rdp_graphics_write_map_surface_to_output(&output, 1, 0, 0);
    output.length = 0;
    (void)rdp_graphics_write_map_surface_to_scaled_output(&output, 1, 0, 0, 64, 64);
    output.length = 0;
    (void)rdp_graphics_write_point16(&output, &valid_points[0]);
    output.length = 0;
    (void)rdp_graphics_write_rect16(&output, &valid_rect);
    output.length = 0;
    (void)rdp_graphics_write_solid_fill(&output, 1, 0xff000000u, &valid_rect, 1);
    output.length = 0;
    (void)rdp_graphics_write_wire_to_surface_1(&output,
                                               1,
                                               RDP_GRAPHICS_CODECID_UNCOMPRESSED,
                                               RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                               &valid_rect,
                                               data,
                                               (uint32_t)(size < 64u ? size : 64u));
    output.length = 0;
    (void)rdp_graphics_write_wire_to_surface_2(&output,
                                               1,
                                               RDP_GRAPHICS_CODECID_CAPROGRESSIVE,
                                               0,
                                               RDP_GRAPHICS_PIXEL_FORMAT_ARGB_8888,
                                               data,
                                               (uint32_t)(size < 64u ? size : 64u));
    output.length = 0;
    (void)rdp_graphics_write_surface_to_surface(&output, 1, 2, &valid_rect, valid_points, 2);
    output.length = 0;
    (void)rdp_graphics_write_surface_to_cache(&output, 1, 1, 1, &valid_rect);
    output.length = 0;
    (void)rdp_graphics_write_cache_to_surface(&output, 1, 1, valid_points, 2);
    output.length = 0;
    (void)rdp_graphics_write_evict_cache_entry(&output, 1);
    output.length = 0;
    (void)rdp_graphics_write_delete_encoding_context(&output, 1, 1);
    output.length = 0;
    (void)rdp_graphics_write_start_frame(&output, 1, 1);
    output.length = 0;
    (void)rdp_graphics_write_end_frame(&output, 1);
    output.length = 0;
    (void)rdp_graphics_write_frame_ack(&output, RDP_GRAPHICS_QUEUE_DEPTH_UNAVAILABLE, 1, 1);
    output.length = 0;
    (void)rdp_graphics_progressive_write_context(&output, &valid_progressive_context);
    output.length = 0;
    (void)rdp_graphics_progressive_write_frame_begin(&output, &valid_progressive_frame);
    output.length = 0;
    (void)rdp_graphics_progressive_write_frame_end(&output);
    output.length = 0;
    (void)rdp_graphics_progressive_write_region_rect(&output, &valid_rect);
    output.length = 0;
    (void)rdp_graphics_progressive_write_region(&output, &valid_progressive_region);
    valid_simple_tile.block_type = RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_SIMPLE;
    valid_simple_tile.quant_idx_y = 0;
    valid_simple_tile.quant_idx_cb = 0;
    valid_simple_tile.quant_idx_cr = 0;
    valid_simple_tile.x_idx = 0;
    valid_simple_tile.y_idx = 0;
    valid_simple_tile.flags = 0;
    valid_simple_tile.y_len = (uint16_t)(size < 16u ? size : 16u);
    valid_simple_tile.cb_len = 0;
    valid_simple_tile.cr_len = 0;
    valid_simple_tile.tail_len = 0;
    valid_simple_tile.y_data = data;
    valid_simple_tile.cb_data = NULL;
    valid_simple_tile.cr_data = NULL;
    valid_simple_tile.tail_data = NULL;
    output.length = 0;
    (void)rdp_graphics_progressive_write_tile_simple(&output, &valid_simple_tile);
    valid_first_tile.block_type = RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_FIRST;
    valid_first_tile.quant_idx_y = 0;
    valid_first_tile.quant_idx_cb = 0;
    valid_first_tile.quant_idx_cr = 0;
    valid_first_tile.x_idx = 0;
    valid_first_tile.y_idx = 0;
    valid_first_tile.flags = 0;
    valid_first_tile.progressive_quality = 0;
    valid_first_tile.y_len = valid_simple_tile.y_len;
    valid_first_tile.cb_len = 0;
    valid_first_tile.cr_len = 0;
    valid_first_tile.tail_len = 0;
    valid_first_tile.y_data = data;
    valid_first_tile.cb_data = NULL;
    valid_first_tile.cr_data = NULL;
    valid_first_tile.tail_data = NULL;
    output.length = 0;
    (void)rdp_graphics_progressive_write_tile_first(&output, &valid_first_tile);
    valid_upgrade_tile.block_type = RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_UPGRADE;
    valid_upgrade_tile.quant_idx_y = 0;
    valid_upgrade_tile.quant_idx_cb = 0;
    valid_upgrade_tile.quant_idx_cr = 0;
    valid_upgrade_tile.x_idx = 0;
    valid_upgrade_tile.y_idx = 0;
    valid_upgrade_tile.progressive_quality = 0;
    valid_upgrade_tile.y_srl_len = valid_simple_tile.y_len;
    valid_upgrade_tile.y_raw_len = 0;
    valid_upgrade_tile.cb_srl_len = 0;
    valid_upgrade_tile.cb_raw_len = 0;
    valid_upgrade_tile.cr_srl_len = 0;
    valid_upgrade_tile.cr_raw_len = 0;
    valid_upgrade_tile.y_srl_data = data;
    valid_upgrade_tile.y_raw_data = NULL;
    valid_upgrade_tile.cb_srl_data = NULL;
    valid_upgrade_tile.cb_raw_data = NULL;
    valid_upgrade_tile.cr_srl_data = NULL;
    valid_upgrade_tile.cr_raw_data = NULL;
    output.length = 0;
    (void)rdp_graphics_progressive_write_tile_upgrade(&output, &valid_upgrade_tile);
    rdp_buffer_free(&output);
    rdp_graphics_decompressor_free(&decompressor);
    return 0;
}
