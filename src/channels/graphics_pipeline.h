/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: graphics pipeline capability, segment, cache, and surface
 * declarations.
 * Invariants: channel payload lengths, message identifiers, and negotiated
 * capabilities must be validated before state changes.
 * Ownership: parsed packet structs remain caller-owned unless a session
 * explicitly stores a copy.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths are local policy inputs.
 */


#ifndef RDP_CHANNELS_GRAPHICS_PIPELINE_H
#define RDP_CHANNELS_GRAPHICS_PIPELINE_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_GRAPHICS_CMDID_WIRE_TO_SURFACE_1 0x0001u
#define RDP_GRAPHICS_CMDID_WIRE_TO_SURFACE_2 0x0002u
#define RDP_GRAPHICS_CMDID_DELETE_ENCODING_CONTEXT 0x0003u
#define RDP_GRAPHICS_CMDID_SOLIDFILL 0x0004u
#define RDP_GRAPHICS_CMDID_SURFACE_TO_SURFACE 0x0005u
#define RDP_GRAPHICS_CMDID_SURFACE_TO_CACHE 0x0006u
#define RDP_GRAPHICS_CMDID_CACHE_TO_SURFACE 0x0007u
#define RDP_GRAPHICS_CMDID_EVICT_CACHE_ENTRY 0x0008u
#define RDP_GRAPHICS_CMDID_CREATE_SURFACE 0x0009u
#define RDP_GRAPHICS_CMDID_DELETE_SURFACE 0x000au
#define RDP_GRAPHICS_CMDID_START_FRAME 0x000bu
#define RDP_GRAPHICS_CMDID_END_FRAME 0x000cu
#define RDP_GRAPHICS_CMDID_FRAME_ACKNOWLEDGE 0x000du
#define RDP_GRAPHICS_CMDID_RESET_GRAPHICS 0x000eu
#define RDP_GRAPHICS_CMDID_MAP_SURFACE_TO_OUTPUT 0x000fu
#define RDP_GRAPHICS_CMDID_CAPS_ADVERTISE 0x0012u
#define RDP_GRAPHICS_CMDID_CAPS_CONFIRM 0x0013u
#define RDP_GRAPHICS_CMDID_MAP_SURFACE_TO_SCALED_OUTPUT 0x0017u
#define RDP_GRAPHICS_CAPVERSION_8 0x00080004u
#define RDP_GRAPHICS_CAPVERSION_81 0x00080105u
#define RDP_GRAPHICS_CAPVERSION_10 0x000a0002u
#define RDP_GRAPHICS_CAPVERSION_101 0x000a0100u
#define RDP_GRAPHICS_CAPVERSION_102 0x000a0200u
#define RDP_GRAPHICS_CAPVERSION_103 0x000a0301u
#define RDP_GRAPHICS_CAPVERSION_104 0x000a0400u
#define RDP_GRAPHICS_CAPVERSION_105 0x000a0502u
#define RDP_GRAPHICS_CAPVERSION_106 0x000a0600u
#define RDP_GRAPHICS_CAPVERSION_106_ERR 0x000a0601u
#define RDP_GRAPHICS_CAPVERSION_107 0x000a0701u
#define RDP_GRAPHICS_CAPS_FLAG_THINCLIENT 0x00000001u
#define RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE 0x00000002u
#define RDP_GRAPHICS_CAPS_FLAG_AVC420_ENABLED 0x00000010u
#define RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED 0x00000020u
#define RDP_GRAPHICS_CAPS_FLAG_AVC_THINCLIENT 0x00000040u
#define RDP_GRAPHICS_CAPS_FLAG_SCALEDMAP_DISABLE 0x00000080u
#define RDP_GRAPHICS_DEFAULT_CAPSET_LIMIT 5u
#define RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888 0x20u
#define RDP_GRAPHICS_PIXEL_FORMAT_ARGB_8888 0x21u
#define RDP_GRAPHICS_CODECID_UNCOMPRESSED 0x0000u
#define RDP_GRAPHICS_CODECID_CAVIDEO 0x0003u
#define RDP_GRAPHICS_CODECID_CLEARCODEC 0x0008u
#define RDP_GRAPHICS_CODECID_CAPROGRESSIVE 0x0009u
#define RDP_GRAPHICS_CODECID_PLANAR 0x000au
#define RDP_GRAPHICS_CODECID_AVC420 0x000bu
#define RDP_GRAPHICS_CODECID_ALPHA 0x000cu
#define RDP_GRAPHICS_CODECID_AVC444 0x000eu
#define RDP_GRAPHICS_CODECID_AVC444V2 0x000fu
#define RDP_GRAPHICS_QUEUE_DEPTH_UNAVAILABLE 0x00000000u
#define RDP_GRAPHICS_SEGMENT_SINGLE 0xe0u
#define RDP_GRAPHICS_SEGMENT_MULTIPART 0xe1u
#define RDP_GRAPHICS_BULK_PACKET_COMPRESSED 0x20u
#define RDP_GRAPHICS_BULK_MAX_DECODED (64u * 1024u * 1024u)
#define RDP_GRAPHICS_BULK_HISTORY_SIZE 2500000u
#define RDP_GRAPHICS_PROGRESSIVE_BLOCK_SYNC 0xccc0u
#define RDP_GRAPHICS_PROGRESSIVE_BLOCK_FRAME_BEGIN 0xccc1u
#define RDP_GRAPHICS_PROGRESSIVE_BLOCK_FRAME_END 0xccc2u
#define RDP_GRAPHICS_PROGRESSIVE_BLOCK_CONTEXT 0xccc3u
#define RDP_GRAPHICS_PROGRESSIVE_BLOCK_REGION 0xccc4u
#define RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_SIMPLE 0xccc5u
#define RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_FIRST 0xccc6u
#define RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_UPGRADE 0xccc7u
#define RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE 0x40u
#define RDP_GRAPHICS_PROGRESSIVE_MAX_REGIONS 4096u
#define RDP_GRAPHICS_PROGRESSIVE_MAX_RECTS 4096u
#define RDP_GRAPHICS_PROGRESSIVE_MAX_TILES 4096u
#define RDP_GRAPHICS_AVC420_MAX_REGION_RECTS 8192u
#define RDP_GRAPHICS_AVC444_STREAM1_SIZE_MASK 0x3fffffffu
#define RDP_GRAPHICS_AVC444_LC_SHIFT 30u
#define RDP_GRAPHICS_AVC444_LC_BOTH 0u
#define RDP_GRAPHICS_AVC444_LC_LUMA 1u
#define RDP_GRAPHICS_AVC444_LC_CHROMA 2u
#define RDP_GRAPHICS_AVC444_LC_INVALID 3u

typedef struct rdp_graphics_header
{
    uint16_t cmd_id;
    uint16_t flags;
    uint32_t pdu_length;
} rdp_graphics_header;

typedef struct rdp_graphics_capset
{
    uint32_t version;
    uint32_t flags;
} rdp_graphics_capset;

typedef struct rdp_graphics_caps_confirm
{
    rdp_graphics_capset selected;
} rdp_graphics_caps_confirm;

typedef struct rdp_graphics_create_surface
{
    uint16_t surface_id;
    uint16_t width;
    uint16_t height;
    uint8_t pixel_format;
} rdp_graphics_create_surface;

typedef struct rdp_graphics_delete_surface
{
    uint16_t surface_id;
} rdp_graphics_delete_surface;

typedef struct rdp_graphics_reset
{
    uint32_t width;
    uint32_t height;
    uint32_t monitor_count;
} rdp_graphics_reset;

typedef struct rdp_graphics_map_surface_to_output
{
    uint16_t surface_id;
    uint32_t output_origin_x;
    uint32_t output_origin_y;
} rdp_graphics_map_surface_to_output;

typedef struct rdp_graphics_map_surface_to_scaled_output
{
    uint16_t surface_id;
    uint32_t output_origin_x;
    uint32_t output_origin_y;
    uint32_t target_width;
    uint32_t target_height;
} rdp_graphics_map_surface_to_scaled_output;

typedef struct rdp_graphics_point16
{
    uint16_t x;
    uint16_t y;
} rdp_graphics_point16;

typedef struct rdp_graphics_rect16
{
    uint16_t left;
    uint16_t top;
    uint16_t right;
    uint16_t bottom;
} rdp_graphics_rect16;

typedef struct rdp_graphics_solid_fill
{
    uint16_t surface_id;
    uint32_t fill_pixel;
    uint16_t rect_count;
    const uint8_t* rects;
    size_t rects_len;
} rdp_graphics_solid_fill;

typedef struct rdp_graphics_wire_to_surface_1
{
    uint16_t surface_id;
    uint16_t codec_id;
    uint8_t pixel_format;
    rdp_graphics_rect16 dest_rect;
    uint32_t bitmap_data_length;
    const uint8_t* bitmap_data;
} rdp_graphics_wire_to_surface_1;

typedef struct rdp_graphics_wire_to_surface_2
{
    uint16_t surface_id;
    uint16_t codec_id;
    uint32_t codec_context_id;
    uint8_t pixel_format;
    uint32_t bitmap_data_length;
    const uint8_t* bitmap_data;
} rdp_graphics_wire_to_surface_2;

typedef struct rdp_graphics_surface_to_surface
{
    uint16_t surface_id_src;
    uint16_t surface_id_dest;
    rdp_graphics_rect16 rect_src;
    uint16_t dest_points_count;
    const uint8_t* dest_points;
    size_t dest_points_len;
} rdp_graphics_surface_to_surface;

typedef struct rdp_graphics_surface_to_cache
{
    uint16_t surface_id;
    uint64_t cache_key;
    uint16_t cache_slot;
    rdp_graphics_rect16 rect_src;
} rdp_graphics_surface_to_cache;

typedef struct rdp_graphics_cache_to_surface
{
    uint16_t cache_slot;
    uint16_t surface_id;
    uint16_t dest_points_count;
    const uint8_t* dest_points;
    size_t dest_points_len;
} rdp_graphics_cache_to_surface;

typedef struct rdp_graphics_evict_cache_entry
{
    uint16_t cache_slot;
} rdp_graphics_evict_cache_entry;

typedef struct rdp_graphics_delete_encoding_context
{
    uint16_t surface_id;
    uint32_t codec_context_id;
} rdp_graphics_delete_encoding_context;

typedef struct rdp_graphics_start_frame
{
    uint32_t timestamp;
    uint32_t frame_id;
} rdp_graphics_start_frame;

typedef struct rdp_graphics_end_frame
{
    uint32_t frame_id;
} rdp_graphics_end_frame;

typedef struct rdp_graphics_frame_ack
{
    uint32_t queue_depth;
    uint32_t frame_id;
    uint32_t total_frames_decoded;
} rdp_graphics_frame_ack;

typedef struct rdp_graphics_decompressor
{
    uint8_t* history;
    uint32_t history_index;
    uint32_t history_filled;
} rdp_graphics_decompressor;

typedef struct rdp_graphics_progressive_block
{
    uint16_t type;
    uint32_t length;
    const uint8_t* payload;
    size_t payload_len;
} rdp_graphics_progressive_block;

typedef struct rdp_graphics_progressive_context
{
    uint8_t context_id;
    uint16_t tile_size;
    uint8_t flags;
} rdp_graphics_progressive_context;

typedef struct rdp_graphics_progressive_frame_begin
{
    uint32_t frame_index;
    uint16_t region_count;
} rdp_graphics_progressive_frame_begin;

typedef struct rdp_graphics_progressive_region
{
    uint8_t tile_size;
    uint16_t rect_count;
    uint8_t quant_count;
    uint8_t progressive_quant_count;
    uint8_t flags;
    uint16_t tile_count;
    uint32_t tile_data_size;
    const uint8_t* rects;
    size_t rects_len;
    const uint8_t* quant_values;
    size_t quant_values_len;
    const uint8_t* progressive_quant_values;
    size_t progressive_quant_values_len;
    const uint8_t* tiles;
    size_t tiles_len;
} rdp_graphics_progressive_region;

typedef struct rdp_graphics_progressive_tile_simple
{
    uint16_t block_type;
    uint8_t quant_idx_y;
    uint8_t quant_idx_cb;
    uint8_t quant_idx_cr;
    uint16_t x_idx;
    uint16_t y_idx;
    uint8_t flags;
    uint16_t y_len;
    uint16_t cb_len;
    uint16_t cr_len;
    uint16_t tail_len;
    const uint8_t* y_data;
    const uint8_t* cb_data;
    const uint8_t* cr_data;
    const uint8_t* tail_data;
} rdp_graphics_progressive_tile_simple;

typedef struct rdp_graphics_progressive_tile_first
{
    uint16_t block_type;
    uint8_t quant_idx_y;
    uint8_t quant_idx_cb;
    uint8_t quant_idx_cr;
    uint16_t x_idx;
    uint16_t y_idx;
    uint8_t flags;
    uint8_t progressive_quality;
    uint16_t y_len;
    uint16_t cb_len;
    uint16_t cr_len;
    uint16_t tail_len;
    const uint8_t* y_data;
    const uint8_t* cb_data;
    const uint8_t* cr_data;
    const uint8_t* tail_data;
} rdp_graphics_progressive_tile_first;

typedef struct rdp_graphics_progressive_tile_upgrade
{
    uint16_t block_type;
    uint8_t quant_idx_y;
    uint8_t quant_idx_cb;
    uint8_t quant_idx_cr;
    uint16_t x_idx;
    uint16_t y_idx;
    uint8_t progressive_quality;
    uint16_t y_srl_len;
    uint16_t y_raw_len;
    uint16_t cb_srl_len;
    uint16_t cb_raw_len;
    uint16_t cr_srl_len;
    uint16_t cr_raw_len;
    const uint8_t* y_srl_data;
    const uint8_t* y_raw_data;
    const uint8_t* cb_srl_data;
    const uint8_t* cb_raw_data;
    const uint8_t* cr_srl_data;
    const uint8_t* cr_raw_data;
} rdp_graphics_progressive_tile_upgrade;

typedef struct rdp_graphics_progressive_stream
{
    uint32_t block_count;
    uint32_t known_block_count;
    uint32_t region_count;
    uint32_t tile_count;
    uint32_t simple_tile_count;
    uint32_t first_tile_count;
    uint32_t upgrade_tile_count;
    uint8_t has_context;
    uint8_t has_frame_begin;
    uint8_t has_frame_end;
    uint8_t tile_size;
    uint8_t flags;
} rdp_graphics_progressive_stream;

typedef struct rdp_graphics_avc420_quant_quality
{
    uint8_t qp_val;
    uint8_t qp;
    uint8_t r;
    uint8_t p;
    uint8_t quality;
} rdp_graphics_avc420_quant_quality;

typedef struct rdp_graphics_avc420_metablock
{
    uint32_t rect_count;
    const uint8_t* rects;
    size_t rects_len;
    const uint8_t* quant_quality;
    size_t quant_quality_len;
} rdp_graphics_avc420_metablock;

typedef struct rdp_graphics_avc420_stream
{
    rdp_graphics_avc420_metablock meta;
    const uint8_t* bitstream;
    size_t bitstream_len;
} rdp_graphics_avc420_stream;

typedef struct rdp_graphics_avc444_stream
{
    uint32_t stream1_size;
    uint8_t lc;
    uint8_t has_stream1;
    uint8_t has_stream2;
    rdp_graphics_avc420_stream stream1;
    rdp_graphics_avc420_stream stream2;
} rdp_graphics_avc444_stream;

void rdp_graphics_decompressor_init(rdp_graphics_decompressor* decompressor);
void rdp_graphics_decompressor_reset(rdp_graphics_decompressor* decompressor);
void rdp_graphics_decompressor_free(rdp_graphics_decompressor* decompressor);
librdp_status rdp_graphics_parse_header(const void* data, size_t length, rdp_graphics_header* header);
librdp_status rdp_graphics_parse_capset(const void* data, size_t length, rdp_graphics_capset* capset);
librdp_status rdp_graphics_default_capsets(rdp_graphics_capset* capsets,
                                           uint16_t capset_capacity,
                                           uint16_t* capset_count);
int rdp_graphics_capset_is_default_supported(const rdp_graphics_capset* capset);
librdp_status rdp_graphics_write_caps_advertise(rdp_buffer* buffer,
                                                const rdp_graphics_capset* capsets,
                                                uint16_t capset_count);
librdp_status rdp_graphics_write_default_caps_advertise(rdp_buffer* buffer);
librdp_status rdp_graphics_parse_caps_confirm(const void* data,
                                              size_t length,
                                              rdp_graphics_caps_confirm* confirm);
librdp_status rdp_graphics_parse_create_surface(const void* data,
                                                size_t length,
                                                rdp_graphics_create_surface* create_surface);
librdp_status rdp_graphics_write_create_surface(rdp_buffer* buffer,
                                                uint16_t surface_id,
                                                uint16_t width,
                                                uint16_t height,
                                                uint8_t pixel_format);
librdp_status rdp_graphics_parse_delete_surface(const void* data,
                                                size_t length,
                                                rdp_graphics_delete_surface* delete_surface);
librdp_status rdp_graphics_write_delete_surface(rdp_buffer* buffer, uint16_t surface_id);
librdp_status rdp_graphics_parse_reset(const void* data, size_t length, rdp_graphics_reset* reset);
librdp_status rdp_graphics_write_reset(rdp_buffer* buffer, uint32_t width, uint32_t height);
librdp_status rdp_graphics_parse_map_surface_to_output(const void* data,
                                                       size_t length,
                                                       rdp_graphics_map_surface_to_output* map);
librdp_status rdp_graphics_write_map_surface_to_output(rdp_buffer* buffer,
                                                       uint16_t surface_id,
                                                       uint32_t output_origin_x,
                                                       uint32_t output_origin_y);
librdp_status rdp_graphics_parse_map_surface_to_scaled_output(
    const void* data,
    size_t length,
    rdp_graphics_map_surface_to_scaled_output* map);
librdp_status rdp_graphics_write_map_surface_to_scaled_output(
    rdp_buffer* buffer,
    uint16_t surface_id,
    uint32_t output_origin_x,
    uint32_t output_origin_y,
    uint32_t target_width,
    uint32_t target_height);
librdp_status rdp_graphics_parse_point16(const void* data, size_t length, rdp_graphics_point16* point);
librdp_status rdp_graphics_write_point16(rdp_buffer* buffer, const rdp_graphics_point16* point);
librdp_status rdp_graphics_parse_rect16(const void* data, size_t length, rdp_graphics_rect16* rect);
librdp_status rdp_graphics_write_rect16(rdp_buffer* buffer, const rdp_graphics_rect16* rect);
librdp_status rdp_graphics_parse_solid_fill(const void* data,
                                            size_t length,
                                            rdp_graphics_solid_fill* solid_fill);
librdp_status rdp_graphics_write_solid_fill(rdp_buffer* buffer,
                                            uint16_t surface_id,
                                            uint32_t fill_pixel,
                                            const rdp_graphics_rect16* rects,
                                            uint16_t rect_count);
librdp_status rdp_graphics_parse_wire_to_surface_1(const void* data,
                                                   size_t length,
                                                   rdp_graphics_wire_to_surface_1* wire);
librdp_status rdp_graphics_write_wire_to_surface_1(rdp_buffer* buffer,
                                                   uint16_t surface_id,
                                                   uint16_t codec_id,
                                                   uint8_t pixel_format,
                                                   const rdp_graphics_rect16* dest_rect,
                                                   const void* bitmap_data,
                                                   uint32_t bitmap_data_length);
librdp_status rdp_graphics_parse_wire_to_surface_2(const void* data,
                                                   size_t length,
                                                   rdp_graphics_wire_to_surface_2* wire);
librdp_status rdp_graphics_write_wire_to_surface_2(rdp_buffer* buffer,
                                                   uint16_t surface_id,
                                                   uint16_t codec_id,
                                                   uint32_t codec_context_id,
                                                   uint8_t pixel_format,
                                                   const void* bitmap_data,
                                                   uint32_t bitmap_data_length);
librdp_status rdp_graphics_parse_surface_to_surface(const void* data,
                                                    size_t length,
                                                    rdp_graphics_surface_to_surface* surface_to_surface);
librdp_status rdp_graphics_write_surface_to_surface(rdp_buffer* buffer,
                                                    uint16_t surface_id_src,
                                                    uint16_t surface_id_dest,
                                                    const rdp_graphics_rect16* rect_src,
                                                    const rdp_graphics_point16* dest_points,
                                                    uint16_t dest_points_count);
librdp_status rdp_graphics_parse_surface_to_cache(const void* data,
                                                  size_t length,
                                                  rdp_graphics_surface_to_cache* surface_to_cache);
librdp_status rdp_graphics_write_surface_to_cache(rdp_buffer* buffer,
                                                  uint16_t surface_id,
                                                  uint64_t cache_key,
                                                  uint16_t cache_slot,
                                                  const rdp_graphics_rect16* rect_src);
librdp_status rdp_graphics_parse_cache_to_surface(const void* data,
                                                  size_t length,
                                                  rdp_graphics_cache_to_surface* cache_to_surface);
librdp_status rdp_graphics_write_cache_to_surface(rdp_buffer* buffer,
                                                  uint16_t cache_slot,
                                                  uint16_t surface_id,
                                                  const rdp_graphics_point16* dest_points,
                                                  uint16_t dest_points_count);
librdp_status rdp_graphics_parse_evict_cache_entry(const void* data,
                                                   size_t length,
                                                   rdp_graphics_evict_cache_entry* evict);
librdp_status rdp_graphics_write_evict_cache_entry(rdp_buffer* buffer, uint16_t cache_slot);
librdp_status rdp_graphics_parse_delete_encoding_context(const void* data,
                                                         size_t length,
                                                         rdp_graphics_delete_encoding_context* context);
librdp_status rdp_graphics_write_delete_encoding_context(rdp_buffer* buffer,
                                                         uint16_t surface_id,
                                                         uint32_t codec_context_id);
librdp_status rdp_graphics_parse_start_frame(const void* data,
                                             size_t length,
                                             rdp_graphics_start_frame* start_frame);
librdp_status rdp_graphics_write_start_frame(rdp_buffer* buffer, uint32_t timestamp, uint32_t frame_id);
librdp_status rdp_graphics_parse_end_frame(const void* data,
                                           size_t length,
                                           rdp_graphics_end_frame* end_frame);
librdp_status rdp_graphics_write_end_frame(rdp_buffer* buffer, uint32_t frame_id);
librdp_status rdp_graphics_parse_frame_ack(const void* data,
                                           size_t length,
                                           rdp_graphics_frame_ack* ack);
librdp_status rdp_graphics_write_frame_ack(rdp_buffer* buffer,
                                           uint32_t queue_depth,
                                           uint32_t frame_id,
                                           uint32_t total_frames_decoded);
librdp_status rdp_graphics_decode_segmented_data(rdp_graphics_decompressor* decompressor,
                                                 const void* data,
                                                 size_t length,
                                                 rdp_buffer* decoded);
librdp_status rdp_graphics_progressive_parse_block(const void* data,
                                                   size_t length,
                                                   rdp_graphics_progressive_block* block);
librdp_status rdp_graphics_progressive_write_block(rdp_buffer* buffer,
                                                   uint16_t type,
                                                   const void* payload,
                                                   uint32_t payload_len);
librdp_status rdp_graphics_progressive_parse_context(const void* data,
                                                     size_t length,
                                                     rdp_graphics_progressive_context* context);
librdp_status rdp_graphics_progressive_write_context(
    rdp_buffer* buffer,
    const rdp_graphics_progressive_context* context);
librdp_status rdp_graphics_progressive_parse_frame_begin(
    const void* data,
    size_t length,
    rdp_graphics_progressive_frame_begin* frame_begin);
librdp_status rdp_graphics_progressive_write_frame_begin(
    rdp_buffer* buffer,
    const rdp_graphics_progressive_frame_begin* frame_begin);
librdp_status rdp_graphics_progressive_parse_frame_end(const void* data, size_t length);
librdp_status rdp_graphics_progressive_write_frame_end(rdp_buffer* buffer);
librdp_status rdp_graphics_progressive_parse_region(const void* data,
                                                    size_t length,
                                                    rdp_graphics_progressive_region* region);
librdp_status rdp_graphics_progressive_write_region(
    rdp_buffer* buffer,
    const rdp_graphics_progressive_region* region);
librdp_status rdp_graphics_progressive_parse_region_rect(const void* data,
                                                         size_t length,
                                                         rdp_graphics_rect16* rect);
librdp_status rdp_graphics_progressive_write_region_rect(rdp_buffer* buffer,
                                                         const rdp_graphics_rect16* rect);
librdp_status rdp_graphics_progressive_parse_tile_simple(
    const void* data,
    size_t length,
    rdp_graphics_progressive_tile_simple* tile);
librdp_status rdp_graphics_progressive_write_tile_simple(
    rdp_buffer* buffer,
    const rdp_graphics_progressive_tile_simple* tile);
librdp_status rdp_graphics_progressive_parse_tile_first(const void* data,
                                                       size_t length,
                                                       rdp_graphics_progressive_tile_first* tile);
librdp_status rdp_graphics_progressive_write_tile_first(
    rdp_buffer* buffer,
    const rdp_graphics_progressive_tile_first* tile);
librdp_status rdp_graphics_progressive_parse_tile_upgrade(
    const void* data,
    size_t length,
    rdp_graphics_progressive_tile_upgrade* tile);
librdp_status rdp_graphics_progressive_write_tile_upgrade(
    rdp_buffer* buffer,
    const rdp_graphics_progressive_tile_upgrade* tile);
librdp_status rdp_graphics_progressive_parse_stream(const void* data,
                                                    size_t length,
                                                    rdp_graphics_progressive_stream* stream);
librdp_status rdp_graphics_parse_avc420_quant_quality(const void* data,
                                                      size_t length,
                                                      rdp_graphics_avc420_quant_quality* quant_quality);
librdp_status rdp_graphics_write_avc420_quant_quality(
    rdp_buffer* buffer,
    const rdp_graphics_avc420_quant_quality* quant_quality);
librdp_status rdp_graphics_parse_avc420_metablock(const void* data,
                                                  size_t length,
                                                  rdp_graphics_avc420_metablock* metablock);
librdp_status rdp_graphics_write_avc420_metablock(
    rdp_buffer* buffer,
    const rdp_graphics_avc420_metablock* metablock);
librdp_status rdp_graphics_parse_avc420_stream(const void* data,
                                               size_t length,
                                               rdp_graphics_avc420_stream* stream);
librdp_status rdp_graphics_write_avc420_stream(rdp_buffer* buffer,
                                               const rdp_graphics_avc420_stream* stream);
librdp_status rdp_graphics_parse_avc444_stream(const void* data,
                                               size_t length,
                                               rdp_graphics_avc444_stream* stream);
librdp_status rdp_graphics_write_avc444_stream(rdp_buffer* buffer,
                                               const rdp_graphics_avc444_stream* stream);

#endif
