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
#define RDP_GRAPHICS_CAPVERSION_10 0x000a0002u
#define RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE 0x00000002u
#define RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED 0x00000020u
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

typedef struct rdp_graphics_start_frame
{
    uint32_t timestamp;
    uint32_t frame_id;
} rdp_graphics_start_frame;

typedef struct rdp_graphics_end_frame
{
    uint32_t frame_id;
} rdp_graphics_end_frame;

typedef struct rdp_graphics_decompressor
{
    uint8_t* history;
    uint32_t history_index;
    uint32_t history_filled;
} rdp_graphics_decompressor;

void rdp_graphics_decompressor_init(rdp_graphics_decompressor* decompressor);
void rdp_graphics_decompressor_reset(rdp_graphics_decompressor* decompressor);
void rdp_graphics_decompressor_free(rdp_graphics_decompressor* decompressor);
librdp_status rdp_graphics_parse_header(const void* data, size_t length, rdp_graphics_header* header);
librdp_status rdp_graphics_parse_capset(const void* data, size_t length, rdp_graphics_capset* capset);
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
librdp_status rdp_graphics_parse_delete_surface(const void* data,
                                                size_t length,
                                                rdp_graphics_delete_surface* delete_surface);
librdp_status rdp_graphics_parse_reset(const void* data, size_t length, rdp_graphics_reset* reset);
librdp_status rdp_graphics_parse_map_surface_to_output(const void* data,
                                                       size_t length,
                                                       rdp_graphics_map_surface_to_output* map);
librdp_status rdp_graphics_parse_point16(const void* data, size_t length, rdp_graphics_point16* point);
librdp_status rdp_graphics_parse_rect16(const void* data, size_t length, rdp_graphics_rect16* rect);
librdp_status rdp_graphics_parse_solid_fill(const void* data,
                                            size_t length,
                                            rdp_graphics_solid_fill* solid_fill);
librdp_status rdp_graphics_parse_wire_to_surface_1(const void* data,
                                                   size_t length,
                                                   rdp_graphics_wire_to_surface_1* wire);
librdp_status rdp_graphics_parse_wire_to_surface_2(const void* data,
                                                   size_t length,
                                                   rdp_graphics_wire_to_surface_2* wire);
librdp_status rdp_graphics_parse_surface_to_surface(const void* data,
                                                    size_t length,
                                                    rdp_graphics_surface_to_surface* surface_to_surface);
librdp_status rdp_graphics_parse_surface_to_cache(const void* data,
                                                  size_t length,
                                                  rdp_graphics_surface_to_cache* surface_to_cache);
librdp_status rdp_graphics_parse_cache_to_surface(const void* data,
                                                  size_t length,
                                                  rdp_graphics_cache_to_surface* cache_to_surface);
librdp_status rdp_graphics_parse_evict_cache_entry(const void* data,
                                                   size_t length,
                                                   rdp_graphics_evict_cache_entry* evict);
librdp_status rdp_graphics_parse_start_frame(const void* data,
                                             size_t length,
                                             rdp_graphics_start_frame* start_frame);
librdp_status rdp_graphics_parse_end_frame(const void* data,
                                           size_t length,
                                           rdp_graphics_end_frame* end_frame);
librdp_status rdp_graphics_write_frame_ack(rdp_buffer* buffer,
                                           uint32_t queue_depth,
                                           uint32_t frame_id,
                                           uint32_t total_frames_decoded);
librdp_status rdp_graphics_decode_segmented_data(rdp_graphics_decompressor* decompressor,
                                                 const void* data,
                                                 size_t length,
                                                 rdp_buffer* decoded);

#endif
