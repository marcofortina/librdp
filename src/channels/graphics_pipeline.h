#ifndef RDP_CHANNELS_GRAPHICS_PIPELINE_H
#define RDP_CHANNELS_GRAPHICS_PIPELINE_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_GRAPHICS_CMDID_WIRE_TO_SURFACE_1 0x0001u
#define RDP_GRAPHICS_CMDID_WIRE_TO_SURFACE_2 0x0002u
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
librdp_status rdp_graphics_decode_segmented_data(rdp_graphics_decompressor* decompressor,
                                                 const void* data,
                                                 size_t length,
                                                 rdp_buffer* decoded);

#endif
