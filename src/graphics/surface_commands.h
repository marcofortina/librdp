#ifndef RDP_GRAPHICS_SURFACE_COMMANDS_H
#define RDP_GRAPHICS_SURFACE_COMMANDS_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_SURFACE_COMMAND_SET_BITS 0x0001u
#define RDP_SURFACE_COMMAND_FRAME_MARKER 0x0004u
#define RDP_SURFACE_COMMAND_STREAM_BITS 0x0006u
#define RDP_SURFACE_COMMAND_MAX_COMMANDS 256u
#define RDP_SURFACE_BITS_FLAG_EXTENDED_HEADER 0x01u
#define RDP_SURFACE_CODEC_NONE 0x00u
#define RDP_SURFACE_CODEC_NSCODEC 0x01u
#define RDP_SURFACE_CODEC_REMOTEFX 0x03u
#define RDP_SURFACE_CODEC_IMAGE_REMOTEFX 0x04u

typedef enum rdp_surface_command_kind
{
    RDP_SURFACE_COMMAND_KIND_BITS = 1,
    RDP_SURFACE_COMMAND_KIND_FRAME_MARKER = 2
} rdp_surface_command_kind;

typedef struct rdp_surface_bits
{
    uint16_t command_type;
    uint16_t dest_left;
    uint16_t dest_top;
    uint16_t dest_right;
    uint16_t dest_bottom;
    uint8_t bpp;
    uint8_t flags;
    uint8_t codec_id;
    uint16_t width;
    uint16_t height;
    uint32_t bitmap_data_length;
    uint8_t has_extended_header;
    uint32_t high_unique_id;
    uint32_t low_unique_id;
    uint64_t timestamp_ms;
    uint64_t timestamp_s;
    const uint8_t* bitmap_data;
} rdp_surface_bits;

typedef struct rdp_surface_frame_marker
{
    uint16_t action;
    uint32_t frame_id;
    uint8_t has_frame_id;
} rdp_surface_frame_marker;

typedef struct rdp_surface_command
{
    rdp_surface_command_kind kind;
    rdp_surface_bits bits;
    rdp_surface_frame_marker frame_marker;
} rdp_surface_command;

typedef struct rdp_surface_command_list
{
    uint16_t count;
    rdp_surface_command commands[RDP_SURFACE_COMMAND_MAX_COMMANDS];
} rdp_surface_command_list;

librdp_status rdp_surface_commands_parse(const void* data,
                                         size_t length,
                                         rdp_surface_command_list* list);
librdp_status rdp_surface_commands_write_bits(rdp_buffer* buffer,
                                              const rdp_surface_bits* bits);
librdp_status rdp_surface_commands_write_frame_marker(rdp_buffer* buffer,
                                                      uint16_t action,
                                                      uint32_t frame_id);

#endif
