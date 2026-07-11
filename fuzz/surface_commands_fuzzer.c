/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "graphics/surface_commands.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_surface_command_list list;
    rdp_surface_bits bits;
    rdp_buffer output;
    size_t bounded = size < 128u ? size : 128u;

    (void)rdp_surface_commands_parse(data, size, &list);
    rdp_buffer_init(&output);
    bits.command_type = RDP_SURFACE_COMMAND_SET_BITS;
    bits.dest_left = 0;
    bits.dest_top = 0;
    bits.dest_right = 8;
    bits.dest_bottom = 8;
    bits.bpp = 32;
    bits.flags = 0;
    bits.codec_id = RDP_SURFACE_CODEC_NONE;
    bits.width = 8;
    bits.height = 8;
    bits.bitmap_data_length = (uint32_t)bounded;
    bits.has_extended_header = 0;
    bits.high_unique_id = 0;
    bits.low_unique_id = 0;
    bits.timestamp_ms = 0;
    bits.timestamp_s = 0;
    bits.bitmap_data = data;
    (void)rdp_surface_commands_write_bits(&output, &bits);
    output.length = 0;
    (void)rdp_surface_commands_write_frame_marker(&output, 0, 1);
    rdp_buffer_free(&output);
    return 0;
}
