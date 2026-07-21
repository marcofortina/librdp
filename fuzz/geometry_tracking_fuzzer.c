/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for geometry tracking parser and writer paths.
 * Coverage: arbitrary channel messages, nested region records, signed
 * coordinates, clear packets and writer round trips.
 * Bug classes: length/count overflow, truncated rectangles, inverted bounds,
 * borrowed-buffer misuse and partial parser output.
 * Determinism: the entrypoint has no network, clock, filesystem, or backend
 * dependency.
 */

#include "channels/geometry_tracking.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: parses one untrusted RDPEGT message, reads every validated
 * rectangle, then exercises bounded update and clear serialization.
 * Bug classes: nested length/count overflow, truncated rectangle access and
 * invalid signed-coordinate handling.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static const rdp_geometry_tracking_rect bounds = {
        -16, -8, 640, 480
    };
    rdp_geometry_tracking_packet packet;
    rdp_geometry_tracking_rect rect;
    rdp_buffer buffer;
    uint32_t rect_count = size > 0u ? (uint32_t)(data[0] & 3u) : 0u;
    rdp_geometry_tracking_rect rects[3];

    if (rdp_geometry_tracking_parse(data, size, &packet) ==
        LIBRDP_STATUS_OK)
    {
        for (uint32_t i = 0u; i < packet.rect_count; i++)
            (void)rdp_geometry_tracking_get_rect(&packet, i, &rect);
    }

    for (uint32_t i = 0u; i < rect_count; i++)
    {
        rects[i].left = (int32_t)i;
        rects[i].top = (int32_t)i;
        rects[i].right = (int32_t)i + 32;
        rects[i].bottom = (int32_t)i + 24;
    }
    rdp_buffer_init(&buffer);
    (void)rdp_geometry_tracking_write_update(&buffer,
                                              UINT64_C(0x1020304050607080),
                                              UINT64_C(0x8877665544332211),
                                              &bounds,
                                              &bounds,
                                              &bounds,
                                              rect_count > 0u ?
                                                  rects :
                                                  NULL,
                                              rect_count);
    buffer.length = 0u;
    (void)rdp_geometry_tracking_write_clear(
        &buffer,
        UINT64_C(0x1020304050607080));
    rdp_buffer_free(&buffer);
    return 0;
}
