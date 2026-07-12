/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for display control monitor layout parser and writer
 * paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "channels/display_control.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises display control monitor layout parser and writer
 * paths with one arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_display_control_caps caps = {0};
    rdp_display_control_monitor monitor;
    rdp_display_control_monitor monitors[2];
    uint32_t monitor_count = 0;
    rdp_buffer layout;

    (void)rdp_display_control_parse_caps(data, size, &caps);
    (void)rdp_display_control_parse_monitor_layout(data,
                                                   size,
                                                   monitors,
                                                   (uint32_t)(sizeof(monitors) / sizeof(monitors[0])),
                                                   &monitor_count);
    (void)rdp_display_control_parse_monitor_layout_with_caps(data,
                                                             size,
                                                             monitors,
                                                             (uint32_t)(sizeof(monitors) / sizeof(monitors[0])),
                                                             &monitor_count,
                                                             &caps);
    rdp_buffer_init(&layout);
    if (rdp_display_control_make_single_monitor(&monitor,
                                                size > 0 ? (uint32_t)data[0] * 64u : 1024u,
                                                size > 1 ? (uint32_t)data[1] * 64u : 768u) == LIBRDP_STATUS_OK)
    {
        (void)rdp_display_control_write_monitor_layout(&layout, &monitor, 1);
        layout.length = 0;
        monitors[0] = monitor;
        monitors[1] = monitor;
        monitors[1].flags = 0;
        monitors[1].left = (int32_t)monitor.width;
        (void)rdp_display_control_write_monitor_layout_with_caps(&layout, monitors, 2, &caps);
    }
    rdp_buffer_free(&layout);
    return 0;
}
