/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for mouse cursor channel pointer shape parser paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "channels/mouse_cursor.h"

#include "common/buffer.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises mouse cursor channel pointer shape parser paths with
 * one arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_mouse_cursor_header header;
    rdp_mouse_cursor_capset capset;
    rdp_pointer_update update;
    rdp_buffer response;
    rdp_buffer decoded;
    size_t stride = 0;

    rdp_buffer_init(&response);
    rdp_buffer_init(&decoded);
    (void)rdp_mouse_cursor_parse_header(data, size, &header);
    (void)rdp_mouse_cursor_parse_caps_confirm(data, size, &capset);
    if (rdp_mouse_cursor_parse_update(data, size, &update) == LIBRDP_STATUS_OK)
        (void)rdp_pointer_decode_bgra32(&update, &decoded, &stride);
    (void)rdp_mouse_cursor_write_caps_advertise(&response);
    rdp_buffer_free(&decoded);
    rdp_buffer_free(&response);
    return 0;
}
