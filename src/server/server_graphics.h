/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: server framebuffer, graphics output, and desktop composition.
 * Invariants: rectangles and frame state are bounded before wire emission.
 * Ownership: peers own framebuffer and graphics lifecycle state.
 * Threading: graphics operations run on the peer owner thread.
 * Trust boundary: client acknowledgements and refresh requests are untrusted.
 */

#ifndef RDP_SERVER_GRAPHICS_H
#define RDP_SERVER_GRAPHICS_H

#include "server/server_common.h"

void rdp_server_graphics_frame_state_reset(librdp_server_peer* peer);

/*
 * Replace the peer-owned desktop buffer while preserving the negotiated
 * dimensions as the sole bounds used by subsequent graphics operations.
 */
librdp_status rdp_server_surface_set_dimensions(librdp_server_peer* peer,
                                                uint32_t width,
                                                uint32_t height);

librdp_status rdp_server_surface_flush_repaint(librdp_server_peer* peer);

librdp_status rdp_server_handle_refresh_rect(librdp_server_peer* peer,
                                                    const uint8_t* payload,
                                                    size_t payload_len);

librdp_status rdp_server_graphics_handle_frame_ack(librdp_server_peer* peer,
                                                          const uint8_t* data,
                                                          size_t data_len);

#endif
