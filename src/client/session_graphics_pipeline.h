/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal graphics pipeline channel contracts.
 * Invariants: RDP graphics capability, surface lifecycle, codec availability,
 * frame markers, and backpressure are enforced before updates are normalized.
 * Ownership: graphics pipeline frames and decompressor state are session-owned.
 * Threading: graphics pipeline dispatch runs on the session owner thread.
 * Trust boundary: graphics channel PDUs and codec payloads are untrusted server
 * input.
 */

#ifndef RDP_CLIENT_SESSION_GRAPHICS_PIPELINE_H
#define RDP_CLIENT_SESSION_GRAPHICS_PIPELINE_H

#include <librdp/session.h>

#include <stddef.h>
#include <stdint.h>

void rdp_session_graphics_cache_clear(librdp_session* session);
librdp_status rdp_session_send_graphics_caps(librdp_session* session);
librdp_status rdp_session_handle_graphics_message(librdp_session* session,
                                                  uint32_t channel_id,
                                                  const uint8_t* data,
                                                  size_t data_len);

#endif
