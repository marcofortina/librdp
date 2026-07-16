/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal GDI order and cache contracts.
 * Invariants: negotiated order support, cache quotas, glyph extents, palette
 * state, and destination bounds are checked before rendering.
 * Ownership: GDI caches, offscreen bitmaps, and stream-bitmap buffers are owned
 * by the session.
 * Threading: GDI decode and render helpers run on the session owner thread.
 * Trust boundary: GDI order streams and cache references are untrusted server
 * data.
 */

#ifndef RDP_CLIENT_SESSION_GDI_H
#define RDP_CLIENT_SESSION_GDI_H

#include <librdp/session.h>

#include "graphics/gdi_orders.h"
#include "graphics/surface_commands.h"
#include "protocol/slowpath.h"

void rdp_session_gdi_bitmap_cache_clear(librdp_session* session);
void rdp_session_gdi_color_table_cache_clear(librdp_session* session);
void rdp_session_gdi_brush_cache_clear(librdp_session* session);
void rdp_session_gdi_ninegrid_cache_clear(librdp_session* session);
void rdp_session_gdi_glyph_cache_clear(librdp_session* session);
void rdp_session_gdi_glyph_fragment_cache_clear(librdp_session* session);
void rdp_session_gdi_saved_bitmaps_clear(librdp_session* session);
void rdp_session_gdi_offscreen_cache_clear(librdp_session* session);
void rdp_session_gdi_stream_bitmap_reset(librdp_session* session);
void rdp_session_gdi_gdiplus_reset(librdp_session* session);
void rdp_session_gdi_window_state_reset(librdp_session* session);
void rdp_session_palette_reset(librdp_session* session);
librdp_status rdp_session_apply_palette_update(librdp_session* session, const rdp_palette_update* palette);
librdp_status rdp_session_apply_surface_commands(librdp_session* session,
                                                 const rdp_surface_command_list* list);
librdp_status rdp_session_apply_gdi_orders_update(librdp_session* session, const rdp_gdi_orders_update* update);

#endif
