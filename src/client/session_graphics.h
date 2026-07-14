/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal primary graphics, surface, and pointer contracts.
 * Invariants: rectangles, strides, cache indices, and pointer dimensions are
 * validated before surface mutation or callback emission.
 * Ownership: graphics surfaces, caches, dirty regions, and pointer entries are
 * owned by the session.
 * Threading: graphics helpers run on the session owner thread.
 * Trust boundary: bitmap updates, pointer shapes, and cache references are
 * untrusted server data.
 */

#ifndef RDP_CLIENT_SESSION_GRAPHICS_H
#define RDP_CLIENT_SESSION_GRAPHICS_H

#include <librdp/session.h>

#include "common/buffer.h"
#include "protocol/pointer.h"

#include <stddef.h>
#include <stdint.h>

struct rdp_session_graphics_surface;

void rdp_session_emit_surface_invalidated(librdp_session* session, uint32_t x, uint32_t y, uint32_t width, uint32_t height);
void rdp_session_graphics_dirty_reset(librdp_session* session);
void rdp_session_graphics_dirty_add(librdp_session* session, uint32_t x, uint32_t y, uint32_t width, uint32_t height);
void rdp_session_graphics_dirty_flush(librdp_session* session);
struct rdp_session_graphics_surface* rdp_session_graphics_surface_find(librdp_session* session, uint16_t surface_id);
void rdp_session_graphics_surfaces_clear(librdp_session* session);
uint64_t rdp_session_trace_hash_bgra(const uint8_t* pixels, uint32_t width, uint32_t height, size_t stride);
uint64_t rdp_session_trace_surface_hash(const struct rdp_session_graphics_surface* surface,
                                        uint32_t x,
                                        uint32_t y,
                                        uint32_t width,
                                        uint32_t height);
librdp_status rdp_session_graphics_surface_write_bgra(librdp_session* session,
                                                      struct rdp_session_graphics_surface* surface,
                                                      uint16_t x,
                                                      uint16_t y,
                                                      uint16_t width,
                                                      uint16_t height,
                                                      const uint8_t* pixels,
                                                      size_t stride,
                                                      int force_opaque,
                                                      const char* source);
void rdp_session_pointer_cache_clear(librdp_session* session);
void rdp_session_pointer_emit_default(librdp_session* session);
librdp_status rdp_session_pointer_apply_update(librdp_session* session, const rdp_pointer_update* update);

#endif
