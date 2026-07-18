/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client RDP graphics pipeline session domain.
 * Invariants: surface, codec, and graphics-cache state is updated only after wire bounds and negotiated codec support are validated.
 * Ownership: the session owns all surface/cache buffers and progressive tile state; emitted callbacks receive temporary views only.
 * Threading: callers must run on the session owner thread because frame, dirty-region, and cache sequencing are mutable session state.
 * Trust boundary: all rectangles, codec payloads, cache slots, and frame markers originate from dynamic virtual channel traffic.
 */

#include "client/session_internal.h"
#include "graphics/planar.h"
#include "graphics/rfx_stream.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

rdp_session_graphics_surface* rdp_session_graphics_surface_find(librdp_session* session, uint16_t surface_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < session->limits.surface_count; i++)
    {
        if (session->graphics_surfaces[i].active && session->graphics_surfaces[i].surface_id == surface_id)
            return &session->graphics_surfaces[i];
    }
    return NULL;
}

static rdp_session_graphics_surface* rdp_session_graphics_surface_find_slot(librdp_session* session,
                                                                            uint16_t surface_id)
{
    size_t i = 0;
    rdp_session_graphics_surface* free_slot = NULL;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_MAX_GRAPHICS_SURFACES; i++)
    {
        if (session->graphics_surfaces[i].active && session->graphics_surfaces[i].surface_id == surface_id)
            return &session->graphics_surfaces[i];
        if (!session->graphics_surfaces[i].active && !free_slot)
            free_slot = &session->graphics_surfaces[i];
    }
    return free_slot;
}

static void rdp_session_progressive_tiles_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        free(session->progressive_tiles[i].state);
        free(session->progressive_tiles[i].pixels);
        session->progressive_tiles[i].state = NULL;
        session->progressive_tiles[i].pixels = NULL;
    }
    memset(session->progressive_tiles, 0, sizeof(session->progressive_tiles));
    session->progressive_tile_clock = 0;
}

static void rdp_session_progressive_tiles_clear_surface(librdp_session* session, uint16_t surface_id)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        rdp_session_progressive_tile_cache* entry = &session->progressive_tiles[i];

        if (entry->active && entry->surface_id == surface_id)
        {
            free(entry->state);
            free(entry->pixels);
            memset(entry, 0, sizeof(*entry));
        }
    }
}

static rdp_session_progressive_tile_cache* rdp_session_progressive_tile_find(librdp_session* session,
                                                                             uint16_t surface_id,
                                                                             uint16_t x_idx,
                                                                             uint16_t y_idx)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        rdp_session_progressive_tile_cache* entry = &session->progressive_tiles[i];

        if (entry->active && entry->surface_id == surface_id &&
            entry->x_idx == x_idx && entry->y_idx == y_idx)
            return entry;
    }
    return NULL;
}

static rdp_session_progressive_tile_cache* rdp_session_progressive_tile_get(librdp_session* session,
                                                                            uint16_t surface_id,
                                                                            uint16_t x_idx,
                                                                            uint16_t y_idx,
                                                                            int create)
{
    size_t i = 0;
    rdp_session_progressive_tile_cache* entry = NULL;
    rdp_session_progressive_tile_cache* victim = NULL;
    size_t victim_slot = 0;
    int evicting = 0;
    uint16_t old_surface_id = 0;
    uint16_t old_x_idx = 0;
    uint16_t old_y_idx = 0;
    uint32_t old_valid = 0;
    uint32_t old_pass = 0;

    if (!session)
        return NULL;
    entry = rdp_session_progressive_tile_find(session, surface_id, x_idx, y_idx);
    if (entry)
    {
        entry->last_used = ++session->progressive_tile_clock;
        return entry;
    }
    if (!create)
        return NULL;

    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        rdp_session_progressive_tile_cache* candidate = &session->progressive_tiles[i];

        if (!candidate->active)
        {
            victim = candidate;
            break;
        }
        if (!victim || candidate->last_used < victim->last_used)
            victim = candidate;
    }
    if (!victim)
        return NULL;
    victim_slot = (size_t)(victim - session->progressive_tiles);
    evicting = victim->active != 0;
    if (evicting)
    {
        old_surface_id = victim->surface_id;
        old_x_idx = victim->x_idx;
        old_y_idx = victim->y_idx;
        old_valid = victim->state ? victim->state->valid : 0u;
        old_pass = victim->state ? victim->state->pass : 0u;
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "client.graphics.progressive.tile_state.evict",
                              "slot=%u old_surface_id=%u old_x_idx=%u old_y_idx=%u old_valid=%u old_pass=%u old_frame_id=%u new_surface_id=%u new_x_idx=%u new_y_idx=%u",
                              (unsigned)victim_slot,
                              old_surface_id,
                              old_x_idx,
                              old_y_idx,
                              old_valid,
                              old_pass,
                              victim->updated_frame_id,
                              surface_id,
                              x_idx,
                              y_idx);
    }
    if (!victim->state)
    {
        victim->state = (rdp_rfx_progressive_tile_state*)calloc(1, sizeof(*victim->state));
        if (!victim->state)
            return NULL;
    }
    if (!victim->pixels)
    {
        victim->pixels = (rdp_rfx_tile_pixels*)calloc(1, sizeof(*victim->pixels));
        if (!victim->pixels)
            return NULL;
    }
    else
    {
        memset(victim->pixels, 0, sizeof(*victim->pixels));
    }
    if (victim->state)
    {
        memset(victim->state, 0, sizeof(*victim->state));
    }
    victim->active = 1;
    victim->surface_id = surface_id;
    victim->x_idx = x_idx;
    victim->y_idx = y_idx;
    victim->has_pixels = 0;
    victim->updated_frame_id = 0;
    victim->last_used = ++session->progressive_tile_clock;
    victim->state->x_idx = x_idx;
    victim->state->y_idx = y_idx;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.progressive.tile_state.alloc",
                          "slot=%u surface_id=%u x_idx=%u y_idx=%u evicted=%u",
                          (unsigned)victim_slot,
                          surface_id,
                          x_idx,
                          y_idx,
                          (unsigned)evicting);
    return victim;
}

void rdp_session_graphics_surfaces_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    rdp_session_progressive_tiles_clear(session);
    rdp_avc_decoder_reset(session->avc);
    for (i = 0; i < RDP_SESSION_MAX_GRAPHICS_SURFACES; i++)
        rdp_buffer_free(&session->graphics_surfaces[i].pixels);
    memset(session->graphics_surfaces, 0, sizeof(session->graphics_surfaces));
}

static librdp_status rdp_session_graphics_surface_create(librdp_session* session,
                                                         const rdp_graphics_create_surface* create)
{
    rdp_session_graphics_surface* surface = NULL;
    size_t stride = 0;
    size_t size = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !create)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (create->width == 0 || create->height == 0 ||
        create->width > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION ||
        create->height > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (create->width > session->limits.surface_max_dimension ||
        create->height > session->limits.surface_max_dimension)
        return rdp_session_limit_rejected(session);

    stride = (size_t)create->width * 4u;
    if ((size_t)create->height > ((size_t)-1) / stride)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    size = stride * (size_t)create->height;

    surface = rdp_session_graphics_surface_find_slot(session, create->surface_id);
    if (!surface)
        return LIBRDP_STATUS_NO_MEMORY;

    if (surface->active)
        rdp_session_progressive_tiles_clear_surface(session, create->surface_id);
    rdp_buffer_free(&surface->pixels);
    memset(surface, 0, sizeof(*surface));
    status = rdp_buffer_reserve(&surface->pixels, size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(surface->pixels.data, 0, size);
    surface->pixels.length = size;
    surface->active = 1;
    surface->surface_id = create->surface_id;
    surface->width = create->width;
    surface->height = create->height;
    surface->target_width = create->width;
    surface->target_height = create->height;
    surface->pixel_format = create->pixel_format;
    {
        librdp_rect rect;

        rect.x = 0;
        rect.y = 0;
        rect.width = create->width;
        rect.height = create->height;
        rdp_session_emit_graphics_update(session,
                                         LIBRDP_GRAPHICS_UPDATE_SURFACE_CREATE,
                                         create->surface_id,
                                         session->graphics_current_frame_id,
                                         &rect,
                                         LIBRDP_PIXEL_FORMAT_BGRA32,
                                         NULL,
                                         0);
    }
    return LIBRDP_STATUS_OK;
}

static void rdp_session_graphics_surface_delete(librdp_session* session, uint16_t surface_id)
{
    rdp_session_graphics_surface* surface = rdp_session_graphics_surface_find(session, surface_id);
    librdp_rect rect;

    if (!surface)
        return;
    rect.x = 0;
    rect.y = 0;
    rect.width = surface->width;
    rect.height = surface->height;
    rdp_session_emit_graphics_update(session,
                                     LIBRDP_GRAPHICS_UPDATE_SURFACE_DESTROY,
                                     surface_id,
                                     session->graphics_current_frame_id,
                                     &rect,
                                     LIBRDP_PIXEL_FORMAT_BGRA32,
                                     NULL,
                                     0);
    rdp_session_progressive_tiles_clear_surface(session, surface_id);
    rdp_avc_decoder_reset(session->avc);
    rdp_buffer_free(&surface->pixels);
    memset(surface, 0, sizeof(*surface));
}

uint64_t rdp_session_trace_hash_bgra(const uint8_t* pixels,
                                            uint32_t width,
                                            uint32_t height,
                                            size_t stride);
uint64_t rdp_session_trace_surface_hash(const rdp_session_graphics_surface* surface,
                                               uint32_t x,
                                               uint32_t y,
                                               uint32_t width,
                                               uint32_t height);

/*
 * Flush a graphics surface into the primary framebuffer with scaling. Source
 * and destination rectangles are clipped together so partial monitor layouts
 * cannot read outside cached surfaces.
 */
static librdp_status rdp_session_graphics_surface_flush_scaled(librdp_session* session,
                                                               rdp_session_graphics_surface* surface,
                                                               uint16_t left,
                                                               uint16_t top,
                                                               uint16_t right,
                                                               uint16_t bottom,
                                                               const char* source)
{
    uint32_t output_width = 0;
    uint32_t output_height = 0;
    uint64_t rel_left = 0;
    uint64_t rel_top = 0;
    uint64_t rel_right = 0;
    uint64_t rel_bottom = 0;
    uint64_t abs_left = 0;
    uint64_t abs_top = 0;
    uint64_t abs_right = 0;
    uint64_t abs_bottom = 0;
    uint32_t dst_x = 0;
    uint32_t dst_y = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    size_t stride = 0;
    size_t scaled_stride = 0;
    size_t scaled_len = 0;
    uint32_t y = 0;
    rdp_buffer scaled;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !surface->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (surface->target_width == 0 || surface->target_height == 0 ||
        surface->target_width > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION ||
        surface->target_height > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (surface->target_width > session->limits.surface_max_dimension ||
        surface->target_height > session->limits.surface_max_dimension)
        return rdp_session_limit_rejected(session);

    output_width = librdp_surface_width(session->surface);
    output_height = librdp_surface_height(session->surface);
    rel_left = ((uint64_t)left * surface->target_width) / surface->width;
    rel_top = ((uint64_t)top * surface->target_height) / surface->height;
    rel_right = (((uint64_t)right * surface->target_width) + surface->width - 1u) / surface->width;
    rel_bottom = (((uint64_t)bottom * surface->target_height) + surface->height - 1u) / surface->height;
    if (rel_right <= rel_left || rel_bottom <= rel_top)
        return LIBRDP_STATUS_OK;

    abs_left = (uint64_t)surface->output_origin_x + rel_left;
    abs_top = (uint64_t)surface->output_origin_y + rel_top;
    abs_right = (uint64_t)surface->output_origin_x + rel_right;
    abs_bottom = (uint64_t)surface->output_origin_y + rel_bottom;
    if (abs_left >= output_width || abs_top >= output_height || abs_right <= abs_left || abs_bottom <= abs_top)
        return LIBRDP_STATUS_OK;
    if (abs_right > output_width)
        abs_right = output_width;
    if (abs_bottom > output_height)
        abs_bottom = output_height;
    dst_x = (uint32_t)abs_left;
    dst_y = (uint32_t)abs_top;
    width = (uint32_t)(abs_right - abs_left);
    height = (uint32_t)(abs_bottom - abs_top);
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_OK;

    scaled_stride = (size_t)width * 4u;
    if ((size_t)height > ((size_t)-1) / scaled_stride)
        return LIBRDP_STATUS_NO_MEMORY;
    scaled_len = scaled_stride * height;
    rdp_buffer_init(&scaled);
    status = rdp_buffer_reserve(&scaled, scaled_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    scaled.length = scaled_len;

    stride = (size_t)surface->width * 4u;
    for (y = 0; y < height; y++)
    {
        uint64_t rel_y = ((uint64_t)dst_y + y) - surface->output_origin_y;
        uint32_t src_y = (uint32_t)((rel_y * surface->height) / surface->target_height);
        uint8_t* dst = scaled.data + ((size_t)y * scaled_stride);
        uint32_t x = 0;

        if (src_y >= surface->height)
            src_y = surface->height - 1u;
        for (x = 0; x < width; x++)
        {
            uint64_t rel_x = ((uint64_t)dst_x + x) - surface->output_origin_x;
            uint32_t src_x = (uint32_t)((rel_x * surface->width) / surface->target_width);
            const uint8_t* src = NULL;

            if (src_x >= surface->width)
                src_x = surface->width - 1u;
            src = surface->pixels.data + ((size_t)src_y * stride) + ((size_t)src_x * 4u);
            memcpy(dst + ((size_t)x * 4u), src, 4u);
        }
    }

    status = librdp_surface_blit_bgra32(session->surface,
                                        dst_x,
                                        dst_y,
                                        width,
                                        height,
                                        scaled.data,
                                        scaled_stride);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_session_graphics_dirty_add(session, dst_x, dst_y, width, height);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "client.graphics.surface.flush_scaled",
                              "source=%s surface_id=%u src_x=%u src_y=%u src_width=%u src_height=%u dst_x=%u dst_y=%u dst_width=%u dst_height=%u surface_width=%u surface_height=%u target_width=%u target_height=%u frame_id=%u scaled_hash=%016llx",
                              source ? source : "unknown",
                              surface->surface_id,
                              left,
                              top,
                              (uint32_t)(right - left),
                              (uint32_t)(bottom - top),
                              dst_x,
                              dst_y,
                              width,
                              height,
                              surface->width,
                              surface->height,
                              surface->target_width,
                              surface->target_height,
                              session->graphics_current_frame_id,
                              (unsigned long long)rdp_session_trace_hash_bgra(scaled.data,
                                                                               width,
                                                                               height,
                                                                               scaled_stride));
    }
    rdp_buffer_free(&scaled);
    return status;
}

/*
 * Flush a graphics surface into the primary framebuffer without scaling. Dirty
 * tracking is updated only after clipped blits have reached the session
 * surface.
 */
static librdp_status rdp_session_graphics_surface_flush(librdp_session* session,
                                                        rdp_session_graphics_surface* surface,
                                                        uint16_t left,
                                                        uint16_t top,
                                                        uint16_t right,
                                                        uint16_t bottom,
                                                        const char* source)
{
    uint64_t dst_x64 = 0;
    uint64_t dst_y64 = 0;
    uint32_t dst_x = 0;
    uint32_t dst_y = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t output_width = 0;
    uint32_t output_height = 0;
    size_t stride = 0;
    size_t output_stride = 0;
    const uint8_t* pixels = NULL;
    const uint8_t* output_pixels = NULL;
    uint64_t source_hash = 0;
    uint64_t output_hash = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !surface->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!surface->mapped || left >= right || top >= bottom)
        return LIBRDP_STATUS_OK;
    if (right > surface->width || bottom > surface->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (surface->scaled)
        return rdp_session_graphics_surface_flush_scaled(session,
                                                         surface,
                                                         left,
                                                         top,
                                                         right,
                                                         bottom,
                                                         source);

    output_width = librdp_surface_width(session->surface);
    output_height = librdp_surface_height(session->surface);
    dst_x64 = (uint64_t)surface->output_origin_x + left;
    dst_y64 = (uint64_t)surface->output_origin_y + top;
    if (dst_x64 >= output_width || dst_y64 >= output_height)
        return LIBRDP_STATUS_OK;
    dst_x = (uint32_t)dst_x64;
    dst_y = (uint32_t)dst_y64;
    width = (uint32_t)(right - left);
    height = (uint32_t)(bottom - top);
    if (width > output_width - dst_x)
        width = output_width - dst_x;
    if (height > output_height - dst_y)
        height = output_height - dst_y;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_OK;

    stride = (size_t)surface->width * 4u;
    pixels = surface->pixels.data + ((size_t)top * stride) + ((size_t)left * 4u);
    source_hash = rdp_session_trace_hash_bgra(pixels, width, height, stride);
    status = librdp_surface_blit_bgra32(session->surface, dst_x, dst_y, width, height, pixels, stride);
    if (status == LIBRDP_STATUS_OK)
    {
        output_stride = librdp_surface_stride(session->surface);
        output_pixels = librdp_surface_pixels(session->surface);
        if (output_pixels)
        {
            output_hash = rdp_session_trace_hash_bgra(output_pixels + ((size_t)dst_y * output_stride) +
                                                          ((size_t)dst_x * 4u),
                                                      width,
                                                      height,
                                                      output_stride);
        }
        rdp_session_graphics_dirty_add(session, dst_x, dst_y, width, height);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "client.graphics.surface.flush",
                              "source=%s surface_id=%u src_x=%u src_y=%u dst_x=%u dst_y=%u width=%u height=%u surface_width=%u surface_height=%u output_width=%u output_height=%u frame_id=%u frame_active=%u source_hash=%016llx output_hash=%016llx",
                              source ? source : "unknown",
                              surface->surface_id,
                              left,
                              top,
                              dst_x,
                              dst_y,
                              width,
                              height,
                              surface->width,
                              surface->height,
                              output_width,
                              output_height,
                              session->graphics_current_frame_id,
                              session->graphics_frame_active ? 1u : 0u,
                              (unsigned long long)source_hash,
                              (unsigned long long)output_hash);
    }
    return status;
}

static librdp_status rdp_session_graphics_surface_map(librdp_session* session,
                                                      const rdp_graphics_map_surface_to_output* map)
{
    rdp_session_graphics_surface* surface = NULL;

    if (!session || !map)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    surface = rdp_session_graphics_surface_find(session, map->surface_id);
    if (!surface)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    surface->mapped = 1;
    surface->output_origin_x = map->output_origin_x;
    surface->output_origin_y = map->output_origin_y;
    surface->target_width = surface->width;
    surface->target_height = surface->height;
    surface->scaled = 0;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_surface_map_scaled(
    librdp_session* session,
    const rdp_graphics_map_surface_to_scaled_output* map)
{
    rdp_session_graphics_surface* surface = NULL;

    if (!session || !map)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (map->target_width == 0 || map->target_height == 0 ||
        map->target_width > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION ||
        map->target_height > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (map->target_width > session->limits.surface_max_dimension ||
        map->target_height > session->limits.surface_max_dimension)
        return rdp_session_limit_rejected(session);
    surface = rdp_session_graphics_surface_find(session, map->surface_id);
    if (!surface)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    surface->mapped = 1;
    surface->output_origin_x = map->output_origin_x;
    surface->output_origin_y = map->output_origin_y;
    surface->target_width = map->target_width;
    surface->target_height = map->target_height;
    surface->scaled = map->target_width != surface->width || map->target_height != surface->height;
    return rdp_session_graphics_surface_flush(session,
                                              surface,
                                              0,
                                              0,
                                              surface->width,
                                              surface->height,
                                              surface->scaled ? "map_scaled_output" : "map_output");
}

static librdp_status rdp_session_graphics_surface_fill(librdp_session* session,
                                                       rdp_session_graphics_surface* surface,
                                                       const rdp_graphics_rect16* rect,
                                                       uint32_t fill_pixel)
{
    uint8_t b = (uint8_t)(fill_pixel & 0xffu);
    uint8_t g = (uint8_t)((fill_pixel >> 8) & 0xffu);
    uint8_t r = (uint8_t)((fill_pixel >> 16) & 0xffu);
    uint8_t a = 0xffu;
    size_t stride = 0;
    uint16_t y = 0;

    if (!session || !surface || !rect || !surface->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rect->right > surface->width || rect->bottom > surface->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rect->left >= rect->right || rect->top >= rect->bottom)
        return LIBRDP_STATUS_OK;
    if (surface->pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_ARGB_8888)
        a = (uint8_t)((fill_pixel >> 24) & 0xffu);

    stride = (size_t)surface->width * 4u;
    for (y = rect->top; y < rect->bottom; y++)
    {
        uint8_t* pixel = surface->pixels.data + ((size_t)y * stride) + ((size_t)rect->left * 4u);
        uint16_t x = 0;

        for (x = rect->left; x < rect->right; x++)
        {
            pixel[0] = b;
            pixel[1] = g;
            pixel[2] = r;
            pixel[3] = a;
            pixel += 4;
        }
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.surface.fill.rect",
                          "source=solid_fill surface_id=%u x=%u y=%u width=%u height=%u surface_width=%u surface_height=%u fill_pixel=%08x frame_id=%u dest_hash=%016llx",
                          surface->surface_id,
                          rect->left,
                          rect->top,
                          (unsigned)(rect->right - rect->left),
                          (unsigned)(rect->bottom - rect->top),
                          surface->width,
                          surface->height,
                          fill_pixel,
                          session->graphics_current_frame_id,
                          (unsigned long long)rdp_session_trace_surface_hash(surface,
                                                                              rect->left,
                                                                              rect->top,
                                                                              (uint32_t)(rect->right - rect->left),
                                                                              (uint32_t)(rect->bottom - rect->top)));
    return rdp_session_graphics_surface_flush(session,
                                              surface,
                                              rect->left,
                                              rect->top,
                                              rect->right,
                                              rect->bottom,
                                              "solid_fill");
}

librdp_status rdp_session_graphics_surface_write_bgra(librdp_session* session,
                                                             rdp_session_graphics_surface* surface,
                                                             uint16_t x,
                                                             uint16_t y,
                                                             uint16_t width,
                                                             uint16_t height,
                                                             const uint8_t* pixels,
                                                             size_t stride,
                                                             int force_opaque,
                                                             const char* source)
{
    uint16_t row = 0;
    size_t dest_stride = 0;
    uint64_t source_hash = 0;
    uint64_t dest_hash = 0;

    if (!session || !surface || !surface->active || !pixels)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_OK;
    if (x > surface->width || y > surface->height ||
        width > surface->width - x || height > surface->height - y ||
        stride < (size_t)width * 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    source_hash = rdp_session_trace_hash_bgra(pixels, width, height, stride);
    dest_stride = (size_t)surface->width * 4u;
    for (row = 0; row < height; row++)
    {
        uint8_t* dest = surface->pixels.data + ((size_t)(y + row) * dest_stride) + ((size_t)x * 4u);
        const uint8_t* source = pixels + ((size_t)row * stride);

        memcpy(dest, source, (size_t)width * 4u);
        if (force_opaque)
        {
            uint16_t column = 0;

            for (column = 0; column < width; column++)
                dest[((size_t)column * 4u) + 3u] = 0xffu;
        }
    }
    dest_hash = rdp_session_trace_surface_hash(surface, x, y, width, height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.surface.write",
                          "source=%s surface_id=%u x=%u y=%u width=%u height=%u surface_width=%u surface_height=%u stride=%u dest_stride=%u force_opaque=%u frame_id=%u source_hash=%016llx dest_hash=%016llx",
                          source ? source : "unknown",
                          surface->surface_id,
                          x,
                          y,
                          width,
                          height,
                          surface->width,
                          surface->height,
                          (unsigned)stride,
                          (unsigned)dest_stride,
                          force_opaque ? 1u : 0u,
                          session->graphics_current_frame_id,
                          (unsigned long long)source_hash,
                          (unsigned long long)dest_hash);
    return rdp_session_graphics_surface_flush(session,
                                              surface,
                                              x,
                                              y,
                                              (uint16_t)(x + width),
                                              (uint16_t)(y + height),
                                              source);
}

static librdp_status rdp_session_graphics_surface_write_avc_regions(
    librdp_session* session,
    rdp_session_graphics_surface* surface,
    const rdp_graphics_avc420_metablock* meta,
    const rdp_avc_frame* frame,
    int force_opaque,
    const char* source)
{
    uint32_t i = 0;

    if (!session || !surface || !meta || !frame || !frame->pixels.data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (frame->stride < (size_t)frame->width * 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    for (i = 0; i < meta->rect_count; i++)
    {
        rdp_graphics_rect16 rect;
        uint16_t width = 0;
        uint16_t height = 0;
        const uint8_t* pixels = NULL;
        librdp_status status = LIBRDP_STATUS_OK;

        if (meta->rects_len < ((size_t)i + 1u) * 8u ||
            rdp_graphics_parse_rect16(meta->rects + ((size_t)i * 8u), 8u, &rect) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rect.left >= rect.right || rect.top >= rect.bottom ||
            rect.right > surface->width || rect.bottom > surface->height ||
            rect.right > frame->width || rect.bottom > frame->height)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        width = (uint16_t)(rect.right - rect.left);
        height = (uint16_t)(rect.bottom - rect.top);
        pixels = frame->pixels.data + ((size_t)rect.top * frame->stride) + ((size_t)rect.left * 4u);
        status = rdp_session_graphics_surface_write_bgra(session,
                                                         surface,
                                                         rect.left,
                                                         rect.top,
                                                         width,
                                                         height,
                                                         pixels,
                                                         frame->stride,
                                                         force_opaque,
                                                         source);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_surface_write_wire(librdp_session* session,
                                                             rdp_session_graphics_surface* surface,
                                                             const rdp_graphics_wire_to_surface_1* wire)
{
    uint16_t width = 0;
    uint16_t height = 0;
    size_t expected = 0;

    if (!session || !surface || !wire)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (wire->dest_rect.right < wire->dest_rect.left || wire->dest_rect.bottom < wire->dest_rect.top)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    width = (uint16_t)(wire->dest_rect.right - wire->dest_rect.left);
    height = (uint16_t)(wire->dest_rect.bottom - wire->dest_rect.top);
    expected = (size_t)width * (size_t)height * 4u;
    if (wire->bitmap_data_length != expected)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_session_graphics_surface_write_bgra(session,
                                                   surface,
                                                   wire->dest_rect.left,
                                                   wire->dest_rect.top,
                                                   width,
                                                   height,
                                                   wire->bitmap_data,
                                                   (size_t)width * 4u,
                                                   wire->pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                                   "uncompressed");
}

static librdp_status rdp_session_graphics_surface_alpha_run(rdp_session_graphics_surface* surface,
                                                            uint16_t left,
                                                            uint16_t top,
                                                            uint16_t width,
                                                            uint32_t* position,
                                                            uint32_t total,
                                                            uint32_t count,
                                                            uint8_t alpha)
{
    uint32_t i = 0;
    size_t stride = 0;

    if (!surface || !position || count == 0 || count > total - *position)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    stride = (size_t)surface->width * 4u;
    for (i = 0; i < count; i++)
    {
        uint32_t index = *position + i;
        uint32_t x = (uint32_t)left + (index % width);
        uint32_t y = (uint32_t)top + (index / width);
        uint8_t* pixel = surface->pixels.data + ((size_t)y * stride) + ((size_t)x * 4u);

        pixel[3] = alpha;
    }
    *position += count;
    return LIBRDP_STATUS_OK;
}

/*
 * Apply alpha composition for a graphics surface update. The routine keeps
 * source pixels, destination clips, and blend mode validation together before
 * mutating the visible framebuffer.
 */
static librdp_status rdp_session_graphics_surface_apply_alpha(librdp_session* session,
                                                              rdp_session_graphics_surface* surface,
                                                              const rdp_graphics_wire_to_surface_1* wire)
{
    uint16_t left = 0;
    uint16_t top = 0;
    uint16_t width = 0;
    uint16_t height = 0;
    uint16_t signature = 0;
    uint16_t compressed = 0;
    uint32_t total = 0;
    uint32_t position = 0;
    size_t offset = 4u;
    size_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !wire || !wire->bitmap_data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (wire->dest_rect.left >= wire->dest_rect.right ||
        wire->dest_rect.top >= wire->dest_rect.bottom ||
        wire->dest_rect.right > surface->width ||
        wire->dest_rect.bottom > surface->height ||
        wire->bitmap_data_length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    left = wire->dest_rect.left;
    top = wire->dest_rect.top;
    width = (uint16_t)(wire->dest_rect.right - wire->dest_rect.left);
    height = (uint16_t)(wire->dest_rect.bottom - wire->dest_rect.top);
    if ((uint32_t)width > UINT32_MAX / (uint32_t)height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    total = (uint32_t)width * (uint32_t)height;
    signature = (uint16_t)(wire->bitmap_data[0] | ((uint16_t)wire->bitmap_data[1] << 8u));
    compressed = (uint16_t)(wire->bitmap_data[2] | ((uint16_t)wire->bitmap_data[3] << 8u));
    if (signature != 0x414cu)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (compressed == 0)
    {
        if (wire->bitmap_data_length - offset != total)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (i = 0; i < total; i++)
        {
            status = rdp_session_graphics_surface_alpha_run(surface,
                                                            left,
                                                            top,
                                                            width,
                                                            &position,
                                                            total,
                                                            1,
                                                            wire->bitmap_data[offset + i]);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
    }
    else
    {
        while (position < total)
        {
            uint8_t alpha = 0;
            uint32_t count = 0;

            if (wire->bitmap_data_length - offset < 2u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            alpha = wire->bitmap_data[offset++];
            count = wire->bitmap_data[offset++];
            if (count >= 0xffu)
            {
                if (wire->bitmap_data_length - offset < 2u)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                count = (uint32_t)wire->bitmap_data[offset] |
                        ((uint32_t)wire->bitmap_data[offset + 1u] << 8u);
                offset += 2u;
                if (count >= 0xffffu)
                {
                    if (wire->bitmap_data_length - offset < 4u)
                        return LIBRDP_STATUS_PROTOCOL_ERROR;
                    count = (uint32_t)wire->bitmap_data[offset] |
                            ((uint32_t)wire->bitmap_data[offset + 1u] << 8u) |
                            ((uint32_t)wire->bitmap_data[offset + 2u] << 16u) |
                            ((uint32_t)wire->bitmap_data[offset + 3u] << 24u);
                    offset += 4u;
                }
            }
            status = rdp_session_graphics_surface_alpha_run(surface,
                                                            left,
                                                            top,
                                                            width,
                                                            &position,
                                                            total,
                                                            count,
                                                            alpha);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        if (offset != wire->bitmap_data_length)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }

    status = rdp_session_graphics_surface_flush(session,
                                                surface,
                                                left,
                                                top,
                                                wire->dest_rect.right,
                                                wire->dest_rect.bottom,
                                                "alpha");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.alpha",
                        "surface_id=%u x=%u y=%u width=%u height=%u compressed=%u pixels=%u",
                        surface->surface_id,
                        left,
                        top,
                        width,
                        height,
                        compressed ? 1u : 0u,
                        total);
    return status;
}

typedef struct rdp_session_graphics_rfx_context
{
    librdp_session* session;
    rdp_session_graphics_surface* surface;
    int force_opaque;
    uint16_t tiles;
} rdp_session_graphics_rfx_context;

static librdp_status rdp_session_graphics_rfx_tile(const rdp_rfx_stream_tile* tile, void* user)
{
    rdp_session_graphics_rfx_context* context = (rdp_session_graphics_rfx_context*)user;
    uint32_t width = 0;
    uint32_t height = 0;

    if (!tile || !context || !context->session || !context->surface)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (tile->x >= context->surface->width || tile->y >= context->surface->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    width = tile->width;
    height = tile->height;
    if (width > context->surface->width - tile->x)
        width = context->surface->width - tile->x;
    if (height > context->surface->height - tile->y)
        height = context->surface->height - tile->y;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (context->tiles < UINT16_MAX)
        context->tiles++;
    return rdp_session_graphics_surface_write_bgra(context->session,
                                                   context->surface,
                                                   (uint16_t)tile->x,
                                                   (uint16_t)tile->y,
                                                   (uint16_t)width,
                                                   (uint16_t)height,
                                                   tile->pixels.bgra,
                                                   tile->pixels.stride,
                                                   context->force_opaque,
                                                   "cavideo");
}

static librdp_status rdp_session_graphics_surface_write_rfx(librdp_session* session,
                                                            rdp_session_graphics_surface* surface,
                                                            const uint8_t* data,
                                                            size_t data_len,
                                                            uint8_t pixel_format)
{
    rdp_session_graphics_rfx_context context;
    rdp_rfx_stream_summary summary;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&context, 0, sizeof(context));
    memset(&summary, 0, sizeof(summary));
    context.session = session;
    context.surface = surface;
    context.force_opaque = pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888;
    status = rdp_rfx_stream_decode(data, data_len, rdp_session_graphics_rfx_tile, &context, &summary);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.cavideo",
                        "surface_id=%u frame_id=%u width=%u height=%u tiles=%u rects=%u blitted=%u",
                        surface->surface_id,
                        summary.frame_id,
                        summary.width,
                        summary.height,
                        summary.tile_count,
                        summary.rect_count,
                        context.tiles);
    return status;
}

static uint32_t rdp_session_min_u32(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}

static uint32_t rdp_session_max_u32(uint32_t a, uint32_t b)
{
    return a > b ? a : b;
}

static uint64_t rdp_session_trace_hash_seed(uint64_t hash, uint64_t value)
{
    unsigned int i = 0;

    for (i = 0; i < 8; i++)
    {
        hash ^= (uint8_t)((value >> (i * 8u)) & 0xffu);
        hash *= 1099511628211ull;
    }
    return hash;
}

static uint64_t rdp_session_trace_hash_bytes(uint64_t hash, const uint8_t* bytes, size_t length)
{
    size_t i = 0;

    for (i = 0; i < length; i++)
    {
        hash ^= bytes[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

uint64_t rdp_session_trace_hash_bgra(const uint8_t* pixels,
                                            uint32_t width,
                                            uint32_t height,
                                            size_t stride)
{
    const size_t row_bytes = (size_t)width * 4u;
    const uint64_t offset = 1469598103934665603ull;
    uint64_t hash = offset;
    uint64_t pixel_count = 0;
    uint64_t samples = 0;
    uint64_t i = 0;

    if (!rdp_trace_enabled_level(RDP_TRACE_CLIENT, RDP_TRACE_LEVEL_TRACE) ||
        !pixels || width == 0 || height == 0 || stride < row_bytes)
        return 0;

    hash = rdp_session_trace_hash_seed(hash, width);
    hash = rdp_session_trace_hash_seed(hash, height);
    pixel_count = (uint64_t)width * (uint64_t)height;
    samples = pixel_count < 8192u ? pixel_count : 8192u;
    if (samples == 0)
        return hash;
    if (samples == 1)
        return rdp_session_trace_hash_bytes(hash, pixels, 4u);

    for (i = 0; i < samples; i++)
    {
        const uint64_t pixel_index = (i * (pixel_count - 1u)) / (samples - 1u);
        const uint32_t row = (uint32_t)(pixel_index / width);
        const uint32_t column = (uint32_t)(pixel_index % width);
        const uint8_t* p = pixels + ((size_t)row * stride) + ((size_t)column * 4u);

        hash = rdp_session_trace_hash_bytes(hash, p, 4u);
    }
    return hash;
}

uint64_t rdp_session_trace_surface_hash(const rdp_session_graphics_surface* surface,
                                               uint32_t x,
                                               uint32_t y,
                                               uint32_t width,
                                               uint32_t height)
{
    size_t stride = 0;
    const uint8_t* pixels = NULL;

    if (!surface || !surface->active || !surface->pixels.data)
        return 0;
    if (width == 0 || height == 0 || x > surface->width || y > surface->height ||
        width > (uint32_t)surface->width - x || height > (uint32_t)surface->height - y)
        return 0;
    stride = (size_t)surface->width * 4u;
    pixels = surface->pixels.data + ((size_t)y * stride) + ((size_t)x * 4u);
    return rdp_session_trace_hash_bgra(pixels, width, height, stride);
}

static librdp_status rdp_session_graphics_progressive_base_quant(const rdp_graphics_progressive_region* region,
                                                                 uint8_t quant_idx,
                                                                 rdp_rfx_component_quant* quant)
{
    if (!region || !quant)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (quant_idx >= region->quant_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_rfx_parse_component_quant(region->quant_values + ((size_t)quant_idx * 5u), 5u, quant);
}

static librdp_status rdp_session_graphics_progressive_delta_quant(const rdp_graphics_progressive_region* region,
                                                                  uint8_t progressive_idx,
                                                                  uint8_t component_idx,
                                                                  rdp_rfx_component_quant* delta)
{
    rdp_rfx_progressive_quant progressive;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!region || !delta)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(delta, 0, sizeof(*delta));
    if (progressive_idx == 0xffu)
        return LIBRDP_STATUS_OK;
    if (progressive_idx >= region->progressive_quant_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_rfx_parse_progressive_quant(region->progressive_quant_values + ((size_t)progressive_idx * 16u),
                                             16u,
                                             &progressive);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (component_idx == 0)
        *delta = progressive.y;
    else if (component_idx == 1)
        *delta = progressive.cb;
    else if (component_idx == 2)
        *delta = progressive.cr;
    else
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

/*
 * Write one progressive-codec tile into a region buffer. Tile coordinates,
 * quantization state, and destination stride are validated before the partial
 * region becomes renderable.
 */
static librdp_status rdp_session_graphics_progressive_write_region_tile(
    librdp_session* session,
    rdp_session_graphics_surface* surface,
    const rdp_graphics_progressive_region* region,
    uint32_t x,
    uint32_t y,
    uint32_t width,
    uint32_t height,
    const rdp_rfx_tile_pixels* pixels,
    int* wrote)
{
    uint16_t i = 0;
    uint32_t tile_right = 0;
    uint32_t tile_bottom = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !region || !pixels || !wrote)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (pixels->stride < RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE * 4u)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.write_region.failed",
                        "stage=stride surface_id=%u tile_x=%u tile_y=%u tile_width=%u tile_height=%u stride=%u",
                        surface ? surface->surface_id : 0u,
                        x,
                        y,
                        width,
                        height,
                        (unsigned)pixels->stride);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }

    *wrote = 0;
    tile_right = x + width;
    tile_bottom = y + height;
    for (i = 0; i < region->rect_count; i++)
    {
        rdp_graphics_rect16 rect;
        uint32_t left = 0;
        uint32_t top = 0;
        uint32_t right = 0;
        uint32_t bottom = 0;
        const uint8_t* src = NULL;

        status = rdp_graphics_progressive_parse_region_rect(region->rects + ((size_t)i * 8u),
                                                            region->rects_len - ((size_t)i * 8u),
                                                            &rect);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.progressive.write_region.failed",
                            "stage=rect_parse surface_id=%u tile_x=%u tile_y=%u tile_width=%u tile_height=%u rect_index=%u status=%d",
                            surface->surface_id,
                            x,
                            y,
                            width,
                            height,
                            i,
                            (int)status);
            return status;
        }
        if (rect.right <= rect.left || rect.bottom <= rect.top)
            continue;

        left = rdp_session_max_u32(x, rect.left);
        top = rdp_session_max_u32(y, rect.top);
        right = rdp_session_min_u32(tile_right, rect.right);
        bottom = rdp_session_min_u32(tile_bottom, rect.bottom);
        if (right <= left || bottom <= top)
            continue;

        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "client.graphics.progressive.region.write",
                              "surface_id=%u tile_x=%u tile_y=%u tile_width=%u tile_height=%u rect_index=%u rect_left=%u rect_top=%u rect_right=%u rect_bottom=%u write_left=%u write_top=%u write_width=%u write_height=%u frame_id=%u",
                              surface->surface_id,
                              x,
                              y,
                              width,
                              height,
                              i,
                              rect.left,
                              rect.top,
                              rect.right,
                              rect.bottom,
                              left,
                              top,
                              right - left,
                              bottom - top,
                              session->graphics_current_frame_id);
        src = pixels->bgra + (((size_t)top - y) * pixels->stride) + (((size_t)left - x) * 4u);
        status = rdp_session_graphics_surface_write_bgra(session,
                                                         surface,
                                                         (uint16_t)left,
                                                         (uint16_t)top,
                                                         (uint16_t)(right - left),
                                                         (uint16_t)(bottom - top),
                                                         src,
                                                         pixels->stride,
                                                         0,
                                                         "progressive");
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.progressive.write_region.failed",
                            "stage=surface_write surface_id=%u surface_width=%u surface_height=%u tile_x=%u tile_y=%u tile_width=%u tile_height=%u rect_left=%u rect_top=%u rect_right=%u rect_bottom=%u write_left=%u write_top=%u write_width=%u write_height=%u stride=%u status=%d",
                            surface->surface_id,
                            surface->width,
                            surface->height,
                            x,
                            y,
                            width,
                            height,
                            rect.left,
                            rect.top,
                            rect.right,
                            rect.bottom,
                            left,
                            top,
                            right - left,
                            bottom - top,
                            (unsigned)pixels->stride,
                            (int)status);
            return status;
        }
        *wrote = 1;
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Progressive tiles update a cached surface through region clipping, optional
 * quantization upgrades, and dirty tracking. Render through this single path so
 * partial progressive state is promoted to the visible surface only after the
 * tile payload and destination rectangle have both been validated.
 */
static librdp_status rdp_session_graphics_progressive_render_tile(librdp_session* session,
                                                                  uint32_t channel_id,
                                                                  uint32_t codec_context_id,
                                                                  rdp_session_graphics_surface* surface,
                                                                  const rdp_graphics_progressive_region* region,
                                                                  uint16_t block_type,
                                                                  uint8_t quant_idx_y,
                                                                  uint8_t quant_idx_cb,
                                                                  uint8_t quant_idx_cr,
                                                                  uint16_t x_idx,
                                                                  uint16_t y_idx,
                                                                  uint8_t tile_flags,
                                                                  uint8_t progressive_idx,
                                                                  const uint8_t* y_data,
                                                                  size_t y_len,
                                                                  const uint8_t* cb_data,
                                                                  size_t cb_len,
                                                                  const uint8_t* cr_data,
                                                                  size_t cr_len,
                                                                  uint32_t* rendered_tiles,
                                                                  uint32_t* failed_tiles,
                                                                  uint32_t* missing_tiles)
{
    rdp_session_progressive_tile_cache* tile_cache = NULL;
    rdp_rfx_component_quant y_quant;
    rdp_rfx_component_quant y_delta;
    rdp_rfx_component_quant cb_quant;
    rdp_rfx_component_quant cb_delta;
    rdp_rfx_component_quant cr_quant;
    rdp_rfx_component_quant cr_delta;
    rdp_rfx_tile_pixels pixels;
    uint32_t x = (uint32_t)x_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    uint32_t y = (uint32_t)y_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    uint32_t width = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    uint32_t height = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    int extrapolate = 0;
    const char* stage = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !region || !rendered_tiles || !failed_tiles || !missing_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!y_data || !cb_data || !cr_data)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (x >= surface->width || y >= surface->height)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.clipped",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        block_type);
        return LIBRDP_STATUS_OK;
    }
    if (width > (uint32_t)surface->width - x)
        width = (uint32_t)surface->width - x;
    if (height > (uint32_t)surface->height - y)
        height = (uint32_t)surface->height - y;

    stage = "base_quant.y";
    status = rdp_session_graphics_progressive_base_quant(region, quant_idx_y, &y_quant);
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.y";
        status = rdp_session_graphics_progressive_delta_quant(region, progressive_idx, 0, &y_delta);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "base_quant.cb";
        status = rdp_session_graphics_progressive_base_quant(region, quant_idx_cb, &cb_quant);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.cb";
        status = rdp_session_graphics_progressive_delta_quant(region, progressive_idx, 1, &cb_delta);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "base_quant.cr";
        status = rdp_session_graphics_progressive_base_quant(region, quant_idx_cr, &cr_quant);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.cr";
        status = rdp_session_graphics_progressive_delta_quant(region, progressive_idx, 2, &cr_delta);
    }
    extrapolate = (region->flags & 0x01u) != 0;
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "state";
        tile_cache = rdp_session_progressive_tile_get(session,
                                                      surface->surface_id,
                                                      x_idx,
                                                      y_idx,
                                                      1);
        if (!tile_cache || !tile_cache->state || !tile_cache->pixels)
            status = LIBRDP_STATUS_NO_MEMORY;
    }
    if (status == LIBRDP_STATUS_OK &&
        (tile_flags & 0x01u) != 0 &&
        (!tile_cache->state->valid ||
         !tile_cache->state->y.valid ||
         !tile_cache->state->cb.valid ||
         !tile_cache->state->cr.valid))
    {
        (*missing_tiles)++;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.missing",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u flags=%u progressive_idx=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        block_type,
                        tile_flags,
                        progressive_idx);
        return LIBRDP_STATUS_OK;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "decode";
        status = rdp_rfx_decode_progressive_tile_state(y_data,
                                                       y_len,
                                                       cb_data,
                                                       cb_len,
                                                       cr_data,
                                                       cr_len,
                                                       &y_quant,
                                                       &y_delta,
                                                       &cb_quant,
                                                       &cb_delta,
                                                       &cr_quant,
                                                       &cr_delta,
                                                       extrapolate,
                                                       (tile_flags & 0x01u) != 0,
                                                       tile_cache->state,
                                                       &pixels);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        tile_cache->state->x_idx = x_idx;
        tile_cache->state->y_idx = y_idx;
        memcpy(tile_cache->pixels, &pixels, sizeof(*tile_cache->pixels));
        tile_cache->has_pixels = 1;
        tile_cache->updated_frame_id = session->graphics_current_frame_id;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        (*failed_tiles)++;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.failed",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u flags=%u progressive_idx=%u stage=%s status=%d y_len=%u cb_len=%u cr_len=%u extrapolate=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        block_type,
                        tile_flags,
                        progressive_idx,
                        stage,
                        (int)status,
                        (unsigned)y_len,
                        (unsigned)cb_len,
                        (unsigned)cr_len,
                        (unsigned)extrapolate);
        return LIBRDP_STATUS_OK;
    }

    (*rendered_tiles)++;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.progressive.tile",
                          "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u width=%u height=%u block_type=%u flags=%u progressive_idx=%u pass=%u extrapolate=%u frame_id=%u queued=1",
                          channel_id,
                          codec_context_id,
                          surface->surface_id,
                          x,
                          y,
                          width,
                          height,
                          block_type,
                          tile_flags,
                          progressive_idx,
                          tile_cache && tile_cache->state ? tile_cache->state->pass : 0u,
                          (unsigned)extrapolate,
                          session->graphics_current_frame_id);
    return LIBRDP_STATUS_OK;
}

/*
 * Render a progressive-codec upgrade pass. The function merges cached tile
 * state with new coefficient data while preserving the previous visible
 * surface until the upgrade is complete.
 */
static librdp_status rdp_session_graphics_progressive_render_upgrade(
    librdp_session* session,
    uint32_t channel_id,
    uint32_t codec_context_id,
    rdp_session_graphics_surface* surface,
    const rdp_graphics_progressive_region* region,
    const rdp_graphics_progressive_tile_upgrade* tile,
    uint32_t* rendered_tiles,
    uint32_t* failed_tiles,
    uint32_t* missing_tiles)
{
    rdp_session_progressive_tile_cache* tile_cache = NULL;
    rdp_rfx_component_quant y_quant;
    rdp_rfx_component_quant y_delta;
    rdp_rfx_component_quant cb_quant;
    rdp_rfx_component_quant cb_delta;
    rdp_rfx_component_quant cr_quant;
    rdp_rfx_component_quant cr_delta;
    rdp_rfx_tile_pixels pixels;
    uint32_t x = 0;
    uint32_t y = 0;
    uint32_t width = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    uint32_t height = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    int extrapolate = 0;
    const char* stage = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !region || !tile || !rendered_tiles || !failed_tiles || !missing_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    x = (uint32_t)tile->x_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    y = (uint32_t)tile->y_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    if (x >= surface->width || y >= surface->height)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.clipped",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        tile->block_type);
        return LIBRDP_STATUS_OK;
    }
    if (width > (uint32_t)surface->width - x)
        width = (uint32_t)surface->width - x;
    if (height > (uint32_t)surface->height - y)
        height = (uint32_t)surface->height - y;

    tile_cache = rdp_session_progressive_tile_get(session,
                                                  surface->surface_id,
                                                  tile->x_idx,
                                                  tile->y_idx,
                                                  0);
    if (!tile_cache || !tile_cache->state || !tile_cache->pixels || !tile_cache->state->valid)
    {
        (*missing_tiles)++;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.missing",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u progressive_idx=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        tile->block_type,
                        tile->progressive_quality);
        return LIBRDP_STATUS_OK;
    }

    stage = "base_quant.y";
    status = rdp_session_graphics_progressive_base_quant(region, tile->quant_idx_y, &y_quant);
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.y";
        status = rdp_session_graphics_progressive_delta_quant(region, tile->progressive_quality, 0, &y_delta);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "base_quant.cb";
        status = rdp_session_graphics_progressive_base_quant(region, tile->quant_idx_cb, &cb_quant);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.cb";
        status = rdp_session_graphics_progressive_delta_quant(region, tile->progressive_quality, 1, &cb_delta);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "base_quant.cr";
        status = rdp_session_graphics_progressive_base_quant(region, tile->quant_idx_cr, &cr_quant);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.cr";
        status = rdp_session_graphics_progressive_delta_quant(region, tile->progressive_quality, 2, &cr_delta);
    }

    extrapolate = (region->flags & 0x01u) != 0;
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "decode";
        status = rdp_rfx_decode_progressive_upgrade_tile(tile->y_srl_data,
                                                         tile->y_srl_len,
                                                         tile->y_raw_data,
                                                         tile->y_raw_len,
                                                         tile->cb_srl_data,
                                                         tile->cb_srl_len,
                                                         tile->cb_raw_data,
                                                         tile->cb_raw_len,
                                                         tile->cr_srl_data,
                                                         tile->cr_srl_len,
                                                         tile->cr_raw_data,
                                                         tile->cr_raw_len,
                                                         &y_quant,
                                                         &y_delta,
                                                         &cb_quant,
                                                         &cb_delta,
                                                         &cr_quant,
                                                         &cr_delta,
                                                         extrapolate,
                                                         tile_cache->state,
                                                         &pixels);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        memcpy(tile_cache->pixels, &pixels, sizeof(*tile_cache->pixels));
        tile_cache->has_pixels = 1;
        tile_cache->updated_frame_id = session->graphics_current_frame_id;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        (*failed_tiles)++;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.failed",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u stage=%s status=%d y_srl_len=%u y_raw_len=%u cb_srl_len=%u cb_raw_len=%u cr_srl_len=%u cr_raw_len=%u extrapolate=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        tile->block_type,
                        stage,
                        (int)status,
                        tile->y_srl_len,
                        tile->y_raw_len,
                        tile->cb_srl_len,
                        tile->cb_raw_len,
                        tile->cr_srl_len,
                        tile->cr_raw_len,
                        (unsigned)extrapolate);
        return LIBRDP_STATUS_OK;
    }

    (*rendered_tiles)++;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.progressive.tile",
                          "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u width=%u height=%u block_type=%u progressive_idx=%u pass=%u extrapolate=%u frame_id=%u queued=1",
                          channel_id,
                          codec_context_id,
                          surface->surface_id,
                          x,
                          y,
                          width,
                          height,
                          tile->block_type,
                          tile->progressive_quality,
                          tile_cache->state->pass,
                          (unsigned)extrapolate,
                          session->graphics_current_frame_id);
    return LIBRDP_STATUS_OK;
}

/*
 * Flush a completed progressive region to the target surface. Region damage is
 * emitted only after every clipped tile in the region has been applied.
 */
static librdp_status rdp_session_graphics_progressive_flush_region(librdp_session* session,
                                                                   uint32_t channel_id,
                                                                   uint32_t codec_context_id,
                                                                   rdp_session_graphics_surface* surface,
                                                                   const rdp_graphics_progressive_region* region,
                                                                   uint32_t* flushed_tiles,
                                                                   uint32_t* failed_tiles)
{
    size_t i = 0;
    uint32_t considered_tiles = 0;
    uint32_t clipped_tiles = 0;

    if (!session || !surface || !region || !flushed_tiles || !failed_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        rdp_session_progressive_tile_cache* tile_cache = &session->progressive_tiles[i];
        uint32_t x = 0;
        uint32_t y = 0;
        uint32_t width = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
        uint32_t height = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
        int wrote = 0;
        librdp_status status = LIBRDP_STATUS_OK;

        if (!tile_cache->active || tile_cache->surface_id != surface->surface_id ||
            tile_cache->updated_frame_id != session->graphics_current_frame_id ||
            !tile_cache->has_pixels || !tile_cache->pixels)
            continue;

        x = (uint32_t)tile_cache->x_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
        y = (uint32_t)tile_cache->y_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
        if (x >= surface->width || y >= surface->height)
        {
            clipped_tiles++;
            continue;
        }
        if (width > (uint32_t)surface->width - x)
            width = (uint32_t)surface->width - x;
        if (height > (uint32_t)surface->height - y)
            height = (uint32_t)surface->height - y;
        considered_tiles++;
        status = rdp_session_graphics_progressive_write_region_tile(session,
                                                                    surface,
                                                                    region,
                                                                    x,
                                                                    y,
                                                                    width,
                                                                    height,
                                                                    tile_cache->pixels,
                                                                    &wrote);
        if (status != LIBRDP_STATUS_OK)
        {
            (*failed_tiles)++;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.progressive.tile.flush.failed",
                            "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u width=%u height=%u frame_id=%u status=%d",
                            channel_id,
                            codec_context_id,
                            surface->surface_id,
                            x,
                            y,
                            width,
                            height,
                            session->graphics_current_frame_id,
                            (int)status);
            continue;
        }
        if (wrote)
            (*flushed_tiles)++;
        else
            clipped_tiles++;
    }

    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.progressive.region.flush",
                          "dvc_channel_id=%u context_id=%u surface_id=%u frame_id=%u considered_tiles=%u flushed_tiles=%u clipped_tiles=%u failed_tiles=%u",
                          channel_id,
                          codec_context_id,
                          surface->surface_id,
                          session->graphics_current_frame_id,
                          considered_tiles,
                          *flushed_tiles,
                          clipped_tiles,
                          *failed_tiles);
    return LIBRDP_STATUS_OK;
}

/*
 * Render all tiles for a progressive region. Codec state, tile cache lookup,
 * and destination clipping stay ordered so incomplete regions do not leak into
 * the framebuffer.
 */
static librdp_status rdp_session_graphics_progressive_render_region(librdp_session* session,
                                                                    uint32_t channel_id,
                                                                    uint32_t codec_context_id,
                                                                    rdp_session_graphics_surface* surface,
                                                                    const rdp_graphics_progressive_region* region,
                                                                    uint32_t* rendered_tiles,
                                                                    uint32_t* failed_tiles,
                                                                    uint32_t* missing_tiles)
{
    size_t offset = 0;

    if (!session || !surface || !region || !rendered_tiles || !failed_tiles || !missing_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    while (offset < region->tiles_len)
    {
        rdp_graphics_progressive_block block;
        librdp_status status = rdp_graphics_progressive_parse_block(region->tiles + offset,
                                                                    region->tiles_len - offset,
                                                                    &block);

        if (status != LIBRDP_STATUS_OK)
            return status;
        if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_SIMPLE)
        {
            rdp_graphics_progressive_tile_simple tile;

            status = rdp_graphics_progressive_parse_tile_simple(region->tiles + offset,
                                                                region->tiles_len - offset,
                                                                &tile);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_graphics_progressive_render_tile(session,
                                                                  channel_id,
                                                                  codec_context_id,
                                                                  surface,
                                                                  region,
                                                                  block.type,
                                                                  tile.quant_idx_y,
                                                                  tile.quant_idx_cb,
                                                                  tile.quant_idx_cr,
                                                                  tile.x_idx,
                                                                  tile.y_idx,
                                                                  tile.flags,
                                                                  0xffu,
                                                                  tile.y_data,
                                                                  tile.y_len,
                                                                  tile.cb_data,
                                                                  tile.cb_len,
                                                                  tile.cr_data,
                                                                  tile.cr_len,
                                                                  rendered_tiles,
                                                                  failed_tiles,
                                                                  missing_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_FIRST)
        {
            rdp_graphics_progressive_tile_first tile;

            status = rdp_graphics_progressive_parse_tile_first(region->tiles + offset,
                                                               region->tiles_len - offset,
                                                               &tile);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_graphics_progressive_render_tile(session,
                                                                  channel_id,
                                                                  codec_context_id,
                                                                  surface,
                                                                  region,
                                                                  block.type,
                                                                  tile.quant_idx_y,
                                                                  tile.quant_idx_cb,
                                                                  tile.quant_idx_cr,
                                                                  tile.x_idx,
                                                                  tile.y_idx,
                                                                  tile.flags,
                                                                  tile.progressive_quality,
                                                                  tile.y_data,
                                                                  tile.y_len,
                                                                  tile.cb_data,
                                                                  tile.cb_len,
                                                                  tile.cr_data,
                                                                  tile.cr_len,
                                                                  rendered_tiles,
                                                                  failed_tiles,
                                                                  missing_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_UPGRADE)
        {
            rdp_graphics_progressive_tile_upgrade tile;

            status = rdp_graphics_progressive_parse_tile_upgrade(region->tiles + offset,
                                                                 region->tiles_len - offset,
                                                                 &tile);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_graphics_progressive_render_upgrade(session,
                                                                     channel_id,
                                                                     codec_context_id,
                                                                     surface,
                                                                     region,
                                                                     &tile,
                                                                     rendered_tiles,
                                                                     failed_tiles,
                                                                     missing_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else
        {
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        offset += block.length;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_progressive_render_stream(librdp_session* session,
                                                                    uint32_t channel_id,
                                                                    rdp_session_graphics_surface* surface,
                                                                    const rdp_graphics_wire_to_surface_2* wire,
                                                                    uint32_t* rendered_tiles,
                                                                    uint32_t* failed_tiles,
                                                                    uint32_t* missing_tiles)
{
    size_t offset = 0;
    uint32_t region_index = 0;

    if (!session || !surface || !wire || !rendered_tiles || !failed_tiles || !missing_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    *rendered_tiles = 0;
    *failed_tiles = 0;
    *missing_tiles = 0;
    while (offset < wire->bitmap_data_length)
    {
        rdp_graphics_progressive_block block;
        librdp_status status = rdp_graphics_progressive_parse_block(wire->bitmap_data + offset,
                                                                    wire->bitmap_data_length - offset,
                                                                    &block);

        if (status != LIBRDP_STATUS_OK)
            return status;
        if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_REGION)
        {
            rdp_graphics_progressive_region region;
            uint32_t flushed_tiles = 0;

            status = rdp_graphics_progressive_parse_region(wire->bitmap_data + offset,
                                                           wire->bitmap_data_length - offset,
                                                           &region);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.progressive.region",
                            "dvc_channel_id=%u context_id=%u surface_id=%u region_index=%u rect_count=%u quant_count=%u progressive_quant_count=%u tile_count=%u tile_data_size=%u flags=%u tile_size=%u frame_id=%u",
                            channel_id,
                            wire->codec_context_id,
                            surface->surface_id,
                            region_index,
                            region.rect_count,
                            region.quant_count,
                            region.progressive_quant_count,
                            region.tile_count,
                            region.tile_data_size,
                            region.flags,
                            region.tile_size,
                            session->graphics_current_frame_id);
            status = rdp_session_graphics_progressive_render_region(session,
                                                                    channel_id,
                                                                    wire->codec_context_id,
                                                                    surface,
                                                                    &region,
                                                                    rendered_tiles,
                                                                    failed_tiles,
                                                                    missing_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_graphics_progressive_flush_region(session,
                                                                   channel_id,
                                                                   wire->codec_context_id,
                                                                   surface,
                                                                   &region,
                                                                   &flushed_tiles,
                                                                   failed_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
            region_index++;
        }
        offset += block.length;
    }
    return LIBRDP_STATUS_OK;
}

static void rdp_session_graphics_cache_evict(librdp_session* session, uint16_t cache_slot)
{
    rdp_session_graphics_cache_entry* entry = NULL;

    if (!session || cache_slot >= RDP_SESSION_GRAPHICS_CACHE_SLOTS)
        return;
    entry = &session->graphics_cache[cache_slot];
    if (entry->active)
    {
        if (session->graphics_cache_bytes >= entry->pixels.length)
            session->graphics_cache_bytes -= entry->pixels.length;
        else
            session->graphics_cache_bytes = 0;
    }
    rdp_buffer_free(&entry->pixels);
    memset(entry, 0, sizeof(*entry));
}

void rdp_session_graphics_cache_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_GRAPHICS_CACHE_SLOTS; i++)
        rdp_buffer_free(&session->graphics_cache[i].pixels);
    memset(session->graphics_cache, 0, sizeof(session->graphics_cache));
    session->graphics_cache_bytes = 0;
}


static rdp_session_graphics_cache_entry* rdp_session_graphics_cache_find(librdp_session* session, uint16_t cache_slot)
{
    if (!session || cache_slot >= RDP_SESSION_GRAPHICS_CACHE_SLOTS || !session->graphics_cache[cache_slot].active)
        return NULL;
    return &session->graphics_cache[cache_slot];
}

/*
 * Store graphics-pipeline cache entries supplied by the server. Keys, payload
 * lengths, and replacement ownership are validated before the session cache is
 * updated.
 */
static librdp_status rdp_session_graphics_cache_store(librdp_session* session,
                                                      const rdp_graphics_surface_to_cache* surface_to_cache)
{
    rdp_session_graphics_surface* surface = NULL;
    rdp_session_graphics_cache_entry* entry = NULL;
    uint16_t width = 0;
    uint16_t height = 0;
    size_t source_stride = 0;
    size_t size = 0;
    size_t old_size = 0;
    size_t current_without_old = 0;
    uint16_t row = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface_to_cache)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (surface_to_cache->cache_slot >= RDP_SESSION_GRAPHICS_CACHE_SLOTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    surface = rdp_session_graphics_surface_find(session, surface_to_cache->surface_id);
    if (!surface)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (surface_to_cache->rect_src.right > surface->width ||
        surface_to_cache->rect_src.bottom > surface->height ||
        surface_to_cache->rect_src.left >= surface_to_cache->rect_src.right ||
        surface_to_cache->rect_src.top >= surface_to_cache->rect_src.bottom)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    width = (uint16_t)(surface_to_cache->rect_src.right - surface_to_cache->rect_src.left);
    height = (uint16_t)(surface_to_cache->rect_src.bottom - surface_to_cache->rect_src.top);
    size = (size_t)width * (size_t)height * 4u;
    entry = &session->graphics_cache[surface_to_cache->cache_slot];
    old_size = entry->active ? entry->pixels.length : 0;
    current_without_old = session->graphics_cache_bytes >= old_size ? session->graphics_cache_bytes - old_size : 0;
    if (size > RDP_SESSION_GRAPHICS_CACHE_MAX_BYTES ||
        current_without_old > RDP_SESSION_GRAPHICS_CACHE_MAX_BYTES - size)
        return LIBRDP_STATUS_NO_MEMORY;

    status = rdp_buffer_reserve(&entry->pixels, size);
    if (status != LIBRDP_STATUS_OK)
        return status;

    source_stride = (size_t)surface->width * 4u;
    for (row = 0; row < height; row++)
    {
        memcpy(entry->pixels.data + ((size_t)row * (size_t)width * 4u),
               surface->pixels.data + ((size_t)(surface_to_cache->rect_src.top + row) * source_stride) +
                   ((size_t)surface_to_cache->rect_src.left * 4u),
               (size_t)width * 4u);
    }
    entry->pixels.length = size;
    entry->active = 1;
    entry->cache_slot = surface_to_cache->cache_slot;
    entry->width = width;
    entry->height = height;
    entry->cache_key = surface_to_cache->cache_key;
    session->graphics_cache_bytes = current_without_old + size;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.cache.store",
                          "surface_id=%u cache_slot=%u width=%u height=%u src_left=%u src_top=%u src_right=%u src_bottom=%u cache_key=%llu cache_bytes=%llu source_hash=%016llx cache_hash=%016llx frame_id=%u",
                          surface_to_cache->surface_id,
                          surface_to_cache->cache_slot,
                          width,
                          height,
                          surface_to_cache->rect_src.left,
                          surface_to_cache->rect_src.top,
                          surface_to_cache->rect_src.right,
                          surface_to_cache->rect_src.bottom,
                          (unsigned long long)surface_to_cache->cache_key,
                          (unsigned long long)session->graphics_cache_bytes,
                          (unsigned long long)rdp_session_trace_surface_hash(surface,
                                                                              surface_to_cache->rect_src.left,
                                                                              surface_to_cache->rect_src.top,
                                                                              width,
                                                                              height),
                          (unsigned long long)rdp_session_trace_hash_bgra(entry->pixels.data,
                                                                          width,
                                                                          height,
                                                                          (size_t)width * 4u),
                          session->graphics_current_frame_id);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_surface_copy(librdp_session* session,
                                                       rdp_session_graphics_surface* source,
                                                       rdp_session_graphics_surface* dest,
                                                       const rdp_graphics_rect16* rect,
                                                       const rdp_graphics_point16* point)
{
    rdp_buffer copy;
    uint16_t width = 0;
    uint16_t height = 0;
    size_t source_stride = 0;
    size_t row_stride = 0;
    uint16_t row = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !source || !dest || !rect || !point || !source->active || !dest->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rect->right > source->width || rect->bottom > source->height ||
        rect->left >= rect->right || rect->top >= rect->bottom)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    width = (uint16_t)(rect->right - rect->left);
    height = (uint16_t)(rect->bottom - rect->top);
    if (point->x > dest->width || point->y > dest->height ||
        width > dest->width - point->x || height > dest->height - point->y)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_buffer_init(&copy);
    row_stride = (size_t)width * 4u;
    status = rdp_buffer_reserve(&copy, row_stride * (size_t)height);
    if (status == LIBRDP_STATUS_OK)
    {
        source_stride = (size_t)source->width * 4u;
        for (row = 0; row < height; row++)
        {
            memcpy(copy.data + ((size_t)row * row_stride),
                   source->pixels.data + ((size_t)(rect->top + row) * source_stride) + ((size_t)rect->left * 4u),
                   row_stride);
        }
        copy.length = row_stride * (size_t)height;
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "client.graphics.surface.copy",
                              "source_id=%u dest_id=%u src_left=%u src_top=%u src_right=%u src_bottom=%u dst_x=%u dst_y=%u width=%u height=%u frame_id=%u copy_hash=%016llx",
                              source->surface_id,
                              dest->surface_id,
                              rect->left,
                              rect->top,
                              rect->right,
                              rect->bottom,
                              point->x,
                              point->y,
                              width,
                              height,
                              session->graphics_current_frame_id,
                              (unsigned long long)rdp_session_trace_hash_bgra(copy.data, width, height, row_stride));
        status = rdp_session_graphics_surface_write_bgra(session,
                                                         dest,
                                                         point->x,
                                                         point->y,
                                                         width,
                                                         height,
                                                         copy.data,
                                                         row_stride,
                                                         0,
                                                         "surface_to_surface");
    }
    rdp_buffer_free(&copy);
    return status;
}

static librdp_status rdp_session_graphics_cache_copy_to_surface(librdp_session* session,
                                                                rdp_session_graphics_cache_entry* cache,
                                                                rdp_session_graphics_surface* surface,
                                                                const rdp_graphics_point16* point)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !cache || !surface || !point || !cache->active || !surface->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (point->x > surface->width || point->y > surface->height ||
        cache->width > surface->width - point->x || cache->height > surface->height - point->y)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.cache.copy",
                          "cache_slot=%u surface_id=%u dst_x=%u dst_y=%u width=%u height=%u cache_key=%llu frame_id=%u cache_hash=%016llx",
                          cache->cache_slot,
                          surface->surface_id,
                          point->x,
                          point->y,
                          cache->width,
                          cache->height,
                          (unsigned long long)cache->cache_key,
                          session->graphics_current_frame_id,
                          (unsigned long long)rdp_session_trace_hash_bgra(cache->pixels.data,
                                                                          cache->width,
                                                                          cache->height,
                                                                          (size_t)cache->width * 4u));
    status = rdp_session_graphics_surface_write_bgra(session,
                                                     surface,
                                                     point->x,
                                                     point->y,
                                                     cache->width,
                                                     cache->height,
                                                     cache->pixels.data,
                                                     (size_t)cache->width * 4u,
                                                     0,
                                                     "cache_to_surface");
    return status;
}


librdp_status rdp_session_send_graphics_caps(librdp_session* session)
{
    rdp_buffer caps;
    uint32_t avc_support = 0;
    size_t caps_length = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->graphics_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&caps);
    avc_support = rdp_avc_runtime_support();
    status = rdp_graphics_write_default_caps_advertise_for_avc(&caps, avc_support);
    if (status == LIBRDP_STATUS_OK)
    {
        caps_length = caps.length;
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->graphics_channel_id,
                                                       session->graphics_channel_id_bytes,
                                                       caps.data,
                                                       caps.length,
                                                       "client.graphics.caps_advertise");
    }
    rdp_buffer_free(&caps);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.caps_advertise",
                        "dvc_channel_id=%u payload_len=%u avc_support=%u",
                        session->graphics_channel_id,
                        (unsigned)caps_length,
                        avc_support);
    return status;
}

static librdp_status rdp_session_send_graphics_frame_ack(librdp_session* session, uint32_t frame_id)
{
    rdp_buffer ack;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->graphics_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&ack);
    status = rdp_graphics_write_frame_ack(&ack,
                                          RDP_GRAPHICS_QUEUE_DEPTH_UNAVAILABLE,
                                          frame_id,
                                          session->graphics_frames_decoded);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->graphics_channel_id,
                                                       session->graphics_channel_id_bytes,
                                                       ack.data,
                                                       ack.length,
                                                       "client.graphics.frame_ack");
    rdp_buffer_free(&ack);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.frame_ack",
                        "dvc_channel_id=%u frame_id=%u total_frames_decoded=%u",
                        session->graphics_channel_id,
                        frame_id,
                        session->graphics_frames_decoded);
    return status;
}

/*
 * Graphics pipeline traffic is segmented, optionally bulk-compressed, and can
 * carry frame markers, cache operations, surface commands, and codec payloads
 * in one byte stream. Decode and apply in-order here so frame acknowledgements
 * reflect only work that has reached the local surface/cache state.
 */
librdp_status rdp_session_handle_graphics_message(librdp_session* session,
                                                         uint32_t channel_id,
                                                         const uint8_t* data,
                                                         size_t data_len)
{
    rdp_buffer decoded;
    size_t offset = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&decoded);
    status = rdp_graphics_decode_segmented_data(&session->graphics_decompressor, data, data_len, &decoded);
    if (status == LIBRDP_STATUS_UNSUPPORTED)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.rejected",
                        "dvc_channel_id=%u reason=bulk_compression payload_len=%u",
                        channel_id,
                        (unsigned)data_len);
        rdp_buffer_free(&decoded);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&decoded);
        return status;
    }

    while (offset < decoded.length)
    {
        rdp_graphics_header header;
        const uint8_t* pdu = decoded.data + offset;
        size_t remaining = decoded.length - offset;

        status = rdp_graphics_parse_header(pdu, remaining, &header);
        if (status != LIBRDP_STATUS_OK)
            break;
        rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                              RDP_TRACE_LEVEL_DEBUG,
                              "rdp.graphics.pdu",
                              "dvc_channel_id=%u cmd_id=%u pdu_len=%u",
                              channel_id,
                              header.cmd_id,
                              header.pdu_length);
        rdp_trace_hexdump("rdp.graphics.pdu", RDP_TRACE_SENSITIVITY_VIDEO, pdu, header.pdu_length);
        if (header.cmd_id == RDP_GRAPHICS_CMDID_CAPS_CONFIRM)
        {
            rdp_graphics_caps_confirm confirm;

            status = rdp_graphics_parse_caps_confirm(pdu, header.pdu_length, &confirm);
            if (status != LIBRDP_STATUS_OK)
                break;
            if (!rdp_graphics_capset_is_supported_for_avc(&confirm.selected, rdp_avc_runtime_support()))
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.graphics.caps_confirm.invalid",
                                "dvc_channel_id=%u version=%u flags=%u",
                                channel_id,
                                confirm.selected.version,
                                confirm.selected.flags);
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            session->graphics_selected_version = confirm.selected.version;
            session->graphics_selected_flags = confirm.selected.flags;
            session->graphics_ready = 1;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.caps_confirm",
                            "dvc_channel_id=%u version=%u flags=%u",
                            channel_id,
                            confirm.selected.version,
                            confirm.selected.flags);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_WIRE_TO_SURFACE_1)
        {
            rdp_graphics_wire_to_surface_1 wire;

            status = rdp_graphics_parse_wire_to_surface_1(pdu, header.pdu_length, &wire);
            if (status != LIBRDP_STATUS_OK)
                break;
            if (wire.codec_id == RDP_GRAPHICS_CODECID_UNCOMPRESSED ||
                wire.codec_id == RDP_GRAPHICS_CODECID_CLEARCODEC ||
                wire.codec_id == RDP_GRAPHICS_CODECID_PLANAR ||
                wire.codec_id == RDP_GRAPHICS_CODECID_ALPHA ||
                wire.codec_id == RDP_GRAPHICS_CODECID_AVC420 ||
                wire.codec_id == RDP_GRAPHICS_CODECID_AVC444 ||
                wire.codec_id == RDP_GRAPHICS_CODECID_AVC444V2)
            {
                rdp_session_graphics_surface* surface = rdp_session_graphics_surface_find(session, wire.surface_id);
                int rendered = 0;

                if (!surface)
                {
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    break;
                }
                if (wire.codec_id == RDP_GRAPHICS_CODECID_UNCOMPRESSED)
                {
                    status = rdp_session_graphics_surface_write_wire(session, surface, &wire);
                    if (status != LIBRDP_STATUS_OK)
                        break;
                    rendered = 1;
                }
                else if (wire.codec_id == RDP_GRAPHICS_CODECID_ALPHA)
                {
                    status = rdp_session_graphics_surface_apply_alpha(session, surface, &wire);
                    if (status != LIBRDP_STATUS_OK)
                        break;
                    rendered = 1;
                }
                else if (wire.codec_id == RDP_GRAPHICS_CODECID_CLEARCODEC ||
                         wire.codec_id == RDP_GRAPHICS_CODECID_PLANAR)
                {
                    rdp_buffer decoded_bitmap;
                    size_t decoded_stride = 0;
                    uint16_t width = (uint16_t)(wire.dest_rect.right - wire.dest_rect.left);
                    uint16_t height = (uint16_t)(wire.dest_rect.bottom - wire.dest_rect.top);

                    rdp_buffer_init(&decoded_bitmap);
                    if (wire.codec_id == RDP_GRAPHICS_CODECID_CLEARCODEC)
                    {
                        status = rdp_clearcodec_decode_bitmap(&session->clearcodec,
                                                              wire.bitmap_data,
                                                              wire.bitmap_data_length,
                                                              width,
                                                              height,
                                                              &decoded_bitmap,
                                                              &decoded_stride);
                    }
                    else
                    {
                        status = rdp_planar_decode_argb(wire.bitmap_data,
                                                        wire.bitmap_data_length,
                                                        width,
                                                        height,
                                                        &decoded_bitmap,
                                                        &decoded_stride);
                    }
                    if (status == LIBRDP_STATUS_OK)
                        status = rdp_session_graphics_surface_write_bgra(session,
                                                                         surface,
                                                                         wire.dest_rect.left,
                                                                         wire.dest_rect.top,
                                                                         width,
                                                                         height,
                                                                         decoded_bitmap.data,
                                                                         decoded_stride,
                                                                         wire.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                                                         wire.codec_id == RDP_GRAPHICS_CODECID_CLEARCODEC ? "clearcodec" : "planar");
                    rdp_buffer_free(&decoded_bitmap);
                    if (status == LIBRDP_STATUS_UNSUPPORTED)
                    {
                        rdp_trace_event(RDP_TRACE_CLIENT,
                                        "client.graphics.codec.rejected",
                                        "dvc_channel_id=%u surface_id=%u codec_id=%u payload_len=%u decoder_status=%d",
                                        channel_id,
                                        wire.surface_id,
                                        wire.codec_id,
                                        wire.bitmap_data_length,
                                        (int)status);
                        status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    }
                    if (status != LIBRDP_STATUS_OK)
                        break;
                    if (decoded_stride != 0)
                        rendered = 1;
                }
                else
                {
                    rdp_avc_frame avc_frame;
                    int avc_rendered = 0;
                    const char* source = wire.codec_id == RDP_GRAPHICS_CODECID_AVC420 ? "avc420" :
                                         wire.codec_id == RDP_GRAPHICS_CODECID_AVC444 ? "avc444" :
                                                                                        "avc444v2";

                    rdp_avc_frame_init(&avc_frame);
                    if (wire.codec_id == RDP_GRAPHICS_CODECID_AVC420)
                    {
                        rdp_graphics_avc420_stream avc420;

                        status = rdp_graphics_parse_avc420_stream(wire.bitmap_data,
                                                                  wire.bitmap_data_length,
                                                                  &avc420);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_avc_decode_420(session->avc,
                                                        &avc420,
                                                        surface->width,
                                                        surface->height,
                                                        &avc_frame);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_session_graphics_surface_write_avc_regions(
                                session,
                                surface,
                                &avc420.meta,
                                &avc_frame,
                                wire.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                source);
                        if (status == LIBRDP_STATUS_OK)
                            avc_rendered = 1;
                    }
                    else
                    {
                        rdp_graphics_avc444_stream avc444;

                        status = rdp_graphics_parse_avc444_stream(wire.bitmap_data,
                                                                  wire.bitmap_data_length,
                                                                  &avc444);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_avc_decode_444(session->avc,
                                                        wire.codec_id,
                                                        &avc444,
                                                        surface->width,
                                                        surface->height,
                                                        &avc_frame);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_session_graphics_surface_write_avc_regions(
                                session,
                                surface,
                                &avc444.stream1.meta,
                                &avc_frame,
                                wire.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                source);
                        if (status == LIBRDP_STATUS_OK && avc444.lc == RDP_GRAPHICS_AVC444_LC_BOTH)
                            status = rdp_session_graphics_surface_write_avc_regions(
                                session,
                                surface,
                                &avc444.stream2.meta,
                                &avc_frame,
                                wire.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                source);
                        if (status == LIBRDP_STATUS_OK)
                            avc_rendered = 1;
                    }
                    if (status == LIBRDP_STATUS_UNSUPPORTED)
                    {
                        rdp_trace_event(RDP_TRACE_CLIENT,
                                        "client.graphics.codec.rejected",
                                        "dvc_channel_id=%u surface_id=%u codec_id=%u payload_len=%u decoder_status=%d",
                                        channel_id,
                                        wire.surface_id,
                                        wire.codec_id,
                                        wire.bitmap_data_length,
                                        (int)status);
                        status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    }
                    if (status == LIBRDP_STATUS_OK && avc_rendered)
                        rendered = 1;
                    rdp_avc_frame_free(&avc_frame);
                    if (status != LIBRDP_STATUS_OK)
                        break;
                }
                if (rendered)
                    rdp_trace_event_level(RDP_TRACE_CLIENT,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "client.graphics.wire_to_surface",
                                          "dvc_channel_id=%u surface_id=%u codec_id=%u x=%u y=%u width=%u height=%u",
                                          channel_id,
                                          wire.surface_id,
                                          wire.codec_id,
                                          wire.dest_rect.left,
                                          wire.dest_rect.top,
                                          (unsigned)(wire.dest_rect.right - wire.dest_rect.left),
                                          (unsigned)(wire.dest_rect.bottom - wire.dest_rect.top));
            }
            else
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.graphics.wire_to_surface.rejected",
                                "dvc_channel_id=%u surface_id=%u codec_id=%u payload_len=%u",
                                channel_id,
                                wire.surface_id,
                                wire.codec_id,
                                wire.bitmap_data_length);
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_WIRE_TO_SURFACE_2)
        {
            rdp_graphics_wire_to_surface_2 wire;

            status = rdp_graphics_parse_wire_to_surface_2(pdu, header.pdu_length, &wire);
            if (status != LIBRDP_STATUS_OK)
                break;
            if (wire.codec_id == RDP_GRAPHICS_CODECID_CAPROGRESSIVE)
            {
                rdp_session_graphics_surface* surface = rdp_session_graphics_surface_find(session, wire.surface_id);
                rdp_graphics_progressive_stream progressive;
                uint32_t rendered_tiles = 0;
                uint32_t failed_tiles = 0;
                uint32_t missing_tiles = 0;

                if (!surface)
                {
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    break;
                }
                status = rdp_graphics_progressive_parse_stream(wire.bitmap_data,
                                                               wire.bitmap_data_length,
                                                               &progressive);
                if (status == LIBRDP_STATUS_OK)
                {
                    status = rdp_session_graphics_progressive_render_stream(session,
                                                                           channel_id,
                                                                           surface,
                                                                           &wire,
                                                                           &rendered_tiles,
                                                                           &failed_tiles,
                                                                           &missing_tiles);
                    if (status != LIBRDP_STATUS_OK)
                        break;
                    rdp_trace_event_level(RDP_TRACE_CLIENT,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "client.graphics.progressive",
                                          "dvc_channel_id=%u surface_id=%u context_id=%u blocks=%u regions=%u tiles=%u simple_tiles=%u first_tiles=%u upgrade_tiles=%u rendered_tiles=%u failed_tiles=%u missing_tiles=%u",
                                          channel_id,
                                          wire.surface_id,
                                          wire.codec_context_id,
                                          progressive.block_count,
                                          progressive.region_count,
                                          progressive.tile_count,
                                          progressive.simple_tile_count,
                                          progressive.first_tile_count,
                                          progressive.upgrade_tile_count,
                                          rendered_tiles,
                                          failed_tiles,
                                          missing_tiles);
                }
                else
                {
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.graphics.progressive.rejected",
                                    "dvc_channel_id=%u surface_id=%u context_id=%u payload_len=%u parser_status=%d",
                                    channel_id,
                                    wire.surface_id,
                                    wire.codec_context_id,
                                    wire.bitmap_data_length,
                                    (int)status);
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    break;
                }
            }
            else if (wire.codec_id == RDP_GRAPHICS_CODECID_CAVIDEO)
            {
                rdp_session_graphics_surface* surface = rdp_session_graphics_surface_find(session, wire.surface_id);

                if (!surface)
                {
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    break;
                }
                status = rdp_session_graphics_surface_write_rfx(session,
                                                                surface,
                                                                wire.bitmap_data,
                                                                wire.bitmap_data_length,
                                                                wire.pixel_format);
                if (status == LIBRDP_STATUS_UNSUPPORTED)
                {
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.graphics.codec.rejected",
                                    "dvc_channel_id=%u surface_id=%u codec_id=%u context_id=%u payload_len=%u decoder_status=%d",
                                    channel_id,
                                    wire.surface_id,
                                    wire.codec_id,
                                    wire.codec_context_id,
                                    wire.bitmap_data_length,
                                    (int)status);
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                }
                if (status != LIBRDP_STATUS_OK)
                    break;
            }
            else
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.graphics.wire_to_surface.rejected",
                                "dvc_channel_id=%u surface_id=%u codec_id=%u context_id=%u payload_len=%u",
                                channel_id,
                                wire.surface_id,
                                wire.codec_id,
                                wire.codec_context_id,
                                wire.bitmap_data_length);
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_DELETE_ENCODING_CONTEXT)
        {
            rdp_graphics_delete_encoding_context context;

            status = rdp_graphics_parse_delete_encoding_context(pdu, header.pdu_length, &context);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.encoding_context.delete",
                            "dvc_channel_id=%u surface_id=%u context_id=%u",
                            channel_id,
                            context.surface_id,
                            context.codec_context_id);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_SURFACE_TO_SURFACE)
        {
            rdp_graphics_surface_to_surface surface_to_surface;
            rdp_session_graphics_surface* source = NULL;
            rdp_session_graphics_surface* dest = NULL;
            rdp_graphics_point16 last_point;
            uint16_t i = 0;

            memset(&last_point, 0, sizeof(last_point));
            status = rdp_graphics_parse_surface_to_surface(pdu, header.pdu_length, &surface_to_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            source = rdp_session_graphics_surface_find(session, surface_to_surface.surface_id_src);
            dest = rdp_session_graphics_surface_find(session, surface_to_surface.surface_id_dest);
            if (!source || !dest)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            for (i = 0; i < surface_to_surface.dest_points_count; i++)
            {
                rdp_graphics_point16 point;

                status = rdp_graphics_parse_point16(surface_to_surface.dest_points + ((size_t)i * 4u),
                                                    surface_to_surface.dest_points_len - ((size_t)i * 4u),
                                                    &point);
                if (status == LIBRDP_STATUS_OK)
                {
                    status = rdp_session_graphics_surface_copy(session,
                                                               source,
                                                               dest,
                                                               &surface_to_surface.rect_src,
                                                               &point);
                    if (status == LIBRDP_STATUS_OK)
                        last_point = point;
                }
                if (status != LIBRDP_STATUS_OK)
                    break;
            }
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.graphics.surface_to_surface",
                                  "dvc_channel_id=%u source_id=%u dest_id=%u points=%u src_left=%u src_top=%u src_right=%u src_bottom=%u last_dst_x=%u last_dst_y=%u",
                                  channel_id,
                                  surface_to_surface.surface_id_src,
                                  surface_to_surface.surface_id_dest,
                                  surface_to_surface.dest_points_count,
                                  surface_to_surface.rect_src.left,
                                  surface_to_surface.rect_src.top,
                                  surface_to_surface.rect_src.right,
                                  surface_to_surface.rect_src.bottom,
                                  last_point.x,
                                  last_point.y);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_SURFACE_TO_CACHE)
        {
            rdp_graphics_surface_to_cache surface_to_cache;

            status = rdp_graphics_parse_surface_to_cache(pdu, header.pdu_length, &surface_to_cache);
            if (status != LIBRDP_STATUS_OK)
                break;
            status = rdp_session_graphics_cache_store(session, &surface_to_cache);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.graphics.surface_to_cache",
                                  "dvc_channel_id=%u surface_id=%u cache_slot=%u width=%u height=%u src_left=%u src_top=%u src_right=%u src_bottom=%u",
                                  channel_id,
                                  surface_to_cache.surface_id,
                                  surface_to_cache.cache_slot,
                                  (unsigned)(surface_to_cache.rect_src.right - surface_to_cache.rect_src.left),
                                  (unsigned)(surface_to_cache.rect_src.bottom - surface_to_cache.rect_src.top),
                                  surface_to_cache.rect_src.left,
                                  surface_to_cache.rect_src.top,
                                  surface_to_cache.rect_src.right,
                                  surface_to_cache.rect_src.bottom);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_CACHE_TO_SURFACE)
        {
            rdp_graphics_cache_to_surface cache_to_surface;
            rdp_session_graphics_cache_entry* cache = NULL;
            rdp_session_graphics_surface* surface = NULL;
            rdp_graphics_point16 last_point;
            uint16_t i = 0;

            memset(&last_point, 0, sizeof(last_point));
            status = rdp_graphics_parse_cache_to_surface(pdu, header.pdu_length, &cache_to_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            cache = rdp_session_graphics_cache_find(session, cache_to_surface.cache_slot);
            surface = rdp_session_graphics_surface_find(session, cache_to_surface.surface_id);
            if (!cache || !surface)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            for (i = 0; i < cache_to_surface.dest_points_count; i++)
            {
                rdp_graphics_point16 point;

                status = rdp_graphics_parse_point16(cache_to_surface.dest_points + ((size_t)i * 4u),
                                                    cache_to_surface.dest_points_len - ((size_t)i * 4u),
                                                    &point);
                if (status == LIBRDP_STATUS_OK)
                {
                    status = rdp_session_graphics_cache_copy_to_surface(session, cache, surface, &point);
                    if (status == LIBRDP_STATUS_OK)
                        last_point = point;
                }
                if (status != LIBRDP_STATUS_OK)
                    break;
            }
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.graphics.cache_to_surface",
                                  "dvc_channel_id=%u cache_slot=%u surface_id=%u points=%u cache_width=%u cache_height=%u last_dst_x=%u last_dst_y=%u",
                                  channel_id,
                                  cache_to_surface.cache_slot,
                                  cache_to_surface.surface_id,
                                  cache_to_surface.dest_points_count,
                                  cache->width,
                                  cache->height,
                                  last_point.x,
                                  last_point.y);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_EVICT_CACHE_ENTRY)
        {
            rdp_graphics_evict_cache_entry evict;

            status = rdp_graphics_parse_evict_cache_entry(pdu, header.pdu_length, &evict);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_session_graphics_cache_evict(session, evict.cache_slot);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.cache.evict",
                            "dvc_channel_id=%u cache_slot=%u",
                            channel_id,
                            evict.cache_slot);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_RESET_GRAPHICS)
        {
            rdp_graphics_reset reset;

            status = rdp_graphics_parse_reset(pdu, header.pdu_length, &reset);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_session_graphics_dirty_reset(session);
            rdp_session_graphics_surfaces_clear(session);
            if (reset.width != librdp_surface_width(session->surface) ||
                reset.height != librdp_surface_height(session->surface))
            {
                status = librdp_surface_resize(session->surface, reset.width, reset.height);
                if (status != LIBRDP_STATUS_OK)
                    break;
                {
                    librdp_rect rect;

                    rect.x = 0;
                    rect.y = 0;
                    rect.width = reset.width;
                    rect.height = reset.height;
                    rdp_session_emit_graphics_update(session,
                                                     LIBRDP_GRAPHICS_UPDATE_DESKTOP_RESIZE,
                                                     0,
                                                     session->graphics_current_frame_id,
                                                     &rect,
                                                     LIBRDP_PIXEL_FORMAT_BGRA32,
                                                     NULL,
                                                     0);
                }
                rdp_session_emit_surface_invalidated(session, 0, 0, reset.width, reset.height);
            }
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.reset",
                            "dvc_channel_id=%u width=%u height=%u monitors=%u",
                            channel_id,
                            reset.width,
                            reset.height,
                            reset.monitor_count);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_CREATE_SURFACE)
        {
            rdp_graphics_create_surface create_surface;

            status = rdp_graphics_parse_create_surface(pdu, header.pdu_length, &create_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            status = rdp_session_graphics_surface_create(session, &create_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface.create",
                            "dvc_channel_id=%u surface_id=%u width=%u height=%u pixel_format=%u",
                            channel_id,
                            create_surface.surface_id,
                            create_surface.width,
                            create_surface.height,
                            create_surface.pixel_format);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_DELETE_SURFACE)
        {
            rdp_graphics_delete_surface delete_surface;

            status = rdp_graphics_parse_delete_surface(pdu, header.pdu_length, &delete_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_session_graphics_surface_delete(session, delete_surface.surface_id);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface.delete",
                            "dvc_channel_id=%u surface_id=%u",
                            channel_id,
                            delete_surface.surface_id);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_MAP_SURFACE_TO_OUTPUT)
        {
            rdp_graphics_map_surface_to_output map;

            status = rdp_graphics_parse_map_surface_to_output(pdu, header.pdu_length, &map);
            if (status != LIBRDP_STATUS_OK)
                break;
            status = rdp_session_graphics_surface_map(session, &map);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface.map_output",
                            "dvc_channel_id=%u surface_id=%u x=%u y=%u",
                            channel_id,
                            map.surface_id,
                            map.output_origin_x,
                            map.output_origin_y);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_MAP_SURFACE_TO_SCALED_OUTPUT)
        {
            rdp_graphics_map_surface_to_scaled_output map;

            status = rdp_graphics_parse_map_surface_to_scaled_output(pdu, header.pdu_length, &map);
            if (status != LIBRDP_STATUS_OK)
                break;
            status = rdp_session_graphics_surface_map_scaled(session, &map);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface.map_scaled_output",
                            "dvc_channel_id=%u surface_id=%u x=%u y=%u target_width=%u target_height=%u",
                            channel_id,
                            map.surface_id,
                            map.output_origin_x,
                            map.output_origin_y,
                            map.target_width,
                            map.target_height);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_SOLIDFILL)
        {
            rdp_graphics_solid_fill solid_fill;
            rdp_session_graphics_surface* surface = NULL;
            uint16_t i = 0;

            status = rdp_graphics_parse_solid_fill(pdu, header.pdu_length, &solid_fill);
            if (status != LIBRDP_STATUS_OK)
                break;
            surface = rdp_session_graphics_surface_find(session, solid_fill.surface_id);
            if (!surface)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            for (i = 0; i < solid_fill.rect_count; i++)
            {
                rdp_graphics_rect16 rect;

                status = rdp_graphics_parse_rect16(solid_fill.rects + ((size_t)i * 8u),
                                                   solid_fill.rects_len - ((size_t)i * 8u),
                                                   &rect);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_graphics_surface_fill(session, surface, &rect, solid_fill.fill_pixel);
                if (status != LIBRDP_STATUS_OK)
                    break;
            }
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.solid_fill",
                            "dvc_channel_id=%u surface_id=%u rects=%u",
                            channel_id,
                            solid_fill.surface_id,
                            solid_fill.rect_count);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_START_FRAME)
        {
            rdp_graphics_start_frame start_frame;

            status = rdp_graphics_parse_start_frame(pdu, header.pdu_length, &start_frame);
            if (status != LIBRDP_STATUS_OK)
                break;
            if (session->graphics_frame_active)
                rdp_session_graphics_dirty_flush(session);
            session->graphics_frame_active = 1;
            session->graphics_current_frame_id = start_frame.frame_id;
            session->graphics_dirty_pending = 0;
            rdp_session_emit_graphics_frame(session,
                                            LIBRDP_GRAPHICS_UPDATE_FRAME_BEGIN,
                                            start_frame.frame_id);
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.graphics.frame.start",
                                  "dvc_channel_id=%u frame_id=%u timestamp=%u",
                                  channel_id,
                                  start_frame.frame_id,
                                  start_frame.timestamp);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_END_FRAME)
        {
            rdp_graphics_end_frame end_frame;

            status = rdp_graphics_parse_end_frame(pdu, header.pdu_length, &end_frame);
            if (status != LIBRDP_STATUS_OK)
                break;
            session->graphics_frame_active = 0;
            rdp_session_graphics_dirty_flush(session);
            session->graphics_frames_decoded++;
            rdp_session_metric_add(&session->metrics.frames, 1);
            rdp_session_emit_graphics_frame(session,
                                            LIBRDP_GRAPHICS_UPDATE_FRAME_END,
                                            end_frame.frame_id);
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.graphics.frame.end",
                                  "dvc_channel_id=%u frame_id=%u total_frames_decoded=%u",
                                  channel_id,
                                  end_frame.frame_id,
                                  session->graphics_frames_decoded);
            status = rdp_session_send_graphics_frame_ack(session, end_frame.frame_id);
            if (status != LIBRDP_STATUS_OK)
                break;
        }
        offset += header.pdu_length;
    }

    rdp_buffer_free(&decoded);
    return status;
}
