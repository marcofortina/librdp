/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: session graphics invalidation and pointer update dispatch.
 * Invariants: dirty rectangles are emitted in frame order and pointer cache entries own decoded BGRA buffers.
 * Ownership: the session owns cached cursor pixels; callbacks receive borrowed buffers valid only for the event.
 * Threading: callers must already satisfy the session owner-thread contract before mutating graphics state.
 * Trust boundary: wire pointer masks and surface rectangles are bounds-checked before reaching viewer callbacks.
 */

#include "client/session_internal.h"
#include "common/trace.h"

#include <stdint.h>
#include <string.h>

void rdp_session_emit_surface_invalidated(librdp_session* session,
                                                 uint32_t x,
                                                 uint32_t y,
                                                 uint32_t width,
                                                 uint32_t height)
{
    librdp_event event;

    if (!session || width == 0 || height == 0)
        return;
    if (session->gdi_drawing_to_offscreen)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "client.gdi.offscreen.invalidated",
                              "surface_id=%u x=%u y=%u width=%u height=%u",
                              session->gdi_current_surface_id,
                              x,
                              y,
                              width,
                              height);
        return;
    }
    event.type = LIBRDP_EVENT_SURFACE_INVALIDATED;
    event.data.surface.x = x;
    event.data.surface.y = y;
    event.data.surface.width = width;
    event.data.surface.height = height;
    rdp_session_emit(session, &event);
    rdp_session_emit_graphics_pixel_rect(session, x, y, width, height);
    rdp_session_metric_add(&session->metrics.surface_updates, 1);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.surface.invalidated",
                    "x=%u y=%u width=%u height=%u output_width=%u output_height=%u frame_id=%u frame_active=%u",
                    x,
                    y,
                    width,
                    height,
                    librdp_surface_width(session->surface),
                    librdp_surface_height(session->surface),
                    session->graphics_current_frame_id,
                    session->graphics_frame_active ? 1u : 0u);
}

void rdp_session_graphics_dirty_reset(librdp_session* session)
{
    if (!session)
        return;
    session->graphics_frame_active = 0;
    session->graphics_dirty_pending = 0;
    session->graphics_dirty_left = 0;
    session->graphics_dirty_top = 0;
    session->graphics_dirty_right = 0;
    session->graphics_dirty_bottom = 0;
    session->graphics_current_frame_id = 0;
}

void rdp_session_graphics_dirty_add(librdp_session* session,
                                           uint32_t x,
                                           uint32_t y,
                                           uint32_t width,
                                           uint32_t height)
{
    uint32_t right = 0;
    uint32_t bottom = 0;

    if (!session || width == 0 || height == 0)
        return;
    if (!session->graphics_frame_active)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.graphics.dirty.immediate",
                              "x=%u y=%u width=%u height=%u frame_id=%u",
                              x,
                              y,
                              width,
                              height,
                              session->graphics_current_frame_id);
        rdp_session_emit_surface_invalidated(session, x, y, width, height);
        return;
    }

    right = x + width;
    bottom = y + height;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.frame.dirty.add",
                          "frame_id=%u x=%u y=%u width=%u height=%u pending=%u previous_left=%u previous_top=%u previous_right=%u previous_bottom=%u",
                          session->graphics_current_frame_id,
                          x,
                          y,
                          width,
                          height,
                          session->graphics_dirty_pending ? 1u : 0u,
                          session->graphics_dirty_left,
                          session->graphics_dirty_top,
                          session->graphics_dirty_right,
                          session->graphics_dirty_bottom);
    if (!session->graphics_dirty_pending)
    {
        session->graphics_dirty_pending = 1;
        session->graphics_dirty_left = x;
        session->graphics_dirty_top = y;
        session->graphics_dirty_right = right;
        session->graphics_dirty_bottom = bottom;
        return;
    }
    if (x < session->graphics_dirty_left)
        session->graphics_dirty_left = x;
    if (y < session->graphics_dirty_top)
        session->graphics_dirty_top = y;
    if (right > session->graphics_dirty_right)
        session->graphics_dirty_right = right;
    if (bottom > session->graphics_dirty_bottom)
        session->graphics_dirty_bottom = bottom;
}

void rdp_session_graphics_dirty_flush(librdp_session* session)
{
    if (!session || !session->graphics_dirty_pending)
        return;
    rdp_session_emit_surface_invalidated(session,
                                         session->graphics_dirty_left,
                                         session->graphics_dirty_top,
                                         session->graphics_dirty_right - session->graphics_dirty_left,
                                         session->graphics_dirty_bottom - session->graphics_dirty_top);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.graphics.frame.flush",
                          "frame_id=%u x=%u y=%u width=%u height=%u",
                          session->graphics_current_frame_id,
                          session->graphics_dirty_left,
                          session->graphics_dirty_top,
                          session->graphics_dirty_right - session->graphics_dirty_left,
                          session->graphics_dirty_bottom - session->graphics_dirty_top);
    session->graphics_dirty_pending = 0;
}

void rdp_session_pointer_cache_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_POINTER_CACHE_SLOTS; i++)
        rdp_buffer_free(&session->pointer_cache[i].pixels);
    memset(session->pointer_cache, 0, sizeof(session->pointer_cache));
}

static size_t rdp_session_pointer_mask_stride(uint16_t width)
{
    return (((size_t)width + 15u) / 16u) * 2u;
}

static size_t rdp_session_pointer_xor_stride(uint16_t width, uint16_t bpp)
{
    return ((((size_t)width * bpp) + 15u) / 16u) * 2u;
}

static int rdp_session_pointer_mask_bit(const uint8_t* data,
                                        size_t stride,
                                        uint16_t width,
                                        uint16_t height,
                                        uint16_t x,
                                        uint16_t y)
{
    size_t row = (size_t)(height - 1u - y);
    size_t offset = row * stride + ((size_t)x / 8u);
    uint8_t mask = (uint8_t)(0x80u >> (x % 8u));

    if (!data || x >= width || y >= height)
        return 0;
    return (data[offset] & mask) != 0;
}

static uint64_t rdp_session_pointer_hash_bytes(const uint8_t* data, size_t length)
{
    uint64_t hash = 1469598103934665603ull;
    size_t i = 0;

    if (!data)
        return 0;
    for (i = 0; i < length; i++)
    {
        hash ^= data[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

static int rdp_session_pointer_xor_pixel_nonzero(const rdp_pointer_update* update,
                                                 size_t xor_stride,
                                                 uint16_t x,
                                                 uint16_t y)
{
    const uint8_t* row = NULL;
    const uint8_t* pixel = NULL;

    if (!update || !update->xor_mask)
        return 0;
    if (update->xor_bpp == 1u)
        return rdp_session_pointer_mask_bit(update->xor_mask,
                                            xor_stride,
                                            update->width,
                                            update->height,
                                            x,
                                            y);
    row = update->xor_mask + ((size_t)(update->height - 1u - y) * xor_stride);
    if (update->xor_bpp == 24u)
    {
        pixel = row + ((size_t)x * 3u);
        return pixel[0] != 0 || pixel[1] != 0 || pixel[2] != 0;
    }
    if (update->xor_bpp == 32u)
    {
        pixel = row + ((size_t)x * 4u);
        return pixel[0] != 0 || pixel[1] != 0 || pixel[2] != 0 || pixel[3] != 0;
    }
    return 0;
}

/*
 * Format pointer-shape metadata for trace without dumping sensitive or
 * unbounded pixel data. The routine keeps visibility, cache, hotspot, and mask
 * information correlated for cursor interop debugging, and its failure policy
 * is to report only bounded counters instead of raw cursor payloads.
 */
static void rdp_session_pointer_trace_shape(const rdp_pointer_update* update,
                                            const rdp_buffer* decoded,
                                            size_t decoded_stride)
{
    uint32_t and_set = 0;
    uint32_t xor_nonzero = 0;
    uint32_t invert_like = 0;
    uint32_t decoded_opaque = 0;
    uint32_t decoded_transparent = 0;
    uint32_t decoded_rgb_nonzero = 0;
    uint32_t decoded_alpha_nonzero = 0;
    uint32_t has_alpha = 0;
    uint16_t y = 0;
    uint16_t x = 0;
    size_t and_stride = 0;
    size_t xor_stride = 0;

    if (!rdp_trace_enabled_level(RDP_TRACE_CLIENT, RDP_TRACE_LEVEL_TRACE) ||
        !update || !decoded || !decoded->data || update->kind != RDP_POINTER_UPDATE_KIND_SHAPE ||
        decoded_stride < (size_t)update->width * 4u)
        return;

    and_stride = rdp_session_pointer_mask_stride(update->width);
    xor_stride = rdp_session_pointer_xor_stride(update->width, update->xor_bpp);
    if (and_stride == 0 || xor_stride == 0)
        return;
    if (update->and_mask_len < and_stride * update->height ||
        update->xor_mask_len < xor_stride * update->height ||
        decoded->length < decoded_stride * update->height)
        return;

    if (update->xor_bpp == 32u)
    {
        size_t i = 3;

        for (i = 3; i < update->xor_mask_len; i += 4)
        {
            if (update->xor_mask[i] != 0)
            {
                has_alpha = 1;
                break;
            }
        }
    }

    for (y = 0; y < update->height; y++)
    {
        const uint8_t* row = decoded->data + ((size_t)y * decoded_stride);

        for (x = 0; x < update->width; x++)
        {
            int and_bit = rdp_session_pointer_mask_bit(update->and_mask,
                                                       and_stride,
                                                       update->width,
                                                       update->height,
                                                       x,
                                                       y);
            int xor_pixel = rdp_session_pointer_xor_pixel_nonzero(update, xor_stride, x, y);
            const uint8_t* pixel = row + ((size_t)x * 4u);

            if (and_bit)
                and_set++;
            if (xor_pixel)
                xor_nonzero++;
            if (and_bit && xor_pixel)
                invert_like++;
            if (pixel[0] != 0 || pixel[1] != 0 || pixel[2] != 0)
                decoded_rgb_nonzero++;
            if (pixel[3] != 0)
            {
                decoded_alpha_nonzero++;
                decoded_opaque++;
            }
            else
            {
                decoded_transparent++;
            }
        }
    }

    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.pointer.shape.stats",
                          "cache_index=%u width=%u height=%u hot_x=%u hot_y=%u xor_bpp=%u has_alpha=%u xor_len=%u and_len=%u and_set=%u xor_nonzero=%u invert_like=%u decoded_opaque=%u decoded_transparent=%u decoded_rgb_nonzero=%u decoded_alpha_nonzero=%u hash_xor=%016llx hash_and=%016llx hash_bgra=%016llx",
                          update->cache_index,
                          update->width,
                          update->height,
                          update->hot_x,
                          update->hot_y,
                          update->xor_bpp,
                          has_alpha,
                          (unsigned)update->xor_mask_len,
                          (unsigned)update->and_mask_len,
                          and_set,
                          xor_nonzero,
                          invert_like,
                          decoded_opaque,
                          decoded_transparent,
                          decoded_rgb_nonzero,
                          decoded_alpha_nonzero,
                          (unsigned long long)rdp_session_pointer_hash_bytes(update->xor_mask,
                                                                              update->xor_mask_len),
                          (unsigned long long)rdp_session_pointer_hash_bytes(update->and_mask,
                                                                              update->and_mask_len),
                          (unsigned long long)rdp_session_pointer_hash_bytes(decoded->data,
                                                                              decoded->length));
}

void rdp_session_pointer_emit_default(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_POINTER;
    event.data.pointer.update_type = LIBRDP_POINTER_UPDATE_DEFAULT;
    event.data.pointer.visible = 1;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.pointer.default", "visible=1");
}

static void rdp_session_pointer_emit_hidden(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_POINTER;
    event.data.pointer.update_type = LIBRDP_POINTER_UPDATE_HIDDEN;
    event.data.pointer.visible = 0;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.pointer.hidden", "visible=0");
}

static void rdp_session_pointer_emit_position(librdp_session* session, uint16_t x, uint16_t y)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_POINTER;
    event.data.pointer.update_type = LIBRDP_POINTER_UPDATE_POSITION;
    event.data.pointer.x = x;
    event.data.pointer.y = y;
    event.data.pointer.visible = 1;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.pointer.position", "x=%u y=%u", x, y);
}

static void rdp_session_pointer_emit_shape(librdp_session* session, const rdp_session_pointer_cache_entry* entry)
{
    librdp_event event;

    if (!session || !entry || !entry->active)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_POINTER;
    event.data.pointer = entry->pointer;
    event.data.pointer.pixels = entry->pixels.data;
    event.data.pointer.pixels_len = entry->pixels.length;
    event.data.pointer.visible = 1;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.pointer.shape",
                    "cache_index=%u width=%u height=%u hot_x=%u hot_y=%u pixels=%u",
                    event.data.pointer.cache_index,
                    event.data.pointer.width,
                    event.data.pointer.height,
                    event.data.pointer.hot_x,
                    event.data.pointer.hot_y,
                    (unsigned)event.data.pointer.pixels_len);
}

static librdp_status rdp_session_pointer_store_shape(librdp_session* session, const rdp_pointer_update* update)
{
    rdp_session_pointer_cache_entry* entry = NULL;
    rdp_buffer decoded;
    size_t stride = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !update || update->kind != RDP_POINTER_UPDATE_KIND_SHAPE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (update->cache_index >= RDP_SESSION_POINTER_CACHE_SLOTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_buffer_init(&decoded);
    status = rdp_pointer_decode_bgra32(update, &decoded, &stride);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&decoded);
        return status;
    }

    entry = &session->pointer_cache[update->cache_index];
    rdp_buffer_free(&entry->pixels);
    entry->pixels = decoded;
    memset(&entry->pointer, 0, sizeof(entry->pointer));
    entry->pointer.update_type = LIBRDP_POINTER_UPDATE_SHAPE;
    entry->pointer.cache_index = update->cache_index;
    entry->pointer.hot_x = update->hot_x;
    entry->pointer.hot_y = update->hot_y;
    entry->pointer.width = update->width;
    entry->pointer.height = update->height;
    entry->pointer.stride = (uint32_t)stride;
    entry->pointer.pixels = entry->pixels.data;
    entry->pointer.pixels_len = entry->pixels.length;
    entry->pointer.visible = 1;
    entry->active = 1;
    rdp_session_pointer_trace_shape(update, &entry->pixels, stride);
    rdp_session_pointer_emit_shape(session, entry);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_session_pointer_apply_update(librdp_session* session, const rdp_pointer_update* update)
{
    if (!session || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    switch (update->kind)
    {
        case RDP_POINTER_UPDATE_KIND_NULL:
            rdp_session_pointer_emit_hidden(session);
            return LIBRDP_STATUS_OK;
        case RDP_POINTER_UPDATE_KIND_DEFAULT:
            rdp_session_pointer_emit_default(session);
            return LIBRDP_STATUS_OK;
        case RDP_POINTER_UPDATE_KIND_POSITION:
            rdp_session_pointer_emit_position(session, update->x, update->y);
            return LIBRDP_STATUS_OK;
        case RDP_POINTER_UPDATE_KIND_CACHED:
            if (update->cache_index >= RDP_SESSION_POINTER_CACHE_SLOTS ||
                !session->pointer_cache[update->cache_index].active)
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.pointer.cached.missing",
                                "cache_index=%u",
                                update->cache_index);
                return LIBRDP_STATUS_OK;
            }
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.pointer.cached",
                            "cache_index=%u",
                            update->cache_index);
            rdp_session_pointer_emit_shape(session, &session->pointer_cache[update->cache_index]);
            return LIBRDP_STATUS_OK;
        case RDP_POINTER_UPDATE_KIND_SHAPE:
            return rdp_session_pointer_store_shape(session, update);
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}
