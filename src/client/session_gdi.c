/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client classic graphics and GDI session domain.
 * Invariants: palette, surface-command, cache, offscreen, brush, glyph, and saved-bitmap state changes are applied only after order bounds are validated.
 * Ownership: the session owns all decoded bitmap buffers, cache entries, offscreen surfaces, and transient stream-bitmap state.
 * Threading: callers must run on the session owner thread because GDI order state and rendering caches are shared mutable session data.
 * Trust boundary: all GDI orders, surface commands, cache entries, and bitmap payloads originate from slow-path or fast-path server updates.
 */

#include "client/session_internal.h"
#include "graphics/rfx_stream.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static size_t rdp_session_gdi_bitmap_cache_entry_size(const rdp_session_gdi_bitmap_cache_entry* entry);

static void rdp_session_gdi_bitmap_cache_evict(librdp_session* session, size_t index)
{
    rdp_session_gdi_bitmap_cache_entry* entry = NULL;

    if (!session || index >= RDP_SESSION_GDI_BITMAP_CACHE_SLOTS)
        return;
    entry = &session->gdi_bitmap_cache[index];
    if (entry->active)
    {
        size_t size = rdp_session_gdi_bitmap_cache_entry_size(entry);

        if (session->gdi_bitmap_cache_bytes >= size)
            session->gdi_bitmap_cache_bytes -= size;
        else
            session->gdi_bitmap_cache_bytes = 0;
    }
    rdp_buffer_free(&entry->pixels);
    rdp_buffer_free(&entry->raw);
    memset(entry, 0, sizeof(*entry));
}

void rdp_session_gdi_bitmap_cache_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_GDI_BITMAP_CACHE_SLOTS; i++)
    {
        rdp_buffer_free(&session->gdi_bitmap_cache[i].pixels);
        rdp_buffer_free(&session->gdi_bitmap_cache[i].raw);
    }
    memset(session->gdi_bitmap_cache, 0, sizeof(session->gdi_bitmap_cache));
    session->gdi_bitmap_cache_bytes = 0;
    session->gdi_bitmap_cache_clock = 0;
}

void rdp_session_gdi_color_table_cache_clear(librdp_session* session)
{
    if (!session)
        return;
    memset(session->gdi_color_table_cache, 0, sizeof(session->gdi_color_table_cache));
}

void rdp_session_gdi_brush_cache_clear(librdp_session* session)
{
    if (!session)
        return;
    memset(session->gdi_brush_cache, 0, sizeof(session->gdi_brush_cache));
}

void rdp_session_gdi_ninegrid_cache_clear(librdp_session* session)
{
    if (!session)
        return;
    memset(session->gdi_ninegrid_cache, 0, sizeof(session->gdi_ninegrid_cache));
}

void rdp_session_gdi_glyph_cache_clear(librdp_session* session)
{
    size_t id = 0;
    size_t index = 0;

    if (!session)
        return;
    for (id = 0; id < RDP_SESSION_GDI_GLYPH_CACHE_IDS; id++)
    {
        for (index = 0; index < RDP_SESSION_GDI_GLYPH_CACHE_SLOTS; index++)
            rdp_buffer_free(&session->gdi_glyph_cache[id][index].bitmap);
    }
    memset(session->gdi_glyph_cache, 0, sizeof(session->gdi_glyph_cache));
    session->gdi_glyph_cache_bytes = 0;
}

void rdp_session_gdi_glyph_fragment_cache_clear(librdp_session* session)
{
    size_t index = 0;

    if (!session)
        return;
    for (index = 0; index < RDP_SESSION_GDI_GLYPH_FRAGMENT_SLOTS; index++)
        rdp_buffer_free(&session->gdi_glyph_fragments[index].data);
    memset(session->gdi_glyph_fragments, 0, sizeof(session->gdi_glyph_fragments));
}

static rdp_session_gdi_glyph_cache_entry* rdp_session_gdi_glyph_cache_find(librdp_session* session,
                                                                           uint32_t cache_id,
                                                                           uint32_t cache_index)
{
    if (!session || cache_id >= RDP_SESSION_GDI_GLYPH_CACHE_IDS ||
        cache_index >= RDP_SESSION_GDI_GLYPH_CACHE_SLOTS)
        return NULL;
    if (!session->gdi_glyph_cache[cache_id][cache_index].active)
        return NULL;
    return &session->gdi_glyph_cache[cache_id][cache_index];
}

static librdp_status rdp_session_gdi_glyph_cache_store(librdp_session* session,
                                                       uint32_t cache_id,
                                                       const rdp_gdi_glyph_bitmap* glyph)
{
    rdp_session_gdi_glyph_cache_entry* entry = NULL;
    size_t old_size = 0;

    if (!session || !glyph || !glyph->bitmap || glyph->bitmap_len == 0 ||
        cache_id >= RDP_SESSION_GDI_GLYPH_CACHE_IDS ||
        glyph->cache_index >= RDP_SESSION_GDI_GLYPH_CACHE_SLOTS ||
        glyph->bitmap_len > RDP_SESSION_GDI_GLYPH_MAX_BYTES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    entry = &session->gdi_glyph_cache[cache_id][glyph->cache_index];
    old_size = entry->bitmap.length;
    if (session->gdi_glyph_cache_bytes >= old_size)
        session->gdi_glyph_cache_bytes -= old_size;
    else
        session->gdi_glyph_cache_bytes = 0;
    if (session->gdi_glyph_cache_bytes > RDP_SESSION_GDI_GLYPH_MAX_BYTES - glyph->bitmap_len)
    {
        rdp_session_gdi_glyph_cache_clear(session);
        entry = &session->gdi_glyph_cache[cache_id][glyph->cache_index];
    }
    if (rdp_buffer_reserve(&entry->bitmap, glyph->bitmap_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_NO_MEMORY;
    memcpy(entry->bitmap.data, glyph->bitmap, glyph->bitmap_len);
    entry->bitmap.length = glyph->bitmap_len;
    entry->active = 1;
    entry->cache_id = cache_id;
    entry->cache_index = glyph->cache_index;
    entry->x = glyph->x;
    entry->y = glyph->y;
    entry->width = glyph->width;
    entry->height = glyph->height;
    session->gdi_glyph_cache_bytes += glyph->bitmap_len;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.glyph_cache.store",
                          "cache_id=%u cache_index=%u x=%d y=%d width=%u height=%u bytes=%u total_bytes=%u",
                          cache_id,
                          glyph->cache_index,
                          glyph->x,
                          glyph->y,
                          glyph->width,
                          glyph->height,
                          glyph->bitmap_len,
                          (unsigned)session->gdi_glyph_cache_bytes);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_glyph_fragment_store(librdp_session* session,
                                                          uint8_t fragment_id,
                                                          const uint8_t* data,
                                                          uint32_t length)
{
    rdp_session_gdi_glyph_fragment* fragment = NULL;

    if (!session || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    fragment = &session->gdi_glyph_fragments[fragment_id];
    if (rdp_buffer_reserve(&fragment->data, length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_NO_MEMORY;
    if (length > 0)
        memcpy(fragment->data.data, data, length);
    fragment->data.length = length;
    fragment->active = 1;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.glyph_fragment.store",
                          "fragment_id=%u bytes=%u",
                          fragment_id,
                          length);
    return LIBRDP_STATUS_OK;
}

static size_t rdp_session_gdi_bitmap_cache_entry_size(const rdp_session_gdi_bitmap_cache_entry* entry)
{
    if (!entry || !entry->active)
        return 0;
    return entry->pixels.length + entry->raw.length;
}

static rdp_session_gdi_ninegrid_cache_entry* rdp_session_gdi_ninegrid_cache_find(librdp_session* session,
                                                                                 uint32_t bitmap_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_NINEGRID_CACHE_SLOTS; i++)
    {
        rdp_session_gdi_ninegrid_cache_entry* entry = &session->gdi_ninegrid_cache[i];

        if (entry->active && entry->bitmap_id == bitmap_id)
            return entry;
    }
    return NULL;
}

static rdp_session_gdi_ninegrid_cache_entry* rdp_session_gdi_ninegrid_cache_slot(librdp_session* session,
                                                                                 uint32_t bitmap_id)
{
    size_t i = 0;
    rdp_session_gdi_ninegrid_cache_entry* entry =
        rdp_session_gdi_ninegrid_cache_find(session, bitmap_id);

    if (entry)
        return entry;
    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_NINEGRID_CACHE_SLOTS; i++)
    {
        if (!session->gdi_ninegrid_cache[i].active)
            return &session->gdi_ninegrid_cache[i];
    }
    return &session->gdi_ninegrid_cache[bitmap_id % RDP_SESSION_GDI_NINEGRID_CACHE_SLOTS];
}

static const rdp_palette_update* rdp_session_gdi_color_table_find(const librdp_session* session,
                                                                  uint32_t cache_index)
{
    if (!session || cache_index >= RDP_SESSION_GDI_COLOR_TABLE_SLOTS ||
        !session->gdi_color_table_cache[cache_index].active)
        return NULL;
    return &session->gdi_color_table_cache[cache_index].palette;
}

static librdp_status rdp_session_gdi_color_table_store(librdp_session* session,
                                                       const rdp_gdi_cache_color_table_order* order)
{
    rdp_session_gdi_color_table_cache_entry* entry = NULL;

    if (!session || !order || order->palette.count != RDP_BITMAP_PALETTE_MAX_ENTRIES ||
        order->cache_index >= RDP_SESSION_GDI_COLOR_TABLE_SLOTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    entry = &session->gdi_color_table_cache[order->cache_index];
    entry->active = 1;
    entry->palette = order->palette;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.color_table.store",
                          "cache_index=%u colors=%u",
                          order->cache_index,
                          order->palette.count);
    return LIBRDP_STATUS_OK;
}

static uint8_t rdp_session_gdi_scale_5_to_8(uint16_t value)
{
    return (uint8_t)((value << 3u) | (value >> 2u));
}

static uint8_t rdp_session_gdi_scale_6_to_8(uint16_t value)
{
    return (uint8_t)((value << 2u) | (value >> 4u));
}

static uint32_t rdp_session_gdi_brush_bpp(uint32_t format)
{
    if (format == RDP_GDI_BMF_1BPP)
        return 1;
    if (format == RDP_GDI_BMF_8BPP)
        return 8;
    if (format == RDP_GDI_BMF_16BPP)
        return 16;
    if (format == RDP_GDI_BMF_24BPP)
        return 24;
    if (format == RDP_GDI_BMF_32BPP)
        return 32;
    return 0;
}

static void rdp_session_gdi_brush_index_to_bgra(const librdp_session* session,
                                                uint8_t index,
                                                uint8_t* dst)
{
    const rdp_palette_update* palette = session && session->palette_valid ? &session->palette : NULL;

    if (palette && index < palette->count)
    {
        dst[0] = palette->entries[index].blue;
        dst[1] = palette->entries[index].green;
        dst[2] = palette->entries[index].red;
    }
    else
    {
        dst[0] = index;
        dst[1] = index;
        dst[2] = index;
    }
    dst[3] = 0xffu;
}

static librdp_status rdp_session_gdi_brush_read_color(const librdp_session* session,
                                                      uint32_t format,
                                                      const uint8_t* data,
                                                      size_t length,
                                                      uint8_t* dst,
                                                      size_t* consumed)
{
    uint32_t pixel = 0;

    if (!data || !dst || !consumed)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (format == RDP_GDI_BMF_8BPP)
    {
        if (length < 1u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        rdp_session_gdi_brush_index_to_bgra(session, data[0], dst);
        *consumed = 1;
        return LIBRDP_STATUS_OK;
    }
    if (format == RDP_GDI_BMF_16BPP)
    {
        if (length < 2u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        pixel = (uint32_t)data[0] | ((uint32_t)data[1] << 8u);
        dst[0] = rdp_session_gdi_scale_5_to_8((uint16_t)(pixel & 0x001fu));
        dst[1] = rdp_session_gdi_scale_6_to_8((uint16_t)((pixel >> 5u) & 0x003fu));
        dst[2] = rdp_session_gdi_scale_5_to_8((uint16_t)((pixel >> 11u) & 0x001fu));
        dst[3] = 0xffu;
        *consumed = 2;
        return LIBRDP_STATUS_OK;
    }
    if (format == RDP_GDI_BMF_24BPP)
    {
        if (length < 3u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        dst[0] = data[0];
        dst[1] = data[1];
        dst[2] = data[2];
        dst[3] = 0xffu;
        *consumed = 3;
        return LIBRDP_STATUS_OK;
    }
    if (format == RDP_GDI_BMF_32BPP)
    {
        if (length < 4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        dst[0] = data[0];
        dst[1] = data[1];
        dst[2] = data[2];
        dst[3] = 0xffu;
        *consumed = 4;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

static int rdp_session_gdi_brush_compressed(uint32_t format, uint32_t length)
{
    return (format == RDP_GDI_BMF_8BPP && length == 20u) ||
           (format == RDP_GDI_BMF_16BPP && length == 24u) ||
           (format == RDP_GDI_BMF_24BPP && length == 28u) ||
           (format == RDP_GDI_BMF_32BPP && length == 32u);
}

/*
 * Store a decoded GDI brush in the session cache. Cache index validation and
 * brush ownership transfer happen together so later orders never reference
 * transient order memory.
 */
static librdp_status rdp_session_gdi_store_cache_brush(librdp_session* session,
                                                       const rdp_gdi_cache_brush_order* order)
{
    rdp_session_gdi_brush_cache_entry* entry = NULL;
    uint32_t bits_per_pixel = 0;
    uint32_t bytes_per_pixel = 0;
    uint32_t i = 0;

    if (!session || !order || !order->brush_data ||
        order->cache_entry >= RDP_SESSION_GDI_BRUSH_CACHE_SLOTS ||
        order->width != 8u ||
        order->height != 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    bits_per_pixel = rdp_session_gdi_brush_bpp(order->bitmap_format);
    if (bits_per_pixel == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    entry = &session->gdi_brush_cache[order->cache_entry];
    memset(entry, 0, sizeof(*entry));
    entry->cache_entry = order->cache_entry;
    entry->bitmap_format = order->bitmap_format;
    if (bits_per_pixel == 1u)
    {
        if (order->brush_data_len != sizeof(entry->mono_rows))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        entry->mono = 1;
        for (i = 0; i < 8u; i++)
            entry->mono_rows[i] = order->brush_data[7u - i];
    }
    else if (rdp_session_gdi_brush_compressed(order->bitmap_format, order->brush_data_len))
    {
        uint8_t table[4u * 4u];
        size_t offset = 16u;
        uint32_t table_entry = 0;

        for (table_entry = 0; table_entry < 4u; table_entry++)
        {
            size_t consumed = 0;
            librdp_status status = rdp_session_gdi_brush_read_color(session,
                                                                    order->bitmap_format,
                                                                    order->brush_data + offset,
                                                                    order->brush_data_len - offset,
                                                                    table + table_entry * 4u,
                                                                    &consumed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            offset += consumed;
        }
        if (offset != order->brush_data_len)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (i = 0; i < 64u; i++)
        {
            uint8_t packed = order->brush_data[i / 4u];
            uint32_t table_index = (uint32_t)((packed >> ((3u - (i & 3u)) * 2u)) & 0x03u);

            memcpy(entry->bgra + ((size_t)i * 4u), table + table_index * 4u, 4u);
        }
    }
    else
    {
        size_t offset = 0;

        bytes_per_pixel = (bits_per_pixel + 7u) / 8u;
        if (order->brush_data_len != 64u * bytes_per_pixel)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (i = 0; i < 64u; i++)
        {
            size_t consumed = 0;
            librdp_status status = rdp_session_gdi_brush_read_color(session,
                                                                    order->bitmap_format,
                                                                    order->brush_data + offset,
                                                                    order->brush_data_len - offset,
                                                                    entry->bgra + ((size_t)i * 4u),
                                                                    &consumed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            offset += consumed;
        }
    }
    entry->active = 1;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.brush_cache.store",
                          "cache_entry=%u bitmap_format=%u mono=%u bytes=%u",
                          order->cache_entry,
                          order->bitmap_format,
                          entry->mono,
                          order->brush_data_len);
    return LIBRDP_STATUS_OK;
}

static rdp_session_gdi_bitmap_cache_entry* rdp_session_gdi_bitmap_cache_find(librdp_session* session,
                                                                             uint32_t cache_id,
                                                                             uint32_t cache_index)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_BITMAP_CACHE_SLOTS; i++)
    {
        rdp_session_gdi_bitmap_cache_entry* entry = &session->gdi_bitmap_cache[i];

        if (entry->active && entry->cache_id == cache_id && entry->cache_index == cache_index)
        {
            entry->last_used = ++session->gdi_bitmap_cache_clock;
            return entry;
        }
    }
    return NULL;
}

static size_t rdp_session_gdi_bitmap_cache_lru(librdp_session* session,
                                               const rdp_session_gdi_bitmap_cache_entry* skip)
{
    size_t i = 0;
    size_t candidate = RDP_SESSION_GDI_BITMAP_CACHE_SLOTS;
    uint64_t oldest = UINT64_MAX;

    if (!session)
        return candidate;
    for (i = 0; i < RDP_SESSION_GDI_BITMAP_CACHE_SLOTS; i++)
    {
        rdp_session_gdi_bitmap_cache_entry* entry = &session->gdi_bitmap_cache[i];

        if (!entry->active || entry == skip)
            continue;
        if (entry->last_used < oldest)
        {
            oldest = entry->last_used;
            candidate = i;
        }
    }
    return candidate;
}

static rdp_session_gdi_bitmap_cache_entry* rdp_session_gdi_bitmap_cache_slot(librdp_session* session,
                                                                             uint32_t cache_id,
                                                                             uint32_t cache_index)
{
    size_t i = 0;
    rdp_session_gdi_bitmap_cache_entry* entry = rdp_session_gdi_bitmap_cache_find(session, cache_id, cache_index);

    if (entry)
        return entry;
    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_BITMAP_CACHE_SLOTS; i++)
    {
        if (!session->gdi_bitmap_cache[i].active)
            return &session->gdi_bitmap_cache[i];
    }
    i = rdp_session_gdi_bitmap_cache_lru(session, NULL);
    if (i >= RDP_SESSION_GDI_BITMAP_CACHE_SLOTS)
        return NULL;
    rdp_session_gdi_bitmap_cache_evict(session, i);
    return &session->gdi_bitmap_cache[i];
}

static void rdp_session_gdi_saved_bitmap_evict(librdp_session* session, size_t index)
{
    rdp_session_gdi_saved_bitmap* entry = NULL;

    if (!session || index >= RDP_SESSION_GDI_SAVE_BITMAP_SLOTS)
        return;
    entry = &session->gdi_saved_bitmaps[index];
    if (entry->active)
    {
        if (session->gdi_saved_bitmap_bytes >= entry->pixels.length)
            session->gdi_saved_bitmap_bytes -= entry->pixels.length;
        else
            session->gdi_saved_bitmap_bytes = 0;
    }
    rdp_buffer_free(&entry->pixels);
    memset(entry, 0, sizeof(*entry));
}

void rdp_session_gdi_saved_bitmaps_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_GDI_SAVE_BITMAP_SLOTS; i++)
        rdp_buffer_free(&session->gdi_saved_bitmaps[i].pixels);
    memset(session->gdi_saved_bitmaps, 0, sizeof(session->gdi_saved_bitmaps));
    session->gdi_saved_bitmap_bytes = 0;
}

static rdp_session_gdi_saved_bitmap* rdp_session_gdi_saved_bitmap_find(librdp_session* session,
                                                                       uint32_t bitmap_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_SAVE_BITMAP_SLOTS; i++)
    {
        rdp_session_gdi_saved_bitmap* entry = &session->gdi_saved_bitmaps[i];

        if (entry->active && entry->bitmap_id == bitmap_id)
            return entry;
    }
    return NULL;
}

static rdp_session_gdi_saved_bitmap* rdp_session_gdi_saved_bitmap_slot(librdp_session* session,
                                                                       uint32_t bitmap_id)
{
    size_t i = 0;
    rdp_session_gdi_saved_bitmap* entry = rdp_session_gdi_saved_bitmap_find(session, bitmap_id);

    if (entry)
        return entry;
    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_SAVE_BITMAP_SLOTS; i++)
    {
        if (!session->gdi_saved_bitmaps[i].active)
            return &session->gdi_saved_bitmaps[i];
    }
    i = (size_t)(bitmap_id % RDP_SESSION_GDI_SAVE_BITMAP_SLOTS);
    rdp_session_gdi_saved_bitmap_evict(session, i);
    return &session->gdi_saved_bitmaps[i];
}

static rdp_session_gdi_offscreen_bitmap* rdp_session_gdi_offscreen_find(librdp_session* session,
                                                                        uint32_t bitmap_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_OFFSCREEN_CACHE_SLOTS; i++)
    {
        rdp_session_gdi_offscreen_bitmap* entry = &session->gdi_offscreen_cache[i];

        if (entry->active && entry->bitmap_id == bitmap_id)
            return entry;
    }
    return NULL;
}

static void rdp_session_gdi_offscreen_delete(librdp_session* session, uint32_t bitmap_id)
{
    rdp_session_gdi_offscreen_bitmap* entry = rdp_session_gdi_offscreen_find(session, bitmap_id);

    if (!session || !entry)
        return;
    librdp_surface_free(entry->surface);
    memset(entry, 0, sizeof(*entry));
    if (session->gdi_current_surface_id == bitmap_id)
        session->gdi_current_surface_id = RDP_SESSION_GDI_SCREEN_BITMAP_SURFACE;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.offscreen.delete",
                          "surface_id=%u",
                          bitmap_id);
}

void rdp_session_gdi_offscreen_cache_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_GDI_OFFSCREEN_CACHE_SLOTS; i++)
        librdp_surface_free(session->gdi_offscreen_cache[i].surface);
    memset(session->gdi_offscreen_cache, 0, sizeof(session->gdi_offscreen_cache));
    session->gdi_current_surface_id = RDP_SESSION_GDI_SCREEN_BITMAP_SURFACE;
    session->gdi_drawing_to_offscreen = 0;
}

static rdp_session_gdi_offscreen_bitmap* rdp_session_gdi_offscreen_slot(librdp_session* session,
                                                                       uint32_t bitmap_id)
{
    size_t i = 0;
    rdp_session_gdi_offscreen_bitmap* entry = rdp_session_gdi_offscreen_find(session, bitmap_id);

    if (entry)
        return entry;
    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_OFFSCREEN_CACHE_SLOTS; i++)
    {
        if (!session->gdi_offscreen_cache[i].active)
            return &session->gdi_offscreen_cache[i];
    }
    i = (size_t)(bitmap_id % RDP_SESSION_GDI_OFFSCREEN_CACHE_SLOTS);
    librdp_surface_free(session->gdi_offscreen_cache[i].surface);
    memset(&session->gdi_offscreen_cache[i], 0, sizeof(session->gdi_offscreen_cache[i]));
    return &session->gdi_offscreen_cache[i];
}

static librdp_status rdp_session_gdi_create_offscreen_bitmap(
    librdp_session* session,
    const rdp_gdi_create_offscreen_bitmap_order* order)
{
    rdp_session_gdi_offscreen_bitmap* entry = NULL;
    librdp_surface* surface = NULL;
    uint32_t i = 0;

    if (!session || !order || order->bitmap_id > 0x7fffu ||
        order->width == 0 || order->height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < order->delete_count; i++)
        rdp_session_gdi_offscreen_delete(session, order->delete_indices[i]);
    entry = rdp_session_gdi_offscreen_slot(session, order->bitmap_id);
    if (!entry)
        return LIBRDP_STATUS_NO_MEMORY;
    surface = librdp_surface_new(order->width, order->height, LIBRDP_PIXEL_FORMAT_BGRA32);
    if (!surface)
        return LIBRDP_STATUS_NO_MEMORY;
    librdp_surface_free(entry->surface);
    memset(entry, 0, sizeof(*entry));
    entry->active = 1;
    entry->bitmap_id = order->bitmap_id;
    entry->surface = surface;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.offscreen.create",
                          "surface_id=%u width=%u height=%u delete_count=%u",
                          order->bitmap_id,
                          order->width,
                          order->height,
                          order->delete_count);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_switch_surface(librdp_session* session, uint32_t bitmap_id)
{
    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (bitmap_id == RDP_SESSION_GDI_SCREEN_BITMAP_SURFACE)
    {
        session->gdi_current_surface_id = RDP_SESSION_GDI_SCREEN_BITMAP_SURFACE;
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.surface.switch",
                              "surface_id=%u primary=1",
                              bitmap_id);
        return LIBRDP_STATUS_OK;
    }
    if (!rdp_session_gdi_offscreen_find(session, bitmap_id))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    session->gdi_current_surface_id = bitmap_id;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.surface.switch",
                          "surface_id=%u primary=0",
                          bitmap_id);
    return LIBRDP_STATUS_OK;
}

static librdp_surface* rdp_session_gdi_target_surface(librdp_session* session)
{
    rdp_session_gdi_offscreen_bitmap* entry = NULL;

    if (!session)
        return NULL;
    if (session->gdi_current_surface_id == RDP_SESSION_GDI_SCREEN_BITMAP_SURFACE)
        return session->surface;
    entry = rdp_session_gdi_offscreen_find(session, session->gdi_current_surface_id);
    return entry ? entry->surface : NULL;
}

void rdp_session_gdi_stream_bitmap_reset(librdp_session* session)
{
    if (!session)
        return;
    rdp_buffer_free(&session->gdi_stream_bitmap.bitmap_data);
    memset(&session->gdi_stream_bitmap, 0, sizeof(session->gdi_stream_bitmap));
}

static librdp_status rdp_session_gdi_stream_bitmap_blit(librdp_session* session)
{
    rdp_bitmap_rect rect;
    rdp_buffer pixels;
    librdp_surface* target = NULL;
    size_t stride = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t to_offscreen = 0;

    if (!session || !session->gdi_stream_bitmap.bitmap_data.data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->gdi_stream_bitmap.bitmap_data.length != session->gdi_stream_bitmap.bitmap_size)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    target = rdp_session_gdi_target_surface(session);
    if (!target ||
        session->gdi_stream_bitmap.width > librdp_surface_width(target) ||
        session->gdi_stream_bitmap.height > librdp_surface_height(target))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&rect, 0, sizeof(rect));
    rect.dest_left = 0;
    rect.dest_top = 0;
    rect.dest_right = (uint16_t)(session->gdi_stream_bitmap.width - 1u);
    rect.dest_bottom = (uint16_t)(session->gdi_stream_bitmap.height - 1u);
    rect.width = (uint16_t)session->gdi_stream_bitmap.width;
    rect.height = (uint16_t)session->gdi_stream_bitmap.height;
    rect.bits_per_pixel = (uint16_t)session->gdi_stream_bitmap.bits_per_pixel;
    rect.flags = (session->gdi_stream_bitmap.flags & RDP_GDI_STREAM_BITMAP_COMPRESSED) != 0 ?
                 RDP_SESSION_BITMAP_FLAG_COMPRESSED : 0;
    rect.data = session->gdi_stream_bitmap.bitmap_data.data;
    rect.data_len = (uint32_t)session->gdi_stream_bitmap.bitmap_data.length;

    rdp_buffer_init(&pixels);
    status = rdp_bitmap_decode_rect_bgra32_with_palette(&rect,
                                                        session->palette_valid ? &session->palette : NULL,
                                                        &pixels,
                                                        &stride);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_surface_blit_bgra32(target,
                                            0,
                                            0,
                                            session->gdi_stream_bitmap.width,
                                            session->gdi_stream_bitmap.height,
                                            pixels.data,
                                            stride);
    if (status == LIBRDP_STATUS_OK)
    {
        to_offscreen = target != session->surface;
        if (to_offscreen)
        {
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_TRACE,
                                  "client.gdi.stream_bitmap.offscreen_blit",
                                  "surface_id=%u width=%u height=%u bpp=%u compressed=%u",
                                  session->gdi_current_surface_id,
                                  session->gdi_stream_bitmap.width,
                                  session->gdi_stream_bitmap.height,
                                  session->gdi_stream_bitmap.bits_per_pixel,
                                  (session->gdi_stream_bitmap.flags & RDP_GDI_STREAM_BITMAP_COMPRESSED) != 0 ? 1u : 0u);
        }
        else
        {
            rdp_session_emit_surface_invalidated(session,
                                                 0,
                                                 0,
                                                 session->gdi_stream_bitmap.width,
                                                 session->gdi_stream_bitmap.height);
        }
    }
    rdp_buffer_free(&pixels);
    return status;
}

static librdp_status rdp_session_gdi_stream_bitmap_finish_if_needed(librdp_session* session, uint32_t flags)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((flags & RDP_GDI_STREAM_BITMAP_END) == 0)
        return LIBRDP_STATUS_OK;
    status = rdp_session_gdi_stream_bitmap_blit(session);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          status == LIBRDP_STATUS_OK ? RDP_TRACE_LEVEL_DEBUG : RDP_TRACE_LEVEL_INFO,
                          status == LIBRDP_STATUS_OK ? "client.gdi.stream_bitmap.done" :
                                                        "client.gdi.stream_bitmap.failed",
                          "status=%d surface_id=%u width=%u height=%u bpp=%u received=%u expected=%u flags=%u type=%u",
                          (int)status,
                          session->gdi_current_surface_id,
                          session->gdi_stream_bitmap.width,
                          session->gdi_stream_bitmap.height,
                          session->gdi_stream_bitmap.bits_per_pixel,
                          (unsigned)session->gdi_stream_bitmap.bitmap_data.length,
                          session->gdi_stream_bitmap.bitmap_size,
                          session->gdi_stream_bitmap.flags,
                          session->gdi_stream_bitmap.bitmap_type);
    rdp_session_gdi_stream_bitmap_reset(session);
    return status;
}

static librdp_status rdp_session_gdi_stream_bitmap_first(
    librdp_session* session,
    const rdp_gdi_stream_bitmap_first_order* order)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !order || !order->bitmap_block)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (order->width == 0 || order->height == 0 ||
        order->width > UINT16_MAX || order->height > UINT16_MAX ||
        order->bits_per_pixel == 0 || order->bits_per_pixel > UINT16_MAX ||
        order->bitmap_size == 0 || order->bitmap_block_len > order->bitmap_size)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_session_gdi_stream_bitmap_reset(session);
    session->gdi_stream_bitmap.active = 1;
    session->gdi_stream_bitmap.flags = order->flags;
    session->gdi_stream_bitmap.bits_per_pixel = order->bits_per_pixel;
    session->gdi_stream_bitmap.bitmap_type = order->bitmap_type;
    session->gdi_stream_bitmap.width = order->width;
    session->gdi_stream_bitmap.height = order->height;
    session->gdi_stream_bitmap.bitmap_size = order->bitmap_size;
    status = rdp_buffer_reserve(&session->gdi_stream_bitmap.bitmap_data, order->bitmap_size);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&session->gdi_stream_bitmap.bitmap_data,
                                   order->bitmap_block,
                                   order->bitmap_block_len);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_session_gdi_stream_bitmap_reset(session);
        return status;
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.stream_bitmap.first",
                          "surface_id=%u width=%u height=%u bpp=%u received=%u expected=%u flags=%u type=%u",
                          session->gdi_current_surface_id,
                          order->width,
                          order->height,
                          order->bits_per_pixel,
                          order->bitmap_block_len,
                          order->bitmap_size,
                          order->flags,
                          order->bitmap_type);
    return rdp_session_gdi_stream_bitmap_finish_if_needed(session, order->flags);
}

static librdp_status rdp_session_gdi_stream_bitmap_next(
    librdp_session* session,
    const rdp_gdi_stream_bitmap_next_order* order)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !order || (!order->bitmap_block && order->bitmap_block_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!session->gdi_stream_bitmap.active ||
        order->bitmap_type != session->gdi_stream_bitmap.bitmap_type ||
        order->bitmap_block_len > session->gdi_stream_bitmap.bitmap_size ||
        session->gdi_stream_bitmap.bitmap_data.length >
            session->gdi_stream_bitmap.bitmap_size - order->bitmap_block_len)
    {
        rdp_session_gdi_stream_bitmap_reset(session);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    status = rdp_buffer_append(&session->gdi_stream_bitmap.bitmap_data,
                               order->bitmap_block,
                               order->bitmap_block_len);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_session_gdi_stream_bitmap_reset(session);
        return status;
    }
    session->gdi_stream_bitmap.flags = order->flags;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.gdi.stream_bitmap.next",
                          "surface_id=%u received=%u expected=%u block_len=%u flags=%u type=%u",
                          session->gdi_current_surface_id,
                          (unsigned)session->gdi_stream_bitmap.bitmap_data.length,
                          session->gdi_stream_bitmap.bitmap_size,
                          order->bitmap_block_len,
                          order->flags,
                          order->bitmap_type);
    return rdp_session_gdi_stream_bitmap_finish_if_needed(session, order->flags);
}


static librdp_status rdp_session_blit_bgra32_flipped(librdp_session* session,
                                                     uint32_t x,
                                                     uint32_t y,
                                                     uint32_t width,
                                                     uint32_t height,
                                                     const uint8_t* pixels,
                                                     size_t stride)
{
    rdp_buffer flipped;
    size_t output_stride = 0;
    size_t output_size = 0;
    uint32_t row = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !pixels)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_OK;
    if (stride < (size_t)width * 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    output_stride = (size_t)width * 4u;
    if ((size_t)height > ((size_t)-1) / output_stride)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    output_size = (size_t)height * output_stride;
    rdp_buffer_init(&flipped);
    status = rdp_buffer_reserve(&flipped, output_size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    flipped.length = output_size;
    for (row = 0; row < height; row++)
    {
        const uint8_t* src = pixels + ((size_t)(height - 1u - row) * stride);
        uint8_t* dst = flipped.data + ((size_t)row * output_stride);

        memcpy(dst, src, output_stride);
    }
    status = librdp_surface_blit_bgra32(session->surface,
                                        x,
                                        y,
                                        width,
                                        height,
                                        flipped.data,
                                        output_stride);
    rdp_buffer_free(&flipped);
    return status;
}


static librdp_status rdp_session_apply_surface_bits_raw(librdp_session* session,
                                                        const rdp_surface_bits* bits)
{
    rdp_bitmap_rect rect;
    rdp_buffer pixels;
    size_t stride = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !bits)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&rect, 0, sizeof(rect));
    rect.dest_left = bits->dest_left;
    rect.dest_top = bits->dest_top;
    rect.dest_right = bits->dest_right;
    rect.dest_bottom = bits->dest_bottom;
    rect.width = bits->width;
    rect.height = bits->height;
    rect.bits_per_pixel = bits->bpp;
    rect.flags = 0;
    rect.data = bits->bitmap_data;
    rect.data_len = bits->bitmap_data_length;
    rdp_buffer_init(&pixels);
    status = rdp_bitmap_decode_rect_bgra32_with_palette(&rect,
                                                        session->palette_valid ? &session->palette : NULL,
                                                        &pixels,
                                                        &stride);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_surface_blit_bgra32(session->surface,
                                            bits->dest_left,
                                            bits->dest_top,
                                            bits->width,
                                            bits->height,
                                            pixels.data,
                                            stride);
    rdp_buffer_free(&pixels);
    return status;
}

static librdp_status rdp_session_apply_surface_bits_nscodec(librdp_session* session,
                                                            const rdp_surface_bits* bits)
{
    rdp_buffer pixels;
    size_t stride = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !bits)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&pixels);
    status = rdp_nscodec_decode_bgra32(&session->surface_nscodec,
                                       bits->bitmap_data,
                                       bits->bitmap_data_length,
                                       bits->width,
                                       bits->height,
                                       &pixels,
                                       &stride);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_blit_bgra32_flipped(session,
                                                 bits->dest_left,
                                                 bits->dest_top,
                                                 bits->width,
                                                 bits->height,
                                                 pixels.data,
                                                 stride);
    rdp_buffer_free(&pixels);
    return status;
}

typedef struct rdp_session_rfx_surface_context
{
    librdp_session* session;
    const rdp_surface_bits* bits;
    uint16_t tiles;
} rdp_session_rfx_surface_context;

static librdp_status rdp_session_rfx_surface_tile(const rdp_rfx_stream_tile* tile, void* user)
{
    rdp_session_rfx_surface_context* context = (rdp_session_rfx_surface_context*)user;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t dest_x = 0;
    uint32_t dest_y = 0;

    if (!tile || !context || !context->session || !context->bits)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (tile->x >= context->bits->width || tile->y >= context->bits->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    width = tile->width;
    height = tile->height;
    if (width > context->bits->width - tile->x)
        width = context->bits->width - tile->x;
    if (height > context->bits->height - tile->y)
        height = context->bits->height - tile->y;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    dest_x = (uint32_t)context->bits->dest_left + tile->x;
    dest_y = (uint32_t)context->bits->dest_top + tile->y;
    if (dest_x > librdp_surface_width(context->session->surface) ||
        dest_y > librdp_surface_height(context->session->surface) ||
        width > librdp_surface_width(context->session->surface) - dest_x ||
        height > librdp_surface_height(context->session->surface) - dest_y)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (context->tiles < UINT16_MAX)
        context->tiles++;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.surface.rfx.tile",
                          "x=%u y=%u width=%u height=%u tile_x=%u tile_y=%u",
                          dest_x,
                          dest_y,
                          width,
                          height,
                          tile->x_idx,
                          tile->y_idx);
    return librdp_surface_blit_bgra32(context->session->surface,
                                      dest_x,
                                      dest_y,
                                      width,
                                      height,
                                      tile->pixels.bgra,
                                      tile->pixels.stride);
}

static librdp_status rdp_session_apply_surface_bits_rfx(librdp_session* session,
                                                        const rdp_surface_bits* bits)
{
    rdp_session_rfx_surface_context context;
    rdp_rfx_stream_summary summary;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !bits)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&context, 0, sizeof(context));
    memset(&summary, 0, sizeof(summary));
    context.session = session;
    context.bits = bits;
    status = rdp_rfx_stream_decode(bits->bitmap_data,
                                   bits->bitmap_data_length,
                                   rdp_session_rfx_surface_tile,
                                   &context,
                                   &summary);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.surface.rfx.blit",
                        "frame_id=%u width=%u height=%u tiles=%u rects=%u blitted=%u",
                        summary.frame_id,
                        summary.width,
                        summary.height,
                        summary.tile_count,
                        summary.rect_count,
                        context.tiles);
    return status;
}

static librdp_status rdp_session_apply_surface_bits(librdp_session* session,
                                                    const rdp_surface_bits* bits)
{
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;
    uint32_t dest_width = 0;
    uint32_t dest_height = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !bits)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    surface_width = librdp_surface_width(session->surface);
    surface_height = librdp_surface_height(session->surface);
    if (bits->dest_right > surface_width || bits->dest_bottom > surface_height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    dest_width = (uint32_t)(bits->dest_right - bits->dest_left);
    dest_height = (uint32_t)(bits->dest_bottom - bits->dest_top);
    if (dest_width == 0 || dest_height == 0 || bits->width != dest_width || bits->height != dest_height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (bits->codec_id == RDP_SURFACE_CODEC_NONE)
        status = rdp_session_apply_surface_bits_raw(session, bits);
    else if (bits->codec_id == RDP_SURFACE_CODEC_NSCODEC)
        status = rdp_session_apply_surface_bits_nscodec(session, bits);
    else if (bits->codec_id == RDP_SURFACE_CODEC_REMOTEFX ||
             bits->codec_id == RDP_SURFACE_CODEC_IMAGE_REMOTEFX)
        status = rdp_session_apply_surface_bits_rfx(session, bits);
    else
        status = LIBRDP_STATUS_UNSUPPORTED;

    if (status == LIBRDP_STATUS_OK)
    {
        rdp_session_emit_surface_invalidated(session,
                                             bits->dest_left,
                                             bits->dest_top,
                                             bits->width,
                                             bits->height);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.surface.bits.blit",
                        "codec_id=%u x=%u y=%u width=%u height=%u bpp=%u command_type=%u",
                        bits->codec_id,
                        bits->dest_left,
                        bits->dest_top,
                        bits->width,
                        bits->height,
                        bits->bpp,
                        bits->command_type);
    }
    return status;
}

librdp_status rdp_session_apply_surface_commands(librdp_session* session,
                                                        const rdp_surface_command_list* list)
{
    uint16_t i = 0;

    if (!session || !list)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < list->count; i++)
    {
        const rdp_surface_command* command = &list->commands[i];
        librdp_status status = LIBRDP_STATUS_OK;

        if (command->kind == RDP_SURFACE_COMMAND_KIND_FRAME_MARKER)
        {
            if (command->frame_marker.action == 0u)
                rdp_session_emit_graphics_frame(session,
                                                LIBRDP_GRAPHICS_UPDATE_FRAME_BEGIN,
                                                command->frame_marker.has_frame_id ?
                                                    command->frame_marker.frame_id :
                                                    session->graphics_current_frame_id);
            else if (command->frame_marker.action == 1u)
                rdp_session_emit_graphics_frame(session,
                                                LIBRDP_GRAPHICS_UPDATE_FRAME_END,
                                                command->frame_marker.has_frame_id ?
                                                    command->frame_marker.frame_id :
                                                    session->graphics_current_frame_id);
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.surface.frame_marker",
                                  "action=%u frame_id=%u has_frame_id=%u",
                                  command->frame_marker.action,
                                  command->frame_marker.frame_id,
                                  command->frame_marker.has_frame_id);
            continue;
        }
        if (command->kind != RDP_SURFACE_COMMAND_KIND_BITS)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        status = rdp_session_apply_surface_bits(session, &command->bits);
        if (status == LIBRDP_STATUS_UNSUPPORTED)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.surface.bits.rejected",
                            "codec_id=%u command_type=%u width=%u height=%u payload_len=%u",
                            command->bits.codec_id,
                            command->bits.command_type,
                            command->bits.width,
                            command->bits.height,
                            command->bits.bitmap_data_length);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

void rdp_session_palette_reset(librdp_session* session)
{
    if (!session)
        return;
    session->palette_valid = 0;
    memset(&session->palette, 0, sizeof(session->palette));
}

librdp_status rdp_session_apply_palette_update(librdp_session* session, const rdp_palette_update* palette)
{
    if (!session || !palette || palette->count > RDP_BITMAP_PALETTE_MAX_ENTRIES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    session->palette = *palette;
    session->palette_valid = 1;
    rdp_trace_event(RDP_TRACE_CLIENT, "client.graphics.palette.update", "colors=%u", palette->count);
    return LIBRDP_STATUS_OK;
}

typedef struct rdp_session_gdi_region
{
    uint32_t dst_x;
    uint32_t dst_y;
    uint32_t src_x;
    uint32_t src_y;
    uint32_t width;
    uint32_t height;
} rdp_session_gdi_region;

static uint8_t rdp_session_gdi_rop3(uint8_t rop, uint8_t source, uint8_t pattern, uint8_t dest)
{
    uint8_t result = 0;
    uint8_t bit = 0;

    for (bit = 0; bit < 8u; bit++)
    {
        uint8_t index = (uint8_t)((((pattern >> bit) & 1u) << 2u) |
                                  (((source >> bit) & 1u) << 1u) |
                                  ((dest >> bit) & 1u));

        if ((rop >> index) & 1u)
            result |= (uint8_t)(1u << bit);
    }
    return result;
}

static int rdp_session_gdi_clip_dest(const rdp_gdi_render_op* op,
                                     uint32_t surface_width,
                                     uint32_t surface_height,
                                     rdp_session_gdi_region* region)
{
    int64_t left = 0;
    int64_t top = 0;
    int64_t right = 0;
    int64_t bottom = 0;
    int64_t clip_left = 0;
    int64_t clip_top = 0;
    int64_t clip_right = surface_width;
    int64_t clip_bottom = surface_height;

    if (!op || !region || op->rect.width <= 0 || op->rect.height <= 0 || surface_width == 0 || surface_height == 0)
        return 0;
    left = op->rect.x;
    top = op->rect.y;
    right = (int64_t)op->rect.x + op->rect.width;
    bottom = (int64_t)op->rect.y + op->rect.height;
    if (op->bounds.present)
    {
        clip_left = op->bounds.left;
        clip_top = op->bounds.top;
        clip_right = (int64_t)op->bounds.right + 1;
        clip_bottom = (int64_t)op->bounds.bottom + 1;
    }
    if (clip_left < 0)
        clip_left = 0;
    if (clip_top < 0)
        clip_top = 0;
    if (clip_right > (int64_t)surface_width)
        clip_right = surface_width;
    if (clip_bottom > (int64_t)surface_height)
        clip_bottom = surface_height;
    if (left < clip_left)
        left = clip_left;
    if (top < clip_top)
        top = clip_top;
    if (right > clip_right)
        right = clip_right;
    if (bottom > clip_bottom)
        bottom = clip_bottom;
    if (left >= right || top >= bottom)
        return 0;
    region->dst_x = (uint32_t)left;
    region->dst_y = (uint32_t)top;
    region->width = (uint32_t)(right - left);
    region->height = (uint32_t)(bottom - top);
    region->src_x = 0;
    region->src_y = 0;
    return 1;
}

static int rdp_session_gdi_clip_copy(const rdp_gdi_render_op* op,
                                     uint32_t surface_width,
                                     uint32_t surface_height,
                                     rdp_session_gdi_region* region)
{
    int64_t src_x = 0;
    int64_t src_y = 0;
    int64_t shift = 0;

    if (!rdp_session_gdi_clip_dest(op, surface_width, surface_height, region))
        return 0;
    src_x = (int64_t)op->src_x + ((int64_t)region->dst_x - op->rect.x);
    src_y = (int64_t)op->src_y + ((int64_t)region->dst_y - op->rect.y);
    if (src_x < 0)
    {
        shift = -src_x;
        if (shift >= (int64_t)region->width)
            return 0;
        region->dst_x += (uint32_t)shift;
        region->width -= (uint32_t)shift;
        src_x = 0;
    }
    if (src_y < 0)
    {
        shift = -src_y;
        if (shift >= (int64_t)region->height)
            return 0;
        region->dst_y += (uint32_t)shift;
        region->height -= (uint32_t)shift;
        src_y = 0;
    }
    if (src_x >= (int64_t)surface_width || src_y >= (int64_t)surface_height)
        return 0;
    if (region->width > surface_width - (uint32_t)src_x)
        region->width = surface_width - (uint32_t)src_x;
    if (region->height > surface_height - (uint32_t)src_y)
        region->height = surface_height - (uint32_t)src_y;
    if (region->width == 0 || region->height == 0)
        return 0;
    region->src_x = (uint32_t)src_x;
    region->src_y = (uint32_t)src_y;
    return 1;
}

static int rdp_session_gdi_clip_bitmap_copy(const rdp_gdi_render_op* op,
                                            uint32_t surface_width,
                                            uint32_t surface_height,
                                            uint32_t source_width,
                                            uint32_t source_height,
                                            rdp_session_gdi_region* region)
{
    int64_t src_x = 0;
    int64_t src_y = 0;
    int64_t shift = 0;

    if (!rdp_session_gdi_clip_dest(op, surface_width, surface_height, region) ||
        source_width == 0 || source_height == 0)
        return 0;
    src_x = (int64_t)op->src_x + ((int64_t)region->dst_x - op->rect.x);
    src_y = (int64_t)op->src_y + ((int64_t)region->dst_y - op->rect.y);
    if (src_x < 0)
    {
        shift = -src_x;
        if (shift >= (int64_t)region->width)
            return 0;
        region->dst_x += (uint32_t)shift;
        region->width -= (uint32_t)shift;
        src_x = 0;
    }
    if (src_y < 0)
    {
        shift = -src_y;
        if (shift >= (int64_t)region->height)
            return 0;
        region->dst_y += (uint32_t)shift;
        region->height -= (uint32_t)shift;
        src_y = 0;
    }
    if (src_x >= (int64_t)source_width || src_y >= (int64_t)source_height)
        return 0;
    if (region->width > source_width - (uint32_t)src_x)
        region->width = source_width - (uint32_t)src_x;
    if (region->height > source_height - (uint32_t)src_y)
        region->height = source_height - (uint32_t)src_y;
    if (region->width == 0 || region->height == 0)
        return 0;
    region->src_x = (uint32_t)src_x;
    region->src_y = (uint32_t)src_y;
    return 1;
}

static librdp_status rdp_session_gdi_save_bitmap(librdp_session* session,
                                                 const rdp_gdi_render_op* op,
                                                 const rdp_session_gdi_region* region)
{
    rdp_session_gdi_saved_bitmap* entry = NULL;
    uint8_t* pixels = NULL;
    size_t stride = 0;
    size_t row_bytes = 0;
    size_t size = 0;
    size_t old_size = 0;
    size_t current_without_old = 0;
    uint32_t y = 0;
    uint32_t origin_x = 0;
    uint32_t origin_y = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !op || !region)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (region->width == 0 || region->height == 0)
        return LIBRDP_STATUS_OK;
    row_bytes = (size_t)region->width * 4u;
    if ((size_t)region->height > ((size_t)-1) / row_bytes)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    size = row_bytes * (size_t)region->height;

    entry = rdp_session_gdi_saved_bitmap_slot(session, op->bitmap_id);
    if (!entry)
        return LIBRDP_STATUS_NO_MEMORY;
    old_size = entry->active ? entry->pixels.length : 0;
    current_without_old = session->gdi_saved_bitmap_bytes >= old_size ?
                          session->gdi_saved_bitmap_bytes - old_size :
                          0;
    if (size > RDP_SESSION_GDI_SAVE_BITMAP_MAX_BYTES ||
        current_without_old > RDP_SESSION_GDI_SAVE_BITMAP_MAX_BYTES - size)
        return LIBRDP_STATUS_NO_MEMORY;

    status = rdp_buffer_reserve(&entry->pixels, size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    if (!pixels || stride == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (y = 0; y < region->height; y++)
    {
        const uint8_t* src = pixels + ((size_t)(region->dst_y + y) * stride) +
                             ((size_t)region->dst_x * 4u);
        uint8_t* dst = entry->pixels.data + ((size_t)y * row_bytes);

        memcpy(dst, src, row_bytes);
    }
    origin_x = (uint32_t)((int64_t)region->dst_x - op->rect.x);
    origin_y = (uint32_t)((int64_t)region->dst_y - op->rect.y);
    entry->pixels.length = size;
    entry->active = 1;
    entry->bitmap_id = op->bitmap_id;
    entry->width = region->width;
    entry->height = region->height;
    entry->origin_x = origin_x;
    entry->origin_y = origin_y;
    session->gdi_saved_bitmap_bytes = current_without_old + size;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.save_bitmap.store",
                          "id=%u x=%u y=%u width=%u height=%u bytes=%u total_bytes=%u",
                          op->bitmap_id,
                          region->dst_x,
                          region->dst_y,
                          region->width,
                          region->height,
                          (unsigned)size,
                          (unsigned)session->gdi_saved_bitmap_bytes);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_restore_bitmap(librdp_session* session,
                                                    const rdp_gdi_render_op* op,
                                                    const rdp_session_gdi_region* region)
{
    rdp_session_gdi_saved_bitmap* entry = NULL;
    uint8_t* pixels = NULL;
    size_t stride = 0;
    size_t row_bytes = 0;
    uint32_t src_x = 0;
    uint32_t src_y = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t y = 0;

    if (!session || !op || !region)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    entry = rdp_session_gdi_saved_bitmap_find(session, op->bitmap_id);
    if (!entry || !entry->active)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.save_bitmap.miss",
                              "id=%u x=%u y=%u width=%u height=%u",
                              op->bitmap_id,
                              region->dst_x,
                              region->dst_y,
                              region->width,
                              region->height);
        return LIBRDP_STATUS_OK;
    }
    if ((int64_t)region->dst_x - op->rect.x < (int64_t)entry->origin_x ||
        (int64_t)region->dst_y - op->rect.y < (int64_t)entry->origin_y)
        return LIBRDP_STATUS_OK;
    src_x = (uint32_t)((int64_t)region->dst_x - op->rect.x - entry->origin_x);
    src_y = (uint32_t)((int64_t)region->dst_y - op->rect.y - entry->origin_y);
    if (src_x >= entry->width || src_y >= entry->height)
        return LIBRDP_STATUS_OK;
    width = region->width;
    height = region->height;
    if (width > entry->width - src_x)
        width = entry->width - src_x;
    if (height > entry->height - src_y)
        height = entry->height - src_y;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_OK;
    pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    if (!pixels || stride == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    row_bytes = (size_t)width * 4u;
    for (y = 0; y < height; y++)
    {
        const uint8_t* src = entry->pixels.data + (((size_t)(src_y + y) * entry->width) + src_x) * 4u;
        uint8_t* dst = pixels + ((size_t)(region->dst_y + y) * stride) +
                       ((size_t)region->dst_x * 4u);

        memcpy(dst, src, row_bytes);
    }
    rdp_session_emit_surface_invalidated(session, region->dst_x, region->dst_y, width, height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.save_bitmap.restore",
                          "id=%u x=%u y=%u width=%u height=%u",
                          op->bitmap_id,
                          region->dst_x,
                          region->dst_y,
                          width,
                          height);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_fill_rect(librdp_session* session,
                                               const rdp_gdi_render_op* op,
                                               const rdp_session_gdi_region* region,
                                               uint8_t rop,
                                               uint32_t color,
                                               int use_rop)
{
    uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t y = 0;
    uint8_t b = (uint8_t)(color & 0xffu);
    uint8_t g = (uint8_t)((color >> 8u) & 0xffu);
    uint8_t r = (uint8_t)((color >> 16u) & 0xffu);

    if (!session || !op || !region)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    if (!pixels || stride == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (y = 0; y < region->height; y++)
    {
        uint8_t* pixel = pixels + ((size_t)(region->dst_y + y) * stride) + ((size_t)region->dst_x * 4u);
        uint32_t x = 0;

        for (x = 0; x < region->width; x++)
        {
            if (use_rop)
            {
                pixel[0] = rdp_session_gdi_rop3(rop, 0, b, pixel[0]);
                pixel[1] = rdp_session_gdi_rop3(rop, 0, g, pixel[1]);
                pixel[2] = rdp_session_gdi_rop3(rop, 0, r, pixel[2]);
            }
            else
            {
                pixel[0] = b;
                pixel[1] = g;
                pixel[2] = r;
            }
            pixel[3] = 0xffu;
            pixel += 4u;
        }
    }
    rdp_session_emit_surface_invalidated(session, region->dst_x, region->dst_y, region->width, region->height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.order.apply",
                          "type=%u kind=%u x=%u y=%u width=%u height=%u rop=%u color=%06x",
                          op->order_type,
                          op->kind,
                          region->dst_x,
                          region->dst_y,
                          region->width,
                          region->height,
                          rop,
                          color & 0x00ffffffu);
    return LIBRDP_STATUS_OK;
}

static int rdp_session_gdi_hatch_bit(uint8_t hatch, uint32_t x, uint32_t y)
{
    uint32_t px = x & 7u;
    uint32_t py = y & 7u;

    switch (hatch)
    {
        case 0u:
            return py == 0u;
        case 1u:
            return px == 0u;
        case 2u:
            return ((px + py) & 7u) == 0u;
        case 3u:
            return ((px + (7u - py)) & 7u) == 0u;
        case 4u:
            return px == 0u || py == 0u;
        case 5u:
            return ((px + py) & 7u) == 0u || ((px + (7u - py)) & 7u) == 0u;
        default:
            return 0;
    }
}

static int rdp_session_gdi_pattern_bit(const rdp_gdi_render_op* op, uint32_t x, uint32_t y)
{
    uint8_t pattern[8];
    uint32_t px = 0;
    uint32_t py = 0;

    if (!op)
        return 0;
    pattern[0] = op->brush_hatch;
    memcpy(pattern + 1u, op->brush_extra, sizeof(op->brush_extra));
    px = (uint32_t)((int64_t)x - op->brush_x) & 7u;
    py = (uint32_t)((int64_t)y - op->brush_y) & 7u;
    return ((pattern[py] >> (7u - px)) & 1u) != 0;
}

static int rdp_session_gdi_brush_style_is_pattern(uint8_t style)
{
    switch (style & (uint8_t)~RDP_GDI_CACHED_BRUSH)
    {
        case RDP_SESSION_GDI_BRUSH_PATTERN:
        case RDP_SESSION_GDI_BRUSH_INDEXED:
        case RDP_SESSION_GDI_BRUSH_DIBPATTERN:
        case RDP_SESSION_GDI_BRUSH_DIBPATTERNPT:
        case RDP_SESSION_GDI_BRUSH_PATTERN8X8:
        case RDP_SESSION_GDI_BRUSH_DIBPATTERN8X8:
            return 1;
        default:
            return 0;
    }
}

static const rdp_session_gdi_brush_cache_entry*
rdp_session_gdi_cached_brush_find(const librdp_session* session, const rdp_gdi_render_op* op)
{
    uint32_t cache_entry = 0;
    uint32_t format = 0;
    const rdp_session_gdi_brush_cache_entry* entry = NULL;

    if (!session || !op || (op->brush_style & RDP_GDI_CACHED_BRUSH) == 0)
        return NULL;
    cache_entry = op->brush_hatch;
    format = op->brush_style & 0x0fu;
    if (cache_entry >= RDP_SESSION_GDI_BRUSH_CACHE_SLOTS)
        return NULL;
    entry = &session->gdi_brush_cache[cache_entry];
    if (!entry->active || entry->cache_entry != cache_entry || entry->bitmap_format != format)
        return NULL;
    return entry;
}

static int rdp_session_gdi_cached_brush_bgr(const rdp_session_gdi_brush_cache_entry* entry,
                                            const rdp_gdi_render_op* op,
                                            uint32_t x,
                                            uint32_t y,
                                            uint8_t* b,
                                            uint8_t* g,
                                            uint8_t* r)
{
    uint32_t px = 0;
    uint32_t py = 0;
    const uint8_t* color = NULL;

    if (!entry || !op)
        return 0;
    px = (uint32_t)((int64_t)x - op->brush_x) & 7u;
    py = (uint32_t)((int64_t)y - op->brush_y) & 7u;
    if (entry->mono)
    {
        uint32_t source = ((entry->mono_rows[py] >> (7u - px)) & 1u) ? op->color : op->back_color;

        if (b)
            *b = (uint8_t)(source & 0xffu);
        if (g)
            *g = (uint8_t)((source >> 8u) & 0xffu);
        if (r)
            *r = (uint8_t)((source >> 16u) & 0xffu);
        return 1;
    }
    color = entry->bgra + (((size_t)py * 8u + px) * 4u);
    if (b)
        *b = color[0];
    if (g)
        *g = color[1];
    if (r)
        *r = color[2];
    return 1;
}

static void rdp_session_gdi_brush_bgr(const librdp_session* session,
                                      const rdp_gdi_render_op* op,
                                      uint32_t x,
                                      uint32_t y,
                                      uint8_t* b,
                                      uint8_t* g,
                                      uint8_t* r)
{
    const rdp_session_gdi_brush_cache_entry* cached = rdp_session_gdi_cached_brush_find(session, op);
    uint32_t color = op ? op->color : 0;
    int foreground = 1;

    if (cached && rdp_session_gdi_cached_brush_bgr(cached, op, x, y, b, g, r))
        return;
    if (op && op->brush_style == RDP_SESSION_GDI_BRUSH_HATCHED)
        foreground = rdp_session_gdi_hatch_bit(op->brush_hatch, x, y);
    else if (op && rdp_session_gdi_brush_style_is_pattern(op->brush_style))
        foreground = rdp_session_gdi_pattern_bit(op, x, y);
    if (!foreground && op)
        color = op->back_color;
    if (b)
        *b = (uint8_t)(color & 0xffu);
    if (g)
        *g = (uint8_t)((color >> 8u) & 0xffu);
    if (r)
        *r = (uint8_t)((color >> 16u) & 0xffu);
}

/*
 * Copy a cached GDI bitmap into the target surface. Cache lookup, source
 * clipping, raster operation, and destination bounds are validated before
 * pixels are written.
 */
static librdp_status rdp_session_gdi_copy_cached_bitmap(librdp_session* session,
                                                        const rdp_gdi_render_op* op,
                                                        const rdp_session_gdi_bitmap_cache_entry* entry,
                                                        const rdp_session_gdi_region* region)
{
    uint8_t* pixels = NULL;
    size_t stride = 0;
    const uint8_t* source_pixels = NULL;
    size_t source_stride = 0;
    rdp_buffer decoded;
    uint32_t y = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !op || !entry || !region)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&decoded);
    if (op->kind == RDP_GDI_RENDER_OP_MEM3BLT &&
        (op->brush_style & RDP_GDI_CACHED_BRUSH) != 0 &&
        !rdp_session_gdi_cached_brush_find(session, op))
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.brush_cache.miss",
                              "kind=%u cache_entry=%u brush_style=%u",
                              op->kind,
                              op->brush_hatch,
                              op->brush_style);
        return LIBRDP_STATUS_OK;
    }
    if (entry->pixels.data)
    {
        if (entry->stride < (size_t)entry->width * 4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        source_pixels = entry->pixels.data;
        source_stride = entry->stride;
    }
    else if (entry->bits_per_pixel == 8u && entry->raw.data)
    {
        rdp_bitmap_rect rect;
        const rdp_palette_update* palette = rdp_session_gdi_color_table_find(session, op->color_index);

        if (!palette && session->palette_valid)
            palette = &session->palette;
        if (!palette)
        {
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.gdi.color_table.miss",
                                  "cache_id=%u cache_index=%u color_index=%u",
                                  op->cache_id,
                                  op->cache_index,
                                  op->color_index);
            return LIBRDP_STATUS_OK;
        }
        if (entry->raw.length > UINT32_MAX)
        {
            rdp_buffer_free(&decoded);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        memset(&rect, 0, sizeof(rect));
        rect.dest_right = (uint16_t)(entry->width - 1u);
        rect.dest_bottom = (uint16_t)(entry->height - 1u);
        rect.width = (uint16_t)entry->width;
        rect.height = (uint16_t)entry->height;
        rect.bits_per_pixel = (uint16_t)entry->bits_per_pixel;
        rect.flags = entry->bitmap_flags;
        rect.data = entry->raw.data;
        rect.data_len = (uint32_t)entry->raw.length;
        status = rdp_bitmap_decode_rect_bgra32_with_palette(&rect, palette, &decoded, &source_stride);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&decoded);
            return status;
        }
        source_pixels = decoded.data;
    }
    else
    {
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    if (!pixels || stride == 0)
    {
        rdp_buffer_free(&decoded);
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    for (y = 0; y < region->height; y++)
    {
        const uint8_t* src = source_pixels + ((size_t)(region->src_y + y) * source_stride) +
                             ((size_t)region->src_x * 4u);
        uint8_t* dst = pixels + ((size_t)(region->dst_y + y) * stride) + ((size_t)region->dst_x * 4u);
        uint32_t x = 0;

        for (x = 0; x < region->width; x++)
        {
            uint8_t pb = 0;
            uint8_t pg = 0;
            uint8_t pr = 0;

            if (op->kind == RDP_GDI_RENDER_OP_MEM3BLT)
                rdp_session_gdi_brush_bgr(session, op, region->dst_x + x, region->dst_y + y, &pb, &pg, &pr);
            dst[0] = rdp_session_gdi_rop3(op->rop, src[0], pb, dst[0]);
            dst[1] = rdp_session_gdi_rop3(op->rop, src[1], pg, dst[1]);
            dst[2] = rdp_session_gdi_rop3(op->rop, src[2], pr, dst[2]);
            dst[3] = 0xffu;
            src += 4u;
            dst += 4u;
        }
    }
    rdp_session_emit_surface_invalidated(session, region->dst_x, region->dst_y, region->width, region->height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.bitmap_cache.blit",
                          "kind=%u cache_id=%u cache_index=%u src_x=%u src_y=%u x=%u y=%u width=%u height=%u rop=%u",
                          op->kind,
                          op->cache_id,
                          op->cache_index,
                          region->src_x,
                          region->src_y,
                          region->dst_x,
                          region->dst_y,
                          region->width,
                          region->height,
                          op->rop);
    rdp_buffer_free(&decoded);
    return LIBRDP_STATUS_OK;
}

/*
 * Render a GDI PatBlt order into the session surface. Brush resolution, raster
 * operation selection, and clipping are kept in one path to avoid inconsistent
 * cache use.
 */
static librdp_status rdp_session_gdi_patblt(librdp_session* session,
                                            const rdp_gdi_render_op* op,
                                            const rdp_session_gdi_region* region)
{
    uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t y = 0;
    uint8_t fore_b = 0;
    uint8_t fore_g = 0;
    uint8_t fore_r = 0;
    uint8_t back_b = 0;
    uint8_t back_g = 0;
    uint8_t back_r = 0;

    if (!session || !op || !region)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (op->brush_style == RDP_SESSION_GDI_BRUSH_NULL)
        return LIBRDP_STATUS_OK;
    if ((op->brush_style & RDP_GDI_CACHED_BRUSH) != 0 &&
        !rdp_session_gdi_cached_brush_find(session, op))
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.brush_cache.miss",
                              "kind=%u cache_entry=%u brush_style=%u",
                              op->kind,
                              op->brush_hatch,
                              op->brush_style);
        return LIBRDP_STATUS_OK;
    }
    if ((op->brush_style & RDP_GDI_CACHED_BRUSH) == 0 &&
        op->brush_style != RDP_SESSION_GDI_BRUSH_SOLID &&
        op->brush_style != RDP_SESSION_GDI_BRUSH_HATCHED &&
        !rdp_session_gdi_brush_style_is_pattern(op->brush_style))
        return LIBRDP_STATUS_UNSUPPORTED;
    pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    if (!pixels || stride == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    fore_b = (uint8_t)(op->color & 0xffu);
    fore_g = (uint8_t)((op->color >> 8u) & 0xffu);
    fore_r = (uint8_t)((op->color >> 16u) & 0xffu);
    back_b = (uint8_t)(op->back_color & 0xffu);
    back_g = (uint8_t)((op->back_color >> 8u) & 0xffu);
    back_r = (uint8_t)((op->back_color >> 16u) & 0xffu);
    for (y = 0; y < region->height; y++)
    {
        uint8_t* pixel = pixels + ((size_t)(region->dst_y + y) * stride) + ((size_t)region->dst_x * 4u);
        uint32_t x = 0;

        for (x = 0; x < region->width; x++)
        {
            uint32_t absolute_x = region->dst_x + x;
            uint32_t absolute_y = region->dst_y + y;
            int foreground = 1;
            uint8_t b = fore_b;
            uint8_t g = fore_g;
            uint8_t r = fore_r;

            if ((op->brush_style & RDP_GDI_CACHED_BRUSH) != 0)
            {
                rdp_session_gdi_brush_bgr(session, op, absolute_x, absolute_y, &b, &g, &r);
                foreground = 1;
            }
            else if (op->brush_style == RDP_SESSION_GDI_BRUSH_HATCHED)
                foreground = rdp_session_gdi_hatch_bit(op->brush_hatch, absolute_x, absolute_y);
            else if (rdp_session_gdi_brush_style_is_pattern(op->brush_style))
                foreground = rdp_session_gdi_pattern_bit(op, absolute_x, absolute_y);
            if (!foreground)
            {
                b = back_b;
                g = back_g;
                r = back_r;
            }
            pixel[0] = rdp_session_gdi_rop3(op->rop, 0, b, pixel[0]);
            pixel[1] = rdp_session_gdi_rop3(op->rop, 0, g, pixel[1]);
            pixel[2] = rdp_session_gdi_rop3(op->rop, 0, r, pixel[2]);
            pixel[3] = 0xffu;
            pixel += 4u;
        }
    }
    rdp_session_emit_surface_invalidated(session, region->dst_x, region->dst_y, region->width, region->height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.order.apply",
                          "type=%u kind=%u x=%u y=%u width=%u height=%u rop=%u brush_style=%u brush_hatch=%u fore=%06x back=%06x",
                          op->order_type,
                          op->kind,
                          region->dst_x,
                          region->dst_y,
                          region->width,
                          region->height,
                          op->rop,
                          op->brush_style,
                          op->brush_hatch,
                          op->color & 0x00ffffffu,
                          op->back_color & 0x00ffffffu);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_copy_rect(librdp_session* session,
                                               const rdp_gdi_render_op* op,
                                               const rdp_session_gdi_region* region)
{
    rdp_buffer temp;
    const uint8_t* pixels = NULL;
    uint8_t* mutable_pixels = NULL;
    size_t stride = 0;
    size_t row_stride = 0;
    uint32_t y = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !op || !region)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    pixels = librdp_surface_pixels(session->surface);
    mutable_pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    if (!pixels || !mutable_pixels || stride == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    row_stride = (size_t)region->width * 4u;
    rdp_buffer_init(&temp);
    status = rdp_buffer_reserve(&temp, row_stride * (size_t)region->height);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (y = 0; y < region->height; y++)
    {
        memcpy(temp.data + ((size_t)y * row_stride),
               pixels + ((size_t)(region->src_y + y) * stride) + ((size_t)region->src_x * 4u),
               row_stride);
    }
    temp.length = row_stride * (size_t)region->height;
    for (y = 0; y < region->height; y++)
    {
        const uint8_t* src = temp.data + ((size_t)y * row_stride);
        uint8_t* dst = mutable_pixels + ((size_t)(region->dst_y + y) * stride) + ((size_t)region->dst_x * 4u);
        uint32_t x = 0;

        for (x = 0; x < region->width; x++)
        {
            dst[0] = rdp_session_gdi_rop3(op->rop, src[0], 0, dst[0]);
            dst[1] = rdp_session_gdi_rop3(op->rop, src[1], 0, dst[1]);
            dst[2] = rdp_session_gdi_rop3(op->rop, src[2], 0, dst[2]);
            dst[3] = 0xffu;
            src += 4u;
            dst += 4u;
        }
    }
    rdp_session_emit_surface_invalidated(session, region->dst_x, region->dst_y, region->width, region->height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.order.apply",
                          "type=%u kind=%u src_x=%u src_y=%u x=%u y=%u width=%u height=%u rop=%u",
                          op->order_type,
                          op->kind,
                          region->src_x,
                          region->src_y,
                          region->dst_x,
                          region->dst_y,
                          region->width,
                          region->height,
                          op->rop);
    rdp_buffer_free(&temp);
    return LIBRDP_STATUS_OK;
}

static int rdp_session_gdi_glyph_bit(const rdp_session_gdi_glyph_cache_entry* glyph,
                                     uint32_t x,
                                     uint32_t y)
{
    size_t row_stride = 0;
    size_t offset = 0;
    uint8_t mask = 0;

    if (!glyph || !glyph->active || !glyph->bitmap.data ||
        x >= glyph->width || y >= glyph->height)
        return 0;
    row_stride = (size_t)(glyph->width + 7u) / 8u;
    offset = (size_t)y * row_stride + (x / 8u);
    if (offset >= glyph->bitmap.length)
        return 0;
    mask = (uint8_t)(0x80u >> (x & 7u));
    return (glyph->bitmap.data[offset] & mask) != 0;
}

static void rdp_session_gdi_glyph_advance(const uint8_t* data,
                                          uint32_t length,
                                          uint32_t* index,
                                          int32_t* x,
                                          int32_t* y,
                                          uint32_t char_inc,
                                          uint32_t flags)
{
    uint32_t offset = 0;

    if (!data || !index || !x || !y)
        return;
    if (char_inc != 0u)
        return;
    if ((flags & RDP_GDI_GLYPH_SO_CHAR_INC_EQUAL_BM_BASE) != 0)
        return;
    if (*index >= length)
        return;
    offset = data[(*index)++];
    if ((offset & 0x80u) != 0)
    {
        if (*index + 2u > length)
            return;
        offset = data[(*index)++];
        offset |= (uint32_t)data[(*index)++] << 8u;
    }
    if ((flags & RDP_GDI_GLYPH_SO_VERTICAL) != 0)
        *y += (int32_t)offset;
    if ((flags & RDP_GDI_GLYPH_SO_HORIZONTAL) != 0 ||
        (flags & RDP_GDI_GLYPH_SO_VERTICAL) == 0)
        *x += (int32_t)offset;
}

static void rdp_session_gdi_glyph_post_advance(const rdp_session_gdi_glyph_cache_entry* glyph,
                                               int32_t* x,
                                               int32_t* y,
                                               uint32_t char_inc,
                                               uint32_t flags)
{
    int32_t amount = 0;

    if (!glyph || !x || !y)
        return;
    if ((flags & RDP_GDI_GLYPH_SO_CHAR_INC_EQUAL_BM_BASE) != 0)
        amount = (int32_t)glyph->width;
    else if (char_inc != 0u)
        amount = (int32_t)char_inc;
    else
        return;
    if ((flags & RDP_GDI_GLYPH_SO_VERTICAL) != 0)
        *y += amount;
    else
        *x += amount;
}

/*
 * Render one cached glyph from a GDI text order. Glyph cache lookup and
 * foreground/background composition are bounded by the current clipping
 * region.
 */
static librdp_status rdp_session_gdi_draw_cached_glyph(librdp_session* session,
                                                       const rdp_gdi_render_op* op,
                                                       const rdp_session_gdi_glyph_cache_entry* glyph,
                                                       int32_t* pen_x,
                                                       int32_t* pen_y)
{
    uint8_t* pixels = NULL;
    size_t stride = 0;
    int64_t left = 0;
    int64_t top = 0;
    int64_t right = 0;
    int64_t bottom = 0;
    int64_t clip_left = 0;
    int64_t clip_top = 0;
    int64_t clip_right = 0;
    int64_t clip_bottom = 0;
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;
    uint32_t y = 0;
    uint8_t b = 0;
    uint8_t g = 0;
    uint8_t r = 0;

    if (!session || !op || !glyph || !pen_x || !pen_y)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!glyph->active || glyph->width == 0 || glyph->height == 0)
        return LIBRDP_STATUS_OK;
    surface_width = librdp_surface_width(session->surface);
    surface_height = librdp_surface_height(session->surface);
    left = (int64_t)*pen_x + glyph->x;
    top = (int64_t)*pen_y + glyph->y;
    right = left + glyph->width;
    bottom = top + glyph->height;
    clip_right = surface_width;
    clip_bottom = surface_height;
    if (op->glyph_back_rect.width > 0 && op->glyph_back_rect.height > 0)
    {
        clip_left = op->glyph_back_rect.x;
        clip_top = op->glyph_back_rect.y;
        clip_right = (int64_t)op->glyph_back_rect.x + op->glyph_back_rect.width;
        clip_bottom = (int64_t)op->glyph_back_rect.y + op->glyph_back_rect.height;
    }
    if (clip_left < 0)
        clip_left = 0;
    if (clip_top < 0)
        clip_top = 0;
    if (clip_right > (int64_t)surface_width)
        clip_right = surface_width;
    if (clip_bottom > (int64_t)surface_height)
        clip_bottom = surface_height;
    if (left < clip_left)
        left = clip_left;
    if (top < clip_top)
        top = clip_top;
    if (right > clip_right)
        right = clip_right;
    if (bottom > clip_bottom)
        bottom = clip_bottom;
    if (right <= left || bottom <= top)
    {
        rdp_session_gdi_glyph_post_advance(glyph, pen_x, pen_y, op->glyph_char_inc, op->glyph_flags);
        return LIBRDP_STATUS_OK;
    }
    pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    if (!pixels || stride == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    b = (uint8_t)(op->color & 0xffu);
    g = (uint8_t)((op->color >> 8u) & 0xffu);
    r = (uint8_t)((op->color >> 16u) & 0xffu);
    for (y = (uint32_t)top; y < (uint32_t)bottom; y++)
    {
        uint32_t x = 0;
        uint8_t* dst = pixels + ((size_t)y * stride) + ((size_t)left * 4u);

        for (x = (uint32_t)left; x < (uint32_t)right; x++)
        {
            uint32_t gx = (uint32_t)((int64_t)x - ((int64_t)*pen_x + glyph->x));
            uint32_t gy = (uint32_t)((int64_t)y - ((int64_t)*pen_y + glyph->y));

            if (rdp_session_gdi_glyph_bit(glyph, gx, gy))
            {
                dst[0] = b;
                dst[1] = g;
                dst[2] = r;
                dst[3] = 0xffu;
            }
            dst += 4u;
        }
    }
    rdp_session_emit_surface_invalidated(session,
                                         (uint32_t)left,
                                         (uint32_t)top,
                                         (uint32_t)(right - left),
                                         (uint32_t)(bottom - top));
    rdp_session_gdi_glyph_post_advance(glyph, pen_x, pen_y, op->glyph_char_inc, op->glyph_flags);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_process_glyph_bytes(librdp_session* session,
                                                         const rdp_gdi_render_op* op,
                                                         const uint8_t* data,
                                                         uint32_t length,
                                                         int32_t* pen_x,
                                                         int32_t* pen_y);

static librdp_status rdp_session_gdi_process_glyph_fragment(librdp_session* session,
                                                            const rdp_gdi_render_op* op,
                                                            uint8_t fragment_id,
                                                            int32_t* pen_x,
                                                            int32_t* pen_y)
{
    rdp_session_gdi_glyph_fragment* fragment = NULL;

    if (!session || !op || !pen_x || !pen_y)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    fragment = &session->gdi_glyph_fragments[fragment_id];
    if (!fragment->active)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.glyph_fragment.miss",
                              "fragment_id=%u",
                              fragment_id);
        return LIBRDP_STATUS_OK;
    }
    return rdp_session_gdi_process_glyph_bytes(session,
                                               op,
                                               fragment->data.data,
                                               (uint32_t)fragment->data.length,
                                               pen_x,
                                               pen_y);
}

static librdp_status rdp_session_gdi_process_glyph_bytes(librdp_session* session,
                                                         const rdp_gdi_render_op* op,
                                                         const uint8_t* data,
                                                         uint32_t length,
                                                         int32_t* pen_x,
                                                         int32_t* pen_y)
{
    uint32_t index = 0;

    if (!session || !op || (!data && length > 0) || !pen_x || !pen_y)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (index < length)
    {
        uint8_t token = data[index++];
        librdp_status status = LIBRDP_STATUS_OK;

        if (token == RDP_GDI_GLYPH_FRAGMENT_USE)
        {
            if (index >= length)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_session_gdi_process_glyph_fragment(session, op, data[index++], pen_x, pen_y);
            if (status != LIBRDP_STATUS_OK)
                return status;
            continue;
        }
        if (token == RDP_GDI_GLYPH_FRAGMENT_ADD)
        {
            uint8_t fragment_id = 0;
            uint8_t fragment_len = 0;

            if (index + 2u > length)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            fragment_id = data[index++];
            fragment_len = data[index++];
            if (index + fragment_len > length)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_session_gdi_glyph_fragment_store(session, fragment_id, data + index, fragment_len);
            if (status != LIBRDP_STATUS_OK)
                return status;
            index += fragment_len;
            continue;
        }
        rdp_session_gdi_glyph_advance(data,
                                      length,
                                      &index,
                                      pen_x,
                                      pen_y,
                                      op->glyph_char_inc,
                                      op->glyph_flags);
        {
            const rdp_session_gdi_glyph_cache_entry* glyph =
                rdp_session_gdi_glyph_cache_find(session, op->cache_id, token);

            if (!glyph)
            {
                if (op->glyph_char_inc != 0u)
                {
                    if ((op->glyph_flags & RDP_GDI_GLYPH_SO_VERTICAL) != 0)
                        *pen_y += (int32_t)op->glyph_char_inc;
                    else
                        *pen_x += (int32_t)op->glyph_char_inc;
                }
                rdp_trace_event_level(RDP_TRACE_CLIENT,
                                      RDP_TRACE_LEVEL_DEBUG,
                                      "client.gdi.glyph_cache.miss",
                                      "cache_id=%u cache_index=%u",
                                      op->cache_id,
                                      token);
                continue;
            }
            status = rdp_session_gdi_draw_cached_glyph(session, op, glyph, pen_x, pen_y);
        }
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_draw_glyphs(librdp_session* session, const rdp_gdi_render_op* op)
{
    rdp_session_gdi_region region;
    rdp_gdi_render_op fill_op;
    int32_t pen_x = 0;
    int32_t pen_y = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !op)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (op->inline_glyph_present)
    {
        rdp_gdi_glyph_bitmap glyph;

        memset(&glyph, 0, sizeof(glyph));
        glyph.cache_index = op->inline_glyph_cache_index;
        glyph.x = op->inline_glyph_x;
        glyph.y = op->inline_glyph_y;
        glyph.width = op->inline_glyph_width;
        glyph.height = op->inline_glyph_height;
        glyph.bitmap = op->inline_glyph_bitmap;
        glyph.bitmap_len = op->inline_glyph_bitmap_len;
        status = rdp_session_gdi_glyph_cache_store(session, op->cache_id, &glyph);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (!op->glyph_opaque && op->rect.width > 0 && op->rect.height > 0)
    {
        memset(&region, 0, sizeof(region));
        fill_op = *op;
        fill_op.kind = RDP_GDI_RENDER_OP_OPAQUE_RECT;
        if (rdp_session_gdi_clip_dest(&fill_op,
                                      librdp_surface_width(session->surface),
                                      librdp_surface_height(session->surface),
                                      &region))
        {
            status = rdp_session_gdi_fill_rect(session, &fill_op, &region, 0, op->back_color, 0);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
    }
    pen_x = op->glyph_x;
    pen_y = op->glyph_y;
    status = rdp_session_gdi_process_glyph_bytes(session,
                                                 op,
                                                 op->glyph_data,
                                                 op->glyph_data_len,
                                                 &pen_x,
                                                 &pen_y);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.glyph.draw",
                              "cache_id=%u x=%d y=%d bytes=%u fore=%06x back=%06x",
                              op->cache_id,
                              op->glyph_x,
                              op->glyph_y,
                              op->glyph_data_len,
                              op->color & 0x00ffffffu,
                              op->back_color & 0x00ffffffu);
    }
    return status;
}

static rdp_session_gdi_bitmap_cache_entry* rdp_session_gdi_ninegrid_bitmap_find(librdp_session* session,
                                                                                uint32_t bitmap_id)
{
    size_t i = 0;
    rdp_session_gdi_bitmap_cache_entry* entry = NULL;

    entry = rdp_session_gdi_bitmap_cache_find(session, 0, bitmap_id);
    if (entry)
        return entry;
    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_BITMAP_CACHE_SLOTS; i++)
    {
        entry = &session->gdi_bitmap_cache[i];
        if (entry->active && entry->cache_index == bitmap_id)
        {
            entry->last_used = ++session->gdi_bitmap_cache_clock;
            return entry;
        }
    }
    return NULL;
}

static uint32_t rdp_session_gdi_min_u32(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}

static uint32_t rdp_session_gdi_ninegrid_axis(uint32_t pos,
                                              uint32_t dst_len,
                                              uint32_t src_start,
                                              uint32_t src_len,
                                              uint32_t src_leading,
                                              uint32_t src_trailing,
                                              uint32_t dst_leading,
                                              uint32_t dst_trailing)
{
    uint32_t src_center = 0;
    uint32_t dst_center = 0;

    if (src_len == 0 || dst_len == 0)
        return src_start;
    if (pos < dst_leading)
        return src_start + rdp_session_gdi_min_u32(pos, src_len - 1u);
    if (pos >= dst_len - dst_trailing)
    {
        uint32_t tail = dst_len - 1u - pos;

        return src_start + src_len - 1u - rdp_session_gdi_min_u32(tail, src_len - 1u);
    }
    src_center = src_len - src_leading - src_trailing;
    dst_center = dst_len - dst_leading - dst_trailing;
    if (src_center == 0 || dst_center == 0)
        return src_start + rdp_session_gdi_min_u32(src_leading, src_len - 1u);
    return src_start + src_leading + (uint32_t)(((uint64_t)(pos - dst_leading) * src_center) / dst_center);
}

/*
 * Render a nine-grid order by splitting stretchable and fixed regions. Source
 * bitmap bounds and destination slices are checked before each blit.
 */
static librdp_status rdp_session_gdi_draw_ninegrid(librdp_session* session, const rdp_gdi_render_op* op)
{
    rdp_session_gdi_ninegrid_cache_entry* grid = NULL;
    rdp_session_gdi_bitmap_cache_entry* bitmap = NULL;
    rdp_session_gdi_region region;
    uint8_t* dst_pixels = NULL;
    const uint8_t* src_pixels = NULL;
    size_t dst_stride = 0;
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;
    uint32_t src_left = 0;
    uint32_t src_top = 0;
    uint32_t src_right = 0;
    uint32_t src_bottom = 0;
    uint32_t src_width = 0;
    uint32_t src_height = 0;
    uint32_t src_left_band = 0;
    uint32_t src_right_band = 0;
    uint32_t src_top_band = 0;
    uint32_t src_bottom_band = 0;
    uint32_t dst_left_band = 0;
    uint32_t dst_right_band = 0;
    uint32_t dst_top_band = 0;
    uint32_t dst_bottom_band = 0;
    uint32_t y = 0;

    if (!session || !op)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    grid = rdp_session_gdi_ninegrid_cache_find(session, op->bitmap_id);
    bitmap = rdp_session_gdi_ninegrid_bitmap_find(session, op->bitmap_id);
    if (!grid || !bitmap || !bitmap->active || bitmap->pixels.length == 0 || bitmap->stride == 0)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.ninegrid.miss",
                              "bitmap_id=%u has_grid=%u has_bitmap=%u x=%d y=%d width=%d height=%d",
                              op->bitmap_id,
                              grid ? 1u : 0u,
                              bitmap ? 1u : 0u,
                              op->rect.x,
                              op->rect.y,
                              op->rect.width,
                              op->rect.height);
        return LIBRDP_STATUS_OK;
    }
    if (op->src_left < 0 || op->src_top < 0 || op->src_right < op->src_left || op->src_bottom < op->src_top)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    src_left = (uint32_t)op->src_left;
    src_top = (uint32_t)op->src_top;
    src_right = (uint32_t)op->src_right;
    src_bottom = (uint32_t)op->src_bottom;
    if (src_left >= bitmap->width || src_top >= bitmap->height)
        return LIBRDP_STATUS_OK;
    if (src_right >= bitmap->width)
        src_right = bitmap->width - 1u;
    if (src_bottom >= bitmap->height)
        src_bottom = bitmap->height - 1u;
    if (src_right < src_left || src_bottom < src_top)
        return LIBRDP_STATUS_OK;
    src_width = src_right - src_left + 1u;
    src_height = src_bottom - src_top + 1u;
    surface_width = librdp_surface_width(session->surface);
    surface_height = librdp_surface_height(session->surface);
    if (!rdp_session_gdi_clip_dest(op, surface_width, surface_height, &region))
        return LIBRDP_STATUS_OK;
    dst_pixels = librdp_surface_pixels_mut(session->surface);
    src_pixels = bitmap->pixels.data;
    dst_stride = librdp_surface_stride(session->surface);
    if (!dst_pixels || !src_pixels || dst_stride == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    src_left_band = rdp_session_gdi_min_u32(grid->info.left_width, src_width);
    src_right_band = rdp_session_gdi_min_u32(grid->info.right_width, src_width - src_left_band);
    src_top_band = rdp_session_gdi_min_u32(grid->info.top_height, src_height);
    src_bottom_band = rdp_session_gdi_min_u32(grid->info.bottom_height, src_height - src_top_band);
    dst_left_band = rdp_session_gdi_min_u32(grid->info.left_width, (uint32_t)op->rect.width);
    dst_right_band = rdp_session_gdi_min_u32(grid->info.right_width, (uint32_t)op->rect.width - dst_left_band);
    dst_top_band = rdp_session_gdi_min_u32(grid->info.top_height, (uint32_t)op->rect.height);
    dst_bottom_band = rdp_session_gdi_min_u32(grid->info.bottom_height, (uint32_t)op->rect.height - dst_top_band);
    for (y = 0; y < region.height; y++)
    {
        uint32_t dst_abs_y = region.dst_y + y;
        uint32_t dst_rel_y = (uint32_t)((int32_t)dst_abs_y - op->rect.y);
        uint32_t sy = rdp_session_gdi_ninegrid_axis(dst_rel_y,
                                                    (uint32_t)op->rect.height,
                                                    src_top,
                                                    src_height,
                                                    src_top_band,
                                                    src_bottom_band,
                                                    dst_top_band,
                                                    dst_bottom_band);
        uint8_t* dst = dst_pixels + ((size_t)dst_abs_y * dst_stride) + ((size_t)region.dst_x * 4u);
        uint32_t x = 0;

        for (x = 0; x < region.width; x++)
        {
            uint32_t dst_abs_x = region.dst_x + x;
            uint32_t dst_rel_x = (uint32_t)((int32_t)dst_abs_x - op->rect.x);
            uint32_t sx = rdp_session_gdi_ninegrid_axis(dst_rel_x,
                                                        (uint32_t)op->rect.width,
                                                        src_left,
                                                        src_width,
                                                        src_left_band,
                                                        src_right_band,
                                                        dst_left_band,
                                                        dst_right_band);
            const uint8_t* src = src_pixels + ((size_t)sy * bitmap->stride) + ((size_t)sx * 4u);

            if ((grid->info.flags & 0x01u) != 0 &&
                (((uint32_t)src[0] | ((uint32_t)src[1] << 8u) | ((uint32_t)src[2] << 16u)) ==
                 (grid->info.transparent_color & 0x00ffffffu)))
            {
                dst += 4u;
                continue;
            }
            dst[0] = src[0];
            dst[1] = src[1];
            dst[2] = src[2];
            dst[3] = 0xffu;
            dst += 4u;
        }
    }
    rdp_session_emit_surface_invalidated(session, region.dst_x, region.dst_y, region.width, region.height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.ninegrid.blit",
                          "bitmap_id=%u src=%u,%u,%u,%u x=%u y=%u width=%u height=%u",
                          op->bitmap_id,
                          src_left,
                          src_top,
                          src_right,
                          src_bottom,
                          region.dst_x,
                          region.dst_y,
                          region.width,
                          region.height);
    return LIBRDP_STATUS_OK;
}

static int32_t rdp_session_gdi_abs_i32(int32_t value)
{
    return value < 0 ? -value : value;
}

static uint8_t rdp_session_gdi_rop2(uint8_t rop, uint8_t pen, uint8_t dest)
{
    switch (rop)
    {
        case 1u:
            return 0;
        case 2u:
            return (uint8_t)~(dest | pen);
        case 3u:
            return (uint8_t)(dest & (uint8_t)~pen);
        case 4u:
            return (uint8_t)~pen;
        case 5u:
            return (uint8_t)(pen & (uint8_t)~dest);
        case 6u:
            return (uint8_t)~dest;
        case 7u:
            return (uint8_t)(dest ^ pen);
        case 8u:
            return (uint8_t)~(dest & pen);
        case 9u:
            return (uint8_t)(dest & pen);
        case 10u:
            return (uint8_t)~(dest ^ pen);
        case 11u:
            return dest;
        case 12u:
            return (uint8_t)(dest | (uint8_t)~pen);
        case 13u:
            return pen;
        case 14u:
            return (uint8_t)(pen | (uint8_t)~dest);
        case 15u:
            return (uint8_t)(dest | pen);
        case 16u:
            return 0xffu;
        default:
            return pen;
    }
}

static int rdp_session_gdi_line_point_visible(const rdp_gdi_render_op* op,
                                              int32_t x,
                                              int32_t y,
                                              uint32_t width,
                                              uint32_t height)
{
    if (x < 0 || y < 0 || x >= (int32_t)width || y >= (int32_t)height)
        return 0;
    if (op->bounds.present &&
        (x < op->bounds.left || y < op->bounds.top || x > op->bounds.right || y > op->bounds.bottom))
        return 0;
    return 1;
}

static int rdp_session_gdi_pen_style_visible(uint32_t style, uint32_t step)
{
    uint32_t phase = 0;

    switch (style)
    {
        case RDP_SESSION_GDI_PEN_SOLID:
        case RDP_SESSION_GDI_PEN_INSIDEFRAME:
            return 1;
        case RDP_SESSION_GDI_PEN_DASH:
            phase = step % 24u;
            return phase < 18u;
        case RDP_SESSION_GDI_PEN_DOT:
            phase = step % 6u;
            return phase < 2u;
        case RDP_SESSION_GDI_PEN_DASHDOT:
            phase = step % 22u;
            return phase < 12u || (phase >= 16u && phase < 18u);
        case RDP_SESSION_GDI_PEN_DASHDOTDOT:
            phase = step % 28u;
            return phase < 12u || (phase >= 16u && phase < 18u) || (phase >= 22u && phase < 24u);
        case RDP_SESSION_GDI_PEN_NULL:
        default:
            return 0;
    }
}

static void rdp_session_gdi_line_plot(librdp_session* session,
                                      const rdp_gdi_render_op* op,
                                      int32_t x,
                                      int32_t y,
                                      uint32_t step,
                                      uint32_t surface_width,
                                      uint32_t surface_height,
                                      uint32_t* dirty_left,
                                      uint32_t* dirty_top,
                                      uint32_t* dirty_right,
                                      uint32_t* dirty_bottom)
{
    uint8_t* pixels = librdp_surface_pixels_mut(session->surface);
    size_t stride = librdp_surface_stride(session->surface);
    uint32_t pen_width = op->pen_width == 0 ? 1u : op->pen_width;
    int32_t start = -(int32_t)(pen_width / 2u);
    int32_t end = start + (int32_t)pen_width;
    int32_t dy = 0;
    uint8_t b = (uint8_t)(op->color & 0xffu);
    uint8_t g = (uint8_t)((op->color >> 8u) & 0xffu);
    uint8_t r = (uint8_t)((op->color >> 16u) & 0xffu);

    if (!pixels || stride == 0)
        return;
    if (!rdp_session_gdi_pen_style_visible(op->pen_style, step))
        return;
    for (dy = start; dy < end; dy++)
    {
        int32_t dx = 0;

        for (dx = start; dx < end; dx++)
        {
            int32_t px = x + dx;
            int32_t py = y + dy;
            uint8_t* pixel = NULL;

            if (!rdp_session_gdi_line_point_visible(op, px, py, surface_width, surface_height))
                continue;
            pixel = pixels + ((size_t)(uint32_t)py * stride) + ((size_t)(uint32_t)px * 4u);
            pixel[0] = rdp_session_gdi_rop2(op->rop, b, pixel[0]);
            pixel[1] = rdp_session_gdi_rop2(op->rop, g, pixel[1]);
            pixel[2] = rdp_session_gdi_rop2(op->rop, r, pixel[2]);
            pixel[3] = 0xffu;
            if ((uint32_t)px < *dirty_left)
                *dirty_left = (uint32_t)px;
            if ((uint32_t)py < *dirty_top)
                *dirty_top = (uint32_t)py;
            if ((uint32_t)px + 1u > *dirty_right)
                *dirty_right = (uint32_t)px + 1u;
            if ((uint32_t)py + 1u > *dirty_bottom)
                *dirty_bottom = (uint32_t)py + 1u;
        }
    }
}

static int rdp_session_gdi_shape_color(const librdp_session* session,
                                       const rdp_gdi_render_op* op,
                                       uint32_t x,
                                       uint32_t y,
                                       uint32_t* color)
{
    int foreground = 1;

    if (!op || !color)
        return 0;
    if (op->kind != RDP_GDI_RENDER_OP_POLYGON_CB &&
        op->kind != RDP_GDI_RENDER_OP_ELLIPSE_CB)
    {
        *color = op->color;
        return 1;
    }
    if (op->brush_style == RDP_SESSION_GDI_BRUSH_NULL)
        return 0;
    if ((op->brush_style & RDP_GDI_CACHED_BRUSH) != 0)
    {
        uint8_t b = 0;
        uint8_t g = 0;
        uint8_t r = 0;

        if (!rdp_session_gdi_cached_brush_find(session, op))
            return 0;
        rdp_session_gdi_brush_bgr(session, op, x, y, &b, &g, &r);
        *color = (uint32_t)b | ((uint32_t)g << 8u) | ((uint32_t)r << 16u);
        return 1;
    }
    if (op->brush_style == RDP_SESSION_GDI_BRUSH_HATCHED)
        foreground = rdp_session_gdi_hatch_bit(op->brush_hatch, x, y);
    else if (rdp_session_gdi_brush_style_is_pattern(op->brush_style))
        foreground = rdp_session_gdi_pattern_bit(op, x, y);
    else if (op->brush_style != RDP_SESSION_GDI_BRUSH_SOLID)
        return 0;
    if (!foreground && op->transparent_background)
        return 0;
    *color = foreground ? op->color : op->back_color;
    return 1;
}

static void rdp_session_gdi_plot_rop2_pixel(librdp_session* session,
                                            uint8_t* pixel,
                                            const rdp_gdi_render_op* op,
                                            uint32_t x,
                                            uint32_t y)
{
    uint32_t color = 0;
    uint8_t b = 0;
    uint8_t g = 0;
    uint8_t r = 0;

    if (!rdp_session_gdi_shape_color(session, op, x, y, &color))
        return;
    b = (uint8_t)(color & 0xffu);
    g = (uint8_t)((color >> 8u) & 0xffu);
    r = (uint8_t)((color >> 16u) & 0xffu);
    pixel[0] = rdp_session_gdi_rop2(op->rop, b, pixel[0]);
    pixel[1] = rdp_session_gdi_rop2(op->rop, g, pixel[1]);
    pixel[2] = rdp_session_gdi_rop2(op->rop, r, pixel[2]);
    pixel[3] = 0xffu;
}

/*
 * Render a GDI line order with clipping and raster-operation handling.
 * Endpoint normalization stays local so degenerate or out-of-bounds lines
 * remain safe.
 */
static librdp_status rdp_session_gdi_draw_line(librdp_session* session, const rdp_gdi_render_op* op)
{
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;
    int32_t x0 = 0;
    int32_t y0 = 0;
    int32_t x1 = 0;
    int32_t y1 = 0;
    int32_t dx = 0;
    int32_t dy = 0;
    int32_t sx = 0;
    int32_t sy = 0;
    int32_t err = 0;
    uint32_t dirty_left = UINT32_MAX;
    uint32_t dirty_top = UINT32_MAX;
    uint32_t dirty_right = 0;
    uint32_t dirty_bottom = 0;
    uint32_t step = 0;

    if (!session || !op)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (op->pen_style > RDP_SESSION_GDI_PEN_INSIDEFRAME)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    surface_width = librdp_surface_width(session->surface);
    surface_height = librdp_surface_height(session->surface);
    x0 = op->rect.x;
    y0 = op->rect.y;
    x1 = op->end_x;
    y1 = op->end_y;
    dx = rdp_session_gdi_abs_i32(x1 - x0);
    dy = -rdp_session_gdi_abs_i32(y1 - y0);
    sx = x0 < x1 ? 1 : -1;
    sy = y0 < y1 ? 1 : -1;
    err = dx + dy;
    for (;;)
    {
        int32_t e2 = 0;

        rdp_session_gdi_line_plot(session,
                                  op,
                                  x0,
                                  y0,
                                  step,
                                  surface_width,
                                  surface_height,
                                  &dirty_left,
                                  &dirty_top,
                                  &dirty_right,
                                  &dirty_bottom);
        if (x0 == x1 && y0 == y1)
            break;
        step++;
        e2 = 2 * err;
        if (e2 >= dy)
        {
            err += dy;
            x0 += sx;
        }
        if (e2 <= dx)
        {
            err += dx;
            y0 += sy;
        }
    }
    if (dirty_left < dirty_right && dirty_top < dirty_bottom)
    {
        rdp_session_emit_surface_invalidated(session,
                                             dirty_left,
                                             dirty_top,
                                             dirty_right - dirty_left,
                                             dirty_bottom - dirty_top);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.order.apply",
                              "type=%u kind=%u x0=%d y0=%d x1=%d y1=%d width=%u style=%u rop2=%u dirty_x=%u dirty_y=%u dirty_width=%u dirty_height=%u",
                              op->order_type,
                              op->kind,
                              op->rect.x,
                              op->rect.y,
                              op->end_x,
                              op->end_y,
                              op->pen_width,
                              op->pen_style,
                              op->rop,
                              dirty_left,
                              dirty_top,
                              dirty_right - dirty_left,
                              dirty_bottom - dirty_top);
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_draw_polyline(librdp_session* session, const rdp_gdi_render_op* op)
{
    uint32_t i = 0;
    int32_t x = 0;
    int32_t y = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !op)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (op->point_count > RDP_GDI_RENDER_MAX_POINTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    x = op->rect.x;
    y = op->rect.y;
    for (i = 0; i < op->point_count; i++)
    {
        rdp_gdi_render_op segment = *op;

        segment.kind = RDP_GDI_RENDER_OP_LINE;
        segment.rect.x = x;
        segment.rect.y = y;
        x += op->points[i].x;
        y += op->points[i].y;
        segment.end_x = x;
        segment.end_y = y;
        segment.pen_width = 1;
        status = rdp_session_gdi_draw_line(session, &segment);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.order.apply",
                          "type=%u kind=%u x=%d y=%d points=%u rop2=%u color=%06x",
                          op->order_type,
                          op->kind,
                          op->rect.x,
                          op->rect.y,
                          op->point_count,
                          op->rop,
                          op->color & 0x00ffffffu);
    return LIBRDP_STATUS_OK;
}

static int rdp_session_gdi_shape_point_visible(const rdp_gdi_render_op* op,
                                               int32_t x,
                                               int32_t y,
                                               uint32_t width,
                                               uint32_t height)
{
    return rdp_session_gdi_line_point_visible(op, x, y, width, height);
}

static int rdp_session_gdi_polygon_inside(const rdp_gdi_render_point* points,
                                          uint32_t count,
                                          int32_t x,
                                          int32_t y,
                                          uint32_t fill_mode)
{
    uint32_t i = 0;
    uint32_t j = 0;
    int alternate = 0;
    int winding = 0;
    int64_t px2 = ((int64_t)x * 2) + 1;
    int64_t py2 = ((int64_t)y * 2) + 1;

    if (!points || count < 3)
        return 0;
    j = count - 1u;
    for (i = 0; i < count; i++)
    {
        int64_t xi2 = (int64_t)points[i].x * 2;
        int64_t yi2 = (int64_t)points[i].y * 2;
        int64_t xj2 = (int64_t)points[j].x * 2;
        int64_t yj2 = (int64_t)points[j].y * 2;

        if ((yi2 > py2) != (yj2 > py2))
        {
            int64_t lhs = (px2 - xi2) * (yj2 - yi2);
            int64_t rhs = (xj2 - xi2) * (py2 - yi2);
            int crosses = yj2 > yi2 ? lhs < rhs : lhs > rhs;

            if (crosses)
            {
                alternate = !alternate;
                winding += yj2 > yi2 ? 1 : -1;
            }
        }
        j = i;
    }
    if (fill_mode == 2u)
        return winding != 0;
    return alternate;
}

/*
 * Render a GDI polygon fill order. Point arrays, fill mode, brush selection,
 * and clip state are validated before scan conversion touches the surface.
 */
static librdp_status rdp_session_gdi_fill_polygon(librdp_session* session, const rdp_gdi_render_op* op)
{
    rdp_gdi_render_point points[RDP_GDI_RENDER_MAX_POINTS + 1u];
    uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;
    uint32_t count = 0;
    uint32_t i = 0;
    int32_t x = 0;
    int32_t y = 0;
    int32_t min_x = INT32_MAX;
    int32_t min_y = INT32_MAX;
    int32_t max_x = INT32_MIN;
    int32_t max_y = INT32_MIN;
    uint32_t dirty_left = UINT32_MAX;
    uint32_t dirty_top = UINT32_MAX;
    uint32_t dirty_right = 0;
    uint32_t dirty_bottom = 0;

    if (!session || !op)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (op->point_count == 0 || op->point_count > RDP_GDI_RENDER_MAX_POINTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    surface_width = librdp_surface_width(session->surface);
    surface_height = librdp_surface_height(session->surface);
    if (!pixels || stride == 0 || surface_width == 0 || surface_height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    x = op->rect.x;
    y = op->rect.y;
    points[0].x = x;
    points[0].y = y;
    count = op->point_count + 1u;
    for (i = 0; i < op->point_count; i++)
    {
        x += op->points[i].x;
        y += op->points[i].y;
        points[i + 1u].x = x;
        points[i + 1u].y = y;
    }
    for (i = 0; i < count; i++)
    {
        if (points[i].x < min_x)
            min_x = points[i].x;
        if (points[i].x > max_x)
            max_x = points[i].x;
        if (points[i].y < min_y)
            min_y = points[i].y;
        if (points[i].y > max_y)
            max_y = points[i].y;
    }
    if (min_x < 0)
        min_x = 0;
    if (min_y < 0)
        min_y = 0;
    if (max_x >= (int32_t)surface_width)
        max_x = (int32_t)surface_width - 1;
    if (max_y >= (int32_t)surface_height)
        max_y = (int32_t)surface_height - 1;
    if (min_x > max_x || min_y > max_y)
        return LIBRDP_STATUS_OK;
    for (y = min_y; y <= max_y; y++)
    {
        for (x = min_x; x <= max_x; x++)
        {
            uint8_t* pixel = NULL;

            if (!rdp_session_gdi_shape_point_visible(op, x, y, surface_width, surface_height) ||
                !rdp_session_gdi_polygon_inside(points, count, x, y, op->fill_mode))
                continue;
            pixel = pixels + ((size_t)(uint32_t)y * stride) + ((size_t)(uint32_t)x * 4u);
            rdp_session_gdi_plot_rop2_pixel(session, pixel, op, (uint32_t)x, (uint32_t)y);
            if ((uint32_t)x < dirty_left)
                dirty_left = (uint32_t)x;
            if ((uint32_t)y < dirty_top)
                dirty_top = (uint32_t)y;
            if ((uint32_t)x + 1u > dirty_right)
                dirty_right = (uint32_t)x + 1u;
            if ((uint32_t)y + 1u > dirty_bottom)
                dirty_bottom = (uint32_t)y + 1u;
        }
    }
    if (dirty_left < dirty_right && dirty_top < dirty_bottom)
        rdp_session_emit_surface_invalidated(session,
                                             dirty_left,
                                             dirty_top,
                                             dirty_right - dirty_left,
                                             dirty_bottom - dirty_top);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.order.apply",
                          "type=%u kind=%u x=%d y=%d points=%u fill_mode=%u rop2=%u color=%06x dirty=%u",
                          op->order_type,
                          op->kind,
                          op->rect.x,
                          op->rect.y,
                          op->point_count,
                          op->fill_mode,
                          op->rop,
                          op->color & 0x00ffffffu,
                          dirty_left < dirty_right);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_fill_ellipse(librdp_session* session, const rdp_gdi_render_op* op)
{
    uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;
    rdp_session_gdi_region region;
    uint32_t x = 0;
    uint32_t y = 0;
    double width = 0.0;
    double height = 0.0;

    if (!session || !op)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_session_gdi_clip_dest(op,
                                   librdp_surface_width(session->surface),
                                   librdp_surface_height(session->surface),
                                   &region))
        return LIBRDP_STATUS_OK;
    pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    surface_width = librdp_surface_width(session->surface);
    surface_height = librdp_surface_height(session->surface);
    if (!pixels || stride == 0 || surface_width == 0 || surface_height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    width = (double)op->rect.width;
    height = (double)op->rect.height;
    for (y = 0; y < region.height; y++)
    {
        for (x = 0; x < region.width; x++)
        {
            uint32_t absolute_x = region.dst_x + x;
            uint32_t absolute_y = region.dst_y + y;
            double dx = (((double)(int32_t)absolute_x - (double)op->rect.x) + 0.5) * 2.0 - width;
            double dy = (((double)(int32_t)absolute_y - (double)op->rect.y) + 0.5) * 2.0 - height;
            uint8_t* pixel = NULL;

            if (!rdp_session_gdi_shape_point_visible(op,
                                                     (int32_t)absolute_x,
                                                     (int32_t)absolute_y,
                                                     surface_width,
                                                     surface_height) ||
                ((dx * dx) / (width * width) + (dy * dy) / (height * height)) > 0.25)
                continue;
            pixel = pixels + ((size_t)absolute_y * stride) + ((size_t)absolute_x * 4u);
            rdp_session_gdi_plot_rop2_pixel(session, pixel, op, absolute_x, absolute_y);
        }
    }
    rdp_session_emit_surface_invalidated(session, region.dst_x, region.dst_y, region.width, region.height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.order.apply",
                          "type=%u kind=%u x=%u y=%u width=%u height=%u fill_mode=%u rop2=%u color=%06x",
                          op->order_type,
                          op->kind,
                          region.dst_x,
                          region.dst_y,
                          region.width,
                          region.height,
                          op->fill_mode,
                          op->rop,
                          op->color & 0x00ffffffu);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_apply_gdi_render_op(librdp_session* session, const rdp_gdi_render_op* op);

/*
 * Apply the core GDI raster operation between source, pattern, and destination
 * pixels. Keeping the operation table centralized avoids divergent rendering
 * behavior across order types.
 */
static librdp_status rdp_session_apply_gdi_render_op_core(librdp_session* session, const rdp_gdi_render_op* op)
{
    rdp_session_gdi_region region;
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;

    if (!session || !op)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    surface_width = librdp_surface_width(session->surface);
    surface_height = librdp_surface_height(session->surface);
    memset(&region, 0, sizeof(region));
    if (op->kind == RDP_GDI_RENDER_OP_OPAQUE_RECT)
    {
        if (!rdp_session_gdi_clip_dest(op, surface_width, surface_height, &region))
            return LIBRDP_STATUS_OK;
        return rdp_session_gdi_fill_rect(session, op, &region, 0, op->color, 0);
    }
    if (op->kind == RDP_GDI_RENDER_OP_DSTBLT)
    {
        if (op->rop == 0xaau)
            return LIBRDP_STATUS_OK;
        if (!rdp_session_gdi_clip_dest(op, surface_width, surface_height, &region))
            return LIBRDP_STATUS_OK;
        return rdp_session_gdi_fill_rect(session, op, &region, op->rop, 0, 1);
    }
    if (op->kind == RDP_GDI_RENDER_OP_PATBLT)
    {
        if (!rdp_session_gdi_clip_dest(op, surface_width, surface_height, &region))
            return LIBRDP_STATUS_OK;
        return rdp_session_gdi_patblt(session, op, &region);
    }
    if (op->kind == RDP_GDI_RENDER_OP_SCRBLT)
    {
        if (!rdp_session_gdi_clip_copy(op, surface_width, surface_height, &region))
            return LIBRDP_STATUS_OK;
        return rdp_session_gdi_copy_rect(session, op, &region);
    }
    if (op->kind == RDP_GDI_RENDER_OP_MEMBLT || op->kind == RDP_GDI_RENDER_OP_MEM3BLT)
    {
        rdp_session_gdi_bitmap_cache_entry* entry =
            rdp_session_gdi_bitmap_cache_find(session, op->cache_id, op->cache_index);

        if (entry &&
            rdp_session_gdi_clip_bitmap_copy(op,
                                             surface_width,
                                             surface_height,
                                             entry->width,
                                             entry->height,
                                             &region))
            return rdp_session_gdi_copy_cached_bitmap(session, op, entry, &region);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.bitmap_cache.miss",
                              "kind=%u cache_id=%u color_index=%u cache_index=%u x=%d y=%d width=%d height=%d src_x=%d src_y=%d rop=%u",
                              op->kind,
                              op->cache_id,
                              op->color_index,
                              op->cache_index,
                              op->rect.x,
                              op->rect.y,
                              op->rect.width,
                              op->rect.height,
                              op->src_x,
                              op->src_y,
                              op->rop);
        return LIBRDP_STATUS_OK;
    }
    if (op->kind == RDP_GDI_RENDER_OP_DRAW_NINEGRID)
        return rdp_session_gdi_draw_ninegrid(session, op);
    if (op->kind == RDP_GDI_RENDER_OP_GLYPH)
        return rdp_session_gdi_draw_glyphs(session, op);
    if (op->kind == RDP_GDI_RENDER_OP_LINE)
        return rdp_session_gdi_draw_line(session, op);
    if (op->kind == RDP_GDI_RENDER_OP_POLYLINE)
        return rdp_session_gdi_draw_polyline(session, op);
    if (op->kind == RDP_GDI_RENDER_OP_POLYGON_SC || op->kind == RDP_GDI_RENDER_OP_POLYGON_CB)
        return rdp_session_gdi_fill_polygon(session, op);
    if (op->kind == RDP_GDI_RENDER_OP_ELLIPSE_SC || op->kind == RDP_GDI_RENDER_OP_ELLIPSE_CB)
        return rdp_session_gdi_fill_ellipse(session, op);
    if (op->kind == RDP_GDI_RENDER_OP_SAVE_BITMAP)
    {
        if (!rdp_session_gdi_clip_dest(op, surface_width, surface_height, &region))
            return LIBRDP_STATUS_OK;
        if (op->operation == 0u)
            return rdp_session_gdi_save_bitmap(session, op, &region);
        if (op->operation == 1u)
            return rdp_session_gdi_restore_bitmap(session, op, &region);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (op->kind == RDP_GDI_RENDER_OP_MULTIDSTBLT ||
        op->kind == RDP_GDI_RENDER_OP_MULTIPATBLT ||
        op->kind == RDP_GDI_RENDER_OP_MULTISCRBLT ||
        op->kind == RDP_GDI_RENDER_OP_MULTIOPAQUE_RECT ||
        op->kind == RDP_GDI_RENDER_OP_MULTI_DRAW_NINEGRID)
    {
        uint32_t i = 0;
        librdp_status status = LIBRDP_STATUS_OK;

        if (op->rect_count > RDP_GDI_RENDER_MAX_RECTS)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (i = 0; i < op->rect_count; i++)
        {
            rdp_gdi_render_op single = *op;

            single.rect = op->rects[i];
            single.rect_count = 0;
            if (op->kind == RDP_GDI_RENDER_OP_MULTIDSTBLT)
                single.kind = RDP_GDI_RENDER_OP_DSTBLT;
            else if (op->kind == RDP_GDI_RENDER_OP_MULTIPATBLT)
                single.kind = RDP_GDI_RENDER_OP_PATBLT;
            else if (op->kind == RDP_GDI_RENDER_OP_MULTIOPAQUE_RECT)
                single.kind = RDP_GDI_RENDER_OP_OPAQUE_RECT;
            else if (op->kind == RDP_GDI_RENDER_OP_MULTISCRBLT)
            {
                single.kind = RDP_GDI_RENDER_OP_SCRBLT;
                single.src_x = op->src_x + (op->rects[i].x - op->rect.x);
                single.src_y = op->src_y + (op->rects[i].y - op->rect.y);
            }
            else
                single.kind = RDP_GDI_RENDER_OP_DRAW_NINEGRID;
            status = rdp_session_apply_gdi_render_op(session, &single);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.order.apply",
                              "type=%u kind=%u rects=%u rop=%u color=%06x",
                              op->order_type,
                              op->kind,
                              op->rect_count,
                              op->rop,
                              op->color & 0x00ffffffu);
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_session_apply_gdi_render_op(librdp_session* session, const rdp_gdi_render_op* op)
{
    librdp_surface* primary = NULL;
    librdp_surface* target = NULL;
    uint8_t previous_offscreen = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !op)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    primary = session->surface;
    target = rdp_session_gdi_target_surface(session);
    if (!primary || !target)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    previous_offscreen = session->gdi_drawing_to_offscreen;
    if (target != primary)
    {
        session->surface = target;
        session->gdi_drawing_to_offscreen = 1;
    }
    status = rdp_session_apply_gdi_render_op_core(session, op);
    session->surface = primary;
    session->gdi_drawing_to_offscreen = previous_offscreen;
    return status;
}

typedef struct rdp_session_gdi_rfx_cache_context
{
    rdp_buffer* pixels;
    uint32_t width;
    uint32_t height;
    size_t stride;
    uint16_t tiles;
} rdp_session_gdi_rfx_cache_context;

static librdp_status rdp_session_gdi_rfx_cache_tile(const rdp_rfx_stream_tile* tile, void* user)
{
    rdp_session_gdi_rfx_cache_context* context = (rdp_session_gdi_rfx_cache_context*)user;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t y = 0;

    if (!tile || !context || !context->pixels || !context->pixels->data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (tile->x >= context->width || tile->y >= context->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    width = tile->width;
    height = tile->height;
    if (width > context->width - tile->x)
        width = context->width - tile->x;
    if (height > context->height - tile->y)
        height = context->height - tile->y;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (y = 0; y < height; y++)
    {
        memcpy(context->pixels->data + (((size_t)(tile->y + y) * context->stride) + ((size_t)tile->x * 4u)),
               tile->pixels.bgra + ((size_t)y * tile->pixels.stride),
               (size_t)width * 4u);
    }
    if (context->tiles < UINT16_MAX)
        context->tiles++;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_decode_rfx_cache_bitmap(const rdp_gdi_cache_bitmap_order* order,
                                                             rdp_buffer* pixels,
                                                             size_t* stride)
{
    rdp_session_gdi_rfx_cache_context context;
    rdp_rfx_stream_summary summary;
    size_t length = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!order || !pixels || !stride || !order->bitmap_data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (order->width == 0 || order->height == 0 || order->width > UINT16_MAX ||
        order->height > UINT16_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *stride = (size_t)order->width * 4u;
    length = *stride * (size_t)order->height;
    status = rdp_buffer_reserve(pixels, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(pixels->data, 0, length);
    pixels->length = length;
    memset(&context, 0, sizeof(context));
    memset(&summary, 0, sizeof(summary));
    context.pixels = pixels;
    context.width = order->width;
    context.height = order->height;
    context.stride = *stride;
    status = rdp_rfx_stream_decode(order->bitmap_data,
                                   order->bitmap_data_len,
                                   rdp_session_gdi_rfx_cache_tile,
                                   &context,
                                   &summary);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (context.tiles == 0 || summary.tile_count == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.bitmap_cache.rfx_decode",
                          "cache_id=%u cache_index=%u width=%u height=%u frame_id=%u tiles=%u decoded_tiles=%u",
                          order->cache_id,
                          order->cache_index,
                          order->width,
                          order->height,
                          summary.frame_id,
                          summary.tile_count,
                          context.tiles);
    return LIBRDP_STATUS_OK;
}

/*
 * Store a decoded GDI bitmap into the session bitmap cache. Cell selection,
 * dimensions, and pixel ownership are finalized before later drawing orders
 * can reference the cache entry.
 */
static librdp_status rdp_session_gdi_store_cache_bitmap(librdp_session* session,
                                                        const rdp_gdi_cache_bitmap_order* order)
{
    rdp_bitmap_rect rect;
    rdp_buffer pixels;
    rdp_buffer raw;
    size_t stride = 0;
    size_t old_size = 0;
    size_t current_without_old = 0;
    size_t new_size = 0;
    rdp_session_gdi_bitmap_cache_entry* entry = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !order || !order->bitmap_data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (order->do_not_cache && !order->rev3)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.bitmap_cache.skip",
                              "cache_id=%u cache_index=%u width=%u height=%u bpp=%u",
                              order->cache_id,
                              order->cache_index,
                              order->width,
                              order->height,
                              order->bits_per_pixel);
        return LIBRDP_STATUS_OK;
    }
    if (order->width == 0 || order->height == 0 ||
        order->width > UINT16_MAX || order->height > UINT16_MAX ||
        order->bits_per_pixel > UINT16_MAX || order->bitmap_data_len > UINT32_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(&rect, 0, sizeof(rect));
    rect.dest_left = 0;
    rect.dest_top = 0;
    rect.dest_right = (uint16_t)(order->width - 1u);
    rect.dest_bottom = (uint16_t)(order->height - 1u);
    rect.width = (uint16_t)order->width;
    rect.height = (uint16_t)order->height;
    rect.bits_per_pixel = (uint16_t)order->bits_per_pixel;
    rect.flags = order->compressed ? RDP_SESSION_BITMAP_FLAG_COMPRESSED : 0;
    if (order->compressed && !order->bitmap_data_includes_compression_header)
        rect.flags |= RDP_GDI_NO_BITMAP_COMPRESSION_HEADER;
    rect.data = order->bitmap_data;
    rect.data_len = order->bitmap_data_len;

    rdp_buffer_init(&pixels);
    rdp_buffer_init(&raw);
    if (order->rev3 && order->codec_id == RDP_SURFACE_CODEC_NSCODEC)
    {
        status = rdp_nscodec_decode_bgra32(&session->surface_nscodec,
                                           order->bitmap_data,
                                           order->bitmap_data_len,
                                           order->width,
                                           order->height,
                                           &pixels,
                                           &stride);
    }
    else if (order->rev3 &&
             (order->codec_id == RDP_SURFACE_CODEC_REMOTEFX ||
              order->codec_id == RDP_SURFACE_CODEC_IMAGE_REMOTEFX))
    {
        status = rdp_session_gdi_decode_rfx_cache_bitmap(order, &pixels, &stride);
    }
    else if (order->bits_per_pixel == 8u)
    {
        status = rdp_buffer_append(&raw, order->bitmap_data, order->bitmap_data_len);
    }
    else
    {
        status = rdp_bitmap_decode_rect_bgra32_with_palette(&rect,
                                                            session->palette_valid ? &session->palette : NULL,
                                                            &pixels,
                                                            &stride);
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&pixels);
        rdp_buffer_free(&raw);
        return status;
    }
    new_size = pixels.length + raw.length;
    if (new_size < pixels.length || new_size > RDP_SESSION_GDI_BITMAP_CACHE_MAX_BYTES)
    {
        rdp_buffer_free(&pixels);
        rdp_buffer_free(&raw);
        return LIBRDP_STATUS_NO_MEMORY;
    }

    entry = rdp_session_gdi_bitmap_cache_slot(session, order->cache_id, order->cache_index);
    if (!entry)
    {
        rdp_buffer_free(&pixels);
        rdp_buffer_free(&raw);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    old_size = rdp_session_gdi_bitmap_cache_entry_size(entry);
    current_without_old = session->gdi_bitmap_cache_bytes >= old_size ?
                          session->gdi_bitmap_cache_bytes - old_size :
                          0;
    while (current_without_old > RDP_SESSION_GDI_BITMAP_CACHE_MAX_BYTES - new_size)
    {
        size_t index = rdp_session_gdi_bitmap_cache_lru(session, entry);

        if (index >= RDP_SESSION_GDI_BITMAP_CACHE_SLOTS)
        {
            rdp_buffer_free(&pixels);
            rdp_buffer_free(&raw);
            return LIBRDP_STATUS_NO_MEMORY;
        }
        rdp_session_gdi_bitmap_cache_evict(session, index);
        current_without_old = session->gdi_bitmap_cache_bytes >= old_size ?
                              session->gdi_bitmap_cache_bytes - old_size :
                              session->gdi_bitmap_cache_bytes;
    }
    rdp_buffer_free(&entry->pixels);
    rdp_buffer_free(&entry->raw);
    entry->pixels = pixels;
    entry->raw = raw;
    entry->active = 1;
    entry->cache_id = order->cache_id;
    entry->cache_index = order->cache_index;
    entry->width = order->width;
    entry->height = order->height;
    entry->bits_per_pixel = order->bits_per_pixel;
    entry->bitmap_flags = rect.flags;
    entry->stride = stride;
    entry->last_used = ++session->gdi_bitmap_cache_clock;
    session->gdi_bitmap_cache_bytes = current_without_old + new_size;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.bitmap_cache.store",
                          "cache_id=%u cache_index=%u width=%u height=%u bpp=%u compressed=%u decoded_bytes=%u raw_bytes=%u total_bytes=%u",
                          order->cache_id,
                          order->cache_index,
                          order->width,
                          order->height,
                          order->bits_per_pixel,
                          order->compressed,
                          (unsigned)entry->pixels.length,
                          (unsigned)entry->raw.length,
                          (unsigned)session->gdi_bitmap_cache_bytes);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_apply_gdi_secondary_order(librdp_session* session,
                                                           const rdp_gdi_secondary_order_header* header)
{
    rdp_gdi_cache_bitmap_order bitmap;
    rdp_gdi_cache_color_table_order color_table;
    rdp_gdi_cache_brush_order brush;
    rdp_gdi_cache_glyph_order glyphs;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t i = 0;

    if (!session || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED ||
        header->order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED ||
        header->order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED_REV2 ||
        header->order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV2 ||
        header->order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV3)
    {
        status = rdp_gdi_parse_cache_bitmap_order(header, &bitmap);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_gdi_store_cache_bitmap(session, &bitmap);
        return status;
    }
    if (header->order_type == RDP_GDI_SECONDARY_CACHE_COLOR_TABLE)
    {
        status = rdp_gdi_parse_cache_color_table_order(header, &color_table);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_gdi_color_table_store(session, &color_table);
        return status;
    }
    if (header->order_type == RDP_GDI_SECONDARY_CACHE_BRUSH)
    {
        status = rdp_gdi_parse_cache_brush_order(header, &brush);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_gdi_store_cache_brush(session, &brush);
        return status;
    }
    if (header->order_type == RDP_GDI_SECONDARY_CACHE_GLYPH)
    {
        status = rdp_gdi_parse_cache_glyph_order(header, &glyphs);
        if (status != LIBRDP_STATUS_OK)
            return status;
        for (i = 0; i < glyphs.glyph_count; i++)
        {
            status = rdp_session_gdi_glyph_cache_store(session, glyphs.cache_id, &glyphs.glyphs[i]);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.glyph_cache.order",
                              "cache_id=%u version=%u glyphs=%u flags=%u",
                              glyphs.cache_id,
                              glyphs.version,
                              glyphs.glyph_count,
                              glyphs.flags);
        return LIBRDP_STATUS_OK;
    }
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "rdp.gdi.secondary.rejected",
                          "order_type=%u payload_len=%u",
                          header->order_type,
                          (unsigned)header->payload_len);
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

/*
 * Apply alternate secondary GDI orders such as cache and glyph updates. The
 * dispatcher validates order type and payload length before mutating any GDI
 * cache.
 */
static librdp_status rdp_session_apply_gdi_altsec_order(librdp_session* session,
                                                        const rdp_gdi_altsec_order_header* header)
{
    rdp_gdi_create_ninegrid_bitmap_order order;
    rdp_gdi_create_offscreen_bitmap_order offscreen;
    rdp_gdi_switch_surface_order switch_surface;
    rdp_gdi_frame_marker_order frame_marker;
    rdp_gdi_stream_bitmap_first_order stream_first;
    rdp_gdi_stream_bitmap_next_order stream_next;
    rdp_session_gdi_ninegrid_cache_entry* entry = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->order_type == RDP_GDI_ALTSEC_CREATE_OFFSCREEN_BITMAP)
    {
        status = rdp_gdi_parse_create_offscreen_bitmap_order(header, &offscreen);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_session_gdi_create_offscreen_bitmap(session, &offscreen);
    }
    if (header->order_type == RDP_GDI_ALTSEC_SWITCH_SURFACE)
    {
        status = rdp_gdi_parse_switch_surface_order(header, &switch_surface);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_session_gdi_switch_surface(session, switch_surface.bitmap_id);
    }
    if (header->order_type == RDP_GDI_ALTSEC_CREATE_NINEGRID_BITMAP)
    {
        status = rdp_gdi_parse_create_ninegrid_bitmap_order(header, &order);
        if (status != LIBRDP_STATUS_OK)
            return status;
        entry = rdp_session_gdi_ninegrid_cache_slot(session, order.bitmap_id);
        if (!entry)
            return LIBRDP_STATUS_NO_MEMORY;
        memset(entry, 0, sizeof(*entry));
        entry->active = 1;
        entry->bitmap_id = order.bitmap_id;
        entry->bits_per_pixel = order.bits_per_pixel;
        entry->info = order.info;
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.ninegrid.store",
                              "bitmap_id=%u bpp=%u left=%u right=%u top=%u bottom=%u flags=%u",
                              entry->bitmap_id,
                              entry->bits_per_pixel,
                              entry->info.left_width,
                              entry->info.right_width,
                              entry->info.top_height,
                              entry->info.bottom_height,
                              entry->info.flags);
        return LIBRDP_STATUS_OK;
    }
    if (header->order_type == RDP_GDI_ALTSEC_FRAME_MARKER)
    {
        status = rdp_gdi_parse_frame_marker_order(header, &frame_marker);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (frame_marker.action == 0u)
        {
            if (session->graphics_frame_active)
                rdp_session_graphics_dirty_flush(session);
            session->graphics_frame_active = 1;
            session->graphics_dirty_pending = 0;
            session->graphics_current_frame_id++;
            rdp_session_emit_graphics_frame(session,
                                            LIBRDP_GRAPHICS_UPDATE_FRAME_BEGIN,
                                            session->graphics_current_frame_id);
        }
        else if (frame_marker.action == 1u)
        {
            session->graphics_frame_active = 0;
            rdp_session_graphics_dirty_flush(session);
            session->graphics_frames_decoded++;
            rdp_session_metric_add(&session->metrics.frames, 1);
            rdp_session_emit_graphics_frame(session,
                                            LIBRDP_GRAPHICS_UPDATE_FRAME_END,
                                            session->graphics_current_frame_id);
        }
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.frame_marker",
                              "action=%u frame_id=%u active=%u",
                              frame_marker.action,
                              session->graphics_current_frame_id,
                              session->graphics_frame_active ? 1u : 0u);
        return LIBRDP_STATUS_OK;
    }
    if (header->order_type == RDP_GDI_ALTSEC_STREAM_BITMAP_FIRST)
    {
        status = rdp_gdi_parse_stream_bitmap_first_order(header, &stream_first);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_session_gdi_stream_bitmap_first(session, &stream_first);
    }
    if (header->order_type == RDP_GDI_ALTSEC_STREAM_BITMAP_NEXT)
    {
        status = rdp_gdi_parse_stream_bitmap_next_order(header, &stream_next);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_session_gdi_stream_bitmap_next(session, &stream_next);
    }
    if (header->order_type == RDP_GDI_ALTSEC_COMPDESK_FIRST)
    {
        session->desktop_composition_active = 1;
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.desktop_composition.order",
                              "payload_len=%u",
                              (unsigned)header->payload_len);
        return LIBRDP_STATUS_OK;
    }
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "rdp.gdi.altsec.rejected",
                          "order_type=%u payload_len=%u",
                          header->order_type,
                          (unsigned)header->payload_len);
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_session_apply_gdi_orders_update(librdp_session* session, const rdp_gdi_orders_update* update)
{
    size_t offset = 0;
    uint16_t i = 0;

    if (!session || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < update->number_orders; i++)
    {
        rdp_gdi_render_op op;
        rdp_gdi_secondary_order_header secondary;
        rdp_gdi_altsec_order_header altsec;
        size_t consumed = 0;
        librdp_status status = LIBRDP_STATUS_OK;

        if (offset >= update->order_data_len)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if ((update->order_data[offset] & (RDP_GDI_TS_STANDARD | RDP_GDI_TS_SECONDARY)) ==
            (RDP_GDI_TS_STANDARD | RDP_GDI_TS_SECONDARY))
        {
            status = rdp_gdi_parse_secondary_order(update->order_data + offset,
                                                   update->order_data_len - offset,
                                                   &secondary);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_apply_gdi_secondary_order(session, &secondary);
            if (status != LIBRDP_STATUS_OK)
                return status;
            offset += secondary.actual_length;
            continue;
        }
        if ((update->order_data[offset] & 0x03u) == RDP_GDI_TS_SECONDARY)
        {
            status = rdp_gdi_parse_altsec_order(update->order_data + offset,
                                                update->order_data_len - offset,
                                                &altsec);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_apply_gdi_altsec_order(session, &altsec);
            if (status != LIBRDP_STATUS_OK)
                return status;
            offset += altsec.actual_length;
            continue;
        }
        status = rdp_gdi_decode_primary_render_order(&session->gdi_render,
                                                     update->order_data + offset,
                                                     update->order_data_len - offset,
                                                     &op,
                                                     &consumed);
        if (status == LIBRDP_STATUS_UNSUPPORTED)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.gdi.order.rejected",
                            "index=%u remaining=%u",
                            i,
                            (unsigned)(update->order_data_len - offset));
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (status != LIBRDP_STATUS_OK || consumed == 0 || consumed > update->order_data_len - offset)
            return status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_PROTOCOL_ERROR : status;
        status = rdp_session_apply_gdi_render_op(session, &op);
        if (status != LIBRDP_STATUS_OK)
            return status;
        offset += consumed;
    }
    if (offset != update->order_data_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "rdp.gdi.orders",
                    "count=%u payload_len=%u",
                    update->number_orders,
                    (unsigned)update->order_data_len);
    return LIBRDP_STATUS_OK;
}
