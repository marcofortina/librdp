/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: software surface storage and dirty-region support.
 * Invariants: rectangles, strides, cache keys, and pixel formats are validated
 * before any surface mutation.
 * Ownership: decoded pixels and cache entries are owned by the caller or
 * session surface selected by the API.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: codec payloads, rectangles, and cache references are
 * untrusted server data.
 */


#include <librdp/surface.h>

#include <stdlib.h>
#include <string.h>

struct librdp_surface
{
    uint32_t width;
    uint32_t height;
    size_t stride;
    librdp_pixel_format format;
    uint8_t* pixels;
    uint32_t read_maps;
    uint32_t write_map;
    uint64_t generation;
};

static int rdp_surface_size(uint32_t width, uint32_t height, size_t* stride, size_t* size)
{
    size_t row = 0;

    if (!stride || !size || width == 0 || height == 0 || width > 8192 || height > 8192)
        return 0;
    row = (size_t)width * 4u;
    if (row / 4u != width)
        return 0;
    if ((size_t)height > ((size_t)-1) / row)
        return 0;
    *stride = row;
    *size = row * (size_t)height;
    return 1;
}

librdp_surface* librdp_surface_new(uint32_t width, uint32_t height, librdp_pixel_format format)
{
    librdp_surface* surface = NULL;

    if (format != LIBRDP_PIXEL_FORMAT_BGRA32)
        return NULL;

    surface = (librdp_surface*)calloc(1, sizeof(*surface));
    if (!surface)
        return NULL;

    surface->format = format;
    if (librdp_surface_resize(surface, width, height) != LIBRDP_STATUS_OK)
    {
        librdp_surface_free(surface);
        return NULL;
    }

    return surface;
}

void librdp_surface_free(librdp_surface* surface)
{
    if (!surface)
        return;
    free(surface->pixels);
    free(surface);
}

librdp_status librdp_surface_resize(librdp_surface* surface, uint32_t width, uint32_t height)
{
    size_t stride = 0;
    size_t size = 0;
    uint8_t* pixels = NULL;

    if (!surface || !rdp_surface_size(width, height, &stride, &size))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (surface->read_maps != 0 || surface->write_map != 0)
        return LIBRDP_STATUS_STATE;

    pixels = (uint8_t*)calloc(1, size);
    if (!pixels)
        return LIBRDP_STATUS_NO_MEMORY;

    free(surface->pixels);
    surface->pixels = pixels;
    surface->width = width;
    surface->height = height;
    surface->stride = stride;
    surface->generation++;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_surface_blit_bgra32(librdp_surface* surface,
                                         uint32_t x,
                                         uint32_t y,
                                         uint32_t width,
                                         uint32_t height,
                                         const uint8_t* pixels,
                                         size_t stride)
{
    uint32_t row = 0;

    if (!surface || !pixels || surface->format != LIBRDP_PIXEL_FORMAT_BGRA32)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (surface->read_maps != 0 || surface->write_map != 0)
        return LIBRDP_STATUS_STATE;
    if (width == 0 || height == 0 || x > surface->width || y > surface->height ||
        width > surface->width - x || height > surface->height - y)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (stride < (size_t)width * 4u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    for (row = 0; row < height; row++)
    {
        memcpy(surface->pixels + ((size_t)(y + row) * surface->stride) + ((size_t)x * 4u),
               pixels + ((size_t)row * stride),
               (size_t)width * 4u);
    }

    return LIBRDP_STATUS_OK;
}

uint32_t librdp_surface_width(const librdp_surface* surface)
{
    return surface ? surface->width : 0;
}

uint32_t librdp_surface_height(const librdp_surface* surface)
{
    return surface ? surface->height : 0;
}

size_t librdp_surface_stride(const librdp_surface* surface)
{
    return surface ? surface->stride : 0;
}

librdp_pixel_format librdp_surface_format(const librdp_surface* surface)
{
    return surface ? surface->format : 0;
}

const uint8_t* librdp_surface_pixels(const librdp_surface* surface)
{
    return surface ? surface->pixels : NULL;
}

uint8_t* librdp_surface_pixels_mut(librdp_surface* surface)
{
    return surface ? surface->pixels : NULL;
}

librdp_status librdp_surface_mapping_init(librdp_surface_mapping* mapping)
{
    if (!mapping)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(mapping, 0, sizeof(*mapping));
    mapping->version = LIBRDP_SURFACE_MAPPING_VERSION;
    mapping->size = (uint32_t)sizeof(*mapping);
    return LIBRDP_STATUS_OK;
}

static int rdp_surface_mapping_valid(const librdp_surface_mapping* mapping)
{
    const size_t min_size = offsetof(librdp_surface_mapping, generation) + sizeof(mapping->generation);

    return mapping && mapping->version == LIBRDP_SURFACE_MAPPING_VERSION && mapping->size >= min_size;
}

librdp_status librdp_surface_map(librdp_surface* surface,
                                 librdp_surface_access access,
                                 librdp_surface_mapping* mapping)
{
    if (!surface || !rdp_surface_mapping_valid(mapping))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (access != LIBRDP_SURFACE_ACCESS_READ && access != LIBRDP_SURFACE_ACCESS_WRITE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (mapping->pixels || mapping->writable_pixels)
        return LIBRDP_STATUS_STATE;
    if (access == LIBRDP_SURFACE_ACCESS_WRITE)
    {
        if (surface->read_maps != 0 || surface->write_map != 0)
            return LIBRDP_STATUS_STATE;
        surface->write_map = 1;
    }
    else
    {
        if (surface->write_map != 0 || surface->read_maps == UINT32_MAX)
            return LIBRDP_STATUS_STATE;
        surface->read_maps++;
    }

    mapping->access = access;
    mapping->format = surface->format;
    mapping->width = surface->width;
    mapping->height = surface->height;
    mapping->stride = surface->stride;
    mapping->pixels = surface->pixels;
    mapping->writable_pixels = access == LIBRDP_SURFACE_ACCESS_WRITE ? surface->pixels : NULL;
    mapping->generation = surface->generation;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_surface_unmap(librdp_surface* surface, librdp_surface_mapping* mapping)
{
    librdp_surface_access access;

    if (!surface || !rdp_surface_mapping_valid(mapping) || !mapping->pixels)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (mapping->generation != surface->generation || mapping->format != surface->format ||
        mapping->width != surface->width || mapping->height != surface->height ||
        mapping->stride != surface->stride)
        return LIBRDP_STATUS_STATE;

    access = mapping->access;
    if (access == LIBRDP_SURFACE_ACCESS_WRITE)
    {
        if (surface->write_map == 0 || mapping->writable_pixels != surface->pixels)
            return LIBRDP_STATUS_STATE;
        surface->write_map = 0;
    }
    else if (access == LIBRDP_SURFACE_ACCESS_READ)
    {
        if (surface->read_maps == 0 || mapping->writable_pixels != NULL)
            return LIBRDP_STATUS_STATE;
        surface->read_maps--;
    }
    else
    {
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }

    mapping->access = 0;
    mapping->format = 0;
    mapping->width = 0;
    mapping->height = 0;
    mapping->stride = 0;
    mapping->pixels = NULL;
    mapping->writable_pixels = NULL;
    mapping->generation = 0;
    return LIBRDP_STATUS_OK;
}
