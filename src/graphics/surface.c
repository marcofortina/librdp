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

    pixels = (uint8_t*)calloc(1, size);
    if (!pixels)
        return LIBRDP_STATUS_NO_MEMORY;

    free(surface->pixels);
    surface->pixels = pixels;
    surface->width = width;
    surface->height = height;
    surface->stride = stride;
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
