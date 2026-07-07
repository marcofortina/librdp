#ifndef LIBRDP_SURFACE_H
#define LIBRDP_SURFACE_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct librdp_surface librdp_surface;

typedef enum librdp_pixel_format
{
    LIBRDP_PIXEL_FORMAT_BGRA32 = 1
} librdp_pixel_format;

librdp_surface* librdp_surface_new(uint32_t width, uint32_t height, librdp_pixel_format format);
void librdp_surface_free(librdp_surface* surface);
librdp_status librdp_surface_resize(librdp_surface* surface, uint32_t width, uint32_t height);
librdp_status librdp_surface_blit_bgra32(librdp_surface* surface,
                                         uint32_t x,
                                         uint32_t y,
                                         uint32_t width,
                                         uint32_t height,
                                         const uint8_t* pixels,
                                         size_t stride);
uint32_t librdp_surface_width(const librdp_surface* surface);
uint32_t librdp_surface_height(const librdp_surface* surface);
size_t librdp_surface_stride(const librdp_surface* surface);
librdp_pixel_format librdp_surface_format(const librdp_surface* surface);
const uint8_t* librdp_surface_pixels(const librdp_surface* surface);
uint8_t* librdp_surface_pixels_mut(librdp_surface* surface);

#ifdef __cplusplus
}
#endif

#endif
