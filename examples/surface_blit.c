/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdint.h>
#include <stdio.h>

#include <librdp/librdp.h>

int main(void)
{
    static const uint8_t pixels[2u * 2u * 4u] = {
        0x00u, 0x00u, 0xffu, 0xffu,
        0x00u, 0xffu, 0x00u, 0xffu,
        0xffu, 0x00u, 0x00u, 0xffu,
        0xffu, 0xffu, 0xffu, 0xffu
    };
    librdp_surface* surface = librdp_surface_new(4u, 4u, LIBRDP_PIXEL_FORMAT_BGRA32);
    const uint8_t* framebuffer = NULL;
    librdp_status status;

    if (!surface)
        return 1;

    status = librdp_surface_blit_bgra32(surface, 1u, 1u, 2u, 2u, pixels, 2u * 4u);
    if (status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr, "blit failed: %s\n", librdp_status_string(status));
        librdp_surface_free(surface);
        return 1;
    }

    framebuffer = librdp_surface_pixels(surface);
    if (!framebuffer)
    {
        librdp_surface_free(surface);
        return 1;
    }

    printf("format=%d size=%ux%u first_dirty_b=%u\n",
           (int)librdp_surface_format(surface),
           librdp_surface_width(surface),
           librdp_surface_height(surface),
           framebuffer[librdp_surface_stride(surface) + 4u]);

    librdp_surface_free(surface);
    return 0;
}
