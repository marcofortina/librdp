/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: compressed image decoding for GDI+ Image objects.
 * Invariants: decoded images are bounded BGRA32 buffers with checked dimensions
 * and stride. Ownership: successful decodes transfer pixels to the caller.
 * Threading: decoders keep no shared mutable state.
 * Trust boundary: encoded bytes originate from remote EMF+ object records.
 */

#ifndef RDP_GRAPHICS_GDI_IMAGE_H
#define RDP_GRAPHICS_GDI_IMAGE_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

typedef struct rdp_gdi_image
{
    uint8_t* pixels;
    uint32_t width;
    uint32_t height;
    size_t stride;
} rdp_gdi_image;

void rdp_gdi_image_init(rdp_gdi_image* image);
void rdp_gdi_image_clear(rdp_gdi_image* image);
librdp_status rdp_gdi_image_decode(const uint8_t* data, size_t length, rdp_gdi_image* image);

#if defined(RDP_HAVE_QUARTZ)
librdp_status rdp_gdi_image_decode_quartz(const uint8_t* data,
                                          size_t length,
                                          rdp_gdi_image* image);
#endif

#endif
