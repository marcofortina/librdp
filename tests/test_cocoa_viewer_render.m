/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: headless Cocoa viewer presentation tests.
 * Coverage: public surface mapping, BGRA CoreGraphics presentation, surface
 * resize, exact pixel preservation, and mapping cleanup.
 * Bug classes: stale mappings, stride confusion, channel-order conversion,
 * blank frames, resize lifetime errors, and unchecked destination geometry.
 * Determinism: all drawing targets private in-memory bitmap contexts and does
 * not require AppKit, a window server, or screen capture permission.
 */

#include "cocoa_render.h"

#include <CoreGraphics/CoreGraphics.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct test_bitmap
{
    uint8_t* pixels;
    size_t bytes;
    size_t stride;
    uint32_t width;
    uint32_t height;
    CGColorSpaceRef color_space;
    CGContextRef context;
} test_bitmap;

static int test_check(int condition,
                      const char* expression,
                      int line)
{
    if (!condition)
    {
        fprintf(stderr,
                "test_cocoa_viewer_render:%d: check failed: %s\n",
                line,
                expression);
    }
    return condition;
}

/* Allocate a private BGRA bitmap context with deterministic zeroed storage. */
static int test_bitmap_init(test_bitmap* bitmap,
                            uint32_t width,
                            uint32_t height)
{
    CGBitmapInfo bitmap_info =
        (CGBitmapInfo)((uint32_t)kCGBitmapByteOrder32Little |
                       (uint32_t)kCGImageAlphaNoneSkipFirst);

    if (!bitmap || width == 0u || height == 0u ||
        width > (uint32_t)(SIZE_MAX / 4u))
        return 0;
    memset(bitmap, 0, sizeof(*bitmap));
    bitmap->width = width;
    bitmap->height = height;
    bitmap->stride = (size_t)width * 4u;
    if (bitmap->stride > SIZE_MAX / (size_t)height)
        return 0;
    bitmap->bytes = bitmap->stride * (size_t)height;
    bitmap->pixels = (uint8_t*)calloc(1u, bitmap->bytes);
    bitmap->color_space = CGColorSpaceCreateDeviceRGB();
    if (!bitmap->pixels || !bitmap->color_space)
    {
        if (bitmap->color_space)
            CGColorSpaceRelease(bitmap->color_space);
        free(bitmap->pixels);
        memset(bitmap, 0, sizeof(*bitmap));
        return 0;
    }
    bitmap->context = CGBitmapContextCreate(
        bitmap->pixels,
        width,
        height,
        8u,
        bitmap->stride,
        bitmap->color_space,
        bitmap_info);
    if (!bitmap->context)
    {
        CGColorSpaceRelease(bitmap->color_space);
        free(bitmap->pixels);
        memset(bitmap, 0, sizeof(*bitmap));
        return 0;
    }
    return 1;
}

/* Release all CoreGraphics and byte storage owned by one test bitmap. */
static void test_bitmap_clear(test_bitmap* bitmap)
{
    if (!bitmap)
        return;
    if (bitmap->context)
        CGContextRelease(bitmap->context);
    if (bitmap->color_space)
        CGColorSpaceRelease(bitmap->color_space);
    free(bitmap->pixels);
    memset(bitmap, 0, sizeof(*bitmap));
}

/*
 * Populate a public surface through its write mapping. Distinct channels and
 * rows detect channel-order and stride mistakes in the presenter.
 */
static int test_fill_surface(librdp_surface* surface,
                             uint8_t seed)
{
    librdp_surface_mapping mapping;
    uint32_t y = 0u;
    uint32_t x = 0u;

    if (!test_check(surface != NULL, "surface != NULL", __LINE__) ||
        !test_check(
            librdp_surface_mapping_init(&mapping) ==
                LIBRDP_STATUS_OK,
            "surface mapping initializes",
            __LINE__) ||
        !test_check(
            librdp_surface_map(
                surface,
                LIBRDP_SURFACE_ACCESS_WRITE,
                &mapping) == LIBRDP_STATUS_OK,
            "surface write mapping succeeds",
            __LINE__))
        return 0;
    if (!test_check(
            mapping.writable_pixels != NULL,
            "write mapping has pixels",
            __LINE__))
    {
        (void)librdp_surface_unmap(surface, &mapping);
        return 0;
    }
    for (y = 0u; y < mapping.height; y++)
    {
        for (x = 0u; x < mapping.width; x++)
        {
            size_t offset =
                (size_t)y * mapping.stride + (size_t)x * 4u;

            mapping.writable_pixels[offset] =
                (uint8_t)(seed + x * 3u + y * 5u);
            mapping.writable_pixels[offset + 1u] =
                (uint8_t)(seed + 31u + x * 7u + y * 2u);
            mapping.writable_pixels[offset + 2u] =
                (uint8_t)(seed + 67u + x * 2u + y * 11u);
            mapping.writable_pixels[offset + 3u] = 0xffu;
        }
    }
    return test_check(
        librdp_surface_unmap(surface, &mapping) ==
            LIBRDP_STATUS_OK,
        "surface write mapping closes",
        __LINE__);
}

/*
 * CoreGraphics may expose bitmap storage in either scanline orientation. Both
 * forms preserve the exact remote pixels; no other conversion is accepted.
 */
static int test_bitmap_matches_surface(
    const test_bitmap* bitmap,
    const librdp_surface* surface)
{
    const uint8_t* source = NULL;
    size_t source_stride = 0u;
    uint32_t y = 0u;
    int direct = 1;
    int flipped = 1;

    if (!bitmap || !surface ||
        bitmap->width != librdp_surface_width(surface) ||
        bitmap->height != librdp_surface_height(surface))
        return 0;
    source = librdp_surface_pixels(surface);
    source_stride = librdp_surface_stride(surface);
    if (!source || source_stride < bitmap->stride)
        return 0;
    for (y = 0u; y < bitmap->height; y++)
    {
        const uint8_t* output_row =
            bitmap->pixels + (size_t)y * bitmap->stride;
        const uint8_t* direct_row =
            source + (size_t)y * source_stride;
        const uint8_t* flipped_row =
            source +
            (size_t)(bitmap->height - 1u - y) * source_stride;

        if (memcmp(output_row, direct_row, bitmap->stride) != 0)
            direct = 0;
        if (memcmp(output_row, flipped_row, bitmap->stride) != 0)
            flipped = 0;
    }
    return direct || flipped;
}

/*
 * Render two generations with different dimensions. Successful resize after
 * the first draw proves the presenter released its read mapping.
 */
static int test_surface_present_and_resize(void)
{
    librdp_surface* surface =
        librdp_surface_new(
            7u,
            5u,
            LIBRDP_PIXEL_FORMAT_BGRA32);
    test_bitmap first;
    test_bitmap resized;
    int ok = 0;

    memset(&first, 0, sizeof(first));
    memset(&resized, 0, sizeof(resized));
    if (!surface ||
        !test_fill_surface(surface, 3u) ||
        !test_bitmap_init(&first, 7u, 5u))
        goto cleanup;
    if (!test_check(
            cocoa_render_surface(
                first.context,
                surface,
                CGRectMake(0.0, 0.0, 7.0, 5.0)) ==
                LIBRDP_STATUS_OK,
            "first presentation succeeds",
            __LINE__) ||
        !test_check(
            test_bitmap_matches_surface(&first, surface),
            "first presentation matches surface",
            __LINE__) ||
        !test_check(
            librdp_surface_resize(surface, 11u, 9u) ==
                LIBRDP_STATUS_OK,
            "resize succeeds after presentation",
            __LINE__) ||
        !test_fill_surface(surface, 89u) ||
        !test_bitmap_init(&resized, 11u, 9u) ||
        !test_check(
            cocoa_render_surface(
                resized.context,
                surface,
                CGRectMake(0.0, 0.0, 11.0, 9.0)) ==
                LIBRDP_STATUS_OK,
            "resized presentation succeeds",
            __LINE__) ||
        !test_check(
            test_bitmap_matches_surface(&resized, surface),
            "resized presentation matches surface",
            __LINE__))
        goto cleanup;
    ok = 1;

cleanup:
    test_bitmap_clear(&resized);
    test_bitmap_clear(&first);
    librdp_surface_free(surface);
    return ok;
}

/* Reject invalid contexts, surfaces, and destination geometry before mapping. */
static int test_invalid_presentation(void)
{
    librdp_surface* surface =
        librdp_surface_new(
            2u,
            2u,
            LIBRDP_PIXEL_FORMAT_BGRA32);
    test_bitmap bitmap;
    int ok = 0;

    memset(&bitmap, 0, sizeof(bitmap));
    if (!surface || !test_bitmap_init(&bitmap, 2u, 2u))
        goto cleanup;
    if (!test_check(
            cocoa_render_surface(
                NULL,
                surface,
                CGRectMake(0.0, 0.0, 2.0, 2.0)) ==
                LIBRDP_STATUS_INVALID_ARGUMENT,
            "NULL context is rejected",
            __LINE__) ||
        !test_check(
            cocoa_render_surface(
                bitmap.context,
                NULL,
                CGRectMake(0.0, 0.0, 2.0, 2.0)) ==
                LIBRDP_STATUS_INVALID_ARGUMENT,
            "NULL surface is rejected",
            __LINE__) ||
        !test_check(
            cocoa_render_surface(
                bitmap.context,
                surface,
                CGRectMake(0.0, 0.0, 0.0, 2.0)) ==
                LIBRDP_STATUS_INVALID_ARGUMENT,
            "empty destination is rejected",
            __LINE__))
        goto cleanup;
    ok = 1;

cleanup:
    test_bitmap_clear(&bitmap);
    librdp_surface_free(surface);
    return ok;
}

int main(void)
{
    if (!test_surface_present_and_resize())
        return 1;
    if (!test_invalid_presentation())
        return 1;
    return 0;
}
