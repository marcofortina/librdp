/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared geometry and synchronization contract for the viewer pointer
 * integration fixture.
 */

#ifndef LIBRDP_TEST_VIEWER_POINTER_FIXTURE_H
#define LIBRDP_TEST_VIEWER_POINTER_FIXTURE_H

#include <stdint.h>

enum test_viewer_pointer_stage
{
    TEST_VIEWER_POINTER_LISTENING = 0,
    TEST_VIEWER_POINTER_DEFAULT = 1,
    TEST_VIEWER_POINTER_SHAPE = 2,
    TEST_VIEWER_POINTER_POSITION = 3,
    TEST_VIEWER_POINTER_CACHED = 4,
    TEST_VIEWER_POINTER_HIDDEN = 5,
    TEST_VIEWER_POINTER_MONOCHROME = 6,
    TEST_VIEWER_POINTER_COLOR = 7,
    TEST_VIEWER_POINTER_ALPHA = 8,
    TEST_VIEWER_POINTER_LARGE = 9,
    TEST_VIEWER_POINTER_RESIZE_FOCUS = 10,
    TEST_VIEWER_POINTER_RESTORED = 11,
    TEST_VIEWER_POINTER_COMPLETE = 12
};

enum test_viewer_pointer_shape
{
    TEST_VIEWER_POINTER_SHAPE_BASE = 0,
    TEST_VIEWER_POINTER_SHAPE_MONOCHROME = 1,
    TEST_VIEWER_POINTER_SHAPE_COLOR = 2,
    TEST_VIEWER_POINTER_SHAPE_ALPHA = 3,
    TEST_VIEWER_POINTER_SHAPE_LARGE = 4
};

enum
{
    TEST_VIEWER_POINTER_DESKTOP_WIDTH = 200,
    TEST_VIEWER_POINTER_DESKTOP_HEIGHT = 200,
    TEST_VIEWER_POINTER_WIDTH = 16,
    TEST_VIEWER_POINTER_HEIGHT = 16,
    TEST_VIEWER_POINTER_HOTSPOT_X = 3,
    TEST_VIEWER_POINTER_HOTSPOT_Y = 5,
    TEST_VIEWER_POINTER_CACHE_INDEX = 7,
    TEST_VIEWER_POINTER_POSITION_X = 73,
    TEST_VIEWER_POINTER_POSITION_Y = 81,
    TEST_VIEWER_POINTER_MONOCHROME_WIDTH = 16,
    TEST_VIEWER_POINTER_MONOCHROME_HEIGHT = 16,
    TEST_VIEWER_POINTER_MONOCHROME_HOTSPOT_X = 4,
    TEST_VIEWER_POINTER_MONOCHROME_HOTSPOT_Y = 7,
    TEST_VIEWER_POINTER_MONOCHROME_CACHE_INDEX = 8,
    TEST_VIEWER_POINTER_COLOR_WIDTH = 18,
    TEST_VIEWER_POINTER_COLOR_HEIGHT = 14,
    TEST_VIEWER_POINTER_COLOR_HOTSPOT_X = 2,
    TEST_VIEWER_POINTER_COLOR_HOTSPOT_Y = 6,
    TEST_VIEWER_POINTER_COLOR_CACHE_INDEX = 9,
    TEST_VIEWER_POINTER_ALPHA_WIDTH = 20,
    TEST_VIEWER_POINTER_ALPHA_HEIGHT = 20,
    TEST_VIEWER_POINTER_ALPHA_HOTSPOT_X = 9,
    TEST_VIEWER_POINTER_ALPHA_HOTSPOT_Y = 10,
    TEST_VIEWER_POINTER_ALPHA_CACHE_INDEX = 10,
    TEST_VIEWER_POINTER_LARGE_WIDTH = 129,
    TEST_VIEWER_POINTER_LARGE_HEIGHT = 129,
    TEST_VIEWER_POINTER_LARGE_HOTSPOT_X = 64,
    TEST_VIEWER_POINTER_LARGE_HOTSPOT_Y = 63,
    TEST_VIEWER_POINTER_LARGE_CACHE_INDEX = 11,
    TEST_VIEWER_POINTER_RESIZED_WIDTH = 236,
    TEST_VIEWER_POINTER_RESIZED_HEIGHT = 184
};

static inline uint32_t test_viewer_pointer_argb(uint16_t x,
                                                uint16_t y)
{
    uint32_t red = ((uint32_t)x * 13u + 17u) & 0xffu;
    uint32_t green = ((uint32_t)y * 17u + 29u) & 0xffu;
    uint32_t blue =
        (((uint32_t)x + (uint32_t)y) * 11u + 43u) & 0xffu;

    return 0xff000000u | (red << 16u) |
           (green << 8u) | blue;
}

static inline uint32_t test_viewer_pointer_color_argb(uint16_t x,
                                                      uint16_t y)
{
    uint32_t red = ((uint32_t)x * 7u +
                    (uint32_t)y * 3u + 31u) & 0xffu;
    uint32_t green = ((uint32_t)x * 5u +
                      (uint32_t)y * 11u + 47u) & 0xffu;
    uint32_t blue = ((uint32_t)x * 17u +
                     (uint32_t)y * 2u + 61u) & 0xffu;

    return 0xff000000u | (red << 16u) |
           (green << 8u) | blue;
}

static inline uint32_t test_viewer_pointer_alpha_argb(uint16_t x,
                                                      uint16_t y)
{
    static const uint8_t alpha_values[4] = {
        0x00u, 0x40u, 0x80u, 0xffu
    };
    uint32_t alpha = alpha_values[((uint32_t)x +
                                   (uint32_t)y) % 4u];
    uint32_t red = (((uint32_t)x * 9u + 41u) & 0xffu);
    uint32_t green = (((uint32_t)y * 13u + 53u) & 0xffu);
    uint32_t blue = ((((uint32_t)x + (uint32_t)y) *
                      5u + 67u) & 0xffu);

    red = (red * alpha + 127u) / 255u;
    green = (green * alpha + 127u) / 255u;
    blue = (blue * alpha + 127u) / 255u;
    return (alpha << 24u) | (red << 16u) |
           (green << 8u) | blue;
}

static inline uint32_t test_viewer_pointer_large_argb(uint16_t x,
                                                      uint16_t y)
{
    uint32_t red = ((uint32_t)x * 3u +
                    (uint32_t)y + 19u) & 0xffu;
    uint32_t green = ((uint32_t)y * 5u +
                      (uint32_t)x + 23u) & 0xffu;
    uint32_t blue = (((uint32_t)x ^ (uint32_t)y) *
                     7u + 29u) & 0xffu;

    return 0xff000000u | (red << 16u) |
           (green << 8u) | blue;
}

static inline uint32_t test_viewer_pointer_monochrome_argb(
    uint16_t x,
    uint16_t y)
{
    uint32_t mode =
        (((uint32_t)x / 4u) + ((uint32_t)y / 4u)) % 4u;

    if (mode == 1u)
        return 0xffffffffu;
    if (mode == 2u)
        return 0x00000000u;
    return 0xff000000u;
}

static inline uint32_t test_viewer_pointer_shape_argb(
    enum test_viewer_pointer_shape shape,
    uint16_t x,
    uint16_t y)
{
    switch (shape)
    {
        case TEST_VIEWER_POINTER_SHAPE_BASE:
            return test_viewer_pointer_argb(x, y);
        case TEST_VIEWER_POINTER_SHAPE_MONOCHROME:
            return test_viewer_pointer_monochrome_argb(x, y);
        case TEST_VIEWER_POINTER_SHAPE_COLOR:
            return test_viewer_pointer_color_argb(x, y);
        case TEST_VIEWER_POINTER_SHAPE_ALPHA:
            return test_viewer_pointer_alpha_argb(x, y);
        case TEST_VIEWER_POINTER_SHAPE_LARGE:
            return test_viewer_pointer_large_argb(x, y);
        default:
            return 0u;
    }
}

#endif
