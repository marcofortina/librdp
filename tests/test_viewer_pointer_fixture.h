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
    TEST_VIEWER_POINTER_RESTORED = 6,
    TEST_VIEWER_POINTER_COMPLETE = 7
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
    TEST_VIEWER_POINTER_POSITION_Y = 81
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

#endif
