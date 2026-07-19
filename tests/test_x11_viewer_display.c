/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer display bridge regression tests.
 * Coverage: XRandR monitor-to-RDP layout translation without connecting to a
 * real X server.
 * Bug classes: coordinate overflow, primary-origin mistakes, small sliver
 * monitors, overlap-prone translation, and DPI metadata corruption.
 * Determinism: tests use synthetic XRRMonitorInfo arrays only.
 */

#include "x11_display.h"

#include <stdio.h>
#include <string.h>

static int check_int(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr, "test_x11_viewer_display:%d: check failed: %s\n", line, expression);
    return 1;
}

#define CHECK(expr)                                                                                  \
    do                                                                                               \
    {                                                                                                \
        if (check_int((expr), #expr, __LINE__) != 0)                                                 \
            return 1;                                                                                \
    } while (0)

/*
 * A viewer window spanning two host monitors must become two remote monitors
 * relative to the viewer origin, with the host primary translated to 0,0.
 */
static int test_translate_spanning_window(void)
{
    XRRMonitorInfo host[2];
    librdp_display_monitor out[2];
    uint32_t count = 0;

    memset(host, 0, sizeof(host));
    memset(out, 0, sizeof(out));
    host[0].primary = True;
    host[0].x = 0;
    host[0].y = 0;
    host[0].width = 1920;
    host[0].height = 1080;
    host[0].mwidth = 530;
    host[0].mheight = 300;
    host[1].x = 1920;
    host[1].y = 0;
    host[1].width = 1280;
    host[1].height = 1024;
    host[1].mwidth = 340;
    host[1].mheight = 270;

    count = x11_display_translate_xrandr_monitors(out, 2, host, 2, 1600, 100, 700, 700);
    CHECK(count == 2);
    CHECK(out[0].flags == LIBRDP_DISPLAY_MONITOR_PRIMARY);
    CHECK(out[0].left == 0 && out[0].top == 0);
    CHECK(out[0].width == 320 && out[0].height == 700);
    CHECK(out[1].flags == 0);
    CHECK(out[1].left == 320 && out[1].top == 0);
    CHECK(out[1].width == 380 && out[1].height == 700);
    CHECK(out[0].physical_width >= 10 && out[0].physical_height >= 10);
    CHECK(out[1].physical_width >= 10 && out[1].physical_height >= 10);
    CHECK(out[0].desktop_scale_factor == 100 && out[1].device_scale_factor == 100);
    return 0;
}

/*
 * If no host monitor is explicitly primary, the largest intersecting monitor
 * becomes primary and all other coordinates are translated around it.
 */
static int test_translate_without_primary_uses_largest_area(void)
{
    XRRMonitorInfo host[2];
    librdp_display_monitor out[2];
    uint32_t count = 0;

    memset(host, 0, sizeof(host));
    memset(out, 0, sizeof(out));
    host[0].x = 0;
    host[0].width = 500;
    host[0].height = 500;
    host[1].x = 500;
    host[1].width = 900;
    host[1].height = 500;

    count = x11_display_translate_xrandr_monitors(out, 2, host, 2, 0, 0, 1400, 500);
    CHECK(count == 2);
    CHECK(out[1].flags == LIBRDP_DISPLAY_MONITOR_PRIMARY);
    CHECK(out[1].left == 0);
    CHECK(out[0].left == -500);
    return 0;
}

/*
 * Tiny intersections are ignored so a window barely crossing a monitor edge
 * does not produce a layout that the display-control validator would reject.
 */
static int test_translate_ignores_tiny_intersections(void)
{
    XRRMonitorInfo host[2];
    librdp_display_monitor out[2];
    uint32_t count = 0;

    memset(host, 0, sizeof(host));
    memset(out, 0, sizeof(out));
    host[0].primary = True;
    host[0].x = 0;
    host[0].width = 1920;
    host[0].height = 1080;
    host[1].x = 1920;
    host[1].width = 1280;
    host[1].height = 1080;

    count = x11_display_translate_xrandr_monitors(out, 2, host, 2, 1800, 100, 180, 500);
    CHECK(count == 0);
    return 0;
}

int main(void)
{
    if (test_translate_spanning_window() != 0)
        return 1;
    if (test_translate_without_primary_uses_largest_area() != 0)
        return 1;
    if (test_translate_ignores_tiny_intersections() != 0)
        return 1;
    return 0;
}
