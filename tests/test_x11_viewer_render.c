/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer presentation regression tests.
 * Coverage: row-stride and dirty-region copies plus pixel-identical XShm and
 * XPutImage presentation on private Xvfb displays when Xvfb is available.
 * Bug classes: bounds overrun, stride confusion, zero-sized frames, and
 * fallback-copy corruption during resize.
 * Determinism: synthetic frames are rendered only into isolated test windows;
 * the in-memory coverage remains available without a display server.
 */

#include "x11_render.h"

#include <X11/Xutil.h>

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TEST_RENDER_WIDTH 200u
#define TEST_RENDER_HEIGHT 200u
#define TEST_RENDER_PIXELS \
    ((size_t)TEST_RENDER_WIDTH * TEST_RENDER_HEIGHT)
#define TEST_RENDER_BYTES (TEST_RENDER_PIXELS * 4u)

static int check_int(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr, "test_x11_viewer_render:%d: check failed: %s\n", line, expression);
    return 1;
}

#define CHECK(expr)                                                                                  \
    do                                                                                               \
    {                                                                                                \
        if (check_int((expr), #expr, __LINE__) != 0)                                                 \
            return 1;                                                                                \
    } while (0)

/*
 * Protects the XShm fast path against row-stride mistakes: each BGRA row is
 * copied exactly up to width*4 bytes while source and destination padding stay
 * untouched.
 */
static int test_copy_bgra_rows_preserves_padding(void)
{
    static const uint8_t source[] = {
        0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u, 0xaau, 0xbbu,
        0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu, 0x10u, 0xccu, 0xddu,
    };
    static const uint8_t expected[] = {
        0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u, 0xeeu, 0xeeu, 0xeeu, 0xeeu,
        0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu, 0x10u, 0xeeu, 0xeeu, 0xeeu, 0xeeu,
    };
    uint8_t destination[24];

    memset(destination, 0xee, sizeof(destination));
    CHECK(x11_render_copy_bgra_rows(destination, 12u, source, 10u, 2u, 2u) == 1);
    CHECK(memcmp(destination, expected, sizeof(expected)) == 0);
    return 0;
}

/*
 * Rejects malformed geometry before any copy occurs. These cases mirror the
 * inputs produced by invalid server dimensions or stale resize state.
 */
static int test_copy_bgra_rows_rejects_invalid_inputs(void)
{
    uint8_t source[8] = { 0 };
    uint8_t destination[8] = { 0 };

    CHECK(x11_render_copy_bgra_rows(NULL, 8u, source, 8u, 1u, 1u) == 0);
    CHECK(x11_render_copy_bgra_rows(destination, 8u, NULL, 8u, 1u, 1u) == 0);
    CHECK(x11_render_copy_bgra_rows(destination, 3u, source, 8u, 1u, 1u) == 0);
    CHECK(x11_render_copy_bgra_rows(destination, 8u, source, 3u, 1u, 1u) == 0);
    CHECK(x11_render_copy_bgra_rows(destination, 8u, source, 8u, 0u, 1u) == 0);
    CHECK(x11_render_copy_bgra_rows(destination, 8u, source, 8u, 1u, 0u) == 0);
    return 0;
}

/*
 * Verify that a dirty subrectangle copies identical visible bytes while
 * preserving all destination pixels and row padding outside its bounds.
 */
static int test_copy_bgra_rect_preserves_undamaged_pixels(void)
{
    uint8_t source[60];
    uint8_t destination[72];
    uint8_t expected[72];
    size_t y = 0u;
    size_t x = 0u;

    for (y = 0u; y < sizeof(source); y++)
        source[y] = (uint8_t)(y + 1u);
    memset(destination, 0xe5, sizeof(destination));
    memcpy(expected, destination, sizeof(expected));
    for (y = 1u; y < 3u; y++)
    {
        for (x = 1u; x < 3u; x++)
        {
            memcpy(expected + y * 24u + x * 4u,
                   source + y * 20u + x * 4u,
                   4u);
        }
    }
    CHECK(x11_render_copy_bgra_rect(destination,
                                    24u,
                                    source,
                                    20u,
                                    1u,
                                    1u,
                                    2u,
                                    2u) == 1);
    CHECK(memcmp(destination, expected, sizeof(expected)) == 0);
    CHECK(x11_render_copy_bgra_rect(destination,
                                    8u,
                                    source,
                                    20u,
                                    2u,
                                    0u,
                                    1u,
                                    1u) == 0);
    return 0;
}

/* Check rectangle union and the full-frame damage sentinel used on expose. */
static int test_dirty_region_accumulation(void)
{
    x11_app app;

    memset(&app, 0, sizeof(app));
    x11_render_mark_dirty(&app, 10u, 20u, 30u, 40u);
    CHECK(app.dirty && app.dirty_region_valid);
    CHECK(app.dirty_left == 10u && app.dirty_top == 20u);
    CHECK(app.dirty_right == 40u && app.dirty_bottom == 60u);
    x11_render_mark_dirty(&app, 5u, 25u, 50u, 10u);
    CHECK(app.dirty_left == 5u && app.dirty_top == 20u);
    CHECK(app.dirty_right == 55u && app.dirty_bottom == 60u);
    x11_render_mark_all_dirty(&app);
    CHECK(app.dirty && !app.dirty_region_valid);
    x11_render_mark_dirty(&app, 1u, 2u, 3u, 4u);
    CHECK(app.dirty && !app.dirty_region_valid);
    return 0;
}

#ifdef LIBRDP_TEST_XVFB_PATH
static void test_sleep_ms(unsigned int milliseconds)
{
    struct timespec delay;

    delay.tv_sec = (time_t)(milliseconds / 1000u);
    delay.tv_nsec =
        (long)(milliseconds % 1000u) * 1000000L;
    while (nanosleep(&delay, &delay) != 0)
    {
    }
}

/*
 * Start a private X server with an explicit MIT-SHM policy. No unrelated host
 * windows can appear in the captured drawable.
 */
static int test_start_xvfb(int disable_xshm,
                           char display_name[32],
                           pid_t* child)
{
    unsigned int attempt = 0u;

    if (!display_name || !child)
        return 0;
    for (attempt = 0u; attempt < 20u; attempt++)
    {
        unsigned int number =
            260u +
            ((unsigned int)getpid() + attempt +
             (disable_xshm ? 31u : 0u)) %
                80u;
        pid_t pid = 0;
        unsigned int wait_index = 0u;

        if (snprintf(display_name, 32u, ":%u", number) <= 0)
            return 0;
        pid = fork();
        if (pid < 0)
            return 0;
        if (pid == 0)
        {
            if (disable_xshm)
            {
                execl(LIBRDP_TEST_XVFB_PATH,
                      LIBRDP_TEST_XVFB_PATH,
                      display_name,
                      "-screen",
                      "0",
                      "240x240x24",
                      "-nolisten",
                      "tcp",
                      "-extension",
                      "MIT-SHM",
                      (char*)NULL);
            }
            else
            {
                execl(LIBRDP_TEST_XVFB_PATH,
                      LIBRDP_TEST_XVFB_PATH,
                      display_name,
                      "-screen",
                      "0",
                      "240x240x24",
                      "-nolisten",
                      "tcp",
                      (char*)NULL);
            }
            _exit(127);
        }
        for (wait_index = 0u; wait_index < 100u; wait_index++)
        {
            Display* probe = XOpenDisplay(display_name);
            int status = 0;

            if (probe)
            {
                XCloseDisplay(probe);
                *child = pid;
                return 1;
            }
            if (waitpid(pid, &status, WNOHANG) == pid)
                break;
            test_sleep_ms(10u);
        }
        kill(pid, SIGTERM);
        (void)waitpid(pid, NULL, 0);
    }
    return 0;
}

static void test_stop_xvfb(pid_t child)
{
    if (child <= 0)
        return;
    kill(child, SIGTERM);
    (void)waitpid(child, NULL, 0);
}

static void test_fill_frame(uint8_t* pixels, int updated)
{
    uint32_t y = 0u;
    uint32_t x = 0u;

    if (!pixels)
        return;
    for (y = 0u; y < TEST_RENDER_HEIGHT; y++)
    {
        for (x = 0u; x < TEST_RENDER_WIDTH; x++)
        {
            size_t offset =
                (((size_t)y * TEST_RENDER_WIDTH) + x) * 4u;
            int in_dirty =
                x >= 37u && x < 98u &&
                y >= 41u && y < 114u;

            if (updated && in_dirty)
            {
                pixels[offset] = 0xf1u;
                pixels[offset + 1u] = 0xe2u;
                pixels[offset + 2u] = 0xd3u;
            }
            else
            {
                pixels[offset] =
                    (uint8_t)(1u + ((x + y * 3u) % 120u));
                pixels[offset + 1u] =
                    (uint8_t)(1u + ((x * 5u + y) % 120u));
                pixels[offset + 2u] =
                    (uint8_t)(1u + ((x * 7u + y * 11u) % 120u));
            }
            pixels[offset + 3u] = 0xffu;
        }
    }
}

static int test_capture_window(Display* display,
                               Window window,
                               unsigned long* pixels)
{
    XImage* image = NULL;
    uint32_t y = 0u;
    uint32_t x = 0u;

    if (!display || !pixels)
        return 0;
    XSync(display, False);
    image = XGetImage(display,
                      window,
                      0,
                      0,
                      TEST_RENDER_WIDTH,
                      TEST_RENDER_HEIGHT,
                      AllPlanes,
                      ZPixmap);
    if (!image)
        return 0;
    for (y = 0u; y < TEST_RENDER_HEIGHT; y++)
    {
        for (x = 0u; x < TEST_RENDER_WIDTH; x++)
        {
            pixels[(size_t)y * TEST_RENDER_WIDTH + x] =
                XGetPixel(image, (int)x, (int)y);
        }
    }
    XDestroyImage(image);
    return 1;
}

/*
 * Present the same full frame and subsequent dirty update on one isolated X
 * server. The caller selects whether MIT-SHM is available.
 */
static int test_present_case(int disable_xshm,
                             unsigned long* initial,
                             unsigned long* updated,
                             x11_render_method* method)
{
    x11_app app;
    char display_name[32];
    pid_t child = -1;
    uint8_t* pixels = NULL;
    int result = 0;

    memset(&app, 0, sizeof(app));
    memset(display_name, 0, sizeof(display_name));
    if (!test_start_xvfb(disable_xshm,
                         display_name,
                         &child))
        return 0;
    app.display = XOpenDisplay(display_name);
    if (!app.display)
        goto cleanup;
    app.screen = DefaultScreen(app.display);
    app.window_width = TEST_RENDER_WIDTH;
    app.window_height = TEST_RENDER_HEIGHT;
    app.window = XCreateSimpleWindow(
        app.display,
        RootWindow(app.display, app.screen),
        0,
        0,
        TEST_RENDER_WIDTH,
        TEST_RENDER_HEIGHT,
        0,
        BlackPixel(app.display, app.screen),
        BlackPixel(app.display, app.screen));
    if (!app.window)
        goto cleanup;
    app.gc = XCreateGC(app.display, app.window, 0u, NULL);
    if (!app.gc || !x11_render_init(&app))
        goto cleanup;
    XMapWindow(app.display, app.window);
    XSync(app.display, False);
    pixels = (uint8_t*)malloc(TEST_RENDER_BYTES);
    if (!pixels)
        goto cleanup;
    test_fill_frame(pixels, 0);
    x11_render_mark_all_dirty(&app);
    if (!x11_render_draw_bgra(&app,
                              pixels,
                              TEST_RENDER_WIDTH,
                              TEST_RENDER_HEIGHT,
                              (size_t)TEST_RENDER_WIDTH * 4u) ||
        !test_capture_window(app.display,
                             app.window,
                             initial))
        goto cleanup;
    test_fill_frame(pixels, 1);
    x11_render_mark_dirty(&app, 37u, 41u, 61u, 73u);
    if (!x11_render_draw_bgra(&app,
                              pixels,
                              TEST_RENDER_WIDTH,
                              TEST_RENDER_HEIGHT,
                              (size_t)TEST_RENDER_WIDTH * 4u) ||
        !test_capture_window(app.display,
                             app.window,
                             updated))
        goto cleanup;
    *method = x11_render_last_method(&app);
    result = 1;

cleanup:
    free(pixels);
    x11_render_shutdown(&app);
    if (app.display && app.gc)
        XFreeGC(app.display, app.gc);
    if (app.display && app.window)
        XDestroyWindow(app.display, app.window);
    if (app.display)
        XCloseDisplay(app.display);
    test_stop_xvfb(child);
    return result;
}

/*
 * Compare actual window captures from MIT-SHM and XPutImage. It also proves
 * that the dirty update changes every pixel inside its bounds and none outside.
 */
static int test_xshm_and_xputimage_match(void)
{
    unsigned long* xshm_initial = NULL;
    unsigned long* xshm_updated = NULL;
    unsigned long* xput_initial = NULL;
    unsigned long* xput_updated = NULL;
    x11_render_method xshm_method = X11_RENDER_METHOD_NONE;
    x11_render_method xput_method = X11_RENDER_METHOD_NONE;
    size_t index = 0u;
    size_t changed = 0u;
    int result = 1;

    xshm_initial = (unsigned long*)calloc(
        TEST_RENDER_PIXELS,
        sizeof(*xshm_initial));
    xshm_updated = (unsigned long*)calloc(
        TEST_RENDER_PIXELS,
        sizeof(*xshm_updated));
    xput_initial = (unsigned long*)calloc(
        TEST_RENDER_PIXELS,
        sizeof(*xput_initial));
    xput_updated = (unsigned long*)calloc(
        TEST_RENDER_PIXELS,
        sizeof(*xput_updated));
    if (!xshm_initial || !xshm_updated ||
        !xput_initial || !xput_updated)
        goto cleanup;
    if (!test_present_case(0,
                           xshm_initial,
                           xshm_updated,
                           &xshm_method) ||
        !test_present_case(1,
                           xput_initial,
                           xput_updated,
                           &xput_method))
        goto cleanup;
    if (xshm_method != X11_RENDER_METHOD_XSHM ||
        xput_method != X11_RENDER_METHOD_XPUTIMAGE ||
        memcmp(xshm_initial,
               xput_initial,
               TEST_RENDER_PIXELS * sizeof(*xshm_initial)) != 0 ||
        memcmp(xshm_updated,
               xput_updated,
               TEST_RENDER_PIXELS * sizeof(*xshm_updated)) != 0)
        goto cleanup;
    for (index = 0u; index < TEST_RENDER_PIXELS; index++)
    {
        uint32_t x =
            (uint32_t)(index % TEST_RENDER_WIDTH);
        uint32_t y =
            (uint32_t)(index / TEST_RENDER_WIDTH);
        int in_dirty =
            x >= 37u && x < 98u &&
            y >= 41u && y < 114u;

        if (xshm_initial[index] != xshm_updated[index])
            changed++;
        if (in_dirty !=
            (xshm_initial[index] != xshm_updated[index]))
            goto cleanup;
    }
    if (changed != 61u * 73u)
        goto cleanup;
    result = 0;

cleanup:
    free(xput_updated);
    free(xput_initial);
    free(xshm_updated);
    free(xshm_initial);
    return result;
}
#endif

int main(void)
{
    if (test_copy_bgra_rows_preserves_padding() != 0)
        return 1;
    if (test_copy_bgra_rows_rejects_invalid_inputs() != 0)
        return 1;
    if (test_copy_bgra_rect_preserves_undamaged_pixels() != 0)
        return 1;
    if (test_dirty_region_accumulation() != 0)
        return 1;
#ifdef LIBRDP_TEST_XVFB_PATH
    if (test_xshm_and_xputimage_match() != 0)
        return 1;
#endif
    return 0;
}
