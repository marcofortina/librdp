/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 framebuffer presentation for the viewer.
 * Invariants: all reads are bounded by the public surface stride and size, and
 * XImage never owns the session framebuffer pointer.
 * Ownership: librdp owns surface pixels; the viewer owns only transient XImage
 * wrappers and releases them before returning.
 * Threading: called from the viewer event thread after session dispatch marks
 * the surface dirty.
 * Trust boundary: server-provided graphics updates are consumed only through
 * normalized public surface APIs and are not trusted to match window geometry.
 */

#include "viewer_render.h"

#include "viewer_trace.h"
#include "viewer_window.h"

#include <X11/Xutil.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifdef LIBRDP_HAVE_XSHM
#include <X11/extensions/XShm.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#endif

struct x11_render_state
{
    int xshm_available;
    int xshm_disabled;
#ifdef LIBRDP_HAVE_XSHM
    XImage* xshm_image;
    XShmSegmentInfo xshm_info;
    size_t xshm_bytes;
    uint32_t xshm_width;
    uint32_t xshm_height;
    unsigned int xshm_depth;
    int xshm_attached;
#endif
};

#ifdef LIBRDP_HAVE_XSHM
static volatile int g_x11_render_trap_error;
static volatile unsigned int g_x11_render_trap_code;

static int x11_render_trap_error(Display* display, XErrorEvent* error)
{
    (void)display;
    g_x11_render_trap_error = 1;
    g_x11_render_trap_code = error ? error->error_code : 0u;
    return 0;
}
#endif

static uint64_t x11_trace_hash_seed(uint64_t hash, uint64_t value)
{
    unsigned int i = 0;

    for (i = 0; i < 8; i++)
    {
        hash ^= (uint8_t)((value >> (i * 8u)) & 0xffu);
        hash *= 1099511628211ull;
    }
    return hash;
}

static uint64_t x11_trace_hash_bytes(uint64_t hash, const uint8_t* bytes, size_t length)
{
    size_t i = 0;

    for (i = 0; i < length; i++)
    {
        hash ^= bytes[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

static uint64_t x11_trace_hash_bgra(const uint8_t* pixels, uint32_t width, uint32_t height, size_t stride)
{
    const size_t row_bytes = (size_t)width * 4u;
    const uint64_t offset = 1469598103934665603ull;
    uint64_t hash = offset;
    uint64_t pixel_count = 0;
    uint64_t samples = 0;
    uint64_t i = 0;

    if (!x11_trace_enabled_level(X11_TRACE_CLIENT, X11_TRACE_LEVEL_TRACE) ||
        !pixels || width == 0 || height == 0 || stride < row_bytes)
        return 0;

    hash = x11_trace_hash_seed(hash, width);
    hash = x11_trace_hash_seed(hash, height);
    pixel_count = (uint64_t)width * (uint64_t)height;
    samples = pixel_count < 8192u ? pixel_count : 8192u;
    if (samples == 0)
        return hash;
    if (samples == 1)
        return x11_trace_hash_bytes(hash, pixels, 4u);

    for (i = 0; i < samples; i++)
    {
        const uint64_t pixel_index = (i * (pixel_count - 1u)) / (samples - 1u);
        const uint32_t row = (uint32_t)(pixel_index / width);
        const uint32_t column = (uint32_t)(pixel_index % width);
        const uint8_t* p = pixels + ((size_t)row * stride) + ((size_t)column * 4u);

        hash = x11_trace_hash_bytes(hash, p, 4u);
    }
    return hash;
}

/*
 * Copy a BGRA surface into a destination image with independent source and
 * destination strides. The caller supplies already mapped memory; this helper
 * only validates geometry and preserves per-row padding.
 */
int x11_render_copy_bgra_rows(uint8_t* dst,
                              size_t dst_stride,
                              const uint8_t* src,
                              size_t src_stride,
                              uint32_t width,
                              uint32_t height)
{
    size_t row_bytes = 0;
    size_t max_row = 0;
    uint32_t y = 0;

    if (!dst || !src || width == 0 || height == 0)
        return 0;
    if (width > (uint32_t)(SIZE_MAX / 4u))
        return 0;
    row_bytes = (size_t)width * 4u;
    if (src_stride < row_bytes || dst_stride < row_bytes)
        return 0;
    max_row = (size_t)height - 1u;
    if ((max_row > 0 && src_stride > (SIZE_MAX - row_bytes) / max_row) ||
        (max_row > 0 && dst_stride > (SIZE_MAX - row_bytes) / max_row))
        return 0;

    for (y = 0; y < height; y++)
        memcpy(dst + ((size_t)y * dst_stride), src + ((size_t)y * src_stride), row_bytes);
    return 1;
}

/*
 * Create optional render state for the viewer. Failing to allocate or detect
 * MIT-SHM is not fatal because the presenter can always use XPutImage.
 */
int x11_render_init(x11_app* app)
{
    x11_render_state* render = NULL;

    if (!app)
        return 0;
    render = (x11_render_state*)calloc(1, sizeof(*render));
    if (!render)
    {
        x11_trace_event(X11_TRACE_CLIENT, "x11.render.init", "xshm=0 reason=allocation_failed");
        return 1;
    }
#ifdef LIBRDP_HAVE_XSHM
    if (app->display && XShmQueryExtension(app->display))
    {
        render->xshm_available = 1;
        x11_trace_event(X11_TRACE_CLIENT, "x11.render.init", "xshm=1");
    }
    else
    {
        x11_trace_event(X11_TRACE_CLIENT, "x11.render.init", "xshm=0 reason=extension_unavailable");
    }
#else
    x11_trace_event(X11_TRACE_CLIENT, "x11.render.init", "xshm=0 reason=compile_disabled");
#endif
    app->render = render;
    return 1;
}

#ifdef LIBRDP_HAVE_XSHM
/*
 * Tear down the current shared image in X server order: detach from the server,
 * destroy the XImage wrapper, then unmap the local shared memory segment.
 */
static void x11_render_destroy_xshm(x11_app* app)
{
    x11_render_state* render = app ? app->render : NULL;

    if (!app || !app->display || !render)
        return;
    if (render->xshm_attached)
    {
        XShmDetach(app->display, &render->xshm_info);
        XSync(app->display, False);
        render->xshm_attached = 0;
    }
    if (render->xshm_image)
    {
        XDestroyImage(render->xshm_image);
        render->xshm_image = NULL;
    }
    if (render->xshm_info.shmaddr && render->xshm_info.shmaddr != (char*)-1)
    {
        shmdt(render->xshm_info.shmaddr);
        render->xshm_info.shmaddr = NULL;
    }
    render->xshm_info.shmid = -1;
    render->xshm_bytes = 0;
    render->xshm_width = 0;
    render->xshm_height = 0;
    render->xshm_depth = 0;
}

/*
 * Attach a shared segment while trapping asynchronous X errors locally. Attach
 * failures disable only the XShm fast path and must not invalidate the viewer
 * window unless the server reports a real window/drawable failure elsewhere.
 */
static int x11_render_attach_xshm(x11_app* app, XShmSegmentInfo* info)
{
    XErrorHandler previous = NULL;
    Status attached = 0;

    g_x11_render_trap_error = 0;
    g_x11_render_trap_code = 0;
    previous = XSetErrorHandler(x11_render_trap_error);
    attached = XShmAttach(app->display, info);
    XSync(app->display, False);
    XSetErrorHandler(previous);
    if (!attached || g_x11_render_trap_error)
    {
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.render.xshm.attach.failed",
                        "attached=%u error=%u",
                        attached ? 1u : 0u,
                        g_x11_render_trap_code);
        return 0;
    }
    return 1;
}

/*
 * Ensure the shared image matches the current surface geometry and visual
 * depth. Any allocation or server attach failure permanently disables XShm for
 * the process and falls back to the synchronous presenter.
 */
static int x11_render_prepare_xshm(x11_app* app, uint32_t width, uint32_t height)
{
    x11_render_state* render = app ? app->render : NULL;
    const unsigned int depth = app ? (unsigned int)DefaultDepth(app->display, app->screen) : 0u;
    size_t bytes = 0;

    if (!app || !app->display || !render || !render->xshm_available || render->xshm_disabled)
        return 0;
    if (width == 0 || height == 0 || width > (uint32_t)INT_MAX || height > (uint32_t)INT_MAX)
        return 0;
    if (render->xshm_image && render->xshm_width == width && render->xshm_height == height &&
        render->xshm_depth == depth)
        return 1;

    x11_render_destroy_xshm(app);
    render->xshm_image = XShmCreateImage(app->display,
                                         DefaultVisual(app->display, app->screen),
                                         depth,
                                         ZPixmap,
                                         NULL,
                                         &render->xshm_info,
                                         width,
                                         height);
    if (!render->xshm_image)
    {
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.render.xshm.disabled",
                        "reason=create_image width=%u height=%u",
                        width,
                        height);
        render->xshm_disabled = 1;
        return 0;
    }
    if (render->xshm_image->bytes_per_line <= 0 || render->xshm_image->height <= 0 ||
        (size_t)render->xshm_image->bytes_per_line > SIZE_MAX / (size_t)render->xshm_image->height)
    {
        x11_trace_event(X11_TRACE_CLIENT, "x11.render.xshm.disabled", "reason=image_size");
        render->xshm_disabled = 1;
        x11_render_destroy_xshm(app);
        return 0;
    }
    bytes = (size_t)render->xshm_image->bytes_per_line * (size_t)render->xshm_image->height;
    render->xshm_info.shmid = shmget(IPC_PRIVATE, bytes, IPC_CREAT | 0600);
    if (render->xshm_info.shmid < 0)
    {
        x11_trace_event(X11_TRACE_CLIENT, "x11.render.xshm.disabled", "reason=shmget bytes=%u", (unsigned)bytes);
        render->xshm_disabled = 1;
        x11_render_destroy_xshm(app);
        return 0;
    }
    render->xshm_info.shmaddr = (char*)shmat(render->xshm_info.shmid, NULL, 0);
    render->xshm_info.readOnly = False;
    render->xshm_image->data = render->xshm_info.shmaddr;
    if (render->xshm_info.shmaddr == (char*)-1)
    {
        x11_trace_event(X11_TRACE_CLIENT, "x11.render.xshm.disabled", "reason=shmat bytes=%u", (unsigned)bytes);
        shmctl(render->xshm_info.shmid, IPC_RMID, NULL);
        render->xshm_info.shmid = -1;
        render->xshm_info.shmaddr = NULL;
        render->xshm_disabled = 1;
        x11_render_destroy_xshm(app);
        return 0;
    }
    if (!x11_render_attach_xshm(app, &render->xshm_info))
    {
        shmctl(render->xshm_info.shmid, IPC_RMID, NULL);
        render->xshm_disabled = 1;
        x11_render_destroy_xshm(app);
        return 0;
    }
    shmctl(render->xshm_info.shmid, IPC_RMID, NULL);
    render->xshm_attached = 1;
    render->xshm_bytes = bytes;
    render->xshm_width = width;
    render->xshm_height = height;
    render->xshm_depth = depth;
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.render.xshm.ready",
                    "width=%u height=%u stride=%u bytes=%u depth=%u",
                    width,
                    height,
                    (unsigned)render->xshm_image->bytes_per_line,
                    (unsigned)bytes,
                    depth);
    return 1;
}

/*
 * Present one full-frame dirty rectangle through MIT-SHM. Source pixels remain
 * owned by the session surface; this function copies them into X11-owned shared
 * memory before issuing the request.
 */
static int x11_render_draw_xshm(x11_app* app,
                                const uint8_t* pixels,
                                uint32_t width,
                                uint32_t height,
                                size_t stride,
                                uint64_t surface_hash)
{
    x11_render_state* render = app ? app->render : NULL;
    Status result = 0;

    if (!render || !x11_render_prepare_xshm(app, width, height))
        return 0;
    if (!x11_render_copy_bgra_rows((uint8_t*)render->xshm_image->data,
                                   (size_t)render->xshm_image->bytes_per_line,
                                   pixels,
                                   stride,
                                   width,
                                   height))
    {
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.render.xshm.copy.failed",
                        "width=%u height=%u src_stride=%u dst_stride=%u",
                        width,
                        height,
                        (unsigned)stride,
                        (unsigned)render->xshm_image->bytes_per_line);
        return 0;
    }
    result = XShmPutImage(app->display,
                          app->window,
                          app->gc,
                          render->xshm_image,
                          0,
                          0,
                          0,
                          0,
                          width,
                          height,
                          False);
    XFlush(app->display);
    x11_trace_event_level(X11_TRACE_CLIENT,
                          X11_TRACE_LEVEL_TRACE,
                          "x11.surface.draw.done",
                          "method=xshm surface_width=%u surface_height=%u surface_stride=%u image_stride=%u window_width=%u window_height=%u put_result=%d hash=%016llx",
                          width,
                          height,
                          (unsigned)stride,
                          (unsigned)render->xshm_image->bytes_per_line,
                          app->window_width,
                          app->window_height,
                          (int)result,
                          (unsigned long long)surface_hash);
    return result ? 1 : 0;
}
#endif

/*
 * Release renderer resources before the display connection closes. The helper
 * is idempotent so all partial-startup cleanup paths can call it.
 */
void x11_render_shutdown(x11_app* app)
{
    if (!app || !app->render)
        return;
#ifdef LIBRDP_HAVE_XSHM
    x11_render_destroy_xshm(app);
#endif
    free(app->render);
    app->render = NULL;
}

/*
 * Present the current session surface into the X11 window. Clipping and stride
 * handling stay here so expose and resize repaint paths cannot read outside
 * the framebuffer snapshot delivered by the core.
 */
void x11_render_draw_surface(x11_app* app)
{
    const librdp_surface* surface = NULL;
    XImage* image = NULL;
    uint32_t width = 0;
    uint32_t height = 0;
    size_t stride = 0;
    uint64_t surface_hash = 0;
    int put_result = 0;

    if (!app || !app->display || !app->session || x11_window_is_invalid())
        return;

    surface = librdp_session_get_surface(app->session);
    if (!surface || !librdp_surface_pixels(surface))
        return;

    width = librdp_surface_width(surface);
    height = librdp_surface_height(surface);
    stride = librdp_surface_stride(surface);
    surface_hash = x11_trace_hash_bgra(librdp_surface_pixels(surface), width, height, stride);
    x11_trace_event_level(X11_TRACE_CLIENT,
                          X11_TRACE_LEVEL_TRACE,
                          "x11.surface.draw.start",
                          "surface_width=%u surface_height=%u surface_stride=%u window_width=%u window_height=%u dirty=%u hash=%016llx",
                          width,
                          height,
                          (unsigned)stride,
                          app->window_width,
                          app->window_height,
                          app->dirty ? 1u : 0u,
                          (unsigned long long)surface_hash);
    if ((app->window_width != 0 && app->window_width != width) ||
        (app->window_height != 0 && app->window_height != height))
    {
        XClearWindow(app->display, app->window);
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.window.clear",
                        "reason=surface_window_mismatch surface_width=%u surface_height=%u window_width=%u window_height=%u",
                        width,
                        height,
                        app->window_width,
                        app->window_height);
    }
#ifdef LIBRDP_HAVE_XSHM
    if (x11_render_draw_xshm(app, librdp_surface_pixels(surface), width, height, stride, surface_hash))
    {
        app->dirty = 0;
        return;
    }
#endif
    image = XCreateImage(app->display,
                         DefaultVisual(app->display, app->screen),
                         (unsigned)DefaultDepth(app->display, app->screen),
                         ZPixmap,
                         0,
                         (char*)librdp_surface_pixels(surface),
                         width,
                         height,
                         32,
                         (int)stride);
    if (!image)
    {
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.surface.draw.failed",
                        "stage=create_image surface_width=%u surface_height=%u surface_stride=%u",
                        width,
                        height,
                        (unsigned)stride);
        return;
    }

    put_result = XPutImage(app->display, app->window, app->gc, image, 0, 0, 0, 0, width, height);
    image->data = NULL;
    XDestroyImage(image);
    XFlush(app->display);
    x11_trace_event_level(X11_TRACE_CLIENT,
                          X11_TRACE_LEVEL_TRACE,
                          "x11.surface.draw.done",
                          "method=xputimage surface_width=%u surface_height=%u surface_stride=%u window_width=%u window_height=%u put_result=%d hash=%016llx",
                          width,
                          height,
                          (unsigned)stride,
                          app->window_width,
                          app->window_height,
                          put_result,
                          (unsigned long long)surface_hash);
    app->dirty = 0;
}
