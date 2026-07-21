/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 damage-driven capture and display topology handling.
 * Invariants: frames are top-down BGRA32, every dirty rectangle is clipped to
 * the current source, and image allocation is capped before X11 transfer.
 * Ownership: frame and shared-memory image storage is context-owned and frame
 * callbacks borrow it only for the callback duration.
 * Threading: capture and XRandR handling execute on the host event thread.
 * Trust boundary: XImage layout, visual masks, monitor geometry and damage
 * events are validated before pointer arithmetic or allocation.
 */

#include "x11_server_internal.h"

#include <X11/extensions/Xcomposite.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

extern const server_platform_event_source_vtable
    x11_server_event_source_vtable;

static unsigned int x11_server_mask_shift(unsigned long mask)
{
    unsigned int shift = 0u;

    while (mask != 0ul && (mask & 1ul) == 0ul)
    {
        mask >>= 1u;
        shift++;
    }
    return shift;
}

static uint8_t x11_server_mask_channel(unsigned long pixel,
                                       unsigned long mask)
{
    unsigned int shift = 0u;
    unsigned long maximum = 0ul;
    unsigned long value = 0ul;

    if (mask == 0ul)
        return 0u;
    shift = x11_server_mask_shift(mask);
    maximum = mask >> shift;
    value = (pixel & mask) >> shift;
    if (maximum == 0ul)
        return 0u;
    return (uint8_t)((value * 255ul + maximum / 2ul) / maximum);
}

static librdp_status x11_server_convert_image(
    const x11_server_context* context,
    const XImage* image,
    uint8_t* destination,
    size_t stride,
    size_t destination_len)
{
    size_t required = 0;
    uint32_t y = 0;

    if (!context || !image || !destination ||
        image->width != (int)context->width ||
        image->height != (int)context->height ||
        stride < (size_t)context->width * 4u ||
        !x11_server_checked_multiply(stride,
                                     (size_t)context->height,
                                     &required) ||
        required > destination_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (y = 0u; y < context->height; y++)
    {
        uint8_t* row = destination + (size_t)y * stride;
        uint32_t x = 0;

        for (x = 0u; x < context->width; x++)
        {
            unsigned long pixel = XGetPixel((XImage*)image, (int)x, (int)y);
            uint8_t* output = row + (size_t)x * 4u;

            output[0] =
                x11_server_mask_channel(pixel, image->blue_mask);
            output[1] =
                x11_server_mask_channel(pixel, image->green_mask);
            output[2] =
                x11_server_mask_channel(pixel, image->red_mask);
            output[3] = 0xffu;
        }
    }
    return LIBRDP_STATUS_OK;
}

static void x11_server_shm_discard(x11_server_context* context)
{
    if (!context)
        return;
#ifdef LIBRDP_HAVE_XSHM
    if (context->shm.attached)
    {
        XShmDetach(context->display, &context->shm.segment);
        XSync(context->display, False);
        context->shm.attached = 0;
    }
    if (context->shm.image)
    {
        context->shm.image->data = NULL;
        XDestroyImage(context->shm.image);
        context->shm.image = NULL;
    }
    if (context->shm.segment.shmaddr &&
        context->shm.segment.shmaddr != (char*)-1)
    {
        shmdt(context->shm.segment.shmaddr);
        context->shm.segment.shmaddr = NULL;
    }
    if (context->shm.segment.shmid >= 0)
    {
        shmctl(context->shm.segment.shmid, IPC_RMID, NULL);
        context->shm.segment.shmid = -1;
    }
#else
    (void)context;
#endif
}

#ifdef LIBRDP_HAVE_XSHM
static int x11_server_shm_prepare(x11_server_context* context)
{
    size_t image_bytes = 0;

    if (!context || !context->shm_available)
        return 0;
    if (context->shm.image &&
        context->shm.image->width == (int)context->width &&
        context->shm.image->height == (int)context->height)
        return 1;
    x11_server_shm_discard(context);
    memset(&context->shm.segment, 0, sizeof(context->shm.segment));
    context->shm.segment.shmid = -1;
    context->shm.image = XShmCreateImage(
        context->display,
        context->visual_info.visual,
        (unsigned int)context->depth,
        ZPixmap,
        NULL,
        &context->shm.segment,
        context->width,
        context->height);
    if (!context->shm.image ||
        context->shm.image->bytes_per_line <= 0 ||
        !x11_server_checked_multiply(
            (size_t)context->shm.image->bytes_per_line,
            (size_t)context->height,
            &image_bytes) ||
        image_bytes > context->config.max_frame_bytes)
    {
        x11_server_shm_discard(context);
        return 0;
    }
    context->shm.segment.shmid =
        shmget(IPC_PRIVATE, image_bytes, IPC_CREAT | 0600);
    if (context->shm.segment.shmid < 0)
    {
        x11_server_shm_discard(context);
        return 0;
    }
    context->shm.segment.shmaddr =
        (char*)shmat(context->shm.segment.shmid, NULL, 0);
    if (context->shm.segment.shmaddr == (char*)-1)
    {
        context->shm.segment.shmaddr = NULL;
        x11_server_shm_discard(context);
        return 0;
    }
    context->shm.segment.readOnly = False;
    context->shm.image->data = context->shm.segment.shmaddr;
    if (!XShmAttach(context->display, &context->shm.segment))
    {
        x11_server_shm_discard(context);
        return 0;
    }
    XSync(context->display, False);
    context->shm.attached = 1;
    shmctl(context->shm.segment.shmid, IPC_RMID, NULL);
    context->shm.segment.shmid = -1;
    return 1;
}
#endif

static librdp_status x11_server_monitor_geometry(
    x11_server_context* context,
    int* x,
    int* y,
    uint32_t* width,
    uint32_t* height)
{
    XRRMonitorInfo* monitors = NULL;
    int count = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    monitors = XRRGetMonitors(context->display,
                              context->root,
                              True,
                              &count);
    if (!monitors || count <= 0 ||
        context->config.monitor_index >= (uint32_t)count)
        status = LIBRDP_STATUS_UNSUPPORTED;
    else if (monitors[context->config.monitor_index].width <= 0 ||
             monitors[context->config.monitor_index].height <= 0)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    else
    {
        const XRRMonitorInfo* monitor =
            &monitors[context->config.monitor_index];

        *x = monitor->x;
        *y = monitor->y;
        *width = (uint32_t)monitor->width;
        *height = (uint32_t)monitor->height;
    }
    if (monitors)
        XRRFreeMonitors(monitors);
    return status;
}

librdp_status x11_server_refresh_geometry(x11_server_context* context,
                                          int force)
{
    XWindowAttributes attributes;
    int next_x = 0;
    int next_y = 0;
    uint32_t next_width = 0u;
    uint32_t next_height = 0u;
    size_t row_bytes = 0;
    size_t frame_bytes = 0;

    if (!context || !context->display || context->target == None)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!XGetWindowAttributes(context->display,
                              context->target,
                              &attributes))
        return LIBRDP_STATUS_IO_ERROR;
    if (context->config.source_kind == X11_SERVER_SOURCE_MONITOR)
    {
        librdp_status status = x11_server_monitor_geometry(
            context,
            &next_x,
            &next_y,
            &next_width,
            &next_height);

        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    else
    {
        if (attributes.width <= 0 || attributes.height <= 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        next_width = (uint32_t)attributes.width;
        next_height = (uint32_t)attributes.height;
    }
    if (context->config.source_kind == X11_SERVER_SOURCE_WINDOW)
    {
        Window child = None;
        int root_x = 0;
        int root_y = 0;

        if (!XTranslateCoordinates(context->display,
                                   context->target,
                                   context->root,
                                   0,
                                   0,
                                   &root_x,
                                   &root_y,
                                   &child))
            return LIBRDP_STATUS_IO_ERROR;
        context->desktop_x = root_x;
        context->desktop_y = root_y;
    }
    else
    {
        context->desktop_x = next_x;
        context->desktop_y = next_y;
    }
    if (!x11_server_checked_multiply((size_t)next_width, 4u, &row_bytes) ||
        !x11_server_checked_multiply(row_bytes,
                                     (size_t)next_height,
                                     &frame_bytes) ||
        frame_bytes > context->config.max_frame_bytes)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (!force && context->capture_x == next_x &&
        context->capture_y == next_y && context->width == next_width &&
        context->height == next_height)
        return LIBRDP_STATUS_OK;
    context->capture_x = next_x;
    context->capture_y = next_y;
    context->width = next_width;
    context->height = next_height;
    context->frame_stride = row_bytes;
    if (frame_bytes > context->frame_capacity)
    {
        uint8_t* resized = (uint8_t*)realloc(context->frame_pixels,
                                             frame_bytes);

        if (!resized)
            return LIBRDP_STATUS_NO_MEMORY;
        context->frame_pixels = resized;
        context->frame_capacity = frame_bytes;
    }
    x11_server_shm_discard(context);
    context->dirty_count = 1u;
    context->dirty[0].x = 0u;
    context->dirty[0].y = 0u;
    context->dirty[0].width = next_width;
    context->dirty[0].height = next_height;
    context->capture_due = 1;
    context->full_capture_due = 1;
    return LIBRDP_STATUS_OK;
}

static int x11_server_rects_touch(const server_platform_rect* left,
                                  const server_platform_rect* right)
{
    uint64_t left_right = (uint64_t)left->x + left->width;
    uint64_t right_right = (uint64_t)right->x + right->width;
    uint64_t left_bottom = (uint64_t)left->y + left->height;
    uint64_t right_bottom = (uint64_t)right->y + right->height;

    return left->x <= right_right && right->x <= left_right &&
           left->y <= right_bottom && right->y <= left_bottom;
}

static void x11_server_rect_union(server_platform_rect* target,
                                  const server_platform_rect* source)
{
    uint32_t x1 = target->x < source->x ? target->x : source->x;
    uint32_t y1 = target->y < source->y ? target->y : source->y;
    uint64_t target_x2 = (uint64_t)target->x + target->width;
    uint64_t source_x2 = (uint64_t)source->x + source->width;
    uint64_t target_y2 = (uint64_t)target->y + target->height;
    uint64_t source_y2 = (uint64_t)source->y + source->height;
    uint64_t x2 = target_x2 > source_x2 ? target_x2 : source_x2;
    uint64_t y2 = target_y2 > source_y2 ? target_y2 : source_y2;

    target->x = x1;
    target->y = y1;
    target->width = (uint32_t)(x2 - x1);
    target->height = (uint32_t)(y2 - y1);
}

void x11_server_invalidate(x11_server_context* context,
                           int x,
                           int y,
                           unsigned int width,
                           unsigned int height)
{
    int64_t relative_x = 0;
    int64_t relative_y = 0;
    int64_t right = 0;
    int64_t bottom = 0;
    server_platform_rect rect;
    size_t index = 0;

    if (!context || width == 0u || height == 0u)
        return;
    relative_x = (int64_t)x - (int64_t)context->capture_x;
    relative_y = (int64_t)y - (int64_t)context->capture_y;
    right = relative_x + (int64_t)width;
    bottom = relative_y + (int64_t)height;
    if (right <= 0 || bottom <= 0 ||
        relative_x >= (int64_t)context->width ||
        relative_y >= (int64_t)context->height)
        return;
    if (relative_x < 0)
        relative_x = 0;
    if (relative_y < 0)
        relative_y = 0;
    if (right > (int64_t)context->width)
        right = context->width;
    if (bottom > (int64_t)context->height)
        bottom = context->height;
    rect.x = (uint32_t)relative_x;
    rect.y = (uint32_t)relative_y;
    rect.width = (uint32_t)(right - relative_x);
    rect.height = (uint32_t)(bottom - relative_y);
    for (index = 0; index < context->dirty_count; index++)
    {
        if (x11_server_rects_touch(&context->dirty[index], &rect))
        {
            x11_server_rect_union(&context->dirty[index], &rect);
            context->capture_due = 1;
            return;
        }
    }
    if (context->dirty_count < X11_SERVER_MAX_DIRTY_RECTS)
        context->dirty[context->dirty_count++] = rect;
    else
    {
        context->dirty_count = 1u;
        context->dirty[0].x = 0u;
        context->dirty[0].y = 0u;
        context->dirty[0].width = context->width;
        context->dirty[0].height = context->height;
        context->full_capture_due = 1;
    }
    context->capture_due = 1;
}

librdp_status x11_server_capture_frame(x11_server_context* context)
{
    server_platform_frame frame;
    XImage* image = NULL;
    int shm_used = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !context->capture_started ||
        !context->capture_sink.frame)
        return LIBRDP_STATUS_STATE;
    status = x11_server_refresh_geometry(context, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (context->dirty_count == 0u)
    {
        context->dirty_count = 1u;
        context->dirty[0].x = 0u;
        context->dirty[0].y = 0u;
        context->dirty[0].width = context->width;
        context->dirty[0].height = context->height;
    }
    if (
#ifdef LIBRDP_HAVE_XSHM
        x11_server_shm_prepare(context) &&
        XShmGetImage(context->display,
                     context->capture_drawable,
                     context->shm.image,
                     context->capture_x,
                     context->capture_y,
                     AllPlanes)
#else
        0
#endif
    )
    {
        image = context->shm.image;
        shm_used = 1;
    }
    else
    {
        image = XGetImage(context->display,
                          context->capture_drawable,
                          context->capture_x,
                          context->capture_y,
                          context->width,
                          context->height,
                          AllPlanes,
                          ZPixmap);
    }
    if (!image)
        return LIBRDP_STATUS_IO_ERROR;
    status = x11_server_convert_image(context,
                                      image,
                                      context->frame_pixels,
                                      context->frame_stride,
                                      context->frame_capacity);
    if (!shm_used)
        XDestroyImage(image);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(&frame, 0, sizeof(frame));
    frame.width = context->width;
    frame.height = context->height;
    frame.stride = context->frame_stride;
    frame.pixels = context->frame_pixels;
    frame.pixels_len = context->frame_stride * context->height;
    frame.dirty_rects = context->dirty;
    frame.dirty_count = context->dirty_count;
    frame.sequence = ++context->frame_sequence;
    frame.timestamp_ns = x11_server_now_ns();
    context->capture_sink.frame(&frame,
                                context->capture_sink.user_data);
    context->dirty_count = 0u;
    context->capture_due = 0;
    context->full_capture_due = 0;
    if (!context->damage_available)
    {
        uint64_t now_ns = x11_server_now_ns();

        context->next_capture_poll_ns =
            now_ns <= UINT64_MAX - X11_SERVER_CAPTURE_POLL_INTERVAL_NS
                ? now_ns + X11_SERVER_CAPTURE_POLL_INTERVAL_NS
                : UINT64_MAX;
    }
    return LIBRDP_STATUS_OK;
}

void x11_server_capture_handle_event(x11_server_context* context,
                                     const XEvent* event)
{
    if (!context || !event)
        return;
    if (context->damage_available &&
        event->type == context->damage_event_base + XDamageNotify)
    {
        const XDamageNotifyEvent* damage =
            (const XDamageNotifyEvent*)event;

        x11_server_invalidate(context,
                              damage->area.x,
                              damage->area.y,
                              damage->area.width,
                              damage->area.height);
        XDamageSubtract(context->display,
                        context->damage,
                        None,
                        None);
    }
    else if (event->type == ConfigureNotify &&
             event->xconfigure.window == context->target)
    {
        (void)x11_server_refresh_geometry(context, 1);
    }
    else if (event->type == DestroyNotify &&
             event->xdestroywindow.window == context->target)
    {
        context->target_destroyed = 1;
        if (context->capture_sink.lost)
        {
            context->capture_sink.lost(
                LIBRDP_STATUS_IO_ERROR,
                context->capture_sink.user_data);
        }
    }
    else if (event->type == context->randr_event_base + RRScreenChangeNotify ||
             event->type == context->randr_event_base + RRNotify)
    {
        (void)x11_server_refresh_geometry(context, 1);
    }
}

static librdp_status x11_server_capture_start(
    void* opaque,
    const server_platform_capture_sink* sink)
{
    x11_server_context* context = (x11_server_context*)opaque;

    if (!context || !sink || !sink->frame || !sink->lost)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (context->capture_started)
        return LIBRDP_STATUS_STATE;
    context->capture_sink = *sink;
    context->capture_started = 1;
    context->capture_due = 1;
    context->full_capture_due = 1;
    context->next_capture_poll_ns = x11_server_now_ns();
    return LIBRDP_STATUS_OK;
}

static void x11_server_capture_stop(void* opaque)
{
    x11_server_context* context = (x11_server_context*)opaque;

    if (!context)
        return;
    memset(&context->capture_sink, 0, sizeof(context->capture_sink));
    context->capture_started = 0;
    context->capture_due = 0;
    context->next_capture_poll_ns = 0u;
}

static librdp_status x11_server_capture_request_frame(void* opaque)
{
    x11_server_context* context = (x11_server_context*)opaque;

    if (!context || !context->capture_started)
        return LIBRDP_STATUS_STATE;
    context->dirty_count = 1u;
    context->dirty[0].x = 0u;
    context->dirty[0].y = 0u;
    context->dirty[0].width = context->width;
    context->dirty[0].height = context->height;
    context->capture_due = 1;
    context->full_capture_due = 1;
    return x11_server_capture_frame(context);
}

const server_platform_capture_vtable x11_server_capture_vtable = {
    SERVER_PLATFORM_CAPTURE_VERSION,
    sizeof(server_platform_capture_vtable),
    x11_server_capture_start,
    x11_server_capture_stop,
    x11_server_capture_request_frame,
    &x11_server_event_source_vtable,
};
