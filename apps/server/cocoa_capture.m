/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: ScreenCaptureKit frame ingestion.
 * Invariants: only complete BGRA32 frames enter the bounded single-frame
 * queue, dirty rectangles are clipped to the sample dimensions, and a newer
 * frame replaces an unconsumed one to prevent capture backpressure.
 * Ownership: sample buffers are borrowed by the callback and copied before it
 * returns; the context owns the pending copy.
 * Threading: ScreenCaptureKit invokes this module on a private serial queue.
 * Trust boundary: pixel buffers and attachment dictionaries are validated
 * before arithmetic, allocation or publication.
 */

#include "cocoa_server_internal.h"

#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void cocoa_server_release_dispatch_object(dispatch_object_t object)
{
#if !OS_OBJECT_USE_OBJC
    if (object)
        dispatch_release(object);
#else
    (void)object;
#endif
}

uint64_t cocoa_server_now_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0u;
    return (uint64_t)now.tv_sec * 1000000000u +
           (uint64_t)now.tv_nsec;
}

static int cocoa_server_size_multiply(size_t left,
                                      size_t right,
                                      size_t* result)
{
    if (!result || (left != 0u && right > SIZE_MAX / left))
        return 0;
    *result = left * right;
    return 1;
}

static int cocoa_server_window_bounds(CGWindowID window_id,
                                      CGRect* bounds)
{
    CFArrayRef windows = NULL;
    NSDictionary* window = nil;
    NSNumber* number = nil;
    NSDictionary* value = nil;
    CGRect candidate = CGRectZero;
    int found = 0;

    if (window_id == kCGNullWindowID || !bounds)
        return 0;
    windows = CGWindowListCopyWindowInfo(
        kCGWindowListOptionIncludingWindow,
        window_id);
    if (windows && CFArrayGetCount(windows) == 1)
    {
        window = (NSDictionary*)CFArrayGetValueAtIndex(windows, 0);
        number = [window objectForKey:(id)kCGWindowNumber];
        value = [window objectForKey:(id)kCGWindowBounds];
        found = [number isKindOfClass:[NSNumber class]] &&
                [number unsignedIntValue] == window_id && value &&
                CGRectMakeWithDictionaryRepresentation(
                    (CFDictionaryRef)value,
                    &candidate) &&
                isfinite(candidate.origin.x) &&
                isfinite(candidate.origin.y) &&
                isfinite(candidate.size.width) &&
                isfinite(candidate.size.height) &&
                candidate.size.width > 0.0 &&
                candidate.size.height > 0.0;
    }
    if (windows)
        CFRelease(windows);
    if (found)
        *bounds = candidate;
    return found;
}

/*
 * Rasterize a Quartz window image into tightly packed, top-down BGRA. The
 * output dimensions and logical-to-pixel scale form one topology snapshot so
 * the host thread can update pointer mapping and peer surfaces atomically.
 */
static librdp_status cocoa_server_copy_window_image(
    const cocoa_server_context* context,
    CGImageRef image,
    CGRect source_rect,
    cocoa_server_frame_packet* packet)
{
    CGColorSpaceRef color_space = NULL;
    CGContextRef bitmap = NULL;
    uint8_t* pixels = NULL;
    size_t width = 0u;
    size_t height = 0u;
    size_t stride = 0u;
    size_t bytes = 0u;
    double horizontal_scale = 0.0;
    double vertical_scale = 0.0;
    librdp_status status = LIBRDP_STATUS_INVALID_ARGUMENT;

    if (!context || !image || !packet ||
        !isfinite(source_rect.origin.x) ||
        !isfinite(source_rect.origin.y) ||
        !isfinite(source_rect.size.width) ||
        !isfinite(source_rect.size.height) ||
        source_rect.size.width <= 0.0 || source_rect.size.height <= 0.0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    width = CGImageGetWidth(image);
    height = CGImageGetHeight(image);
    if (width == 0u || height == 0u || width > 16384u ||
        height > 16384u || width > SIZE_MAX / 4u)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    stride = width * 4u;
    if (!cocoa_server_size_multiply(stride, height, &bytes) ||
        bytes > context->config.max_frame_bytes ||
        width > UINT32_MAX || height > UINT32_MAX)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    horizontal_scale = (double)width / source_rect.size.width;
    vertical_scale = (double)height / source_rect.size.height;
    if (!isfinite(horizontal_scale) || !isfinite(vertical_scale) ||
        horizontal_scale <= 0.0 || vertical_scale <= 0.0 ||
        fabs(horizontal_scale - vertical_scale) > 0.05)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    pixels = (uint8_t*)calloc(1u, bytes);
    color_space = CGColorSpaceCreateDeviceRGB();
    if (!pixels || !color_space)
        status = LIBRDP_STATUS_NO_MEMORY;
    else
    {
        bitmap = CGBitmapContextCreate(
            pixels,
            width,
            height,
            8u,
            stride,
            color_space,
            (CGBitmapInfo)((uint32_t)kCGBitmapByteOrder32Little |
                           (uint32_t)kCGImageAlphaPremultipliedFirst));
        if (!bitmap)
            status = LIBRDP_STATUS_IO_ERROR;
        else
        {
            CGContextSetBlendMode(bitmap, kCGBlendModeCopy);
            CGContextDrawImage(bitmap,
                               CGRectMake(0.0,
                                          0.0,
                                          (double)width,
                                          (double)height),
                               image);
            memset(packet, 0, sizeof(*packet));
            packet->pixels = pixels;
            packet->pixels_len = bytes;
            packet->stride = stride;
            packet->width = (uint32_t)width;
            packet->height = (uint32_t)height;
            packet->timestamp_ns = cocoa_server_now_ns();
            packet->source_rect = source_rect;
            packet->source_scale = horizontal_scale;
            packet->topology_valid = 1;
            packet->ready = 1;
            pixels = NULL;
            status = LIBRDP_STATUS_OK;
        }
    }
    if (bitmap)
        CGContextRelease(bitmap);
    if (color_space)
        CGColorSpaceRelease(color_space);
    free(pixels);
    return status;
}

librdp_status cocoa_server_window_snapshot(
    cocoa_server_context* context,
    cocoa_server_frame_packet* packet)
{
    CGImageRef image = NULL;
    CGRect bounds = CGRectZero;
    librdp_status status = LIBRDP_STATUS_CLOSED;

    if (!context || !packet ||
        context->config.source_kind != COCOA_SERVER_SOURCE_WINDOW ||
        !cocoa_server_window_bounds(
            (CGWindowID)context->stable_source_id,
            &bounds))
        return LIBRDP_STATUS_CLOSED;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    image = CGWindowListCreateImage(
        CGRectNull,
        kCGWindowListOptionIncludingWindow,
        (CGWindowID)context->stable_source_id,
        kCGWindowImageBoundsIgnoreFraming |
            kCGWindowImageBestResolution);
#pragma clang diagnostic pop
    if (image)
    {
        status = cocoa_server_copy_window_image(
            context,
            image,
            bounds,
            packet);
        CGImageRelease(image);
    }
    return status;
}

#ifdef LIBRDP_COCOA_SERVER_TESTING
librdp_status cocoa_server_test_copy_window_image(
    const cocoa_server_context* context,
    CGImageRef image,
    CGRect source_rect,
    cocoa_server_frame_packet* packet)
{
    return cocoa_server_copy_window_image(
        context,
        image,
        source_rect,
        packet);
}
#endif

void cocoa_server_wakeup(cocoa_server_context* context)
{
    const uint8_t byte = 1u;
    ssize_t written = 0;

    if (!context || context->wakeup_write_fd < 0)
        return;
    do
    {
        written = write(context->wakeup_write_fd, &byte, sizeof(byte));
    } while (written < 0 && errno == EINTR);
}

static int cocoa_server_rect_from_value(id value,
                                        uint32_t width,
                                        uint32_t height,
                                        server_platform_rect* output)
{
    CGRect rect = CGRectZero;
    double left = 0.0;
    double top = 0.0;
    double right = 0.0;
    double bottom = 0.0;

    if (!value || !output)
        return 0;
    if ([value isKindOfClass:[NSString class]])
        rect = NSRectToCGRect(NSRectFromString((NSString*)value));
    else if ([value isKindOfClass:[NSValue class]])
        rect = [(NSValue*)value rectValue];
    else
        return 0;
    if (!isfinite(rect.origin.x) || !isfinite(rect.origin.y) ||
        !isfinite(rect.size.width) || !isfinite(rect.size.height) ||
        rect.size.width <= 0.0 || rect.size.height <= 0.0)
        return 0;
    left = floor(MAX(0.0, rect.origin.x));
    top = floor(MAX(0.0, rect.origin.y));
    right = ceil(MIN((double)width,
                     rect.origin.x + rect.size.width));
    bottom = ceil(MIN((double)height,
                      rect.origin.y + rect.size.height));
    if (left >= right || top >= bottom ||
        left > (double)UINT32_MAX || top > (double)UINT32_MAX ||
        right > (double)UINT32_MAX || bottom > (double)UINT32_MAX)
        return 0;
    output->x = (uint32_t)left;
    output->y = (uint32_t)top;
    output->width = (uint32_t)(right - left);
    output->height = (uint32_t)(bottom - top);
    return 1;
}

static size_t cocoa_server_dirty_rects(CMSampleBufferRef sample,
                                       uint32_t width,
                                       uint32_t height,
                                       server_platform_rect* output,
                                       size_t capacity)
{
    CFArrayRef attachments = NULL;
    NSDictionary* metadata = nil;
    NSArray* values = nil;
    size_t count = 0u;

    attachments =
        CMSampleBufferGetSampleAttachmentsArray(sample, false);
    if (!attachments || CFArrayGetCount(attachments) < 1)
        return 0u;
    metadata =
        (NSDictionary*)CFArrayGetValueAtIndex(attachments, 0);
    if (@available(macOS 14.0, *))
        values = [metadata objectForKey:SCStreamFrameInfoDirtyRects];
    if (![values isKindOfClass:[NSArray class]])
        return 0u;
    for (id value in values)
    {
        if (count >= capacity)
            break;
        if (cocoa_server_rect_from_value(value,
                                         width,
                                         height,
                                         &output[count]))
            count++;
    }
    return count;
}

static int cocoa_server_frame_complete(CMSampleBufferRef sample)
{
    CFArrayRef attachments = NULL;
    NSDictionary* metadata = nil;
    NSNumber* status = nil;

    attachments =
        CMSampleBufferGetSampleAttachmentsArray(sample, false);
    if (!attachments || CFArrayGetCount(attachments) < 1)
        return 0;
    metadata =
        (NSDictionary*)CFArrayGetValueAtIndex(attachments, 0);
    status = [metadata objectForKey:SCStreamFrameInfoStatus];
    return [status isKindOfClass:[NSNumber class]] &&
           [status integerValue] == SCFrameStatusComplete;
}

static int cocoa_server_content_dimensions(
    CMSampleBufferRef sample,
    uint32_t* width,
    uint32_t* height)
{
    CFArrayRef attachments = NULL;
    NSDictionary* metadata = nil;
    id rect_value = nil;
    NSNumber* scale_value = nil;
    CGRect rect = CGRectZero;
    double scale = 0.0;
    double pixel_width = 0.0;
    double pixel_height = 0.0;

    if (!sample || !width || !height)
        return 0;
    attachments =
        CMSampleBufferGetSampleAttachmentsArray(sample, false);
    if (!attachments || CFArrayGetCount(attachments) < 1)
        return 0;
    metadata =
        (NSDictionary*)CFArrayGetValueAtIndex(attachments, 0);
    rect_value =
        [metadata objectForKey:SCStreamFrameInfoContentRect];
    scale_value =
        [metadata objectForKey:SCStreamFrameInfoScaleFactor];
    if ([rect_value isKindOfClass:[NSString class]])
        rect = NSRectToCGRect(
            NSRectFromString((NSString*)rect_value));
    else if ([rect_value isKindOfClass:[NSValue class]])
        rect = [(NSValue*)rect_value rectValue];
    else
        return 0;
    if (![scale_value isKindOfClass:[NSNumber class]])
        return 0;
    scale = [scale_value doubleValue];
    pixel_width = ceil(rect.size.width * scale);
    pixel_height = ceil(rect.size.height * scale);
    if (!isfinite(pixel_width) || !isfinite(pixel_height) ||
        pixel_width < 1.0 || pixel_height < 1.0 ||
        pixel_width > 16384.0 || pixel_height > 16384.0)
        return 0;
    *width = (uint32_t)pixel_width;
    *height = (uint32_t)pixel_height;
    return 1;
}

/*
 * Convert one complete pixel buffer into the newest pending packet. Allocation
 * and copy sizes are checked before locking; under the mutex, frame replacement
 * is atomic and content-geometry drift schedules a topology refresh without
 * calling native framework methods from the capture queue.
 */
void cocoa_server_capture_enqueue(cocoa_server_context* context,
                                  CMSampleBufferRef sample)
{
    CVPixelBufferRef image = NULL;
    cocoa_server_frame_packet packet;
    size_t bytes = 0u;
    size_t width = 0u;
    size_t height = 0u;
    size_t stride = 0u;
    void* base = NULL;
    uint32_t content_width = 0u;
    uint32_t content_height = 0u;
    int content_dimensions_valid = 0;

    if (!context || !sample || !CMSampleBufferIsValid(sample) ||
        !cocoa_server_frame_complete(sample))
        return;
    image = CMSampleBufferGetImageBuffer(sample);
    if (!image ||
        CVPixelBufferGetPixelFormatType(image) !=
            kCVPixelFormatType_32BGRA)
        return;
    if (CVPixelBufferLockBaseAddress(
            image, kCVPixelBufferLock_ReadOnly) != kCVReturnSuccess)
        return;
    width = CVPixelBufferGetWidth(image);
    height = CVPixelBufferGetHeight(image);
    stride = CVPixelBufferGetBytesPerRow(image);
    base = CVPixelBufferGetBaseAddress(image);
    memset(&packet, 0, sizeof(packet));
    if (!base || width == 0u || height == 0u ||
        width > 16384u || height > 16384u ||
        width > SIZE_MAX / 4u || stride < width * 4u ||
        !cocoa_server_size_multiply(stride, height, &bytes) ||
        bytes > context->config.max_frame_bytes ||
        width > UINT32_MAX || height > UINT32_MAX)
    {
        CVPixelBufferUnlockBaseAddress(
            image, kCVPixelBufferLock_ReadOnly);
        return;
    }
    packet.pixels = (uint8_t*)malloc(bytes);
    if (!packet.pixels)
    {
        CVPixelBufferUnlockBaseAddress(
            image, kCVPixelBufferLock_ReadOnly);
        return;
    }
    memcpy(packet.pixels, base, bytes);
    packet.pixels_len = bytes;
    packet.stride = stride;
    packet.width = (uint32_t)width;
    packet.height = (uint32_t)height;
    packet.dirty_count = cocoa_server_dirty_rects(
        sample,
        packet.width,
        packet.height,
        packet.dirty,
        COCOA_SERVER_MAX_DIRTY_RECTS);
    packet.timestamp_ns = cocoa_server_now_ns();
    packet.ready = 1;
    content_dimensions_valid = cocoa_server_content_dimensions(
        sample,
        &content_width,
        &content_height);
    CVPixelBufferUnlockBaseAddress(
        image, kCVPixelBufferLock_ReadOnly);

    pthread_mutex_lock(&context->lock);
    if (context->force_full_frame)
        packet.dirty_count = 0u;
    if ((content_dimensions_valid &&
         (content_width != context->width ||
          content_height != context->height)) ||
        packet.width != context->width ||
        packet.height != context->height)
        context->topology_refresh_required = 1;
    packet.sequence = ++context->next_sequence;
    free(context->pending_frame.pixels);
    context->pending_frame = packet;
    pthread_mutex_unlock(&context->lock);
    cocoa_server_wakeup(context);
}

void cocoa_server_capture_lost(cocoa_server_context* context,
                               librdp_status status)
{
    if (!context)
        return;
    pthread_mutex_lock(&context->lock);
    if (context->stopping)
    {
        pthread_mutex_unlock(&context->lock);
        return;
    }
    context->capture_lost = 1;
    context->restart_required = 1;
    context->pending_lost_status = status;
    pthread_mutex_unlock(&context->lock);
    cocoa_server_wakeup(context);
}

static void cocoa_server_capture_window(
    cocoa_server_context* context)
{
    cocoa_server_frame_packet packet;
    librdp_status status = LIBRDP_STATUS_OK;
    int publish_lost = 0;

    if (!context)
        return;
    memset(&packet, 0, sizeof(packet));
    status = cocoa_server_window_snapshot(context, &packet);
    pthread_mutex_lock(&context->lock);
    if (context->stopping || context->capture_lost)
    {
        pthread_mutex_unlock(&context->lock);
        free(packet.pixels);
        return;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        context->window_capture_failures = 0u;
        packet.sequence = ++context->next_sequence;
        free(context->pending_frame.pixels);
        context->pending_frame = packet;
        memset(&packet, 0, sizeof(packet));
    }
    else
    {
        context->window_capture_failures++;
        publish_lost = context->window_capture_failures >= 3u;
    }
    pthread_mutex_unlock(&context->lock);
    free(packet.pixels);
    if (publish_lost)
        cocoa_server_capture_lost(context, status);
    else if (status == LIBRDP_STATUS_OK)
        cocoa_server_wakeup(context);
}

@implementation CocoaServerCaptureDelegate
- (id)initWithContext:(cocoa_server_context*)context
{
    self = [super init];
    if (self)
        _context = context;
    return self;
}

- (void)stream:(SCStream*)stream
 didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
        ofType:(SCStreamOutputType)type
{
    (void)stream;
    @autoreleasepool
    {
        if (type == SCStreamOutputTypeScreen)
            cocoa_server_capture_enqueue(_context, sampleBuffer);
    }
}

- (void)stream:(SCStream*)stream didStopWithError:(NSError*)error
{
    (void)stream;
    cocoa_server_capture_lost(
        _context,
        error ? LIBRDP_STATUS_IO_ERROR : LIBRDP_STATUS_CLOSED);
}
@end

static librdp_status cocoa_server_capture_start(
    void* opaque,
    const server_platform_capture_sink* sink)
{
    cocoa_server_context* context =
        (cocoa_server_context*)opaque;
    __block NSError* error = nil;
    dispatch_semaphore_t semaphore = NULL;
    long wait_result = 0;

    if (!context || !sink || !sink->frame || !sink->lost ||
        context->capture_started)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    context->capture_sink = *sink;
    if (context->config.source_kind == COCOA_SERVER_SOURCE_WINDOW)
    {
        uint64_t interval =
            1000000000ull / context->config.max_fps;

        context->window_timer = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_TIMER,
            0u,
            0u,
            context->capture_queue);
        if (!context->window_timer)
        {
            memset(&context->capture_sink, 0, sizeof(context->capture_sink));
            return LIBRDP_STATUS_NO_MEMORY;
        }
        context->capture_started = 1;
        dispatch_source_set_timer(context->window_timer,
                                  DISPATCH_TIME_NOW,
                                  interval,
                                  interval / 10u);
        dispatch_source_set_event_handler(context->window_timer, ^{
            @autoreleasepool
            {
                cocoa_server_capture_window(context);
            }
        });
        dispatch_resume(context->window_timer);
        return LIBRDP_STATUS_OK;
    }
    semaphore = dispatch_semaphore_create(0);
    if (!semaphore)
        return LIBRDP_STATUS_NO_MEMORY;
    [context->stream startCaptureWithCompletionHandler:^(NSError* value) {
        if (value)
            error = [value retain];
        dispatch_semaphore_signal(semaphore);
    }];
    wait_result = dispatch_semaphore_wait(
        semaphore,
        dispatch_time(DISPATCH_TIME_NOW, 15ll * NSEC_PER_SEC));
    cocoa_server_release_dispatch_object(
        (dispatch_object_t)semaphore);
    if (wait_result != 0 || error)
    {
        [error release];
        memset(&context->capture_sink, 0, sizeof(context->capture_sink));
        return wait_result != 0 ? LIBRDP_STATUS_TIMEOUT
                                : LIBRDP_STATUS_IO_ERROR;
    }
    context->capture_started = 1;
    return LIBRDP_STATUS_OK;
}

static void cocoa_server_capture_stop(void* opaque)
{
    cocoa_server_context* context =
        (cocoa_server_context*)opaque;
    dispatch_semaphore_t semaphore = NULL;

    if (!context || !context->capture_started)
        return;
    pthread_mutex_lock(&context->lock);
    context->stopping = 1;
    pthread_mutex_unlock(&context->lock);
    if (context->window_timer)
    {
        dispatch_source_cancel(context->window_timer);
        if (context->capture_queue)
        {
            dispatch_sync(context->capture_queue, ^{
            });
        }
        cocoa_server_release_dispatch_object(
            (dispatch_object_t)context->window_timer);
        context->window_timer = NULL;
    }
    else
    {
        semaphore = dispatch_semaphore_create(0);
        [context->stream stopCaptureWithCompletionHandler:^(NSError* error) {
            (void)error;
            dispatch_semaphore_signal(semaphore);
        }];
        if (semaphore)
        {
            (void)dispatch_semaphore_wait(
                semaphore,
                dispatch_time(DISPATCH_TIME_NOW, 5ll * NSEC_PER_SEC));
            cocoa_server_release_dispatch_object(
                (dispatch_object_t)semaphore);
        }
        if (context->capture_queue)
        {
            dispatch_sync(context->capture_queue, ^{
            });
        }
    }
    context->capture_started = 0;
    pthread_mutex_lock(&context->lock);
    free(context->pending_frame.pixels);
    memset(&context->pending_frame, 0, sizeof(context->pending_frame));
    free(context->latest_frame.pixels);
    memset(&context->latest_frame, 0, sizeof(context->latest_frame));
    context->stopping = 0;
    context->capture_lost = 0;
    context->restart_required = 0;
    context->window_capture_failures = 0u;
    pthread_mutex_unlock(&context->lock);
    memset(&context->capture_sink, 0, sizeof(context->capture_sink));
}

static librdp_status cocoa_server_capture_request_frame(void* opaque)
{
    cocoa_server_context* context =
        (cocoa_server_context*)opaque;
    int queued = 0;

    if (!context || !context->capture_started)
        return LIBRDP_STATUS_STATE;
    if (context->config.source_kind == COCOA_SERVER_SOURCE_WINDOW)
    {
        dispatch_async(context->capture_queue, ^{
            @autoreleasepool
            {
                cocoa_server_capture_window(context);
            }
        });
        return LIBRDP_STATUS_OK;
    }
    pthread_mutex_lock(&context->lock);
    context->force_full_frame = 1;
    if (context->pending_frame.ready)
    {
        context->pending_frame.dirty_count = 0u;
        queued = 1;
    }
    else if (context->latest_frame.ready)
    {
        context->pending_frame = context->latest_frame;
        memset(&context->latest_frame, 0, sizeof(context->latest_frame));
        context->pending_frame.dirty_count = 0u;
        context->pending_frame.sequence = ++context->next_sequence;
        queued = 1;
    }
    pthread_mutex_unlock(&context->lock);
    if (queued)
        cocoa_server_wakeup(context);
    return LIBRDP_STATUS_OK;
}

static librdp_status cocoa_server_events_get_pollfds(
    void* opaque,
    struct pollfd* fds,
    size_t capacity,
    size_t* count)
{
    cocoa_server_context* context =
        (cocoa_server_context*)opaque;

    if (!context || !count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *count = 1u;
    if (!fds)
        return capacity == 0u ? LIBRDP_STATUS_OK
                              : LIBRDP_STATUS_INVALID_ARGUMENT;
    if (capacity < 1u)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    fds[0].fd = context->wakeup_read_fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    return LIBRDP_STATUS_OK;
}

static librdp_status cocoa_server_events_notify_poll(
    void* opaque,
    const struct pollfd* fds,
    size_t count)
{
    cocoa_server_context* context =
        (cocoa_server_context*)opaque;

    if (!context || !fds || count != 1u ||
        fds[0].fd != context->wakeup_read_fd)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return LIBRDP_STATUS_OK;
}

static void cocoa_server_events_drain(cocoa_server_context* context)
{
    uint8_t buffer[128];
    ssize_t count = 0;

    do
    {
        count = read(context->wakeup_read_fd,
                     buffer,
                     sizeof(buffer));
    } while (count > 0 || (count < 0 && errno == EINTR));
}

/*
 * Dispatch one bounded snapshot of capture-queue state on the host thread.
 * Frame ownership moves out of the protected pending slot exactly once;
 * topology refresh and terminal callbacks run only after releasing the lock,
 * and a refresh failure is reported without publishing partial geometry.
 */
static librdp_status cocoa_server_events_dispatch(void* opaque,
                                                  unsigned int max_events)
{
    cocoa_server_context* context =
        (cocoa_server_context*)opaque;
    cocoa_server_frame_packet frame;
    librdp_status lost_status = LIBRDP_STATUS_OK;
    librdp_status topology_status = LIBRDP_STATUS_OK;
    int lost = 0;
    int restart = 0;
    int refresh_topology = 0;

    if (!context || max_events == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&frame, 0, sizeof(frame));
    cocoa_server_events_drain(context);
    pthread_mutex_lock(&context->lock);
    if (context->pending_frame.ready)
    {
        frame = context->pending_frame;
        memset(&context->pending_frame, 0,
               sizeof(context->pending_frame));
        if (frame.dirty_count == 0u)
            context->force_full_frame = 0;
    }
    if (context->capture_lost)
    {
        lost = 1;
        restart = context->restart_required;
        lost_status = context->pending_lost_status;
        context->capture_lost = 0;
        context->restart_required = 0;
    }
    refresh_topology = context->topology_refresh_required;
    context->topology_refresh_required = 0;
    pthread_mutex_unlock(&context->lock);
    if (frame.ready && context->capture_sink.frame)
    {
        server_platform_frame platform_frame;

        if (frame.topology_valid)
        {
            context->width = frame.width;
            context->height = frame.height;
            context->source_rect = frame.source_rect;
            context->source_scale = frame.source_scale;
        }

        memset(&platform_frame, 0, sizeof(platform_frame));
        platform_frame.width = frame.width;
        platform_frame.height = frame.height;
        platform_frame.stride = frame.stride;
        platform_frame.pixels = frame.pixels;
        platform_frame.pixels_len = frame.pixels_len;
        platform_frame.dirty_rects = frame.dirty;
        platform_frame.dirty_count = frame.dirty_count;
        platform_frame.sequence = frame.sequence;
        platform_frame.timestamp_ns = frame.timestamp_ns;
        context->capture_sink.frame(
            &platform_frame,
            context->capture_sink.user_data);
        pthread_mutex_lock(&context->lock);
        free(context->latest_frame.pixels);
        context->latest_frame = frame;
        memset(&frame, 0, sizeof(frame));
        pthread_mutex_unlock(&context->lock);
    }
    free(frame.pixels);
    if (restart || refresh_topology)
    {
        topology_status =
            cocoa_server_refresh_topology(context, restart);
        if (topology_status == LIBRDP_STATUS_OK)
            lost = 0;
        else if (!lost)
        {
            lost = 1;
            lost_status = topology_status;
        }
    }
    if (lost && context->capture_sink.lost)
        context->capture_sink.lost(
            lost_status,
            context->capture_sink.user_data);
    return LIBRDP_STATUS_OK;
}

static librdp_status cocoa_server_events_get_next_timeout(
    void* opaque,
    int* timeout_ms)
{
    if (!opaque || !timeout_ms)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *timeout_ms = -1;
    return LIBRDP_STATUS_OK;
}

static const server_platform_event_source_vtable
    cocoa_server_event_source_vtable = {
        SERVER_PLATFORM_EVENT_SOURCE_VERSION,
        sizeof(server_platform_event_source_vtable),
        cocoa_server_events_get_pollfds,
        cocoa_server_events_notify_poll,
        cocoa_server_events_dispatch,
        cocoa_server_events_get_next_timeout,
    };

const server_platform_capture_vtable cocoa_server_capture_vtable = {
    SERVER_PLATFORM_CAPTURE_VERSION,
    sizeof(server_platform_capture_vtable),
    cocoa_server_capture_start,
    cocoa_server_capture_stop,
    cocoa_server_capture_request_frame,
    &cocoa_server_event_source_vtable,
};
