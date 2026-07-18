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

static void cocoa_server_wakeup(cocoa_server_context* context)
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
        rect = CGRectFromString((NSString*)value);
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
        rect = CGRectFromString((NSString*)rect_value);
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
    {
        packet.dirty_count = 0u;
        context->force_full_frame = 0;
    }
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
    context->capture_started = 0;
    pthread_mutex_lock(&context->lock);
    context->stopping = 0;
    context->capture_lost = 0;
    context->restart_required = 0;
    pthread_mutex_unlock(&context->lock);
    memset(&context->capture_sink, 0, sizeof(context->capture_sink));
}

static librdp_status cocoa_server_capture_request_frame(void* opaque)
{
    cocoa_server_context* context =
        (cocoa_server_context*)opaque;

    if (!context || !context->capture_started)
        return LIBRDP_STATUS_STATE;
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
