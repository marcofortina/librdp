/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic Cocoa server capture ingestion tests.
 * Coverage: synthetic BGRA frame copy, dirty-rectangle clipping, content
 * geometry, frame replacement, incomplete samples and byte limits.
 * Bug classes: borrowed pixel lifetime, unchecked stride arithmetic, stale
 * frame publication, out-of-bounds damage and privacy-dependent test setup.
 * Determinism: CoreVideo buffers and CoreMedia samples are created in process;
 * no display, ScreenCaptureKit stream or Screen Recording permission is used.
 * Failure policy: malformed samples leave the pending frame unchanged.
 */

#include "cocoa_server_internal.h"

#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_check(int condition,
                      const char* expression,
                      int line)
{
    if (!condition)
        fprintf(stderr,
                "check failed %s:%d: %s\n",
                __FILE__,
                line,
                expression);
    return condition;
}

#define CHECK(expression)                                      \
    do                                                         \
    {                                                          \
        if (!test_check((expression), #expression, __LINE__))  \
            return 1;                                          \
    } while (0)

librdp_status cocoa_server_refresh_topology(
    cocoa_server_context* context,
    int restart_stream)
{
    (void)context;
    (void)restart_stream;
    return LIBRDP_STATUS_OK;
}

static CMSampleBufferRef test_sample_new(OSType format,
                                         uint32_t width,
                                         uint32_t height,
                                         SCFrameStatus status)
{
    CVPixelBufferRef pixels = NULL;
    CMVideoFormatDescriptionRef description = NULL;
    CMSampleBufferRef sample = NULL;
    CMSampleTimingInfo timing;
    CFArrayRef attachments = NULL;
    NSMutableDictionary* metadata = nil;
    size_t bytes = 0u;
    size_t index = 0u;

    memset(&timing, 0, sizeof(timing));
    timing.duration = kCMTimeInvalid;
    timing.presentationTimeStamp = kCMTimeZero;
    timing.decodeTimeStamp = kCMTimeInvalid;
    if (CVPixelBufferCreate(kCFAllocatorDefault,
                            width,
                            height,
                            format,
                            NULL,
                            &pixels) != kCVReturnSuccess)
        return NULL;
    if (CMVideoFormatDescriptionCreateForImageBuffer(
            kCFAllocatorDefault,
            pixels,
            &description) != noErr ||
        CMSampleBufferCreateForImageBuffer(
            kCFAllocatorDefault,
            pixels,
            true,
            NULL,
            NULL,
            description,
            &timing,
            &sample) != noErr)
    {
        if (description)
            CFRelease(description);
        CVPixelBufferRelease(pixels);
        return NULL;
    }
    if (CVPixelBufferLockBaseAddress(pixels, 0) != kCVReturnSuccess)
    {
        CFRelease(sample);
        CFRelease(description);
        CVPixelBufferRelease(pixels);
        return NULL;
    }
    bytes = CVPixelBufferGetBytesPerRow(pixels) *
            CVPixelBufferGetHeight(pixels);
    for (index = 0u; index < bytes; index++)
        ((uint8_t*)CVPixelBufferGetBaseAddress(pixels))[index] =
            (uint8_t)(index + 1u);
    CVPixelBufferUnlockBaseAddress(pixels, 0);
    attachments =
        CMSampleBufferGetSampleAttachmentsArray(sample, true);
    if (!attachments || CFArrayGetCount(attachments) != 1)
    {
        CFRelease(sample);
        CFRelease(description);
        CVPixelBufferRelease(pixels);
        return NULL;
    }
    metadata = (NSMutableDictionary*)CFArrayGetValueAtIndex(
        attachments,
        0);
    [metadata setObject:[NSNumber numberWithInteger:status]
                 forKey:SCStreamFrameInfoStatus];
    if (@available(macOS 14.0, *))
    {
        [metadata setObject:
                      @[
                          [NSValue valueWithRect:
                                       NSMakeRect(-1.0, 0.0, 3.0, 2.0)],
                          [NSValue valueWithRect:
                                       NSMakeRect(9.0, 9.0, 1.0, 1.0)]
                      ]
                     forKey:SCStreamFrameInfoDirtyRects];
    }
    [metadata setObject:
                  [NSValue valueWithRect:
                               NSMakeRect(0.0, 0.0, width, height)]
                 forKey:SCStreamFrameInfoContentRect];
    [metadata setObject:[NSNumber numberWithDouble:1.0]
                 forKey:SCStreamFrameInfoScaleFactor];
    CFRelease(description);
    CVPixelBufferRelease(pixels);
    return sample;
}

static int test_context_init(cocoa_server_context* context)
{
    if (!context)
        return 0;
    memset(context, 0, sizeof(*context));
    context->config.version = COCOA_SERVER_CONFIG_VERSION;
    context->config.size = sizeof(context->config);
    context->config.allow_capture = 1;
    context->config.max_frame_bytes = 1024u;
    context->width = 2u;
    context->height = 2u;
    context->wakeup_read_fd = -1;
    context->wakeup_write_fd = -1;
    return pthread_mutex_init(&context->lock, NULL) == 0;
}

static void test_context_clear(cocoa_server_context* context)
{
    if (!context)
        return;
    free(context->pending_frame.pixels);
    context->pending_frame.pixels = NULL;
    free(context->latest_frame.pixels);
    context->latest_frame.pixels = NULL;
    pthread_mutex_destroy(&context->lock);
}

typedef struct test_capture_sink_state
{
    unsigned int frames;
    size_t dirty_count;
    uint64_t sequence;
    uint8_t first_byte;
} test_capture_sink_state;

static void test_capture_sink_frame(const server_platform_frame* frame,
                                    void* user_data)
{
    test_capture_sink_state* state =
        (test_capture_sink_state*)user_data;

    if (!frame || !state || !frame->pixels || frame->pixels_len == 0u)
        return;
    state->frames++;
    state->dirty_count = frame->dirty_count;
    state->sequence = frame->sequence;
    state->first_byte = frame->pixels[0];
}

static void test_capture_sink_lost(librdp_status status,
                                   void* user_data)
{
    (void)status;
    (void)user_data;
}

static int test_capture_ingestion(void)
{
    cocoa_server_context context;
    CMSampleBufferRef complete = NULL;
    CMSampleBufferRef incomplete = NULL;
    CMSampleBufferRef wrong_format = NULL;
    uint8_t first_byte = 0u;
    uint64_t sequence = 0u;

    CHECK(test_context_init(&context));
    complete = test_sample_new(kCVPixelFormatType_32BGRA,
                               2u,
                               2u,
                               SCFrameStatusComplete);
    incomplete = test_sample_new(kCVPixelFormatType_32BGRA,
                                 2u,
                                 2u,
                                 SCFrameStatusIdle);
    wrong_format = test_sample_new(kCVPixelFormatType_32ARGB,
                                   2u,
                                   2u,
                                   SCFrameStatusComplete);
    CHECK(complete != NULL && incomplete != NULL &&
          wrong_format != NULL);
    cocoa_server_capture_enqueue(&context, complete);
    CHECK(context.pending_frame.ready == 1);
    CHECK(context.pending_frame.width == 2u);
    CHECK(context.pending_frame.height == 2u);
    CHECK(context.pending_frame.stride >= 8u);
    CHECK(context.pending_frame.pixels_len ==
          context.pending_frame.stride * 2u);
    if (@available(macOS 14.0, *))
    {
        CHECK(context.pending_frame.dirty_count == 1u);
        CHECK(context.pending_frame.dirty[0].x == 0u);
        CHECK(context.pending_frame.dirty[0].y == 0u);
        CHECK(context.pending_frame.dirty[0].width == 2u);
        CHECK(context.pending_frame.dirty[0].height == 2u);
    }
    else
        CHECK(context.pending_frame.dirty_count == 0u);
    CHECK(context.pending_frame.sequence == 1u);
    first_byte = context.pending_frame.pixels[0];
    sequence = context.pending_frame.sequence;

    cocoa_server_capture_enqueue(&context, incomplete);
    cocoa_server_capture_enqueue(&context, wrong_format);
    CHECK(context.pending_frame.sequence == sequence);
    CHECK(context.pending_frame.pixels[0] == first_byte);

    context.force_full_frame = 1;
    cocoa_server_capture_enqueue(&context, complete);
    CHECK(context.pending_frame.sequence == sequence + 1u);
    CHECK(context.pending_frame.dirty_count == 0u);
    CHECK(context.force_full_frame == 1);

    sequence = context.pending_frame.sequence;
    context.config.max_frame_bytes = 1u;
    cocoa_server_capture_enqueue(&context, complete);
    CHECK(context.pending_frame.sequence == sequence);

    CFRelease(wrong_format);
    CFRelease(incomplete);
    CFRelease(complete);
    test_context_clear(&context);
    return 0;
}

/*
 * Preserve the last delivered ScreenCaptureKit frame and replay it as a full
 * repaint when a peer activates while the desktop is otherwise static.
 */
static int test_capture_repaint(void)
{
    cocoa_server_context context;
    CMSampleBufferRef sample = NULL;
    test_capture_sink_state sink;
    uint64_t first_sequence = 0u;

    CHECK(test_context_init(&context));
    memset(&sink, 0, sizeof(sink));
    context.capture_started = 1;
    context.capture_sink.frame = test_capture_sink_frame;
    context.capture_sink.lost = test_capture_sink_lost;
    context.capture_sink.user_data = &sink;
    sample = test_sample_new(kCVPixelFormatType_32BGRA,
                             2u,
                             2u,
                             SCFrameStatusComplete);
    CHECK(sample != NULL);
    cocoa_server_capture_enqueue(&context, sample);
    CHECK(cocoa_server_capture_vtable.events->dispatch(&context, 1u) ==
          LIBRDP_STATUS_OK);
    CHECK(sink.frames == 1u);
    CHECK(context.pending_frame.ready == 0);
    CHECK(context.latest_frame.ready == 1);
    first_sequence = sink.sequence;

    CHECK(cocoa_server_capture_vtable.request_frame(&context) ==
          LIBRDP_STATUS_OK);
    CHECK(context.pending_frame.ready == 1);
    CHECK(context.pending_frame.dirty_count == 0u);
    CHECK(context.latest_frame.ready == 0);
    CHECK(cocoa_server_capture_vtable.events->dispatch(&context, 1u) ==
          LIBRDP_STATUS_OK);
    CHECK(sink.frames == 2u);
    CHECK(sink.dirty_count == 0u);
    CHECK(sink.sequence > first_sequence);
    CHECK(sink.first_byte == 1u);
    CHECK(context.latest_frame.ready == 1);
    CHECK(context.force_full_frame == 0);

    CFRelease(sample);
    context.capture_started = 0;
    test_context_clear(&context);
    return 0;
}

/*
 * Verify that Quartz images become top-down BGRA frames with one coherent
 * logical window geometry snapshot. Invalid scale and byte limits must fail
 * before publishing caller-owned pixels.
 */
static int test_window_image_copy(void)
{
    static const uint8_t source[] = {
        0u, 0u, 255u, 255u, 0u, 255u, 0u, 255u,
        255u, 0u, 0u, 255u, 255u, 255u, 255u, 255u,
    };
    cocoa_server_context context;
    cocoa_server_frame_packet packet;
    CGColorSpaceRef color_space = NULL;
    CGDataProviderRef provider = NULL;
    CGImageRef image = NULL;
    CGRect source_rect = CGRectMake(10.0, 20.0, 1.0, 1.0);

    CHECK(test_context_init(&context));
    provider = CGDataProviderCreateWithData(NULL,
                                            source,
                                            sizeof(source),
                                            NULL);
    color_space = CGColorSpaceCreateDeviceRGB();
    CHECK(provider != NULL && color_space != NULL);
    image = CGImageCreate(
        2u,
        2u,
        8u,
        32u,
        8u,
        color_space,
        (CGBitmapInfo)((uint32_t)kCGBitmapByteOrder32Little |
                       (uint32_t)kCGImageAlphaPremultipliedFirst),
        provider,
        NULL,
        false,
        kCGRenderingIntentDefault);
    CHECK(image != NULL);
    memset(&packet, 0, sizeof(packet));
    CHECK(cocoa_server_test_copy_window_image(&context,
                                              image,
                                              source_rect,
                                              &packet) == LIBRDP_STATUS_OK);
    CHECK(packet.ready == 1);
    CHECK(packet.topology_valid == 1);
    CHECK(packet.width == 2u && packet.height == 2u);
    CHECK(packet.stride == 8u && packet.pixels_len == sizeof(source));
    CHECK(packet.source_scale == 2.0);
    CHECK(CGRectEqualToRect(packet.source_rect, source_rect));
    CHECK(memcmp(packet.pixels, source, sizeof(source)) == 0);
    free(packet.pixels);
    memset(&packet, 0, sizeof(packet));

    source_rect.size.height = 2.0;
    CHECK(cocoa_server_test_copy_window_image(&context,
                                              image,
                                              source_rect,
                                              &packet) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    context.config.max_frame_bytes = sizeof(source) - 1u;
    source_rect.size.height = 1.0;
    CHECK(cocoa_server_test_copy_window_image(&context,
                                              image,
                                              source_rect,
                                              &packet) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);

    CGImageRelease(image);
    CGColorSpaceRelease(color_space);
    CGDataProviderRelease(provider);
    test_context_clear(&context);
    return 0;
}

int main(void)
{
    @autoreleasepool
    {
        if (test_capture_ingestion() != 0)
            return 1;
        if (test_capture_repaint() != 0)
            return 1;
        return test_window_image_copy();
    }
}
