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
    pthread_mutex_destroy(&context->lock);
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
    CHECK(context.force_full_frame == 0);

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

int main(void)
{
    @autoreleasepool
    {
        return test_capture_ingestion();
    }
}
