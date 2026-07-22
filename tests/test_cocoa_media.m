/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa media backend tests.
 * Coverage: viewer option adaptation, selector validation, camera media
 * bounds, deterministic file source samples, and rejection of malformed
 * capture requests without opening real devices.
 * Failure policy: malformed local sources and oversized media formats must be
 * rejected before AVFoundation or filesystem capture starts.
 */

#include "cocoa_cli.h"
#include "cocoa_media.h"

#import <CoreVideo/CoreVideo.h>
#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int test_check(int condition, const char* expression, int line)
{
    if (!condition)
        fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, line, expression);
    return condition;
}

#define CHECK(expression)                    \
    do                                       \
    {                                        \
        if (!test_check((expression), #expression, __LINE__)) \
            return 0;                        \
    } while (0)

static librdp_video_capture_media test_media(uint8_t format, uint32_t width, uint32_t height)
{
    librdp_video_capture_media media;

    memset(&media, 0, sizeof(media));
    media.format = format;
    media.width = width;
    media.height = height;
    media.frame_rate_numerator = 30u;
    media.frame_rate_denominator = 1u;
    return media;
}

static int test_camera_source_policy(void)
{
    CHECK(!cocoa_camera_source_allowed(NULL));
    CHECK(!cocoa_camera_source_allowed(""));
    CHECK(!cocoa_camera_source_allowed("device="));
    CHECK(!cocoa_camera_source_allowed("file="));
    CHECK(cocoa_camera_source_allowed("device=default"));
    CHECK(cocoa_camera_source_allowed("device=0"));
    CHECK(cocoa_camera_source_allowed("device=Built-in Camera"));
    CHECK(cocoa_camera_source_allowed("file=/tmp/camera.mjpg"));
    CHECK(cocoa_camera_source_allowed("/tmp/camera.mjpg"));
    return 1;
}

static int test_cocoa_viewer_options(void)
{
    char* argv[] = {
        (char*)"viewer",
        (char*)"--target",
        (char*)"host.example",
        (char*)"--audio-output",
        (char*)"--audio-input",
        (char*)"--camera",
        (char*)"device=default",
    };
    cocoa_viewer_options options;
    librdp_settings* settings = librdp_settings_new();

    CHECK(settings != NULL);
    CHECK(cocoa_viewer_configure_settings(settings,
                                          &options,
                                          (int)(sizeof(argv) / sizeof(argv[0])),
                                          argv));
    CHECK(strcmp(librdp_settings_audio_output_device(settings), "coreaudio") == 0);
    CHECK(strcmp(librdp_settings_audio_input_device(settings), "coreaudio") == 0);
    CHECK(strcmp(librdp_settings_camera_source(settings, 0), "device=default") == 0);
    client_options_clear(&options);
    librdp_settings_free(settings);
    return 1;
}

static int test_camera_media_policy(void)
{
    librdp_video_capture_media media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG, 640u, 480u);
    size_t max_sample_bytes = 0;

    CHECK(cocoa_camera_media_supported(&media, &max_sample_bytes));
    CHECK(max_sample_bytes == 64u * 1024u * 1024u);
    media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_H264, 640u, 480u);
    CHECK(cocoa_camera_media_supported(&media, &max_sample_bytes));
    media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_RGB32, 640u, 480u);
    CHECK(cocoa_camera_media_supported(&media, &max_sample_bytes));
    CHECK(max_sample_bytes == 640u * 480u * 4u);
    media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_RGB24, 640u, 480u);
    CHECK(cocoa_camera_media_supported(&media, &max_sample_bytes));
    CHECK(max_sample_bytes == 640u * 480u * 3u);
    media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG, 7681u, 480u);
    CHECK(!cocoa_camera_media_supported(&media, NULL));
    media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG, 640u, 480u);
    media.frame_rate_numerator = 121u;
    media.frame_rate_denominator = 1u;
    CHECK(!cocoa_camera_media_supported(&media, NULL));
    media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG, 640u, 480u);
    media.flags = 0x80u;
    CHECK(!cocoa_camera_media_supported(&media, NULL));
    return 1;
}

static int test_camera_file_source(void)
{
    char path[] = "/tmp/librdp-cocoa-camera-XXXXXX";
    char selector[sizeof(path) + 5u];
    const uint8_t expected[] = { 0xffu, 0xd8u, 0xffu, 0xd9u };
    uint8_t* sample = NULL;
    size_t sample_len = 0;
    int fd = -1;
    int ok = 0;
    int selector_len = 0;
    cocoa_camera_source* camera = NULL;
    librdp_video_capture_media media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG, 640u, 480u);

    fd = mkstemp(path);
    if (!test_check(fd >= 0, "fd >= 0", __LINE__))
        goto cleanup;
    if (!test_check(write(fd, expected, sizeof(expected)) == (ssize_t)sizeof(expected),
                    "write camera sample",
                    __LINE__))
        goto cleanup;
    close(fd);
    fd = -1;
    selector_len = snprintf(selector, sizeof(selector), "file=%s", path);
    if (!test_check(selector_len > 0 && (size_t)selector_len < sizeof(selector),
                    "camera selector fits",
                    __LINE__))
        goto cleanup;
    camera = cocoa_camera_source_new();
    if (!test_check(camera != NULL, "camera != NULL", __LINE__) ||
        !test_check(cocoa_camera_source_start(camera, selector, &media), "camera source starts", __LINE__) ||
        !test_check(cocoa_camera_source_read_sample(camera, &sample, &sample_len) == 1,
                    "camera source returns a sample",
                    __LINE__) ||
        !test_check(sample_len == sizeof(expected), "camera sample length", __LINE__) ||
        !test_check(memcmp(sample, expected, sizeof(expected)) == 0, "camera sample payload", __LINE__))
        goto cleanup;
    ok = 1;

cleanup:
    if (fd >= 0)
        close(fd);
    free(sample);
    cocoa_camera_source_free(camera);
    unlink(path);
    return ok;
}

/*
 * A camera may capture above the negotiated size. This fixture verifies that
 * the native conversion returns the declared dimensions and byte layout.
 */
static int test_camera_live_size_normalization(void)
{
    static const uint8_t formats[] = {
        LIBRDP_VIDEO_CAPTURE_MEDIA_RGB32,
        LIBRDP_VIDEO_CAPTURE_MEDIA_RGB24,
        LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG,
    };
    CVPixelBufferRef pixel_buffer = NULL;
    CVReturn result = kCVReturnError;
    int ok = 1;

    result = CVPixelBufferCreate(kCFAllocatorDefault,
                                 1280u,
                                 720u,
                                 kCVPixelFormatType_32BGRA,
                                 NULL,
                                 &pixel_buffer);
    CHECK(result == kCVReturnSuccess && pixel_buffer != NULL);
    CHECK(CVPixelBufferLockBaseAddress(pixel_buffer, 0u) == kCVReturnSuccess);
    {
        uint8_t* base = (uint8_t*)CVPixelBufferGetBaseAddress(pixel_buffer);
        size_t stride = CVPixelBufferGetBytesPerRow(pixel_buffer);

        CHECK(base != NULL && stride >= 1280u * 4u);
        for (size_t row = 0u; row < 720u; row++)
        {
            uint8_t* output = base + row * stride;

            for (size_t column = 0u; column < 1280u; column++)
            {
                output[column * 4u + 0u] = 0x12u;
                output[column * 4u + 1u] = 0x34u;
                output[column * 4u + 2u] = 0x56u;
                output[column * 4u + 3u] = 0u;
            }
        }
    }
    CVPixelBufferUnlockBaseAddress(pixel_buffer, 0u);
    for (size_t index = 0u; index < sizeof(formats) / sizeof(formats[0]); index++)
    {
        librdp_video_capture_media media = test_media(formats[index], 640u, 480u);
        uint8_t* sample = NULL;
        size_t sample_len = 0u;

        if (!test_check(cocoa_camera_test_convert_pixel_buffer(
                            &media,
                            pixel_buffer,
                            &sample,
                            &sample_len),
                        "camera live conversion",
                        __LINE__))
        {
            ok = 0;
            free(sample);
            continue;
        }
        if (formats[index] == LIBRDP_VIDEO_CAPTURE_MEDIA_RGB32)
        {
            ok &= test_check(sample_len == 640u * 480u * 4u,
                             "RGB32 normalized length",
                             __LINE__);
            ok &= test_check(sample && sample[0] == 0x12u &&
                                 sample[1] == 0x34u && sample[2] == 0x56u,
                             "RGB32 normalized color",
                             __LINE__);
        }
        else if (formats[index] == LIBRDP_VIDEO_CAPTURE_MEDIA_RGB24)
        {
            ok &= test_check(sample_len == 640u * 480u * 3u,
                             "RGB24 normalized length",
                             __LINE__);
            ok &= test_check(sample && sample[0] == 0x56u &&
                                 sample[1] == 0x34u && sample[2] == 0x12u,
                             "RGB24 normalized color",
                             __LINE__);
        }
        else
        {
            CFDataRef encoded = sample
                                    ? CFDataCreate(kCFAllocatorDefault,
                                                   sample,
                                                   (CFIndex)sample_len)
                                    : NULL;
            CGImageSourceRef source = encoded
                                          ? CGImageSourceCreateWithData(encoded,
                                                                        NULL)
                                          : NULL;
            CGImageRef image = source
                                   ? CGImageSourceCreateImageAtIndex(source,
                                                                     0u,
                                                                     NULL)
                                   : NULL;

            ok &= test_check(image && CGImageGetWidth(image) == 640u &&
                                 CGImageGetHeight(image) == 480u,
                             "MJPEG normalized dimensions",
                             __LINE__);
            if (image)
                CGImageRelease(image);
            if (source)
                CFRelease(source);
            if (encoded)
                CFRelease(encoded);
        }
        free(sample);
    }
    if (pixel_buffer)
        CVPixelBufferRelease(pixel_buffer);
    return ok;
}

int main(void)
{
    int ok = 1;

    @autoreleasepool
    {
        ok &= test_cocoa_viewer_options();
        ok &= test_camera_source_policy();
        ok &= test_camera_media_policy();
        ok &= test_camera_file_source();
        ok &= test_camera_live_size_normalization();
    }
    return ok ? 0 : 1;
}
