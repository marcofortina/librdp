/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa media backend tests.
 * Coverage: selector validation, camera media bounds, deterministic file
 * source samples, and rejection of malformed capture requests without opening
 * real devices.
 * Failure policy: malformed local sources and oversized media formats must be
 * rejected before AVFoundation or filesystem capture starts.
 */

#include "cocoa_media.h"

#import <Foundation/Foundation.h>

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

int main(void)
{
    int ok = 1;

    @autoreleasepool
    {
        ok &= test_camera_source_policy();
        ok &= test_camera_media_policy();
        ok &= test_camera_file_source();
    }
    return ok ? 0 : 1;
}
