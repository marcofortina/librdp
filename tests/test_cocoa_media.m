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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

static void test_camera_source_policy(void)
{
    assert(!cocoa_camera_source_allowed(NULL));
    assert(!cocoa_camera_source_allowed(""));
    assert(!cocoa_camera_source_allowed("device="));
    assert(!cocoa_camera_source_allowed("file="));
    assert(cocoa_camera_source_allowed("device=default"));
    assert(cocoa_camera_source_allowed("device=0"));
    assert(cocoa_camera_source_allowed("device=Built-in Camera"));
    assert(cocoa_camera_source_allowed("file=/tmp/camera.mjpg"));
    assert(cocoa_camera_source_allowed("/tmp/camera.mjpg"));
}

static void test_camera_media_policy(void)
{
    librdp_video_capture_media media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG, 640u, 480u);
    size_t max_sample_bytes = 0;

    assert(cocoa_camera_media_supported(&media, &max_sample_bytes));
    assert(max_sample_bytes == 64u * 1024u * 1024u);
    media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_H264, 640u, 480u);
    assert(cocoa_camera_media_supported(&media, &max_sample_bytes));
    media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_RGB32, 640u, 480u);
    assert(cocoa_camera_media_supported(&media, &max_sample_bytes));
    assert(max_sample_bytes == 640u * 480u * 4u);
    media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_RGB24, 640u, 480u);
    assert(cocoa_camera_media_supported(&media, &max_sample_bytes));
    assert(max_sample_bytes == 640u * 480u * 3u);
    media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG, 7681u, 480u);
    assert(!cocoa_camera_media_supported(&media, NULL));
    media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG, 640u, 480u);
    media.frame_rate_numerator = 121u;
    media.frame_rate_denominator = 1u;
    assert(!cocoa_camera_media_supported(&media, NULL));
    media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG, 640u, 480u);
    media.flags = 0x80u;
    assert(!cocoa_camera_media_supported(&media, NULL));
}

static void test_camera_file_source(void)
{
    char path[] = "/tmp/librdp-cocoa-camera-XXXXXX";
    char selector[sizeof(path) + 5u];
    const uint8_t expected[] = { 0xffu, 0xd8u, 0xffu, 0xd9u };
    uint8_t* sample = NULL;
    size_t sample_len = 0;
    int fd = -1;
    int selector_len = 0;
    cocoa_camera_source* camera = NULL;
    librdp_video_capture_media media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG, 640u, 480u);

    fd = mkstemp(path);
    assert(fd >= 0);
    assert(write(fd, expected, sizeof(expected)) == (ssize_t)sizeof(expected));
    close(fd);
    selector_len = snprintf(selector, sizeof(selector), "file=%s", path);
    assert(selector_len > 0 && (size_t)selector_len < sizeof(selector));
    camera = cocoa_camera_source_new();
    assert(camera != NULL);
    assert(cocoa_camera_source_start(camera, selector, &media));
    assert(cocoa_camera_source_read_sample(camera, &sample, &sample_len) == 1);
    assert(sample_len == sizeof(expected));
    assert(memcmp(sample, expected, sizeof(expected)) == 0);
    free(sample);
    cocoa_camera_source_free(camera);
    unlink(path);
}

int main(void)
{
    @autoreleasepool
    {
        test_camera_source_policy();
        test_camera_media_policy();
        test_camera_file_source();
    }
    return 0;
}
