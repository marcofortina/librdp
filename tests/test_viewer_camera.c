/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer camera backend regression tests.
 * Coverage: V4L2 source policy, media bounds, and deterministic mock camera
 * lifecycle without opening a host video device.
 * Bug classes: implicit camera consent, oversized sample allocation, unplug
 * handling, unsupported media negotiation, and stale streaming metrics.
 * Determinism: tests use fixed media descriptors and an in-memory mock backend.
 */

#include "camera_v4l2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check_int(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr, "test_viewer_camera:%d: check failed: %s\n", line, expression);
    return 1;
}

#define CHECK(expr)                                                                                  \
    do                                                                                               \
    {                                                                                                \
        if (check_int((expr), #expr, __LINE__) != 0)                                                 \
            return 1;                                                                                \
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

/*
 * Camera sources must be explicit device paths. The viewer must not accept file
 * sources, relative paths, or directory traversal strings as camera consent.
 */
static int test_camera_source_policy(void)
{
    CHECK(x11_camera_source_allowed("device=/dev/video0") == 1);
    CHECK(x11_camera_source_allowed("/dev/video12") == 1);
    CHECK(x11_camera_source_allowed(NULL) == 0);
    CHECK(x11_camera_source_allowed("file=/tmp/frame.raw") == 0);
    CHECK(x11_camera_source_allowed("/tmp/video0") == 0);
    CHECK(x11_camera_source_allowed("/dev/video0/../mem") == 0);
    CHECK(x11_camera_source_allowed("/dev/video") == 0);
    return 0;
}

/*
 * Media validation bounds frame dimensions, frame rate, format identifiers, and
 * maximum sample allocation before a V4L2 device is opened.
 */
static int test_camera_media_policy(void)
{
    librdp_video_capture_media media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_YUY2, 640u, 480u);
    size_t max_sample = 0;

    CHECK(x11_camera_media_supported(&media, &max_sample) == 1);
    CHECK(max_sample == 640u * 480u * 2u);
    media.width = X11_CAMERA_MAX_WIDTH + 1u;
    CHECK(x11_camera_media_supported(&media, &max_sample) == 0);
    media = test_media(0xffu, 640u, 480u);
    CHECK(x11_camera_media_supported(&media, &max_sample) == 0);
    media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG, 640u, 480u);
    media.frame_rate_numerator = X11_CAMERA_MAX_FPS + 1u;
    media.frame_rate_denominator = 1u;
    CHECK(x11_camera_media_supported(&media, &max_sample) == 0);
    return 0;
}

/*
 * The mock backend verifies camera lifecycle outcomes without a real device:
 * normal samples are copied to caller-owned memory, permission denial fails
 * before streaming, unplug stops streaming, and oversized frames are rejected.
 */
static int test_camera_mock_lifecycle(void)
{
    librdp_video_capture_media media = test_media(LIBRDP_VIDEO_CAPTURE_MEDIA_YUY2, 2u, 2u);
    x11_camera_capture_stats stats;
    x11_camera_mock* mock = NULL;
    uint8_t* sample = NULL;
    size_t sample_len = 0;

    mock = x11_camera_mock_new(0, 0, 8u);
    CHECK(mock != NULL);
    CHECK(x11_camera_mock_start(mock, &media) == 1);
    CHECK(x11_camera_mock_read_sample(mock, &sample, &sample_len) == 1);
    CHECK(sample_len == 8u);
    CHECK(sample != NULL && sample[0] == 0x5a);
    free(sample);
    memset(&stats, 0, sizeof(stats));
    x11_camera_mock_get_stats(mock, &stats);
    CHECK(stats.frames == 1u);
    CHECK(stats.bytes == 8u);
    CHECK(stats.streaming == 1);
    x11_camera_mock_free(mock);

    mock = x11_camera_mock_new(1, 0, 8u);
    CHECK(mock != NULL);
    CHECK(x11_camera_mock_start(mock, &media) == 0);
    x11_camera_mock_get_stats(mock, &stats);
    CHECK(stats.errors == 1u);
    x11_camera_mock_free(mock);

    mock = x11_camera_mock_new(0, 1, 8u);
    CHECK(mock != NULL);
    CHECK(x11_camera_mock_start(mock, &media) == 1);
    CHECK(x11_camera_mock_read_sample(mock, &sample, &sample_len) == -1);
    x11_camera_mock_get_stats(mock, &stats);
    CHECK(stats.errors == 1u);
    CHECK(stats.streaming == 0);
    x11_camera_mock_free(mock);

    mock = x11_camera_mock_new(0, 0, 9u);
    CHECK(mock != NULL);
    CHECK(x11_camera_mock_start(mock, &media) == 1);
    CHECK(x11_camera_mock_read_sample(mock, &sample, &sample_len) == -1);
    x11_camera_mock_get_stats(mock, &stats);
    CHECK(stats.errors == 1u);
    CHECK(stats.oversize_frames == 1u);
    x11_camera_mock_free(mock);
    return 0;
}

int main(void)
{
    if (test_camera_source_policy() != 0)
        return 1;
    if (test_camera_media_policy() != 0)
        return 1;
    if (test_camera_mock_lifecycle() != 0)
        return 1;
    return 0;
}
