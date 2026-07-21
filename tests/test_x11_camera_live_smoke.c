/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: opt-in live V4L2 viewer camera smoke.
 * Coverage: real device format negotiation, bounded frame capture, clean stop,
 * and restart after cancellation.
 * Bug classes: accepted-but-inactive formats, stale MMAP buffers, unbounded
 * samples, lost stream state, and restart failures after teardown.
 * Determinism: the selected device and media parameters are explicit, waits
 * and sample counts are bounded, and captured bytes never affect assertions.
 * Privacy: sample payloads are validated in memory and immediately discarded;
 * no image, frame hash, or payload bytes are written to disk or trace.
 * Environment: LIBRDP_TEST_V4L2_DEVICE selects an explicitly authorized device.
 * Format, dimensions, frame rate, and sample count use the optional
 * LIBRDP_TEST_V4L2_FORMAT, _WIDTH, _HEIGHT, _FPS, and _FRAMES variables.
 */

#include "x11_camera_v4l2.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_SKIP 77
#define TEST_READ_ATTEMPTS 120u

static int check_int(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr,
            "test_x11_camera_live_smoke:%d: check failed: %s\n",
            line,
            expression);
    return 1;
}

#define CHECK(expr)                                                                                  \
    do                                                                                               \
    {                                                                                                \
        if (check_int((expr), #expr, __LINE__) != 0)                                                 \
            return 1;                                                                                \
    } while (0)

static int test_parse_u32(const char* value, uint32_t fallback, uint32_t* result)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!result)
        return 0;
    if (!value || value[0] == '\0')
    {
        *result = fallback;
        return 1;
    }
    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed == 0 || parsed > UINT32_MAX)
        return 0;
    *result = (uint32_t)parsed;
    return 1;
}

static int test_parse_format(const char* value, uint8_t* format)
{
    static const struct
    {
        const char* name;
        uint8_t format;
    } formats[] = {
        {"h264", LIBRDP_VIDEO_CAPTURE_MEDIA_H264},
        {"mjpg", LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG},
        {"yuy2", LIBRDP_VIDEO_CAPTURE_MEDIA_YUY2},
        {"nv12", LIBRDP_VIDEO_CAPTURE_MEDIA_NV12},
        {"i420", LIBRDP_VIDEO_CAPTURE_MEDIA_I420},
        {"rgb24", LIBRDP_VIDEO_CAPTURE_MEDIA_RGB24},
        {"rgb32", LIBRDP_VIDEO_CAPTURE_MEDIA_RGB32},
    };
    size_t i = 0;

    if (!format)
        return 0;
    if (!value || value[0] == '\0')
        value = "yuy2";
    for (i = 0; i < sizeof(formats) / sizeof(formats[0]); i++)
    {
        if (strcmp(value, formats[i].name) == 0)
        {
            *format = formats[i].format;
            return 1;
        }
    }
    return 0;
}

/*
 * Wait for a bounded number of frames. A live producer may need several poll
 * intervals after STREAMON, but every accepted sample must respect the media
 * cap and remain caller-owned after the driver buffer is requeued.
 */
static int test_capture_frames(x11_camera_capture* capture,
                               uint32_t expected_frames,
                               size_t max_sample_bytes)
{
    uint32_t attempts = 0;
    uint32_t captured = 0;

    while (attempts < TEST_READ_ATTEMPTS && captured < expected_frames)
    {
        uint8_t* sample = NULL;
        size_t sample_len = 0;
        int result = x11_camera_capture_read_sample(capture, &sample, &sample_len);

        CHECK(result >= 0);
        if (result == 1)
        {
            CHECK(sample != NULL);
            CHECK(sample_len > 0u);
            CHECK(sample_len <= max_sample_bytes);
            free(sample);
            captured++;
        }
        attempts++;
    }
    CHECK(captured == expected_frames);
    return 0;
}

int main(void)
{
    const char* device = getenv("LIBRDP_TEST_V4L2_DEVICE");
    librdp_video_capture_media media;
    x11_camera_capture_stats stats;
    x11_camera_capture* capture = NULL;
    size_t max_sample_bytes = 0;
    uint32_t frames = 0;

    if (!device || device[0] == '\0')
        return TEST_SKIP;
    memset(&media, 0, sizeof(media));
    CHECK(test_parse_format(getenv("LIBRDP_TEST_V4L2_FORMAT"), &media.format));
    CHECK(test_parse_u32(getenv("LIBRDP_TEST_V4L2_WIDTH"), 320u, &media.width));
    CHECK(test_parse_u32(getenv("LIBRDP_TEST_V4L2_HEIGHT"), 240u, &media.height));
    CHECK(test_parse_u32(getenv("LIBRDP_TEST_V4L2_FPS"), 30u, &media.frame_rate_numerator));
    media.frame_rate_denominator = 1u;
    CHECK(test_parse_u32(getenv("LIBRDP_TEST_V4L2_FRAMES"), 3u, &frames));
    CHECK(x11_camera_media_supported(&media, &max_sample_bytes));

    capture = x11_camera_capture_new();
    CHECK(capture != NULL);
    CHECK(x11_camera_capture_start(capture, device, &media));
    CHECK(test_capture_frames(capture, frames, max_sample_bytes) == 0);
    memset(&stats, 0, sizeof(stats));
    x11_camera_capture_get_stats(capture, &stats);
    CHECK(stats.frames == frames);
    CHECK(stats.bytes > 0u);
    CHECK(stats.errors == 0u);
    CHECK(stats.oversize_frames == 0u);
    CHECK(stats.streaming == 1);

    x11_camera_capture_stop(capture);
    x11_camera_capture_get_stats(capture, &stats);
    CHECK(stats.streaming == 0);
    {
        uint8_t* sample = NULL;
        size_t sample_len = 0;

        CHECK(x11_camera_capture_read_sample(capture, &sample, &sample_len) == -1);
        CHECK(sample == NULL);
        CHECK(sample_len == 0u);
    }

    CHECK(x11_camera_capture_start(capture, device, &media));
    CHECK(test_capture_frames(capture, 1u, max_sample_bytes) == 0);
    x11_camera_capture_stop(capture);
    x11_camera_capture_get_stats(capture, &stats);
    CHECK(stats.frames == 1u);
    CHECK(stats.streaming == 0);
    x11_camera_capture_free(capture);
    fprintf(stderr,
            "camera_live_smoke format=%u width=%u height=%u fps=%u frames=%u status=ok\n",
            media.format,
            media.width,
            media.height,
            media.frame_rate_numerator,
            frames + 1u);
    return 0;
}
