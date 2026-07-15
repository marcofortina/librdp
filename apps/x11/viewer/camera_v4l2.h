/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: V4L2 viewer camera backend interface for redirected camera streams.
 * Invariants: viewer backends validate host resources before attaching them to
 * public settings or callbacks.
 * Ownership: camera backends own device file descriptors and driver buffers
 * until samples are copied out.
 * Threading: viewer backend calls are serialized by the viewer unless the
 * backend documents an OS callback thread.
 * Trust boundary: command-line options, host devices, X11 events, and server
 * callbacks are separate trust domains.
 */


#ifndef LIBRDP_X11_CAMERA_V4L2_H
#define LIBRDP_X11_CAMERA_V4L2_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/video.h>

typedef struct x11_camera_capture x11_camera_capture;
typedef struct x11_camera_capture_stats
{
    uint64_t frames;
    uint64_t bytes;
    uint64_t errors;
    uint64_t oversize_frames;
    int streaming;
} x11_camera_capture_stats;

#define X11_CAMERA_MAX_WIDTH 7680u
#define X11_CAMERA_MAX_HEIGHT 4320u
#define X11_CAMERA_MAX_FPS 120u
#define X11_CAMERA_MAX_SAMPLE_BYTES (64u * 1024u * 1024u)

x11_camera_capture* x11_camera_capture_new(void);
void x11_camera_capture_free(x11_camera_capture* capture);
int x11_camera_capture_start(x11_camera_capture* capture,
                             const char* source,
                             const librdp_video_capture_media* media);
void x11_camera_capture_stop(x11_camera_capture* capture);
int x11_camera_capture_read_sample(x11_camera_capture* capture, uint8_t** data, size_t* data_len);
void x11_camera_capture_get_stats(const x11_camera_capture* capture, x11_camera_capture_stats* stats);
int x11_camera_source_allowed(const char* source);
int x11_camera_media_supported(const librdp_video_capture_media* media, size_t* max_sample_bytes);

#ifdef LIBRDP_X11_CAMERA_TESTING
typedef struct x11_camera_mock x11_camera_mock;

x11_camera_mock* x11_camera_mock_new(int permission_denied, int unplugged, size_t frame_len);
void x11_camera_mock_free(x11_camera_mock* mock);
int x11_camera_mock_start(x11_camera_mock* mock, const librdp_video_capture_media* media);
int x11_camera_mock_read_sample(x11_camera_mock* mock, uint8_t** data, size_t* data_len);
void x11_camera_mock_get_stats(const x11_camera_mock* mock, x11_camera_capture_stats* stats);
#endif

#endif
