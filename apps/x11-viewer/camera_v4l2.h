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

x11_camera_capture* x11_camera_capture_new(void);
void x11_camera_capture_free(x11_camera_capture* capture);
int x11_camera_capture_start(x11_camera_capture* capture,
                             const char* source,
                             const librdp_video_capture_media* media);
void x11_camera_capture_stop(x11_camera_capture* capture);
int x11_camera_capture_read_sample(x11_camera_capture* capture, uint8_t** data, size_t* data_len);

#endif
