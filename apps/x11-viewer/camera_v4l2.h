/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
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
