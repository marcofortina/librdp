/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa viewer media backend interface.
 * Invariants: native audio queues and camera sources remain viewer-owned and
 * exchange only copied buffers with public librdp callbacks.
 * Ownership: callers own backend handles returned by *_new() and release them
 * with the matching free function.
 * Threading: audio queue callbacks may run on CoreAudio threads; public reads
 * and writes serialize through the backend lock.
 * Trust boundary: remote media payloads and local source paths are validated
 * before entering native framework APIs.
 */

#ifndef LIBRDP_COCOA_VIEWER_MEDIA_H
#define LIBRDP_COCOA_VIEWER_MEDIA_H

#include <librdp/audio.h>
#include <librdp/video.h>

#include <stddef.h>
#include <stdint.h>

typedef struct cocoa_audio_backend cocoa_audio_backend;
typedef struct cocoa_camera_source cocoa_camera_source;

cocoa_audio_backend* cocoa_audio_backend_new(void);
void cocoa_audio_backend_free(cocoa_audio_backend* audio);
int cocoa_audio_backend_start_output(cocoa_audio_backend* audio,
                                     const librdp_audio_format* format,
                                     const char* device);
void cocoa_audio_backend_stop_output(cocoa_audio_backend* audio);
int cocoa_audio_backend_write_output(cocoa_audio_backend* audio, const void* data, size_t data_len);
int cocoa_audio_backend_start_input(cocoa_audio_backend* audio,
                                    const librdp_audio_format* format,
                                    const char* device);
void cocoa_audio_backend_stop_input(cocoa_audio_backend* audio);
size_t cocoa_audio_backend_read_input(cocoa_audio_backend* audio, void* data, size_t data_len);

cocoa_camera_source* cocoa_camera_source_new(void);
void cocoa_camera_source_free(cocoa_camera_source* camera);
int cocoa_camera_source_allowed(const char* source);
int cocoa_camera_media_supported(const librdp_video_capture_media* media, size_t* max_sample_bytes);
int cocoa_camera_source_start(cocoa_camera_source* camera,
                              const char* source,
                              const librdp_video_capture_media* media);
void cocoa_camera_source_stop(cocoa_camera_source* camera);
int cocoa_camera_source_read_sample(cocoa_camera_source* camera, uint8_t** data, size_t* data_len);

#ifdef LIBRDP_COCOA_MEDIA_TESTING
int cocoa_camera_test_convert_pixel_buffer(
    const librdp_video_capture_media* media,
    void* pixel_buffer,
    uint8_t** data,
    size_t* data_len);
#endif

#endif
