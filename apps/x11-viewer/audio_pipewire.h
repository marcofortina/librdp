/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: PipeWire viewer audio backend interface for playback and capture
 * smoke paths.
 * Invariants: viewer backends validate host resources before attaching them to
 * public settings or callbacks.
 * Ownership: backend instances own PipeWire handles and expose only copied
 * audio buffers to callbacks.
 * Threading: viewer backend calls are serialized by the viewer unless the
 * backend documents an OS callback thread.
 * Trust boundary: command-line options, host devices, X11 events, and server
 * callbacks are separate trust domains.
 */


#ifndef LIBRDP_X11_AUDIO_PIPEWIRE_H
#define LIBRDP_X11_AUDIO_PIPEWIRE_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/audio.h>

typedef struct x11_pipewire_audio x11_pipewire_audio;

x11_pipewire_audio* x11_pipewire_audio_new(void);
void x11_pipewire_audio_free(x11_pipewire_audio* audio);
int x11_pipewire_audio_start_output(x11_pipewire_audio* audio,
                                    const librdp_audio_format* format,
                                    const char* device);
int x11_pipewire_audio_start_input(x11_pipewire_audio* audio,
                                   const librdp_audio_format* format,
                                   const char* device);
void x11_pipewire_audio_stop_output(x11_pipewire_audio* audio);
void x11_pipewire_audio_stop_input(x11_pipewire_audio* audio);
int x11_pipewire_audio_write_output(x11_pipewire_audio* audio, const void* data, size_t data_len);
size_t x11_pipewire_audio_read_input(x11_pipewire_audio* audio, void* data, size_t data_len);

#endif
