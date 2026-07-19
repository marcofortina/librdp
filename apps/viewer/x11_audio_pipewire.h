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
typedef struct x11_audio_backend_stats
{
    uint64_t output_written_bytes;
    uint64_t output_dropped_bytes;
    uint64_t output_queued_bytes;
    uint32_t output_latency_ms;
    uint64_t input_captured_bytes;
    uint64_t input_dropped_bytes;
    uint64_t input_queued_bytes;
    uint32_t input_latency_ms;
} x11_audio_backend_stats;

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
void x11_pipewire_audio_get_stats(x11_pipewire_audio* audio, x11_audio_backend_stats* stats);

#ifdef LIBRDP_X11_AUDIO_TESTING
typedef struct x11_audio_memory_sink x11_audio_memory_sink;

x11_audio_memory_sink* x11_audio_memory_sink_new(size_t capacity, size_t frame_size, uint32_t rate);
void x11_audio_memory_sink_free(x11_audio_memory_sink* sink);
int x11_audio_memory_sink_write(x11_audio_memory_sink* sink, const void* data, size_t data_len);
size_t x11_audio_memory_sink_read(x11_audio_memory_sink* sink, void* data, size_t data_len);
void x11_audio_memory_sink_get_stats(const x11_audio_memory_sink* sink, x11_audio_backend_stats* stats);
#endif

#endif
