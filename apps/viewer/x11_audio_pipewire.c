/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: PipeWire audio backend used by the viewer for redirected playback
 * and capture smoke paths.
 * Invariants: viewer state, X11 resources, and session callbacks are kept
 * consistent with focus and resize events.
 * Ownership: PipeWire objects remain backend-owned and are never exposed
 * through the public protocol API.
 * Threading: called from the viewer event thread unless a backend explicitly
 * documents its own callback thread.
 * Trust boundary: command-line options, local devices, X11 events, and server
 * callbacks are separate trust domains.
 */


#include "x11_audio_pipewire.h"

#include "x11_trace.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef LIBRDP_HAVE_PIPEWIRE
#include <pipewire/pipewire.h>
#include <spa/param/audio/raw-utils.h>
#include <spa/param/props.h>
#include <spa/pod/builder.h>

#include <pthread.h>
#endif

#if defined(LIBRDP_HAVE_PIPEWIRE) || defined(LIBRDP_X11_AUDIO_TESTING)
typedef struct x11_audio_ring
{
    uint8_t* data;
    size_t capacity;
    size_t read_pos;
    size_t write_pos;
    size_t size;
} x11_audio_ring;
#endif

struct x11_pipewire_audio
{
#ifdef LIBRDP_HAVE_PIPEWIRE
    struct pw_thread_loop* loop;
    struct pw_context* context;
    struct pw_core* core;
    struct pw_stream* output_stream;
    struct pw_stream* input_stream;
    struct spa_hook output_listener;
    struct spa_hook input_listener;
    pthread_mutex_t lock;
    x11_audio_ring output_ring;
    x11_audio_ring input_ring;
    size_t output_frame_size;
    size_t input_frame_size;
    uint32_t output_rate;
    uint32_t input_rate;
    uint16_t output_channels;
    uint16_t input_channels;
    uint16_t output_bits;
    uint16_t input_bits;
    uint64_t output_written_bytes;
    uint64_t output_dropped_bytes;
    uint64_t input_captured_bytes;
    uint64_t input_dropped_bytes;
    int ready;
#else
    int unused;
#endif
};

#define X11_PIPEWIRE_RING_BYTES (4u * 1024u * 1024u)

#if defined(LIBRDP_HAVE_PIPEWIRE) || defined(LIBRDP_X11_AUDIO_TESTING)
static void x11_audio_ring_free(x11_audio_ring* ring)
{
    if (!ring)
        return;
    free(ring->data);
    memset(ring, 0, sizeof(*ring));
}

static int x11_audio_ring_init(x11_audio_ring* ring, size_t capacity)
{
    if (!ring || capacity == 0)
        return 0;
    memset(ring, 0, sizeof(*ring));
    ring->data = (uint8_t*)malloc(capacity);
    if (!ring->data)
        return 0;
    ring->capacity = capacity;
    return 1;
}

static size_t x11_audio_ring_drop(x11_audio_ring* ring, size_t length)
{
    size_t dropped = 0;

    if (!ring || length == 0)
        return 0;
    if (length > ring->size)
        length = ring->size;
    ring->read_pos = (ring->read_pos + length) % ring->capacity;
    ring->size -= length;
    dropped = length;
    return dropped;
}

static size_t x11_audio_ring_write(x11_audio_ring* ring, const uint8_t* data, size_t length)
{
    size_t first = 0;
    size_t dropped = 0;

    if (!ring || !ring->data || !data || length == 0)
        return 0;
    if (length > ring->capacity)
    {
        data += length - ring->capacity;
        dropped += length - ring->capacity;
        length = ring->capacity;
    }
    if (length > ring->capacity - ring->size)
        dropped += x11_audio_ring_drop(ring, length - (ring->capacity - ring->size));
    first = ring->capacity - ring->write_pos;
    if (first > length)
        first = length;
    memcpy(ring->data + ring->write_pos, data, first);
    if (first < length)
        memcpy(ring->data, data + first, length - first);
    ring->write_pos = (ring->write_pos + length) % ring->capacity;
    ring->size += length;
    return dropped;
}

static size_t x11_audio_ring_read(x11_audio_ring* ring, uint8_t* data, size_t length)
{
    size_t first = 0;

    if (!ring || !ring->data || !data || length == 0)
        return 0;
    if (length > ring->size)
        length = ring->size;
    first = ring->capacity - ring->read_pos;
    if (first > length)
        first = length;
    memcpy(data, ring->data + ring->read_pos, first);
    if (first < length)
        memcpy(data + first, ring->data, length - first);
    ring->read_pos = (ring->read_pos + length) % ring->capacity;
    ring->size -= length;
    return length;
}

static uint32_t x11_audio_latency_ms(size_t queued_bytes, size_t frame_size, uint32_t rate)
{
    uint64_t frames = 0;
    uint64_t ms = 0;

    if (frame_size == 0 || rate == 0)
        return 0;
    frames = (uint64_t)(queued_bytes / frame_size);
    ms = (frames * 1000u) / rate;
    return ms > UINT32_MAX ? UINT32_MAX : (uint32_t)ms;
}
#endif

#ifdef LIBRDP_X11_AUDIO_TESTING
struct x11_audio_memory_sink
{
    x11_audio_ring ring;
    size_t frame_size;
    uint32_t rate;
    uint64_t written_bytes;
    uint64_t dropped_bytes;
};

x11_audio_memory_sink* x11_audio_memory_sink_new(size_t capacity, size_t frame_size, uint32_t rate)
{
    x11_audio_memory_sink* sink = NULL;

    if (capacity == 0 || frame_size == 0 || rate == 0)
        return NULL;
    sink = (x11_audio_memory_sink*)calloc(1, sizeof(*sink));
    if (!sink)
        return NULL;
    if (!x11_audio_ring_init(&sink->ring, capacity))
    {
        free(sink);
        return NULL;
    }
    sink->frame_size = frame_size;
    sink->rate = rate;
    return sink;
}

void x11_audio_memory_sink_free(x11_audio_memory_sink* sink)
{
    if (!sink)
        return;
    x11_audio_ring_free(&sink->ring);
    free(sink);
}

int x11_audio_memory_sink_write(x11_audio_memory_sink* sink, const void* data, size_t data_len)
{
    size_t dropped = 0;

    if (!sink || (!data && data_len > 0))
        return 0;
    if (data_len == 0)
        return 1;
    dropped = x11_audio_ring_write(&sink->ring, (const uint8_t*)data, data_len);
    sink->written_bytes += data_len;
    sink->dropped_bytes += dropped;
    return 1;
}

size_t x11_audio_memory_sink_read(x11_audio_memory_sink* sink, void* data, size_t data_len)
{
    if (!sink || !data || data_len == 0)
        return 0;
    return x11_audio_ring_read(&sink->ring, (uint8_t*)data, data_len);
}

void x11_audio_memory_sink_get_stats(const x11_audio_memory_sink* sink, x11_audio_backend_stats* stats)
{
    if (!stats)
        return;
    memset(stats, 0, sizeof(*stats));
    if (!sink)
        return;
    stats->output_written_bytes = sink->written_bytes;
    stats->output_dropped_bytes = sink->dropped_bytes;
    stats->output_queued_bytes = sink->ring.size;
    stats->output_latency_ms = x11_audio_latency_ms(sink->ring.size, sink->frame_size, sink->rate);
}
#endif

#ifdef LIBRDP_HAVE_PIPEWIRE
static int x11_pipewire_map_format(const librdp_audio_format* format,
                                   enum spa_audio_format* spa_format,
                                   size_t* frame_size)
{
    size_t bytes_per_sample = 0;

    if (!format || !spa_format || !frame_size)
        return 0;
    if (format->channels == 0 || format->samples_per_sec == 0 || format->block_align == 0)
        return 0;
    if (format->format_tag == LIBRDP_AUDIO_FORMAT_ALAW ||
        format->format_tag == LIBRDP_AUDIO_FORMAT_MULAW)
    {
        if (format->bits_per_sample != 8 || format->block_align != format->channels)
            return 0;
        *spa_format = format->format_tag == LIBRDP_AUDIO_FORMAT_ALAW ?
            SPA_AUDIO_FORMAT_ALAW :
            SPA_AUDIO_FORMAT_ULAW;
        *frame_size = format->block_align;
        return 1;
    }
    if (format->format_tag != LIBRDP_AUDIO_FORMAT_PCM)
        return 0;
    switch (format->bits_per_sample)
    {
        case 8:
            *spa_format = SPA_AUDIO_FORMAT_U8;
            bytes_per_sample = 1;
            break;
        case 16:
            *spa_format = SPA_AUDIO_FORMAT_S16_LE;
            bytes_per_sample = 2;
            break;
        case 24:
            *spa_format = SPA_AUDIO_FORMAT_S24_LE;
            bytes_per_sample = 3;
            break;
        case 32:
            *spa_format = SPA_AUDIO_FORMAT_S32_LE;
            bytes_per_sample = 4;
            break;
        default:
            return 0;
    }
    if ((size_t)format->channels * bytes_per_sample != format->block_align)
        return 0;
    *frame_size = format->block_align;
    return 1;
}

static int x11_pipewire_ensure(x11_pipewire_audio* audio)
{
    if (!audio)
        return 0;
    if (audio->ready)
        return 1;

    pw_init(NULL, NULL);
    audio->loop = pw_thread_loop_new("librdp-viewer-audio", NULL);
    if (!audio->loop)
        goto fail;
    audio->context = pw_context_new(pw_thread_loop_get_loop(audio->loop), NULL, 0);
    if (!audio->context)
        goto fail;
    audio->core = pw_context_connect(audio->context, NULL, 0);
    if (!audio->core)
        goto fail;
    if (pw_thread_loop_start(audio->loop) < 0)
        goto fail;
    audio->ready = 1;
    x11_trace_event(X11_TRACE_CLIENT, "x11.audio.pipewire.ready", "ready=1");
    return 1;

fail:
    x11_trace_event(X11_TRACE_CLIENT, "x11.audio.pipewire.failed", "stage=init");
    return 0;
}

static struct pw_properties* x11_pipewire_props(const char* node_name,
                                               const char* category,
                                               const char* device)
{
    struct pw_properties* props = pw_properties_new(PW_KEY_MEDIA_TYPE,
                                                    "Audio",
                                                    PW_KEY_MEDIA_CATEGORY,
                                                    category,
                                                    PW_KEY_MEDIA_ROLE,
                                                    "Communication",
                                                    PW_KEY_NODE_NAME,
                                                    node_name,
                                                    NULL);

    if (props && device && strcmp(device, "pipewire") != 0)
        pw_properties_set(props, PW_KEY_TARGET_OBJECT, device);
    return props;
}

static const struct spa_pod* x11_pipewire_format_param(uint8_t* storage,
                                                       size_t storage_len,
                                                       const librdp_audio_format* format,
                                                       enum spa_audio_format spa_format)
{
    struct spa_audio_info_raw info;
    uint32_t builder_len = 0;
    struct spa_pod_builder builder;

    if (!storage || !format || storage_len > UINT32_MAX)
        return NULL;
    builder_len = (uint32_t)storage_len;
    memset(&builder, 0, sizeof(builder));
    builder.data = storage;
    builder.size = builder_len;
    memset(&info, 0, sizeof(info));
    info.format = spa_format;
    info.rate = format->samples_per_sec;
    info.channels = format->channels;
    if (format->channels == 1)
        info.position[0] = SPA_AUDIO_CHANNEL_MONO;
    else if (format->channels >= 2)
    {
        info.position[0] = SPA_AUDIO_CHANNEL_FL;
        info.position[1] = SPA_AUDIO_CHANNEL_FR;
    }
    return spa_format_audio_raw_build(&builder, SPA_PARAM_EnumFormat, &info);
}

static void x11_pipewire_output_process(void* data)
{
    x11_pipewire_audio* audio = (x11_pipewire_audio*)data;
    struct pw_buffer* buffer = NULL;
    struct spa_buffer* spa_buffer = NULL;
    struct spa_data* spa_data = NULL;
    uint8_t* out = NULL;
    size_t writable = 0;
    size_t copied = 0;

    if (!audio || !audio->output_stream)
        return;
    buffer = pw_stream_dequeue_buffer(audio->output_stream);
    if (!buffer)
        return;
    spa_buffer = buffer->buffer;
    if (!spa_buffer || spa_buffer->n_datas == 0)
        goto queue;
    spa_data = &spa_buffer->datas[0];
    if (!spa_data->data || !spa_data->chunk)
        goto queue;
    out = (uint8_t*)spa_data->data;
    writable = spa_data->maxsize;
    pthread_mutex_lock(&audio->lock);
    copied = x11_audio_ring_read(&audio->output_ring, out, writable);
    pthread_mutex_unlock(&audio->lock);
    if (copied < writable)
        memset(out + copied, audio->output_bits == 8 ? 0x80 : 0, writable - copied);
    spa_data->chunk->offset = 0;
    spa_data->chunk->stride = (int32_t)audio->output_frame_size;
    spa_data->chunk->size = (uint32_t)writable;
queue:
    pw_stream_queue_buffer(audio->output_stream, buffer);
}

static void x11_pipewire_input_process(void* data)
{
    x11_pipewire_audio* audio = (x11_pipewire_audio*)data;
    struct pw_buffer* buffer = NULL;

    if (!audio || !audio->input_stream)
        return;
    while ((buffer = pw_stream_dequeue_buffer(audio->input_stream)) != NULL)
    {
        struct spa_buffer* spa_buffer = buffer->buffer;

        if (spa_buffer && spa_buffer->n_datas > 0)
        {
            struct spa_data* spa_data = &spa_buffer->datas[0];

            if (spa_data->data && spa_data->chunk && spa_data->chunk->size > 0)
            {
                const uint8_t* input = (const uint8_t*)spa_data->data + spa_data->chunk->offset;
                size_t dropped = 0;

                pthread_mutex_lock(&audio->lock);
                dropped = x11_audio_ring_write(&audio->input_ring, input, spa_data->chunk->size);
                audio->input_captured_bytes += spa_data->chunk->size;
                audio->input_dropped_bytes += dropped;
                pthread_mutex_unlock(&audio->lock);
                if (dropped > 0)
                    x11_trace_event_level(X11_TRACE_CLIENT,
                                          X11_TRACE_LEVEL_DEBUG,
                                          "x11.audio.input.overflow",
                                          "dropped=%u policy=drop_oldest",
                                          (unsigned)dropped);
            }
        }
        pw_stream_queue_buffer(audio->input_stream, buffer);
    }
}

static const struct pw_stream_events x11_pipewire_output_events = {
    PW_VERSION_STREAM_EVENTS,
    .process = x11_pipewire_output_process,
};

static const struct pw_stream_events x11_pipewire_input_events = {
    PW_VERSION_STREAM_EVENTS,
    .process = x11_pipewire_input_process,
};

x11_pipewire_audio* x11_pipewire_audio_new(void)
{
    x11_pipewire_audio* audio = (x11_pipewire_audio*)calloc(1, sizeof(*audio));

    if (!audio)
        return NULL;
    if (pthread_mutex_init(&audio->lock, NULL) != 0)
    {
        free(audio);
        return NULL;
    }
    if (!x11_audio_ring_init(&audio->output_ring, X11_PIPEWIRE_RING_BYTES) ||
        !x11_audio_ring_init(&audio->input_ring, X11_PIPEWIRE_RING_BYTES))
    {
        x11_pipewire_audio_free(audio);
        return NULL;
    }
    return audio;
}

void x11_pipewire_audio_stop_output(x11_pipewire_audio* audio)
{
    if (!audio || !audio->output_stream)
        return;
    pw_thread_loop_lock(audio->loop);
    pw_stream_destroy(audio->output_stream);
    audio->output_stream = NULL;
    pw_thread_loop_unlock(audio->loop);
    pthread_mutex_lock(&audio->lock);
    audio->output_ring.read_pos = 0;
    audio->output_ring.write_pos = 0;
    audio->output_ring.size = 0;
    pthread_mutex_unlock(&audio->lock);
    x11_trace_event(X11_TRACE_CLIENT, "x11.audio.output.stop", "backend=pipewire");
}

void x11_pipewire_audio_stop_input(x11_pipewire_audio* audio)
{
    if (!audio || !audio->input_stream)
        return;
    pw_thread_loop_lock(audio->loop);
    pw_stream_destroy(audio->input_stream);
    audio->input_stream = NULL;
    pw_thread_loop_unlock(audio->loop);
    pthread_mutex_lock(&audio->lock);
    audio->input_ring.read_pos = 0;
    audio->input_ring.write_pos = 0;
    audio->input_ring.size = 0;
    pthread_mutex_unlock(&audio->lock);
    x11_trace_event(X11_TRACE_CLIENT, "x11.audio.input.stop", "backend=pipewire");
}

void x11_pipewire_audio_free(x11_pipewire_audio* audio)
{
    if (!audio)
        return;
    x11_pipewire_audio_stop_output(audio);
    x11_pipewire_audio_stop_input(audio);
    if (audio->loop)
        pw_thread_loop_stop(audio->loop);
    if (audio->core)
        pw_core_disconnect(audio->core);
    if (audio->context)
        pw_context_destroy(audio->context);
    if (audio->loop)
        pw_thread_loop_destroy(audio->loop);
    x11_audio_ring_free(&audio->output_ring);
    x11_audio_ring_free(&audio->input_ring);
    pthread_mutex_destroy(&audio->lock);
    free(audio);
}

int x11_pipewire_audio_start_output(x11_pipewire_audio* audio,
                                    const librdp_audio_format* format,
                                    const char* device)
{
    enum spa_audio_format spa_format = SPA_AUDIO_FORMAT_UNKNOWN;
    uint8_t format_storage[1024];
    const struct spa_pod* params[1];
    struct pw_properties* props = NULL;
    size_t frame_size = 0;
    int result = 0;

    if (!audio || !format)
        return 0;
    if (!x11_pipewire_map_format(format, &spa_format, &frame_size))
    {
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.audio.output.failed",
                        "reason=rejected_format tag=%u channels=%u rate=%u bits=%u block_align=%u",
                        format->format_tag,
                        format->channels,
                        format->samples_per_sec,
                        format->bits_per_sample,
                        format->block_align);
        return 0;
    }
    if (!x11_pipewire_ensure(audio))
        return 0;
    x11_pipewire_audio_stop_output(audio);
    params[0] = x11_pipewire_format_param(format_storage, sizeof(format_storage), format, spa_format);
    props = x11_pipewire_props("librdp-viewer-audio-output", "Playback", device);
    if (!props || !params[0])
        return 0;

    audio->output_frame_size = frame_size;
    audio->output_rate = format->samples_per_sec;
    audio->output_channels = format->channels;
    audio->output_bits = format->bits_per_sample;
    pw_thread_loop_lock(audio->loop);
    audio->output_stream = pw_stream_new(audio->core, "librdp-viewer-audio-output", props);
    if (audio->output_stream)
    {
        pw_stream_add_listener(audio->output_stream,
                               &audio->output_listener,
                               &x11_pipewire_output_events,
                               audio);
        result = pw_stream_connect(audio->output_stream,
                                   PW_DIRECTION_OUTPUT,
                                   PW_ID_ANY,
                                   PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS,
                                   params,
                                   1) >= 0;
        if (!result)
        {
            pw_stream_destroy(audio->output_stream);
            audio->output_stream = NULL;
        }
    }
    pw_thread_loop_unlock(audio->loop);
    if (result)
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.audio.output.start",
                        "backend=pipewire device=\"%s\" channels=%u rate=%u bits=%u frame_size=%u",
                        device ? device : "pipewire",
                        audio->output_channels,
                        audio->output_rate,
                        audio->output_bits,
                        (unsigned)audio->output_frame_size);
    else
        x11_trace_event(X11_TRACE_CLIENT, "x11.audio.output.failed", "reason=connect");
    return result;
}

int x11_pipewire_audio_start_input(x11_pipewire_audio* audio,
                                   const librdp_audio_format* format,
                                   const char* device)
{
    enum spa_audio_format spa_format = SPA_AUDIO_FORMAT_UNKNOWN;
    uint8_t format_storage[1024];
    const struct spa_pod* params[1];
    struct pw_properties* props = NULL;
    size_t frame_size = 0;
    int result = 0;

    if (!audio || !format)
        return 0;
    if (!x11_pipewire_map_format(format, &spa_format, &frame_size))
    {
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.audio.input.failed",
                        "reason=rejected_format tag=%u channels=%u rate=%u bits=%u block_align=%u",
                        format->format_tag,
                        format->channels,
                        format->samples_per_sec,
                        format->bits_per_sample,
                        format->block_align);
        return 0;
    }
    if (!x11_pipewire_ensure(audio))
        return 0;
    x11_pipewire_audio_stop_input(audio);
    params[0] = x11_pipewire_format_param(format_storage, sizeof(format_storage), format, spa_format);
    props = x11_pipewire_props("librdp-viewer-audio-input", "Capture", device);
    if (!props || !params[0])
        return 0;

    audio->input_frame_size = frame_size;
    audio->input_rate = format->samples_per_sec;
    audio->input_channels = format->channels;
    audio->input_bits = format->bits_per_sample;
    pw_thread_loop_lock(audio->loop);
    audio->input_stream = pw_stream_new(audio->core, "librdp-viewer-audio-input", props);
    if (audio->input_stream)
    {
        pw_stream_add_listener(audio->input_stream, &audio->input_listener, &x11_pipewire_input_events, audio);
        result = pw_stream_connect(audio->input_stream,
                                   PW_DIRECTION_INPUT,
                                   PW_ID_ANY,
                                   PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS,
                                   params,
                                   1) >= 0;
        if (!result)
        {
            pw_stream_destroy(audio->input_stream);
            audio->input_stream = NULL;
        }
    }
    pw_thread_loop_unlock(audio->loop);
    if (result)
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.audio.input.start",
                        "backend=pipewire device=\"%s\" channels=%u rate=%u bits=%u frame_size=%u",
                        device ? device : "pipewire",
                        audio->input_channels,
                        audio->input_rate,
                        audio->input_bits,
                        (unsigned)audio->input_frame_size);
    else
        x11_trace_event(X11_TRACE_CLIENT, "x11.audio.input.failed", "reason=connect");
    return result;
}

int x11_pipewire_audio_write_output(x11_pipewire_audio* audio, const void* data, size_t data_len)
{
    size_t dropped = 0;

    if (!audio || !audio->output_stream || (!data && data_len > 0))
        return 0;
    if (data_len == 0)
        return 1;
    pthread_mutex_lock(&audio->lock);
    dropped = x11_audio_ring_write(&audio->output_ring, (const uint8_t*)data, data_len);
    audio->output_written_bytes += data_len;
    audio->output_dropped_bytes += dropped;
    pthread_mutex_unlock(&audio->lock);
    if (dropped > 0)
        x11_trace_event_level(X11_TRACE_CLIENT,
                              X11_TRACE_LEVEL_DEBUG,
                              "x11.audio.output.overflow",
                              "dropped=%u policy=drop_oldest",
                              (unsigned)dropped);
    return 1;
}

size_t x11_pipewire_audio_read_input(x11_pipewire_audio* audio, void* data, size_t data_len)
{
    size_t read = 0;

    if (!audio || !audio->input_stream || !data || data_len == 0)
        return 0;
    pthread_mutex_lock(&audio->lock);
    read = x11_audio_ring_read(&audio->input_ring, (uint8_t*)data, data_len);
    pthread_mutex_unlock(&audio->lock);
    return read;
}

void x11_pipewire_audio_get_stats(x11_pipewire_audio* audio, x11_audio_backend_stats* stats)
{
    if (!stats)
        return;
    memset(stats, 0, sizeof(*stats));
    if (!audio)
        return;
    pthread_mutex_lock(&audio->lock);
    stats->output_written_bytes = audio->output_written_bytes;
    stats->output_dropped_bytes = audio->output_dropped_bytes;
    stats->output_queued_bytes = audio->output_ring.size;
    stats->output_latency_ms = x11_audio_latency_ms(audio->output_ring.size,
                                                    audio->output_frame_size,
                                                    audio->output_rate);
    stats->input_captured_bytes = audio->input_captured_bytes;
    stats->input_dropped_bytes = audio->input_dropped_bytes;
    stats->input_queued_bytes = audio->input_ring.size;
    stats->input_latency_ms = x11_audio_latency_ms(audio->input_ring.size,
                                                   audio->input_frame_size,
                                                   audio->input_rate);
    pthread_mutex_unlock(&audio->lock);
}
#else
x11_pipewire_audio* x11_pipewire_audio_new(void)
{
    return (x11_pipewire_audio*)calloc(1, sizeof(x11_pipewire_audio));
}

void x11_pipewire_audio_free(x11_pipewire_audio* audio)
{
    free(audio);
}

int x11_pipewire_audio_start_output(x11_pipewire_audio* audio,
                                    const librdp_audio_format* format,
                                    const char* device)
{
    (void)audio;
    (void)format;
    (void)device;
    x11_trace_event(X11_TRACE_CLIENT, "x11.audio.output.failed", "reason=pipewire_unavailable");
    return 0;
}

int x11_pipewire_audio_start_input(x11_pipewire_audio* audio,
                                   const librdp_audio_format* format,
                                   const char* device)
{
    (void)audio;
    (void)format;
    (void)device;
    x11_trace_event(X11_TRACE_CLIENT, "x11.audio.input.failed", "reason=pipewire_unavailable");
    return 0;
}

void x11_pipewire_audio_stop_output(x11_pipewire_audio* audio)
{
    (void)audio;
}

void x11_pipewire_audio_stop_input(x11_pipewire_audio* audio)
{
    (void)audio;
}

int x11_pipewire_audio_write_output(x11_pipewire_audio* audio, const void* data, size_t data_len)
{
    (void)audio;
    (void)data;
    (void)data_len;
    return 0;
}

size_t x11_pipewire_audio_read_input(x11_pipewire_audio* audio, void* data, size_t data_len)
{
    (void)audio;
    (void)data;
    (void)data_len;
    return 0;
}

void x11_pipewire_audio_get_stats(x11_pipewire_audio* audio, x11_audio_backend_stats* stats)
{
    (void)audio;
    if (stats)
        memset(stats, 0, sizeof(*stats));
}
#endif
