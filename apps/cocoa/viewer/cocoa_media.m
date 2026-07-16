/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa viewer media backend.
 * Invariants: native queues are stopped before disposal, media payloads are
 * bounded, and captured data is copied before being returned to librdp.
 * Ownership: audio queues, ring buffers, and file handles are backend-owned.
 * Threading: AudioQueue input callbacks synchronize with the AppKit dispatch
 * thread through a pthread mutex.
 * Trust boundary: server audio data and local camera source paths are not
 * trusted until size and format checks pass.
 */

#include "cocoa_media.h"

#import <AudioToolbox/AudioToolbox.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COCOA_AUDIO_RING_BYTES (4u * 1024u * 1024u)
#define COCOA_AUDIO_MAX_PACKET_BYTES (1024u * 1024u)
#define COCOA_CAMERA_MAX_SAMPLE_BYTES (8u * 1024u * 1024u)

typedef struct cocoa_audio_ring
{
    uint8_t* data;
    size_t capacity;
    size_t read_pos;
    size_t write_pos;
    size_t size;
} cocoa_audio_ring;

struct cocoa_audio_backend
{
    AudioQueueRef output_queue;
    AudioQueueRef input_queue;
    pthread_mutex_t lock;
    cocoa_audio_ring input_ring;
    int lock_ready;
    size_t input_frame_size;
};

struct cocoa_camera_source
{
    FILE* file;
    size_t max_sample_bytes;
};

static void cocoa_audio_ring_free(cocoa_audio_ring* ring)
{
    if (!ring)
        return;
    free(ring->data);
    memset(ring, 0, sizeof(*ring));
}

static int cocoa_audio_ring_init(cocoa_audio_ring* ring, size_t capacity)
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

static size_t cocoa_audio_ring_drop(cocoa_audio_ring* ring, size_t length)
{
    if (!ring || length == 0)
        return 0;
    if (length > ring->size)
        length = ring->size;
    ring->read_pos = (ring->read_pos + length) % ring->capacity;
    ring->size -= length;
    return length;
}

static size_t cocoa_audio_ring_write(cocoa_audio_ring* ring, const uint8_t* data, size_t length)
{
    size_t first = 0;

    if (!ring || !ring->data || !data || length == 0)
        return 0;
    if (length > ring->capacity)
    {
        data += length - ring->capacity;
        length = ring->capacity;
    }
    if (length > ring->capacity - ring->size)
        (void)cocoa_audio_ring_drop(ring, length - (ring->capacity - ring->size));
    first = ring->capacity - ring->write_pos;
    if (first > length)
        first = length;
    memcpy(ring->data + ring->write_pos, data, first);
    if (first < length)
        memcpy(ring->data, data + first, length - first);
    ring->write_pos = (ring->write_pos + length) % ring->capacity;
    ring->size += length;
    return length;
}

static size_t cocoa_audio_ring_read(cocoa_audio_ring* ring, uint8_t* data, size_t length)
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

static int cocoa_audio_description_from_format(const librdp_audio_format* format,
                                               AudioStreamBasicDescription* description)
{
    AudioFormatFlags flags = kAudioFormatFlagIsPacked;

    if (!format || !description ||
        format->channels == 0 ||
        format->samples_per_sec == 0 ||
        format->block_align == 0)
        return 0;
    memset(description, 0, sizeof(*description));
    description->mSampleRate = (Float64)format->samples_per_sec;
    description->mChannelsPerFrame = (UInt32)format->channels;
    description->mFramesPerPacket = 1;
    description->mBytesPerPacket = (UInt32)format->block_align;
    description->mBytesPerFrame = (UInt32)format->block_align;
    description->mBitsPerChannel = (UInt32)format->bits_per_sample;
    if (format->format_tag == LIBRDP_AUDIO_FORMAT_PCM)
    {
        description->mFormatID = kAudioFormatLinearPCM;
        if (format->bits_per_sample != 8)
            flags |= kLinearPCMFormatFlagIsSignedInteger;
        description->mFormatFlags = flags;
        return format->bits_per_sample == 8 || format->bits_per_sample == 16;
    }
    if (format->format_tag == LIBRDP_AUDIO_FORMAT_ALAW)
    {
        description->mFormatID = kAudioFormatALaw;
        return format->bits_per_sample == 8;
    }
    if (format->format_tag == LIBRDP_AUDIO_FORMAT_MULAW)
    {
        description->mFormatID = kAudioFormatULaw;
        return format->bits_per_sample == 8;
    }
    return 0;
}

static void cocoa_audio_output_callback(void* user_data, AudioQueueRef queue, AudioQueueBufferRef buffer)
{
    (void)user_data;
    (void)queue;
    (void)buffer;
}

static void cocoa_audio_input_callback(void* user_data,
                                       AudioQueueRef queue,
                                       AudioQueueBufferRef buffer,
                                       const AudioTimeStamp* start_time,
                                       UInt32 packet_count,
                                       const AudioStreamPacketDescription* packet_descriptions)
{
    cocoa_audio_backend* audio = (cocoa_audio_backend*)user_data;

    (void)start_time;
    (void)packet_count;
    (void)packet_descriptions;
    if (!audio || !buffer || buffer->mAudioDataByteSize == 0)
        return;
    pthread_mutex_lock(&audio->lock);
    (void)cocoa_audio_ring_write(&audio->input_ring, buffer->mAudioData, buffer->mAudioDataByteSize);
    pthread_mutex_unlock(&audio->lock);
    (void)AudioQueueEnqueueBuffer(queue, buffer, 0, NULL);
}

cocoa_audio_backend* cocoa_audio_backend_new(void)
{
    cocoa_audio_backend* audio = (cocoa_audio_backend*)calloc(1u, sizeof(*audio));

    if (!audio)
        return NULL;
    if (pthread_mutex_init(&audio->lock, NULL) != 0)
    {
        free(audio);
        return NULL;
    }
    audio->lock_ready = 1;
    if (!cocoa_audio_ring_init(&audio->input_ring, COCOA_AUDIO_RING_BYTES))
    {
        cocoa_audio_backend_free(audio);
        return NULL;
    }
    return audio;
}

void cocoa_audio_backend_stop_output(cocoa_audio_backend* audio)
{
    if (!audio || !audio->output_queue)
        return;
    AudioQueueStop(audio->output_queue, true);
    AudioQueueDispose(audio->output_queue, true);
    audio->output_queue = NULL;
}

void cocoa_audio_backend_stop_input(cocoa_audio_backend* audio)
{
    if (!audio || !audio->input_queue)
        return;
    AudioQueueStop(audio->input_queue, true);
    AudioQueueDispose(audio->input_queue, true);
    audio->input_queue = NULL;
    pthread_mutex_lock(&audio->lock);
    audio->input_ring.read_pos = 0;
    audio->input_ring.write_pos = 0;
    audio->input_ring.size = 0;
    pthread_mutex_unlock(&audio->lock);
}

void cocoa_audio_backend_free(cocoa_audio_backend* audio)
{
    if (!audio)
        return;
    cocoa_audio_backend_stop_output(audio);
    cocoa_audio_backend_stop_input(audio);
    cocoa_audio_ring_free(&audio->input_ring);
    if (audio->lock_ready)
        pthread_mutex_destroy(&audio->lock);
    free(audio);
}

int cocoa_audio_backend_start_output(cocoa_audio_backend* audio,
                                     const librdp_audio_format* format,
                                     const char* device)
{
    AudioStreamBasicDescription description;

    (void)device;
    if (!audio || !cocoa_audio_description_from_format(format, &description))
        return 0;
    cocoa_audio_backend_stop_output(audio);
    if (AudioQueueNewOutput(&description,
                            cocoa_audio_output_callback,
                            audio,
                            CFRunLoopGetMain(),
                            kCFRunLoopCommonModes,
                            0,
                            &audio->output_queue) != noErr)
        return 0;
    if (AudioQueueStart(audio->output_queue, NULL) != noErr)
    {
        cocoa_audio_backend_stop_output(audio);
        return 0;
    }
    return 1;
}

int cocoa_audio_backend_write_output(cocoa_audio_backend* audio, const void* data, size_t data_len)
{
    AudioQueueBufferRef buffer = NULL;

    if (!audio || !audio->output_queue || (!data && data_len > 0) || data_len > COCOA_AUDIO_MAX_PACKET_BYTES)
        return 0;
    if (data_len == 0)
        return 1;
    if (AudioQueueAllocateBuffer(audio->output_queue, (UInt32)data_len, &buffer) != noErr || !buffer)
        return 0;
    memcpy(buffer->mAudioData, data, data_len);
    buffer->mAudioDataByteSize = (UInt32)data_len;
    if (AudioQueueEnqueueBuffer(audio->output_queue, buffer, 0, NULL) != noErr)
    {
        (void)AudioQueueFreeBuffer(audio->output_queue, buffer);
        return 0;
    }
    return 1;
}

int cocoa_audio_backend_start_input(cocoa_audio_backend* audio,
                                    const librdp_audio_format* format,
                                    const char* device)
{
    AudioStreamBasicDescription description;
    UInt32 buffer_size = 0;

    (void)device;
    if (!audio || !cocoa_audio_description_from_format(format, &description))
        return 0;
    cocoa_audio_backend_stop_input(audio);
    audio->input_frame_size = format->block_align;
    if (AudioQueueNewInput(&description,
                           cocoa_audio_input_callback,
                           audio,
                           CFRunLoopGetMain(),
                           kCFRunLoopCommonModes,
                           0,
                           &audio->input_queue) != noErr)
        return 0;
    buffer_size = (UInt32)((uint32_t)format->block_align * 1024u);
    if (buffer_size == 0 || buffer_size > 65536u)
        buffer_size = 4096u;
    for (uint32_t i = 0; i < 3u; i++)
    {
        AudioQueueBufferRef buffer = NULL;

        if (AudioQueueAllocateBuffer(audio->input_queue, buffer_size, &buffer) != noErr)
        {
            cocoa_audio_backend_stop_input(audio);
            return 0;
        }
        if (AudioQueueEnqueueBuffer(audio->input_queue, buffer, 0, NULL) != noErr)
        {
            (void)AudioQueueFreeBuffer(audio->input_queue, buffer);
            cocoa_audio_backend_stop_input(audio);
            return 0;
        }
    }
    if (AudioQueueStart(audio->input_queue, NULL) != noErr)
    {
        cocoa_audio_backend_stop_input(audio);
        return 0;
    }
    return 1;
}

size_t cocoa_audio_backend_read_input(cocoa_audio_backend* audio, void* data, size_t data_len)
{
    size_t read_bytes = 0;

    if (!audio || !data || data_len == 0)
        return 0;
    pthread_mutex_lock(&audio->lock);
    read_bytes = cocoa_audio_ring_read(&audio->input_ring, (uint8_t*)data, data_len);
    pthread_mutex_unlock(&audio->lock);
    return read_bytes;
}

static const char* cocoa_camera_file_path(const char* source)
{
    static const char prefix[] = "file=";

    if (!source)
        return NULL;
    if (strncmp(source, prefix, sizeof(prefix) - 1u) == 0 && source[sizeof(prefix) - 1u] != '\0')
        return source + sizeof(prefix) - 1u;
    if (strncmp(source, "device=", 7u) == 0)
        return NULL;
    return source[0] != '\0' ? source : NULL;
}

static int cocoa_camera_media_supported(const librdp_video_capture_media* media, size_t* max_sample_bytes)
{
    size_t pixels = 0;

    if (max_sample_bytes)
        *max_sample_bytes = 0;
    if (!media || media->width == 0 || media->height == 0 ||
        media->width > 4096u || media->height > 4096u ||
        media->width > SIZE_MAX / media->height)
        return 0;
    pixels = (size_t)media->width * media->height;
    switch (media->format)
    {
        case LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG:
        case LIBRDP_VIDEO_CAPTURE_MEDIA_H264:
            if (max_sample_bytes)
                *max_sample_bytes = COCOA_CAMERA_MAX_SAMPLE_BYTES;
            return 1;
        case LIBRDP_VIDEO_CAPTURE_MEDIA_RGB32:
            if (pixels > SIZE_MAX / 4u)
                return 0;
            if (max_sample_bytes)
                *max_sample_bytes = pixels * 4u;
            return pixels * 4u <= COCOA_CAMERA_MAX_SAMPLE_BYTES;
        case LIBRDP_VIDEO_CAPTURE_MEDIA_RGB24:
            if (pixels > SIZE_MAX / 3u)
                return 0;
            if (max_sample_bytes)
                *max_sample_bytes = pixels * 3u;
            return pixels * 3u <= COCOA_CAMERA_MAX_SAMPLE_BYTES;
        default:
            return 0;
    }
}

cocoa_camera_source* cocoa_camera_source_new(void)
{
    return (cocoa_camera_source*)calloc(1u, sizeof(cocoa_camera_source));
}

void cocoa_camera_source_stop(cocoa_camera_source* camera)
{
    if (!camera || !camera->file)
        return;
    fclose(camera->file);
    camera->file = NULL;
    camera->max_sample_bytes = 0;
}

void cocoa_camera_source_free(cocoa_camera_source* camera)
{
    if (!camera)
        return;
    cocoa_camera_source_stop(camera);
    free(camera);
}

int cocoa_camera_source_start(cocoa_camera_source* camera,
                              const char* source,
                              const librdp_video_capture_media* media)
{
    const char* path = cocoa_camera_file_path(source);
    size_t max_sample_bytes = 0;

    if (!camera || !path || !cocoa_camera_media_supported(media, &max_sample_bytes))
        return 0;
    cocoa_camera_source_stop(camera);
    camera->file = fopen(path, "rb");
    if (!camera->file)
        return 0;
    camera->max_sample_bytes = max_sample_bytes;
    return 1;
}

int cocoa_camera_source_read_sample(cocoa_camera_source* camera, uint8_t** data, size_t* data_len)
{
    uint8_t* sample = NULL;
    size_t read_bytes = 0;

    if (!camera || !camera->file || !data || !data_len || camera->max_sample_bytes == 0)
        return 0;
    *data = NULL;
    *data_len = 0;
    sample = (uint8_t*)malloc(camera->max_sample_bytes);
    if (!sample)
        return -1;
    read_bytes = fread(sample, 1, camera->max_sample_bytes, camera->file);
    if (read_bytes == 0)
    {
        if (ferror(camera->file))
        {
            free(sample);
            return -1;
        }
        rewind(camera->file);
        read_bytes = fread(sample, 1, camera->max_sample_bytes, camera->file);
    }
    if (read_bytes == 0)
    {
        free(sample);
        return 0;
    }
    *data = sample;
    *data_len = read_bytes;
    return 1;
}
