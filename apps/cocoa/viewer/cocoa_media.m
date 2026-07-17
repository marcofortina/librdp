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

#import <AVFoundation/AVFoundation.h>
#import <AudioToolbox/AudioToolbox.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreFoundation/CoreFoundation.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <dispatch/dispatch.h>

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define COCOA_AUDIO_RING_BYTES (4u * 1024u * 1024u)
#define COCOA_AUDIO_MAX_PACKET_BYTES (1024u * 1024u)
#define COCOA_CAMERA_MAX_WIDTH 7680u
#define COCOA_CAMERA_MAX_HEIGHT 4320u
#define COCOA_CAMERA_MAX_FPS 120u
#define COCOA_CAMERA_MAX_SAMPLE_BYTES (64u * 1024u * 1024u)

typedef struct cocoa_audio_ring
{
    uint8_t* data;
    size_t capacity;
    size_t read_pos;
    size_t write_pos;
    size_t size;
} cocoa_audio_ring;

@class CocoaCameraFrameSink;

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
    AVCaptureSession* session;
    AVCaptureVideoDataOutput* output;
    CocoaCameraFrameSink* sink;
    dispatch_queue_t queue;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    uint8_t* frame;
    size_t frame_len;
    size_t frame_capacity;
    size_t max_sample_bytes;
    uint32_t width;
    uint32_t height;
    uint8_t format;
    int lock_ready;
    int cond_ready;
    int live;
    uint64_t frames;
    uint64_t errors;
    uint64_t oversize_frames;
};

@interface CocoaCameraFrameSink : NSObject<AVCaptureVideoDataOutputSampleBufferDelegate>
{
    cocoa_camera_source* _camera;
}
- (id)initWithCamera:(cocoa_camera_source*)camera;
@end

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

static void cocoa_camera_release_dispatch_object(dispatch_object_t object)
{
#if !OS_OBJECT_USE_OBJC
    if (object)
        dispatch_release(object);
#else
    (void)object;
#endif
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

static const char* cocoa_camera_device_selector(const char* source)
{
    static const char prefix[] = "device=";

    if (!source || strncmp(source, prefix, sizeof(prefix) - 1u) != 0)
        return NULL;
    return source[sizeof(prefix) - 1u] != '\0' ? source + sizeof(prefix) - 1u : NULL;
}

int cocoa_camera_source_allowed(const char* source)
{
    return cocoa_camera_file_path(source) != NULL || cocoa_camera_device_selector(source) != NULL;
}

static int cocoa_camera_common_media_supported(const librdp_video_capture_media* media,
                                               size_t* pixels)
{
    const uint8_t allowed_flags = LIBRDP_VIDEO_CAPTURE_MEDIA_FLAG_DECODING_REQUIRED |
                                  LIBRDP_VIDEO_CAPTURE_MEDIA_FLAG_BOTTOM_UP;

    if (pixels)
        *pixels = 0;
    if (!media || media->width == 0 || media->height == 0 ||
        media->width > COCOA_CAMERA_MAX_WIDTH ||
        media->height > COCOA_CAMERA_MAX_HEIGHT ||
        (media->flags & (uint8_t)~allowed_flags) != 0 ||
        media->width > SIZE_MAX / media->height)
        return 0;
    if (media->frame_rate_denominator != 0 &&
        (uint64_t)media->frame_rate_numerator >
            (uint64_t)media->frame_rate_denominator * COCOA_CAMERA_MAX_FPS)
        return 0;
    if (pixels)
        *pixels = (size_t)media->width * media->height;
    return 1;
}

int cocoa_camera_media_supported(const librdp_video_capture_media* media, size_t* max_sample_bytes)
{
    size_t pixels = 0;

    if (max_sample_bytes)
        *max_sample_bytes = 0;
    if (!cocoa_camera_common_media_supported(media, &pixels))
        return 0;
    switch (media->format)
    {
        case LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG:
        case LIBRDP_VIDEO_CAPTURE_MEDIA_H264:
            if (max_sample_bytes)
                *max_sample_bytes = COCOA_CAMERA_MAX_SAMPLE_BYTES;
            return 1;
        case LIBRDP_VIDEO_CAPTURE_MEDIA_RGB32:
            if (pixels > SIZE_MAX / 4u || pixels * 4u > COCOA_CAMERA_MAX_SAMPLE_BYTES)
                return 0;
            if (max_sample_bytes)
                *max_sample_bytes = pixels * 4u;
            return 1;
        case LIBRDP_VIDEO_CAPTURE_MEDIA_RGB24:
            if (pixels > SIZE_MAX / 3u || pixels * 3u > COCOA_CAMERA_MAX_SAMPLE_BYTES)
                return 0;
            if (max_sample_bytes)
                *max_sample_bytes = pixels * 3u;
            return 1;
        default:
            return 0;
    }
}

static int cocoa_camera_live_media_supported(const librdp_video_capture_media* media,
                                             size_t* max_sample_bytes)
{
    if (!cocoa_camera_media_supported(media, max_sample_bytes))
        return 0;
    return media->format == LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG ||
           media->format == LIBRDP_VIDEO_CAPTURE_MEDIA_RGB32 ||
           media->format == LIBRDP_VIDEO_CAPTURE_MEDIA_RGB24;
}

static int cocoa_camera_copy_frame(cocoa_camera_source* camera, const uint8_t* data, size_t data_len)
{
    uint8_t* frame = NULL;

    if (!camera || !data || data_len == 0 || data_len > camera->max_sample_bytes)
        return 0;
    pthread_mutex_lock(&camera->lock);
    if (data_len > camera->frame_capacity)
    {
        frame = (uint8_t*)realloc(camera->frame, data_len);
        if (!frame)
        {
            camera->errors++;
            pthread_mutex_unlock(&camera->lock);
            return 0;
        }
        camera->frame = frame;
        camera->frame_capacity = data_len;
    }
    memcpy(camera->frame, data, data_len);
    camera->frame_len = data_len;
    camera->frames++;
    pthread_cond_broadcast(&camera->cond);
    pthread_mutex_unlock(&camera->lock);
    return 1;
}

static int cocoa_camera_copy_bgra_sample(cocoa_camera_source* camera,
                                         CVPixelBufferRef pixel_buffer)
{
    uint8_t* sample = NULL;
    const uint8_t* source = NULL;
    size_t width = 0;
    size_t height = 0;
    size_t stride = 0;
    size_t row_bytes = 0;
    size_t sample_len = 0;
    int ok = 0;

    if (!camera || !pixel_buffer ||
        CVPixelBufferGetPixelFormatType(pixel_buffer) != kCVPixelFormatType_32BGRA)
        return 0;
    width = CVPixelBufferGetWidth(pixel_buffer);
    height = CVPixelBufferGetHeight(pixel_buffer);
    stride = CVPixelBufferGetBytesPerRow(pixel_buffer);
    if (width == 0 || height == 0 || width > SIZE_MAX / 4u ||
        height > SIZE_MAX / (width * 4u))
        return 0;
    row_bytes = width * 4u;
    sample_len = row_bytes * height;
    if (sample_len > camera->max_sample_bytes)
    {
        camera->oversize_frames++;
        return 0;
    }
    if (CVPixelBufferLockBaseAddress(pixel_buffer, kCVPixelBufferLock_ReadOnly) != kCVReturnSuccess)
        return 0;
    source = (const uint8_t*)CVPixelBufferGetBaseAddress(pixel_buffer);
    if (source)
    {
        sample = (uint8_t*)malloc(sample_len);
        if (sample)
        {
            for (size_t row = 0; row < height; row++)
                memcpy(sample + row * row_bytes, source + row * stride, row_bytes);
            ok = cocoa_camera_copy_frame(camera, sample, sample_len);
            free(sample);
        }
    }
    CVPixelBufferUnlockBaseAddress(pixel_buffer, kCVPixelBufferLock_ReadOnly);
    return ok;
}

static int cocoa_camera_copy_rgb24_sample(cocoa_camera_source* camera,
                                          CVPixelBufferRef pixel_buffer)
{
    uint8_t* sample = NULL;
    const uint8_t* source = NULL;
    size_t width = 0;
    size_t height = 0;
    size_t stride = 0;
    size_t sample_len = 0;
    int ok = 0;

    if (!camera || !pixel_buffer ||
        CVPixelBufferGetPixelFormatType(pixel_buffer) != kCVPixelFormatType_32BGRA)
        return 0;
    width = CVPixelBufferGetWidth(pixel_buffer);
    height = CVPixelBufferGetHeight(pixel_buffer);
    stride = CVPixelBufferGetBytesPerRow(pixel_buffer);
    if (width == 0 || height == 0 || width > SIZE_MAX / 3u ||
        height > SIZE_MAX / (width * 3u))
        return 0;
    sample_len = width * height * 3u;
    if (sample_len > camera->max_sample_bytes)
    {
        camera->oversize_frames++;
        return 0;
    }
    if (CVPixelBufferLockBaseAddress(pixel_buffer, kCVPixelBufferLock_ReadOnly) != kCVReturnSuccess)
        return 0;
    source = (const uint8_t*)CVPixelBufferGetBaseAddress(pixel_buffer);
    if (source)
    {
        sample = (uint8_t*)malloc(sample_len);
        if (sample)
        {
            for (size_t y = 0; y < height; y++)
            {
                const uint8_t* input = source + y * stride;
                uint8_t* output = sample + y * width * 3u;

                for (size_t x = 0; x < width; x++)
                {
                    output[x * 3u + 0u] = input[x * 4u + 2u];
                    output[x * 3u + 1u] = input[x * 4u + 1u];
                    output[x * 3u + 2u] = input[x * 4u + 0u];
                }
            }
            ok = cocoa_camera_copy_frame(camera, sample, sample_len);
            free(sample);
        }
    }
    CVPixelBufferUnlockBaseAddress(pixel_buffer, kCVPixelBufferLock_ReadOnly);
    return ok;
}

static int cocoa_camera_copy_jpeg_sample(cocoa_camera_source* camera,
                                         CVPixelBufferRef pixel_buffer)
{
    CGColorSpaceRef color_space = NULL;
    CGContextRef context = NULL;
    CGImageRef image = NULL;
    CGImageDestinationRef destination = NULL;
    CFMutableDataRef encoded = NULL;
    const uint8_t* data = NULL;
    size_t length = 0;
    size_t width = 0;
    size_t height = 0;
    size_t stride = 0;
    void* base = NULL;
    int ok = 0;

    if (!camera || !pixel_buffer ||
        CVPixelBufferGetPixelFormatType(pixel_buffer) != kCVPixelFormatType_32BGRA)
        return 0;
    width = CVPixelBufferGetWidth(pixel_buffer);
    height = CVPixelBufferGetHeight(pixel_buffer);
    stride = CVPixelBufferGetBytesPerRow(pixel_buffer);
    if (width == 0 || height == 0)
        return 0;
    if (CVPixelBufferLockBaseAddress(pixel_buffer, kCVPixelBufferLock_ReadOnly) != kCVReturnSuccess)
        return 0;
    base = CVPixelBufferGetBaseAddress(pixel_buffer);
    color_space = CGColorSpaceCreateDeviceRGB();
    if (base && color_space)
    {
        context = CGBitmapContextCreate(
            base,
            width,
            height,
            8u,
            stride,
            color_space,
            (CGBitmapInfo)((uint32_t)kCGBitmapByteOrder32Little | (uint32_t)kCGImageAlphaNoneSkipFirst));
        if (context)
            image = CGBitmapContextCreateImage(context);
    }
    if (image)
    {
        NSNumber* quality = [NSNumber numberWithDouble:0.85];
        NSDictionary* properties =
            [NSDictionary dictionaryWithObject:quality
                                        forKey:(id)kCGImageDestinationLossyCompressionQuality];

        encoded = CFDataCreateMutable(kCFAllocatorDefault, 0);
        if (encoded)
            destination = CGImageDestinationCreateWithData(encoded, CFSTR("public.jpeg"), 1u, NULL);
        if (destination)
        {
            CGImageDestinationAddImage(destination, image, (CFDictionaryRef)properties);
            if (CGImageDestinationFinalize(destination))
            {
                length = (size_t)CFDataGetLength(encoded);
                data = CFDataGetBytePtr(encoded);
                if (length <= camera->max_sample_bytes)
                    ok = cocoa_camera_copy_frame(camera, data, length);
                else
                    camera->oversize_frames++;
            }
        }
    }
    if (destination)
        CFRelease(destination);
    if (encoded)
        CFRelease(encoded);
    if (image)
        CGImageRelease(image);
    if (context)
        CGContextRelease(context);
    if (color_space)
        CGColorSpaceRelease(color_space);
    CVPixelBufferUnlockBaseAddress(pixel_buffer, kCVPixelBufferLock_ReadOnly);
    return ok;
}

static int cocoa_camera_store_sample(cocoa_camera_source* camera,
                                     CMSampleBufferRef sample_buffer)
{
    CVPixelBufferRef pixel_buffer = NULL;

    if (!camera || !sample_buffer)
        return 0;
    pixel_buffer = CMSampleBufferGetImageBuffer(sample_buffer);
    if (!pixel_buffer)
        return 0;
    switch (camera->format)
    {
        case LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG:
            return cocoa_camera_copy_jpeg_sample(camera, pixel_buffer);
        case LIBRDP_VIDEO_CAPTURE_MEDIA_RGB32:
            return cocoa_camera_copy_bgra_sample(camera, pixel_buffer);
        case LIBRDP_VIDEO_CAPTURE_MEDIA_RGB24:
            return cocoa_camera_copy_rgb24_sample(camera, pixel_buffer);
        default:
            camera->errors++;
            return 0;
    }
}

@implementation CocoaCameraFrameSink
- (id)initWithCamera:(cocoa_camera_source*)camera
{
    self = [super init];
    if (self)
        _camera = camera;
    return self;
}

- (void)captureOutput:(AVCaptureOutput*)output
 didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
        fromConnection:(AVCaptureConnection*)connection
{
    (void)output;
    (void)connection;
    @autoreleasepool
    {
        (void)cocoa_camera_store_sample(_camera, sampleBuffer);
    }
}
@end

static int cocoa_camera_authorized(void)
{
    __block BOOL granted = NO;
    dispatch_semaphore_t semaphore = NULL;
    AVAuthorizationStatus status =
        [AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeVideo];

    if (status == AVAuthorizationStatusAuthorized)
        return 1;
    if (status == AVAuthorizationStatusDenied || status == AVAuthorizationStatusRestricted)
        return 0;
    if (status != AVAuthorizationStatusNotDetermined)
        return 0;
    semaphore = dispatch_semaphore_create(0);
    if (!semaphore)
        return 0;
    [AVCaptureDevice requestAccessForMediaType:AVMediaTypeVideo
                             completionHandler:^(BOOL accepted) {
                                 granted = accepted;
                                 dispatch_semaphore_signal(semaphore);
                             }];
    (void)dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    cocoa_camera_release_dispatch_object((dispatch_object_t)semaphore);
    return granted ? 1 : 0;
}

static NSArray* cocoa_camera_devices(void)
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return [AVCaptureDevice devicesWithMediaType:AVMediaTypeVideo];
#pragma clang diagnostic pop
}

static AVCaptureDevice* cocoa_camera_default_device(void)
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeVideo];
#pragma clang diagnostic pop
}

static AVCaptureDevice* cocoa_camera_find_device(const char* selector)
{
    NSArray* devices = nil;
    NSString* wanted = nil;
    char* end = NULL;
    unsigned long index = 0;

    if (!selector || strcmp(selector, "default") == 0)
        return cocoa_camera_default_device();
    devices = cocoa_camera_devices();
    errno = 0;
    index = strtoul(selector, &end, 10);
    if (errno == 0 && end && *end == '\0' && index < (unsigned long)[devices count])
        return [devices objectAtIndex:(NSUInteger)index];
    wanted = [NSString stringWithUTF8String:selector];
    if (!wanted)
        return nil;
    for (AVCaptureDevice* device in devices)
    {
        if ([[device uniqueID] isEqualToString:wanted] ||
            [[device localizedName] isEqualToString:wanted])
            return device;
    }
    return nil;
}

static int cocoa_camera_start_live(cocoa_camera_source* camera,
                                   const char* selector,
                                   const librdp_video_capture_media* media)
{
    AVCaptureDevice* device = nil;
    AVCaptureDeviceInput* input = nil;
    NSError* error = nil;
    NSDictionary* video_settings = nil;
    size_t max_sample_bytes = 0;

    if (!camera || !selector || !cocoa_camera_live_media_supported(media, &max_sample_bytes))
        return 0;
    if (!cocoa_camera_authorized())
        return 0;
    device = cocoa_camera_find_device(selector);
    if (!device)
        return 0;
    input = [AVCaptureDeviceInput deviceInputWithDevice:device error:&error];
    if (!input || error)
        return 0;
    camera->session = [[AVCaptureSession alloc] init];
    camera->output = [[AVCaptureVideoDataOutput alloc] init];
    camera->sink = [[CocoaCameraFrameSink alloc] initWithCamera:camera];
    camera->queue = dispatch_queue_create("librdp.cocoa.camera", DISPATCH_QUEUE_SERIAL);
    if (!camera->session || !camera->output || !camera->sink || !camera->queue)
    {
        cocoa_camera_source_stop(camera);
        return 0;
    }
    video_settings =
        [NSDictionary dictionaryWithObject:[NSNumber numberWithUnsignedInt:kCVPixelFormatType_32BGRA]
                                    forKey:(id)kCVPixelBufferPixelFormatTypeKey];
    [camera->output setVideoSettings:video_settings];
    [camera->output setAlwaysDiscardsLateVideoFrames:YES];
    [camera->output setSampleBufferDelegate:camera->sink queue:camera->queue];
    if (![camera->session canAddInput:input] || ![camera->session canAddOutput:camera->output])
    {
        cocoa_camera_source_stop(camera);
        return 0;
    }
    [camera->session addInput:input];
    [camera->session addOutput:camera->output];
    camera->max_sample_bytes = max_sample_bytes;
    camera->width = media->width;
    camera->height = media->height;
    camera->format = media->format;
    camera->live = 1;
    [camera->session startRunning];
    if (![camera->session isRunning])
    {
        cocoa_camera_source_stop(camera);
        return 0;
    }
    return 1;
}

cocoa_camera_source* cocoa_camera_source_new(void)
{
    cocoa_camera_source* camera = (cocoa_camera_source*)calloc(1u, sizeof(*camera));

    if (!camera)
        return NULL;
    if (pthread_mutex_init(&camera->lock, NULL) != 0)
    {
        free(camera);
        return NULL;
    }
    camera->lock_ready = 1;
    if (pthread_cond_init(&camera->cond, NULL) != 0)
    {
        pthread_mutex_destroy(&camera->lock);
        free(camera);
        return NULL;
    }
    camera->cond_ready = 1;
    return camera;
}

void cocoa_camera_source_stop(cocoa_camera_source* camera)
{
    if (!camera)
        return;
    if (camera->output)
        [camera->output setSampleBufferDelegate:nil queue:NULL];
    if (camera->queue)
        dispatch_sync(camera->queue, ^{
        });
    if (camera->session)
        [camera->session stopRunning];
    if (camera->file)
    {
        fclose(camera->file);
        camera->file = NULL;
    }
    if (camera->output)
    {
        [camera->output release];
        camera->output = nil;
    }
    if (camera->session)
    {
        [camera->session release];
        camera->session = nil;
    }
    if (camera->sink)
    {
        [camera->sink release];
        camera->sink = nil;
    }
    if (camera->queue)
    {
        cocoa_camera_release_dispatch_object((dispatch_object_t)camera->queue);
        camera->queue = NULL;
    }
    pthread_mutex_lock(&camera->lock);
    camera->max_sample_bytes = 0;
    camera->width = 0;
    camera->height = 0;
    camera->format = 0;
    camera->frame_len = 0;
    camera->live = 0;
    pthread_cond_broadcast(&camera->cond);
    pthread_mutex_unlock(&camera->lock);
}

void cocoa_camera_source_free(cocoa_camera_source* camera)
{
    if (!camera)
        return;
    cocoa_camera_source_stop(camera);
    free(camera->frame);
    if (camera->cond_ready)
        pthread_cond_destroy(&camera->cond);
    if (camera->lock_ready)
        pthread_mutex_destroy(&camera->lock);
    free(camera);
}

int cocoa_camera_source_start(cocoa_camera_source* camera,
                              const char* source,
                              const librdp_video_capture_media* media)
{
    const char* path = NULL;
    const char* selector = NULL;
    size_t max_sample_bytes = 0;

    if (!camera || !source)
        return 0;
    cocoa_camera_source_stop(camera);
    selector = cocoa_camera_device_selector(source);
    if (selector)
        return cocoa_camera_start_live(camera, selector, media);
    path = cocoa_camera_file_path(source);
    if (!path || !cocoa_camera_media_supported(media, &max_sample_bytes))
        return 0;
    camera->file = fopen(path, "rb");
    if (!camera->file)
        return 0;
    camera->max_sample_bytes = max_sample_bytes;
    return 1;
}

static int cocoa_camera_read_live_sample(cocoa_camera_source* camera,
                                         uint8_t** data,
                                         size_t* data_len)
{
    struct timespec deadline;
    uint8_t* sample = NULL;
    int wait_status = 0;

    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0)
        return -1;
    deadline.tv_nsec += 100000000L;
    if (deadline.tv_nsec >= 1000000000L)
    {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&camera->lock);
    while (camera->live && camera->frame_len == 0 && wait_status == 0)
        wait_status = pthread_cond_timedwait(&camera->cond, &camera->lock, &deadline);
    if (!camera->live || camera->frame_len == 0)
    {
        pthread_mutex_unlock(&camera->lock);
        return wait_status == ETIMEDOUT ? 0 : -1;
    }
    sample = (uint8_t*)malloc(camera->frame_len);
    if (sample)
    {
        memcpy(sample, camera->frame, camera->frame_len);
        *data = sample;
        *data_len = camera->frame_len;
    }
    pthread_mutex_unlock(&camera->lock);
    return sample ? 1 : -1;
}

int cocoa_camera_source_read_sample(cocoa_camera_source* camera, uint8_t** data, size_t* data_len)
{
    uint8_t* sample = NULL;
    size_t read_bytes = 0;

    if (!camera || !data || !data_len || camera->max_sample_bytes == 0)
        return 0;
    *data = NULL;
    *data_len = 0;
    if (camera->live)
        return cocoa_camera_read_live_sample(camera, data, data_len);
    if (!camera->file)
        return 0;
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
