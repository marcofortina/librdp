/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: private Cocoa desktop-server capture state.
 * Invariants: the capture queue owns native sample access, at most one newest
 * frame is pending, and all host callbacks are emitted by the poll dispatcher.
 * Ownership: queued pixels and dirty rectangles belong to the context; native
 * Objective-C objects use manual reference counting.
 * Threading: the capture queue and host thread synchronize through one mutex
 * and a nonblocking wakeup pipe.
 * Trust boundary: dimensions, strides, attachment dictionaries and status
 * values are untrusted until bounded before allocation or callback delivery.
 */

#ifndef LIBRDP_COCOA_SERVER_INTERNAL_H
#define LIBRDP_COCOA_SERVER_INTERNAL_H

#include "cocoa_input.h"
#include "cocoa_server.h"

#import <Cocoa/Cocoa.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>

#include <pthread.h>

#define COCOA_SERVER_KEY_CAPACITY 128u

typedef struct cocoa_server_frame_packet
{
    uint8_t* pixels;
    size_t pixels_len;
    size_t stride;
    uint32_t width;
    uint32_t height;
    server_platform_rect dirty[COCOA_SERVER_MAX_DIRTY_RECTS];
    size_t dirty_count;
    uint64_t sequence;
    uint64_t timestamp_ns;
    int ready;
} cocoa_server_frame_packet;

@interface CocoaServerCaptureDelegate
    : NSObject <SCStreamOutput, SCStreamDelegate>
{
    struct cocoa_server_context* _context;
}
- (id)initWithContext:(struct cocoa_server_context*)context;
@end

struct cocoa_server_context
{
    cocoa_server_config config;
    SCContentFilter* filter;
    SCStreamConfiguration* stream_config;
    SCStream* stream;
    CocoaServerCaptureDelegate* capture_delegate;
    dispatch_queue_t capture_queue;
    pthread_mutex_t lock;
    int lock_ready;
    int wakeup_read_fd;
    int wakeup_write_fd;
    server_platform_capture_sink capture_sink;
    server_platform_permission_sink permission_sink;
    cocoa_server_frame_packet pending_frame;
    librdp_status pending_lost_status;
    uint32_t width;
    uint32_t height;
    uint32_t stable_source_id;
    CGRect source_rect;
    double source_scale;
    uint64_t next_sequence;
    uint8_t pressed_keys[COCOA_SERVER_KEY_CAPACITY];
    uint16_t pressed_buttons;
    uint16_t pending_high_surrogate;
    int capture_started;
    int permission_started;
    int capture_lost;
    int restart_required;
    int topology_refresh_required;
    int stopping;
    int force_full_frame;
};

uint64_t cocoa_server_now_ns(void);
void cocoa_server_capture_enqueue(cocoa_server_context* context,
                                  CMSampleBufferRef sample);
void cocoa_server_capture_lost(cocoa_server_context* context,
                               librdp_status status);
librdp_status cocoa_server_refresh_topology(
    cocoa_server_context* context,
    int restart_stream);
extern const server_platform_capture_vtable cocoa_server_capture_vtable;
extern const server_platform_input_vtable cocoa_server_input_vtable;
extern const server_platform_permission_vtable cocoa_server_permission_vtable;

#endif
