/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: native Cocoa viewer for exercising public client APIs.
 * Invariants: AppKit owns windowing on the main thread, librdp session dispatch
 * is serialized on the same thread, and framebuffer bytes are borrowed only
 * while drawing.
 * Ownership: settings are released after session creation, the session owns
 * protocol state, and AppKit owns windows, views, run-loop sources, and events.
 * Threading: single-threaded AppKit event loop; callbacks are invoked by the
 * descriptor-driven session dispatch path.
 * Trust boundary: command-line values and remote desktop pixels are untrusted
 * inputs; credentials are copied into settings and never printed.
 */

#import <Cocoa/Cocoa.h>
#include <librdp/librdp.h>

#include "client_callbacks.h"
#include "cocoa_cli.h"
#include "cocoa_media.h"
#include "cocoa_render.h"
#include "cocoa_session_loop.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COCOA_AUDIO_OUTPUT_FORMATS_MAX 16u
#define COCOA_AUDIO_INPUT_BUFFER_BYTES 16384u

@class CocoaViewerController;

@interface CocoaViewerView : NSView
@property(nonatomic, assign) CocoaViewerController* controller;
@end

@interface CocoaViewerController : NSObject<NSWindowDelegate>
{
    librdp_audio_format _audioOutputFormats[COCOA_AUDIO_OUTPUT_FORMATS_MAX];
    uint8_t _audioInputBuffer[COCOA_AUDIO_INPUT_BUFFER_BYTES];
}
@property(nonatomic, assign) librdp_session* session;
@property(nonatomic, assign) cocoa_session_loop* sessionLoop;
@property(nonatomic, strong) NSWindow* window;
@property(nonatomic, strong) CocoaViewerView* view;
@property(nonatomic, strong) NSCursor* currentCursor;
@property(nonatomic, assign) cocoa_audio_backend* audio;
@property(nonatomic, assign) cocoa_camera_source* camera;
@property(nonatomic, assign) FILE* videoOutputFile;
@property(nonatomic, assign) const char* audioOutputDevice;
@property(nonatomic, assign) const char* audioInputDevice;
@property(nonatomic, assign) const char* cameraSource;
@property(nonatomic, assign) uint32_t audioOutputFormatCount;
@property(nonatomic, assign) uint32_t audioOutputCurrentFormat;
@property(nonatomic, assign) size_t audioInputChunk;
@property(nonatomic, assign) NSInteger pasteboardChangeCount;
@property(nonatomic, assign) BOOL dirty;
@property(nonatomic, assign) BOOL closed;
@property(nonatomic, assign) BOOL audioOutputRequested;
@property(nonatomic, assign) BOOL audioInputRequested;
@property(nonatomic, assign) BOOL audioInputActive;
@property(nonatomic, assign) BOOL videoRequested;
@property(nonatomic, assign) BOOL cameraRequested;
- (id)initWithSession:(librdp_session*)session width:(uint32_t)width height:(uint32_t)height;
- (BOOL)configureMediaWithOptions:(const cocoa_viewer_options*)options;
- (void)shutdownMedia;
- (void)shutdownSession;
- (BOOL)start;
- (void)markDirty;
- (void)pumpAudioInput;
- (void)handleAudioEnvelope:(librdp_session*)session envelope:(const librdp_event_envelope*)envelope;
- (void)handleVideoEnvelope:(librdp_session*)session envelope:(const librdp_event_envelope*)envelope;
- (void)handleChannelEnvelope:(librdp_session*)session envelope:(const librdp_event_envelope*)envelope;
- (void)sendResizeForView;
- (void)sendMouseEvent:(NSEvent*)event button:(librdp_mouse_button)button state:(librdp_mouse_state)state;
- (void)sendWheelEvent:(NSEvent*)event;
- (void)sendKeyEvent:(NSEvent*)event pressed:(BOOL)pressed;
- (void)applyPointerEvent:(const librdp_pointer_event*)pointer;
- (void)handleClipboardEnvelope:(const librdp_event_envelope*)envelope;
- (void)publishLocalPasteboardIfChanged;
- (void)setOutputSuppressed:(BOOL)suppressed;
@end

static void cocoa_viewer_graphics_callback(librdp_session* session,
                                           const librdp_graphics_update* update,
                                           void* user_data)
{
    CocoaViewerController* controller = (__bridge CocoaViewerController*)user_data;

    (void)session;
    if (!update || !controller)
        return;
    [controller markDirty];
}

static void cocoa_viewer_pointer_callback(librdp_session* session,
                                          const librdp_event_envelope* envelope,
                                          void* user_data)
{
    CocoaViewerController* controller = (__bridge CocoaViewerController*)user_data;
    const librdp_pointer_event* pointer = NULL;

    (void)session;
    if (!controller || !envelope || envelope->type != LIBRDP_EVENT_POINTER ||
        envelope->payload_size < sizeof(*pointer))
        return;
    pointer = (const librdp_pointer_event*)envelope->payload;
    [controller applyPointerEvent:pointer];
}

static void cocoa_viewer_clipboard_callback(librdp_session* session,
                                            const librdp_event_envelope* envelope,
                                            void* user_data)
{
    CocoaViewerController* controller = (__bridge CocoaViewerController*)user_data;

    (void)session;
    if (!controller || !envelope)
        return;
    [controller handleClipboardEnvelope:envelope];
}

static void cocoa_viewer_audio_callback(librdp_session* session,
                                        const librdp_event_envelope* envelope,
                                        void* user_data)
{
    CocoaViewerController* controller = (__bridge CocoaViewerController*)user_data;

    if (!controller || !session || !envelope)
        return;
    [controller handleAudioEnvelope:session envelope:envelope];
}

static void cocoa_viewer_video_callback(librdp_session* session,
                                        const librdp_event_envelope* envelope,
                                        void* user_data)
{
    CocoaViewerController* controller = (__bridge CocoaViewerController*)user_data;

    if (!controller || !session || !envelope)
        return;
    [controller handleVideoEnvelope:session envelope:envelope];
}

static void cocoa_viewer_channel_callback(librdp_session* session,
                                          const librdp_event_envelope* envelope,
                                          void* user_data)
{
    CocoaViewerController* controller = (__bridge CocoaViewerController*)user_data;

    if (!controller || !session || !envelope)
        return;
    [controller handleChannelEnvelope:session envelope:envelope];
}

static int cocoa_viewer_channel_name_contains(const char* name, size_t name_len, const char* needle)
{
    size_t needle_len = 0;

    if (!name || !needle)
        return 0;
    needle_len = strlen(needle);
    if (needle_len == 0 || needle_len > name_len)
        return 0;
    for (size_t i = 0; i + needle_len <= name_len; i++)
    {
        size_t j = 0;

        for (j = 0; j < needle_len; j++)
        {
            if (tolower((unsigned char)name[i + j]) != tolower((unsigned char)needle[j]))
                break;
        }
        if (j == needle_len)
            return 1;
    }
    return 0;
}

static void cocoa_viewer_session_prepare(void* user_data)
{
    CocoaViewerController* controller = (__bridge CocoaViewerController*)user_data;

    if (!controller || controller.closed)
        return;
    [controller publishLocalPasteboardIfChanged];
    [controller pumpAudioInput];
    if (controller.dirty)
    {
        controller.dirty = NO;
        [controller.view setNeedsDisplay:YES];
    }
}

static int cocoa_viewer_session_timeout(void* user_data)
{
    CocoaViewerController* controller = (__bridge CocoaViewerController*)user_data;

    if (!controller)
        return -1;
    return controller.audioInputActive ? 10 : 100;
}

static void cocoa_viewer_session_status(librdp_status status,
                                        librdp_session_state state,
                                        void* user_data)
{
    CocoaViewerController* controller = (__bridge CocoaViewerController*)user_data;

    if (!controller)
        return;
    if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_CLOSED &&
        status != LIBRDP_STATUS_CANCELLED)
    {
        fprintf(stderr, "session dispatch failed: %s\n", librdp_status_string(status));
    }
    if (status != LIBRDP_STATUS_OK || state == LIBRDP_SESSION_CLOSED ||
        state == LIBRDP_SESSION_FAILED || state == LIBRDP_SESSION_CANCELLED)
    {
        controller.closed = YES;
        [NSApp terminate:nil];
    }
}

@implementation CocoaViewerView

- (BOOL)isFlipped
{
    return YES;
}

- (BOOL)acceptsFirstResponder
{
    return YES;
}

- (void)resetCursorRects
{
    NSCursor* cursor = self.controller.currentCursor ? self.controller.currentCursor : [NSCursor arrowCursor];

    [self addCursorRect:self.bounds cursor:cursor];
}

- (void)drawRect:(NSRect)dirtyRect
{
    const librdp_surface* surface = NULL;
    CGRect destination;

    (void)dirtyRect;
    if (!self.controller || !self.controller.session)
        return;
    surface = librdp_session_get_surface(self.controller.session);
    if (!surface)
        return;
    destination = CGRectMake(
        0.0,
        0.0,
        NSWidth(self.bounds),
        NSHeight(self.bounds));
    (void)cocoa_render_surface(
        (CGContextRef)[[NSGraphicsContext currentContext] CGContext],
        (librdp_surface*)surface,
        destination);
}

- (void)mouseMoved:(NSEvent*)event
{
    [self.controller sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_NONE state:LIBRDP_MOUSE_MOVED];
}

- (void)mouseDragged:(NSEvent*)event
{
    [self mouseMoved:event];
}

- (void)rightMouseDragged:(NSEvent*)event
{
    [self mouseMoved:event];
}

- (void)otherMouseDragged:(NSEvent*)event
{
    [self mouseMoved:event];
}

- (void)mouseDown:(NSEvent*)event
{
    [self.controller sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_LEFT state:LIBRDP_MOUSE_PRESSED];
}

- (void)mouseUp:(NSEvent*)event
{
    [self.controller sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_LEFT state:LIBRDP_MOUSE_RELEASED];
}

- (void)rightMouseDown:(NSEvent*)event
{
    [self.controller sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_RIGHT state:LIBRDP_MOUSE_PRESSED];
}

- (void)rightMouseUp:(NSEvent*)event
{
    [self.controller sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_RIGHT state:LIBRDP_MOUSE_RELEASED];
}

- (void)otherMouseDown:(NSEvent*)event
{
    NSInteger raw_button_number = [event buttonNumber];
    NSUInteger button_number = 0;
    librdp_mouse_button button = LIBRDP_MOUSE_BUTTON_X2;

    if (raw_button_number < 0)
        return;
    button_number = (NSUInteger)raw_button_number;
    if (button_number == 2)
        button = LIBRDP_MOUSE_BUTTON_MIDDLE;
    else if (button_number == 3)
        button = LIBRDP_MOUSE_BUTTON_X1;

    [self.controller sendMouseEvent:event button:button state:LIBRDP_MOUSE_PRESSED];
}

- (void)otherMouseUp:(NSEvent*)event
{
    NSInteger raw_button_number = [event buttonNumber];
    NSUInteger button_number = 0;
    librdp_mouse_button button = LIBRDP_MOUSE_BUTTON_X2;

    if (raw_button_number < 0)
        return;
    button_number = (NSUInteger)raw_button_number;
    if (button_number == 2)
        button = LIBRDP_MOUSE_BUTTON_MIDDLE;
    else if (button_number == 3)
        button = LIBRDP_MOUSE_BUTTON_X1;

    [self.controller sendMouseEvent:event button:button state:LIBRDP_MOUSE_RELEASED];
}

- (void)scrollWheel:(NSEvent*)event
{
    [self.controller sendWheelEvent:event];
}

- (void)keyDown:(NSEvent*)event
{
    [self.controller sendKeyEvent:event pressed:YES];
}

- (void)keyUp:(NSEvent*)event
{
    [self.controller sendKeyEvent:event pressed:NO];
}

- (void)flagsChanged:(NSEvent*)event
{
    (void)event;
}

@end

@implementation CocoaViewerController

- (id)initWithSession:(librdp_session*)session width:(uint32_t)width height:(uint32_t)height
{
    NSRect frame = NSMakeRect(0.0, 0.0, (CGFloat)width, (CGFloat)height);
    cocoa_session_loop_callbacks callbacks;

    self = [super init];
    if (!self)
        return nil;
    self.session = session;
    self.view = [[CocoaViewerView alloc] initWithFrame:frame];
    self.view.controller = self;
    self.window = [[NSWindow alloc] initWithContentRect:frame
                                              styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                                        NSWindowStyleMaskResizable | NSWindowStyleMaskMiniaturizable
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    [self.window setTitle:@"librdp-viewer"];
    [self.window setContentView:self.view];
    [self.window setDelegate:self];
    [self.window setAcceptsMouseMovedEvents:YES];
    [self.window center];
    self.currentCursor = [NSCursor arrowCursor];
    self.pasteboardChangeCount = [[NSPasteboard generalPasteboard] changeCount];
    self.audioOutputCurrentFormat = UINT32_MAX;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.prepare = cocoa_viewer_session_prepare;
    callbacks.timeout = cocoa_viewer_session_timeout;
    callbacks.status = cocoa_viewer_session_status;
    callbacks.user_data = (__bridge void*)self;
    self.sessionLoop = cocoa_session_loop_new(session, &callbacks);
    if (!self.sessionLoop)
        return nil;
    return self;
}

- (BOOL)configureMediaWithOptions:(const cocoa_viewer_options*)options
{
    if (!options)
        return NO;
    self.audioOutputRequested = options->audio_output_requested ? YES : NO;
    self.audioInputRequested = options->audio_input_requested ? YES : NO;
    self.videoRequested = options->video_requested ? YES : NO;
    self.cameraRequested = options->camera_requested ? YES : NO;
    self.audioOutputDevice = options->audio_output_device ? options->audio_output_device : "coreaudio";
    self.audioInputDevice = options->audio_input_device ? options->audio_input_device : "coreaudio";
    self.cameraSource = options->camera_source;
    self.audioOutputCurrentFormat = UINT32_MAX;
    if (self.audioOutputRequested || self.audioInputRequested)
    {
        self.audio = cocoa_audio_backend_new();
        if (!self.audio)
            return NO;
    }
    if (self.videoRequested && options->video_output_path)
    {
        self.videoOutputFile = fopen(options->video_output_path, "ab");
        if (!self.videoOutputFile)
            return NO;
    }
    if (self.cameraRequested)
    {
        self.camera = cocoa_camera_source_new();
        if (!self.camera)
            return NO;
    }
    return YES;
}

- (void)shutdownMedia
{
    if (self.audio)
    {
        cocoa_audio_backend_free(self.audio);
        self.audio = NULL;
    }
    if (self.camera)
    {
        cocoa_camera_source_free(self.camera);
        self.camera = NULL;
    }
    if (self.videoOutputFile)
    {
        fclose(self.videoOutputFile);
        self.videoOutputFile = NULL;
    }
    self.audioInputActive = NO;
    self.audioInputChunk = 0;
    self.audioOutputCurrentFormat = UINT32_MAX;
}

- (void)shutdownSession
{
    if (!self.sessionLoop)
        return;
    (void)cocoa_session_loop_disconnect(self.sessionLoop);
    cocoa_session_loop_free(self.sessionLoop);
    self.sessionLoop = NULL;
}

- (BOOL)start
{
    librdp_status status = LIBRDP_STATUS_OK;

    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    [self.window makeKeyAndOrderFront:nil];
    [self.window makeFirstResponder:self.view];
    [NSApp activateIgnoringOtherApps:YES];
    status = cocoa_session_loop_start(self.sessionLoop);
    if (status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr, "session loop failed: %s\n", librdp_status_string(status));
        return NO;
    }
    return YES;
}

- (void)markDirty
{
    self.dirty = YES;
    [self.view setNeedsDisplay:YES];
}

- (void)setOutputSuppressed:(BOOL)suppressed
{
    librdp_status status = LIBRDP_STATUS_STATE;

    if (self.session)
    {
        status = librdp_session_set_output_suppressed(
            self.session,
            suppressed ? 1 : 0);
    }
    if (status != LIBRDP_STATUS_OK &&
        status != LIBRDP_STATUS_STATE &&
        status != LIBRDP_STATUS_UNSUPPORTED)
    {
        fprintf(stderr,
                "output update failed: %s\n",
                librdp_status_string(status));
    }
}

- (void)windowDidMiniaturize:(NSNotification*)notification
{
    (void)notification;
    [self setOutputSuppressed:YES];
}

- (void)windowDidDeminiaturize:(NSNotification*)notification
{
    (void)notification;
    [self setOutputSuppressed:NO];
}

- (size_t)audioInputChunkForOpen:(const librdp_audio_input_open_event*)open
{
    size_t chunk = 0;

    if (!open || open->format.block_align == 0)
        return 0;
    chunk = (size_t)open->frames_per_packet * open->format.block_align;
    if (chunk == 0)
        chunk = open->format.block_align;
    if (chunk > COCOA_AUDIO_INPUT_BUFFER_BYTES)
    {
        chunk = COCOA_AUDIO_INPUT_BUFFER_BYTES -
                (COCOA_AUDIO_INPUT_BUFFER_BYTES % open->format.block_align);
        if (chunk == 0)
            chunk = open->format.block_align;
    }
    return chunk;
}

- (void)storeAudioOutputFormats:(const librdp_audio_output_formats_event*)formats
{
    uint32_t count = 0;

    self.audioOutputFormatCount = 0;
    self.audioOutputCurrentFormat = UINT32_MAX;
    memset(_audioOutputFormats, 0, sizeof(_audioOutputFormats));
    if (!formats || !formats->formats || formats->count == 0)
        return;
    count = formats->count > COCOA_AUDIO_OUTPUT_FORMATS_MAX ?
        COCOA_AUDIO_OUTPUT_FORMATS_MAX :
        formats->count;
    memcpy(_audioOutputFormats, formats->formats, sizeof(_audioOutputFormats[0]) * count);
    self.audioOutputFormatCount = count;
}

- (BOOL)selectAudioOutputFormat:(uint32_t)formatNo
{
    if (!self.audioOutputRequested || !self.audio)
        return NO;
    if (formatNo >= self.audioOutputFormatCount)
        return NO;
    if (self.audioOutputCurrentFormat == formatNo)
        return YES;
    if (!cocoa_audio_backend_start_output(self.audio, &_audioOutputFormats[formatNo], self.audioOutputDevice))
        return NO;
    self.audioOutputCurrentFormat = formatNo;
    return YES;
}

- (void)pumpAudioInput
{
    size_t bytes = 0;

    if (!self.audioInputActive || !self.audio || !self.session || self.audioInputChunk == 0)
        return;
    bytes = cocoa_audio_backend_read_input(self.audio, _audioInputBuffer, self.audioInputChunk);
    if (bytes == 0)
        return;
    if (librdp_session_audio_input_send_data(self.session, _audioInputBuffer, bytes) != LIBRDP_STATUS_OK)
        self.audioInputActive = NO;
}

- (void)handleAudioEnvelope:(librdp_session*)session envelope:(const librdp_event_envelope*)envelope
{
    if (!session || !envelope)
        return;
    switch (envelope->type)
    {
        case LIBRDP_EVENT_AUDIO_OUTPUT_FORMATS:
            if (envelope->payload_size >= sizeof(librdp_audio_output_formats_event))
            {
                [self storeAudioOutputFormats:(const librdp_audio_output_formats_event*)envelope->payload];
                if (self.audioOutputFormatCount > 0)
                    (void)[self selectAudioOutputFormat:0];
            }
            break;
        case LIBRDP_EVENT_AUDIO_OUTPUT_DATA:
            if (envelope->payload_size >= sizeof(librdp_audio_output_data_event))
            {
                const librdp_audio_output_data_event* data =
                    (const librdp_audio_output_data_event*)envelope->payload;

                if ([self selectAudioOutputFormat:data->format_no])
                    (void)cocoa_audio_backend_write_output(self.audio, data->data, data->data_len);
            }
            break;
        case LIBRDP_EVENT_AUDIO_OUTPUT_CLOSE:
            if (self.audio)
                cocoa_audio_backend_stop_output(self.audio);
            self.audioOutputCurrentFormat = UINT32_MAX;
            break;
        case LIBRDP_EVENT_AUDIO_INPUT_OPEN:
            if (envelope->payload_size >= sizeof(librdp_audio_input_open_event))
            {
                const librdp_audio_input_open_event* open =
                    (const librdp_audio_input_open_event*)envelope->payload;
                int ok = 0;

                self.audioInputActive = NO;
                self.audioInputChunk = [self audioInputChunkForOpen:open];
                if (self.audioInputRequested && self.audio && self.audioInputChunk > 0)
                    ok = cocoa_audio_backend_start_input(self.audio, &open->format, self.audioInputDevice);
                (void)librdp_session_audio_input_open_reply(session,
                                                            ok ? LIBRDP_AUDIO_INPUT_RESULT_OK :
                                                                 LIBRDP_AUDIO_INPUT_RESULT_FAIL);
                self.audioInputActive = ok ? YES : NO;
            }
            break;
        default:
            break;
    }
}

- (void)handleVideoEnvelope:(librdp_session*)session envelope:(const librdp_event_envelope*)envelope
{
    if (!session || !envelope)
        return;
    switch (envelope->type)
    {
        case LIBRDP_EVENT_VIDEO_CAPTURE_OPEN:
            if (envelope->payload_size >= sizeof(librdp_video_capture_open_event) &&
                self.cameraRequested && self.camera && self.cameraSource)
            {
                const librdp_video_capture_open_event* open =
                    (const librdp_video_capture_open_event*)envelope->payload;

                (void)cocoa_camera_source_start(self.camera, self.cameraSource, &open->media);
            }
            break;
        case LIBRDP_EVENT_VIDEO_CAPTURE_SAMPLE_REQUEST:
            if (envelope->payload_size >= sizeof(librdp_video_capture_sample_request_event))
            {
                const librdp_video_capture_sample_request_event* request =
                    (const librdp_video_capture_sample_request_event*)envelope->payload;
                uint8_t* sample = NULL;
                size_t sampleLen = 0;
                int sampleResult = 0;

                if (self.cameraRequested && self.camera)
                    sampleResult = cocoa_camera_source_read_sample(self.camera, &sample, &sampleLen);
                if (sampleResult == 1)
                    (void)librdp_session_video_capture_send_sample(session,
                                                                   request->stream_index,
                                                                   sample,
                                                                   sampleLen);
                else
                    (void)librdp_session_video_capture_send_error(
                        session,
                        request->stream_index,
                        sampleResult == 0 ? LIBRDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED :
                                            LIBRDP_VIDEO_CAPTURE_ERROR_UNEXPECTED);
                free(sample);
            }
            break;
        case LIBRDP_EVENT_VIDEO_CAPTURE_CLOSE:
            if (self.camera)
                cocoa_camera_source_stop(self.camera);
            break;
        default:
            break;
    }
}

- (void)handleChannelEnvelope:(librdp_session*)session envelope:(const librdp_event_envelope*)envelope
{
    const librdp_channel_data_event* event = NULL;

    (void)session;
    if (!envelope || envelope->type != LIBRDP_EVENT_CHANNEL_DATA ||
        envelope->payload_size < sizeof(*event))
        return;
    event = (const librdp_channel_data_event*)envelope->payload;
    if (self.videoOutputFile &&
        (cocoa_viewer_channel_name_contains(event->name, event->name_len, "video") ||
         cocoa_viewer_channel_name_contains(event->name, event->name_len, "tsmf")) &&
        event->data_len > 0)
    {
        (void)fwrite(event->data, 1, event->data_len, self.videoOutputFile);
        fflush(self.videoOutputFile);
    }
}

- (void)sendResizeForView
{
    NSSize size = self.view.bounds.size;
    uint32_t width = size.width > 1.0 ? (uint32_t)size.width : 1u;
    uint32_t height = size.height > 1.0 ? (uint32_t)size.height : 1u;

    if (!self.session)
        return;
    if (width > 8192u)
        width = 8192u;
    if (height > 8192u)
        height = 8192u;
    (void)librdp_session_resize(self.session, width, height);
}

- (void)sendMouseEvent:(NSEvent*)event button:(librdp_mouse_button)button state:(librdp_mouse_state)state
{
    NSPoint point;
    librdp_mouse_event mouse;

    if (!self.session || !event)
        return;
    point = [self.view convertPoint:[event locationInWindow] fromView:nil];
    memset(&mouse, 0, sizeof(mouse));
    mouse.x = point.x < 0.0 ? 0u : (point.x > 65535.0 ? 65535u : (uint16_t)point.x);
    mouse.y = point.y < 0.0 ? 0u : (point.y > 65535.0 ? 65535u : (uint16_t)point.y);
    mouse.button = button;
    mouse.state = state;
    (void)librdp_session_send_mouse(self.session, &mouse);
}

- (void)sendWheelEvent:(NSEvent*)event
{
    CGFloat delta_x = 0.0;
    CGFloat delta_y = 0.0;

    if (!event)
        return;
    delta_x = [event scrollingDeltaX];
    delta_y = [event scrollingDeltaY];
    if (delta_y > 0.0)
        [self sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_WHEEL_UP state:LIBRDP_MOUSE_PRESSED];
    else if (delta_y < 0.0)
        [self sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_WHEEL_DOWN state:LIBRDP_MOUSE_PRESSED];
    if (delta_x > 0.0)
        [self sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_WHEEL_LEFT state:LIBRDP_MOUSE_PRESSED];
    else if (delta_x < 0.0)
        [self sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_WHEEL_RIGHT state:LIBRDP_MOUSE_PRESSED];
}

- (void)sendKeyEvent:(NSEvent*)event pressed:(BOOL)pressed
{
    NSString* characters = nil;
    NSUInteger length = 0;
    NSUInteger i = 0;

    if (!self.session || !event)
        return;
    characters = [event characters];
    length = [characters length];
    for (i = 0; i < length; i++)
    {
        librdp_key_event key;

        memset(&key, 0, sizeof(key));
        key.state = pressed ? LIBRDP_KEY_PRESSED : LIBRDP_KEY_RELEASED;
        key.flags = LIBRDP_KEY_FLAG_UNICODE;
        key.unicode = (uint32_t)[characters characterAtIndex:i];
        (void)librdp_session_send_key(self.session, &key);
    }
}

- (NSCursor*)hiddenCursor
{
    NSImage* image = [[NSImage alloc] initWithSize:NSMakeSize(1.0, 1.0)];

    return [[NSCursor alloc] initWithImage:image hotSpot:NSMakePoint(0.0, 0.0)];
}

- (NSCursor*)cursorFromPointer:(const librdp_pointer_event*)pointer
{
    CFDataRef data = NULL;
    CGColorSpaceRef color_space = NULL;
    CGDataProviderRef provider = NULL;
    CGImageRef cg_image = NULL;
    NSImage* image = nil;
    NSCursor* cursor = nil;
    size_t payload_len = 0;
    CGBitmapInfo bitmap_info = (CGBitmapInfo)((uint32_t)kCGBitmapByteOrder32Little |
                                             (uint32_t)kCGImageAlphaPremultipliedFirst);

    if (!pointer || !pointer->pixels || pointer->pixels_len == 0 || pointer->width == 0 || pointer->height == 0 ||
        pointer->stride < (uint32_t)pointer->width * 4u ||
        pointer->pixels_len < (size_t)pointer->stride * (size_t)pointer->height)
        return [NSCursor arrowCursor];

    payload_len = (size_t)pointer->stride * (size_t)pointer->height;
    if (payload_len > (size_t)LONG_MAX)
        return [NSCursor arrowCursor];
    data = CFDataCreate(kCFAllocatorDefault, pointer->pixels, (CFIndex)payload_len);
    color_space = CGColorSpaceCreateDeviceRGB();
    if (data)
        provider = CGDataProviderCreateWithCFData(data);
    if (color_space && provider)
        cg_image = CGImageCreate(pointer->width,
                                 pointer->height,
                                 8,
                                 32,
                                 pointer->stride,
                                 color_space,
                                 bitmap_info,
                                 provider,
                                 NULL,
                                 false,
                                 kCGRenderingIntentDefault);
    if (cg_image)
        image = [[NSImage alloc] initWithCGImage:cg_image
                                           size:NSMakeSize((CGFloat)pointer->width, (CGFloat)pointer->height)];
    if (image)
        cursor = [[NSCursor alloc] initWithImage:image
                                         hotSpot:NSMakePoint((CGFloat)pointer->hot_x, (CGFloat)pointer->hot_y)];
    if (cg_image)
        CGImageRelease(cg_image);
    if (provider)
        CGDataProviderRelease(provider);
    if (color_space)
        CGColorSpaceRelease(color_space);
    if (data)
        CFRelease(data);
    return cursor ? cursor : [NSCursor arrowCursor];
}

- (void)setCurrentCursor:(NSCursor*)cursor
{
    _currentCursor = cursor ? cursor : [NSCursor arrowCursor];
    [_currentCursor set];
    [self.window invalidateCursorRectsForView:self.view];
}

- (void)applyPointerEvent:(const librdp_pointer_event*)pointer
{
    if (!pointer)
        return;
    switch (pointer->update_type)
    {
        case LIBRDP_POINTER_UPDATE_DEFAULT:
            [self setCurrentCursor:[NSCursor arrowCursor]];
            break;
        case LIBRDP_POINTER_UPDATE_HIDDEN:
            [self setCurrentCursor:[self hiddenCursor]];
            break;
        case LIBRDP_POINTER_UPDATE_SHAPE:
            [self setCurrentCursor:[self cursorFromPointer:pointer]];
            break;
        case LIBRDP_POINTER_UPDATE_POSITION:
            break;
    }
}

- (void)publishLocalPasteboardIfChanged
{
    NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];
    NSString* string = nil;
    NSData* utf16 = nil;

    if (!self.session || !pasteboard || [pasteboard changeCount] == self.pasteboardChangeCount)
        return;
    self.pasteboardChangeCount = [pasteboard changeCount];
    string = [pasteboard stringForType:NSPasteboardTypeString];
    if (!string)
    {
        (void)librdp_session_clipboard_clear(self.session);
        return;
    }
    utf16 = [string dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
    if (!utf16)
        return;
    (void)librdp_session_clipboard_set_data(self.session,
                                            LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT,
                                            [utf16 bytes],
                                            [utf16 length]);
}

- (void)writeStringToPasteboard:(NSString*)string type:(NSPasteboardType)type
{
    NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];

    if (!pasteboard || !string)
        return;
    [pasteboard clearContents];
    [pasteboard setString:string forType:type];
    self.pasteboardChangeCount = [pasteboard changeCount];
}

- (void)writeDataToPasteboard:(NSData*)data type:(NSPasteboardType)type
{
    NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];

    if (!pasteboard || !data)
        return;
    [pasteboard clearContents];
    [pasteboard setData:data forType:type];
    self.pasteboardChangeCount = [pasteboard changeCount];
}

- (void)handleRemoteFormats:(const librdp_clipboard_formats_event*)formats
{
    uint32_t i = 0;

    if (!self.session || !formats || !formats->formats)
        return;
    for (i = 0; i < formats->count; i++)
    {
        uint32_t format_id = formats->formats[i].format_id;

        if (format_id == LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT || format_id == LIBRDP_CLIPBOARD_FORMAT_TEXT ||
            format_id == LIBRDP_CLIPBOARD_FORMAT_PNG || format_id == LIBRDP_CLIPBOARD_FORMAT_HTML)
        {
            (void)librdp_session_clipboard_request_data(self.session, format_id);
            return;
        }
    }
}

- (void)handleRemoteClipboardData:(const librdp_clipboard_data_event*)data
{
    NSData* ns_data = nil;
    NSString* string = nil;

    if (!data || !data->ok || !data->data || data->data_len == 0)
        return;
    ns_data = [NSData dataWithBytes:data->data length:data->data_len];
    if (!ns_data)
        return;
    if (data->format_id == LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT)
    {
        string = [[NSString alloc] initWithBytes:data->data
                                          length:data->data_len
                                        encoding:NSUTF16LittleEndianStringEncoding];
        [self writeStringToPasteboard:string type:NSPasteboardTypeString];
    }
    else if (data->format_id == LIBRDP_CLIPBOARD_FORMAT_TEXT)
    {
        string = [[NSString alloc] initWithData:ns_data encoding:NSUTF8StringEncoding];
        if (!string)
            string = [[NSString alloc] initWithData:ns_data encoding:NSISOLatin1StringEncoding];
        [self writeStringToPasteboard:string type:NSPasteboardTypeString];
    }
    else if (data->format_id == LIBRDP_CLIPBOARD_FORMAT_HTML)
    {
        string = [[NSString alloc] initWithData:ns_data encoding:NSUTF8StringEncoding];
        [self writeStringToPasteboard:string type:NSPasteboardTypeHTML];
    }
    else if (data->format_id == LIBRDP_CLIPBOARD_FORMAT_PNG)
        [self writeDataToPasteboard:ns_data type:NSPasteboardTypePNG];
}

- (void)handleClipboardEnvelope:(const librdp_event_envelope*)envelope
{
    if (!envelope || !envelope->payload)
        return;
    switch (envelope->type)
    {
        case LIBRDP_EVENT_CLIPBOARD_FORMATS:
            if (envelope->payload_size >= sizeof(librdp_clipboard_formats_event))
                [self handleRemoteFormats:(const librdp_clipboard_formats_event*)envelope->payload];
            break;
        case LIBRDP_EVENT_CLIPBOARD_DATA:
            if (envelope->payload_size >= sizeof(librdp_clipboard_data_event))
                [self handleRemoteClipboardData:(const librdp_clipboard_data_event*)envelope->payload];
            break;
        case LIBRDP_EVENT_CLIPBOARD_REQUEST:
            [self publishLocalPasteboardIfChanged];
            break;
        default:
            break;
    }
}

@end

int main(int argc, char** argv)
{
    cocoa_viewer_options options;
    client_callbacks callbacks;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    CocoaViewerController* controller = nil;
    librdp_status status = LIBRDP_STATUS_OK;
    int exit_code = 1;

    @autoreleasepool
    {
        settings = librdp_settings_new();
        if (!settings)
        {
            fprintf(stderr, "failed to create settings\n");
            return 1;
        }
        if (!cocoa_viewer_configure_settings(settings, &options, argc, argv))
        {
            cocoa_viewer_usage(stderr, argv[0]);
            client_options_clear(&options);
            librdp_settings_free(settings);
            return 2;
        }
        if (options.show_help)
        {
            cocoa_viewer_usage(stdout, argv[0]);
            client_options_clear(&options);
            librdp_settings_free(settings);
            return 0;
        }
        session = librdp_session_new(settings);
        librdp_settings_free(settings);
        if (!session)
        {
            fprintf(stderr, "failed to create session\n");
            client_options_clear(&options);
            return 1;
        }
        controller = [[CocoaViewerController alloc] initWithSession:session width:options.width height:options.height];
        if (!controller)
        {
            fprintf(stderr, "failed to create viewer window\n");
            librdp_session_free(session);
            client_options_clear(&options);
            return 1;
        }
        if (![controller configureMediaWithOptions:&options])
        {
            fprintf(stderr, "failed to configure media backends\n");
            [controller shutdownMedia];
            [controller shutdownSession];
            librdp_session_free(session);
            client_options_clear(&options);
            return 1;
        }
        client_callbacks_init(&callbacks);
        callbacks.graphics_update = cocoa_viewer_graphics_callback;
        callbacks.graphics_update_user_data = (__bridge void*)controller;
        callbacks.pointer = cocoa_viewer_pointer_callback;
        callbacks.pointer_user_data = (__bridge void*)controller;
        callbacks.channel = cocoa_viewer_channel_callback;
        callbacks.channel_user_data = (__bridge void*)controller;
        callbacks.clipboard = cocoa_viewer_clipboard_callback;
        callbacks.clipboard_user_data = (__bridge void*)controller;
        callbacks.audio = cocoa_viewer_audio_callback;
        callbacks.audio_user_data = (__bridge void*)controller;
        callbacks.video = cocoa_viewer_video_callback;
        callbacks.video_user_data = (__bridge void*)controller;
        status = client_callbacks_apply(session, &callbacks);
        if (status != LIBRDP_STATUS_OK)
        {
            fprintf(stderr, "callback registration failed: %s\n", librdp_status_string(status));
            [controller shutdownMedia];
            [controller shutdownSession];
            librdp_session_free(session);
            client_options_clear(&options);
            return 1;
        }
        status = cocoa_session_loop_connect(controller.sessionLoop);
        if (status != LIBRDP_STATUS_OK)
        {
            fprintf(stderr, "connect failed: %s\n", librdp_status_string(status));
            [controller shutdownMedia];
            [controller shutdownSession];
            librdp_session_free(session);
            client_options_clear(&options);
            return 1;
        }
        [NSApplication sharedApplication];
        if (![controller start])
        {
            [controller shutdownMedia];
            [controller shutdownSession];
            librdp_session_free(session);
            client_options_clear(&options);
            return 1;
        }
        [NSApp run];
        [controller shutdownMedia];
        [controller shutdownSession];
        librdp_session_free(session);
        client_options_clear(&options);
        exit_code = 0;
    }
    return exit_code;
}
