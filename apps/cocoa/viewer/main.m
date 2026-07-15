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
 * protocol state, and AppKit owns windows, views, timers, and events.
 * Threading: single-threaded AppKit event loop; callbacks are invoked by the
 * timer-driven session dispatch path.
 * Trust boundary: command-line values and remote desktop pixels are untrusted
 * inputs; credentials are copied into settings and never printed.
 */

#import <Cocoa/Cocoa.h>
#include <librdp/librdp.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct macos_viewer_options
{
    const char* target;
    const char* username;
    const char* password;
    const char* domain;
    uint16_t port;
    uint32_t width;
    uint32_t height;
    librdp_security_mode security;
    int accept_tls_certificate;
    int show_help;
} macos_viewer_options;

@class CocoaViewerController;

@interface CocoaViewerView : NSView
@property(nonatomic, assign) CocoaViewerController* controller;
@end

@interface CocoaViewerController : NSObject
@property(nonatomic, assign) librdp_session* session;
@property(nonatomic, strong) NSWindow* window;
@property(nonatomic, strong) CocoaViewerView* view;
@property(nonatomic, strong) NSTimer* timer;
@property(nonatomic, assign) BOOL dirty;
@property(nonatomic, assign) BOOL closed;
- (id)initWithSession:(librdp_session*)session width:(uint32_t)width height:(uint32_t)height;
- (void)start;
- (void)markDirty;
- (void)driveSession:(NSTimer*)timer;
- (void)sendResizeForView;
- (void)sendMouseEvent:(NSEvent*)event button:(librdp_mouse_button)button state:(librdp_mouse_state)state;
- (void)sendWheelEvent:(NSEvent*)event;
- (void)sendKeyEvent:(NSEvent*)event pressed:(BOOL)pressed;
@end

static void macos_viewer_usage(FILE* stream, const char* program)
{
    fprintf(stream,
            "usage: %s --target host [--port port] [--user name] [--password value] "
            "[--domain name] [--width px] [--height px] [--security auto|rdp|tls|nla] "
            "[--accept-tls-certificate]\n",
            program);
}

static int macos_viewer_need_value(int argc, int* index, const char* option)
{
    if (*index + 1 < argc)
    {
        *index += 1;
        return 1;
    }
    fprintf(stderr, "%s requires a value\n", option);
    return 0;
}

static int macos_viewer_parse_u16(const char* text, uint16_t* value)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!text || !value)
        return 0;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed == 0 || parsed > UINT16_MAX)
        return 0;
    *value = (uint16_t)parsed;
    return 1;
}

static int macos_viewer_parse_size(const char* text, uint32_t* value)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!text || !value)
        return 0;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed == 0 || parsed > 8192ul)
        return 0;
    *value = (uint32_t)parsed;
    return 1;
}

static int macos_viewer_parse_security(const char* text, librdp_security_mode* mode)
{
    if (!text || !mode)
        return 0;
    if (strcmp(text, "auto") == 0)
        *mode = LIBRDP_SECURITY_AUTO;
    else if (strcmp(text, "rdp") == 0)
        *mode = LIBRDP_SECURITY_STANDARD;
    else if (strcmp(text, "tls") == 0)
        *mode = LIBRDP_SECURITY_TLS;
    else if (strcmp(text, "nla") == 0)
        *mode = LIBRDP_SECURITY_NLA;
    else
        return 0;
    return 1;
}

static int macos_viewer_parse_args(int argc, char** argv, macos_viewer_options* options)
{
    int i = 0;

    if (!options)
        return 0;
    memset(options, 0, sizeof(*options));
    options->port = 3389u;
    options->width = 1024u;
    options->height = 768u;
    options->security = LIBRDP_SECURITY_AUTO;
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
            options->show_help = 1;
        else if (strcmp(argv[i], "--target") == 0)
        {
            if (!macos_viewer_need_value(argc, &i, argv[i]))
                return 0;
            options->target = argv[i];
        }
        else if (strcmp(argv[i], "--port") == 0)
        {
            if (!macos_viewer_need_value(argc, &i, argv[i]) ||
                !macos_viewer_parse_u16(argv[i], &options->port))
                return 0;
        }
        else if (strcmp(argv[i], "--user") == 0)
        {
            if (!macos_viewer_need_value(argc, &i, argv[i]))
                return 0;
            options->username = argv[i];
        }
        else if (strcmp(argv[i], "--password") == 0)
        {
            if (!macos_viewer_need_value(argc, &i, argv[i]))
                return 0;
            options->password = argv[i];
        }
        else if (strcmp(argv[i], "--domain") == 0)
        {
            if (!macos_viewer_need_value(argc, &i, argv[i]))
                return 0;
            options->domain = argv[i];
        }
        else if (strcmp(argv[i], "--width") == 0)
        {
            if (!macos_viewer_need_value(argc, &i, argv[i]) ||
                !macos_viewer_parse_size(argv[i], &options->width))
                return 0;
        }
        else if (strcmp(argv[i], "--height") == 0)
        {
            if (!macos_viewer_need_value(argc, &i, argv[i]) ||
                !macos_viewer_parse_size(argv[i], &options->height))
                return 0;
        }
        else if (strcmp(argv[i], "--security") == 0)
        {
            if (!macos_viewer_need_value(argc, &i, argv[i]) ||
                !macos_viewer_parse_security(argv[i], &options->security))
                return 0;
        }
        else if (strcmp(argv[i], "--accept-tls-certificate") == 0)
            options->accept_tls_certificate = 1;
        else
        {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            return 0;
        }
    }
    if (!options->show_help && (!options->target || options->target[0] == '\0'))
    {
        fprintf(stderr, "--target is required\n");
        return 0;
    }
    return 1;
}

static librdp_tls_certificate_decision macos_viewer_tls_callback(
    const librdp_tls_certificate_info* certificate,
    void* user_data)
{
    const macos_viewer_options* options = (const macos_viewer_options*)user_data;

    if (!certificate || !options || !options->accept_tls_certificate)
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
    fprintf(stderr, "tls_certificate host=\"%s\"\n", certificate->host ? certificate->host : "");
    fprintf(stderr, "tls_certificate subject=\"%s\"\n", certificate->subject ? certificate->subject : "");
    fprintf(stderr, "tls_certificate issuer=\"%s\"\n", certificate->issuer ? certificate->issuer : "");
    fprintf(stderr, "tls_certificate sha256=%s\n", certificate->sha256_fingerprint);
    fprintf(stderr, "tls_certificate decision=accepted mode=auto\n");
    return LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT;
}

static librdp_settings* macos_viewer_create_settings(macos_viewer_options* options)
{
    librdp_settings* settings = NULL;
    librdp_tls_policy tls_policy;

    if (!options)
        return NULL;
    settings = librdp_settings_new();
    if (!settings)
        return NULL;
    if (librdp_settings_set_target(settings, options->target) != LIBRDP_STATUS_OK ||
        librdp_settings_set_port(settings, options->port) != LIBRDP_STATUS_OK ||
        librdp_settings_set_desktop_size(settings, options->width, options->height) != LIBRDP_STATUS_OK ||
        librdp_settings_set_security_mode(settings, options->security) != LIBRDP_STATUS_OK ||
        librdp_settings_enable_feature(settings, LIBRDP_FEATURE_DISPLAY_CONTROL, 1) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return NULL;
    }
    if (options->username && librdp_settings_set_username(settings, options->username) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return NULL;
    }
    if (options->password && librdp_settings_set_password(settings, options->password) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return NULL;
    }
    if (options->domain && librdp_settings_set_domain(settings, options->domain) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return NULL;
    }
    if (options->accept_tls_certificate)
    {
        if (librdp_tls_policy_init(&tls_policy) != LIBRDP_STATUS_OK)
        {
            librdp_settings_free(settings);
            return NULL;
        }
        tls_policy.mode = LIBRDP_TLS_POLICY_TOFU;
        tls_policy.use_system_store = 1;
        tls_policy.certificate_callback = macos_viewer_tls_callback;
        tls_policy.certificate_callback_user_data = options;
        if (librdp_settings_set_tls_policy(settings, &tls_policy) != LIBRDP_STATUS_OK)
        {
            librdp_settings_free(settings);
            return NULL;
        }
    }
    return settings;
}

static void macos_viewer_graphics_callback(librdp_session* session,
                                           const librdp_graphics_update* update,
                                           void* user_data)
{
    CocoaViewerController* controller = (__bridge CocoaViewerController*)user_data;

    (void)session;
    if (!update || !controller)
        return;
    [controller markDirty];
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

- (void)drawRect:(NSRect)dirtyRect
{
    const librdp_surface* surface = NULL;
    librdp_surface_mapping mapping;
    CGColorSpaceRef color_space = NULL;
    CGDataProviderRef provider = NULL;
    CGImageRef image = NULL;
    CGRect destination;
    librdp_status status = LIBRDP_STATUS_OK;

    (void)dirtyRect;
    if (!self.controller || !self.controller.session)
        return;
    surface = librdp_session_get_surface(self.controller.session);
    if (!surface)
        return;
    if (librdp_surface_mapping_init(&mapping) != LIBRDP_STATUS_OK)
        return;
    status = librdp_surface_map((librdp_surface*)surface, LIBRDP_SURFACE_ACCESS_READ, &mapping);
    if (status != LIBRDP_STATUS_OK || !mapping.pixels)
        return;

    color_space = CGColorSpaceCreateDeviceRGB();
    provider = CGDataProviderCreateWithData(NULL,
                                            mapping.pixels,
                                            mapping.stride * mapping.height,
                                            NULL);
    if (color_space && provider)
        image = CGImageCreate(mapping.width,
                              mapping.height,
                              8,
                              32,
                              mapping.stride,
                              color_space,
                              kCGBitmapByteOrder32Little | kCGImageAlphaNoneSkipFirst,
                              provider,
                              NULL,
                              false,
                              kCGRenderingIntentDefault);
    if (image)
    {
        destination = CGRectMake(0.0, 0.0, NSWidth(self.bounds), NSHeight(self.bounds));
        CGContextDrawImage((CGContextRef)[[NSGraphicsContext currentContext] CGContext], destination, image);
    }
    if (image)
        CGImageRelease(image);
    if (provider)
        CGDataProviderRelease(provider);
    if (color_space)
        CGColorSpaceRelease(color_space);
    (void)librdp_surface_unmap((librdp_surface*)surface, &mapping);
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
    librdp_mouse_button button = [event buttonNumber] == 2 ? LIBRDP_MOUSE_BUTTON_MIDDLE : LIBRDP_MOUSE_BUTTON_X1;

    [self.controller sendMouseEvent:event button:button state:LIBRDP_MOUSE_PRESSED];
}

- (void)otherMouseUp:(NSEvent*)event
{
    librdp_mouse_button button = [event buttonNumber] == 2 ? LIBRDP_MOUSE_BUTTON_MIDDLE : LIBRDP_MOUSE_BUTTON_X1;

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

@end

@implementation CocoaViewerController

- (id)initWithSession:(librdp_session*)session width:(uint32_t)width height:(uint32_t)height
{
    NSRect frame = NSMakeRect(0.0, 0.0, (CGFloat)width, (CGFloat)height);

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
    [self.window setTitle:@"librdp-cocoa-viewer"];
    [self.window setContentView:self.view];
    [self.window setAcceptsMouseMovedEvents:YES];
    [self.window center];
    return self;
}

- (void)start
{
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    [self.window makeKeyAndOrderFront:nil];
    [self.window makeFirstResponder:self.view];
    [NSApp activateIgnoringOtherApps:YES];
    self.timer = [NSTimer scheduledTimerWithTimeInterval:0.01
                                                  target:self
                                                selector:@selector(driveSession:)
                                                userInfo:nil
                                                 repeats:YES];
}

- (void)markDirty
{
    self.dirty = YES;
    [self.view setNeedsDisplay:YES];
}

- (void)driveSession:(NSTimer*)timer
{
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_session_state state = LIBRDP_SESSION_IDLE;

    (void)timer;
    if (!self.session || self.closed)
        return;
    status = librdp_session_run_once(self.session, 0);
    if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_CLOSED)
        fprintf(stderr, "session dispatch failed: %s\n", librdp_status_string(status));
    state = librdp_session_get_state(self.session);
    if (status == LIBRDP_STATUS_CLOSED || state == LIBRDP_SESSION_CLOSED ||
        state == LIBRDP_SESSION_FAILED || state == LIBRDP_SESSION_CANCELLED)
    {
        self.closed = YES;
        [self.timer invalidate];
        self.timer = nil;
        [NSApp terminate:nil];
        return;
    }
    if (self.dirty)
    {
        self.dirty = NO;
        [self.view setNeedsDisplay:YES];
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

@end

int main(int argc, char** argv)
{
    macos_viewer_options options;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    CocoaViewerController* controller = nil;
    librdp_status status = LIBRDP_STATUS_OK;
    int exit_code = 1;

    @autoreleasepool
    {
        if (!macos_viewer_parse_args(argc, argv, &options))
        {
            macos_viewer_usage(stderr, argv[0]);
            return 2;
        }
        if (options.show_help)
        {
            macos_viewer_usage(stdout, argv[0]);
            return 0;
        }
        settings = macos_viewer_create_settings(&options);
        if (!settings)
        {
            fprintf(stderr, "failed to create settings\n");
            return 1;
        }
        session = librdp_session_new(settings);
        librdp_settings_free(settings);
        if (!session)
        {
            fprintf(stderr, "failed to create session\n");
            return 1;
        }
        controller = [[CocoaViewerController alloc] initWithSession:session width:options.width height:options.height];
        if (!controller)
        {
            fprintf(stderr, "failed to create viewer window\n");
            librdp_session_free(session);
            return 1;
        }
        librdp_session_set_graphics_update_callback(session, macos_viewer_graphics_callback, (__bridge void*)controller);
        status = librdp_session_connect(session);
        if (status != LIBRDP_STATUS_OK)
        {
            fprintf(stderr, "connect failed: %s\n", librdp_status_string(status));
            librdp_session_free(session);
            return 1;
        }
        [NSApplication sharedApplication];
        [controller start];
        [NSApp run];
        (void)librdp_session_disconnect(session);
        librdp_session_free(session);
        exit_code = 0;
    }
    return exit_code;
}
