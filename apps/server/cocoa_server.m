/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa server context and ScreenCaptureKit source selection.
 * Invariants: only public display or window sources from the active graphical
 * session are selected, dimensions are bounded before stream construction,
 * and native cursor pixels remain composited into the capture stream.
 * Ownership: the context owns Objective-C objects, descriptors, mutex and
 * pending frame storage.
 * Threading: construction and provider methods run on the host thread; frame
 * ingestion is serialized by the capture queue.
 * Trust boundary: capture identifiers and framework-returned geometry are
 * validated before becoming server surface dimensions.
 */

#include "cocoa_server_internal.h"

#import <AvailabilityMacros.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreVideo/CoreVideo.h>

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void cocoa_server_release_dispatch_object(
    dispatch_object_t object)
{
#if !OS_OBJECT_USE_OBJC
    if (object)
        dispatch_release(object);
#else
    (void)object;
#endif
}

void cocoa_server_config_init(cocoa_server_config* config)
{
    if (!config)
        return;
    memset(config, 0, sizeof(*config));
    config->version = COCOA_SERVER_CONFIG_VERSION;
    config->size = sizeof(*config);
    config->source_kind = COCOA_SERVER_SOURCE_DISPLAY;
    config->max_fps = 30u;
    config->max_frame_bytes = 256u * 1024u * 1024u;
}

static int cocoa_server_config_valid(
    const cocoa_server_config* config)
{
    return config &&
           config->version == COCOA_SERVER_CONFIG_VERSION &&
           config->size >= sizeof(*config) &&
           config->source_kind >= COCOA_SERVER_SOURCE_DISPLAY &&
           config->source_kind <= COCOA_SERVER_SOURCE_WINDOW &&
           (config->source_kind != COCOA_SERVER_SOURCE_WINDOW ||
            config->source_id != 0u) &&
           config->max_fps > 0u && config->max_fps <= 60u &&
           config->max_frame_bytes >= 4u &&
           config->max_frame_bytes <= 512u * 1024u * 1024u &&
           config->allow_capture == 1 &&
           (config->allow_input == 0 ||
            config->allow_input == 1) &&
           (config->allow_clipboard == 0 ||
            config->allow_clipboard == 1) &&
           (config->allow_drive == 0 ||
            config->allow_drive == 1);
}

static int cocoa_server_set_nonblocking(int descriptor)
{
    int flags = fcntl(descriptor, F_GETFL, 0);
    int descriptor_flags = fcntl(descriptor, F_GETFD, 0);

    return flags >= 0 && descriptor_flags >= 0 &&
           fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 &&
           fcntl(descriptor,
                 F_SETFD,
                 descriptor_flags | FD_CLOEXEC) == 0;
}

static int cocoa_server_create_pipe(cocoa_server_context* context)
{
    int descriptors[2] = { -1, -1 };

    if (!context || pipe(descriptors) != 0)
        return 0;
    if (!cocoa_server_set_nonblocking(descriptors[0]) ||
        !cocoa_server_set_nonblocking(descriptors[1]))
    {
        close(descriptors[0]);
        close(descriptors[1]);
        return 0;
    }
    context->wakeup_read_fd = descriptors[0];
    context->wakeup_write_fd = descriptors[1];
    return 1;
}

static SCShareableContent* cocoa_server_shareable_content(
    librdp_status* output_status)
{
    __block SCShareableContent* content = nil;
    __block NSError* error = nil;
    dispatch_semaphore_t semaphore = NULL;
    long wait_result = 0;

    semaphore = dispatch_semaphore_create(0);
    if (!semaphore)
    {
        *output_status = LIBRDP_STATUS_NO_MEMORY;
        return nil;
    }
    [SCShareableContent
        getShareableContentExcludingDesktopWindows:NO
                                onScreenWindowsOnly:NO
                                 completionHandler:^(
                                     SCShareableContent* value,
                                     NSError* value_error) {
                                     if (value)
                                         content = [value retain];
                                     if (value_error)
                                         error = [value_error retain];
                                     dispatch_semaphore_signal(semaphore);
                                 }];
    wait_result = dispatch_semaphore_wait(
        semaphore,
        dispatch_time(DISPATCH_TIME_NOW, 15ll * NSEC_PER_SEC));
    cocoa_server_release_dispatch_object(
        (dispatch_object_t)semaphore);
    if (wait_result != 0 || error || !content)
    {
        [error release];
        [content release];
        *output_status = wait_result != 0
                             ? LIBRDP_STATUS_TIMEOUT
                             : LIBRDP_STATUS_STATE;
        return nil;
    }
    return content;
}

static SCContentFilter* cocoa_server_select_initial_filter(
    cocoa_server_context* context,
    SCShareableContent* content)
{
    if (context->config.source_kind == COCOA_SERVER_SOURCE_DISPLAY)
    {
        SCDisplay* display = nil;

        if ((NSUInteger)context->config.source_id >=
            [[content displays] count])
            return nil;
        display = [[content displays]
            objectAtIndex:(NSUInteger)context->config.source_id];
        context->stable_source_id = (uint32_t)[display displayID];
        return [[SCContentFilter alloc]
            initWithDisplay:display
          excludingWindows:@[]];
    }
    for (SCWindow* window in [content windows])
    {
        if ([window windowID] ==
            (CGWindowID)context->config.source_id)
        {
            context->stable_source_id =
                (uint32_t)[window windowID];
            return [[SCContentFilter alloc]
                initWithDesktopIndependentWindow:window];
        }
    }
    return nil;
}

static SCContentFilter* cocoa_server_select_stable_filter(
    cocoa_server_context* context,
    SCShareableContent* content)
{
    if (context->config.source_kind ==
        COCOA_SERVER_SOURCE_DISPLAY)
    {
        for (SCDisplay* display in [content displays])
        {
            if ([display displayID] ==
                (CGDirectDisplayID)context->stable_source_id)
            {
                return [[SCContentFilter alloc]
                    initWithDisplay:display
                  excludingWindows:@[]];
            }
        }
        return nil;
    }
    for (SCWindow* window in [content windows])
    {
        if ([window windowID] ==
            (CGWindowID)context->stable_source_id)
        {
            return [[SCContentFilter alloc]
                initWithDesktopIndependentWindow:window];
        }
    }
    return nil;
}

static int cocoa_server_geometry_from_rect(
    CGRect content_rect,
    double scale,
    uint32_t* width,
    uint32_t* height,
    CGRect* source_rect,
    double* source_scale)
{
    double pixel_width = 0.0;
    double pixel_height = 0.0;

    pixel_width = ceil(content_rect.size.width * scale);
    pixel_height = ceil(content_rect.size.height * scale);
    if (!width || !height || !source_rect || !source_scale ||
        !isfinite(content_rect.origin.x) ||
        !isfinite(content_rect.origin.y) ||
        !isfinite(content_rect.size.width) ||
        !isfinite(content_rect.size.height) ||
        !isfinite(scale) || scale <= 0.0 ||
        !isfinite(pixel_width) || !isfinite(pixel_height) ||
        pixel_width < 1.0 || pixel_height < 1.0 ||
        pixel_width > 16384.0 || pixel_height > 16384.0)
        return 0;
    *width = (uint32_t)pixel_width;
    *height = (uint32_t)pixel_height;
    *source_rect = content_rect;
    *source_scale = scale;
    return 1;
}

static int cocoa_server_display_scale(SCDisplay* display,
                                      double* scale)
{
    CGRect frame = CGRectZero;
    size_t pixel_width = 0u;
    size_t pixel_height = 0u;
    double horizontal = 0.0;
    double vertical = 0.0;

    if (!display || !scale)
        return 0;
    frame = [display frame];
    pixel_width = CGDisplayPixelsWide([display displayID]);
    pixel_height = CGDisplayPixelsHigh([display displayID]);
    if (!isfinite(frame.size.width) ||
        !isfinite(frame.size.height) ||
        frame.size.width <= 0.0 || frame.size.height <= 0.0 ||
        pixel_width == 0u || pixel_height == 0u)
        return 0;
    horizontal = (double)pixel_width / frame.size.width;
    vertical = (double)pixel_height / frame.size.height;
    if (!isfinite(horizontal) || !isfinite(vertical) ||
        horizontal <= 0.0 || vertical <= 0.0 ||
        fabs(horizontal - vertical) > 0.01)
        return 0;
    *scale = horizontal;
    return 1;
}

static int cocoa_server_legacy_filter_geometry(
    const cocoa_server_context* context,
    SCShareableContent* content,
    uint32_t* width,
    uint32_t* height,
    CGRect* source_rect,
    double* source_scale)
{
    if (!context || !content)
        return 0;
    if (context->config.source_kind ==
        COCOA_SERVER_SOURCE_DISPLAY)
    {
        for (SCDisplay* display in [content displays])
        {
            double scale = 0.0;

            if ([display displayID] !=
                    (CGDirectDisplayID)context->stable_source_id ||
                !cocoa_server_display_scale(display, &scale))
                continue;
            return cocoa_server_geometry_from_rect(
                [display frame],
                scale,
                width,
                height,
                source_rect,
                source_scale);
        }
        return 0;
    }
    for (SCWindow* window in [content windows])
    {
        CGRect window_frame = CGRectZero;
        double selected_scale = 0.0;
        double selected_area = 0.0;

        if ([window windowID] !=
            (CGWindowID)context->stable_source_id)
            continue;
        window_frame = [window frame];
        for (SCDisplay* display in [content displays])
        {
            CGRect overlap =
                CGRectIntersection(window_frame, [display frame]);
            double scale = 0.0;
            double area = 0.0;

            if (CGRectIsNull(overlap) ||
                CGRectIsEmpty(overlap) ||
                !cocoa_server_display_scale(display, &scale))
                continue;
            area = overlap.size.width * overlap.size.height;
            if (isfinite(area) && area > selected_area)
            {
                selected_area = area;
                selected_scale = scale;
            }
        }
        if (selected_scale <= 0.0)
            selected_scale = 1.0;
        return cocoa_server_geometry_from_rect(
            window_frame,
            selected_scale,
            width,
            height,
            source_rect,
            source_scale);
    }
    return 0;
}

static int cocoa_server_filter_geometry(
    const cocoa_server_context* context,
    SCShareableContent* content,
    SCContentFilter* filter,
    uint32_t* width,
    uint32_t* height,
    CGRect* source_rect,
    double* source_scale)
{
    if (!context || !content || !filter)
        return 0;
#if __MAC_OS_X_VERSION_MAX_ALLOWED >= 140000
    if (@available(macOS 14.0, *))
    {
        return cocoa_server_geometry_from_rect(
            [filter contentRect],
            (double)[filter pointPixelScale],
            width,
            height,
            source_rect,
            source_scale);
    }
#endif
    return cocoa_server_legacy_filter_geometry(
        context,
        content,
        width,
        height,
        source_rect,
        source_scale);
}

static int cocoa_server_prepare_stream(
    cocoa_server_context* context,
    librdp_status* output_status)
{
    SCShareableContent* content = nil;
    cocoa_server_frame_packet snapshot;
    NSError* error = nil;

    memset(&snapshot, 0, sizeof(snapshot));
    if (context->config.source_kind == COCOA_SERVER_SOURCE_WINDOW)
    {
        context->stable_source_id = context->config.source_id;
        context->capture_queue =
            dispatch_queue_create("librdp.cocoa.server.window",
                                  DISPATCH_QUEUE_SERIAL);
        if (!context->capture_queue)
        {
            *output_status = LIBRDP_STATUS_NO_MEMORY;
            return 0;
        }
        *output_status = cocoa_server_window_snapshot(context, &snapshot);
        if (*output_status != LIBRDP_STATUS_OK)
            return 0;
        context->width = snapshot.width;
        context->height = snapshot.height;
        context->source_rect = snapshot.source_rect;
        context->source_scale = snapshot.source_scale;
        free(snapshot.pixels);
        return 1;
    }
    content = cocoa_server_shareable_content(output_status);
    if (!content)
        return 0;
    context->filter =
        cocoa_server_select_initial_filter(context, content);
    if (!context->filter ||
        !cocoa_server_filter_geometry(context,
                                      content,
                                      context->filter,
                                      &context->width,
                                      &context->height,
                                      &context->source_rect,
                                      &context->source_scale))
    {
        [content release];
        *output_status = LIBRDP_STATUS_INVALID_ARGUMENT;
        return 0;
    }
    [content release];
    if ((size_t)context->width >
            context->config.max_frame_bytes / 4u ||
        (size_t)context->height >
            context->config.max_frame_bytes /
                ((size_t)context->width * 4u))
    {
        *output_status = LIBRDP_STATUS_LIMIT_EXCEEDED;
        return 0;
    }
    context->stream_config =
        [[SCStreamConfiguration alloc] init];
    context->capture_delegate =
        [[CocoaServerCaptureDelegate alloc]
            initWithContext:context];
    context->capture_queue =
        dispatch_queue_create("librdp.cocoa.server.capture",
                              DISPATCH_QUEUE_SERIAL);
    if (!context->stream_config || !context->capture_delegate ||
        !context->capture_queue)
    {
        *output_status = LIBRDP_STATUS_NO_MEMORY;
        return 0;
    }
    [context->stream_config setWidth:(size_t)context->width];
    [context->stream_config setHeight:(size_t)context->height];
    [context->stream_config
        setPixelFormat:kCVPixelFormatType_32BGRA];
    [context->stream_config setShowsCursor:YES];
    [context->stream_config setQueueDepth:3];
    [context->stream_config
        setMinimumFrameInterval:
            CMTimeMake(1, (int32_t)context->config.max_fps)];
    context->stream =
        [[SCStream alloc] initWithFilter:context->filter
                          configuration:context->stream_config
                               delegate:context->capture_delegate];
    if (!context->stream ||
        ![context->stream
            addStreamOutput:context->capture_delegate
                       type:SCStreamOutputTypeScreen
         sampleHandlerQueue:context->capture_queue
                      error:&error])
    {
        *output_status = LIBRDP_STATUS_IO_ERROR;
        return 0;
    }
    return 1;
}

static SCStreamConfiguration*
cocoa_server_stream_configuration(
    const cocoa_server_context* context,
    uint32_t width,
    uint32_t height)
{
    SCStreamConfiguration* configuration =
        [[SCStreamConfiguration alloc] init];

    if (!configuration)
        return nil;
    [configuration setWidth:(size_t)width];
    [configuration setHeight:(size_t)height];
    [configuration setPixelFormat:kCVPixelFormatType_32BGRA];
    [configuration setShowsCursor:YES];
    [configuration setQueueDepth:3];
    [configuration
        setMinimumFrameInterval:
            CMTimeMake(1, (int32_t)context->config.max_fps)];
    return configuration;
}

static librdp_status cocoa_server_wait_for_filter_update(
    SCStream* stream,
    SCContentFilter* filter)
{
    __block NSError* error = nil;
    dispatch_semaphore_t semaphore =
        dispatch_semaphore_create(0);
    long wait_result = 0;

    if (!semaphore)
        return LIBRDP_STATUS_NO_MEMORY;
    [stream updateContentFilter:filter
              completionHandler:^(NSError* value) {
                  if (value)
                      error = [value retain];
                  dispatch_semaphore_signal(semaphore);
              }];
    wait_result = dispatch_semaphore_wait(
        semaphore,
        dispatch_time(DISPATCH_TIME_NOW, 10ll * NSEC_PER_SEC));
    cocoa_server_release_dispatch_object(
        (dispatch_object_t)semaphore);
    if (wait_result != 0)
        return LIBRDP_STATUS_TIMEOUT;
    if (error)
    {
        [error release];
        return LIBRDP_STATUS_IO_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status cocoa_server_wait_for_config_update(
    SCStream* stream,
    SCStreamConfiguration* configuration)
{
    __block NSError* error = nil;
    dispatch_semaphore_t semaphore =
        dispatch_semaphore_create(0);
    long wait_result = 0;

    if (!semaphore)
        return LIBRDP_STATUS_NO_MEMORY;
    [stream updateConfiguration:configuration
              completionHandler:^(NSError* value) {
                  if (value)
                      error = [value retain];
                  dispatch_semaphore_signal(semaphore);
              }];
    wait_result = dispatch_semaphore_wait(
        semaphore,
        dispatch_time(DISPATCH_TIME_NOW, 10ll * NSEC_PER_SEC));
    cocoa_server_release_dispatch_object(
        (dispatch_object_t)semaphore);
    if (wait_result != 0)
        return LIBRDP_STATUS_TIMEOUT;
    if (error)
    {
        [error release];
        return LIBRDP_STATUS_IO_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status cocoa_server_wait_for_restart(
    SCStream* stream)
{
    __block NSError* error = nil;
    dispatch_semaphore_t semaphore =
        dispatch_semaphore_create(0);
    long wait_result = 0;

    if (!semaphore)
        return LIBRDP_STATUS_NO_MEMORY;
    [stream startCaptureWithCompletionHandler:^(NSError* value) {
        if (value)
            error = [value retain];
        dispatch_semaphore_signal(semaphore);
    }];
    wait_result = dispatch_semaphore_wait(
        semaphore,
        dispatch_time(DISPATCH_TIME_NOW, 15ll * NSEC_PER_SEC));
    cocoa_server_release_dispatch_object(
        (dispatch_object_t)semaphore);
    if (wait_result != 0)
        return LIBRDP_STATUS_TIMEOUT;
    if (error)
    {
        [error release];
        return LIBRDP_STATUS_IO_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Re-enumerate the stable source and update filter and pixel geometry as one
 * bounded operation. Existing provider objects remain active until both
 * framework updates succeed; a refresh failure never publishes partial
 * geometry or replaces the working capture objects.
 */
librdp_status cocoa_server_refresh_topology(
    cocoa_server_context* context,
    int restart_stream)
{
    cocoa_server_frame_packet snapshot;
    SCShareableContent* content = nil;
    SCContentFilter* filter = nil;
    SCStreamConfiguration* configuration = nil;
    uint32_t width = 0u;
    uint32_t height = 0u;
    CGRect source_rect = CGRectZero;
    double source_scale = 0.0;
    librdp_status status = LIBRDP_STATUS_OK;
    int changed = 0;

    if (!context || !context->capture_started)
        return LIBRDP_STATUS_STATE;
    if (context->config.source_kind == COCOA_SERVER_SOURCE_WINDOW)
    {
        memset(&snapshot, 0, sizeof(snapshot));
        status = cocoa_server_window_snapshot(context, &snapshot);
        if (status != LIBRDP_STATUS_OK)
            return status;
        pthread_mutex_lock(&context->lock);
        snapshot.sequence = ++context->next_sequence;
        free(context->pending_frame.pixels);
        context->pending_frame = snapshot;
        free(context->latest_frame.pixels);
        memset(&context->latest_frame,
               0,
               sizeof(context->latest_frame));
        context->width = snapshot.width;
        context->height = snapshot.height;
        context->source_rect = snapshot.source_rect;
        context->source_scale = snapshot.source_scale;
        context->window_capture_failures = 0u;
        context->force_full_frame = 0;
        pthread_mutex_unlock(&context->lock);
        cocoa_server_wakeup(context);
        return LIBRDP_STATUS_OK;
    }
    if (!context->stream)
        return LIBRDP_STATUS_STATE;
    content = cocoa_server_shareable_content(&status);
    if (!content)
        return status;
    filter = cocoa_server_select_stable_filter(context, content);
    if (!filter ||
        !cocoa_server_filter_geometry(context,
                                      content,
                                      filter,
                                      &width,
                                      &height,
                                      &source_rect,
                                      &source_scale))
    {
        [content release];
        [filter release];
        return LIBRDP_STATUS_CLOSED;
    }
    [content release];
    if ((size_t)width > context->config.max_frame_bytes / 4u ||
        (size_t)height >
            context->config.max_frame_bytes /
                ((size_t)width * 4u))
    {
        [filter release];
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    changed = width != context->width ||
              height != context->height ||
              !CGRectEqualToRect(source_rect,
                                 context->source_rect) ||
              source_scale != context->source_scale;
    if (!changed && !restart_stream)
    {
        [filter release];
        return LIBRDP_STATUS_OK;
    }
    configuration =
        cocoa_server_stream_configuration(context, width, height);
    if (!configuration)
    {
        [filter release];
        return LIBRDP_STATUS_NO_MEMORY;
    }
    status =
        cocoa_server_wait_for_filter_update(context->stream, filter);
    if (status == LIBRDP_STATUS_OK)
        status = cocoa_server_wait_for_config_update(
            context->stream,
            configuration);
    if (status == LIBRDP_STATUS_OK && restart_stream)
        status = cocoa_server_wait_for_restart(context->stream);
    if (status == LIBRDP_STATUS_OK)
    {
        pthread_mutex_lock(&context->lock);
        free(context->pending_frame.pixels);
        memset(&context->pending_frame,
               0,
               sizeof(context->pending_frame));
        free(context->latest_frame.pixels);
        memset(&context->latest_frame,
               0,
               sizeof(context->latest_frame));
        context->width = width;
        context->height = height;
        context->source_rect = source_rect;
        context->source_scale = source_scale;
        context->force_full_frame = 1;
        pthread_mutex_unlock(&context->lock);
        [context->filter release];
        context->filter = filter;
        filter = nil;
        [context->stream_config release];
        context->stream_config = configuration;
        configuration = nil;
    }
    [configuration release];
    [filter release];
    return status;
}

cocoa_server_context* cocoa_server_context_new(
    const cocoa_server_config* config,
    librdp_status* output_status)
{
    cocoa_server_context* context = NULL;

    if (output_status)
        *output_status = LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!output_status || !cocoa_server_config_valid(config))
        return NULL;
    if (@available(macOS 12.3, *))
    {
    }
    else
    {
        *output_status = LIBRDP_STATUS_UNSUPPORTED;
        return NULL;
    }
    if (!CGPreflightScreenCaptureAccess())
    {
        *output_status = LIBRDP_STATUS_STATE;
        return NULL;
    }
    context =
        (cocoa_server_context*)calloc(1u, sizeof(*context));
    if (!context)
    {
        *output_status = LIBRDP_STATUS_NO_MEMORY;
        return NULL;
    }
    context->config = *config;
    context->wakeup_read_fd = -1;
    context->wakeup_write_fd = -1;
    if (pthread_mutex_init(&context->lock, NULL) != 0)
    {
        *output_status = LIBRDP_STATUS_IO_ERROR;
        free(context);
        return NULL;
    }
    context->lock_ready = 1;
    if (!cocoa_server_create_pipe(context) ||
        !cocoa_server_prepare_stream(context, output_status))
    {
        cocoa_server_context_free(context);
        return NULL;
    }
    if (context->config.allow_clipboard)
        context->clipboard = cocoa_server_clipboard_new();
    *output_status = LIBRDP_STATUS_OK;
    return context;
}

void cocoa_server_context_free(cocoa_server_context* context)
{
    if (!context)
        return;
    if (context->config.allow_input)
        cocoa_server_input_vtable.release_all(context);
    cocoa_server_clipboard_free(context->clipboard);
    context->clipboard = NULL;
    cocoa_server_capture_vtable.stop(context);
    if (context->stream && context->capture_delegate)
    {
        NSError* error = nil;

        (void)[context->stream
            removeStreamOutput:context->capture_delegate
                          type:SCStreamOutputTypeScreen
                         error:&error];
    }
    [context->stream release];
    [context->capture_delegate release];
    [context->stream_config release];
    [context->filter release];
    if (context->capture_queue)
        cocoa_server_release_dispatch_object(
            (dispatch_object_t)context->capture_queue);
    if (context->wakeup_read_fd >= 0)
        close(context->wakeup_read_fd);
    if (context->wakeup_write_fd >= 0)
        close(context->wakeup_write_fd);
    if (context->lock_ready)
    {
        pthread_mutex_lock(&context->lock);
        free(context->pending_frame.pixels);
        context->pending_frame.pixels = NULL;
        free(context->latest_frame.pixels);
        context->latest_frame.pixels = NULL;
        pthread_mutex_unlock(&context->lock);
        pthread_mutex_destroy(&context->lock);
    }
    memset(context, 0, sizeof(*context));
    free(context);
}

static librdp_status cocoa_server_permission_start(
    void* opaque,
    const server_platform_permission_sink* sink)
{
    cocoa_server_context* context =
        (cocoa_server_context*)opaque;

    if (!context || !sink || !sink->changed ||
        context->permission_started)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    context->permission_sink = *sink;
    context->permission_started = 1;
    return LIBRDP_STATUS_OK;
}

static void cocoa_server_permission_stop(void* opaque)
{
    cocoa_server_context* context =
        (cocoa_server_context*)opaque;

    if (!context)
        return;
    context->permission_started = 0;
    memset(&context->permission_sink,
           0,
           sizeof(context->permission_sink));
}

static librdp_status cocoa_server_permission_query(
    void* opaque,
    server_platform_permission_kind kind,
    server_platform_permission_state* state)
{
    cocoa_server_context* context =
        (cocoa_server_context*)opaque;

    if (!context || !state ||
        kind < SERVER_PLATFORM_PERMISSION_CAPTURE ||
        kind > SERVER_PLATFORM_PERMISSION_DRIVE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (context->permission_revoked[kind])
    {
        *state = SERVER_PLATFORM_PERMISSION_DENIED;
        return LIBRDP_STATUS_OK;
    }
    if (kind == SERVER_PLATFORM_PERMISSION_CAPTURE)
    {
        *state =
            context->config.allow_capture &&
                    CGPreflightScreenCaptureAccess()
                ? SERVER_PLATFORM_PERMISSION_GRANTED
                : SERVER_PLATFORM_PERMISSION_DENIED;
    }
    else if (kind == SERVER_PLATFORM_PERMISSION_INPUT)
    {
        *state =
            context->config.allow_input &&
                    cocoa_server_accessibility_permission(0)
                ? SERVER_PLATFORM_PERMISSION_GRANTED
                : SERVER_PLATFORM_PERMISSION_DENIED;
    }
    else if (kind == SERVER_PLATFORM_PERMISSION_CLIPBOARD)
    {
        *state =
            context->config.allow_clipboard &&
                    context->clipboard
                ? SERVER_PLATFORM_PERMISSION_GRANTED
                : SERVER_PLATFORM_PERMISSION_DENIED;
    }
    else if (kind == SERVER_PLATFORM_PERMISSION_DRIVE)
    {
        *state = context->config.allow_drive
                     ? SERVER_PLATFORM_PERMISSION_GRANTED
                     : SERVER_PLATFORM_PERMISSION_DENIED;
    }
    else
        *state = SERVER_PLATFORM_PERMISSION_DENIED;
    return LIBRDP_STATUS_OK;
}

static librdp_status cocoa_server_permission_request(
    void* opaque,
    server_platform_permission_kind kind)
{
    cocoa_server_context* context =
        (cocoa_server_context*)opaque;
    server_platform_permission_state state =
        SERVER_PLATFORM_PERMISSION_DENIED;

    if (!context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (kind == SERVER_PLATFORM_PERMISSION_CAPTURE)
    {
        state = CGRequestScreenCaptureAccess()
                    ? SERVER_PLATFORM_PERMISSION_GRANTED
                    : SERVER_PLATFORM_PERMISSION_DENIED;
    }
    else if (kind == SERVER_PLATFORM_PERMISSION_INPUT &&
             context->config.allow_input)
    {
        state = cocoa_server_accessibility_permission(1)
                    ? SERVER_PLATFORM_PERMISSION_GRANTED
                    : SERVER_PLATFORM_PERMISSION_DENIED;
    }
    else if (kind == SERVER_PLATFORM_PERMISSION_CLIPBOARD &&
             context->config.allow_clipboard &&
             context->clipboard)
        state = SERVER_PLATFORM_PERMISSION_GRANTED;
    else if (kind == SERVER_PLATFORM_PERMISSION_DRIVE &&
             context->config.allow_drive)
        state = SERVER_PLATFORM_PERMISSION_GRANTED;
    else
        return LIBRDP_STATUS_UNSUPPORTED;
    context->permission_revoked[kind] =
        state == SERVER_PLATFORM_PERMISSION_GRANTED ? 0u : 1u;
    if (context->permission_sink.changed)
        context->permission_sink.changed(
            kind,
            state,
            context->permission_sink.user_data);
    return state == SERVER_PLATFORM_PERMISSION_GRANTED
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_STATE;
}

static librdp_status cocoa_server_permission_revoke(
    void* opaque,
    server_platform_permission_kind kind)
{
    cocoa_server_context* context =
        (cocoa_server_context*)opaque;

    if (!context ||
        kind < SERVER_PLATFORM_PERMISSION_CAPTURE ||
        kind > SERVER_PLATFORM_PERMISSION_DRIVE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    context->permission_revoked[kind] = 1u;
    if (kind == SERVER_PLATFORM_PERMISSION_INPUT)
        cocoa_server_input_vtable.release_all(context);
    else if (kind == SERVER_PLATFORM_PERMISSION_CLIPBOARD)
        cocoa_server_clipboard_revoke(context->clipboard);
    if (context->permission_sink.changed)
        context->permission_sink.changed(
            kind,
            SERVER_PLATFORM_PERMISSION_DENIED,
            context->permission_sink.user_data);
    return LIBRDP_STATUS_OK;
}

const server_platform_permission_vtable
    cocoa_server_permission_vtable = {
        SERVER_PLATFORM_PERMISSION_VERSION,
        sizeof(server_platform_permission_vtable),
        cocoa_server_permission_start,
        cocoa_server_permission_stop,
        cocoa_server_permission_query,
        cocoa_server_permission_request,
        cocoa_server_permission_revoke,
        NULL,
    };

librdp_status cocoa_server_context_platform(
    cocoa_server_context* context,
    server_platform* platform)
{
    if (!context || !platform)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    server_platform_init(platform);
    platform->capture.vtable = &cocoa_server_capture_vtable;
    platform->capture.context = context;
    if (context->config.allow_input)
    {
        platform->input.vtable = &cocoa_server_input_vtable;
        platform->input.context = context;
    }
    if (context->config.allow_clipboard &&
        context->clipboard)
    {
        platform->clipboard.vtable =
            &cocoa_server_clipboard_vtable;
        platform->clipboard.context = context->clipboard;
    }
    platform->permission.vtable =
        &cocoa_server_permission_vtable;
    platform->permission.context = context;
    return server_platform_validate(platform);
}

uint32_t cocoa_server_context_width(
    const cocoa_server_context* context)
{
    return context ? context->width : 0u;
}

uint32_t cocoa_server_context_height(
    const cocoa_server_context* context)
{
    return context ? context->height : 0u;
}
