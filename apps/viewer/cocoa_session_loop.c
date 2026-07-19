/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: event-driven Cocoa session dispatch.
 * Invariants: CF descriptor callbacks are one-shot, protocol dispatch is
 * bounded, and a terminal session state removes every run-loop source.
 * Ownership: CF objects and descriptor arrays are loop-owned; callback state
 * and the librdp session remain application-owned.
 * Threading: sources execute on the main CFRunLoop; cross-thread cancellation
 * delegates to the thread-safe public session operation.
 * Trust boundary: file-descriptor readiness and timeout events are validated
 * before reaching shared runtime dispatch.
 */

#include "cocoa_session_loop.h"
#include "client_runtime.h"

#include <CoreFoundation/CoreFoundation.h>

#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define COCOA_SESSION_MAX_DISPATCH 64u
#define COCOA_SESSION_MIN_TIMER_SECONDS 0.001

typedef struct cocoa_session_watch
{
    CFFileDescriptorRef descriptor;
    CFRunLoopSourceRef source;
} cocoa_session_watch;

struct cocoa_session_loop
{
    librdp_session* session;
    client_runtime* runtime;
    cocoa_session_loop_callbacks callbacks;
    cocoa_session_watch* watches;
    size_t watch_count;
    CFRunLoopTimerRef timer;
    int running;
    int dispatching;
};

static void cocoa_session_loop_dispatch(cocoa_session_loop* loop);

static void cocoa_session_loop_clear_sources(cocoa_session_loop* loop)
{
    size_t index = 0;

    if (!loop)
        return;
    if (loop->timer)
    {
        CFRunLoopTimerInvalidate(loop->timer);
        CFRelease(loop->timer);
        loop->timer = NULL;
    }
    for (index = 0; index < loop->watch_count; index++)
    {
        if (loop->watches[index].source)
        {
            CFRunLoopRemoveSource(CFRunLoopGetMain(),
                                  loop->watches[index].source,
                                  kCFRunLoopCommonModes);
            CFRelease(loop->watches[index].source);
        }
        if (loop->watches[index].descriptor)
        {
            CFFileDescriptorInvalidate(loop->watches[index].descriptor);
            CFRelease(loop->watches[index].descriptor);
        }
    }
    free(loop->watches);
    loop->watches = NULL;
    loop->watch_count = 0;
}

static void cocoa_session_descriptor_callback(CFFileDescriptorRef descriptor,
                                              CFOptionFlags flags,
                                              void* info)
{
    cocoa_session_loop* loop = (cocoa_session_loop*)info;

    (void)descriptor;
    (void)flags;
    cocoa_session_loop_dispatch(loop);
}

static void cocoa_session_timer_callback(CFRunLoopTimerRef timer, void* info)
{
    cocoa_session_loop* loop = (cocoa_session_loop*)info;

    (void)timer;
    cocoa_session_loop_dispatch(loop);
}

static int cocoa_session_loop_is_terminal(librdp_session_state state)
{
    return state == LIBRDP_SESSION_CLOSED ||
           state == LIBRDP_SESSION_FAILED ||
           state == LIBRDP_SESSION_CANCELLED;
}

/*
 * Arm one source per current session descriptor plus a one-shot deadline. A
 * failed allocation or CF object creation tears down the partial source set so
 * the caller can terminate the session deterministically.
 */
static librdp_status cocoa_session_loop_arm(cocoa_session_loop* loop)
{
    CFFileDescriptorContext descriptor_context;
    CFRunLoopTimerContext timer_context;
    struct pollfd* pollfds = NULL;
    size_t poll_count = 0;
    size_t index = 0;
    int local_timeout_ms = -1;
    int timeout_ms = -1;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!loop || !loop->running)
        return LIBRDP_STATUS_STATE;
    cocoa_session_loop_clear_sources(loop);
    if (loop->callbacks.timeout)
        local_timeout_ms = loop->callbacks.timeout(loop->callbacks.user_data);
    if (local_timeout_ms < -1)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = client_runtime_prepare_poll(loop->runtime,
                                         NULL,
                                         0,
                                         local_timeout_ms,
                                         &pollfds,
                                         &poll_count,
                                         &timeout_ms);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (poll_count > SIZE_MAX / sizeof(*loop->watches))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (poll_count > 0)
    {
        loop->watches = (cocoa_session_watch*)calloc(poll_count,
                                                     sizeof(*loop->watches));
        if (!loop->watches)
            return LIBRDP_STATUS_NO_MEMORY;
    }
    loop->watch_count = poll_count;
    memset(&descriptor_context, 0, sizeof(descriptor_context));
    descriptor_context.info = loop;
    for (index = 0; index < poll_count; index++)
    {
        CFOptionFlags flags = 0;

        if ((pollfds[index].events & (POLLIN | POLLPRI)) != 0)
            flags |= kCFFileDescriptorReadCallBack;
        if ((pollfds[index].events & POLLOUT) != 0)
            flags |= kCFFileDescriptorWriteCallBack;
        if (flags == 0)
            continue;
        loop->watches[index].descriptor = CFFileDescriptorCreate(
            kCFAllocatorDefault,
            pollfds[index].fd,
            false,
            cocoa_session_descriptor_callback,
            &descriptor_context);
        if (!loop->watches[index].descriptor)
        {
            cocoa_session_loop_clear_sources(loop);
            return LIBRDP_STATUS_NO_MEMORY;
        }
        loop->watches[index].source = CFFileDescriptorCreateRunLoopSource(
            kCFAllocatorDefault,
            loop->watches[index].descriptor,
            0);
        if (!loop->watches[index].source)
        {
            cocoa_session_loop_clear_sources(loop);
            return LIBRDP_STATUS_NO_MEMORY;
        }
        CFRunLoopAddSource(CFRunLoopGetMain(),
                           loop->watches[index].source,
                           kCFRunLoopCommonModes);
        CFFileDescriptorEnableCallBacks(loop->watches[index].descriptor, flags);
    }
    if (timeout_ms >= 0)
    {
        CFTimeInterval interval = (CFTimeInterval)timeout_ms / 1000.0;

        if (interval < COCOA_SESSION_MIN_TIMER_SECONDS)
            interval = COCOA_SESSION_MIN_TIMER_SECONDS;
        memset(&timer_context, 0, sizeof(timer_context));
        timer_context.info = loop;
        loop->timer = CFRunLoopTimerCreate(kCFAllocatorDefault,
                                           CFAbsoluteTimeGetCurrent() + interval,
                                           0.0,
                                           0,
                                           0,
                                           cocoa_session_timer_callback,
                                           &timer_context);
        if (!loop->timer)
        {
            cocoa_session_loop_clear_sources(loop);
            return LIBRDP_STATUS_NO_MEMORY;
        }
        CFRunLoopAddTimer(CFRunLoopGetMain(), loop->timer, kCFRunLoopCommonModes);
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Convert the firing source into a fresh poll snapshot before dispatch. This
 * catches combined read/write/error readiness and avoids relying on stale CF
 * callbacks after TLS or reconnect replaces a transport descriptor.
 */
static void cocoa_session_loop_dispatch(cocoa_session_loop* loop)
{
    struct pollfd* pollfds = NULL;
    size_t poll_count = 0;
    int timeout_ms = -1;
    int rc = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_session_state state = LIBRDP_SESSION_IDLE;

    if (!loop || !loop->running || loop->dispatching)
        return;
    loop->dispatching = 1;
    cocoa_session_loop_clear_sources(loop);
    if (loop->callbacks.prepare)
        loop->callbacks.prepare(loop->callbacks.user_data);
    status = client_runtime_prepare_poll(loop->runtime,
                                         NULL,
                                         0,
                                         0,
                                         &pollfds,
                                         &poll_count,
                                         &timeout_ms);
    if (status == LIBRDP_STATUS_OK && poll_count > 0)
    {
        do
        {
            rc = poll(pollfds, (nfds_t)poll_count, 0);
        } while (rc < 0 && errno == EINTR);
        if (rc < 0)
            status = LIBRDP_STATUS_IO_ERROR;
    }
    if (status == LIBRDP_STATUS_OK)
        status = client_runtime_dispatch_poll(loop->runtime,
                                              COCOA_SESSION_MAX_DISPATCH);
    state = librdp_session_get_state(loop->session);
    if (loop->callbacks.status)
        loop->callbacks.status(status, state, loop->callbacks.user_data);
    if (status != LIBRDP_STATUS_OK || cocoa_session_loop_is_terminal(state))
        loop->running = 0;
    loop->dispatching = 0;
    if (loop->running)
    {
        status = cocoa_session_loop_arm(loop);
        if (status != LIBRDP_STATUS_OK)
        {
            loop->running = 0;
            if (loop->callbacks.status)
            {
                loop->callbacks.status(status,
                                       librdp_session_get_state(loop->session),
                                       loop->callbacks.user_data);
            }
        }
    }
}

cocoa_session_loop* cocoa_session_loop_new(
    librdp_session* session,
    const cocoa_session_loop_callbacks* callbacks)
{
    cocoa_session_loop* loop = NULL;

    if (!session || !callbacks)
        return NULL;
    loop = (cocoa_session_loop*)calloc(1u, sizeof(*loop));
    if (!loop)
        return NULL;
    loop->session = session;
    loop->callbacks = *callbacks;
    loop->runtime = client_runtime_new(session);
    if (!loop->runtime)
    {
        free(loop);
        return NULL;
    }
    return loop;
}

void cocoa_session_loop_free(cocoa_session_loop* loop)
{
    if (!loop)
        return;
    cocoa_session_loop_stop(loop);
    client_runtime_free(loop->runtime);
    free(loop);
}

librdp_status cocoa_session_loop_connect(cocoa_session_loop* loop)
{
    if (!loop)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return client_runtime_connect(loop->runtime);
}

librdp_status cocoa_session_loop_start(cocoa_session_loop* loop)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!loop)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (loop->running)
        return LIBRDP_STATUS_STATE;
    loop->running = 1;
    status = cocoa_session_loop_arm(loop);
    if (status != LIBRDP_STATUS_OK)
        loop->running = 0;
    return status;
}

void cocoa_session_loop_stop(cocoa_session_loop* loop)
{
    if (!loop)
        return;
    loop->running = 0;
    cocoa_session_loop_clear_sources(loop);
}

librdp_status cocoa_session_loop_cancel(cocoa_session_loop* loop)
{
    if (!loop)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return client_runtime_cancel(loop->runtime);
}

librdp_status cocoa_session_loop_disconnect(cocoa_session_loop* loop)
{
    if (!loop)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    cocoa_session_loop_stop(loop);
    return client_runtime_disconnect(loop->runtime);
}
