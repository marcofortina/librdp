/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa run-loop bridge for the shared client runtime.
 * Invariants: all session dispatch occurs on the main CFRunLoop and descriptor
 * watches are rebuilt after protocol work can change transport state.
 * Ownership: the loop borrows the session and callback user data while owning
 * its CF descriptors, timer, and shared-runtime poll storage.
 * Threading: connect, start, dispatch, stop, and disconnect use the main
 * thread; cancel is the sole cross-thread operation.
 * Trust boundary: kernel readiness is normalized by client_runtime before
 * untrusted protocol data reaches session callbacks.
 */

#ifndef LIBRDP_COCOA_VIEWER_SESSION_LOOP_H
#define LIBRDP_COCOA_VIEWER_SESSION_LOOP_H

#include <librdp/librdp.h>

typedef struct cocoa_session_loop cocoa_session_loop;

typedef void (*cocoa_session_loop_prepare_callback)(void* user_data);
typedef int (*cocoa_session_loop_timeout_callback)(void* user_data);
typedef void (*cocoa_session_loop_status_callback)(librdp_status status,
                                                   librdp_session_state state,
                                                   void* user_data);

typedef struct cocoa_session_loop_callbacks
{
    cocoa_session_loop_prepare_callback prepare;
    cocoa_session_loop_timeout_callback timeout;
    cocoa_session_loop_status_callback status;
    void* user_data;
} cocoa_session_loop_callbacks;

cocoa_session_loop* cocoa_session_loop_new(
    librdp_session* session,
    const cocoa_session_loop_callbacks* callbacks);
void cocoa_session_loop_free(cocoa_session_loop* loop);
librdp_status cocoa_session_loop_connect(cocoa_session_loop* loop);
librdp_status cocoa_session_loop_start(cocoa_session_loop* loop);
void cocoa_session_loop_stop(cocoa_session_loop* loop);
librdp_status cocoa_session_loop_cancel(cocoa_session_loop* loop);
librdp_status cocoa_session_loop_disconnect(cocoa_session_loop* loop);

#endif
