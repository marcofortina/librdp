/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer window validity and error handling.
 * Invariants: once the X server reports BadWindow or BadDrawable, later
 * operations observe the invalid flag and stop issuing protocol-affecting X11
 * requests.
 * Ownership: no X11 resource is created or destroyed here; x11_app retains
 * ownership of display, window, and graphics context.
 * Threading: Xlib invokes the error handler synchronously on the calling
 * thread; callers serialize through the viewer event loop.
 * Trust boundary: server-side X errors are converted into local shutdown state
 * without trusting resource IDs or request codes beyond diagnostics.
 */

#include "x11_window.h"

#include "x11_trace.h"

static volatile int g_x11_window_invalid;
static volatile int g_x11_trap_error;

int x11_window_handle_error(Display* display, XErrorEvent* error)
{
    if (display && error)
    {
        if (error->error_code == BadDrawable || error->error_code == BadWindow)
            g_x11_window_invalid = 1;
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.error",
                        "code=%u request=%u resource=%lu",
                        (unsigned)error->error_code,
                        (unsigned)error->request_code,
                        error->resourceid);
    }
    return 0;
}

static int x11_window_trap_error(Display* display, XErrorEvent* error)
{
    (void)display;

    if (error)
    {
        g_x11_trap_error = 1;
        if (error->error_code == BadDrawable || error->error_code == BadWindow)
            g_x11_window_invalid = 1;
    }
    return 0;
}

int x11_window_is_invalid(void)
{
    return g_x11_window_invalid ? 1 : 0;
}

void x11_window_mark_invalid(x11_app* app)
{
    g_x11_window_invalid = 1;
    if (app)
        app->running = 0;
}

int x11_window_is_live(x11_app* app)
{
    XWindowAttributes attributes;
    XErrorHandler previous = NULL;
    int result = 0;

    if (!app || !app->display || !app->window || g_x11_window_invalid)
        return 0;

    XSync(app->display, False);
    g_x11_trap_error = 0;
    previous = XSetErrorHandler(x11_window_trap_error);
    result = XGetWindowAttributes(app->display, app->window, &attributes);
    XSync(app->display, False);
    XSetErrorHandler(previous);

    if (!result || g_x11_trap_error)
    {
        x11_window_mark_invalid(app);
        return 0;
    }
    return 1;
}
