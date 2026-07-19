/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: XRandR monitor layout bridge for the X11 viewer.
 * Invariants: XRandR geometry is converted into validated public monitor
 * layouts relative to the viewer window; protocol serialization remains in
 * the core session.
 * Ownership: XRR monitor arrays are freed immediately after conversion and no
 * borrowed X11 pointers escape the module.
 * Threading: all functions are called from the viewer event thread.
 * Trust boundary: host monitor metadata and remote display-control capability
 * state are both treated as untrusted and checked before sending layouts.
 */

#include "x11_display.h"

#include "x11_trace.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

#ifdef LIBRDP_HAVE_XRANDR
#define X11_DISPLAY_MIN_DIMENSION 200u
#define X11_DISPLAY_MAX_DIMENSION 8192u

typedef struct x11_display_candidate
{
    librdp_display_monitor monitor;
    uint64_t area;
    int primary_hint;
} x11_display_candidate;

static uint32_t x11_display_even_width(uint32_t value)
{
    if (value < X11_DISPLAY_MIN_DIMENSION)
        return 0;
    if (value > X11_DISPLAY_MAX_DIMENSION)
        value = X11_DISPLAY_MAX_DIMENSION;
    if ((value & 1u) != 0)
        value--;
    return value >= X11_DISPLAY_MIN_DIMENSION ? value : 0;
}

static uint32_t x11_display_height(uint32_t value)
{
    if (value < X11_DISPLAY_MIN_DIMENSION)
        return 0;
    if (value > X11_DISPLAY_MAX_DIMENSION)
        return X11_DISPLAY_MAX_DIMENSION;
    return value;
}

static uint32_t x11_display_scaled_mm(int monitor_pixels, int monitor_mm, uint32_t selected_pixels)
{
    uint64_t scaled = 0;

    if (monitor_pixels <= 0 || monitor_mm <= 0 || selected_pixels == 0)
        return 0;
    scaled = ((uint64_t)(uint32_t)monitor_mm * (uint64_t)selected_pixels) / (uint64_t)(uint32_t)monitor_pixels;
    if (scaled == 0)
        return 0;
    if (scaled < 10u)
        return 10u;
    if (scaled > 10000u)
        return 10000u;
    return (uint32_t)scaled;
}

static int x11_display_i64_to_i32(int64_t value, int32_t* out)
{
    if (!out || value < INT32_MIN || value > INT32_MAX)
        return 0;
    *out = (int32_t)value;
    return 1;
}

static int x11_display_add_candidate(x11_display_candidate* candidates,
                                     uint32_t* count,
                                     uint32_t capacity,
                                     const XRRMonitorInfo* monitor,
                                     int64_t left,
                                     int64_t top,
                                     int64_t right,
                                     int64_t bottom,
                                     int window_x,
                                     int window_y)
{
    x11_display_candidate* candidate = NULL;
    int64_t rel_left = 0;
    int64_t rel_top = 0;
    uint32_t width = 0;
    uint32_t height = 0;

    if (!candidates || !count || !monitor || *count >= capacity || right <= left || bottom <= top)
        return 0;
    if ((uint64_t)(right - left) > UINT32_MAX || (uint64_t)(bottom - top) > UINT32_MAX)
        return 0;
    width = x11_display_even_width((uint32_t)(right - left));
    height = x11_display_height((uint32_t)(bottom - top));
    if (width == 0 || height == 0)
        return 0;

    candidate = &candidates[*count];
    memset(candidate, 0, sizeof(*candidate));
    rel_left = left - (int64_t)window_x;
    rel_top = top - (int64_t)window_y;
    if (!x11_display_i64_to_i32(rel_left, &candidate->monitor.left) ||
        !x11_display_i64_to_i32(rel_top, &candidate->monitor.top))
        return 0;
    candidate->monitor.width = width;
    candidate->monitor.height = height;
    candidate->monitor.physical_width = x11_display_scaled_mm(monitor->width, monitor->mwidth, width);
    candidate->monitor.physical_height = x11_display_scaled_mm(monitor->height, monitor->mheight, height);
    candidate->monitor.orientation = 0;
    candidate->monitor.desktop_scale_factor = 100;
    candidate->monitor.device_scale_factor = 100;
    candidate->area = (uint64_t)width * (uint64_t)height;
    candidate->primary_hint = monitor->primary ? 1 : 0;
    (*count)++;
    return 1;
}

/*
 * Convert active XRandR monitors that intersect the viewer window into a
 * display-control layout. The primary monitor is translated to origin because
 * the public display-control validator requires exactly one primary at 0,0.
 * Validation rejects zero-sized windows, tiny monitor slivers, overflowing
 * coordinates, and dimensions outside the display-control contract. Ownership
 * remains with the caller: XRandR input is borrowed and only value copies are
 * written to out. The trust boundary is host display metadata entering the RDP
 * session API, so all geometry is normalized before leaving this function.
 */
uint32_t x11_display_translate_xrandr_monitors(librdp_display_monitor* out,
                                               uint32_t capacity,
                                               const XRRMonitorInfo* monitors,
                                               int monitor_count,
                                               int window_x,
                                               int window_y,
                                               uint32_t window_width,
                                               uint32_t window_height)
{
    x11_display_candidate candidates[LIBRDP_DISPLAY_MAX_MONITORS];
    uint32_t count = 0;
    uint32_t primary_index = 0;
    uint32_t i = 0;
    int64_t window_left = window_x;
    int64_t window_top = window_y;
    int64_t window_right = 0;
    int64_t window_bottom = 0;
    int found_primary = 0;
    int64_t origin_left = 0;
    int64_t origin_top = 0;

    if (!out || capacity == 0 || !monitors || monitor_count <= 0 || window_width == 0 || window_height == 0)
        return 0;
    if (capacity > LIBRDP_DISPLAY_MAX_MONITORS)
        capacity = LIBRDP_DISPLAY_MAX_MONITORS;
    if ((uint64_t)window_width > (uint64_t)INT64_MAX - (uint64_t)(window_x < 0 ? 0 : window_x) ||
        (uint64_t)window_height > (uint64_t)INT64_MAX - (uint64_t)(window_y < 0 ? 0 : window_y))
        return 0;
    window_right = window_left + (int64_t)window_width;
    window_bottom = window_top + (int64_t)window_height;
    memset(candidates, 0, sizeof(candidates));

    for (int monitor_index = 0; monitor_index < monitor_count && count < capacity; monitor_index++)
    {
        const XRRMonitorInfo* monitor = &monitors[monitor_index];
        const int64_t monitor_left = monitor->x;
        const int64_t monitor_top = monitor->y;
        const int64_t monitor_right = monitor_left + (int64_t)monitor->width;
        const int64_t monitor_bottom = monitor_top + (int64_t)monitor->height;
        const int64_t left = monitor_left > window_left ? monitor_left : window_left;
        const int64_t top = monitor_top > window_top ? monitor_top : window_top;
        const int64_t right = monitor_right < window_right ? monitor_right : window_right;
        const int64_t bottom = monitor_bottom < window_bottom ? monitor_bottom : window_bottom;

        if (monitor->width <= 0 || monitor->height <= 0)
            continue;
        (void)x11_display_add_candidate(candidates,
                                        &count,
                                        capacity,
                                        monitor,
                                        left,
                                        top,
                                        right,
                                        bottom,
                                        window_x,
                                        window_y);
    }
    if (count == 0)
        return 0;

    for (i = 0; i < count; i++)
    {
        if (candidates[i].primary_hint)
        {
            primary_index = i;
            found_primary = 1;
            break;
        }
    }
    if (!found_primary)
    {
        uint64_t best_area = 0;

        for (i = 0; i < count; i++)
        {
            if (candidates[i].area > best_area)
            {
                best_area = candidates[i].area;
                primary_index = i;
            }
        }
    }

    origin_left = candidates[primary_index].monitor.left;
    origin_top = candidates[primary_index].monitor.top;
    for (i = 0; i < count; i++)
    {
        int32_t translated_left = 0;
        int32_t translated_top = 0;

        if (!x11_display_i64_to_i32((int64_t)candidates[i].monitor.left - origin_left, &translated_left) ||
            !x11_display_i64_to_i32((int64_t)candidates[i].monitor.top - origin_top, &translated_top))
            return 0;
        out[i] = candidates[i].monitor;
        out[i].left = translated_left;
        out[i].top = translated_top;
        out[i].flags = i == primary_index ? LIBRDP_DISPLAY_MONITOR_PRIMARY : 0u;
    }
    return count;
}

static int x11_display_window_origin(x11_app* app, int* x, int* y)
{
    Window child = 0;

    if (!app || !app->display || !app->window || !x || !y)
        return 0;
    return XTranslateCoordinates(app->display,
                                 app->window,
                                 RootWindow(app->display, app->screen),
                                 0,
                                 0,
                                 x,
                                 y,
                                 &child) ? 1 : 0;
}

static uint32_t x11_display_current_layout(x11_app* app, librdp_display_monitor* monitors, uint32_t capacity)
{
    XRRMonitorInfo* xrandr_monitors = NULL;
    int monitor_count = 0;
    int window_x = 0;
    int window_y = 0;
    uint32_t count = 0;

    if (!app || !app->display || !monitors || capacity == 0 || !app->xrandr_available)
        return 0;
    if (!x11_display_window_origin(app, &window_x, &window_y))
        return 0;
    xrandr_monitors = XRRGetMonitors(app->display, RootWindow(app->display, app->screen), True, &monitor_count);
    if (!xrandr_monitors)
        return 0;
    count = x11_display_translate_xrandr_monitors(monitors,
                                                  capacity,
                                                  xrandr_monitors,
                                                  monitor_count,
                                                  window_x,
                                                  window_y,
                                                  app->window_width,
                                                  app->window_height);
    XRRFreeMonitors(xrandr_monitors);
    return count;
}
#endif

#ifdef LIBRDP_HAVE_XRANDR
static int x11_display_control_active(x11_app* app, const char* reason)
{
    librdp_feature_status status;
    librdp_status rc = LIBRDP_STATUS_OK;

    if (!app || !app->session)
        return 0;
    memset(&status, 0, sizeof(status));
    rc = librdp_session_get_feature_status(app->session, LIBRDP_FEATURE_DISPLAY_CONTROL, &status);
    if (rc != LIBRDP_STATUS_OK)
    {
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.display.layout.skip",
                        "reason=%s status=%s",
                        reason ? reason : "unknown",
                        librdp_status_string(rc));
        return 0;
    }
    if (!status.negotiated || !status.active)
    {
        x11_trace_event_level(X11_TRACE_CLIENT,
                              X11_TRACE_LEVEL_DEBUG,
                              "x11.display.layout.skip",
                              "reason=%s negotiated=%u active=%u unavailable=%u",
                              reason ? reason : "unknown",
                              status.negotiated ? 1u : 0u,
                              status.active ? 1u : 0u,
                              (unsigned)status.reason);
        return 0;
    }
    return 1;
}
#endif

int x11_display_init(x11_app* app)
{
    if (!app || !app->display)
        return 0;
#ifdef LIBRDP_HAVE_XRANDR
    if (XRRQueryExtension(app->display, &app->xrandr_event_base, &app->xrandr_error_base))
    {
        app->xrandr_available = 1;
        XRRSelectInput(app->display,
                       RootWindow(app->display, app->screen),
                       RRScreenChangeNotifyMask | RRCrtcChangeNotifyMask | RROutputChangeNotifyMask);
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.display.xrandr.init",
                        "available=1 event_base=%d error_base=%d",
                        app->xrandr_event_base,
                        app->xrandr_error_base);
        return 1;
    }
#endif
    app->xrandr_available = 0;
    x11_trace_event(X11_TRACE_CLIENT, "x11.display.xrandr.init", "available=0");
    return 1;
}

librdp_status x11_display_update_layout(x11_app* app, const char* reason)
{
#ifdef LIBRDP_HAVE_XRANDR
    librdp_display_monitor monitors[LIBRDP_DISPLAY_MAX_MONITORS];
    uint32_t monitor_count = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!app || !app->session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!app->xrandr_available)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (!x11_display_control_active(app, reason))
        return LIBRDP_STATUS_STATE;
    memset(monitors, 0, sizeof(monitors));
    monitor_count = x11_display_current_layout(app, monitors, LIBRDP_DISPLAY_MAX_MONITORS);
    if (monitor_count == 0)
        return LIBRDP_STATUS_UNSUPPORTED;
    status = librdp_session_set_display_layout(app->session, monitors, monitor_count);
    x11_trace_event(X11_TRACE_CLIENT,
                    status == LIBRDP_STATUS_OK ? "x11.display.layout.sent" : "x11.display.layout.failed",
                    "reason=%s monitors=%u status=%s",
                    reason ? reason : "unknown",
                    monitor_count,
                    librdp_status_string(status));
    return status;
#else
    (void)app;
    (void)reason;
    return LIBRDP_STATUS_UNSUPPORTED;
#endif
}

librdp_status x11_display_update_or_resize(x11_app* app, const char* reason)
{
    librdp_status status = x11_display_update_layout(app, reason);

    if (!app || !app->session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_STATE)
        return status == LIBRDP_STATUS_STATE ? LIBRDP_STATUS_OK : status;
    if (status == LIBRDP_STATUS_UNSUPPORTED ||
        status == LIBRDP_STATUS_INVALID_ARGUMENT ||
        status == LIBRDP_STATUS_LIMIT_EXCEEDED)
    {
        librdp_status fallback = librdp_session_resize(app->session, app->window_width, app->window_height);

        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.display.layout.fallback",
                        "reason=%s source_status=%s fallback_status=%s width=%u height=%u",
                        reason ? reason : "unknown",
                        librdp_status_string(status),
                        librdp_status_string(fallback),
                        app->window_width,
                        app->window_height);
        return fallback;
    }
    return status;
}

int x11_display_handle_event(x11_app* app, const XEvent* event)
{
#ifdef LIBRDP_HAVE_XRANDR
    if (!app || !event || !app->xrandr_available)
        return 0;
    if (event->type == app->xrandr_event_base + RRScreenChangeNotify)
    {
        XRRUpdateConfiguration((XEvent*)event);
        (void)x11_display_update_or_resize(app, "xrandr.screen");
        return 1;
    }
    if (event->type == app->xrandr_event_base + RRNotify)
    {
        (void)x11_display_update_or_resize(app, "xrandr.notify");
        return 1;
    }
#else
    (void)app;
    (void)event;
#endif
    return 0;
}
