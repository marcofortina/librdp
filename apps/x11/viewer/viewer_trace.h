/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: local X11 viewer trace facade.
 * Invariants: viewer trace never depends on private core headers.
 * Ownership: trace configuration is read from environment and output is stderr.
 * Threading: trace sequence uses atomics; callers may emit from backend threads.
 * Trust boundary: messages must be pre-redacted by the caller.
 */

#ifndef LIBRDP_X11_VIEWER_TRACE_H
#define LIBRDP_X11_VIEWER_TRACE_H

#include <stdarg.h>

typedef enum x11_trace_category
{
    X11_TRACE_CLIENT = 1
} x11_trace_category;

typedef enum x11_trace_level
{
    X11_TRACE_LEVEL_ERROR = 0,
    X11_TRACE_LEVEL_WARN = 1,
    X11_TRACE_LEVEL_INFO = 2,
    X11_TRACE_LEVEL_DEBUG = 3,
    X11_TRACE_LEVEL_TRACE = 4
} x11_trace_level;

#if defined(__GNUC__) || defined(__clang__)
#define X11_TRACE_PRINTF(fmt_index, first_arg) __attribute__((format(printf, fmt_index, first_arg)))
#else
#define X11_TRACE_PRINTF(fmt_index, first_arg)
#endif

int x11_trace_enabled_level(x11_trace_category category, x11_trace_level level);
void x11_trace_event(x11_trace_category category, const char* event, const char* fmt, ...)
    X11_TRACE_PRINTF(3, 4);
void x11_trace_event_level(x11_trace_category category, x11_trace_level level, const char* event, const char* fmt, ...)
    X11_TRACE_PRINTF(4, 5);
void x11_trace_event_level_v(x11_trace_category category,
                             x11_trace_level level,
                             const char* event,
                             const char* fmt,
                             va_list ap);

#endif
