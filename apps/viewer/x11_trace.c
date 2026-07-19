/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: local X11 viewer trace formatting.
 * Invariants: every emitted line uses the stable librdp trace key=value shape.
 * Ownership: no caller-provided string is retained after emission.
 * Threading: sequence generation is atomic; environment reload is benignly
 * repeated because viewer trace is diagnostic only.
 * Trust boundary: this module formats already-redacted viewer diagnostics.
 */

#include "x11_trace.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct x11_trace_config
{
    int client;
    x11_trace_level level;
    uint64_t first_ns;
} x11_trace_config;

static x11_trace_config g_x11_trace;
static atomic_ullong g_x11_trace_seq;

static uint64_t x11_trace_now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

static int x11_trace_ascii_equal_fold(const char* a, const char* b)
{
    while (*a && *b)
    {
        const unsigned char ca = (unsigned char)*a++;
        const unsigned char cb = (unsigned char)*b++;

        if (tolower(ca) != tolower(cb))
            return 0;
    }
    return *a == '\0' && *b == '\0';
}

static int x11_trace_bool_env(const char* value)
{
    if (!value)
        return 0;
    return strcmp(value, "1") == 0 || x11_trace_ascii_equal_fold(value, "true") ||
           x11_trace_ascii_equal_fold(value, "yes") || x11_trace_ascii_equal_fold(value, "on");
}

static x11_trace_level x11_trace_level_env(const char* value)
{
    if (!value || value[0] == '\0')
        return X11_TRACE_LEVEL_INFO;
    if (x11_trace_ascii_equal_fold(value, "error"))
        return X11_TRACE_LEVEL_ERROR;
    if (x11_trace_ascii_equal_fold(value, "warn") || x11_trace_ascii_equal_fold(value, "warning"))
        return X11_TRACE_LEVEL_WARN;
    if (x11_trace_ascii_equal_fold(value, "info"))
        return X11_TRACE_LEVEL_INFO;
    if (x11_trace_ascii_equal_fold(value, "debug"))
        return X11_TRACE_LEVEL_DEBUG;
    if (x11_trace_ascii_equal_fold(value, "trace"))
        return X11_TRACE_LEVEL_TRACE;
    return X11_TRACE_LEVEL_INFO;
}

static void x11_trace_refresh(void)
{
    g_x11_trace.client = x11_trace_bool_env(getenv("LIBRDP_TRACE_CLIENT"));
    g_x11_trace.level = x11_trace_level_env(getenv("LIBRDP_TRACE_LEVEL"));
    if (g_x11_trace.first_ns == 0)
        g_x11_trace.first_ns = x11_trace_now_ns();
}

static const char* x11_trace_category_name(x11_trace_category category)
{
    return category == X11_TRACE_CLIENT ? "client" : "unknown";
}

static const char* x11_trace_level_name(x11_trace_level level)
{
    switch (level)
    {
        case X11_TRACE_LEVEL_ERROR:
            return "error";
        case X11_TRACE_LEVEL_WARN:
            return "warn";
        case X11_TRACE_LEVEL_INFO:
            return "info";
        case X11_TRACE_LEVEL_DEBUG:
            return "debug";
        case X11_TRACE_LEVEL_TRACE:
            return "trace";
        default:
            return "info";
    }
}

static void x11_trace_escape_message(const char* in, char* out, size_t out_len)
{
    size_t used = 0;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!in)
        return;
    while (*in && used + 1u < out_len)
    {
        const unsigned char ch = (unsigned char)*in++;

        if ((ch == '"' || ch == '\\') && used + 2u < out_len)
        {
            out[used++] = '\\';
            out[used++] = (char)ch;
        }
        else if (ch >= 0x20u && ch < 0x7fu)
        {
            out[used++] = (char)ch;
        }
        else
        {
            out[used++] = '?';
        }
    }
    out[used] = '\0';
}

int x11_trace_enabled_level(x11_trace_category category, x11_trace_level level)
{
    x11_trace_refresh();
    if (category != X11_TRACE_CLIENT || !g_x11_trace.client)
        return 0;
    return level <= g_x11_trace.level;
}

static void x11_trace_emit_message(x11_trace_category category,
                                   x11_trace_level level,
                                   const char* event,
                                   const char* message)
{
    char escaped[2048];
    uint64_t now = 0;
    uint64_t elapsed_us = 0;
    unsigned long long seq = 0;

    if (!event || !x11_trace_enabled_level(category, level))
        return;
    x11_trace_escape_message(message ? message : "", escaped, sizeof(escaped));
    now = x11_trace_now_ns();
    if (g_x11_trace.first_ns != 0 && now >= g_x11_trace.first_ns)
        elapsed_us = (now - g_x11_trace.first_ns) / 1000u;
    seq = atomic_fetch_add_explicit(&g_x11_trace_seq, 1u, memory_order_relaxed) + 1u;
    (void)fprintf(stderr,
                  "librdp trace seq=%llu ts_ns=%llu elapsed_us=%llu category=%s event=%s level=%s message=\"%s\"\n",
                  seq,
                  (unsigned long long)now,
                  (unsigned long long)elapsed_us,
                  x11_trace_category_name(category),
                  event,
                  x11_trace_level_name(level),
                  escaped);
}

void x11_trace_event(x11_trace_category category, const char* event, const char* fmt, ...)
{
    char message[1024] = {0};
    va_list ap;

    va_start(ap, fmt);
    if (fmt)
        (void)vsnprintf(message, sizeof(message), fmt, ap);
    va_end(ap);
    x11_trace_emit_message(category, X11_TRACE_LEVEL_INFO, event, message);
}

void x11_trace_event_level(x11_trace_category category, x11_trace_level level, const char* event, const char* fmt, ...)
{
    char message[1024] = {0};
    va_list ap;

    va_start(ap, fmt);
    if (fmt)
        (void)vsnprintf(message, sizeof(message), fmt, ap);
    va_end(ap);
    x11_trace_emit_message(category, level, event, message);
}
