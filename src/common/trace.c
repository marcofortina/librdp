/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: runtime trace filtering, formatting, monotonic sequencing, and
 * bounded protocol hexdumps.
 * Invariants: publicly observable state is updated only after local validation
 * succeeds.
 * Ownership: trace configuration is process-global after lazy initialization
 * and never records credentials.
 * Threading: uses internal atomics for sequencing but callers should not
 * mutate environment configuration concurrently.
 * Trust boundary: external input is treated as untrusted until validated by
 * this module or its caller.
 */


#include "common/trace.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RDP_TRACE_REDACTED_HEADER_BYTES 16u

typedef struct rdp_trace_config
{
    bool client;
    bool transport;
    bool protocol;
    bool unsafe_hexdump;
    size_t hex_limit;
    rdp_trace_level level;
    bool initialized;
    uint64_t first_ns;
} rdp_trace_config;

static rdp_trace_config g_trace;
static atomic_ullong g_trace_seq;

static uint64_t rdp_trace_now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

static bool rdp_ascii_equal_fold(const char* a, const char* b)
{
    while (*a && *b)
    {
        const unsigned char ca = (unsigned char)*a++;
        const unsigned char cb = (unsigned char)*b++;
        if (tolower(ca) != tolower(cb))
            return false;
    }
    return *a == '\0' && *b == '\0';
}

bool rdp_trace_parse_bool_value(const char* value)
{
    if (!value)
        return false;
    return strcmp(value, "1") == 0 || rdp_ascii_equal_fold(value, "true") ||
           rdp_ascii_equal_fold(value, "yes") || rdp_ascii_equal_fold(value, "on");
}

size_t rdp_trace_parse_hex_limit_value(const char* value)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!value || value[0] == '\0')
        return 0;

    parsed = strtoul(value, &end, 10);
    if (!end || *end != '\0')
        return 0;
    return (size_t)parsed;
}

rdp_trace_level rdp_trace_parse_level_value(const char* value)
{
    if (!value || value[0] == '\0')
        return RDP_TRACE_LEVEL_INFO;
    if (strcmp(value, "0") == 0 || rdp_ascii_equal_fold(value, "error"))
        return RDP_TRACE_LEVEL_ERROR;
    if (strcmp(value, "1") == 0 || rdp_ascii_equal_fold(value, "warn") ||
        rdp_ascii_equal_fold(value, "warning"))
        return RDP_TRACE_LEVEL_WARN;
    if (strcmp(value, "2") == 0 || rdp_ascii_equal_fold(value, "info"))
        return RDP_TRACE_LEVEL_INFO;
    if (strcmp(value, "3") == 0 || rdp_ascii_equal_fold(value, "debug"))
        return RDP_TRACE_LEVEL_DEBUG;
    if (strcmp(value, "4") == 0 || rdp_ascii_equal_fold(value, "trace"))
        return RDP_TRACE_LEVEL_TRACE;
    return RDP_TRACE_LEVEL_INFO;
}

void rdp_trace_refresh_from_env(void)
{
    g_trace.client = rdp_trace_parse_bool_value(getenv("LIBRDP_TRACE_CLIENT"));
    g_trace.transport = rdp_trace_parse_bool_value(getenv("LIBRDP_TRACE_TRANSPORT"));
    g_trace.protocol = rdp_trace_parse_bool_value(getenv("LIBRDP_TRACE_PROTOCOL"));
    g_trace.unsafe_hexdump = rdp_trace_parse_bool_value(getenv("LIBRDP_TRACE_UNSAFE"));
    g_trace.hex_limit = rdp_trace_parse_hex_limit_value(getenv("LIBRDP_TRACE_HEX_BYTES"));
    g_trace.level = rdp_trace_parse_level_value(getenv("LIBRDP_TRACE_LEVEL"));
    g_trace.initialized = true;
    g_trace.first_ns = 0;
    atomic_store(&g_trace_seq, 0);
}

void rdp_trace_reset_for_tests(void)
{
    memset(&g_trace, 0, sizeof(g_trace));
    atomic_store(&g_trace_seq, 0);
}

bool rdp_trace_enabled(rdp_trace_category category)
{
    if (!g_trace.initialized)
        rdp_trace_refresh_from_env();

    switch (category)
    {
        case RDP_TRACE_CLIENT:
            return g_trace.client;
        case RDP_TRACE_TRANSPORT:
            return g_trace.transport;
        case RDP_TRACE_PROTOCOL:
            return g_trace.protocol;
        default:
            return false;
    }
}

bool rdp_trace_enabled_level(rdp_trace_category category, rdp_trace_level level)
{
    if (!rdp_trace_enabled(category))
        return false;
    return level <= g_trace.level;
}

static const char* rdp_trace_category_name(rdp_trace_category category)
{
    switch (category)
    {
        case RDP_TRACE_CLIENT:
            return "client";
        case RDP_TRACE_TRANSPORT:
            return "transport";
        case RDP_TRACE_PROTOCOL:
            return "protocol";
        default:
            return "unknown";
    }
}

static const char* rdp_trace_level_name(rdp_trace_level level)
{
    switch (level)
    {
        case RDP_TRACE_LEVEL_ERROR:
            return "error";
        case RDP_TRACE_LEVEL_WARN:
            return "warn";
        case RDP_TRACE_LEVEL_INFO:
            return "info";
        case RDP_TRACE_LEVEL_DEBUG:
            return "debug";
        case RDP_TRACE_LEVEL_TRACE:
            return "trace";
        default:
            return "unknown";
    }
}

static const char* rdp_trace_sensitivity_name(rdp_trace_sensitivity sensitivity)
{
    switch (sensitivity)
    {
        case RDP_TRACE_SENSITIVITY_HEADER:
            return "header";
        case RDP_TRACE_SENSITIVITY_AUTH:
            return "auth";
        case RDP_TRACE_SENSITIVITY_INPUT:
            return "input";
        case RDP_TRACE_SENSITIVITY_CLIPBOARD:
            return "clipboard";
        case RDP_TRACE_SENSITIVITY_FILE:
            return "file";
        case RDP_TRACE_SENSITIVITY_APDU:
            return "apdu";
        case RDP_TRACE_SENSITIVITY_AUDIO:
            return "audio";
        case RDP_TRACE_SENSITIVITY_VIDEO:
            return "video";
        case RDP_TRACE_SENSITIVITY_USB:
            return "usb";
        default:
            return "unknown";
    }
}

static unsigned long long rdp_trace_next_seq(uint64_t* now, uint64_t* elapsed_us)
{
    const unsigned long long seq = atomic_fetch_add(&g_trace_seq, 1) + 1;

    *now = rdp_trace_now_ns();
    if (g_trace.first_ns == 0)
        g_trace.first_ns = *now;
    *elapsed_us = (*now >= g_trace.first_ns) ? ((*now - g_trace.first_ns) / 1000u) : 0;
    return seq;
}

static void rdp_trace_escape_message(const char* in, char* out, size_t out_len)
{
    size_t pos = 0;

    if (!out || out_len == 0)
        return;

    if (!in)
    {
        out[0] = '\0';
        return;
    }

    while (*in && pos + 1 < out_len)
    {
        unsigned char c = (unsigned char)*in++;
        if (c == '"' || c == '\\')
        {
            if (pos + 2 >= out_len)
                break;
            out[pos++] = '\\';
            out[pos++] = (char)c;
        }
        else if (c < 0x20 || c == 0x7f)
        {
            out[pos++] = ' ';
        }
        else
        {
            out[pos++] = (char)c;
        }
    }
    out[pos] = '\0';
}

static void rdp_trace_event_v(rdp_trace_category category,
                              rdp_trace_level level,
                              const char* event,
                              const char* fmt,
                              va_list ap)
{
    uint64_t now = 0;
    uint64_t elapsed_us = 0;
    unsigned long long seq = 0;
    char message[1024];
    char escaped[2048];

    if (!event || !rdp_trace_enabled_level(category, level))
        return;

    message[0] = '\0';
    if (fmt)
        (void)vsnprintf(message, sizeof(message), fmt, ap);

    rdp_trace_escape_message(message, escaped, sizeof(escaped));
    seq = rdp_trace_next_seq(&now, &elapsed_us);
    fprintf(stderr,
            "librdp trace seq=%llu ts_ns=%llu elapsed_us=%llu category=%s event=%s level=%s message=\"%s\"\n",
            seq,
            (unsigned long long)now,
            (unsigned long long)elapsed_us,
            rdp_trace_category_name(category),
            event,
            rdp_trace_level_name(level),
            escaped);
}

void rdp_trace_event(rdp_trace_category category, const char* event, const char* fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    rdp_trace_event_v(category, RDP_TRACE_LEVEL_INFO, event, fmt, ap);
    va_end(ap);
}

void rdp_trace_event_level(rdp_trace_category category, rdp_trace_level level, const char* event, const char* fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    rdp_trace_event_v(category, level, event, fmt, ap);
    va_end(ap);
}

void rdp_trace_hexdump(const char* event,
                       rdp_trace_sensitivity sensitivity,
                       const void* payload,
                       size_t payload_len)
{
    const uint8_t* bytes = (const uint8_t*)payload;
    size_t limit = 0;
    size_t dumped = 0;
    bool unsafe = false;
    bool redacted = false;
    uint64_t now = 0;
    uint64_t elapsed_us = 0;
    unsigned long long seq = 0;
    char hex[1024];
    char ascii[256];
    size_t hpos = 0;
    size_t apos = 0;
    size_t i = 0;

    if (!event || (!payload && payload_len > 0) ||
        !rdp_trace_enabled_level(RDP_TRACE_PROTOCOL, RDP_TRACE_LEVEL_TRACE))
        return;

    unsafe = g_trace.initialized ? g_trace.unsafe_hexdump : rdp_trace_parse_bool_value(getenv("LIBRDP_TRACE_UNSAFE"));
    limit = g_trace.initialized ? g_trace.hex_limit : rdp_trace_parse_hex_limit_value(getenv("LIBRDP_TRACE_HEX_BYTES"));
    if (!unsafe && sensitivity != RDP_TRACE_SENSITIVITY_HEADER && limit > RDP_TRACE_REDACTED_HEADER_BYTES)
        limit = RDP_TRACE_REDACTED_HEADER_BYTES;
    dumped = payload_len < limit ? payload_len : limit;
    redacted = !unsafe && sensitivity != RDP_TRACE_SENSITIVITY_HEADER && dumped < payload_len;

    for (i = 0; i < dumped && hpos + 3 < sizeof(hex); i++)
    {
        static const char table[] = "0123456789abcdef";
        hex[hpos++] = table[(bytes[i] >> 4) & 0x0f];
        hex[hpos++] = table[bytes[i] & 0x0f];
    }
    hex[hpos] = '\0';

    for (i = 0; i < dumped && apos + 1 < sizeof(ascii); i++)
    {
        const unsigned char c = bytes[i];
        ascii[apos++] = (char)((c >= 0x20 && c < 0x7f) ? c : '.');
    }
    ascii[apos] = '\0';

    seq = rdp_trace_next_seq(&now, &elapsed_us);
    fprintf(stderr,
            "librdp trace seq=%llu ts_ns=%llu elapsed_us=%llu category=protocol event=%s level=trace payload_len=%llu dumped=%llu hex=%s ascii=\"%s\" sensitivity=%s redacted=%u unsafe=%u\n",
            seq,
            (unsigned long long)now,
            (unsigned long long)elapsed_us,
            event,
            (unsigned long long)payload_len,
            (unsigned long long)dumped,
            hex,
            ascii,
            rdp_trace_sensitivity_name(sensitivity),
            redacted ? 1u : 0u,
            unsafe ? 1u : 0u);
}
