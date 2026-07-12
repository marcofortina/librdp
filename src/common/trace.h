/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal runtime trace contract for categorized events and bounded
 * hexdumps.
 * Invariants: declarations preserve explicit bounds, ownership, and error
 * propagation across module boundaries.
 * Ownership: trace state is process-global and must never own or print
 * credential material.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: external inputs are untrusted until validated by the
 * declaring module or caller.
 */


#ifndef RDP_COMMON_TRACE_H
#define RDP_COMMON_TRACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <librdp/session.h>

typedef enum rdp_trace_category
{
    RDP_TRACE_CLIENT = 1,
    RDP_TRACE_TRANSPORT = 2,
    RDP_TRACE_PROTOCOL = 4
} rdp_trace_category;

typedef enum rdp_trace_level
{
    RDP_TRACE_LEVEL_ERROR = 0,
    RDP_TRACE_LEVEL_WARN = 1,
    RDP_TRACE_LEVEL_INFO = 2,
    RDP_TRACE_LEVEL_DEBUG = 3,
    RDP_TRACE_LEVEL_TRACE = 4
} rdp_trace_level;

typedef enum rdp_trace_sensitivity
{
    RDP_TRACE_SENSITIVITY_HEADER = 0,
    RDP_TRACE_SENSITIVITY_AUTH = 1,
    RDP_TRACE_SENSITIVITY_INPUT = 2,
    RDP_TRACE_SENSITIVITY_CLIPBOARD = 3,
    RDP_TRACE_SENSITIVITY_FILE = 4,
    RDP_TRACE_SENSITIVITY_APDU = 5,
    RDP_TRACE_SENSITIVITY_AUDIO = 6,
    RDP_TRACE_SENSITIVITY_VIDEO = 7,
    RDP_TRACE_SENSITIVITY_USB = 8
} rdp_trace_sensitivity;

typedef struct rdp_trace_session_scope
{
    librdp_session* session;
    uint32_t categories;
    rdp_trace_level level;
    size_t hex_limit;
    bool unsafe_hexdump;
    librdp_trace_sink sink;
    FILE* file;
    librdp_trace_callback callback;
    void* callback_user_data;
    const char* session_id;
    const char* connection_id;
    const char* trace_id;
    uint64_t* sequence;
    uint64_t* first_ns;
} rdp_trace_session_scope;

bool rdp_trace_parse_bool_value(const char* value);
size_t rdp_trace_parse_hex_limit_value(const char* value);
rdp_trace_level rdp_trace_parse_level_value(const char* value);
void rdp_trace_refresh_from_env(void);
void rdp_trace_reset_for_tests(void);
void rdp_trace_push_session(rdp_trace_session_scope* scope);
void rdp_trace_pop_session(void);
bool rdp_trace_enabled(rdp_trace_category category);
bool rdp_trace_enabled_level(rdp_trace_category category, rdp_trace_level level);
void rdp_trace_event(rdp_trace_category category, const char* event, const char* fmt, ...);
void rdp_trace_event_level(rdp_trace_category category, rdp_trace_level level, const char* event, const char* fmt, ...);
void rdp_trace_hexdump(const char* event,
                       rdp_trace_sensitivity sensitivity,
                       const void* payload,
                       size_t payload_len);

#endif
