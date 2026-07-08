#ifndef RDP_COMMON_TRACE_H
#define RDP_COMMON_TRACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

bool rdp_trace_parse_bool_value(const char* value);
size_t rdp_trace_parse_hex_limit_value(const char* value);
rdp_trace_level rdp_trace_parse_level_value(const char* value);
void rdp_trace_refresh_from_env(void);
void rdp_trace_reset_for_tests(void);
bool rdp_trace_enabled(rdp_trace_category category);
bool rdp_trace_enabled_level(rdp_trace_category category, rdp_trace_level level);
void rdp_trace_event(rdp_trace_category category, const char* event, const char* fmt, ...);
void rdp_trace_event_level(rdp_trace_category category, rdp_trace_level level, const char* event, const char* fmt, ...);
void rdp_trace_hexdump(const char* event, const void* payload, size_t payload_len);

#endif
