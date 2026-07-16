/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: multiparty channel parser and writer declarations.
 * Invariants: channel payload lengths, message identifiers, and negotiated
 * capabilities must be validated before state changes.
 * Ownership: parsed packet structs remain caller-owned unless a session
 * explicitly stores a copy.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths are local policy inputs.
 */


#ifndef RDP_CHANNELS_MULTIPARTY_H
#define RDP_CHANNELS_MULTIPARTY_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_MULTIPARTY_CHANNEL_NAME "encomsp"
#define RDP_MULTIPARTY_TYPE_FILTER_STATE_UPDATED 0x0001u
#define RDP_MULTIPARTY_TYPE_APP_REMOVED 0x0002u
#define RDP_MULTIPARTY_TYPE_APP_CREATED 0x0003u
#define RDP_MULTIPARTY_TYPE_WND_REMOVED 0x0004u
#define RDP_MULTIPARTY_TYPE_WND_CREATED 0x0005u
#define RDP_MULTIPARTY_TYPE_WND_SHOW 0x0006u
#define RDP_MULTIPARTY_TYPE_PARTICIPANT_REMOVED 0x0007u
#define RDP_MULTIPARTY_TYPE_PARTICIPANT_CREATED 0x0008u
#define RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGED 0x0009u
#define RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_PAUSED 0x000au
#define RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_RESUMED 0x000bu
#define RDP_MULTIPARTY_TYPE_WND_REGION_UPDATE 0x000cu
#define RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGE_RESPONSE 0x000du

#define RDP_MULTIPARTY_FILTER_ENABLED 0x01u
#define RDP_MULTIPARTY_APPLICATION_SHARED 0x0001u
#define RDP_MULTIPARTY_WINDOW_SHARED 0x0001u
#define RDP_MULTIPARTY_MAY_VIEW 0x0001u
#define RDP_MULTIPARTY_MAY_INTERACT 0x0002u
#define RDP_MULTIPARTY_IS_PARTICIPANT 0x0004u
#define RDP_MULTIPARTY_REQUEST_VIEW 0x0001u
#define RDP_MULTIPARTY_REQUEST_INTERACT 0x0002u
#define RDP_MULTIPARTY_ALLOW_CONTROL_REQUESTS 0x0008u
#define RDP_MULTIPARTY_STRING_MAX_CHARS 1024u

typedef struct rdp_multiparty_header
{
    uint16_t type;
    uint16_t length;
    const uint8_t* payload;
    size_t payload_len;
} rdp_multiparty_header;

typedef struct rdp_multiparty_string
{
    uint16_t char_count;
    const uint8_t* utf16;
    size_t utf16_len;
} rdp_multiparty_string;

typedef struct rdp_multiparty_filter_state
{
    rdp_multiparty_header header;
    uint8_t flags;
} rdp_multiparty_filter_state;

typedef struct rdp_multiparty_app_created
{
    rdp_multiparty_header header;
    uint16_t flags;
    uint32_t app_id;
    rdp_multiparty_string name;
} rdp_multiparty_app_created;

typedef struct rdp_multiparty_id_message
{
    rdp_multiparty_header header;
    uint32_t id;
} rdp_multiparty_id_message;

typedef struct rdp_multiparty_window_created
{
    rdp_multiparty_header header;
    uint16_t flags;
    uint32_t app_id;
    uint32_t window_id;
    rdp_multiparty_string name;
} rdp_multiparty_window_created;

typedef struct rdp_multiparty_region_update
{
    rdp_multiparty_header header;
    uint32_t left;
    uint32_t top;
    uint32_t right;
    uint32_t bottom;
} rdp_multiparty_region_update;

typedef struct rdp_multiparty_participant_created
{
    rdp_multiparty_header header;
    uint32_t participant_id;
    uint32_t group_id;
    uint16_t flags;
    rdp_multiparty_string friendly_name;
} rdp_multiparty_participant_created;

typedef struct rdp_multiparty_participant_removed
{
    rdp_multiparty_header header;
    uint32_t participant_id;
    uint32_t disconnect_type;
    uint32_t disconnect_code;
} rdp_multiparty_participant_removed;

typedef struct rdp_multiparty_control_change
{
    rdp_multiparty_header header;
    uint16_t flags;
    uint32_t participant_id;
} rdp_multiparty_control_change;

typedef struct rdp_multiparty_control_change_response
{
    rdp_multiparty_header header;
    uint16_t flags;
    uint32_t participant_id;
    uint32_t reason_code;
} rdp_multiparty_control_change_response;

typedef struct rdp_multiparty_message
{
    uint16_t type;
    union
    {
        rdp_multiparty_header header;
        rdp_multiparty_filter_state filter_state;
        rdp_multiparty_app_created app_created;
        rdp_multiparty_id_message id_message;
        rdp_multiparty_window_created window_created;
        rdp_multiparty_region_update region_update;
        rdp_multiparty_participant_created participant_created;
        rdp_multiparty_participant_removed participant_removed;
        rdp_multiparty_control_change control_change;
        rdp_multiparty_control_change_response control_change_response;
    } body;
} rdp_multiparty_message;

librdp_status rdp_multiparty_parse_header(const void* data, size_t length, rdp_multiparty_header* header);
librdp_status rdp_multiparty_write_header(rdp_buffer* buffer, uint16_t type, uint16_t payload_len);
librdp_status rdp_multiparty_parse_message(const void* data,
                                           size_t length,
                                           rdp_multiparty_message* message);
librdp_status rdp_multiparty_parse_string(const void* data,
                                          size_t length,
                                          rdp_multiparty_string* string,
                                          size_t* consumed);
librdp_status rdp_multiparty_write_string(rdp_buffer* buffer, const uint8_t* utf16, uint16_t char_count);
librdp_status rdp_multiparty_parse_filter_state(const void* data,
                                                size_t length,
                                                rdp_multiparty_filter_state* state);
librdp_status rdp_multiparty_write_filter_state(rdp_buffer* buffer, uint8_t flags);
librdp_status rdp_multiparty_parse_app_created(const void* data,
                                               size_t length,
                                               rdp_multiparty_app_created* app);
librdp_status rdp_multiparty_write_app_created(rdp_buffer* buffer,
                                               uint16_t flags,
                                               uint32_t app_id,
                                               const uint8_t* name_utf16,
                                               uint16_t name_chars);
librdp_status rdp_multiparty_parse_id_message(const void* data,
                                              size_t length,
                                              uint16_t expected_type,
                                              rdp_multiparty_id_message* message);
librdp_status rdp_multiparty_write_id_message(rdp_buffer* buffer, uint16_t type, uint32_t id);
librdp_status rdp_multiparty_parse_window_created(const void* data,
                                                  size_t length,
                                                  rdp_multiparty_window_created* window);
librdp_status rdp_multiparty_write_window_created(rdp_buffer* buffer,
                                                  uint16_t flags,
                                                  uint32_t app_id,
                                                  uint32_t window_id,
                                                  const uint8_t* name_utf16,
                                                  uint16_t name_chars);
librdp_status rdp_multiparty_parse_region_update(const void* data,
                                                 size_t length,
                                                 rdp_multiparty_region_update* region);
librdp_status rdp_multiparty_write_region_update(rdp_buffer* buffer,
                                                 uint32_t left,
                                                 uint32_t top,
                                                 uint32_t right,
                                                 uint32_t bottom);
librdp_status rdp_multiparty_parse_participant_created(
    const void* data,
    size_t length,
    rdp_multiparty_participant_created* participant);
librdp_status rdp_multiparty_write_participant_created(rdp_buffer* buffer,
                                                       uint32_t participant_id,
                                                       uint32_t group_id,
                                                       uint16_t flags,
                                                       const uint8_t* name_utf16,
                                                       uint16_t name_chars);
librdp_status rdp_multiparty_parse_participant_removed(
    const void* data,
    size_t length,
    rdp_multiparty_participant_removed* participant);
librdp_status rdp_multiparty_write_participant_removed(rdp_buffer* buffer,
                                                       uint32_t participant_id,
                                                       uint32_t disconnect_type,
                                                       uint32_t disconnect_code);
librdp_status rdp_multiparty_parse_control_change(const void* data,
                                                  size_t length,
                                                  rdp_multiparty_control_change* change);
librdp_status rdp_multiparty_write_control_change(rdp_buffer* buffer,
                                                  uint16_t flags,
                                                  uint32_t participant_id);
librdp_status rdp_multiparty_parse_control_change_response(
    const void* data,
    size_t length,
    rdp_multiparty_control_change_response* response);
librdp_status rdp_multiparty_write_control_change_response(rdp_buffer* buffer,
                                                           uint16_t flags,
                                                           uint32_t participant_id,
                                                           uint32_t reason_code);
librdp_status rdp_multiparty_parse_empty(const void* data, size_t length, uint16_t expected_type);
librdp_status rdp_multiparty_write_empty(rdp_buffer* buffer, uint16_t type);

#endif
