/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: modern input channel parser declarations.
 * Invariants: channel payload lengths, message identifiers, and negotiated
 * capabilities must be validated before state changes.
 * Ownership: parsed packet structs remain caller-owned unless a session
 * explicitly stores a copy.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths are local policy inputs.
 */


#ifndef RDP_CHANNELS_CORE_INPUT_H
#define RDP_CHANNELS_CORE_INPUT_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_CORE_INPUT_CHANNEL_NAME "Microsoft::Windows::RDS::CoreInput"
#define RDP_CORE_INPUT_SIGNATURE 0x03u
#define RDP_CORE_INPUT_PDU_CS_INIT_REQUEST 0x01u
#define RDP_CORE_INPUT_PDU_SC_INIT_RESPONSE 0x02u
#define RDP_CORE_INPUT_PDU_CS_KEYBOARD_AND_MOUSE 0x03u
#define RDP_CORE_INPUT_PROTOCOL_VERSION_100 0x0100u
#define RDP_CORE_INPUT_EVENT_SCANCODE 0x00u
#define RDP_CORE_INPUT_EVENT_MOUSE 0x01u
#define RDP_CORE_INPUT_EVENT_MOUSEX 0x02u
#define RDP_CORE_INPUT_EVENT_SYNC 0x03u
#define RDP_CORE_INPUT_EVENT_UNICODE 0x04u
#define RDP_CORE_INPUT_EVENT_RELMOUSE 0x05u
#define RDP_CORE_INPUT_EVENT_QOE_TIMESTAMP 0x06u
#define RDP_CORE_INPUT_KBDFLAGS_RELEASE 0x01u
#define RDP_CORE_INPUT_KBDFLAGS_EXTENDED 0x02u
#define RDP_CORE_INPUT_KBDFLAGS_EXTENDED1 0x04u
#define RDP_CORE_INPUT_SYNC_SCROLL_LOCK 0x01u
#define RDP_CORE_INPUT_SYNC_NUM_LOCK 0x02u
#define RDP_CORE_INPUT_SYNC_CAPS_LOCK 0x04u
#define RDP_CORE_INPUT_SYNC_KANA_LOCK 0x08u

typedef struct rdp_core_input_header
{
    uint8_t signature;
    uint8_t pdu_type;
    uint8_t event_count;
    uint8_t padding;
} rdp_core_input_header;

typedef struct rdp_core_input_init_request
{
    uint16_t protocol_version_min;
    uint16_t protocol_version_max;
} rdp_core_input_init_request;

typedef struct rdp_core_input_init_response
{
    uint16_t selected_protocol_version;
    uint16_t protocol_version_max;
} rdp_core_input_init_response;

typedef struct rdp_core_input_negotiation
{
    uint16_t selected_protocol_version;
    uint16_t protocol_version_max;
    uint8_t supports_relative_mouse;
    uint8_t supports_qoe_timestamp;
} rdp_core_input_negotiation;

typedef struct rdp_core_input_event
{
    uint8_t type;
    uint8_t flags;
    uint16_t pointer_flags;
    uint16_t x;
    uint16_t y;
    int16_t dx;
    int16_t dy;
    uint32_t timestamp;
    uint16_t unicode_code;
    uint8_t scancode;
} rdp_core_input_event;

librdp_status rdp_core_input_parse_header(const void* data,
                                          size_t length,
                                          rdp_core_input_header* header);
librdp_status rdp_core_input_write_init_request(rdp_buffer* buffer);
librdp_status rdp_core_input_parse_init_request(
    const void* data,
    size_t length,
    rdp_core_input_init_request* request);
librdp_status rdp_core_input_write_init_response(
    rdp_buffer* buffer,
    uint16_t selected_protocol_version,
    uint16_t protocol_version_max);
librdp_status rdp_core_input_parse_init_response(const void* data,
                                                 size_t length,
                                                 rdp_core_input_init_response* response);
librdp_status rdp_core_input_negotiate(const rdp_core_input_init_response* response,
                                       rdp_core_input_negotiation* negotiation);
librdp_status rdp_core_input_parse_events(const void* data,
                                          size_t length,
                                          rdp_core_input_event* events,
                                          uint8_t capacity,
                                          uint8_t* event_count);
librdp_status rdp_core_input_write_events(rdp_buffer* buffer,
                                          const rdp_core_input_event* events,
                                          uint8_t event_count);
librdp_status rdp_core_input_write_keyboard_event(rdp_buffer* buffer, uint8_t scancode, uint8_t released);
librdp_status rdp_core_input_write_keyboard_event_ex(rdp_buffer* buffer, uint8_t scancode, uint8_t flags);
librdp_status rdp_core_input_write_unicode_event(rdp_buffer* buffer, uint16_t code, uint8_t released);
librdp_status rdp_core_input_write_sync_event(rdp_buffer* buffer, uint8_t flags);
librdp_status rdp_core_input_write_mouse_event(rdp_buffer* buffer, uint16_t pointer_flags, uint16_t x, uint16_t y);
librdp_status rdp_core_input_write_extended_mouse_event(rdp_buffer* buffer,
                                                       uint16_t pointer_flags,
                                                       uint16_t x,
                                                       uint16_t y);
librdp_status rdp_core_input_write_relative_mouse_event(rdp_buffer* buffer,
                                                       uint16_t pointer_flags,
                                                       int16_t dx,
                                                       int16_t dy);
librdp_status rdp_core_input_write_qoe_timestamp_event(rdp_buffer* buffer, uint32_t timestamp);

#endif
