/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: extended input channel parser and writer declarations.
 * Invariants: channel payload lengths, message identifiers, and negotiated
 * capabilities must be validated before state changes.
 * Ownership: parsed packet structs remain caller-owned unless a session
 * explicitly stores a copy.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths are local policy inputs.
 */


#ifndef RDP_CHANNELS_INPUT_CHANNEL_H
#define RDP_CHANNELS_INPUT_CHANNEL_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_INPUT_CHANNEL_NAME "Microsoft::Windows::RDS::Input"
#define RDP_INPUT_CHANNEL_EVENT_SC_READY 0x0001u
#define RDP_INPUT_CHANNEL_EVENT_CS_READY 0x0002u
#define RDP_INPUT_CHANNEL_EVENT_TOUCH 0x0003u
#define RDP_INPUT_CHANNEL_EVENT_SUSPEND_INPUT 0x0004u
#define RDP_INPUT_CHANNEL_EVENT_RESUME_INPUT 0x0005u
#define RDP_INPUT_CHANNEL_EVENT_DISMISS_HOVERING_TOUCH_CONTACT 0x0006u
#define RDP_INPUT_CHANNEL_EVENT_PEN 0x0008u

#define RDP_INPUT_CHANNEL_PROTOCOL_V100 0x00010000u
#define RDP_INPUT_CHANNEL_PROTOCOL_V101 0x00010001u
#define RDP_INPUT_CHANNEL_PROTOCOL_V200 0x00020000u
#define RDP_INPUT_CHANNEL_PROTOCOL_V300 0x00030000u

#define RDP_INPUT_CHANNEL_SC_READY_MULTIPEN 0x00000001u
#define RDP_INPUT_CHANNEL_CS_SHOW_TOUCH_VISUALS 0x00000001u
#define RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION 0x00000002u
#define RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN 0x00000004u

#define RDP_INPUT_CHANNEL_TOUCH_CONTACTRECT_PRESENT 0x0001u
#define RDP_INPUT_CHANNEL_TOUCH_ORIENTATION_PRESENT 0x0002u
#define RDP_INPUT_CHANNEL_TOUCH_PRESSURE_PRESENT 0x0004u

#define RDP_INPUT_CHANNEL_PEN_FLAGS_PRESENT 0x0001u
#define RDP_INPUT_CHANNEL_PEN_PRESSURE_PRESENT 0x0002u
#define RDP_INPUT_CHANNEL_PEN_ROTATION_PRESENT 0x0004u
#define RDP_INPUT_CHANNEL_PEN_TILTX_PRESENT 0x0008u
#define RDP_INPUT_CHANNEL_PEN_TILTY_PRESENT 0x0010u

#define RDP_INPUT_CHANNEL_CONTACT_DOWN 0x00000001u
#define RDP_INPUT_CHANNEL_CONTACT_UPDATE 0x00000002u
#define RDP_INPUT_CHANNEL_CONTACT_UP 0x00000004u
#define RDP_INPUT_CHANNEL_CONTACT_INRANGE 0x00000008u
#define RDP_INPUT_CHANNEL_CONTACT_INCONTACT 0x00000010u
#define RDP_INPUT_CHANNEL_CONTACT_CANCELED 0x00000020u

#define RDP_INPUT_CHANNEL_PEN_BARREL_PRESSED 0x00000001u
#define RDP_INPUT_CHANNEL_PEN_ERASER_PRESSED 0x00000002u
#define RDP_INPUT_CHANNEL_PEN_INVERTED 0x00000004u
#define RDP_INPUT_CHANNEL_MAX_FRAME_CONTACTS 256u

typedef struct rdp_input_channel_header
{
    uint16_t event_id;
    uint32_t pdu_length;
} rdp_input_channel_header;

typedef struct rdp_input_channel_sc_ready
{
    uint32_t protocol_version;
    uint8_t has_supported_features;
    uint32_t supported_features;
} rdp_input_channel_sc_ready;

typedef struct rdp_input_channel_cs_ready
{
    uint32_t flags;
    uint32_t protocol_version;
    uint16_t max_touch_contacts;
} rdp_input_channel_cs_ready;

typedef struct rdp_input_channel_negotiation
{
    uint32_t flags;
    uint32_t protocol_version;
    uint16_t max_touch_contacts;
    uint8_t supports_touch;
    uint8_t supports_pen;
    uint8_t disables_timestamp_injection;
} rdp_input_channel_negotiation;

typedef struct rdp_input_channel_touch_contact
{
    uint8_t contact_id;
    uint16_t fields_present;
    int32_t x;
    int32_t y;
    uint32_t contact_flags;
    int16_t contact_rect_left;
    int16_t contact_rect_top;
    int16_t contact_rect_right;
    int16_t contact_rect_bottom;
    uint32_t orientation;
    uint32_t pressure;
} rdp_input_channel_touch_contact;

typedef struct rdp_input_channel_touch_frame
{
    uint16_t contact_count;
    uint64_t frame_offset;
    const uint8_t* contacts;
    size_t contacts_len;
} rdp_input_channel_touch_frame;

typedef struct rdp_input_channel_touch_event
{
    uint32_t encode_time;
    uint16_t frame_count;
    const uint8_t* frames;
    size_t frames_len;
} rdp_input_channel_touch_event;

typedef struct rdp_input_channel_pen_contact
{
    uint8_t device_id;
    uint16_t fields_present;
    int32_t x;
    int32_t y;
    uint32_t contact_flags;
    uint32_t pen_flags;
    uint32_t pressure;
    uint16_t rotation;
    int16_t tilt_x;
    int16_t tilt_y;
} rdp_input_channel_pen_contact;

typedef struct rdp_input_channel_pen_frame
{
    uint16_t contact_count;
    uint64_t frame_offset;
    const uint8_t* contacts;
    size_t contacts_len;
} rdp_input_channel_pen_frame;

typedef struct rdp_input_channel_pen_event
{
    uint32_t encode_time;
    uint16_t frame_count;
    const uint8_t* frames;
    size_t frames_len;
} rdp_input_channel_pen_event;

librdp_status rdp_input_channel_parse_header(const void* data, size_t length, rdp_input_channel_header* header);
librdp_status rdp_input_channel_write_header(rdp_buffer* buffer, uint16_t event_id, uint32_t pdu_length);
librdp_status rdp_input_channel_parse_sc_ready(const void* data, size_t length, rdp_input_channel_sc_ready* ready);
librdp_status rdp_input_channel_write_sc_ready(rdp_buffer* buffer,
                                               uint32_t protocol_version,
                                               uint32_t supported_features,
                                               uint8_t has_supported_features);
librdp_status rdp_input_channel_write_cs_ready(rdp_buffer* buffer,
                                               uint32_t flags,
                                               uint32_t protocol_version,
                                               uint16_t max_touch_contacts);
librdp_status rdp_input_channel_parse_cs_ready(const void* data, size_t length, rdp_input_channel_cs_ready* ready);
librdp_status rdp_input_channel_negotiate_client_ready(const rdp_input_channel_sc_ready* server_ready,
                                                       uint16_t max_touch_contacts,
                                                       uint8_t show_touch_visuals,
                                                       rdp_input_channel_negotiation* negotiation);
librdp_status rdp_input_channel_write_suspend(rdp_buffer* buffer);
librdp_status rdp_input_channel_write_resume(rdp_buffer* buffer);
librdp_status rdp_input_channel_parse_empty(const void* data, size_t length, uint16_t event_id);
librdp_status rdp_input_channel_write_dismiss_hovering(rdp_buffer* buffer, uint8_t contact_id);
librdp_status rdp_input_channel_parse_dismiss_hovering(const void* data, size_t length, uint8_t* contact_id);
librdp_status rdp_input_channel_write_touch_event(rdp_buffer* buffer,
                                                  uint32_t encode_time,
                                                  const rdp_input_channel_touch_frame* frames,
                                                  uint16_t frame_count);
librdp_status rdp_input_channel_validate_touch_contact(const rdp_input_channel_touch_contact* contact);
librdp_status rdp_input_channel_write_touch_contact(rdp_buffer* buffer,
                                                    const rdp_input_channel_touch_contact* contact);
librdp_status rdp_input_channel_write_touch_frame(rdp_buffer* buffer,
                                                  uint64_t frame_offset,
                                                  const rdp_input_channel_touch_contact* contacts,
                                                  uint16_t contact_count);
librdp_status rdp_input_channel_parse_touch_event(const void* data,
                                                  size_t length,
                                                  rdp_input_channel_touch_event* event);
librdp_status rdp_input_channel_touch_event_get_frame(const rdp_input_channel_touch_event* event,
                                                      uint16_t index,
                                                      rdp_input_channel_touch_frame* frame);
librdp_status rdp_input_channel_touch_frame_get_contact(const rdp_input_channel_touch_frame* frame,
                                                        uint16_t index,
                                                        rdp_input_channel_touch_contact* contact);
librdp_status rdp_input_channel_write_pen_event(rdp_buffer* buffer,
                                                uint32_t encode_time,
                                                const rdp_input_channel_pen_frame* frames,
                                                uint16_t frame_count);
librdp_status rdp_input_channel_validate_pen_contact(const rdp_input_channel_pen_contact* contact);
librdp_status rdp_input_channel_write_pen_contact(rdp_buffer* buffer,
                                                  const rdp_input_channel_pen_contact* contact);
librdp_status rdp_input_channel_write_pen_frame(rdp_buffer* buffer,
                                                uint64_t frame_offset,
                                                const rdp_input_channel_pen_contact* contacts,
                                                uint16_t contact_count);
librdp_status rdp_input_channel_parse_pen_event(const void* data,
                                                size_t length,
                                                rdp_input_channel_pen_event* event);
librdp_status rdp_input_channel_pen_event_get_frame(const rdp_input_channel_pen_event* event,
                                                    uint16_t index,
                                                    rdp_input_channel_pen_frame* frame);
librdp_status rdp_input_channel_pen_frame_get_contact(const rdp_input_channel_pen_frame* frame,
                                                      uint16_t index,
                                                      rdp_input_channel_pen_contact* contact);

#endif
