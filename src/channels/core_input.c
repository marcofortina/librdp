/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "channels/core_input.h"

#include "common/stream.h"

#include <string.h>

static librdp_status rdp_core_input_write_header(rdp_buffer* buffer, uint8_t pdu_type, uint8_t event_count)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, RDP_CORE_INPUT_SIGNATURE);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, pdu_type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, event_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

static uint8_t rdp_core_input_pack_event(uint8_t type, uint8_t flags)
{
    return (uint8_t)(((type & 0x07u) << 5) | (flags & 0x1fu));
}

static uint8_t rdp_core_input_event_payload_len(uint8_t type)
{
    if (type == RDP_CORE_INPUT_EVENT_SCANCODE)
        return 1;
    if (type == RDP_CORE_INPUT_EVENT_MOUSE ||
        type == RDP_CORE_INPUT_EVENT_MOUSEX ||
        type == RDP_CORE_INPUT_EVENT_RELMOUSE)
        return 6;
    if (type == RDP_CORE_INPUT_EVENT_UNICODE)
        return 2;
    if (type == RDP_CORE_INPUT_EVENT_QOE_TIMESTAMP)
        return 4;
    if (type == RDP_CORE_INPUT_EVENT_SYNC)
        return 0;
    return 0xffu;
}

static librdp_status rdp_core_input_validate_event(const rdp_core_input_event* event)
{
    if (!event || rdp_core_input_event_payload_len(event->type) == 0xffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (event->type == RDP_CORE_INPUT_EVENT_SCANCODE &&
        (event->flags & ~(RDP_CORE_INPUT_KBDFLAGS_RELEASE |
                          RDP_CORE_INPUT_KBDFLAGS_EXTENDED |
                          RDP_CORE_INPUT_KBDFLAGS_EXTENDED1)) != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (event->type == RDP_CORE_INPUT_EVENT_UNICODE &&
        (event->flags & ~RDP_CORE_INPUT_KBDFLAGS_RELEASE) != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (event->type == RDP_CORE_INPUT_EVENT_SYNC &&
        (event->flags & ~(RDP_CORE_INPUT_SYNC_SCROLL_LOCK |
                          RDP_CORE_INPUT_SYNC_NUM_LOCK |
                          RDP_CORE_INPUT_SYNC_CAPS_LOCK |
                          RDP_CORE_INPUT_SYNC_KANA_LOCK)) != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((event->type == RDP_CORE_INPUT_EVENT_MOUSE ||
         event->type == RDP_CORE_INPUT_EVENT_MOUSEX ||
         event->type == RDP_CORE_INPUT_EVENT_RELMOUSE ||
         event->type == RDP_CORE_INPUT_EVENT_QOE_TIMESTAMP) &&
        event->flags != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_core_input_parse_header(const void* data,
                                          size_t length,
                                          rdp_core_input_header* header)
{
    rdp_core_input_header parsed;
    const uint8_t* bytes = (const uint8_t*)data;

    if (!data || !header || length < 4)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(&parsed, 0, sizeof(parsed));
    parsed.signature = bytes[0];
    parsed.pdu_type = bytes[1];
    parsed.event_count = bytes[2];
    parsed.padding = bytes[3];
    if (parsed.signature != RDP_CORE_INPUT_SIGNATURE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.pdu_type != RDP_CORE_INPUT_PDU_CS_INIT_REQUEST &&
        parsed.pdu_type != RDP_CORE_INPUT_PDU_SC_INIT_RESPONSE &&
        parsed.pdu_type != RDP_CORE_INPUT_PDU_CS_KEYBOARD_AND_MOUSE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.padding != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.pdu_type != RDP_CORE_INPUT_PDU_CS_KEYBOARD_AND_MOUSE && parsed.event_count != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *header = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_core_input_write_init_request(rdp_buffer* buffer)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_core_input_write_header(buffer, RDP_CORE_INPUT_PDU_CS_INIT_REQUEST, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, RDP_CORE_INPUT_PROTOCOL_VERSION_100);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, RDP_CORE_INPUT_PROTOCOL_VERSION_100);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_core_input_parse_init_response(const void* data,
                                                 size_t length,
                                                 rdp_core_input_init_response* response)
{
    rdp_core_input_init_response parsed;
    rdp_stream stream;
    rdp_core_input_header header;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 16)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_core_input_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.pdu_type != RDP_CORE_INPUT_PDU_SC_INIT_RESPONSE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.selected_protocol_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.protocol_version_max) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.selected_protocol_version == 0 ||
        parsed.selected_protocol_version > parsed.protocol_version_max)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *response = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_core_input_negotiate(const rdp_core_input_init_response* response,
                                       rdp_core_input_negotiation* negotiation)
{
    if (!response || !negotiation)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (response->selected_protocol_version == 0 ||
        response->selected_protocol_version > response->protocol_version_max ||
        response->protocol_version_max < RDP_CORE_INPUT_PROTOCOL_VERSION_100)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(negotiation, 0, sizeof(*negotiation));
    negotiation->selected_protocol_version =
        response->selected_protocol_version > RDP_CORE_INPUT_PROTOCOL_VERSION_100 ?
            RDP_CORE_INPUT_PROTOCOL_VERSION_100 :
            response->selected_protocol_version;
    negotiation->protocol_version_max = response->protocol_version_max;
    negotiation->supports_relative_mouse = 1;
    negotiation->supports_qoe_timestamp = 1;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_core_input_parse_events(const void* data,
                                          size_t length,
                                          rdp_core_input_event* events,
                                          uint8_t capacity,
                                          uint8_t* event_count)
{
    rdp_stream stream;
    rdp_core_input_header header;
    rdp_core_input_event parsed[UINT8_MAX + 1u];
    uint8_t i = 0;

    if (!data || !events || !event_count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_core_input_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.pdu_type != RDP_CORE_INPUT_PDU_CS_KEYBOARD_AND_MOUSE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.event_count > capacity)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < header.event_count; i++)
    {
        uint8_t packed = 0;
        uint8_t payload_len = 0;
        uint16_t dx = 0;
        uint16_t dy = 0;

        if (rdp_stream_read_u8(&stream, &packed) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        parsed[i].type = (uint8_t)((packed >> 5) & 0x07u);
        parsed[i].flags = (uint8_t)(packed & 0x1fu);
        payload_len = rdp_core_input_event_payload_len(parsed[i].type);
        if (payload_len == 0xffu || rdp_stream_remaining(&stream) < payload_len)
            return LIBRDP_STATUS_PROTOCOL_ERROR;

        if (parsed[i].type == RDP_CORE_INPUT_EVENT_SCANCODE)
        {
            if ((parsed[i].flags & ~(RDP_CORE_INPUT_KBDFLAGS_RELEASE |
                                     RDP_CORE_INPUT_KBDFLAGS_EXTENDED |
                                     RDP_CORE_INPUT_KBDFLAGS_EXTENDED1)) != 0 ||
                rdp_stream_read_u8(&stream, &parsed[i].scancode) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (parsed[i].type == RDP_CORE_INPUT_EVENT_UNICODE)
        {
            if ((parsed[i].flags & ~RDP_CORE_INPUT_KBDFLAGS_RELEASE) != 0 ||
                rdp_stream_read_u16_le(&stream, &parsed[i].unicode_code) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (parsed[i].type == RDP_CORE_INPUT_EVENT_SYNC)
        {
            if ((parsed[i].flags & ~(RDP_CORE_INPUT_SYNC_SCROLL_LOCK |
                                     RDP_CORE_INPUT_SYNC_NUM_LOCK |
                                     RDP_CORE_INPUT_SYNC_CAPS_LOCK |
                                     RDP_CORE_INPUT_SYNC_KANA_LOCK)) != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (parsed[i].type == RDP_CORE_INPUT_EVENT_QOE_TIMESTAMP)
        {
            if (parsed[i].flags != 0 ||
                rdp_stream_read_u32_le(&stream, &parsed[i].timestamp) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (parsed[i].type == RDP_CORE_INPUT_EVENT_RELMOUSE)
        {
            if (parsed[i].flags != 0 ||
                rdp_stream_read_u16_le(&stream, &parsed[i].pointer_flags) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u16_le(&stream, &dx) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u16_le(&stream, &dy) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            parsed[i].dx = (int16_t)dx;
            parsed[i].dy = (int16_t)dy;
        }
        else
        {
            if (parsed[i].flags != 0 ||
                rdp_stream_read_u16_le(&stream, &parsed[i].pointer_flags) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u16_le(&stream, &parsed[i].x) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u16_le(&stream, &parsed[i].y) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
    }
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(events, 0, sizeof(*events) * capacity);
    if (header.event_count > 0)
        memcpy(events, parsed, sizeof(*events) * header.event_count);
    *event_count = header.event_count;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_core_input_write_events(rdp_buffer* buffer,
                                          const rdp_core_input_event* events,
                                          uint8_t event_count)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t i = 0;
    size_t start = 0;

    if (!buffer || (!events && event_count > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < event_count; i++)
    {
        status = rdp_core_input_validate_event(&events[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }

    start = buffer->length;
    status = rdp_core_input_write_header(buffer, RDP_CORE_INPUT_PDU_CS_KEYBOARD_AND_MOUSE, event_count);
    for (i = 0; status == LIBRDP_STATUS_OK && i < event_count; i++)
    {
        status = rdp_buffer_append_u8(buffer, rdp_core_input_pack_event(events[i].type, events[i].flags));
        if (status != LIBRDP_STATUS_OK)
            break;
        if (events[i].type == RDP_CORE_INPUT_EVENT_SCANCODE)
            status = rdp_buffer_append_u8(buffer, events[i].scancode);
        else if (events[i].type == RDP_CORE_INPUT_EVENT_UNICODE)
            status = rdp_buffer_append_u16_le(buffer, events[i].unicode_code);
        else if (events[i].type == RDP_CORE_INPUT_EVENT_MOUSE ||
                 events[i].type == RDP_CORE_INPUT_EVENT_MOUSEX)
        {
            status = rdp_buffer_append_u16_le(buffer, events[i].pointer_flags);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(buffer, events[i].x);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(buffer, events[i].y);
        }
        else if (events[i].type == RDP_CORE_INPUT_EVENT_RELMOUSE)
        {
            status = rdp_buffer_append_u16_le(buffer, events[i].pointer_flags);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(buffer, (uint16_t)events[i].dx);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(buffer, (uint16_t)events[i].dy);
        }
        else if (events[i].type == RDP_CORE_INPUT_EVENT_QOE_TIMESTAMP)
            status = rdp_buffer_append_u32_le(buffer, events[i].timestamp);
    }
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_core_input_write_keyboard_event_ex(rdp_buffer* buffer, uint8_t scancode, uint8_t flags)
{
    rdp_core_input_event event;

    memset(&event, 0, sizeof(event));
    event.type = RDP_CORE_INPUT_EVENT_SCANCODE;
    event.flags = flags;
    event.scancode = scancode;
    return rdp_core_input_write_events(buffer, &event, 1);
}

librdp_status rdp_core_input_write_keyboard_event(rdp_buffer* buffer, uint8_t scancode, uint8_t released)
{
    return rdp_core_input_write_keyboard_event_ex(buffer,
                                                 scancode,
                                                 released ? RDP_CORE_INPUT_KBDFLAGS_RELEASE : 0);
}

librdp_status rdp_core_input_write_unicode_event(rdp_buffer* buffer, uint16_t code, uint8_t released)
{
    rdp_core_input_event event;

    memset(&event, 0, sizeof(event));
    event.type = RDP_CORE_INPUT_EVENT_UNICODE;
    event.flags = released ? RDP_CORE_INPUT_KBDFLAGS_RELEASE : 0;
    event.unicode_code = code;
    return rdp_core_input_write_events(buffer, &event, 1);
}

librdp_status rdp_core_input_write_sync_event(rdp_buffer* buffer, uint8_t flags)
{
    rdp_core_input_event event;

    memset(&event, 0, sizeof(event));
    event.type = RDP_CORE_INPUT_EVENT_SYNC;
    event.flags = flags;
    return rdp_core_input_write_events(buffer, &event, 1);
}

librdp_status rdp_core_input_write_mouse_event(rdp_buffer* buffer, uint16_t pointer_flags, uint16_t x, uint16_t y)
{
    rdp_core_input_event event;

    memset(&event, 0, sizeof(event));
    event.type = RDP_CORE_INPUT_EVENT_MOUSE;
    event.pointer_flags = pointer_flags;
    event.x = x;
    event.y = y;
    return rdp_core_input_write_events(buffer, &event, 1);
}

librdp_status rdp_core_input_write_extended_mouse_event(rdp_buffer* buffer,
                                                       uint16_t pointer_flags,
                                                       uint16_t x,
                                                       uint16_t y)
{
    rdp_core_input_event event;

    memset(&event, 0, sizeof(event));
    event.type = RDP_CORE_INPUT_EVENT_MOUSEX;
    event.pointer_flags = pointer_flags;
    event.x = x;
    event.y = y;
    return rdp_core_input_write_events(buffer, &event, 1);
}

librdp_status rdp_core_input_write_relative_mouse_event(rdp_buffer* buffer,
                                                       uint16_t pointer_flags,
                                                       int16_t dx,
                                                       int16_t dy)
{
    rdp_core_input_event event;

    memset(&event, 0, sizeof(event));
    event.type = RDP_CORE_INPUT_EVENT_RELMOUSE;
    event.pointer_flags = pointer_flags;
    event.dx = dx;
    event.dy = dy;
    return rdp_core_input_write_events(buffer, &event, 1);
}

librdp_status rdp_core_input_write_qoe_timestamp_event(rdp_buffer* buffer, uint32_t timestamp)
{
    rdp_core_input_event event;

    memset(&event, 0, sizeof(event));
    event.type = RDP_CORE_INPUT_EVENT_QOE_TIMESTAMP;
    event.timestamp = timestamp;
    return rdp_core_input_write_events(buffer, &event, 1);
}
