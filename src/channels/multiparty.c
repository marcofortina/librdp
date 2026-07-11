/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "channels/multiparty.h"

#include "common/stream.h"

#include <limits.h>
#include <string.h>

static int rdp_multiparty_valid_type(uint16_t type)
{
    return type >= RDP_MULTIPARTY_TYPE_FILTER_STATE_UPDATED &&
           type <= RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGE_RESPONSE;
}

static int rdp_multiparty_valid_filter_flags(uint8_t flags)
{
    return (flags & ~RDP_MULTIPARTY_FILTER_ENABLED) == 0;
}

static int rdp_multiparty_valid_share_flags(uint16_t flags, uint16_t allowed)
{
    return (flags & (uint16_t)~allowed) == 0;
}

static librdp_status rdp_multiparty_restore_on_error(rdp_buffer* buffer,
                                                     size_t start,
                                                     librdp_status status)
{
    if (status != LIBRDP_STATUS_OK && buffer)
        buffer->length = start;
    return status;
}

static librdp_status rdp_multiparty_parse_exact_header(const void* data,
                                                       size_t length,
                                                       uint16_t expected_type,
                                                       rdp_multiparty_header* header)
{
    if (rdp_multiparty_parse_header(data, length, header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header->type != expected_type || header->length != length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_parse_header(const void* data, size_t length, rdp_multiparty_header* header)
{
    rdp_multiparty_header parsed;
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u || length > UINT16_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &parsed.type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_multiparty_valid_type(parsed.type) ||
        parsed.length < 4u || parsed.length > length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.payload = (const uint8_t*)data + 4u;
    parsed.payload_len = (size_t)parsed.length - 4u;
    *header = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_header(rdp_buffer* buffer, uint16_t type, uint16_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !rdp_multiparty_valid_type(type) || payload_len > UINT16_MAX - 4u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u16_le(buffer, type);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)(payload_len + 4u));
    return rdp_multiparty_restore_on_error(buffer, start, status);
}

librdp_status rdp_multiparty_parse_message(const void* data,
                                           size_t length,
                                           rdp_multiparty_message* message)
{
    rdp_multiparty_header header;
    rdp_multiparty_message parsed;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !message)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_multiparty_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.type = header.type;
    switch (header.type)
    {
        case RDP_MULTIPARTY_TYPE_FILTER_STATE_UPDATED:
            status = rdp_multiparty_parse_filter_state(data, length, &parsed.body.filter_state);
            break;
        case RDP_MULTIPARTY_TYPE_APP_CREATED:
            status = rdp_multiparty_parse_app_created(data, length, &parsed.body.app_created);
            break;
        case RDP_MULTIPARTY_TYPE_APP_REMOVED:
        case RDP_MULTIPARTY_TYPE_WND_REMOVED:
        case RDP_MULTIPARTY_TYPE_WND_SHOW:
            status = rdp_multiparty_parse_id_message(data,
                                                     length,
                                                     header.type,
                                                     &parsed.body.id_message);
            break;
        case RDP_MULTIPARTY_TYPE_WND_CREATED:
            status = rdp_multiparty_parse_window_created(data, length, &parsed.body.window_created);
            break;
        case RDP_MULTIPARTY_TYPE_WND_REGION_UPDATE:
            status = rdp_multiparty_parse_region_update(data, length, &parsed.body.region_update);
            break;
        case RDP_MULTIPARTY_TYPE_PARTICIPANT_CREATED:
            status = rdp_multiparty_parse_participant_created(data,
                                                              length,
                                                              &parsed.body.participant_created);
            break;
        case RDP_MULTIPARTY_TYPE_PARTICIPANT_REMOVED:
            status = rdp_multiparty_parse_participant_removed(data,
                                                              length,
                                                              &parsed.body.participant_removed);
            break;
        case RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGED:
            status = rdp_multiparty_parse_control_change(data,
                                                         length,
                                                         &parsed.body.control_change);
            break;
        case RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGE_RESPONSE:
            status = rdp_multiparty_parse_control_change_response(
                data,
                length,
                &parsed.body.control_change_response);
            break;
        case RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_PAUSED:
        case RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_RESUMED:
            status = rdp_multiparty_parse_empty(data, length, header.type);
            if (status == LIBRDP_STATUS_OK)
                parsed.body.header = header;
            break;
        default:
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    *message = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_parse_string(const void* data,
                                          size_t length,
                                          rdp_multiparty_string* string,
                                          size_t* consumed)
{
    rdp_multiparty_string parsed;
    rdp_stream stream;
    size_t parsed_consumed = 0;

    if (!data || !string || !consumed)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &parsed.char_count) != LIBRDP_STATUS_OK ||
        parsed.char_count > RDP_MULTIPARTY_STRING_MAX_CHARS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.utf16_len = (size_t)parsed.char_count * 2u;
    if (parsed.utf16_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &parsed.utf16, parsed.utf16_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed_consumed = 2u + parsed.utf16_len;
    *string = parsed;
    *consumed = parsed_consumed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_string(rdp_buffer* buffer, const uint8_t* utf16, uint16_t char_count)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t byte_count = (size_t)char_count * 2u;
    size_t start = 0;

    if (!buffer || char_count > RDP_MULTIPARTY_STRING_MAX_CHARS || (!utf16 && char_count > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u16_le(buffer, char_count);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer, utf16, byte_count);
    return rdp_multiparty_restore_on_error(buffer, start, status);
}

librdp_status rdp_multiparty_parse_filter_state(const void* data,
                                                size_t length,
                                                rdp_multiparty_filter_state* state)
{
    rdp_multiparty_filter_state parsed;
    rdp_stream stream;

    if (!data || !state)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_multiparty_parse_exact_header(data,
                                          length,
                                          RDP_MULTIPARTY_TYPE_FILTER_STATE_UPDATED,
                                          &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.payload_len != 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u8(&stream, &parsed.flags) != LIBRDP_STATUS_OK ||
        !rdp_multiparty_valid_filter_flags(parsed.flags))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *state = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_filter_state(rdp_buffer* buffer, uint8_t flags)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !rdp_multiparty_valid_filter_flags(flags))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_multiparty_write_header(buffer, RDP_MULTIPARTY_TYPE_FILTER_STATE_UPDATED, 1u);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u8(buffer, flags);
    return rdp_multiparty_restore_on_error(buffer, start, status);
}

librdp_status rdp_multiparty_parse_app_created(const void* data,
                                               size_t length,
                                               rdp_multiparty_app_created* app)
{
    rdp_multiparty_app_created parsed;
    rdp_stream stream;
    size_t consumed = 0;

    if (!data || !app)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_multiparty_parse_exact_header(data,
                                          length,
                                          RDP_MULTIPARTY_TYPE_APP_CREATED,
                                          &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.payload_len < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u16_le(&stream, &parsed.flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.app_id) != LIBRDP_STATUS_OK ||
        !rdp_multiparty_valid_share_flags(parsed.flags, RDP_MULTIPARTY_APPLICATION_SHARED) ||
        rdp_multiparty_parse_string(parsed.header.payload + 6u,
                                    parsed.header.payload_len - 6u,
                                    &parsed.name,
                                    &consumed) != LIBRDP_STATUS_OK ||
        consumed != parsed.header.payload_len - 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *app = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_app_created(rdp_buffer* buffer,
                                               uint16_t flags,
                                               uint32_t app_id,
                                               const uint8_t* name_utf16,
                                               uint16_t name_chars)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t payload_len = 8u + (size_t)name_chars * 2u;
    size_t start = 0;

    if (!buffer || !rdp_multiparty_valid_share_flags(flags, RDP_MULTIPARTY_APPLICATION_SHARED) ||
        name_chars > RDP_MULTIPARTY_STRING_MAX_CHARS ||
        (!name_utf16 && name_chars > 0) ||
        payload_len > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_multiparty_write_header(buffer,
                                         RDP_MULTIPARTY_TYPE_APP_CREATED,
                                         (uint16_t)payload_len);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, flags);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, app_id);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_multiparty_write_string(buffer, name_utf16, name_chars);
    return rdp_multiparty_restore_on_error(buffer, start, status);
}

librdp_status rdp_multiparty_parse_id_message(const void* data,
                                              size_t length,
                                              uint16_t expected_type,
                                              rdp_multiparty_id_message* message)
{
    rdp_multiparty_id_message parsed;
    rdp_stream stream;

    if (!data || !message)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_multiparty_parse_exact_header(data, length, expected_type, &parsed.header) !=
            LIBRDP_STATUS_OK ||
        parsed.header.payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *message = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_id_message(rdp_buffer* buffer, uint16_t type, uint32_t id)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || (type != RDP_MULTIPARTY_TYPE_APP_REMOVED &&
                    type != RDP_MULTIPARTY_TYPE_WND_REMOVED &&
                    type != RDP_MULTIPARTY_TYPE_WND_SHOW))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_multiparty_write_header(buffer, type, 4u);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, id);
    return rdp_multiparty_restore_on_error(buffer, start, status);
}

librdp_status rdp_multiparty_parse_window_created(const void* data,
                                                  size_t length,
                                                  rdp_multiparty_window_created* window)
{
    rdp_multiparty_window_created parsed;
    rdp_stream stream;
    size_t consumed = 0;

    if (!data || !window)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_multiparty_parse_exact_header(data,
                                          length,
                                          RDP_MULTIPARTY_TYPE_WND_CREATED,
                                          &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.payload_len < 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u16_le(&stream, &parsed.flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.app_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.window_id) != LIBRDP_STATUS_OK ||
        !rdp_multiparty_valid_share_flags(parsed.flags, RDP_MULTIPARTY_WINDOW_SHARED) ||
        rdp_multiparty_parse_string(parsed.header.payload + 10u,
                                    parsed.header.payload_len - 10u,
                                    &parsed.name,
                                    &consumed) != LIBRDP_STATUS_OK ||
        consumed != parsed.header.payload_len - 10u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *window = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_window_created(rdp_buffer* buffer,
                                                  uint16_t flags,
                                                  uint32_t app_id,
                                                  uint32_t window_id,
                                                  const uint8_t* name_utf16,
                                                  uint16_t name_chars)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t payload_len = 12u + (size_t)name_chars * 2u;
    size_t start = 0;

    if (!buffer || !rdp_multiparty_valid_share_flags(flags, RDP_MULTIPARTY_WINDOW_SHARED) ||
        name_chars > RDP_MULTIPARTY_STRING_MAX_CHARS ||
        (!name_utf16 && name_chars > 0) ||
        payload_len > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_multiparty_write_header(buffer,
                                         RDP_MULTIPARTY_TYPE_WND_CREATED,
                                         (uint16_t)payload_len);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, flags);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, app_id);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, window_id);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_multiparty_write_string(buffer, name_utf16, name_chars);
    return rdp_multiparty_restore_on_error(buffer, start, status);
}

librdp_status rdp_multiparty_parse_region_update(const void* data,
                                                 size_t length,
                                                 rdp_multiparty_region_update* region)
{
    rdp_multiparty_region_update parsed;
    rdp_stream stream;

    if (!data || !region)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_multiparty_parse_exact_header(data,
                                          length,
                                          RDP_MULTIPARTY_TYPE_WND_REGION_UPDATE,
                                          &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.payload_len != 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.left) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.top) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.right) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.bottom) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.right < parsed.left || parsed.bottom < parsed.top)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *region = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_region_update(rdp_buffer* buffer,
                                                 uint32_t left,
                                                 uint32_t top,
                                                 uint32_t right,
                                                 uint32_t bottom)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || right < left || bottom < top)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_multiparty_write_header(buffer, RDP_MULTIPARTY_TYPE_WND_REGION_UPDATE, 16u);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, left);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, top);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, right);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, bottom);
    return rdp_multiparty_restore_on_error(buffer, start, status);
}

librdp_status rdp_multiparty_parse_participant_created(
    const void* data,
    size_t length,
    rdp_multiparty_participant_created* participant)
{
    rdp_multiparty_participant_created parsed;
    rdp_stream stream;
    size_t consumed = 0;

    if (!data || !participant)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_multiparty_parse_exact_header(data,
                                          length,
                                          RDP_MULTIPARTY_TYPE_PARTICIPANT_CREATED,
                                          &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.payload_len < 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.participant_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.group_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.flags) != LIBRDP_STATUS_OK ||
        !rdp_multiparty_valid_share_flags(parsed.flags,
                                          RDP_MULTIPARTY_MAY_VIEW |
                                          RDP_MULTIPARTY_MAY_INTERACT |
                                          RDP_MULTIPARTY_IS_PARTICIPANT) ||
        rdp_multiparty_parse_string(parsed.header.payload + 10u,
                                    parsed.header.payload_len - 10u,
                                    &parsed.friendly_name,
                                    &consumed) != LIBRDP_STATUS_OK ||
        consumed != parsed.header.payload_len - 10u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *participant = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_participant_created(rdp_buffer* buffer,
                                                       uint32_t participant_id,
                                                       uint32_t group_id,
                                                       uint16_t flags,
                                                       const uint8_t* name_utf16,
                                                       uint16_t name_chars)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t payload_len = 12u + (size_t)name_chars * 2u;
    size_t start = 0;

    if (!buffer ||
        !rdp_multiparty_valid_share_flags(flags,
                                          RDP_MULTIPARTY_MAY_VIEW |
                                          RDP_MULTIPARTY_MAY_INTERACT |
                                          RDP_MULTIPARTY_IS_PARTICIPANT) ||
        name_chars > RDP_MULTIPARTY_STRING_MAX_CHARS ||
        (!name_utf16 && name_chars > 0) ||
        payload_len > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_multiparty_write_header(buffer,
                                         RDP_MULTIPARTY_TYPE_PARTICIPANT_CREATED,
                                         (uint16_t)payload_len);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, participant_id);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, group_id);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, flags);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_multiparty_write_string(buffer, name_utf16, name_chars);
    return rdp_multiparty_restore_on_error(buffer, start, status);
}

librdp_status rdp_multiparty_parse_participant_removed(
    const void* data,
    size_t length,
    rdp_multiparty_participant_removed* participant)
{
    rdp_multiparty_participant_removed parsed;
    rdp_stream stream;

    if (!data || !participant)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_multiparty_parse_exact_header(data,
                                          length,
                                          RDP_MULTIPARTY_TYPE_PARTICIPANT_REMOVED,
                                          &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.payload_len != 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.participant_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.disconnect_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.disconnect_code) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *participant = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_participant_removed(rdp_buffer* buffer,
                                                       uint32_t participant_id,
                                                       uint32_t disconnect_type,
                                                       uint32_t disconnect_code)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_multiparty_write_header(buffer, RDP_MULTIPARTY_TYPE_PARTICIPANT_REMOVED, 12u);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, participant_id);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, disconnect_type);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, disconnect_code);
    return rdp_multiparty_restore_on_error(buffer, start, status);
}

librdp_status rdp_multiparty_parse_control_change(const void* data,
                                                  size_t length,
                                                  rdp_multiparty_control_change* change)
{
    rdp_multiparty_control_change parsed;
    rdp_stream stream;

    if (!data || !change)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_multiparty_parse_exact_header(data,
                                          length,
                                          RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGED,
                                          &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.payload_len != 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u16_le(&stream, &parsed.flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.participant_id) != LIBRDP_STATUS_OK ||
        !rdp_multiparty_valid_share_flags(parsed.flags,
                                          RDP_MULTIPARTY_REQUEST_VIEW |
                                          RDP_MULTIPARTY_REQUEST_INTERACT |
                                          RDP_MULTIPARTY_ALLOW_CONTROL_REQUESTS))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *change = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_control_change(rdp_buffer* buffer,
                                                  uint16_t flags,
                                                  uint32_t participant_id)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer ||
        !rdp_multiparty_valid_share_flags(flags,
                                          RDP_MULTIPARTY_REQUEST_VIEW |
                                          RDP_MULTIPARTY_REQUEST_INTERACT |
                                          RDP_MULTIPARTY_ALLOW_CONTROL_REQUESTS))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_multiparty_write_header(buffer, RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGED, 6u);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, flags);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, participant_id);
    return rdp_multiparty_restore_on_error(buffer, start, status);
}

librdp_status rdp_multiparty_parse_control_change_response(
    const void* data,
    size_t length,
    rdp_multiparty_control_change_response* response)
{
    rdp_multiparty_control_change_response parsed;
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_multiparty_parse_exact_header(data,
                                          length,
                                          RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGE_RESPONSE,
                                          &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.payload_len != 10u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u16_le(&stream, &parsed.flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.participant_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.reason_code) != LIBRDP_STATUS_OK ||
        !rdp_multiparty_valid_share_flags(parsed.flags,
                                          RDP_MULTIPARTY_REQUEST_VIEW |
                                          RDP_MULTIPARTY_REQUEST_INTERACT |
                                          RDP_MULTIPARTY_ALLOW_CONTROL_REQUESTS))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *response = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_control_change_response(rdp_buffer* buffer,
                                                           uint16_t flags,
                                                           uint32_t participant_id,
                                                           uint32_t reason_code)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer ||
        !rdp_multiparty_valid_share_flags(flags,
                                          RDP_MULTIPARTY_REQUEST_VIEW |
                                          RDP_MULTIPARTY_REQUEST_INTERACT |
                                          RDP_MULTIPARTY_ALLOW_CONTROL_REQUESTS))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_multiparty_write_header(buffer,
                                         RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGE_RESPONSE,
                                         10u);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, flags);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, participant_id);
    if (status != LIBRDP_STATUS_OK)
        return rdp_multiparty_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, reason_code);
    return rdp_multiparty_restore_on_error(buffer, start, status);
}

librdp_status rdp_multiparty_parse_empty(const void* data, size_t length, uint16_t expected_type)
{
    rdp_multiparty_header header;

    if (!data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_multiparty_parse_exact_header(data, length, expected_type, &header) != LIBRDP_STATUS_OK ||
        header.payload_len != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_empty(rdp_buffer* buffer, uint16_t type)
{
    if (!buffer || (type != RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_PAUSED &&
                    type != RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_RESUMED))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_multiparty_write_header(buffer, type, 0);
}
