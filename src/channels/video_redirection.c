/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: video redirection presentation and media packet helpers.
 * Invariants: channel payload lengths and negotiated capabilities are checked
 * before state changes or callbacks.
 * Ownership: parsed channel objects are caller-owned unless the session stores
 * an explicit copy.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths remain local policy inputs.
 */


#include "channels/video_redirection.h"

#include "common/stream.h"

#include <string.h>

static int rdp_video_redirection_valid_stream_mask(uint32_t stream_mask)
{
    return stream_mask == RDP_VIDEO_REDIRECTION_STREAM_ID_NONE ||
           stream_mask == RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY ||
           stream_mask == RDP_VIDEO_REDIRECTION_STREAM_ID_STUB;
}

static int rdp_video_redirection_geometry_info_valid(const rdp_video_redirection_geometry_info* info);

static int rdp_video_redirection_valid_capability_type(uint32_t type)
{
    return type == RDP_VIDEO_REDIRECTION_CAPABILITY_PROTOCOL_VERSION ||
           type == RDP_VIDEO_REDIRECTION_CAPABILITY_PLATFORM ||
           type == RDP_VIDEO_REDIRECTION_CAPABILITY_AUDIO_SUPPORT ||
           type == RDP_VIDEO_REDIRECTION_CAPABILITY_LATENCY;
}

static librdp_status rdp_video_redirection_read_u64_le(rdp_stream* stream, uint64_t* value)
{
    uint32_t low = 0;
    uint32_t high = 0;

    if (!stream || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u32_le(stream, &low) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &high) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = ((uint64_t)high << 32) | low;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_video_redirection_append_u64_le(rdp_buffer* buffer, uint64_t value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, (uint32_t)(value & 0xffffffffu));
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, (uint32_t)((value >> 32) & 0xffffffffu));
}

static librdp_status rdp_video_redirection_read_guid(rdp_stream* stream, uint8_t guid[16])
{
    const uint8_t* data = NULL;

    if (!stream || !guid)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_bytes(stream, &data, 16u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(guid, data, 16u);
    return LIBRDP_STATUS_OK;
}

static int rdp_video_redirection_header_matches(
    const rdp_video_redirection_header* header,
    uint32_t interface_id,
    uint32_t stream_mask,
    uint32_t function_id)
{
    return header &&
           header->has_function_id &&
           header->interface_id == interface_id &&
           header->stream_id_mask == stream_mask &&
           header->function_id == function_id;
}

static librdp_status rdp_video_redirection_parse_capability_list_from_stream(
    rdp_stream* stream,
    rdp_video_redirection_capability_list* list,
    uint32_t count)
{
    uint32_t i = 0;

    if (!stream || !list)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (count > RDP_VIDEO_REDIRECTION_MAX_CAPABILITIES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(list, 0, sizeof(*list));
    list->count = count;
    for (i = 0; i < count; i++)
    {
        rdp_video_redirection_capability* capability = &list->capabilities[i];

        if (rdp_stream_read_u32_le(stream, &capability->type) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(stream, &capability->length) != LIBRDP_STATUS_OK ||
            !rdp_video_redirection_valid_capability_type(capability->type) ||
            capability->length != 4u ||
            capability->length > rdp_stream_remaining(stream) ||
            rdp_stream_read_bytes(stream, &capability->data, capability->length) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        capability->data_len = capability->length;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_video_redirection_write_capability_list(
    rdp_buffer* buffer,
    const rdp_video_redirection_capability* capabilities,
    uint32_t count)
{
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (count > 0 && !capabilities) ||
        count > RDP_VIDEO_REDIRECTION_MAX_CAPABILITIES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < count; i++)
    {
        if (!capabilities[i].data ||
            capabilities[i].length != capabilities[i].data_len ||
            !rdp_video_redirection_valid_capability_type(capabilities[i].type) ||
            capabilities[i].length != 4u)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        status = rdp_buffer_append_u32_le(buffer, capabilities[i].type);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append_u32_le(buffer, capabilities[i].length);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append(buffer, capabilities[i].data, capabilities[i].data_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_video_redirection_parse_capability_request_payload(
    const rdp_video_redirection_header* header,
    rdp_video_redirection_capability_message* request)
{
    rdp_stream stream;
    uint32_t count = 0;

    if (!header || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, header->payload, header->payload_len);
    if (rdp_stream_read_u32_le(&stream, &count) != LIBRDP_STATUS_OK ||
        rdp_video_redirection_parse_capability_list_from_stream(&stream,
                                                                &request->capabilities,
                                                                count) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_video_redirection_parse_capability_response_payload(
    const rdp_video_redirection_header* header,
    rdp_video_redirection_capability_message* response)
{
    rdp_stream stream;
    uint32_t count = 0;

    if (!header || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->payload_len < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, header->payload, header->payload_len);
    if (rdp_stream_read_u32_le(&stream, &count) != LIBRDP_STATUS_OK ||
        rdp_video_redirection_parse_capability_list_from_stream(&stream,
                                                                &response->capabilities,
                                                                count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &response->result) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    response->has_result = 1u;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_video_redirection_parse_payload_guid(
    const rdp_video_redirection_header* header,
    uint8_t presentation_id[16],
    rdp_stream* stream)
{
    if (!header || !presentation_id || !stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->payload_len < 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(stream, header->payload, header->payload_len);
    return rdp_video_redirection_read_guid(stream, presentation_id);
}

static librdp_status rdp_video_redirection_write_default_header(
    rdp_buffer* buffer,
    uint32_t message_id,
    uint32_t function_id)
{
    return rdp_video_redirection_write_header(buffer,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              message_id,
                                              1,
                                              function_id);
}

static librdp_status rdp_video_redirection_append_presentation_id(
    rdp_buffer* buffer,
    const uint8_t* presentation_id)
{
    if (!buffer || !presentation_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append(buffer, presentation_id, 16u);
}

static librdp_status rdp_video_redirection_write_stream_data(
    rdp_buffer* buffer,
    uint32_t message_id,
    uint32_t function_id,
    const uint8_t* presentation_id,
    uint32_t stream_id,
    const void* data,
    uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !presentation_id || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_default_header(buffer, message_id, function_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_redirection_append_presentation_id(buffer, presentation_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, stream_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, data_len);
}

librdp_status rdp_video_redirection_parse_header(
    const void* data,
    size_t length,
    uint8_t has_function_id,
    rdp_video_redirection_header* header)
{
    rdp_video_redirection_header parsed;
    rdp_stream stream;
    size_t fixed_len = has_function_id ? 12u : 8u;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < fixed_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &parsed.raw_interface_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.message_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.interface_id = parsed.raw_interface_id & RDP_VIDEO_REDIRECTION_INTERFACE_VALUE_MASK;
    parsed.stream_id_mask = parsed.raw_interface_id & ~RDP_VIDEO_REDIRECTION_INTERFACE_VALUE_MASK;
    if (!rdp_video_redirection_valid_stream_mask(parsed.stream_id_mask))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.has_function_id = has_function_id ? 1u : 0u;
    if (has_function_id &&
        rdp_stream_read_u32_le(&stream, &parsed.function_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.payload_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &parsed.payload, parsed.payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *header = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_write_set_channel_params(
    rdp_buffer* buffer,
    uint32_t message_id,
    const uint8_t* presentation_id,
    uint32_t stream_id)
{
    return rdp_video_redirection_write_stream_only(buffer,
                                                  message_id,
                                                  RDP_VIDEO_REDIRECTION_FUNC_SET_CHANNEL_PARAMS,
                                                  presentation_id,
                                                  stream_id);
}

librdp_status rdp_video_redirection_write_new_presentation(
    rdp_buffer* buffer,
    uint32_t message_id,
    const uint8_t* presentation_id,
    uint32_t platform_cookie)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !presentation_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_default_header(buffer,
                                                        message_id,
                                                        RDP_VIDEO_REDIRECTION_FUNC_ON_NEW_PRESENTATION);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_redirection_append_presentation_id(buffer, presentation_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, platform_cookie);
}

librdp_status rdp_video_redirection_write_add_stream(
    rdp_buffer* buffer,
    uint32_t message_id,
    const uint8_t* presentation_id,
    uint32_t stream_id,
    const void* data,
    uint32_t data_len)
{
    return rdp_video_redirection_write_stream_data(buffer,
                                                  message_id,
                                                  RDP_VIDEO_REDIRECTION_FUNC_ADD_STREAM,
                                                  presentation_id,
                                                  stream_id,
                                                  data,
                                                  data_len);
}

librdp_status rdp_video_redirection_write_presentation_only(
    rdp_buffer* buffer,
    uint32_t message_id,
    uint32_t function_id,
    const uint8_t* presentation_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !presentation_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_default_header(buffer, message_id, function_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_video_redirection_append_presentation_id(buffer, presentation_id);
}

librdp_status rdp_video_redirection_write_stream_only(
    rdp_buffer* buffer,
    uint32_t message_id,
    uint32_t function_id,
    const uint8_t* presentation_id,
    uint32_t stream_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !presentation_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_default_header(buffer, message_id, function_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_redirection_append_presentation_id(buffer, presentation_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, stream_id);
}

librdp_status rdp_video_redirection_write_playback_started(
    rdp_buffer* buffer,
    uint32_t message_id,
    const uint8_t* presentation_id,
    uint64_t playback_start_offset,
    uint32_t is_seek)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !presentation_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_default_header(buffer,
                                                        message_id,
                                                        RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_STARTED);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_redirection_append_presentation_id(buffer, presentation_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_redirection_append_u64_le(buffer, playback_start_offset);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, is_seek);
}

librdp_status rdp_video_redirection_write_playback_rate(
    rdp_buffer* buffer,
    uint32_t message_id,
    const uint8_t* presentation_id,
    uint32_t rate_bits)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !presentation_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_default_header(buffer,
                                                        message_id,
                                                        RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_RATE_CHANGED);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_redirection_append_presentation_id(buffer, presentation_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, rate_bits);
}

librdp_status rdp_video_redirection_write_sample_message(
    rdp_buffer* buffer,
    uint32_t message_id,
    const uint8_t* presentation_id,
    uint32_t stream_id,
    const void* data,
    uint32_t data_len)
{
    return rdp_video_redirection_write_stream_data(buffer,
                                                  message_id,
                                                  RDP_VIDEO_REDIRECTION_FUNC_ON_SAMPLE,
                                                  presentation_id,
                                                  stream_id,
                                                  data,
                                                  data_len);
}

librdp_status rdp_video_redirection_write_set_video_window(
    rdp_buffer* buffer,
    uint32_t message_id,
    const uint8_t* presentation_id,
    uint64_t video_window_id,
    uint64_t parent_window_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !presentation_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_default_header(buffer,
                                                        message_id,
                                                        RDP_VIDEO_REDIRECTION_FUNC_SET_VIDEO_WINDOW);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_redirection_append_presentation_id(buffer, presentation_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_redirection_append_u64_le(buffer, video_window_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_video_redirection_append_u64_le(buffer, parent_window_id);
}

librdp_status rdp_video_redirection_write_geometry_update(
    rdp_buffer* buffer,
    uint32_t message_id,
    const uint8_t* presentation_id,
    const void* geometry,
    uint32_t geometry_len,
    const void* visible_rect,
    uint32_t visible_rect_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !presentation_id || (!geometry && geometry_len > 0) ||
        (!visible_rect && visible_rect_len > 0) ||
        visible_rect_len % 16u != 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_default_header(buffer,
                                                        message_id,
                                                        RDP_VIDEO_REDIRECTION_FUNC_UPDATE_GEOMETRY_INFO);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_redirection_append_presentation_id(buffer, presentation_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, geometry_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, geometry, geometry_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, visible_rect_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, visible_rect, visible_rect_len);
}

librdp_status rdp_video_redirection_write_geometry_info(
    rdp_buffer* buffer,
    const rdp_video_redirection_geometry_info* info)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !info || !rdp_video_redirection_geometry_info_valid(info))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_append_u64_le(buffer, info->video_window_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, info->window_state);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, info->width);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, info->height);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, info->left);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, info->top);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_redirection_append_u64_le(buffer, info->reserved);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, info->client_left);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, info->client_top);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (info->has_padding)
        return rdp_buffer_append_u32_le(buffer, info->padding);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_write_rect(
    rdp_buffer* buffer,
    uint32_t top,
    uint32_t left,
    uint32_t bottom,
    uint32_t right)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || top >= bottom || left >= right)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, top);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, left);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, bottom);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, right);
}

librdp_status rdp_video_redirection_write_stream_volume(
    rdp_buffer* buffer,
    uint32_t message_id,
    const uint8_t* presentation_id,
    uint32_t value,
    uint32_t second_value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !presentation_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_default_header(buffer,
                                                        message_id,
                                                        RDP_VIDEO_REDIRECTION_FUNC_ON_STREAM_VOLUME);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_redirection_append_presentation_id(buffer, presentation_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, value);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, second_value);
}

librdp_status rdp_video_redirection_write_channel_volume(
    rdp_buffer* buffer,
    uint32_t message_id,
    const uint8_t* presentation_id,
    uint32_t value,
    uint32_t second_value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !presentation_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_default_header(buffer,
                                                        message_id,
                                                        RDP_VIDEO_REDIRECTION_FUNC_ON_CHANNEL_VOLUME);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_redirection_append_presentation_id(buffer, presentation_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, value);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, second_value);
}

librdp_status rdp_video_redirection_write_header(
    rdp_buffer* buffer,
    uint32_t interface_id,
    uint32_t stream_id_mask,
    uint32_t message_id,
    uint8_t has_function_id,
    uint32_t function_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer ||
        interface_id > RDP_VIDEO_REDIRECTION_INTERFACE_VALUE_MASK ||
        !rdp_video_redirection_valid_stream_mask(stream_id_mask))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, interface_id | stream_id_mask);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, message_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (has_function_id)
        return rdp_buffer_append_u32_le(buffer, function_id);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_rim_capability_request(
    const void* data,
    size_t length,
    rdp_video_redirection_rim_capability* request)
{
    rdp_video_redirection_rim_capability parsed;
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_RIM_CAPABILITIES,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_NONE,
                                              RDP_VIDEO_REDIRECTION_FUNC_RIM_EXCHANGE_CAPABILITY_REQUEST) ||
        parsed.header.payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.capability) != LIBRDP_STATUS_OK ||
        parsed.capability != RDP_VIDEO_REDIRECTION_RIM_CAPABILITY_VERSION_01)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *request = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_write_rim_capability_request(
    rdp_buffer* buffer,
    uint32_t message_id,
    uint32_t capability)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || capability != RDP_VIDEO_REDIRECTION_RIM_CAPABILITY_VERSION_01)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_header(buffer,
                                                RDP_VIDEO_REDIRECTION_INTERFACE_RIM_CAPABILITIES,
                                                RDP_VIDEO_REDIRECTION_STREAM_ID_NONE,
                                                message_id,
                                                1,
                                                RDP_VIDEO_REDIRECTION_FUNC_RIM_EXCHANGE_CAPABILITY_REQUEST);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, capability);
}

librdp_status rdp_video_redirection_write_rim_capability_response(
    rdp_buffer* buffer,
    uint32_t message_id,
    uint32_t capability,
    uint32_t result)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || capability != RDP_VIDEO_REDIRECTION_RIM_CAPABILITY_VERSION_01)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_header(buffer,
                                                RDP_VIDEO_REDIRECTION_INTERFACE_RIM_CAPABILITIES,
                                                RDP_VIDEO_REDIRECTION_STREAM_ID_NONE,
                                                message_id,
                                                0,
                                                0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, capability);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, result);
}

librdp_status rdp_video_redirection_parse_rim_capability_response(
    const void* data,
    size_t length,
    rdp_video_redirection_rim_capability* response)
{
    rdp_video_redirection_rim_capability parsed;
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 0, &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.interface_id != RDP_VIDEO_REDIRECTION_INTERFACE_RIM_CAPABILITIES ||
        parsed.header.stream_id_mask != RDP_VIDEO_REDIRECTION_STREAM_ID_NONE ||
        parsed.header.payload_len != 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.capability) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.result) != LIBRDP_STATUS_OK ||
        parsed.capability != RDP_VIDEO_REDIRECTION_RIM_CAPABILITY_VERSION_01)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.has_result = 1u;
    *response = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_exchange_capabilities_request(
    const void* data,
    size_t length,
    rdp_video_redirection_capability_message* request)
{
    rdp_video_redirection_capability_message parsed;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              RDP_VIDEO_REDIRECTION_FUNC_EXCHANGE_CAPABILITIES_REQ))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_video_redirection_parse_capability_request_payload(&parsed.header, &parsed) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *request = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_write_exchange_capabilities_request(
    rdp_buffer* buffer,
    uint32_t message_id,
    const rdp_video_redirection_capability* capabilities,
    uint32_t count)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_header(buffer,
                                                RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                                RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                                message_id,
                                                1,
                                                RDP_VIDEO_REDIRECTION_FUNC_EXCHANGE_CAPABILITIES_REQ);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_video_redirection_write_capability_list(buffer, capabilities, count);
}

librdp_status rdp_video_redirection_write_exchange_capabilities_response(
    rdp_buffer* buffer,
    uint32_t message_id,
    const rdp_video_redirection_capability* capabilities,
    uint32_t count,
    uint32_t result)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_header(buffer,
                                                RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                                RDP_VIDEO_REDIRECTION_STREAM_ID_STUB,
                                                message_id,
                                                0,
                                                0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_redirection_write_capability_list(buffer, capabilities, count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, result);
}

librdp_status rdp_video_redirection_parse_exchange_capabilities_response(
    const void* data,
    size_t length,
    rdp_video_redirection_capability_message* response)
{
    rdp_video_redirection_capability_message parsed;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 0, &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.interface_id != RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT ||
        parsed.header.stream_id_mask != RDP_VIDEO_REDIRECTION_STREAM_ID_STUB)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_video_redirection_parse_capability_response_payload(&parsed.header, &parsed) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *response = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_write_u32_capability(
    rdp_buffer* buffer,
    uint32_t capability_type,
    uint32_t value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_video_redirection_valid_capability_type(capability_type))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, capability_type);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, 4u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, value);
}

librdp_status rdp_video_redirection_parse_check_format_support_request(
    const void* data,
    size_t length,
    rdp_video_redirection_format_support_request* request)
{
    rdp_video_redirection_format_support_request parsed;
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              RDP_VIDEO_REDIRECTION_FUNC_CHECK_FORMAT_SUPPORT_REQ) ||
        parsed.header.payload_len < 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.platform_cookie) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.no_rollover_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.media_type_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.media_types_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream,
                              &parsed.media_types,
                              parsed.media_types_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.media_type_count == 0 && parsed.media_types_len != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.media_type_count != 0 && parsed.media_types_len == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *request = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_write_check_format_support_response(
    rdp_buffer* buffer,
    uint32_t message_id,
    uint32_t format_supported,
    uint32_t platform_cookie,
    uint32_t result)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || format_supported > 1u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_header(buffer,
                                                RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                                RDP_VIDEO_REDIRECTION_STREAM_ID_STUB,
                                                message_id,
                                                0,
                                                0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, format_supported);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, platform_cookie);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, result);
}

librdp_status rdp_video_redirection_parse_check_format_support_response(
    const void* data,
    size_t length,
    rdp_video_redirection_format_support_response* response)
{
    rdp_video_redirection_format_support_response parsed;
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 0, &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.interface_id != RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT ||
        parsed.header.stream_id_mask != RDP_VIDEO_REDIRECTION_STREAM_ID_STUB ||
        parsed.header.payload_len != 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.format_supported) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.platform_cookie) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.result) != LIBRDP_STATUS_OK ||
        parsed.format_supported > 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *response = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_write_set_topology_response(
    rdp_buffer* buffer,
    uint32_t message_id,
    uint32_t topology_ready,
    uint32_t result)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || topology_ready > 1u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_header(buffer,
                                                RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                                RDP_VIDEO_REDIRECTION_STREAM_ID_STUB,
                                                message_id,
                                                0,
                                                0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, topology_ready);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, result);
}

librdp_status rdp_video_redirection_parse_set_topology_response(
    const void* data,
    size_t length,
    rdp_video_redirection_topology_response* response)
{
    rdp_video_redirection_topology_response parsed;
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 0, &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.interface_id != RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT ||
        parsed.header.stream_id_mask != RDP_VIDEO_REDIRECTION_STREAM_ID_STUB ||
        parsed.header.payload_len != 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.topology_ready) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.result) != LIBRDP_STATUS_OK ||
        parsed.topology_ready > 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *response = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_media_type(
    const void* data,
    size_t length,
    rdp_video_redirection_media_type* media_type)
{
    rdp_video_redirection_media_type parsed;
    rdp_stream stream;
    const uint8_t* guid = NULL;

    if (!data || !media_type)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 64u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_bytes(&stream, &guid, 16u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(parsed.major_type, guid, 16u);
    if (rdp_stream_read_bytes(&stream, &guid, 16u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(parsed.sub_type, guid, 16u);
    if (rdp_stream_read_u32_le(&stream, &parsed.fixed_size_samples) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.temporal_compression) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.sample_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &guid, 16u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(parsed.format_type, guid, 16u);
    if (rdp_stream_read_u32_le(&stream, &parsed.format_len) != LIBRDP_STATUS_OK ||
        parsed.format_len != rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &parsed.format, parsed.format_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *media_type = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_write_media_type(
    rdp_buffer* buffer,
    const uint8_t major_type[16],
    const uint8_t sub_type[16],
    uint32_t fixed_size_samples,
    uint32_t temporal_compression,
    uint32_t sample_size,
    const uint8_t format_type[16],
    const void* format,
    uint32_t format_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !major_type || !sub_type || !format_type || (!format && format_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append(buffer, major_type, 16u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, sub_type, 16u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, fixed_size_samples);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, temporal_compression);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, sample_size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, format_type, 16u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, format_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, format, format_len);
}

librdp_status rdp_video_redirection_parse_data_sample(
    const void* data,
    size_t length,
    rdp_video_redirection_data_sample* sample)
{
    rdp_video_redirection_data_sample parsed;
    rdp_stream stream;

    if (!data || !sample)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 36u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_video_redirection_read_u64_le(&stream, &parsed.sample_start_time) != LIBRDP_STATUS_OK ||
        rdp_video_redirection_read_u64_le(&stream, &parsed.sample_end_time) != LIBRDP_STATUS_OK ||
        rdp_video_redirection_read_u64_le(&stream, &parsed.throttle_duration) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.sample_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.sample_extensions) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.data_len) != LIBRDP_STATUS_OK ||
        parsed.data_len != rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &parsed.data, parsed.data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.sample_end_time < parsed.sample_start_time)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *sample = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_write_data_sample(
    rdp_buffer* buffer,
    uint64_t sample_start_time,
    uint64_t sample_end_time,
    uint64_t throttle_duration,
    uint32_t sample_flags,
    uint32_t sample_extensions,
    const void* data,
    uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0) || sample_end_time < sample_start_time)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_append_u64_le(buffer, sample_start_time);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_redirection_append_u64_le(buffer, sample_end_time);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_redirection_append_u64_le(buffer, throttle_duration);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, sample_flags);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, sample_extensions);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, data_len);
}

librdp_status rdp_video_redirection_write_playback_ack(
    rdp_buffer* buffer,
    uint32_t message_id,
    uint32_t stream_id,
    uint64_t data_duration,
    uint64_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_video_redirection_write_header(buffer,
                                                RDP_VIDEO_REDIRECTION_INTERFACE_CLIENT_NOTIFICATIONS,
                                                RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                                message_id,
                                                1,
                                                RDP_VIDEO_REDIRECTION_FUNC_PLAYBACK_ACK);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, stream_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_redirection_append_u64_le(buffer, data_duration);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_video_redirection_append_u64_le(buffer, data_len);
}

librdp_status rdp_video_redirection_parse_playback_ack(
    const void* data,
    size_t length,
    rdp_video_redirection_playback_ack* ack)
{
    rdp_video_redirection_playback_ack parsed;
    rdp_stream stream;

    if (!data || !ack)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_CLIENT_NOTIFICATIONS,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              RDP_VIDEO_REDIRECTION_FUNC_PLAYBACK_ACK) ||
        parsed.header.payload_len != 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.stream_id) != LIBRDP_STATUS_OK ||
        rdp_video_redirection_read_u64_le(&stream, &parsed.data_duration) != LIBRDP_STATUS_OK ||
        rdp_video_redirection_read_u64_le(&stream, &parsed.data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *ack = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_write_client_event(
    rdp_buffer* buffer,
    uint32_t message_id,
    uint32_t stream_id,
    uint32_t event_id,
    const void* data,
    uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_write_header(buffer,
                                                RDP_VIDEO_REDIRECTION_INTERFACE_CLIENT_NOTIFICATIONS,
                                                RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                                message_id,
                                                1,
                                                RDP_VIDEO_REDIRECTION_FUNC_CLIENT_EVENT_NOTIFICATION);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, stream_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, event_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, data_len);
}

librdp_status rdp_video_redirection_parse_client_event(
    const void* data,
    size_t length,
    rdp_video_redirection_client_event* event)
{
    rdp_video_redirection_client_event parsed;
    rdp_stream stream;

    if (!data || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_CLIENT_NOTIFICATIONS,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              RDP_VIDEO_REDIRECTION_FUNC_CLIENT_EVENT_NOTIFICATION) ||
        parsed.header.payload_len < 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.stream_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.event_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.data_len) != LIBRDP_STATUS_OK ||
        parsed.data_len != rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &parsed.data, parsed.data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *event = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_set_channel_params(
    const void* data,
    size_t length,
    rdp_video_redirection_stream* params)
{
    rdp_video_redirection_stream parsed;
    rdp_stream stream;

    if (!data || !params)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              RDP_VIDEO_REDIRECTION_FUNC_SET_CHANNEL_PARAMS) ||
        parsed.header.payload_len != 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_video_redirection_read_guid(&stream, parsed.presentation_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.stream_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *params = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_new_presentation(
    const void* data,
    size_t length,
    rdp_video_redirection_presentation* presentation)
{
    rdp_video_redirection_presentation parsed;
    rdp_stream stream;

    if (!data || !presentation)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              RDP_VIDEO_REDIRECTION_FUNC_ON_NEW_PRESENTATION) ||
        parsed.header.payload_len != 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_video_redirection_read_guid(&stream, parsed.presentation_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.platform_cookie) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *presentation = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_add_stream(
    const void* data,
    size_t length,
    rdp_video_redirection_stream* stream_message)
{
    rdp_video_redirection_stream parsed;
    rdp_stream stream;

    if (!data || !stream_message)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              RDP_VIDEO_REDIRECTION_FUNC_ADD_STREAM) ||
        parsed.header.payload_len < 24u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_video_redirection_read_guid(&stream, parsed.presentation_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.stream_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.data_len) != LIBRDP_STATUS_OK ||
        parsed.data_len != rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &parsed.data, parsed.data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *stream_message = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_presentation_only(
    const void* data,
    size_t length,
    uint32_t function_id,
    rdp_video_redirection_presentation* presentation)
{
    rdp_video_redirection_presentation parsed;
    rdp_stream stream;

    if (!data || !presentation)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              function_id) ||
        parsed.header.payload_len != 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_video_redirection_read_guid(&stream, parsed.presentation_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *presentation = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_stream_only(
    const void* data,
    size_t length,
    uint32_t function_id,
    rdp_video_redirection_stream* stream_message)
{
    rdp_video_redirection_stream parsed;
    rdp_stream stream;

    if (!data || !stream_message)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              function_id) ||
        parsed.header.payload_len != 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_video_redirection_read_guid(&stream, parsed.presentation_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.stream_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *stream_message = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_playback_started(
    const void* data,
    size_t length,
    rdp_video_redirection_playback_started* started)
{
    rdp_video_redirection_playback_started parsed;
    rdp_stream stream;

    if (!data || !started)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_STARTED) ||
        parsed.header.payload_len != 28u ||
        rdp_video_redirection_parse_payload_guid(&parsed.header,
                                                 parsed.presentation_id,
                                                 &stream) != LIBRDP_STATUS_OK ||
        rdp_video_redirection_read_u64_le(&stream, &parsed.playback_start_offset) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.is_seek) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *started = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_playback_rate(
    const void* data,
    size_t length,
    rdp_video_redirection_playback_rate* rate)
{
    rdp_video_redirection_playback_rate parsed;
    rdp_stream stream;

    if (!data || !rate)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_RATE_CHANGED) ||
        parsed.header.payload_len != 20u ||
        rdp_video_redirection_parse_payload_guid(&parsed.header,
                                                 parsed.presentation_id,
                                                 &stream) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.rate_bits) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *rate = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_sample_message(
    const void* data,
    size_t length,
    rdp_video_redirection_stream* sample)
{
    rdp_video_redirection_stream parsed;
    rdp_stream stream;

    if (!data || !sample)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              RDP_VIDEO_REDIRECTION_FUNC_ON_SAMPLE) ||
        parsed.header.payload_len < 24u ||
        rdp_video_redirection_parse_payload_guid(&parsed.header,
                                                 parsed.presentation_id,
                                                 &stream) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.stream_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.data_len) != LIBRDP_STATUS_OK ||
        parsed.data_len != rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &parsed.data, parsed.data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *sample = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_set_video_window(
    const void* data,
    size_t length,
    rdp_video_redirection_window* window)
{
    rdp_video_redirection_window parsed;
    rdp_stream stream;

    if (!data || !window)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              RDP_VIDEO_REDIRECTION_FUNC_SET_VIDEO_WINDOW) ||
        parsed.header.payload_len != 32u ||
        rdp_video_redirection_parse_payload_guid(&parsed.header,
                                                 parsed.presentation_id,
                                                 &stream) != LIBRDP_STATUS_OK ||
        rdp_video_redirection_read_u64_le(&stream, &parsed.video_window_id) != LIBRDP_STATUS_OK ||
        rdp_video_redirection_read_u64_le(&stream, &parsed.parent_window_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *window = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_geometry_update(
    const void* data,
    size_t length,
    rdp_video_redirection_geometry_update* update)
{
    rdp_video_redirection_geometry_update parsed;
    rdp_stream stream;

    if (!data || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              RDP_VIDEO_REDIRECTION_FUNC_UPDATE_GEOMETRY_INFO) ||
        parsed.header.payload_len < 24u ||
        rdp_video_redirection_parse_payload_guid(&parsed.header,
                                                 parsed.presentation_id,
                                                 &stream) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.geometry_len) != LIBRDP_STATUS_OK ||
        parsed.geometry_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &parsed.geometry, parsed.geometry_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.visible_rect_len) != LIBRDP_STATUS_OK ||
        parsed.visible_rect_len != rdp_stream_remaining(&stream) ||
        parsed.visible_rect_len % 16u != 0u ||
        rdp_stream_read_bytes(&stream, &parsed.visible_rect, parsed.visible_rect_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *update = parsed;
    return LIBRDP_STATUS_OK;
}

/*
 * Geometry records bind video samples to remote window regions. The parser
 * accepts only known state bits and rejects rectangles whose dimensions would
 * wrap the 32-bit coordinate space before session code can bind them to a
 * presentation.
 */
static int rdp_video_redirection_geometry_info_valid(const rdp_video_redirection_geometry_info* info)
{
    const uint32_t known_state = RDP_VIDEO_REDIRECTION_WINDOW_NEW |
                                RDP_VIDEO_REDIRECTION_WINDOW_DELETED |
                                RDP_VIDEO_REDIRECTION_WINDOW_VISRGN;
    uint64_t right = 0;
    uint64_t bottom = 0;

    if (!info)
        return 0;
    if (info->window_state == 0 || (info->window_state & ~known_state) != 0)
        return 0;
    if ((info->window_state & RDP_VIDEO_REDIRECTION_WINDOW_NEW) != 0 &&
        (info->window_state & RDP_VIDEO_REDIRECTION_WINDOW_DELETED) != 0)
        return 0;
    if (info->reserved != 0 || (info->has_padding && info->padding != 0))
        return 0;
    if ((info->window_state & RDP_VIDEO_REDIRECTION_WINDOW_DELETED) != 0)
        return 1;
    if (info->width == 0 || info->height == 0)
        return 0;
    right = (uint64_t)info->left + info->width;
    bottom = (uint64_t)info->top + info->height;
    if (right > UINT32_MAX || bottom > UINT32_MAX)
        return 0;
    return 1;
}

librdp_status rdp_video_redirection_parse_geometry_info(
    const void* data,
    size_t length,
    rdp_video_redirection_geometry_info* info)
{
    rdp_video_redirection_geometry_info parsed;
    rdp_stream stream;

    if (!data || !info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 44u && length != 48u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_video_redirection_read_u64_le(&stream, &parsed.video_window_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.window_state) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.height) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.left) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.top) != LIBRDP_STATUS_OK ||
        rdp_video_redirection_read_u64_le(&stream, &parsed.reserved) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.client_left) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.client_top) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) == 4u)
    {
        if (rdp_stream_read_u32_le(&stream, &parsed.padding) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        parsed.has_padding = 1u;
    }
    if (rdp_stream_remaining(&stream) != 0 || !rdp_video_redirection_geometry_info_valid(&parsed))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *info = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_rect(
    const void* data,
    size_t length,
    rdp_video_redirection_rect* rect)
{
    rdp_video_redirection_rect parsed;
    rdp_stream stream;

    if (!data || !rect)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &parsed.top) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.left) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.bottom) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.right) != LIBRDP_STATUS_OK ||
        parsed.top >= parsed.bottom ||
        parsed.left >= parsed.right)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *rect = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_stream_volume(
    const void* data,
    size_t length,
    rdp_video_redirection_volume* volume)
{
    rdp_video_redirection_volume parsed;
    rdp_stream stream;

    if (!data || !volume)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              RDP_VIDEO_REDIRECTION_FUNC_ON_STREAM_VOLUME) ||
        parsed.header.payload_len != 24u ||
        rdp_video_redirection_parse_payload_guid(&parsed.header,
                                                 parsed.presentation_id,
                                                 &stream) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.value) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.second_value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *volume = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_channel_volume(
    const void* data,
    size_t length,
    rdp_video_redirection_volume* volume)
{
    rdp_video_redirection_volume parsed;
    rdp_stream stream;

    if (!data || !volume)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              RDP_VIDEO_REDIRECTION_FUNC_ON_CHANNEL_VOLUME) ||
        parsed.header.payload_len != 24u ||
        rdp_video_redirection_parse_payload_guid(&parsed.header,
                                                 parsed.presentation_id,
                                                 &stream) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.value) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.second_value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *volume = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_redirection_parse_source_video_rect(
    const void* data,
    size_t length,
    rdp_video_redirection_source_video_rect* rect)
{
    rdp_video_redirection_source_video_rect parsed;
    rdp_stream stream;

    if (!data || !rect)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_redirection_parse_header(data, length, 1, &parsed.header) != LIBRDP_STATUS_OK ||
        !rdp_video_redirection_header_matches(&parsed.header,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              RDP_VIDEO_REDIRECTION_FUNC_SET_SOURCE_VIDEO_RECT) ||
        parsed.header.payload_len != 32u ||
        rdp_video_redirection_parse_payload_guid(&parsed.header,
                                                 parsed.presentation_id,
                                                 &stream) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.left_bits) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.top_bits) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.right_bits) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.bottom_bits) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *rect = parsed;
    return LIBRDP_STATUS_OK;
}
