/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: camera/video capture channel helpers.
 * Invariants: channel payload lengths and negotiated capabilities are checked
 * before state changes or callbacks.
 * Ownership: parsed channel objects are caller-owned unless the session stores
 * an explicit copy.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths remain local policy inputs.
 */


#include "channels/video_capture.h"

#include "common/stream.h"

#include <string.h>

static int rdp_video_capture_bool_valid(uint8_t value)
{
    return value <= 1u;
}

static int rdp_video_capture_error_valid(uint32_t error_code)
{
    return error_code >= RDP_VIDEO_CAPTURE_ERROR_UNEXPECTED &&
           error_code <= RDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED;
}

static int rdp_video_capture_source_valid(uint16_t value)
{
    return value != 0 && (value & ~(RDP_VIDEO_CAPTURE_STREAM_SOURCE_COLOR |
                                    RDP_VIDEO_CAPTURE_STREAM_SOURCE_INFRARED |
                                    RDP_VIDEO_CAPTURE_STREAM_SOURCE_CUSTOM)) == 0;
}

static int rdp_video_capture_media_format_valid(uint8_t format)
{
    return format >= RDP_VIDEO_CAPTURE_MEDIA_H264 && format <= RDP_VIDEO_CAPTURE_MEDIA_RGB32;
}

static int rdp_video_capture_property_set_valid(uint8_t property_set)
{
    return property_set == RDP_VIDEO_CAPTURE_PROPERTY_SET_CAMERA_CONTROL ||
           property_set == RDP_VIDEO_CAPTURE_PROPERTY_SET_VIDEO_PROC_AMP;
}

static int rdp_video_capture_property_capabilities_valid(uint8_t capabilities)
{
    return (capabilities & ~(RDP_VIDEO_CAPTURE_PROPERTY_CAPABILITY_MANUAL |
                             RDP_VIDEO_CAPTURE_PROPERTY_CAPABILITY_AUTO)) == 0;
}

static int rdp_video_capture_property_mode_valid(uint8_t mode)
{
    return mode == RDP_VIDEO_CAPTURE_PROPERTY_MODE_MANUAL ||
           mode == RDP_VIDEO_CAPTURE_PROPERTY_MODE_AUTO;
}

static int rdp_video_capture_property_description_valid(
    const rdp_video_capture_property_description* property)
{
    if (!property || !rdp_video_capture_property_set_valid(property->property_set) ||
        !rdp_video_capture_property_capabilities_valid(property->capabilities))
        return 0;
    if (property->min_value > property->max_value)
        return 0;
    if (property->default_value < property->min_value ||
        property->default_value > property->max_value)
        return 0;
    return 1;
}

static int rdp_video_capture_media_valid(const rdp_video_capture_media_type* media)
{
    if (!media || !rdp_video_capture_media_format_valid(media->format))
        return 0;
    if (media->width == 0 || media->height == 0 ||
        media->frame_rate_numerator == 0 || media->frame_rate_denominator == 0 ||
        media->pixel_aspect_ratio_numerator == 0 || media->pixel_aspect_ratio_denominator == 0)
        return 0;
    return (media->flags & ~(RDP_VIDEO_CAPTURE_MEDIA_FLAG_DECODING_REQUIRED |
                             RDP_VIDEO_CAPTURE_MEDIA_FLAG_BOTTOM_UP)) == 0;
}

static librdp_status rdp_video_capture_read_header(rdp_stream* stream, rdp_video_capture_header* header)
{
    if (!stream || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u8(stream, &header->version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &header->message_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_video_capture_message_valid(header->version, header->message_id))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_video_capture_read_media(rdp_stream* stream,
                                                  rdp_video_capture_media_type* media)
{
    if (!stream || !media)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(media, 0, sizeof(*media));
    if (rdp_stream_read_u8(stream, &media->format) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &media->width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &media->height) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &media->frame_rate_numerator) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &media->frame_rate_denominator) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &media->pixel_aspect_ratio_numerator) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &media->pixel_aspect_ratio_denominator) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &media->flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_video_capture_media_valid(media))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_video_capture_read_i32_le(rdp_stream* stream, int32_t* value)
{
    uint32_t raw = 0;

    if (!value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u32_le(stream, &raw) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = (int32_t)raw;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_video_capture_append_i32_le(rdp_buffer* buffer, int32_t value)
{
    return rdp_buffer_append_u32_le(buffer, (uint32_t)value);
}

static librdp_status rdp_video_capture_read_property_description(
    rdp_stream* stream,
    rdp_video_capture_property_description* property)
{
    if (!stream || !property)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(property, 0, sizeof(*property));
    if (rdp_stream_read_u8(stream, &property->property_set) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &property->property_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &property->capabilities) != LIBRDP_STATUS_OK ||
        rdp_video_capture_read_i32_le(stream, &property->min_value) != LIBRDP_STATUS_OK ||
        rdp_video_capture_read_i32_le(stream, &property->max_value) != LIBRDP_STATUS_OK ||
        rdp_video_capture_read_i32_le(stream, &property->step) != LIBRDP_STATUS_OK ||
        rdp_video_capture_read_i32_le(stream, &property->default_value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_video_capture_property_description_valid(property))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_video_capture_append_property_description(
    rdp_buffer* buffer,
    const rdp_video_capture_property_description* property)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_video_capture_property_description_valid(property))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, property->property_set);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, property->property_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, property->capabilities);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_capture_append_i32_le(buffer, property->min_value);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_capture_append_i32_le(buffer, property->max_value);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_capture_append_i32_le(buffer, property->step);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_video_capture_append_i32_le(buffer, property->default_value);
}

static const uint8_t* rdp_video_capture_find_utf16_null(const uint8_t* data, size_t length)
{
    size_t i = 0;

    if (!data)
        return NULL;
    for (i = 0; i + 1u < length; i += 2u)
    {
        if (data[i] == 0 && data[i + 1u] == 0)
            return data + i;
    }
    return NULL;
}

static const uint8_t* rdp_video_capture_find_ansi_null(const uint8_t* data, size_t length)
{
    size_t i = 0;

    if (!data)
        return NULL;
    for (i = 0; i < length; i++)
    {
        if (data[i] == 0)
            return data + i;
    }
    return NULL;
}

int rdp_video_capture_version_valid(uint8_t version)
{
    return version == RDP_VIDEO_CAPTURE_VERSION_1 || version == RDP_VIDEO_CAPTURE_VERSION_2;
}

int rdp_video_capture_message_valid(uint8_t version, uint8_t message_id)
{
    if (!rdp_video_capture_version_valid(version))
        return 0;
    if (message_id < RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE ||
        message_id > RDP_VIDEO_CAPTURE_MESSAGE_SET_PROPERTY_VALUE_REQUEST)
        return 0;
    if (version == RDP_VIDEO_CAPTURE_VERSION_1 &&
        message_id >= RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_LIST_REQUEST)
        return 0;
    return 1;
}

librdp_status rdp_video_capture_parse_header(const void* data,
                                             size_t length,
                                             rdp_video_capture_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    return rdp_video_capture_read_header(&stream, header);
}

librdp_status rdp_video_capture_write_header(rdp_buffer* buffer, uint8_t version, uint8_t message_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_video_capture_message_valid(version, message_id))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, version);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, message_id);
}

librdp_status rdp_video_capture_parse_empty(const void* data,
                                            size_t length,
                                            uint8_t expected_message_id,
                                            rdp_video_capture_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_video_capture_read_header(&stream, header) != LIBRDP_STATUS_OK ||
        header->message_id != expected_message_id)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_capture_write_empty(rdp_buffer* buffer, uint8_t version, uint8_t message_id)
{
    return rdp_video_capture_write_header(buffer, version, message_id);
}

librdp_status rdp_video_capture_parse_error(const void* data,
                                            size_t length,
                                            rdp_video_capture_error* error)
{
    rdp_stream stream;

    if (!data || !error)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(error, 0, sizeof(*error));
    rdp_stream_init(&stream, data, length);
    if (rdp_video_capture_read_header(&stream, &error->header) != LIBRDP_STATUS_OK ||
        error->header.message_id != RDP_VIDEO_CAPTURE_MESSAGE_ERROR_RESPONSE ||
        rdp_stream_read_u32_le(&stream, &error->error_code) != LIBRDP_STATUS_OK ||
        !rdp_video_capture_error_valid(error->error_code))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_capture_write_error(rdp_buffer* buffer, uint8_t version, uint32_t error_code)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_video_capture_error_valid(error_code))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_capture_write_header(buffer, version, RDP_VIDEO_CAPTURE_MESSAGE_ERROR_RESPONSE);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, error_code);
}

librdp_status rdp_video_capture_parse_device_added(
    const void* data,
    size_t length,
    rdp_video_capture_device_notification* notification)
{
    rdp_stream stream;
    const uint8_t* rest = NULL;
    const uint8_t* utf16_end = NULL;
    const uint8_t* ansi_end = NULL;
    size_t rest_len = 0;

    if (!data || !notification)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 5u || length > RDP_VIDEO_CAPTURE_MAX_STRING_BYTES * 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(notification, 0, sizeof(*notification));
    rdp_stream_init(&stream, data, length);
    if (rdp_video_capture_read_header(&stream, &notification->header) != LIBRDP_STATUS_OK ||
        notification->header.message_id != RDP_VIDEO_CAPTURE_MESSAGE_DEVICE_ADDED)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rest_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &rest, rest_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    utf16_end = rdp_video_capture_find_utf16_null(rest, rest_len);
    if (!utf16_end)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    notification->device_name_utf16le = rest;
    notification->device_name_len = (size_t)(utf16_end - rest);
    rest_len -= notification->device_name_len + 2u;
    rest = utf16_end + 2u;
    ansi_end = rdp_video_capture_find_ansi_null(rest, rest_len);
    if (!ansi_end || ansi_end == rest)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    notification->channel_name = rest;
    notification->channel_name_len = (size_t)(ansi_end - rest);
    if (notification->device_name_len == 0 || ansi_end + 1u != ((const uint8_t*)data) + length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_capture_write_device_added(rdp_buffer* buffer,
                                                   uint8_t version,
                                                   const void* device_name_utf16le,
                                                   size_t device_name_len,
                                                   const char* channel_name)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t channel_len = channel_name ? strlen(channel_name) : 0;

    if (!buffer || !device_name_utf16le || device_name_len == 0 ||
        (device_name_len & 1u) != 0 ||
        device_name_len > RDP_VIDEO_CAPTURE_MAX_STRING_BYTES ||
        !channel_name || channel_len == 0 ||
        channel_len > RDP_VIDEO_CAPTURE_MAX_STRING_BYTES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_capture_write_header(buffer, version, RDP_VIDEO_CAPTURE_MESSAGE_DEVICE_ADDED);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, device_name_utf16le, device_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, channel_name, channel_len + 1u);
    return status;
}

librdp_status rdp_video_capture_parse_device_removed(
    const void* data,
    size_t length,
    rdp_video_capture_device_notification* notification)
{
    rdp_stream stream;
    const uint8_t* rest = NULL;
    const uint8_t* ansi_end = NULL;
    size_t rest_len = 0;

    if (!data || !notification)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u || length > RDP_VIDEO_CAPTURE_MAX_STRING_BYTES + 3u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(notification, 0, sizeof(*notification));
    rdp_stream_init(&stream, data, length);
    if (rdp_video_capture_read_header(&stream, &notification->header) != LIBRDP_STATUS_OK ||
        notification->header.message_id != RDP_VIDEO_CAPTURE_MESSAGE_DEVICE_REMOVED)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rest_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &rest, rest_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    ansi_end = rdp_video_capture_find_ansi_null(rest, rest_len);
    if (!ansi_end || ansi_end == rest || ansi_end + 1u != ((const uint8_t*)data) + length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    notification->channel_name = rest;
    notification->channel_name_len = (size_t)(ansi_end - rest);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_capture_write_device_removed(rdp_buffer* buffer,
                                                     uint8_t version,
                                                     const char* channel_name)
{
    size_t channel_len = channel_name ? strlen(channel_name) : 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !channel_name || channel_len == 0 ||
        channel_len > RDP_VIDEO_CAPTURE_MAX_STRING_BYTES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_capture_write_header(buffer, version, RDP_VIDEO_CAPTURE_MESSAGE_DEVICE_REMOVED);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, channel_name, channel_len + 1u);
}

librdp_status rdp_video_capture_parse_stream_list(const void* data,
                                                  size_t length,
                                                  rdp_video_capture_stream_list* list)
{
    rdp_stream stream;
    size_t i = 0;
    size_t count = 0;

    if (!data || !list)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 7u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(list, 0, sizeof(*list));
    rdp_stream_init(&stream, data, length);
    if (rdp_video_capture_read_header(&stream, &list->header) != LIBRDP_STATUS_OK ||
        list->header.message_id != RDP_VIDEO_CAPTURE_MESSAGE_STREAM_LIST_RESPONSE ||
        (rdp_stream_remaining(&stream) % 5u) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    count = rdp_stream_remaining(&stream) / 5u;
    if (count == 0 || count > RDP_VIDEO_CAPTURE_MAX_STREAMS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    list->count = (uint8_t)count;
    for (i = 0; i < count; i++)
    {
        rdp_video_capture_stream_description* item = &list->streams[i];
        if (rdp_stream_read_u16_le(&stream, &item->frame_source_types) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &item->stream_category) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &item->selected) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &item->can_be_shared) != LIBRDP_STATUS_OK ||
            !rdp_video_capture_source_valid(item->frame_source_types) ||
            item->stream_category != RDP_VIDEO_CAPTURE_STREAM_CATEGORY_CAPTURE ||
            !rdp_video_capture_bool_valid(item->selected) ||
            !rdp_video_capture_bool_valid(item->can_be_shared))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_capture_write_stream_list(
    rdp_buffer* buffer,
    uint8_t version,
    const rdp_video_capture_stream_description* streams,
    uint8_t count)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t i = 0;

    if (!buffer || !streams || count == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_capture_write_header(buffer, version, RDP_VIDEO_CAPTURE_MESSAGE_STREAM_LIST_RESPONSE);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < count; i++)
    {
        if (!rdp_video_capture_source_valid(streams[i].frame_source_types) ||
            streams[i].stream_category != RDP_VIDEO_CAPTURE_STREAM_CATEGORY_CAPTURE ||
            !rdp_video_capture_bool_valid(streams[i].selected) ||
            !rdp_video_capture_bool_valid(streams[i].can_be_shared))
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        status = rdp_buffer_append_u16_le(buffer, streams[i].frame_source_types);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u8(buffer, streams[i].stream_category);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u8(buffer, streams[i].selected);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u8(buffer, streams[i].can_be_shared);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_capture_parse_media_type(const void* data,
                                                 size_t length,
                                                 rdp_video_capture_media_type* media)
{
    rdp_stream stream;

    if (!data || !media)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != RDP_VIDEO_CAPTURE_MEDIA_TYPE_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    return rdp_video_capture_read_media(&stream, media);
}

librdp_status rdp_video_capture_write_media_type(rdp_buffer* buffer,
                                                 const rdp_video_capture_media_type* media)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_video_capture_media_valid(media))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, media->format);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, media->width);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, media->height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, media->frame_rate_numerator);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, media->frame_rate_denominator);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, media->pixel_aspect_ratio_numerator);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, media->pixel_aspect_ratio_denominator);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, media->flags);
    return status;
}

librdp_status rdp_video_capture_parse_media_list(const void* data,
                                                 size_t length,
                                                 uint8_t expected_message_id,
                                                 rdp_video_capture_media_list* list)
{
    rdp_stream stream;
    size_t i = 0;
    size_t count = 0;

    if (!data || !list)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 2u + RDP_VIDEO_CAPTURE_MEDIA_TYPE_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(list, 0, sizeof(*list));
    rdp_stream_init(&stream, data, length);
    if (rdp_video_capture_read_header(&stream, &list->header) != LIBRDP_STATUS_OK ||
        list->header.message_id != expected_message_id ||
        (rdp_stream_remaining(&stream) % RDP_VIDEO_CAPTURE_MEDIA_TYPE_LENGTH) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    count = rdp_stream_remaining(&stream) / RDP_VIDEO_CAPTURE_MEDIA_TYPE_LENGTH;
    if (count == 0 || count > RDP_VIDEO_CAPTURE_MAX_STREAMS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    list->count = (uint8_t)count;
    for (i = 0; i < count; i++)
    {
        if (rdp_video_capture_read_media(&stream, &list->media[i]) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_capture_write_media_list(rdp_buffer* buffer,
                                                 uint8_t version,
                                                 uint8_t message_id,
                                                 const rdp_video_capture_media_type* media,
                                                 uint8_t count)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t i = 0;

    if (!buffer || !media || count == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_capture_write_header(buffer, version, message_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < count; i++)
    {
        status = rdp_video_capture_write_media_type(buffer, &media[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_capture_parse_stream_index(const void* data,
                                                   size_t length,
                                                   uint8_t expected_message_id,
                                                   rdp_video_capture_stream_index* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 3u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(request, 0, sizeof(*request));
    rdp_stream_init(&stream, data, length);
    if (rdp_video_capture_read_header(&stream, &request->header) != LIBRDP_STATUS_OK ||
        request->header.message_id != expected_message_id ||
        rdp_stream_read_u8(&stream, &request->stream_index) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_capture_write_stream_index(rdp_buffer* buffer,
                                                   uint8_t version,
                                                   uint8_t message_id,
                                                   uint8_t stream_index)
{
    librdp_status status = rdp_video_capture_write_header(buffer, version, message_id);

    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, stream_index);
}

librdp_status rdp_video_capture_parse_sample(const void* data,
                                             size_t length,
                                             rdp_video_capture_sample* sample)
{
    rdp_stream stream;

    if (!data || !sample)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 3u || length > RDP_VIDEO_CAPTURE_MAX_SAMPLE_BYTES + 3u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(sample, 0, sizeof(*sample));
    rdp_stream_init(&stream, data, length);
    if (rdp_video_capture_read_header(&stream, &sample->header) != LIBRDP_STATUS_OK ||
        sample->header.message_id != RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_RESPONSE ||
        rdp_stream_read_u8(&stream, &sample->stream_index) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    sample->sample_len = rdp_stream_remaining(&stream);
    return rdp_stream_read_bytes(&stream, &sample->sample, sample->sample_len);
}

librdp_status rdp_video_capture_write_sample(rdp_buffer* buffer,
                                             uint8_t version,
                                             uint8_t stream_index,
                                             const void* sample,
                                             size_t sample_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!sample && sample_len > 0) ||
        sample_len > RDP_VIDEO_CAPTURE_MAX_SAMPLE_BYTES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_capture_write_header(buffer, version, RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_RESPONSE);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, stream_index);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, sample, sample_len);
}

librdp_status rdp_video_capture_parse_sample_error(const void* data,
                                                   size_t length,
                                                   rdp_video_capture_error* error,
                                                   uint8_t* stream_index)
{
    rdp_stream stream;

    if (!data || !error || !stream_index)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 7u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(error, 0, sizeof(*error));
    rdp_stream_init(&stream, data, length);
    if (rdp_video_capture_read_header(&stream, &error->header) != LIBRDP_STATUS_OK ||
        error->header.message_id != RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_ERROR_RESPONSE ||
        rdp_stream_read_u8(&stream, stream_index) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &error->error_code) != LIBRDP_STATUS_OK ||
        !rdp_video_capture_error_valid(error->error_code))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_capture_write_sample_error(rdp_buffer* buffer,
                                                   uint8_t version,
                                                   uint8_t stream_index,
                                                   uint32_t error_code)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_video_capture_error_valid(error_code))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_capture_write_header(buffer, version, RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_ERROR_RESPONSE);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, stream_index);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, error_code);
}

librdp_status rdp_video_capture_parse_opaque(const void* data,
                                             size_t length,
                                             uint8_t expected_message_id,
                                             rdp_video_capture_opaque* pdu)
{
    rdp_stream stream;

    if (!data || !pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 2u || length > RDP_VIDEO_CAPTURE_MAX_OPAQUE_BYTES + 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(pdu, 0, sizeof(*pdu));
    rdp_stream_init(&stream, data, length);
    if (rdp_video_capture_read_header(&stream, &pdu->header) != LIBRDP_STATUS_OK ||
        pdu->header.message_id != expected_message_id)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    pdu->payload_len = rdp_stream_remaining(&stream);
    return rdp_stream_read_bytes(&stream, &pdu->payload, pdu->payload_len);
}

librdp_status rdp_video_capture_write_opaque(rdp_buffer* buffer,
                                             uint8_t version,
                                             uint8_t message_id,
                                             const void* payload,
                                             size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!payload && payload_len > 0) ||
        payload_len > RDP_VIDEO_CAPTURE_MAX_OPAQUE_BYTES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_capture_write_header(buffer, version, message_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, payload, payload_len);
}

librdp_status rdp_video_capture_parse_property_list(const void* data,
                                                    size_t length,
                                                    rdp_video_capture_property_list* list)
{
    rdp_stream stream;
    size_t remaining = 0;
    size_t i = 0;

    if (!data || !list)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(list, 0, sizeof(*list));
    rdp_stream_init(&stream, data, length);
    if (rdp_video_capture_read_header(&stream, &list->header) != LIBRDP_STATUS_OK ||
        list->header.message_id != RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_LIST_RESPONSE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    remaining = rdp_stream_remaining(&stream);
    if (remaining % RDP_VIDEO_CAPTURE_PROPERTY_DESCRIPTION_LENGTH != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    list->count = (uint8_t)(remaining / RDP_VIDEO_CAPTURE_PROPERTY_DESCRIPTION_LENGTH);
    if (list->count > RDP_VIDEO_CAPTURE_MAX_PROPERTIES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < list->count; i++)
    {
        if (rdp_video_capture_read_property_description(&stream, &list->properties[i]) !=
            LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_video_capture_write_property_list(
    rdp_buffer* buffer,
    uint8_t version,
    const rdp_video_capture_property_description* properties,
    uint8_t count)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t i = 0;

    if (!buffer || (!properties && count > 0) || count > RDP_VIDEO_CAPTURE_MAX_PROPERTIES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_capture_write_header(buffer,
                                            version,
                                            RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_LIST_RESPONSE);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < count; i++)
    {
        status = rdp_video_capture_append_property_description(buffer, &properties[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_capture_parse_property_request(
    const void* data,
    size_t length,
    uint8_t expected_message_id,
    rdp_video_capture_property_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(request, 0, sizeof(*request));
    rdp_stream_init(&stream, data, length);
    if (rdp_video_capture_read_header(&stream, &request->header) != LIBRDP_STATUS_OK ||
        request->header.message_id != expected_message_id ||
        rdp_stream_read_u8(&stream, &request->property_set) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &request->property_id) != LIBRDP_STATUS_OK ||
        !rdp_video_capture_property_set_valid(request->property_set) ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_capture_parse_property_value(const void* data,
                                                     size_t length,
                                                     rdp_video_capture_property_value* value)
{
    rdp_stream stream;

    if (!data || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 5u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(value, 0, sizeof(*value));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &value->mode) != LIBRDP_STATUS_OK ||
        rdp_video_capture_read_i32_le(&stream, &value->value) != LIBRDP_STATUS_OK ||
        !rdp_video_capture_property_mode_valid(value->mode) ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_capture_parse_set_property_request(
    const void* data,
    size_t length,
    rdp_video_capture_property_request* request,
    rdp_video_capture_property_value* value)
{
    if (!data || !request || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 9u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_video_capture_parse_property_request(data,
                                                 4u,
                                                 RDP_VIDEO_CAPTURE_MESSAGE_SET_PROPERTY_VALUE_REQUEST,
                                                 request) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_video_capture_parse_property_value((const uint8_t*)data + 4u, 5u, value);
}

librdp_status rdp_video_capture_write_property_value(rdp_buffer* buffer,
                                                     uint8_t version,
                                                     const rdp_video_capture_property_value* value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !value || !rdp_video_capture_property_mode_valid(value->mode))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_capture_write_header(buffer,
                                            version,
                                            RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_RESPONSE);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, value->mode);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_video_capture_append_i32_le(buffer, value->value);
}
