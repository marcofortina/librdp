/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: video optimized remoting packet helpers.
 * Invariants: channel payload lengths and negotiated capabilities are checked
 * before state changes or callbacks.
 * Ownership: parsed channel objects are caller-owned unless the session stores
 * an explicit copy.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths remain local policy inputs.
 */


#include "channels/video_optimized.h"

#include "common/stream.h"

#include <string.h>

static const uint8_t rdp_video_optimized_h264_guid[16] = {
    0x48, 0x32, 0x36, 0x34, 0x00, 0x00, 0x10, 0x00,
    0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71
};

static int rdp_video_optimized_valid_packet_type(uint32_t packet_type)
{
    return packet_type == RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_REQUEST ||
           packet_type == RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_RESPONSE ||
           packet_type == RDP_VIDEO_OPTIMIZED_PACKET_CLIENT_NOTIFICATION ||
           packet_type == RDP_VIDEO_OPTIMIZED_PACKET_VIDEO_DATA;
}

static librdp_status rdp_video_optimized_read_u64_le(rdp_stream* stream, uint64_t* value)
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

static librdp_status rdp_video_optimized_append_u64_le(rdp_buffer* buffer, uint64_t value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, (uint32_t)(value & 0xffffffffu));
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, (uint32_t)((value >> 32) & 0xffffffffu));
}

librdp_status rdp_video_optimized_parse_header(
    const void* data,
    size_t length,
    rdp_video_optimized_header* header)
{
    rdp_video_optimized_header parsed;
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u || length > (size_t)UINT32_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &parsed.size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.packet_type) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.size != (uint32_t)length ||
        !rdp_video_optimized_valid_packet_type(parsed.packet_type))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.payload_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &parsed.payload, parsed.payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *header = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_optimized_write_header(
    rdp_buffer* buffer,
    uint32_t packet_type,
    uint32_t size)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || size < 8u || !rdp_video_optimized_valid_packet_type(packet_type))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, packet_type);
}

/*
 * Parse a video-optimized presentation request and validate the H.264 subtype.
 * Start/stop command invariants, dimensions, and optional payload lengths are
 * checked before the request is exposed to the session media pipeline.
 */
librdp_status rdp_video_optimized_parse_presentation_request(
    const void* data,
    size_t length,
    rdp_video_optimized_presentation_request* request)
{
    rdp_video_optimized_presentation_request parsed;
    rdp_stream stream;
    const uint8_t* guid = NULL;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_optimized_parse_header(data, length, &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.packet_type != RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_REQUEST ||
        parsed.header.payload_len < 3u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u8(&stream, &parsed.presentation_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.command) != LIBRDP_STATUS_OK ||
        parsed.version != RDP_VIDEO_OPTIMIZED_VERSION_1 ||
        (parsed.command != RDP_VIDEO_OPTIMIZED_COMMAND_START &&
         parsed.command != RDP_VIDEO_OPTIMIZED_COMMAND_STOP))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.command == RDP_VIDEO_OPTIMIZED_COMMAND_STOP)
    {
        if (rdp_stream_remaining(&stream) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *request = parsed;
        return LIBRDP_STATUS_OK;
    }
    if (rdp_stream_read_u8(&stream, &parsed.frame_rate) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.average_bitrate_kbps) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.reserved) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.source_width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.source_height) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.scaled_width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.scaled_height) != LIBRDP_STATUS_OK ||
        rdp_video_optimized_read_u64_le(&stream, &parsed.timestamp_offset) != LIBRDP_STATUS_OK ||
        rdp_video_optimized_read_u64_le(&stream, &parsed.geometry_mapping_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &guid, 16u) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.extra_len) != LIBRDP_STATUS_OK ||
        parsed.extra_len != rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &parsed.extra, parsed.extra_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(parsed.video_subtype_id, guid, 16u);
    if (parsed.source_width == 0 || parsed.source_height == 0 ||
        parsed.scaled_width == 0 || parsed.scaled_height == 0 ||
        parsed.scaled_width > RDP_VIDEO_OPTIMIZED_MAX_SCALED_WIDTH ||
        parsed.scaled_height > RDP_VIDEO_OPTIMIZED_MAX_SCALED_HEIGHT ||
        memcmp(parsed.video_subtype_id, rdp_video_optimized_h264_guid, 16u) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *request = parsed;
    return LIBRDP_STATUS_OK;
}

/*
 * Serialize a presentation-start request for the optimized video channel.
 * The writer validates dimensions, GUID subtype, and extension length first so
 * callers cannot emit packets that the paired parser would reject.
 */
librdp_status rdp_video_optimized_write_presentation_start_request(
    rdp_buffer* buffer,
    uint8_t presentation_id,
    uint8_t frame_rate,
    uint16_t average_bitrate_kbps,
    uint32_t source_width,
    uint32_t source_height,
    uint32_t scaled_width,
    uint32_t scaled_height,
    uint64_t timestamp_offset,
    uint64_t geometry_mapping_id,
    const uint8_t* video_subtype_id,
    const void* extra,
    uint32_t extra_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t size = 0;

    if (!buffer || !video_subtype_id || (!extra && extra_len > 0) ||
        source_width == 0 || source_height == 0 ||
        scaled_width == 0 || scaled_height == 0 ||
        scaled_width > RDP_VIDEO_OPTIMIZED_MAX_SCALED_WIDTH ||
        scaled_height > RDP_VIDEO_OPTIMIZED_MAX_SCALED_HEIGHT ||
        memcmp(video_subtype_id, rdp_video_optimized_h264_guid, 16u) != 0 ||
        extra_len > UINT32_MAX - 68u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    size = 68u + extra_len;
    status = rdp_video_optimized_write_header(buffer,
                                             RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_REQUEST,
                                             size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, presentation_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, RDP_VIDEO_OPTIMIZED_VERSION_1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, RDP_VIDEO_OPTIMIZED_COMMAND_START);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, frame_rate);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, average_bitrate_kbps);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, source_width);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, source_height);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, scaled_width);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, scaled_height);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_optimized_append_u64_le(buffer, timestamp_offset);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_optimized_append_u64_le(buffer, geometry_mapping_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, video_subtype_id, 16u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, extra_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, extra, extra_len);
}

librdp_status rdp_video_optimized_write_presentation_stop_request(
    rdp_buffer* buffer,
    uint8_t presentation_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_video_optimized_write_header(buffer,
                                             RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_REQUEST,
                                             11u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, presentation_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, RDP_VIDEO_OPTIMIZED_VERSION_1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, RDP_VIDEO_OPTIMIZED_COMMAND_STOP);
}

librdp_status rdp_video_optimized_write_presentation_response(
    rdp_buffer* buffer,
    uint8_t presentation_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_video_optimized_write_header(buffer,
                                             RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_RESPONSE,
                                             12u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, presentation_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u16_le(buffer, 0);
}

librdp_status rdp_video_optimized_parse_presentation_response(
    const void* data,
    size_t length,
    rdp_video_optimized_presentation_response* response)
{
    rdp_video_optimized_presentation_response parsed;
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_optimized_parse_header(data, length, &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.packet_type != RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_RESPONSE ||
        parsed.header.payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u8(&stream, &parsed.presentation_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.response_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.result_flags) != LIBRDP_STATUS_OK ||
        parsed.response_flags != 0 ||
        parsed.result_flags != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *response = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_optimized_write_client_notification(
    rdp_buffer* buffer,
    uint8_t presentation_id,
    uint8_t notification_type,
    const void* data,
    uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0) ||
        (notification_type != RDP_VIDEO_OPTIMIZED_NOTIFICATION_NETWORK_ERROR &&
         notification_type != RDP_VIDEO_OPTIMIZED_NOTIFICATION_FRAMERATE_OVERRIDE) ||
        (notification_type == RDP_VIDEO_OPTIMIZED_NOTIFICATION_NETWORK_ERROR && data_len != 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_optimized_write_header(buffer,
                                             RDP_VIDEO_OPTIMIZED_PACKET_CLIENT_NOTIFICATION,
                                             16u + data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, presentation_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, notification_type);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, data_len);
}

librdp_status rdp_video_optimized_parse_client_notification(
    const void* data,
    size_t length,
    rdp_video_optimized_client_notification* notification)
{
    rdp_video_optimized_client_notification parsed;
    rdp_stream stream;

    if (!data || !notification)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_optimized_parse_header(data, length, &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.packet_type != RDP_VIDEO_OPTIMIZED_PACKET_CLIENT_NOTIFICATION ||
        parsed.header.payload_len < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u8(&stream, &parsed.presentation_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.notification_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.reserved) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.data_len) != LIBRDP_STATUS_OK ||
        parsed.data_len != rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &parsed.data, parsed.data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.notification_type == RDP_VIDEO_OPTIMIZED_NOTIFICATION_NETWORK_ERROR)
    {
        if (parsed.data_len != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *notification = parsed;
        return LIBRDP_STATUS_OK;
    }
    if (parsed.notification_type == RDP_VIDEO_OPTIMIZED_NOTIFICATION_FRAMERATE_OVERRIDE)
    {
        if (parsed.data_len != 16u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *notification = parsed;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_video_optimized_write_framerate_override(
    rdp_buffer* buffer,
    uint32_t flags,
    uint32_t desired_frame_rate)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer ||
        (flags != RDP_VIDEO_OPTIMIZED_FRAMERATE_UNRESTRICTED &&
         flags != RDP_VIDEO_OPTIMIZED_FRAMERATE_OVERRIDE) ||
        (flags == RDP_VIDEO_OPTIMIZED_FRAMERATE_UNRESTRICTED && desired_frame_rate != 0) ||
        (flags == RDP_VIDEO_OPTIMIZED_FRAMERATE_OVERRIDE &&
         (desired_frame_rate == 0 || desired_frame_rate > 30u)))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, flags);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, desired_frame_rate);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, 0);
}

librdp_status rdp_video_optimized_parse_framerate_override(
    const void* data,
    size_t length,
    rdp_video_optimized_framerate_override* framerate)
{
    rdp_video_optimized_framerate_override parsed;
    rdp_stream stream;

    if (!data || !framerate)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &parsed.flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.desired_frame_rate) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.reserved1) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.reserved2) != LIBRDP_STATUS_OK ||
        parsed.reserved1 != 0 ||
        parsed.reserved2 != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.flags == RDP_VIDEO_OPTIMIZED_FRAMERATE_UNRESTRICTED)
    {
        if (parsed.desired_frame_rate != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *framerate = parsed;
        return LIBRDP_STATUS_OK;
    }
    if (parsed.flags == RDP_VIDEO_OPTIMIZED_FRAMERATE_OVERRIDE)
    {
        if (parsed.desired_frame_rate < 1u || parsed.desired_frame_rate > 30u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *framerate = parsed;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_video_optimized_parse_video_data(
    const void* data,
    size_t length,
    rdp_video_optimized_video_data* video)
{
    rdp_video_optimized_video_data parsed;
    rdp_stream stream;

    if (!data || !video)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_video_optimized_parse_header(data, length, &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.packet_type != RDP_VIDEO_OPTIMIZED_PACKET_VIDEO_DATA ||
        parsed.header.payload_len < 32u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u8(&stream, &parsed.presentation_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.reserved) != LIBRDP_STATUS_OK ||
        rdp_video_optimized_read_u64_le(&stream, &parsed.timestamp) != LIBRDP_STATUS_OK ||
        rdp_video_optimized_read_u64_le(&stream, &parsed.duration) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.current_packet_index) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.packets_in_sample) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.sample_number) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.sample_len) != LIBRDP_STATUS_OK ||
        parsed.sample_len != rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &parsed.sample, parsed.sample_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.version != RDP_VIDEO_OPTIMIZED_VERSION_1 ||
        (parsed.flags & ~(RDP_VIDEO_OPTIMIZED_DATA_FLAG_HAS_TIMESTAMPS |
                          RDP_VIDEO_OPTIMIZED_DATA_FLAG_KEYFRAME |
                          RDP_VIDEO_OPTIMIZED_DATA_FLAG_NEW_FRAMERATE)) != 0 ||
        parsed.packets_in_sample == 0 ||
        parsed.current_packet_index == 0 ||
        parsed.current_packet_index > parsed.packets_in_sample ||
        parsed.sample_number == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *video = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_video_optimized_write_video_data(
    rdp_buffer* buffer,
    uint8_t presentation_id,
    uint8_t flags,
    uint64_t timestamp,
    uint64_t duration,
    uint16_t current_packet_index,
    uint16_t packets_in_sample,
    uint32_t sample_number,
    const void* sample,
    uint32_t sample_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!sample && sample_len > 0) ||
        sample_len > UINT32_MAX - 40u ||
        (flags & ~(RDP_VIDEO_OPTIMIZED_DATA_FLAG_HAS_TIMESTAMPS |
                   RDP_VIDEO_OPTIMIZED_DATA_FLAG_KEYFRAME |
                   RDP_VIDEO_OPTIMIZED_DATA_FLAG_NEW_FRAMERATE)) != 0 ||
        packets_in_sample == 0 ||
        current_packet_index == 0 ||
        current_packet_index > packets_in_sample ||
        sample_number == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_optimized_write_header(buffer,
                                             RDP_VIDEO_OPTIMIZED_PACKET_VIDEO_DATA,
                                             40u + sample_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, presentation_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, RDP_VIDEO_OPTIMIZED_VERSION_1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, flags);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_optimized_append_u64_le(buffer, timestamp);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_video_optimized_append_u64_le(buffer, duration);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, current_packet_index);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, packets_in_sample);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, sample_number);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, sample_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, sample, sample_len);
}

const uint8_t* rdp_video_optimized_h264_subtype_guid(void)
{
    return rdp_video_optimized_h264_guid;
}
