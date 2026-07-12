/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: video optimized remoting parser declarations.
 * Invariants: channel payload lengths, message identifiers, and negotiated
 * capabilities must be validated before state changes.
 * Ownership: parsed packet structs remain caller-owned unless a session
 * explicitly stores a copy.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths are local policy inputs.
 */


#ifndef RDP_CHANNELS_VIDEO_OPTIMIZED_H
#define RDP_CHANNELS_VIDEO_OPTIMIZED_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_VIDEO_OPTIMIZED_CONTROL_CHANNEL "Microsoft::Windows::RDS::Video::Control::v08.01"
#define RDP_VIDEO_OPTIMIZED_DATA_CHANNEL "Microsoft::Windows::RDS::Video::Data::v08.01"

#define RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_REQUEST 0x00000001u
#define RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_RESPONSE 0x00000002u
#define RDP_VIDEO_OPTIMIZED_PACKET_CLIENT_NOTIFICATION 0x00000003u
#define RDP_VIDEO_OPTIMIZED_PACKET_VIDEO_DATA 0x00000004u

#define RDP_VIDEO_OPTIMIZED_VERSION_1 0x01u
#define RDP_VIDEO_OPTIMIZED_COMMAND_START 0x01u
#define RDP_VIDEO_OPTIMIZED_COMMAND_STOP 0x02u

#define RDP_VIDEO_OPTIMIZED_NOTIFICATION_NETWORK_ERROR 0x01u
#define RDP_VIDEO_OPTIMIZED_NOTIFICATION_FRAMERATE_OVERRIDE 0x02u

#define RDP_VIDEO_OPTIMIZED_FRAMERATE_UNRESTRICTED 0x00000001u
#define RDP_VIDEO_OPTIMIZED_FRAMERATE_OVERRIDE 0x00000002u

#define RDP_VIDEO_OPTIMIZED_DATA_FLAG_HAS_TIMESTAMPS 0x01u
#define RDP_VIDEO_OPTIMIZED_DATA_FLAG_KEYFRAME 0x02u
#define RDP_VIDEO_OPTIMIZED_DATA_FLAG_NEW_FRAMERATE 0x04u

#define RDP_VIDEO_OPTIMIZED_MAX_SCALED_WIDTH 1920u
#define RDP_VIDEO_OPTIMIZED_MAX_SCALED_HEIGHT 1080u

typedef struct rdp_video_optimized_header
{
    uint32_t size;
    uint32_t packet_type;
    const uint8_t* payload;
    size_t payload_len;
} rdp_video_optimized_header;

typedef struct rdp_video_optimized_presentation_request
{
    rdp_video_optimized_header header;
    uint8_t presentation_id;
    uint8_t version;
    uint8_t command;
    uint8_t frame_rate;
    uint16_t average_bitrate_kbps;
    uint16_t reserved;
    uint32_t source_width;
    uint32_t source_height;
    uint32_t scaled_width;
    uint32_t scaled_height;
    uint64_t timestamp_offset;
    uint64_t geometry_mapping_id;
    uint8_t video_subtype_id[16];
    uint32_t extra_len;
    const uint8_t* extra;
} rdp_video_optimized_presentation_request;

typedef struct rdp_video_optimized_presentation_response
{
    rdp_video_optimized_header header;
    uint8_t presentation_id;
    uint8_t response_flags;
    uint16_t result_flags;
} rdp_video_optimized_presentation_response;

typedef struct rdp_video_optimized_framerate_override
{
    uint32_t flags;
    uint32_t desired_frame_rate;
    uint32_t reserved1;
    uint32_t reserved2;
} rdp_video_optimized_framerate_override;

typedef struct rdp_video_optimized_client_notification
{
    rdp_video_optimized_header header;
    uint8_t presentation_id;
    uint8_t notification_type;
    uint16_t reserved;
    uint32_t data_len;
    const uint8_t* data;
} rdp_video_optimized_client_notification;

typedef struct rdp_video_optimized_video_data
{
    rdp_video_optimized_header header;
    uint8_t presentation_id;
    uint8_t version;
    uint8_t flags;
    uint8_t reserved;
    uint64_t timestamp;
    uint64_t duration;
    uint16_t current_packet_index;
    uint16_t packets_in_sample;
    uint32_t sample_number;
    uint32_t sample_len;
    const uint8_t* sample;
} rdp_video_optimized_video_data;

librdp_status rdp_video_optimized_parse_header(
    const void* data,
    size_t length,
    rdp_video_optimized_header* header);
librdp_status rdp_video_optimized_write_header(
    rdp_buffer* buffer,
    uint32_t packet_type,
    uint32_t size);
librdp_status rdp_video_optimized_parse_presentation_request(
    const void* data,
    size_t length,
    rdp_video_optimized_presentation_request* request);
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
    uint32_t extra_len);
librdp_status rdp_video_optimized_write_presentation_stop_request(
    rdp_buffer* buffer,
    uint8_t presentation_id);
librdp_status rdp_video_optimized_write_presentation_response(
    rdp_buffer* buffer,
    uint8_t presentation_id);
librdp_status rdp_video_optimized_parse_presentation_response(
    const void* data,
    size_t length,
    rdp_video_optimized_presentation_response* response);
librdp_status rdp_video_optimized_write_client_notification(
    rdp_buffer* buffer,
    uint8_t presentation_id,
    uint8_t notification_type,
    const void* data,
    uint32_t data_len);
librdp_status rdp_video_optimized_parse_client_notification(
    const void* data,
    size_t length,
    rdp_video_optimized_client_notification* notification);
librdp_status rdp_video_optimized_write_framerate_override(
    rdp_buffer* buffer,
    uint32_t flags,
    uint32_t desired_frame_rate);
librdp_status rdp_video_optimized_parse_framerate_override(
    const void* data,
    size_t length,
    rdp_video_optimized_framerate_override* framerate);
librdp_status rdp_video_optimized_parse_video_data(
    const void* data,
    size_t length,
    rdp_video_optimized_video_data* video);
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
    uint32_t sample_len);
const uint8_t* rdp_video_optimized_h264_subtype_guid(void);

#endif
