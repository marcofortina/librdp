/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: camera/video capture channel parser and writer declarations.
 * Invariants: channel payload lengths, message identifiers, and negotiated
 * capabilities must be validated before state changes.
 * Ownership: parsed packet structs remain caller-owned unless a session
 * explicitly stores a copy.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths are local policy inputs.
 */


#ifndef RDP_CHANNELS_VIDEO_CAPTURE_H
#define RDP_CHANNELS_VIDEO_CAPTURE_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_VIDEO_CAPTURE_VERSION_1 1u
#define RDP_VIDEO_CAPTURE_VERSION_2 2u
#define RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE 0x01u
#define RDP_VIDEO_CAPTURE_MESSAGE_ERROR_RESPONSE 0x02u
#define RDP_VIDEO_CAPTURE_MESSAGE_SELECT_VERSION_REQUEST 0x03u
#define RDP_VIDEO_CAPTURE_MESSAGE_SELECT_VERSION_RESPONSE 0x04u
#define RDP_VIDEO_CAPTURE_MESSAGE_DEVICE_ADDED 0x05u
#define RDP_VIDEO_CAPTURE_MESSAGE_DEVICE_REMOVED 0x06u
#define RDP_VIDEO_CAPTURE_MESSAGE_ACTIVATE_DEVICE_REQUEST 0x07u
#define RDP_VIDEO_CAPTURE_MESSAGE_DEACTIVATE_DEVICE_REQUEST 0x08u
#define RDP_VIDEO_CAPTURE_MESSAGE_STREAM_LIST_REQUEST 0x09u
#define RDP_VIDEO_CAPTURE_MESSAGE_STREAM_LIST_RESPONSE 0x0au
#define RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_REQUEST 0x0bu
#define RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_RESPONSE 0x0cu
#define RDP_VIDEO_CAPTURE_MESSAGE_CURRENT_MEDIA_TYPE_REQUEST 0x0du
#define RDP_VIDEO_CAPTURE_MESSAGE_CURRENT_MEDIA_TYPE_RESPONSE 0x0eu
#define RDP_VIDEO_CAPTURE_MESSAGE_START_STREAMS_REQUEST 0x0fu
#define RDP_VIDEO_CAPTURE_MESSAGE_STOP_STREAMS_REQUEST 0x10u
#define RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_REQUEST 0x11u
#define RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_RESPONSE 0x12u
#define RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_ERROR_RESPONSE 0x13u
#define RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_LIST_REQUEST 0x14u
#define RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_LIST_RESPONSE 0x15u
#define RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_REQUEST 0x16u
#define RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_RESPONSE 0x17u
#define RDP_VIDEO_CAPTURE_MESSAGE_SET_PROPERTY_VALUE_REQUEST 0x18u
#define RDP_VIDEO_CAPTURE_ERROR_UNEXPECTED 0x00000001u
#define RDP_VIDEO_CAPTURE_ERROR_INVALID_MESSAGE 0x00000002u
#define RDP_VIDEO_CAPTURE_ERROR_NOT_INITIALIZED 0x00000003u
#define RDP_VIDEO_CAPTURE_ERROR_INVALID_REQUEST 0x00000004u
#define RDP_VIDEO_CAPTURE_ERROR_INVALID_STREAM_NUMBER 0x00000005u
#define RDP_VIDEO_CAPTURE_ERROR_INVALID_MEDIA_TYPE 0x00000006u
#define RDP_VIDEO_CAPTURE_ERROR_OUT_OF_MEMORY 0x00000007u
#define RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND 0x00000008u
#define RDP_VIDEO_CAPTURE_ERROR_SET_NOT_FOUND 0x00000009u
#define RDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED 0x0000000au
#define RDP_VIDEO_CAPTURE_STREAM_SOURCE_COLOR 0x0001u
#define RDP_VIDEO_CAPTURE_STREAM_SOURCE_INFRARED 0x0002u
#define RDP_VIDEO_CAPTURE_STREAM_SOURCE_CUSTOM 0x0008u
#define RDP_VIDEO_CAPTURE_STREAM_CATEGORY_CAPTURE 0x01u
#define RDP_VIDEO_CAPTURE_MEDIA_H264 0x01u
#define RDP_VIDEO_CAPTURE_MEDIA_MJPG 0x02u
#define RDP_VIDEO_CAPTURE_MEDIA_YUY2 0x03u
#define RDP_VIDEO_CAPTURE_MEDIA_NV12 0x04u
#define RDP_VIDEO_CAPTURE_MEDIA_I420 0x05u
#define RDP_VIDEO_CAPTURE_MEDIA_RGB24 0x06u
#define RDP_VIDEO_CAPTURE_MEDIA_RGB32 0x07u
#define RDP_VIDEO_CAPTURE_MEDIA_FLAG_DECODING_REQUIRED 0x01u
#define RDP_VIDEO_CAPTURE_MEDIA_FLAG_BOTTOM_UP 0x02u
#define RDP_VIDEO_CAPTURE_MEDIA_TYPE_LENGTH 26u
#define RDP_VIDEO_CAPTURE_PROPERTY_DESCRIPTION_LENGTH 19u
#define RDP_VIDEO_CAPTURE_MAX_STRING_BYTES 4096u
#define RDP_VIDEO_CAPTURE_MAX_SAMPLE_BYTES 16777216u
#define RDP_VIDEO_CAPTURE_MAX_OPAQUE_BYTES 1048576u
#define RDP_VIDEO_CAPTURE_MAX_STREAMS 255u
#define RDP_VIDEO_CAPTURE_MAX_PROPERTIES 64u
#define RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME "RDCamera_Device_Enumerator"
#define RDP_VIDEO_CAPTURE_CHANNEL_NAME "rdpecam"
#define RDP_VIDEO_CAPTURE_PROPERTY_SET_CAMERA_CONTROL 0x01u
#define RDP_VIDEO_CAPTURE_PROPERTY_SET_VIDEO_PROC_AMP 0x02u
#define RDP_VIDEO_CAPTURE_PROPERTY_ID_CAMERA_EXPOSURE 0x01u
#define RDP_VIDEO_CAPTURE_PROPERTY_ID_CAMERA_FOCUS 0x02u
#define RDP_VIDEO_CAPTURE_PROPERTY_ID_CAMERA_PAN 0x03u
#define RDP_VIDEO_CAPTURE_PROPERTY_ID_CAMERA_ROLL 0x04u
#define RDP_VIDEO_CAPTURE_PROPERTY_ID_CAMERA_TILT 0x05u
#define RDP_VIDEO_CAPTURE_PROPERTY_ID_CAMERA_ZOOM 0x06u
#define RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_BACKLIGHT 0x01u
#define RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_BRIGHTNESS 0x02u
#define RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_CONTRAST 0x03u
#define RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_HUE 0x04u
#define RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_WHITE_BALANCE 0x05u
#define RDP_VIDEO_CAPTURE_PROPERTY_CAPABILITY_MANUAL 0x01u
#define RDP_VIDEO_CAPTURE_PROPERTY_CAPABILITY_AUTO 0x02u
#define RDP_VIDEO_CAPTURE_PROPERTY_MODE_MANUAL 0x01u
#define RDP_VIDEO_CAPTURE_PROPERTY_MODE_AUTO 0x02u

typedef struct rdp_video_capture_header
{
    uint8_t version;
    uint8_t message_id;
} rdp_video_capture_header;

typedef struct rdp_video_capture_device_notification
{
    rdp_video_capture_header header;
    const uint8_t* device_name_utf16le;
    size_t device_name_len;
    const uint8_t* channel_name;
    size_t channel_name_len;
} rdp_video_capture_device_notification;

typedef struct rdp_video_capture_error
{
    rdp_video_capture_header header;
    uint32_t error_code;
} rdp_video_capture_error;

typedef struct rdp_video_capture_stream_description
{
    uint16_t frame_source_types;
    uint8_t stream_category;
    uint8_t selected;
    uint8_t can_be_shared;
} rdp_video_capture_stream_description;

typedef struct rdp_video_capture_stream_list
{
    rdp_video_capture_header header;
    uint8_t count;
    rdp_video_capture_stream_description streams[RDP_VIDEO_CAPTURE_MAX_STREAMS];
} rdp_video_capture_stream_list;

typedef struct rdp_video_capture_media_type
{
    uint8_t format;
    uint32_t width;
    uint32_t height;
    uint32_t frame_rate_numerator;
    uint32_t frame_rate_denominator;
    uint32_t pixel_aspect_ratio_numerator;
    uint32_t pixel_aspect_ratio_denominator;
    uint8_t flags;
} rdp_video_capture_media_type;

typedef struct rdp_video_capture_media_list
{
    rdp_video_capture_header header;
    uint8_t count;
    rdp_video_capture_media_type media[RDP_VIDEO_CAPTURE_MAX_STREAMS];
} rdp_video_capture_media_list;

typedef struct rdp_video_capture_stream_index
{
    rdp_video_capture_header header;
    uint8_t stream_index;
} rdp_video_capture_stream_index;

typedef struct rdp_video_capture_sample
{
    rdp_video_capture_header header;
    uint8_t stream_index;
    const uint8_t* sample;
    size_t sample_len;
} rdp_video_capture_sample;

typedef struct rdp_video_capture_opaque
{
    rdp_video_capture_header header;
    const uint8_t* payload;
    size_t payload_len;
} rdp_video_capture_opaque;

typedef struct rdp_video_capture_property_description
{
    uint8_t property_set;
    uint8_t property_id;
    uint8_t capabilities;
    int32_t min_value;
    int32_t max_value;
    int32_t step;
    int32_t default_value;
} rdp_video_capture_property_description;

typedef struct rdp_video_capture_property_list
{
    rdp_video_capture_header header;
    uint8_t count;
    rdp_video_capture_property_description properties[RDP_VIDEO_CAPTURE_MAX_PROPERTIES];
} rdp_video_capture_property_list;

typedef struct rdp_video_capture_property_request
{
    rdp_video_capture_header header;
    uint8_t property_set;
    uint8_t property_id;
} rdp_video_capture_property_request;

typedef struct rdp_video_capture_property_value
{
    uint8_t mode;
    int32_t value;
} rdp_video_capture_property_value;

int rdp_video_capture_version_valid(uint8_t version);
int rdp_video_capture_message_valid(uint8_t version, uint8_t message_id);
librdp_status rdp_video_capture_parse_header(const void* data,
                                             size_t length,
                                             rdp_video_capture_header* header);
librdp_status rdp_video_capture_write_header(rdp_buffer* buffer, uint8_t version, uint8_t message_id);
librdp_status rdp_video_capture_parse_empty(const void* data,
                                            size_t length,
                                            uint8_t expected_message_id,
                                            rdp_video_capture_header* header);
librdp_status rdp_video_capture_write_empty(rdp_buffer* buffer, uint8_t version, uint8_t message_id);
librdp_status rdp_video_capture_parse_error(const void* data,
                                            size_t length,
                                            rdp_video_capture_error* error);
librdp_status rdp_video_capture_write_error(rdp_buffer* buffer, uint8_t version, uint32_t error_code);
librdp_status rdp_video_capture_parse_device_added(
    const void* data,
    size_t length,
    rdp_video_capture_device_notification* notification);
librdp_status rdp_video_capture_write_device_added(rdp_buffer* buffer,
                                                   uint8_t version,
                                                   const void* device_name_utf16le,
                                                   size_t device_name_len,
                                                   const char* channel_name);
librdp_status rdp_video_capture_parse_device_removed(
    const void* data,
    size_t length,
    rdp_video_capture_device_notification* notification);
librdp_status rdp_video_capture_write_device_removed(rdp_buffer* buffer,
                                                     uint8_t version,
                                                     const char* channel_name);
librdp_status rdp_video_capture_parse_stream_list(const void* data,
                                                  size_t length,
                                                  rdp_video_capture_stream_list* list);
librdp_status rdp_video_capture_write_stream_list(
    rdp_buffer* buffer,
    uint8_t version,
    const rdp_video_capture_stream_description* streams,
    uint8_t count);
librdp_status rdp_video_capture_parse_media_type(const void* data,
                                                 size_t length,
                                                 rdp_video_capture_media_type* media);
librdp_status rdp_video_capture_write_media_type(rdp_buffer* buffer,
                                                 const rdp_video_capture_media_type* media);
librdp_status rdp_video_capture_parse_media_list(const void* data,
                                                 size_t length,
                                                 uint8_t expected_message_id,
                                                 rdp_video_capture_media_list* list);
librdp_status rdp_video_capture_write_media_list(rdp_buffer* buffer,
                                                 uint8_t version,
                                                 uint8_t message_id,
                                                 const rdp_video_capture_media_type* media,
                                                 uint8_t count);
librdp_status rdp_video_capture_parse_stream_index(const void* data,
                                                   size_t length,
                                                   uint8_t expected_message_id,
                                                   rdp_video_capture_stream_index* request);
librdp_status rdp_video_capture_write_stream_index(rdp_buffer* buffer,
                                                   uint8_t version,
                                                   uint8_t message_id,
                                                   uint8_t stream_index);
librdp_status rdp_video_capture_parse_sample(const void* data,
                                             size_t length,
                                             rdp_video_capture_sample* sample);
librdp_status rdp_video_capture_write_sample(rdp_buffer* buffer,
                                             uint8_t version,
                                             uint8_t stream_index,
                                             const void* sample,
                                             size_t sample_len);
librdp_status rdp_video_capture_parse_sample_error(const void* data,
                                                   size_t length,
                                                   rdp_video_capture_error* error,
                                                   uint8_t* stream_index);
librdp_status rdp_video_capture_write_sample_error(rdp_buffer* buffer,
                                                   uint8_t version,
                                                   uint8_t stream_index,
                                                   uint32_t error_code);
librdp_status rdp_video_capture_parse_opaque(const void* data,
                                             size_t length,
                                             uint8_t expected_message_id,
                                             rdp_video_capture_opaque* pdu);
librdp_status rdp_video_capture_write_opaque(rdp_buffer* buffer,
                                             uint8_t version,
                                             uint8_t message_id,
                                             const void* payload,
                                             size_t payload_len);
librdp_status rdp_video_capture_parse_property_list(const void* data,
                                                    size_t length,
                                                    rdp_video_capture_property_list* list);
librdp_status rdp_video_capture_write_property_list(
    rdp_buffer* buffer,
    uint8_t version,
    const rdp_video_capture_property_description* properties,
    uint8_t count);
librdp_status rdp_video_capture_parse_property_request(
    const void* data,
    size_t length,
    uint8_t expected_message_id,
    rdp_video_capture_property_request* request);
librdp_status rdp_video_capture_parse_set_property_request(
    const void* data,
    size_t length,
    rdp_video_capture_property_request* request,
    rdp_video_capture_property_value* value);
librdp_status rdp_video_capture_parse_property_value(const void* data,
                                                     size_t length,
                                                     rdp_video_capture_property_value* value);
librdp_status rdp_video_capture_write_property_value(rdp_buffer* buffer,
                                                     uint8_t version,
                                                     const rdp_video_capture_property_value* value);

#endif
