/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "channels/video_capture.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_video_capture_header header;
    rdp_video_capture_device_notification notice;
    rdp_video_capture_error error;
    rdp_video_capture_stream_list stream_list;
    rdp_video_capture_media_type media;
    rdp_video_capture_media_list media_list;
    rdp_video_capture_stream_index stream_index;
    rdp_video_capture_sample sample;
    rdp_video_capture_opaque opaque;
    rdp_video_capture_stream_description stream = {
        RDP_VIDEO_CAPTURE_STREAM_SOURCE_COLOR,
        RDP_VIDEO_CAPTURE_STREAM_CATEGORY_CAPTURE,
        1,
        0
    };
    rdp_video_capture_media_type writable_media = {
        RDP_VIDEO_CAPTURE_MEDIA_NV12,
        640,
        480,
        30,
        1,
        1,
        1,
        0
    };
    rdp_buffer buffer;
    size_t bounded_sample = size > RDP_VIDEO_CAPTURE_MAX_SAMPLE_BYTES ?
        RDP_VIDEO_CAPTURE_MAX_SAMPLE_BYTES :
        size;
    size_t bounded_opaque = size > RDP_VIDEO_CAPTURE_MAX_OPAQUE_BYTES ?
        RDP_VIDEO_CAPTURE_MAX_OPAQUE_BYTES :
        size;

    (void)rdp_video_capture_parse_header(data, size, &header);
    (void)rdp_video_capture_parse_empty(data, size, RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE, &header);
    (void)rdp_video_capture_parse_error(data, size, &error);
    (void)rdp_video_capture_parse_device_added(data, size, &notice);
    (void)rdp_video_capture_parse_device_removed(data, size, &notice);
    (void)rdp_video_capture_parse_stream_list(data, size, &stream_list);
    (void)rdp_video_capture_parse_media_type(data, size, &media);
    (void)rdp_video_capture_parse_media_list(data, size, RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_RESPONSE, &media_list);
    (void)rdp_video_capture_parse_stream_index(data, size, RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_REQUEST, &stream_index);
    (void)rdp_video_capture_parse_sample(data, size, &sample);
    (void)rdp_video_capture_parse_sample_error(data, size, &error, &header.version);
    (void)rdp_video_capture_parse_opaque(data, size, RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_RESPONSE, &opaque);

    rdp_buffer_init(&buffer);
    (void)rdp_video_capture_write_empty(&buffer, RDP_VIDEO_CAPTURE_VERSION_2, RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE);
    buffer.length = 0;
    (void)rdp_video_capture_write_error(&buffer, RDP_VIDEO_CAPTURE_VERSION_2, RDP_VIDEO_CAPTURE_ERROR_INVALID_REQUEST);
    buffer.length = 0;
    (void)rdp_video_capture_write_device_added(&buffer, RDP_VIDEO_CAPTURE_VERSION_2, data, size & ~(size_t)1u, "cam");
    buffer.length = 0;
    (void)rdp_video_capture_write_device_removed(&buffer, RDP_VIDEO_CAPTURE_VERSION_2, "cam");
    buffer.length = 0;
    (void)rdp_video_capture_write_stream_list(&buffer, RDP_VIDEO_CAPTURE_VERSION_2, &stream, 1);
    buffer.length = 0;
    (void)rdp_video_capture_write_media_type(&buffer, &writable_media);
    buffer.length = 0;
    (void)rdp_video_capture_write_media_list(&buffer,
                                             RDP_VIDEO_CAPTURE_VERSION_2,
                                             RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_RESPONSE,
                                             &writable_media,
                                             1);
    buffer.length = 0;
    (void)rdp_video_capture_write_stream_index(&buffer,
                                               RDP_VIDEO_CAPTURE_VERSION_2,
                                               RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_REQUEST,
                                               0);
    buffer.length = 0;
    (void)rdp_video_capture_write_sample(&buffer, RDP_VIDEO_CAPTURE_VERSION_2, 0, data, bounded_sample);
    buffer.length = 0;
    (void)rdp_video_capture_write_sample_error(&buffer,
                                               RDP_VIDEO_CAPTURE_VERSION_2,
                                               0,
                                               RDP_VIDEO_CAPTURE_ERROR_INVALID_STREAM_NUMBER);
    buffer.length = 0;
    (void)rdp_video_capture_write_opaque(&buffer,
                                         RDP_VIDEO_CAPTURE_VERSION_2,
                                         RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_RESPONSE,
                                         data,
                                         bounded_opaque);
    rdp_buffer_free(&buffer);
    return 0;
}
