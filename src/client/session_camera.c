/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client camera redirection session domain.
 * Invariants: camera sample requests have exactly one reply and streaming state gates every sample response.
 * Ownership: configured sources are borrowed from settings, generated sample buffers are temporary, and public callback payloads are borrowed.
 * Threading: called on the session owner thread; public camera reply APIs enforce the owner-thread contract.
 * Trust boundary: camera source paths and server requests are untrusted, type-checked, size-capped, and never traced as raw payloads.
 */

#include "client/session_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

void rdp_session_video_capture_reset(librdp_session* session)
{
    if (!session)
        return;
    session->video_capture_control_channel_id = 0;
    session->video_capture_control_channel_id_bytes = 0;
    session->video_capture_channel_id = 0;
    session->video_capture_channel_id_bytes = 0;
    session->video_capture_version = 0;
    session->video_capture_active = 0;
    session->video_capture_streaming = 0;
    session->video_capture_selected_stream = 0;
    session->video_capture_sample_reply_pending = 0;
    memset(&session->video_capture_media, 0, sizeof(session->video_capture_media));
    session->video_capture_brightness_mode = RDP_VIDEO_CAPTURE_PROPERTY_MODE_MANUAL;
    session->video_capture_brightness = RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_DEFAULT;
}

static uint8_t rdp_session_video_capture_version(const librdp_session* session)
{
    if (!session || session->video_capture_version == 0)
        return RDP_VIDEO_CAPTURE_VERSION_2;
    return session->video_capture_version;
}

static const char* rdp_session_video_capture_source(const librdp_session* session)
{
    if (!session || !rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_CAMERA) ||
        librdp_settings_camera_count(session->settings) == 0)
        return NULL;
    return librdp_settings_camera_source(session->settings, 0);
}

static const char* rdp_session_video_capture_source_value(const char* source)
{
    if (!source)
        return NULL;
    if (strncmp(source, "device=", 7u) == 0 && source[7] != '\0')
        return source + 7u;
    if (strncmp(source, "file=", 5u) == 0 && source[5] != '\0')
        return source + 5u;
    return source;
}

static const char* rdp_session_video_capture_source_kind(const char* source)
{
    struct stat st;
    const char* value = rdp_session_video_capture_source_value(source);

    if (!source || source[0] == '\0' || !value || value[0] == '\0')
        return "none";
    if (strncmp(source, "file=", 5u) == 0)
        return "file";
    if (strncmp(source, "device=", 7u) == 0)
        return "device";
    memset(&st, 0, sizeof(st));
    if (stat(value, &st) == 0 && S_ISREG(st.st_mode))
        return "file";
    return "device";
}

static int rdp_session_video_capture_source_is_file(const char* source)
{
    struct stat st;
    const char* value = rdp_session_video_capture_source_value(source);

    if (!source || source[0] == '\0' || !value || value[0] == '\0')
        return 0;
    if (strncmp(source, "file=", 5u) == 0)
        return 1;
    memset(&st, 0, sizeof(st));
    return stat(value, &st) == 0 && S_ISREG(st.st_mode);
}

static void rdp_session_video_capture_media_from_source(const char* source,
                                                        rdp_video_capture_media_type* media)
{
    const char* value = rdp_session_video_capture_source_value(source);
    const char* ext = value ? strrchr(value, '.') : NULL;

    memset(media, 0, sizeof(*media));
    media->format = RDP_VIDEO_CAPTURE_MEDIA_NV12;
    media->width = RDP_SESSION_VIDEO_CAPTURE_DEFAULT_WIDTH;
    media->height = RDP_SESSION_VIDEO_CAPTURE_DEFAULT_HEIGHT;
    media->frame_rate_numerator = RDP_SESSION_VIDEO_CAPTURE_DEFAULT_FPS;
    media->frame_rate_denominator = 1;
    media->pixel_aspect_ratio_numerator = 1;
    media->pixel_aspect_ratio_denominator = 1;
    media->flags = 0;
    if ((source && strncmp(source, "device=", 7u) == 0) ||
        (value && strncmp(value, "/dev/video", 10u) == 0))
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_MJPG;
        media->flags = RDP_VIDEO_CAPTURE_MEDIA_FLAG_DECODING_REQUIRED;
    }
    if (!value || !ext)
        return;
    if (strcasecmp(ext, ".h264") == 0 || strcasecmp(ext, ".avc") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_H264;
        media->flags = RDP_VIDEO_CAPTURE_MEDIA_FLAG_DECODING_REQUIRED;
    }
    else if (strcasecmp(ext, ".jpg") == 0 || strcasecmp(ext, ".jpeg") == 0 ||
             strcasecmp(ext, ".mjpg") == 0 || strcasecmp(ext, ".mjpeg") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_MJPG;
        media->flags = RDP_VIDEO_CAPTURE_MEDIA_FLAG_DECODING_REQUIRED;
    }
    else if (strcasecmp(ext, ".yuy2") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_YUY2;
    }
    else if (strcasecmp(ext, ".i420") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_I420;
    }
    else if (strcasecmp(ext, ".rgb24") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_RGB24;
    }
    else if (strcasecmp(ext, ".rgb32") == 0 || strcasecmp(ext, ".bgra") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_RGB32;
    }
}

static void rdp_session_video_capture_update_media(librdp_session* session, const char* source)
{
    if (!session)
        return;
    rdp_session_video_capture_media_from_source(source, &session->video_capture_media);
}

static void rdp_session_video_capture_media_to_public(const rdp_video_capture_media_type* in,
                                                      librdp_video_capture_media* out)
{
    if (!in || !out)
        return;
    memset(out, 0, sizeof(*out));
    out->format = in->format;
    out->width = in->width;
    out->height = in->height;
    out->frame_rate_numerator = in->frame_rate_numerator;
    out->frame_rate_denominator = in->frame_rate_denominator;
    out->pixel_aspect_ratio_numerator = in->pixel_aspect_ratio_numerator;
    out->pixel_aspect_ratio_denominator = in->pixel_aspect_ratio_denominator;
    out->flags = in->flags;
}

static void rdp_session_emit_video_capture_open(librdp_session* session, uint8_t stream_index)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_VIDEO_CAPTURE_OPEN;
    event.data.video_capture_open.stream_index = stream_index;
    rdp_session_video_capture_media_to_public(&session->video_capture_media,
                                              &event.data.video_capture_open.media);
    rdp_session_emit(session, &event);
}

static void rdp_session_emit_video_capture_sample_request(librdp_session* session, uint8_t stream_index)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_VIDEO_CAPTURE_SAMPLE_REQUEST;
    event.data.video_capture_sample_request.stream_index = stream_index;
    rdp_session_video_capture_media_to_public(&session->video_capture_media,
                                              &event.data.video_capture_sample_request.media);
    rdp_session_emit(session, &event);
}

static void rdp_session_emit_video_capture_close(librdp_session* session, uint8_t stream_index)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_VIDEO_CAPTURE_CLOSE;
    event.data.video_capture_close.stream_index = stream_index;
    rdp_session_emit(session, &event);
}

/*
 * Reads one synthetic camera sample from a viewer-provided file source. The
 * source string is untrusted configuration, so the function opens the final
 * path directly, refuses symlink traversal when the platform exposes
 * O_NOFOLLOW, validates the resulting descriptor with fstat, and caps the
 * accumulated sample before it can be queued on the video-capture channel.
 * Failures are converted to the protocol error code consumed by the caller.
 */
static librdp_status rdp_session_video_capture_read_sample(const char* source,
                                                           rdp_buffer* sample,
                                                           uint32_t* error_code)
{
    struct stat st;
    const char* value = rdp_session_video_capture_source_value(source);
    int fd = -1;
    int flags = O_RDONLY;
    uint8_t chunk[8192];
    librdp_status status = LIBRDP_STATUS_OK;

    if (error_code)
        *error_code = RDP_VIDEO_CAPTURE_ERROR_UNEXPECTED;
    if (!source || !sample || !error_code)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&st, 0, sizeof(st));
    if (!value || value[0] == '\0')
    {
        *error_code = RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND;
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    fd = open(value, flags);
    if (fd < 0)
    {
        *error_code = errno == EACCES ? RDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED :
                                        RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND;
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    if (fstat(fd, &st) != 0)
    {
        *error_code = RDP_VIDEO_CAPTURE_ERROR_UNEXPECTED;
        close(fd);
        return LIBRDP_STATUS_IO_ERROR;
    }
    if (!S_ISREG(st.st_mode))
    {
        *error_code = RDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED;
        close(fd);
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    if (st.st_size < 0 || (uint64_t)st.st_size > RDP_VIDEO_CAPTURE_MAX_SAMPLE_BYTES)
    {
        *error_code = RDP_VIDEO_CAPTURE_ERROR_INVALID_MEDIA_TYPE;
        close(fd);
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    for (;;)
    {
        ssize_t count = read(fd, chunk, sizeof(chunk));

        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0)
        {
            *error_code = RDP_VIDEO_CAPTURE_ERROR_UNEXPECTED;
            status = LIBRDP_STATUS_IO_ERROR;
            break;
        }
        if (count == 0)
            break;
        if ((uint64_t)sample->length + (uint64_t)count > RDP_VIDEO_CAPTURE_MAX_SAMPLE_BYTES)
        {
            *error_code = RDP_VIDEO_CAPTURE_ERROR_INVALID_MEDIA_TYPE;
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        }
        status = rdp_buffer_append(sample, chunk, (size_t)count);
        if (status != LIBRDP_STATUS_OK)
        {
            *error_code = status == LIBRDP_STATUS_NO_MEMORY ?
                              RDP_VIDEO_CAPTURE_ERROR_OUT_OF_MEMORY :
                              RDP_VIDEO_CAPTURE_ERROR_UNEXPECTED;
            break;
        }
    }
    close(fd);
    return status;
}

static librdp_status rdp_session_send_video_capture_packet(librdp_session* session,
                                                           uint32_t channel_id,
                                                           uint8_t channel_id_bytes,
                                                           const rdp_buffer* payload,
                                                           const char* event)
{
    if (!session || !payload || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (channel_id == 0 || channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    return rdp_session_send_dynamic_channel_data(session,
                                                 channel_id,
                                                 channel_id_bytes,
                                                 payload->data,
                                                 payload->length,
                                                 event);
}

static librdp_status rdp_session_send_video_capture_control(librdp_session* session,
                                                            const rdp_buffer* payload,
                                                            const char* event)
{
    return rdp_session_send_video_capture_packet(session,
                                                 session ? session->video_capture_control_channel_id : 0,
                                                 session ? session->video_capture_control_channel_id_bytes : 0,
                                                 payload,
                                                 event);
}

static librdp_status rdp_session_send_video_capture_data(librdp_session* session,
                                                         const rdp_buffer* payload,
                                                         const char* event)
{
    return rdp_session_send_video_capture_packet(session,
                                                 session ? session->video_capture_channel_id : 0,
                                                 session ? session->video_capture_channel_id_bytes : 0,
                                                 payload,
                                                 event);
}

static librdp_status rdp_session_send_video_capture_error(librdp_session* session,
                                                          int control_channel,
                                                          uint32_t error_code,
                                                          const char* event)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t version = rdp_session_video_capture_version(session);

    if (!session || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_error(&response, version, error_code);
    if (status == LIBRDP_STATUS_OK)
    {
        status = control_channel ?
                     rdp_session_send_video_capture_control(session, &response, event) :
                     rdp_session_send_video_capture_data(session, &response, event);
    }
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event,
                        "channel=%s error=%u",
                        control_channel ? "control" : "data",
                        error_code);
    return status;
}

static librdp_status rdp_session_send_video_capture_success(librdp_session* session, const char* event)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t version = rdp_session_video_capture_version(session);

    if (!session || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_empty(&response,
                                           version,
                                           RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session, &response, event);
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event,
                        "dvc_channel_id=%u version=%u",
                        session->video_capture_channel_id,
                        version);
    return status;
}

static librdp_status rdp_session_send_video_capture_device_added(librdp_session* session)
{
    const char* source = rdp_session_video_capture_source(session);
    rdp_buffer device_name;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t version = rdp_session_video_capture_version(session);

    if (!session || !source)
        return LIBRDP_STATUS_OK;
    rdp_buffer_init(&device_name);
    rdp_buffer_init(&response);
    status = rdp_session_utf8_to_utf16le("Camera", &device_name, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_video_capture_write_device_added(&response,
                                                      version,
                                                      device_name.data,
                                                      device_name.length,
                                                      RDP_VIDEO_CAPTURE_CHANNEL_NAME);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_control(session,
                                                        &response,
                                                        "client.rdpecam.device.added");
    rdp_buffer_free(&response);
    rdp_buffer_free(&device_name);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.device.added",
                        "control_channel_id=%u capture_channel=%s source_kind=%s version=%u",
                        session->video_capture_control_channel_id,
                        RDP_VIDEO_CAPTURE_CHANNEL_NAME,
                        rdp_session_video_capture_source_kind(source),
                        version);
    return status;
}

static librdp_status rdp_session_send_video_capture_stream_list(librdp_session* session)
{
    const char* source = rdp_session_video_capture_source(session);
    rdp_video_capture_stream_description stream;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!source)
        return rdp_session_send_video_capture_error(session,
                                                    0,
                                                    RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND,
                                                    "client.rdpecam.stream_list.error");
    memset(&stream, 0, sizeof(stream));
    stream.frame_source_types = RDP_VIDEO_CAPTURE_STREAM_SOURCE_COLOR;
    stream.stream_category = RDP_VIDEO_CAPTURE_STREAM_CATEGORY_CAPTURE;
    stream.selected = 1;
    stream.can_be_shared = 1;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_stream_list(&response,
                                                 rdp_session_video_capture_version(session),
                                                 &stream,
                                                 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session,
                                                     &response,
                                                     "client.rdpecam.stream_list.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.stream_list.response",
                        "dvc_channel_id=%u count=1 source_kind=%s",
                        session->video_capture_channel_id,
                        rdp_session_video_capture_source_kind(source));
    return status;
}

static librdp_status rdp_session_send_video_capture_media_list(librdp_session* session,
                                                               uint8_t message_id,
                                                               const char* event)
{
    const char* source = rdp_session_video_capture_source(session);
    rdp_video_capture_media_type media;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!source)
        return rdp_session_send_video_capture_error(session,
                                                    0,
                                                    RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND,
                                                    "client.rdpecam.media.error");
    rdp_session_video_capture_update_media(session, source);
    media = session->video_capture_media;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_media_list(&response,
                                                rdp_session_video_capture_version(session),
                                                message_id,
                                                &media,
                                                1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session, &response, event);
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event,
                        "dvc_channel_id=%u format=%u width=%u height=%u fps_num=%u fps_den=%u flags=%u",
                        session->video_capture_channel_id,
                        media.format,
                        media.width,
                        media.height,
                        media.frame_rate_numerator,
                        media.frame_rate_denominator,
                        media.flags);
    return status;
}

static int rdp_session_video_capture_property_is_brightness(
    const rdp_video_capture_property_request* request)
{
    return request &&
           request->property_set == RDP_VIDEO_CAPTURE_PROPERTY_SET_VIDEO_PROC_AMP &&
           request->property_id == RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_BRIGHTNESS;
}

static rdp_video_capture_property_description rdp_session_video_capture_brightness_property(void)
{
    rdp_video_capture_property_description property;

    memset(&property, 0, sizeof(property));
    property.property_set = RDP_VIDEO_CAPTURE_PROPERTY_SET_VIDEO_PROC_AMP;
    property.property_id = RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_BRIGHTNESS;
    property.capabilities = RDP_VIDEO_CAPTURE_PROPERTY_CAPABILITY_MANUAL |
                            RDP_VIDEO_CAPTURE_PROPERTY_CAPABILITY_AUTO;
    property.min_value = RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_MIN;
    property.max_value = RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_MAX;
    property.step = RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_STEP;
    property.default_value = RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_DEFAULT;
    return property;
}

static librdp_status rdp_session_send_video_capture_property_list(librdp_session* session)
{
    rdp_video_capture_property_description property;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    property = rdp_session_video_capture_brightness_property();
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_property_list(&response,
                                                   rdp_session_video_capture_version(session),
                                                   &property,
                                                   1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session,
                                                     &response,
                                                     "client.rdpecam.property_list.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.property_list.response",
                        "dvc_channel_id=%u count=1 property_set=%u property_id=%u",
                        session->video_capture_channel_id,
                        property.property_set,
                        property.property_id);
    return status;
}

static librdp_status rdp_session_send_video_capture_property_value(librdp_session* session,
                                                                   const char* event)
{
    rdp_video_capture_property_value value;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&value, 0, sizeof(value));
    value.mode = session->video_capture_brightness_mode;
    value.value = session->video_capture_brightness;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_property_value(&response,
                                                    rdp_session_video_capture_version(session),
                                                    &value);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session, &response, event);
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event,
                        "dvc_channel_id=%u property_set=%u property_id=%u mode=%u value=%d",
                        session->video_capture_channel_id,
                        RDP_VIDEO_CAPTURE_PROPERTY_SET_VIDEO_PROC_AMP,
                        RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_BRIGHTNESS,
                        value.mode,
                        value.value);
    return status;
}

static librdp_status rdp_session_send_video_capture_sample_error(librdp_session* session,
                                                                 uint8_t stream_index,
                                                                 uint32_t error_code)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_sample_error(&response,
                                                  rdp_session_video_capture_version(session),
                                                  stream_index,
                                                  error_code);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session,
                                                     &response,
                                                     "client.rdpecam.sample.error");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
    {
        session->video_capture_sample_reply_pending = 0;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.sample.error",
                        "dvc_channel_id=%u stream=%u error=%u",
                        session->video_capture_channel_id,
                        stream_index,
                        error_code);
    }
    return status;
}

static librdp_status rdp_session_send_video_capture_sample_payload(librdp_session* session,
                                                                   uint8_t stream_index,
                                                                   const void* data,
                                                                   size_t data_len,
                                                                   const char* event)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0) || !event ||
        data_len > RDP_VIDEO_CAPTURE_MAX_SAMPLE_BYTES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_sample(&response,
                                            rdp_session_video_capture_version(session),
                                            stream_index,
                                            data,
                                            data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session, &response, event);
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
    {
        session->video_capture_sample_reply_pending = 0;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event,
                        "dvc_channel_id=%u stream=%u data_len=%u",
                        session->video_capture_channel_id,
                        stream_index,
                        (unsigned)data_len);
    }
    return status;
}

static librdp_status rdp_session_send_video_capture_sample(librdp_session* session, uint8_t stream_index)
{
    const char* source = rdp_session_video_capture_source(session);
    rdp_buffer sample;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t error_code = RDP_VIDEO_CAPTURE_ERROR_UNEXPECTED;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!source)
        return rdp_session_send_video_capture_sample_error(session,
                                                          stream_index,
                                                          RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND);
    rdp_buffer_init(&sample);
    status = rdp_session_video_capture_read_sample(source, &sample, &error_code);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_sample_payload(session,
                                                               stream_index,
                                                               sample.data,
                                                               sample.length,
                                                               "client.rdpecam.sample.response");
    rdp_buffer_free(&sample);
    if (status == LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_OK;
    return rdp_session_send_video_capture_sample_error(session, stream_index, error_code);
}

/*
 * Handle redirected camera control messages. Open, sample request, close, and
 * error paths keep backend state and protocol request IDs synchronized.
 */
librdp_status rdp_session_handle_video_capture_control_message(librdp_session* session,
                                                                      uint32_t channel_id,
                                                                      const uint8_t* data,
                                                                      size_t data_len)
{
    rdp_video_capture_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_capture_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.control.invalid",
                        "dvc_channel_id=%u payload_len=%u status=%s",
                        channel_id,
                        (unsigned)data_len,
                        librdp_status_string(status));
        return status;
    }
    session->video_capture_version = header.version == RDP_VIDEO_CAPTURE_VERSION_1 ?
                                         RDP_VIDEO_CAPTURE_VERSION_1 :
                                         RDP_VIDEO_CAPTURE_VERSION_2;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.rdpecam.control.pdu",
                          "dvc_channel_id=%u version=%u message_id=%u payload_len=%u enabled=%u cameras=%u",
                          channel_id,
                          header.version,
                          header.message_id,
                          (unsigned)data_len,
                          rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_CAMERA),
                          librdp_settings_camera_count(session->settings));
    switch (header.message_id)
    {
        case RDP_VIDEO_CAPTURE_MESSAGE_SELECT_VERSION_REQUEST:
        {
            rdp_buffer response;
            rdp_video_capture_header request;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_SELECT_VERSION_REQUEST,
                                                   &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_buffer_init(&response);
            status = rdp_video_capture_write_empty(&response,
                                                   session->video_capture_version,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_SELECT_VERSION_RESPONSE);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_send_video_capture_control(session,
                                                                &response,
                                                                "client.rdpecam.version.response");
            rdp_buffer_free(&response);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.version.response",
                            "dvc_channel_id=%u version=%u",
                            channel_id,
                            session->video_capture_version);
            return rdp_session_send_video_capture_device_added(session);
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE:
        {
            rdp_video_capture_header response;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE,
                                                   &response);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.control.success",
                            "dvc_channel_id=%u version=%u",
                            channel_id,
                            response.version);
            break;
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_ERROR_RESPONSE:
        {
            rdp_video_capture_error error;

            status = rdp_video_capture_parse_error(data, data_len, &error);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.control.error",
                            "dvc_channel_id=%u error=%u",
                            channel_id,
                            error.error_code);
            break;
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_DEVICE_REMOVED:
        {
            rdp_video_capture_device_notification removed;

            status = rdp_video_capture_parse_device_removed(data, data_len, &removed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.device.removed",
                            "dvc_channel_id=%u channel_name_len=%u",
                            channel_id,
                            (unsigned)removed.channel_name_len);
            break;
        }
        default:
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.control.invalid_message",
                            "dvc_channel_id=%u message_id=%u payload_len=%u",
                            channel_id,
                            header.message_id,
                            (unsigned)data_len);
            return rdp_session_send_video_capture_error(session,
                                                        1,
                                                        RDP_VIDEO_CAPTURE_ERROR_INVALID_MESSAGE,
                                                        "client.rdpecam.control.error");
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Camera data-channel messages drive a request/reply protocol: open selects a
 * source, sample requests arm exactly one pending reply, and close/error clear
 * the streaming state. Keeping that state here prevents duplicate replies.
 */
librdp_status rdp_session_handle_video_capture_data_message(librdp_session* session,
                                                                   uint32_t channel_id,
                                                                   const uint8_t* data,
                                                                   size_t data_len)
{
    rdp_video_capture_header header;
    librdp_status status = LIBRDP_STATUS_OK;
    const char* source = NULL;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_capture_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.data.invalid",
                        "dvc_channel_id=%u payload_len=%u status=%s",
                        channel_id,
                        (unsigned)data_len,
                        librdp_status_string(status));
        return status;
    }
    session->video_capture_version = header.version;
    source = rdp_session_video_capture_source(session);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.rdpecam.data.pdu",
                          "dvc_channel_id=%u version=%u message_id=%u payload_len=%u active=%u streaming=%u source_kind=%s",
                          channel_id,
                          header.version,
                          header.message_id,
                          (unsigned)data_len,
                          session->video_capture_active,
                          session->video_capture_streaming,
                          rdp_session_video_capture_source_kind(source));
    switch (header.message_id)
    {
        case RDP_VIDEO_CAPTURE_MESSAGE_ACTIVATE_DEVICE_REQUEST:
        {
            rdp_video_capture_header request;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_ACTIVATE_DEVICE_REQUEST,
                                                   &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (!source)
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND,
                                                            "client.rdpecam.activate.error");
            session->video_capture_active = 1;
            return rdp_session_send_video_capture_success(session, "client.rdpecam.activate.success");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_DEACTIVATE_DEVICE_REQUEST:
        {
            rdp_video_capture_header request;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_DEACTIVATE_DEVICE_REQUEST,
                                                   &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (session->video_capture_streaming)
                rdp_session_emit_video_capture_close(session, session->video_capture_selected_stream);
            session->video_capture_active = 0;
            session->video_capture_streaming = 0;
            return rdp_session_send_video_capture_success(session, "client.rdpecam.deactivate.success");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_STREAM_LIST_REQUEST:
        {
            rdp_video_capture_header request;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_STREAM_LIST_REQUEST,
                                                   &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            return rdp_session_send_video_capture_stream_list(session);
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_REQUEST:
        case RDP_VIDEO_CAPTURE_MESSAGE_CURRENT_MEDIA_TYPE_REQUEST:
        {
            rdp_video_capture_stream_index request;
            uint8_t response_id = header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_REQUEST ?
                                      RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_RESPONSE :
                                      RDP_VIDEO_CAPTURE_MESSAGE_CURRENT_MEDIA_TYPE_RESPONSE;

            status = rdp_video_capture_parse_stream_index(data, data_len, header.message_id, &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (request.stream_index != 0)
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_INVALID_STREAM_NUMBER,
                                                            "client.rdpecam.media.error");
            return rdp_session_send_video_capture_media_list(
                session,
                response_id,
                response_id == RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_RESPONSE ?
                    "client.rdpecam.media_list.response" :
                    "client.rdpecam.current_media.response");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_START_STREAMS_REQUEST:
        case RDP_VIDEO_CAPTURE_MESSAGE_STOP_STREAMS_REQUEST:
        {
            rdp_video_capture_stream_index request;

            status = rdp_video_capture_parse_stream_index(data, data_len, header.message_id, &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (request.stream_index != 0)
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_INVALID_STREAM_NUMBER,
                                                            "client.rdpecam.stream.error");
            if (!source)
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND,
                                                            "client.rdpecam.stream.error");
            rdp_session_video_capture_update_media(session, source);
            session->video_capture_selected_stream = request.stream_index;
            session->video_capture_active = header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_START_STREAMS_REQUEST ?
                                                1u :
                                                session->video_capture_active;
            session->video_capture_streaming =
                header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_START_STREAMS_REQUEST ? 1u : 0u;
            if (header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_START_STREAMS_REQUEST &&
                !rdp_session_video_capture_source_is_file(source))
                rdp_session_emit_video_capture_open(session, request.stream_index);
            if (header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_STOP_STREAMS_REQUEST)
                rdp_session_emit_video_capture_close(session, request.stream_index);
            return rdp_session_send_video_capture_success(
                session,
                header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_START_STREAMS_REQUEST ?
                    "client.rdpecam.stream.start.success" :
                    "client.rdpecam.stream.stop.success");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_REQUEST:
        {
            rdp_video_capture_stream_index request;

            status = rdp_video_capture_parse_stream_index(data,
                                                          data_len,
                                                          RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_REQUEST,
                                                          &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (request.stream_index != session->video_capture_selected_stream)
                return rdp_session_send_video_capture_sample_error(
                    session,
                    request.stream_index,
                    RDP_VIDEO_CAPTURE_ERROR_INVALID_STREAM_NUMBER);
            if (!session->video_capture_active || !session->video_capture_streaming)
                return rdp_session_send_video_capture_sample_error(
                    session,
                    request.stream_index,
                    RDP_VIDEO_CAPTURE_ERROR_NOT_INITIALIZED);
            if (!rdp_session_video_capture_source_is_file(source))
            {
                session->video_capture_sample_reply_pending = 1;
                rdp_session_emit_video_capture_sample_request(session, request.stream_index);
                if (session->video_capture_sample_reply_pending)
                {
                    session->video_capture_sample_reply_pending = 0;
                    return rdp_session_send_video_capture_sample_error(
                        session,
                        request.stream_index,
                        RDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED);
                }
                return LIBRDP_STATUS_OK;
            }
            return rdp_session_send_video_capture_sample(session, request.stream_index);
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_LIST_REQUEST:
        {
            rdp_video_capture_header request;

            status = rdp_video_capture_parse_empty(data,
                                                    data_len,
                                                    RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_LIST_REQUEST,
                                                    &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            return rdp_session_send_video_capture_property_list(session);
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_REQUEST:
        {
            rdp_video_capture_property_request request;

            status = rdp_video_capture_parse_property_request(
                data,
                data_len,
                RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_REQUEST,
                &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (!rdp_session_video_capture_property_is_brightness(&request))
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_SET_NOT_FOUND,
                                                            "client.rdpecam.property.error");
            return rdp_session_send_video_capture_property_value(
                session,
                "client.rdpecam.property_value.response");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_SET_PROPERTY_VALUE_REQUEST:
        {
            rdp_video_capture_property_request request;
            rdp_video_capture_property_value value;

            status = rdp_video_capture_parse_set_property_request(data, data_len, &request, &value);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (!rdp_session_video_capture_property_is_brightness(&request))
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_SET_NOT_FOUND,
                                                            "client.rdpecam.property.error");
            if (value.mode == RDP_VIDEO_CAPTURE_PROPERTY_MODE_MANUAL &&
                (value.value < RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_MIN ||
                 value.value > RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_MAX))
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_INVALID_REQUEST,
                                                            "client.rdpecam.property.error");
            session->video_capture_brightness_mode = value.mode;
            if (value.mode == RDP_VIDEO_CAPTURE_PROPERTY_MODE_MANUAL)
                session->video_capture_brightness = value.value;
            else
                session->video_capture_brightness = RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_DEFAULT;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.property.set",
                            "dvc_channel_id=%u property_set=%u property_id=%u mode=%u value=%d",
                            session->video_capture_channel_id,
                            request.property_set,
                            request.property_id,
                            session->video_capture_brightness_mode,
                            session->video_capture_brightness);
            return rdp_session_send_video_capture_success(session,
                                                          "client.rdpecam.property.set.success");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE:
        {
            rdp_video_capture_header response;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE,
                                                   &response);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.data.success",
                            "dvc_channel_id=%u version=%u",
                            channel_id,
                            response.version);
            break;
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_ERROR_RESPONSE:
        {
            rdp_video_capture_error error;

            status = rdp_video_capture_parse_error(data, data_len, &error);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.data.error",
                            "dvc_channel_id=%u error=%u",
                            channel_id,
                            error.error_code);
            break;
        }
        default:
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.data.invalid_message",
                            "dvc_channel_id=%u message_id=%u payload_len=%u",
                            channel_id,
                            header.message_id,
                            (unsigned)data_len);
            return rdp_session_send_video_capture_error(session,
                                                        0,
                                                        RDP_VIDEO_CAPTURE_ERROR_INVALID_MESSAGE,
                                                        "client.rdpecam.data.error");
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Dynamic virtual channels are the extension demultiplexer for display,
 * graphics, input, devices, media, and application-owned channels. Route known
 * channel names internally first; only unknown active user channels are exposed
 * to the public callback surface after state and payload validation.
 */
librdp_status librdp_session_video_capture_send_sample(librdp_session* session,
                                                       uint8_t stream_index,
                                                       const void* data,
                                                       size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.video_capture.sample.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (data_len > session->limits.frame_bytes)
        return rdp_session_limit_rejected(session);
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->video_capture_channel_id == 0 || session->video_capture_channel_id_bytes == 0 ||
        !session->video_capture_active || !session->video_capture_streaming ||
        !session->video_capture_sample_reply_pending ||
        stream_index != session->video_capture_selected_stream)
        return LIBRDP_STATUS_STATE;
    status = rdp_session_send_video_capture_sample_payload(session,
                                                           stream_index,
                                                           data,
                                                           data_len,
                                                           "client.rdpecam.sample.response");
    return status;
}

librdp_status librdp_session_video_capture_send_error(librdp_session* session,
                                                      uint8_t stream_index,
                                                      uint32_t error_code)
{
    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    {
        librdp_status status = rdp_session_require_owner(session, "client.video_capture.error.owner");
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->video_capture_channel_id == 0 || session->video_capture_channel_id_bytes == 0 ||
        !session->video_capture_active || !session->video_capture_streaming ||
        !session->video_capture_sample_reply_pending ||
        stream_index != session->video_capture_selected_stream)
        return LIBRDP_STATUS_STATE;
    return rdp_session_send_video_capture_sample_error(session, stream_index, error_code);
}

