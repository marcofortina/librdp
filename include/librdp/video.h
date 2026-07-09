#ifndef LIBRDP_VIDEO_H
#define LIBRDP_VIDEO_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct librdp_session librdp_session;

#define LIBRDP_VIDEO_CAPTURE_MEDIA_H264 0x01u
#define LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG 0x02u
#define LIBRDP_VIDEO_CAPTURE_MEDIA_YUY2 0x03u
#define LIBRDP_VIDEO_CAPTURE_MEDIA_NV12 0x04u
#define LIBRDP_VIDEO_CAPTURE_MEDIA_I420 0x05u
#define LIBRDP_VIDEO_CAPTURE_MEDIA_RGB24 0x06u
#define LIBRDP_VIDEO_CAPTURE_MEDIA_RGB32 0x07u
#define LIBRDP_VIDEO_CAPTURE_MEDIA_FLAG_DECODING_REQUIRED 0x01u
#define LIBRDP_VIDEO_CAPTURE_MEDIA_FLAG_BOTTOM_UP 0x02u
#define LIBRDP_VIDEO_CAPTURE_ERROR_UNEXPECTED 0x00000001u
#define LIBRDP_VIDEO_CAPTURE_ERROR_INVALID_MESSAGE 0x00000002u
#define LIBRDP_VIDEO_CAPTURE_ERROR_NOT_INITIALIZED 0x00000003u
#define LIBRDP_VIDEO_CAPTURE_ERROR_INVALID_REQUEST 0x00000004u
#define LIBRDP_VIDEO_CAPTURE_ERROR_INVALID_STREAM_NUMBER 0x00000005u
#define LIBRDP_VIDEO_CAPTURE_ERROR_INVALID_MEDIA_TYPE 0x00000006u
#define LIBRDP_VIDEO_CAPTURE_ERROR_OUT_OF_MEMORY 0x00000007u
#define LIBRDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND 0x00000008u
#define LIBRDP_VIDEO_CAPTURE_ERROR_SET_NOT_FOUND 0x00000009u
#define LIBRDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED 0x0000000au

typedef struct librdp_video_capture_media
{
    uint8_t format;
    uint32_t width;
    uint32_t height;
    uint32_t frame_rate_numerator;
    uint32_t frame_rate_denominator;
    uint32_t pixel_aspect_ratio_numerator;
    uint32_t pixel_aspect_ratio_denominator;
    uint8_t flags;
} librdp_video_capture_media;

librdp_status librdp_session_video_capture_send_sample(librdp_session* session,
                                                       uint8_t stream_index,
                                                       const void* data,
                                                       size_t data_len);
librdp_status librdp_session_video_capture_send_error(librdp_session* session,
                                                      uint8_t stream_index,
                                                      uint32_t error_code);

#ifdef __cplusplus
}
#endif

#endif
