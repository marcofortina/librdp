/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_VIDEO_H
#define LIBRDP_VIDEO_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque client session handle used by video capture APIs.
 *
 * The handle is owned by the caller after librdp_session_new() and remains
 * valid until librdp_session_free().
 *
 * @since 0.1.0
 */
typedef struct librdp_session librdp_session;

#define LIBRDP_VIDEO_CAPTURE_MEDIA_H264 0x01u  /**< H.264 encoded camera sample format. */
#define LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG 0x02u  /**< Motion JPEG encoded camera sample format. */
#define LIBRDP_VIDEO_CAPTURE_MEDIA_YUY2 0x03u  /**< Packed YUY2 camera sample format. */
#define LIBRDP_VIDEO_CAPTURE_MEDIA_NV12 0x04u  /**< Semi-planar NV12 camera sample format. */
#define LIBRDP_VIDEO_CAPTURE_MEDIA_I420 0x05u  /**< Planar I420 camera sample format. */
#define LIBRDP_VIDEO_CAPTURE_MEDIA_RGB24 0x06u /**< Packed RGB24 camera sample format. */
#define LIBRDP_VIDEO_CAPTURE_MEDIA_RGB32 0x07u /**< Packed RGB32 camera sample format. */
#define LIBRDP_VIDEO_CAPTURE_MEDIA_FLAG_DECODING_REQUIRED 0x01u /**< Server requires decoded output. */
#define LIBRDP_VIDEO_CAPTURE_MEDIA_FLAG_BOTTOM_UP 0x02u         /**< Sample rows are bottom-up. */
#define LIBRDP_VIDEO_CAPTURE_ERROR_UNEXPECTED 0x00000001u       /**< Unexpected capture failure. */
#define LIBRDP_VIDEO_CAPTURE_ERROR_INVALID_MESSAGE 0x00000002u  /**< Server request was invalid. */
#define LIBRDP_VIDEO_CAPTURE_ERROR_NOT_INITIALIZED 0x00000003u  /**< Capture stream is not initialized. */
#define LIBRDP_VIDEO_CAPTURE_ERROR_INVALID_REQUEST 0x00000004u  /**< Capture request cannot be satisfied. */
#define LIBRDP_VIDEO_CAPTURE_ERROR_INVALID_STREAM_NUMBER 0x00000005u /**< Stream index is invalid. */
#define LIBRDP_VIDEO_CAPTURE_ERROR_INVALID_MEDIA_TYPE 0x00000006u    /**< Requested media type is invalid. */
#define LIBRDP_VIDEO_CAPTURE_ERROR_OUT_OF_MEMORY 0x00000007u         /**< Capture backend ran out of memory. */
#define LIBRDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND 0x00000008u        /**< Requested capture item was not found. */
#define LIBRDP_VIDEO_CAPTURE_ERROR_SET_NOT_FOUND 0x00000009u         /**< Requested capture set was not found. */
#define LIBRDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED 0x0000000au         /**< Requested capture operation is unsupported. */

/**
 * @brief Camera media format requested by the server.
 *
 * Values are copied into events. Applications may use them to select a local
 * camera mode and to format samples sent back through the video capture API.
 *
 * @since 0.1.0
 */
typedef struct librdp_video_capture_media
{
    uint8_t format;                       /**< One LIBRDP_VIDEO_CAPTURE_MEDIA_* format value. */
    uint32_t width;                       /**< Requested frame width in pixels. */
    uint32_t height;                      /**< Requested frame height in pixels. */
    uint32_t frame_rate_numerator;        /**< Frame-rate numerator. */
    uint32_t frame_rate_denominator;      /**< Frame-rate denominator. */
    uint32_t pixel_aspect_ratio_numerator; /**< Pixel aspect-ratio numerator. */
    uint32_t pixel_aspect_ratio_denominator; /**< Pixel aspect-ratio denominator. */
    uint8_t flags;                        /**< Bitmask of LIBRDP_VIDEO_CAPTURE_MEDIA_FLAG_* values. */
} librdp_video_capture_media;

/**
 * @brief Send one captured camera sample to the server.
 *
 * This replies to a pending LIBRDP_EVENT_VIDEO_CAPTURE_SAMPLE_REQUEST for the
 * selected stream. The data buffer is read during the call only and is not
 * retained.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] stream_index Stream index from the current video capture request.
 * @param[in] data Encoded or raw sample bytes. NULL is allowed only when
 * data_len is 0.
 * @param[in] data_len Sample length in bytes.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or oversized sample arguments; LIBRDP_STATUS_STATE when the session, capture
 * channel, stream, or pending request state does not allow a sample reply;
 * allocation or transport errors propagated from the send path.
 *
 * @note Thread-safety: sessions are not internally synchronized; call from the
 * same serialized context that processes video capture events.
 * @warning Camera frames can contain sensitive user data; the application is
 * responsible for capture consent, device access policy, and local buffering.
 * @since 0.1.0
 */
librdp_status librdp_session_video_capture_send_sample(librdp_session* session,
                                                       uint8_t stream_index,
                                                       const void* data,
                                                       size_t data_len);

/**
 * @brief Report a camera sample error to the server.
 *
 * This replies to a pending LIBRDP_EVENT_VIDEO_CAPTURE_SAMPLE_REQUEST when the
 * application cannot provide a sample for the selected stream.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] stream_index Stream index from the current video capture request.
 * @param[in] error_code Video capture error code to send to the server.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * session is NULL; LIBRDP_STATUS_STATE when the session, capture channel,
 * stream, or pending request state does not allow an error reply; allocation
 * or transport errors propagated from the send path.
 *
 * @note Thread-safety: sessions are not internally synchronized; call from the
 * same serialized context that processes video capture events.
 * @since 0.1.0
 */
librdp_status librdp_session_video_capture_send_error(librdp_session* session,
                                                      uint8_t stream_index,
                                                      uint32_t error_code);

#ifdef __cplusplus
}
#endif

#endif
