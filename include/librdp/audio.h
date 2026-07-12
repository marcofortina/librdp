/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_AUDIO_H
#define LIBRDP_AUDIO_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup librdp_audio Audio API
 * @brief Audio format and audio input response functions.
 *
 * These APIs operate on negotiated audio channels. Device capture/playback
 * backends are selected by the application or viewer; protocol helpers return
 * LIBRDP_STATUS_STATE when the remote channel is not ready.
 * @{
 */

/**
 * @brief Opaque client session handle used by audio APIs.
 *
 * The handle is owned by the caller after librdp_session_new() and remains
 * valid until librdp_session_free().
 *
 * @since 0.1.0
 */
typedef struct librdp_session librdp_session;

#define LIBRDP_AUDIO_FORMAT_PCM 0x0001u     /**< Linear PCM audio format tag. */
#define LIBRDP_AUDIO_FORMAT_ALAW 0x0006u    /**< A-law compressed audio format tag. */
#define LIBRDP_AUDIO_FORMAT_MULAW 0x0007u   /**< mu-law compressed audio format tag. */
#define LIBRDP_AUDIO_INPUT_RESULT_OK 0x00000000u   /**< Audio input open request accepted. */
#define LIBRDP_AUDIO_INPUT_RESULT_FAIL 0x80004005u /**< Audio input open request rejected. */

/**
 * @brief Audio format advertised or selected by audio redirection.
 *
 * The structure is a borrowed view when delivered through events and a
 * caller-owned value when supplied by applications. extra_data points to
 * codec-specific bytes valid for the same lifetime as the containing object.
 *
 * @since 0.1.0
 */
typedef struct librdp_audio_format
{
    uint16_t format_tag;        /**< Audio encoding tag, for example LIBRDP_AUDIO_FORMAT_PCM. */
    uint16_t channels;          /**< Number of interleaved audio channels. */
    uint32_t samples_per_sec;   /**< Sample rate in frames per second. */
    uint32_t avg_bytes_per_sec; /**< Average encoded byte rate for stream pacing. */
    uint16_t block_align;       /**< Encoded block alignment in bytes. */
    uint16_t bits_per_sample;   /**< Bits per sample for PCM-like formats. */
    const uint8_t* extra_data;  /**< Optional codec-specific bytes; may be NULL when extra_data_len is 0. */
    size_t extra_data_len;      /**< Length in bytes of extra_data. */
} librdp_audio_format;

/**
 * @brief Reply to an audio input open request from the server.
 *
 * Call this after receiving LIBRDP_EVENT_AUDIO_INPUT_OPEN. A successful OK
 * reply marks audio input as open; a failure result rejects the server request.
 * The function sends only the protocol response; local microphone setup is the
 * responsibility of the application backend that received the event.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] result Server-visible HRESULT-style result, typically
 * LIBRDP_AUDIO_INPUT_RESULT_OK or LIBRDP_AUDIO_INPUT_RESULT_FAIL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * session is NULL; LIBRDP_STATUS_STATE when the session or audio input channel
 * is not ready; allocation or transport errors propagated from the send path.
 *
 * @note Thread-safety: call from the serialized session-driving thread that
 * delivered the audio input event.
 * @warning Audio capture may expose user speech or room audio to the remote
 * session. Trace output redacts payload bodies unless unsafe tracing is
 * explicitly enabled.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_audio_input_open_reply(librdp_session* session, uint32_t result);

/**
 * @brief Send captured audio input data to the server.
 *
 * The audio input channel must be ready and successfully opened. The data
 * buffer is read during the call only and is not retained. The caller is
 * responsible for providing bytes encoded in the currently selected negotiated
 * audio input format.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] data Audio payload bytes. NULL is allowed only when data_len is 0.
 * @param[in] data_len Payload length in bytes.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or oversized payload arguments; LIBRDP_STATUS_STATE when the session or
 * audio input channel is not ready or not open; allocation or transport errors
 * propagated from the send path.
 *
 * @note Thread-safety: call from the serialized session-driving thread.
 * @warning Audio samples can contain user speech or other sensitive data; the
 * application is responsible for capture consent and local data handling.
 * Trace output redacts payload bodies unless unsafe tracing is explicitly
 * enabled.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_audio_input_send_data(librdp_session* session, const void* data, size_t data_len);

/**
 * @brief Notify the server that the audio input format changed.
 *
 * The audio input channel must be ready. The new format index is interpreted in
 * the negotiated audio input format list delivered by the server; this API
 * does not validate the index against an application-side backend format list.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] new_format Negotiated audio input format index to select.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * session is NULL; LIBRDP_STATUS_STATE when the session or audio input channel
 * is not ready; allocation or transport errors propagated from the send path.
 *
 * @note Thread-safety: call from the serialized session-driving thread.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_audio_input_send_format_change(librdp_session* session, uint32_t new_format);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
