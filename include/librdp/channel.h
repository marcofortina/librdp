/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_CHANNEL_H
#define LIBRDP_CHANNEL_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup librdp_channel Dynamic Channel API
 * @brief Application-owned dynamic virtual channel send and close functions.
 * @{
 */

/**
 * @brief Opaque client session handle used by channel APIs.
 *
 * The handle is owned by the caller after librdp_session_new() and remains
 * valid until librdp_session_free().
 *
 * @since 0.1.0
 */
typedef struct librdp_session librdp_session;

/**
 * @brief Runtime identifier for an open dynamic virtual channel.
 *
 * Channel identifiers are assigned by the protocol layer and are valid only
 * for the lifetime of the open-channel event and the corresponding session.
 *
 * @since 0.1.0
 */
typedef uint32_t librdp_channel_id;

/**
 * @brief Send data on an application-owned dynamic virtual channel.
 *
 * The channel must have been announced to the application through a channel
 * open event and must still be active. Internal library channels cannot be sent
 * through this API. The data buffer is read during the call only and is not
 * retained.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] channel_id Dynamic channel identifier; must be non-zero.
 * @param[in] data Payload bytes. NULL is allowed only when data_len is 0.
 * @param[in] data_len Payload length in bytes.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments; LIBRDP_STATUS_STATE when the session or channel is not
 * ready; LIBRDP_STATUS_UNSUPPORTED for internal channels; transport or
 * allocation errors propagated from the send path.
 *
 * @note Thread-safety: sessions are not internally synchronized; call from the
 * same thread that drives the session unless the application serializes access.
 * @since 0.1.0
 */
librdp_status librdp_session_channel_send(librdp_session* session,
                                          librdp_channel_id channel_id,
                                          const void* data,
                                          size_t data_len);

/**
 * @brief Close an application-owned dynamic virtual channel.
 *
 * The channel must have been announced to the application through a channel
 * open event and must still be active. On success the local channel entry is
 * cleared and the channel identifier must not be reused by the caller.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] channel_id Dynamic channel identifier; must be non-zero.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments; LIBRDP_STATUS_STATE when the session or channel is not
 * ready; LIBRDP_STATUS_UNSUPPORTED for internal channels; transport or
 * allocation errors propagated from the close path.
 *
 * @note Thread-safety: sessions are not internally synchronized; call from the
 * same thread that drives the session unless the application serializes access.
 * @since 0.1.0
 */
librdp_status librdp_session_channel_close(librdp_session* session, librdp_channel_id channel_id);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
