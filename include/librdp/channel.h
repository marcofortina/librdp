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

#define LIBRDP_CHANNEL_INFO_VERSION 1u /**< Current librdp_channel_info version. */
#define LIBRDP_CHANNEL_SEND_OPTIONS_VERSION 1u /**< Current librdp_channel_send_options version. */
#define LIBRDP_CHANNEL_NAME_MAX 63u /**< Maximum bytes copied into public channel info names. */

/**
 * @brief Opaque dynamic virtual channel handle token.
 *
 * A handle combines an internal channel table slot and generation. It remains
 * valid only while the matching channel is active in the owning session. The
 * numeric value is intentionally opaque and must not be interpreted by
 * applications.
 *
 * @since 0.1.0
 */
typedef uint64_t librdp_channel_handle;

/**
 * @brief Dynamic virtual channel priority for outbound data.
 *
 * The values map to the two-bit protocol priority field used by dynamic
 * channel data PDUs. The reserved wire value is intentionally not exposed.
 *
 * @since 0.1.0
 */
typedef enum librdp_channel_priority
{
    LIBRDP_CHANNEL_PRIORITY_LOW = 0,    /**< Normal priority. */
    LIBRDP_CHANNEL_PRIORITY_MEDIUM = 1, /**< Medium priority. */
    LIBRDP_CHANNEL_PRIORITY_HIGH = 2    /**< High priority. */
} librdp_channel_priority;

/**
 * @brief Versioned snapshot of an active dynamic virtual channel.
 *
 * Applications initialize this struct with librdp_channel_info_init() before
 * passing it to query functions. name contains a NUL-terminated copy truncated
 * to LIBRDP_CHANNEL_NAME_MAX bytes; name_len reports the copied byte count,
 * not the original server-advertised length. application_owned is non-zero
 * only for channels that may be sent or closed through public channel APIs.
 *
 * @since 0.1.0
 */
typedef struct librdp_channel_info
{
    uint32_t version;                 /**< Struct version, LIBRDP_CHANNEL_INFO_VERSION. */
    uint32_t size;                    /**< Size of this struct in bytes. */
    librdp_channel_handle handle;     /**< Opaque handle token for this channel. */
    librdp_channel_id channel_id;     /**< Protocol channel identifier. */
    librdp_channel_priority priority; /**< Priority advertised on channel creation. */
    int active;                       /**< Non-zero when this snapshot described an active channel. */
    int application_owned;            /**< Non-zero when public send/close APIs are allowed. */
    size_t name_len;                  /**< Bytes copied into name, excluding the NUL terminator. */
    char name[LIBRDP_CHANNEL_NAME_MAX + 1u]; /**< NUL-terminated channel name copy. */
} librdp_channel_info;

/**
 * @brief Versioned options for dynamic virtual channel sends.
 *
 * Applications initialize this struct with librdp_channel_send_options_init()
 * and set handle to a value returned by librdp_session_channel_handle_for_id()
 * or librdp_session_channel_list(). data buffers passed to send calls are read
 * during the call only and are not retained.
 *
 * @since 0.1.0
 */
typedef struct librdp_channel_send_options
{
    uint32_t version;                 /**< Struct version, LIBRDP_CHANNEL_SEND_OPTIONS_VERSION. */
    uint32_t size;                    /**< Size of this struct in bytes. */
    librdp_channel_handle handle;     /**< Active channel handle to send on. */
    librdp_channel_priority priority; /**< Outbound dynamic-channel priority. */
} librdp_channel_send_options;

/**
 * @brief Initialize a dynamic channel info descriptor.
 *
 * @param[out] info Descriptor to initialize; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * info is NULL.
 *
 * @note Thread-safety: this function does not access shared state.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_channel_info_init(librdp_channel_info* info);

/**
 * @brief Initialize dynamic channel send options.
 *
 * The default priority is LIBRDP_CHANNEL_PRIORITY_LOW and the handle is zero,
 * which is invalid until replaced by a queried active channel handle.
 *
 * @param[out] options Options object to initialize; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * options is NULL.
 *
 * @note Thread-safety: this function does not access shared state.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_channel_send_options_init(librdp_channel_send_options* options);

/**
 * @brief List active dynamic virtual channels.
 *
 * If infos is NULL and capacity is zero, the function only reports the number
 * of active channels through count. When infos is non-NULL, each entry must
 * have been initialized with librdp_channel_info_init(); at most capacity
 * entries are written. count receives the total active channel count even when
 * capacity is smaller.
 *
 * @param[in,out] session Session to inspect; must not be NULL.
 * @param[out] infos Optional array of initialized descriptors; may be NULL
 * only when capacity is zero.
 * @param[in] capacity Number of entries available in infos.
 * @param[out] count Total active channel count; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid descriptor arguments; LIBRDP_STATUS_STATE when called from a
 * non-owner thread or before the session has an owner.
 *
 * @note Thread-safety: call from the session owner thread.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_channel_list(librdp_session* session,
                                                    librdp_channel_info* infos,
                                                    size_t capacity,
                                                    size_t* count);

/**
 * @brief Resolve an active channel identifier to an opaque handle.
 *
 * @param[in,out] session Session to inspect; must not be NULL.
 * @param[in] channel_id Dynamic channel identifier; must be non-zero.
 * @param[out] handle Receives the active handle; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments; LIBRDP_STATUS_STATE when the channel is not active or
 * the call is made from a non-owner thread.
 *
 * @note Thread-safety: call from the session owner thread.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_channel_handle_for_id(librdp_session* session,
                                                             librdp_channel_id channel_id,
                                                             librdp_channel_handle* handle);

/**
 * @brief Query information for an active channel handle.
 *
 * info must have been initialized with librdp_channel_info_init(). The function
 * writes only fields that fit inside info->size, allowing older consumers to
 * ignore fields added in later versions.
 *
 * @param[in,out] session Session that owns the handle; must not be NULL.
 * @param[in] handle Active channel handle returned by this session.
 * @param[in,out] info Initialized descriptor to fill; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid descriptors; LIBRDP_STATUS_STATE when the handle is stale or the
 * call is made from a non-owner thread.
 *
 * @note Thread-safety: call from the session owner thread.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_channel_get_info(librdp_session* session,
                                                        librdp_channel_handle handle,
                                                        librdp_channel_info* info);

/**
 * @brief Send data on a dynamic channel handle.
 *
 * The handle must reference an active application-owned channel. Internal
 * library channels reject public sends with LIBRDP_STATUS_UNSUPPORTED. The data
 * buffer is read during the call only and is not retained.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] options Initialized send options; must not be NULL.
 * @param[in] data Payload bytes. NULL is allowed only when data_len is 0.
 * @param[in] data_len Payload length in bytes.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL,
 * invalid version/size, invalid handle, or invalid priority;
 * LIBRDP_STATUS_STATE when the session or handle is not active;
 * LIBRDP_STATUS_LIMIT_EXCEEDED when the payload exceeds configured limits;
 * LIBRDP_STATUS_UNSUPPORTED for internal library channels; transport or
 * allocation errors propagated from the send path.
 *
 * @note Thread-safety: call from the session owner thread.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_channel_send_ex(librdp_session* session,
                                                       const librdp_channel_send_options* options,
                                                       const void* data,
                                                       size_t data_len);

/**
 * @brief Close an application-owned dynamic channel handle.
 *
 * The handle is invalidated on success and must not be reused. Internal
 * library channels reject public closes with LIBRDP_STATUS_UNSUPPORTED.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] handle Active channel handle.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for an
 * invalid handle; LIBRDP_STATUS_STATE when the session or handle is not active;
 * LIBRDP_STATUS_UNSUPPORTED for internal library channels; transport or
 * allocation errors propagated from the close path.
 *
 * @note Thread-safety: call from the session owner thread.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_channel_close_handle(librdp_session* session,
                                                            librdp_channel_handle handle);

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
LIBRDP_API librdp_status librdp_session_channel_send(librdp_session* session,
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
LIBRDP_API librdp_status librdp_session_channel_close(librdp_session* session, librdp_channel_id channel_id);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
