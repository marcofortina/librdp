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
 * @defgroup librdp_channel Virtual Channel API
 * @brief Application-owned static and dynamic virtual channel functions.
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
 * @brief Opaque settings object used to register static channels before connect.
 *
 * Settings are owned by the caller and cloned by librdp_session_new().
 *
 * @since 0.1.0
 */
typedef struct librdp_settings librdp_settings;

/**
 * @brief Runtime identifier for an open application virtual channel.
 *
 * Channel identifiers are assigned by the protocol layer and are valid only
 * for the lifetime of the open-channel event and the corresponding session.
 * Dynamic-channel handle APIs accept identifiers for dynamic channels only;
 * static-channel APIs identify channels by their registered name.
 *
 * @since 0.1.0
 */
typedef uint32_t librdp_channel_id;

#define LIBRDP_CHANNEL_INFO_VERSION 1u /**< Current librdp_channel_info version. */
#define LIBRDP_CHANNEL_SEND_OPTIONS_VERSION 1u /**< Current librdp_channel_send_options version. */
#define LIBRDP_CHANNEL_NAME_MAX 63u /**< Maximum bytes copied into public channel info names. */
#define LIBRDP_STATIC_CHANNEL_INFO_VERSION 1u /**< Current librdp_static_channel_info version. */
#define LIBRDP_STATIC_CHANNEL_NAME_MAX 7u /**< Maximum application static-channel name bytes. */
#define LIBRDP_STATIC_CHANNEL_DEFAULT_FLAGS 0xc0800000u /**< Default static-channel wire flags. */

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
 * only for dynamic channels that may be sent or closed through public
 * dynamic-channel APIs. Static channels are reported through
 * librdp_static_channel_info.
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
 * @brief Versioned descriptor for an application static virtual channel.
 *
 * Applications initialize this struct with librdp_static_channel_info_init().
 * Settings queries report registered channels before connection with active set
 * to zero and channel_id set to zero. Session queries report negotiated
 * channels after MCS join with active non-zero and channel_id set to the server
 * assigned channel id. name is always NUL-terminated.
 *
 * @since 0.1.0
 */
typedef struct librdp_static_channel_info
{
    uint32_t version;             /**< Struct version, LIBRDP_STATIC_CHANNEL_INFO_VERSION. */
    uint32_t size;                /**< Size of this struct in bytes. */
    librdp_channel_id channel_id; /**< Server-assigned static channel id, or zero before negotiation. */
    uint32_t flags;               /**< Static-channel flags advertised during GCC negotiation. */
    int active;                   /**< Non-zero when this channel is joined in a live session. */
    size_t name_len;              /**< Bytes copied into name, excluding the NUL terminator. */
    char name[LIBRDP_STATIC_CHANNEL_NAME_MAX + 1u]; /**< NUL-terminated channel name copy. */
} librdp_static_channel_info;

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
 * @brief Initialize a static channel info descriptor.
 *
 * @param[out] info Descriptor to initialize; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * info is NULL.
 *
 * @note Thread-safety: this function does not access shared state.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_static_channel_info_init(librdp_static_channel_info* info);

/**
 * @brief Register an application static virtual channel in settings.
 *
 * The name must be 1 to LIBRDP_STATIC_CHANNEL_NAME_MAX printable ASCII bytes,
 * must be unique in the settings object, and must not collide with built-in
 * channels managed by the core. Names are compared case-insensitively for
 * duplicate and reserved-name checks. Passing flags as zero installs
 * LIBRDP_STATIC_CHANNEL_DEFAULT_FLAGS. The settings object stores a copy of
 * the name and flags; the input string is not retained.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] name NUL-terminated channel name; must not be NULL or empty.
 * @param[in] flags Static-channel flags, or zero for the default flags.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL,
 * invalid, duplicate, reserved, or over-limit arguments.
 *
 * @note Thread-safety: settings objects are not internally synchronized;
 * register channels before constructing sessions, or serialize externally with
 * all settings readers and writers. Existing sessions own a clone of earlier
 * settings and do not observe later changes.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_add_static_channel(librdp_settings* settings,
                                                           const char* name,
                                                           uint32_t flags);

/**
 * @brief Return the number of configured application static channels.
 *
 * @param[in] settings Settings object to inspect; may be NULL.
 *
 * @return Configured channel count, or zero when settings is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while the settings object
 * is not being mutated or freed by another thread.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_settings_static_channel_count(const librdp_settings* settings);

/**
 * @brief Copy one configured application static channel descriptor.
 *
 * info must have been initialized with librdp_static_channel_info_init().
 *
 * @param[in] settings Settings object to inspect; must not be NULL.
 * @param[in] index Zero-based channel index, less than
 * librdp_settings_static_channel_count().
 * @param[in,out] info Initialized descriptor to fill; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL,
 * invalid descriptor metadata, or out-of-range index.
 *
 * @note Thread-safety: concurrent reads are safe only while the settings object
 * is not being mutated or freed by another thread.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_static_channel_info(const librdp_settings* settings,
                                                            uint32_t index,
                                                            librdp_static_channel_info* info);

/**
 * @brief List active dynamic virtual channels.
 *
 * If infos is NULL and capacity is zero, the function only reports the number
 * of active dynamic channels through count. When infos is non-NULL, each entry must
 * have been initialized with librdp_channel_info_init(); at most capacity
 * entries are written. count receives the total active channel count even when
 * capacity is smaller.
 *
 * @param[in,out] session Session to inspect; must not be NULL.
 * @param[out] infos Optional array of initialized descriptors; may be NULL
 * only when capacity is zero.
 * @param[in] capacity Number of entries available in infos.
 * @param[out] count Total active dynamic-channel count; must not be NULL.
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
 * @param[in] channel_id Dynamic channel identifier from a channel event; must
 * be non-zero.
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
 * @warning Channel payloads may contain application data. Trace output redacts
 * payload bodies unless unsafe tracing is explicitly enabled.
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
 * @brief List application static channels joined by a session.
 *
 * If infos is NULL and capacity is zero, the function reports the total active
 * static channel count through count. When infos is non-NULL, each entry must
 * have been initialized with librdp_static_channel_info_init(); at most
 * capacity entries are written. count receives the total active static channel
 * count even when capacity is smaller.
 *
 * @param[in,out] session Session to inspect; must not be NULL.
 * @param[out] infos Optional array of initialized descriptors; may be NULL
 * only when capacity is zero.
 * @param[in] capacity Number of entries available in infos.
 * @param[out] count Total active static channel count; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid descriptor arguments; LIBRDP_STATUS_STATE when called from a
 * non-owner thread or before the session has negotiated static channels.
 *
 * @note Thread-safety: call from the session owner thread.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_static_channel_list(librdp_session* session,
                                                           librdp_static_channel_info* infos,
                                                           size_t capacity,
                                                           size_t* count);

/**
 * @brief Send one complete payload on an application static channel.
 *
 * The named channel must have been registered in settings, negotiated by the
 * server, and joined by the current session. The payload buffer is read during
 * the call only and is not retained.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] name NUL-terminated static channel name; must not be NULL.
 * @param[in] data Payload bytes. NULL is allowed only when data_len is zero.
 * @param[in] data_len Payload length in bytes.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments; LIBRDP_STATUS_STATE when the session or channel is not
 * active; LIBRDP_STATUS_LIMIT_EXCEEDED when the payload exceeds configured
 * static-channel limits; transport, protocol, or allocation errors propagated
 * from the send path.
 *
 * @note Thread-safety: call from the session owner thread.
 * @warning Channel payloads may contain application data. Trace output redacts
 * payload bodies unless unsafe tracing is explicitly enabled.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_static_channel_send(librdp_session* session,
                                                           const char* name,
                                                           const void* data,
                                                           size_t data_len);

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
 * ready, or when the call is made from a non-owner thread;
 * LIBRDP_STATUS_UNSUPPORTED for internal channels; transport or allocation
 * errors propagated from the send path.
 *
 * @note Thread-safety: call from the session owner thread.
 * @warning Channel payloads may contain application data. Trace output redacts
 * payload bodies unless unsafe tracing is explicitly enabled.
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
 * ready, or when the call is made from a non-owner thread;
 * LIBRDP_STATUS_UNSUPPORTED for internal channels; transport or allocation
 * errors propagated from the close path.
 *
 * @note Thread-safety: call from the session owner thread.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_channel_close(librdp_session* session, librdp_channel_id channel_id);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
