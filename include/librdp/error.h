/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_ERROR_H
#define LIBRDP_ERROR_H

#include <stdint.h>

/**
 * @brief Public API export marker for shared-library symbols.
 *
 * LIBRDP_API marks functions that are part of the stable dynamic linking
 * surface. Applications should not define this macro themselves unless they
 * are integrating librdp into a non-standard build system.
 *
 * @since 0.1.0
 */
#ifndef LIBRDP_API
#if defined(__GNUC__) || defined(__clang__)
#define LIBRDP_API __attribute__((visibility("default"))) /**< Marks a public function for dynamic-library export. */
#else
#define LIBRDP_API /**< Marks a public function for dynamic-library export. */
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup librdp_error Error API
 * @brief Stable status codes and diagnostic status strings.
 * @{
 */

/**
 * @brief Stable status codes returned by public APIs.
 *
 * Negative values represent failures. Applications should compare against the
 * named constants instead of relying on numeric values except for logging or
 * ABI diagnostics.
 *
 * @since 0.1.0
 */
typedef enum librdp_status
{
    LIBRDP_STATUS_OK = 0,                 /**< Operation completed successfully. */
    LIBRDP_STATUS_INVALID_ARGUMENT = -1,  /**< Caller supplied an invalid argument. */
    LIBRDP_STATUS_NO_MEMORY = -2,         /**< Memory allocation failed. */
    LIBRDP_STATUS_IO_ERROR = -3,          /**< Transport or host I/O operation failed. */
    LIBRDP_STATUS_PROTOCOL_ERROR = -4,    /**< Remote protocol data was invalid or inconsistent. */
    LIBRDP_STATUS_UNSUPPORTED = -5,       /**< Requested feature or wire path is not supported. */
    LIBRDP_STATUS_TIMEOUT = -6,           /**< Operation reached its timeout without completion. */
    LIBRDP_STATUS_CLOSED = -7,            /**< Session or transport was closed. */
    LIBRDP_STATUS_AGAIN = -8,             /**< Operation should be retried later. */
    LIBRDP_STATUS_STATE = -9,             /**< Current object state does not permit the operation. */
    LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED = -10, /**< TLS peer certificate chain was rejected. */
    LIBRDP_STATUS_TLS_HOSTNAME_MISMATCH = -11,    /**< TLS peer certificate does not match the target host. */
    LIBRDP_STATUS_TLS_HANDSHAKE_FAILED = -12,     /**< TLS handshake failed independently from verification. */
    LIBRDP_STATUS_SECURITY_DOWNGRADE = -13        /**< Security negotiation would downgrade below policy. */
} librdp_status;

#define LIBRDP_ERROR_INFO_VERSION 1u /**< Current librdp_error_info version. */

/**
 * @brief Component that reported a session error.
 *
 * Components are intentionally coarse so applications can route diagnostics
 * without depending on internal module names.
 *
 * @since 0.1.0
 */
typedef enum librdp_error_component
{
    LIBRDP_ERROR_COMPONENT_NONE = 0,      /**< No component; used when no error is recorded. */
    LIBRDP_ERROR_COMPONENT_CLIENT = 1,    /**< Public client API, lifecycle, or settings boundary. */
    LIBRDP_ERROR_COMPONENT_TRANSPORT = 2, /**< TCP, polling, read, write, or close boundary. */
    LIBRDP_ERROR_COMPONENT_TLS = 3,       /**< TLS handshake or certificate verification boundary. */
    LIBRDP_ERROR_COMPONENT_CREDSSP = 4,   /**< NLA/CredSSP authentication boundary. */
    LIBRDP_ERROR_COMPONENT_PROTOCOL = 5,  /**< RDP parser, encoder, negotiation, or PDU boundary. */
    LIBRDP_ERROR_COMPONENT_CHANNEL = 6,   /**< Static or dynamic virtual channel boundary. */
    LIBRDP_ERROR_COMPONENT_BACKEND = 7    /**< Host backend boundary such as files, devices, or media. */
} librdp_error_component;

/**
 * @brief Opaque recorded error object owned by a session.
 *
 * Applications never allocate or free this object directly. Obtain it with
 * librdp_session_last_error() and copy a stable view with
 * librdp_error_copy_info().
 *
 * @since 0.1.0
 */
typedef struct librdp_error librdp_error;

/**
 * @brief Versioned borrowed view of a recorded session error.
 *
 * Initialize with librdp_error_info_init(). Strings returned by
 * librdp_error_copy_info() are borrowed from the opaque error object and remain
 * valid until the owning session records another error, clears the error, or is
 * freed. message is redacted and must not contain passwords, tokens, clipboard
 * data, APDUs, file contents, or media payloads.
 *
 * @since 0.1.0
 */
typedef struct librdp_error_info
{
    uint32_t version;                  /**< Struct version, LIBRDP_ERROR_INFO_VERSION. */
    uint32_t size;                     /**< Size of this struct in bytes. */
    librdp_status status;              /**< Public status code associated with the error. */
    int os_errno;                      /**< Captured errno value, or 0 when not applicable. */
    librdp_error_component component;  /**< Component that recorded the error. */
    const char* phase;                 /**< Borrowed stable phase token, or NULL when no error is recorded. */
    const char* message;               /**< Borrowed redacted diagnostic message, or NULL when none is recorded. */
    const char* trace_id;              /**< Borrowed trace identifier from the session policy, or NULL. */
} librdp_error_info;

/**
 * @brief Initialize an error info object for librdp_error_copy_info().
 *
 * @param[out] info Caller-owned info object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * info is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_error_info_init(librdp_error_info* info);

/**
 * @brief Copy a borrowed view from an opaque error object.
 *
 * info must have been initialized with librdp_error_info_init(). The function
 * writes only fields that fit inside info->size, allowing older consumers to
 * ignore fields added in later versions.
 *
 * @param[in] error Opaque error object obtained from a session; must not be NULL.
 * @param[in,out] info Initialized destination info object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * arguments, unsupported version, or a size smaller than the status field.
 *
 * @note Thread-safety: copy from the serialized session-driving context, or
 * protect the owning session externally.
 * @warning Returned string pointers are borrowed and invalidated by subsequent
 * session errors, clear operations, and session destruction.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_error_copy_info(const librdp_error* error, librdp_error_info* info);

/**
 * @brief Return a stable component token for a public error component.
 *
 * @param[in] component Component value to name.
 *
 * @return Non-NULL component token in immutable static storage owned by the
 * library and valid for the lifetime of the process; unknown values return
 * "unknown".
 *
 * @note Thread-safety: this function uses immutable static strings.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_error_component_name(librdp_error_component component);

/**
 * @brief Return the stable symbolic name for a status code.
 *
 * The returned pointer refers to static storage owned by the library and
 * remains valid for the lifetime of the process. Unknown status values return
 * the token "unknown". The name is stable and intended for logs, metrics,
 * structured error objects, and machine-readable diagnostics.
 *
 * @param[in] status Status code to describe.
 *
 * @return Non-NULL NUL-terminated status name owned by the library.
 *
 * @note Thread-safety: this function uses immutable static strings and can be
 * called concurrently.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_status_name(librdp_status status);

/**
 * @brief Return a human-readable description for a status code.
 *
 * The returned pointer refers to static storage owned by the library and
 * remains valid for the lifetime of the process. Descriptions are intended for
 * diagnostics and UI text; applications should compare status values directly
 * and use librdp_status_name() for stable machine-readable tokens. Unknown
 * status values return a generic description.
 *
 * @param[in] status Status code to describe.
 *
 * @return Non-NULL NUL-terminated status description owned by the library.
 *
 * @note Thread-safety: this function uses immutable static strings and can be
 * called concurrently.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_status_description(librdp_status status);

/**
 * @brief Return the legacy stable text token for a status code.
 *
 * This function is a compatibility alias for librdp_status_name(). The returned
 * pointer refers to static storage owned by the library and remains valid for
 * the lifetime of the process.
 *
 * @param[in] status Status code to describe.
 *
 * @return Non-NULL NUL-terminated status token owned by the library.
 *
 * @note Thread-safety: this function uses immutable static strings and can be
 * called concurrently.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_status_string(librdp_status status);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
