/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_ERROR_H
#define LIBRDP_ERROR_H

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
    LIBRDP_STATUS_TLS_HANDSHAKE_FAILED = -12      /**< TLS handshake failed independently from verification. */
} librdp_status;

/**
 * @brief Return the stable text token for a status code.
 *
 * The returned pointer refers to static storage owned by the library and
 * remains valid for the lifetime of the process. Unknown status values return
 * the token "unknown".
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
