/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_ERROR_H
#define LIBRDP_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum librdp_status
{
    LIBRDP_STATUS_OK = 0,
    LIBRDP_STATUS_INVALID_ARGUMENT = -1,
    LIBRDP_STATUS_NO_MEMORY = -2,
    LIBRDP_STATUS_IO_ERROR = -3,
    LIBRDP_STATUS_PROTOCOL_ERROR = -4,
    LIBRDP_STATUS_UNSUPPORTED = -5,
    LIBRDP_STATUS_TIMEOUT = -6,
    LIBRDP_STATUS_CLOSED = -7,
    LIBRDP_STATUS_AGAIN = -8,
    LIBRDP_STATUS_STATE = -9
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
const char* librdp_status_string(librdp_status status);

#ifdef __cplusplus
}
#endif

#endif
