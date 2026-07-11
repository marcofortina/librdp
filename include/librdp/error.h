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

const char* librdp_status_string(librdp_status status);

#ifdef __cplusplus
}
#endif

#endif
