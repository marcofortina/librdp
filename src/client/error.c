/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client-facing status and error string conversion helpers.
 * Invariants: session state transitions happen in protocol order and callbacks
 * never receive invalid surfaces or channels.
 * Ownership: error constants remain stable and do not allocate caller-visible
 * storage.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: external input is treated as untrusted until validated by
 * this module or its caller.
 */


#include <librdp/error.h>

const char* librdp_status_string(librdp_status status)
{
    switch (status)
    {
        case LIBRDP_STATUS_OK:
            return "ok";
        case LIBRDP_STATUS_INVALID_ARGUMENT:
            return "invalid_argument";
        case LIBRDP_STATUS_NO_MEMORY:
            return "no_memory";
        case LIBRDP_STATUS_IO_ERROR:
            return "io_error";
        case LIBRDP_STATUS_PROTOCOL_ERROR:
            return "protocol_error";
        case LIBRDP_STATUS_UNSUPPORTED:
            return "unsupported";
        case LIBRDP_STATUS_TIMEOUT:
            return "timeout";
        case LIBRDP_STATUS_CLOSED:
            return "closed";
        case LIBRDP_STATUS_AGAIN:
            return "again";
        case LIBRDP_STATUS_STATE:
            return "state";
        case LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED:
            return "tls_certificate_rejected";
        case LIBRDP_STATUS_TLS_HOSTNAME_MISMATCH:
            return "tls_hostname_mismatch";
        case LIBRDP_STATUS_TLS_HANDSHAKE_FAILED:
            return "tls_handshake_failed";
        case LIBRDP_STATUS_SECURITY_DOWNGRADE:
            return "security_downgrade";
        default:
            return "unknown";
    }
}
