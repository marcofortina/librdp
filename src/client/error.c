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

#include <stddef.h>

typedef struct rdp_status_info
{
    librdp_status status;
    const char* name;
    const char* description;
} rdp_status_info;

static const rdp_status_info RDP_STATUS_INFO[] = {
    {LIBRDP_STATUS_OK, "ok", "Operation completed successfully."},
    {LIBRDP_STATUS_INVALID_ARGUMENT, "invalid_argument", "Caller supplied an invalid argument."},
    {LIBRDP_STATUS_NO_MEMORY, "no_memory", "Memory allocation failed."},
    {LIBRDP_STATUS_IO_ERROR, "io_error", "Transport or host I/O operation failed."},
    {LIBRDP_STATUS_PROTOCOL_ERROR, "protocol_error", "Remote protocol data was invalid or inconsistent."},
    {LIBRDP_STATUS_UNSUPPORTED, "unsupported", "Requested feature or wire path is not supported."},
    {LIBRDP_STATUS_TIMEOUT, "timeout", "Operation reached its timeout without completion."},
    {LIBRDP_STATUS_CLOSED, "closed", "Session or transport was closed."},
    {LIBRDP_STATUS_AGAIN, "again", "Operation should be retried later."},
    {LIBRDP_STATUS_STATE, "state", "Current object state does not permit the operation."},
    {LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED,
     "tls_certificate_rejected",
     "TLS peer certificate chain was rejected."},
    {LIBRDP_STATUS_TLS_HOSTNAME_MISMATCH,
     "tls_hostname_mismatch",
     "TLS peer certificate does not match the target host."},
    {LIBRDP_STATUS_TLS_HANDSHAKE_FAILED,
     "tls_handshake_failed",
     "TLS handshake failed independently from verification."},
    {LIBRDP_STATUS_SECURITY_DOWNGRADE,
     "security_downgrade",
     "Security negotiation would downgrade below policy."}
};

static const rdp_status_info* rdp_status_info_find(librdp_status status)
{
    for (size_t i = 0; i < sizeof(RDP_STATUS_INFO) / sizeof(RDP_STATUS_INFO[0]); i++)
    {
        if (RDP_STATUS_INFO[i].status == status)
            return &RDP_STATUS_INFO[i];
    }
    return NULL;
}

const char* librdp_status_name(librdp_status status)
{
    const rdp_status_info* info = rdp_status_info_find(status);

    return info ? info->name : "unknown";
}

const char* librdp_status_description(librdp_status status)
{
    const rdp_status_info* info = rdp_status_info_find(status);

    return info ? info->description : "Unknown status code.";
}

const char* librdp_status_string(librdp_status status)
{
    return librdp_status_name(status);
}
