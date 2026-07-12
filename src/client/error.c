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

#include "client/error_internal.h"

#include <stddef.h>
#include <string.h>

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
     "Security negotiation would downgrade below policy."},
    {LIBRDP_STATUS_LIMIT_EXCEEDED,
     "limit_exceeded",
     "Configured size, count, or pending-operation limit was exceeded."}
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

static void rdp_error_copy_redacted(char* dest, size_t dest_len, const char* src)
{
    size_t i = 0;

    if (!dest || dest_len == 0)
        return;
    dest[0] = '\0';
    if (!src)
        return;
    for (i = 0; i + 1u < dest_len && src[i] != '\0'; i++)
    {
        unsigned char c = (unsigned char)src[i];

        dest[i] = (c < 0x20u || c == '"' || c == '\\') ? '?' : (char)c;
    }
    dest[i] = '\0';
}

void rdp_error_clear(librdp_error* error)
{
    if (!error)
        return;
    memset(error, 0, sizeof(*error));
    error->status = LIBRDP_STATUS_OK;
    error->component = LIBRDP_ERROR_COMPONENT_NONE;
}

int rdp_error_has_error(const librdp_error* error)
{
    return error && error->status != LIBRDP_STATUS_OK;
}

void rdp_error_set(librdp_error* error,
                   librdp_status status,
                   int os_errno,
                   librdp_error_component component,
                   const char* phase,
                   const char* message,
                   const char* trace_id)
{
    if (!error)
        return;
    rdp_error_clear(error);
    if (status == LIBRDP_STATUS_OK)
        return;
    error->status = status;
    error->os_errno = os_errno;
    error->component = component;
    rdp_error_copy_redacted(error->phase, sizeof(error->phase), phase);
    rdp_error_copy_redacted(error->message, sizeof(error->message), message);
    rdp_error_copy_redacted(error->trace_id, sizeof(error->trace_id), trace_id);
}

librdp_status librdp_error_info_init(librdp_error_info* info)
{
    if (!info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(info, 0, sizeof(*info));
    info->version = LIBRDP_ERROR_INFO_VERSION;
    info->size = (uint32_t)sizeof(*info);
    info->status = LIBRDP_STATUS_OK;
    info->component = LIBRDP_ERROR_COMPONENT_NONE;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_error_copy_info(const librdp_error* error, librdp_error_info* info)
{
    const size_t min_size = offsetof(librdp_error_info, status) + sizeof(info->status);

    if (!error || !info || info->version != LIBRDP_ERROR_INFO_VERSION || info->size < min_size)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (info->size >= offsetof(librdp_error_info, status) + sizeof(info->status))
        info->status = error->status;
    if (info->size >= offsetof(librdp_error_info, os_errno) + sizeof(info->os_errno))
        info->os_errno = error->os_errno;
    if (info->size >= offsetof(librdp_error_info, component) + sizeof(info->component))
        info->component = error->component;
    if (info->size >= offsetof(librdp_error_info, phase) + sizeof(info->phase))
        info->phase = error->phase[0] != '\0' ? error->phase : NULL;
    if (info->size >= offsetof(librdp_error_info, message) + sizeof(info->message))
        info->message = error->message[0] != '\0' ? error->message : NULL;
    if (info->size >= offsetof(librdp_error_info, trace_id) + sizeof(info->trace_id))
        info->trace_id = error->trace_id[0] != '\0' ? error->trace_id : NULL;
    return LIBRDP_STATUS_OK;
}

const char* librdp_error_component_name(librdp_error_component component)
{
    switch (component)
    {
        case LIBRDP_ERROR_COMPONENT_NONE:
            return "none";
        case LIBRDP_ERROR_COMPONENT_CLIENT:
            return "client";
        case LIBRDP_ERROR_COMPONENT_TRANSPORT:
            return "transport";
        case LIBRDP_ERROR_COMPONENT_TLS:
            return "tls";
        case LIBRDP_ERROR_COMPONENT_CREDSSP:
            return "credssp";
        case LIBRDP_ERROR_COMPONENT_PROTOCOL:
            return "protocol";
        case LIBRDP_ERROR_COMPONENT_CHANNEL:
            return "channel";
        case LIBRDP_ERROR_COMPONENT_BACKEND:
            return "backend";
        default:
            return "unknown";
    }
}
