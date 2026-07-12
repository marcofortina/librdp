/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal session error storage.
 * Invariants: phase, message, and trace identifiers are redacted bounded
 * strings owned by the session error object.
 * Ownership: callers copy text into the object; public info views borrow it
 * until the next mutation.
 * Threading: not synchronized; callers serialize through the owning session.
 * Trust boundary: diagnostic text must describe failures without embedding
 * credentials or payload data.
 */

#ifndef RDP_CLIENT_ERROR_INTERNAL_H
#define RDP_CLIENT_ERROR_INTERNAL_H

#include <librdp/error.h>

#define RDP_ERROR_PHASE_MAX 48u
#define RDP_ERROR_MESSAGE_MAX 160u
#define RDP_ERROR_TRACE_ID_MAX 96u

struct librdp_error
{
    librdp_status status;
    int os_errno;
    librdp_error_component component;
    char phase[RDP_ERROR_PHASE_MAX];
    char message[RDP_ERROR_MESSAGE_MAX];
    char trace_id[RDP_ERROR_TRACE_ID_MAX];
};

void rdp_error_clear(librdp_error* error);
int rdp_error_has_error(const librdp_error* error);
void rdp_error_set(librdp_error* error,
                   librdp_status status,
                   int os_errno,
                   librdp_error_component component,
                   const char* phase,
                   const char* message,
                   const char* trace_id);

#endif
