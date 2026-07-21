/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client MCS Message Channel routing.
 * Invariants: one and only one routing flag selects a protocol family and
 * security-only flags cannot alter that selection.
 * Ownership: handlers borrow the verified plaintext payload during dispatch.
 * Threading: the session owner thread serializes all message processing.
 * Trust boundary: the server controls routing flags and record bytes.
 */

#include "client/session_message_channel.h"

#include "client/session_autodetect.h"
#include "client/session_internal.h"
#include "client/session_multitransport.h"
#include "common/trace.h"
#include "security/security.h"

librdp_status rdp_session_handle_message_channel(
    librdp_session* session,
    uint16_t security_flags,
    const uint8_t* payload,
    size_t payload_len)
{
    const uint16_t routing_mask =
        RDP_SEC_TRANSPORT_REQ | RDP_SEC_TRANSPORT_RSP |
        RDP_SEC_AUTODETECT_REQ | RDP_SEC_AUTODETECT_RSP;
    const uint16_t allowed_mask =
        routing_mask | RDP_SEC_ENCRYPT | RDP_SEC_SECURE_CHECKSUM;
    uint16_t routing_flags = 0u;

    if (!session || !payload || payload_len == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((security_flags & (uint16_t)~allowed_mask) != 0u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    routing_flags = (uint16_t)(security_flags & routing_mask);
    rdp_trace_hexdump("rdp.message_channel.pdu",
                      RDP_TRACE_SENSITIVITY_AUTH,
                      payload,
                      payload_len);
    if (routing_flags == RDP_SEC_AUTODETECT_REQ ||
        routing_flags == RDP_SEC_AUTODETECT_RSP)
        return rdp_session_handle_autodetect_message(session,
                                                     routing_flags,
                                                     payload,
                                                     payload_len);
    if (routing_flags == RDP_SEC_TRANSPORT_REQ ||
        routing_flags == RDP_SEC_TRANSPORT_RSP)
        return rdp_session_handle_multitransport_message(session,
                                                        routing_flags,
                                                        payload,
                                                        payload_len);
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}
