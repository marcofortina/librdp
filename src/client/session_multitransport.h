/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client multitransport receive state.
 * Invariants: receive windows commit only after a complete response fits the
 * caller buffer; reconnect invalidates all sequence and tunnel state.
 * Ownership: datagram and response storage remain caller-owned.
 * Threading: helpers require the serialized session owner context.
 * Trust boundary: side-transport bytes are untrusted until fully parsed.
 */

#ifndef RDP_CLIENT_SESSION_MULTITRANSPORT_H
#define RDP_CLIENT_SESSION_MULTITRANSPORT_H

#include <librdp/session.h>

void rdp_session_multitransport_reset(librdp_session* session,
                                      int reset_metrics);
librdp_status rdp_session_handle_multitransport_message(
    librdp_session* session,
    uint16_t security_flags,
    const uint8_t* payload,
    size_t payload_len);
int rdp_session_multitransport_next_timeout_ms(
    const librdp_session* session);
librdp_status rdp_session_multitransport_check_timeout(
    librdp_session* session);

#endif
