/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client MCS Message Channel routing.
 * Invariants: exactly one routing security flag selects each record handler.
 * Ownership: payload bytes remain owned by the caller for the duration of the
 * dispatch call.
 * Threading: dispatch runs on the serialized session owner thread.
 * Trust boundary: security flags and payload bytes are remote input.
 */

#ifndef RDP_CLIENT_SESSION_MESSAGE_CHANNEL_H
#define RDP_CLIENT_SESSION_MESSAGE_CHANNEL_H

#include <librdp/session.h>

librdp_status rdp_session_handle_message_channel(
    librdp_session* session,
    uint16_t security_flags,
    const uint8_t* payload,
    size_t payload_len);

#endif
