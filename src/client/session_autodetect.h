/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client network auto-detect session state.
 * Invariants: only joined message-channel records with a verified Security
 * Header can advance measurement state or produce a response.
 * Ownership: all timers and counters are session-owned; payload views are
 * borrowed only for the duration of a dispatch call.
 * Threading: functions run on the session owner thread.
 * Trust boundary: callers pass decrypted but otherwise untrusted wire data.
 */

#ifndef RDP_CLIENT_SESSION_AUTODETECT_H
#define RDP_CLIENT_SESSION_AUTODETECT_H

#include <librdp/session.h>

#include <stddef.h>
#include <stdint.h>

void rdp_session_autodetect_reset(librdp_session* session);

void rdp_session_autodetect_reset_metrics(librdp_session* session);

void rdp_session_autodetect_account_bytes(librdp_session* session,
                                          size_t payload_len);

librdp_status rdp_session_handle_autodetect_message(
    librdp_session* session,
    uint16_t security_flags,
    const uint8_t* payload,
    size_t payload_len);

#endif
