/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal smartcard redirection contracts.
 * Invariants: smartcard context and handle generations are checked before any
 * APDU or reader operation is processed.
 * Ownership: reader contexts, card handles, and fallback caches are owned by
 * the session smartcard backend.
 * Threading: completion delivery returns to the session owner thread.
 * Trust boundary: APDU bytes, reader names, and cache records are sensitive
 * untrusted channel data and must not be traced raw.
 */

#ifndef RDP_CLIENT_SESSION_SMARTCARD_H
#define RDP_CLIENT_SESSION_SMARTCARD_H

#include <librdp/session.h>

#include <stddef.h>
#include <stdint.h>

librdp_status rdp_session_handle_smartcard_io_request(librdp_session* session,
                                                      const uint8_t* data,
                                                      size_t data_len);
void rdp_session_smartcard_reset(librdp_session* session);

#endif
