/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal session lifecycle contracts.
 * Invariants: reset helpers clear remote-derived handles before state changes
 * become visible to callbacks.
 * Ownership: teardown helpers release session-owned security, channel, and
 * backend state without transferring ownership to callers.
 * Threading: lifecycle mutation requires the session owner thread except when
 * called from the internal cancel path.
 * Trust boundary: partially negotiated server state is treated as invalid
 * during reset and disconnect.
 */

#ifndef RDP_CLIENT_SESSION_LIFECYCLE_H
#define RDP_CLIENT_SESSION_LIFECYCLE_H

#include <librdp/session.h>

librdp_status rdp_session_disconnect_inner(librdp_session* session);
void rdp_session_composited_reset(librdp_session* session);
void rdp_session_auth_redirection_channel_reset(librdp_session* session);
void rdp_session_webauthn_channel_reset(librdp_session* session);
void rdp_session_credssp_security_reset(librdp_session* session);

#endif
