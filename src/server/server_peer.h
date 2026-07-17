/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: accepted peer lifecycle, callbacks, polling, and dispatch.
 * Invariants: each dispatch advances only a valid peer state transition.
 * Ownership: peer objects own accepted sockets and retained runtime state.
 * Threading: callers serialize access except where public contracts say otherwise.
 * Trust boundary: readiness notifications never bypass protocol validation.
 */

#ifndef RDP_SERVER_PEER_H
#define RDP_SERVER_PEER_H

#include "server/server_common.h"

void rdp_server_copy_token(char* output, size_t output_len, const char* input);

librdp_error_component rdp_server_component_for_status(librdp_status status);

void rdp_server_emit_event(librdp_server_peer* peer, const librdp_server_event* event);

void rdp_server_set_state(librdp_server_peer* peer, librdp_server_peer_state state);

void rdp_server_record_status(librdp_server_peer* peer,
                                     librdp_status status,
                                     librdp_error_component component,
                                     const char* phase,
                                     const char* message);

#endif
