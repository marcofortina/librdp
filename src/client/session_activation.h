/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal activation and slow-path status contracts.
 * Invariants: active state is entered only after Demand Active processing and
 * finalization PDUs complete successfully.
 * Ownership: activation payloads are borrowed from decoded slow-path packets.
 * Threading: activation helpers run on the session owner thread.
 * Trust boundary: Demand Active and slow-path data PDU bodies are untrusted
 * server data.
 */

#ifndef RDP_CLIENT_SESSION_ACTIVATION_H
#define RDP_CLIENT_SESSION_ACTIVATION_H

#include <librdp/session.h>

#include "protocol/slowpath.h"

#include <stddef.h>
#include <stdint.h>

librdp_status rdp_session_trace_slowpath_data_pdu(librdp_session* session, const rdp_slowpath_data_pdu* data_pdu);
librdp_status rdp_session_handle_deactivate_all(librdp_session* session,
                                                const uint8_t* payload,
                                                size_t payload_len);
librdp_status rdp_session_handle_demand_active(librdp_session* session, const uint8_t* payload, size_t payload_len);

#endif
