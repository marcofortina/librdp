/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X.224, MCS/GCC, licensing, activation, and PDU dispatch.
 * Invariants: protocol messages are accepted only in their lifecycle phase.
 * Ownership: parsed packet views borrow peer input for the current dispatch.
 * Threading: protocol dispatch runs on the peer owner thread.
 * Trust boundary: all packet fields are validated before state transitions.
 */

#ifndef RDP_SERVER_PROTOCOL_H
#define RDP_SERVER_PROTOCOL_H

#include "server/server_common.h"

librdp_status rdp_server_handle_mcs_connect_initial(librdp_server_peer* peer, const rdp_tpkt* packet);

librdp_status rdp_server_handle_erect_domain(librdp_server_peer* peer, const rdp_tpkt* packet);

librdp_status rdp_server_handle_attach_user(librdp_server_peer* peer, const rdp_tpkt* packet);

librdp_status rdp_server_send_demand_active(librdp_server_peer* peer);

size_t rdp_server_channel_name_len(const char name[8]);

void rdp_server_copy_channel_name(char output[LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY], const char name[8]);

void rdp_server_emit_input(librdp_server_peer* peer, const librdp_server_input_event* event);

librdp_status rdp_server_handle_channel_join(librdp_server_peer* peer, const rdp_tpkt* packet);

librdp_status rdp_server_handle_client_info(librdp_server_peer* peer, const rdp_tpkt* packet);

librdp_status rdp_server_handle_runtime_data(librdp_server_peer* peer, const rdp_tpkt* packet);

#endif
