/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: server-side network characteristics auto-detection runtime.
 * Invariants: at most one server-initiated RTT probe is pending per peer and
 * every response is bound to the negotiated, joined Message Channel.
 * Ownership: probe state belongs to the peer; wire buffers are call-local.
 * Threading: calls are serialized by the peer dispatch owner.
 * Trust boundary: security routing flags and every response field are checked
 * before timing state is committed.
 */

#ifndef RDP_SERVER_AUTODETECT_H
#define RDP_SERVER_AUTODETECT_H

#include "server/server_common.h"

void rdp_server_autodetect_reset(librdp_server_peer* peer);

librdp_status rdp_server_autodetect_start(librdp_server_peer* peer);

librdp_status rdp_server_autodetect_handle(librdp_server_peer* peer,
                                           const uint8_t* payload,
                                           size_t payload_len);

#endif
