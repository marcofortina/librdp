/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Microsoft RD Gateway HTTP transport provider.
 * Invariants: the gateway channel is attached to rdp_transport only after
 * OUT/IN HTTP streams, RDG handshake, tunnel authorization, and channel
 * creation all succeed.
 * Ownership: successful setup transfers the provider context to transport.
 * Threading: libcurl network progress runs in one worker; transport callers
 * serialize through the owning session.
 * Trust boundary: gateway HTTP bodies and protocol packets are untrusted and
 * validated before becoming RDP stream bytes.
 */

#ifndef RDP_GATEWAY_RDG_HTTP_H
#define RDP_GATEWAY_RDG_HTTP_H

#include "gateway/gateway.h"

librdp_status rdp_gateway_connect_rdg_http(rdp_transport* transport,
                                           const rdp_gateway_connect_config* config);

#endif
