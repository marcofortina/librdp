/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: TCP transport primitive contract.
 * Invariants: socket/TLS handles and buffered bytes change ownership only on
 * successful setup or teardown calls.
 * Ownership: socket ownership moves to the caller only through successful
 * open/close paths.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: external inputs are untrusted until validated by the
 * declaring module or caller.
 */


#ifndef RDP_TRANSPORT_TCP_H
#define RDP_TRANSPORT_TCP_H

#include <stdint.h>

#include <librdp/error.h>

librdp_status rdp_tcp_connect(const char* host, uint16_t port, int timeout_ms, int* out_fd);

#endif
