/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal serial and parallel redirection contracts.
 * Invariants: port type and index are validated before I/O request dispatch.
 * Ownership: host file descriptors are stored in redirected file entries owned
 * by the session.
 * Threading: port handlers run on the session owner thread.
 * Trust boundary: IOCTLs, offsets, and data lengths are untrusted device input.
 */

#ifndef RDP_CLIENT_SESSION_PORTS_H
#define RDP_CLIENT_SESSION_PORTS_H

#include <librdp/session.h>

#include <stddef.h>
#include <stdint.h>

librdp_status rdp_session_handle_port_io_request(librdp_session* session,
                                                 const uint8_t* data,
                                                 size_t data_len,
                                                 uint8_t port_type,
                                                 uint32_t port_index);

#endif
