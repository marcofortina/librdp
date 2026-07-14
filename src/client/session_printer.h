/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal printer redirection contracts.
 * Invariants: job ids, cache ids, and backend selection are checked before
 * writing spool data.
 * Ownership: printer cache events and backend job state are session-owned until
 * reset or disconnect.
 * Threading: printer I/O dispatch runs on the session owner thread; slow
 * backend work is delegated through configured providers.
 * Trust boundary: print job bytes and cache metadata are untrusted device data.
 */

#ifndef RDP_CLIENT_SESSION_PRINTER_H
#define RDP_CLIENT_SESSION_PRINTER_H

#include <librdp/session.h>

#include "channels/printer_redirection.h"

#include <stddef.h>
#include <stdint.h>

librdp_status rdp_session_handle_printer_io_request(librdp_session* session,
                                                    const uint8_t* data,
                                                    size_t data_len);
uint32_t rdp_session_store_printer_cache_event(librdp_session* session,
                                               const rdp_printer_redirection_cache_event* event);

#endif
