/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: device and media extension serializers and provider operations.
 * Invariants: only negotiated and provider-ready families emit messages.
 * Ownership: caller payloads are borrowed only for the duration of each send.
 * Threading: extension operations run on the peer owner thread.
 * Trust boundary: provider input and remote extension state are validated.
 */

#ifndef RDP_SERVER_EXTENSIONS_H
#define RDP_SERVER_EXTENSIONS_H

#include "server/server_common.h"

librdp_status rdp_server_send_dynamic_named_buffer(librdp_server_peer* peer,
                                                         uint32_t dynamic_channel_id,
                                                         const char* expected_name,
                                                         const rdp_buffer* buffer);

#endif
