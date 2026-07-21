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

librdp_status rdp_server_peer_send_pointer_wire_update(
    librdp_server_peer* peer,
    const rdp_pointer_update* update);

librdp_status rdp_server_send_dynamic_named_buffer(librdp_server_peer* peer,
                                                         uint32_t dynamic_channel_id,
                                                         const char* expected_name,
                                                         const rdp_buffer* buffer);

librdp_status rdp_server_auth_redirection_decode(
    librdp_server_peer* peer,
    const void* data,
    size_t data_len,
    rdp_buffer* plaintext,
    uint32_t* package,
    const uint8_t** payload,
    size_t* payload_len);

void rdp_server_auth_redirection_reset(librdp_server_peer* peer);

void rdp_server_auth_redirection_retire_pending(librdp_server_peer* peer);

#endif
