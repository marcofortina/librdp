/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: server-side client-drive registry and asynchronous request runtime.
 * Invariants: device, file, and request identifiers remain scoped to one peer
 * and reconnect generation; each accepted request emits at most one terminal
 * callback.
 * Ownership: peers own registry strings, file records, and pending requests.
 * Callback payloads borrow dispatch buffers only until callback return.
 * Threading: all operations run on the serialized peer owner thread.
 * Trust boundary: client announcements and completions are untrusted and are
 * validated before application callbacks observe them.
 */

#ifndef RDP_SERVER_DRIVE_H
#define RDP_SERVER_DRIVE_H

#include "channels/device_redirection.h"
#include "server/server_common.h"

librdp_status rdp_server_redirected_device_store(
    librdp_server_peer* peer,
    uint16_t channel_id,
    const rdp_device_redirection_device_announce* announce);

void rdp_server_redirected_device_remove(
    librdp_server_peer* peer,
    uint32_t device_id);

void rdp_server_drive_state_reset(
    librdp_server_peer* peer,
    int reconnect);

librdp_status rdp_server_drive_handle_completion(
    librdp_server_peer* peer,
    const uint8_t* data,
    size_t data_len);

#endif
