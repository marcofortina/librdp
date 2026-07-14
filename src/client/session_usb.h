/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal USB redirection contracts.
 * Invariants: URB function support, device allowlist policy, and completion
 * ids are validated before backend dispatch.
 * Ownership: libusb device state and URB completion buffers are session-owned.
 * Threading: backend completions are delivered back to the session owner thread.
 * Trust boundary: USB payloads can contain sensitive device data and must stay
 * redacted in diagnostics.
 */

#ifndef RDP_CLIENT_SESSION_USB_H
#define RDP_CLIENT_SESSION_USB_H

#include <librdp/session.h>

#include <stddef.h>
#include <stdint.h>

librdp_status rdp_session_handle_usb_redirection_message(librdp_session* session,
                                                         const uint8_t* data,
                                                         size_t data_len);
void rdp_session_usb_redirection_reset(librdp_session* session);

#endif
