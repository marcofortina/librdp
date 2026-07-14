/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal device, PnP, and remote-program channel contracts.
 * Invariants: device IDs are validated before dispatch and channel fragments
 * are reassembled before protocol handlers observe payloads.
 * Ownership: outgoing buffers are caller-owned; device and PnP runtime state
 * remains owned by the session.
 * Threading: callers run on the session owner thread.
 * Trust boundary: device, PnP, and RAIL payloads are untrusted virtual-channel
 * data until parsed by their domain handlers.
 */

#ifndef RDP_CLIENT_SESSION_DEVICE_H
#define RDP_CLIENT_SESSION_DEVICE_H

#include <librdp/session.h>

#include "common/buffer.h"

#include <stddef.h>
#include <stdint.h>

librdp_status rdp_session_send_device_redirection_packet(librdp_session* session,
                                                         const rdp_buffer* payload,
                                                         const char* event);
librdp_status rdp_session_send_pnp_redirection_packet(librdp_session* session,
                                                      const rdp_buffer* payload,
                                                      const char* event);
librdp_status rdp_session_send_remote_programs_packet(librdp_session* session,
                                                      const rdp_buffer* payload,
                                                      const char* event);
uint32_t rdp_session_errno_to_device_status(int error);
librdp_status rdp_session_send_remote_programs_startup(librdp_session* session);
librdp_status rdp_session_handle_remote_programs_message(librdp_session* session,
                                                         const uint8_t* data,
                                                         size_t data_len);
librdp_status rdp_session_handle_device_redirection_message(librdp_session* session,
                                                            const uint8_t* data,
                                                            size_t data_len);
librdp_status rdp_session_handle_pnp_redirection_message(librdp_session* session,
                                                         const uint8_t* data,
                                                         size_t data_len);
librdp_status rdp_session_pnp_send_version(librdp_session* session);
librdp_status rdp_session_pnp_send_authenticated(librdp_session* session);
librdp_status rdp_session_pnp_send_devices(librdp_session* session);

#endif
