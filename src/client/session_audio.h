/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal audio input and output contracts.
 * Invariants: negotiated formats, block numbers, UDP peer state, and queue
 * limits are checked before audio frames become callback-visible.
 * Ownership: audio fragments, pending wave buffers, and UDP state are owned by
 * the session audio domain.
 * Threading: channel handlers run on the session owner thread.
 * Trust boundary: audio payloads are media data and must not be dumped by trace.
 */

#ifndef RDP_CLIENT_SESSION_AUDIO_H
#define RDP_CLIENT_SESSION_AUDIO_H

#include <librdp/session.h>

#include <stddef.h>
#include <stdint.h>

librdp_status rdp_session_handle_audio_input_message(librdp_session* session,
                                                     uint32_t channel_id,
                                                     const uint8_t* data,
                                                     size_t data_len);
librdp_status rdp_session_handle_audio_output_message(librdp_session* session,
                                                      const uint8_t* data,
                                                      size_t data_len);
librdp_status rdp_session_handle_audio_output_udp_datagram(librdp_session* session);
void rdp_session_audio_output_udp_close(librdp_session* session);

#endif
