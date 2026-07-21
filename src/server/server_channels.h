/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: static and dynamic virtual-channel state, framing, and dispatch.
 * Invariants: channel IDs, lifecycle, fragments, and quotas are validated.
 * Ownership: peers own channel records and reassembly buffers.
 * Threading: channel operations run on the peer owner thread.
 * Trust boundary: channel payloads remain untrusted until domain validation.
 */

#ifndef RDP_SERVER_CHANNELS_H
#define RDP_SERVER_CHANNELS_H

#include "server/server_common.h"

void rdp_server_clipboard_state_reset(librdp_server_peer* peer, int reconnect);

librdp_server_extension_state* rdp_server_extension_state_mut(librdp_server_peer* peer,
                                                                     librdp_server_extension_family family);

void rdp_server_extension_states_reset(librdp_server_peer* peer, int reconnect);

void rdp_server_extension_state_mark_open(librdp_server_peer* peer,
                                                 librdp_server_extension_family family,
                                                 uint16_t static_channel_id,
                                                 uint32_t dynamic_channel_id,
                                                 uint8_t dynamic_priority);

void rdp_server_dynamic_channels_reset(librdp_server_peer* peer, int emit_close_events);

void rdp_server_multitransport_reset(librdp_server_peer* peer);

/* Return non-zero only for a tunnel mode advertised during GCC negotiation. */
int rdp_server_multitransport_tunnel_allowed(
    const librdp_server_peer* peer,
    uint32_t tunnel_type);

void rdp_server_dynamic_channels_cancel_pending_family(
    librdp_server_peer* peer,
    librdp_server_extension_family family);

librdp_status rdp_server_dynamic_channels_start(librdp_server_peer* peer);

void rdp_server_static_channels_reset(librdp_server_peer* peer);

void rdp_server_device_redirection_reset(librdp_server_peer* peer);

librdp_status rdp_server_device_redirection_start(librdp_server_peer* peer);

void rdp_server_emit_channel_joined_event(librdp_server_peer* peer, uint16_t channel_id);

librdp_server_extension_family rdp_server_redirected_device_family(uint32_t device_type,
                                                                          librdp_feature* feature);

const rdp_server_redirected_device* rdp_server_find_redirected_device_const(
    const librdp_server_peer* peer,
    uint32_t device_id);

void rdp_server_extension_classify_name(const char* name,
                                               size_t name_len,
                                               librdp_server_extension_family* family,
                                               librdp_feature* feature);

librdp_status rdp_server_extension_validate(librdp_server_extension_event* event);

librdp_status rdp_server_emit_extension_event(librdp_server_peer* peer,
                                                     const char* name,
                                                     size_t name_len,
                                                     uint16_t channel_id,
                                                     uint32_t dynamic_channel_id,
                                                     uint8_t dynamic_priority,
                                                     const uint8_t* data,
                                                     size_t data_len);

int rdp_server_channel_allowed(const librdp_server_peer* peer, uint16_t channel_id);

int rdp_server_static_channel_index(const librdp_server_peer* peer, uint16_t channel_id, uint16_t* index);

librdp_status rdp_server_handle_static_channel_message(librdp_server_peer* peer,
                                                        uint16_t channel_index,
                                                        uint16_t channel_id,
                                                        const uint8_t* data,
                                                        size_t data_len);

rdp_server_dynamic_channel* rdp_server_find_dynamic_channel(librdp_server_peer* peer, uint32_t channel_id);

librdp_status librdp_server_peer_send_channel_data(librdp_server_peer* peer,
                                                   uint16_t channel_id,
                                                   const void* data,
                                                   size_t data_len);

librdp_status librdp_server_peer_send_dynamic_channel_data(librdp_server_peer* peer,
                                                           uint32_t dynamic_channel_id,
                                                           const void* data,
                                                           size_t data_len);

int rdp_server_dynamic_channel_open_named(librdp_server_peer* peer,
                                                 uint32_t dynamic_channel_id,
                                                 const char* expected_name);

librdp_status rdp_server_send_static_named_buffer(librdp_server_peer* peer,
                                                        uint16_t channel_id,
                                                        const char* expected_name,
                                                        const rdp_buffer* buffer);

librdp_status rdp_server_handle_dynamic_channel_message(librdp_server_peer* peer,
                                                               const uint8_t* data,
                                                               size_t data_len);

#endif
