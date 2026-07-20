/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal static and dynamic virtual-channel contracts.
 * Invariants: channel ids, priorities, fragments, and close state are checked
 * before payload delivery.
 * Ownership: channel entries and reassembly buffers are session-owned.
 * Threading: channel manager helpers run on the session owner thread.
 * Trust boundary: virtual-channel payloads are untrusted until dispatched to a
 * registered protocol handler.
 */

#ifndef RDP_CLIENT_SESSION_CHANNELS_H
#define RDP_CLIENT_SESSION_CHANNELS_H

#include <librdp/channel.h>
#include <librdp/session.h>

#include "channels/dynamic_channel.h"
#include "channels/virtual_channel.h"

#include <stddef.h>
#include <stdint.h>

struct rdp_session_dynamic_channel;
struct rdp_session_static_channel;

struct rdp_session_dynamic_channel* rdp_session_dynamic_channel_find(librdp_session* session, uint32_t channel_id);
struct rdp_session_dynamic_channel* rdp_session_dynamic_channel_find_opening(librdp_session* session, uint32_t channel_id);
void rdp_session_dynamic_channel_clear_entry(struct rdp_session_dynamic_channel* entry);
librdp_status rdp_session_dynamic_channel_add(librdp_session* session,
                                              const rdp_dynamic_channel_create_request* request);
int rdp_session_dynamic_channel_is_internal(const struct rdp_session_dynamic_channel* entry);
uint32_t rdp_session_dynamic_channel_create_status(librdp_session* session,
                                                   const rdp_dynamic_channel_create_request* request);
void rdp_session_emit_channel_open_data(librdp_session* session, librdp_channel_id channel_id, const char* name);
void rdp_session_emit_channel_payload(librdp_session* session,
                                      librdp_channel_id channel_id,
                                      const char* name,
                                      const uint8_t* data,
                                      size_t data_len);
void rdp_session_emit_channel_open(librdp_session* session, const struct rdp_session_dynamic_channel* entry);
void rdp_session_emit_channel_data(librdp_session* session,
                                   const struct rdp_session_dynamic_channel* entry,
                                   const uint8_t* data,
                                   size_t data_len);
void rdp_session_emit_channel_close(librdp_session* session, const struct rdp_session_dynamic_channel* entry);
void rdp_session_dynamic_channels_clear(librdp_session* session);
void rdp_session_static_channels_clear(librdp_session* session);
void rdp_session_channels_reset_activation_fragments(librdp_session* session);
struct rdp_session_static_channel* rdp_session_static_channel_find_by_id(librdp_session* session, uint16_t channel_id);
librdp_status rdp_session_static_channel_configure(librdp_session* session,
                                                   uint32_t index,
                                                   const char* name,
                                                   uint32_t flags,
                                                   uint16_t channel_id);
librdp_status rdp_session_handle_static_channel(librdp_session* session,
                                                struct rdp_session_static_channel* entry,
                                                const rdp_virtual_channel_packet* packet);
int rdp_session_echo_channel_active(const librdp_session* session);
void rdp_session_echo_clear_pending(librdp_session* session);
void rdp_session_echo_emit_result(librdp_session* session,
                                  uint64_t sequence,
                                  const uint8_t* data,
                                  size_t data_len,
                                  uint64_t rtt_us,
                                  int ok,
                                  int timed_out);
void rdp_session_echo_record_rtt(librdp_session* session, uint64_t rtt_us);
int rdp_session_echo_pending_expired(const librdp_session* session, uint64_t now_ns, uint64_t* elapsed_us);
void rdp_session_echo_check_timeout(librdp_session* session);
int rdp_session_echo_next_timeout_ms(const librdp_session* session);

#endif
