/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal protocol I/O contracts for session wire traffic.
 * Invariants: transport reads and writes update metrics, trace, encryption,
 * compression, and channel framing consistently.
 * Ownership: packet buffers are caller-owned unless explicitly filled by a
 * read helper.
 * Threading: protocol I/O runs on the session owner thread.
 * Trust boundary: incoming MCS, fast-path, slow-path, and security-wrapped
 * payloads are untrusted until decoded by protocol parsers.
 */

#ifndef RDP_CLIENT_SESSION_PROTOCOL_IO_H
#define RDP_CLIENT_SESSION_PROTOCOL_IO_H

#include <librdp/session.h>

#include "common/buffer.h"
#include "graphics/bitmap.h"

#include <stddef.h>
#include <stdint.h>

librdp_status rdp_session_write_mcs_pdu(librdp_session* session,
                                        const rdp_buffer* pdu,
                                        const char* event,
                                        int allow_hexdump);
librdp_status rdp_session_write_slowpath_pdu(librdp_session* session,
                                             const rdp_buffer* pdu,
                                             const char* event);
librdp_status rdp_session_write_license_pdu(librdp_session* session,
                                            const rdp_buffer* license,
                                            const char* event);
librdp_status rdp_session_write_channel_pdu(librdp_session* session,
                                            uint16_t channel_id,
                                            const rdp_buffer* payload,
                                            const char* event);
librdp_status rdp_session_send_dynamic_channel_data_priority(librdp_session* session,
                                                             uint32_t channel_id,
                                                             uint8_t channel_id_bytes,
                                                             uint8_t priority,
                                                             const void* data,
                                                             size_t data_len,
                                                             const char* event);
librdp_status rdp_session_send_dynamic_channel_data(librdp_session* session,
                                                    uint32_t channel_id,
                                                    uint8_t channel_id_bytes,
                                                    const void* data,
                                                    size_t data_len,
                                                    const char* event);
librdp_status rdp_session_read_mcs_pdu(librdp_session* session,
                                       rdp_buffer* packet,
                                       const uint8_t** pdu,
                                       size_t* pdu_len,
                                       const char* event);
librdp_status rdp_session_read_mcs_pdu_timeout(librdp_session* session,
                                               rdp_buffer* packet,
                                               const uint8_t** pdu,
                                               size_t* pdu_len,
                                               const char* event,
                                               int timeout_ms);
librdp_status rdp_session_read_fastpath_packet(librdp_session* session, rdp_buffer* packet);
librdp_status rdp_session_read_credssp_ts_request(librdp_session* session, rdp_buffer* packet, int timeout_ms);
librdp_status rdp_session_apply_bitmap_update(librdp_session* session, const rdp_bitmap_update* update);
void rdp_session_fastpath_fragment_reset(librdp_session* session);
librdp_status rdp_session_decompress_bulk_payload(librdp_session* session,
                                                  uint8_t flags,
                                                  const uint8_t* data,
                                                  size_t data_len,
                                                  rdp_buffer* decoded);
librdp_status rdp_session_process_fastpath_packet(librdp_session* session, const rdp_buffer* packet);

#endif
