/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal clipboard redirection contracts.
 * Invariants: format ids, stream ids, chunk lengths, and file indices are
 * correlated before local clipboard data is exposed.
 * Ownership: local clipboard buffers and pending file requests are session-owned.
 * Threading: clipboard handlers run on the session owner thread.
 * Trust boundary: clipboard text, HTML, image, and file-list payloads are user
 * data and must remain redacted by default.
 */

#ifndef RDP_CLIENT_SESSION_CLIPBOARD_H
#define RDP_CLIENT_SESSION_CLIPBOARD_H

#include <librdp/session.h>

#include "clipboard/clipboard.h"
#include "common/buffer.h"

#include <stddef.h>
#include <stdint.h>

struct rdp_session_clipboard_file_request;

void rdp_session_clipboard_clear(librdp_session* session);
void rdp_session_clipboard_local_clear(librdp_session* session);
librdp_status rdp_session_send_clipboard_packet(librdp_session* session, const rdp_buffer* payload, const char* event);
librdp_status rdp_session_send_clipboard_format_list(librdp_session* session);
librdp_status rdp_session_send_clipboard_handshake(librdp_session* session);
librdp_status rdp_session_clipboard_store_remote_formats(
    librdp_session* session,
    const rdp_clipboard_format_list* list,
    int long_names,
    librdp_clipboard_format* formats,
    uint32_t capacity,
    uint32_t* stored,
    uint32_t* total);
librdp_status rdp_session_clipboard_write_local_data_response(librdp_session* session,
                                                              uint32_t format_id,
                                                              rdp_buffer* response,
                                                              uint8_t* available,
                                                              size_t* data_len);
librdp_status rdp_session_clipboard_write_file_contents(librdp_session* session,
                                                        const rdp_clipboard_file_contents_request* request,
                                                        rdp_buffer* response,
                                                        uint8_t* ok,
                                                        size_t* data_len);
struct rdp_session_clipboard_file_request* rdp_session_clipboard_file_request_find(librdp_session* session,
                                                                                  uint32_t stream_id);
librdp_status rdp_session_clipboard_file_request_store(librdp_session* session,
                                                       uint32_t stream_id,
                                                       int32_t file_index,
                                                       uint32_t flags,
                                                       uint64_t position,
                                                       uint32_t requested);

#endif
