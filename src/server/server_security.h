/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: transport I/O, TLS, Standard Security, and CredSSP/NLA.
 * Invariants: authenticated and decrypted data is committed only after validation.
 * Ownership: peer objects own TLS, key, credential, and security contexts.
 * Threading: security operations run on the peer dispatch thread.
 * Trust boundary: encrypted transport and authentication tokens are untrusted.
 */

#ifndef RDP_SERVER_SECURITY_H
#define RDP_SERVER_SECURITY_H

#include "server/server_common.h"

char* rdp_server_strdup_bounded(const char* text);

char* rdp_server_secure_strdup_bounded(const char* text);

void rdp_server_secure_free(char* text);

void rdp_server_credssp_expected_clear(librdp_server_peer* peer);

librdp_status rdp_server_create_tls_context(const char* certificate_path,
                                                   const char* private_key_path,
                                                   SSL_CTX** context,
                                                   const char** failure_message);

librdp_status rdp_server_send_mcs_pdu(librdp_server_peer* peer, const rdp_buffer* mcs_pdu);

size_t rdp_server_outbound_security_overhead(const librdp_server_peer* peer);

librdp_status rdp_server_prepare_outbound_security_payload(librdp_server_peer* peer,
                                                                  rdp_buffer* secured,
                                                                  const uint8_t** payload,
                                                                  size_t* payload_len);

librdp_status rdp_server_send_slowpath(librdp_server_peer* peer, const rdp_buffer* slowpath_pdu);

void rdp_server_close_peer(librdp_server_peer* peer, librdp_server_peer_state state);

int rdp_server_uses_standard_security(const librdp_server_peer* peer);

librdp_status rdp_server_prepare_standard_security(librdp_server_peer* peer);

librdp_status rdp_server_read_tpkt(librdp_server_peer* peer,
                                          int timeout_ms,
                                          rdp_tpkt* packet,
                                          size_t* packet_len);

librdp_status rdp_server_start_tls(librdp_server_peer* peer,
                                          int timeout_ms,
                                          const char** failure_message);

librdp_status rdp_server_handle_credssp(librdp_server_peer* peer, int timeout_ms);

librdp_status rdp_server_handle_x224(librdp_server_peer* peer, const rdp_tpkt* packet);

int rdp_server_security_payload_has_flag(const uint8_t* input, size_t input_len, uint16_t required);

librdp_status rdp_server_handle_security_exchange(librdp_server_peer* peer,
                                                         const uint8_t* input,
                                                         size_t input_len);

librdp_status rdp_server_parse_client_info_security_payload(librdp_server_peer* peer,
                                                                   const uint8_t* input,
                                                                   size_t input_len,
                                                                   rdp_client_info_summary* summary);

librdp_status rdp_server_unwrap_optional_security_header(librdp_server_peer* peer,
                                                                const uint8_t* input,
                                                                size_t input_len,
                                                                rdp_buffer* storage,
                                                                const uint8_t** output,
                                                                size_t* output_len);

#endif
