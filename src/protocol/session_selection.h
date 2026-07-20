/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: session selection helper declaration contract.
 * Invariants: wire lengths, tags, and stream offsets must remain synchronized
 * across parse and write helpers.
 * Ownership: parsed views borrow input bytes and serialized buffers are
 * caller-owned.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: all network bytes are untrusted until parsed by the declared
 * helper.
 */


#ifndef RDP_PROTOCOL_SESSION_SELECTION_H
#define RDP_PROTOCOL_SESSION_SELECTION_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_SESSION_SELECTION_VERSION1 0x00000001u
#define RDP_SESSION_SELECTION_VERSION2 0x00000002u
#define RDP_SESSION_SELECTION_V1_LENGTH 16u
#define RDP_SESSION_SELECTION_V2_HEADER_LENGTH 18u
#define RDP_SESSION_SELECTION_MAX_TEXT_CHARS 4096u
#define RDP_SERVER_REDIRECTION_PACKET_FLAGS 0x0400u
#define RDP_SERVER_REDIRECTION_PACKET_BASE_LENGTH 12u
#define RDP_SERVER_REDIRECTION_PACKET_PAD_LENGTH 8u
#define RDP_SERVER_REDIRECTION_LB_TARGET_NET_ADDRESS 0x00000001u
#define RDP_SERVER_REDIRECTION_LB_LOAD_BALANCE_INFO 0x00000002u
#define RDP_SERVER_REDIRECTION_LB_USERNAME 0x00000004u
#define RDP_SERVER_REDIRECTION_LB_DOMAIN 0x00000008u
#define RDP_SERVER_REDIRECTION_LB_PASSWORD 0x00000010u
#define RDP_SERVER_REDIRECTION_LB_DONT_STORE_USERNAME 0x00000020u
#define RDP_SERVER_REDIRECTION_LB_SMARTCARD_LOGON 0x00000040u
#define RDP_SERVER_REDIRECTION_LB_NO_REDIRECT 0x00000080u
#define RDP_SERVER_REDIRECTION_LB_TARGET_FQDN 0x00000100u
#define RDP_SERVER_REDIRECTION_LB_TARGET_NETBIOS_NAME 0x00000200u
#define RDP_SERVER_REDIRECTION_LB_TARGET_NET_ADDRESSES 0x00000800u
#define RDP_SERVER_REDIRECTION_LB_CLIENT_TSV_URL 0x00001000u
#define RDP_SERVER_REDIRECTION_LB_SERVER_TSV_CAPABLE 0x00002000u
#define RDP_SERVER_REDIRECTION_LB_PASSWORD_IS_PK_ENCRYPTED 0x00004000u
#define RDP_SERVER_REDIRECTION_LB_REDIRECTION_GUID 0x00008000u
#define RDP_SERVER_REDIRECTION_LB_TARGET_CERTIFICATE 0x00010000u
#define RDP_SERVER_REDIRECTION_KNOWN_FLAGS 0x0001fbffu

typedef struct rdp_session_selection_pdu
{
    uint32_t cb_size;
    uint32_t flags;
    uint32_t version;
    uint32_t id;
    uint16_t text_chars;
    const uint8_t* text_utf16le;
} rdp_session_selection_pdu;

typedef struct rdp_server_redirection_blob
{
    const uint8_t* data;
    uint32_t length;
} rdp_server_redirection_blob;

typedef struct rdp_server_redirection_packet
{
    uint16_t flags;
    uint16_t length;
    uint32_t session_id;
    uint32_t redirection_flags;
    rdp_server_redirection_blob target_net_address;
    rdp_server_redirection_blob load_balance_info;
    rdp_server_redirection_blob username;
    rdp_server_redirection_blob domain;
    rdp_server_redirection_blob password;
    rdp_server_redirection_blob target_fqdn;
    rdp_server_redirection_blob target_netbios_name;
    rdp_server_redirection_blob tsv_url;
    rdp_server_redirection_blob redirection_guid;
    rdp_server_redirection_blob target_certificate;
    rdp_server_redirection_blob target_net_addresses;
    uint8_t has_pad;
} rdp_server_redirection_packet;

librdp_status rdp_session_selection_parse_pdu(const void* data,
                                              size_t length,
                                              rdp_session_selection_pdu* pdu);
librdp_status rdp_session_selection_write_v1(rdp_buffer* buffer, uint32_t id);
librdp_status rdp_session_selection_write_v2(rdp_buffer* buffer,
                                             uint32_t id,
                                             const void* text_utf16le,
                                             uint16_t text_chars);
librdp_status rdp_server_redirection_parse_packet(
    const void* data,
    size_t length,
    rdp_server_redirection_packet* packet);
librdp_status rdp_server_redirection_write_packet(
    rdp_buffer* buffer,
    const rdp_server_redirection_packet* packet,
    int append_pad);
librdp_status rdp_server_redirection_parse_enhanced(
    const void* data,
    size_t length,
    rdp_server_redirection_packet* packet);
librdp_status rdp_server_redirection_write_enhanced(
    rdp_buffer* buffer,
    uint16_t channel_id,
    const rdp_server_redirection_packet* packet,
    int append_packet_pad,
    int append_outer_pad);

#endif
