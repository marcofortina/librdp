/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: dynamic virtual-channel control and data declarations.
 * Invariants: channel payload lengths, message identifiers, and negotiated
 * capabilities must be validated before state changes.
 * Ownership: parsed packet structs remain caller-owned unless a session
 * explicitly stores a copy.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths are local policy inputs.
 */


#ifndef RDP_CHANNELS_DYNAMIC_CHANNEL_H
#define RDP_CHANNELS_DYNAMIC_CHANNEL_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_DYNAMIC_CHANNEL_CMD_CREATE 0x01u
#define RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST 0x02u
#define RDP_DYNAMIC_CHANNEL_CMD_DATA 0x03u
#define RDP_DYNAMIC_CHANNEL_CMD_CLOSE 0x04u
#define RDP_DYNAMIC_CHANNEL_CMD_CAPABILITIES 0x05u
#define RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST_COMPRESSED 0x06u
#define RDP_DYNAMIC_CHANNEL_CMD_DATA_COMPRESSED 0x07u
#define RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_REQUEST 0x08u
#define RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_RESPONSE 0x09u
#define RDP_DYNAMIC_CHANNEL_STATUS_OK 0x00000000u
#define RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE 1600u
#define RDP_DYNAMIC_CHANNEL_SINGLE_MESSAGE_LIMIT 1590u
#define RDP_DYNAMIC_CHANNEL_SOFT_SYNC_TCP_FLUSHED 0x0001u
#define RDP_DYNAMIC_CHANNEL_SOFT_SYNC_CHANNEL_LIST_PRESENT 0x0002u
#define RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE 0x00000001u
#define RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY 0x00000003u

typedef struct rdp_dynamic_channel_header
{
    uint8_t command;
    uint8_t priority;
    uint8_t length_bytes;
    uint8_t channel_id_bytes;
    uint8_t raw;
} rdp_dynamic_channel_header;

typedef struct rdp_dynamic_channel_capabilities
{
    uint16_t version;
    uint8_t has_priority_charges;
    uint16_t priority_charge[4];
} rdp_dynamic_channel_capabilities;

typedef struct rdp_dynamic_channel_create_request
{
    uint32_t channel_id;
    uint8_t channel_id_bytes;
    uint8_t priority;
    const char* name;
    size_t name_len;
} rdp_dynamic_channel_create_request;

typedef struct rdp_dynamic_channel_data_pdu
{
    uint32_t channel_id;
    uint8_t channel_id_bytes;
    const uint8_t* data;
    size_t data_len;
} rdp_dynamic_channel_data_pdu;

typedef struct rdp_dynamic_channel_data_first_pdu
{
    uint32_t channel_id;
    uint8_t channel_id_bytes;
    uint32_t total_length;
    const uint8_t* data;
    size_t data_len;
} rdp_dynamic_channel_data_first_pdu;

typedef struct rdp_dynamic_channel_close_pdu
{
    uint32_t channel_id;
    uint8_t channel_id_bytes;
} rdp_dynamic_channel_close_pdu;

typedef struct rdp_dynamic_channel_compressed_data_pdu
{
    uint32_t channel_id;
    uint8_t channel_id_bytes;
    const uint8_t* data;
    size_t data_len;
} rdp_dynamic_channel_compressed_data_pdu;

typedef struct rdp_dynamic_channel_compressed_data_first_pdu
{
    uint32_t channel_id;
    uint8_t channel_id_bytes;
    uint32_t total_length;
    const uint8_t* data;
    size_t data_len;
} rdp_dynamic_channel_compressed_data_first_pdu;

typedef struct rdp_dynamic_channel_soft_sync_request
{
    uint32_t length;
    uint16_t flags;
    uint16_t tunnel_count;
    const uint8_t* lists;
    size_t lists_len;
} rdp_dynamic_channel_soft_sync_request;

typedef struct rdp_dynamic_channel_soft_sync_channel_list
{
    uint32_t tunnel_type;
    uint16_t channel_count;
    const uint8_t* channel_ids;
    size_t channel_ids_len;
} rdp_dynamic_channel_soft_sync_channel_list;

typedef struct rdp_dynamic_channel_soft_sync_response
{
    uint32_t tunnel_count;
    const uint8_t* tunnel_types;
    size_t tunnel_types_len;
} rdp_dynamic_channel_soft_sync_response;

uint16_t rdp_dynamic_channel_select_version(uint16_t server_version);
uint8_t rdp_dynamic_channel_select_channel_id_bytes(uint32_t channel_id);
size_t rdp_dynamic_channel_data_pdu_header_size(uint8_t channel_id_bytes);
size_t rdp_dynamic_channel_data_first_pdu_header_size(uint8_t channel_id_bytes, uint32_t total_length);
librdp_status rdp_dynamic_channel_parse_header(const void* data,
                                               size_t length,
                                               rdp_dynamic_channel_header* header);
librdp_status rdp_dynamic_channel_parse_capabilities(const void* data,
                                                     size_t length,
                                                     rdp_dynamic_channel_capabilities* capabilities);
librdp_status rdp_dynamic_channel_write_capabilities_response(rdp_buffer* buffer, uint16_t version);
librdp_status rdp_dynamic_channel_parse_create_request(const void* data,
                                                       size_t length,
                                                       rdp_dynamic_channel_create_request* request);
librdp_status rdp_dynamic_channel_write_create_response(rdp_buffer* buffer,
                                                       uint32_t channel_id,
                                                       uint8_t channel_id_bytes,
                                                       uint32_t status_code);
librdp_status rdp_dynamic_channel_parse_data(const void* data,
                                             size_t length,
                                             rdp_dynamic_channel_data_pdu* pdu);
librdp_status rdp_dynamic_channel_write_data(rdp_buffer* buffer,
                                             uint32_t channel_id,
                                             uint8_t channel_id_bytes,
                                             const void* data,
                                             size_t data_len);
librdp_status rdp_dynamic_channel_write_data_ex(rdp_buffer* buffer,
                                                uint32_t channel_id,
                                                uint8_t channel_id_bytes,
                                                uint8_t priority,
                                                const void* data,
                                                size_t data_len);
librdp_status rdp_dynamic_channel_parse_data_first(const void* data,
                                                   size_t length,
                                                   rdp_dynamic_channel_data_first_pdu* pdu);
librdp_status rdp_dynamic_channel_write_data_first(rdp_buffer* buffer,
                                                  uint32_t channel_id,
                                                  uint8_t channel_id_bytes,
                                                  uint32_t total_length,
                                                  const void* data,
                                                  size_t data_len);
librdp_status rdp_dynamic_channel_write_data_first_ex(rdp_buffer* buffer,
                                                     uint32_t channel_id,
                                                     uint8_t channel_id_bytes,
                                                     uint8_t priority,
                                                     uint32_t total_length,
                                                     const void* data,
                                                     size_t data_len);
librdp_status rdp_dynamic_channel_parse_close(const void* data,
                                              size_t length,
                                              rdp_dynamic_channel_close_pdu* pdu);
librdp_status rdp_dynamic_channel_write_close(rdp_buffer* buffer,
                                             uint32_t channel_id,
                                             uint8_t channel_id_bytes);
librdp_status rdp_dynamic_channel_parse_compressed_data(
    const void* data,
    size_t length,
    rdp_dynamic_channel_compressed_data_pdu* pdu);
librdp_status rdp_dynamic_channel_write_compressed_data(rdp_buffer* buffer,
                                                        uint32_t channel_id,
                                                        uint8_t channel_id_bytes,
                                                        const void* data,
                                                        size_t data_len);
librdp_status rdp_dynamic_channel_parse_compressed_data_first(
    const void* data,
    size_t length,
    rdp_dynamic_channel_compressed_data_first_pdu* pdu);
librdp_status rdp_dynamic_channel_write_compressed_data_first(rdp_buffer* buffer,
                                                              uint32_t channel_id,
                                                              uint8_t channel_id_bytes,
                                                              uint32_t total_length,
                                                              const void* data,
                                                              size_t data_len);
librdp_status rdp_dynamic_channel_parse_soft_sync_request(
    const void* data,
    size_t length,
    rdp_dynamic_channel_soft_sync_request* request);
librdp_status rdp_dynamic_channel_soft_sync_request_get_list(
    const rdp_dynamic_channel_soft_sync_request* request,
    uint16_t index,
    rdp_dynamic_channel_soft_sync_channel_list* list);
librdp_status rdp_dynamic_channel_soft_sync_channel_list_get_id(
    const rdp_dynamic_channel_soft_sync_channel_list* list,
    uint16_t index,
    uint32_t* channel_id);
librdp_status rdp_dynamic_channel_write_soft_sync_response(rdp_buffer* buffer,
                                                          const uint32_t* tunnel_types,
                                                          uint32_t tunnel_count);
librdp_status rdp_dynamic_channel_parse_soft_sync_response(
    const void* data,
    size_t length,
    rdp_dynamic_channel_soft_sync_response* response);
librdp_status rdp_dynamic_channel_soft_sync_response_get_tunnel(
    const rdp_dynamic_channel_soft_sync_response* response,
    uint32_t index,
    uint32_t* tunnel_type);

#endif
