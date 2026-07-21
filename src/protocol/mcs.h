/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: MCS connect and channel declaration contract.
 * Invariants: wire lengths, tags, and stream offsets must remain synchronized
 * across parse and write helpers.
 * Ownership: parsed views borrow input bytes and serialized buffers are
 * caller-owned.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: all network bytes are untrusted until parsed by the declared
 * helper.
 */


#ifndef RDP_PROTOCOL_MCS_H
#define RDP_PROTOCOL_MCS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"
#include "common/stream.h"

typedef struct rdp_mcs_connect_response
{
    bool has_result;
    uint8_t result;
    const uint8_t* user_data;
    size_t user_data_len;
} rdp_mcs_connect_response;

typedef struct rdp_mcs_connect_initial
{
    const uint8_t* user_data;
    size_t user_data_len;
} rdp_mcs_connect_initial;

typedef struct rdp_mcs_attach_user_confirm
{
    uint8_t result;
    uint16_t user_id;
} rdp_mcs_attach_user_confirm;

typedef struct rdp_mcs_channel_join_confirm
{
    uint8_t result;
    uint16_t initiator;
    uint16_t requested_channel_id;
    uint16_t channel_id;
} rdp_mcs_channel_join_confirm;

typedef struct rdp_mcs_channel_join_request
{
    uint16_t initiator;
    uint16_t channel_id;
} rdp_mcs_channel_join_request;

typedef struct rdp_mcs_send_data_indication
{
    uint16_t initiator;
    uint16_t channel_id;
    const uint8_t* payload;
    size_t payload_len;
} rdp_mcs_send_data_indication;

#define RDP_MCS_GLOBAL_CHANNEL_ID 1003u
#define RDP_MCS_BASE_CHANNEL_ID 1001u
#define RDP_MCS_DOMAIN_PDU_DISCONNECT_PROVIDER_ULTIMATUM 8u

librdp_status rdp_mcs_write_ber_length(rdp_buffer* buffer, size_t length);
librdp_status rdp_mcs_write_ber_integer(rdp_buffer* buffer, uint32_t value);
librdp_status rdp_mcs_write_connect_initial(rdp_buffer* buffer, const void* gcc_data, size_t gcc_data_len);
librdp_status rdp_mcs_parse_connect_initial(const void* data, size_t length, rdp_mcs_connect_initial* initial);
librdp_status rdp_mcs_write_connect_response(rdp_buffer* buffer, const void* gcc_data, size_t gcc_data_len);
librdp_status rdp_mcs_write_erect_domain_request(rdp_buffer* buffer);
librdp_status rdp_mcs_parse_erect_domain_request(const void* data, size_t length);
librdp_status rdp_mcs_write_attach_user_request(rdp_buffer* buffer);
librdp_status rdp_mcs_parse_attach_user_request(const void* data, size_t length);
librdp_status rdp_mcs_write_attach_user_confirm(rdp_buffer* buffer, uint16_t user_id);
librdp_status rdp_mcs_parse_attach_user_confirm(const void* data, size_t length, rdp_mcs_attach_user_confirm* confirm);
librdp_status rdp_mcs_write_channel_join_request(rdp_buffer* buffer, uint16_t user_id, uint16_t channel_id);
librdp_status rdp_mcs_parse_channel_join_request(const void* data,
                                                 size_t length,
                                                 rdp_mcs_channel_join_request* request);
librdp_status rdp_mcs_write_channel_join_confirm(rdp_buffer* buffer,
                                                 uint16_t user_id,
                                                 uint16_t requested_channel_id);
librdp_status rdp_mcs_parse_channel_join_confirm(const void* data, size_t length, rdp_mcs_channel_join_confirm* confirm);
librdp_status rdp_mcs_read_ber_length(rdp_stream* stream, size_t* length);
librdp_status rdp_mcs_parse_connect_response(const void* data, size_t length, rdp_mcs_connect_response* response);
librdp_status rdp_mcs_parse_send_data_request(const void* data,
                                              size_t length,
                                              rdp_mcs_send_data_indication* request);
librdp_status rdp_mcs_parse_disconnect_provider_ultimatum(
    const void* data,
    size_t length,
    uint8_t* reason);
librdp_status rdp_mcs_write_send_data_indication(rdp_buffer* buffer,
                                                 uint16_t user_id,
                                                 uint16_t channel_id,
                                                 const void* payload,
                                                 size_t payload_len);
librdp_status rdp_mcs_parse_send_data_indication(const void* data,
                                                 size_t length,
                                                 rdp_mcs_send_data_indication* indication);

#endif
