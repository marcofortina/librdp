/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: MCS connect and channel PDU support.
 * Invariants: wire lengths, tags, and stream offsets stay consistent across
 * every parse and write path.
 * Ownership: serialized buffers are caller-owned and parsed views never
 * outlive the input stream.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: all protocol bytes are untrusted network input until parsed
 * successfully.
 */


#include "protocol/mcs.h"

#include <string.h>

#define RDP_MCS_PDU_ERECT_DOMAIN_REQUEST 1u
#define RDP_MCS_PDU_ATTACH_USER_REQUEST 10u
#define RDP_MCS_PDU_ATTACH_USER_CONFIRM 11u
#define RDP_MCS_PDU_CHANNEL_JOIN_REQUEST 14u
#define RDP_MCS_PDU_CHANNEL_JOIN_CONFIRM 15u
#define RDP_MCS_PDU_SEND_DATA_INDICATION 26u

static librdp_status rdp_mcs_write_domain_choice(rdp_buffer* buffer, uint8_t pdu_type, uint8_t options)
{
    if (!buffer || pdu_type > 0x3fu || options > 0x03u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u8(buffer, (uint8_t)((pdu_type << 2) | options));
}

static librdp_status rdp_mcs_read_domain_choice(rdp_stream* stream, uint8_t expected_type, uint8_t* options)
{
    uint8_t value = 0;
    uint8_t type = 0;

    if (!stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u8(stream, &value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    type = (uint8_t)(value >> 2);
    if (type != expected_type)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (options)
        *options = (uint8_t)(value & 0x03u);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_mcs_write_per_integer(rdp_buffer* buffer, uint32_t value)
{
    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (value <= 0xffu)
    {
        librdp_status status = rdp_buffer_append_u8(buffer, 1);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_buffer_append_u8(buffer, (uint8_t)value);
    }
    if (value <= 0xffffu)
    {
        librdp_status status = rdp_buffer_append_u8(buffer, 2);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_buffer_append_u16_be(buffer, (uint16_t)value);
    }
    {
        librdp_status status = rdp_buffer_append_u8(buffer, 4);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_buffer_append_u32_be(buffer, value);
    }
}

static librdp_status rdp_mcs_write_per_integer16(rdp_buffer* buffer, uint16_t value, uint16_t min)
{
    if (!buffer || value < min)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u16_be(buffer, (uint16_t)(value - min));
}

static librdp_status rdp_mcs_read_per_integer16(rdp_stream* stream, uint16_t min, uint16_t* value)
{
    uint16_t raw = 0;

    if (!stream || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u16_be(stream, &raw) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (raw > (uint16_t)(0xffffu - min))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = (uint16_t)(raw + min);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_mcs_read_per_enum(rdp_stream* stream, uint8_t* value)
{
    if (!stream || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_stream_read_u8(stream, value);
}

static librdp_status rdp_mcs_read_per_length(rdp_stream* stream, size_t* length)
{
    uint8_t first = 0;

    if (!stream || !length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u8(stream, &first) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((first & 0x80u) == 0)
    {
        *length = first;
        return LIBRDP_STATUS_OK;
    }
    {
        uint8_t second = 0;
        if (rdp_stream_read_u8(stream, &second) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *length = (size_t)(((uint16_t)(first & 0x7fu) << 8) | second);
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_mcs_write_ber_tag(rdp_buffer* buffer, const uint8_t* tag, size_t tag_len, size_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !tag || tag_len == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append(buffer, tag, tag_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_mcs_write_ber_length(buffer, length);
}

librdp_status rdp_mcs_write_ber_length(rdp_buffer* buffer, size_t length)
{
    uint8_t tmp[sizeof(size_t)];
    size_t count = 0;
    size_t value = length;
    size_t i = 0;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 0x80u)
        return rdp_buffer_append_u8(buffer, (uint8_t)length);

    while (value > 0)
    {
        tmp[sizeof(tmp) - 1u - count] = (uint8_t)(value & 0xffu);
        value >>= 8;
        count++;
    }
    if (count > 0x7fu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    {
        librdp_status status = rdp_buffer_append_u8(buffer, (uint8_t)(0x80u | count));
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    for (i = sizeof(tmp) - count; i < sizeof(tmp); i++)
    {
        librdp_status status = rdp_buffer_append_u8(buffer, tmp[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_mcs_write_ber_integer(rdp_buffer* buffer, uint32_t value)
{
    uint8_t tmp[5];
    uint8_t bytes[4];
    size_t first = 0;
    size_t length = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    bytes[0] = (uint8_t)((value >> 24) & 0xffu);
    bytes[1] = (uint8_t)((value >> 16) & 0xffu);
    bytes[2] = (uint8_t)((value >> 8) & 0xffu);
    bytes[3] = (uint8_t)(value & 0xffu);
    while (first < 3 && bytes[first] == 0 && (bytes[first + 1u] & 0x80u) == 0)
        first++;

    if ((bytes[first] & 0x80u) != 0)
    {
        tmp[0] = 0;
        memcpy(tmp + 1, bytes + first, sizeof(bytes) - first);
        length = sizeof(bytes) - first + 1u;
    }
    else
    {
        memcpy(tmp, bytes + first, sizeof(bytes) - first);
        length = sizeof(bytes) - first;
    }

    status = rdp_buffer_append_u8(buffer, 0x02);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_mcs_write_ber_length(buffer, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, tmp, length);
}

static librdp_status rdp_mcs_write_ber_octet_string(rdp_buffer* buffer, const void* data, size_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, 0x04);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_mcs_write_ber_length(buffer, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, length);
}

static librdp_status rdp_mcs_write_domain_parameters(rdp_buffer* buffer,
                                                     uint32_t max_channels,
                                                     uint32_t max_users,
                                                     uint32_t max_tokens,
                                                     uint32_t priorities,
                                                     uint32_t min_throughput,
                                                     uint32_t max_height,
                                                     uint32_t max_pdu_size,
                                                     uint32_t protocol_version)
{
    rdp_buffer body;
    librdp_status status = LIBRDP_STATUS_OK;
    const uint8_t tag = 0x30;

    rdp_buffer_init(&body);
    status = rdp_mcs_write_ber_integer(&body, max_channels);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_ber_integer(&body, max_users);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_ber_integer(&body, max_tokens);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_ber_integer(&body, priorities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_ber_integer(&body, min_throughput);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_ber_integer(&body, max_height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_ber_integer(&body, max_pdu_size);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_ber_integer(&body, protocol_version);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_ber_tag(buffer, &tag, 1, body.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, body.data, body.length);

    rdp_buffer_free(&body);
    return status;
}

librdp_status rdp_mcs_write_connect_initial(rdp_buffer* buffer, const void* gcc_data, size_t gcc_data_len)
{
    static const uint8_t selector[] = {0x01};
    static const uint8_t app_tag[] = {0x7f, 0x65};
    rdp_buffer body;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!gcc_data && gcc_data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&body);
    status = rdp_mcs_write_ber_octet_string(&body, selector, sizeof(selector));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_ber_octet_string(&body, selector, sizeof(selector));
    if (status == LIBRDP_STATUS_OK)
    {
        static const uint8_t boolean_true[] = {0x01, 0x01, 0xff};
        status = rdp_buffer_append(&body, boolean_true, sizeof(boolean_true));
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_domain_parameters(&body, 34, 2, 0, 1, 0, 1, 65535, 2);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_domain_parameters(&body, 1, 1, 1, 1, 0, 1, 1056, 2);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_domain_parameters(&body, 65535, 64535, 65535, 1, 0, 1, 65535, 2);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_ber_octet_string(&body, gcc_data, gcc_data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_ber_tag(buffer, app_tag, sizeof(app_tag), body.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, body.data, body.length);

    rdp_buffer_free(&body);
    return status;
}

librdp_status rdp_mcs_write_erect_domain_request(rdp_buffer* buffer)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_mcs_write_domain_choice(buffer, RDP_MCS_PDU_ERECT_DOMAIN_REQUEST, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_per_integer(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_per_integer(buffer, 0);
    return status;
}

librdp_status rdp_mcs_write_attach_user_request(rdp_buffer* buffer)
{
    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_mcs_write_domain_choice(buffer, RDP_MCS_PDU_ATTACH_USER_REQUEST, 0);
}

librdp_status rdp_mcs_parse_attach_user_confirm(const void* data, size_t length, rdp_mcs_attach_user_confirm* confirm)
{
    rdp_stream stream;
    uint8_t options = 0;

    if (!data || !confirm)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(confirm, 0, sizeof(*confirm));
    rdp_stream_init(&stream, data, length);
    if (rdp_mcs_read_domain_choice(&stream, RDP_MCS_PDU_ATTACH_USER_CONFIRM, &options) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (options != 2)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_mcs_read_per_enum(&stream, &confirm->result) != LIBRDP_STATUS_OK ||
        rdp_mcs_read_per_integer16(&stream, (uint16_t)RDP_MCS_BASE_CHANNEL_ID, &confirm->user_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_mcs_write_channel_join_request(rdp_buffer* buffer, uint16_t user_id, uint16_t channel_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || user_id < RDP_MCS_BASE_CHANNEL_ID)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_mcs_write_domain_choice(buffer, RDP_MCS_PDU_CHANNEL_JOIN_REQUEST, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_per_integer16(buffer, user_id, (uint16_t)RDP_MCS_BASE_CHANNEL_ID);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_per_integer16(buffer, channel_id, 0);
    return status;
}

librdp_status rdp_mcs_parse_channel_join_confirm(const void* data,
                                                 size_t length,
                                                 rdp_mcs_channel_join_confirm* confirm)
{
    rdp_stream stream;
    uint8_t options = 0;

    if (!data || !confirm)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(confirm, 0, sizeof(*confirm));
    rdp_stream_init(&stream, data, length);
    if (rdp_mcs_read_domain_choice(&stream, RDP_MCS_PDU_CHANNEL_JOIN_CONFIRM, &options) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (options != 2)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_mcs_read_per_enum(&stream, &confirm->result) != LIBRDP_STATUS_OK ||
        rdp_mcs_read_per_integer16(&stream, (uint16_t)RDP_MCS_BASE_CHANNEL_ID, &confirm->initiator) !=
            LIBRDP_STATUS_OK ||
        rdp_mcs_read_per_integer16(&stream, 0, &confirm->requested_channel_id) != LIBRDP_STATUS_OK ||
        rdp_mcs_read_per_integer16(&stream, 0, &confirm->channel_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_mcs_read_ber_length(rdp_stream* stream, size_t* length)
{
    uint8_t first = 0;
    uint8_t count = 0;
    size_t value = 0;
    uint8_t i = 0;

    if (!stream || !length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u8(stream, &first) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((first & 0x80u) == 0)
    {
        *length = first;
        return LIBRDP_STATUS_OK;
    }

    count = (uint8_t)(first & 0x7fu);
    if (count == 0 || count > sizeof(size_t) || rdp_stream_remaining(stream) < count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    for (i = 0; i < count; i++)
    {
        uint8_t byte = 0;
        if (rdp_stream_read_u8(stream, &byte) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        value = (value << 8) | byte;
    }

    *length = value;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_mcs_read_ber_tag(rdp_stream* stream, uint8_t* tag, size_t* tag_len, bool* constructed)
{
    uint8_t first = 0;
    size_t count = 0;

    if (!stream || !tag || !tag_len || !constructed)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u8(stream, &first) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    tag[count++] = first;
    *constructed = (first & 0x20u) != 0;
    if ((first & 0x1fu) == 0x1fu)
    {
        uint8_t next = 0;
        do
        {
            if (count >= 8 || rdp_stream_read_u8(stream, &next) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            tag[count++] = next;
        } while ((next & 0x80u) != 0);
    }

    *tag_len = count;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_mcs_scan_connect_response(const uint8_t* data,
                                                   size_t length,
                                                   unsigned depth,
                                                   rdp_mcs_connect_response* response)
{
    rdp_stream stream;

    if (!data || !response || depth > 8)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    while (rdp_stream_remaining(&stream) > 0)
    {
        uint8_t tag[8];
        size_t tag_len = 0;
        size_t item_len = 0;
        const uint8_t* payload = NULL;
        bool constructed = false;

        if (rdp_mcs_read_ber_tag(&stream, tag, &tag_len, &constructed) != LIBRDP_STATUS_OK ||
            rdp_mcs_read_ber_length(&stream, &item_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_stream_remaining(&stream) < item_len)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_stream_read_bytes(&stream, &payload, item_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;

        if (tag_len == 1 && tag[0] == 0x0a && item_len == 1)
        {
            response->has_result = true;
            response->result = payload[0];
        }
        else if (tag_len == 1 && tag[0] == 0x04)
        {
            response->user_data = payload;
            response->user_data_len = item_len;
        }
        else if (constructed)
        {
            librdp_status status = rdp_mcs_scan_connect_response(payload, item_len, depth + 1u, response);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
    }

    return response->has_result ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_mcs_parse_connect_response(const void* data, size_t length, rdp_mcs_connect_response* response)
{
    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(response, 0, sizeof(*response));
    return rdp_mcs_scan_connect_response((const uint8_t*)data, length, 0, response);
}

librdp_status rdp_mcs_parse_send_data_indication(const void* data,
                                                 size_t length,
                                                 rdp_mcs_send_data_indication* indication)
{
    rdp_stream stream;
    uint8_t ignored = 0;
    size_t payload_len = 0;

    if (!data || !indication)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(indication, 0, sizeof(*indication));
    rdp_stream_init(&stream, data, length);
    if (rdp_mcs_read_domain_choice(&stream, RDP_MCS_PDU_SEND_DATA_INDICATION, NULL) != LIBRDP_STATUS_OK ||
        rdp_mcs_read_per_integer16(&stream, (uint16_t)RDP_MCS_BASE_CHANNEL_ID, &indication->initiator) !=
            LIBRDP_STATUS_OK ||
        rdp_mcs_read_per_integer16(&stream, 0, &indication->channel_id) != LIBRDP_STATUS_OK ||
        rdp_mcs_read_per_enum(&stream, &ignored) != LIBRDP_STATUS_OK ||
        rdp_mcs_read_per_length(&stream, &payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (payload_len == 0 || payload_len > rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &indication->payload, payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    indication->payload_len = payload_len;
    return LIBRDP_STATUS_OK;
}
