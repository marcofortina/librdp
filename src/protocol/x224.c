#include "protocol/x224.h"

#include "common/stream.h"

#include <string.h>

librdp_status rdp_x224_build_connection_request(rdp_buffer* buffer, const char* cookie_name, uint32_t protocols)
{
    librdp_status status = LIBRDP_STATUS_OK;
    const char prefix[] = "Cookie: mstshash=";
    const char suffix[] = "\r\n";
    size_t cookie_len = 0;
    size_t user_len = 0;
    uint8_t li = 0;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (cookie_name && cookie_name[0] != '\0')
    {
        user_len = strlen(cookie_name);
        if (user_len > 64)
            user_len = 64;
        cookie_len = (sizeof(prefix) - 1u) + user_len + (sizeof(suffix) - 1u);
    }

    if (6u + cookie_len + 8u > 255u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    li = (uint8_t)(6u + cookie_len + 8u);
    status = rdp_buffer_append_u8(buffer, li);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, 0xe0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_be(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_be(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (cookie_len > 0)
    {
        status = rdp_buffer_append(buffer, prefix, sizeof(prefix) - 1u);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append(buffer, cookie_name, user_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append(buffer, suffix, sizeof(suffix) - 1u);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }

    status = rdp_buffer_append_u8(buffer, 1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, 8);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, protocols);
}

librdp_status rdp_x224_parse_connection_confirm(const void* payload, size_t payload_len, rdp_x224_connection_confirm* confirm)
{
    rdp_stream stream;
    uint8_t li = 0;
    uint8_t type = 0;

    if (!payload || !confirm || payload_len < 7)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(confirm, 0, sizeof(*confirm));
    rdp_stream_init(&stream, payload, payload_len);
    if (rdp_stream_read_u8(&stream, &li) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &type) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (type != 0xd0 || li + 1u > payload_len || li < 6)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (rdp_stream_read_u16_be(&stream, &confirm->destination_ref) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_be(&stream, &confirm->source_ref) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &confirm->class_option) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (rdp_stream_remaining(&stream) >= 8)
    {
        uint8_t neg_type = 0;
        uint8_t flags = 0;
        uint16_t length = 0;
        uint32_t value = 0;

        if (rdp_stream_read_u8(&stream, &neg_type) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &flags) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &length) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &value) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if ((neg_type != 2 && neg_type != 3) || length != 8)
            return LIBRDP_STATUS_PROTOCOL_ERROR;

        confirm->negotiation.present = true;
        confirm->negotiation.failure = neg_type == 3;
        confirm->negotiation.type = neg_type;
        confirm->negotiation.flags = flags;
        confirm->negotiation.length = length;
        if (neg_type == 2)
            confirm->negotiation.selected_protocol = value;
        else
            confirm->negotiation.failure_code = value;
    }

    return LIBRDP_STATUS_OK;
}

librdp_status rdp_x224_wrap_data(rdp_buffer* buffer, const void* payload, size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!payload && payload_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u8(buffer, 0x02);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, 0xf0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, 0x80);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, payload, payload_len);
}

librdp_status rdp_x224_parse_data(const void* payload, size_t payload_len, const uint8_t** data, size_t* data_len)
{
    const uint8_t* bytes = (const uint8_t*)payload;

    if (!payload || !data || !data_len || payload_len < 3)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (bytes[0] != 0x02 || bytes[1] != 0xf0 || bytes[2] != 0x80)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    *data = bytes + 3;
    *data_len = payload_len - 3u;
    return LIBRDP_STATUS_OK;
}
