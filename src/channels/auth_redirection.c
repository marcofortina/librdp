#include "channels/auth_redirection.h"

#include "common/stream.h"

#include <string.h>

int rdp_auth_redirection_call_id_valid(uint32_t call_id)
{
    if (call_id <= RDP_AUTH_REDIRECTION_CALL_GENERIC_MAXIMUM)
        return 1;
    if (call_id >= RDP_AUTH_REDIRECTION_CALL_KERB_MINIMUM &&
        call_id <= RDP_AUTH_REDIRECTION_CALL_KERB_MAXIMUM)
        return 1;
    if (call_id >= RDP_AUTH_REDIRECTION_CALL_NTLM_MINIMUM &&
        call_id <= RDP_AUTH_REDIRECTION_CALL_NTLM_MAXIMUM)
        return 1;
    return call_id == RDP_AUTH_REDIRECTION_CALL_INVALID;
}

librdp_status rdp_auth_redirection_parse_outer_packet(
    const void* data,
    size_t length,
    rdp_auth_redirection_outer_packet* packet)
{
    rdp_stream stream;
    uint32_t context_low = 0;
    uint32_t context_high = 0;

    if (!data || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_AUTH_REDIRECTION_OUTER_HEADER_LENGTH || length > (size_t)UINT32_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(packet, 0, sizeof(*packet));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &packet->protocol_magic) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &packet->length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &packet->version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &packet->reserved) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &context_low) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &context_high) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    packet->ts_pkg_context = ((uint64_t)context_high << 32) | context_low;
    if (packet->protocol_magic != RDP_AUTH_REDIRECTION_MAGIC ||
        packet->length != (uint32_t)length ||
        packet->version != RDP_AUTH_REDIRECTION_VERSION ||
        packet->reserved != 0 ||
        packet->ts_pkg_context != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    packet->payload_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &packet->payload, packet->payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_auth_redirection_write_outer_packet(
    rdp_buffer* buffer,
    const void* payload,
    size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t length = 0;

    if (!buffer || (!payload && payload_len > 0) ||
        payload_len > (size_t)UINT32_MAX - RDP_AUTH_REDIRECTION_OUTER_HEADER_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    length = (uint32_t)(payload_len + RDP_AUTH_REDIRECTION_OUTER_HEADER_LENGTH);
    status = rdp_buffer_append_u32_le(buffer, RDP_AUTH_REDIRECTION_MAGIC);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, RDP_AUTH_REDIRECTION_VERSION);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, payload, payload_len);
}

librdp_status rdp_auth_redirection_parse_inner_buffer(
    const void* data,
    size_t length,
    rdp_auth_redirection_inner_buffer* inner)
{
    rdp_stream stream;
    const uint8_t* reserved = NULL;
    size_t i = 0;

    if (!data || !inner)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_AUTH_REDIRECTION_INNER_HEADER_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(inner, 0, sizeof(*inner));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &inner->revision) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &reserved, sizeof(inner->reserved)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(inner->reserved, reserved, sizeof(inner->reserved));
    if (inner->revision != RDP_AUTH_REDIRECTION_INNER_REVISION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < sizeof(inner->reserved); i++)
    {
        if (inner->reserved[i] != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    inner->payload_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &inner->payload, inner->payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_auth_redirection_write_inner_buffer(
    rdp_buffer* buffer,
    const void* payload,
    size_t payload_len)
{
    static const uint8_t zeroes[14] = {0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!payload && payload_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, RDP_AUTH_REDIRECTION_INNER_REVISION);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, zeroes, sizeof(zeroes));
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, payload, payload_len);
}

librdp_status rdp_auth_redirection_parse_call(
    const void* data,
    size_t length,
    rdp_auth_redirection_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &call->call_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_auth_redirection_call_id_valid(call->call_id))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    call->payload_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &call->payload, call->payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_auth_redirection_write_call(
    rdp_buffer* buffer,
    uint32_t call_id,
    const void* payload,
    size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!payload && payload_len > 0) ||
        !rdp_auth_redirection_call_id_valid(call_id))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, call_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, payload, payload_len);
}
