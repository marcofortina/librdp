#include "channels/auth_redirection.h"

#include "common/stream.h"

#include <string.h>

static librdp_status rdp_auth_redirection_parse_u32_call(
    const void* data,
    size_t length,
    uint32_t expected_call_id,
    uint32_t* value)
{
    rdp_auth_redirection_call call;
    rdp_stream stream;

    if (!data || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_auth_redirection_parse_call(data, length, &call) != LIBRDP_STATUS_OK ||
        call.call_id != expected_call_id ||
        call.payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, call.payload, call.payload_len);
    if (rdp_stream_read_u32_le(&stream, value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_auth_redirection_parse_fixed_response(
    const void* data,
    size_t length,
    uint32_t expected_call_id,
    size_t expected_len,
    rdp_auth_redirection_fixed_response* fixed)
{
    if (!data || !fixed)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(fixed, 0, sizeof(*fixed));
    if (rdp_auth_redirection_parse_response(data, length, &fixed->response) != LIBRDP_STATUS_OK ||
        fixed->response.call_id != expected_call_id ||
        fixed->response.payload_len != expected_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    fixed->data = fixed->response.payload;
    fixed->data_len = fixed->response.payload_len;
    return LIBRDP_STATUS_OK;
}

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

int rdp_auth_redirection_kerb_call_id_valid(uint32_t call_id)
{
    return call_id >= RDP_AUTH_REDIRECTION_CALL_KERB_MINIMUM &&
           call_id <= RDP_AUTH_REDIRECTION_CALL_KERB_MAXIMUM;
}

int rdp_auth_redirection_ntlm_call_id_valid(uint32_t call_id)
{
    return call_id >= RDP_AUTH_REDIRECTION_CALL_NTLM_MINIMUM &&
           call_id <= RDP_AUTH_REDIRECTION_CALL_NTLM_MAXIMUM;
}

int rdp_auth_redirection_negotiate_call_id_valid(uint32_t call_id)
{
    return call_id == RDP_AUTH_REDIRECTION_CALL_KERB_NEGOTIATE_VERSION ||
           call_id == RDP_AUTH_REDIRECTION_CALL_NTLM_NEGOTIATE_VERSION;
}

int rdp_auth_redirection_ecdh_key_bits_valid(uint32_t key_bits)
{
    return key_bits == RDP_AUTH_REDIRECTION_ECDH_KEY_BITS_P256 ||
           key_bits == RDP_AUTH_REDIRECTION_ECDH_KEY_BITS_P384 ||
           key_bits == RDP_AUTH_REDIRECTION_ECDH_KEY_BITS_P521;
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

librdp_status rdp_auth_redirection_parse_response(
    const void* data,
    size_t length,
    rdp_auth_redirection_response* response)
{
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(response, 0, sizeof(*response));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &response->call_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &response->status) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_auth_redirection_call_id_valid(response->call_id))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    response->payload_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &response->payload, response->payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_auth_redirection_write_response(
    rdp_buffer* buffer,
    uint32_t call_id,
    uint32_t status,
    const void* payload,
    size_t payload_len)
{
    librdp_status result = LIBRDP_STATUS_OK;

    if (!buffer || (!payload && payload_len > 0) ||
        !rdp_auth_redirection_call_id_valid(call_id))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    result = rdp_buffer_append_u32_le(buffer, call_id);
    if (result != LIBRDP_STATUS_OK)
        return result;
    result = rdp_buffer_append_u32_le(buffer, status);
    if (result != LIBRDP_STATUS_OK)
        return result;
    return rdp_buffer_append(buffer, payload, payload_len);
}

librdp_status rdp_auth_redirection_parse_negotiate_version_call(
    const void* data,
    size_t length,
    rdp_auth_redirection_negotiate_version* version)
{
    rdp_auth_redirection_call call;
    rdp_stream stream;

    if (!data || !version)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(version, 0, sizeof(*version));
    if (rdp_auth_redirection_parse_call(data, length, &call) != LIBRDP_STATUS_OK ||
        !rdp_auth_redirection_negotiate_call_id_valid(call.call_id) ||
        call.payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, call.payload, call.payload_len);
    if (rdp_stream_read_u32_le(&stream, &version->version) != LIBRDP_STATUS_OK ||
        version->version != RDP_AUTH_REDIRECTION_VERSION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_auth_redirection_write_negotiate_version_call(
    rdp_buffer* buffer,
    uint32_t call_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_auth_redirection_negotiate_call_id_valid(call_id))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, call_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, RDP_AUTH_REDIRECTION_VERSION);
}

librdp_status rdp_auth_redirection_parse_negotiate_version_response(
    const void* data,
    size_t length,
    rdp_auth_redirection_response* response,
    rdp_auth_redirection_negotiate_version* version)
{
    rdp_stream stream;

    if (!data || !response || !version)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(version, 0, sizeof(*version));
    if (rdp_auth_redirection_parse_response(data, length, response) != LIBRDP_STATUS_OK ||
        !rdp_auth_redirection_negotiate_call_id_valid(response->call_id) ||
        response->payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, response->payload, response->payload_len);
    if (rdp_stream_read_u32_le(&stream, &version->version) != LIBRDP_STATUS_OK ||
        version->version != RDP_AUTH_REDIRECTION_VERSION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_auth_redirection_write_negotiate_version_response(
    rdp_buffer* buffer,
    uint32_t call_id,
    uint32_t status)
{
    librdp_status result = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_auth_redirection_negotiate_call_id_valid(call_id))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    result = rdp_buffer_append_u32_le(buffer, call_id);
    if (result != LIBRDP_STATUS_OK)
        return result;
    result = rdp_buffer_append_u32_le(buffer, status);
    if (result != LIBRDP_STATUS_OK)
        return result;
    return rdp_buffer_append_u32_le(buffer, RDP_AUTH_REDIRECTION_VERSION);
}

librdp_status rdp_auth_redirection_parse_ecdh_key_agreement_call(
    const void* data,
    size_t length,
    rdp_auth_redirection_ecdh_key_agreement_call* call)
{
    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    if (rdp_auth_redirection_parse_u32_call(data,
                                            length,
                                            RDP_AUTH_REDIRECTION_CALL_KERB_CREATE_ECDH_KEY_AGREEMENT,
                                            &call->key_bits) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_auth_redirection_ecdh_key_bits_valid(call->key_bits))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_auth_redirection_write_ecdh_key_agreement_call(
    rdp_buffer* buffer,
    uint32_t key_bits)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_auth_redirection_ecdh_key_bits_valid(key_bits))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, key_bits);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_auth_redirection_write_call(buffer,
                                                 RDP_AUTH_REDIRECTION_CALL_KERB_CREATE_ECDH_KEY_AGREEMENT,
                                                 payload.data,
                                                 payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_auth_redirection_parse_dh_key_agreement_call(
    const void* data,
    size_t length,
    rdp_auth_redirection_dh_key_agreement_call* call)
{
    rdp_auth_redirection_call parsed;
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    if (rdp_auth_redirection_parse_call(data, length, &parsed) != LIBRDP_STATUS_OK ||
        parsed.call_id != RDP_AUTH_REDIRECTION_CALL_KERB_CREATE_DH_KEY_AGREEMENT ||
        parsed.payload_len != 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.payload, parsed.payload_len);
    if (rdp_stream_read_u8(&stream, &call->ignored) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_auth_redirection_write_dh_key_agreement_call(
    rdp_buffer* buffer,
    uint8_t ignored)
{
    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_auth_redirection_write_call(buffer,
                                           RDP_AUTH_REDIRECTION_CALL_KERB_CREATE_DH_KEY_AGREEMENT,
                                           &ignored,
                                           1u);
}

librdp_status rdp_auth_redirection_parse_key_agreement_handle_call(
    const void* data,
    size_t length,
    uint32_t expected_call_id,
    rdp_auth_redirection_key_agreement_handle_call* call)
{
    rdp_auth_redirection_call parsed;
    rdp_stream stream;
    uint32_t low = 0;
    uint32_t high = 0;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (expected_call_id != RDP_AUTH_REDIRECTION_CALL_KERB_DESTROY_KEY_AGREEMENT &&
        expected_call_id != RDP_AUTH_REDIRECTION_CALL_KERB_KEY_AGREEMENT_GENERATE_NONCE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    if (rdp_auth_redirection_parse_call(data, length, &parsed) != LIBRDP_STATUS_OK ||
        parsed.call_id != expected_call_id ||
        parsed.payload_len != 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.payload, parsed.payload_len);
    if (rdp_stream_read_u32_le(&stream, &low) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &high) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    call->handle = (int64_t)(((uint64_t)high << 32) | low);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_auth_redirection_write_key_agreement_handle_call(
    rdp_buffer* buffer,
    uint32_t call_id,
    int64_t handle)
{
    rdp_buffer payload;
    uint64_t value = (uint64_t)handle;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer ||
        (call_id != RDP_AUTH_REDIRECTION_CALL_KERB_DESTROY_KEY_AGREEMENT &&
         call_id != RDP_AUTH_REDIRECTION_CALL_KERB_KEY_AGREEMENT_GENERATE_NONCE))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, (uint32_t)(value & 0xffffffffu));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, (uint32_t)(value >> 32));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_auth_redirection_write_call(buffer, call_id, payload.data, payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_auth_redirection_parse_nt_response_response(
    const void* data,
    size_t length,
    rdp_auth_redirection_fixed_response* fixed)
{
    return rdp_auth_redirection_parse_fixed_response(data,
                                                     length,
                                                     RDP_AUTH_REDIRECTION_CALL_NTLM_CALCULATE_NT_RESPONSE,
                                                     RDP_AUTH_REDIRECTION_NT_RESPONSE_LENGTH,
                                                     fixed);
}

librdp_status rdp_auth_redirection_parse_user_session_key_response(
    const void* data,
    size_t length,
    rdp_auth_redirection_fixed_response* fixed)
{
    return rdp_auth_redirection_parse_fixed_response(
        data,
        length,
        RDP_AUTH_REDIRECTION_CALL_NTLM_CALCULATE_USER_SESSION_KEY_NT,
        RDP_AUTH_REDIRECTION_USER_SESSION_KEY_LENGTH,
        fixed);
}

librdp_status rdp_auth_redirection_parse_compare_credentials_response(
    const void* data,
    size_t length,
    rdp_auth_redirection_response* response,
    rdp_auth_redirection_compare_credentials_result* result)
{
    rdp_stream stream;

    if (!data || !response || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));
    if (rdp_auth_redirection_parse_response(data, length, response) != LIBRDP_STATUS_OK ||
        response->call_id != RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS ||
        response->payload_len != 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, response->payload, response->payload_len);
    if (rdp_stream_read_u32_le(&stream, &result->nt_equal) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &result->lm_equal) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &result->sha_equal) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (result->nt_equal > 1u || result->lm_equal > 1u || result->sha_equal > 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_auth_redirection_write_compare_credentials_response(
    rdp_buffer* buffer,
    uint32_t status,
    const rdp_auth_redirection_compare_credentials_result* result)
{
    rdp_buffer payload;
    librdp_status write_status = LIBRDP_STATUS_OK;

    if (!buffer || !result || result->nt_equal > 1u || result->lm_equal > 1u || result->sha_equal > 1u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    write_status = rdp_buffer_append_u32_le(&payload, result->nt_equal);
    if (write_status == LIBRDP_STATUS_OK)
        write_status = rdp_buffer_append_u32_le(&payload, result->lm_equal);
    if (write_status == LIBRDP_STATUS_OK)
        write_status = rdp_buffer_append_u32_le(&payload, result->sha_equal);
    if (write_status == LIBRDP_STATUS_OK)
        write_status = rdp_auth_redirection_write_response(buffer,
                                                           RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS,
                                                           status,
                                                           payload.data,
                                                           payload.length);
    rdp_buffer_free(&payload);
    return write_status;
}
