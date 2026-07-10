#include "channels/auth_redirection.h"

#include "common/stream.h"

#include <string.h>

static const uint8_t rdp_auth_redirection_kerberos_name[] = {
    'K', 0, 'e', 0, 'r', 0, 'b', 0, 'e', 0, 'r', 0, 'o', 0, 's', 0
};
static const uint8_t rdp_auth_redirection_ntlm_name[] = {'N', 0, 'T', 0, 'L', 0, 'M', 0};

static librdp_status rdp_auth_redirection_read_der_length(const uint8_t* data,
                                                          size_t length,
                                                          size_t* offset,
                                                          size_t* value)
{
    uint8_t first = 0;
    size_t count = 0;
    size_t result = 0;
    size_t i = 0;

    if (!data || !offset || !value || *offset >= length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    first = data[*offset];
    *offset += 1u;
    if ((first & 0x80u) == 0)
    {
        *value = first;
        return LIBRDP_STATUS_OK;
    }
    count = first & 0x7fu;
    if (count == 0 || count > sizeof(size_t) || count > length - *offset)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (count > 1u && data[*offset] == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < count; i++)
    {
        if (result > (((size_t)-1) >> 8))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        result = (result << 8) | data[*offset + i];
    }
    if (result < 0x80u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *offset += count;
    *value = result;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_auth_redirection_write_der_length(rdp_buffer* buffer, size_t length)
{
    uint8_t bytes[sizeof(size_t)];
    size_t count = 0;
    size_t value = length;
    size_t i = 0;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 0x80u)
        return rdp_buffer_append_u8(buffer, (uint8_t)length);
    while (value > 0)
    {
        bytes[sizeof(bytes) - 1u - count] = (uint8_t)(value & 0xffu);
        value >>= 8;
        count++;
    }
    if (count > 0x7fu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_buffer_append_u8(buffer, (uint8_t)(0x80u | count)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_NO_MEMORY;
    for (i = sizeof(bytes) - count; i < sizeof(bytes); i++)
    {
        librdp_status status = rdp_buffer_append_u8(buffer, bytes[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static uint32_t rdp_auth_redirection_package_from_name(const uint8_t* data, size_t length)
{
    if (data && length == sizeof(rdp_auth_redirection_kerberos_name) &&
        memcmp(data, rdp_auth_redirection_kerberos_name, length) == 0)
        return RDP_AUTH_REDIRECTION_PACKAGE_KERBEROS;
    if (data && length == sizeof(rdp_auth_redirection_ntlm_name) &&
        memcmp(data, rdp_auth_redirection_ntlm_name, length) == 0)
        return RDP_AUTH_REDIRECTION_PACKAGE_NTLM;
    return RDP_AUTH_REDIRECTION_PACKAGE_UNKNOWN;
}

static librdp_status rdp_auth_redirection_package_name(uint32_t package,
                                                       const uint8_t** data,
                                                       size_t* length)
{
    if (!data || !length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (package == RDP_AUTH_REDIRECTION_PACKAGE_KERBEROS)
    {
        *data = rdp_auth_redirection_kerberos_name;
        *length = sizeof(rdp_auth_redirection_kerberos_name);
        return LIBRDP_STATUS_OK;
    }
    if (package == RDP_AUTH_REDIRECTION_PACKAGE_NTLM)
    {
        *data = rdp_auth_redirection_ntlm_name;
        *length = sizeof(rdp_auth_redirection_ntlm_name);
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_INVALID_ARGUMENT;
}

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
    if (rdp_auth_redirection_kerb_call_id_valid(call_id))
        return 1;
    if (rdp_auth_redirection_ntlm_call_id_valid(call_id))
        return 1;
    return call_id == RDP_AUTH_REDIRECTION_CALL_INVALID;
}

static int rdp_auth_redirection_call_id_writable(uint32_t call_id)
{
    return call_id != RDP_AUTH_REDIRECTION_CALL_INVALID &&
           rdp_auth_redirection_call_id_valid(call_id);
}

int rdp_auth_redirection_kerb_call_id_valid(uint32_t call_id)
{
    switch (call_id)
    {
        case RDP_AUTH_REDIRECTION_CALL_KERB_NEGOTIATE_VERSION:
        case RDP_AUTH_REDIRECTION_CALL_KERB_BUILD_AS_REQ_AUTHENTICATOR:
        case RDP_AUTH_REDIRECTION_CALL_KERB_VERIFY_SERVICE_TICKET:
        case RDP_AUTH_REDIRECTION_CALL_KERB_CREATE_AP_REQ_AUTHENTICATOR:
        case RDP_AUTH_REDIRECTION_CALL_KERB_DECRYPT_AP_REPLY:
        case RDP_AUTH_REDIRECTION_CALL_KERB_UNPACK_KDC_REPLY_BODY:
        case RDP_AUTH_REDIRECTION_CALL_KERB_COMPUTE_TGS_CHECKSUM:
        case RDP_AUTH_REDIRECTION_CALL_KERB_BUILD_ENCRYPTED_AUTH_DATA:
        case RDP_AUTH_REDIRECTION_CALL_KERB_PACK_AP_REPLY:
        case RDP_AUTH_REDIRECTION_CALL_KERB_HASH_S4U_PREAUTH:
        case RDP_AUTH_REDIRECTION_CALL_KERB_SIGN_S4U_PREAUTH_DATA:
        case RDP_AUTH_REDIRECTION_CALL_KERB_VERIFY_CHECKSUM:
        case RDP_AUTH_REDIRECTION_CALL_KERB_DECRYPT_PAC_CREDENTIALS:
        case RDP_AUTH_REDIRECTION_CALL_KERB_CREATE_ECDH_KEY_AGREEMENT:
        case RDP_AUTH_REDIRECTION_CALL_KERB_CREATE_DH_KEY_AGREEMENT:
        case RDP_AUTH_REDIRECTION_CALL_KERB_DESTROY_KEY_AGREEMENT:
        case RDP_AUTH_REDIRECTION_CALL_KERB_KEY_AGREEMENT_GENERATE_NONCE:
        case RDP_AUTH_REDIRECTION_CALL_KERB_FINALIZE_KEY_AGREEMENT:
            return 1;
        default:
            return 0;
    }
}

int rdp_auth_redirection_ntlm_call_id_valid(uint32_t call_id)
{
    switch (call_id)
    {
        case RDP_AUTH_REDIRECTION_CALL_NTLM_NEGOTIATE_VERSION:
        case RDP_AUTH_REDIRECTION_CALL_NTLM_LM20_GET_NTLM3_CHALLENGE_RESPONSE:
        case RDP_AUTH_REDIRECTION_CALL_NTLM_CALCULATE_NT_RESPONSE:
        case RDP_AUTH_REDIRECTION_CALL_NTLM_CALCULATE_USER_SESSION_KEY_NT:
        case RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS:
            return 1;
        default:
            return 0;
    }
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

int rdp_auth_redirection_asn1_pdu_valid(uint32_t pdu)
{
    return pdu == RDP_AUTH_REDIRECTION_ASN1_PDU_IGNORED ||
           pdu == RDP_AUTH_REDIRECTION_ASN1_PDU_COMPAT_AS_REP ||
           pdu == RDP_AUTH_REDIRECTION_ASN1_PDU_AS_REP ||
           pdu == RDP_AUTH_REDIRECTION_ASN1_PDU_TGS_REP;
}

librdp_status rdp_auth_redirection_parse_octet_string(
    const void* data,
    size_t length,
    rdp_auth_redirection_octet_string* string)
{
    rdp_stream stream;

    if (!data || !string)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(string, 0, sizeof(*string));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &string->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (string->length > RDP_AUTH_REDIRECTION_BLOB_MAX_LENGTH ||
        string->length != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &string->value, string->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_auth_redirection_write_octet_string(
    rdp_buffer* buffer,
    const void* value,
    uint32_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!value && length > 0) || length > RDP_AUTH_REDIRECTION_BLOB_MAX_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, value, length);
}

librdp_status rdp_auth_redirection_parse_octet_response(
    const void* data,
    size_t length,
    uint32_t expected_call_id,
    rdp_auth_redirection_response* response,
    rdp_auth_redirection_octet_string* string)
{
    if (!data || !response || !string)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_auth_redirection_call_id_valid(expected_call_id))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_auth_redirection_parse_response(data, length, response) != LIBRDP_STATUS_OK ||
        response->call_id != expected_call_id)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_auth_redirection_parse_octet_string(response->payload,
                                                   response->payload_len,
                                                   string);
}

librdp_status rdp_auth_redirection_write_octet_response(
    rdp_buffer* buffer,
    uint32_t call_id,
    uint32_t status,
    const void* value,
    uint32_t length)
{
    rdp_buffer payload;
    librdp_status result = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_auth_redirection_call_id_writable(call_id))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    result = rdp_auth_redirection_write_octet_string(&payload, value, length);
    if (result == LIBRDP_STATUS_OK)
        result = rdp_auth_redirection_write_response(buffer,
                                                     call_id,
                                                     status,
                                                     payload.data,
                                                     payload.length);
    rdp_buffer_free(&payload);
    return result;
}

librdp_status rdp_auth_redirection_parse_asn1_data(
    const void* data,
    size_t length,
    rdp_auth_redirection_asn1_data* asn1)
{
    rdp_stream stream;

    if (!data || !asn1)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(asn1, 0, sizeof(*asn1));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &asn1->pdu) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &asn1->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_auth_redirection_asn1_pdu_valid(asn1->pdu) ||
        asn1->length > RDP_AUTH_REDIRECTION_BLOB_MAX_LENGTH ||
        asn1->length != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &asn1->value, asn1->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_auth_redirection_write_asn1_data(
    rdp_buffer* buffer,
    uint32_t pdu,
    const void* value,
    uint32_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!value && length > 0) ||
        !rdp_auth_redirection_asn1_pdu_valid(pdu) ||
        length > RDP_AUTH_REDIRECTION_BLOB_MAX_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, pdu);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, value, length);
}

librdp_status rdp_auth_redirection_parse_asn1_response(
    const void* data,
    size_t length,
    uint32_t expected_call_id,
    rdp_auth_redirection_response* response,
    rdp_auth_redirection_asn1_data* asn1)
{
    if (!data || !response || !asn1)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_auth_redirection_call_id_valid(expected_call_id))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_auth_redirection_parse_response(data, length, response) != LIBRDP_STATUS_OK ||
        response->call_id != expected_call_id)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_auth_redirection_parse_asn1_data(response->payload,
                                                response->payload_len,
                                                asn1);
}

librdp_status rdp_auth_redirection_write_asn1_response(
    rdp_buffer* buffer,
    uint32_t call_id,
    uint32_t status,
    uint32_t pdu,
    const void* value,
    uint32_t length)
{
    rdp_buffer payload;
    librdp_status result = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_auth_redirection_call_id_writable(call_id))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    result = rdp_auth_redirection_write_asn1_data(&payload, pdu, value, length);
    if (result == LIBRDP_STATUS_OK)
        result = rdp_auth_redirection_write_response(buffer,
                                                     call_id,
                                                     status,
                                                     payload.data,
                                                     payload.length);
    rdp_buffer_free(&payload);
    return result;
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
        packet->length != length - RDP_AUTH_REDIRECTION_OUTER_HEADER_LENGTH ||
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
    length = (uint32_t)payload_len;
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

librdp_status rdp_auth_redirection_parse_encoded_payload(
    const void* data,
    size_t length,
    rdp_auth_redirection_encoded_payload* payload)
{
    const uint8_t* bytes = (const uint8_t*)data;
    size_t offset = 0;
    size_t sequence_len = 0;
    size_t sequence_end = 0;
    size_t field_len = 0;

    if (!data || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(payload, 0, sizeof(*payload));
    if (length < 2u || bytes[offset++] != 0x30u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_auth_redirection_read_der_length(bytes, length, &offset, &sequence_len) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (sequence_len > length - offset)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    sequence_end = offset + sequence_len;
    if (offset >= sequence_end || bytes[offset++] != 0x81u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_auth_redirection_read_der_length(bytes, sequence_end, &offset, &field_len) !=
        LIBRDP_STATUS_OK ||
        field_len > sequence_end - offset)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    payload->package_name = bytes + offset;
    payload->package_name_len = field_len;
    payload->package = rdp_auth_redirection_package_from_name(payload->package_name, payload->package_name_len);
    offset += field_len;
    if (offset >= sequence_end || bytes[offset++] != 0x82u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_auth_redirection_read_der_length(bytes, sequence_end, &offset, &field_len) !=
        LIBRDP_STATUS_OK ||
        field_len > sequence_end - offset)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    payload->payload = bytes + offset;
    payload->payload_len = field_len;
    offset += field_len;
    if (offset != sequence_end || sequence_end != length || payload->package == RDP_AUTH_REDIRECTION_PACKAGE_UNKNOWN)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_auth_redirection_write_encoded_payload(
    rdp_buffer* buffer,
    uint32_t package,
    const void* payload,
    size_t payload_len)
{
    rdp_buffer body;
    const uint8_t* package_name = NULL;
    size_t package_name_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!payload && payload_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_auth_redirection_package_name(package, &package_name, &package_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&body);
    status = rdp_buffer_append_u8(&body, 0x81u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_auth_redirection_write_der_length(&body, package_name_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&body, package_name, package_name_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&body, 0x82u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_auth_redirection_write_der_length(&body, payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&body, payload, payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0x30u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_auth_redirection_write_der_length(buffer, body.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, body.data, body.length);
    rdp_buffer_free(&body);
    return status;
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
        !rdp_auth_redirection_call_id_writable(call_id))
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
        !rdp_auth_redirection_call_id_writable(call_id))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    result = rdp_buffer_append_u32_le(buffer, call_id);
    if (result != LIBRDP_STATUS_OK)
        return result;
    result = rdp_buffer_append_u32_le(buffer, status);
    if (result != LIBRDP_STATUS_OK)
        return result;
    return rdp_buffer_append(buffer, payload, payload_len);
}

librdp_status rdp_auth_redirection_parse_call_message(
    const void* data,
    size_t length,
    rdp_auth_redirection_call_message* message)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !message)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(message, 0, sizeof(*message));
    status = rdp_auth_redirection_parse_call(data, length, &message->call);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (message->call.payload_len > RDP_AUTH_REDIRECTION_BLOB_MAX_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    message->kind = RDP_AUTH_REDIRECTION_MESSAGE_RAW;
    switch (message->call.call_id)
    {
        case RDP_AUTH_REDIRECTION_CALL_KERB_NEGOTIATE_VERSION:
        case RDP_AUTH_REDIRECTION_CALL_NTLM_NEGOTIATE_VERSION:
            status = rdp_auth_redirection_parse_negotiate_version_call(
                data,
                length,
                &message->body.negotiate_version);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_AUTH_REDIRECTION_MESSAGE_NEGOTIATE_VERSION;
            return status;
        case RDP_AUTH_REDIRECTION_CALL_KERB_CREATE_ECDH_KEY_AGREEMENT:
            status = rdp_auth_redirection_parse_ecdh_key_agreement_call(data,
                                                                        length,
                                                                        &message->body.ecdh);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_AUTH_REDIRECTION_MESSAGE_ECDH_KEY_AGREEMENT;
            return status;
        case RDP_AUTH_REDIRECTION_CALL_KERB_CREATE_DH_KEY_AGREEMENT:
            status = rdp_auth_redirection_parse_dh_key_agreement_call(data,
                                                                      length,
                                                                      &message->body.dh);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_AUTH_REDIRECTION_MESSAGE_DH_KEY_AGREEMENT;
            return status;
        case RDP_AUTH_REDIRECTION_CALL_KERB_DESTROY_KEY_AGREEMENT:
        case RDP_AUTH_REDIRECTION_CALL_KERB_KEY_AGREEMENT_GENERATE_NONCE:
            status = rdp_auth_redirection_parse_key_agreement_handle_call(
                data,
                length,
                message->call.call_id,
                &message->body.key_handle);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_AUTH_REDIRECTION_MESSAGE_KEY_AGREEMENT_HANDLE;
            return status;
        case RDP_AUTH_REDIRECTION_CALL_KERB_FINALIZE_KEY_AGREEMENT:
            status = rdp_auth_redirection_parse_finalize_key_agreement_call(
                data,
                length,
                &message->body.finalize_key_agreement);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_AUTH_REDIRECTION_MESSAGE_FINALIZE_KEY_AGREEMENT;
            return status;
        default:
            return LIBRDP_STATUS_OK;
    }
}

librdp_status rdp_auth_redirection_parse_response_message(
    const void* data,
    size_t length,
    rdp_auth_redirection_response_message* message)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !message)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(message, 0, sizeof(*message));
    status = rdp_auth_redirection_parse_response(data, length, &message->response);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (message->response.payload_len > RDP_AUTH_REDIRECTION_BLOB_MAX_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    message->kind = RDP_AUTH_REDIRECTION_MESSAGE_RAW;
    switch (message->response.call_id)
    {
        case RDP_AUTH_REDIRECTION_CALL_KERB_NEGOTIATE_VERSION:
        case RDP_AUTH_REDIRECTION_CALL_NTLM_NEGOTIATE_VERSION:
            status = rdp_auth_redirection_parse_negotiate_version_response(
                data,
                length,
                &message->response,
                &message->body.negotiate_version);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_AUTH_REDIRECTION_MESSAGE_NEGOTIATE_VERSION;
            return status;
        case RDP_AUTH_REDIRECTION_CALL_NTLM_CALCULATE_NT_RESPONSE:
            status = rdp_auth_redirection_parse_nt_response_response(data,
                                                                     length,
                                                                     &message->body.fixed);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_AUTH_REDIRECTION_MESSAGE_FIXED_RESPONSE;
            return status;
        case RDP_AUTH_REDIRECTION_CALL_NTLM_CALCULATE_USER_SESSION_KEY_NT:
            status = rdp_auth_redirection_parse_user_session_key_response(
                data,
                length,
                &message->body.fixed);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_AUTH_REDIRECTION_MESSAGE_FIXED_RESPONSE;
            return status;
        case RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS:
            status = rdp_auth_redirection_parse_compare_credentials_response(
                data,
                length,
                &message->response,
                &message->body.compare_credentials);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_AUTH_REDIRECTION_MESSAGE_COMPARE_CREDENTIALS;
            return status;
        case RDP_AUTH_REDIRECTION_CALL_KERB_DECRYPT_AP_REPLY:
        case RDP_AUTH_REDIRECTION_CALL_KERB_COMPUTE_TGS_CHECKSUM:
        case RDP_AUTH_REDIRECTION_CALL_KERB_BUILD_ENCRYPTED_AUTH_DATA:
            status = rdp_auth_redirection_parse_asn1_response(data,
                                                              length,
                                                              message->response.call_id,
                                                              &message->response,
                                                              &message->body.asn1);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_AUTH_REDIRECTION_MESSAGE_ASN1_RESPONSE;
            return status;
        case RDP_AUTH_REDIRECTION_CALL_KERB_PACK_AP_REPLY:
        case RDP_AUTH_REDIRECTION_CALL_KERB_KEY_AGREEMENT_GENERATE_NONCE:
            status = rdp_auth_redirection_parse_octet_response(data,
                                                               length,
                                                               message->response.call_id,
                                                               &message->response,
                                                               &message->body.octet);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_AUTH_REDIRECTION_MESSAGE_OCTET_RESPONSE;
            return status;
        default:
            return LIBRDP_STATUS_OK;
    }
}

librdp_status rdp_auth_redirection_write_default_response(
    rdp_buffer* buffer,
    const rdp_auth_redirection_call_message* call,
    uint32_t status)
{
    rdp_auth_redirection_compare_credentials_result compare;
    uint8_t fixed[RDP_AUTH_REDIRECTION_NT_RESPONSE_LENGTH];

    if (!buffer || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (call->call.call_id)
    {
        case RDP_AUTH_REDIRECTION_CALL_KERB_NEGOTIATE_VERSION:
        case RDP_AUTH_REDIRECTION_CALL_NTLM_NEGOTIATE_VERSION:
            return rdp_auth_redirection_write_negotiate_version_response(buffer,
                                                                         call->call.call_id,
                                                                         status);
        case RDP_AUTH_REDIRECTION_CALL_NTLM_CALCULATE_NT_RESPONSE:
            memset(fixed, 0, RDP_AUTH_REDIRECTION_NT_RESPONSE_LENGTH);
            return rdp_auth_redirection_write_response(buffer,
                                                       call->call.call_id,
                                                       status,
                                                       fixed,
                                                       RDP_AUTH_REDIRECTION_NT_RESPONSE_LENGTH);
        case RDP_AUTH_REDIRECTION_CALL_NTLM_CALCULATE_USER_SESSION_KEY_NT:
            memset(fixed, 0, RDP_AUTH_REDIRECTION_USER_SESSION_KEY_LENGTH);
            return rdp_auth_redirection_write_response(buffer,
                                                       call->call.call_id,
                                                       status,
                                                       fixed,
                                                       RDP_AUTH_REDIRECTION_USER_SESSION_KEY_LENGTH);
        case RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS:
            memset(&compare, 0, sizeof(compare));
            return rdp_auth_redirection_write_compare_credentials_response(buffer,
                                                                          status,
                                                                          &compare);
        case RDP_AUTH_REDIRECTION_CALL_KERB_DECRYPT_AP_REPLY:
        case RDP_AUTH_REDIRECTION_CALL_KERB_COMPUTE_TGS_CHECKSUM:
        case RDP_AUTH_REDIRECTION_CALL_KERB_BUILD_ENCRYPTED_AUTH_DATA:
            return rdp_auth_redirection_write_asn1_response(buffer,
                                                            call->call.call_id,
                                                            status,
                                                            RDP_AUTH_REDIRECTION_ASN1_PDU_IGNORED,
                                                            NULL,
                                                            0);
        case RDP_AUTH_REDIRECTION_CALL_KERB_PACK_AP_REPLY:
        case RDP_AUTH_REDIRECTION_CALL_KERB_KEY_AGREEMENT_GENERATE_NONCE:
            return rdp_auth_redirection_write_octet_response(buffer,
                                                             call->call.call_id,
                                                             status,
                                                             NULL,
                                                             0);
        default:
            return rdp_auth_redirection_write_response(buffer,
                                                       call->call.call_id,
                                                       status,
                                                       NULL,
                                                       0);
    }
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

librdp_status rdp_auth_redirection_parse_finalize_key_agreement_call(
    const void* data,
    size_t length,
    rdp_auth_redirection_finalize_key_agreement_call* call)
{
    rdp_auth_redirection_call parsed;
    rdp_stream stream;
    uint32_t low = 0;
    uint32_t high = 0;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    if (rdp_auth_redirection_parse_call(data, length, &parsed) != LIBRDP_STATUS_OK ||
        parsed.call_id != RDP_AUTH_REDIRECTION_CALL_KERB_FINALIZE_KEY_AGREEMENT ||
        parsed.payload_len < 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.payload, parsed.payload_len);
    if (rdp_stream_read_u32_le(&stream, &low) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &high) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->kerb_etype) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->remote_nonce_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    call->handle = (int64_t)(((uint64_t)high << 32) | low);
    if (call->remote_nonce_len > RDP_AUTH_REDIRECTION_BLOB_MAX_LENGTH ||
        call->remote_nonce_len > rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &call->remote_nonce, call->remote_nonce_len) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u32_le(&stream, &call->x509_public_key_len) != LIBRDP_STATUS_OK ||
        call->x509_public_key_len > RDP_AUTH_REDIRECTION_BLOB_MAX_LENGTH ||
        call->x509_public_key_len != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &call->x509_public_key, call->x509_public_key_len) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_auth_redirection_write_finalize_key_agreement_call(
    rdp_buffer* buffer,
    int64_t handle,
    uint32_t kerb_etype,
    const void* remote_nonce,
    uint32_t remote_nonce_len,
    const void* x509_public_key,
    uint32_t x509_public_key_len)
{
    rdp_buffer payload;
    uint64_t value = (uint64_t)handle;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer ||
        (!remote_nonce && remote_nonce_len > 0) ||
        (!x509_public_key && x509_public_key_len > 0) ||
        remote_nonce_len > RDP_AUTH_REDIRECTION_BLOB_MAX_LENGTH ||
        x509_public_key_len > RDP_AUTH_REDIRECTION_BLOB_MAX_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, (uint32_t)(value & 0xffffffffu));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, (uint32_t)(value >> 32));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, kerb_etype);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, remote_nonce_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&payload, remote_nonce, remote_nonce_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, x509_public_key_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&payload, x509_public_key, x509_public_key_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_auth_redirection_write_call(buffer,
                                                 RDP_AUTH_REDIRECTION_CALL_KERB_FINALIZE_KEY_AGREEMENT,
                                                 payload.data,
                                                 payload.length);
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
