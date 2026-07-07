#include "nla/credssp.h"

#include "common/stream.h"

#include <ctype.h>
#include <string.h>

#define RDP_NTLM_NEGOTIATE_UNICODE 0x00000001u
#define RDP_NTLM_REQUEST_TARGET 0x00000004u
#define RDP_NTLM_NEGOTIATE_SIGN 0x00000010u
#define RDP_NTLM_NEGOTIATE_SEAL 0x00000020u
#define RDP_NTLM_NEGOTIATE_NTLM 0x00000200u
#define RDP_NTLM_NEGOTIATE_ALWAYS_SIGN 0x00008000u
#define RDP_NTLM_NEGOTIATE_EXTENDED_SESSION 0x00080000u
#define RDP_NTLM_NEGOTIATE_TARGET_INFO 0x00800000u
#define RDP_NTLM_NEGOTIATE_VERSION 0x02000000u
#define RDP_NTLM_NEGOTIATE_128 0x20000000u
#define RDP_NTLM_NEGOTIATE_KEY_EXCH 0x40000000u
#define RDP_NTLM_NEGOTIATE_56 0x80000000u

librdp_status rdp_credssp_begin(bool enabled, rdp_credssp_state* state)
{
    if (!state)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!enabled)
    {
        *state = RDP_CREDSSP_DISABLED;
        return LIBRDP_STATUS_OK;
    }
    *state = RDP_CREDSSP_NEGOTIATING;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_der_write_length(rdp_buffer* buffer, size_t length)
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

static librdp_status rdp_der_wrap(rdp_buffer* output, uint8_t tag, const rdp_buffer* body)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!output || !body)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(output, tag);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_length(output, body->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(output, body->data, body->length);
    return status;
}

static librdp_status rdp_der_write_integer(rdp_buffer* output, uint32_t value)
{
    rdp_buffer body;
    uint8_t bytes[5];
    size_t first = 0;
    size_t length = 4;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&body);
    bytes[0] = (uint8_t)((value >> 24) & 0xffu);
    bytes[1] = (uint8_t)((value >> 16) & 0xffu);
    bytes[2] = (uint8_t)((value >> 8) & 0xffu);
    bytes[3] = (uint8_t)(value & 0xffu);
    while (first < 3u && bytes[first] == 0 && (bytes[first + 1u] & 0x80u) == 0)
        first++;
    if ((bytes[first] & 0x80u) != 0)
    {
        memmove(bytes + 1, bytes + first, 4u - first);
        bytes[0] = 0;
        length = 5u - first;
        first = 0;
    }
    else
    {
        length = 4u - first;
    }
    status = rdp_buffer_append(&body, bytes + first, length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(output, 0x02, &body);
    rdp_buffer_free(&body);
    return status;
}

static librdp_status rdp_der_write_octet_string(rdp_buffer* output, const uint8_t* data, size_t length)
{
    rdp_buffer body;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!output || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&body);
    status = rdp_buffer_append(&body, data, length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(output, 0x04, &body);
    rdp_buffer_free(&body);
    return status;
}

static librdp_status rdp_der_write_context(rdp_buffer* output, uint8_t index, const rdp_buffer* body)
{
    if (index > 30u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_der_wrap(output, (uint8_t)(0xa0u + index), body);
}

static librdp_status rdp_der_write_oid(rdp_buffer* output, const uint8_t* encoded, size_t length)
{
    rdp_buffer body;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!output || !encoded || length == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&body);
    status = rdp_buffer_append(&body, encoded, length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(output, 0x06, &body);
    rdp_buffer_free(&body);
    return status;
}

static size_t rdp_ascii_token_len(const char* text)
{
    return text ? strlen(text) : 0;
}

static librdp_status rdp_append_upper_ascii(rdp_buffer* buffer, const char* text, size_t length)
{
    size_t i = 0;

    if (!buffer || (!text && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < length; i++)
    {
        int ch = (unsigned char)text[i];
        librdp_status status = rdp_buffer_append_u8(buffer, (uint8_t)toupper(ch));
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_ntlm_write_security_buffer(rdp_buffer* buffer, size_t length, size_t offset)
{
    if (!buffer || length > 0xffffu || offset > 0xffffffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u16_le(buffer, (uint16_t)length) == LIBRDP_STATUS_OK &&
                   rdp_buffer_append_u16_le(buffer, (uint16_t)length) == LIBRDP_STATUS_OK &&
                   rdp_buffer_append_u32_le(buffer, (uint32_t)offset) == LIBRDP_STATUS_OK
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_NO_MEMORY;
}

librdp_status rdp_credssp_write_ntlm_negotiate(rdp_buffer* buffer, const char* workstation, const char* domain)
{
    static const uint8_t signature[] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
    const size_t domain_len = rdp_ascii_token_len(domain);
    const size_t workstation_len = rdp_ascii_token_len(workstation);
    const size_t payload_offset = 40u;
    const uint32_t flags = RDP_NTLM_NEGOTIATE_UNICODE | RDP_NTLM_REQUEST_TARGET | RDP_NTLM_NEGOTIATE_SIGN |
                           RDP_NTLM_NEGOTIATE_SEAL | RDP_NTLM_NEGOTIATE_NTLM |
                           RDP_NTLM_NEGOTIATE_ALWAYS_SIGN | RDP_NTLM_NEGOTIATE_EXTENDED_SESSION |
                           RDP_NTLM_NEGOTIATE_TARGET_INFO | RDP_NTLM_NEGOTIATE_VERSION |
                           RDP_NTLM_NEGOTIATE_128 | RDP_NTLM_NEGOTIATE_KEY_EXCH | RDP_NTLM_NEGOTIATE_56;
    static const uint8_t version[] = {10, 0, 0, 0, 0, 0, 0, 15};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || domain_len > 0xffffu || workstation_len > 0xffffu ||
        domain_len + workstation_len > 0xffffffffu - payload_offset)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append(buffer, signature, sizeof(signature));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_ntlm_write_security_buffer(buffer, domain_len, payload_offset);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_ntlm_write_security_buffer(buffer, workstation_len, payload_offset + domain_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, version, sizeof(version));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_append_upper_ascii(buffer, domain, domain_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_append_upper_ascii(buffer, workstation, workstation_len);
    return status;
}

librdp_status rdp_credssp_write_spnego_ntlm_negotiate(rdp_buffer* buffer,
                                                      const uint8_t* ntlm_token,
                                                      size_t ntlm_token_len)
{
    static const uint8_t spnego_oid[] = {0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};
    static const uint8_t ntlm_oid[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a};
    rdp_buffer oid_list;
    rdp_buffer oid_seq;
    rdp_buffer mech_types;
    rdp_buffer mech_token_body;
    rdp_buffer mech_token;
    rdp_buffer init_inner;
    rdp_buffer init_sequence;
    rdp_buffer neg_token_init;
    rdp_buffer application;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!ntlm_token && ntlm_token_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&oid_list);
    rdp_buffer_init(&oid_seq);
    rdp_buffer_init(&mech_types);
    rdp_buffer_init(&mech_token_body);
    rdp_buffer_init(&mech_token);
    rdp_buffer_init(&init_inner);
    rdp_buffer_init(&init_sequence);
    rdp_buffer_init(&neg_token_init);
    rdp_buffer_init(&application);

    status = rdp_der_write_oid(&oid_list, ntlm_oid, sizeof(ntlm_oid));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(&oid_seq, 0x30, &oid_list);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_context(&mech_types, 0, &oid_seq);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_octet_string(&mech_token_body, ntlm_token, ntlm_token_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_context(&mech_token, 2, &mech_token_body);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&init_inner, mech_types.data, mech_types.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&init_inner, mech_token.data, mech_token.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(&init_sequence, 0x30, &init_inner);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_context(&neg_token_init, 0, &init_sequence);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_oid(&application, spnego_oid, sizeof(spnego_oid));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&application, neg_token_init.data, neg_token_init.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(buffer, 0x60, &application);

    rdp_buffer_free(&application);
    rdp_buffer_free(&neg_token_init);
    rdp_buffer_free(&init_sequence);
    rdp_buffer_free(&init_inner);
    rdp_buffer_free(&mech_token);
    rdp_buffer_free(&mech_token_body);
    rdp_buffer_free(&mech_types);
    rdp_buffer_free(&oid_seq);
    rdp_buffer_free(&oid_list);
    return status;
}

librdp_status rdp_credssp_write_ts_request(rdp_buffer* buffer,
                                           uint32_t version,
                                           const uint8_t* nego_token,
                                           size_t nego_token_len,
                                           const uint8_t* auth_info,
                                           size_t auth_info_len,
                                           const uint8_t* pub_key_auth,
                                           size_t pub_key_auth_len)
{
    rdp_buffer body;
    rdp_buffer field;
    rdp_buffer inner;
    rdp_buffer token_sequence;
    rdp_buffer token_list;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || version == 0 || (!nego_token && nego_token_len > 0) || (!auth_info && auth_info_len > 0) ||
        (!pub_key_auth && pub_key_auth_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&body);
    rdp_buffer_init(&field);
    rdp_buffer_init(&inner);
    rdp_buffer_init(&token_sequence);
    rdp_buffer_init(&token_list);

    status = rdp_der_write_integer(&field, version);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_context(&body, 0, &field);

    if (status == LIBRDP_STATUS_OK && nego_token_len > 0)
    {
        rdp_buffer_free(&field);
        rdp_buffer_init(&field);
        status = rdp_der_write_octet_string(&field, nego_token, nego_token_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_der_write_context(&inner, 0, &field);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_der_wrap(&token_sequence, 0x30, &inner);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_der_wrap(&token_list, 0x30, &token_sequence);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_der_write_context(&body, 1, &token_list);
    }

    if (status == LIBRDP_STATUS_OK && auth_info_len > 0)
    {
        rdp_buffer_free(&field);
        rdp_buffer_init(&field);
        status = rdp_der_write_octet_string(&field, auth_info, auth_info_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_der_write_context(&body, 2, &field);
    }

    if (status == LIBRDP_STATUS_OK && pub_key_auth_len > 0)
    {
        rdp_buffer_free(&field);
        rdp_buffer_init(&field);
        status = rdp_der_write_octet_string(&field, pub_key_auth, pub_key_auth_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_der_write_context(&body, 3, &field);
    }

    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(buffer, 0x30, &body);

    rdp_buffer_free(&token_list);
    rdp_buffer_free(&token_sequence);
    rdp_buffer_free(&inner);
    rdp_buffer_free(&field);
    rdp_buffer_free(&body);
    return status;
}

librdp_status rdp_credssp_write_negotiate_request(rdp_buffer* buffer, const char* workstation, const char* domain)
{
    rdp_buffer ntlm;
    rdp_buffer spnego;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&ntlm);
    rdp_buffer_init(&spnego);

    status = rdp_credssp_write_ntlm_negotiate(&ntlm, workstation, domain);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_write_spnego_ntlm_negotiate(&spnego, ntlm.data, ntlm.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_write_ts_request(buffer, 6, spnego.data, spnego.length, NULL, 0, NULL, 0);

    rdp_buffer_free(&spnego);
    rdp_buffer_free(&ntlm);
    return status;
}

static librdp_status rdp_der_read_length(rdp_stream* stream, size_t* length)
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

static librdp_status rdp_der_read_tlv(rdp_stream* stream, uint8_t* tag, const uint8_t** value, size_t* length)
{
    if (!stream || !tag || !value || !length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u8(stream, tag) != LIBRDP_STATUS_OK ||
        rdp_der_read_length(stream, length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (*length > rdp_stream_remaining(stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_stream_read_bytes(stream, value, *length);
}

static librdp_status rdp_der_parse_integer(const uint8_t* data, size_t length, uint32_t* value)
{
    size_t i = 0;
    uint32_t out = 0;

    if (!data || !value || length == 0 || length > 5)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (length == 5 && data[0] != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = (length == 5 ? 1u : 0u); i < length; i++)
        out = (out << 8) | data[i];
    *value = out;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_credssp_parse_nego_tokens(const uint8_t* data,
                                                   size_t length,
                                                   rdp_credssp_ts_request* request)
{
    rdp_stream outer;
    rdp_stream list;
    rdp_stream item;
    rdp_stream context;
    uint8_t tag = 0;
    const uint8_t* value = NULL;
    size_t value_len = 0;

    rdp_stream_init(&outer, data, length);
    if (rdp_der_read_tlv(&outer, &tag, &value, &value_len) != LIBRDP_STATUS_OK || tag != 0x30)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&list, value, value_len);
    if (rdp_der_read_tlv(&list, &tag, &value, &value_len) != LIBRDP_STATUS_OK || tag != 0x30)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&item, value, value_len);
    if (rdp_der_read_tlv(&item, &tag, &value, &value_len) != LIBRDP_STATUS_OK || tag != 0xa0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&context, value, value_len);
    if (rdp_der_read_tlv(&context, &tag, &value, &value_len) != LIBRDP_STATUS_OK || tag != 0x04)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    request->nego_token = value;
    request->nego_token_len = value_len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_credssp_parse_ts_request(const void* data, size_t length, rdp_credssp_ts_request* request)
{
    rdp_stream stream;
    rdp_stream sequence;
    uint8_t tag = 0;
    const uint8_t* value = NULL;
    size_t value_len = 0;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    rdp_stream_init(&stream, data, length);
    if (rdp_der_read_tlv(&stream, &tag, &value, &value_len) != LIBRDP_STATUS_OK || tag != 0x30)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&sequence, value, value_len);
    while (rdp_stream_remaining(&sequence) > 0)
    {
        rdp_stream field;
        uint8_t inner_tag = 0;
        const uint8_t* inner = NULL;
        size_t inner_len = 0;

        if (rdp_der_read_tlv(&sequence, &tag, &value, &value_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        rdp_stream_init(&field, value, value_len);
        if (tag == 0xa0)
        {
            if (rdp_der_read_tlv(&field, &inner_tag, &inner, &inner_len) != LIBRDP_STATUS_OK || inner_tag != 0x02)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (rdp_der_parse_integer(inner, inner_len, &request->version) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (tag == 0xa1)
        {
            if (rdp_credssp_parse_nego_tokens(value, value_len, request) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (tag == 0xa2)
        {
            if (rdp_der_read_tlv(&field, &inner_tag, &request->auth_info, &request->auth_info_len) !=
                    LIBRDP_STATUS_OK ||
                inner_tag != 0x04)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (tag == 0xa3)
        {
            if (rdp_der_read_tlv(&field, &inner_tag, &request->pub_key_auth, &request->pub_key_auth_len) !=
                    LIBRDP_STATUS_OK ||
                inner_tag != 0x04)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (tag == 0xa4)
        {
            if (rdp_der_read_tlv(&field, &inner_tag, &inner, &inner_len) != LIBRDP_STATUS_OK || inner_tag != 0x02)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (rdp_der_parse_integer(inner, inner_len, &request->error_code) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            request->has_error_code = 1;
        }
    }
    return request->version > 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

static uint16_t rdp_read_u16_le_bytes(const uint8_t* data)
{
    return (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
}

static uint32_t rdp_read_u32_le_bytes(const uint8_t* data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static librdp_status rdp_ntlm_read_security_buffer(const uint8_t* base,
                                                   size_t length,
                                                   size_t offset,
                                                   const uint8_t** value,
                                                   size_t* value_len)
{
    uint16_t len = 0;
    uint16_t max_len = 0;
    uint32_t data_offset = 0;

    if (!base || !value || !value_len || offset > length || length - offset < 8)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    len = rdp_read_u16_le_bytes(base + offset);
    max_len = rdp_read_u16_le_bytes(base + offset + 2u);
    data_offset = rdp_read_u32_le_bytes(base + offset + 4u);
    if (len > max_len || data_offset > length || (size_t)len > length - data_offset)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = base + data_offset;
    *value_len = len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_credssp_extract_ntlm_challenge(const void* token,
                                                 size_t token_len,
                                                 const uint8_t** ntlm,
                                                 size_t* ntlm_len)
{
    static const uint8_t signature[] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
    const uint8_t* bytes = (const uint8_t*)token;
    size_t i = 0;

    if (!token || !ntlm || !ntlm_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (token_len < sizeof(signature) + 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i <= token_len - sizeof(signature) - 4u; i++)
    {
        if (memcmp(bytes + i, signature, sizeof(signature)) == 0 &&
            rdp_read_u32_le_bytes(bytes + i + sizeof(signature)) == 2u)
        {
            *ntlm = bytes + i;
            *ntlm_len = token_len - i;
            return LIBRDP_STATUS_OK;
        }
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_credssp_parse_ntlm_challenge(const void* data,
                                               size_t length,
                                               rdp_ntlm_challenge* challenge)
{
    static const uint8_t signature[] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
    const uint8_t* bytes = (const uint8_t*)data;

    if (!data || !challenge)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 48 || memcmp(bytes, signature, sizeof(signature)) != 0 ||
        rdp_read_u32_le_bytes(bytes + 8) != 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(challenge, 0, sizeof(*challenge));
    if (rdp_ntlm_read_security_buffer(bytes, length, 12, &challenge->target_name, &challenge->target_name_len) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    challenge->flags = rdp_read_u32_le_bytes(bytes + 20);
    memcpy(challenge->server_challenge, bytes + 24, sizeof(challenge->server_challenge));
    if (rdp_ntlm_read_security_buffer(bytes, length, 40, &challenge->target_info, &challenge->target_info_len) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}
