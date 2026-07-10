#include "licensing/licensing.h"

#include "common/stream.h"

#include <limits.h>
#include <string.h>

static int rdp_license_valid_message_type(uint8_t message_type)
{
    return message_type == RDP_LICENSE_MESSAGE_REQUEST ||
           message_type == RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE ||
           message_type == RDP_LICENSE_MESSAGE_NEW_LICENSE ||
           message_type == RDP_LICENSE_MESSAGE_UPGRADE_LICENSE ||
           message_type == RDP_LICENSE_MESSAGE_INFO ||
           message_type == RDP_LICENSE_MESSAGE_NEW_LICENSE_REQUEST ||
           message_type == RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE_RESPONSE ||
           message_type == RDP_LICENSE_MESSAGE_ERROR_ALERT;
}

static int rdp_license_valid_version(uint8_t version)
{
    uint8_t base = (uint8_t)(version & 0x0fu);

    return base == RDP_LICENSE_VERSION_2 || base == RDP_LICENSE_VERSION_3;
}

static int rdp_license_valid_blob_type(uint16_t type)
{
    return type == RDP_LICENSE_BLOB_DATA ||
           type == RDP_LICENSE_BLOB_RANDOM ||
           type == RDP_LICENSE_BLOB_CERTIFICATE ||
           type == RDP_LICENSE_BLOB_ERROR ||
           type == RDP_LICENSE_BLOB_ENCRYPTED_DATA ||
           type == RDP_LICENSE_BLOB_KEY_EXCHANGE_ALG ||
           type == RDP_LICENSE_BLOB_SCOPE ||
           type == RDP_LICENSE_BLOB_CLIENT_USER_NAME ||
           type == RDP_LICENSE_BLOB_CLIENT_MACHINE_NAME;
}

static librdp_status rdp_license_read_blob(rdp_stream* stream, rdp_license_binary_blob* blob)
{
    if (!stream || !blob)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(blob, 0, sizeof(*blob));
    if (rdp_stream_read_u16_le(stream, &blob->type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &blob->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_license_valid_blob_type(blob->type) ||
        blob->length > rdp_stream_remaining(stream) ||
        rdp_stream_read_bytes(stream, &blob->data, blob->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_license_read_sized_blob(rdp_stream* stream, uint32_t* length, const uint8_t** data)
{
    if (!stream || !length || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *length = 0;
    *data = NULL;
    if (rdp_stream_read_u32_le(stream, length) != LIBRDP_STATUS_OK ||
        *length > rdp_stream_remaining(stream) ||
        rdp_stream_read_bytes(stream, data, *length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_license_parse_product_info_stream(rdp_stream* stream,
                                                           rdp_license_product_info* product)
{
    if (!stream || !product)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(product, 0, sizeof(*product));
    if (rdp_stream_read_u32_le(stream, &product->version) != LIBRDP_STATUS_OK ||
        rdp_license_read_sized_blob(stream,
                                    &product->company_name_len,
                                    &product->company_name) != LIBRDP_STATUS_OK ||
        rdp_license_read_sized_blob(stream,
                                    &product->product_id_len,
                                    &product->product_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (product->company_name_len == 0 || product->product_id_len == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_license_write_blob_checked(rdp_buffer* buffer,
                                                    const rdp_license_binary_blob* blob,
                                                    uint16_t expected_type)
{
    if (!blob || blob->type != expected_type)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_license_write_binary_blob(buffer, blob->type, blob->data, blob->length);
}

static int rdp_license_range_valid(size_t length, size_t offset, size_t range_len)
{
    return offset <= length && range_len <= length - offset;
}

static int rdp_license_utf16z_valid(const uint8_t* data, size_t length)
{
    if (!data || length < 2u || (length % 2u) != 0)
        return 0;
    return data[length - 2u] == 0 && data[length - 1u] == 0;
}

static librdp_status rdp_license_append_version_info(rdp_buffer* buffer,
                                                     const rdp_license_version_info* info)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, info->major_version);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, info->minor_version);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, info->flags);
}

void rdp_license_client_state_init(rdp_license_client_state* state)
{
    if (!state)
        return;
    memset(state, 0, sizeof(*state));
    state->state = RDP_LICENSE_CLIENT_STATE_INITIAL;
}

static int rdp_license_message_from_server(uint8_t message_type)
{
    return message_type == RDP_LICENSE_MESSAGE_REQUEST ||
           message_type == RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE ||
           message_type == RDP_LICENSE_MESSAGE_NEW_LICENSE ||
           message_type == RDP_LICENSE_MESSAGE_UPGRADE_LICENSE ||
           message_type == RDP_LICENSE_MESSAGE_ERROR_ALERT;
}

static int rdp_license_message_from_client(uint8_t message_type)
{
    return message_type == RDP_LICENSE_MESSAGE_NEW_LICENSE_REQUEST ||
           message_type == RDP_LICENSE_MESSAGE_INFO ||
           message_type == RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE_RESPONSE;
}

librdp_status rdp_license_classify_message(const void* data, size_t length, uint8_t* message_type)
{
    rdp_license_preamble preamble;

    if (!message_type)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_license_parse_preamble(data, length, &preamble) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *message_type = preamble.message_type;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_client_state_step(rdp_license_client_state* state,
                                            rdp_license_direction direction,
                                            uint8_t message_type)
{
    rdp_license_client_state_id next_state = RDP_LICENSE_CLIENT_STATE_FAILED;

    if (!state || !rdp_license_valid_message_type(message_type) ||
        (direction != RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT &&
         direction != RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((direction == RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT &&
         !rdp_license_message_from_server(message_type)) ||
        (direction == RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER &&
         !rdp_license_message_from_client(message_type)))
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (direction == RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT &&
        message_type == RDP_LICENSE_MESSAGE_ERROR_ALERT)
        next_state = RDP_LICENSE_CLIENT_STATE_FAILED;
    else if (state->state == RDP_LICENSE_CLIENT_STATE_INITIAL &&
             direction == RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT &&
             message_type == RDP_LICENSE_MESSAGE_REQUEST)
        next_state = RDP_LICENSE_CLIENT_STATE_SERVER_REQUEST_RECEIVED;
    else if (state->state == RDP_LICENSE_CLIENT_STATE_INITIAL &&
             direction == RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT &&
             message_type == RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE)
        next_state = RDP_LICENSE_CLIENT_STATE_PLATFORM_CHALLENGE_RECEIVED;
    else if (state->state == RDP_LICENSE_CLIENT_STATE_SERVER_REQUEST_RECEIVED &&
             direction == RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER &&
             message_type == RDP_LICENSE_MESSAGE_NEW_LICENSE_REQUEST)
        next_state = RDP_LICENSE_CLIENT_STATE_CLIENT_REQUEST_SENT;
    else if (state->state == RDP_LICENSE_CLIENT_STATE_SERVER_REQUEST_RECEIVED &&
             direction == RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER &&
             message_type == RDP_LICENSE_MESSAGE_INFO)
        next_state = RDP_LICENSE_CLIENT_STATE_CLIENT_INFO_SENT;
    else if ((state->state == RDP_LICENSE_CLIENT_STATE_CLIENT_REQUEST_SENT ||
              state->state == RDP_LICENSE_CLIENT_STATE_CLIENT_INFO_SENT) &&
             direction == RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT &&
             message_type == RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE)
        next_state = RDP_LICENSE_CLIENT_STATE_PLATFORM_CHALLENGE_RECEIVED;
    else if (state->state == RDP_LICENSE_CLIENT_STATE_PLATFORM_CHALLENGE_RECEIVED &&
             direction == RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER &&
             message_type == RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE_RESPONSE)
        next_state = RDP_LICENSE_CLIENT_STATE_PLATFORM_CHALLENGE_RESPONSE_SENT;
    else if ((state->state == RDP_LICENSE_CLIENT_STATE_CLIENT_REQUEST_SENT ||
              state->state == RDP_LICENSE_CLIENT_STATE_CLIENT_INFO_SENT ||
              state->state == RDP_LICENSE_CLIENT_STATE_PLATFORM_CHALLENGE_RESPONSE_SENT) &&
             direction == RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT &&
             (message_type == RDP_LICENSE_MESSAGE_NEW_LICENSE ||
              message_type == RDP_LICENSE_MESSAGE_UPGRADE_LICENSE))
        next_state = RDP_LICENSE_CLIENT_STATE_COMPLETED;
    else
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    state->state = next_state;
    state->last_message_type = message_type;
    state->last_direction = (uint8_t)direction;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_parse_preamble(const void* data, size_t length, rdp_license_preamble* preamble)
{
    rdp_stream stream;

    if (!data || !preamble)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u || length > UINT16_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(preamble, 0, sizeof(*preamble));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &preamble->message_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &preamble->version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &preamble->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_license_valid_message_type(preamble->message_type) ||
        !rdp_license_valid_version(preamble->version) ||
        preamble->length < 4u || preamble->length > length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    preamble->payload = (const uint8_t*)data + 4u;
    preamble->payload_len = (size_t)preamble->length - 4u;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_write_preamble(rdp_buffer* buffer,
                                         uint8_t message_type,
                                         uint8_t version,
                                         uint16_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_license_valid_message_type(message_type) ||
        !rdp_license_valid_version(version) ||
        payload_len > UINT16_MAX - 4u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, message_type);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, version);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u16_le(buffer, (uint16_t)(payload_len + 4u));
}

librdp_status rdp_license_parse_binary_blob(const void* data,
                                            size_t length,
                                            rdp_license_binary_blob* blob)
{
    rdp_stream stream;

    if (!data || !blob)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u || length > UINT16_MAX + 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_license_read_blob(&stream, blob) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_license_write_binary_blob(rdp_buffer* buffer,
                                            uint16_t type,
                                            const void* data,
                                            uint16_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_license_valid_blob_type(type) || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, type);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, length);
}

librdp_status rdp_license_parse_product_info(const void* data,
                                             size_t length,
                                             rdp_license_product_info* product)
{
    rdp_stream stream;

    if (!data || !product)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, data, length);
    if (rdp_license_parse_product_info_stream(&stream, product) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_license_parse_server_request(const void* data,
                                               size_t length,
                                               rdp_license_server_request* request)
{
    rdp_stream stream;
    const uint8_t* random = NULL;
    uint32_t scope_count = 0;
    uint32_t i = 0;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_license_parse_preamble(data, length, &request->preamble) != LIBRDP_STATUS_OK ||
        request->preamble.message_type != RDP_LICENSE_MESSAGE_REQUEST)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, request->preamble.payload, request->preamble.payload_len);
    if (rdp_stream_read_bytes(&stream, &random, sizeof(request->server_random)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(request->server_random, random, sizeof(request->server_random));
    if (rdp_license_parse_product_info_stream(&stream, &request->product_info) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &request->key_exchange_list) != LIBRDP_STATUS_OK ||
        request->key_exchange_list.type != RDP_LICENSE_BLOB_KEY_EXCHANGE_ALG ||
        (request->key_exchange_list.length % 4u) != 0 ||
        request->key_exchange_list.length == 0 ||
        rdp_license_read_blob(&stream, &request->server_certificate) != LIBRDP_STATUS_OK ||
        request->server_certificate.type != RDP_LICENSE_BLOB_CERTIFICATE ||
        rdp_stream_read_u32_le(&stream, &scope_count) != LIBRDP_STATUS_OK ||
        scope_count > RDP_LICENSE_SCOPE_MAX_COUNT)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    request->scope_list.count = scope_count;
    for (i = 0; i < scope_count; i++)
    {
        if (rdp_license_read_blob(&stream, &request->scope_list.scopes[i]) != LIBRDP_STATUS_OK ||
            request->scope_list.scopes[i].type != RDP_LICENSE_BLOB_SCOPE)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_license_parse_platform_challenge(const void* data,
                                                   size_t length,
                                                   rdp_license_platform_challenge* challenge)
{
    rdp_stream stream;
    const uint8_t* mac = NULL;

    if (!data || !challenge)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(challenge, 0, sizeof(*challenge));
    if (rdp_license_parse_preamble(data, length, &challenge->preamble) != LIBRDP_STATUS_OK ||
        challenge->preamble.message_type != RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, challenge->preamble.payload, challenge->preamble.payload_len);
    if (rdp_stream_read_u32_le(&stream, &challenge->connect_flags) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &challenge->encrypted_challenge) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &mac, sizeof(challenge->mac)) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(challenge->mac, mac, sizeof(challenge->mac));
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_parse_new_or_upgrade(const void* data,
                                               size_t length,
                                               rdp_license_new_or_upgrade* license)
{
    rdp_stream stream;
    const uint8_t* mac = NULL;

    if (!data || !license)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(license, 0, sizeof(*license));
    if (rdp_license_parse_preamble(data, length, &license->preamble) != LIBRDP_STATUS_OK ||
        (license->preamble.message_type != RDP_LICENSE_MESSAGE_NEW_LICENSE &&
         license->preamble.message_type != RDP_LICENSE_MESSAGE_UPGRADE_LICENSE))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, license->preamble.payload, license->preamble.payload_len);
    if (rdp_license_read_blob(&stream, &license->encrypted_license_info) != LIBRDP_STATUS_OK ||
        license->encrypted_license_info.type != RDP_LICENSE_BLOB_ENCRYPTED_DATA ||
        rdp_stream_read_bytes(&stream, &mac, sizeof(license->mac)) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(license->mac, mac, sizeof(license->mac));
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_parse_new_license_info(const void* data,
                                                 size_t length,
                                                 rdp_license_new_license_info* info)
{
    rdp_stream stream;

    if (!data || !info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(info, 0, sizeof(*info));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &info->version) != LIBRDP_STATUS_OK ||
        rdp_license_read_sized_blob(&stream, &info->scope_len, &info->scope) != LIBRDP_STATUS_OK ||
        rdp_license_read_sized_blob(&stream,
                                    &info->company_name_len,
                                    &info->company_name) != LIBRDP_STATUS_OK ||
        rdp_license_read_sized_blob(&stream,
                                    &info->product_id_len,
                                    &info->product_id) != LIBRDP_STATUS_OK ||
        rdp_license_read_sized_blob(&stream,
                                    &info->license_info_len,
                                    &info->license_info) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (info->scope_len == 0 || info->company_name_len == 0 ||
        info->product_id_len == 0 || info->license_info_len == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_parse_product_certificate_info(
    const void* data,
    size_t length,
    rdp_license_product_certificate_info* info)
{
    rdp_stream stream;
    uint16_t requested_offset = 0;
    uint16_t adjusted_offset = 0;
    uint16_t version_info_offset = 0;
    uint16_t version_info_count = 0;

    if (!data || !info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 36u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(info, 0, sizeof(*info));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &info->version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &info->license_count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &info->platform_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &info->language_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &requested_offset) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &info->requested_product_id_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &adjusted_offset) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &info->adjusted_product_id_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &version_info_offset) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &version_info_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (version_info_count != 1u ||
        !rdp_license_range_valid(length, requested_offset, info->requested_product_id_len) ||
        !rdp_license_range_valid(length, adjusted_offset, info->adjusted_product_id_len) ||
        !rdp_license_range_valid(length, version_info_offset, 8u) ||
        info->requested_product_id_len == 0 ||
        info->adjusted_product_id_len == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    info->requested_product_id = (const uint8_t*)data + requested_offset;
    info->adjusted_product_id = (const uint8_t*)data + adjusted_offset;
    rdp_stream_init(&stream, (const uint8_t*)data + version_info_offset, 8u);
    if (rdp_stream_read_u16_le(&stream, &info->version_info.major_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &info->version_info.minor_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &info->version_info.flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_write_product_certificate_info(
    rdp_buffer* buffer,
    const rdp_license_product_certificate_info* info)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t requested_offset = 28u;
    uint32_t adjusted_offset = 0;
    uint32_t version_info_offset = 0;

    if (!buffer || !info ||
        !info->requested_product_id || !info->adjusted_product_id ||
        info->requested_product_id_len == 0 ||
        info->adjusted_product_id_len == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    adjusted_offset = requested_offset + info->requested_product_id_len;
    version_info_offset = adjusted_offset + info->adjusted_product_id_len;
    if (version_info_offset > UINT16_MAX - 8u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, info->version);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, info->license_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, info->platform_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, info->language_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)requested_offset);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, info->requested_product_id_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)adjusted_offset);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, info->adjusted_product_id_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)version_info_offset);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, 1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer,
                               info->requested_product_id,
                               info->requested_product_id_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer,
                               info->adjusted_product_id,
                               info->adjusted_product_id_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_license_append_version_info(buffer, &info->version_info);
}

librdp_status rdp_license_parse_server_info(const void* data,
                                            size_t length,
                                            rdp_license_server_info* info)
{
    rdp_stream stream;
    uint16_t issuer_name_offset = 0;
    uint16_t issuer_id_offset = 0;
    uint16_t scope_offset = 0;
    const uint8_t* variable = NULL;
    size_t variable_len = 0;

    if (!data || !info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(info, 0, sizeof(*info));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &info->version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &issuer_name_offset) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (issuer_name_offset != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (info->version == RDP_LICENSE_SERVER_INFO_VERSION_1)
    {
        if (rdp_stream_read_u16_le(&stream, &scope_offset) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        variable = (const uint8_t*)data + 8u;
        variable_len = length - 8u;
        if (scope_offset == 0 ||
            scope_offset > variable_len)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        info->issuer_name = variable;
        info->issuer_name_len = scope_offset;
        info->scope = variable + scope_offset;
        info->scope_len = (uint16_t)(variable_len - scope_offset);
        if (!rdp_license_utf16z_valid(info->issuer_name, info->issuer_name_len) ||
            !rdp_license_utf16z_valid(info->scope, info->scope_len))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        return LIBRDP_STATUS_OK;
    }
    if (info->version == RDP_LICENSE_SERVER_INFO_VERSION_2)
    {
        if (length < 10u ||
            rdp_stream_read_u16_le(&stream, &issuer_id_offset) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &scope_offset) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        variable = (const uint8_t*)data + 10u;
        variable_len = length - 10u;
        if (issuer_id_offset == 0 ||
            scope_offset <= issuer_id_offset ||
            scope_offset > variable_len)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        info->issuer_name = variable;
        info->issuer_name_len = issuer_id_offset;
        info->issuer_id = variable + issuer_id_offset;
        info->issuer_id_len = (uint16_t)(scope_offset - issuer_id_offset);
        info->scope = variable + scope_offset;
        info->scope_len = (uint16_t)(variable_len - scope_offset);
        info->has_issuer_id = 1;
        if (!rdp_license_utf16z_valid(info->issuer_name, info->issuer_name_len) ||
            !rdp_license_utf16z_valid(info->issuer_id, info->issuer_id_len) ||
            !rdp_license_utf16z_valid(info->scope, info->scope_len))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_license_write_server_info(rdp_buffer* buffer,
                                            const rdp_license_server_info* info)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t issuer_id_offset = 0;
    uint32_t scope_offset = 0;

    if (!buffer || !info ||
        !rdp_license_utf16z_valid(info->issuer_name, info->issuer_name_len) ||
        !rdp_license_utf16z_valid(info->scope, info->scope_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (info->has_issuer_id)
    {
        if (!rdp_license_utf16z_valid(info->issuer_id, info->issuer_id_len))
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        issuer_id_offset = info->issuer_name_len;
        scope_offset = issuer_id_offset + info->issuer_id_len;
        if (scope_offset > UINT16_MAX)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        status = rdp_buffer_append_u32_le(buffer, RDP_LICENSE_SERVER_INFO_VERSION_2);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append_u16_le(buffer, 0);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)issuer_id_offset);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)scope_offset);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append(buffer, info->issuer_name, info->issuer_name_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append(buffer, info->issuer_id, info->issuer_id_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_buffer_append(buffer, info->scope, info->scope_len);
    }
    scope_offset = info->issuer_name_len;
    if (scope_offset > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, RDP_LICENSE_SERVER_INFO_VERSION_1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)scope_offset);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, info->issuer_name, info->issuer_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, info->scope, info->scope_len);
}

librdp_status rdp_license_parse_hardware_id(const void* data,
                                            size_t length,
                                            rdp_license_hardware_id* hardware_id)
{
    rdp_stream stream;

    if (!data || !hardware_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(hardware_id, 0, sizeof(*hardware_id));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &hardware_id->platform_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &hardware_id->data1) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &hardware_id->data2) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &hardware_id->data3) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &hardware_id->data4) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_write_hardware_id(rdp_buffer* buffer,
                                            const rdp_license_hardware_id* hardware_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !hardware_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, hardware_id->platform_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, hardware_id->data1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, hardware_id->data2);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, hardware_id->data3);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, hardware_id->data4);
}

librdp_status rdp_license_parse_platform_challenge_response_data(
    const void* data,
    size_t length,
    rdp_license_platform_challenge_response_data* response)
{
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(response, 0, sizeof(*response));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &response->version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &response->client_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &response->license_detail_level) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &response->challenge_len) != LIBRDP_STATUS_OK ||
        response->challenge_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &response->challenge, response->challenge_len) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (response->version != 0x0100u || response->license_detail_level == 0 ||
        response->license_detail_level > 3u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_write_platform_challenge_response_data(
    rdp_buffer* buffer,
    const rdp_license_platform_challenge_response_data* response)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !response ||
        response->version != 0x0100u ||
        response->license_detail_level == 0 ||
        response->license_detail_level > 3u ||
        (!response->challenge && response->challenge_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, response->version);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, response->client_type);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, response->license_detail_level);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, response->challenge_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, response->challenge, response->challenge_len);
}

librdp_status rdp_license_parse_error_alert(const void* data, size_t length, rdp_license_error_alert* alert)
{
    rdp_stream stream;
    rdp_license_preamble preamble;

    if (!data || !alert)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(alert, 0, sizeof(*alert));
    if (rdp_license_parse_preamble(data, length, &preamble) != LIBRDP_STATUS_OK ||
        preamble.message_type != RDP_LICENSE_MESSAGE_ERROR_ALERT)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &alert->message_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &alert->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &alert->length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &alert->error_code) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &alert->state_transition) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &alert->blob_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &alert->blob_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (alert->length < 16u || alert->length > length ||
        !rdp_license_valid_blob_type(alert->blob_type) ||
        rdp_stream_remaining(&stream) < alert->blob_length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &alert->blob, alert->blob_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_write_error_alert(rdp_buffer* buffer,
                                            uint8_t version,
                                            uint32_t error_code,
                                            uint32_t state_transition,
                                            uint16_t blob_type,
                                            const void* blob,
                                            uint16_t blob_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_license_valid_blob_type(blob_type) || (!blob && blob_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_license_write_preamble(buffer,
                                        RDP_LICENSE_MESSAGE_ERROR_ALERT,
                                        version,
                                        (uint16_t)(12u + blob_len));
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, error_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, state_transition);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_license_write_binary_blob(buffer, blob_type, blob, blob_len);
}

librdp_status rdp_license_parse_client_new_license_request(
    const void* data,
    size_t length,
    rdp_license_client_new_license_request* request)
{
    rdp_stream stream;
    const uint8_t* random = NULL;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_license_parse_preamble(data, length, &request->preamble) != LIBRDP_STATUS_OK ||
        request->preamble.message_type != RDP_LICENSE_MESSAGE_NEW_LICENSE_REQUEST)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, request->preamble.payload, request->preamble.payload_len);
    if (rdp_stream_read_u32_le(&stream, &request->preferred_key_exchange_alg) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->platform_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &random, sizeof(request->client_random)) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &request->encrypted_pre_master) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &request->user_name) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &request->machine_name) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->preferred_key_exchange_alg != RDP_LICENSE_KEY_EXCHANGE_RSA ||
        request->encrypted_pre_master.type != RDP_LICENSE_BLOB_RANDOM ||
        request->user_name.type != RDP_LICENSE_BLOB_CLIENT_USER_NAME ||
        request->machine_name.type != RDP_LICENSE_BLOB_CLIENT_MACHINE_NAME)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(request->client_random, random, sizeof(request->client_random));
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_write_client_new_license_request(rdp_buffer* buffer,
                                                           uint8_t version,
                                                           uint32_t preferred_key_exchange_alg,
                                                           uint32_t platform_id,
                                                           const uint8_t client_random[32],
                                                           const rdp_license_binary_blob* encrypted_pre_master,
                                                           const rdp_license_binary_blob* user_name,
                                                           const rdp_license_binary_blob* machine_name)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t total = 0;

    if (!buffer || !client_random ||
        preferred_key_exchange_alg != RDP_LICENSE_KEY_EXCHANGE_RSA ||
        !encrypted_pre_master || !user_name || !machine_name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    total = 40u + 4u + encrypted_pre_master->length + 4u + user_name->length +
            4u + machine_name->length;
    if (total > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_license_write_preamble(buffer,
                                        RDP_LICENSE_MESSAGE_NEW_LICENSE_REQUEST,
                                        version,
                                        (uint16_t)total);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, preferred_key_exchange_alg);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, platform_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, client_random, 32u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_license_write_blob_checked(buffer,
                                            encrypted_pre_master,
                                            RDP_LICENSE_BLOB_RANDOM);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_license_write_blob_checked(buffer,
                                            user_name,
                                            RDP_LICENSE_BLOB_CLIENT_USER_NAME);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_license_write_blob_checked(buffer,
                                          machine_name,
                                          RDP_LICENSE_BLOB_CLIENT_MACHINE_NAME);
}

librdp_status rdp_license_parse_client_info(const void* data,
                                            size_t length,
                                            rdp_license_client_info* info)
{
    rdp_stream stream;
    const uint8_t* random = NULL;
    const uint8_t* mac = NULL;

    if (!data || !info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(info, 0, sizeof(*info));
    if (rdp_license_parse_preamble(data, length, &info->preamble) != LIBRDP_STATUS_OK ||
        info->preamble.message_type != RDP_LICENSE_MESSAGE_INFO)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, info->preamble.payload, info->preamble.payload_len);
    if (rdp_stream_read_u32_le(&stream, &info->preferred_key_exchange_alg) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &info->platform_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &random, sizeof(info->client_random)) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &info->encrypted_pre_master) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &info->license_info) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &info->encrypted_hardware_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &mac, sizeof(info->mac)) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (info->preferred_key_exchange_alg != RDP_LICENSE_KEY_EXCHANGE_RSA ||
        info->encrypted_pre_master.type != RDP_LICENSE_BLOB_RANDOM ||
        info->license_info.type != RDP_LICENSE_BLOB_DATA ||
        info->encrypted_hardware_id.type != RDP_LICENSE_BLOB_ENCRYPTED_DATA)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(info->client_random, random, sizeof(info->client_random));
    memcpy(info->mac, mac, sizeof(info->mac));
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_write_client_info(rdp_buffer* buffer,
                                            uint8_t version,
                                            uint32_t preferred_key_exchange_alg,
                                            uint32_t platform_id,
                                            const uint8_t client_random[32],
                                            const rdp_license_binary_blob* encrypted_pre_master,
                                            const rdp_license_binary_blob* license_info,
                                            const rdp_license_binary_blob* encrypted_hardware_id,
                                            const uint8_t mac[16])
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t total = 0;

    if (!buffer || !client_random || !mac ||
        preferred_key_exchange_alg != RDP_LICENSE_KEY_EXCHANGE_RSA ||
        !encrypted_pre_master || !license_info || !encrypted_hardware_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    total = 40u + 4u + encrypted_pre_master->length + 4u + license_info->length +
            4u + encrypted_hardware_id->length + 16u;
    if (total > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_license_write_preamble(buffer,
                                        RDP_LICENSE_MESSAGE_INFO,
                                        version,
                                        (uint16_t)total);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, preferred_key_exchange_alg);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, platform_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, client_random, 32u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_license_write_blob_checked(buffer,
                                            encrypted_pre_master,
                                            RDP_LICENSE_BLOB_RANDOM);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_license_write_blob_checked(buffer, license_info, RDP_LICENSE_BLOB_DATA);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_license_write_blob_checked(buffer,
                                            encrypted_hardware_id,
                                            RDP_LICENSE_BLOB_ENCRYPTED_DATA);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, mac, 16u);
}

librdp_status rdp_license_parse_platform_challenge_response(
    const void* data,
    size_t length,
    rdp_license_platform_challenge_response* response)
{
    rdp_stream stream;
    const uint8_t* mac = NULL;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(response, 0, sizeof(*response));
    if (rdp_license_parse_preamble(data, length, &response->preamble) != LIBRDP_STATUS_OK ||
        response->preamble.message_type != RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE_RESPONSE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, response->preamble.payload, response->preamble.payload_len);
    if (rdp_license_read_blob(&stream, &response->encrypted_response) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &response->encrypted_hardware_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &mac, sizeof(response->mac)) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (response->encrypted_response.type != RDP_LICENSE_BLOB_ENCRYPTED_DATA ||
        response->encrypted_hardware_id.type != RDP_LICENSE_BLOB_ENCRYPTED_DATA)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(response->mac, mac, sizeof(response->mac));
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_write_platform_challenge_response(
    rdp_buffer* buffer,
    uint8_t version,
    const rdp_license_binary_blob* encrypted_response,
    const rdp_license_binary_blob* encrypted_hardware_id,
    const uint8_t mac[16])
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t total = 0;

    if (!buffer || !encrypted_response || !encrypted_hardware_id || !mac)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    total = 4u + encrypted_response->length + 4u + encrypted_hardware_id->length + 16u;
    if (total > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_license_write_preamble(buffer,
                                        RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE_RESPONSE,
                                        version,
                                        (uint16_t)total);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_license_write_blob_checked(buffer,
                                            encrypted_response,
                                            RDP_LICENSE_BLOB_ENCRYPTED_DATA);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_license_write_blob_checked(buffer,
                                            encrypted_hardware_id,
                                            RDP_LICENSE_BLOB_ENCRYPTED_DATA);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, mac, 16u);
}
