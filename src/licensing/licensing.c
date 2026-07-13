/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: licensing PDU parser and writer support.
 * Invariants: publicly observable state is updated only after local validation
 * succeeds.
 * Ownership: licensing state transitions follow the negotiated security mode
 * and reject truncated PDUs.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: external input is treated as untrusted until validated by
 * this module or its caller.
 */


#include "licensing/licensing.h"

#include "common/stream.h"
#include "security/security.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

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

static int rdp_license_blob_writeable(const rdp_license_binary_blob* blob, uint16_t expected_type)
{
    return blob &&
           blob->type == expected_type &&
           (blob->data || blob->length == 0);
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

static librdp_status rdp_license_restore_on_error(rdp_buffer* buffer,
                                                  size_t length,
                                                  librdp_status status)
{
    if (status != LIBRDP_STATUS_OK && buffer)
        buffer->length = length;
    return status;
}

void rdp_license_client_state_init(rdp_license_client_state* state)
{
    if (!state)
        return;
    memset(state, 0, sizeof(*state));
    state->state = RDP_LICENSE_CLIENT_STATE_INITIAL;
}

void rdp_license_crypto_context_clear(rdp_license_crypto_context* context)
{
    if (!context)
        return;
    OPENSSL_cleanse(context, sizeof(*context));
}

static int rdp_license_key_exchange_supports_rsa(const rdp_license_binary_blob* blob)
{
    size_t offset = 0;

    if (!blob || blob->type != RDP_LICENSE_BLOB_KEY_EXCHANGE_ALG || !blob->data ||
        blob->length == 0 || (blob->length % 4u) != 0)
        return 0;
    while (offset < blob->length)
    {
        uint32_t alg = (uint32_t)blob->data[offset] |
                       ((uint32_t)blob->data[offset + 1u] << 8u) |
                       ((uint32_t)blob->data[offset + 2u] << 16u) |
                       ((uint32_t)blob->data[offset + 3u] << 24u);

        if (alg == RDP_LICENSE_KEY_EXCHANGE_RSA)
            return 1;
        offset += 4u;
    }
    return 0;
}

static librdp_status rdp_license_write_u32_le_bytes(uint8_t output[4], uint32_t value)
{
    if (!output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    output[0] = (uint8_t)(value & 0xffu);
    output[1] = (uint8_t)((value >> 8u) & 0xffu);
    output[2] = (uint8_t)((value >> 16u) & 0xffu);
    output[3] = (uint8_t)((value >> 24u) & 0xffu);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_license_build_hardware_id(const char* machine_name,
                                                   uint8_t hardware_id[RDP_LICENSE_HARDWARE_ID_LEN])
{
    EVP_MD_CTX* digest = NULL;
    unsigned int got = 0;
    const uint8_t* hash_data = (const uint8_t*)(machine_name ? machine_name : "librdp");
    size_t hash_len = strlen((const char*)hash_data);
    librdp_status status = LIBRDP_STATUS_PROTOCOL_ERROR;

    if (!hardware_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(hardware_id, 0, RDP_LICENSE_HARDWARE_ID_LEN);
    status = rdp_license_write_u32_le_bytes(hardware_id, RDP_LICENSE_PLATFORM_ID_CLIENT);
    if (status != LIBRDP_STATUS_OK)
        return status;
    digest = EVP_MD_CTX_new();
    if (!digest)
        return LIBRDP_STATUS_NO_MEMORY;
    if (EVP_DigestInit_ex(digest, EVP_md5(), NULL) != 1 ||
        (hash_len > 0 && EVP_DigestUpdate(digest, hash_data, hash_len) != 1) ||
        EVP_DigestFinal_ex(digest, hardware_id + 4u, &got) != 1 ||
        got != RDP_LICENSE_HARDWARE_ID_LEN - 4u)
        goto out;
    status = LIBRDP_STATUS_OK;

out:
    EVP_MD_CTX_free(digest);
    return status;
}

static librdp_status rdp_license_blob_from_buffer(rdp_license_binary_blob* blob,
                                                  uint16_t type,
                                                  const rdp_buffer* buffer)
{
    if (!blob || !buffer || buffer->length > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    blob->type = type;
    blob->length = (uint16_t)buffer->length;
    blob->data = buffer->data;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_license_build_response_data(const rdp_buffer* challenge,
                                                     rdp_buffer* response)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!challenge || !response || challenge->length > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(response, RDP_LICENSE_PLATFORM_CHALLENGE_RESPONSE_VERSION);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(response, RDP_LICENSE_CLIENT_TYPE_OTHER);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(response, RDP_LICENSE_DETAIL_LEVEL_DETAIL);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(response, (uint16_t)challenge->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(response, challenge->data, challenge->length);
    return status;
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

/*
 * Advance the client licensing state machine for one validated message type
 * and direction. Illegal ordering moves no state and returns a protocol error,
 * which keeps handshake sequencing explicit for both legacy and bypass paths.
 */
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
    if (state->state == RDP_LICENSE_CLIENT_STATE_COMPLETED ||
        state->state == RDP_LICENSE_CLIENT_STATE_FAILED)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (direction == RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT &&
        message_type == RDP_LICENSE_MESSAGE_ERROR_ALERT)
        next_state = RDP_LICENSE_CLIENT_STATE_FAILED;
    else if (state->state == RDP_LICENSE_CLIENT_STATE_INITIAL &&
             direction == RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT &&
             (message_type == RDP_LICENSE_MESSAGE_NEW_LICENSE ||
              message_type == RDP_LICENSE_MESSAGE_UPGRADE_LICENSE))
        next_state = RDP_LICENSE_CLIENT_STATE_COMPLETED;
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

/*
 * Apply a parsed server error alert to the client licensing state. The
 * STATUS_VALID_CLIENT alert is a terminal success; all other error alerts are
 * terminal failures, and neither path may be replayed after a terminal state.
 */
librdp_status rdp_license_client_state_step_error_alert(rdp_license_client_state* state,
                                                        const rdp_license_error_alert* alert)
{
    if (!state || !alert || alert->message_type != RDP_LICENSE_MESSAGE_ERROR_ALERT)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (state->state == RDP_LICENSE_CLIENT_STATE_COMPLETED ||
        state->state == RDP_LICENSE_CLIENT_STATE_FAILED)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    state->state = rdp_license_error_alert_is_terminal_success(alert) ?
                       RDP_LICENSE_CLIENT_STATE_COMPLETED :
                       RDP_LICENSE_CLIENT_STATE_FAILED;
    state->last_message_type = RDP_LICENSE_MESSAGE_ERROR_ALERT;
    state->last_direction = (uint8_t)RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_parse_preamble(const void* data, size_t length, rdp_license_preamble* preamble)
{
    rdp_license_preamble parsed;
    rdp_stream stream;

    if (!data || !preamble)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u || length > UINT16_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &parsed.message_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_license_valid_message_type(parsed.message_type) ||
        !rdp_license_valid_version(parsed.version) ||
        parsed.length < 4u || parsed.length != length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.payload = (const uint8_t*)data + 4u;
    parsed.payload_len = (size_t)parsed.length - 4u;
    *preamble = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_write_preamble(rdp_buffer* buffer,
                                         uint8_t message_type,
                                         uint8_t version,
                                         uint16_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !rdp_license_valid_message_type(message_type) ||
        !rdp_license_valid_version(version) ||
        payload_len > UINT16_MAX - 4u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, message_type);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u8(buffer, version);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)(payload_len + 4u));
    return rdp_license_restore_on_error(buffer, start, status);
}

librdp_status rdp_license_parse_binary_blob(const void* data,
                                            size_t length,
                                            rdp_license_binary_blob* blob)
{
    rdp_license_binary_blob parsed;
    rdp_stream stream;

    if (!data || !blob)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u || length > UINT16_MAX + 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_license_read_blob(&stream, &parsed) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *blob = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_write_binary_blob(rdp_buffer* buffer,
                                            uint16_t type,
                                            const void* data,
                                            uint16_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !rdp_license_valid_blob_type(type) || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u16_le(buffer, type);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, length);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer, data, length);
    return rdp_license_restore_on_error(buffer, start, status);
}

librdp_status rdp_license_parse_product_info(const void* data,
                                             size_t length,
                                             rdp_license_product_info* product)
{
    rdp_license_product_info parsed;
    rdp_stream stream;

    if (!data || !product)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, data, length);
    if (rdp_license_parse_product_info_stream(&stream, &parsed) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *product = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_parse_server_request(const void* data,
                                               size_t length,
                                               rdp_license_server_request* request)
{
    rdp_license_server_request parsed;
    rdp_stream stream;
    const uint8_t* random = NULL;
    uint32_t scope_count = 0;
    uint32_t i = 0;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_license_parse_preamble(data, length, &parsed.preamble) != LIBRDP_STATUS_OK ||
        parsed.preamble.message_type != RDP_LICENSE_MESSAGE_REQUEST)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.preamble.payload, parsed.preamble.payload_len);
    if (rdp_stream_read_bytes(&stream, &random, sizeof(parsed.server_random)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(parsed.server_random, random, sizeof(parsed.server_random));
    if (rdp_license_parse_product_info_stream(&stream, &parsed.product_info) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &parsed.key_exchange_list) != LIBRDP_STATUS_OK ||
        parsed.key_exchange_list.type != RDP_LICENSE_BLOB_KEY_EXCHANGE_ALG ||
        (parsed.key_exchange_list.length % 4u) != 0 ||
        parsed.key_exchange_list.length == 0 ||
        rdp_license_read_blob(&stream, &parsed.server_certificate) != LIBRDP_STATUS_OK ||
        parsed.server_certificate.type != RDP_LICENSE_BLOB_CERTIFICATE ||
        rdp_stream_read_u32_le(&stream, &scope_count) != LIBRDP_STATUS_OK ||
        scope_count > RDP_LICENSE_SCOPE_MAX_COUNT)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.scope_list.count = scope_count;
    for (i = 0; i < scope_count; i++)
    {
        if (rdp_license_read_blob(&stream, &parsed.scope_list.scopes[i]) != LIBRDP_STATUS_OK ||
            parsed.scope_list.scopes[i].type != RDP_LICENSE_BLOB_SCOPE)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *request = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_parse_platform_challenge(const void* data,
                                                   size_t length,
                                                   rdp_license_platform_challenge* challenge)
{
    rdp_license_platform_challenge parsed;
    rdp_stream stream;
    const uint8_t* mac = NULL;

    if (!data || !challenge)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_license_parse_preamble(data, length, &parsed.preamble) != LIBRDP_STATUS_OK ||
        parsed.preamble.message_type != RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.preamble.payload, parsed.preamble.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.connect_flags) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &parsed.encrypted_challenge) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &mac, sizeof(parsed.mac)) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(parsed.mac, mac, sizeof(parsed.mac));
    *challenge = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_parse_new_or_upgrade(const void* data,
                                               size_t length,
                                               rdp_license_new_or_upgrade* license)
{
    rdp_license_new_or_upgrade parsed;
    rdp_stream stream;
    const uint8_t* mac = NULL;

    if (!data || !license)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_license_parse_preamble(data, length, &parsed.preamble) != LIBRDP_STATUS_OK ||
        (parsed.preamble.message_type != RDP_LICENSE_MESSAGE_NEW_LICENSE &&
         parsed.preamble.message_type != RDP_LICENSE_MESSAGE_UPGRADE_LICENSE))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.preamble.payload, parsed.preamble.payload_len);
    if (rdp_license_read_blob(&stream, &parsed.encrypted_license_info) != LIBRDP_STATUS_OK ||
        parsed.encrypted_license_info.type != RDP_LICENSE_BLOB_ENCRYPTED_DATA ||
        rdp_stream_read_bytes(&stream, &mac, sizeof(parsed.mac)) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(parsed.mac, mac, sizeof(parsed.mac));
    *license = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_parse_new_license_info(const void* data,
                                                 size_t length,
                                                 rdp_license_new_license_info* info)
{
    rdp_license_new_license_info parsed;
    rdp_stream stream;

    if (!data || !info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &parsed.version) != LIBRDP_STATUS_OK ||
        rdp_license_read_sized_blob(&stream, &parsed.scope_len, &parsed.scope) != LIBRDP_STATUS_OK ||
        rdp_license_read_sized_blob(&stream,
                                    &parsed.company_name_len,
                                    &parsed.company_name) != LIBRDP_STATUS_OK ||
        rdp_license_read_sized_blob(&stream,
                                    &parsed.product_id_len,
                                    &parsed.product_id) != LIBRDP_STATUS_OK ||
        rdp_license_read_sized_blob(&stream,
                                    &parsed.license_info_len,
                                    &parsed.license_info) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.scope_len == 0 || parsed.company_name_len == 0 ||
        parsed.product_id_len == 0 || parsed.license_info_len == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *info = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_parse_product_certificate_info(
    const void* data,
    size_t length,
    rdp_license_product_certificate_info* info)
{
    rdp_license_product_certificate_info parsed;
    rdp_stream stream;
    uint16_t requested_offset = 0;
    uint16_t adjusted_offset = 0;
    uint16_t version_info_offset = 0;
    uint16_t version_info_count = 0;

    if (!data || !info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 36u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &parsed.version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.license_count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.platform_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.language_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &requested_offset) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.requested_product_id_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &adjusted_offset) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.adjusted_product_id_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &version_info_offset) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &version_info_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (version_info_count != 1u ||
        !rdp_license_range_valid(length, requested_offset, parsed.requested_product_id_len) ||
        !rdp_license_range_valid(length, adjusted_offset, parsed.adjusted_product_id_len) ||
        !rdp_license_range_valid(length, version_info_offset, 8u) ||
        parsed.requested_product_id_len == 0 ||
        parsed.adjusted_product_id_len == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.requested_product_id = (const uint8_t*)data + requested_offset;
    parsed.adjusted_product_id = (const uint8_t*)data + adjusted_offset;
    rdp_stream_init(&stream, (const uint8_t*)data + version_info_offset, 8u);
    if (rdp_stream_read_u16_le(&stream, &parsed.version_info.major_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.version_info.minor_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.version_info.flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *info = parsed;
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
    size_t start = 0;

    if (!buffer || !info ||
        !info->requested_product_id || !info->adjusted_product_id ||
        info->requested_product_id_len == 0 ||
        info->adjusted_product_id_len == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    adjusted_offset = requested_offset + info->requested_product_id_len;
    version_info_offset = adjusted_offset + info->adjusted_product_id_len;
    if (version_info_offset > UINT16_MAX - 8u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u32_le(buffer, info->version);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, info->license_count);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, info->platform_id);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, info->language_id);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)requested_offset);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, info->requested_product_id_len);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)adjusted_offset);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, info->adjusted_product_id_len);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)version_info_offset);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, 1);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer,
                               info->requested_product_id,
                               info->requested_product_id_len);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer,
                               info->adjusted_product_id,
                               info->adjusted_product_id_len);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_license_append_version_info(buffer, &info->version_info);
    return rdp_license_restore_on_error(buffer, start, status);
}

librdp_status rdp_license_parse_server_info(const void* data,
                                            size_t length,
                                            rdp_license_server_info* info)
{
    rdp_license_server_info parsed;
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
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &parsed.version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &issuer_name_offset) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (issuer_name_offset != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.version == RDP_LICENSE_SERVER_INFO_VERSION_1)
    {
        if (rdp_stream_read_u16_le(&stream, &scope_offset) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        variable = (const uint8_t*)data + 8u;
        variable_len = length - 8u;
        if (scope_offset == 0 ||
            scope_offset > variable_len)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        parsed.issuer_name = variable;
        parsed.issuer_name_len = scope_offset;
        parsed.scope = variable + scope_offset;
        parsed.scope_len = (uint16_t)(variable_len - scope_offset);
        if (!rdp_license_utf16z_valid(parsed.issuer_name, parsed.issuer_name_len) ||
            !rdp_license_utf16z_valid(parsed.scope, parsed.scope_len))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *info = parsed;
        return LIBRDP_STATUS_OK;
    }
    if (parsed.version == RDP_LICENSE_SERVER_INFO_VERSION_2)
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
        parsed.issuer_name = variable;
        parsed.issuer_name_len = issuer_id_offset;
        parsed.issuer_id = variable + issuer_id_offset;
        parsed.issuer_id_len = (uint16_t)(scope_offset - issuer_id_offset);
        parsed.scope = variable + scope_offset;
        parsed.scope_len = (uint16_t)(variable_len - scope_offset);
        parsed.has_issuer_id = 1;
        if (!rdp_license_utf16z_valid(parsed.issuer_name, parsed.issuer_name_len) ||
            !rdp_license_utf16z_valid(parsed.issuer_id, parsed.issuer_id_len) ||
            !rdp_license_utf16z_valid(parsed.scope, parsed.scope_len))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *info = parsed;
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
    size_t start = 0;

    if (!buffer || !info ||
        !rdp_license_utf16z_valid(info->issuer_name, info->issuer_name_len) ||
        !rdp_license_utf16z_valid(info->scope, info->scope_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
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
            return rdp_license_restore_on_error(buffer, start, status);
        status = rdp_buffer_append_u16_le(buffer, 0);
        if (status != LIBRDP_STATUS_OK)
            return rdp_license_restore_on_error(buffer, start, status);
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)issuer_id_offset);
        if (status != LIBRDP_STATUS_OK)
            return rdp_license_restore_on_error(buffer, start, status);
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)scope_offset);
        if (status != LIBRDP_STATUS_OK)
            return rdp_license_restore_on_error(buffer, start, status);
        status = rdp_buffer_append(buffer, info->issuer_name, info->issuer_name_len);
        if (status != LIBRDP_STATUS_OK)
            return rdp_license_restore_on_error(buffer, start, status);
        status = rdp_buffer_append(buffer, info->issuer_id, info->issuer_id_len);
        if (status != LIBRDP_STATUS_OK)
            return rdp_license_restore_on_error(buffer, start, status);
        status = rdp_buffer_append(buffer, info->scope, info->scope_len);
        return rdp_license_restore_on_error(buffer, start, status);
    }
    scope_offset = info->issuer_name_len;
    if (scope_offset > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, RDP_LICENSE_SERVER_INFO_VERSION_1);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)scope_offset);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer, info->issuer_name, info->issuer_name_len);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer, info->scope, info->scope_len);
    return rdp_license_restore_on_error(buffer, start, status);
}

librdp_status rdp_license_parse_hardware_id(const void* data,
                                            size_t length,
                                            rdp_license_hardware_id* hardware_id)
{
    rdp_license_hardware_id parsed;
    rdp_stream stream;

    if (!data || !hardware_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &parsed.platform_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.data1) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.data2) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.data3) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.data4) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *hardware_id = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_write_hardware_id(rdp_buffer* buffer,
                                            const rdp_license_hardware_id* hardware_id)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !hardware_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u32_le(buffer, hardware_id->platform_id);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, hardware_id->data1);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, hardware_id->data2);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, hardware_id->data3);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, hardware_id->data4);
    return rdp_license_restore_on_error(buffer, start, status);
}

librdp_status rdp_license_parse_platform_challenge_response_data(
    const void* data,
    size_t length,
    rdp_license_platform_challenge_response_data* response)
{
    rdp_license_platform_challenge_response_data parsed;
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &parsed.version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.client_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.license_detail_level) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.challenge_len) != LIBRDP_STATUS_OK ||
        parsed.challenge_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &parsed.challenge, parsed.challenge_len) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.version != 0x0100u || parsed.license_detail_level == 0 ||
        parsed.license_detail_level > 3u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *response = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_license_write_platform_challenge_response_data(
    rdp_buffer* buffer,
    const rdp_license_platform_challenge_response_data* response)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !response ||
        response->version != 0x0100u ||
        response->license_detail_level == 0 ||
        response->license_detail_level > 3u ||
        (!response->challenge && response->challenge_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u16_le(buffer, response->version);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, response->client_type);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, response->license_detail_level);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u16_le(buffer, response->challenge_len);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer, response->challenge, response->challenge_len);
    return rdp_license_restore_on_error(buffer, start, status);
}

librdp_status rdp_license_parse_error_alert(const void* data, size_t length, rdp_license_error_alert* alert)
{
    rdp_license_error_alert parsed;
    rdp_stream stream;
    rdp_license_preamble preamble;

    if (!data || !alert)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_license_parse_preamble(data, length, &preamble) != LIBRDP_STATUS_OK ||
        preamble.message_type != RDP_LICENSE_MESSAGE_ERROR_ALERT)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.message_type = preamble.message_type;
    parsed.flags = preamble.version;
    parsed.length = preamble.length;
    rdp_stream_init(&stream, preamble.payload, preamble.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.error_code) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.state_transition) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.blob_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.blob_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.length < 16u ||
        !rdp_license_valid_blob_type(parsed.blob_type) ||
        rdp_stream_remaining(&stream) != parsed.blob_length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &parsed.blob, parsed.blob_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *alert = parsed;
    return LIBRDP_STATUS_OK;
}

int rdp_license_error_alert_is_terminal_success(const rdp_license_error_alert* alert)
{
    return alert &&
           alert->message_type == RDP_LICENSE_MESSAGE_ERROR_ALERT &&
           alert->error_code == RDP_LICENSE_ERROR_STATUS_VALID_CLIENT &&
           alert->state_transition == RDP_LICENSE_STATE_TRANSITION_NO_TRANSITION &&
           alert->blob_type == RDP_LICENSE_BLOB_ERROR &&
           alert->blob_length == 0;
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
    size_t start = 0;

    if (!buffer || !rdp_license_valid_blob_type(blob_type) || (!blob && blob_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_license_write_preamble(buffer,
                                        RDP_LICENSE_MESSAGE_ERROR_ALERT,
                                        version,
                                        (uint16_t)(12u + blob_len));
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, error_code);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, state_transition);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_license_write_binary_blob(buffer, blob_type, blob, blob_len);
    return rdp_license_restore_on_error(buffer, start, status);
}

librdp_status rdp_license_parse_client_new_license_request(
    const void* data,
    size_t length,
    rdp_license_client_new_license_request* request)
{
    rdp_license_client_new_license_request parsed;
    rdp_stream stream;
    const uint8_t* random = NULL;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_license_parse_preamble(data, length, &parsed.preamble) != LIBRDP_STATUS_OK ||
        parsed.preamble.message_type != RDP_LICENSE_MESSAGE_NEW_LICENSE_REQUEST)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.preamble.payload, parsed.preamble.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.preferred_key_exchange_alg) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.platform_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &random, sizeof(parsed.client_random)) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &parsed.encrypted_pre_master) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &parsed.user_name) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &parsed.machine_name) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.preferred_key_exchange_alg != RDP_LICENSE_KEY_EXCHANGE_RSA ||
        parsed.encrypted_pre_master.type != RDP_LICENSE_BLOB_RANDOM ||
        parsed.user_name.type != RDP_LICENSE_BLOB_CLIENT_USER_NAME ||
        parsed.machine_name.type != RDP_LICENSE_BLOB_CLIENT_MACHINE_NAME)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(parsed.client_random, random, sizeof(parsed.client_random));
    *request = parsed;
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
    size_t start = 0;

    if (!buffer || !client_random ||
        preferred_key_exchange_alg != RDP_LICENSE_KEY_EXCHANGE_RSA ||
        !rdp_license_blob_writeable(encrypted_pre_master, RDP_LICENSE_BLOB_RANDOM) ||
        !rdp_license_blob_writeable(user_name, RDP_LICENSE_BLOB_CLIENT_USER_NAME) ||
        !rdp_license_blob_writeable(machine_name, RDP_LICENSE_BLOB_CLIENT_MACHINE_NAME))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    total = 40u + 4u + encrypted_pre_master->length + 4u + user_name->length +
            4u + machine_name->length;
    if (total > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_license_write_preamble(buffer,
                                        RDP_LICENSE_MESSAGE_NEW_LICENSE_REQUEST,
                                        version,
                                        (uint16_t)total);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, preferred_key_exchange_alg);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, platform_id);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer, client_random, 32u);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_license_write_blob_checked(buffer,
                                            encrypted_pre_master,
                                            RDP_LICENSE_BLOB_RANDOM);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_license_write_blob_checked(buffer,
                                            user_name,
                                            RDP_LICENSE_BLOB_CLIENT_USER_NAME);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_license_write_blob_checked(buffer,
                                            machine_name,
                                            RDP_LICENSE_BLOB_CLIENT_MACHINE_NAME);
    return rdp_license_restore_on_error(buffer, start, status);
}

librdp_status rdp_license_parse_client_info(const void* data,
                                            size_t length,
                                            rdp_license_client_info* info)
{
    rdp_license_client_info parsed;
    rdp_stream stream;
    const uint8_t* random = NULL;
    const uint8_t* mac = NULL;

    if (!data || !info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_license_parse_preamble(data, length, &parsed.preamble) != LIBRDP_STATUS_OK ||
        parsed.preamble.message_type != RDP_LICENSE_MESSAGE_INFO)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.preamble.payload, parsed.preamble.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.preferred_key_exchange_alg) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.platform_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &random, sizeof(parsed.client_random)) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &parsed.encrypted_pre_master) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &parsed.license_info) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &parsed.encrypted_hardware_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &mac, sizeof(parsed.mac)) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.preferred_key_exchange_alg != RDP_LICENSE_KEY_EXCHANGE_RSA ||
        parsed.encrypted_pre_master.type != RDP_LICENSE_BLOB_RANDOM ||
        parsed.license_info.type != RDP_LICENSE_BLOB_DATA ||
        parsed.encrypted_hardware_id.type != RDP_LICENSE_BLOB_ENCRYPTED_DATA)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(parsed.client_random, random, sizeof(parsed.client_random));
    memcpy(parsed.mac, mac, sizeof(parsed.mac));
    *info = parsed;
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
    size_t start = 0;

    if (!buffer || !client_random || !mac ||
        preferred_key_exchange_alg != RDP_LICENSE_KEY_EXCHANGE_RSA ||
        !rdp_license_blob_writeable(encrypted_pre_master, RDP_LICENSE_BLOB_RANDOM) ||
        !rdp_license_blob_writeable(license_info, RDP_LICENSE_BLOB_DATA) ||
        !rdp_license_blob_writeable(encrypted_hardware_id, RDP_LICENSE_BLOB_ENCRYPTED_DATA))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    total = 40u + 4u + encrypted_pre_master->length + 4u + license_info->length +
            4u + encrypted_hardware_id->length + 16u;
    if (total > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_license_write_preamble(buffer,
                                        RDP_LICENSE_MESSAGE_INFO,
                                        version,
                                        (uint16_t)total);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, preferred_key_exchange_alg);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append_u32_le(buffer, platform_id);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer, client_random, 32u);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_license_write_blob_checked(buffer,
                                            encrypted_pre_master,
                                            RDP_LICENSE_BLOB_RANDOM);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_license_write_blob_checked(buffer, license_info, RDP_LICENSE_BLOB_DATA);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_license_write_blob_checked(buffer,
                                            encrypted_hardware_id,
                                            RDP_LICENSE_BLOB_ENCRYPTED_DATA);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer, mac, 16u);
    return rdp_license_restore_on_error(buffer, start, status);
}

librdp_status rdp_license_parse_platform_challenge_response(
    const void* data,
    size_t length,
    rdp_license_platform_challenge_response* response)
{
    rdp_license_platform_challenge_response parsed;
    rdp_stream stream;
    const uint8_t* mac = NULL;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_license_parse_preamble(data, length, &parsed.preamble) != LIBRDP_STATUS_OK ||
        parsed.preamble.message_type != RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE_RESPONSE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.preamble.payload, parsed.preamble.payload_len);
    if (rdp_license_read_blob(&stream, &parsed.encrypted_response) != LIBRDP_STATUS_OK ||
        rdp_license_read_blob(&stream, &parsed.encrypted_hardware_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &mac, sizeof(parsed.mac)) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.encrypted_response.type != RDP_LICENSE_BLOB_ENCRYPTED_DATA ||
        parsed.encrypted_hardware_id.type != RDP_LICENSE_BLOB_ENCRYPTED_DATA)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(parsed.mac, mac, sizeof(parsed.mac));
    *response = parsed;
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
    size_t start = 0;

    if (!buffer || !mac ||
        !rdp_license_blob_writeable(encrypted_response, RDP_LICENSE_BLOB_ENCRYPTED_DATA) ||
        !rdp_license_blob_writeable(encrypted_hardware_id, RDP_LICENSE_BLOB_ENCRYPTED_DATA))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    total = 4u + encrypted_response->length + 4u + encrypted_hardware_id->length + 16u;
    if (total > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_license_write_preamble(buffer,
                                        RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE_RESPONSE,
                                        version,
                                        (uint16_t)total);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_license_write_blob_checked(buffer,
                                            encrypted_response,
                                            RDP_LICENSE_BLOB_ENCRYPTED_DATA);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_license_write_blob_checked(buffer,
                                            encrypted_hardware_id,
                                            RDP_LICENSE_BLOB_ENCRYPTED_DATA);
    if (status != LIBRDP_STATUS_OK)
        return rdp_license_restore_on_error(buffer, start, status);
    status = rdp_buffer_append(buffer, mac, 16u);
    return rdp_license_restore_on_error(buffer, start, status);
}

/*
 * Purpose: create the client response to a server License Request and install
 * the transient licensing crypto context only after every derivation and
 * serialization step succeeds.
 * Invariants: server certificate and key-exchange list are validated before
 * generating secrets, generated secrets never leave the context except through
 * the RSA-encrypted premaster blob, and the caller-owned output buffer is the
 * only committed wire artifact.
 * Failure policy: cleanse all temporary secret material, leave the previous
 * context unchanged unless the new response is complete, and return a precise
 * protocol/unsupported/status error to the session state machine.
 */
librdp_status rdp_license_build_new_license_request(rdp_license_crypto_context* context,
                                                    const rdp_license_server_request* request,
                                                    const char* username,
                                                    const char* machine_name,
                                                    rdp_buffer* output)
{
    rdp_license_crypto_context next;
    rdp_security_public_key public_key;
    rdp_buffer encrypted_premaster;
    rdp_license_binary_blob encrypted_blob;
    rdp_license_binary_blob user_blob;
    rdp_license_binary_blob machine_blob;
    const char* safe_user = username ? username : "user";
    const char* safe_machine = machine_name ? machine_name : "librdp";
    size_t user_len = strlen(safe_user) + 1u;
    size_t machine_len = strlen(safe_machine) + 1u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !request || !output || user_len > UINT16_MAX || machine_len > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_license_key_exchange_supports_rsa(&request->key_exchange_list))
        return LIBRDP_STATUS_UNSUPPORTED;

    memset(&next, 0, sizeof(next));
    memset(&public_key, 0, sizeof(public_key));
    rdp_buffer_init(&encrypted_premaster);

    memcpy(next.server_random, request->server_random, sizeof(next.server_random));
    status = rdp_security_parse_server_certificate(request->server_certificate.data,
                                                   request->server_certificate.length,
                                                   &public_key);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_generate_client_random(next.client_random);
    if (status == LIBRDP_STATUS_OK && RAND_bytes(next.premaster_secret, sizeof(next.premaster_secret)) != 1)
        status = LIBRDP_STATUS_IO_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_license_keys(next.premaster_secret,
                                           next.client_random,
                                           next.server_random,
                                           next.mac_salt_key,
                                           next.encryption_key);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_license_build_hardware_id(safe_machine, next.hardware_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_encrypt_public_secret(&public_key,
                                                    next.premaster_secret,
                                                    sizeof(next.premaster_secret),
                                                    &encrypted_premaster);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_license_blob_from_buffer(&encrypted_blob,
                                              RDP_LICENSE_BLOB_RANDOM,
                                              &encrypted_premaster);
    if (status == LIBRDP_STATUS_OK)
    {
        user_blob.type = RDP_LICENSE_BLOB_CLIENT_USER_NAME;
        user_blob.length = (uint16_t)user_len;
        user_blob.data = (const uint8_t*)safe_user;
        machine_blob.type = RDP_LICENSE_BLOB_CLIENT_MACHINE_NAME;
        machine_blob.length = (uint16_t)machine_len;
        machine_blob.data = (const uint8_t*)safe_machine;
        status = rdp_license_write_client_new_license_request(output,
                                                              request->preamble.version,
                                                              RDP_LICENSE_KEY_EXCHANGE_RSA,
                                                              RDP_LICENSE_PLATFORM_ID_CLIENT,
                                                              next.client_random,
                                                              &encrypted_blob,
                                                              &user_blob,
                                                              &machine_blob);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_license_crypto_context_clear(context);
        next.ready = 1;
        *context = next;
        OPENSSL_cleanse(&next, sizeof(next));
    }
    else
        rdp_license_crypto_context_clear(&next);

    if (encrypted_premaster.data)
        OPENSSL_cleanse(encrypted_premaster.data, encrypted_premaster.length);
    rdp_buffer_free(&encrypted_premaster);
    rdp_security_public_key_clear(&public_key);
    return status;
}

/*
 * Purpose: answer a server Platform Challenge using the negotiated licensing
 * key material from the preceding License Request.
 * Invariants: encrypted challenge data is decrypted with a fresh RC4 instance,
 * authenticated against the server MAC before reuse, and response MAC covers
 * the exact plaintext response plus CLIENT_HARDWARE_ID bytes.
 * Failure policy: reject out-of-order challenges as protocol errors, cleanse
 * plaintext challenge/response buffers and MAC scratch space, and emit no
 * partially serialized response on authentication or allocation failure.
 */
librdp_status rdp_license_build_platform_challenge_response(rdp_license_crypto_context* context,
                                                            const rdp_license_platform_challenge* challenge,
                                                            rdp_buffer* output)
{
    rdp_buffer plain_challenge;
    rdp_buffer response_data;
    rdp_buffer mac_input;
    rdp_buffer encrypted_response;
    rdp_buffer encrypted_hardware;
    rdp_license_binary_blob response_blob;
    rdp_license_binary_blob hardware_blob;
    uint8_t expected_mac[RDP_LICENSE_MAC_LEN];
    uint8_t response_mac[RDP_LICENSE_MAC_LEN];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !challenge || !output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!context->ready || challenge->encrypted_challenge.type != RDP_LICENSE_BLOB_ENCRYPTED_DATA)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_buffer_init(&plain_challenge);
    rdp_buffer_init(&response_data);
    rdp_buffer_init(&mac_input);
    rdp_buffer_init(&encrypted_response);
    rdp_buffer_init(&encrypted_hardware);
    memset(expected_mac, 0, sizeof(expected_mac));
    memset(response_mac, 0, sizeof(response_mac));

    status = rdp_security_license_crypt(context->encryption_key,
                                        challenge->encrypted_challenge.data,
                                        challenge->encrypted_challenge.length,
                                        &plain_challenge);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_license_mac(context->mac_salt_key,
                                          plain_challenge.data,
                                          plain_challenge.length,
                                          expected_mac);
    if (status == LIBRDP_STATUS_OK &&
        CRYPTO_memcmp(expected_mac, challenge->mac, sizeof(expected_mac)) != 0)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_license_build_response_data(&plain_challenge, &response_data);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&mac_input, response_data.data, response_data.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&mac_input, context->hardware_id, sizeof(context->hardware_id));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_license_mac(context->mac_salt_key,
                                          mac_input.data,
                                          mac_input.length,
                                          response_mac);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_license_crypt(context->encryption_key,
                                            response_data.data,
                                            response_data.length,
                                            &encrypted_response);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_license_crypt(context->encryption_key,
                                            context->hardware_id,
                                            sizeof(context->hardware_id),
                                            &encrypted_hardware);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_license_blob_from_buffer(&response_blob,
                                              RDP_LICENSE_BLOB_ENCRYPTED_DATA,
                                              &encrypted_response);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_license_blob_from_buffer(&hardware_blob,
                                              RDP_LICENSE_BLOB_ENCRYPTED_DATA,
                                              &encrypted_hardware);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_license_write_platform_challenge_response(output,
                                                               challenge->preamble.version,
                                                               &response_blob,
                                                               &hardware_blob,
                                                               response_mac);

    if (plain_challenge.data)
        OPENSSL_cleanse(plain_challenge.data, plain_challenge.length);
    if (response_data.data)
        OPENSSL_cleanse(response_data.data, response_data.length);
    if (mac_input.data)
        OPENSSL_cleanse(mac_input.data, mac_input.length);
    if (encrypted_response.data)
        OPENSSL_cleanse(encrypted_response.data, encrypted_response.length);
    if (encrypted_hardware.data)
        OPENSSL_cleanse(encrypted_hardware.data, encrypted_hardware.length);
    OPENSSL_cleanse(expected_mac, sizeof(expected_mac));
    OPENSSL_cleanse(response_mac, sizeof(response_mac));
    rdp_buffer_free(&encrypted_hardware);
    rdp_buffer_free(&encrypted_response);
    rdp_buffer_free(&mac_input);
    rdp_buffer_free(&response_data);
    rdp_buffer_free(&plain_challenge);
    return status;
}
