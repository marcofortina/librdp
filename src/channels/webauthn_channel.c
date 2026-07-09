#include "channels/webauthn_channel.h"

#include "common/stream.h"

#include <string.h>

typedef struct rdp_webauthn_cbor_item
{
    uint8_t major;
    uint64_t value;
    size_t header_len;
} rdp_webauthn_cbor_item;

static int rdp_webauthn_key_equals(const uint8_t* data, size_t length, const char* value)
{
    size_t value_len = value ? strlen(value) : 0;

    return data && value && length == value_len && memcmp(data, value, length) == 0;
}

static librdp_status rdp_webauthn_cbor_read_item(const uint8_t* data,
                                                 size_t length,
                                                 rdp_webauthn_cbor_item* item)
{
    uint8_t ai = 0;

    if (!data || !item || length == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(item, 0, sizeof(*item));
    item->major = (uint8_t)(data[0] >> 5);
    ai = (uint8_t)(data[0] & 0x1fu);
    item->header_len = 1;
    if (ai < 24u)
    {
        item->value = ai;
        return LIBRDP_STATUS_OK;
    }
    if (ai == 24u)
    {
        if (length < 2u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        item->value = data[1];
        item->header_len = 2;
        return LIBRDP_STATUS_OK;
    }
    if (ai == 25u)
    {
        if (length < 3u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        item->value = ((uint64_t)data[1] << 8) | data[2];
        item->header_len = 3;
        return LIBRDP_STATUS_OK;
    }
    if (ai == 26u)
    {
        if (length < 5u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        item->value = ((uint64_t)data[1] << 24) | ((uint64_t)data[2] << 16) |
                      ((uint64_t)data[3] << 8) | data[4];
        item->header_len = 5;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_UNSUPPORTED;
}

static librdp_status rdp_webauthn_cbor_skip(const uint8_t* data,
                                            size_t length,
                                            size_t* consumed,
                                            unsigned depth)
{
    rdp_webauthn_cbor_item item;
    size_t offset = 0;
    uint64_t i = 0;

    if (!data || !consumed || depth > 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_webauthn_cbor_read_item(data, length, &item) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (item.major == 0 || item.major == 1 || item.major == 7)
    {
        *consumed = item.header_len;
        return LIBRDP_STATUS_OK;
    }
    if (item.major == 2 || item.major == 3)
    {
        if (item.value > SIZE_MAX || item.header_len > length ||
            (size_t)item.value > length - item.header_len)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *consumed = item.header_len + (size_t)item.value;
        return LIBRDP_STATUS_OK;
    }
    if (item.major == 4)
    {
        offset = item.header_len;
        for (i = 0; i < item.value; i++)
        {
            size_t child = 0;
            if (offset > length ||
                rdp_webauthn_cbor_skip(data + offset, length - offset, &child, depth + 1u) !=
                    LIBRDP_STATUS_OK ||
                child > length - offset)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            offset += child;
        }
        *consumed = offset;
        return LIBRDP_STATUS_OK;
    }
    if (item.major == 5)
    {
        offset = item.header_len;
        for (i = 0; i < item.value; i++)
        {
            size_t key_len = 0;
            size_t value_len = 0;
            if (offset > length ||
                rdp_webauthn_cbor_skip(data + offset, length - offset, &key_len, depth + 1u) !=
                    LIBRDP_STATUS_OK ||
                key_len > length - offset)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            offset += key_len;
            if (offset > length ||
                rdp_webauthn_cbor_skip(data + offset, length - offset, &value_len, depth + 1u) !=
                    LIBRDP_STATUS_OK ||
                value_len > length - offset)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            offset += value_len;
        }
        *consumed = offset;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_UNSUPPORTED;
}

static librdp_status rdp_webauthn_cbor_read_uint(const uint8_t* data,
                                                 size_t length,
                                                 uint32_t* value,
                                                 size_t* consumed)
{
    rdp_webauthn_cbor_item item;

    if (!data || !value || !consumed)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_webauthn_cbor_read_item(data, length, &item) != LIBRDP_STATUS_OK ||
        item.major != 0 ||
        item.value > UINT32_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = (uint32_t)item.value;
    *consumed = item.header_len;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_webauthn_cbor_read_slice(const uint8_t* data,
                                                  size_t length,
                                                  uint8_t expected_major,
                                                  const uint8_t** value,
                                                  size_t* value_len,
                                                  size_t* consumed)
{
    rdp_webauthn_cbor_item item;

    if (!data || !value || !value_len || !consumed)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_webauthn_cbor_read_item(data, length, &item) != LIBRDP_STATUS_OK ||
        item.major != expected_major ||
        item.value > SIZE_MAX ||
        item.header_len > length ||
        (size_t)item.value > length - item.header_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = data + item.header_len;
    *value_len = (size_t)item.value;
    *consumed = item.header_len + (size_t)item.value;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_webauthn_write_type_len(rdp_buffer* buffer, uint8_t major, size_t length)
{
    if (!buffer || major > 7u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 24u)
        return rdp_buffer_append_u8(buffer, (uint8_t)((major << 5) | (uint8_t)length));
    if (length <= UINT8_MAX)
    {
        librdp_status status = rdp_buffer_append_u8(buffer, (uint8_t)((major << 5) | 24u));
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_buffer_append_u8(buffer, (uint8_t)length);
    }
    if (length <= UINT16_MAX)
    {
        librdp_status status = rdp_buffer_append_u8(buffer, (uint8_t)((major << 5) | 25u));
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_buffer_append_u16_be(buffer, (uint16_t)length);
    }
    if (length <= UINT32_MAX)
    {
        librdp_status status = rdp_buffer_append_u8(buffer, (uint8_t)((major << 5) | 26u));
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_buffer_append_u32_be(buffer, (uint32_t)length);
    }
    return LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status rdp_webauthn_write_text(rdp_buffer* buffer, const char* text)
{
    size_t length = text ? strlen(text) : 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !text || length > RDP_WEBAUTHN_MAX_MESSAGE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_webauthn_write_type_len(buffer, 3, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, text, length);
}

static librdp_status rdp_webauthn_write_uint(rdp_buffer* buffer, uint32_t value)
{
    if (value < 24u)
        return rdp_buffer_append_u8(buffer, (uint8_t)value);
    if (value <= UINT8_MAX)
    {
        librdp_status status = rdp_buffer_append_u8(buffer, 0x18u);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_buffer_append_u8(buffer, (uint8_t)value);
    }
    if (value <= UINT16_MAX)
    {
        librdp_status status = rdp_buffer_append_u8(buffer, 0x19u);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_buffer_append_u16_be(buffer, (uint16_t)value);
    }
    {
        librdp_status status = rdp_buffer_append_u8(buffer, 0x1au);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_buffer_append_u32_be(buffer, value);
    }
}

static librdp_status rdp_webauthn_write_bytes(rdp_buffer* buffer, const void* data, size_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && length > 0) || length > RDP_WEBAUTHN_MAX_MESSAGE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_webauthn_write_type_len(buffer, 2, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, length);
}

int rdp_webauthn_command_valid(uint32_t command)
{
    return command == RDP_WEBAUTHN_COMMAND_WEB_AUTHN ||
           command == RDP_WEBAUTHN_COMMAND_IUVPAA ||
           command == RDP_WEBAUTHN_COMMAND_CANCEL ||
           command == RDP_WEBAUTHN_COMMAND_API_VERSION ||
           command == RDP_WEBAUTHN_COMMAND_GET_CREDENTIALS ||
           command == RDP_WEBAUTHN_COMMAND_GET_AUTHENTICATOR_LIST;
}

int rdp_webauthn_flags_valid(uint32_t flags)
{
    return (flags & ~RDP_WEBAUTHN_FLAG_KNOWN_MASK) == 0;
}

librdp_status rdp_webauthn_parse_request(const void* data,
                                         size_t length,
                                         rdp_webauthn_request* request)
{
    rdp_webauthn_cbor_item map;
    const uint8_t* input = (const uint8_t*)data;
    size_t offset = 0;
    uint64_t i = 0;
    uint8_t has_command = 0;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length == 0 || length > RDP_WEBAUTHN_MAX_MESSAGE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(request, 0, sizeof(*request));
    if (rdp_webauthn_cbor_read_item(input, length, &map) != LIBRDP_STATUS_OK ||
        map.major != 5)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    offset = map.header_len;
    for (i = 0; i < map.value; i++)
    {
        const uint8_t* key = NULL;
        size_t key_len = 0;
        size_t key_consumed = 0;
        size_t value_consumed = 0;

        if (offset > length ||
            rdp_webauthn_cbor_read_slice(input + offset,
                                         length - offset,
                                         3,
                                         &key,
                                         &key_len,
                                         &key_consumed) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        offset += key_consumed;
        if (offset > length)
            return LIBRDP_STATUS_PROTOCOL_ERROR;

        if (rdp_webauthn_key_equals(key, key_len, "command"))
        {
            if (rdp_webauthn_cbor_read_uint(input + offset,
                                            length - offset,
                                            &request->command,
                                            &value_consumed) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            has_command = 1;
        }
        else if (rdp_webauthn_key_equals(key, key_len, "flags"))
        {
            if (rdp_webauthn_cbor_read_uint(input + offset,
                                            length - offset,
                                            &request->flags,
                                            &value_consumed) != LIBRDP_STATUS_OK ||
                !rdp_webauthn_flags_valid(request->flags))
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            request->has_flags = 1;
        }
        else if (rdp_webauthn_key_equals(key, key_len, "request"))
        {
            if (rdp_webauthn_cbor_read_slice(input + offset,
                                             length - offset,
                                             2,
                                             &request->request,
                                             &request->request_len,
                                             &value_consumed) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (rdp_webauthn_key_equals(key, key_len, "rpId"))
        {
            if (rdp_webauthn_cbor_read_slice(input + offset,
                                             length - offset,
                                             3,
                                             &request->rp_id,
                                             &request->rp_id_len,
                                             &value_consumed) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (rdp_webauthn_key_equals(key, key_len, "transactionid"))
        {
            if (rdp_webauthn_cbor_read_slice(input + offset,
                                             length - offset,
                                             2,
                                             &request->transaction_id,
                                             &request->transaction_id_len,
                                             &value_consumed) != LIBRDP_STATUS_OK ||
                request->transaction_id_len != RDP_WEBAUTHN_GUID_LENGTH)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else
        {
            if (rdp_webauthn_cbor_skip(input + offset,
                                       length - offset,
                                       &value_consumed,
                                       0) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (value_consumed > length - offset)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        offset += value_consumed;
    }

    if (offset != length || !has_command || !rdp_webauthn_command_valid(request->command))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->command == RDP_WEBAUTHN_COMMAND_WEB_AUTHN)
    {
        if (!request->request || request->request_len < 1u ||
            (request->request[0] != RDP_WEBAUTHN_CMD_MAKE_CREDENTIAL &&
             request->request[0] != RDP_WEBAUTHN_CMD_GET_ASSERTION))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (request->command == RDP_WEBAUTHN_COMMAND_CANCEL &&
        (!request->request || request->request_len != RDP_WEBAUTHN_GUID_LENGTH))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_webauthn_write_request(rdp_buffer* buffer,
                                         uint32_t command,
                                         uint32_t flags,
                                         const void* request_data,
                                         size_t request_len,
                                         const char* rp_id,
                                         const void* transaction_id)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t pairs = 1u;

    if (!buffer || !rdp_webauthn_command_valid(command) ||
        !rdp_webauthn_flags_valid(flags) ||
        (!request_data && request_len > 0) ||
        request_len > RDP_WEBAUTHN_MAX_MESSAGE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (flags != 0)
        pairs++;
    if (request_len > 0)
        pairs++;
    if (rp_id)
        pairs++;
    if (transaction_id)
        pairs++;
    if (command == RDP_WEBAUTHN_COMMAND_CANCEL &&
        (!request_data || request_len != RDP_WEBAUTHN_GUID_LENGTH))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (command == RDP_WEBAUTHN_COMMAND_WEB_AUTHN &&
        (!request_data || request_len < 1u ||
         (((const uint8_t*)request_data)[0] != RDP_WEBAUTHN_CMD_MAKE_CREDENTIAL &&
          ((const uint8_t*)request_data)[0] != RDP_WEBAUTHN_CMD_GET_ASSERTION)))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_webauthn_write_type_len(buffer, 5, pairs);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_webauthn_write_text(buffer, "command");
    if (status == LIBRDP_STATUS_OK)
        status = rdp_webauthn_write_uint(buffer, command);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (flags != 0)
    {
        status = rdp_webauthn_write_text(buffer, "flags");
        if (status == LIBRDP_STATUS_OK)
            status = rdp_webauthn_write_uint(buffer, flags);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (request_len > 0)
    {
        status = rdp_webauthn_write_text(buffer, "request");
        if (status == LIBRDP_STATUS_OK)
            status = rdp_webauthn_write_bytes(buffer, request_data, request_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (rp_id)
    {
        status = rdp_webauthn_write_text(buffer, "rpId");
        if (status == LIBRDP_STATUS_OK)
            status = rdp_webauthn_write_text(buffer, rp_id);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (transaction_id)
    {
        status = rdp_webauthn_write_text(buffer, "transactionid");
        if (status == LIBRDP_STATUS_OK)
            status = rdp_webauthn_write_bytes(buffer, transaction_id, RDP_WEBAUTHN_GUID_LENGTH);
    }
    return status;
}

librdp_status rdp_webauthn_parse_response(const void* data,
                                          size_t length,
                                          rdp_webauthn_response* response)
{
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u || length > RDP_WEBAUTHN_MAX_MESSAGE + 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(response, 0, sizeof(*response));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &response->hresult) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    response->payload_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &response->payload, response->payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_webauthn_write_response(rdp_buffer* buffer,
                                          uint32_t hresult,
                                          const void* payload,
                                          size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!payload && payload_len > 0) ||
        payload_len > RDP_WEBAUTHN_MAX_MESSAGE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, hresult);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, payload, payload_len);
}

librdp_status rdp_webauthn_parse_u32_response(const rdp_webauthn_response* response,
                                              uint32_t* value)
{
    if (!response || !value || !response->payload || response->payload_len != 4u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *value = (uint32_t)response->payload[0] |
             ((uint32_t)response->payload[1] << 8) |
             ((uint32_t)response->payload[2] << 16) |
             ((uint32_t)response->payload[3] << 24);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_webauthn_write_u32_response(rdp_buffer* buffer, uint32_t hresult, uint32_t value)
{
    uint8_t payload[4];

    payload[0] = (uint8_t)(value & 0xffu);
    payload[1] = (uint8_t)((value >> 8) & 0xffu);
    payload[2] = (uint8_t)((value >> 16) & 0xffu);
    payload[3] = (uint8_t)((value >> 24) & 0xffu);
    return rdp_webauthn_write_response(buffer, hresult, payload, sizeof(payload));
}
