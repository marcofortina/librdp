#include "protocol/gcc.h"

#include <string.h>

static librdp_status rdp_gcc_write_per_length(rdp_buffer* buffer, size_t length)
{
    if (!buffer || length > 0x7fffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length > 0x7fu)
        return rdp_buffer_append_u16_be(buffer, (uint16_t)(length | 0x8000u));
    return rdp_buffer_append_u8(buffer, (uint8_t)length);
}

static librdp_status rdp_gcc_read_per_length(rdp_stream* stream, size_t* length)
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

static librdp_status rdp_gcc_read_per_integer(rdp_stream* stream, uint32_t* value)
{
    size_t length = 0;
    uint8_t u8 = 0;
    uint16_t u16 = 0;
    uint32_t u32 = 0;

    if (!stream || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_gcc_read_per_length(stream, &length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (length == 1)
    {
        if (rdp_stream_read_u8(stream, &u8) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *value = u8;
        return LIBRDP_STATUS_OK;
    }
    if (length == 2)
    {
        if (rdp_stream_read_u16_be(stream, &u16) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *value = u16;
        return LIBRDP_STATUS_OK;
    }
    if (length == 4)
    {
        if (rdp_stream_read_u32_be(stream, &u32) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *value = u32;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_gcc_read_per_integer16(rdp_stream* stream, uint16_t min, uint16_t* value)
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

static librdp_status rdp_gcc_read_per_octet_string(rdp_stream* stream,
                                                   const uint8_t* expected,
                                                   size_t expected_len,
                                                   size_t min)
{
    size_t length = 0;
    const uint8_t* value = NULL;

    if (!stream || (!expected && expected_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_gcc_read_per_length(stream, &length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (length + min != expected_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(stream, &value, expected_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (expected_len > 0 && memcmp(value, expected, expected_len) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gcc_read_object_identifier(rdp_stream* stream, const uint8_t* expected, size_t expected_len)
{
    const uint8_t* value = NULL;

    if (!stream || !expected || expected_len == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_bytes(stream, &value, expected_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (memcmp(value, expected, expected_len) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gcc_write_per_octet_string(rdp_buffer* buffer, const void* data, size_t length, size_t min)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t encoded_len = 0;

    if (!buffer || (!data && length > 0) || length > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    encoded_len = length >= min ? length - min : min;
    status = rdp_gcc_write_per_length(buffer, encoded_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, length);
}

static librdp_status rdp_gcc_write_per_numeric_string(rdp_buffer* buffer, const char* text, size_t length, size_t min)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t encoded_len = length >= min ? length - min : min;
    size_t i = 0;

    if (!buffer || !text)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_gcc_write_per_length(buffer, encoded_len);
    if (status != LIBRDP_STATUS_OK)
        return status;

    for (i = 0; i < length; i += 2u)
    {
        uint8_t c1 = (uint8_t)text[i];
        uint8_t c2 = (i + 1u < length) ? (uint8_t)text[i + 1u] : (uint8_t)'0';
        if (c1 < (uint8_t)'0' || c1 > (uint8_t)'9' || c2 < (uint8_t)'0' || c2 > (uint8_t)'9')
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        status = rdp_buffer_append_u8(buffer, (uint8_t)(((c1 - (uint8_t)'0') << 4) | (c2 - (uint8_t)'0')));
        if (status != LIBRDP_STATUS_OK)
            return status;
    }

    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gcc_write_block(rdp_buffer* buffer, uint16_t type, const rdp_buffer* payload)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t total = 0;

    if (!buffer || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    total = payload->length + 4u;
    if (total > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u16_le(buffer, type);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)total);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, payload->data, payload->length);
}

static librdp_status rdp_gcc_write_utf16le_fixed(rdp_buffer* buffer, const char* text, size_t bytes)
{
    size_t i = 0;
    size_t chars = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || bytes % 2u != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    chars = bytes / 2u;
    for (i = 0; i < chars; i++)
    {
        uint16_t ch = 0;
        if (text && text[i] != '\0' && i + 1u < chars)
            ch = (uint8_t)text[i];
        status = rdp_buffer_append_u16_le(buffer, ch);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gcc_write_client_core(rdp_buffer* buffer, const rdp_gcc_client_config* config)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t client_version = RDP_GCC_CLIENT_VERSION_5;
    uint16_t early_capability_flags = RDP_GCC_EARLY_SUPPORT_ERRINFO;
    uint8_t connection_type = RDP_GCC_CONNECTION_TYPE_LAN;

    if (config->client_version != 0)
        client_version = config->client_version;
    if (config->early_capability_flags != 0)
        early_capability_flags = config->early_capability_flags;
    if (config->connection_type != 0)
        connection_type = config->connection_type;

    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, client_version);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, config->desktop_width);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, config->desktop_height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 0xca01u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 0xaa03u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 0x00000409u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 2600);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_write_utf16le_fixed(&payload, config->client_name ? config->client_name : "librdp", 32);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 4);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 12);
    if (status == LIBRDP_STATUS_OK)
    {
        uint8_t zeros[64];
        memset(zeros, 0, sizeof(zeros));
        status = rdp_buffer_append(&payload, zeros, sizeof(zeros));
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 0xca01u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 0x0018u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 0x0007u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, early_capability_flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_write_utf16le_fixed(&payload, "librdp", 64);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&payload, connection_type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&payload, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, config->requested_protocols);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 100);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 100);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_write_block(buffer, RDP_GCC_CS_CORE, &payload);

    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_gcc_write_client_security(rdp_buffer* buffer)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, 0x0000000bu);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_write_block(buffer, RDP_GCC_CS_SECURITY, &payload);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_gcc_write_client_network(rdp_buffer* buffer, const rdp_gcc_client_config* config)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!config)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, config->enable_dynamic_channels ? 1u : 0u);
    if (status == LIBRDP_STATUS_OK)
    {
        static const uint8_t name[8] = {'d', 'r', 'd', 'y', 'n', 'v', 'c', 0};
        if (config->enable_dynamic_channels)
            status = rdp_buffer_append(&payload, name, sizeof(name));
    }
    if (status == LIBRDP_STATUS_OK && config->enable_dynamic_channels)
        status = rdp_buffer_append_u32_le(&payload, 0x80800000u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_write_block(buffer, RDP_GCC_CS_NETWORK, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_gcc_write_client_data_blocks(rdp_buffer* buffer, const rdp_gcc_client_config* config)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !config || config->desktop_width == 0 || config->desktop_height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_gcc_write_client_core(buffer, config);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_write_client_security(buffer);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_write_client_network(buffer, config);
    return status;
}

librdp_status rdp_gcc_write_conference_create_request(rdp_buffer* buffer, const void* user_data, size_t user_data_len)
{
    static const uint8_t oid[] = {5, 0, 20, 124, 0, 1};
    static const uint8_t key[] = {'D', 'u', 'c', 'a'};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!user_data && user_data_len > 0) || user_data_len > 0xffffu - 14u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, oid, sizeof(oid));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_write_per_length(buffer, user_data_len + 14u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0x08);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_write_per_numeric_string(buffer, "1", 1, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0xc0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_write_per_octet_string(buffer, key, sizeof(key), sizeof(key));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_write_per_octet_string(buffer, user_data, user_data_len, 0);
    return status;
}

librdp_status rdp_gcc_parse_conference_create_response(const void* data,
                                                       size_t length,
                                                       rdp_gcc_conference_response* response)
{
    static const uint8_t oid[] = {5, 0, 20, 124, 0, 1};
    static const uint8_t key[] = {'M', 'c', 'D', 'n'};
    rdp_stream stream;
    uint8_t choice = 0;
    uint8_t result = 0;
    uint8_t set_count = 0;
    size_t connect_len = 0;
    size_t user_len = 0;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(response, 0, sizeof(*response));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &choice) != LIBRDP_STATUS_OK || choice != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_gcc_read_object_identifier(&stream, oid, sizeof(oid)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_gcc_read_per_length(&stream, &connect_len) != LIBRDP_STATUS_OK || connect_len > rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u8(&stream, &choice) != LIBRDP_STATUS_OK || choice != 0x14)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_gcc_read_per_integer16(&stream, 1001, &response->node_id) != LIBRDP_STATUS_OK ||
        rdp_gcc_read_per_integer(&stream, &response->tag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &result) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &set_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    response->result = result;
    if (set_count != 1)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u8(&stream, &choice) != LIBRDP_STATUS_OK || choice != 0xc0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_gcc_read_per_octet_string(&stream, key, sizeof(key), sizeof(key)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_gcc_read_per_length(&stream, &user_len) != LIBRDP_STATUS_OK || user_len > rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &response->user_data, user_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    response->user_data_len = user_len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_gcc_read_user_data_block(rdp_stream* stream, rdp_gcc_user_data_block* block)
{
    if (!stream || !block)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_remaining(stream) < 4)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(block, 0, sizeof(*block));
    if (rdp_stream_read_u16_le(stream, &block->type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &block->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (block->length < 4 || rdp_stream_remaining(stream) < (size_t)block->length - 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    block->payload_len = (size_t)block->length - 4u;
    return rdp_stream_read_bytes(stream, &block->payload, block->payload_len);
}

librdp_status rdp_gcc_parse_server_data_blocks(const void* data, size_t length, rdp_gcc_server_data* server_data)
{
    rdp_stream stream;

    if (!data || !server_data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(server_data, 0, sizeof(*server_data));
    rdp_stream_init(&stream, data, length);
    while (rdp_stream_remaining(&stream) > 0)
    {
        rdp_gcc_user_data_block block;
        rdp_stream payload;

        if (rdp_gcc_read_user_data_block(&stream, &block) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        rdp_stream_init(&payload, block.payload, block.payload_len);

        if (block.type == RDP_GCC_SC_CORE)
        {
            if (rdp_stream_read_u32_le(&payload, &server_data->version) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (rdp_stream_remaining(&payload) >= 4 &&
                rdp_stream_read_u32_le(&payload, &server_data->requested_protocols) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (rdp_stream_remaining(&payload) >= 4 &&
                rdp_stream_read_u32_le(&payload, &server_data->early_capability_flags) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            server_data->has_core = 1;
        }
        else if (block.type == RDP_GCC_SC_SECURITY)
        {
            if (rdp_stream_read_u32_le(&payload, &server_data->encryption_method) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u32_le(&payload, &server_data->encryption_level) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (server_data->encryption_method != 0 || server_data->encryption_level != 0)
            {
                if (rdp_stream_read_u32_le(&payload, &server_data->server_random_len) != LIBRDP_STATUS_OK ||
                    rdp_stream_read_u32_le(&payload, &server_data->server_certificate_len) != LIBRDP_STATUS_OK)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                if (server_data->server_random_len == 0 || server_data->server_certificate_len == 0 ||
                    rdp_stream_remaining(&payload) <
                        (size_t)server_data->server_random_len + server_data->server_certificate_len)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                if (rdp_stream_read_bytes(&payload, &server_data->server_random, server_data->server_random_len) !=
                        LIBRDP_STATUS_OK ||
                    rdp_stream_read_bytes(&payload,
                                          &server_data->server_certificate,
                                          server_data->server_certificate_len) != LIBRDP_STATUS_OK)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            server_data->has_security = 1;
        }
        else if (block.type == RDP_GCC_SC_NETWORK)
        {
            uint16_t i = 0;
            if (rdp_stream_read_u16_le(&payload, &server_data->mcs_channel_id) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u16_le(&payload, &server_data->channel_count) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (server_data->channel_count > RDP_GCC_MAX_SERVER_CHANNELS)
                return LIBRDP_STATUS_UNSUPPORTED;
            if (rdp_stream_remaining(&payload) < (size_t)server_data->channel_count * 2u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            for (i = 0; i < server_data->channel_count; i++)
            {
                if (rdp_stream_read_u16_le(&payload, &server_data->channel_ids[i]) != LIBRDP_STATUS_OK)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            server_data->has_network = 1;
        }
    }

    return server_data->has_core && server_data->has_security ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_gcc_parse_client_data_blocks(const void* data, size_t length, rdp_gcc_client_data_summary* summary)
{
    rdp_stream stream;

    if (!data || !summary)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(summary, 0, sizeof(*summary));
    rdp_stream_init(&stream, data, length);
    while (rdp_stream_remaining(&stream) > 0)
    {
        rdp_gcc_user_data_block block;
        rdp_stream payload;
        uint32_t ignored32 = 0;
        uint16_t ignored16 = 0;

        if (rdp_gcc_read_user_data_block(&stream, &block) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;

        rdp_stream_init(&payload, block.payload, block.payload_len);
        if (block.type == RDP_GCC_CS_CORE)
        {
            if (rdp_stream_read_u32_le(&payload, &summary->version) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u16_le(&payload, &summary->desktop_width) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u16_le(&payload, &summary->desktop_height) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            summary->has_core = 1;
            if (block.payload_len >= 212)
            {
                payload.position = 208;
                if (rdp_stream_read_u32_le(&payload, &summary->requested_protocols) != LIBRDP_STATUS_OK)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            if (block.payload_len >= 142)
            {
                payload.position = 140;
                if (rdp_stream_read_u16_le(&payload, &summary->early_capability_flags) != LIBRDP_STATUS_OK)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            if (block.payload_len >= 207)
            {
                payload.position = 206;
                if (rdp_stream_read_u8(&payload, &summary->connection_type) != LIBRDP_STATUS_OK)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
            }
        }
        else if (block.type == RDP_GCC_CS_SECURITY)
        {
            if (rdp_stream_read_u32_le(&payload, &ignored32) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u32_le(&payload, &ignored32) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            summary->has_security = 1;
        }
        else if (block.type == RDP_GCC_CS_NETWORK)
        {
            if (rdp_stream_read_u16_le(&payload, &summary->channel_count) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u16_le(&payload, &ignored16) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            summary->has_network = 1;
        }
    }

    return summary->has_core && summary->has_security && summary->has_network ? LIBRDP_STATUS_OK
                                                                              : LIBRDP_STATUS_PROTOCOL_ERROR;
}
