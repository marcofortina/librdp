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

    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, 0x00080004u);
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
        status = rdp_buffer_append_u16_le(&payload, 0x0001u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_write_utf16le_fixed(&payload, "librdp", 64);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&payload, 6);
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

static librdp_status rdp_gcc_write_client_network(rdp_buffer* buffer)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u16_le(&payload, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 0);
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
        status = rdp_gcc_write_client_network(buffer);
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
