#include "protocol/bulk.h"

#include <stdlib.h>
#include <string.h>

typedef struct rdp_bulk_bit_reader
{
    const uint8_t* data;
    size_t length;
    size_t bit;
} rdp_bulk_bit_reader;

#define RDP_BULK_RDP61_L1_COMPRESSED 0x01u
#define RDP_BULK_RDP61_L1_NO_COMPRESSION 0x02u
#define RDP_BULK_RDP61_L1_PACKET_AT_FRONT 0x04u
#define RDP_BULK_RDP61_L1_INNER_COMPRESSION 0x10u
#define RDP_BULK_RDP61_L1_KNOWN_MASK 0x17u
#define RDP_BULK_RDP61_MATCH_SIZE 8u

static void rdp_bulk_mppc_state_init(rdp_bulk_mppc_state* state, uint8_t level)
{
    if (!state)
        return;
    state->history = NULL;
    state->history_size = level ? 65536u : 8192u;
    state->write_offset = 0;
    state->level = level;
}

static void rdp_bulk_mppc_state_reset(rdp_bulk_mppc_state* state, int clear)
{
    if (!state)
        return;
    state->write_offset = 0;
    if (clear && state->history)
        memset(state->history, 0, state->history_size);
}

static void rdp_bulk_rdp61_state_init(rdp_bulk_rdp61_state* state)
{
    if (!state)
        return;
    state->history = NULL;
    state->write_offset = 0;
}

static void rdp_bulk_rdp61_state_reset(rdp_bulk_rdp61_state* state, int clear)
{
    if (!state)
        return;
    state->write_offset = 0;
    if (clear && state->history)
        memset(state->history, 0, RDP_BULK_RDP61_HISTORY_SIZE);
}

static void rdp_bulk_mppc_state_free(rdp_bulk_mppc_state* state)
{
    if (!state)
        return;
    free(state->history);
    state->history = NULL;
    state->write_offset = 0;
}

static void rdp_bulk_rdp61_state_free(rdp_bulk_rdp61_state* state)
{
    if (!state)
        return;
    free(state->history);
    state->history = NULL;
    state->write_offset = 0;
}

static librdp_status rdp_bulk_mppc_state_ensure(rdp_bulk_mppc_state* state)
{
    if (!state || state->history_size == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (state->history)
        return LIBRDP_STATUS_OK;
    state->history = (uint8_t*)calloc(1, state->history_size);
    if (!state->history)
        return LIBRDP_STATUS_NO_MEMORY;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bulk_rdp61_state_ensure(rdp_bulk_rdp61_state* state)
{
    if (!state)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (state->history)
        return LIBRDP_STATUS_OK;
    state->history = (uint8_t*)calloc(1, RDP_BULK_RDP61_HISTORY_SIZE);
    if (!state->history)
        return LIBRDP_STATUS_NO_MEMORY;
    return LIBRDP_STATUS_OK;
}

static size_t rdp_bulk_bits_remaining(const rdp_bulk_bit_reader* reader)
{
    size_t total = 0;

    if (!reader || reader->length > SIZE_MAX / 8u)
        return 0;
    total = reader->length * 8u;
    if (reader->bit > total)
        return 0;
    return total - reader->bit;
}

static librdp_status rdp_bulk_read_bits(rdp_bulk_bit_reader* reader, uint8_t count, uint32_t* value)
{
    uint32_t result = 0;
    uint8_t i = 0;

    if (!reader || !value || count > 31u || rdp_bulk_bits_remaining(reader) < count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < count; i++)
    {
        size_t byte_index = reader->bit / 8u;
        uint8_t bit_index = (uint8_t)(7u - (reader->bit & 7u));
        uint8_t bit = (uint8_t)((reader->data[byte_index] >> bit_index) & 1u);

        result = (result << 1u) | bit;
        reader->bit++;
    }
    *value = result;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bulk_read_prefixed_value(rdp_bulk_bit_reader* reader,
                                                  const uint8_t* value_bits,
                                                  const uint32_t* bases,
                                                  size_t count,
                                                  uint32_t* value)
{
    uint32_t prefix = 0;
    size_t i = 0;

    if (!reader || !value_bits || !bases || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < count; i++)
    {
        uint32_t bit = 0;
        uint32_t low = 0;

        if (rdp_bulk_read_bits(reader, 1, &bit) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        prefix = (prefix << 1u) | bit;
        if (bit == 1u)
            continue;
        if (value_bits[i] > 0 &&
            rdp_bulk_read_bits(reader, value_bits[i], &low) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *value = bases[i] + low;
        return LIBRDP_STATUS_OK;
    }
    (void)prefix;
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_bulk_mppc_read_offset(rdp_bulk_bit_reader* reader,
                                               uint8_t level,
                                               uint32_t* offset)
{
    uint32_t first = 0;
    uint32_t second = 0;
    uint32_t bit = 0;
    uint32_t low = 0;

    if (!reader || !offset)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_bulk_read_bits(reader, 1, &first) != LIBRDP_STATUS_OK ||
        rdp_bulk_read_bits(reader, 1, &second) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (first != 1u || second != 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_bulk_read_bits(reader, 1, &bit) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (bit == 0)
    {
        uint8_t value_bits = level ? 16u : 13u;
        uint32_t base = level ? 2368u : 320u;

        if (rdp_bulk_read_bits(reader, value_bits, &low) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *offset = base + low;
        return LIBRDP_STATUS_OK;
    }
    if (rdp_bulk_read_bits(reader, 1, &bit) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (bit == 0)
    {
        uint8_t value_bits = level ? 11u : 8u;
        uint32_t base = level ? 320u : 64u;

        if (rdp_bulk_read_bits(reader, value_bits, &low) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *offset = base + low;
        return LIBRDP_STATUS_OK;
    }
    if (level)
    {
        if (rdp_bulk_read_bits(reader, 1, &bit) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (bit == 0)
        {
            if (rdp_bulk_read_bits(reader, 8, &low) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            *offset = 64u + low;
            return LIBRDP_STATUS_OK;
        }
    }
    if (rdp_bulk_read_bits(reader, 6, &low) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *offset = low;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bulk_mppc_read_length(rdp_bulk_bit_reader* reader,
                                               uint8_t level,
                                               uint32_t* length)
{
    static const uint8_t bits_common[] = {0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    static const uint32_t bases_common[] = {
        3, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096
    };
    static const uint8_t bits64k[] = {0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    static const uint32_t bases64k[] = {
        3, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768
    };

    if (level)
        return rdp_bulk_read_prefixed_value(reader, bits64k, bases64k, 15u, length);
    return rdp_bulk_read_prefixed_value(reader, bits_common, bases_common, 12u, length);
}

static librdp_status rdp_bulk_mppc_copy_match(rdp_bulk_mppc_state* state,
                                              uint32_t offset,
                                              uint32_t length)
{
    size_t mask = 0;
    size_t src = 0;
    uint32_t i = 0;

    if (!state || !state->history || length == 0 ||
        state->write_offset > state->history_size ||
        length > state->history_size - state->write_offset)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    mask = state->level ? 0xffffu : 0x1fffu;
    src = (state->write_offset - (size_t)offset) & mask;
    if (src >= state->history_size || length > state->history_size - src)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < length; i++)
        state->history[state->write_offset++] = state->history[src++];
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bulk_mppc_decompress(rdp_bulk_mppc_state* state,
                                              uint8_t flags,
                                              const uint8_t* data,
                                              size_t data_len,
                                              rdp_buffer* decoded)
{
    rdp_bulk_bit_reader reader;
    size_t start = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!state || !data || !decoded)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_bulk_mppc_state_ensure(state);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if ((flags & RDP_BULK_PACKET_AT_FRONT) != 0)
        rdp_bulk_mppc_state_reset(state, 0);
    if ((flags & RDP_BULK_PACKET_FLUSHED) != 0)
        rdp_bulk_mppc_state_reset(state, 1);
    if ((flags & RDP_BULK_PACKET_COMPRESSED) == 0)
        return rdp_buffer_append(decoded, data, data_len);

    start = state->write_offset;
    reader.data = data;
    reader.length = data_len;
    reader.bit = 0;
    while (rdp_bulk_bits_remaining(&reader) >= 8u)
    {
        uint32_t first = 0;
        uint32_t literal = 0;
        uint32_t offset = 0;
        uint32_t length = 0;

        if (state->write_offset >= state->history_size)
        {
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
        }
        status = rdp_bulk_read_bits(&reader, 1, &first);
        if (status != LIBRDP_STATUS_OK)
            break;
        if (first == 0)
        {
            status = rdp_bulk_read_bits(&reader, 7, &literal);
            if (status != LIBRDP_STATUS_OK)
                break;
            state->history[state->write_offset++] = (uint8_t)literal;
            continue;
        }
        status = rdp_bulk_read_bits(&reader, 1, &literal);
        if (status != LIBRDP_STATUS_OK)
            break;
        if (literal == 0)
        {
            status = rdp_bulk_read_bits(&reader, 7, &literal);
            if (status != LIBRDP_STATUS_OK)
                break;
            state->history[state->write_offset++] = (uint8_t)(0x80u + literal);
            continue;
        }
        reader.bit -= 2u;
        status = rdp_bulk_mppc_read_offset(&reader, state->level, &offset);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_bulk_mppc_read_length(&reader, state->level, &length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_bulk_mppc_copy_match(state, offset, length);
        if (status != LIBRDP_STATUS_OK)
            break;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        state->write_offset = start;
        return status;
    }
    return rdp_buffer_append(decoded, state->history + start, state->write_offset - start);
}

static uint16_t rdp_bulk_read_u16_le(const uint8_t* data)
{
    return (uint16_t)(data[0] | ((uint16_t)data[1] << 8u));
}

static uint32_t rdp_bulk_read_u32_le(const uint8_t* data)
{
    return (uint32_t)data[0] |
           ((uint32_t)data[1] << 8u) |
           ((uint32_t)data[2] << 16u) |
           ((uint32_t)data[3] << 24u);
}

static librdp_status rdp_bulk_rdp61_emit(rdp_bulk_rdp61_state* state,
                                         rdp_buffer* decoded,
                                         uint8_t value,
                                         size_t* output_offset)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!state || !decoded || !output_offset)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (state->write_offset >= RDP_BULK_RDP61_HISTORY_SIZE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_buffer_append_u8(decoded, value);
    if (status != LIBRDP_STATUS_OK)
        return status;
    state->history[state->write_offset++] = value;
    (*output_offset)++;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bulk_rdp61_emit_literals(rdp_bulk_rdp61_state* state,
                                                  rdp_buffer* decoded,
                                                  const uint8_t* literals,
                                                  size_t literal_len,
                                                  size_t* literal_offset,
                                                  size_t count,
                                                  size_t* output_offset)
{
    size_t i = 0;

    if (!state || !decoded || !literal_offset || !output_offset ||
        (!literals && literal_len > 0) ||
        *literal_offset > literal_len ||
        count > literal_len - *literal_offset)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < count; i++)
    {
        librdp_status status =
            rdp_bulk_rdp61_emit(state, decoded, literals[*literal_offset], output_offset);

        if (status != LIBRDP_STATUS_OK)
            return status;
        (*literal_offset)++;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bulk_rdp61_emit_match(rdp_bulk_rdp61_state* state,
                                               rdp_buffer* decoded,
                                               uint32_t history_offset,
                                               uint16_t length,
                                               size_t* output_offset)
{
    uint32_t i = 0;

    if (!state || !state->history || !decoded || !output_offset ||
        length == 0 ||
        history_offset >= RDP_BULK_RDP61_HISTORY_SIZE ||
        (size_t)history_offset + (size_t)length > RDP_BULK_RDP61_HISTORY_SIZE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < length; i++)
    {
        librdp_status status =
            rdp_bulk_rdp61_emit(state, decoded, state->history[(size_t)history_offset + i], output_offset);

        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bulk_rdp61_decompress_level1(rdp_bulk_rdp61_state* state,
                                                       const uint8_t* data,
                                                       size_t data_len,
                                                       rdp_buffer* decoded)
{
    uint8_t l1_flags = 0;
    size_t output_offset = 0;
    size_t literal_offset = 0;
    size_t start_offset = 0;
    const uint8_t* payload = NULL;
    size_t payload_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!state || !data || !decoded || data_len < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_bulk_rdp61_state_ensure(state);
    if (status != LIBRDP_STATUS_OK)
        return status;

    l1_flags = data[0];
    if ((l1_flags & ~RDP_BULK_RDP61_L1_KNOWN_MASK) != 0 ||
        ((l1_flags & RDP_BULK_RDP61_L1_COMPRESSED) != 0 &&
         (l1_flags & RDP_BULK_RDP61_L1_NO_COMPRESSION) != 0) ||
        ((l1_flags & (RDP_BULK_RDP61_L1_COMPRESSED | RDP_BULK_RDP61_L1_NO_COMPRESSION)) == 0))
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if ((l1_flags & RDP_BULK_RDP61_L1_PACKET_AT_FRONT) != 0)
        rdp_bulk_rdp61_state_reset(state, 1);

    payload = data + 2u;
    payload_len = data_len - 2u;
    start_offset = state->write_offset;
    if ((l1_flags & RDP_BULK_RDP61_L1_NO_COMPRESSION) != 0)
    {
        status = rdp_bulk_rdp61_emit_literals(state,
                                              decoded,
                                              payload,
                                              payload_len,
                                              &literal_offset,
                                              payload_len,
                                              &output_offset);
        if (status != LIBRDP_STATUS_OK)
            state->write_offset = start_offset;
        return status;
    }

    if (payload_len < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    {
        uint16_t match_count = rdp_bulk_read_u16_le(payload);
        size_t match_offset = 2u;
        size_t details_len = (size_t)match_count * RDP_BULK_RDP61_MATCH_SIZE;
        const uint8_t* literals = NULL;
        size_t literal_len = 0;
        uint16_t i = 0;

        if (match_count == 0 || 2u + details_len > payload_len)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        literals = payload + 2u + details_len;
        literal_len = payload_len - 2u - details_len;

        for (i = 0; i < match_count; i++)
        {
            const uint8_t* detail = payload + match_offset;
            uint16_t length = rdp_bulk_read_u16_le(detail);
            uint16_t match_output = rdp_bulk_read_u16_le(detail + 2u);
            uint32_t history_offset = rdp_bulk_read_u32_le(detail + 4u);
            size_t literal_gap = 0;

            if ((size_t)match_output < output_offset)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            literal_gap = (size_t)match_output - output_offset;
            status = rdp_bulk_rdp61_emit_literals(state,
                                                  decoded,
                                                  literals,
                                                  literal_len,
                                                  &literal_offset,
                                                  literal_gap,
                                                  &output_offset);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_bulk_rdp61_emit_match(state,
                                                   decoded,
                                                   history_offset,
                                                   length,
                                                   &output_offset);
            if (status != LIBRDP_STATUS_OK)
                break;
            match_offset += RDP_BULK_RDP61_MATCH_SIZE;
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_bulk_rdp61_emit_literals(state,
                                                  decoded,
                                                  literals,
                                                  literal_len,
                                                  &literal_offset,
                                                  literal_len - literal_offset,
                                                  &output_offset);
    }

    if (status != LIBRDP_STATUS_OK)
        state->write_offset = start_offset;
    return status;
}

static librdp_status rdp_bulk_rdp61_decompress(rdp_bulk_rdp61_state* state,
                                               rdp_bulk_mppc_state* level2,
                                               const uint8_t* data,
                                               size_t data_len,
                                               rdp_buffer* decoded)
{
    rdp_buffer inner;
    uint8_t l1_flags = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!state || !level2 || !data || !decoded || data_len < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    l1_flags = data[0];
    if ((l1_flags & RDP_BULK_RDP61_L1_INNER_COMPRESSION) == 0)
        return rdp_bulk_rdp61_decompress_level1(state, data, data_len, decoded);

    rdp_buffer_init(&inner);
    status = rdp_buffer_append_u8(&inner, data[0]);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&inner, data[1]);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_bulk_mppc_decompress(level2, data[1], data + 2u, data_len - 2u, &inner);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_bulk_rdp61_decompress_level1(state, inner.data, inner.length, decoded);
    rdp_buffer_free(&inner);
    return status;
}

void rdp_bulk_decompressor_init(rdp_bulk_decompressor* decompressor)
{
    if (!decompressor)
        return;
    rdp_bulk_mppc_state_init(&decompressor->mppc8k, 0);
    rdp_bulk_mppc_state_init(&decompressor->mppc64k, 1);
    rdp_bulk_mppc_state_init(&decompressor->rdp61_level2, 1);
    rdp_bulk_rdp61_state_init(&decompressor->rdp61);
}

void rdp_bulk_decompressor_reset(rdp_bulk_decompressor* decompressor)
{
    if (!decompressor)
        return;
    rdp_bulk_mppc_state_reset(&decompressor->mppc8k, 1);
    rdp_bulk_mppc_state_reset(&decompressor->mppc64k, 1);
    rdp_bulk_mppc_state_reset(&decompressor->rdp61_level2, 1);
    rdp_bulk_rdp61_state_reset(&decompressor->rdp61, 1);
}

void rdp_bulk_decompressor_free(rdp_bulk_decompressor* decompressor)
{
    if (!decompressor)
        return;
    rdp_bulk_mppc_state_free(&decompressor->mppc8k);
    rdp_bulk_mppc_state_free(&decompressor->mppc64k);
    rdp_bulk_mppc_state_free(&decompressor->rdp61_level2);
    rdp_bulk_rdp61_state_free(&decompressor->rdp61);
}

librdp_status rdp_bulk_decompress(rdp_bulk_decompressor* decompressor,
                                  uint8_t flags,
                                  const void* data,
                                  size_t data_len,
                                  rdp_buffer* decoded)
{
    uint8_t type = (uint8_t)(flags & RDP_BULK_TYPE_MASK);
    const uint8_t* bytes = (const uint8_t*)data;

    if (!decompressor || (!data && data_len > 0) || !decoded)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (data_len == 0)
        return LIBRDP_STATUS_OK;
    if ((flags & RDP_BULK_FLAGS_MASK) == 0)
        return rdp_buffer_append(decoded, data, data_len);
    if (type == RDP_BULK_TYPE_8K)
        return rdp_bulk_mppc_decompress(&decompressor->mppc8k, flags, bytes, data_len, decoded);
    if (type == RDP_BULK_TYPE_64K)
        return rdp_bulk_mppc_decompress(&decompressor->mppc64k, flags, bytes, data_len, decoded);
    if (type == RDP_BULK_TYPE_RDP61)
        return rdp_bulk_rdp61_decompress(&decompressor->rdp61,
                                         &decompressor->rdp61_level2,
                                         bytes,
                                         data_len,
                                         decoded);
    return LIBRDP_STATUS_UNSUPPORTED;
}
