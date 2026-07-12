/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: bulk compression and decompression support.
 * Invariants: wire lengths, tags, and stream offsets stay consistent across
 * every parse and write path.
 * Ownership: serialized buffers are caller-owned and parsed views never
 * outlive the input stream.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: all protocol bytes are untrusted network input until parsed
 * successfully.
 */


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
#define RDP_BULK_RDP6_LEC_TABLE_BITS 13u
#define RDP_BULK_RDP6_LOM_TABLE_BITS 9u
#define RDP_BULK_RDP6_LEC_TABLE_SIZE (1u << RDP_BULK_RDP6_LEC_TABLE_BITS)
#define RDP_BULK_RDP6_LOM_TABLE_SIZE (1u << RDP_BULK_RDP6_LOM_TABLE_BITS)

typedef struct rdp_bulk_rdp6_bit_reader
{
    const uint8_t* ptr;
    const uint8_t* end;
    uint64_t bits;
    uint8_t bit_count;
} rdp_bulk_rdp6_bit_reader;

static const uint8_t rdp_bulk_rdp6_lec_lengths[294] = {
    6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 9, 8, 9, 9, 9, 9,
    8, 8, 9, 9, 9, 9, 9, 9, 8, 9, 9, 10, 9, 9, 9, 9, 9, 9, 9, 10, 9, 10, 10, 10,
    9, 9, 10, 9, 10, 9, 10, 9, 9, 9, 10, 10, 9, 10, 9, 9, 8, 9, 9, 9, 9, 10, 10, 10,
    9, 9, 10, 10, 10, 10, 10, 10, 9, 9, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10,
    8, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 9, 7, 9, 9, 10, 9, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 13, 10, 10, 10, 10, 10, 10, 11, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 9, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10,
    8, 9, 9, 10, 9, 10, 10, 10, 9, 10, 10, 10, 9, 9, 8, 7, 13, 13, 7, 7, 10, 7, 7, 6,
    6, 6, 6, 5, 6, 6, 6, 5, 6, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    8, 5, 6, 7, 7, 13
};

static const uint8_t rdp_bulk_rdp6_lom_lengths[32] = {
    4, 2, 3, 4, 3, 4, 4, 5, 4, 5, 5, 6, 6, 7, 7, 8,
    7, 8, 8, 9, 9, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9
};

static const uint32_t rdp_bulk_rdp6_copy_offset_bits[32] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14
};

static const uint32_t rdp_bulk_rdp6_copy_offset_base[32] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289,
    16385, 24577, 32769, 49153
};

static const uint32_t rdp_bulk_rdp6_lom_bits[30] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
    2, 3, 3, 3, 3, 4, 4, 4, 4, 6, 6, 8, 8, 14, 14
};

static const uint32_t rdp_bulk_rdp6_lom_base[30] = {
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 18, 22, 26,
    30, 34, 42, 50, 58, 66, 82, 98, 114, 130, 194, 258, 514, 2, 2
};

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

static void rdp_bulk_rdp6_state_init(rdp_bulk_rdp6_state* state)
{
    if (!state)
        return;
    memset(state, 0, sizeof(*state));
}

static void rdp_bulk_rdp6_state_reset(rdp_bulk_rdp6_state* state, int clear)
{
    if (!state)
        return;
    state->write_offset = 0;
    memset(state->offset_cache, 0, sizeof(state->offset_cache));
    if (clear)
        memset(state->history, 0, sizeof(state->history));
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

static uint32_t rdp_bulk_rdp6_reverse_bits(uint32_t value, uint8_t count)
{
    uint32_t reversed = 0;
    uint8_t i = 0;

    for (i = 0; i < count; i++)
    {
        reversed = (reversed << 1u) | (value & 1u);
        value >>= 1u;
    }
    return reversed;
}

static librdp_status rdp_bulk_rdp6_build_table(rdp_bulk_rdp6_decode_entry* table,
                                               size_t table_size,
                                               uint8_t table_bits,
                                               const uint8_t* lengths,
                                               size_t symbol_count)
{
    uint16_t length_counts[16] = {0};
    uint16_t next_code[16] = {0};
    uint32_t code = 0;
    size_t i = 0;

    if (!table || !lengths || table_bits >= 16u || table_size != ((size_t)1u << table_bits))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(table, 0, table_size * sizeof(*table));
    for (i = 0; i < symbol_count; i++)
    {
        if (lengths[i] == 0 || lengths[i] > table_bits)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        length_counts[lengths[i]]++;
    }
    for (i = 1; i <= table_bits; i++)
    {
        code = (code + length_counts[i - 1u]) << 1u;
        if (code > 0xffffu)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        next_code[i] = (uint16_t)code;
    }
    for (i = 0; i < symbol_count; i++)
    {
        uint8_t bit_count = lengths[i];
        uint32_t reversed = rdp_bulk_rdp6_reverse_bits(next_code[bit_count]++, bit_count);
        size_t step = (size_t)1u << bit_count;
        size_t entry = 0;

        for (entry = reversed; entry < table_size; entry += step)
        {
            if (table[entry].bit_count != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            table[entry].symbol = (uint16_t)i;
            table[entry].bit_count = bit_count;
        }
    }
    for (i = 0; i < table_size; i++)
    {
        if (table[i].bit_count == 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bulk_rdp6_prepare(rdp_bulk_rdp6_state* state)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!state)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (state->tables_ready)
        return LIBRDP_STATUS_OK;
    status = rdp_bulk_rdp6_build_table(state->literal_offset,
                                       RDP_BULK_RDP6_LEC_TABLE_SIZE,
                                       RDP_BULK_RDP6_LEC_TABLE_BITS,
                                       rdp_bulk_rdp6_lec_lengths,
                                       sizeof(rdp_bulk_rdp6_lec_lengths) / sizeof(rdp_bulk_rdp6_lec_lengths[0]));
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_bulk_rdp6_build_table(state->match_length,
                                       RDP_BULK_RDP6_LOM_TABLE_SIZE,
                                       RDP_BULK_RDP6_LOM_TABLE_BITS,
                                       rdp_bulk_rdp6_lom_lengths,
                                       sizeof(rdp_bulk_rdp6_lom_lengths) / sizeof(rdp_bulk_rdp6_lom_lengths[0]));
    if (status != LIBRDP_STATUS_OK)
        return status;
    state->tables_ready = 1u;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bulk_rdp6_reader_init(rdp_bulk_rdp6_bit_reader* reader,
                                               const uint8_t* data,
                                               size_t data_len)
{
    if (!reader || !data || data_len < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    reader->ptr = data + 4u;
    reader->end = data + data_len;
    reader->bits = rdp_bulk_read_u32_le(data);
    reader->bit_count = 32u;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bulk_rdp6_reader_ensure(rdp_bulk_rdp6_bit_reader* reader, uint8_t count)
{
    if (!reader || count > 32u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (reader->bit_count < count && reader->ptr < reader->end)
    {
        reader->bits |= ((uint64_t)*reader->ptr++) << reader->bit_count;
        reader->bit_count += 8u;
    }
    return reader->bit_count >= count ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_bulk_rdp6_reader_read(rdp_bulk_rdp6_bit_reader* reader,
                                               uint8_t count,
                                               uint32_t* value)
{
    uint64_t mask = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!reader || !value || count > 31u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (count == 0)
    {
        *value = 0;
        return LIBRDP_STATUS_OK;
    }
    status = rdp_bulk_rdp6_reader_ensure(reader, count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    mask = ((uint64_t)1u << count) - 1u;
    *value = (uint32_t)(reader->bits & mask);
    reader->bits >>= count;
    reader->bit_count = (uint8_t)(reader->bit_count - count);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bulk_rdp6_decode_symbol(rdp_bulk_rdp6_bit_reader* reader,
                                                 const rdp_bulk_rdp6_decode_entry* table,
                                                 uint8_t table_bits,
                                                 uint16_t* symbol)
{
    uint32_t bits = 0;
    uint64_t mask = 0;
    rdp_bulk_rdp6_decode_entry entry;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!reader || !table || !symbol || table_bits > 15u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_bulk_rdp6_reader_ensure(reader, table_bits);
    if (status != LIBRDP_STATUS_OK)
        return status;
    mask = ((uint64_t)1u << table_bits) - 1u;
    bits = (uint32_t)(reader->bits & mask);
    entry = table[bits];
    if (entry.bit_count == 0 || entry.bit_count > reader->bit_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    reader->bits >>= entry.bit_count;
    reader->bit_count = (uint8_t)(reader->bit_count - entry.bit_count);
    *symbol = entry.symbol;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bulk_rdp6_move_front(rdp_bulk_rdp6_state* state)
{
    if (!state || state->write_offset <= 32768u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memmove(state->history, state->history + state->write_offset - 32768u, 32768u);
    memset(state->history + 32768u, 0, 32768u);
    state->write_offset = 32768u;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bulk_rdp6_emit(rdp_bulk_rdp6_state* state,
                                        uint8_t value,
                                        size_t* output_offset)
{
    if (!state || !output_offset || state->write_offset >= RDP_BULK_RDP6_HISTORY_SIZE - 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    state->history[state->write_offset++] = value;
    (*output_offset)++;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bulk_rdp6_copy(rdp_bulk_rdp6_state* state,
                                        uint32_t copy_offset,
                                        uint32_t length,
                                        size_t* output_offset)
{
    uint32_t i = 0;
    size_t src = 0;

    if (!state || !output_offset || copy_offset == 0 || length < 2u ||
        length > RDP_BULK_RDP6_HISTORY_SIZE - state->write_offset - 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    src = (state->write_offset - (size_t)copy_offset) & 0xffffu;
    for (i = 0; i < length; i++)
    {
        librdp_status status = rdp_bulk_rdp6_emit(state, state->history[src], output_offset);

        if (status != LIBRDP_STATUS_OK)
            return status;
        src = (src + 1u) & 0xffffu;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bulk_rdp6_read_match_length(rdp_bulk_rdp6_state* state,
                                                     rdp_bulk_rdp6_bit_reader* reader,
                                                     uint32_t* length)
{
    uint16_t symbol = 0;
    uint32_t extra = 0;
    uint32_t bits = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!state || !reader || !length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_bulk_rdp6_decode_symbol(reader,
                                         state->match_length,
                                         RDP_BULK_RDP6_LOM_TABLE_BITS,
                                         &symbol);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (symbol >= sizeof(rdp_bulk_rdp6_lom_bits) / sizeof(rdp_bulk_rdp6_lom_bits[0]))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    bits = rdp_bulk_rdp6_lom_bits[symbol];
    status = rdp_bulk_rdp6_reader_read(reader, (uint8_t)bits, &extra);
    if (status != LIBRDP_STATUS_OK)
        return status;
    *length = rdp_bulk_rdp6_lom_base[symbol] + extra;
    return LIBRDP_STATUS_OK;
}

/*
 * Decode bulk-compressed data using the negotiated RDP6 history state. History
 * updates are committed only after the advertised output size has been
 * produced successfully.
 */
static librdp_status rdp_bulk_rdp6_decode(rdp_bulk_rdp6_state* state,
                                          uint8_t flags,
                                          const uint8_t* data,
                                          size_t data_len,
                                          rdp_buffer* decoded)
{
    rdp_bulk_rdp6_bit_reader reader;
    size_t start = 0;
    size_t output_offset = 0;
    uint32_t saved_cache[4];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!state || !data || !decoded)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_bulk_rdp6_prepare(state);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if ((flags & RDP_BULK_PACKET_AT_FRONT) != 0)
    {
        status = rdp_bulk_rdp6_move_front(state);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if ((flags & RDP_BULK_PACKET_FLUSHED) != 0)
        rdp_bulk_rdp6_state_reset(state, 1);
    if ((flags & RDP_BULK_PACKET_COMPRESSED) == 0)
        return rdp_buffer_append(decoded, data, data_len);
    status = rdp_bulk_rdp6_reader_init(&reader, data, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    start = state->write_offset;
    memcpy(saved_cache, state->offset_cache, sizeof(saved_cache));
    while (1)
    {
        uint16_t symbol = 0;
        uint32_t copy_offset = 0;
        uint32_t match_length = 0;

        status = rdp_bulk_rdp6_decode_symbol(&reader,
                                             state->literal_offset,
                                             RDP_BULK_RDP6_LEC_TABLE_BITS,
                                             &symbol);
        if (status != LIBRDP_STATUS_OK)
            break;
        if (symbol < 256u)
        {
            status = rdp_bulk_rdp6_emit(state, (uint8_t)symbol, &output_offset);
            if (status != LIBRDP_STATUS_OK)
                break;
            continue;
        }
        if (symbol == 256u)
            break;
        if (symbol <= 288u)
        {
            uint32_t index = (uint32_t)symbol - 257u;
            uint32_t extra_bits = rdp_bulk_rdp6_copy_offset_bits[index];
            uint32_t extra = 0;

            status = rdp_bulk_rdp6_reader_read(&reader, (uint8_t)extra_bits, &extra);
            if (status != LIBRDP_STATUS_OK)
                break;
            copy_offset = rdp_bulk_rdp6_copy_offset_base[index] + extra - 1u;
            status = rdp_bulk_rdp6_read_match_length(state, &reader, &match_length);
            if (status != LIBRDP_STATUS_OK)
                break;
            state->offset_cache[3] = state->offset_cache[2];
            state->offset_cache[2] = state->offset_cache[1];
            state->offset_cache[1] = state->offset_cache[0];
            state->offset_cache[0] = copy_offset;
        }
        else if (symbol <= 292u)
        {
            uint32_t index = (uint32_t)symbol - 289u;
            uint32_t old = state->offset_cache[index];

            copy_offset = old;
            status = rdp_bulk_rdp6_read_match_length(state, &reader, &match_length);
            if (status != LIBRDP_STATUS_OK)
                break;
            state->offset_cache[index] = state->offset_cache[0];
            state->offset_cache[0] = old;
        }
        else
        {
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
        }
        status = rdp_bulk_rdp6_copy(state, copy_offset, match_length, &output_offset);
        if (status != LIBRDP_STATUS_OK)
            break;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        state->write_offset = start;
        memcpy(state->offset_cache, saved_cache, sizeof(saved_cache));
        return status;
    }
    return rdp_buffer_append(decoded, state->history + start, state->write_offset - start);
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
    rdp_bulk_rdp6_state_init(&decompressor->rdp6);
    rdp_bulk_mppc_state_init(&decompressor->rdp61_level2, 1);
    rdp_bulk_rdp61_state_init(&decompressor->rdp61);
}

void rdp_bulk_decompressor_reset(rdp_bulk_decompressor* decompressor)
{
    if (!decompressor)
        return;
    rdp_bulk_mppc_state_reset(&decompressor->mppc8k, 1);
    rdp_bulk_mppc_state_reset(&decompressor->mppc64k, 1);
    rdp_bulk_rdp6_state_reset(&decompressor->rdp6, 1);
    rdp_bulk_mppc_state_reset(&decompressor->rdp61_level2, 1);
    rdp_bulk_rdp61_state_reset(&decompressor->rdp61, 1);
}

void rdp_bulk_decompressor_free(rdp_bulk_decompressor* decompressor)
{
    if (!decompressor)
        return;
    rdp_bulk_mppc_state_free(&decompressor->mppc8k);
    rdp_bulk_mppc_state_free(&decompressor->mppc64k);
    rdp_bulk_rdp6_state_reset(&decompressor->rdp6, 1);
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
    if (type == RDP_BULK_TYPE_RDP6)
        return rdp_bulk_rdp6_decode(&decompressor->rdp6, flags, bytes, data_len, decoded);
    if (type == RDP_BULK_TYPE_RDP61)
        return rdp_bulk_rdp61_decompress(&decompressor->rdp61,
                                         &decompressor->rdp61_level2,
                                         bytes,
                                         data_len,
                                         decoded);
    return LIBRDP_STATUS_UNSUPPORTED;
}
