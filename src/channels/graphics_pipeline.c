#include "channels/graphics_pipeline.h"

#include "common/stream.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct rdp_graphics_token
{
    uint8_t prefix_length;
    uint16_t prefix_code;
    uint8_t value_bits;
    uint8_t is_match;
    uint32_t value_base;
} rdp_graphics_token;

typedef struct rdp_graphics_bit_reader
{
    const uint8_t* current;
    const uint8_t* end;
    uint32_t bits_remaining;
    uint32_t cache;
    uint8_t cache_bits;
} rdp_graphics_bit_reader;

static const rdp_graphics_token rdp_graphics_tokens[] = {
    {1, 0, 8, 0, 0},
    {5, 17, 5, 1, 0},
    {5, 18, 7, 1, 32},
    {5, 19, 9, 1, 160},
    {5, 20, 10, 1, 672},
    {5, 21, 12, 1, 1696},
    {5, 24, 0, 0, 0x00},
    {5, 25, 0, 0, 0x01},
    {6, 44, 14, 1, 5792},
    {6, 45, 15, 1, 22176},
    {6, 52, 0, 0, 0x02},
    {6, 53, 0, 0, 0x03},
    {6, 54, 0, 0, 0xff},
    {7, 92, 18, 1, 54944},
    {7, 93, 20, 1, 317088},
    {7, 110, 0, 0, 0x04},
    {7, 111, 0, 0, 0x05},
    {7, 112, 0, 0, 0x06},
    {7, 113, 0, 0, 0x07},
    {7, 114, 0, 0, 0x08},
    {7, 115, 0, 0, 0x09},
    {7, 116, 0, 0, 0x0a},
    {7, 117, 0, 0, 0x0b},
    {7, 118, 0, 0, 0x3a},
    {7, 119, 0, 0, 0x3b},
    {7, 120, 0, 0, 0x3c},
    {7, 121, 0, 0, 0x3d},
    {7, 122, 0, 0, 0x3e},
    {7, 123, 0, 0, 0x3f},
    {7, 124, 0, 0, 0x40},
    {7, 125, 0, 0, 0x80},
    {8, 188, 20, 1, 1365664},
    {8, 189, 21, 1, 2414240},
    {8, 252, 0, 0, 0x0c},
    {8, 253, 0, 0, 0x38},
    {8, 254, 0, 0, 0x39},
    {8, 255, 0, 0, 0x66}
};

void rdp_graphics_decompressor_init(rdp_graphics_decompressor* decompressor)
{
    if (!decompressor)
        return;
    decompressor->history = NULL;
    decompressor->history_index = 0;
    decompressor->history_filled = 0;
}

void rdp_graphics_decompressor_reset(rdp_graphics_decompressor* decompressor)
{
    if (!decompressor)
        return;
    decompressor->history_index = 0;
    decompressor->history_filled = 0;
}

void rdp_graphics_decompressor_free(rdp_graphics_decompressor* decompressor)
{
    if (!decompressor)
        return;
    free(decompressor->history);
    decompressor->history = NULL;
    decompressor->history_index = 0;
    decompressor->history_filled = 0;
}

static librdp_status rdp_graphics_decompressor_ensure(rdp_graphics_decompressor* decompressor)
{
    if (!decompressor)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (decompressor->history)
        return LIBRDP_STATUS_OK;
    decompressor->history = (uint8_t*)calloc(1, RDP_GRAPHICS_BULK_HISTORY_SIZE);
    if (!decompressor->history)
        return LIBRDP_STATUS_NO_MEMORY;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_graphics_write_header(rdp_buffer* buffer, uint16_t cmd_id, uint32_t pdu_length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || pdu_length < 8u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u16_le(buffer, cmd_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, pdu_length);
    return status;
}

static int rdp_graphics_is_short_literal(uint32_t value)
{
    return value <= 0x0cu || (value >= 0x38u && value <= 0x40u) || value == 0x66u || value == 0x80u ||
           value == 0xffu;
}

static librdp_status rdp_graphics_bit_reader_init(rdp_graphics_bit_reader* reader,
                                                  const uint8_t* data,
                                                  size_t length)
{
    uint8_t trailer = 0;

    if (!reader || !data || length == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    trailer = data[length - 1u];
    if ((trailer & 0xf8u) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    reader->current = data;
    reader->end = data + length - 1u;
    reader->bits_remaining = (uint32_t)((length - 1u) * 8u) - trailer;
    reader->cache = 0;
    reader->cache_bits = 0;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_graphics_read_bits(rdp_graphics_bit_reader* reader, uint8_t count, uint32_t* value)
{
    uint32_t mask = 0;

    if (!reader || !value || count > 24u || reader->bits_remaining < count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    while (reader->cache_bits < count)
    {
        if (reader->current >= reader->end)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        reader->cache = (reader->cache << 8) | *reader->current;
        reader->current++;
        reader->cache_bits = (uint8_t)(reader->cache_bits + 8u);
    }
    reader->bits_remaining -= count;
    reader->cache_bits = (uint8_t)(reader->cache_bits - count);
    *value = reader->cache >> reader->cache_bits;
    mask = reader->cache_bits == 0 ? 0 : ((uint32_t)1u << reader->cache_bits) - 1u;
    reader->cache &= mask;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_graphics_output_byte(rdp_graphics_decompressor* decompressor,
                                              rdp_buffer* decoded,
                                              uint8_t value,
                                              uint32_t* segment_output)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!decompressor || !decoded || !segment_output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (*segment_output >= 65535u || decoded->length >= RDP_GRAPHICS_BULK_MAX_DECODED)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_graphics_decompressor_ensure(decompressor);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(decoded, value);
    if (status != LIBRDP_STATUS_OK)
        return status;
    decompressor->history[decompressor->history_index] = value;
    decompressor->history_index++;
    if (decompressor->history_index == RDP_GRAPHICS_BULK_HISTORY_SIZE)
        decompressor->history_index = 0;
    if (decompressor->history_filled < RDP_GRAPHICS_BULK_HISTORY_SIZE)
        decompressor->history_filled++;
    (*segment_output)++;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_graphics_copy_match(rdp_graphics_decompressor* decompressor,
                                             rdp_buffer* decoded,
                                             uint32_t distance,
                                             uint32_t count,
                                             uint32_t* segment_output)
{
    uint32_t source = 0;
    uint32_t i = 0;

    if (!decompressor || !decompressor->history || distance == 0 ||
        distance > decompressor->history_filled || distance > RDP_GRAPHICS_BULK_HISTORY_SIZE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (decompressor->history_index >= distance)
        source = decompressor->history_index - distance;
    else
        source = RDP_GRAPHICS_BULK_HISTORY_SIZE - (distance - decompressor->history_index);

    for (i = 0; i < count; i++)
    {
        uint8_t value = decompressor->history[source];

        source++;
        if (source == RDP_GRAPHICS_BULK_HISTORY_SIZE)
            source = 0;
        if (rdp_graphics_output_byte(decompressor, decoded, value, segment_output) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_graphics_read_length(rdp_graphics_bit_reader* reader, uint32_t* count)
{
    uint32_t bit = 0;
    uint8_t extra = 2;
    uint32_t value = 0;

    if (rdp_graphics_read_bits(reader, 1, &bit) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (bit == 0)
    {
        *count = 3;
        return LIBRDP_STATUS_OK;
    }

    *count = 4;
    for (;;)
    {
        if (rdp_graphics_read_bits(reader, 1, &bit) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (bit == 0)
            break;
        if (extra == 15u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *count *= 2u;
        extra++;
    }
    if (rdp_graphics_read_bits(reader, extra, &value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *count += value;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_graphics_copy_unencoded(rdp_graphics_decompressor* decompressor,
                                                 rdp_graphics_bit_reader* reader,
                                                 rdp_buffer* decoded,
                                                 uint32_t count,
                                                 uint32_t* segment_output)
{
    uint32_t i = 0;

    if (!decompressor || !reader || !decoded || !segment_output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (reader->bits_remaining < reader->cache_bits)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    reader->bits_remaining -= reader->cache_bits;
    reader->cache = 0;
    reader->cache_bits = 0;
    if (count > reader->bits_remaining / 8u || (size_t)(reader->end - reader->current) < count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < count; i++)
    {
        if (rdp_graphics_output_byte(decompressor, decoded, *reader->current, segment_output) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        reader->current++;
        reader->bits_remaining -= 8u;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_graphics_decode_compressed_segment(rdp_graphics_decompressor* decompressor,
                                                           const uint8_t* data,
                                                           size_t length,
                                                           rdp_buffer* decoded)
{
    rdp_graphics_bit_reader reader;
    uint32_t segment_output = 0;

    if (!decompressor || !data || !decoded)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_bit_reader_init(&reader, data, length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    while (reader.bits_remaining > 0)
    {
        uint16_t prefix = 0;
        uint8_t prefix_bits = 0;
        size_t i = 0;
        int matched = 0;

        for (i = 0; i < sizeof(rdp_graphics_tokens) / sizeof(rdp_graphics_tokens[0]); i++)
        {
            const rdp_graphics_token* token = &rdp_graphics_tokens[i];

            while (prefix_bits < token->prefix_length)
            {
                uint32_t bit = 0;

                if (rdp_graphics_read_bits(&reader, 1, &bit) != LIBRDP_STATUS_OK)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                prefix = (uint16_t)((prefix << 1) | (uint16_t)bit);
                prefix_bits++;
            }
            if (prefix == token->prefix_code)
            {
                uint32_t value = 0;

                matched = 1;
                if (token->value_bits > 0 &&
                    rdp_graphics_read_bits(&reader, token->value_bits, &value) != LIBRDP_STATUS_OK)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                value += token->value_base;
                if (!token->is_match)
                {
                    if (token->prefix_length == 1u && rdp_graphics_is_short_literal(value))
                        return LIBRDP_STATUS_PROTOCOL_ERROR;
                    if (rdp_graphics_output_byte(decompressor,
                                                 decoded,
                                                 (uint8_t)value,
                                                 &segment_output) != LIBRDP_STATUS_OK)
                        return LIBRDP_STATUS_PROTOCOL_ERROR;
                }
                else if (value == 0)
                {
                    uint32_t count = 0;

                    if (rdp_graphics_read_bits(&reader, 15, &count) != LIBRDP_STATUS_OK)
                        return LIBRDP_STATUS_PROTOCOL_ERROR;
                    if (rdp_graphics_copy_unencoded(decompressor,
                                                    &reader,
                                                    decoded,
                                                    count,
                                                    &segment_output) != LIBRDP_STATUS_OK)
                        return LIBRDP_STATUS_PROTOCOL_ERROR;
                }
                else
                {
                    uint32_t count = 0;

                    if (rdp_graphics_read_length(&reader, &count) != LIBRDP_STATUS_OK)
                        return LIBRDP_STATUS_PROTOCOL_ERROR;
                    if (rdp_graphics_copy_match(decompressor,
                                                decoded,
                                                value,
                                                count,
                                                &segment_output) != LIBRDP_STATUS_OK)
                        return LIBRDP_STATUS_PROTOCOL_ERROR;
                }
                break;
            }
        }
        if (!matched)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_header(const void* data, size_t length, rdp_graphics_header* header)
{
    rdp_stream stream;

    if (!data || !header || length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &header->cmd_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &header->pdu_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header->flags != 0 || header->pdu_length < 8u || header->pdu_length > length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_capset(const void* data, size_t length, rdp_graphics_capset* capset)
{
    rdp_stream stream;
    uint32_t caps_data_length = 0;

    if (!data || !capset || length < 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(capset, 0, sizeof(*capset));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &capset->version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &caps_data_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (caps_data_length != 4u || length < 8u + caps_data_length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u32_le(&stream, &capset->flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_write_caps_advertise(rdp_buffer* buffer,
                                                const rdp_graphics_capset* capsets,
                                                uint16_t capset_count)
{
    uint16_t i = 0;
    uint32_t pdu_length = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !capsets || capset_count == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    pdu_length = 10u + (uint32_t)capset_count * 12u;
    status = rdp_graphics_write_header(buffer, RDP_GRAPHICS_CMDID_CAPS_ADVERTISE, pdu_length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, capset_count);
    for (i = 0; status == LIBRDP_STATUS_OK && i < capset_count; i++)
    {
        status = rdp_buffer_append_u32_le(buffer, capsets[i].version);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, 4);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, capsets[i].flags);
    }
    return status;
}

librdp_status rdp_graphics_write_default_caps_advertise(rdp_buffer* buffer)
{
    const rdp_graphics_capset capsets[] = {
        {RDP_GRAPHICS_CAPVERSION_8, RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE}
    };

    return rdp_graphics_write_caps_advertise(buffer, capsets, (uint16_t)(sizeof(capsets) / sizeof(capsets[0])));
}

librdp_status rdp_graphics_parse_caps_confirm(const void* data,
                                              size_t length,
                                              rdp_graphics_caps_confirm* confirm)
{
    rdp_graphics_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !confirm)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(confirm, 0, sizeof(*confirm));
    status = rdp_graphics_parse_header(data, length, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header.cmd_id != RDP_GRAPHICS_CMDID_CAPS_CONFIRM || header.pdu_length != length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_graphics_parse_capset(((const uint8_t*)data) + 8u, length - 8u, &confirm->selected);
}

static librdp_status rdp_graphics_parse_fixed_header(const void* data,
                                                     size_t length,
                                                     uint16_t cmd_id,
                                                     uint32_t pdu_length)
{
    rdp_graphics_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_graphics_parse_header(data, length, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header.cmd_id != cmd_id || header.pdu_length != pdu_length || length != pdu_length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_graphics_stream_read_u64_le(rdp_stream* stream, uint64_t* value)
{
    uint32_t low = 0;
    uint32_t high = 0;

    if (!stream || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u32_le(stream, &low) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &high) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = (uint64_t)low | ((uint64_t)high << 32);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_create_surface(const void* data,
                                                size_t length,
                                                rdp_graphics_create_surface* create_surface)
{
    rdp_stream stream;

    if (!data || !create_surface)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_parse_fixed_header(data, length, RDP_GRAPHICS_CMDID_CREATE_SURFACE, 15) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(create_surface, 0, sizeof(*create_surface));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &create_surface->surface_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &create_surface->width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &create_surface->height) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &create_surface->pixel_format) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (create_surface->width == 0 || create_surface->height == 0 ||
        (create_surface->pixel_format != RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888 &&
         create_surface->pixel_format != RDP_GRAPHICS_PIXEL_FORMAT_ARGB_8888))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_delete_surface(const void* data,
                                                size_t length,
                                                rdp_graphics_delete_surface* delete_surface)
{
    rdp_stream stream;

    if (!data || !delete_surface)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_parse_fixed_header(data, length, RDP_GRAPHICS_CMDID_DELETE_SURFACE, 10) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(delete_surface, 0, sizeof(*delete_surface));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &delete_surface->surface_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_reset(const void* data, size_t length, rdp_graphics_reset* reset)
{
    rdp_stream stream;

    if (!data || !reset)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_parse_fixed_header(data, length, RDP_GRAPHICS_CMDID_RESET_GRAPHICS, 340) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(reset, 0, sizeof(*reset));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &reset->width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &reset->height) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &reset->monitor_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (reset->width == 0 || reset->height == 0 || reset->width > 32766u || reset->height > 32766u ||
        reset->monitor_count > 16u || reset->monitor_count > rdp_stream_remaining(&stream) / 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_map_surface_to_output(const void* data,
                                                       size_t length,
                                                       rdp_graphics_map_surface_to_output* map)
{
    rdp_stream stream;
    uint16_t reserved = 0;

    if (!data || !map)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_parse_fixed_header(data, length, RDP_GRAPHICS_CMDID_MAP_SURFACE_TO_OUTPUT, 20) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(map, 0, sizeof(*map));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &map->surface_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &reserved) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &map->output_origin_x) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &map->output_origin_y) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (reserved != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_map_surface_to_scaled_output(
    const void* data,
    size_t length,
    rdp_graphics_map_surface_to_scaled_output* map)
{
    rdp_stream stream;
    uint16_t reserved = 0;

    if (!data || !map)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_parse_fixed_header(data, length, RDP_GRAPHICS_CMDID_MAP_SURFACE_TO_SCALED_OUTPUT, 28) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(map, 0, sizeof(*map));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &map->surface_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &reserved) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &map->output_origin_x) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &map->output_origin_y) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &map->target_width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &map->target_height) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (reserved != 0 || map->target_width == 0 || map->target_height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_point16(const void* data, size_t length, rdp_graphics_point16* point)
{
    rdp_stream stream;

    if (!data || !point)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(point, 0, sizeof(*point));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &point->x) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &point->y) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_rect16(const void* data, size_t length, rdp_graphics_rect16* rect)
{
    rdp_stream stream;

    if (!data || !rect)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(rect, 0, sizeof(*rect));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &rect->left) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &rect->top) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &rect->right) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &rect->bottom) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rect->right < rect->left || rect->bottom < rect->top)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_solid_fill(const void* data,
                                            size_t length,
                                            rdp_graphics_solid_fill* solid_fill)
{
    rdp_graphics_header header;
    rdp_stream stream;

    if (!data || !solid_fill)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(solid_fill, 0, sizeof(*solid_fill));
    if (rdp_graphics_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.cmd_id != RDP_GRAPHICS_CMDID_SOLIDFILL || header.pdu_length != length || length < 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &solid_fill->surface_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &solid_fill->fill_pixel) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &solid_fill->rect_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((size_t)solid_fill->rect_count != rdp_stream_remaining(&stream) / 8u ||
        rdp_stream_remaining(&stream) % 8u != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &solid_fill->rects, rdp_stream_remaining(&stream)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    solid_fill->rects_len = (size_t)solid_fill->rect_count * 8u;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_wire_to_surface_1(const void* data,
                                                   size_t length,
                                                   rdp_graphics_wire_to_surface_1* wire)
{
    rdp_graphics_header header;
    rdp_stream stream;
    const uint8_t* rect = NULL;

    if (!data || !wire)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(wire, 0, sizeof(*wire));
    if (rdp_graphics_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.cmd_id != RDP_GRAPHICS_CMDID_WIRE_TO_SURFACE_1 || header.pdu_length != length || length < 25u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &wire->surface_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &wire->codec_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &wire->pixel_format) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &rect, 8) != LIBRDP_STATUS_OK ||
        rdp_graphics_parse_rect16(rect, 8, &wire->dest_rect) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &wire->bitmap_data_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((wire->pixel_format != RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888 &&
         wire->pixel_format != RDP_GRAPHICS_PIXEL_FORMAT_ARGB_8888) ||
        rdp_stream_remaining(&stream) != wire->bitmap_data_length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &wire->bitmap_data, wire->bitmap_data_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_wire_to_surface_2(const void* data,
                                                   size_t length,
                                                   rdp_graphics_wire_to_surface_2* wire)
{
    rdp_graphics_header header;
    rdp_stream stream;

    if (!data || !wire)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(wire, 0, sizeof(*wire));
    if (rdp_graphics_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.cmd_id != RDP_GRAPHICS_CMDID_WIRE_TO_SURFACE_2 || header.pdu_length != length || length < 21u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &wire->surface_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &wire->codec_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &wire->codec_context_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &wire->pixel_format) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &wire->bitmap_data_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((wire->pixel_format != RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888 &&
         wire->pixel_format != RDP_GRAPHICS_PIXEL_FORMAT_ARGB_8888) ||
        rdp_stream_remaining(&stream) != wire->bitmap_data_length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &wire->bitmap_data, wire->bitmap_data_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_surface_to_surface(const void* data,
                                                    size_t length,
                                                    rdp_graphics_surface_to_surface* surface_to_surface)
{
    rdp_graphics_header header;
    rdp_stream stream;
    const uint8_t* rect = NULL;

    if (!data || !surface_to_surface)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(surface_to_surface, 0, sizeof(*surface_to_surface));
    if (rdp_graphics_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.cmd_id != RDP_GRAPHICS_CMDID_SURFACE_TO_SURFACE || header.pdu_length != length || length < 22u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &surface_to_surface->surface_id_src) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &surface_to_surface->surface_id_dest) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &rect, 8) != LIBRDP_STATUS_OK ||
        rdp_graphics_parse_rect16(rect, 8, &surface_to_surface->rect_src) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &surface_to_surface->dest_points_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((size_t)surface_to_surface->dest_points_count != rdp_stream_remaining(&stream) / 4u ||
        rdp_stream_remaining(&stream) % 4u != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream,
                              &surface_to_surface->dest_points,
                              rdp_stream_remaining(&stream)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    surface_to_surface->dest_points_len = (size_t)surface_to_surface->dest_points_count * 4u;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_surface_to_cache(const void* data,
                                                  size_t length,
                                                  rdp_graphics_surface_to_cache* surface_to_cache)
{
    rdp_stream stream;
    const uint8_t* rect = NULL;

    if (!data || !surface_to_cache)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_parse_fixed_header(data, length, RDP_GRAPHICS_CMDID_SURFACE_TO_CACHE, 28) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(surface_to_cache, 0, sizeof(*surface_to_cache));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &surface_to_cache->surface_id) != LIBRDP_STATUS_OK ||
        rdp_graphics_stream_read_u64_le(&stream, &surface_to_cache->cache_key) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &surface_to_cache->cache_slot) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &rect, 8) != LIBRDP_STATUS_OK ||
        rdp_graphics_parse_rect16(rect, 8, &surface_to_cache->rect_src) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_cache_to_surface(const void* data,
                                                  size_t length,
                                                  rdp_graphics_cache_to_surface* cache_to_surface)
{
    rdp_graphics_header header;
    rdp_stream stream;

    if (!data || !cache_to_surface)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(cache_to_surface, 0, sizeof(*cache_to_surface));
    if (rdp_graphics_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.cmd_id != RDP_GRAPHICS_CMDID_CACHE_TO_SURFACE || header.pdu_length != length || length < 14u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &cache_to_surface->cache_slot) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &cache_to_surface->surface_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &cache_to_surface->dest_points_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((size_t)cache_to_surface->dest_points_count != rdp_stream_remaining(&stream) / 4u ||
        rdp_stream_remaining(&stream) % 4u != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream,
                              &cache_to_surface->dest_points,
                              rdp_stream_remaining(&stream)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    cache_to_surface->dest_points_len = (size_t)cache_to_surface->dest_points_count * 4u;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_evict_cache_entry(const void* data,
                                                   size_t length,
                                                   rdp_graphics_evict_cache_entry* evict)
{
    rdp_stream stream;

    if (!data || !evict)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_parse_fixed_header(data, length, RDP_GRAPHICS_CMDID_EVICT_CACHE_ENTRY, 10) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(evict, 0, sizeof(*evict));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &evict->cache_slot) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_delete_encoding_context(const void* data,
                                                         size_t length,
                                                         rdp_graphics_delete_encoding_context* context)
{
    rdp_stream stream;

    if (!data || !context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_parse_fixed_header(data, length, RDP_GRAPHICS_CMDID_DELETE_ENCODING_CONTEXT, 14) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(context, 0, sizeof(*context));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &context->surface_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &context->codec_context_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_start_frame(const void* data,
                                             size_t length,
                                             rdp_graphics_start_frame* start_frame)
{
    rdp_stream stream;

    if (!data || !start_frame)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_parse_fixed_header(data, length, RDP_GRAPHICS_CMDID_START_FRAME, 16) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(start_frame, 0, sizeof(*start_frame));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &start_frame->timestamp) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &start_frame->frame_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_parse_end_frame(const void* data,
                                           size_t length,
                                           rdp_graphics_end_frame* end_frame)
{
    rdp_stream stream;

    if (!data || !end_frame)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_parse_fixed_header(data, length, RDP_GRAPHICS_CMDID_END_FRAME, 12) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(end_frame, 0, sizeof(*end_frame));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 8) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &end_frame->frame_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_write_frame_ack(rdp_buffer* buffer,
                                           uint32_t queue_depth,
                                           uint32_t frame_id,
                                           uint32_t total_frames_decoded)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_graphics_write_header(buffer, RDP_GRAPHICS_CMDID_FRAME_ACKNOWLEDGE, 20);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, queue_depth);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, frame_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, total_frames_decoded);
    return status;
}

static librdp_status rdp_graphics_append_bulk_data(rdp_graphics_decompressor* decompressor,
                                                   const uint8_t* data,
                                                   size_t length,
                                                   rdp_buffer* decoded)
{
    uint8_t bulk_header = 0;
    uint8_t compression_type = 0;
    uint32_t segment_output = 0;
    size_t i = 0;

    if (!decompressor || !data || !decoded || length < 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    bulk_header = data[0];
    compression_type = (uint8_t)(bulk_header & 0x0fu);
    if ((bulk_header & 0xd0u) != 0 || compression_type != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((bulk_header & RDP_GRAPHICS_BULK_PACKET_COMPRESSED) != 0)
        return rdp_graphics_decode_compressed_segment(decompressor, data + 1u, length - 1u, decoded);
    if (decoded->length > RDP_GRAPHICS_BULK_MAX_DECODED)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (length - 1u > RDP_GRAPHICS_BULK_MAX_DECODED - decoded->length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (length - 1u > 65535u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 1u; i < length; i++)
    {
        if (rdp_graphics_output_byte(decompressor, decoded, data[i], &segment_output) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_decode_segmented_data(rdp_graphics_decompressor* decompressor,
                                                 const void* data,
                                                 size_t length,
                                                 rdp_buffer* decoded)
{
    rdp_stream stream;
    uint8_t descriptor = 0;
    size_t start_length = 0;

    if (!decompressor || !data || !decoded)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    start_length = decoded->length;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &descriptor) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (descriptor == RDP_GRAPHICS_SEGMENT_SINGLE)
    {
        const uint8_t* bulk = NULL;
        size_t bulk_len = rdp_stream_remaining(&stream);

        if (rdp_stream_read_bytes(&stream, &bulk, bulk_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        return rdp_graphics_append_bulk_data(decompressor, bulk, bulk_len, decoded);
    }
    if (descriptor == RDP_GRAPHICS_SEGMENT_MULTIPART)
    {
        uint16_t segment_count = 0;
        uint32_t uncompressed_size = 0;
        uint16_t i = 0;
        librdp_status status = LIBRDP_STATUS_OK;

        if (rdp_stream_read_u16_le(&stream, &segment_count) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &uncompressed_size) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (segment_count == 0 || uncompressed_size > RDP_GRAPHICS_BULK_MAX_DECODED)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (i = 0; i < segment_count; i++)
        {
            uint32_t segment_size = 0;
            const uint8_t* segment = NULL;

            if (rdp_stream_read_u32_le(&stream, &segment_size) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (rdp_stream_read_bytes(&stream, &segment, segment_size) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_graphics_append_bulk_data(decompressor, segment, segment_size, decoded);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        if (rdp_stream_remaining(&stream) != 0 || decoded->length - start_length != uncompressed_size)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_graphics_progressive_parse_block(const void* data,
                                                   size_t length,
                                                   rdp_graphics_progressive_block* block)
{
    rdp_stream stream;

    if (!data || !block || length < 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(block, 0, sizeof(*block));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &block->type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &block->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (block->length < 6u || (size_t)block->length > length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &block->payload, (size_t)block->length - 6u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    block->payload_len = (size_t)block->length - 6u;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_progressive_parse_context(const void* data,
                                                     size_t length,
                                                     rdp_graphics_progressive_context* context)
{
    rdp_graphics_progressive_block block;
    rdp_stream stream;

    if (!data || !context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_progressive_parse_block(data, length, &block) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (block.type != RDP_GRAPHICS_PROGRESSIVE_BLOCK_CONTEXT || block.length != 10u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(context, 0, sizeof(*context));
    rdp_stream_init(&stream, block.payload, block.payload_len);
    if (rdp_stream_read_u8(&stream, &context->context_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &context->tile_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &context->flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (context->tile_size != RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_progressive_parse_frame_begin(
    const void* data,
    size_t length,
    rdp_graphics_progressive_frame_begin* frame_begin)
{
    rdp_graphics_progressive_block block;
    rdp_stream stream;

    if (!data || !frame_begin)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_progressive_parse_block(data, length, &block) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (block.type != RDP_GRAPHICS_PROGRESSIVE_BLOCK_FRAME_BEGIN || block.length != 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(frame_begin, 0, sizeof(*frame_begin));
    rdp_stream_init(&stream, block.payload, block.payload_len);
    if (rdp_stream_read_u32_le(&stream, &frame_begin->frame_index) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &frame_begin->region_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (frame_begin->region_count == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_progressive_parse_frame_end(const void* data, size_t length)
{
    rdp_graphics_progressive_block block;

    if (!data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_progressive_parse_block(data, length, &block) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (block.type != RDP_GRAPHICS_PROGRESSIVE_BLOCK_FRAME_END || block.length != 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_progressive_parse_region(const void* data,
                                                    size_t length,
                                                    rdp_graphics_progressive_region* region)
{
    rdp_graphics_progressive_block block;
    rdp_stream stream;
    size_t rects_len = 0;
    size_t quant_values_len = 0;
    size_t progressive_quant_values_len = 0;

    if (!data || !region)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_progressive_parse_block(data, length, &block) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (block.type != RDP_GRAPHICS_PROGRESSIVE_BLOCK_REGION || block.length < 18u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(region, 0, sizeof(*region));
    rdp_stream_init(&stream, block.payload, block.payload_len);
    if (rdp_stream_read_u8(&stream, &region->tile_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &region->rect_count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &region->quant_count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &region->progressive_quant_count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &region->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &region->tile_count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &region->tile_data_size) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (region->tile_size != RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE ||
        region->rect_count == 0 ||
        region->quant_count == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((region->tile_count == 0 && region->tile_data_size != 0) ||
        (region->tile_count != 0 && region->tile_data_size == 0))
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rects_len = (size_t)region->rect_count * 8u;
    quant_values_len = (size_t)region->quant_count * 5u;
    progressive_quant_values_len = (size_t)region->progressive_quant_count * 16u;
    if (rdp_stream_remaining(&stream) < rects_len + quant_values_len + progressive_quant_values_len ||
        (size_t)region->tile_data_size >
            rdp_stream_remaining(&stream) - rects_len - quant_values_len - progressive_quant_values_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &region->rects, rects_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &region->quant_values, quant_values_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream,
                              &region->progressive_quant_values,
                              progressive_quant_values_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &region->tiles, region->tile_data_size) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    region->rects_len = rects_len;
    region->quant_values_len = quant_values_len;
    region->progressive_quant_values_len = progressive_quant_values_len;
    region->tiles_len = (size_t)region->tile_data_size;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_progressive_parse_region_rect(const void* data,
                                                         size_t length,
                                                         rdp_graphics_rect16* rect)
{
    rdp_stream stream;
    uint16_t x = 0;
    uint16_t y = 0;
    uint16_t width = 0;
    uint16_t height = 0;
    uint32_t right = 0;
    uint32_t bottom = 0;

    if (!data || !rect)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(rect, 0, sizeof(*rect));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &x) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &y) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &height) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    right = (uint32_t)x + width;
    bottom = (uint32_t)y + height;
    if (right > UINT16_MAX || bottom > UINT16_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rect->left = x;
    rect->top = y;
    rect->right = (uint16_t)right;
    rect->bottom = (uint16_t)bottom;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_graphics_progressive_read_tile_prefix(rdp_stream* stream,
                                                              uint8_t* quant_idx_y,
                                                              uint8_t* quant_idx_cb,
                                                              uint8_t* quant_idx_cr,
                                                              uint16_t* x_idx,
                                                              uint16_t* y_idx)
{
    if (rdp_stream_read_u8(stream, quant_idx_y) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, quant_idx_cb) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, quant_idx_cr) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, x_idx) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, y_idx) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_graphics_progressive_read_tile_data(rdp_stream* stream,
                                                            uint16_t length,
                                                            const uint8_t** data)
{
    if (length == 0)
    {
        *data = NULL;
        return LIBRDP_STATUS_OK;
    }
    return rdp_stream_read_bytes(stream, data, length);
}

librdp_status rdp_graphics_progressive_parse_tile_simple(
    const void* data,
    size_t length,
    rdp_graphics_progressive_tile_simple* tile)
{
    rdp_graphics_progressive_block block;
    rdp_stream stream;
    size_t payload_len = 0;

    if (!data || !tile)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_progressive_parse_block(data, length, &block) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (block.type != RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_SIMPLE || block.length < 22u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(tile, 0, sizeof(*tile));
    rdp_stream_init(&stream, block.payload, block.payload_len);
    tile->block_type = block.type;
    if (rdp_graphics_progressive_read_tile_prefix(&stream,
                                                  &tile->quant_idx_y,
                                                  &tile->quant_idx_cb,
                                                  &tile->quant_idx_cr,
                                                  &tile->x_idx,
                                                  &tile->y_idx) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &tile->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &tile->y_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &tile->cb_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &tile->cr_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &tile->tail_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    payload_len = (size_t)tile->y_len + tile->cb_len + tile->cr_len + tile->tail_len;
    if (rdp_stream_remaining(&stream) != payload_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_graphics_progressive_read_tile_data(&stream, tile->y_len, &tile->y_data) != LIBRDP_STATUS_OK ||
        rdp_graphics_progressive_read_tile_data(&stream, tile->cb_len, &tile->cb_data) != LIBRDP_STATUS_OK ||
        rdp_graphics_progressive_read_tile_data(&stream, tile->cr_len, &tile->cr_data) != LIBRDP_STATUS_OK ||
        rdp_graphics_progressive_read_tile_data(&stream, tile->tail_len, &tile->tail_data) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_progressive_parse_tile_first(const void* data,
                                                       size_t length,
                                                       rdp_graphics_progressive_tile_first* tile)
{
    rdp_graphics_progressive_block block;
    rdp_stream stream;
    size_t payload_len = 0;

    if (!data || !tile)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_progressive_parse_block(data, length, &block) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (block.type != RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_FIRST || block.length < 23u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(tile, 0, sizeof(*tile));
    rdp_stream_init(&stream, block.payload, block.payload_len);
    tile->block_type = block.type;
    if (rdp_graphics_progressive_read_tile_prefix(&stream,
                                                  &tile->quant_idx_y,
                                                  &tile->quant_idx_cb,
                                                  &tile->quant_idx_cr,
                                                  &tile->x_idx,
                                                  &tile->y_idx) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &tile->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &tile->progressive_quality) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &tile->y_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &tile->cb_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &tile->cr_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &tile->tail_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    payload_len = (size_t)tile->y_len + tile->cb_len + tile->cr_len + tile->tail_len;
    if (rdp_stream_remaining(&stream) != payload_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_graphics_progressive_read_tile_data(&stream, tile->y_len, &tile->y_data) != LIBRDP_STATUS_OK ||
        rdp_graphics_progressive_read_tile_data(&stream, tile->cb_len, &tile->cb_data) != LIBRDP_STATUS_OK ||
        rdp_graphics_progressive_read_tile_data(&stream, tile->cr_len, &tile->cr_data) != LIBRDP_STATUS_OK ||
        rdp_graphics_progressive_read_tile_data(&stream, tile->tail_len, &tile->tail_data) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_progressive_parse_tile_upgrade(
    const void* data,
    size_t length,
    rdp_graphics_progressive_tile_upgrade* tile)
{
    rdp_graphics_progressive_block block;
    rdp_stream stream;
    size_t payload_len = 0;

    if (!data || !tile)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_graphics_progressive_parse_block(data, length, &block) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (block.type != RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_UPGRADE || block.length < 26u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(tile, 0, sizeof(*tile));
    rdp_stream_init(&stream, block.payload, block.payload_len);
    tile->block_type = block.type;
    if (rdp_graphics_progressive_read_tile_prefix(&stream,
                                                  &tile->quant_idx_y,
                                                  &tile->quant_idx_cb,
                                                  &tile->quant_idx_cr,
                                                  &tile->x_idx,
                                                  &tile->y_idx) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &tile->progressive_quality) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &tile->y_srl_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &tile->y_raw_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &tile->cb_srl_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &tile->cb_raw_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &tile->cr_srl_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &tile->cr_raw_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    payload_len = (size_t)tile->y_srl_len + tile->y_raw_len + tile->cb_srl_len +
                  tile->cb_raw_len + tile->cr_srl_len + tile->cr_raw_len;
    if (rdp_stream_remaining(&stream) != payload_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_graphics_progressive_read_tile_data(&stream, tile->y_srl_len, &tile->y_srl_data) !=
            LIBRDP_STATUS_OK ||
        rdp_graphics_progressive_read_tile_data(&stream, tile->y_raw_len, &tile->y_raw_data) !=
            LIBRDP_STATUS_OK ||
        rdp_graphics_progressive_read_tile_data(&stream, tile->cb_srl_len, &tile->cb_srl_data) !=
            LIBRDP_STATUS_OK ||
        rdp_graphics_progressive_read_tile_data(&stream, tile->cb_raw_len, &tile->cb_raw_data) !=
            LIBRDP_STATUS_OK ||
        rdp_graphics_progressive_read_tile_data(&stream, tile->cr_srl_len, &tile->cr_srl_data) !=
            LIBRDP_STATUS_OK ||
        rdp_graphics_progressive_read_tile_data(&stream, tile->cr_raw_len, &tile->cr_raw_data) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static int rdp_graphics_progressive_known_block(uint16_t type)
{
    return type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_SYNC ||
           type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_FRAME_BEGIN ||
           type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_FRAME_END ||
           type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_CONTEXT ||
           type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_REGION ||
           type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_SIMPLE ||
           type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_FIRST ||
           type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_UPGRADE;
}

static librdp_status rdp_graphics_progressive_validate_tile_quant(uint8_t quant_idx_y,
                                                                  uint8_t quant_idx_cb,
                                                                  uint8_t quant_idx_cr,
                                                                  uint8_t progressive_quality,
                                                                  const rdp_graphics_progressive_region* region)
{
    if (!region || quant_idx_y >= region->quant_count ||
        quant_idx_cb >= region->quant_count ||
        quant_idx_cr >= region->quant_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (progressive_quality != 0xffu && progressive_quality >= region->progressive_quant_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_graphics_progressive_count_region_tiles(const rdp_graphics_progressive_region* region,
                                                                 rdp_graphics_progressive_stream* stream)
{
    size_t offset = 0;
    uint32_t tiles_seen = 0;

    while (offset < region->tiles_len)
    {
        rdp_graphics_progressive_block block;

        if (rdp_graphics_progressive_parse_block(region->tiles + offset,
                                                 region->tiles_len - offset,
                                                 &block) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_SIMPLE)
        {
            rdp_graphics_progressive_tile_simple tile;

            if (rdp_graphics_progressive_parse_tile_simple(region->tiles + offset,
                                                           region->tiles_len - offset,
                                                           &tile) != LIBRDP_STATUS_OK ||
                rdp_graphics_progressive_validate_tile_quant(tile.quant_idx_y,
                                                             tile.quant_idx_cb,
                                                             tile.quant_idx_cr,
                                                             0xffu,
                                                             region) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            stream->simple_tile_count++;
        }
        else if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_FIRST)
        {
            rdp_graphics_progressive_tile_first tile;

            if (rdp_graphics_progressive_parse_tile_first(region->tiles + offset,
                                                          region->tiles_len - offset,
                                                          &tile) != LIBRDP_STATUS_OK ||
                rdp_graphics_progressive_validate_tile_quant(tile.quant_idx_y,
                                                             tile.quant_idx_cb,
                                                             tile.quant_idx_cr,
                                                             tile.progressive_quality,
                                                             region) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            stream->first_tile_count++;
        }
        else if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_UPGRADE)
        {
            rdp_graphics_progressive_tile_upgrade tile;

            if (rdp_graphics_progressive_parse_tile_upgrade(region->tiles + offset,
                                                            region->tiles_len - offset,
                                                            &tile) != LIBRDP_STATUS_OK ||
                rdp_graphics_progressive_validate_tile_quant(tile.quant_idx_y,
                                                             tile.quant_idx_cb,
                                                             tile.quant_idx_cr,
                                                             tile.progressive_quality,
                                                             region) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            stream->upgrade_tile_count++;
        }
        else
        {
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        offset += block.length;
        tiles_seen++;
    }
    if (tiles_seen != region->tile_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    stream->tile_count += tiles_seen;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_graphics_progressive_parse_stream(const void* data,
                                                    size_t length,
                                                    rdp_graphics_progressive_stream* stream)
{
    size_t offset = 0;

    if (!data || !stream || length == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(stream, 0, sizeof(*stream));
    while (offset < length)
    {
        rdp_graphics_progressive_block block;

        if (rdp_graphics_progressive_parse_block((const uint8_t*)data + offset,
                                                 length - offset,
                                                 &block) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        stream->block_count++;
        if (rdp_graphics_progressive_known_block(block.type))
            stream->known_block_count++;
        if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_CONTEXT)
        {
            rdp_graphics_progressive_context context;

            if (rdp_graphics_progressive_parse_context((const uint8_t*)data + offset,
                                                       length - offset,
                                                       &context) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            stream->has_context = 1;
            stream->tile_size = (uint8_t)context.tile_size;
            stream->flags = context.flags;
        }
        else if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_FRAME_BEGIN)
        {
            rdp_graphics_progressive_frame_begin frame_begin;

            if (rdp_graphics_progressive_parse_frame_begin((const uint8_t*)data + offset,
                                                           length - offset,
                                                           &frame_begin) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            stream->has_frame_begin = 1;
            stream->region_count += frame_begin.region_count;
        }
        else if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_FRAME_END)
        {
            if (rdp_graphics_progressive_parse_frame_end((const uint8_t*)data + offset,
                                                         length - offset) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            stream->has_frame_end = 1;
        }
        else if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_REGION)
        {
            rdp_graphics_progressive_region region;

            if (rdp_graphics_progressive_parse_region((const uint8_t*)data + offset,
                                                      length - offset,
                                                      &region) != LIBRDP_STATUS_OK ||
                rdp_graphics_progressive_count_region_tiles(&region, stream) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        offset += block.length;
    }
    return offset == length ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}
