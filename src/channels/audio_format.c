#include "channels/audio_format.h"

#include "common/stream.h"

#include <string.h>

size_t rdp_audio_format_encoded_size(const rdp_audio_format* format)
{
    if (!format || format->extra_data_len > 0xffffu)
        return 0;
    return RDP_AUDIO_FORMAT_MIN_SIZE + format->extra_data_len;
}

librdp_status rdp_audio_format_parse(const void* data,
                                     size_t length,
                                     rdp_audio_format* format,
                                     size_t* consumed)
{
    rdp_stream stream;
    uint16_t extra_len = 0;

    if (!data || !format)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_AUDIO_FORMAT_MIN_SIZE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(format, 0, sizeof(*format));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &format->format_tag) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &format->channels) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &format->samples_per_sec) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &format->avg_bytes_per_sec) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &format->block_align) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &format->bits_per_sample) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &extra_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (extra_len > rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (extra_len > 0 &&
        rdp_stream_read_bytes(&stream, &format->extra_data, extra_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    format->extra_data_len = extra_len;
    if (format->format_tag == RDP_AUDIO_FORMAT_EXTENSIBLE && extra_len != 22u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (format->channels == 0 || format->samples_per_sec == 0 || format->block_align == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (consumed)
        *consumed = RDP_AUDIO_FORMAT_MIN_SIZE + (size_t)extra_len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_format_validate_list(const void* data,
                                             size_t length,
                                             uint32_t format_count,
                                             size_t* consumed)
{
    const uint8_t* bytes = (const uint8_t*)data;
    size_t offset = 0;
    uint32_t i = 0;

    if ((!data && length > 0) || format_count > RDP_AUDIO_FORMAT_MAX_COUNT)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < format_count; i++)
    {
        rdp_audio_format format;
        size_t item = 0;

        if (rdp_audio_format_parse(bytes + offset, length - offset, &format, &item) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        offset += item;
    }
    if (consumed)
        *consumed = offset;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_format_get_from_list(const void* data,
                                             size_t length,
                                             uint32_t format_count,
                                             uint32_t index,
                                             rdp_audio_format* format)
{
    const uint8_t* bytes = (const uint8_t*)data;
    size_t offset = 0;
    uint32_t i = 0;

    if ((!data && length > 0) || !format || format_count > RDP_AUDIO_FORMAT_MAX_COUNT || index >= format_count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < format_count; i++)
    {
        size_t item = 0;
        librdp_status status = rdp_audio_format_parse(bytes + offset, length - offset, format, &item);
        if (status != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (i == index)
            return LIBRDP_STATUS_OK;
        offset += item;
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_audio_format_write(rdp_buffer* buffer, const rdp_audio_format* format)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !format || (!format->extra_data && format->extra_data_len > 0) ||
        format->channels == 0 || format->samples_per_sec == 0 || format->block_align == 0 ||
        format->extra_data_len > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (format->format_tag == RDP_AUDIO_FORMAT_EXTENSIBLE && format->extra_data_len != 22u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u16_le(buffer, format->format_tag);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, format->channels);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, format->samples_per_sec);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, format->avg_bytes_per_sec);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, format->block_align);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, format->bits_per_sample);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)format->extra_data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, format->extra_data, format->extra_data_len);
    return status;
}

int rdp_audio_format_wire_equal(const rdp_audio_format* a, const rdp_audio_format* b)
{
    if (!a || !b)
        return 0;
    if (a->format_tag != b->format_tag || a->channels != b->channels ||
        a->samples_per_sec != b->samples_per_sec || a->avg_bytes_per_sec != b->avg_bytes_per_sec ||
        a->block_align != b->block_align || a->bits_per_sample != b->bits_per_sample ||
        a->extra_data_len != b->extra_data_len)
        return 0;
    if (a->extra_data_len == 0)
        return 1;
    return a->extra_data && b->extra_data && memcmp(a->extra_data, b->extra_data, a->extra_data_len) == 0;
}
