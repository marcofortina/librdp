#include "channels/audio_output.h"

#include "common/stream.h"

#include <string.h>

static librdp_status rdp_audio_output_write_header(rdp_buffer* buffer,
                                                   uint8_t msg_type,
                                                   uint8_t pad,
                                                   uint16_t body_size)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, msg_type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, pad);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, body_size);
    return status;
}

librdp_status rdp_audio_output_parse_header(const void* data,
                                            size_t length,
                                            rdp_audio_output_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &header->msg_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &header->pad) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->body_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &header->body, rdp_stream_remaining(&stream)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->body_len = length - 4u;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_output_parse_formats(const void* data,
                                             size_t length,
                                             rdp_audio_output_formats* formats)
{
    rdp_audio_output_header header;
    rdp_stream stream;
    size_t formats_len = 0;
    size_t consumed = 0;

    if (!data || !formats)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(formats, 0, sizeof(*formats));
    if (rdp_audio_output_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.msg_type != RDP_AUDIO_OUTPUT_FORMATS || header.body_size != header.body_len || header.body_len < 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, header.body, header.body_len);
    if (rdp_stream_read_u32_le(&stream, &formats->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &formats->volume) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &formats->pitch) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &formats->datagram_port) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &formats->format_count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &formats->last_block_confirmed) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &formats->version) != LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 1) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    formats_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &formats->formats, formats_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_audio_format_validate_list(formats->formats,
                                       formats_len,
                                       formats->format_count,
                                       &consumed) != LIBRDP_STATUS_OK ||
        consumed != formats_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    formats->formats_len = formats_len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_output_write_client_formats(rdp_buffer* buffer,
                                                   uint32_t flags,
                                                   uint32_t volume,
                                                   uint32_t pitch,
                                                   uint16_t datagram_port,
                                                   uint8_t last_block_confirmed,
                                                   uint16_t version,
                                                   const rdp_audio_format* formats,
                                                   uint16_t format_count)
{
    rdp_buffer body;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t i = 0;

    if (!buffer || (!formats && format_count > 0) || format_count > RDP_AUDIO_FORMAT_MAX_COUNT)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&body);
    status = rdp_buffer_append_u32_le(&body, flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&body, volume);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&body, pitch);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_be(&body, datagram_port);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&body, format_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&body, last_block_confirmed);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&body, version);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&body, 0);
    for (i = 0; status == LIBRDP_STATUS_OK && i < format_count; i++)
        status = rdp_audio_format_write(&body, &formats[i]);
    if (status == LIBRDP_STATUS_OK)
    {
        if (body.length > 0xffffu)
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        else
            status = rdp_audio_output_write_header(buffer,
                                                   RDP_AUDIO_OUTPUT_FORMATS,
                                                   0,
                                                   (uint16_t)body.length);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, body.data, body.length);
    rdp_buffer_free(&body);
    return status;
}

librdp_status rdp_audio_output_write_quality_mode(rdp_buffer* buffer, uint16_t quality_mode)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || quality_mode > RDP_AUDIO_OUTPUT_QUALITY_HIGH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_audio_output_write_header(buffer, RDP_AUDIO_OUTPUT_QUALITYMODE, 0, 4);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, quality_mode);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    return status;
}

librdp_status rdp_audio_output_parse_training(const void* data,
                                             size_t length,
                                             rdp_audio_output_training* training)
{
    rdp_audio_output_header header;
    rdp_stream stream;

    if (!data || !training)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(training, 0, sizeof(*training));
    if (rdp_audio_output_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.msg_type != RDP_AUDIO_OUTPUT_TRAINING || header.body_size != header.body_len || header.body_len < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, header.body, header.body_len);
    if (rdp_stream_read_u16_le(&stream, &training->timestamp) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &training->packet_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &training->data, rdp_stream_remaining(&stream)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    training->data_len = header.body_len - 4u;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_output_write_training_confirm(rdp_buffer* buffer,
                                                     uint16_t timestamp,
                                                     uint16_t packet_size)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_audio_output_write_header(buffer, RDP_AUDIO_OUTPUT_TRAINING, 0, 4);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, timestamp);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, packet_size);
    return status;
}

librdp_status rdp_audio_output_parse_wave_info(const void* data,
                                              size_t length,
                                              rdp_audio_output_wave_info* wave)
{
    rdp_audio_output_header header;
    rdp_stream stream;

    if (!data || !wave)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(wave, 0, sizeof(*wave));
    if (rdp_audio_output_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.msg_type != RDP_AUDIO_OUTPUT_WAVE || header.body_len != 12u || header.body_size < 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, header.body, header.body_len);
    if (rdp_stream_read_u16_le(&stream, &wave->timestamp) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &wave->format_no) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &wave->block_no) != LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 3) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &wave->first_data, 4) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    wave->first_data_len = 4;
    wave->expected_data_len = (uint16_t)(header.body_size - 12u);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_output_parse_wave_data(const void* data,
                                              size_t length,
                                              rdp_audio_output_wave_data* wave)
{
    rdp_stream stream;

    if (!data || !wave)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(wave, 0, sizeof(*wave));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &wave->data, rdp_stream_remaining(&stream)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    wave->data_len = length - 4u;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_output_parse_wave2(const void* data, size_t length, rdp_audio_output_wave2* wave)
{
    rdp_audio_output_header header;
    rdp_stream stream;

    if (!data || !wave)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(wave, 0, sizeof(*wave));
    if (rdp_audio_output_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.msg_type != RDP_AUDIO_OUTPUT_WAVE2 || header.body_size != header.body_len || header.body_len < 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, header.body, header.body_len);
    if (rdp_stream_read_u16_le(&stream, &wave->timestamp) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &wave->format_no) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &wave->block_no) != LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 3) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &wave->audio_timestamp) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &wave->data, rdp_stream_remaining(&stream)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    wave->data_len = header.body_len - 12u;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_output_write_wave_confirm(rdp_buffer* buffer,
                                                 uint16_t timestamp,
                                                 uint8_t block_no)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_audio_output_write_header(buffer, RDP_AUDIO_OUTPUT_WAVECONFIRM, 0, 4);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, timestamp);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, block_no);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    return status;
}

librdp_status rdp_audio_output_parse_setting(const void* data,
                                            size_t length,
                                            uint8_t expected_type,
                                            rdp_audio_output_setting* setting)
{
    rdp_audio_output_header header;
    rdp_stream stream;

    if (!data || !setting)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(setting, 0, sizeof(*setting));
    if (rdp_audio_output_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.msg_type != expected_type || header.body_size != 4u || header.body_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, header.body, header.body_len);
    if (rdp_stream_read_u32_le(&stream, &setting->value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_output_parse_close(const void* data, size_t length)
{
    rdp_audio_output_header header;

    if (!data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_audio_output_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.msg_type != RDP_AUDIO_OUTPUT_CLOSE || header.body_size != 0 || header.body_len != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}
