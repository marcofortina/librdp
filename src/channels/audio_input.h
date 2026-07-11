/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef RDP_CHANNELS_AUDIO_INPUT_H
#define RDP_CHANNELS_AUDIO_INPUT_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "channels/audio_format.h"
#include "common/buffer.h"

#define RDP_AUDIO_INPUT_CHANNEL_NAME "AUDIO_INPUT"

#define RDP_AUDIO_INPUT_VERSION 0x01u
#define RDP_AUDIO_INPUT_FORMATS 0x02u
#define RDP_AUDIO_INPUT_OPEN 0x03u
#define RDP_AUDIO_INPUT_OPEN_REPLY 0x04u
#define RDP_AUDIO_INPUT_DATA_INCOMING 0x05u
#define RDP_AUDIO_INPUT_DATA 0x06u
#define RDP_AUDIO_INPUT_FORMAT_CHANGE 0x07u

#define RDP_AUDIO_INPUT_VERSION_1 0x00000001u
#define RDP_AUDIO_INPUT_VERSION_2 0x00000002u

#define RDP_AUDIO_INPUT_RESULT_OK 0x00000000u
#define RDP_AUDIO_INPUT_RESULT_FAIL 0x80004005u

typedef struct rdp_audio_input_header
{
    uint8_t message_id;
    const uint8_t* body;
    size_t body_len;
} rdp_audio_input_header;

typedef struct rdp_audio_input_formats
{
    uint32_t format_count;
    uint32_t formats_packet_size;
    const uint8_t* formats;
    size_t formats_len;
    const uint8_t* extra_data;
    size_t extra_data_len;
} rdp_audio_input_formats;

typedef struct rdp_audio_input_open
{
    uint32_t frames_per_packet;
    uint32_t initial_format;
    rdp_audio_format format;
} rdp_audio_input_open;

typedef struct rdp_audio_input_data
{
    const uint8_t* data;
    size_t data_len;
} rdp_audio_input_data;

librdp_status rdp_audio_input_parse_header(const void* data, size_t length, rdp_audio_input_header* header);
librdp_status rdp_audio_input_parse_version(const void* data, size_t length, uint32_t* version);
librdp_status rdp_audio_input_write_version(rdp_buffer* buffer, uint32_t version);
librdp_status rdp_audio_input_parse_formats(const void* data,
                                            size_t length,
                                            rdp_audio_input_formats* formats);
librdp_status rdp_audio_input_parse_client_formats(const void* data,
                                                   size_t length,
                                                   rdp_audio_input_formats* formats);
librdp_status rdp_audio_input_write_formats(rdp_buffer* buffer,
                                           const rdp_audio_format* formats,
                                           uint32_t format_count);
librdp_status rdp_audio_input_write_formats_with_extra(rdp_buffer* buffer,
                                                       const rdp_audio_format* formats,
                                                       uint32_t format_count,
                                                       const void* extra_data,
                                                       size_t extra_data_len);
librdp_status rdp_audio_input_parse_open(const void* data, size_t length, rdp_audio_input_open* open);
librdp_status rdp_audio_input_write_open(rdp_buffer* buffer,
                                         uint32_t frames_per_packet,
                                         uint32_t initial_format,
                                         const rdp_audio_format* format);
librdp_status rdp_audio_input_write_open_reply(rdp_buffer* buffer, uint32_t result);
librdp_status rdp_audio_input_parse_open_reply(const void* data, size_t length, uint32_t* result);
librdp_status rdp_audio_input_write_incoming_data(rdp_buffer* buffer);
librdp_status rdp_audio_input_parse_empty(const void* data, size_t length, uint8_t expected_message);
librdp_status rdp_audio_input_parse_data(const void* data, size_t length, rdp_audio_input_data* data_pdu);
librdp_status rdp_audio_input_write_data(rdp_buffer* buffer, const void* data, size_t data_len);
librdp_status rdp_audio_input_parse_format_change(const void* data, size_t length, uint32_t* new_format);
librdp_status rdp_audio_input_write_format_change(rdp_buffer* buffer, uint32_t new_format);

#endif
