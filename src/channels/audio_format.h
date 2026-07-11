/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef RDP_CHANNELS_AUDIO_FORMAT_H
#define RDP_CHANNELS_AUDIO_FORMAT_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_AUDIO_FORMAT_PCM 0x0001u
#define RDP_AUDIO_FORMAT_ALAW 0x0006u
#define RDP_AUDIO_FORMAT_MULAW 0x0007u
#define RDP_AUDIO_FORMAT_EXTENSIBLE 0xfffeu
#define RDP_AUDIO_FORMAT_MIN_SIZE 18u
#define RDP_AUDIO_FORMAT_MAX_COUNT 256u

typedef struct rdp_audio_format
{
    uint16_t format_tag;
    uint16_t channels;
    uint32_t samples_per_sec;
    uint32_t avg_bytes_per_sec;
    uint16_t block_align;
    uint16_t bits_per_sample;
    const uint8_t* extra_data;
    size_t extra_data_len;
} rdp_audio_format;

size_t rdp_audio_format_encoded_size(const rdp_audio_format* format);
librdp_status rdp_audio_format_parse(const void* data,
                                     size_t length,
                                     rdp_audio_format* format,
                                     size_t* consumed);
librdp_status rdp_audio_format_validate_list(const void* data,
                                             size_t length,
                                             uint32_t format_count,
                                             size_t* consumed);
librdp_status rdp_audio_format_get_from_list(const void* data,
                                             size_t length,
                                             uint32_t format_count,
                                             uint32_t index,
                                             rdp_audio_format* format);
librdp_status rdp_audio_format_write(rdp_buffer* buffer, const rdp_audio_format* format);
int rdp_audio_format_wire_equal(const rdp_audio_format* a, const rdp_audio_format* b);

#endif
