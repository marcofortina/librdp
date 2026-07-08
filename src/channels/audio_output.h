#ifndef RDP_CHANNELS_AUDIO_OUTPUT_H
#define RDP_CHANNELS_AUDIO_OUTPUT_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "channels/audio_format.h"
#include "common/buffer.h"

#define RDP_AUDIO_OUTPUT_CHANNEL_NAME "rdpsnd"

#define RDP_AUDIO_OUTPUT_CLOSE 0x01u
#define RDP_AUDIO_OUTPUT_WAVE 0x02u
#define RDP_AUDIO_OUTPUT_SETVOLUME 0x03u
#define RDP_AUDIO_OUTPUT_SETPITCH 0x04u
#define RDP_AUDIO_OUTPUT_WAVECONFIRM 0x05u
#define RDP_AUDIO_OUTPUT_TRAINING 0x06u
#define RDP_AUDIO_OUTPUT_FORMATS 0x07u
#define RDP_AUDIO_OUTPUT_CRYPTKEY 0x08u
#define RDP_AUDIO_OUTPUT_WAVEENCRYPT 0x09u
#define RDP_AUDIO_OUTPUT_UDPWAVE 0x0au
#define RDP_AUDIO_OUTPUT_UDPWAVELAST 0x0bu
#define RDP_AUDIO_OUTPUT_QUALITYMODE 0x0cu
#define RDP_AUDIO_OUTPUT_WAVE2 0x0du

#define RDP_AUDIO_OUTPUT_CAP_ALIVE 0x00000001u
#define RDP_AUDIO_OUTPUT_CAP_VOLUME 0x00000002u
#define RDP_AUDIO_OUTPUT_CAP_PITCH 0x00000004u

#define RDP_AUDIO_OUTPUT_QUALITY_DYNAMIC 0x0000u
#define RDP_AUDIO_OUTPUT_QUALITY_MEDIUM 0x0001u
#define RDP_AUDIO_OUTPUT_QUALITY_HIGH 0x0002u

typedef struct rdp_audio_output_header
{
    uint8_t msg_type;
    uint8_t pad;
    uint16_t body_size;
    const uint8_t* body;
    size_t body_len;
} rdp_audio_output_header;

typedef struct rdp_audio_output_formats
{
    uint32_t flags;
    uint32_t volume;
    uint32_t pitch;
    uint16_t datagram_port;
    uint16_t format_count;
    uint8_t last_block_confirmed;
    uint16_t version;
    const uint8_t* formats;
    size_t formats_len;
} rdp_audio_output_formats;

typedef struct rdp_audio_output_training
{
    uint16_t timestamp;
    uint16_t packet_size;
    const uint8_t* data;
    size_t data_len;
} rdp_audio_output_training;

typedef struct rdp_audio_output_wave_info
{
    uint16_t timestamp;
    uint16_t format_no;
    uint8_t block_no;
    const uint8_t* first_data;
    size_t first_data_len;
    uint16_t expected_data_len;
} rdp_audio_output_wave_info;

typedef struct rdp_audio_output_wave_data
{
    const uint8_t* data;
    size_t data_len;
} rdp_audio_output_wave_data;

typedef struct rdp_audio_output_wave2
{
    uint16_t timestamp;
    uint16_t format_no;
    uint8_t block_no;
    uint32_t audio_timestamp;
    const uint8_t* data;
    size_t data_len;
} rdp_audio_output_wave2;

typedef struct rdp_audio_output_setting
{
    uint32_t value;
} rdp_audio_output_setting;

librdp_status rdp_audio_output_parse_header(const void* data,
                                            size_t length,
                                            rdp_audio_output_header* header);
librdp_status rdp_audio_output_parse_formats(const void* data,
                                             size_t length,
                                             rdp_audio_output_formats* formats);
librdp_status rdp_audio_output_write_client_formats(rdp_buffer* buffer,
                                                   uint32_t flags,
                                                   uint32_t volume,
                                                   uint32_t pitch,
                                                   uint16_t datagram_port,
                                                   uint8_t last_block_confirmed,
                                                   uint16_t version,
                                                   const rdp_audio_format* formats,
                                                   uint16_t format_count);
librdp_status rdp_audio_output_write_quality_mode(rdp_buffer* buffer, uint16_t quality_mode);
librdp_status rdp_audio_output_parse_training(const void* data,
                                             size_t length,
                                             rdp_audio_output_training* training);
librdp_status rdp_audio_output_write_training_confirm(rdp_buffer* buffer,
                                                     uint16_t timestamp,
                                                     uint16_t packet_size);
librdp_status rdp_audio_output_parse_wave_info(const void* data,
                                              size_t length,
                                              rdp_audio_output_wave_info* wave);
librdp_status rdp_audio_output_parse_wave_data(const void* data,
                                              size_t length,
                                              rdp_audio_output_wave_data* wave);
librdp_status rdp_audio_output_parse_wave2(const void* data, size_t length, rdp_audio_output_wave2* wave);
librdp_status rdp_audio_output_write_wave_confirm(rdp_buffer* buffer,
                                                 uint16_t timestamp,
                                                 uint8_t block_no);
librdp_status rdp_audio_output_parse_setting(const void* data,
                                            size_t length,
                                            uint8_t expected_type,
                                            rdp_audio_output_setting* setting);
librdp_status rdp_audio_output_parse_close(const void* data, size_t length);

#endif
