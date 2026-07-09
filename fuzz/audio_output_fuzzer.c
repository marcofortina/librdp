#include "channels/audio_output.h"

int LLVMFuzzerTestOneInput(const unsigned char* data, unsigned long size)
{
    rdp_audio_output_header header;
    rdp_audio_output_formats formats;
    rdp_audio_output_training training;
    rdp_audio_output_wave_info wave_info;
    rdp_audio_output_wave_data wave_data;
    rdp_audio_output_wave2 wave2;
    rdp_audio_output_crypt_key crypt_key;
    rdp_audio_output_wave_encrypt wave_encrypt;
    rdp_audio_output_udp_wave udp_wave;
    rdp_audio_output_udp_wave_last udp_wave_last;
    rdp_audio_output_frag_data frag;
    rdp_audio_output_setting setting;
    rdp_audio_format pcm;
    rdp_buffer out;
    uint16_t timestamp = 0;
    uint16_t quality = 0;
    uint8_t block_no = 0;

    if (!data && size > 0)
        return 0;

    rdp_buffer_init(&out);
    (void)rdp_audio_output_parse_header(data, (size_t)size, &header);
    (void)rdp_audio_output_parse_formats(data, (size_t)size, &formats);
    (void)rdp_audio_output_parse_training(data, (size_t)size, &training);
    (void)rdp_audio_output_parse_wave_info(data, (size_t)size, &wave_info);
    (void)rdp_audio_output_parse_wave_data(data, (size_t)size, &wave_data);
    (void)rdp_audio_output_parse_wave2(data, (size_t)size, &wave2);
    (void)rdp_audio_output_parse_quality_mode(data, (size_t)size, &quality);
    (void)rdp_audio_output_parse_wave_confirm(data, (size_t)size, &timestamp, &block_no);
    (void)rdp_audio_output_parse_crypt_key(data, (size_t)size, &crypt_key);
    (void)rdp_audio_output_parse_wave_encrypt(data, (size_t)size, 0, &wave_encrypt);
    (void)rdp_audio_output_parse_wave_encrypt(data, (size_t)size, 1, &wave_encrypt);
    (void)rdp_audio_output_parse_udp_wave(data, (size_t)size, &udp_wave);
    (void)rdp_audio_output_parse_udp_wave_last(data, (size_t)size, &udp_wave_last);
    (void)rdp_audio_output_parse_frag_data(data, (size_t)size, &frag);
    (void)rdp_audio_output_parse_setting(data, (size_t)size, RDP_AUDIO_OUTPUT_SETVOLUME, &setting);
    (void)rdp_audio_output_parse_setting(data, (size_t)size, RDP_AUDIO_OUTPUT_SETPITCH, &setting);
    (void)rdp_audio_output_parse_close(data, (size_t)size);

    pcm.format_tag = RDP_AUDIO_FORMAT_PCM;
    pcm.channels = 2;
    pcm.samples_per_sec = 44100;
    pcm.avg_bytes_per_sec = 176400;
    pcm.block_align = 4;
    pcm.bits_per_sample = 16;
    pcm.extra_data = NULL;
    pcm.extra_data_len = 0;
    (void)rdp_audio_output_write_client_formats(&out,
                                                RDP_AUDIO_OUTPUT_CAP_ALIVE,
                                                0xffffffffu,
                                                0x00010000u,
                                                0,
                                                size > 0 ? data[0] : 0,
                                                6,
                                                &pcm,
                                                1);
    out.length = 0;
    (void)rdp_audio_output_write_quality_mode(&out, size > 0 ? (uint16_t)(data[0] % 3u) : 0);
    out.length = 0;
    (void)rdp_audio_output_write_training_confirm(&out,
                                                  size > 1 ? (uint16_t)(((uint16_t)data[0] << 8) | data[1]) : 0,
                                                  (uint16_t)size);
    out.length = 0;
    (void)rdp_audio_output_write_wave_confirm(&out, (uint16_t)size, size > 0 ? data[0] : 0);
    out.length = 0;
    (void)rdp_audio_output_write_setting(&out,
                                         size > 0 && (data[0] & 1u) ? RDP_AUDIO_OUTPUT_SETPITCH :
                                                                     RDP_AUDIO_OUTPUT_SETVOLUME,
                                         (uint32_t)size);
    rdp_buffer_free(&out);
    return 0;
}
