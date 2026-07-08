#include "channels/audio_output.h"

int LLVMFuzzerTestOneInput(const unsigned char* data, unsigned long size)
{
    rdp_audio_output_header header;
    rdp_audio_output_formats formats;
    rdp_audio_output_training training;
    rdp_audio_output_wave_info wave_info;
    rdp_audio_output_wave_data wave_data;
    rdp_audio_output_wave2 wave2;
    rdp_audio_output_setting setting;
    rdp_audio_format pcm;
    rdp_buffer out;

    if (!data && size > 0)
        return 0;

    rdp_buffer_init(&out);
    (void)rdp_audio_output_parse_header(data, (size_t)size, &header);
    (void)rdp_audio_output_parse_formats(data, (size_t)size, &formats);
    (void)rdp_audio_output_parse_training(data, (size_t)size, &training);
    (void)rdp_audio_output_parse_wave_info(data, (size_t)size, &wave_info);
    (void)rdp_audio_output_parse_wave_data(data, (size_t)size, &wave_data);
    (void)rdp_audio_output_parse_wave2(data, (size_t)size, &wave2);
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
    rdp_buffer_free(&out);
    return 0;
}
