#include "channels/audio_input.h"

int LLVMFuzzerTestOneInput(const unsigned char* data, unsigned long size)
{
    rdp_audio_input_header header;
    rdp_audio_input_formats formats;
    rdp_audio_input_open open;
    rdp_audio_input_data data_pdu;
    rdp_audio_format pcm;
    rdp_buffer out;
    uint32_t value = 0;

    if (!data && size > 0)
        return 0;

    rdp_buffer_init(&out);
    (void)rdp_audio_input_parse_header(data, (size_t)size, &header);
    (void)rdp_audio_input_parse_version(data, (size_t)size, &value);
    (void)rdp_audio_input_parse_formats(data, (size_t)size, &formats);
    (void)rdp_audio_input_parse_client_formats(data, (size_t)size, &formats);
    (void)rdp_audio_input_parse_open(data, (size_t)size, &open);
    (void)rdp_audio_input_parse_open_reply(data, (size_t)size, &value);
    (void)rdp_audio_input_parse_empty(data, (size_t)size, RDP_AUDIO_INPUT_DATA_INCOMING);
    (void)rdp_audio_input_parse_data(data, (size_t)size, &data_pdu);
    (void)rdp_audio_input_parse_format_change(data, (size_t)size, &value);

    pcm.format_tag = RDP_AUDIO_FORMAT_PCM;
    pcm.channels = 2;
    pcm.samples_per_sec = 44100;
    pcm.avg_bytes_per_sec = 176400;
    pcm.block_align = 4;
    pcm.bits_per_sample = 16;
    pcm.extra_data = NULL;
    pcm.extra_data_len = 0;
    (void)rdp_audio_input_write_version(&out, RDP_AUDIO_INPUT_VERSION_2);
    out.length = 0;
    (void)rdp_audio_input_write_formats(&out, &pcm, 1);
    out.length = 0;
    (void)rdp_audio_input_write_formats_with_extra(&out, &pcm, 1, data, (size_t)size);
    out.length = 0;
    (void)rdp_audio_input_write_open(&out, (uint32_t)size, size > 0 ? data[0] : 0, &pcm);
    out.length = 0;
    (void)rdp_audio_input_write_open_reply(&out, RDP_AUDIO_INPUT_RESULT_FAIL);
    out.length = 0;
    (void)rdp_audio_input_write_incoming_data(&out);
    out.length = 0;
    (void)rdp_audio_input_write_data(&out, data, (size_t)size);
    out.length = 0;
    (void)rdp_audio_input_write_format_change(&out, (uint32_t)size);
    rdp_buffer_free(&out);
    return 0;
}
