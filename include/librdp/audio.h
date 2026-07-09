#ifndef LIBRDP_AUDIO_H
#define LIBRDP_AUDIO_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct librdp_session librdp_session;

#define LIBRDP_AUDIO_FORMAT_PCM 0x0001u
#define LIBRDP_AUDIO_FORMAT_ALAW 0x0006u
#define LIBRDP_AUDIO_FORMAT_MULAW 0x0007u
#define LIBRDP_AUDIO_INPUT_RESULT_OK 0x00000000u
#define LIBRDP_AUDIO_INPUT_RESULT_FAIL 0x80004005u

typedef struct librdp_audio_format
{
    uint16_t format_tag;
    uint16_t channels;
    uint32_t samples_per_sec;
    uint32_t avg_bytes_per_sec;
    uint16_t block_align;
    uint16_t bits_per_sample;
    const uint8_t* extra_data;
    size_t extra_data_len;
} librdp_audio_format;

librdp_status librdp_session_audio_input_open_reply(librdp_session* session, uint32_t result);
librdp_status librdp_session_audio_input_send_data(librdp_session* session, const void* data, size_t data_len);
librdp_status librdp_session_audio_input_send_format_change(librdp_session* session, uint32_t new_format);

#ifdef __cplusplus
}
#endif

#endif
