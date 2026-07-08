#ifndef LIBRDP_CLIPBOARD_H
#define LIBRDP_CLIPBOARD_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct librdp_session librdp_session;

#define LIBRDP_CLIPBOARD_FORMAT_TEXT 1u
#define LIBRDP_CLIPBOARD_FORMAT_BITMAP 2u
#define LIBRDP_CLIPBOARD_FORMAT_DIB 8u
#define LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT 13u
#define LIBRDP_CLIPBOARD_FORMAT_HDROP 15u

typedef struct librdp_clipboard_format
{
    uint32_t format_id;
    const uint8_t* name;
    size_t name_len;
} librdp_clipboard_format;

librdp_status librdp_session_clipboard_set_data(librdp_session* session,
                                                uint32_t format_id,
                                                const void* data,
                                                size_t data_len);
librdp_status librdp_session_clipboard_clear(librdp_session* session);
librdp_status librdp_session_clipboard_request_data(librdp_session* session, uint32_t format_id);

#ifdef __cplusplus
}
#endif

#endif
