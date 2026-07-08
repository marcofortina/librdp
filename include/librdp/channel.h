#ifndef LIBRDP_CHANNEL_H
#define LIBRDP_CHANNEL_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct librdp_session librdp_session;
typedef uint32_t librdp_channel_id;

librdp_status librdp_session_channel_send(librdp_session* session,
                                          librdp_channel_id channel_id,
                                          const void* data,
                                          size_t data_len);
librdp_status librdp_session_channel_close(librdp_session* session, librdp_channel_id channel_id);

#ifdef __cplusplus
}
#endif

#endif
