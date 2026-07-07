#ifndef LIBRDP_SESSION_H
#define LIBRDP_SESSION_H

#include <stdint.h>

#include <librdp/error.h>
#include <librdp/event.h>
#include <librdp/settings.h>
#include <librdp/surface.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct librdp_session librdp_session;

typedef enum librdp_session_state
{
    LIBRDP_SESSION_IDLE = 0,
    LIBRDP_SESSION_CONNECTING = 1,
    LIBRDP_SESSION_CONNECTED = 2,
    LIBRDP_SESSION_ACTIVE = 3,
    LIBRDP_SESSION_CLOSING = 4,
    LIBRDP_SESSION_CLOSED = 5,
    LIBRDP_SESSION_FAILED = 6
} librdp_session_state;

typedef void (*librdp_event_callback)(librdp_session* session, const librdp_event* event, void* user_data);

librdp_session* librdp_session_new(const librdp_settings* settings);
void librdp_session_free(librdp_session* session);
void librdp_session_set_event_callback(librdp_session* session, librdp_event_callback callback, void* user_data);
librdp_status librdp_session_connect(librdp_session* session);
librdp_status librdp_session_run_once(librdp_session* session, int timeout_ms);
librdp_status librdp_session_disconnect(librdp_session* session);
librdp_status librdp_session_resize(librdp_session* session, uint32_t width, uint32_t height);
librdp_status librdp_session_refresh(librdp_session* session, uint32_t x, uint32_t y, uint32_t width, uint32_t height);
librdp_status librdp_session_send_key(librdp_session* session, const librdp_key_event* event);
librdp_status librdp_session_send_mouse(librdp_session* session, const librdp_mouse_event* event);
librdp_session_state librdp_session_get_state(const librdp_session* session);
const librdp_surface* librdp_session_get_surface(const librdp_session* session);

#ifdef __cplusplus
}
#endif

#endif
