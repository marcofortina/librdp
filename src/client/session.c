#include <librdp/session.h>

#include "common/trace.h"
#include "input/input.h"

#include <stdlib.h>

struct librdp_session
{
    librdp_settings* settings;
    librdp_surface* surface;
    librdp_session_state state;
    librdp_event_callback callback;
    void* callback_data;
};

static void rdp_session_emit(librdp_session* session, const librdp_event* event)
{
    if (session && session->callback && event)
        session->callback(session, event, session->callback_data);
}

static void rdp_session_set_state(librdp_session* session, librdp_session_state state)
{
    librdp_event event;
    librdp_session_state old_state = LIBRDP_SESSION_IDLE;

    if (!session || session->state == state)
        return;

    old_state = session->state;
    session->state = state;

    event.type = LIBRDP_EVENT_STATE_CHANGED;
    event.data.state.old_state = (int)old_state;
    event.data.state.new_state = (int)state;
    rdp_session_emit(session, &event);
}

librdp_session* librdp_session_new(const librdp_settings* settings)
{
    librdp_session* session = NULL;

    if (!settings)
        return NULL;

    session = (librdp_session*)calloc(1, sizeof(*session));
    if (!session)
        return NULL;

    session->settings = librdp_settings_clone(settings);
    if (!session->settings)
    {
        free(session);
        return NULL;
    }

    session->surface = librdp_surface_new(librdp_settings_width(session->settings),
                                          librdp_settings_height(session->settings),
                                          LIBRDP_PIXEL_FORMAT_BGRA32);
    if (!session->surface)
    {
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }

    session->state = LIBRDP_SESSION_IDLE;
    rdp_trace_event(RDP_TRACE_CLIENT, "client.session.new", "width=%u height=%u",
                    librdp_settings_width(session->settings),
                    librdp_settings_height(session->settings));
    return session;
}

void librdp_session_free(librdp_session* session)
{
    if (!session)
        return;
    (void)librdp_session_disconnect(session);
    librdp_surface_free(session->surface);
    librdp_settings_free(session->settings);
    free(session);
}

void librdp_session_set_event_callback(librdp_session* session, librdp_event_callback callback, void* user_data)
{
    if (!session)
        return;
    session->callback = callback;
    session->callback_data = user_data;
}

librdp_status librdp_session_connect(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_IDLE && session->state != LIBRDP_SESSION_CLOSED &&
        session->state != LIBRDP_SESSION_FAILED)
        return LIBRDP_STATUS_STATE;
    if (!librdp_settings_target(session->settings))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_trace_event(RDP_TRACE_CLIENT, "client.connect.start", "target=%s port=%u width=%u height=%u",
                    librdp_settings_target(session->settings),
                    (unsigned)librdp_settings_port(session->settings),
                    librdp_settings_width(session->settings),
                    librdp_settings_height(session->settings));

    rdp_session_set_state(session, LIBRDP_SESSION_CONNECTING);
    rdp_session_set_state(session, LIBRDP_SESSION_CONNECTED);

    event.type = LIBRDP_EVENT_SURFACE_INVALIDATED;
    event.data.surface.x = 0;
    event.data.surface.y = 0;
    event.data.surface.width = librdp_surface_width(session->surface);
    event.data.surface.height = librdp_surface_height(session->surface);
    rdp_session_emit(session, &event);

    rdp_trace_event(RDP_TRACE_CLIENT, "client.connect.done", "transport=deferred");
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_run_once(librdp_session* session, int timeout_ms)
{
    if (!session || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;

    rdp_trace_event(RDP_TRACE_CLIENT, "client.active.loop.start", "timeout_ms=%d", timeout_ms);
    if (session->state == LIBRDP_SESSION_CONNECTED)
        rdp_session_set_state(session, LIBRDP_SESSION_ACTIVE);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.active.loop.done", "status=idle");
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_disconnect(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state == LIBRDP_SESSION_CLOSED || session->state == LIBRDP_SESSION_IDLE)
        return LIBRDP_STATUS_OK;

    rdp_trace_event(RDP_TRACE_CLIENT, "client.disconnect.start", "state=%d", (int)session->state);
    rdp_session_set_state(session, LIBRDP_SESSION_CLOSING);
    rdp_session_set_state(session, LIBRDP_SESSION_CLOSED);

    event.type = LIBRDP_EVENT_DISCONNECTED;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.disconnect.done", "status=ok");
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_resize(librdp_session* session, uint32_t width, uint32_t height)
{
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_event event;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = librdp_surface_resize(session->surface, width, height);
    if (status != LIBRDP_STATUS_OK)
        return status;

    event.type = LIBRDP_EVENT_SURFACE_INVALIDATED;
    event.data.surface.x = 0;
    event.data.surface.y = 0;
    event.data.surface.width = width;
    event.data.surface.height = height;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.display_control.layout_sent", "width=%u height=%u", width, height);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_send_key(librdp_session* session, const librdp_key_event* key)
{
    uint16_t flags = 0;
    librdp_event event;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;

    status = rdp_input_make_keyboard_flags(key, &flags);
    if (status != LIBRDP_STATUS_OK)
        return status;

    event.type = LIBRDP_EVENT_KEY_SENT;
    event.data.key = *key;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.input.send", "kind=keyboard scancode=%u flags=%u", key->scancode, flags);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_send_mouse(librdp_session* session, const librdp_mouse_event* mouse)
{
    uint16_t flags = 0;
    librdp_event event;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;

    status = rdp_input_make_pointer_flags(mouse, &flags);
    if (status != LIBRDP_STATUS_OK)
        return status;

    event.type = LIBRDP_EVENT_MOUSE_SENT;
    event.data.mouse = *mouse;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.input.send", "kind=mouse x=%u y=%u flags=%u", mouse->x, mouse->y, flags);
    return LIBRDP_STATUS_OK;
}

librdp_session_state librdp_session_get_state(const librdp_session* session)
{
    return session ? session->state : LIBRDP_SESSION_FAILED;
}

const librdp_surface* librdp_session_get_surface(const librdp_session* session)
{
    return session ? session->surface : NULL;
}
