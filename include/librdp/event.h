#ifndef LIBRDP_EVENT_H
#define LIBRDP_EVENT_H

#include <stdint.h>

#include <librdp/error.h>
#include <librdp/input.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum librdp_event_type
{
    LIBRDP_EVENT_NONE = 0,
    LIBRDP_EVENT_STATE_CHANGED = 1,
    LIBRDP_EVENT_SURFACE_INVALIDATED = 2,
    LIBRDP_EVENT_KEY_SENT = 3,
    LIBRDP_EVENT_MOUSE_SENT = 4,
    LIBRDP_EVENT_ERROR = 5,
    LIBRDP_EVENT_DISCONNECTED = 6
} librdp_event_type;

typedef struct librdp_rect
{
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} librdp_rect;

typedef struct librdp_event
{
    librdp_event_type type;
    union
    {
        struct
        {
            int old_state;
            int new_state;
        } state;
        librdp_rect surface;
        librdp_key_event key;
        librdp_mouse_event mouse;
        struct
        {
            librdp_status status;
        } error;
    } data;
} librdp_event;

#ifdef __cplusplus
}
#endif

#endif
