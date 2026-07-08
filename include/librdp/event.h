#ifndef LIBRDP_EVENT_H
#define LIBRDP_EVENT_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/channel.h>
#include <librdp/clipboard.h>
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
    LIBRDP_EVENT_DISCONNECTED = 6,
    LIBRDP_EVENT_POINTER = 7,
    LIBRDP_EVENT_CLIPBOARD_FORMATS = 8,
    LIBRDP_EVENT_CLIPBOARD_DATA = 9,
    LIBRDP_EVENT_CLIPBOARD_REQUEST = 10,
    LIBRDP_EVENT_CHANNEL_OPEN = 11,
    LIBRDP_EVENT_CHANNEL_DATA = 12,
    LIBRDP_EVENT_CHANNEL_CLOSE = 13
} librdp_event_type;

typedef enum librdp_pointer_update_type
{
    LIBRDP_POINTER_UPDATE_DEFAULT = 0,
    LIBRDP_POINTER_UPDATE_HIDDEN = 1,
    LIBRDP_POINTER_UPDATE_POSITION = 2,
    LIBRDP_POINTER_UPDATE_SHAPE = 3
} librdp_pointer_update_type;

typedef struct librdp_rect
{
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} librdp_rect;

typedef struct librdp_pointer_event
{
    librdp_pointer_update_type update_type;
    uint16_t cache_index;
    uint16_t x;
    uint16_t y;
    uint16_t hot_x;
    uint16_t hot_y;
    uint16_t width;
    uint16_t height;
    uint32_t stride;
    const uint8_t* pixels;
    size_t pixels_len;
    int visible;
} librdp_pointer_event;

typedef struct librdp_clipboard_formats_event
{
    const librdp_clipboard_format* formats;
    uint32_t count;
    uint32_t total_count;
} librdp_clipboard_formats_event;

typedef struct librdp_clipboard_data_event
{
    uint32_t format_id;
    const uint8_t* data;
    size_t data_len;
    int ok;
} librdp_clipboard_data_event;

typedef struct librdp_clipboard_request_event
{
    uint32_t format_id;
} librdp_clipboard_request_event;

typedef struct librdp_channel_open_event
{
    librdp_channel_id channel_id;
    const char* name;
    size_t name_len;
} librdp_channel_open_event;

typedef struct librdp_channel_data_event
{
    librdp_channel_id channel_id;
    const char* name;
    size_t name_len;
    const uint8_t* data;
    size_t data_len;
} librdp_channel_data_event;

typedef struct librdp_channel_close_event
{
    librdp_channel_id channel_id;
    const char* name;
    size_t name_len;
} librdp_channel_close_event;

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
        librdp_pointer_event pointer;
        librdp_clipboard_formats_event clipboard_formats;
        librdp_clipboard_data_event clipboard_data;
        librdp_clipboard_request_event clipboard_request;
        librdp_channel_open_event channel_open;
        librdp_channel_data_event channel_data;
        librdp_channel_close_event channel_close;
    } data;
} librdp_event;

#ifdef __cplusplus
}
#endif

#endif
