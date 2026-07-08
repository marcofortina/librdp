#ifndef LIBRDP_INPUT_H
#define LIBRDP_INPUT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum librdp_key_state
{
    LIBRDP_KEY_RELEASED = 0,
    LIBRDP_KEY_PRESSED = 1
} librdp_key_state;

typedef enum librdp_mouse_button
{
    LIBRDP_MOUSE_BUTTON_NONE = 0,
    LIBRDP_MOUSE_BUTTON_LEFT = 1,
    LIBRDP_MOUSE_BUTTON_RIGHT = 2,
    LIBRDP_MOUSE_BUTTON_MIDDLE = 3,
    LIBRDP_MOUSE_BUTTON_WHEEL_UP = 4,
    LIBRDP_MOUSE_BUTTON_WHEEL_DOWN = 5,
    LIBRDP_MOUSE_BUTTON_WHEEL_LEFT = 6,
    LIBRDP_MOUSE_BUTTON_WHEEL_RIGHT = 7,
    LIBRDP_MOUSE_BUTTON_X1 = 8,
    LIBRDP_MOUSE_BUTTON_X2 = 9
} librdp_mouse_button;

typedef enum librdp_mouse_state
{
    LIBRDP_MOUSE_RELEASED = 0,
    LIBRDP_MOUSE_PRESSED = 1,
    LIBRDP_MOUSE_MOVED = 2
} librdp_mouse_state;

typedef struct librdp_key_event
{
    uint32_t scancode;
    librdp_key_state state;
    uint32_t flags;
    uint32_t unicode;
} librdp_key_event;

#define LIBRDP_KEY_FLAG_EXTENDED 0x00000001u
#define LIBRDP_KEY_FLAG_EXTENDED1 0x00000002u
#define LIBRDP_KEY_FLAG_UNICODE 0x00000004u

typedef struct librdp_mouse_event
{
    uint16_t x;
    uint16_t y;
    librdp_mouse_button button;
    librdp_mouse_state state;
} librdp_mouse_event;

#ifdef __cplusplus
}
#endif

#endif
