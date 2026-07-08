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

#define LIBRDP_TOUCH_CONTACTRECT_PRESENT 0x0001u
#define LIBRDP_TOUCH_ORIENTATION_PRESENT 0x0002u
#define LIBRDP_TOUCH_PRESSURE_PRESENT 0x0004u

#define LIBRDP_PEN_FLAGS_PRESENT 0x0001u
#define LIBRDP_PEN_PRESSURE_PRESENT 0x0002u
#define LIBRDP_PEN_ROTATION_PRESENT 0x0004u
#define LIBRDP_PEN_TILTX_PRESENT 0x0008u
#define LIBRDP_PEN_TILTY_PRESENT 0x0010u

#define LIBRDP_CONTACT_DOWN 0x00000001u
#define LIBRDP_CONTACT_UPDATE 0x00000002u
#define LIBRDP_CONTACT_UP 0x00000004u
#define LIBRDP_CONTACT_INRANGE 0x00000008u
#define LIBRDP_CONTACT_INCONTACT 0x00000010u
#define LIBRDP_CONTACT_CANCELED 0x00000020u

#define LIBRDP_PEN_BARREL_PRESSED 0x00000001u
#define LIBRDP_PEN_ERASER_PRESSED 0x00000002u
#define LIBRDP_PEN_INVERTED 0x00000004u

typedef struct librdp_touch_contact
{
    uint8_t contact_id;
    uint16_t fields_present;
    int32_t x;
    int32_t y;
    uint32_t contact_flags;
    int16_t contact_rect_left;
    int16_t contact_rect_top;
    int16_t contact_rect_right;
    int16_t contact_rect_bottom;
    uint32_t orientation;
    uint32_t pressure;
} librdp_touch_contact;

typedef struct librdp_touch_frame
{
    uint16_t contact_count;
    uint64_t frame_offset;
    const librdp_touch_contact* contacts;
} librdp_touch_frame;

typedef struct librdp_pen_contact
{
    uint8_t device_id;
    uint16_t fields_present;
    int32_t x;
    int32_t y;
    uint32_t contact_flags;
    uint32_t pen_flags;
    uint32_t pressure;
    uint16_t rotation;
    int16_t tilt_x;
    int16_t tilt_y;
} librdp_pen_contact;

typedef struct librdp_pen_frame
{
    uint16_t contact_count;
    uint64_t frame_offset;
    const librdp_pen_contact* contacts;
} librdp_pen_frame;

#ifdef __cplusplus
}
#endif

#endif
