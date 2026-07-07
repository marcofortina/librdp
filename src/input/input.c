#include "input/input.h"

librdp_status rdp_input_make_keyboard_flags(const librdp_key_event* event, uint16_t* flags)
{
    if (!event || !flags || event->scancode > 0xffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    *flags = (event->state == LIBRDP_KEY_RELEASED) ? 0x8000u : 0x0000u;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_input_make_pointer_flags(const librdp_mouse_event* event, uint16_t* flags)
{
    if (!event || !flags)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    *flags = 0x0800u;
    if (event->state == LIBRDP_MOUSE_MOVED)
        return LIBRDP_STATUS_OK;

    switch (event->button)
    {
        case LIBRDP_MOUSE_BUTTON_LEFT:
            *flags |= 0x1000u;
            break;
        case LIBRDP_MOUSE_BUTTON_RIGHT:
            *flags |= 0x2000u;
            break;
        case LIBRDP_MOUSE_BUTTON_MIDDLE:
            *flags |= 0x4000u;
            break;
        case LIBRDP_MOUSE_BUTTON_WHEEL_UP:
            *flags = 0x0200u | 0x0078u;
            return LIBRDP_STATUS_OK;
        case LIBRDP_MOUSE_BUTTON_WHEEL_DOWN:
            *flags = 0x0200u | 0x0088u;
            return LIBRDP_STATUS_OK;
        case LIBRDP_MOUSE_BUTTON_NONE:
            break;
        default:
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }

    if (event->state == LIBRDP_MOUSE_PRESSED)
        *flags |= 0x8000u;
    return LIBRDP_STATUS_OK;
}
