#include "input/input.h"

librdp_status rdp_input_make_keyboard_flags(const librdp_key_event* event, uint16_t* flags)
{
    if (!event || !flags)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((event->flags & LIBRDP_KEY_FLAG_UNICODE) == 0 && event->scancode > 0xffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    *flags = (event->state == LIBRDP_KEY_RELEASED) ? 0x8000u : 0x0000u;
    if ((event->flags & LIBRDP_KEY_FLAG_EXTENDED) != 0)
        *flags |= 0x0100u;
    if ((event->flags & LIBRDP_KEY_FLAG_EXTENDED1) != 0)
        *flags |= 0x0200u;
    return LIBRDP_STATUS_OK;
}

int rdp_input_mouse_uses_extended(const librdp_mouse_event* event)
{
    if (!event)
        return 0;
    return event->button == LIBRDP_MOUSE_BUTTON_X1 || event->button == LIBRDP_MOUSE_BUTTON_X2;
}

librdp_status rdp_input_make_pointer_flags(const librdp_mouse_event* event, uint16_t* flags)
{
    if (!event || !flags)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    *flags = rdp_input_mouse_uses_extended(event) ? 0x0000u : 0x0800u;
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
            *flags = 0x0200u | 0x0100u | 0x0088u;
            return LIBRDP_STATUS_OK;
        case LIBRDP_MOUSE_BUTTON_WHEEL_LEFT:
            *flags = 0x0400u | 0x0100u | 0x0088u;
            return LIBRDP_STATUS_OK;
        case LIBRDP_MOUSE_BUTTON_WHEEL_RIGHT:
            *flags = 0x0400u | 0x0078u;
            return LIBRDP_STATUS_OK;
        case LIBRDP_MOUSE_BUTTON_X1:
            *flags = 0x0001u;
            break;
        case LIBRDP_MOUSE_BUTTON_X2:
            *flags = 0x0002u;
            break;
        case LIBRDP_MOUSE_BUTTON_NONE:
            break;
        default:
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }

    if (event->state == LIBRDP_MOUSE_PRESSED)
        *flags |= 0x8000u;
    return LIBRDP_STATUS_OK;
}
