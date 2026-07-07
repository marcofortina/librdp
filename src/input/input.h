#ifndef RDP_INPUT_INPUT_H
#define RDP_INPUT_INPUT_H

#include <stdint.h>

#include <librdp/error.h>
#include <librdp/input.h>

librdp_status rdp_input_make_keyboard_flags(const librdp_key_event* event, uint16_t* flags);
librdp_status rdp_input_make_pointer_flags(const librdp_mouse_event* event, uint16_t* flags);

#endif
