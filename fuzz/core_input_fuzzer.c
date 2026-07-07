#include "channels/core_input.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_core_input_header header;
    rdp_core_input_init_response response;
    rdp_buffer out;

    rdp_buffer_init(&out);
    (void)rdp_core_input_parse_header(data, size, &header);
    (void)rdp_core_input_parse_init_response(data, size, &response);
    (void)rdp_core_input_write_init_request(&out);
    out.length = 0;
    (void)rdp_core_input_write_keyboard_event(&out,
                                              size > 0 ? data[0] : 0,
                                              size > 1 ? (uint8_t)(data[1] & 1u) : 0);
    out.length = 0;
    (void)rdp_core_input_write_mouse_event(&out,
                                           size > 1 ? (uint16_t)(((uint16_t)data[0] << 8) | data[1]) : 0,
                                           size > 2 ? data[2] : 0,
                                           size > 3 ? data[3] : 0);
    rdp_buffer_free(&out);
    return 0;
}
