#include "channels/core_input.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_core_input_header header;
    rdp_core_input_init_response response;
    rdp_core_input_negotiation negotiation;
    rdp_core_input_event events[4];
    uint8_t event_count = 0;
    rdp_buffer out;

    rdp_buffer_init(&out);
    (void)rdp_core_input_parse_header(data, size, &header);
    if (rdp_core_input_parse_init_response(data, size, &response) == LIBRDP_STATUS_OK)
        (void)rdp_core_input_negotiate(&response, &negotiation);
    (void)rdp_core_input_parse_events(data,
                                      size,
                                      events,
                                      (uint8_t)(sizeof(events) / sizeof(events[0])),
                                      &event_count);
    (void)rdp_core_input_write_init_request(&out);
    out.length = 0;
    (void)rdp_core_input_write_keyboard_event(&out,
                                              size > 0 ? data[0] : 0,
                                              size > 1 ? (uint8_t)(data[1] & 1u) : 0);
    out.length = 0;
    (void)rdp_core_input_write_keyboard_event_ex(&out,
                                                 size > 0 ? data[0] : 0,
                                                 size > 1 ? (uint8_t)(data[1] & 0x07u) : 0);
    out.length = 0;
    (void)rdp_core_input_write_unicode_event(&out,
                                             size > 1 ? (uint16_t)(((uint16_t)data[0] << 8) | data[1]) : 0,
                                             size > 2 ? (uint8_t)(data[2] & 1u) : 0);
    out.length = 0;
    (void)rdp_core_input_write_sync_event(&out, size > 0 ? (uint8_t)(data[0] & 0x0fu) : 0);
    out.length = 0;
    (void)rdp_core_input_write_mouse_event(&out,
                                           size > 1 ? (uint16_t)(((uint16_t)data[0] << 8) | data[1]) : 0,
                                           size > 2 ? data[2] : 0,
                                           size > 3 ? data[3] : 0);
    out.length = 0;
    (void)rdp_core_input_write_extended_mouse_event(
        &out,
        size > 1 ? (uint16_t)(((uint16_t)data[0] << 8) | data[1]) : 0,
        size > 2 ? data[2] : 0,
        size > 3 ? data[3] : 0);
    out.length = 0;
    (void)rdp_core_input_write_relative_mouse_event(&out,
                                                    size > 1 ? (uint16_t)(((uint16_t)data[0] << 8) | data[1]) : 0,
                                                    size > 2 ? (int8_t)data[2] : 0,
                                                    size > 3 ? (int8_t)data[3] : 0);
    out.length = 0;
    (void)rdp_core_input_write_qoe_timestamp_event(&out, (uint32_t)size);
    out.length = 0;
    events[0].type = RDP_CORE_INPUT_EVENT_SYNC;
    events[0].flags = size > 0 ? (uint8_t)(data[0] & 0x0fu) : 0;
    (void)rdp_core_input_write_events(&out, events, 1);
    rdp_buffer_free(&out);
    return 0;
}
