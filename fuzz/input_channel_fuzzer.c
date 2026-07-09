#include "channels/input_channel.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_input_channel_header header;
    rdp_input_channel_sc_ready sc_ready;
    rdp_input_channel_cs_ready cs_ready;
    rdp_input_channel_touch_event touch_event;
    rdp_input_channel_touch_frame touch_frame;
    rdp_input_channel_touch_contact touch_contact;
    rdp_input_channel_pen_event pen_event;
    rdp_input_channel_pen_frame pen_frame;
    rdp_input_channel_pen_contact pen_contact;
    rdp_buffer contact;
    rdp_buffer out;
    uint8_t contact_id = 0;

    rdp_buffer_init(&contact);
    rdp_buffer_init(&out);
    (void)rdp_input_channel_parse_header(data, size, &header);
    (void)rdp_input_channel_parse_sc_ready(data, size, &sc_ready);
    (void)rdp_input_channel_parse_cs_ready(data, size, &cs_ready);
    (void)rdp_input_channel_parse_empty(data, size, RDP_INPUT_CHANNEL_EVENT_SUSPEND_INPUT);
    (void)rdp_input_channel_parse_empty(data, size, RDP_INPUT_CHANNEL_EVENT_RESUME_INPUT);
    (void)rdp_input_channel_parse_dismiss_hovering(data, size, &contact_id);
    if (rdp_input_channel_parse_touch_event(data, size, &touch_event) == LIBRDP_STATUS_OK)
    {
        if (rdp_input_channel_touch_event_get_frame(&touch_event, 0, &touch_frame) == LIBRDP_STATUS_OK)
            (void)rdp_input_channel_touch_frame_get_contact(&touch_frame, 0, &touch_contact);
    }
    if (rdp_input_channel_parse_pen_event(data, size, &pen_event) == LIBRDP_STATUS_OK)
    {
        if (rdp_input_channel_pen_event_get_frame(&pen_event, 0, &pen_frame) == LIBRDP_STATUS_OK)
            (void)rdp_input_channel_pen_frame_get_contact(&pen_frame, 0, &pen_contact);
    }

    (void)rdp_input_channel_write_sc_ready(&out,
                                           RDP_INPUT_CHANNEL_PROTOCOL_V300,
                                           RDP_INPUT_CHANNEL_SC_READY_MULTIPEN,
                                           1);
    out.length = 0;
    (void)rdp_input_channel_write_cs_ready(&out,
                                           RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION,
                                           RDP_INPUT_CHANNEL_PROTOCOL_V300,
                                           10);
    out.length = 0;
    (void)rdp_input_channel_write_suspend(&out);
    out.length = 0;
    (void)rdp_input_channel_write_resume(&out);
    out.length = 0;
    (void)rdp_input_channel_write_dismiss_hovering(&out, size > 0 ? data[0] : 0);
    out.length = 0;

    touch_contact.contact_id = size > 0 ? data[0] : 0;
    touch_contact.fields_present = RDP_INPUT_CHANNEL_TOUCH_CONTACTRECT_PRESENT |
                                   RDP_INPUT_CHANNEL_TOUCH_ORIENTATION_PRESENT |
                                   RDP_INPUT_CHANNEL_TOUCH_PRESSURE_PRESENT;
    touch_contact.x = size > 1 ? (int32_t)data[1] : 0;
    touch_contact.y = size > 2 ? (int32_t)data[2] : 0;
    touch_contact.contact_flags = RDP_INPUT_CHANNEL_CONTACT_UPDATE |
                                  RDP_INPUT_CHANNEL_CONTACT_INRANGE |
                                  RDP_INPUT_CHANNEL_CONTACT_INCONTACT;
    touch_contact.contact_rect_left = -1;
    touch_contact.contact_rect_top = -1;
    touch_contact.contact_rect_right = 1;
    touch_contact.contact_rect_bottom = 1;
    touch_contact.orientation = size > 3 ? (uint32_t)(data[3] % 360u) : 0;
    touch_contact.pressure = size > 4 ? (uint32_t)data[4] : 0;
    (void)rdp_input_channel_write_touch_contact(&contact, &touch_contact);
    touch_frame.contact_count = 1;
    touch_frame.frame_offset = 0;
    touch_frame.contacts = contact.data;
    touch_frame.contacts_len = contact.length;
    (void)rdp_input_channel_write_touch_event(&out, (uint32_t)size, &touch_frame, 1);
    contact.length = 0;
    out.length = 0;

    pen_contact.device_id = size > 0 ? data[0] : 0;
    pen_contact.fields_present = RDP_INPUT_CHANNEL_PEN_FLAGS_PRESENT |
                                 RDP_INPUT_CHANNEL_PEN_PRESSURE_PRESENT |
                                 RDP_INPUT_CHANNEL_PEN_ROTATION_PRESENT |
                                 RDP_INPUT_CHANNEL_PEN_TILTX_PRESENT |
                                 RDP_INPUT_CHANNEL_PEN_TILTY_PRESENT;
    pen_contact.x = size > 1 ? (int32_t)data[1] : 0;
    pen_contact.y = size > 2 ? (int32_t)data[2] : 0;
    pen_contact.contact_flags = RDP_INPUT_CHANNEL_CONTACT_UPDATE |
                                RDP_INPUT_CHANNEL_CONTACT_INRANGE |
                                RDP_INPUT_CHANNEL_CONTACT_INCONTACT;
    pen_contact.pen_flags = RDP_INPUT_CHANNEL_PEN_BARREL_PRESSED;
    pen_contact.pressure = size > 3 ? (uint32_t)data[3] : 0;
    pen_contact.rotation = size > 4 ? (uint16_t)(data[4] % 360u) : 0;
    pen_contact.tilt_x = size > 5 ? (int16_t)((int)data[5] % 181 - 90) : 0;
    pen_contact.tilt_y = size > 6 ? (int16_t)((int)data[6] % 181 - 90) : 0;
    (void)rdp_input_channel_write_pen_contact(&contact, &pen_contact);
    pen_frame.contact_count = 1;
    pen_frame.frame_offset = 0;
    pen_frame.contacts = contact.data;
    pen_frame.contacts_len = contact.length;
    (void)rdp_input_channel_write_pen_event(&out, (uint32_t)size, &pen_frame, 1);

    rdp_buffer_free(&out);
    rdp_buffer_free(&contact);
    return 0;
}
