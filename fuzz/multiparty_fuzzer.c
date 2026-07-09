#include "channels/multiparty.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_multiparty_header header;
    rdp_multiparty_string string;
    rdp_multiparty_filter_state filter;
    rdp_multiparty_app_created app;
    rdp_multiparty_id_message id_message;
    rdp_multiparty_window_created window;
    rdp_multiparty_region_update region;
    rdp_multiparty_participant_created participant;
    rdp_multiparty_participant_removed removed;
    rdp_multiparty_control_change change;
    rdp_multiparty_control_change_response response;
    rdp_multiparty_message message;
    rdp_buffer buffer;
    size_t consumed = 0;
    uint16_t chars = 0;
    uint16_t control_flags = RDP_MULTIPARTY_REQUEST_VIEW;
    uint16_t participant_flags = RDP_MULTIPARTY_MAY_VIEW;
    uint16_t share_flags = RDP_MULTIPARTY_APPLICATION_SHARED;

    if (!data && size > 0)
        return 0;
    chars = (uint16_t)((size / 2u) > 16u ? 16u : (size / 2u));
    if (size > 0 && (data[0] & 1u))
        control_flags = RDP_MULTIPARTY_REQUEST_VIEW | RDP_MULTIPARTY_REQUEST_INTERACT;
    if (size > 0 && (data[0] & 2u))
        participant_flags = RDP_MULTIPARTY_MAY_VIEW | RDP_MULTIPARTY_MAY_INTERACT;
    if (size > 0 && (data[0] & 4u))
        share_flags = 0;

    (void)rdp_multiparty_parse_header(data, size, &header);
    (void)rdp_multiparty_parse_message(data, size, &message);
    (void)rdp_multiparty_parse_string(data, size, &string, &consumed);
    (void)rdp_multiparty_parse_filter_state(data, size, &filter);
    (void)rdp_multiparty_parse_app_created(data, size, &app);
    (void)rdp_multiparty_parse_id_message(data, size, RDP_MULTIPARTY_TYPE_APP_REMOVED, &id_message);
    (void)rdp_multiparty_parse_id_message(data, size, RDP_MULTIPARTY_TYPE_WND_REMOVED, &id_message);
    (void)rdp_multiparty_parse_id_message(data, size, RDP_MULTIPARTY_TYPE_WND_SHOW, &id_message);
    (void)rdp_multiparty_parse_window_created(data, size, &window);
    (void)rdp_multiparty_parse_region_update(data, size, &region);
    (void)rdp_multiparty_parse_participant_created(data, size, &participant);
    (void)rdp_multiparty_parse_participant_removed(data, size, &removed);
    (void)rdp_multiparty_parse_control_change(data, size, &change);
    (void)rdp_multiparty_parse_control_change_response(data, size, &response);
    (void)rdp_multiparty_parse_empty(data, size, RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_PAUSED);

    rdp_buffer_init(&buffer);
    (void)rdp_multiparty_write_header(&buffer, RDP_MULTIPARTY_TYPE_WND_SHOW, 4u);
    buffer.length = 0;
    (void)rdp_multiparty_write_string(&buffer, data, chars);
    buffer.length = 0;
    (void)rdp_multiparty_write_filter_state(&buffer, RDP_MULTIPARTY_FILTER_ENABLED);
    buffer.length = 0;
    (void)rdp_multiparty_write_app_created(&buffer, share_flags, (uint32_t)size, data, chars);
    buffer.length = 0;
    (void)rdp_multiparty_write_id_message(&buffer, RDP_MULTIPARTY_TYPE_APP_REMOVED, (uint32_t)size);
    buffer.length = 0;
    (void)rdp_multiparty_write_id_message(&buffer, RDP_MULTIPARTY_TYPE_WND_REMOVED, (uint32_t)size);
    buffer.length = 0;
    (void)rdp_multiparty_write_id_message(&buffer, RDP_MULTIPARTY_TYPE_WND_SHOW, (uint32_t)size);
    buffer.length = 0;
    (void)rdp_multiparty_write_window_created(&buffer,
                                              (uint16_t)(share_flags & RDP_MULTIPARTY_WINDOW_SHARED),
                                              (uint32_t)size,
                                              (uint32_t)(size + 1u),
                                              data,
                                              chars);
    buffer.length = 0;
    (void)rdp_multiparty_write_region_update(&buffer, 0, 1, 2, 3);
    buffer.length = 0;
    (void)rdp_multiparty_write_participant_created(&buffer,
                                                   (uint32_t)size,
                                                   (uint32_t)(size + 1u),
                                                   participant_flags,
                                                   data,
                                                   chars);
    buffer.length = 0;
    (void)rdp_multiparty_write_participant_removed(&buffer,
                                                   (uint32_t)size,
                                                   (uint32_t)(size >> 1u),
                                                   (uint32_t)(size >> 2u));
    buffer.length = 0;
    (void)rdp_multiparty_write_control_change(&buffer, control_flags, 1);
    buffer.length = 0;
    (void)rdp_multiparty_write_control_change_response(&buffer, control_flags, 1, (uint32_t)size);
    buffer.length = 0;
    (void)rdp_multiparty_write_empty(&buffer, RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_PAUSED);
    buffer.length = 0;
    (void)rdp_multiparty_write_empty(&buffer, RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_RESUMED);
    rdp_buffer_free(&buffer);
    return 0;
}
