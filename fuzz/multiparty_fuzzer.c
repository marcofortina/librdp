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
    rdp_buffer buffer;
    size_t consumed = 0;

    (void)rdp_multiparty_parse_header(data, size, &header);
    (void)rdp_multiparty_parse_string(data, size, &string, &consumed);
    (void)rdp_multiparty_parse_filter_state(data, size, &filter);
    (void)rdp_multiparty_parse_app_created(data, size, &app);
    (void)rdp_multiparty_parse_id_message(data,
                                          size,
                                          RDP_MULTIPARTY_TYPE_WND_SHOW,
                                          &id_message);
    (void)rdp_multiparty_parse_window_created(data, size, &window);
    (void)rdp_multiparty_parse_region_update(data, size, &region);
    (void)rdp_multiparty_parse_participant_created(data, size, &participant);
    (void)rdp_multiparty_parse_participant_removed(data, size, &removed);
    (void)rdp_multiparty_parse_control_change(data, size, &change);
    (void)rdp_multiparty_parse_control_change_response(data, size, &response);
    (void)rdp_multiparty_parse_empty(data, size, RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_PAUSED);

    rdp_buffer_init(&buffer);
    (void)rdp_multiparty_write_filter_state(&buffer, RDP_MULTIPARTY_FILTER_ENABLED);
    buffer.length = 0;
    (void)rdp_multiparty_write_control_change(&buffer, RDP_MULTIPARTY_REQUEST_VIEW, 1);
    rdp_buffer_free(&buffer);
    return 0;
}
