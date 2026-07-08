#include "channels/dynamic_channel.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_dynamic_channel_header header;
    rdp_dynamic_channel_capabilities capabilities;
    rdp_dynamic_channel_create_request request;
    rdp_dynamic_channel_data_pdu data_pdu;
    rdp_dynamic_channel_data_first_pdu first_pdu;
    rdp_dynamic_channel_close_pdu close_pdu;
    rdp_buffer response;

    rdp_buffer_init(&response);
    (void)rdp_dynamic_channel_parse_header(data, size, &header);
    (void)rdp_dynamic_channel_parse_capabilities(data, size, &capabilities);
    (void)rdp_dynamic_channel_parse_create_request(data, size, &request);
    (void)rdp_dynamic_channel_parse_data_first(data, size, &first_pdu);
    (void)rdp_dynamic_channel_parse_data(data, size, &data_pdu);
    (void)rdp_dynamic_channel_parse_close(data, size, &close_pdu);
    (void)rdp_dynamic_channel_write_capabilities_response(&response, 1);
    response.length = 0;
    (void)rdp_dynamic_channel_write_close(&response, 1, 1);
    response.length = 0;
    if (size > 0)
        (void)rdp_dynamic_channel_write_data_first(&response, 1, 1, (uint32_t)size, data, size > 8u ? 8u : size);
    rdp_buffer_free(&response);
    return 0;
}
