#include "channels/dynamic_channel.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_dynamic_channel_header header;
    rdp_dynamic_channel_capabilities capabilities;
    rdp_dynamic_channel_create_request request;
    rdp_buffer response;

    rdp_buffer_init(&response);
    (void)rdp_dynamic_channel_parse_header(data, size, &header);
    (void)rdp_dynamic_channel_parse_capabilities(data, size, &capabilities);
    (void)rdp_dynamic_channel_parse_create_request(data, size, &request);
    (void)rdp_dynamic_channel_write_capabilities_response(&response, 1);
    rdp_buffer_free(&response);
    return 0;
}
