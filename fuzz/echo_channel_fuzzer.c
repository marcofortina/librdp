#include "channels/echo_channel.h"

#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_echo_channel_pdu pdu;
    rdp_buffer buffer;
    size_t bounded = size > RDP_ECHO_CHANNEL_MAX_PAYLOAD ? RDP_ECHO_CHANNEL_MAX_PAYLOAD : size;

    (void)rdp_echo_channel_parse_request(data, size, &pdu);
    (void)rdp_echo_channel_parse_response(data, size, &pdu);
    rdp_buffer_init(&buffer);
    (void)rdp_echo_channel_write_request(&buffer, data, bounded);
    buffer.length = 0;
    (void)rdp_echo_channel_write_response(&buffer, data, bounded);
    rdp_buffer_free(&buffer);
    return 0;
}
