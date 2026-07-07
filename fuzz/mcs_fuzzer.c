#include "common/stream.h"
#include "protocol/mcs.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_mcs_connect_response response;
    rdp_stream stream;
    size_t length = 0;

    rdp_stream_init(&stream, data, size);
    (void)rdp_mcs_read_ber_length(&stream, &length);
    (void)rdp_mcs_parse_connect_response(data, size, &response);
    return 0;
}
