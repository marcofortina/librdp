#include "common/stream.h"
#include "protocol/gcc.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_stream stream;
    rdp_gcc_user_data_block block;
    rdp_gcc_client_data_summary summary;

    (void)rdp_gcc_parse_client_data_blocks(data, size, &summary);
    rdp_stream_init(&stream, data, size);
    while (rdp_stream_remaining(&stream) > 0)
    {
        if (rdp_gcc_read_user_data_block(&stream, &block) != LIBRDP_STATUS_OK)
            break;
    }
    return 0;
}
