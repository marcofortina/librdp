#include "protocol/tpkt.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_tpkt packet;
    rdp_buffer buffer;
    size_t bounded = size < 4096u ? size : 4096u;

    (void)rdp_tpkt_parse(data, size, &packet);
    rdp_buffer_init(&buffer);
    (void)rdp_tpkt_write(&buffer, data, bounded);
    if (buffer.length > 0)
        (void)rdp_tpkt_parse(buffer.data, buffer.length, &packet);
    rdp_buffer_free(&buffer);
    return 0;
}
