#include "protocol/fastpath.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_fastpath_header header;
    (void)rdp_fastpath_parse_header(data, size, &header);
    return 0;
}
