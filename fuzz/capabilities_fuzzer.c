#include "protocol/capabilities.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_capability_list list;
    (void)rdp_capabilities_parse(data, size, &list);
    return 0;
}
