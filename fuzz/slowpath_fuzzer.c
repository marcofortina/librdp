#include "protocol/slowpath.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_slowpath_share_control_header header;
    rdp_slowpath_demand_active demand;

    (void)rdp_slowpath_parse_share_control_header(data, size, &header);
    (void)rdp_slowpath_parse_demand_active(data, size, &demand);
    return 0;
}
