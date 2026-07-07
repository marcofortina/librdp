#include "nla/credssp.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_credssp_ts_request request;

    (void)rdp_credssp_parse_ts_request(data, size, &request);
    return 0;
}
