#include "security/security.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_client_info_summary summary;
    (void)rdp_security_parse_client_info_pdu(data, size, &summary);
    return 0;
}
