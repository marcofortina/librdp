#include "graphics/rfx_codec.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    int32_t coefficients[64];
    size_t written = 0;

    (void)rdp_rfx_rlgr_decode(RDP_RFX_RLGR1, data, size, coefficients, 64, &written);
    (void)rdp_rfx_rlgr_decode(RDP_RFX_RLGR3, data, size, coefficients, 64, &written);
    return 0;
}
