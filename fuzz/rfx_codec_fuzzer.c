#include "graphics/rfx_codec.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    int32_t coefficients[64];
    size_t written = 0;
    rdp_rfx_component_quant component_quant;
    rdp_rfx_progressive_quant progressive_quant;
    rdp_rfx_component_quant added_quant;

    memset(&component_quant, 0, sizeof(component_quant));
    memset(&progressive_quant, 0, sizeof(progressive_quant));
    memset(&added_quant, 0, sizeof(added_quant));
    (void)rdp_rfx_rlgr_decode(RDP_RFX_RLGR1, data, size, coefficients, 64, &written);
    (void)rdp_rfx_rlgr_decode(RDP_RFX_RLGR3, data, size, coefficients, 64, &written);
    (void)rdp_rfx_parse_component_quant(data, size, &component_quant);
    (void)rdp_rfx_parse_progressive_quant(data, size, &progressive_quant);
    (void)rdp_rfx_add_component_quant(&component_quant, &progressive_quant.y, &added_quant);
    return 0;
}
