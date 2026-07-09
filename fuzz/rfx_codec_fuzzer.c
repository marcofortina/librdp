#include "graphics/rfx_codec.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    int32_t coefficients[64];
    int32_t tile_coefficients[RDP_RFX_TILE_COEFFICIENTS];
    int32_t y[RDP_RFX_TILE_COEFFICIENTS];
    int32_t cb[RDP_RFX_TILE_COEFFICIENTS];
    int32_t cr[RDP_RFX_TILE_COEFFICIENTS];
    size_t written = 0;
    rdp_rfx_component_quant component_quant;
    rdp_rfx_progressive_quant progressive_quant;
    rdp_rfx_component_quant added_quant;
    rdp_rfx_component_quant valid_quant;
    rdp_rfx_component_quant zero_delta;
    rdp_rfx_tile_pixels pixels;
    rdp_rfx_progressive_tile_state state;
    rdp_buffer output;

    rdp_buffer_init(&output);
    memset(&component_quant, 0, sizeof(component_quant));
    memset(&progressive_quant, 0, sizeof(progressive_quant));
    memset(&added_quant, 0, sizeof(added_quant));
    memset(&valid_quant, 1, sizeof(valid_quant));
    memset(&zero_delta, 0, sizeof(zero_delta));
    memset(&pixels, 0, sizeof(pixels));
    memset(&state, 0, sizeof(state));
    memset(tile_coefficients, 0, sizeof(tile_coefficients));
    memset(y, 0, sizeof(y));
    memset(cb, 0, sizeof(cb));
    memset(cr, 0, sizeof(cr));
    (void)rdp_rfx_rlgr_decode(RDP_RFX_RLGR1, data, size, coefficients, 64, &written);
    (void)rdp_rfx_rlgr_decode(RDP_RFX_RLGR3, data, size, coefficients, 64, &written);
    (void)rdp_rfx_parse_component_quant(data, size, &component_quant);
    (void)rdp_rfx_parse_progressive_quant(data, size, &progressive_quant);
    (void)rdp_rfx_write_component_quant(&output, &component_quant);
    output.length = 0;
    (void)rdp_rfx_write_component_quant(&output, &valid_quant);
    output.length = 0;
    (void)rdp_rfx_write_progressive_quant(&output, &progressive_quant);
    output.length = 0;
    (void)rdp_rfx_rlgr_write_zeroes(&output, RDP_RFX_TILE_COEFFICIENTS);
    output.length = 0;
    (void)rdp_rfx_rlgr_write_zeroes(&output, 2);
    output.length = 0;
    (void)rdp_rfx_add_component_quant(&component_quant, &progressive_quant.y, &added_quant);
    (void)rdp_rfx_differential_decode(tile_coefficients, RDP_RFX_TILE_COEFFICIENTS);
    (void)rdp_rfx_inverse_quantize(tile_coefficients, RDP_RFX_TILE_COEFFICIENTS, &valid_quant);
    (void)rdp_rfx_inverse_dwt_2d(tile_coefficients, RDP_RFX_TILE_COEFFICIENTS);
    (void)rdp_rfx_ycbcr_to_bgra(y, cb, cr, pixels.bgra, 64u * 4u);
    (void)rdp_rfx_decode_component(RDP_RFX_RLGR1,
                                   data,
                                   size,
                                   &valid_quant,
                                   tile_coefficients,
                                   RDP_RFX_TILE_COEFFICIENTS);
    (void)rdp_rfx_decode_progressive_component(data,
                                               size,
                                               &valid_quant,
                                               0,
                                               tile_coefficients,
                                               RDP_RFX_TILE_COEFFICIENTS);
    (void)rdp_rfx_decode_progressive_component(data,
                                               size,
                                               &valid_quant,
                                               1,
                                               tile_coefficients,
                                               RDP_RFX_TILE_COEFFICIENTS);
    (void)rdp_rfx_decode_progressive_tile(data,
                                          size,
                                          data,
                                          size,
                                          data,
                                          size,
                                          &valid_quant,
                                          &valid_quant,
                                          &valid_quant,
                                          0,
                                          &pixels);
    (void)rdp_rfx_decode_progressive_tile_state(data,
                                                size,
                                                data,
                                                size,
                                                data,
                                                size,
                                                &valid_quant,
                                                &zero_delta,
                                                &valid_quant,
                                                &zero_delta,
                                                &valid_quant,
                                                &zero_delta,
                                                1,
                                                0,
                                                &state,
                                                &pixels);
    (void)rdp_rfx_decode_progressive_upgrade_tile(data,
                                                  size,
                                                  data,
                                                  size,
                                                  data,
                                                  size,
                                                  data,
                                                  size,
                                                  data,
                                                  size,
                                                  data,
                                                  size,
                                                  &valid_quant,
                                                  &zero_delta,
                                                  &valid_quant,
                                                  &zero_delta,
                                                  &valid_quant,
                                                  &zero_delta,
                                                  1,
                                                  &state,
                                                  &pixels);
    rdp_buffer_free(&output);
    return 0;
}
