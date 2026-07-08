#ifndef RDP_GRAPHICS_RFX_CODEC_H
#define RDP_GRAPHICS_RFX_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#define RDP_RFX_TILE_COEFFICIENTS 4096u

typedef enum rdp_rfx_rlgr_mode
{
    RDP_RFX_RLGR1 = 1,
    RDP_RFX_RLGR3 = 3
} rdp_rfx_rlgr_mode;

typedef struct rdp_rfx_component_quant
{
    uint8_t ll3;
    uint8_t hl3;
    uint8_t lh3;
    uint8_t hh3;
    uint8_t hl2;
    uint8_t lh2;
    uint8_t hh2;
    uint8_t hl1;
    uint8_t lh1;
    uint8_t hh1;
} rdp_rfx_component_quant;

typedef struct rdp_rfx_progressive_quant
{
    uint8_t quality;
    rdp_rfx_component_quant y;
    rdp_rfx_component_quant cb;
    rdp_rfx_component_quant cr;
} rdp_rfx_progressive_quant;

typedef struct rdp_rfx_tile_pixels
{
    uint8_t bgra[RDP_RFX_TILE_COEFFICIENTS * 4u];
    size_t stride;
} rdp_rfx_tile_pixels;

librdp_status rdp_rfx_rlgr_decode(rdp_rfx_rlgr_mode mode,
                                  const void* data,
                                  size_t length,
                                  int32_t* coefficients,
                                  size_t coefficient_count,
                                  size_t* coefficients_written);
librdp_status rdp_rfx_parse_component_quant(const void* data,
                                            size_t length,
                                            rdp_rfx_component_quant* quant);
librdp_status rdp_rfx_parse_progressive_quant(const void* data,
                                              size_t length,
                                              rdp_rfx_progressive_quant* quant);
librdp_status rdp_rfx_add_component_quant(const rdp_rfx_component_quant* base,
                                          const rdp_rfx_component_quant* delta,
                                          rdp_rfx_component_quant* output);
librdp_status rdp_rfx_differential_decode(int32_t* coefficients, size_t coefficient_count);
librdp_status rdp_rfx_inverse_quantize(int32_t* coefficients,
                                       size_t coefficient_count,
                                       const rdp_rfx_component_quant* quant);
librdp_status rdp_rfx_inverse_dwt_2d(int32_t* coefficients, size_t coefficient_count);
librdp_status rdp_rfx_ycbcr_to_bgra(const int32_t* y,
                                    const int32_t* cb,
                                    const int32_t* cr,
                                    uint8_t* bgra,
                                    size_t stride);
librdp_status rdp_rfx_decode_component(rdp_rfx_rlgr_mode mode,
                                       const void* data,
                                       size_t length,
                                       const rdp_rfx_component_quant* quant,
                                       int32_t* coefficients,
                                       size_t coefficient_count);
librdp_status rdp_rfx_decode_tile(rdp_rfx_rlgr_mode mode,
                                  const void* y_data,
                                  size_t y_len,
                                  const void* cb_data,
                                  size_t cb_len,
                                  const void* cr_data,
                                  size_t cr_len,
                                  const rdp_rfx_component_quant* y_quant,
                                  const rdp_rfx_component_quant* cb_quant,
                                  const rdp_rfx_component_quant* cr_quant,
                                  rdp_rfx_tile_pixels* pixels);

#endif
