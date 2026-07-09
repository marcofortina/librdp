#ifndef RDP_GRAPHICS_RFX_CODEC_H
#define RDP_GRAPHICS_RFX_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

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

typedef struct rdp_rfx_progressive_component_state
{
    int32_t current[RDP_RFX_TILE_COEFFICIENTS];
    int32_t sign[RDP_RFX_TILE_COEFFICIENTS];
    rdp_rfx_component_quant bit_pos;
    rdp_rfx_component_quant quant;
    rdp_rfx_component_quant progressive_quant;
    uint8_t valid;
} rdp_rfx_progressive_component_state;

typedef struct rdp_rfx_progressive_tile_state
{
    rdp_rfx_progressive_component_state y;
    rdp_rfx_progressive_component_state cb;
    rdp_rfx_progressive_component_state cr;
    uint16_t x_idx;
    uint16_t y_idx;
    uint16_t pass;
    uint8_t extrapolate;
    uint8_t valid;
} rdp_rfx_progressive_tile_state;

librdp_status rdp_rfx_rlgr_decode(rdp_rfx_rlgr_mode mode,
                                  const void* data,
                                  size_t length,
                                  int32_t* coefficients,
                                  size_t coefficient_count,
                                  size_t* coefficients_written);
librdp_status rdp_rfx_rlgr_write_zeroes(rdp_buffer* buffer, size_t coefficient_count);
librdp_status rdp_rfx_parse_component_quant(const void* data,
                                            size_t length,
                                            rdp_rfx_component_quant* quant);
librdp_status rdp_rfx_write_component_quant(rdp_buffer* buffer, const rdp_rfx_component_quant* quant);
librdp_status rdp_rfx_parse_progressive_quant(const void* data,
                                              size_t length,
                                              rdp_rfx_progressive_quant* quant);
librdp_status rdp_rfx_write_progressive_quant(rdp_buffer* buffer, const rdp_rfx_progressive_quant* quant);
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
librdp_status rdp_rfx_decode_progressive_component(const void* data,
                                                   size_t length,
                                                   const rdp_rfx_component_quant* quant,
                                                   int extrapolate,
                                                   int32_t* coefficients,
                                                   size_t coefficient_count);
librdp_status rdp_rfx_decode_progressive_tile(const void* y_data,
                                              size_t y_len,
                                              const void* cb_data,
                                              size_t cb_len,
                                              const void* cr_data,
                                              size_t cr_len,
                                              const rdp_rfx_component_quant* y_quant,
                                              const rdp_rfx_component_quant* cb_quant,
                                              const rdp_rfx_component_quant* cr_quant,
                                              int extrapolate,
                                              rdp_rfx_tile_pixels* pixels);
librdp_status rdp_rfx_decode_progressive_tile_state(const void* y_data,
                                                    size_t y_len,
                                                    const void* cb_data,
                                                    size_t cb_len,
                                                    const void* cr_data,
                                                    size_t cr_len,
                                                    const rdp_rfx_component_quant* y_quant,
                                                    const rdp_rfx_component_quant* y_delta,
                                                    const rdp_rfx_component_quant* cb_quant,
                                                    const rdp_rfx_component_quant* cb_delta,
                                                    const rdp_rfx_component_quant* cr_quant,
                                                    const rdp_rfx_component_quant* cr_delta,
                                                    int extrapolate,
                                                    int difference,
                                                    rdp_rfx_progressive_tile_state* state,
                                                    rdp_rfx_tile_pixels* pixels);
librdp_status rdp_rfx_decode_progressive_upgrade_tile(const void* y_srl_data,
                                                      size_t y_srl_len,
                                                      const void* y_raw_data,
                                                      size_t y_raw_len,
                                                      const void* cb_srl_data,
                                                      size_t cb_srl_len,
                                                      const void* cb_raw_data,
                                                      size_t cb_raw_len,
                                                      const void* cr_srl_data,
                                                      size_t cr_srl_len,
                                                      const void* cr_raw_data,
                                                      size_t cr_raw_len,
                                                      const rdp_rfx_component_quant* y_quant,
                                                      const rdp_rfx_component_quant* y_delta,
                                                      const rdp_rfx_component_quant* cb_quant,
                                                      const rdp_rfx_component_quant* cb_delta,
                                                      const rdp_rfx_component_quant* cr_quant,
                                                      const rdp_rfx_component_quant* cr_delta,
                                                      int extrapolate,
                                                      rdp_rfx_progressive_tile_state* state,
                                                      rdp_rfx_tile_pixels* pixels);

#endif
