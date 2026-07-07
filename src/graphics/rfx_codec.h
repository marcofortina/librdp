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

librdp_status rdp_rfx_rlgr_decode(rdp_rfx_rlgr_mode mode,
                                  const void* data,
                                  size_t length,
                                  int32_t* coefficients,
                                  size_t coefficient_count,
                                  size_t* coefficients_written);

#endif
