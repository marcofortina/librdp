#ifndef RDP_GRAPHICS_GDI_RENDER_H
#define RDP_GRAPHICS_GDI_RENDER_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

typedef enum rdp_gdi_render_op_kind
{
    RDP_GDI_RENDER_OP_NONE = 0,
    RDP_GDI_RENDER_OP_OPAQUE_RECT = 1,
    RDP_GDI_RENDER_OP_DSTBLT = 2,
    RDP_GDI_RENDER_OP_SCRBLT = 3,
    RDP_GDI_RENDER_OP_PATBLT = 4
} rdp_gdi_render_op_kind;

typedef struct rdp_gdi_render_rect
{
    int32_t x;
    int32_t y;
    int32_t width;
    int32_t height;
} rdp_gdi_render_rect;

typedef struct rdp_gdi_render_bounds
{
    uint8_t present;
    int32_t left;
    int32_t top;
    int32_t right;
    int32_t bottom;
} rdp_gdi_render_bounds;

typedef struct rdp_gdi_render_op
{
    rdp_gdi_render_op_kind kind;
    uint8_t order_type;
    uint8_t rop;
    uint32_t color;
    rdp_gdi_render_rect rect;
    int32_t src_x;
    int32_t src_y;
    rdp_gdi_render_bounds bounds;
} rdp_gdi_render_op;

typedef struct rdp_gdi_render_state
{
    uint8_t current_order_type;
    int32_t bounds_left;
    int32_t bounds_top;
    int32_t bounds_right;
    int32_t bounds_bottom;
    int32_t dst_left;
    int32_t dst_top;
    int32_t dst_width;
    int32_t dst_height;
    uint8_t dst_rop;
    int32_t opaque_left;
    int32_t opaque_top;
    int32_t opaque_width;
    int32_t opaque_height;
    uint32_t opaque_color;
    int32_t scr_left;
    int32_t scr_top;
    int32_t scr_width;
    int32_t scr_height;
    uint8_t scr_rop;
    int32_t scr_src_x;
    int32_t scr_src_y;
    int32_t pat_left;
    int32_t pat_top;
    int32_t pat_width;
    int32_t pat_height;
    uint8_t pat_rop;
    uint32_t pat_back_color;
    uint32_t pat_fore_color;
    int32_t pat_brush_x;
    int32_t pat_brush_y;
    uint8_t pat_brush_style;
    uint8_t pat_brush_hatch;
    uint8_t pat_brush_extra[7];
} rdp_gdi_render_state;

void rdp_gdi_render_state_init(rdp_gdi_render_state* state);
librdp_status rdp_gdi_decode_primary_render_order(rdp_gdi_render_state* state,
                                                  const void* data,
                                                  size_t length,
                                                  rdp_gdi_render_op* op,
                                                  size_t* consumed);

#endif
