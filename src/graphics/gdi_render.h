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
    RDP_GDI_RENDER_OP_PATBLT = 4,
    RDP_GDI_RENDER_OP_LINE = 5,
    RDP_GDI_RENDER_OP_POLYLINE = 6,
    RDP_GDI_RENDER_OP_POLYGON_SC = 7,
    RDP_GDI_RENDER_OP_ELLIPSE_SC = 8,
    RDP_GDI_RENDER_OP_MULTIDSTBLT = 9,
    RDP_GDI_RENDER_OP_MULTISCRBLT = 10,
    RDP_GDI_RENDER_OP_MULTIOPAQUE_RECT = 11,
    RDP_GDI_RENDER_OP_MULTIPATBLT = 12,
    RDP_GDI_RENDER_OP_SAVE_BITMAP = 13,
    RDP_GDI_RENDER_OP_POLYGON_CB = 14,
    RDP_GDI_RENDER_OP_ELLIPSE_CB = 15
} rdp_gdi_render_op_kind;

#define RDP_GDI_RENDER_MAX_POINTS 256u
#define RDP_GDI_RENDER_MAX_RECTS 45u

typedef struct rdp_gdi_render_point
{
    int32_t x;
    int32_t y;
} rdp_gdi_render_point;

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
    uint32_t back_color;
    rdp_gdi_render_rect rect;
    int32_t src_x;
    int32_t src_y;
    int32_t end_x;
    int32_t end_y;
    uint32_t pen_width;
    uint32_t pen_style;
    int32_t brush_x;
    int32_t brush_y;
    uint8_t brush_style;
    uint8_t brush_hatch;
    uint8_t brush_extra[7];
    uint8_t transparent_background;
    uint32_t bitmap_id;
    uint8_t operation;
    uint32_t fill_mode;
    uint32_t point_count;
    rdp_gdi_render_point points[RDP_GDI_RENDER_MAX_POINTS];
    uint32_t rect_count;
    rdp_gdi_render_rect rects[RDP_GDI_RENDER_MAX_RECTS];
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
    uint32_t line_back_mode;
    int32_t line_start_x;
    int32_t line_start_y;
    int32_t line_end_x;
    int32_t line_end_y;
    uint32_t line_back_color;
    uint8_t line_rop2;
    uint8_t line_pen_style;
    uint8_t line_pen_width;
    uint32_t line_pen_color;
    int32_t polyline_start_x;
    int32_t polyline_start_y;
    uint8_t polyline_rop2;
    uint32_t polyline_unused;
    uint32_t polyline_pen_color;
    uint32_t polyline_point_count;
    rdp_gdi_render_point polyline_points[RDP_GDI_RENDER_MAX_POINTS];
    int32_t polygon_start_x;
    int32_t polygon_start_y;
    uint8_t polygon_rop2;
    uint8_t polygon_fill_mode;
    uint32_t polygon_color;
    uint32_t polygon_point_count;
    rdp_gdi_render_point polygon_points[RDP_GDI_RENDER_MAX_POINTS];
    int32_t ellipse_left;
    int32_t ellipse_top;
    int32_t ellipse_right;
    int32_t ellipse_bottom;
    uint8_t ellipse_rop2;
    uint8_t ellipse_fill_mode;
    uint32_t ellipse_color;
    int32_t multi_dst_left;
    int32_t multi_dst_top;
    int32_t multi_dst_width;
    int32_t multi_dst_height;
    uint8_t multi_dst_rop;
    uint32_t multi_dst_rect_count;
    rdp_gdi_render_rect multi_dst_rects[RDP_GDI_RENDER_MAX_RECTS];
    int32_t multi_scr_left;
    int32_t multi_scr_top;
    int32_t multi_scr_width;
    int32_t multi_scr_height;
    uint8_t multi_scr_rop;
    int32_t multi_scr_src_x;
    int32_t multi_scr_src_y;
    uint32_t multi_scr_rect_count;
    rdp_gdi_render_rect multi_scr_rects[RDP_GDI_RENDER_MAX_RECTS];
    int32_t multi_opaque_left;
    int32_t multi_opaque_top;
    int32_t multi_opaque_width;
    int32_t multi_opaque_height;
    uint32_t multi_opaque_color;
    uint32_t multi_opaque_rect_count;
    rdp_gdi_render_rect multi_opaque_rects[RDP_GDI_RENDER_MAX_RECTS];
    int32_t multi_pat_left;
    int32_t multi_pat_top;
    int32_t multi_pat_width;
    int32_t multi_pat_height;
    uint8_t multi_pat_rop;
    uint32_t multi_pat_back_color;
    uint32_t multi_pat_fore_color;
    int32_t multi_pat_brush_x;
    int32_t multi_pat_brush_y;
    uint8_t multi_pat_brush_style;
    uint8_t multi_pat_brush_hatch;
    uint8_t multi_pat_brush_extra[7];
    uint32_t multi_pat_rect_count;
    rdp_gdi_render_rect multi_pat_rects[RDP_GDI_RENDER_MAX_RECTS];
    uint32_t save_bitmap_position;
    int32_t save_bitmap_left;
    int32_t save_bitmap_top;
    int32_t save_bitmap_right;
    int32_t save_bitmap_bottom;
    uint8_t save_bitmap_operation;
} rdp_gdi_render_state;

void rdp_gdi_render_state_init(rdp_gdi_render_state* state);
librdp_status rdp_gdi_decode_primary_render_order(rdp_gdi_render_state* state,
                                                  const void* data,
                                                  size_t length,
                                                  rdp_gdi_render_op* op,
                                                  size_t* consumed);

#endif
