#include "graphics/gdi_orders.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_gdi_orders_update update;
    rdp_gdi_order_list list;
    rdp_gdi_primary_order_header primary;
    rdp_gdi_secondary_order_header secondary;
    rdp_gdi_altsec_order_header altsec;
    rdp_gdi_bitmap_cache_error bitmap_error;
    rdp_gdi_color_cache_capability color;
    rdp_gdi_ninegrid_capability ninegrid;
    rdp_gdi_gdiplus_capability gdiplus;
    rdp_buffer buffer;
    uint32_t flags = 0;

    (void)rdp_gdi_parse_slow_orders_update_payload(data, size, &update);
    (void)rdp_gdi_parse_fast_orders_update_payload(data, size, &update);
    (void)rdp_gdi_parse_order_list(data, size, (uint16_t)(size & 0xffu), RDP_GDI_ORDER_PATBLT, &list);
    (void)rdp_gdi_parse_primary_order(data, size, RDP_GDI_ORDER_PATBLT, &primary);
    (void)rdp_gdi_parse_secondary_order(data, size, &secondary);
    (void)rdp_gdi_parse_altsec_order(data, size, &altsec);
    (void)rdp_gdi_parse_bitmap_cache_error_payload(data, size, &bitmap_error);
    (void)rdp_gdi_parse_cache_error_flags(data,
                                          size,
                                          RDP_GDI_OFFSCREEN_CACHE_ERROR_FLUSH_AND_DISABLE,
                                          &flags);
    (void)rdp_gdi_parse_color_cache_capability(data, size, &color);
    (void)rdp_gdi_parse_ninegrid_capability(data, size, &ninegrid);
    (void)rdp_gdi_parse_gdiplus_capability(data, size, &gdiplus);

    rdp_buffer_init(&buffer);
    bitmap_error.count = 1;
    bitmap_error.infos[0].cache_id = 1;
    bitmap_error.infos[0].flags = RDP_GDI_BITMAP_CACHE_ERROR_FLUSH_CACHE;
    bitmap_error.infos[0].new_num_entries = 64;
    (void)rdp_gdi_write_bitmap_cache_error_payload(&buffer, &bitmap_error);
    buffer.length = 0;
    (void)rdp_gdi_write_cache_error_flags(&buffer, RDP_GDI_OFFSCREEN_CACHE_ERROR_FLUSH_AND_DISABLE);
    rdp_buffer_free(&buffer);
    return 0;
}
