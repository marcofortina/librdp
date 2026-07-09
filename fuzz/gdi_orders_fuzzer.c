#include "graphics/gdi_orders.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

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
    const uint8_t payload[] = {0, 1, 2, 3, 4, 5, 6, 7};
    const uint8_t bounds[] = {0x03u, 0, 0, 1, 0};

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
    (void)rdp_gdi_write_primary_order(&buffer,
                                      RDP_GDI_ORDER_PATBLT,
                                      RDP_GDI_ORDER_DSTBLT,
                                      RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
                                      0x0cu,
                                      NULL,
                                      0,
                                      payload,
                                      2u);
    buffer.length = 0;
    (void)rdp_gdi_write_primary_order(&buffer,
                                      RDP_GDI_ORDER_PATBLT,
                                      RDP_GDI_ORDER_OPAQUERECT,
                                      RDP_GDI_TS_STANDARD | RDP_GDI_TS_BOUNDS |
                                          RDP_GDI_TS_TYPE_CHANGE,
                                      0x0fu,
                                      bounds,
                                      sizeof(bounds),
                                      payload,
                                      2u);
    buffer.length = 0;
    (void)rdp_gdi_write_secondary_order(&buffer,
                                        0,
                                        RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED,
                                        payload,
                                        sizeof(payload));
    buffer.length = 0;
    (void)rdp_gdi_write_altsec_order(&buffer,
                                     RDP_GDI_ALTSEC_SWITCH_SURFACE,
                                     payload,
                                     2u);
    buffer.length = 0;
    (void)rdp_gdi_write_slow_orders_update_payload(&buffer,
                                                   1,
                                                   payload,
                                                   sizeof(payload));
    buffer.length = 0;
    (void)rdp_gdi_write_fast_orders_update_payload(&buffer,
                                                   1,
                                                   payload,
                                                   sizeof(payload));
    buffer.length = 0;
    bitmap_error.count = 1;
    bitmap_error.infos[0].cache_id = 1;
    bitmap_error.infos[0].flags = RDP_GDI_BITMAP_CACHE_ERROR_FLUSH_CACHE;
    bitmap_error.infos[0].new_num_entries = 64;
    (void)rdp_gdi_write_bitmap_cache_error_payload(&buffer, &bitmap_error);
    buffer.length = 0;
    (void)rdp_gdi_write_cache_error_flags(&buffer, RDP_GDI_OFFSCREEN_CACHE_ERROR_FLUSH_AND_DISABLE);
    buffer.length = 0;
    color.color_table_cache_size = 6;
    (void)rdp_gdi_write_color_cache_capability(&buffer, &color);
    buffer.length = 0;
    ninegrid.support_level = RDP_GDI_NINEGRID_SUPPORT_SUPPORTED;
    ninegrid.cache_size = 128;
    ninegrid.cache_entries = 32;
    (void)rdp_gdi_write_ninegrid_capability(&buffer, &ninegrid);
    buffer.length = 0;
    memset(&gdiplus, 0, sizeof(gdiplus));
    gdiplus.support_level = RDP_GDI_GDIPLUS_SUPPORT_SUPPORTED;
    gdiplus.version = 1;
    gdiplus.cache_level = RDP_GDI_GDIPLUS_CACHE_LEVEL_ONE;
    gdiplus.cache_entries[0] = 1;
    gdiplus.cache_chunk_size[0] = 64;
    gdiplus.image_cache_properties[0] = 128;
    (void)rdp_gdi_write_gdiplus_capability(&buffer, &gdiplus);
    rdp_buffer_free(&buffer);
    return 0;
}
