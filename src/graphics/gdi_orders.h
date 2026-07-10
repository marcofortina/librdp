#ifndef RDP_GRAPHICS_GDI_ORDERS_H
#define RDP_GRAPHICS_GDI_ORDERS_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"
#include "graphics/bitmap.h"

#define RDP_GDI_UPDATE_TYPE_ORDERS 0x0000u

#define RDP_GDI_TS_STANDARD 0x01u
#define RDP_GDI_TS_SECONDARY 0x02u
#define RDP_GDI_TS_BOUNDS 0x04u
#define RDP_GDI_TS_TYPE_CHANGE 0x08u
#define RDP_GDI_TS_DELTA_COORDINATES 0x10u
#define RDP_GDI_TS_ZERO_BOUNDS_DELTAS 0x20u
#define RDP_GDI_TS_ZERO_FIELD_BYTE_BIT0 0x40u
#define RDP_GDI_TS_ZERO_FIELD_BYTE_BIT1 0x80u

#define RDP_GDI_ORDER_DSTBLT 0x00u
#define RDP_GDI_ORDER_PATBLT 0x01u
#define RDP_GDI_ORDER_SCRBLT 0x02u
#define RDP_GDI_ORDER_DRAWNINEGRID 0x07u
#define RDP_GDI_ORDER_MULTI_DRAWNINEGRID 0x08u
#define RDP_GDI_ORDER_LINETO 0x09u
#define RDP_GDI_ORDER_OPAQUERECT 0x0au
#define RDP_GDI_ORDER_SAVEBITMAP 0x0bu
#define RDP_GDI_ORDER_MEMBLT 0x0du
#define RDP_GDI_ORDER_MEM3BLT 0x0eu
#define RDP_GDI_ORDER_MULTIDSTBLT 0x0fu
#define RDP_GDI_ORDER_MULTIPATBLT 0x10u
#define RDP_GDI_ORDER_MULTISCRBLT 0x11u
#define RDP_GDI_ORDER_MULTIOPAQUERECT 0x12u
#define RDP_GDI_ORDER_FAST_INDEX 0x13u
#define RDP_GDI_ORDER_POLYGON_SC 0x14u
#define RDP_GDI_ORDER_POLYGON_CB 0x15u
#define RDP_GDI_ORDER_POLYLINE 0x16u
#define RDP_GDI_ORDER_FAST_GLYPH 0x18u
#define RDP_GDI_ORDER_ELLIPSE_SC 0x19u
#define RDP_GDI_ORDER_ELLIPSE_CB 0x1au
#define RDP_GDI_ORDER_GLYPH_INDEX 0x1bu

#define RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED 0x00u
#define RDP_GDI_SECONDARY_CACHE_COLOR_TABLE 0x01u
#define RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED 0x02u
#define RDP_GDI_SECONDARY_CACHE_GLYPH 0x03u
#define RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED_REV2 0x04u
#define RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV2 0x05u
#define RDP_GDI_SECONDARY_CACHE_BRUSH 0x07u
#define RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV3 0x08u

#define RDP_GDI_ALTSEC_SWITCH_SURFACE 0x00u
#define RDP_GDI_ALTSEC_CREATE_OFFSCREEN_BITMAP 0x01u
#define RDP_GDI_ALTSEC_STREAM_BITMAP_FIRST 0x02u
#define RDP_GDI_ALTSEC_STREAM_BITMAP_NEXT 0x03u
#define RDP_GDI_ALTSEC_CREATE_NINEGRID_BITMAP 0x04u
#define RDP_GDI_ALTSEC_DRAW_GDIPLUS_FIRST 0x05u
#define RDP_GDI_ALTSEC_DRAW_GDIPLUS_NEXT 0x06u
#define RDP_GDI_ALTSEC_DRAW_GDIPLUS_END 0x07u
#define RDP_GDI_ALTSEC_DRAW_GDIPLUS_CACHE_FIRST 0x08u
#define RDP_GDI_ALTSEC_DRAW_GDIPLUS_CACHE_NEXT 0x09u
#define RDP_GDI_ALTSEC_DRAW_GDIPLUS_CACHE_END 0x0au
#define RDP_GDI_ALTSEC_WINDOW 0x0bu
#define RDP_GDI_ALTSEC_COMPDESK_FIRST 0x0cu
#define RDP_GDI_ALTSEC_FRAME_MARKER 0x0du

#define RDP_GDI_CAPSTYPE_COLOR_CACHE 0x000au
#define RDP_GDI_CAPSTYPE_DRAW_NINEGRID_CACHE 0x0015u
#define RDP_GDI_CAPSTYPE_DRAW_GDIPLUS 0x0016u

#define RDP_GDI_COLOR_CACHE_CAPABILITY_LENGTH 8u
#define RDP_GDI_DRAW_NINEGRID_CAPABILITY_LENGTH 12u
#define RDP_GDI_DRAW_GDIPLUS_CAPABILITY_LENGTH 40u

#define RDP_GDI_NINEGRID_SUPPORT_NONE 0x00000000u
#define RDP_GDI_NINEGRID_SUPPORT_SUPPORTED 0x00000001u
#define RDP_GDI_NINEGRID_SUPPORT_SUPPORTED_REV2 0x00000002u
#define RDP_GDI_GDIPLUS_SUPPORT_NONE 0x00000000u
#define RDP_GDI_GDIPLUS_SUPPORT_SUPPORTED 0x00000001u
#define RDP_GDI_GDIPLUS_CACHE_LEVEL_NONE 0x00000000u
#define RDP_GDI_GDIPLUS_CACHE_LEVEL_ONE 0x00000001u

#define RDP_GDI_BITMAP_CACHE_ERROR_FLUSH_CACHE 0x01u
#define RDP_GDI_BITMAP_CACHE_ERROR_NEWNUMENTRIES_VALID 0x02u
#define RDP_GDI_CACHE_GLYPH_UNICODE_PRESENT 0x0010u
#define RDP_GDI_NO_BITMAP_COMPRESSION_HEADER 0x0400u
#define RDP_GDI_CBR2_HEIGHT_SAME_AS_WIDTH 0x01u
#define RDP_GDI_CBR2_PERSISTENT_KEY_PRESENT 0x02u
#define RDP_GDI_CBR2_NO_BITMAP_COMPRESSION_HEADER 0x08u
#define RDP_GDI_CBR2_DO_NOT_CACHE 0x10u
#define RDP_GDI_CBR3_IGNORABLE_FLAG 0x08u
#define RDP_GDI_CBR3_DO_NOT_CACHE 0x10u
#define RDP_GDI_BITMAP_CACHE_WAITING_LIST_INDEX 0x7fffu
#define RDP_GDI_CACHED_BRUSH 0x80u
#define RDP_GDI_BMF_1BPP 0x01u
#define RDP_GDI_BMF_8BPP 0x03u
#define RDP_GDI_BMF_16BPP 0x04u
#define RDP_GDI_BMF_24BPP 0x05u
#define RDP_GDI_BMF_32BPP 0x06u
#define RDP_GDI_BRUSH_CACHE_ENTRIES 64u
#define RDP_GDI_OFFSCREEN_CACHE_ERROR_FLUSH_AND_DISABLE 0x00000001u
#define RDP_GDI_NINEGRID_CACHE_ERROR_FLUSH_AND_DISABLE 0x00000001u
#define RDP_GDI_GDIPLUS_CACHE_ERROR_FLUSH_AND_DISABLE 0x00000001u
#define RDP_GDI_GLYPH_FRAGMENT_NOP 0x00u
#define RDP_GDI_GLYPH_FRAGMENT_USE 0xfeu
#define RDP_GDI_GLYPH_FRAGMENT_ADD 0xffu
#define RDP_GDI_GLYPH_SO_FLAG_DEFAULT_PLACEMENT 0x01u
#define RDP_GDI_GLYPH_SO_HORIZONTAL 0x02u
#define RDP_GDI_GLYPH_SO_VERTICAL 0x04u
#define RDP_GDI_GLYPH_SO_REVERSED 0x08u
#define RDP_GDI_GLYPH_SO_ZERO_BEARINGS 0x10u
#define RDP_GDI_GLYPH_SO_CHAR_INC_EQUAL_BM_BASE 0x20u
#define RDP_GDI_GLYPH_SO_MAXEXT_EQUAL_BM_SIDE 0x40u

#define RDP_GDI_MAX_ORDERS 256u
#define RDP_GDI_MAX_BITMAP_CACHE_ERROR_INFO 16u
#define RDP_GDI_MAX_CACHE_GLYPHS 256u

typedef enum rdp_gdi_order_kind
{
    RDP_GDI_ORDER_KIND_PRIMARY = 1,
    RDP_GDI_ORDER_KIND_SECONDARY = 2,
    RDP_GDI_ORDER_KIND_ALTSEC = 3
} rdp_gdi_order_kind;

typedef struct rdp_gdi_orders_update
{
    uint16_t update_type;
    uint16_t number_orders;
    const uint8_t* order_data;
    size_t order_data_len;
} rdp_gdi_orders_update;

typedef struct rdp_gdi_order_span
{
    rdp_gdi_order_kind kind;
    uint8_t order_type;
    const uint8_t* data;
    size_t length;
} rdp_gdi_order_span;

typedef struct rdp_gdi_order_list
{
    uint16_t count;
    rdp_gdi_order_span orders[RDP_GDI_MAX_ORDERS];
} rdp_gdi_order_list;

typedef struct rdp_gdi_primary_order_header
{
    uint8_t control_flags;
    uint8_t order_type;
    uint32_t field_flags;
    uint8_t field_flag_bytes;
    uint8_t bounds_flags;
    size_t bounds_len;
    const uint8_t* payload;
    size_t payload_len;
    uint8_t next_order_type;
} rdp_gdi_primary_order_header;

typedef struct rdp_gdi_secondary_order_header
{
    uint8_t control_flags;
    uint16_t order_length;
    size_t actual_length;
    uint16_t extra_flags;
    uint8_t order_type;
    const uint8_t* payload;
    size_t payload_len;
} rdp_gdi_secondary_order_header;

typedef struct rdp_gdi_cache_bitmap_order
{
    uint32_t cache_id;
    uint32_t key1;
    uint32_t key2;
    uint32_t bits_per_pixel;
    uint32_t width;
    uint32_t height;
    uint32_t cache_index;
    uint8_t compressed;
    uint8_t do_not_cache;
    uint8_t rev3;
    uint8_t codec_id;
    uint8_t has_compression_header;
    uint8_t bitmap_data_includes_compression_header;
    uint8_t compression_header[8];
    const uint8_t* bitmap_data;
    uint32_t bitmap_data_len;
} rdp_gdi_cache_bitmap_order;

typedef struct rdp_gdi_cache_color_table_order
{
    uint32_t cache_index;
    rdp_palette_update palette;
} rdp_gdi_cache_color_table_order;

typedef struct rdp_gdi_cache_brush_order
{
    uint32_t cache_entry;
    uint32_t bitmap_format;
    uint32_t width;
    uint32_t height;
    uint32_t style;
    const uint8_t* brush_data;
    uint32_t brush_data_len;
} rdp_gdi_cache_brush_order;

typedef struct rdp_gdi_glyph_bitmap
{
    uint32_t cache_index;
    int32_t x;
    int32_t y;
    uint32_t width;
    uint32_t height;
    const uint8_t* bitmap;
    uint32_t bitmap_len;
    uint16_t unicode_codepoint;
    uint8_t has_unicode;
} rdp_gdi_glyph_bitmap;

typedef struct rdp_gdi_cache_glyph_order
{
    uint32_t cache_id;
    uint32_t flags;
    uint8_t version;
    uint32_t glyph_count;
    rdp_gdi_glyph_bitmap glyphs[RDP_GDI_MAX_CACHE_GLYPHS];
} rdp_gdi_cache_glyph_order;

typedef struct rdp_gdi_altsec_order_header
{
    uint8_t control_flags;
    uint8_t order_type;
    const uint8_t* payload;
    size_t payload_len;
} rdp_gdi_altsec_order_header;

typedef struct rdp_gdi_bitmap_cache_error_info
{
    uint8_t cache_id;
    uint8_t flags;
    uint32_t new_num_entries;
} rdp_gdi_bitmap_cache_error_info;

typedef struct rdp_gdi_bitmap_cache_error
{
    uint8_t count;
    rdp_gdi_bitmap_cache_error_info infos[RDP_GDI_MAX_BITMAP_CACHE_ERROR_INFO];
} rdp_gdi_bitmap_cache_error;

typedef struct rdp_gdi_color_cache_capability
{
    uint16_t color_table_cache_size;
} rdp_gdi_color_cache_capability;

typedef struct rdp_gdi_ninegrid_capability
{
    uint32_t support_level;
    uint16_t cache_size;
    uint16_t cache_entries;
} rdp_gdi_ninegrid_capability;

typedef struct rdp_gdi_gdiplus_capability
{
    uint32_t support_level;
    uint32_t version;
    uint32_t cache_level;
    uint16_t cache_entries[5];
    uint16_t cache_chunk_size[4];
    uint16_t image_cache_properties[3];
} rdp_gdi_gdiplus_capability;

typedef struct rdp_gdi_ninegrid_bitmap_info
{
    uint32_t flags;
    uint32_t left_width;
    uint32_t right_width;
    uint32_t top_height;
    uint32_t bottom_height;
    uint32_t transparent_color;
} rdp_gdi_ninegrid_bitmap_info;

typedef struct rdp_gdi_create_ninegrid_bitmap_order
{
    uint32_t bits_per_pixel;
    uint32_t bitmap_id;
    uint32_t width;
    uint32_t height;
    rdp_gdi_ninegrid_bitmap_info info;
} rdp_gdi_create_ninegrid_bitmap_order;

librdp_status rdp_gdi_parse_slow_orders_update_payload(const void* data,
                                                       size_t length,
                                                       rdp_gdi_orders_update* update);
librdp_status rdp_gdi_write_slow_orders_update_payload(rdp_buffer* buffer,
                                                       uint16_t number_orders,
                                                       const void* order_data,
                                                       size_t order_data_len);
librdp_status rdp_gdi_parse_fast_orders_update_payload(const void* data,
                                                       size_t length,
                                                       rdp_gdi_orders_update* update);
librdp_status rdp_gdi_write_fast_orders_update_payload(rdp_buffer* buffer,
                                                       uint16_t number_orders,
                                                       const void* order_data,
                                                       size_t order_data_len);
librdp_status rdp_gdi_parse_order_list(const void* data,
                                       size_t length,
                                       uint16_t number_orders,
                                       uint8_t initial_order_type,
                                       rdp_gdi_order_list* list);
librdp_status rdp_gdi_parse_primary_order(const void* data,
                                          size_t length,
                                          uint8_t previous_order_type,
                                          rdp_gdi_primary_order_header* header);
librdp_status rdp_gdi_write_primary_order(rdp_buffer* buffer,
                                          uint8_t previous_order_type,
                                          uint8_t order_type,
                                          uint8_t control_flags,
                                          uint32_t field_flags,
                                          const void* bounds,
                                          size_t bounds_len,
                                          const void* payload,
                                          size_t payload_len);
librdp_status rdp_gdi_parse_secondary_order(const void* data,
                                            size_t length,
                                            rdp_gdi_secondary_order_header* header);
librdp_status rdp_gdi_write_secondary_order(rdp_buffer* buffer,
                                            uint16_t extra_flags,
                                            uint8_t order_type,
                                            const void* payload,
                                            size_t payload_len);
librdp_status rdp_gdi_parse_cache_bitmap_order(const rdp_gdi_secondary_order_header* header,
                                               rdp_gdi_cache_bitmap_order* order);
librdp_status rdp_gdi_parse_cache_color_table_order(const rdp_gdi_secondary_order_header* header,
                                                    rdp_gdi_cache_color_table_order* order);
librdp_status rdp_gdi_parse_cache_brush_order(const rdp_gdi_secondary_order_header* header,
                                              rdp_gdi_cache_brush_order* order);
librdp_status rdp_gdi_parse_cache_glyph_order(const rdp_gdi_secondary_order_header* header,
                                              rdp_gdi_cache_glyph_order* order);
librdp_status rdp_gdi_parse_altsec_order(const void* data,
                                         size_t length,
                                         rdp_gdi_altsec_order_header* header);
librdp_status rdp_gdi_write_altsec_order(rdp_buffer* buffer,
                                         uint8_t order_type,
                                         const void* payload,
                                         size_t payload_len);
librdp_status rdp_gdi_parse_create_ninegrid_bitmap_order(const rdp_gdi_altsec_order_header* header,
                                                         rdp_gdi_create_ninegrid_bitmap_order* order);
librdp_status rdp_gdi_write_create_ninegrid_bitmap_order(rdp_buffer* buffer,
                                                         const rdp_gdi_create_ninegrid_bitmap_order* order);
librdp_status rdp_gdi_parse_bitmap_cache_error_payload(const void* data,
                                                       size_t length,
                                                       rdp_gdi_bitmap_cache_error* error);
librdp_status rdp_gdi_write_bitmap_cache_error_payload(rdp_buffer* buffer,
                                                       const rdp_gdi_bitmap_cache_error* error);
librdp_status rdp_gdi_parse_cache_error_flags(const void* data,
                                              size_t length,
                                              uint32_t expected_flags,
                                              uint32_t* flags);
librdp_status rdp_gdi_write_cache_error_flags(rdp_buffer* buffer, uint32_t flags);
librdp_status rdp_gdi_parse_color_cache_capability(const void* data,
                                                   size_t length,
                                                   rdp_gdi_color_cache_capability* capability);
librdp_status rdp_gdi_write_color_cache_capability(
    rdp_buffer* buffer,
    const rdp_gdi_color_cache_capability* capability);
librdp_status rdp_gdi_parse_ninegrid_capability(const void* data,
                                                size_t length,
                                                rdp_gdi_ninegrid_capability* capability);
librdp_status rdp_gdi_write_ninegrid_capability(
    rdp_buffer* buffer,
    const rdp_gdi_ninegrid_capability* capability);
librdp_status rdp_gdi_parse_gdiplus_capability(const void* data,
                                               size_t length,
                                               rdp_gdi_gdiplus_capability* capability);
librdp_status rdp_gdi_write_gdiplus_capability(
    rdp_buffer* buffer,
    const rdp_gdi_gdiplus_capability* capability);

#endif
