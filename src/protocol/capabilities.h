#ifndef RDP_PROTOCOL_CAPABILITIES_H
#define RDP_PROTOCOL_CAPABILITIES_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#define RDP_CAPABILITY_MAX_SETS 64u
#define RDP_CAPABILITY_TYPE_GENERAL 0x0001u
#define RDP_CAPABILITY_TYPE_BITMAP 0x0002u
#define RDP_CAPABILITY_TYPE_ORDER 0x0003u
#define RDP_CAPABILITY_TYPE_CONTROL 0x0005u
#define RDP_CAPABILITY_TYPE_ACTIVATION 0x0007u
#define RDP_CAPABILITY_TYPE_POINTER 0x0008u
#define RDP_CAPABILITY_TYPE_SHARE 0x0009u
#define RDP_CAPABILITY_TYPE_COLOR_CACHE 0x000au
#define RDP_CAPABILITY_TYPE_SOUND 0x000cu
#define RDP_CAPABILITY_TYPE_INPUT 0x000du
#define RDP_CAPABILITY_TYPE_FONT 0x000eu
#define RDP_CAPABILITY_TYPE_BRUSH 0x000fu
#define RDP_CAPABILITY_TYPE_GLYPH_CACHE 0x0010u
#define RDP_CAPABILITY_TYPE_BITMAP_CACHE_V2 0x0013u
#define RDP_CAPABILITY_TYPE_VIRTUAL_CHANNEL 0x0014u
#define RDP_CAPABILITY_TYPE_LARGE_POINTER 0x001bu
#define RDP_CAPABILITY_TYPE_BITMAP_CODECS 0x001du
#define RDP_CAPABILITY_BITMAP_CODECS_MAX 16u

typedef struct rdp_capability_set
{
    uint16_t type;
    uint16_t length;
    const uint8_t* data;
    size_t data_len;
} rdp_capability_set;

typedef struct rdp_capability_list
{
    uint16_t count;
    rdp_capability_set sets[RDP_CAPABILITY_MAX_SETS];
} rdp_capability_list;

typedef struct rdp_capability_general
{
    uint16_t os_major_type;
    uint16_t os_minor_type;
    uint16_t protocol_version;
    uint16_t compression_types;
    uint16_t extra_flags;
    uint16_t update_capability_flag;
    uint16_t remote_unshare_flag;
    uint16_t compression_level;
    uint8_t refresh_rect_support;
    uint8_t suppress_output_support;
} rdp_capability_general;

typedef struct rdp_capability_bitmap
{
    uint16_t preferred_bits_per_pixel;
    uint16_t receive_1_bit_per_pixel;
    uint16_t receive_4_bits_per_pixel;
    uint16_t receive_8_bits_per_pixel;
    uint16_t desktop_width;
    uint16_t desktop_height;
    uint16_t desktop_resize_flag;
    uint16_t bitmap_compression_flag;
    uint8_t high_color_flags;
    uint8_t drawing_flags;
    uint16_t multiple_rectangle_support;
} rdp_capability_bitmap;

typedef struct rdp_capability_order
{
    uint8_t terminal_descriptor[16];
    uint32_t desktop_save_size;
    uint16_t desktop_save_x_granularity;
    uint16_t desktop_save_y_granularity;
    uint16_t maximum_order_level;
    uint16_t number_fonts;
    uint16_t order_flags;
    uint8_t order_support[32];
    uint16_t text_flags;
    uint16_t order_support_ex_flags;
    uint16_t text_ansi_code_page;
} rdp_capability_order;

typedef struct rdp_capability_bitmap_cache_v2
{
    uint16_t cache_flags;
    uint8_t num_cell_caches;
    uint32_t cell_info[5];
} rdp_capability_bitmap_cache_v2;

typedef struct rdp_capability_pointer
{
    uint16_t color_pointer_flag;
    uint16_t color_pointer_cache_size;
    uint16_t pointer_cache_size;
} rdp_capability_pointer;

typedef struct rdp_capability_large_pointer
{
    uint16_t support_flags;
} rdp_capability_large_pointer;

typedef struct rdp_capability_input
{
    uint16_t input_flags;
    uint32_t keyboard_layout;
    uint32_t keyboard_type;
    uint32_t keyboard_subtype;
    uint32_t keyboard_function_key;
    uint8_t ime_file_name[64];
} rdp_capability_input;

typedef struct rdp_capability_brush
{
    uint32_t support_level;
} rdp_capability_brush;

typedef struct rdp_capability_glyph_cache_entry
{
    uint16_t cache_entries;
    uint16_t maximum_cell_size;
} rdp_capability_glyph_cache_entry;

typedef struct rdp_capability_glyph_cache
{
    rdp_capability_glyph_cache_entry glyph_cache[10];
    uint16_t frag_cache_entries;
    uint16_t frag_cache_maximum_cell_size;
    uint16_t glyph_support_level;
} rdp_capability_glyph_cache;

typedef struct rdp_capability_virtual_channel
{
    uint32_t flags;
    uint32_t chunk_size;
    uint8_t has_chunk_size;
} rdp_capability_virtual_channel;

typedef struct rdp_capability_sound
{
    uint16_t flags;
} rdp_capability_sound;

typedef struct rdp_capability_share
{
    uint16_t node_id;
} rdp_capability_share;

typedef struct rdp_capability_font
{
    uint16_t support_flags;
} rdp_capability_font;

typedef struct rdp_capability_control
{
    uint16_t control_flags;
    uint16_t remote_detach_flag;
    uint16_t control_interest;
    uint16_t detach_interest;
} rdp_capability_control;

typedef struct rdp_capability_color_cache
{
    uint16_t cache_size;
} rdp_capability_color_cache;

typedef struct rdp_capability_activation
{
    uint16_t help_key_flag;
    uint16_t help_key_index_flag;
    uint16_t help_extended_key_flag;
    uint16_t window_manager_key_flag;
} rdp_capability_activation;

typedef struct rdp_capability_bitmap_codec
{
    uint8_t guid[16];
    uint8_t codec_id;
    uint16_t properties_len;
    const uint8_t* properties;
} rdp_capability_bitmap_codec;

typedef struct rdp_capability_bitmap_codecs
{
    uint8_t count;
    rdp_capability_bitmap_codec codecs[RDP_CAPABILITY_BITMAP_CODECS_MAX];
} rdp_capability_bitmap_codecs;

librdp_status rdp_capabilities_parse(const void* data, size_t length, rdp_capability_list* list);
const rdp_capability_set* rdp_capabilities_find(const rdp_capability_list* list, uint16_t type);
librdp_status rdp_capability_parse_general(const rdp_capability_set* set, rdp_capability_general* general);
librdp_status rdp_capability_parse_bitmap(const rdp_capability_set* set, rdp_capability_bitmap* bitmap);
librdp_status rdp_capability_parse_order(const rdp_capability_set* set, rdp_capability_order* order);
librdp_status rdp_capability_parse_bitmap_cache_v2(const rdp_capability_set* set,
                                                   rdp_capability_bitmap_cache_v2* cache);
librdp_status rdp_capability_parse_pointer(const rdp_capability_set* set, rdp_capability_pointer* pointer);
librdp_status rdp_capability_parse_large_pointer(const rdp_capability_set* set,
                                                 rdp_capability_large_pointer* pointer);
librdp_status rdp_capability_parse_input(const rdp_capability_set* set, rdp_capability_input* input);
librdp_status rdp_capability_parse_brush(const rdp_capability_set* set, rdp_capability_brush* brush);
librdp_status rdp_capability_parse_glyph_cache(const rdp_capability_set* set,
                                               rdp_capability_glyph_cache* glyph);
librdp_status rdp_capability_parse_virtual_channel(const rdp_capability_set* set,
                                                   rdp_capability_virtual_channel* channel);
librdp_status rdp_capability_parse_sound(const rdp_capability_set* set, rdp_capability_sound* sound);
librdp_status rdp_capability_parse_share(const rdp_capability_set* set, rdp_capability_share* share);
librdp_status rdp_capability_parse_font(const rdp_capability_set* set, rdp_capability_font* font);
librdp_status rdp_capability_parse_control(const rdp_capability_set* set, rdp_capability_control* control);
librdp_status rdp_capability_parse_color_cache(const rdp_capability_set* set,
                                               rdp_capability_color_cache* color_cache);
librdp_status rdp_capability_parse_activation(const rdp_capability_set* set,
                                              rdp_capability_activation* activation);
librdp_status rdp_capability_parse_bitmap_codecs(const rdp_capability_set* set,
                                                 rdp_capability_bitmap_codecs* codecs);

#endif
