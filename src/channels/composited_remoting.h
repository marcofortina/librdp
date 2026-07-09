#ifndef RDP_CHANNELS_COMPOSITED_REMOTING_H
#define RDP_CHANNELS_COMPOSITED_REMOTING_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_COMPOSITED_CHANNEL_NAME "dwmprox"
#define RDP_COMPOSITED_PROTOCOL_VERSION 0x1042ea27u
#define RDP_COMPOSITED_MAX_VERSION_COUNT 16u
#define RDP_COMPOSITED_TEXTURE_SET_BYTES 208u
#define RDP_COMPOSITED_TEXTURE_SLOT_BYTES 24u
#define RDP_COMPOSITED_TEXTURE_SLOT_COUNT 8u
#define RDP_COMPOSITED_CONTROL_VERSION_REQUEST 0x00000001u
#define RDP_COMPOSITED_CONTROL_VERSION_ANNOUNCEMENT 0x00000002u
#define RDP_COMPOSITED_CONTROL_OPEN_CONNECTION 0x00000003u
#define RDP_COMPOSITED_CONTROL_CLOSE_CONNECTION 0x00000004u
#define RDP_COMPOSITED_CONTROL_OPEN_CHANNEL 0x00000005u
#define RDP_COMPOSITED_CONTROL_CLOSE_CHANNEL 0x00000006u
#define RDP_COMPOSITED_CONTROL_DATA_ON_CHANNEL 0x00000007u
#define RDP_COMPOSITED_CONTROL_CONNECTION_NOTIFICATION 0x00000009u
#define RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION 0x0000000au
#define RDP_COMPOSITED_CONTROL_CONNECTION_BROADCAST 0x0000000bu
#define RDP_COMPOSITED_CONTROL_SURFACE_MANAGER_EVENT 0x0000000cu
#define RDP_COMPOSITED_CMD_SYNC_FLUSH 0x00000001u
#define RDP_COMPOSITED_CMD_ROUNDTRIP_REQUEST 0x00000003u
#define RDP_COMPOSITED_CMD_ASYNC_FLUSH 0x00000004u
#define RDP_COMPOSITED_CMD_REGISTER_NOTIFICATIONS 0x00000005u
#define RDP_COMPOSITED_CMD_REQUEST_TIER 0x00000009u
#define RDP_COMPOSITED_CMD_CREATE_RESOURCE 0x0000000au
#define RDP_COMPOSITED_CMD_DELETE_RESOURCE 0x0000000bu
#define RDP_COMPOSITED_CMD_DUPLICATE_HANDLE 0x0000000cu
#define RDP_COMPOSITED_CMD_BITMAP_PIXELS 0x0000000eu
#define RDP_COMPOSITED_CMD_BITMAP_COMPRESSED_PIXELS 0x0000000fu
#define RDP_COMPOSITED_CMD_RENDERDATA 0x00000019u
#define RDP_COMPOSITED_CMD_WINDOW_NODE_CREATE 0x0000002bu
#define RDP_COMPOSITED_CMD_WINDOW_NODE_DETACH 0x0000002cu
#define RDP_COMPOSITED_CMD_WINDOW_NODE_SET_BOUNDS 0x0000002eu
#define RDP_COMPOSITED_CMD_WINDOW_NODE_UPDATE_SPRITE_HANDLE 0x00000030u
#define RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SPRITE_IMAGE 0x00000032u
#define RDP_COMPOSITED_CMD_WINDOW_NODE_SET_LOGICAL_SURFACE_IMAGE 0x00000034u
#define RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SPRITE_CLIP 0x00000035u
#define RDP_COMPOSITED_CMD_WINDOW_NODE_SET_DX_CLIP 0x00000036u
#define RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SOURCE_MODIFICATIONS 0x00000037u
#define RDP_COMPOSITED_CMD_WINDOW_NODE_SET_ALPHA_MARGINS 0x00000038u
#define RDP_COMPOSITED_CMD_WINDOW_NODE_SET_COMPOSE_ONCE 0x00000039u
#define RDP_COMPOSITED_CMD_WINDOW_NODE_COPY_OWNED_RESOURCES 0x0000003au
#define RDP_COMPOSITED_CMD_WINDOW_NODE_SET_MAXIMIZED_CLIP_MARGINS 0x0000003bu
#define RDP_COMPOSITED_CMD_WINDOW_NODE_NOTIFY_VISIBLE_REGION 0x0000003cu
#define RDP_COMPOSITED_CMD_WINDOW_NODE_PROTECT_CONTENT 0x0000003fu
#define RDP_COMPOSITED_CMD_VISUAL_GROUP 0x00000041u
#define RDP_COMPOSITED_CMD_HWND_TARGET_CREATE 0x00000042u
#define RDP_COMPOSITED_CMD_TARGET_UPDATE_WINDOW_SETTINGS 0x00000043u
#define RDP_COMPOSITED_CMD_TARGET_SET_ROOT 0x00000045u
#define RDP_COMPOSITED_CMD_TARGET_SET_CLEAR_COLOR 0x00000046u
#define RDP_COMPOSITED_CMD_TARGET_INVALIDATE 0x00000047u
#define RDP_COMPOSITED_CMD_TARGET_CAPTURE_BITS 0x00000049u
#define RDP_COMPOSITED_CMD_META_TARGET_CAPTURE_BITS 0x0000004au
#define RDP_COMPOSITED_CMD_META_TARGET_CREATE 0x0000004bu
#define RDP_COMPOSITED_CMD_META_TARGET_SET_TRANSFORM 0x0000004cu
#define RDP_COMPOSITED_CMD_META_TARGET_SET_COLOR_TRANSFORM 0x0000004du
#define RDP_COMPOSITED_CMD_META_TARGET_UPDATE 0x0000004eu
#define RDP_COMPOSITED_CMD_META_TARGET_SET_FILTER_LIST 0x00000050u
#define RDP_COMPOSITED_CMD_GLYPH_CACHE_ADD_BITMAPS 0x00000052u
#define RDP_COMPOSITED_CMD_GLYPH_CACHE_REMOVE_BITMAPS 0x00000053u
#define RDP_COMPOSITED_CMD_GLYPH_RUN_CREATE 0x00000054u
#define RDP_COMPOSITED_CMD_GLYPH_RUN_ADD_REALIZATION 0x00000055u
#define RDP_COMPOSITED_CMD_GLYPH_RUN_REMOVE_REALIZATION 0x00000056u
#define RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP 0x00000057u
#define RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UPDATE_MARGINS 0x00000058u
#define RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UPDATE_SURFACE 0x00000059u
#define RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UNMAP_SECTION 0x0000005au
#define RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_NOTIFY_DIRTY 0x0000005bu
#define RDP_COMPOSITED_MSG_SYNC_FLUSH_REPLY 0x00000001u
#define RDP_COMPOSITED_MSG_CAPTURE_BITS_REPLY 0x00000002u
#define RDP_COMPOSITED_MSG_VERSION_REPLY 0x00000003u
#define RDP_COMPOSITED_MSG_HARDWARE_TIER 0x00000004u
#define RDP_COMPOSITED_MSG_COMPOSITION_DEVICE_STATE_CHANGE 0x00000005u
#define RDP_COMPOSITED_MSG_PARTITION_ZOMBIE 0x00000006u
#define RDP_COMPOSITED_MSG_COMPOSITION_TIME_EXCEEDED 0x00000007u
#define RDP_COMPOSITED_MSG_ROUNDTRIP_REPLY 0x00000009u
#define RDP_COMPOSITED_MSG_CONNECTION_LOST 0x0000000au
#define RDP_COMPOSITED_MSG_ASYNC_FLUSH_REPLY 0x0000000bu
#define RDP_COMPOSITED_MSG_RENDER_STATUS 0x0000000du
#define RDP_COMPOSITED_MSG_DISABLE_COMPOSITION 0x0000000eu
#define RDP_COMPOSITED_MSG_META_CAPTURE_BITS_REPLY 0x00000010u
#define RDP_COMPOSITED_RESOURCE_WINDOW_NODE 0x00000013u
#define RDP_COMPOSITED_RESOURCE_GLYPH_RUN 0x00000014u
#define RDP_COMPOSITED_RESOURCE_HWND_TARGET 0x00000018u
#define RDP_COMPOSITED_RESOURCE_DESKTOP_TARGET 0x00000019u
#define RDP_COMPOSITED_RESOURCE_META_BITMAP_TARGET 0x00000023u
#define RDP_COMPOSITED_RESOURCE_GDI_SPRITE_BITMAP 0x00000038u
#define RDP_COMPOSITED_RENDER_RESOURCE_LIMIT 512u

typedef struct rdp_composited_control
{
    uint32_t control_code;
    uint32_t message_size;
    uint32_t word0;
    uint32_t word1;
    const uint8_t* payload;
    size_t payload_len;
} rdp_composited_control;

typedef struct rdp_composited_channel_message
{
    uint32_t message_size;
    uint32_t control_code;
    const uint8_t* data;
    const uint8_t* payload;
    size_t payload_len;
} rdp_composited_channel_message;

typedef struct rdp_composited_batch_reader
{
    const uint8_t* data;
    size_t remaining;
} rdp_composited_batch_reader;

typedef struct rdp_composited_version_reply
{
    uint32_t notification_code;
    uint32_t version_count;
    const uint8_t* versions;
} rdp_composited_version_reply;

typedef struct rdp_composited_resource_order
{
    rdp_composited_channel_message header;
    uint32_t resource;
    uint32_t resource_type;
} rdp_composited_resource_order;

typedef struct rdp_composited_duplicate_handle
{
    rdp_composited_channel_message header;
    uint32_t original;
    uint32_t target_channel;
    uint32_t duplicate;
} rdp_composited_duplicate_handle;

typedef struct rdp_composited_u32_target_order
{
    rdp_composited_channel_message header;
    uint32_t target_resource;
    uint32_t value;
} rdp_composited_u32_target_order;

typedef struct rdp_composited_window_node_create
{
    rdp_composited_channel_message header;
    uint32_t target_resource;
    uint64_t sprite_id;
    uint64_t window_id;
    uint32_t caching_mode;
} rdp_composited_window_node_create;

typedef struct rdp_composited_target_create
{
    rdp_composited_channel_message header;
    uint32_t target_resource;
    uint32_t width;
    uint32_t height;
    uint8_t clear_color[16];
} rdp_composited_target_create;

typedef struct rdp_composited_glyph_run
{
    rdp_composited_channel_message header;
    uint32_t target_resource;
    uint32_t glyph_cache;
    uint32_t glyph_count;
    int32_t precontrast_level;
    const uint8_t* glyph_indices;
    size_t glyph_indices_len;
} rdp_composited_glyph_run;

typedef struct rdp_composited_gdi_sprite_bitmap
{
    rdp_composited_channel_message header;
    uint32_t target_resource;
    uint64_t sprite_id;
    uint64_t logical_surface_id;
} rdp_composited_gdi_sprite_bitmap;

typedef struct rdp_composited_gdi_surface_update
{
    rdp_composited_channel_message header;
    uint32_t target_resource;
    uint32_t dxgi_format;
} rdp_composited_gdi_surface_update;

typedef struct rdp_composited_texture_set
{
    uint32_t surface_count;
    uint32_t dxgi_format;
    uint32_t width;
    uint32_t height;
    const uint8_t* surfaces;
    size_t surfaces_len;
} rdp_composited_texture_set;

typedef struct rdp_composited_meta_target
{
    rdp_composited_channel_message header;
    uint32_t target_resource;
    rdp_composited_texture_set textures;
} rdp_composited_meta_target;

typedef struct rdp_composited_render_resource
{
    uint8_t active;
    uint32_t resource;
    uint32_t resource_type;
    uint32_t duplicate_source;
    uint32_t duplicate_target_channel;
    uint32_t target_resource;
    uint32_t root_resource;
    uint32_t width;
    uint32_t height;
    uint32_t dxgi_format;
    uint32_t surface_count;
    uint32_t texture_width;
    uint32_t texture_height;
    uint64_t sprite_id;
    uint64_t window_id;
    uint64_t logical_surface_id;
    uint8_t clear_color[16];
} rdp_composited_render_resource;

typedef struct rdp_composited_render_tree
{
    rdp_composited_render_resource resources[RDP_COMPOSITED_RENDER_RESOURCE_LIMIT];
    uint32_t resource_count;
    uint32_t command_count;
    uint32_t flush_count;
    uint32_t roundtrip_count;
    uint32_t tier_request_count;
    uint32_t notification_registration_count;
    uint32_t invalidation_count;
    uint32_t skipped_known_count;
} rdp_composited_render_tree;

int rdp_composited_control_code_valid(uint32_t control_code);
int rdp_composited_channel_command_known(uint32_t control_code);
int rdp_composited_notification_code_valid(uint32_t notification_code);
void rdp_composited_render_tree_init(rdp_composited_render_tree* tree);
void rdp_composited_render_tree_reset(rdp_composited_render_tree* tree);
const rdp_composited_render_resource* rdp_composited_render_tree_find(
    const rdp_composited_render_tree* tree,
    uint32_t resource);
librdp_status rdp_composited_render_tree_apply_message(
    rdp_composited_render_tree* tree,
    const rdp_composited_channel_message* message);
librdp_status rdp_composited_render_tree_apply_batch(rdp_composited_render_tree* tree,
                                                     const void* data,
                                                     size_t length);
librdp_status rdp_composited_parse_control(const void* data,
                                           size_t length,
                                           rdp_composited_control* message);
librdp_status rdp_composited_write_control_fixed(rdp_buffer* buffer,
                                                 uint32_t control_code,
                                                 uint32_t word0,
                                                 uint32_t word1);
librdp_status rdp_composited_write_data_on_channel(rdp_buffer* buffer,
                                                   uint32_t channel,
                                                   const void* payload,
                                                   size_t payload_len);
librdp_status rdp_composited_write_notification(rdp_buffer* buffer,
                                                uint32_t control_code,
                                                uint32_t channel,
                                                const void* payload,
                                                size_t payload_len);
librdp_status rdp_composited_write_version_reply(rdp_buffer* buffer,
                                                 const uint32_t* versions,
                                                 uint32_t version_count);
librdp_status rdp_composited_parse_version_reply(const void* data,
                                                 size_t length,
                                                 rdp_composited_version_reply* reply);
int rdp_composited_version_reply_has(const rdp_composited_version_reply* reply,
                                     uint32_t version);
librdp_status rdp_composited_parse_channel_message(const void* data,
                                                   size_t length,
                                                   rdp_composited_channel_message* message);
librdp_status rdp_composited_write_channel_message(rdp_buffer* buffer,
                                                   uint32_t control_code,
                                                   const void* payload,
                                                   size_t payload_len);
librdp_status rdp_composited_batch_init(rdp_composited_batch_reader* reader,
                                        const void* data,
                                        size_t length);
librdp_status rdp_composited_batch_next(rdp_composited_batch_reader* reader,
                                        rdp_composited_channel_message* message);
librdp_status rdp_composited_parse_resource_order(const void* data,
                                                  size_t length,
                                                  uint32_t expected_code,
                                                  rdp_composited_resource_order* order);
librdp_status rdp_composited_write_resource_order(rdp_buffer* buffer,
                                                  uint32_t control_code,
                                                  uint32_t resource,
                                                  uint32_t resource_type);
librdp_status rdp_composited_parse_duplicate_handle(const void* data,
                                                    size_t length,
                                                    rdp_composited_duplicate_handle* order);
librdp_status rdp_composited_write_duplicate_handle(rdp_buffer* buffer,
                                                    uint32_t original,
                                                    uint32_t target_channel,
                                                    uint32_t duplicate);
librdp_status rdp_composited_parse_u32_target_order(const void* data,
                                                    size_t length,
                                                    uint32_t expected_code,
                                                    rdp_composited_u32_target_order* order);
librdp_status rdp_composited_write_u32_target_order(rdp_buffer* buffer,
                                                    uint32_t control_code,
                                                    uint32_t target_resource,
                                                    uint32_t value);
librdp_status rdp_composited_parse_window_node_create(const void* data,
                                                      size_t length,
                                                      rdp_composited_window_node_create* order);
librdp_status rdp_composited_write_window_node_create(rdp_buffer* buffer,
                                                      uint32_t target_resource,
                                                      uint64_t sprite_id,
                                                      uint64_t window_id,
                                                      uint32_t caching_mode);
librdp_status rdp_composited_parse_target_create(const void* data,
                                                 size_t length,
                                                 rdp_composited_target_create* order);
librdp_status rdp_composited_write_target_create(rdp_buffer* buffer,
                                                 uint32_t target_resource,
                                                 uint32_t width,
                                                 uint32_t height,
                                                 const uint8_t clear_color[16]);
librdp_status rdp_composited_parse_glyph_run(const void* data,
                                             size_t length,
                                             rdp_composited_glyph_run* order);
librdp_status rdp_composited_write_glyph_run(rdp_buffer* buffer,
                                             uint32_t target_resource,
                                             uint32_t glyph_cache,
                                             int32_t precontrast_level,
                                             const uint32_t* glyph_indices,
                                             uint32_t glyph_count);
librdp_status rdp_composited_parse_gdi_sprite_bitmap(const void* data,
                                                     size_t length,
                                                     rdp_composited_gdi_sprite_bitmap* order);
librdp_status rdp_composited_write_gdi_sprite_bitmap(rdp_buffer* buffer,
                                                     uint32_t target_resource,
                                                     uint64_t sprite_id,
                                                     uint64_t logical_surface_id);
librdp_status rdp_composited_parse_gdi_surface_update(const void* data,
                                                      size_t length,
                                                      rdp_composited_gdi_surface_update* order);
librdp_status rdp_composited_write_gdi_surface_update(rdp_buffer* buffer,
                                                      uint32_t target_resource,
                                                      uint32_t dxgi_format);
librdp_status rdp_composited_parse_texture_set(const void* data,
                                               size_t length,
                                               rdp_composited_texture_set* textures);
librdp_status rdp_composited_parse_meta_target(const void* data,
                                               size_t length,
                                               uint32_t expected_code,
                                               rdp_composited_meta_target* order);
librdp_status rdp_composited_write_meta_target(rdp_buffer* buffer,
                                               uint32_t control_code,
                                               uint32_t target_resource,
                                               uint32_t surface_count,
                                               uint32_t dxgi_format,
                                               uint32_t width,
                                               uint32_t height,
                                               const uint8_t surfaces[RDP_COMPOSITED_TEXTURE_SLOT_COUNT *
                                                                      RDP_COMPOSITED_TEXTURE_SLOT_BYTES]);

#endif
