#include "channels/composited_remoting.h"

#include "common/stream.h"

#include <string.h>

static int rdp_composited_aligned_size(size_t length)
{
    return (length % 4u) == 0;
}

static uint32_t rdp_composited_read_u32_at(const uint8_t* data, size_t offset)
{
    return (uint32_t)data[offset] | ((uint32_t)data[offset + 1u] << 8) |
           ((uint32_t)data[offset + 2u] << 16) | ((uint32_t)data[offset + 3u] << 24);
}

static librdp_status rdp_composited_read_u64(rdp_stream* stream, uint64_t* value)
{
    uint32_t low = 0;
    uint32_t high = 0;

    if (rdp_stream_read_u32_le(stream, &low) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &high) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = (uint64_t)low | ((uint64_t)high << 32);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_composited_write_u64(rdp_buffer* buffer, uint64_t value)
{
    librdp_status status = rdp_buffer_append_u32_le(buffer, (uint32_t)(value & 0xffffffffu));

    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, (uint32_t)((value >> 32) & 0xffffffffu));
}

static librdp_status rdp_composited_write_zeroes(rdp_buffer* buffer, size_t count)
{
    static const uint8_t zeroes[64] = {0};

    while (count > 0)
    {
        size_t chunk = count > sizeof(zeroes) ? sizeof(zeroes) : count;
        librdp_status status = rdp_buffer_append(buffer, zeroes, chunk);

        if (status != LIBRDP_STATUS_OK)
            return status;
        count -= chunk;
    }
    return LIBRDP_STATUS_OK;
}

int rdp_composited_control_code_valid(uint32_t control_code)
{
    switch (control_code)
    {
        case RDP_COMPOSITED_CONTROL_VERSION_REQUEST:
        case RDP_COMPOSITED_CONTROL_VERSION_ANNOUNCEMENT:
        case RDP_COMPOSITED_CONTROL_OPEN_CONNECTION:
        case RDP_COMPOSITED_CONTROL_CLOSE_CONNECTION:
        case RDP_COMPOSITED_CONTROL_OPEN_CHANNEL:
        case RDP_COMPOSITED_CONTROL_CLOSE_CHANNEL:
        case RDP_COMPOSITED_CONTROL_DATA_ON_CHANNEL:
        case RDP_COMPOSITED_CONTROL_CONNECTION_NOTIFICATION:
        case RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION:
        case RDP_COMPOSITED_CONTROL_CONNECTION_BROADCAST:
        case RDP_COMPOSITED_CONTROL_SURFACE_MANAGER_EVENT:
            return 1;
        default:
            return 0;
    }
}

int rdp_composited_channel_command_known(uint32_t control_code)
{
    if ((control_code >= 0x12u && control_code <= 0x20u) ||
        (control_code >= 0x82u && control_code <= 0x8du))
        return 1;
    switch (control_code)
    {
        case RDP_COMPOSITED_CMD_SYNC_FLUSH:
        case RDP_COMPOSITED_CMD_ROUNDTRIP_REQUEST:
        case RDP_COMPOSITED_CMD_ASYNC_FLUSH:
        case RDP_COMPOSITED_CMD_REGISTER_NOTIFICATIONS:
        case RDP_COMPOSITED_CMD_REQUEST_TIER:
        case RDP_COMPOSITED_CMD_CREATE_RESOURCE:
        case RDP_COMPOSITED_CMD_DELETE_RESOURCE:
        case RDP_COMPOSITED_CMD_DUPLICATE_HANDLE:
        case RDP_COMPOSITED_CMD_BITMAP_PIXELS:
        case RDP_COMPOSITED_CMD_BITMAP_COMPRESSED_PIXELS:
        case RDP_COMPOSITED_CMD_RENDERDATA:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_CREATE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_DETACH:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_BOUNDS:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_UPDATE_SPRITE_HANDLE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SPRITE_IMAGE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_LOGICAL_SURFACE_IMAGE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SPRITE_CLIP:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_DX_CLIP:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SOURCE_MODIFICATIONS:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_ALPHA_MARGINS:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_COMPOSE_ONCE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_COPY_OWNED_RESOURCES:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_MAXIMIZED_CLIP_MARGINS:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_NOTIFY_VISIBLE_REGION:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_PROTECT_CONTENT:
        case RDP_COMPOSITED_CMD_VISUAL_GROUP:
        case RDP_COMPOSITED_CMD_HWND_TARGET_CREATE:
        case RDP_COMPOSITED_CMD_TARGET_UPDATE_WINDOW_SETTINGS:
        case RDP_COMPOSITED_CMD_TARGET_SET_ROOT:
        case RDP_COMPOSITED_CMD_TARGET_SET_CLEAR_COLOR:
        case RDP_COMPOSITED_CMD_TARGET_INVALIDATE:
        case RDP_COMPOSITED_CMD_TARGET_CAPTURE_BITS:
        case RDP_COMPOSITED_CMD_META_TARGET_CAPTURE_BITS:
        case RDP_COMPOSITED_CMD_META_TARGET_CREATE:
        case RDP_COMPOSITED_CMD_META_TARGET_SET_TRANSFORM:
        case RDP_COMPOSITED_CMD_META_TARGET_SET_COLOR_TRANSFORM:
        case RDP_COMPOSITED_CMD_META_TARGET_UPDATE:
        case RDP_COMPOSITED_CMD_META_TARGET_SET_FILTER_LIST:
        case RDP_COMPOSITED_CMD_GLYPH_CACHE_ADD_BITMAPS:
        case RDP_COMPOSITED_CMD_GLYPH_CACHE_REMOVE_BITMAPS:
        case RDP_COMPOSITED_CMD_GLYPH_RUN_CREATE:
        case RDP_COMPOSITED_CMD_GLYPH_RUN_ADD_REALIZATION:
        case RDP_COMPOSITED_CMD_GLYPH_RUN_REMOVE_REALIZATION:
        case RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP:
        case RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UPDATE_MARGINS:
        case RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UPDATE_SURFACE:
        case RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UNMAP_SECTION:
        case RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_NOTIFY_DIRTY:
            return 1;
        default:
            return 0;
    }
}

int rdp_composited_notification_code_valid(uint32_t notification_code)
{
    switch (notification_code)
    {
        case RDP_COMPOSITED_MSG_SYNC_FLUSH_REPLY:
        case RDP_COMPOSITED_MSG_CAPTURE_BITS_REPLY:
        case RDP_COMPOSITED_MSG_VERSION_REPLY:
        case RDP_COMPOSITED_MSG_HARDWARE_TIER:
        case RDP_COMPOSITED_MSG_COMPOSITION_DEVICE_STATE_CHANGE:
        case RDP_COMPOSITED_MSG_PARTITION_ZOMBIE:
        case RDP_COMPOSITED_MSG_COMPOSITION_TIME_EXCEEDED:
        case RDP_COMPOSITED_MSG_ROUNDTRIP_REPLY:
        case RDP_COMPOSITED_MSG_CONNECTION_LOST:
        case RDP_COMPOSITED_MSG_ASYNC_FLUSH_REPLY:
        case RDP_COMPOSITED_MSG_RENDER_STATUS:
        case RDP_COMPOSITED_MSG_DISABLE_COMPOSITION:
        case RDP_COMPOSITED_MSG_META_CAPTURE_BITS_REPLY:
            return 1;
        default:
            return 0;
    }
}

static rdp_composited_render_resource* rdp_composited_render_tree_find_mutable(
    rdp_composited_render_tree* tree,
    uint32_t resource)
{
    uint32_t i = 0;

    if (!tree)
        return NULL;
    for (i = 0; i < RDP_COMPOSITED_RENDER_RESOURCE_LIMIT; i++)
    {
        if (tree->resources[i].active && tree->resources[i].resource == resource)
            return &tree->resources[i];
    }
    return NULL;
}

static rdp_composited_render_resource* rdp_composited_render_tree_upsert(
    rdp_composited_render_tree* tree,
    uint32_t resource,
    uint32_t resource_type)
{
    uint32_t i = 0;
    rdp_composited_render_resource* entry =
        rdp_composited_render_tree_find_mutable(tree, resource);

    if (entry)
    {
        if (resource_type != 0)
            entry->resource_type = resource_type;
        return entry;
    }
    for (i = 0; i < RDP_COMPOSITED_RENDER_RESOURCE_LIMIT; i++)
    {
        if (!tree->resources[i].active)
        {
            memset(&tree->resources[i], 0, sizeof(tree->resources[i]));
            tree->resources[i].active = 1;
            tree->resources[i].resource = resource;
            tree->resources[i].resource_type = resource_type;
            tree->resource_count++;
            return &tree->resources[i];
        }
    }
    return NULL;
}

static void rdp_composited_render_tree_delete(rdp_composited_render_tree* tree, uint32_t resource)
{
    rdp_composited_render_resource* entry = rdp_composited_render_tree_find_mutable(tree, resource);

    if (!entry)
        return;
    memset(entry, 0, sizeof(*entry));
    if (tree->resource_count > 0)
        tree->resource_count--;
}

void rdp_composited_render_tree_init(rdp_composited_render_tree* tree)
{
    if (!tree)
        return;
    memset(tree, 0, sizeof(*tree));
}

void rdp_composited_render_tree_reset(rdp_composited_render_tree* tree)
{
    rdp_composited_render_tree_init(tree);
}

const rdp_composited_render_resource* rdp_composited_render_tree_find(
    const rdp_composited_render_tree* tree,
    uint32_t resource)
{
    uint32_t i = 0;

    if (!tree)
        return NULL;
    for (i = 0; i < RDP_COMPOSITED_RENDER_RESOURCE_LIMIT; i++)
    {
        if (tree->resources[i].active && tree->resources[i].resource == resource)
            return &tree->resources[i];
    }
    return NULL;
}

static librdp_status rdp_composited_render_apply_u32(rdp_composited_render_tree* tree,
                                                     const rdp_composited_channel_message* message)
{
    rdp_composited_u32_target_order order;
    rdp_composited_render_resource* target = NULL;
    librdp_status status = rdp_composited_parse_u32_target_order(message->data,
                                                                 message->message_size,
                                                                 message->control_code,
                                                                 &order);

    if (status != LIBRDP_STATUS_OK)
        return status;
    target = rdp_composited_render_tree_upsert(tree, order.target_resource, 0);
    if (!target)
        return LIBRDP_STATUS_NO_MEMORY;
    target->target_resource = order.target_resource;
    switch (message->control_code)
    {
        case RDP_COMPOSITED_CMD_TARGET_SET_ROOT:
            target->root_resource = order.value;
            break;
        case RDP_COMPOSITED_CMD_TARGET_SET_CLEAR_COLOR:
            target->clear_color[0] = (uint8_t)(order.value & 0xffu);
            target->clear_color[1] = (uint8_t)((order.value >> 8) & 0xffu);
            target->clear_color[2] = (uint8_t)((order.value >> 16) & 0xffu);
            target->clear_color[3] = (uint8_t)((order.value >> 24) & 0xffu);
            break;
        case RDP_COMPOSITED_CMD_TARGET_INVALIDATE:
            tree->invalidation_count++;
            break;
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_LOGICAL_SURFACE_IMAGE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_UPDATE_SPRITE_HANDLE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SPRITE_IMAGE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SPRITE_CLIP:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_DX_CLIP:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_ALPHA_MARGINS:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_COMPOSE_ONCE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_MAXIMIZED_CLIP_MARGINS:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_NOTIFY_VISIBLE_REGION:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_PROTECT_CONTENT:
            target->target_resource = order.value;
            break;
        default:
            break;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_render_tree_apply_message(
    rdp_composited_render_tree* tree,
    const rdp_composited_channel_message* message)
{
    rdp_composited_render_resource* entry = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!tree || !message)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_composited_channel_command_known(message->control_code))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    tree->command_count++;
    switch (message->control_code)
    {
        case RDP_COMPOSITED_CMD_CREATE_RESOURCE:
        {
            rdp_composited_resource_order order;
            status = rdp_composited_parse_resource_order(message->data,
                                                         message->message_size,
                                                         RDP_COMPOSITED_CMD_CREATE_RESOURCE,
                                                         &order);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree, order.resource, order.resource_type);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            break;
        }
        case RDP_COMPOSITED_CMD_DELETE_RESOURCE:
        {
            rdp_composited_resource_order order;
            status = rdp_composited_parse_resource_order(message->data,
                                                         message->message_size,
                                                         RDP_COMPOSITED_CMD_DELETE_RESOURCE,
                                                         &order);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_composited_render_tree_delete(tree, order.resource);
            break;
        }
        case RDP_COMPOSITED_CMD_DUPLICATE_HANDLE:
        {
            rdp_composited_duplicate_handle duplicate;
            const rdp_composited_render_resource* source = NULL;

            status = rdp_composited_parse_duplicate_handle(message->data, message->message_size, &duplicate);
            if (status != LIBRDP_STATUS_OK)
                return status;
            source = rdp_composited_render_tree_find(tree, duplicate.original);
            entry = rdp_composited_render_tree_upsert(tree,
                                                      duplicate.duplicate,
                                                      source ? source->resource_type : 0);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->duplicate_source = duplicate.original;
            entry->duplicate_target_channel = duplicate.target_channel;
            break;
        }
        case RDP_COMPOSITED_CMD_WINDOW_NODE_CREATE:
        {
            rdp_composited_window_node_create window_node;

            status = rdp_composited_parse_window_node_create(message->data,
                                                             message->message_size,
                                                             &window_node);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      window_node.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_WINDOW_NODE);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->sprite_id = window_node.sprite_id;
            entry->window_id = window_node.window_id;
            break;
        }
        case RDP_COMPOSITED_CMD_HWND_TARGET_CREATE:
        {
            rdp_composited_target_create target;

            status = rdp_composited_parse_target_create(message->data, message->message_size, &target);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      target.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_HWND_TARGET);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->width = target.width;
            entry->height = target.height;
            memcpy(entry->clear_color, target.clear_color, sizeof(entry->clear_color));
            break;
        }
        case RDP_COMPOSITED_CMD_GLYPH_RUN_CREATE:
        {
            rdp_composited_glyph_run glyph_run;

            status = rdp_composited_parse_glyph_run(message->data, message->message_size, &glyph_run);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      glyph_run.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_GLYPH_RUN);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->target_resource = glyph_run.target_resource;
            break;
        }
        case RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP:
        {
            rdp_composited_gdi_sprite_bitmap sprite;

            status = rdp_composited_parse_gdi_sprite_bitmap(message->data, message->message_size, &sprite);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      sprite.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_GDI_SPRITE_BITMAP);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->sprite_id = sprite.sprite_id;
            entry->logical_surface_id = sprite.logical_surface_id;
            break;
        }
        case RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UPDATE_SURFACE:
        {
            rdp_composited_gdi_surface_update surface_update;

            status = rdp_composited_parse_gdi_surface_update(message->data,
                                                             message->message_size,
                                                             &surface_update);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      surface_update.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_GDI_SPRITE_BITMAP);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->dxgi_format = surface_update.dxgi_format;
            break;
        }
        case RDP_COMPOSITED_CMD_META_TARGET_CREATE:
        case RDP_COMPOSITED_CMD_META_TARGET_UPDATE:
        {
            rdp_composited_meta_target meta;

            status = rdp_composited_parse_meta_target(message->data,
                                                      message->message_size,
                                                      message->control_code,
                                                      &meta);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      meta.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_META_BITMAP_TARGET);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->surface_count = meta.textures.surface_count;
            entry->dxgi_format = meta.textures.dxgi_format;
            entry->texture_width = meta.textures.width;
            entry->texture_height = meta.textures.height;
            break;
        }
        case RDP_COMPOSITED_CMD_TARGET_SET_ROOT:
        case RDP_COMPOSITED_CMD_TARGET_SET_CLEAR_COLOR:
        case RDP_COMPOSITED_CMD_TARGET_INVALIDATE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_LOGICAL_SURFACE_IMAGE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_UPDATE_SPRITE_HANDLE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SPRITE_IMAGE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SPRITE_CLIP:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_DX_CLIP:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_ALPHA_MARGINS:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_COMPOSE_ONCE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_MAXIMIZED_CLIP_MARGINS:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_NOTIFY_VISIBLE_REGION:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_PROTECT_CONTENT:
            return rdp_composited_render_apply_u32(tree, message);
        case RDP_COMPOSITED_CMD_SYNC_FLUSH:
        case RDP_COMPOSITED_CMD_ASYNC_FLUSH:
            tree->flush_count++;
            break;
        case RDP_COMPOSITED_CMD_ROUNDTRIP_REQUEST:
            tree->roundtrip_count++;
            break;
        case RDP_COMPOSITED_CMD_REQUEST_TIER:
            tree->tier_request_count++;
            break;
        case RDP_COMPOSITED_CMD_REGISTER_NOTIFICATIONS:
            tree->notification_registration_count++;
            break;
        default:
            tree->skipped_known_count++;
            break;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_render_tree_apply_batch(rdp_composited_render_tree* tree,
                                                     const void* data,
                                                     size_t length)
{
    rdp_composited_batch_reader reader;
    rdp_composited_channel_message message;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!tree || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_composited_batch_init(&reader, data, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    while ((status = rdp_composited_batch_next(&reader, &message)) == LIBRDP_STATUS_OK)
    {
        status = rdp_composited_render_tree_apply_message(tree, &message);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return status == LIBRDP_STATUS_AGAIN ? LIBRDP_STATUS_OK : status;
}

librdp_status rdp_composited_parse_control(const void* data,
                                           size_t length,
                                           rdp_composited_control* message)
{
    rdp_stream stream;

    if (!data || !message)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 16u || length > UINT32_MAX || !rdp_composited_aligned_size(length))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(message, 0, sizeof(*message));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &message->control_code) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &message->message_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &message->word0) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &message->word1) != LIBRDP_STATUS_OK ||
        !rdp_composited_control_code_valid(message->control_code) ||
        message->message_size != length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    switch (message->control_code)
    {
        case RDP_COMPOSITED_CONTROL_DATA_ON_CHANNEL:
        case RDP_COMPOSITED_CONTROL_CONNECTION_NOTIFICATION:
        case RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION:
        case RDP_COMPOSITED_CONTROL_CONNECTION_BROADCAST:
            break;
        default:
            if (message->message_size != 16u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
    }
    message->payload_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &message->payload, message->payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_control_fixed(rdp_buffer* buffer,
                                                 uint32_t control_code,
                                                 uint32_t word0,
                                                 uint32_t word1)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_composited_control_code_valid(control_code) ||
        control_code == RDP_COMPOSITED_CONTROL_DATA_ON_CHANNEL ||
        control_code == RDP_COMPOSITED_CONTROL_CONNECTION_NOTIFICATION ||
        control_code == RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION ||
        control_code == RDP_COMPOSITED_CONTROL_CONNECTION_BROADCAST)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, control_code);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 16u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, word0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, word1);
    return status;
}

librdp_status rdp_composited_write_data_on_channel(rdp_buffer* buffer,
                                                   uint32_t channel,
                                                   const void* payload,
                                                   size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!payload && payload_len > 0) || payload_len > UINT32_MAX - 16u ||
        !rdp_composited_aligned_size(payload_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, RDP_COMPOSITED_CONTROL_DATA_ON_CHANNEL);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, (uint32_t)(16u + payload_len));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, channel);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, payload, payload_len);
    return status;
}

librdp_status rdp_composited_write_notification(rdp_buffer* buffer,
                                                uint32_t control_code,
                                                uint32_t channel,
                                                const void* payload,
                                                size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!payload && payload_len > 0) || payload_len > UINT32_MAX - 16u ||
        !rdp_composited_aligned_size(payload_len) ||
        (control_code != RDP_COMPOSITED_CONTROL_CONNECTION_NOTIFICATION &&
         control_code != RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION &&
         control_code != RDP_COMPOSITED_CONTROL_CONNECTION_BROADCAST))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, control_code);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, (uint32_t)(16u + payload_len));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer,
                                          control_code == RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION ?
                                              channel :
                                              0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, payload, payload_len);
    return status;
}

librdp_status rdp_composited_write_version_reply(rdp_buffer* buffer,
                                                 const uint32_t* versions,
                                                 uint32_t version_count)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t i = 0;

    if (!buffer || !versions || version_count == 0 || version_count > RDP_COMPOSITED_MAX_VERSION_COUNT)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, RDP_COMPOSITED_MSG_VERSION_REPLY);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, version_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_zeroes(&payload, 48u);
    for (i = 0; status == LIBRDP_STATUS_OK && i < version_count; i++)
        status = rdp_buffer_append_u32_le(&payload, versions[i]);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_notification(buffer,
                                                   RDP_COMPOSITED_CONTROL_CONNECTION_NOTIFICATION,
                                                   0,
                                                   payload.data,
                                                   payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_version_reply(const void* data,
                                                 size_t length,
                                                 rdp_composited_version_reply* reply)
{
    rdp_stream stream;
    uint32_t unused = 0;

    if (!data || !reply)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 60u || !rdp_composited_aligned_size(length))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(reply, 0, sizeof(*reply));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &reply->notification_code) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &unused) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &reply->version_count) != LIBRDP_STATUS_OK ||
        reply->notification_code != RDP_COMPOSITED_MSG_VERSION_REPLY ||
        reply->version_count == 0 ||
        reply->version_count > RDP_COMPOSITED_MAX_VERSION_COUNT ||
        length != 60u + ((size_t)reply->version_count * 4u) ||
        rdp_stream_skip(&stream, 48u) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &reply->versions, (size_t)reply->version_count * 4u) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

int rdp_composited_version_reply_has(const rdp_composited_version_reply* reply,
                                     uint32_t version)
{
    uint32_t i = 0;

    if (!reply || !reply->versions)
        return 0;
    for (i = 0; i < reply->version_count; i++)
    {
        if (rdp_composited_read_u32_at(reply->versions, (size_t)i * 4u) == version)
            return 1;
    }
    return 0;
}

librdp_status rdp_composited_parse_channel_message(const void* data,
                                                   size_t length,
                                                   rdp_composited_channel_message* message)
{
    rdp_stream stream;

    if (!data || !message)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u || length > UINT32_MAX || !rdp_composited_aligned_size(length))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(message, 0, sizeof(*message));
    message->data = (const uint8_t*)data;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &message->message_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &message->control_code) != LIBRDP_STATUS_OK ||
        message->message_size < 8u ||
        message->message_size > length ||
        !rdp_composited_aligned_size(message->message_size) ||
        message->control_code == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    message->payload_len = message->message_size - 8u;
    if (rdp_stream_read_bytes(&stream, &message->payload, message->payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_channel_message(rdp_buffer* buffer,
                                                   uint32_t control_code,
                                                   const void* payload,
                                                   size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || control_code == 0 || (!payload && payload_len > 0) ||
        payload_len > UINT32_MAX - 8u || !rdp_composited_aligned_size(payload_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, (uint32_t)(8u + payload_len));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, control_code);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, payload, payload_len);
    return status;
}

librdp_status rdp_composited_batch_init(rdp_composited_batch_reader* reader,
                                        const void* data,
                                        size_t length)
{
    if (!reader || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_composited_aligned_size(length))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    reader->data = (const uint8_t*)data;
    reader->remaining = length;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_batch_next(rdp_composited_batch_reader* reader,
                                        rdp_composited_channel_message* message)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!reader || !message)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (reader->remaining == 0)
        return LIBRDP_STATUS_AGAIN;
    status = rdp_composited_parse_channel_message(reader->data, reader->remaining, message);
    if (status != LIBRDP_STATUS_OK)
        return status;
    reader->data += message->message_size;
    reader->remaining -= message->message_size;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_parse_resource_order(const void* data,
                                                  size_t length,
                                                  uint32_t expected_code,
                                                  rdp_composited_resource_order* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != expected_code ||
        (expected_code != RDP_COMPOSITED_CMD_CREATE_RESOURCE &&
         expected_code != RDP_COMPOSITED_CMD_DELETE_RESOURCE))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->resource) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->resource_type) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_resource_order(rdp_buffer* buffer,
                                                  uint32_t control_code,
                                                  uint32_t resource,
                                                  uint32_t resource_type)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (control_code != RDP_COMPOSITED_CMD_CREATE_RESOURCE &&
                    control_code != RDP_COMPOSITED_CMD_DELETE_RESOURCE))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, resource_type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer, control_code, payload.data, payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_duplicate_handle(const void* data,
                                                    size_t length,
                                                    rdp_composited_duplicate_handle* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != RDP_COMPOSITED_CMD_DUPLICATE_HANDLE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->original) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->target_channel) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->duplicate) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_duplicate_handle(rdp_buffer* buffer,
                                                    uint32_t original,
                                                    uint32_t target_channel,
                                                    uint32_t duplicate)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, original);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, target_channel);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, duplicate);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer,
                                                      RDP_COMPOSITED_CMD_DUPLICATE_HANDLE,
                                                      payload.data,
                                                      payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_u32_target_order(const void* data,
                                                    size_t length,
                                                    uint32_t expected_code,
                                                    rdp_composited_u32_target_order* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != expected_code)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_u32_target_order(rdp_buffer* buffer,
                                                    uint32_t control_code,
                                                    uint32_t target_resource,
                                                    uint32_t value)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || control_code == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, value);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer, control_code, payload.data, payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_window_node_create(const void* data,
                                                      size_t length,
                                                      rdp_composited_window_node_create* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 32u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != RDP_COMPOSITED_CMD_WINDOW_NODE_CREATE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_composited_read_u64(&stream, &order->sprite_id) != LIBRDP_STATUS_OK ||
        rdp_composited_read_u64(&stream, &order->window_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->caching_mode) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_window_node_create(rdp_buffer* buffer,
                                                      uint32_t target_resource,
                                                      uint64_t sprite_id,
                                                      uint64_t window_id,
                                                      uint32_t caching_mode)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_u64(&payload, sprite_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_u64(&payload, window_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, caching_mode);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer,
                                                      RDP_COMPOSITED_CMD_WINDOW_NODE_CREATE,
                                                      payload.data,
                                                      payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_target_create(const void* data,
                                                 size_t length,
                                                 rdp_composited_target_create* order)
{
    rdp_stream stream;
    const uint8_t* reserved = NULL;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 52u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != RDP_COMPOSITED_CMD_HWND_TARGET_CREATE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &reserved, 8u) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->height) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &reserved, sizeof(order->clear_color)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(order->clear_color, reserved, sizeof(order->clear_color));
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_target_create(rdp_buffer* buffer,
                                                 uint32_t target_resource,
                                                 uint32_t width,
                                                 uint32_t height,
                                                 const uint8_t clear_color[16])
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !clear_color)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_zeroes(&payload, 8u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, width);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&payload, clear_color, 16u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_zeroes(&payload, 8u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer,
                                                      RDP_COMPOSITED_CMD_HWND_TARGET_CREATE,
                                                      payload.data,
                                                      payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_glyph_run(const void* data,
                                             size_t length,
                                             rdp_composited_glyph_run* order)
{
    rdp_stream stream;
    uint32_t precontrast = 0;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 24u || !rdp_composited_aligned_size(length))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != RDP_COMPOSITED_CMD_GLYPH_RUN_CREATE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->glyph_cache) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->glyph_count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &precontrast) != LIBRDP_STATUS_OK ||
        order->glyph_count > (UINT32_MAX / 4u) ||
        order->header.payload_len != 16u + ((size_t)order->glyph_count * 4u) ||
        precontrast == 0 ||
        precontrast > 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    order->precontrast_level = (int32_t)precontrast;
    order->glyph_indices_len = (size_t)order->glyph_count * 4u;
    if (rdp_stream_read_bytes(&stream, &order->glyph_indices, order->glyph_indices_len) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_glyph_run(rdp_buffer* buffer,
                                             uint32_t target_resource,
                                             uint32_t glyph_cache,
                                             int32_t precontrast_level,
                                             const uint32_t* glyph_indices,
                                             uint32_t glyph_count)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t i = 0;

    if (!buffer || (!glyph_indices && glyph_count > 0) || precontrast_level <= 0 ||
        precontrast_level > 6)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, glyph_cache);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, glyph_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, (uint32_t)precontrast_level);
    for (i = 0; status == LIBRDP_STATUS_OK && i < glyph_count; i++)
        status = rdp_buffer_append_u32_le(&payload, glyph_indices[i]);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer,
                                                      RDP_COMPOSITED_CMD_GLYPH_RUN_CREATE,
                                                      payload.data,
                                                      payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_gdi_sprite_bitmap(const void* data,
                                                     size_t length,
                                                     rdp_composited_gdi_sprite_bitmap* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 28u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_composited_read_u64(&stream, &order->sprite_id) != LIBRDP_STATUS_OK ||
        rdp_composited_read_u64(&stream, &order->logical_surface_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_gdi_sprite_bitmap(rdp_buffer* buffer,
                                                     uint32_t target_resource,
                                                     uint64_t sprite_id,
                                                     uint64_t logical_surface_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_u64(&payload, sprite_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_u64(&payload, logical_surface_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer,
                                                      RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP,
                                                      payload.data,
                                                      payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_gdi_surface_update(const void* data,
                                                      size_t length,
                                                      rdp_composited_gdi_surface_update* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UPDATE_SURFACE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->dxgi_format) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_gdi_surface_update(rdp_buffer* buffer,
                                                      uint32_t target_resource,
                                                      uint32_t dxgi_format)
{
    return rdp_composited_write_u32_target_order(buffer,
                                                RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UPDATE_SURFACE,
                                                target_resource,
                                                dxgi_format);
}

librdp_status rdp_composited_parse_texture_set(const void* data,
                                               size_t length,
                                               rdp_composited_texture_set* textures)
{
    rdp_stream stream;

    if (!data || !textures)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != RDP_COMPOSITED_TEXTURE_SET_BYTES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(textures, 0, sizeof(*textures));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &textures->surface_count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &textures->dxgi_format) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &textures->width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &textures->height) != LIBRDP_STATUS_OK ||
        textures->surface_count > RDP_COMPOSITED_TEXTURE_SLOT_COUNT ||
        rdp_stream_read_bytes(&stream,
                              &textures->surfaces,
                              RDP_COMPOSITED_TEXTURE_SLOT_COUNT * RDP_COMPOSITED_TEXTURE_SLOT_BYTES) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    textures->surfaces_len = RDP_COMPOSITED_TEXTURE_SLOT_COUNT * RDP_COMPOSITED_TEXTURE_SLOT_BYTES;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_parse_meta_target(const void* data,
                                               size_t length,
                                               uint32_t expected_code,
                                               rdp_composited_meta_target* order)
{
    rdp_stream stream;
    const uint8_t* ignored = NULL;
    const uint8_t* textures = NULL;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (expected_code == RDP_COMPOSITED_CMD_META_TARGET_CREATE)
    {
        if (length != 0xe4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    else if (expected_code == RDP_COMPOSITED_CMD_META_TARGET_UPDATE)
    {
        if (length != 0xdcu)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    else
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != expected_code)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (expected_code == RDP_COMPOSITED_CMD_META_TARGET_CREATE &&
        rdp_stream_read_bytes(&stream, &ignored, 8u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &textures, RDP_COMPOSITED_TEXTURE_SET_BYTES) !=
            LIBRDP_STATUS_OK ||
        rdp_composited_parse_texture_set(textures, RDP_COMPOSITED_TEXTURE_SET_BYTES, &order->textures) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_meta_target(rdp_buffer* buffer,
                                               uint32_t control_code,
                                               uint32_t target_resource,
                                               uint32_t surface_count,
                                               uint32_t dxgi_format,
                                               uint32_t width,
                                               uint32_t height,
                                               const uint8_t surfaces[RDP_COMPOSITED_TEXTURE_SLOT_COUNT *
                                                                      RDP_COMPOSITED_TEXTURE_SLOT_BYTES])
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !surfaces ||
        (control_code != RDP_COMPOSITED_CMD_META_TARGET_CREATE &&
         control_code != RDP_COMPOSITED_CMD_META_TARGET_UPDATE) ||
        surface_count > RDP_COMPOSITED_TEXTURE_SLOT_COUNT)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK && control_code == RDP_COMPOSITED_CMD_META_TARGET_CREATE)
        status = rdp_composited_write_zeroes(&payload, 8u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, surface_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, dxgi_format);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, width);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&payload,
                                   surfaces,
                                   RDP_COMPOSITED_TEXTURE_SLOT_COUNT * RDP_COMPOSITED_TEXTURE_SLOT_BYTES);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer, control_code, payload.data, payload.length);
    rdp_buffer_free(&payload);
    return status;
}
