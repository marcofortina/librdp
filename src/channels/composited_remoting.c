#include "channels/composited_remoting.h"

#include "common/stream.h"

#include <string.h>

static int rdp_composited_aligned_size(size_t length)
{
    return (length % 4u) == 0;
}

static int rdp_composited_align4_size(size_t length, size_t* aligned)
{
    size_t rem = 0;

    if (!aligned)
        return 0;
    rem = length % 4u;
    if (rem == 0)
    {
        *aligned = length;
        return 1;
    }
    if (length > SIZE_MAX - (4u - rem))
        return 0;
    *aligned = length + 4u - rem;
    return 1;
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

static librdp_status rdp_composited_read_i32(rdp_stream* stream, int32_t* value)
{
    uint32_t raw = 0;

    if (rdp_stream_read_u32_le(stream, &raw) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = (int32_t)raw;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_composited_write_u64(rdp_buffer* buffer, uint64_t value)
{
    librdp_status status = rdp_buffer_append_u32_le(buffer, (uint32_t)(value & 0xffffffffu));

    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, (uint32_t)((value >> 32) & 0xffffffffu));
}

static librdp_status rdp_composited_write_i32(rdp_buffer* buffer, int32_t value)
{
    return rdp_buffer_append_u32_le(buffer, (uint32_t)value);
}

static uint64_t rdp_composited_hash_bytes_seed(uint64_t hash, const uint8_t* data, size_t length)
{
    size_t i = 0;

    if (!data && length > 0)
        return hash;
    for (i = 0; i < length; i++)
    {
        hash ^= data[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

static uint64_t rdp_composited_hash_u64_seed(uint64_t hash, uint64_t value)
{
    uint8_t bytes[8];
    uint8_t i = 0;

    for (i = 0; i < sizeof(bytes); i++)
        bytes[i] = (uint8_t)((value >> (i * 8u)) & 0xffu);
    return rdp_composited_hash_bytes_seed(hash, bytes, sizeof(bytes));
}

static uint64_t rdp_composited_hash_payload(const uint8_t* data, size_t data_len,
                                            const uint8_t* palette, size_t palette_len)
{
    uint64_t hash = 1469598103934665603ull;

    hash = rdp_composited_hash_u64_seed(hash, data_len);
    hash = rdp_composited_hash_bytes_seed(hash, data, data_len);
    hash = rdp_composited_hash_u64_seed(hash, palette_len);
    return rdp_composited_hash_bytes_seed(hash, palette, palette_len);
}

static int rdp_composited_pixel_format_palettized(uint32_t format)
{
    return format == RDP_COMPOSITED_PIXEL_FORMAT_1BPP_INDEXED ||
           format == RDP_COMPOSITED_PIXEL_FORMAT_2BPP_INDEXED ||
           format == RDP_COMPOSITED_PIXEL_FORMAT_4BPP_INDEXED ||
           format == RDP_COMPOSITED_PIXEL_FORMAT_8BPP_INDEXED;
}

static librdp_status rdp_composited_read_rect_i(rdp_stream* stream, rdp_composited_rect_i* rect)
{
    if (!rect)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_composited_read_i32(stream, &rect->left) != LIBRDP_STATUS_OK ||
        rdp_composited_read_i32(stream, &rect->top) != LIBRDP_STATUS_OK ||
        rdp_composited_read_i32(stream, &rect->right) != LIBRDP_STATUS_OK ||
        rdp_composited_read_i32(stream, &rect->bottom) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_composited_write_rect_i(rdp_buffer* buffer,
                                                 const rdp_composited_rect_i* rect)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rect)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_composited_write_i32(buffer, rect->left);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_i32(buffer, rect->top);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_i32(buffer, rect->right);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_i32(buffer, rect->bottom);
    return status;
}

static librdp_status rdp_composited_read_margins_i(rdp_stream* stream,
                                                   rdp_composited_margins_i* margins)
{
    if (!margins)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_composited_read_i32(stream, &margins->left) != LIBRDP_STATUS_OK ||
        rdp_composited_read_i32(stream, &margins->top) != LIBRDP_STATUS_OK ||
        rdp_composited_read_i32(stream, &margins->right) != LIBRDP_STATUS_OK ||
        rdp_composited_read_i32(stream, &margins->bottom) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_composited_write_margins_i(rdp_buffer* buffer,
                                                    const rdp_composited_margins_i* margins)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !margins)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_composited_write_i32(buffer, margins->left);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_i32(buffer, margins->top);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_i32(buffer, margins->right);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_i32(buffer, margins->bottom);
    return status;
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

static int rdp_composited_resource_rect(const rdp_composited_render_resource* entry,
                                        rdp_composited_rect_i* rect)
{
    if (!entry || !rect)
        return 0;
    if (entry->bounds_valid)
    {
        *rect = entry->window_rect;
        return 1;
    }
    if (entry->width > 0 && entry->height > 0)
    {
        rect->left = 0;
        rect->top = 0;
        rect->right = (int32_t)entry->width;
        rect->bottom = (int32_t)entry->height;
        return 1;
    }
    if (entry->texture_width > 0 && entry->texture_height > 0)
    {
        rect->left = 0;
        rect->top = 0;
        rect->right = (int32_t)entry->texture_width;
        rect->bottom = (int32_t)entry->texture_height;
        return 1;
    }
    if (entry->invalid_rect_valid)
    {
        *rect = entry->invalid_rect;
        return 1;
    }
    return 0;
}

static void rdp_composited_render_tree_invalidate_rect(rdp_composited_render_tree* tree,
                                                       uint32_t resource,
                                                       const rdp_composited_rect_i* rect)
{
    uint32_t i = 0;
    rdp_composited_render_invalidation* slot = NULL;

    if (!tree || !rect)
        return;
    for (i = 0; i < RDP_COMPOSITED_RENDER_INVALIDATION_LIMIT; i++)
    {
        if (tree->invalidations[i].active && tree->invalidations[i].resource == resource)
        {
            slot = &tree->invalidations[i];
            break;
        }
    }
    if (!slot)
    {
        for (i = 0; i < RDP_COMPOSITED_RENDER_INVALIDATION_LIMIT; i++)
        {
            if (!tree->invalidations[i].active)
            {
                slot = &tree->invalidations[i];
                break;
            }
        }
    }
    if (!slot)
        slot = &tree->invalidations[resource % RDP_COMPOSITED_RENDER_INVALIDATION_LIMIT];
    tree->invalidation_count++;
    memset(slot, 0, sizeof(*slot));
    slot->active = 1;
    slot->resource = resource;
    slot->generation = tree->invalidation_count;
    slot->rect = *rect;
}

static void rdp_composited_render_tree_invalidate_resource(
    rdp_composited_render_tree* tree,
    const rdp_composited_render_resource* entry)
{
    rdp_composited_rect_i rect;

    if (!tree || !entry || !entry->active)
        return;
    if (rdp_composited_resource_rect(entry, &rect))
        rdp_composited_render_tree_invalidate_rect(tree, entry->resource, &rect);
}

static int rdp_composited_render_resource_references(
    const rdp_composited_render_resource* entry,
    uint32_t resource)
{
    if (!entry || !entry->active)
        return 0;
    return entry->duplicate_source == resource ||
           entry->root_resource == resource ||
           entry->sprite_image_resource == resource ||
           entry->logical_surface_image_resource == resource ||
           entry->sprite_clip_resource == resource ||
           entry->dx_clip_resource == resource ||
           entry->transform_resource == resource ||
           entry->color_transform_resource == resource ||
           entry->filter_list_resource == resource;
}

static int rdp_composited_render_tree_visited(const uint32_t* visited,
                                              uint32_t visited_count,
                                              uint32_t resource)
{
    uint32_t i = 0;

    if (!visited)
        return 1;
    for (i = 0; i < visited_count; i++)
    {
        if (visited[i] == resource)
            return 1;
    }
    return 0;
}

static void rdp_composited_render_tree_invalidate_dependents(
    rdp_composited_render_tree* tree,
    uint32_t resource,
    uint32_t* visited,
    uint32_t* visited_count)
{
    uint32_t i = 0;

    if (!tree || !visited || !visited_count ||
        *visited_count >= RDP_COMPOSITED_RENDER_RESOURCE_LIMIT)
        return;
    for (i = 0; i < RDP_COMPOSITED_RENDER_RESOURCE_LIMIT; i++)
    {
        rdp_composited_render_resource* current = &tree->resources[i];

        if (!current->active ||
            !rdp_composited_render_resource_references(current, resource) ||
            rdp_composited_render_tree_visited(visited, *visited_count, current->resource))
            continue;
        visited[*visited_count] = current->resource;
        (*visited_count)++;
        rdp_composited_render_tree_invalidate_resource(tree, current);
        rdp_composited_render_tree_invalidate_dependents(tree,
                                                         current->resource,
                                                         visited,
                                                         visited_count);
    }
}

static void rdp_composited_render_tree_invalidate_graph(
    rdp_composited_render_tree* tree,
    const rdp_composited_render_resource* entry)
{
    uint32_t visited[RDP_COMPOSITED_RENDER_RESOURCE_LIMIT];
    uint32_t visited_count = 1;

    if (!tree || !entry || !entry->active)
        return;
    visited[0] = entry->resource;
    rdp_composited_render_tree_invalidate_resource(tree, entry);
    rdp_composited_render_tree_invalidate_dependents(tree,
                                                     entry->resource,
                                                     visited,
                                                     &visited_count);
}

static rdp_composited_render_resource* rdp_composited_render_tree_create_resource(
    rdp_composited_render_tree* tree,
    uint32_t resource,
    uint32_t resource_type)
{
    rdp_composited_render_resource* entry =
        rdp_composited_render_tree_find_mutable(tree, resource);

    if (!tree)
        return NULL;
    if (!entry)
        return rdp_composited_render_tree_upsert(tree, resource, resource_type);
    rdp_composited_render_tree_invalidate_graph(tree, entry);
    memset(entry, 0, sizeof(*entry));
    entry->active = 1;
    entry->resource = resource;
    entry->resource_type = resource_type;
    return entry;
}

static void rdp_composited_render_tree_delete(rdp_composited_render_tree* tree, uint32_t resource)
{
    rdp_composited_render_resource* entry = rdp_composited_render_tree_find_mutable(tree, resource);
    uint32_t i = 0;

    if (entry)
    {
        rdp_composited_render_tree_invalidate_resource(tree, entry);
        memset(entry, 0, sizeof(*entry));
        if (tree->resource_count > 0)
            tree->resource_count--;
    }
    for (i = 0; i < RDP_COMPOSITED_RENDER_RESOURCE_LIMIT; i++)
    {
        rdp_composited_render_resource* current = &tree->resources[i];
        uint8_t changed = 0;

        if (!current->active)
            continue;
        if (current->duplicate_source == resource)
        {
            current->duplicate_source = 0;
            current->duplicate_target_channel = 0;
            changed = 1;
        }
        if (current->root_resource == resource)
        {
            current->root_resource = 0;
            changed = 1;
        }
        if (current->sprite_image_resource == resource)
        {
            current->sprite_image_resource = 0;
            changed = 1;
        }
        if (current->logical_surface_image_resource == resource)
        {
            current->logical_surface_image_resource = 0;
            changed = 1;
        }
        if (current->sprite_clip_resource == resource)
        {
            current->sprite_clip_resource = 0;
            current->sprite_clip_for_dirty_accum = 0;
            changed = 1;
        }
        if (current->dx_clip_resource == resource)
        {
            current->dx_clip_resource = 0;
            changed = 1;
        }
        if (current->transform_resource == resource)
        {
            current->transform_resource = 0;
            changed = 1;
        }
        if (current->color_transform_resource == resource)
        {
            current->color_transform_resource = 0;
            changed = 1;
        }
        if (current->filter_list_resource == resource)
        {
            current->filter_list_resource = 0;
            changed = 1;
        }
        if (changed)
            rdp_composited_render_tree_invalidate_graph(tree, current);
    }
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

uint32_t rdp_composited_render_tree_collect_invalidations(
    const rdp_composited_render_tree* tree,
    uint32_t after_generation,
    rdp_composited_render_invalidation* invalidations,
    uint32_t max_invalidations,
    uint32_t* latest_generation)
{
    uint32_t copied = 0;
    uint32_t cursor = after_generation;

    if (latest_generation)
        *latest_generation = tree ? tree->invalidation_count : 0;
    if (!tree || !invalidations || max_invalidations == 0)
        return 0;

    while (copied < max_invalidations)
    {
        uint32_t i = 0;
        const rdp_composited_render_invalidation* best = NULL;

        for (i = 0; i < RDP_COMPOSITED_RENDER_INVALIDATION_LIMIT; i++)
        {
            const rdp_composited_render_invalidation* current = &tree->invalidations[i];

            if (!current->active || current->generation <= cursor)
                continue;
            if (!best || current->generation < best->generation)
                best = current;
        }
        if (!best)
            break;
        invalidations[copied++] = *best;
        cursor = best->generation;
    }
    return copied;
}

static const rdp_composited_render_resource* rdp_composited_render_tree_resolve_resource(
    const rdp_composited_render_tree* tree,
    uint32_t resource,
    uint32_t* duplicate_resolved)
{
    uint32_t visited[RDP_COMPOSITED_RENDER_RESOURCE_LIMIT];
    uint32_t visited_count = 0;
    const rdp_composited_render_resource* entry = NULL;

    if (duplicate_resolved)
        *duplicate_resolved = 0;
    if (!tree || resource == 0)
        return NULL;
    entry = rdp_composited_render_tree_find(tree, resource);
    while (entry && entry->duplicate_source != 0)
    {
        uint32_t i = 0;
        const rdp_composited_render_resource* source = NULL;

        for (i = 0; i < visited_count; i++)
        {
            if (visited[i] == entry->resource)
                return entry;
        }
        if (visited_count >= RDP_COMPOSITED_RENDER_RESOURCE_LIMIT)
            return entry;
        visited[visited_count++] = entry->resource;
        source = rdp_composited_render_tree_find(tree, entry->duplicate_source);
        if (!source)
            return entry;
        if (duplicate_resolved)
            *duplicate_resolved = 1;
        entry = source;
    }
    return entry;
}

static const rdp_composited_render_invalidation* rdp_composited_render_tree_find_invalidation(
    const rdp_composited_render_tree* tree,
    uint32_t resource)
{
    uint32_t i = 0;

    if (!tree || resource == 0)
        return NULL;
    for (i = 0; i < RDP_COMPOSITED_RENDER_INVALIDATION_LIMIT; i++)
    {
        if (tree->invalidations[i].active && tree->invalidations[i].resource == resource)
            return &tree->invalidations[i];
    }
    return NULL;
}

static uint32_t rdp_composited_render_resource_source_ref(
    const rdp_composited_render_resource* entry)
{
    if (!entry)
        return 0;
    if (entry->logical_surface_image_resource != 0)
        return entry->logical_surface_image_resource;
    if (entry->sprite_image_resource != 0)
        return entry->sprite_image_resource;
    switch (entry->resource_type)
    {
        case RDP_COMPOSITED_RESOURCE_GDI_SPRITE_BITMAP:
        case RDP_COMPOSITED_RESOURCE_BITMAP_SOURCE:
        case RDP_COMPOSITED_RESOURCE_META_BITMAP_TARGET:
        case RDP_COMPOSITED_RESOURCE_RENDERDATA:
        case RDP_COMPOSITED_RESOURCE_GLYPH_RUN:
            return entry->resource;
        default:
            return 0;
    }
}

static void rdp_composited_resolved_view_consider_invalidation(
    const rdp_composited_render_tree* tree,
    uint32_t resource,
    rdp_composited_resolved_view* view,
    uint32_t* generation)
{
    const rdp_composited_render_invalidation* invalidation =
        rdp_composited_render_tree_find_invalidation(tree, resource);

    if (!invalidation || !view || !generation || invalidation->generation < *generation)
        return;
    view->invalid_rect = invalidation->rect;
    view->invalid_rect_valid = 1;
    *generation = invalidation->generation;
}

librdp_status rdp_composited_render_tree_resolve_view(
    const rdp_composited_render_tree* tree,
    uint32_t target_resource,
    rdp_composited_resolved_view* view)
{
    uint32_t duplicate = 0;
    uint32_t invalidation_generation = 0;
    uint32_t source_ref = 0;
    const rdp_composited_render_resource* target = NULL;
    const rdp_composited_render_resource* root = NULL;
    const rdp_composited_render_resource* source = NULL;

    if (!tree || !view || target_resource == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(view, 0, sizeof(*view));
    view->target_resource = target_resource;
    target = rdp_composited_render_tree_resolve_resource(tree, target_resource, &duplicate);
    if (!target)
        return LIBRDP_STATUS_STATE;
    view->flags |= RDP_COMPOSITED_VIEW_TARGET_PRESENT;
    if (duplicate)
        view->flags |= RDP_COMPOSITED_VIEW_TARGET_DUPLICATE;
    view->target_resource = target->resource;
    view->target_type = target->resource_type;
    view->width = target->width;
    view->height = target->height;
    view->dxgi_format = target->dxgi_format;
    view->capture_count = target->capture_count;
    view->capture_x = target->capture_x;
    view->capture_y = target->capture_y;
    view->capture_width = target->capture_width;
    view->capture_height = target->capture_height;
    memcpy(view->clear_color, target->clear_color, sizeof(view->clear_color));
    memcpy(view->color_key, target->color_key, sizeof(view->color_key));
    if (target->capture_count != 0)
        view->flags |= RDP_COMPOSITED_VIEW_TARGET_CAPTURE;
    view->target_rect_valid = (uint8_t)rdp_composited_resource_rect(target, &view->target_rect);
    rdp_composited_resolved_view_consider_invalidation(tree,
                                                       target->resource,
                                                       view,
                                                       &invalidation_generation);

    root = rdp_composited_render_tree_resolve_resource(tree, target->root_resource, &duplicate);
    if (root)
    {
        view->flags |= RDP_COMPOSITED_VIEW_ROOT_PRESENT;
        if (duplicate)
            view->flags |= RDP_COMPOSITED_VIEW_ROOT_DUPLICATE;
        view->root_resource = root->resource;
        view->root_type = root->resource_type;
        view->sprite_id = root->sprite_id;
        view->window_id = root->window_id;
        view->logical_surface_id = root->logical_surface_id;
        if (root->detached)
            view->flags |= RDP_COMPOSITED_VIEW_ROOT_DETACHED;
        if (root->protected_content)
            view->flags |= RDP_COMPOSITED_VIEW_PROTECTED;
        if (root->compose_once)
            view->flags |= RDP_COMPOSITED_VIEW_COMPOSE_ONCE;
        view->root_rect_valid = (uint8_t)rdp_composited_resource_rect(root, &view->root_rect);
        rdp_composited_resolved_view_consider_invalidation(tree,
                                                           root->resource,
                                                           view,
                                                           &invalidation_generation);
    }

    source_ref = rdp_composited_render_resource_source_ref(root ? root : target);
    source = rdp_composited_render_tree_resolve_resource(tree, source_ref, &duplicate);
    if (source)
    {
        view->flags |= RDP_COMPOSITED_VIEW_SOURCE_PRESENT;
        if (duplicate)
            view->flags |= RDP_COMPOSITED_VIEW_SOURCE_DUPLICATE;
        view->source_resource = source->resource;
        view->source_type = source->resource_type;
        if (source->width != 0)
            view->width = source->width;
        if (source->height != 0)
            view->height = source->height;
        if (source->dxgi_format != 0)
            view->dxgi_format = source->dxgi_format;
        view->surface_count = source->surface_count;
        view->texture_width = source->texture_width;
        view->texture_height = source->texture_height;
        view->bitmap_format = source->bitmap_format;
        view->bitmap_stride = source->bitmap_stride;
        view->bitmap_payload_length = source->bitmap_payload_length;
        view->bitmap_palette_entries = source->bitmap_palette_entries;
        view->bitmap_palette_length = source->bitmap_palette_length;
        view->bitmap_compressed = source->bitmap_compressed;
        view->bitmap_dpi_x_bits = source->bitmap_dpi_x_bits;
        view->bitmap_dpi_y_bits = source->bitmap_dpi_y_bits;
        view->bitmap_payload_hash = source->bitmap_payload_hash;
        view->meta_capture_count = source->meta_capture_count;
        view->meta_capture_update_id = source->meta_capture_update_id;
        view->sprite_dirty_count = source->sprite_dirty_count;
        view->sprite_dirty_flags = source->sprite_dirty_flags;
        view->sprite_dirty_cookie = source->sprite_dirty_cookie;
        view->logical_surface_id = source->logical_surface_id;
        if (source->meta_capture_count != 0)
            view->flags |= RDP_COMPOSITED_VIEW_META_CAPTURE;
        if (source->sprite_dirty_count != 0)
            view->flags |= RDP_COMPOSITED_VIEW_SOURCE_DIRTY;
        if (source->sprite_unmapped)
            view->flags |= RDP_COMPOSITED_VIEW_SOURCE_UNMAPPED;
        view->source_rect_valid = (uint8_t)rdp_composited_resource_rect(source, &view->source_rect);
        rdp_composited_resolved_view_consider_invalidation(tree,
                                                           source->resource,
                                                           view,
                                                           &invalidation_generation);
    }
    return LIBRDP_STATUS_OK;
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
            rdp_composited_render_tree_invalidate_graph(tree, target);
            break;
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_LOGICAL_SURFACE_IMAGE:
            target->logical_surface_image_resource = order.value;
            rdp_composited_render_tree_invalidate_graph(tree, target);
            break;
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SPRITE_IMAGE:
            target->sprite_image_resource = order.value;
            rdp_composited_render_tree_invalidate_graph(tree, target);
            break;
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_DX_CLIP:
            target->dx_clip_resource = order.value;
            rdp_composited_render_tree_invalidate_graph(tree, target);
            break;
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_COMPOSE_ONCE:
            target->compose_once = order.value ? 1u : 0u;
            rdp_composited_render_tree_invalidate_graph(tree, target);
            break;
        case RDP_COMPOSITED_CMD_WINDOW_NODE_PROTECT_CONTENT:
            target->protected_content = order.value ? 1u : 0u;
            rdp_composited_render_tree_invalidate_graph(tree, target);
            break;
        case RDP_COMPOSITED_CMD_META_TARGET_SET_TRANSFORM:
            target->transform_resource = order.value;
            rdp_composited_render_tree_invalidate_graph(tree, target);
            break;
        case RDP_COMPOSITED_CMD_META_TARGET_SET_COLOR_TRANSFORM:
            target->color_transform_resource = order.value;
            rdp_composited_render_tree_invalidate_graph(tree, target);
            break;
        case RDP_COMPOSITED_CMD_META_TARGET_SET_FILTER_LIST:
            target->filter_list_resource = order.value;
            rdp_composited_render_tree_invalidate_graph(tree, target);
            break;
        default:
            break;
    }
    return LIBRDP_STATUS_OK;
}

static void rdp_composited_render_copy_owned(rdp_composited_render_resource* target,
                                             const rdp_composited_render_resource* source)
{
    if (!target || !source)
        return;
    target->sprite_clip_resource = source->sprite_clip_resource;
    target->sprite_clip_for_dirty_accum = source->sprite_clip_for_dirty_accum;
    target->dx_clip_resource = source->dx_clip_resource;
    target->alpha_margins = source->alpha_margins;
    target->alpha_margins_valid = source->alpha_margins_valid;
    target->maximized_clip_margins = source->maximized_clip_margins;
    target->maximized_clip_margins_valid = source->maximized_clip_margins_valid;
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
            entry = rdp_composited_render_tree_create_resource(tree,
                                                               order.resource,
                                                               order.resource_type);
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
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_RENDERDATA:
        {
            rdp_composited_render_data render_data;

            status = rdp_composited_parse_render_data(message->data, message->message_size, &render_data);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      render_data.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_RENDERDATA);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->render_data_length = render_data.data_size;
            entry->render_instruction_count = render_data.data_size / 4u;
            rdp_composited_render_tree_invalidate_graph(tree, entry);
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
            entry->detached = 0;
            break;
        }
        case RDP_COMPOSITED_CMD_WINDOW_NODE_DETACH:
        {
            rdp_composited_target_order detach;

            status = rdp_composited_parse_target_order(message->data,
                                                       message->message_size,
                                                       RDP_COMPOSITED_CMD_WINDOW_NODE_DETACH,
                                                       &detach);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      detach.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_WINDOW_NODE);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->detached = 1;
            entry->detach_count++;
            entry->rendering_enabled = 0;
            entry->sprite_image_resource = 0;
            entry->logical_surface_image_resource = 0;
            entry->sprite_clip_resource = 0;
            entry->sprite_clip_for_dirty_accum = 0;
            entry->dx_clip_resource = 0;
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_BOUNDS:
        {
            rdp_composited_window_node_bounds bounds;

            status = rdp_composited_parse_window_node_bounds(message->data,
                                                             message->message_size,
                                                             &bounds);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      bounds.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_WINDOW_NODE);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->window_rect = bounds.window;
            entry->client_rect = bounds.client;
            entry->content_rect = bounds.content;
            entry->bounds_valid = 1;
            entry->detached = 0;
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_WINDOW_NODE_UPDATE_SPRITE_HANDLE:
        {
            rdp_composited_u64_target_order sprite_handle;

            status = rdp_composited_parse_u64_target_order(message->data,
                                                           message->message_size,
                                                           RDP_COMPOSITED_CMD_WINDOW_NODE_UPDATE_SPRITE_HANDLE,
                                                           &sprite_handle);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      sprite_handle.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_WINDOW_NODE);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->sprite_id = sprite_handle.value;
            entry->detached = 0;
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SPRITE_CLIP:
        {
            rdp_composited_window_node_clip clip;

            status = rdp_composited_parse_window_node_clip(message->data,
                                                           message->message_size,
                                                           &clip);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      clip.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_WINDOW_NODE);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->sprite_clip_for_dirty_accum = clip.for_dirty_accum ? 1u : 0u;
            entry->sprite_clip_resource = clip.clip_resource;
            entry->detached = 0;
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SOURCE_MODIFICATIONS:
        {
            rdp_composited_window_node_source_modifications source;

            status = rdp_composited_parse_window_node_source_modifications(message->data,
                                                                           message->message_size,
                                                                           &source);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      source.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_WINDOW_NODE);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->source_modifications = source.source_modifications;
            entry->low_color_key = source.low_color_key;
            entry->high_color_key = source.high_color_key;
            entry->detached = 0;
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_ALPHA_MARGINS:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_MAXIMIZED_CLIP_MARGINS:
        {
            rdp_composited_margins_order margins;

            status = rdp_composited_parse_margins_order(message->data,
                                                        message->message_size,
                                                        message->control_code,
                                                        &margins);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      margins.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_WINDOW_NODE);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            if (message->control_code == RDP_COMPOSITED_CMD_WINDOW_NODE_SET_ALPHA_MARGINS)
            {
                entry->alpha_margins = margins.margins;
                entry->alpha_margins_valid = 1;
            }
            else
            {
                entry->maximized_clip_margins = margins.margins;
                entry->maximized_clip_margins_valid = 1;
            }
            entry->detached = 0;
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_WINDOW_NODE_COPY_OWNED_RESOURCES:
        {
            rdp_composited_u32_target_order copy;
            const rdp_composited_render_resource* source = NULL;

            status = rdp_composited_parse_u32_target_order(message->data,
                                                           message->message_size,
                                                           RDP_COMPOSITED_CMD_WINDOW_NODE_COPY_OWNED_RESOURCES,
                                                           &copy);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      copy.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_WINDOW_NODE);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            source = rdp_composited_render_tree_find(tree, copy.value);
            rdp_composited_render_copy_owned(entry, source);
            entry->detached = 0;
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_WINDOW_NODE_NOTIFY_VISIBLE_REGION:
        {
            rdp_composited_target_order visible;

            status = rdp_composited_parse_target_order(message->data,
                                                       message->message_size,
                                                       RDP_COMPOSITED_CMD_WINDOW_NODE_NOTIFY_VISIBLE_REGION,
                                                       &visible);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      visible.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_WINDOW_NODE);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->visible_region_updates++;
            entry->detached = 0;
            rdp_composited_render_tree_invalidate_graph(tree, entry);
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
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_TARGET_UPDATE_WINDOW_SETTINGS:
        {
            rdp_composited_target_window_settings settings;

            status = rdp_composited_parse_target_window_settings(message->data,
                                                                 message->message_size,
                                                                 &settings);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree, settings.target_resource, 0);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->window_rect = settings.window_rect;
            entry->window_layer_type = settings.window_layer_type;
            entry->transparency_mode = settings.transparency_mode;
            entry->constant_alpha_bits = settings.constant_alpha_bits;
            entry->is_child = settings.is_child ? 1u : 0u;
            entry->is_rtl = settings.is_rtl ? 1u : 0u;
            entry->rendering_enabled = settings.rendering_enabled ? 1u : 0u;
            entry->disable_cookie = settings.disable_cookie;
            memcpy(entry->color_key, settings.color_key, sizeof(entry->color_key));
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_TARGET_SET_CLEAR_COLOR:
        {
            rdp_composited_color_order color;

            status = rdp_composited_parse_color_order(message->data,
                                                      message->message_size,
                                                      RDP_COMPOSITED_CMD_TARGET_SET_CLEAR_COLOR,
                                                      &color);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree, color.target_resource, 0);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            memcpy(entry->clear_color, color.color, sizeof(entry->clear_color));
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_TARGET_INVALIDATE:
        {
            rdp_composited_rect_order invalidate;

            status = rdp_composited_parse_rect_order(message->data,
                                                     message->message_size,
                                                     RDP_COMPOSITED_CMD_TARGET_INVALIDATE,
                                                     &invalidate);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree, invalidate.target_resource, 0);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->invalid_rect = invalidate.rect;
            entry->invalid_rect_valid = 1;
            rdp_composited_render_tree_invalidate_rect(tree, entry->resource, &invalidate.rect);
            entry->invalidation_generation = tree->invalidation_count;
            break;
        }
        case RDP_COMPOSITED_CMD_TARGET_CAPTURE_BITS:
        {
            rdp_composited_target_capture_bits capture;

            status = rdp_composited_parse_target_capture_bits(message->data,
                                                              message->message_size,
                                                              &capture);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree, capture.target_resource, 0);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->capture_count++;
            entry->capture_x = capture.x;
            entry->capture_y = capture.y;
            entry->capture_width = capture.width;
            entry->capture_height = capture.height;
            entry->dxgi_format = capture.dxgi_format;
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_META_TARGET_CAPTURE_BITS:
        {
            rdp_composited_meta_capture_bits capture;

            status = rdp_composited_parse_meta_capture_bits(message->data,
                                                            message->message_size,
                                                            &capture);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      capture.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_META_BITMAP_TARGET);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->meta_capture_count++;
            entry->capture_width = capture.width;
            entry->capture_height = capture.height;
            entry->meta_capture_update_id = capture.update_id;
            rdp_composited_render_tree_invalidate_graph(tree, entry);
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
            rdp_composited_render_tree_invalidate_graph(tree, entry);
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
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UPDATE_MARGINS:
        {
            rdp_composited_margins_order margins;

            status = rdp_composited_parse_margins_order(message->data,
                                                        message->message_size,
                                                        RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UPDATE_MARGINS,
                                                        &margins);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      margins.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_GDI_SPRITE_BITMAP);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->sprite_margins = margins.margins;
            entry->sprite_margins_valid = 1;
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UNMAP_SECTION:
        {
            rdp_composited_target_order unmap;

            status = rdp_composited_parse_target_order(message->data,
                                                       message->message_size,
                                                       RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UNMAP_SECTION,
                                                       &unmap);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      unmap.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_GDI_SPRITE_BITMAP);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->sprite_unmapped = 1;
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_NOTIFY_DIRTY:
        {
            rdp_composited_gdi_dirty dirty;

            status = rdp_composited_parse_gdi_dirty(message->data, message->message_size, &dirty);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      dirty.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_GDI_SPRITE_BITMAP);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->sprite_dirty_count++;
            entry->sprite_dirty_flags = (uint32_t)dirty.dirty_flags;
            entry->sprite_dirty_cookie = dirty.notification_cookie;
            rdp_composited_render_tree_invalidate_graph(tree, entry);
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
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_TARGET_SET_ROOT:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_LOGICAL_SURFACE_IMAGE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SPRITE_IMAGE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_DX_CLIP:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_SET_COMPOSE_ONCE:
        case RDP_COMPOSITED_CMD_WINDOW_NODE_PROTECT_CONTENT:
        case RDP_COMPOSITED_CMD_META_TARGET_SET_TRANSFORM:
        case RDP_COMPOSITED_CMD_META_TARGET_SET_COLOR_TRANSFORM:
        case RDP_COMPOSITED_CMD_META_TARGET_SET_FILTER_LIST:
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
        case RDP_COMPOSITED_CMD_BITMAP_PIXELS:
        {
            rdp_composited_bitmap_pixels pixels;

            status = rdp_composited_parse_bitmap_pixels(message->data, message->message_size, &pixels);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      pixels.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_BITMAP_SOURCE);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->width = pixels.width;
            entry->height = pixels.height;
            entry->dxgi_format = pixels.format;
            entry->bitmap_format = pixels.format;
            entry->bitmap_stride = pixels.stride;
            entry->bitmap_payload_length = (uint32_t)pixels.image_bitmap_len;
            entry->bitmap_palette_entries = pixels.palette_color_count;
            entry->bitmap_palette_length = (uint32_t)pixels.image_palette_len;
            entry->bitmap_compressed = 0;
            entry->bitmap_dpi_x_bits = pixels.dpi_x_bits;
            entry->bitmap_dpi_y_bits = pixels.dpi_y_bits;
            entry->bitmap_payload_hash = rdp_composited_hash_payload(pixels.image_bitmap,
                                                                     pixels.image_bitmap_len,
                                                                     pixels.image_palette,
                                                                     pixels.image_palette_len);
            tree->bitmap_pixels_count++;
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_BITMAP_COMPRESSED_PIXELS:
        {
            rdp_composited_bitmap_compressed_pixels pixels;

            status = rdp_composited_parse_bitmap_compressed_pixels(message->data,
                                                                   message->message_size,
                                                                   &pixels);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_composited_render_tree_upsert(tree,
                                                      pixels.target_resource,
                                                      RDP_COMPOSITED_RESOURCE_BITMAP_SOURCE);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->bitmap_payload_length = (uint32_t)pixels.compressed_image_bitmap_len;
            entry->bitmap_palette_entries = 0;
            entry->bitmap_palette_length = 0;
            entry->bitmap_compressed = 1;
            entry->bitmap_dpi_x_bits = pixels.dpi_x_bits;
            entry->bitmap_dpi_y_bits = pixels.dpi_y_bits;
            entry->bitmap_payload_hash = rdp_composited_hash_payload(pixels.compressed_image_bitmap,
                                                                     pixels.compressed_image_bitmap_len,
                                                                     NULL,
                                                                     0);
            tree->bitmap_compressed_pixels_count++;
            rdp_composited_render_tree_invalidate_graph(tree, entry);
            break;
        }
        case RDP_COMPOSITED_CMD_VISUAL_GROUP:
            tree->visual_group_count++;
            break;
        case RDP_COMPOSITED_CMD_GLYPH_CACHE_ADD_BITMAPS:
            tree->glyph_cache_add_count++;
            break;
        case RDP_COMPOSITED_CMD_GLYPH_CACHE_REMOVE_BITMAPS:
            tree->glyph_cache_remove_count++;
            break;
        case RDP_COMPOSITED_CMD_GLYPH_RUN_ADD_REALIZATION:
            tree->glyph_realization_add_count++;
            break;
        case RDP_COMPOSITED_CMD_GLYPH_RUN_REMOVE_REALIZATION:
            tree->glyph_realization_remove_count++;
            break;
        default:
            tree->extension_command_count++;
            tree->last_extension_command = message->control_code;
            tree->last_extension_payload_len = (uint32_t)message->payload_len;
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

static librdp_status rdp_composited_write_channel_u32_reply(rdp_buffer* buffer,
                                                            uint32_t channel,
                                                            uint32_t notification_code,
                                                            uint32_t value)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_composited_notification_code_valid(notification_code))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, notification_code);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, value);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_zeroes(&payload, 48u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_notification(buffer,
                                                   RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION,
                                                   channel,
                                                   payload.data,
                                                   payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_write_sync_flush_reply(rdp_buffer* buffer,
                                                    uint32_t channel,
                                                    uint32_t hr)
{
    return rdp_composited_write_channel_u32_reply(buffer,
                                                 channel,
                                                 RDP_COMPOSITED_MSG_SYNC_FLUSH_REPLY,
                                                 hr);
}

librdp_status rdp_composited_write_roundtrip_reply(rdp_buffer* buffer,
                                                   uint32_t channel,
                                                   uint32_t request_id)
{
    return rdp_composited_write_channel_u32_reply(buffer,
                                                 channel,
                                                 RDP_COMPOSITED_MSG_ROUNDTRIP_REPLY,
                                                 request_id);
}

librdp_status rdp_composited_write_async_flush_reply(rdp_buffer* buffer,
                                                     uint32_t channel,
                                                     uint32_t response_token,
                                                     uint32_t hr)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, RDP_COMPOSITED_MSG_ASYNC_FLUSH_REPLY);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, response_token);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, hr);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_zeroes(&payload, 44u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_notification(buffer,
                                                   RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION,
                                                   channel,
                                                   payload.data,
                                                   payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_write_hardware_tier(rdp_buffer* buffer,
                                                 uint32_t channel,
                                                 uint32_t common_minimum_caps,
                                                 uint32_t display_uniqueness)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, RDP_COMPOSITED_MSG_HARDWARE_TIER);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, common_minimum_caps ? 1u : 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, display_uniqueness);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_zeroes(&payload, 44u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_notification(buffer,
                                                   RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION,
                                                   channel,
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
        !rdp_composited_channel_command_known(message->control_code))
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

    if (!buffer || !rdp_composited_channel_command_known(control_code) || (!payload && payload_len > 0) ||
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

librdp_status rdp_composited_parse_u64_target_order(const void* data,
                                                    size_t length,
                                                    uint32_t expected_code,
                                                    rdp_composited_u64_target_order* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != expected_code)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_composited_read_u64(&stream, &order->value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_u64_target_order(rdp_buffer* buffer,
                                                    uint32_t control_code,
                                                    uint32_t target_resource,
                                                    uint64_t value)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || control_code == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_u64(&payload, value);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer, control_code, payload.data, payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_target_order(const void* data,
                                                size_t length,
                                                uint32_t expected_code,
                                                rdp_composited_target_order* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != expected_code)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_target_order(rdp_buffer* buffer,
                                                uint32_t control_code,
                                                uint32_t target_resource)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || control_code == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer, control_code, payload.data, payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_window_node_bounds(const void* data,
                                                      size_t length,
                                                      rdp_composited_window_node_bounds* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 60u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != RDP_COMPOSITED_CMD_WINDOW_NODE_SET_BOUNDS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_composited_read_rect_i(&stream, &order->window) != LIBRDP_STATUS_OK ||
        rdp_composited_read_rect_i(&stream, &order->client) != LIBRDP_STATUS_OK ||
        rdp_composited_read_rect_i(&stream, &order->content) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_window_node_bounds(
    rdp_buffer* buffer,
    uint32_t target_resource,
    const rdp_composited_rect_i* window,
    const rdp_composited_rect_i* client,
    const rdp_composited_rect_i* content)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !window || !client || !content)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_rect_i(&payload, window);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_rect_i(&payload, client);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_rect_i(&payload, content);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer,
                                                      RDP_COMPOSITED_CMD_WINDOW_NODE_SET_BOUNDS,
                                                      payload.data,
                                                      payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_window_node_clip(const void* data,
                                                    size_t length,
                                                    rdp_composited_window_node_clip* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SPRITE_CLIP)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->for_dirty_accum) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->clip_resource) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_window_node_clip(rdp_buffer* buffer,
                                                    uint32_t target_resource,
                                                    uint32_t for_dirty_accum,
                                                    uint32_t clip_resource)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, for_dirty_accum);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, clip_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer,
                                                      RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SPRITE_CLIP,
                                                      payload.data,
                                                      payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_window_node_source_modifications(
    const void* data,
    size_t length,
    rdp_composited_window_node_source_modifications* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 24u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SOURCE_MODIFICATIONS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->source_modifications) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->low_color_key) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->high_color_key) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_window_node_source_modifications(
    rdp_buffer* buffer,
    uint32_t target_resource,
    uint32_t source_modifications,
    uint32_t low_color_key,
    uint32_t high_color_key)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, source_modifications);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, low_color_key);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, high_color_key);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer,
                                                      RDP_COMPOSITED_CMD_WINDOW_NODE_SET_SOURCE_MODIFICATIONS,
                                                      payload.data,
                                                      payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_margins_order(const void* data,
                                                 size_t length,
                                                 uint32_t expected_code,
                                                 rdp_composited_margins_order* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 28u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != expected_code)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_composited_read_margins_i(&stream, &order->margins) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_margins_order(rdp_buffer* buffer,
                                                 uint32_t control_code,
                                                 uint32_t target_resource,
                                                 const rdp_composited_margins_i* margins)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !margins)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_margins_i(&payload, margins);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer, control_code, payload.data, payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_color_order(const void* data,
                                               size_t length,
                                               uint32_t expected_code,
                                               rdp_composited_color_order* order)
{
    rdp_stream stream;
    const uint8_t* color = NULL;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 28u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != expected_code)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &color, 16u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(order->color, color, sizeof(order->color));
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_color_order(rdp_buffer* buffer,
                                               uint32_t control_code,
                                               uint32_t target_resource,
                                               const uint8_t color[16])
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !color)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&payload, color, 16u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer, control_code, payload.data, payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_rect_order(const void* data,
                                              size_t length,
                                              uint32_t expected_code,
                                              rdp_composited_rect_order* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 28u || !rdp_composited_aligned_size(length))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != expected_code ||
        order->header.payload_len < 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_composited_read_rect_i(&stream, &order->rect) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_rect_order(rdp_buffer* buffer,
                                              uint32_t control_code,
                                              uint32_t target_resource,
                                              const rdp_composited_rect_i* rect)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rect)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_rect_i(&payload, rect);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer, control_code, payload.data, payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_target_window_settings(
    const void* data,
    size_t length,
    rdp_composited_target_window_settings* order)
{
    rdp_stream stream;
    const uint8_t* color = NULL;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 72u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != RDP_COMPOSITED_CMD_TARGET_UPDATE_WINDOW_SETTINGS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_composited_read_rect_i(&stream, &order->window_rect) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->window_layer_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->transparency_mode) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->constant_alpha_bits) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->is_child) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->is_rtl) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->rendering_enabled) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &color, 16u) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->disable_cookie) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(order->color_key, color, sizeof(order->color_key));
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_target_window_settings(
    rdp_buffer* buffer,
    uint32_t target_resource,
    const rdp_composited_target_window_settings* settings)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_rect_i(&payload, &settings->window_rect);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, settings->window_layer_type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, settings->transparency_mode);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, settings->constant_alpha_bits);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, settings->is_child);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, settings->is_rtl);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, settings->rendering_enabled);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&payload, settings->color_key, sizeof(settings->color_key));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, settings->disable_cookie);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer,
                                                      RDP_COMPOSITED_CMD_TARGET_UPDATE_WINDOW_SETTINGS,
                                                      payload.data,
                                                      payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_render_data(const void* data,
                                               size_t length,
                                               rdp_composited_render_data* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 16u || !rdp_composited_aligned_size(length))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != RDP_COMPOSITED_CMD_RENDERDATA ||
        order->header.payload_len < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->data_size) != LIBRDP_STATUS_OK ||
        order->data_size != order->header.payload_len - 8u ||
        rdp_stream_read_bytes(&stream, &order->data, order->data_size) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    order->data_len = order->data_size;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_render_data(rdp_buffer* buffer,
                                               uint32_t target_resource,
                                               const void* render_data,
                                               size_t render_data_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!render_data && render_data_len > 0) || render_data_len > UINT32_MAX ||
        !rdp_composited_aligned_size(render_data_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, (uint32_t)render_data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&payload, render_data, render_data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer,
                                                      RDP_COMPOSITED_CMD_RENDERDATA,
                                                      payload.data,
                                                      payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_bitmap_pixels(const void* data,
                                                 size_t length,
                                                 rdp_composited_bitmap_pixels* order)
{
    rdp_stream stream;
    const uint8_t* ignored = NULL;
    size_t bitmap_len = 0;
    size_t palette_len = 0;
    size_t variable_len = 0;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 0x38u || !rdp_composited_aligned_size(length))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != RDP_COMPOSITED_CMD_BITMAP_PIXELS ||
        order->header.payload_len < 48u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->height) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->format) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->stride) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->offset) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->reserved) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->palette_color_count) != LIBRDP_STATUS_OK ||
        rdp_composited_read_u64(&stream, &order->dpi_x_bits) != LIBRDP_STATUS_OK ||
        rdp_composited_read_u64(&stream, &order->dpi_y_bits) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (order->target_resource == 0 || order->width == 0 || order->height == 0 ||
        order->stride == 0 || order->palette_color_count > 256u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_composited_pixel_format_palettized(order->format))
    {
        if (order->palette_color_count == 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    else if (order->palette_color_count != 0)
    {
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if ((size_t)order->height > SIZE_MAX / order->stride)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_composited_align4_size((size_t)order->height * order->stride, &bitmap_len))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    palette_len = (size_t)order->palette_color_count * 4u;
    variable_len = rdp_stream_remaining(&stream);
    if (order->offset > variable_len ||
        bitmap_len > variable_len - order->offset ||
        palette_len > variable_len - order->offset - bitmap_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &ignored, order->offset) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &order->image_bitmap, bitmap_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &order->image_palette, palette_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    order->image_bitmap_len = bitmap_len;
    order->image_palette_len = palette_len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_bitmap_pixels(rdp_buffer* buffer,
                                                 uint32_t target_resource,
                                                 uint32_t width,
                                                 uint32_t height,
                                                 uint32_t format,
                                                 uint32_t stride,
                                                 uint32_t palette_color_count,
                                                 uint64_t dpi_x_bits,
                                                 uint64_t dpi_y_bits,
                                                 const void* image_bitmap,
                                                 size_t image_bitmap_len,
                                                 const void* image_palette,
                                                 size_t image_palette_len)
{
    rdp_buffer payload;
    size_t expected_bitmap_len = 0;
    size_t expected_palette_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || target_resource == 0 || width == 0 || height == 0 || stride == 0 ||
        (!image_bitmap && image_bitmap_len > 0) || (!image_palette && image_palette_len > 0) ||
        palette_color_count > 256u || (size_t)height > SIZE_MAX / stride ||
        !rdp_composited_align4_size((size_t)height * stride, &expected_bitmap_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    expected_palette_len = (size_t)palette_color_count * 4u;
    if (image_bitmap_len != expected_bitmap_len ||
        image_palette_len != expected_palette_len ||
        (rdp_composited_pixel_format_palettized(format) && palette_color_count == 0) ||
        (!rdp_composited_pixel_format_palettized(format) && palette_color_count != 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, width);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, format);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, stride);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, palette_color_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_u64(&payload, dpi_x_bits);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_u64(&payload, dpi_y_bits);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&payload, image_bitmap, image_bitmap_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&payload, image_palette, image_palette_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer,
                                                      RDP_COMPOSITED_CMD_BITMAP_PIXELS,
                                                      payload.data,
                                                      payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_bitmap_compressed_pixels(
    const void* data,
    size_t length,
    rdp_composited_bitmap_compressed_pixels* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 0x1cu || !rdp_composited_aligned_size(length))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != RDP_COMPOSITED_CMD_BITMAP_COMPRESSED_PIXELS ||
        order->header.payload_len < 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_composited_read_u64(&stream, &order->dpi_x_bits) != LIBRDP_STATUS_OK ||
        rdp_composited_read_u64(&stream, &order->dpi_y_bits) != LIBRDP_STATUS_OK ||
        order->target_resource == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    order->compressed_image_bitmap_len = rdp_stream_remaining(&stream);
    if (order->compressed_image_bitmap_len == 0 ||
        rdp_stream_read_bytes(&stream,
                              &order->compressed_image_bitmap,
                              order->compressed_image_bitmap_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_bitmap_compressed_pixels(rdp_buffer* buffer,
                                                           uint32_t target_resource,
                                                           uint64_t dpi_x_bits,
                                                           uint64_t dpi_y_bits,
                                                           const void* compressed_image_bitmap,
                                                           size_t compressed_image_bitmap_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || target_resource == 0 || !compressed_image_bitmap ||
        compressed_image_bitmap_len == 0 || !rdp_composited_aligned_size(compressed_image_bitmap_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_u64(&payload, dpi_x_bits);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_u64(&payload, dpi_y_bits);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&payload, compressed_image_bitmap, compressed_image_bitmap_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer,
                                                      RDP_COMPOSITED_CMD_BITMAP_COMPRESSED_PIXELS,
                                                      payload.data,
                                                      payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_target_capture_bits(
    const void* data,
    size_t length,
    rdp_composited_target_capture_bits* order)
{
    rdp_stream stream;
    const uint8_t* unused = NULL;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 40u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != RDP_COMPOSITED_CMD_TARGET_CAPTURE_BITS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->x) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->y) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->height) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->dxgi_format) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &unused, 8u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_target_capture_bits(rdp_buffer* buffer,
                                                       uint32_t target_resource,
                                                       uint32_t x,
                                                       uint32_t y,
                                                       uint32_t width,
                                                       uint32_t height,
                                                       uint32_t dxgi_format)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, x);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, y);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, width);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, dxgi_format);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_zeroes(&payload, 8u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer,
                                                      RDP_COMPOSITED_CMD_TARGET_CAPTURE_BITS,
                                                      payload.data,
                                                      payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_composited_parse_meta_capture_bits(const void* data,
                                                     size_t length,
                                                     rdp_composited_meta_capture_bits* order)
{
    rdp_stream stream;
    const uint8_t* unused = NULL;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 76u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != RDP_COMPOSITED_CMD_META_TARGET_CAPTURE_BITS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->height) != LIBRDP_STATUS_OK ||
        rdp_composited_read_u64(&stream, &order->update_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->include_cursors) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &unused, 4u) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &order->update_param, 40u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    order->update_param_len = 40u;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_meta_capture_bits(rdp_buffer* buffer,
                                                     uint32_t target_resource,
                                                     uint32_t width,
                                                     uint32_t height,
                                                     uint64_t update_id,
                                                     uint32_t include_cursors,
                                                     const uint8_t update_param[40])
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;
    static const uint8_t zero_update_param[40] = {0};

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!update_param)
        update_param = zero_update_param;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, width);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_u64(&payload, update_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, include_cursors);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&payload, update_param, 40u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer,
                                                      RDP_COMPOSITED_CMD_META_TARGET_CAPTURE_BITS,
                                                      payload.data,
                                                      payload.length);
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

librdp_status rdp_composited_parse_gdi_dirty(const void* data,
                                             size_t length,
                                             rdp_composited_gdi_dirty* order)
{
    rdp_stream stream;
    uint32_t flags = 0;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 24u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_composited_parse_channel_message(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.control_code != RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_NOTIFY_DIRTY)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, order->header.payload, order->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &order->target_resource) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &flags) != LIBRDP_STATUS_OK ||
        rdp_composited_read_u64(&stream, &order->notification_cookie) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    order->dirty_flags = (int32_t)flags;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_composited_write_gdi_dirty(rdp_buffer* buffer,
                                             uint32_t target_resource,
                                             int32_t dirty_flags,
                                             uint64_t notification_cookie)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, target_resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, (uint32_t)dirty_flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_u64(&payload, notification_cookie);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(buffer,
                                                      RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_NOTIFY_DIRTY,
                                                      payload.data,
                                                      payload.length);
    rdp_buffer_free(&payload);
    return status;
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
