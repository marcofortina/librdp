/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: RemoteFX stream container parser support.
 * Invariants: rectangles, strides, cache keys, and pixel formats are validated
 * before any surface mutation.
 * Ownership: decoded pixels and cache entries are owned by the caller or
 * session surface selected by the API.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: codec payloads, rectangles, and cache references are
 * untrusted server data.
 */


#include "graphics/rfx_stream.h"

#include "common/stream.h"
#include "common/trace.h"

#include <stdlib.h>
#include <string.h>

#define RDP_RFX_WBT_SYNC 0xCCC0u
#define RDP_RFX_WBT_CODEC_VERSIONS 0xCCC1u
#define RDP_RFX_WBT_CHANNELS 0xCCC2u
#define RDP_RFX_WBT_CONTEXT 0xCCC3u
#define RDP_RFX_WBT_FRAME_BEGIN 0xCCC4u
#define RDP_RFX_WBT_FRAME_END 0xCCC5u
#define RDP_RFX_WBT_REGION 0xCCC6u
#define RDP_RFX_WBT_EXTENSION 0xCCC7u
#define RDP_RFX_CBT_REGION 0xCAC1u
#define RDP_RFX_CBT_TILESET 0xCAC2u
#define RDP_RFX_CBT_TILE 0xCAC3u
#define RDP_RFX_MAGIC 0xCACCACCAu
#define RDP_RFX_VERSION_1_0 0x0100u
#define RDP_RFX_CODEC_ID 0x01u
#define RDP_RFX_CONTEXT_CHANNEL 0xFFu
#define RDP_RFX_DATA_CHANNEL 0x00u
#define RDP_RFX_ENTROPY_MASK 0x1E00u
#define RDP_RFX_ENTROPY_SHIFT 9u
#define RDP_RFX_ENTROPY_RLGR1 0x01u
#define RDP_RFX_ENTROPY_RLGR3 0x04u

typedef struct rdp_rfx_stream_state
{
    rdp_rfx_stream_summary summary;
    rdp_rfx_component_quant quants[RDP_RFX_STREAM_MAX_QUANTS];
    uint8_t quant_count;
    uint8_t frame_active;
    uint8_t region_active;
    uint16_t regions_completed;
} rdp_rfx_stream_state;

typedef struct rdp_rfx_stream_pending_tiles
{
    rdp_rfx_stream_tile* tiles;
    size_t count;
    size_t capacity;
} rdp_rfx_stream_pending_tiles;

static void rdp_rfx_stream_pending_free(rdp_rfx_stream_pending_tiles* pending)
{
    if (!pending)
        return;
    free(pending->tiles);
    pending->tiles = NULL;
    pending->count = 0;
    pending->capacity = 0;
}

static librdp_status rdp_rfx_stream_pending_append(rdp_rfx_stream_pending_tiles* pending,
                                                   const rdp_rfx_stream_tile* tile)
{
    rdp_rfx_stream_tile* next = NULL;
    size_t next_capacity = 0;

    if (!pending || !tile)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (pending->count >= RDP_RFX_STREAM_MAX_TILES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (pending->count == pending->capacity)
    {
        next_capacity = pending->capacity == 0 ? 8u : pending->capacity * 2u;
        if (next_capacity > RDP_RFX_STREAM_MAX_TILES)
            next_capacity = RDP_RFX_STREAM_MAX_TILES;
        if (next_capacity <= pending->capacity ||
            next_capacity > SIZE_MAX / sizeof(pending->tiles[0]))
            return LIBRDP_STATUS_NO_MEMORY;
        next = (rdp_rfx_stream_tile*)realloc(pending->tiles,
                                             next_capacity * sizeof(pending->tiles[0]));
        if (!next)
            return LIBRDP_STATUS_NO_MEMORY;
        pending->tiles = next;
        pending->capacity = next_capacity;
    }
    pending->tiles[pending->count] = *tile;
    pending->count++;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_rfx_stream_require_consumed(const rdp_stream* stream)
{
    if (!stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_stream_remaining(stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_rfx_stream_parse_sync(rdp_rfx_stream_state* state, rdp_stream* stream)
{
    uint32_t magic = 0;
    uint16_t version = 0;

    if (!state || !stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (state->summary.sync_seen ||
        state->summary.codec_versions_seen ||
        state->summary.channels_seen ||
        state->summary.context_seen ||
        state->frame_active)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u32_le(stream, &magic) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &version) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (magic != RDP_RFX_MAGIC || version != RDP_RFX_VERSION_1_0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    state->summary.sync_seen = 1;
    return rdp_rfx_stream_require_consumed(stream);
}

static librdp_status rdp_rfx_stream_parse_codec_versions(rdp_rfx_stream_state* state,
                                                         rdp_stream* stream)
{
    uint8_t count = 0;
    uint8_t codec_id = 0;
    uint16_t version = 0;

    if (!state || !stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!state->summary.sync_seen ||
        state->summary.codec_versions_seen ||
        state->summary.channels_seen ||
        state->summary.context_seen ||
        state->frame_active)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u8(stream, &count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &codec_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &version) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (count != 1u || codec_id != RDP_RFX_CODEC_ID || version != RDP_RFX_VERSION_1_0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    state->summary.codec_versions_seen = 1;
    return rdp_rfx_stream_require_consumed(stream);
}

static librdp_status rdp_rfx_stream_parse_channels(rdp_rfx_stream_state* state, rdp_stream* stream)
{
    uint8_t count = 0;
    uint8_t i = 0;

    if (!state || !stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!state->summary.codec_versions_seen ||
        state->summary.channels_seen ||
        state->summary.context_seen ||
        state->frame_active)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u8(stream, &count) != LIBRDP_STATUS_OK || count == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(stream) < (size_t)count * 5u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < count; i++)
    {
        uint8_t channel_id = 0;
        uint16_t width = 0;
        uint16_t height = 0;

        if (rdp_stream_read_u8(stream, &channel_id) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(stream, &width) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(stream, &height) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (width == 0 || height == 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (i == 0)
        {
            if (channel_id != RDP_RFX_DATA_CHANNEL)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            state->summary.width = width;
            state->summary.height = height;
        }
    }
    state->summary.channels_seen = 1;
    return rdp_rfx_stream_require_consumed(stream);
}

static librdp_status rdp_rfx_stream_parse_context(rdp_rfx_stream_state* state, rdp_stream* stream)
{
    uint8_t context_id = 0;
    uint16_t tile_size = 0;
    uint16_t properties = 0;
    uint16_t entropy = 0;

    if (!state || !stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!state->summary.channels_seen ||
        state->summary.context_seen ||
        state->frame_active)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u8(stream, &context_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &tile_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &properties) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    entropy = (uint16_t)((properties & RDP_RFX_ENTROPY_MASK) >> RDP_RFX_ENTROPY_SHIFT);
    if (context_id != 0 || tile_size != RDP_RFX_STREAM_TILE_SIZE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (entropy == RDP_RFX_ENTROPY_RLGR1)
        state->summary.mode = RDP_RFX_RLGR1;
    else if (entropy == RDP_RFX_ENTROPY_RLGR3)
        state->summary.mode = RDP_RFX_RLGR3;
    else
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    state->summary.context_seen = 1;
    return rdp_rfx_stream_require_consumed(stream);
}

static int rdp_rfx_stream_headers_seen(const rdp_rfx_stream_state* state)
{
    return state &&
           state->summary.sync_seen &&
           state->summary.codec_versions_seen &&
           state->summary.channels_seen &&
           state->summary.context_seen;
}

static librdp_status rdp_rfx_stream_parse_frame_begin(rdp_rfx_stream_state* state,
                                                      rdp_stream* stream)
{
    uint16_t region_count = 0;

    if (!state || !stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_rfx_stream_headers_seen(state) || state->frame_active)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u32_le(stream, &state->summary.frame_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &region_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (region_count == 0 || (uint32_t)region_count > RDP_RFX_STREAM_MAX_REGIONS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    state->summary.region_count = region_count;
    state->summary.rect_count = 0;
    state->summary.tile_count = 0;
    state->summary.frame_end_seen = 0;
    state->frame_active = 1;
    state->region_active = 0;
    state->regions_completed = 0;
    return rdp_rfx_stream_require_consumed(stream);
}

/*
 * Parse a RemoteFX region block and replace the current region state. Rectangle
 * count and bounds validation happen before state mutation so malformed
 * streams cannot leak stale region rectangles into tile decode.
 */
static librdp_status rdp_rfx_stream_parse_region(rdp_rfx_stream_state* state, rdp_stream* stream)
{
    uint8_t flags = 0;
    uint16_t rect_count = 0;
    uint16_t i = 0;
    uint16_t region_type = 0;
    uint16_t tile_set_count = 0;

    if (!state || !stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!state->frame_active || state->region_active)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (state->regions_completed >= state->summary.region_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u8(stream, &flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &rect_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    (void)flags;
    if (rect_count == 0 || (uint32_t)rect_count > RDP_RFX_STREAM_MAX_RECTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(stream) < (size_t)rect_count * 8u + 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < rect_count; i++)
    {
        uint16_t x = 0;
        uint16_t y = 0;
        uint16_t width = 0;
        uint16_t height = 0;

        if (rdp_stream_read_u16_le(stream, &x) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(stream, &y) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(stream, &width) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(stream, &height) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (width == 0 || height == 0 ||
            x > state->summary.width || y > state->summary.height ||
            width > (uint16_t)(state->summary.width - x) ||
            height > (uint16_t)(state->summary.height - y))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if ((uint32_t)rect_count > RDP_RFX_STREAM_MAX_RECTS - state->summary.rect_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    state->summary.rect_count = (uint16_t)(state->summary.rect_count + rect_count);
    if (rdp_stream_read_u16_le(stream, &region_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &tile_set_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (region_type != RDP_RFX_CBT_REGION || tile_set_count != 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    state->region_active = 1;
    return rdp_rfx_stream_require_consumed(stream);
}

/*
 * Decode one RemoteFX tile using the current channel, quant, and region state.
 * Tile coordinates and coefficient payloads are validated before pixels are
 * appended to the output buffer.
 */
static librdp_status rdp_rfx_stream_decode_tile(rdp_rfx_stream_state* state,
                                                rdp_stream* stream,
                                                rdp_rfx_stream_tile* tile)
{
    uint16_t block_type = 0;
    uint32_t block_len = 0;
    uint8_t quant_y = 0;
    uint8_t quant_cb = 0;
    uint8_t quant_cr = 0;
    uint16_t y_len = 0;
    uint16_t cb_len = 0;
    uint16_t cr_len = 0;
    const uint8_t* y_data = NULL;
    const uint8_t* cb_data = NULL;
    const uint8_t* cr_data = NULL;
    rdp_stream tile_stream;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!state || !stream || !tile)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_remaining(stream) < 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u16_le(stream, &block_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &block_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (block_type != RDP_RFX_CBT_TILE || block_len < 19u || block_len - 6u > rdp_stream_remaining(stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&tile_stream, stream->data + stream->position, block_len - 6u);
    if (rdp_stream_skip(stream, block_len - 6u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(tile, 0, sizeof(*tile));
    if (rdp_stream_read_u8(&tile_stream, &quant_y) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&tile_stream, &quant_cb) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&tile_stream, &quant_cr) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&tile_stream, &tile->x_idx) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&tile_stream, &tile->y_idx) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&tile_stream, &y_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&tile_stream, &cb_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&tile_stream, &cr_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (quant_y >= state->quant_count || quant_cb >= state->quant_count || quant_cr >= state->quant_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&tile_stream, &y_data, y_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&tile_stream, &cb_data, cb_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&tile_stream, &cr_data, cr_len) != LIBRDP_STATUS_OK ||
        rdp_rfx_stream_require_consumed(&tile_stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    tile->x = (uint32_t)tile->x_idx * RDP_RFX_STREAM_TILE_SIZE;
    tile->y = (uint32_t)tile->y_idx * RDP_RFX_STREAM_TILE_SIZE;
    if (tile->x >= state->summary.width || tile->y >= state->summary.height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    tile->width = state->summary.width - tile->x;
    tile->height = state->summary.height - tile->y;
    if (tile->width > RDP_RFX_STREAM_TILE_SIZE)
        tile->width = RDP_RFX_STREAM_TILE_SIZE;
    if (tile->height > RDP_RFX_STREAM_TILE_SIZE)
        tile->height = RDP_RFX_STREAM_TILE_SIZE;

    status = rdp_rfx_decode_tile(state->summary.mode,
                                 y_data,
                                 y_len,
                                 cb_data,
                                 cb_len,
                                 cr_data,
                                 cr_len,
                                 &state->quants[quant_y],
                                 &state->quants[quant_cb],
                                 &state->quants[quant_cr],
                                 &tile->pixels);
    return status;
}

/*
 * Parse a RemoteFX tileset block and decode each contained tile. The function
 * enforces quant-table, channel, tile-count, and payload-length invariants so
 * truncated tilesets fail without partial region output.
 */
static librdp_status rdp_rfx_stream_parse_tileset(rdp_rfx_stream_state* state,
                                                  rdp_stream* stream,
                                                  rdp_rfx_stream_pending_tiles* pending)
{
    uint16_t subtype = 0;
    uint16_t index = 0;
    uint16_t properties = 0;
    uint8_t quant_count = 0;
    uint8_t tile_size = 0;
    uint16_t tile_count = 0;
    uint32_t tile_data_size = 0;
    uint16_t i = 0;
    rdp_stream tile_data_stream;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!state || !stream || !pending)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!state->region_active)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u16_le(stream, &subtype) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &index) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &properties) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &quant_count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &tile_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &tile_count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &tile_data_size) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    (void)properties;
    if (subtype != RDP_RFX_CBT_TILESET ||
        index != 0 ||
        quant_count == 0 ||
        quant_count > RDP_RFX_STREAM_MAX_QUANTS ||
        tile_size != RDP_RFX_STREAM_TILE_SIZE ||
        tile_count == 0 ||
        tile_count > RDP_RFX_STREAM_MAX_TILES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(stream) < (size_t)quant_count * 5u ||
        tile_data_size > rdp_stream_remaining(stream) - ((size_t)quant_count * 5u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    state->quant_count = quant_count;
    for (i = 0; i < quant_count; i++)
    {
        const uint8_t* quant = NULL;

        if (rdp_stream_read_bytes(stream, &quant, 5u) != LIBRDP_STATUS_OK ||
            rdp_rfx_parse_component_quant(quant, 5u, &state->quants[i]) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    rdp_stream_init(&tile_data_stream, stream->data + stream->position, tile_data_size);
    if (rdp_stream_skip(stream, tile_data_size) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    for (i = 0; i < tile_count; i++)
    {
        rdp_rfx_stream_tile tile;

        status = rdp_rfx_stream_decode_tile(state, &tile_data_stream, &tile);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_rfx_stream_pending_append(pending, &tile);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (state->summary.tile_count == UINT16_MAX)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        state->summary.tile_count++;
    }
    if (rdp_stream_remaining(&tile_data_stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    state->region_active = 0;
    state->regions_completed++;
    return rdp_rfx_stream_require_consumed(stream);
}

static librdp_status rdp_rfx_stream_parse_frame_end(rdp_rfx_stream_state* state, rdp_stream* stream)
{
    if (!state || !stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!state->frame_active || state->region_active ||
        state->regions_completed != state->summary.region_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    state->frame_active = 0;
    state->summary.frame_end_seen = 1;
    return rdp_rfx_stream_require_consumed(stream);
}

static librdp_status rdp_rfx_stream_read_channel_prefix(uint16_t block_type, rdp_stream* stream)
{
    uint8_t codec_id = 0;
    uint8_t channel_id = 0;

    if (!stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u8(stream, &codec_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &channel_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (codec_id != RDP_RFX_CODEC_ID)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (block_type == RDP_RFX_WBT_CONTEXT)
        return channel_id == RDP_RFX_CONTEXT_CHANNEL ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
    return channel_id == RDP_RFX_DATA_CHANNEL ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

/*
 * Decode a RemoteFX stream container into validated codec blocks. Block
 * lengths and tile references are checked before the codec consumes any
 * component payload.
 */
librdp_status rdp_rfx_stream_decode(const void* data,
                                    size_t length,
                                    rdp_rfx_stream_tile_callback callback,
                                    void* user,
                                    rdp_rfx_stream_summary* summary)
{
    rdp_stream input;
    rdp_rfx_stream_state state;
    rdp_rfx_stream_pending_tiles pending;
    size_t i = 0;
    librdp_status final_status = LIBRDP_STATUS_OK;

    if ((!data && length > 0) || !callback)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&state, 0, sizeof(state));
    memset(&pending, 0, sizeof(pending));
    state.summary.mode = RDP_RFX_RLGR1;
    if (length == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&input, data, length);
    while (rdp_stream_remaining(&input) > 0)
    {
        uint16_t block_type = 0;
        uint32_t block_len = 0;
        size_t payload_len = 0;
        rdp_stream block;
        librdp_status status = LIBRDP_STATUS_OK;

        if (rdp_stream_read_u16_le(&input, &block_type) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&input, &block_len) != LIBRDP_STATUS_OK)
        {
            final_status = LIBRDP_STATUS_PROTOCOL_ERROR;
            goto cleanup;
        }
        if (block_len < 6u || block_len - 6u > rdp_stream_remaining(&input))
        {
            final_status = LIBRDP_STATUS_PROTOCOL_ERROR;
            goto cleanup;
        }
        payload_len = block_len - 6u;
        rdp_stream_init(&block, input.data + input.position, payload_len);
        if (rdp_stream_skip(&input, payload_len) != LIBRDP_STATUS_OK)
        {
            final_status = LIBRDP_STATUS_PROTOCOL_ERROR;
            goto cleanup;
        }

        if (block_type >= RDP_RFX_WBT_CONTEXT && block_type <= RDP_RFX_WBT_EXTENSION)
        {
            status = rdp_rfx_stream_read_channel_prefix(block_type, &block);
            if (status != LIBRDP_STATUS_OK)
            {
                final_status = status;
                goto cleanup;
            }
        }

        switch (block_type)
        {
            case RDP_RFX_WBT_SYNC:
                status = rdp_rfx_stream_parse_sync(&state, &block);
                break;
            case RDP_RFX_WBT_CODEC_VERSIONS:
                status = rdp_rfx_stream_parse_codec_versions(&state, &block);
                break;
            case RDP_RFX_WBT_CHANNELS:
                status = rdp_rfx_stream_parse_channels(&state, &block);
                break;
            case RDP_RFX_WBT_CONTEXT:
                status = rdp_rfx_stream_parse_context(&state, &block);
                break;
            case RDP_RFX_WBT_FRAME_BEGIN:
                status = rdp_rfx_stream_parse_frame_begin(&state, &block);
                break;
            case RDP_RFX_WBT_REGION:
                status = rdp_rfx_stream_parse_region(&state, &block);
                break;
            case RDP_RFX_WBT_EXTENSION:
                status = rdp_rfx_stream_parse_tileset(&state, &block, &pending);
                break;
            case RDP_RFX_WBT_FRAME_END:
                status = rdp_rfx_stream_parse_frame_end(&state, &block);
                break;
            default:
                final_status = LIBRDP_STATUS_PROTOCOL_ERROR;
                goto cleanup;
        }
        if (status != LIBRDP_STATUS_OK)
        {
            final_status = status;
            goto cleanup;
        }
    }
    if (state.frame_active || state.region_active || !state.summary.frame_end_seen)
    {
        final_status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto cleanup;
    }
    for (i = 0; i < pending.count; i++)
    {
        final_status = callback(&pending.tiles[i], user);
        if (final_status != LIBRDP_STATUS_OK)
        {
            goto cleanup;
        }
    }
    if (summary)
        *summary = state.summary;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.graphics.rfx.stream",
                          "frame_id=%u width=%u height=%u rects=%u tiles=%u mode=%u",
                          state.summary.frame_id,
                          state.summary.width,
                          state.summary.height,
                          state.summary.rect_count,
                          state.summary.tile_count,
                          state.summary.mode);
cleanup:
    rdp_rfx_stream_pending_free(&pending);
    return final_status;
}
