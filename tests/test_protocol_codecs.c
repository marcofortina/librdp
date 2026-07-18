/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: focused protocol conformance suite.
 * Coverage: RemoteFX, planar, and NSCodec conformance vectors.
 * Bug classes: entropy decoding, quantization, tile state, plane bounds, truncation, and pixel conversion.
 * Determinism: all vectors and state are synthetic and remain local to this suite.
 */

#include "common/buffer.h"
#include "graphics/bitmap.h"
#include "graphics/nscodec.h"
#include "graphics/planar.h"
#include "graphics/rfx_codec.h"
#include "graphics/rfx_stream.h"
#include "protocol/slowpath.h"

#include <librdp/session.h>

#include <stdio.h>
#include <string.h>

#define PCHECK(expr)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

static int test_append_rfx_block(rdp_buffer* out, uint16_t block_type, const rdp_buffer* payload)
{
    uint32_t length = 0;

    if (!out || !payload || payload->length > UINT32_MAX - 6u)
        return 0;
    length = (uint32_t)payload->length + 6u;
    return rdp_buffer_append_u16_le(out, block_type) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u32_le(out, length) == LIBRDP_STATUS_OK &&
           rdp_buffer_append(out, payload->data, payload->length) == LIBRDP_STATUS_OK;
}
static int test_append_rfx_channel_block(rdp_buffer* out,
                                         uint16_t block_type,
                                         uint8_t channel_id,
                                         const rdp_buffer* payload)
{
    rdp_buffer wrapped;
    int ok = 0;

    if (!out || !payload)
        return 0;
    rdp_buffer_init(&wrapped);
    ok = rdp_buffer_append_u8(&wrapped, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&wrapped, channel_id) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&wrapped, payload->data, payload->length) == LIBRDP_STATUS_OK &&
         test_append_rfx_block(out, block_type, &wrapped);
    rdp_buffer_free(&wrapped);
    return ok;
}
typedef struct test_rfx_stream_capture
{
    uint16_t tiles;
    uint8_t first_b;
    uint8_t first_g;
    uint8_t first_r;
    uint8_t first_a;
} test_rfx_stream_capture;

static librdp_status test_rfx_stream_tile(const rdp_rfx_stream_tile* tile, void* user)
{
    test_rfx_stream_capture* capture = (test_rfx_stream_capture*)user;

    if (!tile || !capture || tile->width != 64u || tile->height != 64u || tile->pixels.stride != 64u * 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    capture->tiles++;
    capture->first_b = tile->pixels.bgra[0];
    capture->first_g = tile->pixels.bgra[1];
    capture->first_r = tile->pixels.bgra[2];
    capture->first_a = tile->pixels.bgra[3];
    return LIBRDP_STATUS_OK;
}
/*
 * Fixture: builds counted RemoteFX stream blocks with adjustable invalid
 * counts and quant indexes. It targets parser bounds, tile routing, and
 * progressive stream edge cases.
 */
static int test_build_rfx_stream_counted(rdp_buffer* out,
                                         uint8_t bad_quant_index,
                                         uint8_t channel_variant,
                                         uint16_t declared_regions,
                                         uint16_t tile_x_idx,
                                         uint16_t region_rect_count)
{
    rdp_buffer payload;
    rdp_buffer tile;
    rdp_buffer zeroes;
    int ok = 0;

    if (!out)
        return 0;
    rdp_buffer_init(&payload);
    rdp_buffer_init(&tile);
    rdp_buffer_init(&zeroes);

    ok = rdp_buffer_append_u32_le(&payload, 0xCACCACCAu) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0x0100u) == LIBRDP_STATUS_OK &&
         test_append_rfx_block(out, 0xCCC0u, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u8(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0x0100u) == LIBRDP_STATUS_OK &&
         test_append_rfx_block(out, 0xCCC1u, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u8(&payload, channel_variant ? 2u : 1u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 64) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 64) == LIBRDP_STATUS_OK;
    if (ok && channel_variant)
    {
        ok = rdp_buffer_append_u8(&payload, 1) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&payload, channel_variant == 2u ? 0u : 32u) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&payload, 32) == LIBRDP_STATUS_OK;
    }
    ok = ok && test_append_rfx_block(out, 0xCCC2u, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u8(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 64) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0x0200u) == LIBRDP_STATUS_OK &&
         test_append_rfx_channel_block(out, 0xCCC3u, 0xffu, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u32_le(&payload, 7) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, declared_regions) == LIBRDP_STATUS_OK &&
         test_append_rfx_channel_block(out, 0xCCC4u, 0, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u8(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, region_rect_count) == LIBRDP_STATUS_OK;
    if (ok && region_rect_count > 0)
    {
        ok = rdp_buffer_append_u16_le(&payload, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&payload, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&payload, 64) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&payload, 64) == LIBRDP_STATUS_OK;
    }
    ok = ok &&
         rdp_buffer_append_u16_le(&payload, 0xCAC1u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
         test_append_rfx_channel_block(out, 0xCCC6u, 0, &payload);

    ok = ok && rdp_rfx_rlgr_write_zeroes(&zeroes, RDP_RFX_TILE_COEFFICIENTS) == LIBRDP_STATUS_OK;
    ok = ok &&
         rdp_buffer_append_u16_le(&tile, 0xCAC3u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&tile, 6u + 13u + (uint32_t)zeroes.length * 3u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&tile, bad_quant_index ? 1 : 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&tile, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&tile, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&tile, tile_x_idx) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&tile, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&tile, (uint16_t)zeroes.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&tile, (uint16_t)zeroes.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&tile, (uint16_t)zeroes.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&tile, zeroes.data, zeroes.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&tile, zeroes.data, zeroes.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&tile, zeroes.data, zeroes.length) == LIBRDP_STATUS_OK;

    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u16_le(&payload, 0xCAC2u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 64) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&payload, (uint32_t)tile.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 0x11u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 0x11u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 0x11u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 0x11u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 0x11u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&payload, tile.data, tile.length) == LIBRDP_STATUS_OK &&
         test_append_rfx_channel_block(out, 0xCCC7u, 0, &payload);
    payload.length = 0;
    ok = ok && test_append_rfx_channel_block(out, 0xCCC5u, 0, &payload);

    rdp_buffer_free(&zeroes);
    rdp_buffer_free(&tile);
    rdp_buffer_free(&payload);
    return ok;
}
static int test_build_rfx_stream_ex(rdp_buffer* out, uint8_t bad_quant_index, uint8_t channel_variant)
{
    return test_build_rfx_stream_counted(out, bad_quant_index, channel_variant, 1, 0, 1);
}
static int test_build_rfx_stream(rdp_buffer* out, uint8_t bad_quant_index)
{
    return test_build_rfx_stream_ex(out, bad_quant_index, 0);
}
/*
 * Fixture: appends RemoteFX region and tile-set blocks with caller-controlled
 * metadata. It validates block length accounting and tile payload ownership in
 * codec tests.
 */
static int test_append_rfx_region_tileset(rdp_buffer* out,
                                          uint16_t rect_x,
                                          uint16_t rect_y,
                                          uint16_t rect_width,
                                          uint16_t rect_height,
                                          uint16_t tile_x_idx,
                                          uint16_t tile_y_idx)
{
    rdp_buffer payload;
    rdp_buffer tile;
    rdp_buffer zeroes;
    int ok = 0;

    if (!out)
        return 0;
    rdp_buffer_init(&payload);
    rdp_buffer_init(&tile);
    rdp_buffer_init(&zeroes);

    ok = rdp_buffer_append_u8(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, rect_x) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, rect_y) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, rect_width) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, rect_height) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0xCAC1u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
         test_append_rfx_channel_block(out, 0xCCC6u, 0, &payload);

    ok = ok && rdp_rfx_rlgr_write_zeroes(&zeroes, RDP_RFX_TILE_COEFFICIENTS) == LIBRDP_STATUS_OK;
    ok = ok &&
         rdp_buffer_append_u16_le(&tile, 0xCAC3u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&tile, 6u + 13u + (uint32_t)zeroes.length * 3u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&tile, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&tile, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&tile, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&tile, tile_x_idx) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&tile, tile_y_idx) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&tile, (uint16_t)zeroes.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&tile, (uint16_t)zeroes.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&tile, (uint16_t)zeroes.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&tile, zeroes.data, zeroes.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&tile, zeroes.data, zeroes.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&tile, zeroes.data, zeroes.length) == LIBRDP_STATUS_OK;

    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u16_le(&payload, 0xCAC2u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 64) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&payload, (uint32_t)tile.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 0x11u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 0x11u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 0x11u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 0x11u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 0x11u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&payload, tile.data, tile.length) == LIBRDP_STATUS_OK &&
         test_append_rfx_channel_block(out, 0xCCC7u, 0, &payload);

    rdp_buffer_free(&zeroes);
    rdp_buffer_free(&tile);
    rdp_buffer_free(&payload);
    return ok;
}
static int test_build_rfx_stream_multi_region(rdp_buffer* out)
{
    rdp_buffer payload;
    int ok = 0;

    if (!out)
        return 0;
    rdp_buffer_init(&payload);

    ok = rdp_buffer_append_u32_le(&payload, 0xCACCACCAu) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0x0100u) == LIBRDP_STATUS_OK &&
         test_append_rfx_block(out, 0xCCC0u, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u8(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0x0100u) == LIBRDP_STATUS_OK &&
         test_append_rfx_block(out, 0xCCC1u, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u8(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 128) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 64) == LIBRDP_STATUS_OK &&
         test_append_rfx_block(out, 0xCCC2u, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u8(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 64) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0x0200u) == LIBRDP_STATUS_OK &&
         test_append_rfx_channel_block(out, 0xCCC3u, 0xffu, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u32_le(&payload, 8) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 2) == LIBRDP_STATUS_OK &&
         test_append_rfx_channel_block(out, 0xCCC4u, 0, &payload);

    ok = ok && test_append_rfx_region_tileset(out, 0, 0, 64, 64, 0, 0);
    ok = ok && test_append_rfx_region_tileset(out, 64, 0, 64, 64, 1, 0);

    payload.length = 0;
    ok = ok && test_append_rfx_channel_block(out, 0xCCC5u, 0, &payload);
    rdp_buffer_free(&payload);
    return ok;
}
static int test_build_rfx_stream_region_mismatch(rdp_buffer* out)
{
    rdp_buffer payload;
    int ok = 0;

    if (!out)
        return 0;
    rdp_buffer_init(&payload);

    ok = rdp_buffer_append_u32_le(&payload, 0xCACCACCAu) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0x0100u) == LIBRDP_STATUS_OK &&
         test_append_rfx_block(out, 0xCCC0u, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u8(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0x0100u) == LIBRDP_STATUS_OK &&
         test_append_rfx_block(out, 0xCCC1u, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u8(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 128) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 64) == LIBRDP_STATUS_OK &&
         test_append_rfx_block(out, 0xCCC2u, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u8(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 64) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0x0200u) == LIBRDP_STATUS_OK &&
         test_append_rfx_channel_block(out, 0xCCC3u, 0xffu, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u32_le(&payload, 10) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
         test_append_rfx_channel_block(out, 0xCCC4u, 0, &payload);

    ok = ok && test_append_rfx_region_tileset(out, 0, 0, 64, 64, 1, 0);

    payload.length = 0;
    ok = ok && test_append_rfx_channel_block(out, 0xCCC5u, 0, &payload);
    rdp_buffer_free(&payload);
    return ok;
}
static int test_build_rfx_stream_many_rects(rdp_buffer* out)
{
    rdp_buffer payload;
    uint32_t i = 0;
    int ok = 0;

    if (!out)
        return 0;
    rdp_buffer_init(&payload);

    ok = rdp_buffer_append_u32_le(&payload, 0xCACCACCAu) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0x0100u) == LIBRDP_STATUS_OK &&
         test_append_rfx_block(out, 0xCCC0u, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u8(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0x0100u) == LIBRDP_STATUS_OK &&
         test_append_rfx_block(out, 0xCCC1u, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u8(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 64) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 64) == LIBRDP_STATUS_OK &&
         test_append_rfx_block(out, 0xCCC2u, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u8(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 64) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0x0200u) == LIBRDP_STATUS_OK &&
         test_append_rfx_channel_block(out, 0xCCC3u, 0xffu, &payload);
    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u32_le(&payload, 9) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
         test_append_rfx_channel_block(out, 0xCCC4u, 0, &payload);

    payload.length = 0;
    ok = ok &&
         rdp_buffer_append_u8(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, (uint16_t)(RDP_RFX_STREAM_MAX_RECTS + 1u)) == LIBRDP_STATUS_OK;
    for (i = 0; ok && i <= RDP_RFX_STREAM_MAX_RECTS; i++)
    {
        ok = rdp_buffer_append_u16_le(&payload, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&payload, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK;
    }
    ok = ok &&
         rdp_buffer_append_u16_le(&payload, 0xCAC1u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
         test_append_rfx_channel_block(out, 0xCCC6u, 0, &payload);

    rdp_buffer_free(&payload);
    return ok;
}

/*
 * Runs RemoteFX, planar, and NSCodec conformance vectors.
 */
int test_protocol_codec_vectors(void)
{
    const uint8_t rfx_rlgr1_run_positive[] = {0xd8};
    const uint8_t rfx_rlgr1_run_negative[] = {0xf8};
    const uint8_t rfx_rlgr1_gr_mode[] = {0x83, 0x80};
    const uint8_t rfx_rlgr3_pair[] = {0x87, 0xd0};
    const uint8_t rfx_quant_values[] = {0x10, 0x32, 0x54, 0x76, 0x98};
    const uint8_t rfx_progressive_quant_values[] = {
        0x64,
        0x11, 0x11, 0x11, 0x11, 0x11,
        0x22, 0x22, 0x22, 0x22, 0x22,
        0x33, 0x33, 0x33, 0x33, 0x33
    };
    const uint8_t rfx_bad_progressive_quant_values[] = {
        0x64,
        0x99, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    };
    const uint8_t rfx_bad_progressive_quality_values[] = {
        0x65,
        0x11, 0x11, 0x11, 0x11, 0x11,
        0x22, 0x22, 0x22, 0x22, 0x22,
        0x33, 0x33, 0x33, 0x33, 0x33
    };
    const uint8_t planar_no_alpha[] = {
        RDP_PLANAR_FORMAT_NO_ALPHA,
        0x10, 0x20,
        0x30, 0x40,
        0x50, 0x60
    };
    const uint8_t planar_alpha_padded[] = {
        0x00,
        0x7f, 0x80,
        0x11, 0x22,
        0x33, 0x44,
        0x55, 0x66,
        0x00
    };
    const uint8_t planar_ycocg_no_alpha[] = {
        RDP_PLANAR_FORMAT_NO_ALPHA | 0x01,
        100, 100,
        10, 0xf6,
        20, 0xec
    };
    const uint8_t planar_ycocg_alpha_padded[] = {
        0x01,
        0x7f,
        100,
        0,
        0,
        0
    };
    const uint8_t planar_ycocg_subsampled[] = {
        RDP_PLANAR_FORMAT_NO_ALPHA | RDP_PLANAR_FORMAT_CHROMA_SUBSAMPLING | 0x01,
        100, 100, 100,
        100, 100, 100,
        100, 100, 100,
        0, 10, 20, 30,
        0, 0, 0, 0
    };
    const uint8_t planar_rle_argb[] = {
        RDP_PLANAR_FORMAT_NO_ALPHA | RDP_PLANAR_FORMAT_RLE,
        0x20, 0x10, 0x20,
        0x20, 0x30, 0x40,
        0x20, 0x50, 0x60
    };
    const uint8_t planar_rle_delta[] = {
        RDP_PLANAR_FORMAT_NO_ALPHA | RDP_PLANAR_FORMAT_RLE,
        0x20, 10, 20,
        0x20, 9, 10,
        0x20, 30, 40,
        0x20, 0, 0,
        0x20, 50, 60,
        0x20, 0, 0
    };
    const uint8_t planar_rle_bad_zero_control[] = {
        RDP_PLANAR_FORMAT_NO_ALPHA | RDP_PLANAR_FORMAT_RLE,
        0x00
    };
    const uint8_t nscodec_capability_data[] = {1, 1, 7};
    const uint8_t nscodec_bad_capability_data[] = {1, 0, 0};
    const uint8_t nscodec_raw_argb[] = {
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        100, 10, 20, 0x7f
    };
    const uint8_t nscodec_subsampled_rle[] = {
        0x07, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x00,
        100, 100, 18, 100, 100, 100, 100,
        0, 0, 2, 0, 0, 0, 0,
        0, 0, 2, 0, 0, 0, 0
    };
    const uint8_t nscodec_rle_plane[] = {0x63, 0x63, 0x01, 0x64, 0x65, 0x65, 0x65};
    const uint8_t nscodec_invalid_stream[] = {
        0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        1, 0, 0
    };
    const uint8_t nscodec_bad_reserved[] = {
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00,
        100, 10, 20, 0x7f
    };
    const uint8_t nscodec_partial_plane_failure[] = {
        0x05, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        100, 100, 100, 100, 100,
        0xaa,
        0, 0, 0, 0, 0
    };
    const uint8_t planar_reserved[] = {0x80, 0, 0, 0};
    const uint8_t planar_subsample_without_loss[] = {RDP_PLANAR_FORMAT_CHROMA_SUBSAMPLING, 0, 0, 0};
    int32_t rfx_coefficients[8];
    int32_t rfx_component[RDP_RFX_TILE_COEFFICIENTS];
    int32_t rfx_y[RDP_RFX_TILE_COEFFICIENTS];
    int32_t rfx_cb[RDP_RFX_TILE_COEFFICIENTS];
    int32_t rfx_cr[RDP_RFX_TILE_COEFFICIENTS];
    uint8_t rfx_zero_rlgr[4];
    size_t rfx_written = 0;
    rdp_rfx_component_quant rfx_quant;
    rdp_rfx_component_quant rfx_decode_quant;
    rdp_rfx_progressive_quant rfx_progressive_quant;
    rdp_rfx_component_quant rfx_added_quant;
    rdp_rfx_component_quant rfx_bad_quant;
    rdp_rfx_component_quant rfx_zero_delta;
    rdp_rfx_tile_pixels rfx_pixels;
    rdp_rfx_tile_pixels rfx_upgrade_pixels;
    rdp_rfx_tile_pixels rfx_saved_upgrade_pixels;
    rdp_rfx_progressive_tile_state rfx_progressive_state;
    rdp_rfx_progressive_tile_state rfx_saved_state;
    rdp_rfx_stream_summary rfx_stream_summary;
    test_rfx_stream_capture rfx_stream_capture;
    rdp_nscodec_context nscodec_context;
    rdp_nscodec_stream nscodec_stream;
    rdp_nscodec_capability nscodec_capability;
    rdp_buffer graphics_decoded;
    rdp_buffer rfx_stream;
    rdp_buffer rfx_bad_stream;
    rdp_buffer planar_pixels;
    rdp_buffer nscodec_pixels;
    rdp_buffer nscodec_capability_buffer;
    rdp_buffer dyn_response;
    uint8_t planar_saved[16];
    size_t decoded_stride = 0;
    size_t planar_saved_len = 0;
    uint8_t nscodec_rle_decoded[24];
    uint8_t nscodec_region_dest[64];

    rdp_nscodec_context_init(&nscodec_context);
    rdp_nscodec_context_reset(&nscodec_context);
    rdp_buffer_init(&graphics_decoded);
    rdp_buffer_init(&rfx_stream);
    rdp_buffer_init(&rfx_bad_stream);
    rdp_buffer_init(&planar_pixels);
    rdp_buffer_init(&nscodec_pixels);
    rdp_buffer_init(&nscodec_capability_buffer);
    rdp_buffer_init(&dyn_response);

    PCHECK(rdp_rfx_rlgr_decode(RDP_RFX_RLGR1,
                               rfx_rlgr1_run_positive,
                               sizeof(rfx_rlgr1_run_positive),
                               rfx_coefficients,
                               2,
                               &rfx_written) == LIBRDP_STATUS_OK);
    PCHECK(rfx_written == 2 && rfx_coefficients[0] == 0 && rfx_coefficients[1] == 5);
    PCHECK(rdp_rfx_rlgr_decode(RDP_RFX_RLGR1,
                               rfx_rlgr1_run_negative,
                               sizeof(rfx_rlgr1_run_negative),
                               rfx_coefficients,
                               2,
                               &rfx_written) == LIBRDP_STATUS_OK);
    PCHECK(rfx_written == 2 && rfx_coefficients[0] == 0 && rfx_coefficients[1] == -5);
    PCHECK(rdp_rfx_rlgr_decode(RDP_RFX_RLGR1,
                               rfx_rlgr1_gr_mode,
                               sizeof(rfx_rlgr1_gr_mode),
                               rfx_coefficients,
                               3,
                               &rfx_written) == LIBRDP_STATUS_OK);
    PCHECK(rfx_written == 3 &&
           rfx_coefficients[0] == 1 &&
           rfx_coefficients[1] == 0 &&
           rfx_coefficients[2] == -2);
    PCHECK(rdp_rfx_rlgr_decode(RDP_RFX_RLGR3,
                               rfx_rlgr3_pair,
                               sizeof(rfx_rlgr3_pair),
                               rfx_coefficients,
                               3,
                               &rfx_written) == LIBRDP_STATUS_OK);
    PCHECK(rfx_written == 3 &&
           rfx_coefficients[0] == 1 &&
           rfx_coefficients[1] == 2 &&
           rfx_coefficients[2] == -1);
    PCHECK(rdp_rfx_rlgr_decode(RDP_RFX_RLGR1,
                               rfx_rlgr1_gr_mode,
                               1,
                               rfx_coefficients,
                               3,
                               &rfx_written) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_rfx_rlgr_decode((rdp_rfx_rlgr_mode)2,
                               rfx_rlgr1_gr_mode,
                               sizeof(rfx_rlgr1_gr_mode),
                               rfx_coefficients,
                               3,
                               &rfx_written) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_rfx_parse_component_quant(rfx_quant_values,
                                         sizeof(rfx_quant_values),
                                         &rfx_quant) == LIBRDP_STATUS_OK);
    PCHECK(rfx_quant.ll3 == 0 &&
           rfx_quant.hl3 == 1 &&
           rfx_quant.lh3 == 2 &&
           rfx_quant.hh3 == 3 &&
           rfx_quant.hl2 == 4 &&
           rfx_quant.lh2 == 5 &&
           rfx_quant.hh2 == 6 &&
           rfx_quant.hl1 == 7 &&
           rfx_quant.lh1 == 8 &&
           rfx_quant.hh1 == 9);
    rdp_buffer_free(&graphics_decoded);
    rdp_buffer_init(&graphics_decoded);
    PCHECK(rdp_rfx_write_component_quant(&graphics_decoded, &rfx_quant) == LIBRDP_STATUS_OK);
    PCHECK(graphics_decoded.length == sizeof(rfx_quant_values));
    PCHECK(rdp_rfx_parse_component_quant(graphics_decoded.data,
                                         graphics_decoded.length,
                                         &rfx_decode_quant) == LIBRDP_STATUS_OK);
    PCHECK(rfx_decode_quant.ll3 == rfx_quant.ll3 &&
           rfx_decode_quant.hl3 == rfx_quant.hl3 &&
           rfx_decode_quant.hh1 == rfx_quant.hh1);
    PCHECK(rdp_rfx_parse_progressive_quant(rfx_progressive_quant_values,
                                           sizeof(rfx_progressive_quant_values),
                                           &rfx_progressive_quant) == LIBRDP_STATUS_OK);
    PCHECK(rfx_progressive_quant.quality == 0x64 &&
           rfx_progressive_quant.y.ll3 == 1 &&
           rfx_progressive_quant.cb.ll3 == 2 &&
           rfx_progressive_quant.cr.ll3 == 3);
    rdp_buffer_free(&graphics_decoded);
    rdp_buffer_init(&graphics_decoded);
    PCHECK(rdp_rfx_write_progressive_quant(&graphics_decoded, &rfx_progressive_quant) == LIBRDP_STATUS_OK);
    PCHECK(graphics_decoded.length == sizeof(rfx_progressive_quant_values));
    PCHECK(rdp_rfx_parse_progressive_quant(graphics_decoded.data,
                                           graphics_decoded.length,
                                           &rfx_progressive_quant) == LIBRDP_STATUS_OK);
    PCHECK(rfx_progressive_quant.quality == 0x64 &&
           rfx_progressive_quant.y.ll3 == 1 &&
           rfx_progressive_quant.cb.ll3 == 2 &&
           rfx_progressive_quant.cr.ll3 == 3);
    {
        rdp_rfx_progressive_quant valid_progressive_quant = rfx_progressive_quant;

        PCHECK(rdp_rfx_parse_progressive_quant(rfx_bad_progressive_quant_values,
                                               sizeof(rfx_bad_progressive_quant_values),
                                               &rfx_progressive_quant) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&rfx_progressive_quant,
                      &valid_progressive_quant,
                      sizeof(rfx_progressive_quant)) == 0);
        PCHECK(rdp_rfx_parse_progressive_quant(rfx_bad_progressive_quality_values,
                                               sizeof(rfx_bad_progressive_quality_values),
                                               &rfx_progressive_quant) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&rfx_progressive_quant,
                      &valid_progressive_quant,
                      sizeof(rfx_progressive_quant)) == 0);
    }
    rfx_decode_quant = rfx_quant;
    rfx_decode_quant.ll3 = 16;
    graphics_decoded.length = 0;
    PCHECK(rdp_buffer_append_u8(&graphics_decoded, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_rfx_write_component_quant(&graphics_decoded, &rfx_decode_quant) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(graphics_decoded.length == 1u && graphics_decoded.data[0] == 0xa5u);
    rdp_buffer_free(&graphics_decoded);
    rdp_buffer_init(&graphics_decoded);
    PCHECK(rdp_rfx_add_component_quant(&rfx_quant,
                                       &rfx_progressive_quant.y,
                                       &rfx_added_quant) == LIBRDP_STATUS_OK);
    PCHECK(rfx_added_quant.ll3 == 1 &&
           rfx_added_quant.hl3 == 2 &&
           rfx_added_quant.hh1 == 10);
    PCHECK(rdp_rfx_add_component_quant(&rfx_quant,
                                       &rfx_progressive_quant.cr,
                                       &rfx_added_quant) == LIBRDP_STATUS_OK);
    PCHECK(rfx_added_quant.hh1 == 12);
    rfx_progressive_quant.cr.hh1 = 8;
    PCHECK(rdp_rfx_add_component_quant(&rfx_quant,
                                       &rfx_progressive_quant.cr,
                                       &rfx_added_quant) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rfx_progressive_quant.quality = 101u;
    PCHECK(rdp_buffer_append_u8(&graphics_decoded, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_rfx_write_progressive_quant(&graphics_decoded,
                                           &rfx_progressive_quant) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(graphics_decoded.length == 1u && graphics_decoded.data[0] == 0xa5u);
    rfx_progressive_quant.quality = 100u;
    {
        rdp_rfx_component_quant valid_component_quant = rfx_quant;

        PCHECK(rdp_rfx_parse_component_quant(rfx_quant_values,
                                             sizeof(rfx_quant_values) - 1u,
                                             &rfx_quant) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&rfx_quant, &valid_component_quant, sizeof(rfx_quant)) == 0);
    }
    rfx_component[0] = 1;
    rfx_component[1] = 2;
    rfx_component[2] = -4;
    PCHECK(rdp_rfx_differential_decode(rfx_component, 3) == LIBRDP_STATUS_OK);
    PCHECK(rfx_component[0] == 1 && rfx_component[1] == 3 && rfx_component[2] == -1);
    memset(rfx_component, 0, sizeof(rfx_component));
    memset(&rfx_decode_quant, 0, sizeof(rfx_decode_quant));
    rfx_decode_quant.ll3 = 4;
    rfx_decode_quant.hl3 = 1;
    rfx_decode_quant.lh3 = 1;
    rfx_decode_quant.hh3 = 1;
    rfx_decode_quant.hl2 = 1;
    rfx_decode_quant.lh2 = 1;
    rfx_decode_quant.hh2 = 1;
    rfx_decode_quant.hl1 = 3;
    rfx_decode_quant.lh1 = 2;
    rfx_decode_quant.hh1 = 1;
    rfx_component[0] = 1;
    rfx_component[1024] = 1;
    rfx_component[4032] = 1;
    PCHECK(rdp_rfx_inverse_quantize(rfx_component,
                                    RDP_RFX_TILE_COEFFICIENTS,
                                    &rfx_decode_quant) == LIBRDP_STATUS_OK);
    PCHECK(rfx_component[0] == 4 && rfx_component[1024] == 2 && rfx_component[4032] == 8);
    PCHECK(rdp_rfx_inverse_quantize(rfx_component,
                                    RDP_RFX_TILE_COEFFICIENTS - 1u,
                                    &rfx_decode_quant) == LIBRDP_STATUS_PROTOCOL_ERROR);
    memset(rfx_component, 0, sizeof(rfx_component));
    PCHECK(rdp_rfx_inverse_dwt_2d(rfx_component, RDP_RFX_TILE_COEFFICIENTS) == LIBRDP_STATUS_OK);
    PCHECK(rfx_component[0] == 0 && rfx_component[RDP_RFX_TILE_COEFFICIENTS - 1u] == 0);
    memset(rfx_y, 0, sizeof(rfx_y));
    memset(rfx_cb, 0, sizeof(rfx_cb));
    memset(rfx_cr, 0, sizeof(rfx_cr));
    memset(&rfx_pixels, 0, sizeof(rfx_pixels));
    PCHECK(rdp_rfx_ycbcr_to_bgra(rfx_y, rfx_cb, rfx_cr, rfx_pixels.bgra, 64u * 4u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rfx_pixels.bgra[0] == 128 && rfx_pixels.bgra[1] == 128 &&
           rfx_pixels.bgra[2] == 128 && rfx_pixels.bgra[3] == 0xff);
    rfx_y[0] = -4096;
    PCHECK(rdp_rfx_ycbcr_to_bgra(rfx_y, rfx_cb, rfx_cr, rfx_pixels.bgra, 64u * 4u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rfx_pixels.bgra[0] == 0 && rfx_pixels.bgra[1] == 0 &&
           rfx_pixels.bgra[2] == 0 && rfx_pixels.bgra[3] == 0xff);
    rfx_zero_rlgr[0] = 0x00;
    rfx_zero_rlgr[1] = 0x00;
    rfx_zero_rlgr[2] = 0x08;
    rfx_zero_rlgr[3] = 0x08;
    rdp_buffer_free(&graphics_decoded);
    rdp_buffer_init(&graphics_decoded);
    PCHECK(rdp_rfx_rlgr_write_zeroes(&graphics_decoded,
                                     RDP_RFX_TILE_COEFFICIENTS) == LIBRDP_STATUS_OK);
    PCHECK(graphics_decoded.length == sizeof(rfx_zero_rlgr) &&
           memcmp(graphics_decoded.data, rfx_zero_rlgr, sizeof(rfx_zero_rlgr)) == 0);
    PCHECK(rdp_rfx_rlgr_decode(RDP_RFX_RLGR1,
                               graphics_decoded.data,
                               graphics_decoded.length,
                               rfx_component,
                               RDP_RFX_TILE_COEFFICIENTS,
                               &rfx_written) == LIBRDP_STATUS_OK);
    PCHECK(rfx_written == RDP_RFX_TILE_COEFFICIENTS &&
           rfx_component[0] == 0 &&
           rfx_component[RDP_RFX_TILE_COEFFICIENTS - 1u] == 0);
    PCHECK(rdp_rfx_rlgr_decode(RDP_RFX_RLGR3,
                               graphics_decoded.data,
                               graphics_decoded.length,
                               rfx_component,
                               RDP_RFX_TILE_COEFFICIENTS,
                               &rfx_written) == LIBRDP_STATUS_OK);
    PCHECK(rfx_written == RDP_RFX_TILE_COEFFICIENTS);
    rdp_buffer_free(&graphics_decoded);
    rdp_buffer_init(&graphics_decoded);
    PCHECK(rdp_rfx_rlgr_write_zeroes(&graphics_decoded, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_rfx_rlgr_decode(RDP_RFX_RLGR1,
                               graphics_decoded.data,
                               graphics_decoded.length,
                               rfx_coefficients,
                               2,
                               &rfx_written) == LIBRDP_STATUS_OK);
    PCHECK(rfx_written == 2 && rfx_coefficients[0] == 0 && rfx_coefficients[1] == 0);
    PCHECK(rdp_rfx_rlgr_write_zeroes(NULL, 2) == LIBRDP_STATUS_INVALID_ARGUMENT);
    graphics_decoded.length = 0;
    memset(&rfx_decode_quant, 0, sizeof(rfx_decode_quant));
    rfx_decode_quant.ll3 = 1;
    rfx_decode_quant.hl3 = 1;
    rfx_decode_quant.lh3 = 1;
    rfx_decode_quant.hh3 = 1;
    rfx_decode_quant.hl2 = 1;
    rfx_decode_quant.lh2 = 1;
    rfx_decode_quant.hh2 = 1;
    rfx_decode_quant.hl1 = 1;
    rfx_decode_quant.lh1 = 1;
    rfx_decode_quant.hh1 = 1;
    PCHECK(rdp_rfx_decode_progressive_tile(rfx_zero_rlgr,
                                           sizeof(rfx_zero_rlgr),
                                           rfx_zero_rlgr,
                                           sizeof(rfx_zero_rlgr),
                                           rfx_zero_rlgr,
                                           sizeof(rfx_zero_rlgr),
                                           &rfx_decode_quant,
                                           &rfx_decode_quant,
                                           &rfx_decode_quant,
                                           0,
                                           &rfx_pixels) == LIBRDP_STATUS_OK);
    PCHECK(rfx_pixels.stride == 64u * 4u &&
           rfx_pixels.bgra[0] == 128 &&
           rfx_pixels.bgra[1] == 128 &&
           rfx_pixels.bgra[2] == 128 &&
           rfx_pixels.bgra[3] == 0xff);
    PCHECK(rdp_rfx_decode_progressive_tile(rfx_zero_rlgr,
                                           sizeof(rfx_zero_rlgr),
                                           rfx_zero_rlgr,
                                           sizeof(rfx_zero_rlgr),
                                           rfx_zero_rlgr,
                                           sizeof(rfx_zero_rlgr),
                                           &rfx_decode_quant,
                                           &rfx_decode_quant,
                                           &rfx_decode_quant,
                                           1,
                                           &rfx_pixels) == LIBRDP_STATUS_OK);
    PCHECK(rfx_pixels.bgra[0] == 128 &&
           rfx_pixels.bgra[(63u * 64u * 4u) + (63u * 4u)] == 128);
    rfx_saved_upgrade_pixels = rfx_pixels;
    rfx_pixels.stride = 0x7777u;
    rfx_pixels.bgra[0] = 0x5au;
    PCHECK(rdp_rfx_decode_tile(RDP_RFX_RLGR1,
                               rfx_zero_rlgr,
                               1,
                               rfx_zero_rlgr,
                               sizeof(rfx_zero_rlgr),
                               rfx_zero_rlgr,
                               sizeof(rfx_zero_rlgr),
                               &rfx_decode_quant,
                               &rfx_decode_quant,
                               &rfx_decode_quant,
                               &rfx_pixels) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rfx_pixels.stride == 0x7777u && rfx_pixels.bgra[0] == 0x5au);
    rfx_pixels = rfx_saved_upgrade_pixels;
    memset(&rfx_zero_delta, 0, sizeof(rfx_zero_delta));
    memset(&rfx_progressive_state, 0, sizeof(rfx_progressive_state));
    memset(&rfx_upgrade_pixels, 0, sizeof(rfx_upgrade_pixels));
    PCHECK(rdp_rfx_decode_progressive_tile_state(rfx_zero_rlgr,
                                                 sizeof(rfx_zero_rlgr),
                                                 rfx_zero_rlgr,
                                                 sizeof(rfx_zero_rlgr),
                                                 rfx_zero_rlgr,
                                                 sizeof(rfx_zero_rlgr),
                                                 &rfx_decode_quant,
                                                 &rfx_zero_delta,
                                                 &rfx_decode_quant,
                                                 &rfx_zero_delta,
                                                 &rfx_decode_quant,
                                                 &rfx_zero_delta,
                                                 1,
                                                 0,
                                                 &rfx_progressive_state,
                                                 &rfx_pixels) == LIBRDP_STATUS_OK);
    PCHECK(rfx_progressive_state.valid &&
           rfx_progressive_state.y.valid &&
           rfx_progressive_state.cb.valid &&
           rfx_progressive_state.cr.valid &&
           rfx_progressive_state.pass == 1 &&
           rfx_progressive_state.extrapolate == 1);
    PCHECK(rdp_rfx_decode_progressive_upgrade_tile(NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   1,
                                                   &rfx_progressive_state,
                                                   &rfx_upgrade_pixels) == LIBRDP_STATUS_OK);
    PCHECK(rfx_progressive_state.pass == 2 &&
           rfx_upgrade_pixels.stride == 64u * 4u &&
           rfx_upgrade_pixels.bgra[0] == 128 &&
           rfx_upgrade_pixels.bgra[1] == 128 &&
           rfx_upgrade_pixels.bgra[2] == 128 &&
           rfx_upgrade_pixels.bgra[3] == 0xff);
    rfx_progressive_state.y.current[0] = 64;
    rfx_progressive_state.y.sign[0] = 1;
    PCHECK(rdp_rfx_decode_progressive_tile_state(rfx_zero_rlgr,
                                                 sizeof(rfx_zero_rlgr),
                                                 rfx_zero_rlgr,
                                                 sizeof(rfx_zero_rlgr),
                                                 rfx_zero_rlgr,
                                                 sizeof(rfx_zero_rlgr),
                                                 &rfx_decode_quant,
                                                 &rfx_zero_delta,
                                                 &rfx_decode_quant,
                                                 &rfx_zero_delta,
                                                 &rfx_decode_quant,
                                                 &rfx_zero_delta,
                                                 1,
                                                 1,
                                                 &rfx_progressive_state,
                                                 &rfx_pixels) == LIBRDP_STATUS_OK);
    PCHECK(rfx_progressive_state.pass == 3 &&
           rfx_progressive_state.y.current[0] == 64 &&
           rfx_progressive_state.y.sign[0] == 1);
    rfx_saved_state = rfx_progressive_state;
    rfx_saved_upgrade_pixels = rfx_pixels;
    rfx_bad_quant = rfx_decode_quant;
    rfx_bad_quant.ll3 = 0;
    rfx_pixels.stride = 0x8888u;
    rfx_pixels.bgra[0] = 0xa5u;
    PCHECK(rdp_rfx_decode_progressive_tile_state(rfx_zero_rlgr,
                                                 sizeof(rfx_zero_rlgr),
                                                 rfx_zero_rlgr,
                                                 sizeof(rfx_zero_rlgr),
                                                 rfx_zero_rlgr,
                                                 sizeof(rfx_zero_rlgr),
                                                 &rfx_bad_quant,
                                                 &rfx_zero_delta,
                                                 &rfx_decode_quant,
                                                 &rfx_zero_delta,
                                                 &rfx_decode_quant,
                                                 &rfx_zero_delta,
                                                 1,
                                                 1,
                                                 &rfx_progressive_state,
                                                 &rfx_pixels) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rfx_progressive_state.pass == rfx_saved_state.pass &&
           rfx_progressive_state.y.current[0] == rfx_saved_state.y.current[0] &&
           rfx_pixels.stride == 0x8888u &&
           rfx_pixels.bgra[0] == 0xa5u);
    rfx_pixels = rfx_saved_upgrade_pixels;
    rfx_saved_upgrade_pixels = rfx_upgrade_pixels;
    PCHECK(rdp_rfx_decode_progressive_upgrade_tile(NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   &rfx_bad_quant,
                                                   &rfx_zero_delta,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   1,
                                                   &rfx_progressive_state,
                                                   &rfx_upgrade_pixels) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rfx_progressive_state.pass == rfx_saved_state.pass &&
           rfx_progressive_state.y.current[0] == rfx_saved_state.y.current[0] &&
           rfx_progressive_state.y.sign[0] == rfx_saved_state.y.sign[0] &&
           memcmp(&rfx_upgrade_pixels, &rfx_saved_upgrade_pixels, sizeof(rfx_upgrade_pixels)) == 0);
    rfx_progressive_state.pass = UINT16_MAX;
    PCHECK(rdp_rfx_decode_progressive_upgrade_tile(NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   1,
                                                   &rfx_progressive_state,
                                                   &rfx_upgrade_pixels) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rfx_progressive_state.pass == UINT16_MAX);
    memset(&rfx_progressive_state, 0, sizeof(rfx_progressive_state));
    PCHECK(rdp_rfx_decode_progressive_upgrade_tile(NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   1,
                                                   &rfx_progressive_state,
                                                   &rfx_upgrade_pixels) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&rfx_stream);
    rdp_buffer_init(&rfx_stream);
    memset(&rfx_stream_summary, 0, sizeof(rfx_stream_summary));
    memset(&rfx_stream_capture, 0, sizeof(rfx_stream_capture));
    PCHECK(test_build_rfx_stream(&rfx_stream, 0));
    PCHECK(rdp_rfx_stream_decode(rfx_stream.data,
                                 rfx_stream.length,
                                 test_rfx_stream_tile,
                                 &rfx_stream_capture,
                                 &rfx_stream_summary) == LIBRDP_STATUS_OK);
    PCHECK(rfx_stream_summary.sync_seen &&
           rfx_stream_summary.codec_versions_seen &&
           rfx_stream_summary.channels_seen &&
           rfx_stream_summary.context_seen &&
           rfx_stream_summary.frame_end_seen &&
           rfx_stream_summary.frame_id == 7 &&
           rfx_stream_summary.width == 64 &&
           rfx_stream_summary.height == 64 &&
           rfx_stream_summary.rect_count == 1 &&
           rfx_stream_summary.tile_count == 1 &&
           rfx_stream_summary.mode == RDP_RFX_RLGR1);
    PCHECK(rfx_stream_capture.tiles == 1 &&
           rfx_stream_capture.first_b == 128 &&
           rfx_stream_capture.first_g == 128 &&
           rfx_stream_capture.first_r == 128 &&
           rfx_stream_capture.first_a == 0xff);
    rdp_buffer_free(&rfx_bad_stream);
    rdp_buffer_init(&rfx_bad_stream);
    memset(&rfx_stream_summary, 0, sizeof(rfx_stream_summary));
    memset(&rfx_stream_capture, 0, sizeof(rfx_stream_capture));
    PCHECK(test_build_rfx_stream_multi_region(&rfx_bad_stream));
    PCHECK(rdp_rfx_stream_decode(rfx_bad_stream.data,
                                 rfx_bad_stream.length,
                                 test_rfx_stream_tile,
                                 &rfx_stream_capture,
                                 &rfx_stream_summary) == LIBRDP_STATUS_OK);
    PCHECK(rfx_stream_summary.frame_id == 8 &&
           rfx_stream_summary.width == 128 &&
           rfx_stream_summary.height == 64 &&
           rfx_stream_summary.region_count == 2 &&
           rfx_stream_summary.rect_count == 2 &&
           rfx_stream_summary.tile_count == 2 &&
           rfx_stream_capture.tiles == 2);
    rdp_buffer_free(&rfx_bad_stream);
    rdp_buffer_init(&rfx_bad_stream);
    memset(&rfx_stream_capture, 0, sizeof(rfx_stream_capture));
    PCHECK(test_build_rfx_stream_region_mismatch(&rfx_bad_stream));
    PCHECK(rdp_rfx_stream_decode(rfx_bad_stream.data,
                                 rfx_bad_stream.length,
                                 test_rfx_stream_tile,
                                 &rfx_stream_capture,
                                 &rfx_stream_summary) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rfx_stream_capture.tiles == 0);
    rdp_buffer_free(&rfx_bad_stream);
    rdp_buffer_init(&rfx_bad_stream);
    dyn_response.length = 0;
    PCHECK(rdp_buffer_append(&rfx_bad_stream, rfx_stream.data, rfx_stream.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&dyn_response, 0xCACCACCAu) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&dyn_response, 0x0100u) == LIBRDP_STATUS_OK);
    PCHECK(test_append_rfx_block(&rfx_bad_stream, 0xCCC0u, &dyn_response));
    {
        rdp_rfx_stream_summary valid_rfx_summary = rfx_stream_summary;

        memset(&rfx_stream_capture, 0, sizeof(rfx_stream_capture));
        PCHECK(rdp_rfx_stream_decode(rfx_bad_stream.data,
                                     rfx_bad_stream.length,
                                     test_rfx_stream_tile,
                                     &rfx_stream_capture,
                                     &rfx_stream_summary) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(rfx_stream_capture.tiles == 0);
        PCHECK(memcmp(&rfx_stream_summary,
                      &valid_rfx_summary,
                      sizeof(rfx_stream_summary)) == 0);
    }
    dyn_response.length = 0;
    rdp_buffer_free(&rfx_bad_stream);
    rdp_buffer_init(&rfx_bad_stream);
    memset(&rfx_stream_capture, 0, sizeof(rfx_stream_capture));
    PCHECK(test_build_rfx_stream_counted(&rfx_bad_stream,
                                         0,
                                         0,
                                         (uint16_t)(RDP_RFX_STREAM_MAX_REGIONS + 1u),
                                         0,
                                         1));
    PCHECK(rdp_rfx_stream_decode(rfx_bad_stream.data,
                                 rfx_bad_stream.length,
                                 test_rfx_stream_tile,
                                 &rfx_stream_capture,
                                 &rfx_stream_summary) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rfx_stream_capture.tiles == 0);
    rdp_buffer_free(&rfx_bad_stream);
    rdp_buffer_init(&rfx_bad_stream);
    memset(&rfx_stream_capture, 0, sizeof(rfx_stream_capture));
    PCHECK(test_build_rfx_stream_many_rects(&rfx_bad_stream));
    PCHECK(rdp_rfx_stream_decode(rfx_bad_stream.data,
                                 rfx_bad_stream.length,
                                 test_rfx_stream_tile,
                                 &rfx_stream_capture,
                                 &rfx_stream_summary) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rfx_stream_capture.tiles == 0);
    rdp_buffer_free(&rfx_bad_stream);
    rdp_buffer_init(&rfx_bad_stream);
    memset(&rfx_stream_capture, 0, sizeof(rfx_stream_capture));
    PCHECK(test_build_rfx_stream_counted(&rfx_bad_stream, 0, 0, 2, 0, 1));
    PCHECK(rdp_rfx_stream_decode(rfx_bad_stream.data,
                                 rfx_bad_stream.length,
                                 test_rfx_stream_tile,
                                 &rfx_stream_capture,
                                 &rfx_stream_summary) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rfx_stream_capture.tiles == 0);
    rdp_buffer_free(&rfx_bad_stream);
    rdp_buffer_init(&rfx_bad_stream);
    memset(&rfx_stream_capture, 0, sizeof(rfx_stream_capture));
    PCHECK(test_build_rfx_stream_counted(&rfx_bad_stream, 0, 0, 1, 1, 1));
    PCHECK(rdp_rfx_stream_decode(rfx_bad_stream.data,
                                 rfx_bad_stream.length,
                                 test_rfx_stream_tile,
                                 &rfx_stream_capture,
                                 &rfx_stream_summary) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rfx_stream_capture.tiles == 0);
    rdp_buffer_free(&rfx_bad_stream);
    rdp_buffer_init(&rfx_bad_stream);
    memset(&rfx_stream_capture, 0, sizeof(rfx_stream_capture));
    PCHECK(test_build_rfx_stream_counted(&rfx_bad_stream, 0, 0, 1, 0, 0));
    PCHECK(rdp_rfx_stream_decode(rfx_bad_stream.data,
                                 rfx_bad_stream.length,
                                 test_rfx_stream_tile,
                                 &rfx_stream_capture,
                                 &rfx_stream_summary) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rfx_stream_capture.tiles == 0);
    rdp_buffer_free(&rfx_bad_stream);
    rdp_buffer_init(&rfx_bad_stream);
    memset(&rfx_stream_capture, 0, sizeof(rfx_stream_capture));
    PCHECK(test_build_rfx_stream_ex(&rfx_bad_stream, 0, 1));
    PCHECK(rdp_rfx_stream_decode(rfx_bad_stream.data,
                                 rfx_bad_stream.length,
                                 test_rfx_stream_tile,
                                 &rfx_stream_capture,
                                 &rfx_stream_summary) == LIBRDP_STATUS_OK);
    PCHECK(rfx_stream_capture.tiles == 1 && rfx_stream_summary.width == 64 && rfx_stream_summary.height == 64);
    rdp_buffer_free(&rfx_bad_stream);
    rdp_buffer_init(&rfx_bad_stream);
    memset(&rfx_stream_capture, 0, sizeof(rfx_stream_capture));
    PCHECK(test_build_rfx_stream_ex(&rfx_bad_stream, 0, 2));
    PCHECK(rdp_rfx_stream_decode(rfx_bad_stream.data,
                                 rfx_bad_stream.length,
                                 test_rfx_stream_tile,
                                 &rfx_stream_capture,
                                 &rfx_stream_summary) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rfx_stream_capture.tiles == 0);
    memset(&rfx_stream_capture, 0, sizeof(rfx_stream_capture));
    PCHECK(rdp_rfx_stream_decode(rfx_stream.data,
                                 rfx_stream.length - 1u,
                                 test_rfx_stream_tile,
                                 &rfx_stream_capture,
                                 &rfx_stream_summary) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rfx_stream_capture.tiles == 0);
    rdp_buffer_free(&rfx_bad_stream);
    rdp_buffer_init(&rfx_bad_stream);
    memset(&rfx_stream_capture, 0, sizeof(rfx_stream_capture));
    PCHECK(test_build_rfx_stream(&rfx_bad_stream, 1));
    PCHECK(rdp_rfx_stream_decode(rfx_bad_stream.data,
                                 rfx_bad_stream.length,
                                 test_rfx_stream_tile,
                                 &rfx_stream_capture,
                                 &rfx_stream_summary) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rfx_stream_capture.tiles == 0);
    PCHECK(rdp_planar_decode_argb(planar_no_alpha,
                                  sizeof(planar_no_alpha),
                                  2,
                                  1,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 &&
           planar_pixels.length == 8 &&
           planar_pixels.data[0] == 0x50 &&
           planar_pixels.data[1] == 0x30 &&
           planar_pixels.data[2] == 0x10 &&
           planar_pixels.data[3] == 0xff &&
           planar_pixels.data[4] == 0x60 &&
           planar_pixels.data[5] == 0x40 &&
           planar_pixels.data[6] == 0x20 &&
           planar_pixels.data[7] == 0xff);
    planar_pixels.length = 0;
    PCHECK(rdp_planar_decode_argb(planar_alpha_padded,
                                  sizeof(planar_alpha_padded),
                                  2,
                                  1,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(planar_pixels.data[0] == 0x55 &&
           planar_pixels.data[1] == 0x33 &&
           planar_pixels.data[2] == 0x11 &&
           planar_pixels.data[3] == 0x7f &&
           planar_pixels.data[4] == 0x66 &&
           planar_pixels.data[5] == 0x44 &&
           planar_pixels.data[6] == 0x22 &&
           planar_pixels.data[7] == 0x80);
    PCHECK(rdp_planar_decode_argb(planar_ycocg_no_alpha,
                                  sizeof(planar_ycocg_no_alpha),
                                  2,
                                  1,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 &&
           planar_pixels.data[0] == 90 &&
           planar_pixels.data[1] == 120 &&
           planar_pixels.data[2] == 70 &&
           planar_pixels.data[3] == 0xff &&
           planar_pixels.data[4] == 110 &&
           planar_pixels.data[5] == 80 &&
           planar_pixels.data[6] == 130 &&
           planar_pixels.data[7] == 0xff);
    PCHECK(rdp_planar_decode_argb(planar_ycocg_alpha_padded,
                                  sizeof(planar_ycocg_alpha_padded),
                                  1,
                                  1,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 4 &&
           planar_pixels.data[0] == 100 &&
           planar_pixels.data[1] == 100 &&
           planar_pixels.data[2] == 100 &&
           planar_pixels.data[3] == 0x7f);
    PCHECK(rdp_planar_decode_argb(planar_ycocg_subsampled,
                                  sizeof(planar_ycocg_subsampled),
                                  3,
                                  3,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 12 &&
           planar_pixels.data[0] == 100 &&
           planar_pixels.data[2] == 100 &&
           planar_pixels.data[8] == 110 &&
           planar_pixels.data[10] == 90 &&
           planar_pixels.data[24] == 120 &&
           planar_pixels.data[26] == 80 &&
           planar_pixels.data[32] == 130 &&
           planar_pixels.data[34] == 70);
    PCHECK(rdp_planar_decode_argb(planar_rle_argb,
                                  sizeof(planar_rle_argb),
                                  2,
                                  1,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 &&
           planar_pixels.data[0] == 0x50 &&
           planar_pixels.data[1] == 0x30 &&
           planar_pixels.data[2] == 0x10 &&
           planar_pixels.data[3] == 0xff &&
           planar_pixels.data[4] == 0x60 &&
           planar_pixels.data[5] == 0x40 &&
           planar_pixels.data[6] == 0x20 &&
           planar_pixels.data[7] == 0xff);
    PCHECK(rdp_planar_decode_argb(planar_rle_delta,
                                  sizeof(planar_rle_delta),
                                  2,
                                  2,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 &&
           planar_pixels.data[0] == 50 &&
           planar_pixels.data[1] == 30 &&
           planar_pixels.data[2] == 10 &&
           planar_pixels.data[8] == 50 &&
           planar_pixels.data[9] == 30 &&
           planar_pixels.data[10] == 5 &&
           planar_pixels.data[12] == 60 &&
           planar_pixels.data[13] == 40 &&
           planar_pixels.data[14] == 25);
    planar_saved_len = planar_pixels.length;
    PCHECK(planar_saved_len <= sizeof(planar_saved));
    memcpy(planar_saved, planar_pixels.data, planar_saved_len);
    PCHECK(rdp_planar_decode_argb(planar_reserved,
                                  sizeof(planar_reserved),
                                  1,
                                  1,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_planar_decode_argb(planar_subsample_without_loss,
                                  sizeof(planar_subsample_without_loss),
                                  1,
                                  1,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_planar_decode_argb(planar_rle_bad_zero_control,
                                  sizeof(planar_rle_bad_zero_control),
                                  1,
                                  1,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(planar_pixels.length == planar_saved_len &&
           memcmp(planar_pixels.data, planar_saved, planar_saved_len) == 0);
    PCHECK(rdp_nscodec_parse_capability(nscodec_capability_data,
                                        sizeof(nscodec_capability_data),
                                        &nscodec_capability) == LIBRDP_STATUS_OK);
    PCHECK(nscodec_capability.allow_dynamic_fidelity == 1 &&
           nscodec_capability.allow_subsampling == 1 &&
           nscodec_capability.color_loss_level == 7);
    {
        rdp_nscodec_capability valid_nscodec_capability = nscodec_capability;

        PCHECK(rdp_nscodec_parse_capability(nscodec_bad_capability_data,
                                            sizeof(nscodec_bad_capability_data),
                                            &nscodec_capability) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&nscodec_capability,
                      &valid_nscodec_capability,
                      sizeof(nscodec_capability)) == 0);
    }
    PCHECK(rdp_nscodec_write_capability(&nscodec_capability_buffer,
                                        &(rdp_nscodec_capability){1, 0, 3}) == LIBRDP_STATUS_OK);
    PCHECK(nscodec_capability_buffer.length == 3 &&
           nscodec_capability_buffer.data[0] == 1 &&
           nscodec_capability_buffer.data[1] == 0 &&
           nscodec_capability_buffer.data[2] == 3);
    nscodec_capability_buffer.length = 0;
    PCHECK(rdp_buffer_append_u8(&nscodec_capability_buffer, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_nscodec_write_capability(&nscodec_capability_buffer,
                                        &(rdp_nscodec_capability){1, 0, 0}) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(nscodec_capability_buffer.length == 1 &&
           nscodec_capability_buffer.data[0] == 0xa5u);
    PCHECK(rdp_nscodec_parse_stream(nscodec_raw_argb,
                                    sizeof(nscodec_raw_argb),
                                    1,
                                    1,
                                    &nscodec_stream) == LIBRDP_STATUS_OK);
    PCHECK(nscodec_stream.luma_len == 1 &&
           nscodec_stream.orange_chroma_len == 1 &&
           nscodec_stream.green_chroma_len == 1 &&
           nscodec_stream.alpha_len == 1 &&
           nscodec_stream.luma[0] == 100);
    {
        rdp_nscodec_stream valid_nscodec_stream = nscodec_stream;

        PCHECK(rdp_nscodec_parse_stream(nscodec_invalid_stream,
                                        sizeof(nscodec_invalid_stream),
                                        1,
                                        1,
                                        &nscodec_stream) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&nscodec_stream, &valid_nscodec_stream, sizeof(nscodec_stream)) == 0);
        PCHECK(rdp_nscodec_parse_stream(nscodec_bad_reserved,
                                        sizeof(nscodec_bad_reserved),
                                        1,
                                        1,
                                        &nscodec_stream) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&nscodec_stream, &valid_nscodec_stream, sizeof(nscodec_stream)) == 0);
        PCHECK(rdp_nscodec_parse_stream(nscodec_raw_argb,
                                        sizeof(nscodec_raw_argb),
                                        RDP_NSCODEC_MAX_DIMENSION + 1u,
                                        1,
                                        &nscodec_stream) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&nscodec_stream, &valid_nscodec_stream, sizeof(nscodec_stream)) == 0);
    }
    PCHECK(rdp_nscodec_decode_bgra32(&nscodec_context,
                                     nscodec_raw_argb,
                                     sizeof(nscodec_raw_argb),
                                     1,
                                     1,
                                     &nscodec_pixels,
                                     &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 4 &&
           nscodec_pixels.length == 4 &&
           nscodec_pixels.data[0] == 70 &&
           nscodec_pixels.data[1] == 120 &&
           nscodec_pixels.data[2] == 90 &&
           nscodec_pixels.data[3] == 0x7f);
    memset(nscodec_region_dest, 0xee, sizeof(nscodec_region_dest));
    PCHECK(rdp_nscodec_decode_region_bgra32(&nscodec_context,
                                            nscodec_raw_argb,
                                            sizeof(nscodec_raw_argb),
                                            1,
                                            1,
                                            nscodec_region_dest,
                                            16,
                                            1,
                                            1,
                                            4,
                                            4) == LIBRDP_STATUS_OK);
    PCHECK(nscodec_region_dest[0] == 0xee &&
           nscodec_region_dest[20] == 70 &&
           nscodec_region_dest[21] == 120 &&
           nscodec_region_dest[22] == 90 &&
           nscodec_region_dest[23] == 0x7f &&
           nscodec_region_dest[24] == 0xee);
    PCHECK(rdp_nscodec_decode_region_bgra32(&nscodec_context,
                                            nscodec_raw_argb,
                                            sizeof(nscodec_raw_argb),
                                            1,
                                            1,
                                            nscodec_region_dest,
                                            0,
                                            0,
                                            0,
                                            RDP_NSCODEC_MAX_DIMENSION + 1u,
                                            1) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_nscodec_decode_rle_plane(nscodec_rle_plane,
                                        sizeof(nscodec_rle_plane),
                                        nscodec_rle_decoded,
                                        7) == LIBRDP_STATUS_OK);
    PCHECK(nscodec_rle_decoded[0] == 0x63 &&
           nscodec_rle_decoded[1] == 0x63 &&
           nscodec_rle_decoded[2] == 0x63 &&
           nscodec_rle_decoded[3] == 0x64 &&
           nscodec_rle_decoded[4] == 0x65 &&
           nscodec_rle_decoded[5] == 0x65 &&
           nscodec_rle_decoded[6] == 0x65);
    memset(nscodec_rle_decoded, 0x5a, sizeof(nscodec_rle_decoded));
    PCHECK(rdp_nscodec_decode_rle_plane(nscodec_rle_plane,
                                        sizeof(nscodec_rle_plane) - 1u,
                                        nscodec_rle_decoded,
                                        7) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(nscodec_rle_decoded[0] == 0x5a &&
           nscodec_rle_decoded[6] == 0x5a);
    nscodec_pixels.length = 0;
    PCHECK(rdp_nscodec_decode_bgra32(&nscodec_context,
                                     nscodec_subsampled_rle,
                                     sizeof(nscodec_subsampled_rle),
                                     3,
                                     3,
                                     &nscodec_pixels,
                                     &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 12 &&
           nscodec_pixels.length == 36 &&
           nscodec_pixels.data[0] == 100 &&
           nscodec_pixels.data[1] == 100 &&
           nscodec_pixels.data[2] == 100 &&
           nscodec_pixels.data[3] == 0xff &&
           nscodec_pixels.data[32] == 100 &&
           nscodec_pixels.data[35] == 0xff);
    {
        size_t nscodec_capacity_before = nscodec_context.plane_capacity;
        uint8_t nscodec_luma_before = nscodec_context.planes[0][0];
        uint8_t nscodec_orange_before = nscodec_context.planes[1][0];
        uint8_t nscodec_green_before = nscodec_context.planes[2][0];
        uint8_t nscodec_alpha_before = nscodec_context.planes[3][0];

        nscodec_pixels.length = 5;
        decoded_stride = 77;
        PCHECK(rdp_nscodec_decode_bgra32(&nscodec_context,
                                         nscodec_partial_plane_failure,
                                         sizeof(nscodec_partial_plane_failure),
                                         5,
                                         1,
                                         &nscodec_pixels,
                                         &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(nscodec_pixels.length == 5 && decoded_stride == 77);
        PCHECK(nscodec_context.plane_capacity == nscodec_capacity_before &&
               nscodec_context.planes[0][0] == nscodec_luma_before &&
               nscodec_context.planes[1][0] == nscodec_orange_before &&
               nscodec_context.planes[2][0] == nscodec_green_before &&
               nscodec_context.planes[3][0] == nscodec_alpha_before);
    }
    nscodec_pixels.length = 5;
    decoded_stride = 77;
    PCHECK(rdp_nscodec_decode_bgra32(&nscodec_context,
                                     nscodec_invalid_stream,
                                     sizeof(nscodec_invalid_stream),
                                     1,
                                     1,
                                     &nscodec_pixels,
                                     &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(nscodec_pixels.length == 5 && decoded_stride == 77);
    PCHECK(rdp_nscodec_decode_bgra32(&nscodec_context,
                                     nscodec_raw_argb,
                                     sizeof(nscodec_raw_argb),
                                     RDP_NSCODEC_MAX_DIMENSION + 1u,
                                     1,
                                     &nscodec_pixels,
                                     &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(nscodec_pixels.length == 5 && decoded_stride == 77);

    rdp_buffer_free(&dyn_response);
    rdp_nscodec_context_free(&nscodec_context);
    rdp_buffer_free(&nscodec_capability_buffer);
    rdp_buffer_free(&nscodec_pixels);
    rdp_buffer_free(&planar_pixels);
    rdp_buffer_free(&graphics_decoded);
    rdp_buffer_free(&rfx_bad_stream);
    rdp_buffer_free(&rfx_stream);
    return 0;
}
