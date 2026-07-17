/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: integrated protocol security and licensing conformance vectors.
 * Coverage: fixtures synthesize a complete protected session path to exercise
 * security, licensing, channel framing, CredSSP, and codec state transitions.
 * Bug classes: malformed PDU bounds, length overflows, codec edge cases, cache
 * state, security vectors, and channel lifetime.
 * Determinism: tests are self-contained and avoid external services unless
 * using local loopback fixtures.
 */


#include "channels/virtual_channel.h"
#include "channels/audio_format.h"
#include "channels/audio_input.h"
#include "channels/audio_output.h"
#include "channels/auth_redirection.h"
#include "channels/composited_remoting.h"
#include "channels/core_input.h"
#include "channels/device_redirection.h"
#include "channels/desktop_composition.h"
#include "channels/display_control.h"
#include "channels/dynamic_channel.h"
#include "channels/echo_channel.h"
#include "channels/filesystem_redirection.h"
#include "channels/graphics_pipeline.h"
#include "channels/input_channel.h"
#include "channels/mouse_cursor.h"
#include "channels/multiparty.h"
#include "channels/port_redirection.h"
#include "channels/pnp_redirection.h"
#include "channels/printer_redirection.h"
#include "channels/remote_programs.h"
#include "channels/smartcard_redirection.h"
#include "channels/telemetry.h"
#include "channels/usb_redirection.h"
#include "channels/video_capture.h"
#include "channels/video_optimized.h"
#include "channels/video_redirection.h"
#include "channels/webauthn_channel.h"
#include "channels/xps_print.h"
#include "clipboard/clipboard.h"
#include "common/buffer.h"
#include "common/stream.h"
#include "graphics/avc.h"
#include "graphics/bitmap.h"
#include "graphics/clearcodec.h"
#include "graphics/gdi_orders.h"
#include "graphics/gdi_render.h"
#include "graphics/nscodec.h"
#include "graphics/planar.h"
#include "graphics/rfx_codec.h"
#include "graphics/rfx_stream.h"
#include "graphics/surface_commands.h"
#include "licensing/licensing.h"
#include "nla/credssp.h"
#include "protocol/bulk.h"
#include "protocol/capabilities.h"
#include "protocol/fastpath.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/pointer.h"
#include "protocol/session_selection.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"
#include "transport/multitransport.h"
#include "transport/udp_transport.h"

#include <librdp/session.h>

#include <openssl/evp.h>

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

static uint16_t test_read_u16_le(const uint8_t* data)
{
    return (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
}

static uint32_t test_read_u32_le(const uint8_t* data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static librdp_status test_append_zeroes(rdp_buffer* buffer, size_t count)
{
    static const uint8_t zeroes[32] = {0};
    librdp_status status = LIBRDP_STATUS_OK;

    while (count > 0)
    {
        size_t chunk = count > sizeof(zeroes) ? sizeof(zeroes) : count;
        status = rdp_buffer_append(buffer, zeroes, chunk);
        if (status != LIBRDP_STATUS_OK)
            return status;
        count -= chunk;
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Fixture: creates encrypted fast-path output packets with legacy or salted
 * signatures. It catches integrity regressions where altered ciphertext,
 * signatures, or sequence counters are accepted by the unwrap path.
 */
static int test_build_encrypted_fastpath(rdp_buffer* out,
                                         rdp_standard_security_context* sender,
                                         uint8_t security_flags,
                                         const uint8_t* plaintext,
                                         size_t plaintext_len)
{
    rdp_buffer encrypted;
    uint8_t signature[8];
    librdp_status status = LIBRDP_STATUS_OK;
    int ok = 0;

    if (!out || !sender || (!plaintext && plaintext_len > 0) ||
        (security_flags & RDP_FASTPATH_OUTPUT_ENCRYPTED) == 0)
        return 0;

    rdp_buffer_init(&encrypted);
    if ((security_flags & RDP_FASTPATH_OUTPUT_SECURE_CHECKSUM) != 0)
        status = rdp_security_salted_mac_signature(sender, plaintext, plaintext_len, sender->decrypt_count, signature);
    else
        status = rdp_security_mac_signature(sender, plaintext, plaintext_len, signature);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&encrypted, plaintext, plaintext_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_decrypt_payload(sender, encrypted.data, encrypted.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_fastpath_write_header(out,
                                           RDP_FASTPATH_OUTPUT_ACTION_FASTPATH,
                                           security_flags,
                                           encrypted.length + sizeof(signature));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(out, signature, sizeof(signature));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(out, encrypted.data, encrypted.length);
    ok = status == LIBRDP_STATUS_OK;
    rdp_buffer_free(&encrypted);
    return ok;
}

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

static int test_sha256_three(const uint8_t* a,
                             size_t a_len,
                             const uint8_t* b,
                             size_t b_len,
                             const uint8_t* c,
                             size_t c_len,
                             uint8_t out[32])
{
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    unsigned int got = 0;
    int ok = 0;

    if (!context)
        return 0;
    if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1)
        goto out;
    if (EVP_DigestUpdate(context, a, a_len) != 1)
        goto out;
    if (EVP_DigestUpdate(context, b, b_len) != 1)
        goto out;
    if (EVP_DigestUpdate(context, c, c_len) != 1)
        goto out;
    if (EVP_DigestFinal_ex(context, out, &got) != 1 || got != 32u)
        goto out;
    ok = 1;

out:
    EVP_MD_CTX_free(context);
    return ok;
}

/*
 * Coverage: security, licensing, slow-path, fast-path, client info, codecs,
 * graphics activation, and malformed boundary vectors that still share the
 * core protocol parser path.
 * Bug classes: truncated PDU, length overflow, authentication state drift,
 * signature mismatch, decoder bounds, and activation sequencing regressions.
 */
int test_protocol_security_vectors(void)
{
    const uint8_t fast_short[] = {0x00, 0x06, 1, 2, 3, 4};
    const uint8_t fast_long[] = {0x40, 0x80, 0x08, 1, 2, 3, 4, 5};
    const uint8_t fast_bad_update_compression[] = {0x00, 0x05, 0x40, 0x00, 0x00};
    const uint8_t slow[] = {0x06, 0x00, 0x13, 0x00, 0xea, 0x03};
    const uint8_t slow_trailing[] = {0x06, 0x00, 0x13, 0x00, 0xea, 0x03, 0xff};
    const uint8_t demand_active[] = {
        0x21, 0x00, 0x11, 0x00, 0xea, 0x03, 0x78, 0x56, 0x34, 0x12,
        0x03, 0x00, 0x0c, 0x00, 's',  'r',  'v',  0x01, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x08, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x44,
        0x33, 0x22, 0x11
    };
    const uint8_t demand_active_trailing[] = {
        0x22, 0x00, 0x11, 0x00, 0xea, 0x03, 0x78, 0x56, 0x34, 0x12,
        0x03, 0x00, 0x0c, 0x00, 's',  'r',  'v',  0x01, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x08, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x44,
        0x33, 0x22, 0x11, 0xff
    };
    const uint8_t capability_list_trailing[] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0xff};
    const uint8_t bitmap_data_pdu[] = {
        0x38, 0x00, 0x17, 0x00, 0xec, 0x03, 0x78, 0x56, 0x34, 0x12,
        0x00, 0x01, 0x26, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x10, 0x00,
        1,    2,    3,    4,    5,    6,    7,    8,
        9,    10,   11,   12,   13,   14,   15,   16
    };
    const uint8_t bitmap_24_data[] = {
        1, 2, 3, 4, 5, 6,
        7, 8, 9, 10, 11, 12
    };
    const uint8_t bitmap_24_padded_data[] = {
        1, 2, 3, 0,
        4, 5, 6, 0
    };
    const uint8_t bitmap_15_data[] = {0x00, 0x7c, 0xe0, 0x03};
    const uint8_t bitmap_16_data[] = {0x00, 0xf8, 0xe0, 0x07};
    const uint8_t bitmap_8_data[] = {0, 1, 2, 3};
    const uint8_t bitmap_4_data[] = {0x12, 0x30, 0x01, 0x20};
    const uint8_t bitmap_1_data[] = {0xb0, 0x40};
    const uint8_t bitmap_8_rle_color_image[] = {0x84, 0, 1, 2, 3};
    const uint8_t palette_update_data[] = {
        0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        10,   20,   30,   200,  100,  50,   1,    2,
        3,    9,    8,    7
    };
    const uint8_t palette_fastpath_data[] = {
        0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        10,   20,   30,   200,  100,  50,   1,
        2,    3,    9,    8,    7
    };
    const uint8_t palette_invalid_count[] = {0x02, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00};
    const uint8_t bitmap_24_rle_color_image[] = {
        0x84,
        1, 2, 3,
        4, 5, 6,
        7, 8, 9,
        10, 11, 12
    };
    const uint8_t bitmap_24_rle_bg_run_cross_row[] = {
        0x82,
        0, 0, 255,
        0, 255, 0,
        0x06
    };
    const uint8_t bitmap_24_rle_fg_run_cross_row[] = {0x26, 0x02};
    const uint8_t bitmap_24_rle_fgbg_cross_row[] = {0x41, 0xff};
    const uint8_t bitmap_16_rle_with_header[] = {
        0x00, 0x00, 0x03, 0x00,
        0x04, 0x00, 0x08, 0x00,
        0x64, 0x00, 0xf8
    };
    const uint8_t bitmap_15_rle_with_header[] = {
        0x00, 0x00, 0x03, 0x00,
        0x04, 0x00, 0x08, 0x00,
        0x64, 0x00, 0x7c
    };
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
    const uint8_t nscodec_guid[RDP_NSCODEC_GUID_LENGTH] = RDP_NSCODEC_GUID_BYTES;
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
    const uint8_t fast_bitmap_update[] = {
        0x00, 0x29, 0x01, 0x24, 0x00,
        0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x10, 0x00,
        1,    2,    3,    4,    5,    6,    7,    8,
        9,    10,   11,   12,   13,   14,   15,   16
    };
    const uint8_t surface_command_payload[] = {
        0x01, 0x00,
        0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00,
        0x20, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x02, 0x00,
        0x10, 0x00, 0x00, 0x00,
        1,    2,    3,    4,    5,    6,    7,    8,
        9,    10,   11,   12,   13,   14,   15,   16,
        0x04, 0x00,
        0x01, 0x00,
        0x44, 0x33, 0x22, 0x11
    };
    const uint8_t surface_command_short_frame_marker[] = {
        0x04, 0x00,
        0x01, 0x00
    };
    const uint8_t surface_command_extended[] = {
        0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x20, 0x01, 0x00, 0x01,
        0x01, 0x00, 0x01, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x78, 0x56, 0x34, 0x12,
        0xef, 0xcd, 0xab, 0x90,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
        0xaa, 0xbb, 0xcc, 0xdd
    };
    const uint8_t pointer_shape_32[] = {
        0x20, 0x00,
        0x05, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0x10, 0x00,
        0xff, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        0x00, 0xff, 0x00, 0xff,
        0x40, 0x00,
        0x00, 0x00
    };
    const uint8_t pointer_shape_16[] = {
        0x10, 0x00,
        0x08, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x01, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0x00, 0xf8,
        0xe0, 0x07,
        0x00, 0x00
    };
    const uint8_t pointer_shape_15[] = {
        0x0f, 0x00,
        0x09, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x01, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0x00, 0x7c,
        0xe0, 0x03,
        0x00, 0x00
    };
    const uint8_t pointer_shape_1bpp_invert[] = {
        0x01, 0x00,
        0x06, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x80, 0x00,
        0x80, 0x00
    };
    const uint8_t pointer_shape_1bpp_transparent[] = {
        0x01, 0x00,
        0x07, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x00, 0x00,
        0x80, 0x00
    };
    const uint8_t pointer_slow_position[] = {
        0x03, 0x00,
        0x22, 0x00,
        0x33, 0x00
    };
    const uint8_t pointer_slow_system_default[] = {
        0x01, 0x00,
        0x00, 0x7f, 0x00, 0x00
    };
    const uint8_t pointer_slow_large[] = {
        0x09, 0x00,
        0x20, 0x00,
        0x05, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0xff, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        0x00, 0xff, 0x00, 0xff,
        0x40, 0x00,
        0x00, 0x00
    };
    const uint8_t mouse_cursor_caps_confirm[] = {
        0x02, 0x00, 0x00, 0x00,
        0x43, 0x41, 0x50, 0x53,
        0x01, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x00, 0x00
    };
    const uint8_t mouse_cursor_hidden[] = {0x03, 0x05, 0x00, 0x00};
    const uint8_t mouse_cursor_default[] = {0x03, 0x06, 0x00, 0x00};
    const uint8_t mouse_cursor_position[] = {
        0x03, 0x08, 0x00, 0x00,
        0x22, 0x00,
        0x33, 0x00
    };
    const uint8_t mouse_cursor_cached[] = {
        0x03, 0x0a, 0x00, 0x00,
        0x05, 0x00
    };
    const uint8_t mouse_cursor_unknown[] = {0x03, 0xff, 0x00, 0x00};
    const uint8_t mouse_cursor_shape_32[] = {
        0x03, 0x0b, 0x00, 0x00,
        0x20, 0x00,
        0x05, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0x10, 0x00,
        0xff, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        0x00, 0xff, 0x00, 0xff,
        0x40, 0x00,
        0x00, 0x00
    };
    const uint8_t mouse_cursor_shape_bad_width[] = {
        0x03, 0x0b, 0x00, 0x00,
        0x20, 0x00,
        0x05, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x01, 0x02,
        0x02, 0x00,
        0x04, 0x00,
        0x10, 0x00,
        0xff, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        0x00, 0xff, 0x00, 0xff,
        0x40, 0x00,
        0x00, 0x00
    };
    const uint8_t mouse_cursor_shape_bad_hotspot[] = {
        0x03, 0x0b, 0x00, 0x00,
        0x20, 0x00,
        0x05, 0x00,
        0x02, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0x10, 0x00,
        0xff, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        0x00, 0xff, 0x00, 0xff,
        0x40, 0x00,
        0x00, 0x00
    };
    const uint8_t mouse_cursor_large_32[] = {
        0x03, 0x0c, 0x00, 0x00,
        0x20, 0x00,
        0x05, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0xff, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        0x00, 0xff, 0x00, 0xff,
        0x40, 0x00,
        0x00, 0x00
    };
    const uint8_t license[] = {
        0xff, 0x03, 0x12, 0x00,
        1, 0, 0, 0,
        2, 0, 0, 0,
        3, 0, 2, 0,
        9, 8
    };
    const uint8_t license_company[] = {'C', 0, 0, 0};
    const uint8_t license_product[] = {'A', 0, '0', 0, '2', 0, 0, 0};
    const uint8_t license_scope[] = {'s', 'c', 'o', 'p', 'e', 0};
    const uint8_t license_cal[] = {'c', 'a', 'l'};
    const uint8_t license_requested_id[] = {'R', 'D', 'S', 0};
    const uint8_t license_adjusted_id[] = {'R', 'D', 'S', '-', 'A', 0};
    const uint8_t license_issuer_name[] = {'L', 0, 'S', 0, 0, 0};
    const uint8_t license_issuer_id[] = {'I', 0, 'D', 0, 0, 0};
    const uint8_t license_issuer_scope[] = {'D', 0, 0, 0};
    const uint8_t channel[] = {3, 0, 0, 0, 0x10, 0, 0, 0, 1, 2, 3};
    const uint8_t channel_fragment[] = {8, 0, 0, 0, RDP_VIRTUAL_CHANNEL_FLAG_FIRST, 0, 0, 0, 1, 2, 3};
    const uint8_t dyn_caps[] = {
        0x50, 0x00, 0x03, 0x00,
        0xa8, 0x03, 0xcc, 0x0c,
        0x92, 0x24, 0x55, 0x55
    };
    const uint8_t dyn_caps_zero[] = {0x50, 0x00, 0x00, 0x00};
    const uint8_t dyn_create[] = {0x18, 0x07, 'E', 'C', 'H', 'O', 0};
    const uint8_t dyn_data[] = {0x30, 0x07, 0xaa, 0xbb, 0xcc};
    const uint8_t dyn_data_first[] = {0x24, 0x07, 0x2c, 0x01, 0xaa, 0xbb, 0xcc};
    const uint8_t dyn_close[] = {0x40, 0x07};
    const uint8_t dyn_data_compressed[] = {0x70, 0x07, 0xe0, 0x06, 0xaa};
    const uint8_t dyn_data_first_compressed[] = {0x64, 0x07, 0x2c, 0x01, 0xe0, 0x06, 0xaa};
    const uint8_t dyn_soft_sync_request[] = {
        0x80, 0x00,
        0x16, 0x00, 0x00, 0x00,
        0x03, 0x00,
        0x01, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x34, 0x12, 0x00, 0x00
    };
    const uint8_t dyn_soft_sync_empty_request[] = {
        0x80, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x01, 0x00,
        0x00, 0x00
    };
    const uint8_t dyn_bad_header[] = {0x33};
    const uint8_t display_caps[] = {
        5, 0, 0, 0,
        20, 0, 0, 0,
        16, 0, 0, 0,
        0, 32, 0, 0,
        0, 32, 0, 0
    };
    const uint8_t core_response[] = {
        3, 2, 0, 0,
        0, 1, 0, 1,
        0, 0, 0, 0,
        0, 0, 0, 0
    };
    const uint8_t input_sc_ready_v300[] = {
        0x01, 0x00,
        0x0e, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00,
        0x01, 0x00, 0x00, 0x00
    };
    const uint8_t input_sc_ready_v300_no_pen[] = {
        0x01, 0x00,
        0x0e, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    const uint8_t input_sc_ready_v200[] = {
        0x01, 0x00,
        0x0a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00
    };
    const uint8_t graphics_confirm[] = {
        0x13, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x08, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_bad_capset[] = {
        0x01, 0x00, 0x01, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_capset_v107[] = {
        0x01, 0x07, 0x0a, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_capset_unknown_flags[] = {
        0x02, 0x00, 0x0a, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00
    };
    const uint8_t graphics_capset_conflicting_avc[] = {
        0x02, 0x00, 0x0a, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x30, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_capset_trailing[] = {
        0x02, 0x00, 0x0a, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0xef, 0xbe, 0xad, 0xde
    };
    const uint8_t graphics_confirm_trailing_capset[] = {
        0x13, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x08, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0xef, 0xbe, 0xad, 0xde
    };
    const uint8_t graphics_segment_single[] = {
        0xe0, 0x04,
        0x13, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x08, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_segment_multipart[] = {
        0xe1, 0x02, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x04,
        0x13, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00,
        0x0d, 0x00, 0x00, 0x00, 0x04,
        0x04, 0x00, 0x08, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_segment_compressed_literal[] = {0xe0, 0x24, 0x24, 0x80, 0x07};
    const uint8_t graphics_segment_bad_compression_type[] = {0xe0, 0x20, 1, 2, 3};
    const uint8_t graphics_segment_multipart_bad_second[] = {
        0xe1, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x04, 0x51,
        0x04, 0x00, 0x00, 0x00, 0x20, 1, 2, 3
    };
    const uint8_t graphics_create_surface[] = {
        0x09, 0x00, 0x00, 0x00,
        0x0f, 0x00, 0x00, 0x00,
        0x34, 0x12, 0x00, 0x04,
        0x00, 0x03, 0x20
    };
    const uint8_t graphics_delete_surface[] = {
        0x0a, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00,
        0x34, 0x12
    };
    const uint8_t graphics_map_output[] = {
        0x0f, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00,
        0x34, 0x12, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_scaled_map_output[] = {
        0x17, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x00, 0x00,
        0x34, 0x12, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00,
        0x00, 0x03, 0x00, 0x00
    };
    const uint8_t graphics_solid_fill[] = {
        0x04, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x11, 0x22, 0x33, 0xff,
        0x01, 0x00,
        0x01, 0x00, 0x02, 0x00,
        0x05, 0x00, 0x06, 0x00
    };
    const uint8_t graphics_bad_rect[] = {
        0x05, 0x00, 0x02, 0x00,
        0x01, 0x00, 0x06, 0x00
    };
    const uint8_t graphics_wire_to_surface_1[] = {
        0x01, 0x00, 0x00, 0x00,
        0x29, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x00, 0x00,
        0x20,
        0x01, 0x00, 0x02, 0x00,
        0x03, 0x00, 0x04, 0x00,
        0x10, 0x00, 0x00, 0x00,
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 11, 12,
        13, 14, 15, 16
    };
    const uint8_t graphics_wire_to_surface_1_alpha[] = {
        0x01, 0x00, 0x00, 0x00,
        0x21, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x0c, 0x00,
        0x21,
        0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x02, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x4c, 0x41, 0x00, 0x00,
        0x10, 0x20, 0x30, 0xff
    };
    const uint8_t graphics_wire_to_surface_2[] = {
        0x02, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x09, 0x00,
        0x44, 0x33, 0x22, 0x11,
        0x21,
        0x03, 0x00, 0x00, 0x00,
        0xaa, 0xbb, 0xcc
    };
    const uint8_t graphics_avc420_stream[] = {
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc420_bad_rect[] = {
        0x01, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc420_empty_bits[] = {
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64
    };
    const uint8_t graphics_avc420_bad_quant[] = {
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x34, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc444_both[] = {
        0x12, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x66
    };
    const uint8_t graphics_avc444_luma[] = {
        0x12, 0x00, 0x00, 0x40,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc444_chroma[] = {
        0x12, 0x00, 0x00, 0x80,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc444_invalid_lc[] = {
        0x12, 0x00, 0x00, 0xc0,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc444_bad_split[] = {
        0x05, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x66
    };
    const uint8_t graphics_avc_red_h264[] = {
        0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xc0, 0x0a,
        0xdd, 0xec, 0x04, 0x40, 0x00, 0x00, 0x03, 0x00,
        0x40, 0x00, 0x00, 0x03, 0x00, 0xa3, 0xc4, 0x89,
        0xe0, 0x00, 0x00, 0x00, 0x01, 0x68, 0xce, 0x0f,
        0xc8, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x3a,
        0x11, 0x8a, 0x00, 0x02, 0x18, 0xf1, 0xc0, 0x00,
        0x40, 0xf6, 0x38, 0x00, 0x08, 0x79, 0x60
    };
    const uint8_t graphics_avc_rect_full_16[] = {
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00
    };
    const uint8_t graphics_avc_rect_oob[] = {
        0x00, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x10, 0x00
    };
    const uint8_t graphics_avc_quant_quality[] = {0x45, 0x64};
    const uint8_t graphics_avc_quant_bad_qp[] = {0x34, 0x64};
    const uint8_t graphics_avc_quant_bad_quality[] = {0x45, 0x65};
    const uint8_t graphics_progressive_stream[] = {
        0xc3, 0xcc, 0x0a, 0x00, 0x00, 0x00,
        0x00, 0x40, 0x00, 0x01,
        0xc1, 0xcc, 0x0c, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00,
        0xc4, 0xcc, 0x48, 0x00, 0x00, 0x00,
        0x40,
        0x01, 0x00,
        0x01,
        0x01,
        0x01,
        0x01, 0x00,
        0x19, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x40, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55,
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
        0xc5, 0xcc, 0x19, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0xaa, 0xbb, 0xcc,
        0xc2, 0xcc, 0x06, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_progressive_sync[] = {
        0xc0, 0xcc, 0x0c, 0x00, 0x00, 0x00,
        0xca, 0xac, 0xcc, 0xca,
        0x00, 0x01
    };
    const uint8_t graphics_progressive_bad_sync[] = {
        0xc0, 0xcc, 0x0c, 0x00, 0x00, 0x00,
        0xca, 0xac, 0xcc, 0x00,
        0x00, 0x01
    };
    const uint8_t graphics_progressive_tile_first[] = {
        0xc6, 0xcc, 0x1a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
        0x01, 0x00,
        0x02, 0x00,
        0x01,
        0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x11, 0x22, 0x33
    };
    const uint8_t graphics_progressive_tile_upgrade[] = {
        0xc7, 0xcc, 0x20, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
        0x03, 0x00,
        0x04, 0x00,
        0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66
    };
    const uint8_t graphics_progressive_bad_block[] = {0xc3, 0xcc, 0x05, 0x00, 0x00, 0x00};
    const uint8_t graphics_progressive_empty_region[] = {
        0xc4, 0xcc, 0x1f, 0x00, 0x00, 0x00,
        0x40,
        0x01, 0x00,
        0x01,
        0x00,
        0x01,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x0d, 0x02, 0xd8, 0x02,
        0x40, 0x00, 0x20, 0x00,
        0x66, 0x76, 0x88, 0x99, 0xa9
    };
    const uint8_t graphics_progressive_bad_region[] = {
        0xc4, 0xcc, 0x17, 0x00, 0x00, 0x00,
        0x40,
        0x01, 0x00,
        0x01,
        0x00,
        0x00,
        0x02, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x40, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55
    };
    const uint8_t graphics_progressive_region_rect[] = {
        0x80, 0x02, 0x20, 0x01,
        0x40, 0x00, 0x20, 0x00
    };
    const uint8_t graphics_progressive_region_rect_overflow[] = {
        0xff, 0xff, 0x00, 0x00,
        0x02, 0x00, 0x01, 0x00
    };
    const uint8_t graphics_surface_to_surface[] = {
        0x05, 0x00, 0x00, 0x00,
        0x1e, 0x00, 0x00, 0x00,
        0x10, 0x00,
        0x20, 0x00,
        0x01, 0x00, 0x02, 0x00,
        0x05, 0x00, 0x06, 0x00,
        0x02, 0x00,
        0x07, 0x00, 0x08, 0x00,
        0x09, 0x00, 0x0a, 0x00
    };
    const uint8_t graphics_surface_to_cache[] = {
        0x06, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x08, 0x07, 0x06, 0x05,
        0x04, 0x03, 0x02, 0x01,
        0x42, 0x00,
        0x01, 0x00, 0x02, 0x00,
        0x05, 0x00, 0x06, 0x00
    };
    const uint8_t graphics_cache_to_surface[] = {
        0x07, 0x00, 0x00, 0x00,
        0x16, 0x00, 0x00, 0x00,
        0x42, 0x00,
        0x34, 0x12,
        0x02, 0x00,
        0x07, 0x00, 0x08, 0x00,
        0x09, 0x00, 0x0a, 0x00
    };
    const uint8_t graphics_evict_cache[] = {
        0x08, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00,
        0x42, 0x00
    };
    const uint8_t graphics_delete_context_pdu[] = {
        0x03, 0x00, 0x00, 0x00,
        0x0e, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x44, 0x33, 0x22, 0x11
    };
    const uint8_t clear_residual_bitmap[] = {
        0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04
    };
    const uint8_t clear_residual_zero_run_bitmap[] = {
        0x00, 0x06,
        0x08, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04
    };
    const uint8_t clear_raw_subcodec_bitmap[] = {
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x19, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x0c, 0x00, 0x00, 0x00,
        0x00,
        1, 2, 3,
        4, 5, 6,
        7, 8, 9,
        10, 11, 12
    };
    const uint8_t clear_rlex_subcodec_bitmap[] = {
        0x00, 0x07,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x0b, 0x00, 0x00, 0x00,
        0x02,
        0x02,
        1, 2, 3,
        4, 5, 6,
        0x03, 0x00,
        0x03, 0x00
    };
    const uint8_t clear_nsc_subcodec_bitmap[] = {
        0x00, 0x08,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x25, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x01,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01,
        0x00,
        0x00, 0x00,
        10, 0, 0, 0xff
    };
    const uint8_t clear_band_miss_bitmap[] = {
        0x04, 0x02,
        0x04, 0x00, 0x00, 0x00,
        0x13, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04,
        0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x00,
        0x0a, 0x14, 0x1e,
        0x00, 0x02,
        1, 2, 3,
        4, 5, 6
    };
    const uint8_t clear_band_hit_bitmap[] = {
        0x00, 0x03,
        0x04, 0x00, 0x00, 0x00,
        0x0d, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00,
        0x0a, 0x14, 0x1e,
        0x00, 0x80
    };
    const uint8_t clear_missing_band_bitmap[] = {
        0x00, 0x04,
        0x04, 0x00, 0x00, 0x00,
        0x0d, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00,
        0x0a, 0x14, 0x1e,
        0x0a, 0x80
    };
    const uint8_t clear_glyph_store_bitmap[] = {
        0x01, 0x05,
        0x02, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        9, 8, 7, 4
    };
    const uint8_t clear_glyph_hit[] = {
        0x03, 0x03,
        0x02, 0x00
    };
    const uint8_t clear_glyph_hit_after_reset[] = {
        0x07, 0x0d,
        0x02, 0x00
    };
    const uint8_t clear_missing_glyph_hit[] = {
        0x03, 0x0a,
        0x03, 0x00
    };
    const uint8_t clear_max_glyph_hit[] = {
        0x03, 0x0e,
        0x9f, 0x0f
    };
    const uint8_t clear_bad_glyph_hit[] = {
        0x03, 0x0f,
        0xa0, 0x0f
    };
    const uint8_t clear_empty_payload[] = {
        0x00, 0x0b
    };
    const uint8_t clear_unknown_subcodec_bitmap[] = {
        0x00, 0x0c,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x19, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x0c, 0x00, 0x00, 0x00,
        0xff,
        1, 2, 3,
        4, 5, 6,
        7, 8, 9,
        10, 11, 12
    };
    const uint8_t graphics_start_frame[] = {
        0x0b, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0x04, 0x03, 0x02, 0x01,
        0x44, 0x33, 0x22, 0x11
    };
    const uint8_t graphics_end_frame[] = {
        0x0c, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x00, 0x00,
        0x44, 0x33, 0x22, 0x11
    };
    const uint8_t clip[] = {1, 0, 2, 0, 3, 0, 0, 0, 4, 5, 6};
    const uint8_t clip_caps[] = {
        0x07, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x0c, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x16, 0x00, 0x00, 0x00
    };
    const uint8_t clip_format_long[] = {
        0x02, 0x00, 0x00, 0x00,
        0x24, 0x00, 0x00, 0x00,
        0x04, 0xc0, 0x00, 0x00,
        'N', 0x00, 'a', 0x00, 't', 0x00, 'i', 0x00, 'v', 0x00, 'e', 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x11, 0x00, 0x00, 0x00,
        0x00, 0x00
    };
    const uint8_t clip_format_short_ascii[] = {
        0x02, 0x00, 0x04, 0x00,
        0x24, 0x00, 0x00, 0x00,
        0xaa, 0xc0, 0x00, 0x00,
        'C', 'u', 's', 't', 'o', 'm', 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0
    };
    const uint8_t clip_data_request[] = {
        0x04, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x0d, 0x00, 0x00, 0x00
    };
    const uint8_t clip_file_size_request[] = {
        0x08, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x22, 0x11, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00
    };
    const uint8_t clip_file_range_request[] = {
        0x08, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x00, 0x00,
        0x33, 0x22, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x78, 0x56, 0x34, 0x12,
        0x01, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00,
        0x99, 0x00, 0x00, 0x00
    };
    const uint8_t clip_file_bad_request[] = {
        0x08, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x22, 0x11, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00
    };
    const uint8_t indication_pdu[] = {0x68, 0x00, 0x03, 0x03, 0xeb, 0x70, 0x04, 1, 2, 3, 4};
    const uint8_t encrypted_random[] = {1, 2, 3, 4, 5};
    const uint8_t ntlm_challenge_token[] = {
        'N',  'T',  'L',  'M',  'S',  'S',  'P',  0,
        2,    0,    0,    0,
        4,    0,    4,    0,    56,   0,    0,    0,
        1,    2,    3,    4,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0,    0,    0,    0,    0,    0,    0,    0,
        8,    0,    8,    0,    60,   0,    0,    0,
        0,    0,    0,    0,    0,    0,    0,    0,
        'S',  0,    'R',  0,
        1,    0,    4,    0,    'A',  0,    0,    0
    };
    const uint8_t wrapped_ntlm_challenge[] = {
        0xa1, 0x4c, 0x30, 0x4a, 0xa2, 0x48, 0x04, 0x46,
        'N',  'T',  'L',  'M',  'S',  'S',  'P',  0,
        2,    0,    0,    0,
        4,    0,    4,    0,    56,   0,    0,    0,
        1,    2,    3,    4,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0,    0,    0,    0,    0,    0,    0,    0,
        8,    0,    8,    0,    60,   0,    0,    0,
        0,    0,    0,    0,    0,    0,    0,    0,
        'S',  0,    'R',  0,
        1,    0,    4,    0,    'A',  0,    0,    0
    };
    const uint8_t ntlm_v2_target_name[] = {'D', 0, 'O', 0, 'M', 0, 'A', 0, 'I', 0, 'N', 0};
    const uint8_t ntlm_v2_target_info[] = {
        0x02, 0x00, 0x0c, 0x00, 'D', 0, 'O', 0, 'M', 0, 'A', 0, 'I', 0, 'N', 0,
        0x01, 0x00, 0x0c, 0x00, 'S', 0, 'E', 0, 'R', 0, 'V', 0, 'E', 0, 'R', 0,
        0x04, 0x00, 0x14, 0x00, 'd', 0, 'o', 0, 'm', 0, 'a', 0, 'i', 0, 'n', 0,
        '.', 0,    'c', 0,    'o', 0,    'm', 0,
        0x03, 0x00, 0x22, 0x00, 's', 0, 'e', 0, 'r', 0, 'v', 0, 'e', 0, 'r', 0,
        '.', 0,    'd', 0,    'o', 0,    'm', 0, 'a', 0, 'i', 0, 'n', 0, '.', 0,
        'c', 0,    'o', 0,    'm', 0,
        0x00, 0x00, 0x00, 0x00
    };
    const uint8_t ntlm_v2_server_challenge[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    const uint8_t ntlm_v2_client_challenge[] = {0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44};
    const uint8_t ntlm_v2_session_key[] = {
        0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xfe, 0xdc,
        0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x99, 0x88
    };
    const uint8_t credssp_client_nonce[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const uint8_t credssp_public_key[] = {
        0x30, 0x13, 0x02, 0x0f, 0x00, 0xb8, 0x2d, 0xf1,
        0xa8, 0x88, 0x3d, 0xa8, 0xfb, 0xa6, 0x99, 0xf8,
        0x74, 0x2e, 0xc3, 0x02, 0x03, 0x01, 0x00, 0x01
    };
    const uint8_t ntlm_v2_expected_lm[] = {
        0xd6, 0xe6, 0x15, 0x2e, 0xa2, 0x5d, 0x03, 0xb7,
        0xc6, 0xba, 0x66, 0x29, 0xc2, 0xd6, 0xaa, 0xf0,
        0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44
    };
    const uint8_t ntlm_v2_expected_proof[] = {
        0x29, 0x15, 0x7f, 0x79, 0xa3, 0x08, 0x93, 0x53,
        0x78, 0x3e, 0x24, 0x4f, 0xad, 0x52, 0x8a, 0x5c
    };
    const uint8_t ntlm_v2_expected_encrypted_key[] = {
        0x89, 0x7f, 0x84, 0x0c, 0x2b, 0x3c, 0xcc, 0xa4,
        0xbd, 0x38, 0x95, 0x03, 0x54, 0xe8, 0x31, 0x05
    };
    const uint8_t ntlm_expected_wrapped_data[] = {
        0x01, 0x00, 0x00, 0x00, 0x47, 0xea, 0xc4, 0xa7,
        0x26, 0xe2, 0x57, 0xb3, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x8d, 0x3d, 0x6c
    };
    const uint8_t server_certificate[] = {
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x9c, 0x00, 0x52, 0x53, 0x41, 0x31, 0x88, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0xeb, 0x63, 0x25, 0x72, 0xe3, 0xeb, 0x4e, 0x15, 0x13, 0x3c, 0x7b, 0x9c,
        0x5c, 0x66, 0x61, 0x89, 0x0f, 0x7f, 0x79, 0x1a, 0x93, 0x75, 0x9c, 0xe2,
        0x98, 0xeb, 0xa5, 0xa6, 0x73, 0xd2, 0xc7, 0x14, 0x2c, 0x5a, 0x57, 0x10,
        0x48, 0x3b, 0x04, 0x69, 0xaf, 0x52, 0x86, 0x58, 0xe3, 0xf7, 0x05, 0xcf,
        0x22, 0x0f, 0x6e, 0x25, 0x41, 0xe0, 0x3a, 0x26, 0x62, 0x2f, 0x31, 0xcf,
        0xd5, 0x97, 0xd3, 0xa0, 0x93, 0x73, 0x4c, 0x9b, 0xc1, 0x9c, 0x2a, 0x30,
        0x66, 0x7f, 0x61, 0x25, 0x67, 0xab, 0xd3, 0xe7, 0xe2, 0x7f, 0x5e, 0x57,
        0x2a, 0x3a, 0x2b, 0x9c, 0x4f, 0x4e, 0x2c, 0xba, 0x8e, 0xf0, 0x93, 0x29,
        0x3f, 0xf7, 0xca, 0x9e, 0x46, 0xd4, 0x1e, 0x11, 0x96, 0x84, 0xef, 0x2d,
        0xa9, 0x57, 0x3d, 0x8b, 0x9b, 0x27, 0x90, 0x5b, 0x98, 0x9d, 0x5b, 0x80,
        0x64, 0x24, 0x76, 0xc0, 0xba, 0x8d, 0xe4, 0xb2, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    const uint8_t x509_der[] = {
        0x30, 0x82, 0x02, 0x08, 0x30, 0x82, 0x01, 0x71, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x2b, 0x77, 0x94, 0x65, 0x7e, 0xcb, 0xa0, 0x19, 0xd9,
        0xec, 0x74, 0x9b, 0x9a, 0xd1, 0xd1, 0x83, 0x77, 0x7f, 0x9e, 0x5a, 0x30,
        0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        0x05, 0x00, 0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x0b, 0x6c, 0x69, 0x62, 0x72, 0x64, 0x70, 0x2d, 0x74, 0x65,
        0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x37, 0x30, 0x37,
        0x31, 0x38, 0x30, 0x35, 0x34, 0x35, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x30,
        0x37, 0x30, 0x38, 0x31, 0x38, 0x30, 0x35, 0x34, 0x35, 0x5a, 0x30, 0x16,
        0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x6c,
        0x69, 0x62, 0x72, 0x64, 0x70, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x30, 0x81,
        0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02,
        0x81, 0x81, 0x00, 0xb8, 0x2d, 0xf1, 0xa8, 0x88, 0x3d, 0xa8, 0xfb, 0xa6,
        0x99, 0xf8, 0x74, 0x2e, 0xc3, 0x89, 0xab, 0x17, 0x5c, 0xb6, 0xd2, 0x7f,
        0xbd, 0x88, 0x48, 0x3f, 0x16, 0x3f, 0x94, 0x9d, 0x6a, 0xd1, 0x38, 0x5b,
        0xe8, 0x53, 0xb4, 0x1c, 0x61, 0x80, 0xef, 0xa9, 0x8c, 0xf7, 0xeb, 0x01,
        0xad, 0x87, 0xc8, 0x70, 0x55, 0x98, 0x64, 0xce, 0x24, 0x07, 0x09, 0x59,
        0x4e, 0xdf, 0x44, 0x2c, 0x4c, 0xe4, 0x44, 0xb4, 0xb1, 0x10, 0x75, 0x0e,
        0x1e, 0x38, 0xda, 0x26, 0xf4, 0x9e, 0xef, 0xec, 0x15, 0xaa, 0x2f, 0x26,
        0x35, 0xb0, 0x17, 0x9d, 0x34, 0x7e, 0x58, 0xa0, 0xeb, 0x22, 0xb3, 0xf0,
        0xff, 0x1c, 0x87, 0x7f, 0xb0, 0xf4, 0xd4, 0x3c, 0x3d, 0x59, 0xe0, 0x10,
        0x77, 0x46, 0x94, 0xa5, 0x90, 0xcf, 0x1d, 0x2c, 0xf0, 0xd7, 0x44, 0x8f,
        0x9e, 0xaa, 0x60, 0x0b, 0x16, 0x6d, 0x79, 0x5c, 0xe4, 0xdd, 0xcd, 0x02,
        0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03,
        0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x7d, 0x2f, 0xcf, 0xa9, 0x1f,
        0xc0, 0x07, 0x93, 0x49, 0xc2, 0x4d, 0xfa, 0x0f, 0x8c, 0xe4, 0x25, 0xcd,
        0x00, 0xc8, 0x15, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
        0x30, 0x16, 0x80, 0x14, 0x7d, 0x2f, 0xcf, 0xa9, 0x1f, 0xc0, 0x07, 0x93,
        0x49, 0xc2, 0x4d, 0xfa, 0x0f, 0x8c, 0xe4, 0x25, 0xcd, 0x00, 0xc8, 0x15,
        0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05,
        0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00,
        0x70, 0x99, 0xde, 0x9e, 0x51, 0xf6, 0x5a, 0x1d, 0x33, 0xab, 0xf4, 0x7b,
        0x4a, 0xa5, 0x9f, 0xf2, 0xda, 0x3a, 0xe3, 0x4d, 0x66, 0xb6, 0xfe, 0x68,
        0x44, 0x29, 0xb3, 0xe4, 0x8d, 0x8e, 0xef, 0xb4, 0x0e, 0xfc, 0xae, 0x74,
        0xb3, 0x2a, 0xf9, 0x90, 0x0c, 0x0c, 0xd6, 0xb1, 0x12, 0x6c, 0x7e, 0x6a,
        0x34, 0xb5, 0xe7, 0xc8, 0xb0, 0xee, 0x56, 0xb8, 0x02, 0xab, 0xf3, 0xe2,
        0x5e, 0xd6, 0xca, 0x4f, 0xa6, 0x3d, 0x10, 0xb1, 0x49, 0x32, 0x75, 0x07,
        0x00, 0x54, 0xa7, 0x9e, 0x65, 0xd0, 0xc4, 0x2b, 0xc4, 0xad, 0xc7, 0x3a,
        0xb9, 0xe5, 0x44, 0xdf, 0xed, 0xb8, 0x91, 0xea, 0xcc, 0x23, 0x16, 0xd3,
        0xa6, 0x23, 0x83, 0x62, 0x2d, 0x4e, 0xe4, 0x1c, 0xb8, 0x6c, 0x75, 0x61,
        0xde, 0xe6, 0x0e, 0xc8, 0xd5, 0x25, 0xc7, 0x69, 0x5a, 0xba, 0x06, 0xa3,
        0x30, 0xdb, 0xdf, 0xd2, 0xd8, 0xdc, 0xa0, 0x3f
    };
    uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    uint8_t server_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    uint8_t fast_payload[130] = {0};
    uint8_t malformed_slowpath[sizeof(bitmap_data_pdu)];
    uint8_t trailing_slowpath[sizeof(bitmap_data_pdu) + 1u];
    rdp_fastpath_header fast;
    rdp_fastpath_update_list fast_updates;
    int fastpath_used_decoded = 0;
    rdp_bulk_decompressor bulk_decompressor;
    rdp_slowpath_share_control_header slow_header;
    rdp_slowpath_demand_active demand;
    rdp_slowpath_data_pdu data_pdu;
    rdp_slowpath_font_map font_map;
    rdp_slowpath_save_session_info save_info;
    rdp_bitmap_update bitmap_update;
    rdp_bitmap_update_header bitmap_header;
    rdp_bitmap_rect bitmap_rect;
    rdp_palette_update palette_update;
    rdp_palette_update palette_roundtrip;
    rdp_pointer_update pointer_update;
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
    rdp_license_error_alert alert;
    rdp_license_preamble license_preamble;
    rdp_license_binary_blob license_blob;
    rdp_license_binary_blob license_bad_blob;
    rdp_license_server_request license_request;
    rdp_license_platform_challenge license_challenge;
    rdp_license_new_or_upgrade license_new;
    rdp_license_new_license_info license_info;
    rdp_license_product_certificate_info license_cert_info;
    rdp_license_product_certificate_info parsed_license_cert_info;
    rdp_license_server_info license_server_info;
    rdp_license_server_info parsed_license_server_info;
    rdp_license_hardware_id hardware_id;
    rdp_license_hardware_id parsed_hardware_id;
    rdp_license_platform_challenge_response_data challenge_response_data;
    rdp_license_platform_challenge_response_data parsed_challenge_response_data;
    rdp_license_client_new_license_request client_license_request;
    rdp_license_client_info client_license_info;
    rdp_license_platform_challenge_response client_challenge_response;
    rdp_license_client_state license_state;
    uint8_t license_message_type = 0;
    rdp_virtual_channel_packet vc;
    rdp_dynamic_channel_header dyn_header;
    rdp_dynamic_channel_capabilities dyn_parsed_caps;
    rdp_dynamic_channel_create_request dyn_create_request;
    rdp_dynamic_channel_create_response dyn_create_response;
    rdp_dynamic_channel_data_pdu dyn_data_pdu;
    rdp_dynamic_channel_data_first_pdu dyn_first_pdu;
    rdp_dynamic_channel_close_pdu dyn_close_pdu;
    rdp_dynamic_channel_compressed_data_pdu dyn_compressed_pdu;
    rdp_dynamic_channel_compressed_data_first_pdu dyn_first_compressed_pdu;
    rdp_dynamic_channel_soft_sync_request dyn_soft_sync;
    rdp_dynamic_channel_soft_sync_channel_list dyn_soft_sync_list;
    rdp_dynamic_channel_soft_sync_response dyn_soft_sync_response;
    rdp_mouse_cursor_header mouse_cursor_header;
    rdp_mouse_cursor_capset mouse_cursor_capset;
    rdp_core_input_header core_header;
    rdp_core_input_init_response core_init_response;
    rdp_core_input_negotiation core_negotiation;
    rdp_core_input_event core_events[8];
    uint8_t core_event_count = 0;
    rdp_input_channel_header input_header;
    rdp_input_channel_sc_ready input_sc_ready;
    rdp_input_channel_cs_ready input_cs_ready;
    rdp_input_channel_cs_ready valid_input_cs_ready;
    rdp_input_channel_negotiation input_negotiation;
    rdp_input_channel_touch_contact input_touch_contact;
    rdp_input_channel_touch_frame input_touch_frame;
    rdp_input_channel_touch_event input_touch_event;
    rdp_input_channel_touch_event valid_input_touch_event;
    rdp_input_channel_pen_contact input_pen_contact;
    rdp_input_channel_pen_frame input_pen_frame;
    rdp_input_channel_pen_event input_pen_event;
    rdp_input_channel_pen_event valid_input_pen_event;
    uint8_t input_contact_id = 0;
    rdp_display_control_caps display_parsed_caps;
    rdp_display_control_monitor display_monitor;
    rdp_display_control_monitor display_monitors[2];
    uint8_t display_mutated[96];
    uint8_t display_bad_caps[20];
    uint32_t display_monitor_count = 0;
    rdp_graphics_header graphics_header;
    rdp_graphics_caps_confirm graphics_caps_confirm;
    rdp_graphics_capset graphics_capset;
    rdp_graphics_capset graphics_default_capsets[RDP_GRAPHICS_DEFAULT_CAPSET_LIMIT];
    uint32_t graphics_avc_runtime_support = 0;
    uint16_t graphics_default_capset_count = 0;
    uint16_t graphics_default_capset_index = 0;
    rdp_graphics_create_surface graphics_create;
    rdp_graphics_delete_surface graphics_delete;
    rdp_graphics_reset graphics_reset;
    rdp_graphics_map_surface_to_output graphics_map;
    rdp_graphics_map_surface_to_scaled_output graphics_scaled_map;
    rdp_graphics_point16 graphics_point;
    rdp_graphics_rect16 graphics_rect;
    rdp_graphics_rect16 graphics_zero_rect;
    rdp_graphics_solid_fill graphics_solid;
    rdp_graphics_wire_to_surface_1 graphics_wire1;
    rdp_graphics_wire_to_surface_2 graphics_wire2;
    rdp_graphics_surface_to_surface graphics_surface_copy;
    rdp_graphics_surface_to_cache graphics_surface_cache;
    rdp_graphics_cache_to_surface graphics_cache_surface;
    rdp_graphics_evict_cache_entry graphics_evict;
    rdp_graphics_delete_encoding_context graphics_delete_context;
    rdp_graphics_start_frame graphics_start;
    rdp_graphics_end_frame graphics_end;
    rdp_graphics_frame_ack graphics_ack;
    rdp_graphics_point16 graphics_points[2];
    rdp_graphics_decompressor graphics_decompressor;
    rdp_graphics_progressive_block graphics_progressive_block;
    rdp_graphics_progressive_context graphics_progressive_context;
    rdp_graphics_progressive_frame_begin graphics_progressive_frame_begin;
    rdp_graphics_progressive_region graphics_progressive_region;
    rdp_graphics_progressive_tile_simple graphics_progressive_simple;
    rdp_graphics_progressive_tile_first graphics_progressive_first;
    rdp_graphics_progressive_tile_upgrade graphics_progressive_upgrade;
    rdp_graphics_rect16 graphics_progressive_rect;
    rdp_graphics_progressive_stream graphics_progressive;
    rdp_graphics_avc420_quant_quality graphics_avc_quant;
    rdp_graphics_avc420_quant_quality graphics_bad_quant;
    rdp_graphics_avc420_metablock graphics_avc_meta;
    rdp_graphics_avc420_stream graphics_avc420;
    rdp_graphics_avc420_stream graphics_avc420_edge;
    rdp_graphics_avc444_stream graphics_avc444;
    rdp_graphics_avc444_stream graphics_avc444_edge;
    rdp_graphics_avc444_stream graphics_avc444_valid;
    rdp_surface_command_list surface_commands;
    rdp_surface_bits surface_bits;
    librdp_status graphics_avc_status;
    librdp_status standard_security_status;
    librdp_status ntlm_auth_status;
    rdp_avc_decoder* avc_decoder;
    rdp_avc_frame avc_frame;
    rdp_clearcodec_stream clear_stream;
    rdp_clearcodec_composite_payload clear_payload;
    rdp_clearcodec_subcodec clear_subcodec;
    rdp_clearcodec_context clear_context;
    rdp_nscodec_context nscodec_context;
    rdp_nscodec_stream nscodec_stream;
    rdp_nscodec_capability nscodec_capability;
    rdp_clipboard_packet cb;
    rdp_clipboard_capabilities cb_caps;
    rdp_clipboard_format_list cb_list;
    rdp_clipboard_format_entry cb_entry;
    rdp_clipboard_format_data_request cb_data_request;
    rdp_clipboard_format_data_response cb_data_response;
    rdp_clipboard_file_contents_request cb_file_request;
    rdp_clipboard_file_contents_response cb_file_response;
    rdp_clipboard_lock cb_lock;
    rdp_mcs_send_data_indication indication;
    rdp_credssp_state cred_state;
    rdp_security_public_key public_key;
    rdp_standard_security_context secure_a;
    rdp_standard_security_context secure_b;
    EVP_PKEY* generated_server_key = NULL;
    rdp_buffer security;
    rdp_buffer send_data;
    rdp_buffer encrypted;
    rdp_buffer encrypted_info;
    rdp_buffer plain_info_body;
    rdp_buffer expected_cipher;
    rdp_buffer protected_pdu;
    rdp_buffer unwrapped_pdu;
    rdp_buffer plain_security;
    rdp_buffer encrypted_fastpath;
    rdp_buffer decoded_fastpath;
    rdp_buffer bulk_decoded;
    rdp_buffer confirm_active;
    rdp_buffer client_sync;
    rdp_buffer client_control;
    rdp_buffer client_persistent_keys;
    rdp_buffer client_font_list;
    rdp_buffer client_keyboard_input;
    rdp_buffer client_mouse_input;
    rdp_buffer client_refresh_rect;
    rdp_buffer client_suppress_output;
    rdp_buffer graphics_decoded;
    rdp_buffer rfx_stream;
    rdp_buffer rfx_bad_stream;
    rdp_buffer planar_pixels;
    rdp_buffer nscodec_pixels;
    rdp_buffer nscodec_capability_buffer;
    rdp_buffer graphics_reset_pdu;
    rdp_buffer decoded_bitmap;
    rdp_buffer decoded_pointer;
    rdp_buffer clear_pixels;
    rdp_buffer x509_chain;
    rdp_buffer generated_server_certificate;
    rdp_buffer ntlm_negotiate;
    rdp_buffer ntlm_challenge_written;
    rdp_buffer spnego_challenge_written;
    rdp_buffer ntlm_authenticate;
    rdp_buffer spnego_negotiate;
    rdp_buffer spnego_authenticate;
    rdp_buffer ntlm_wrapped;
    rdp_buffer ntlm_unwrapped;
    rdp_buffer pub_key_auth;
    rdp_buffer server_pub_key_auth;
    rdp_buffer client_sequence_pub_key_auth;
    rdp_buffer server_sequence_pub_key_auth;
    rdp_buffer client_sequence_auth_info;
    rdp_buffer ts_credentials;
    rdp_buffer auth_info;
    rdp_buffer ts_request;
    rdp_buffer nla_request;
    rdp_buffer license_packet;
    rdp_buffer license_payload;
    rdp_buffer channel_packet;
    rdp_buffer dyn_response;
    rdp_client_info info;
    rdp_client_info no_password_info;
    rdp_client_info_summary info_summary;
    rdp_capability_list confirm_caps;
    const rdp_capability_set* confirm_bitmap_set = NULL;
    const rdp_capability_set* confirm_set = NULL;
    rdp_capability_general confirm_general;
    rdp_capability_bitmap confirm_bitmap;
    rdp_capability_order confirm_order;
    rdp_capability_bitmap_cache_v2 confirm_bitmap_cache;
    rdp_capability_pointer confirm_pointer;
    rdp_capability_large_pointer confirm_large_pointer;
    rdp_capability_input confirm_input;
    rdp_capability_brush confirm_brush;
    rdp_capability_glyph_cache confirm_glyph;
    rdp_capability_virtual_channel confirm_virtual_channel;
    rdp_capability_sound confirm_sound;
    rdp_capability_share confirm_share;
    rdp_capability_font confirm_font;
    rdp_capability_control confirm_control;
    rdp_capability_color_cache confirm_color_cache;
    rdp_capability_activation confirm_activation;
    rdp_capability_bitmap_codecs confirm_bitmap_codecs;
    rdp_nscodec_capability confirm_nscodec;
    rdp_capability_set virtual_channel_minimal_set;
    rdp_credssp_ts_request parsed_ts;
    rdp_ntlm_challenge ntlm_challenge;
    rdp_ntlm_challenge ntlm_v2_challenge;
    rdp_ntlm_authenticate parsed_ntlm_authenticate;
    rdp_ntlm_authenticate_result ntlm_auth_result;
    rdp_ntlm_authenticate_result server_auth_result;
    rdp_ntlm_authenticate_result failed_auth_result;
    rdp_ntlm_security_context ntlm_security;
    rdp_ntlm_security_context server_security;
    rdp_ntlm_security_context client_sequence_security;
    rdp_ntlm_security_context server_sequence_security;
    const uint8_t* extracted_ntlm = NULL;
    size_t extracted_ntlm_len = 0;
    uint8_t server_hash[32];
    uint16_t lm_len = 0;
    uint16_t nt_len = 0;
    uint16_t key_len = 0;
    uint32_t lm_offset = 0;
    uint32_t nt_offset = 0;
    uint32_t key_offset = 0;
    uint32_t error_info = 0;
    uint16_t security_flags = 0;
    uint8_t signature[8];
    uint8_t decrypted_client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    uint8_t standard_work1[16];
    uint8_t standard_work2[8];
    uint8_t standard_update_work[4];
    uint8_t planar_saved[16];
    uint8_t clear_saved[16];
    size_t decoded_stride = 0;
    size_t planar_saved_len = 0;
    size_t clear_saved_len = 0;
    size_t pointer_stride = 0;
    size_t i = 0;
    uint16_t confirm_source_len = 0;
    uint16_t confirm_caps_len = 0;
    uint8_t nscodec_rle_decoded[24];
    uint8_t nscodec_region_dest[64];
    const uint16_t expected_confirm_types[] = {
        RDP_CAPABILITY_TYPE_GENERAL,
        RDP_CAPABILITY_TYPE_BITMAP,
        RDP_CAPABILITY_TYPE_ORDER,
        RDP_CAPABILITY_TYPE_BITMAP_CACHE_V2,
        RDP_CAPABILITY_TYPE_POINTER,
        RDP_CAPABILITY_TYPE_LARGE_POINTER,
        RDP_CAPABILITY_TYPE_INPUT,
        RDP_CAPABILITY_TYPE_BRUSH,
        RDP_CAPABILITY_TYPE_GLYPH_CACHE,
        RDP_CAPABILITY_TYPE_VIRTUAL_CHANNEL,
        RDP_CAPABILITY_TYPE_SOUND,
        RDP_CAPABILITY_TYPE_SHARE,
        RDP_CAPABILITY_TYPE_FONT,
        RDP_CAPABILITY_TYPE_CONTROL,
        RDP_CAPABILITY_TYPE_COLOR_CACHE,
        RDP_GDI_CAPSTYPE_DRAW_NINEGRID_CACHE,
        RDP_CAPABILITY_TYPE_ACTIVATION,
        RDP_CAPABILITY_TYPE_BITMAP_CODECS
    };
    const uint16_t expected_confirm_lengths[] = {
        24, 28, 88, 40, 10, 6, 88, 8, 52, 12, 8, 8, 8, 12, 8, 12, 12, 27
    };
    const uint8_t virtual_channel_minimal_data[] = {1, 0, 0, 0};
    const uint8_t font_map_payload[] = {1, 0, 2, 0, 3, 0, 4, 0};
    const uint8_t set_error_info_payload[] = {0x34, 0x12, 0, 0};
    const uint8_t save_session_info_payload[] = {1, 0, 0, 0, 0xaa, 0x55};
    const uint8_t orders_update_payload[] = {0, 0, 0, 0};
    const uint8_t fastpath_sync_payload[] = {RDP_FASTPATH_UPDATE_SYNCHRONIZE, 0, 0};
    const uint8_t standard_plain1[] = {
        0x00, 0x01, 0x02, 0x03, 0x10, 0x20, 0x30, 0x40,
        0x55, 0xaa, 0xff, 0x7e, 0x80, 0x90, 0xfe, 0xdc
    };
    const uint8_t standard_plain2[] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48};
    const uint8_t standard_update_plain[] = {0x11, 0x22, 0x33, 0x44};
    const uint8_t standard_cipher1[] = {
        0x06, 0x5b, 0xef, 0xa9, 0x84, 0xe0, 0xbb, 0x46,
        0x51, 0x7f, 0xa7, 0xf4, 0xff, 0x0c, 0xb1, 0x12
    };
    const uint8_t standard_cipher2[] = {0x68, 0xec, 0x7e, 0xa5, 0xf2, 0x04, 0xad, 0x55};
    const uint8_t standard_update_cipher[] = {0xc6, 0x08, 0x84, 0xfe};

    memset(&parsed_ntlm_authenticate, 0, sizeof(parsed_ntlm_authenticate));
    memset(&ntlm_auth_result, 0, sizeof(ntlm_auth_result));
    memset(&server_auth_result, 0, sizeof(server_auth_result));
    memset(&failed_auth_result, 0, sizeof(failed_auth_result));
    memset(&ntlm_security, 0, sizeof(ntlm_security));
    memset(&server_security, 0, sizeof(server_security));
    memset(&client_sequence_security, 0, sizeof(client_sequence_security));
    memset(&server_sequence_security, 0, sizeof(server_sequence_security));
    rdp_buffer_init(&security);
    rdp_buffer_init(&send_data);
    rdp_buffer_init(&encrypted);
    rdp_buffer_init(&encrypted_info);
    rdp_buffer_init(&plain_info_body);
    rdp_buffer_init(&expected_cipher);
    rdp_buffer_init(&protected_pdu);
    rdp_buffer_init(&unwrapped_pdu);
    rdp_buffer_init(&plain_security);
    rdp_buffer_init(&encrypted_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    rdp_buffer_init(&bulk_decoded);
    rdp_bulk_decompressor_init(&bulk_decompressor);
    rdp_buffer_init(&confirm_active);
    rdp_buffer_init(&client_sync);
    rdp_buffer_init(&client_control);
    rdp_buffer_init(&client_persistent_keys);
    rdp_buffer_init(&client_font_list);
    rdp_buffer_init(&client_keyboard_input);
    rdp_buffer_init(&client_mouse_input);
    rdp_buffer_init(&client_refresh_rect);
    rdp_buffer_init(&client_suppress_output);
    rdp_graphics_decompressor_init(&graphics_decompressor);
    rdp_clearcodec_context_init(&clear_context);
    rdp_nscodec_context_init(&nscodec_context);
    PCHECK(RDP_GRAPHICS_BULK_MAX_DECODED == 64u * 1024u * 1024u);
    rdp_graphics_decompressor_reset(&graphics_decompressor);
    rdp_clearcodec_context_reset(&clear_context);
    rdp_nscodec_context_reset(&nscodec_context);
    rdp_buffer_init(&graphics_decoded);
    rdp_buffer_init(&rfx_stream);
    rdp_buffer_init(&rfx_bad_stream);
    rdp_buffer_init(&planar_pixels);
    rdp_buffer_init(&nscodec_pixels);
    rdp_buffer_init(&nscodec_capability_buffer);
    rdp_buffer_init(&graphics_reset_pdu);
    rdp_buffer_init(&decoded_bitmap);
    rdp_buffer_init(&decoded_pointer);
    rdp_buffer_init(&clear_pixels);
    rdp_buffer_init(&x509_chain);
    rdp_buffer_init(&generated_server_certificate);
    rdp_buffer_init(&ntlm_negotiate);
    rdp_buffer_init(&ntlm_challenge_written);
    rdp_buffer_init(&spnego_challenge_written);
    rdp_buffer_init(&ntlm_authenticate);
    rdp_buffer_init(&spnego_negotiate);
    rdp_buffer_init(&spnego_authenticate);
    rdp_buffer_init(&ntlm_wrapped);
    rdp_buffer_init(&ntlm_unwrapped);
    rdp_buffer_init(&pub_key_auth);
    rdp_buffer_init(&server_pub_key_auth);
    rdp_buffer_init(&client_sequence_pub_key_auth);
    rdp_buffer_init(&server_sequence_pub_key_auth);
    rdp_buffer_init(&client_sequence_auth_info);
    rdp_buffer_init(&ts_credentials);
    rdp_buffer_init(&auth_info);
    rdp_buffer_init(&ts_request);
    rdp_buffer_init(&nla_request);
    rdp_buffer_init(&license_packet);
    rdp_buffer_init(&license_payload);
    rdp_buffer_init(&channel_packet);
    rdp_buffer_init(&dyn_response);

    PCHECK(rdp_fastpath_parse_header(fast_short, sizeof(fast_short), &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 6 && fast.header_length == 2 && !fast.long_length);
    PCHECK(rdp_fastpath_parse_header(fast_long, sizeof(fast_long), &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 8 && fast.header_length == 3 && fast.long_length);
    {
        const rdp_fastpath_header valid_fast_header = fast;

        PCHECK(rdp_fastpath_parse_header(fast_long, 2, &fast) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&fast, &valid_fast_header, sizeof(fast)) == 0);
    }
    PCHECK(rdp_fastpath_write_header(&decoded_fastpath,
                                     RDP_FASTPATH_OUTPUT_ACTION_FASTPATH,
                                     0,
                                     4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&decoded_fastpath, fast_payload, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_fastpath_parse_header(decoded_fastpath.data,
                                     decoded_fastpath.length,
                                     &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 6 && fast.header_length == 2 && !fast.long_length);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    PCHECK(rdp_fastpath_write_header(&decoded_fastpath,
                                     RDP_FASTPATH_OUTPUT_ACTION_FASTPATH,
                                     0,
                                     130) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&decoded_fastpath, fast_payload, sizeof(fast_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_fastpath_parse_header(decoded_fastpath.data,
                                     decoded_fastpath.length,
                                     &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 133 && fast.header_length == 3 && fast.long_length);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    PCHECK(rdp_fastpath_write_header(&decoded_fastpath, 2, 0, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_fastpath_parse_updates(fast_bitmap_update, sizeof(fast_bitmap_update), &fast_updates) ==
           LIBRDP_STATUS_OK);
    PCHECK(fast_updates.count == 1 && fast_updates.updates[0].update_code == RDP_FASTPATH_UPDATE_BITMAP &&
           fast_updates.updates[0].fragmentation == RDP_FASTPATH_FRAGMENT_SINGLE &&
           fast_updates.updates[0].compression == 0 && fast_updates.updates[0].data_len == 36);
    PCHECK(rdp_fastpath_write_updates(&decoded_fastpath,
                                      fast_updates.updates,
                                      fast_updates.count) == LIBRDP_STATUS_OK);
    PCHECK(rdp_fastpath_parse_updates(decoded_fastpath.data,
                                      decoded_fastpath.length,
                                      &fast_updates) == LIBRDP_STATUS_OK);
    PCHECK(fast_updates.count == 1 &&
           fast_updates.updates[0].update_code == RDP_FASTPATH_UPDATE_BITMAP &&
           fast_updates.updates[0].data_len == 36);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    PCHECK(rdp_fastpath_parse_updates(fast_bitmap_update, sizeof(fast_bitmap_update), &fast_updates) ==
           LIBRDP_STATUS_OK);
    fast_updates.updates[0].compression = RDP_FASTPATH_OUTPUT_COMPRESSION_USED;
    fast_updates.updates[0].compression_flags = 0x20u;
    PCHECK(rdp_fastpath_write_updates(&decoded_fastpath,
                                      fast_updates.updates,
                                      1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_fastpath_parse_updates(decoded_fastpath.data,
                                      decoded_fastpath.length,
                                      &fast_updates) == LIBRDP_STATUS_OK);
    PCHECK(fast_updates.updates[0].compression == RDP_FASTPATH_OUTPUT_COMPRESSION_USED &&
           fast_updates.updates[0].compression_flags == 0x20u);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                               0,
                               "raw",
                               3,
                               &bulk_decoded) == LIBRDP_STATUS_OK);
    PCHECK(bulk_decoded.length == 3 && memcmp(bulk_decoded.data, "raw", 3) == 0);
    bulk_decoded.length = 0;
    {
        const uint8_t mppc_literal[] = {0x41};

        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_PACKET_FLUSHED | RDP_BULK_TYPE_8K,
                                   mppc_literal,
                                   sizeof(mppc_literal),
                                   &bulk_decoded) == LIBRDP_STATUS_OK);
        PCHECK(bulk_decoded.length == 1 && bulk_decoded.data[0] == 'A');
    }
    bulk_decoded.length = 0;
    {
        const uint8_t mppc_match[] = {0x41, 0x42, 0x43, 0xf0, 0xc0};

        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_PACKET_FLUSHED | RDP_BULK_TYPE_8K,
                                   mppc_match,
                                   sizeof(mppc_match),
                                   &bulk_decoded) == LIBRDP_STATUS_OK);
        PCHECK(bulk_decoded.length == 6 && memcmp(bulk_decoded.data, "ABCABC", 6) == 0);
    }
    bulk_decoded.length = 0;
    {
        const uint8_t mppc_literal64[] = {0x58};

        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_PACKET_FLUSHED | RDP_BULK_TYPE_64K,
                                   mppc_literal64,
                                   sizeof(mppc_literal64),
                                   &bulk_decoded) == LIBRDP_STATUS_OK);
        PCHECK(bulk_decoded.length == 1 && bulk_decoded.data[0] == 'X');
    }
    bulk_decoded.length = 0;
    {
        const uint8_t rdp6_literals[] = {
            0x47, 0xee, 0x33, 0x63, 0xfd, 0xff, 0x0b, 0x00
        };
        const uint8_t rdp6_match[] = {
            0x7b, 0xee, 0xb5, 0xf7, 0x7f, 0xfc, 0x5f, 0x00
        };
        const uint8_t rdp6_short[] = {0x47, 0xee, 0x33};

        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_PACKET_FLUSHED | RDP_BULK_TYPE_RDP6,
                                   rdp6_literals,
                                   sizeof(rdp6_literals),
                                   &bulk_decoded) == LIBRDP_STATUS_OK);
        PCHECK(bulk_decoded.length == 4 && memcmp(bulk_decoded.data, "rdp6", 4) == 0);
        bulk_decoded.length = 0;
        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_PACKET_FLUSHED | RDP_BULK_TYPE_RDP6,
                                   rdp6_match,
                                   sizeof(rdp6_match),
                                   &bulk_decoded) == LIBRDP_STATUS_OK);
        PCHECK(bulk_decoded.length == 6 && memcmp(bulk_decoded.data, "abcabc", 6) == 0);
        bulk_decoded.length = 0;
        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_PACKET_FLUSHED | RDP_BULK_TYPE_RDP6,
                                   rdp6_short,
                                   sizeof(rdp6_short),
                                   &bulk_decoded) == LIBRDP_STATUS_PROTOCOL_ERROR);
    }
    bulk_decoded.length = 0;
    rdp_bulk_decompressor_reset(&bulk_decompressor);
    {
        const uint8_t rdp61_literals[] = {
            0x06, 0x00,
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'
        };
        const uint8_t rdp61_matches[] = {
            0x01, 0x00,
            0x02, 0x00,
            0x09, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00,
            'k', 'l', 'm', 'n', 'o', 'u'
        };
        const char expected[] = "klmnodefghijklabcdu";

        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_TYPE_RDP61,
                                   rdp61_literals,
                                   sizeof(rdp61_literals),
                                   &bulk_decoded) == LIBRDP_STATUS_OK);
        PCHECK(bulk_decoded.length == 10 && memcmp(bulk_decoded.data, "abcdefghij", 10) == 0);
        bulk_decoded.length = 0;
        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_TYPE_RDP61,
                                   rdp61_matches,
                                   sizeof(rdp61_matches),
                                   &bulk_decoded) == LIBRDP_STATUS_OK);
        PCHECK(bulk_decoded.length == sizeof(expected) - 1u &&
               memcmp(bulk_decoded.data, expected, sizeof(expected) - 1u) == 0);
    }
    bulk_decoded.length = 0;
    {
        const uint8_t rdp61_inner_literals[] = {
            0x12, RDP_BULK_TYPE_64K,
            'i', 'n', 'n', 'e', 'r'
        };

        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_TYPE_RDP61,
                                   rdp61_inner_literals,
                                   sizeof(rdp61_inner_literals),
                                   &bulk_decoded) == LIBRDP_STATUS_OK);
        PCHECK(bulk_decoded.length == 5 && memcmp(bulk_decoded.data, "inner", 5) == 0);
    }
    bulk_decoded.length = 0;
    {
        const uint8_t rdp61_bad_match_order[] = {
            0x01, 0x00,
            0x02, 0x00,
            0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            'x', 'y'
        };

        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_TYPE_RDP61,
                                   rdp61_bad_match_order,
                                   sizeof(rdp61_bad_match_order),
                                   &bulk_decoded) == LIBRDP_STATUS_PROTOCOL_ERROR);
    }
    PCHECK(rdp_fastpath_write_update(&decoded_fastpath,
                                     0x0fu,
                                     RDP_FASTPATH_FRAGMENT_SINGLE,
                                     0,
                                     0,
                                     NULL,
                                     0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_fastpath_write_header(&decoded_fastpath,
                                     RDP_FASTPATH_OUTPUT_ACTION_FASTPATH,
                                     0,
                                     3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&decoded_fastpath, 0x0fu) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&decoded_fastpath, 0u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_fastpath_parse_updates(decoded_fastpath.data,
                                      decoded_fastpath.length,
                                      &fast_updates) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    {
        rdp_fastpath_update sync_update;
        uint8_t sync_payload = 0;

        memset(&sync_update, 0, sizeof(sync_update));
        sync_update.update_code = RDP_FASTPATH_UPDATE_SYNCHRONIZE;
        sync_update.fragmentation = RDP_FASTPATH_FRAGMENT_SINGLE;
        PCHECK(rdp_fastpath_write_updates(&decoded_fastpath,
                                          &sync_update,
                                          1) == LIBRDP_STATUS_OK);
        PCHECK(rdp_fastpath_parse_updates(decoded_fastpath.data,
                                          decoded_fastpath.length,
                                          &fast_updates) == LIBRDP_STATUS_OK);
        PCHECK(fast_updates.count == 1 &&
               fast_updates.updates[0].update_code == RDP_FASTPATH_UPDATE_SYNCHRONIZE &&
               fast_updates.updates[0].data_len == 0);
        PCHECK(rdp_fastpath_write_update(&decoded_fastpath,
                                         RDP_FASTPATH_UPDATE_SYNCHRONIZE,
                                         RDP_FASTPATH_FRAGMENT_FIRST,
                                         0,
                                         0,
                                         NULL,
                                         0) == LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(rdp_fastpath_write_update(&decoded_fastpath,
                                         RDP_FASTPATH_UPDATE_SYNCHRONIZE,
                                         RDP_FASTPATH_FRAGMENT_SINGLE,
                                         0,
                                         0,
                                         &sync_payload,
                                         1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    }
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    PCHECK(rdp_fastpath_write_header(&decoded_fastpath,
                                     RDP_FASTPATH_OUTPUT_ACTION_FASTPATH,
                                     0,
                                     4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&decoded_fastpath, RDP_FASTPATH_UPDATE_SYNCHRONIZE) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&decoded_fastpath, 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&decoded_fastpath, 0u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_fastpath_parse_updates(decoded_fastpath.data,
                                      decoded_fastpath.length,
                                      &fast_updates) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    PCHECK(rdp_fastpath_parse_updates(fast_bitmap_update, sizeof(fast_bitmap_update), &fast_updates) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_bitmap_parse_fastpath_update(fast_updates.updates[0].data,
                                            fast_updates.updates[0].data_len,
                                            &bitmap_update) == LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1 && bitmap_update.rects[0].data_len == 16);
    {
        const rdp_fastpath_update_list valid_fast_updates = fast_updates;

        PCHECK(rdp_fastpath_parse_updates(fast_bitmap_update,
                                          sizeof(fast_bitmap_update) - 1u,
                                          &fast_updates) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&fast_updates, &valid_fast_updates, sizeof(fast_updates)) == 0);
        PCHECK(rdp_fastpath_parse_updates(fast_bad_update_compression,
                                          sizeof(fast_bad_update_compression),
                                          &fast_updates) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&fast_updates, &valid_fast_updates, sizeof(fast_updates)) == 0);
        PCHECK(rdp_fastpath_parse_updates(fast_long, sizeof(fast_long), &fast_updates) ==
               LIBRDP_STATUS_STATE);
        PCHECK(memcmp(&fast_updates, &valid_fast_updates, sizeof(fast_updates)) == 0);
        PCHECK(rdp_fastpath_parse_updates_payload(fast_long + 3u,
                                                  sizeof(fast_long) - 3u,
                                                  &fast_updates) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&fast_updates, &valid_fast_updates, sizeof(fast_updates)) == 0);
    }
    PCHECK(rdp_surface_commands_parse(surface_command_payload,
                                      sizeof(surface_command_payload),
                                      &surface_commands) == LIBRDP_STATUS_OK);
    PCHECK(surface_commands.count == 2 &&
           surface_commands.commands[0].kind == RDP_SURFACE_COMMAND_KIND_BITS &&
           surface_commands.commands[0].bits.command_type == RDP_SURFACE_COMMAND_SET_BITS &&
           surface_commands.commands[0].bits.dest_left == 1 &&
           surface_commands.commands[0].bits.dest_top == 2 &&
           surface_commands.commands[0].bits.width == 2 &&
           surface_commands.commands[0].bits.height == 2 &&
           surface_commands.commands[0].bits.codec_id == RDP_SURFACE_CODEC_NONE &&
           surface_commands.commands[0].bits.bitmap_data_length == 16 &&
           surface_commands.commands[0].bits.bitmap_data[15] == 16 &&
           surface_commands.commands[1].kind == RDP_SURFACE_COMMAND_KIND_FRAME_MARKER &&
           surface_commands.commands[1].frame_marker.action == 1 &&
           surface_commands.commands[1].frame_marker.frame_id == 0x11223344u);
    {
        rdp_surface_command_list valid_surface_commands = surface_commands;

        PCHECK(rdp_surface_commands_parse(surface_command_payload,
                                          sizeof(surface_command_payload) - 1u,
                                          &surface_commands) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&surface_commands,
                      &valid_surface_commands,
                      sizeof(surface_commands)) == 0);
        PCHECK(rdp_surface_commands_parse(surface_command_short_frame_marker,
                                          sizeof(surface_command_short_frame_marker),
                                          &surface_commands) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&surface_commands,
                      &valid_surface_commands,
                      sizeof(surface_commands)) == 0);
    }
    PCHECK(rdp_surface_commands_parse(surface_command_extended,
                                      sizeof(surface_command_extended),
                                      &surface_commands) == LIBRDP_STATUS_OK);
    PCHECK(surface_commands.count == 1 &&
           surface_commands.commands[0].bits.command_type == RDP_SURFACE_COMMAND_STREAM_BITS &&
           surface_commands.commands[0].bits.has_extended_header == 1 &&
           surface_commands.commands[0].bits.codec_id == RDP_SURFACE_CODEC_NSCODEC &&
           surface_commands.commands[0].bits.high_unique_id == 0x12345678u &&
           surface_commands.commands[0].bits.low_unique_id == 0x90abcdefu &&
           surface_commands.commands[0].bits.timestamp_ms == 0x0102030405060708ull &&
           surface_commands.commands[0].bits.timestamp_s == 0x1112131415161718ull);
    surface_bits = surface_commands.commands[0].bits;
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_surface_commands_write_bits(&dyn_response, &surface_bits) == LIBRDP_STATUS_OK);
    PCHECK(rdp_surface_commands_write_frame_marker(&dyn_response, 0, 0x01020304u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_surface_commands_parse(dyn_response.data, dyn_response.length, &surface_commands) ==
           LIBRDP_STATUS_OK);
    PCHECK(surface_commands.count == 2 &&
           surface_commands.commands[0].bits.bitmap_data[3] == 0xdd &&
           surface_commands.commands[1].frame_marker.frame_id == 0x01020304u);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    {
        size_t command_index = 0;

        for (command_index = 0; command_index < RDP_SURFACE_COMMAND_MAX_COMMANDS + 1u; command_index++)
        {
            PCHECK(rdp_surface_commands_write_frame_marker(&dyn_response,
                                                           1,
                                                           (uint32_t)command_index) == LIBRDP_STATUS_OK);
        }
        PCHECK(rdp_surface_commands_parse(dyn_response.data,
                                          dyn_response.length,
                                          &surface_commands) == LIBRDP_STATUS_PROTOCOL_ERROR);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NULL, NULL, 0, &pointer_update) ==
           LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_NULL);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_DEFAULT, NULL, 0, &pointer_update) ==
           LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_DEFAULT);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_POSITION,
                                      pointer_slow_position + 2,
                                      sizeof(pointer_slow_position) - 2u,
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_POSITION &&
           pointer_update.x == 0x22 && pointer_update.y == 0x33);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_CACHED,
                                      pointer_shape_32 + 2,
                                      2,
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_CACHED && pointer_update.cache_index == 5);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                      pointer_shape_32,
                                      sizeof(pointer_shape_32),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.cache_index == 5 &&
           pointer_update.hot_x == 1 &&
           pointer_update.hot_y == 0 &&
           pointer_update.width == 2 &&
           pointer_update.height == 2 &&
           pointer_update.xor_bpp == 32);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 8 &&
           decoded_pointer.length == 16 &&
           decoded_pointer.data[0] == 0x00 &&
           decoded_pointer.data[1] == 0x00 &&
           decoded_pointer.data[2] == 0xff &&
           decoded_pointer.data[3] == 0xff &&
           decoded_pointer.data[4] == 0x00 &&
           decoded_pointer.data[5] == 0xff &&
           decoded_pointer.data[6] == 0x00 &&
           decoded_pointer.data[7] == 0xff &&
           decoded_pointer.data[15] == 0x00);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                      pointer_shape_16,
                                      sizeof(pointer_shape_16),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.xor_bpp == 16 &&
           pointer_update.cache_index == 8);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 8 &&
           decoded_pointer.length == 8 &&
           decoded_pointer.data[0] == 0x00 &&
           decoded_pointer.data[1] == 0x00 &&
           decoded_pointer.data[2] == 0xff &&
           decoded_pointer.data[4] == 0x00 &&
           decoded_pointer.data[5] == 0xff &&
           decoded_pointer.data[6] == 0x00);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                      pointer_shape_15,
                                      sizeof(pointer_shape_15),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.xor_bpp == 15 &&
           pointer_update.cache_index == 9);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 8 &&
           decoded_pointer.length == 8 &&
           decoded_pointer.data[0] == 0x00 &&
           decoded_pointer.data[1] == 0x00 &&
           decoded_pointer.data[2] == 0xff &&
           decoded_pointer.data[4] == 0x00 &&
           decoded_pointer.data[5] == 0xff &&
           decoded_pointer.data[6] == 0x00);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                      pointer_shape_1bpp_invert,
                                      sizeof(pointer_shape_1bpp_invert),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.xor_bpp == 1 &&
           pointer_update.cache_index == 6);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 4 &&
           decoded_pointer.length == 4 &&
           decoded_pointer.data[0] == 0x00 &&
           decoded_pointer.data[1] == 0x00 &&
           decoded_pointer.data[2] == 0x00 &&
           decoded_pointer.data[3] == 0xff);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                      pointer_shape_1bpp_transparent,
                                      sizeof(pointer_shape_1bpp_transparent),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 4 &&
           decoded_pointer.length == 4 &&
           decoded_pointer.data[3] == 0x00);
    {
        const rdp_pointer_update valid_pointer_update = pointer_update;

        PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                          pointer_shape_32,
                                          sizeof(pointer_shape_32) - 1u,
                                          &pointer_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&pointer_update, &valid_pointer_update, sizeof(pointer_update)) == 0);
    }
    PCHECK(rdp_pointer_parse_slowpath(pointer_slow_position,
                                      sizeof(pointer_slow_position),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_POSITION &&
           pointer_update.x == 0x22 && pointer_update.y == 0x33);
    PCHECK(rdp_pointer_parse_slowpath(pointer_slow_system_default,
                                      sizeof(pointer_slow_system_default),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_DEFAULT);
    PCHECK(rdp_pointer_parse_slowpath(pointer_slow_large,
                                      sizeof(pointer_slow_large),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.cache_index == 5 &&
           pointer_update.width == 2 &&
           pointer_update.height == 2 &&
           pointer_update.xor_bpp == 32);
    {
        const rdp_pointer_update valid_pointer_update = pointer_update;

        PCHECK(rdp_pointer_parse_slowpath(pointer_slow_large,
                                          sizeof(pointer_slow_large) - 1u,
                                          &pointer_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&pointer_update, &valid_pointer_update, sizeof(pointer_update)) == 0);
    }

    PCHECK(rdp_slowpath_parse_share_control_header(slow, sizeof(slow), &slow_header) == LIBRDP_STATUS_OK);
    PCHECK(slow_header.total_length == 6 && slow_header.pdu_type == 0x13);
    {
        const rdp_slowpath_share_control_header valid_slow_header = slow_header;

        PCHECK(rdp_slowpath_parse_share_control_header(slow, sizeof(slow) - 1u, &slow_header) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&slow_header, &valid_slow_header, sizeof(slow_header)) == 0);
        PCHECK(rdp_slowpath_parse_share_control_header(slow_trailing,
                                                       sizeof(slow_trailing),
                                                       &slow_header) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&slow_header, &valid_slow_header, sizeof(slow_header)) == 0);
    }
    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_init(&client_refresh_rect);
    PCHECK(rdp_slowpath_write_share_control_header(&client_refresh_rect,
                                                   6,
                                                   (uint16_t)(RDP_SLOWPATH_PDU_VERSION |
                                                              RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE),
                                                   1004) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_share_control_header(client_refresh_rect.data,
                                                   client_refresh_rect.length,
                                                   &slow_header) == LIBRDP_STATUS_OK);
    PCHECK(slow_header.total_length == 6 &&
           slow_header.pdu_type == (RDP_SLOWPATH_PDU_VERSION | RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE) &&
           slow_header.channel_id == 1004);
    PCHECK(rdp_slowpath_write_share_control_header(&client_refresh_rect,
                                                   5,
                                                   RDP_SLOWPATH_PDU_VERSION,
                                                   1004) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_parse_demand_active(demand_active, sizeof(demand_active), &demand) == LIBRDP_STATUS_OK);
    PCHECK(demand.share_id == 0x12345678u);
    PCHECK(demand.session_id == 0x11223344u);
    PCHECK(demand.source_descriptor_len == 3 && memcmp(demand.source_descriptor, "srv", 3) == 0);
    PCHECK(demand.capabilities.count == 1 && demand.capabilities.sets[0].type == 1);
    PCHECK(rdp_capabilities_find(&demand.capabilities, RDP_CAPABILITY_TYPE_GENERAL) == &demand.capabilities.sets[0]);
    PCHECK(rdp_capabilities_find(&demand.capabilities, RDP_CAPABILITY_TYPE_BITMAP) == NULL);
    {
        const rdp_slowpath_demand_active valid_demand = demand;

        PCHECK(rdp_slowpath_parse_demand_active(demand_active, sizeof(demand_active) - 1u, &demand) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&demand, &valid_demand, sizeof(demand)) == 0);
        PCHECK(rdp_slowpath_parse_demand_active(demand_active_trailing,
                                                sizeof(demand_active_trailing),
                                                &demand) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&demand, &valid_demand, sizeof(demand)) == 0);
    }
    PCHECK(rdp_capabilities_parse(capability_list_trailing,
                                  sizeof(capability_list_trailing),
                                  &confirm_caps) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_slowpath_parse_data_pdu(bitmap_data_pdu, sizeof(bitmap_data_pdu), &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.share_id == 0x12345678u && data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE);
    PCHECK(data_pdu.payload_len == 38);
    {
        const rdp_slowpath_data_pdu valid_data_pdu = data_pdu;

        memcpy(malformed_slowpath, bitmap_data_pdu, sizeof(malformed_slowpath));
        malformed_slowpath[10] = 1;
        PCHECK(rdp_slowpath_parse_data_pdu(malformed_slowpath,
                                           sizeof(malformed_slowpath),
                                           &data_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&data_pdu, &valid_data_pdu, sizeof(data_pdu)) == 0);
        memcpy(malformed_slowpath, bitmap_data_pdu, sizeof(malformed_slowpath));
        malformed_slowpath[11] = 0;
        PCHECK(rdp_slowpath_parse_data_pdu(malformed_slowpath,
                                           sizeof(malformed_slowpath),
                                           &data_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&data_pdu, &valid_data_pdu, sizeof(data_pdu)) == 0);
        memcpy(malformed_slowpath, bitmap_data_pdu, sizeof(malformed_slowpath));
        malformed_slowpath[15] = 0x20;
        PCHECK(rdp_slowpath_parse_data_pdu(malformed_slowpath,
                                           sizeof(malformed_slowpath),
                                           &data_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&data_pdu, &valid_data_pdu, sizeof(data_pdu)) == 0);
        memcpy(trailing_slowpath, bitmap_data_pdu, sizeof(bitmap_data_pdu));
        trailing_slowpath[sizeof(bitmap_data_pdu)] = 0xffu;
        PCHECK(rdp_slowpath_parse_data_pdu(trailing_slowpath,
                                           sizeof(trailing_slowpath),
                                           &data_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&data_pdu, &valid_data_pdu, sizeof(data_pdu)) == 0);
    }
    PCHECK(rdp_slowpath_parse_data_pdu(bitmap_data_pdu, sizeof(bitmap_data_pdu), &data_pdu) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_init(&client_refresh_rect);
    PCHECK(rdp_slowpath_write_share_data_header(&client_refresh_rect,
                                                data_pdu.share_id,
                                                data_pdu.stream_id,
                                                data_pdu.uncompressed_length,
                                                data_pdu.pdu_type2,
                                                data_pdu.compressed_type,
                                                data_pdu.compressed_length) == LIBRDP_STATUS_OK);
    PCHECK(client_refresh_rect.length == 12 &&
           test_read_u32_le(client_refresh_rect.data) == data_pdu.share_id &&
           client_refresh_rect.data[5] == data_pdu.stream_id &&
           client_refresh_rect.data[8] == data_pdu.pdu_type2);
    PCHECK(rdp_slowpath_write_share_data_header(&client_refresh_rect,
                                                data_pdu.share_id,
                                                0,
                                                data_pdu.uncompressed_length,
                                                data_pdu.pdu_type2,
                                                0,
                                                0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_write_share_data_header(&client_refresh_rect,
                                                data_pdu.share_id,
                                                data_pdu.stream_id,
                                                data_pdu.uncompressed_length,
                                                data_pdu.pdu_type2,
                                                0x20,
                                                0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_bitmap_parse_update_header(data_pdu.payload, data_pdu.payload_len, &bitmap_header) ==
           LIBRDP_STATUS_OK);
    PCHECK(bitmap_header.update_type == RDP_UPDATE_TYPE_BITMAP && bitmap_header.count == 1);
    {
        const rdp_bitmap_update_header valid_bitmap_header = bitmap_header;

        PCHECK(rdp_bitmap_parse_update_header(data_pdu.payload, 3, &bitmap_header) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&bitmap_header, &valid_bitmap_header, sizeof(bitmap_header)) == 0);
    }
    PCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &bitmap_update) == LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1);
    PCHECK(bitmap_update.rects[0].width == 2 && bitmap_update.rects[0].height == 2);
    PCHECK(bitmap_update.rects[0].bits_per_pixel == 32 && bitmap_update.rects[0].data_len == 16);
    {
        const rdp_bitmap_update valid_bitmap_update = bitmap_update;

        PCHECK(rdp_bitmap_parse_update(data_pdu.payload,
                                       data_pdu.payload_len - 1u,
                                       &bitmap_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&bitmap_update, &valid_bitmap_update, sizeof(bitmap_update)) == 0);
    }
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_update.rects[0], &decoded_bitmap, &decoded_stride) ==
           LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.length == 16 && decoded_bitmap.data[0] == 9 &&
           decoded_bitmap.data[1] == 10 && decoded_bitmap.data[2] == 11 && decoded_bitmap.data[3] == 12);
    bitmap_rect = bitmap_update.rects[0];
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_init(&decoded_bitmap);
    PCHECK(rdp_bitmap_write_update(&decoded_bitmap, &bitmap_rect, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_bitmap_parse_update(decoded_bitmap.data, decoded_bitmap.length, &bitmap_update) == LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1 &&
           bitmap_update.rects[0].width == 2 &&
           bitmap_update.rects[0].height == 2 &&
           bitmap_update.rects[0].data_len == 16);
    PCHECK(rdp_bitmap_parse_fastpath_update(decoded_bitmap.data,
                                            decoded_bitmap.length,
                                            &bitmap_update) == LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1 &&
           bitmap_update.rects[0].bits_per_pixel == 32 &&
           bitmap_update.rects[0].data_len == 16);
    {
        const rdp_bitmap_update valid_bitmap_update = bitmap_update;

        PCHECK(rdp_bitmap_parse_fastpath_update(decoded_bitmap.data,
                                                decoded_bitmap.length - 1u,
                                                &bitmap_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&bitmap_update, &valid_bitmap_update, sizeof(bitmap_update)) == 0);
    }
    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_init(&client_refresh_rect);
    PCHECK(rdp_slowpath_write_data_pdu(&client_refresh_rect,
                                       data_pdu.share_id,
                                       data_pdu.header.channel_id,
                                       RDP_SLOWPATH_DATA_PDU_UPDATE,
                                       decoded_bitmap.data,
                                       decoded_bitmap.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_refresh_rect.data,
                                       client_refresh_rect.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE &&
           data_pdu.payload_len == decoded_bitmap.length);
    PCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &bitmap_update) ==
           LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1 && bitmap_update.rects[0].data_len == 16);
    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_init(&client_refresh_rect);
    PCHECK(rdp_slowpath_parse_data_pdu(bitmap_data_pdu, sizeof(bitmap_data_pdu), &data_pdu) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_init(&decoded_bitmap);
    PCHECK(rdp_bitmap_write_fastpath_update(&decoded_bitmap, &bitmap_rect, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_bitmap_parse_fastpath_update(decoded_bitmap.data,
                                            decoded_bitmap.length,
                                            &bitmap_update) == LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1 &&
           bitmap_update.rects[0].bits_per_pixel == 32 &&
           bitmap_update.rects[0].data_len == 16);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_init(&decoded_bitmap);
    PCHECK(rdp_bitmap_parse_palette_update(palette_update_data, sizeof(palette_update_data), &palette_update) ==
           LIBRDP_STATUS_OK);
    PCHECK(palette_update.count == 4 && palette_update.entries[1].red == 200 &&
           palette_update.entries[1].green == 100 && palette_update.entries[1].blue == 50);
    PCHECK(rdp_bitmap_parse_fastpath_palette_update(palette_fastpath_data,
                                                    sizeof(palette_fastpath_data),
                                                    &palette_roundtrip) == LIBRDP_STATUS_OK);
    PCHECK(palette_roundtrip.count == 4 && palette_roundtrip.entries[3].red == 9 &&
           palette_roundtrip.entries[3].green == 8 && palette_roundtrip.entries[3].blue == 7);
    {
        const rdp_palette_update valid_palette_update = palette_roundtrip;

        PCHECK(rdp_bitmap_parse_palette_update(palette_fastpath_data,
                                               sizeof(palette_fastpath_data),
                                               &palette_roundtrip) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&palette_roundtrip, &valid_palette_update, sizeof(palette_roundtrip)) == 0);
        PCHECK(rdp_bitmap_parse_palette_update(palette_invalid_count,
                                               sizeof(palette_invalid_count),
                                               &palette_roundtrip) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&palette_roundtrip, &valid_palette_update, sizeof(palette_roundtrip)) == 0);
        PCHECK(rdp_bitmap_parse_fastpath_palette_update(palette_fastpath_data,
                                                        sizeof(palette_fastpath_data) - 1u,
                                                        &palette_roundtrip) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&palette_roundtrip, &valid_palette_update, sizeof(palette_roundtrip)) == 0);
    }
    PCHECK(rdp_bitmap_write_palette_update(&decoded_bitmap, &palette_update) == LIBRDP_STATUS_OK);
    PCHECK(rdp_bitmap_parse_palette_update(decoded_bitmap.data,
                                           decoded_bitmap.length,
                                           &palette_roundtrip) == LIBRDP_STATUS_OK);
    PCHECK(palette_roundtrip.count == 4 && palette_roundtrip.entries[0].red == 10 &&
           palette_roundtrip.entries[2].blue == 3);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_init(&decoded_bitmap);
    PCHECK(rdp_bitmap_write_fastpath_palette_update(&decoded_bitmap, &palette_update) == LIBRDP_STATUS_OK);
    PCHECK(rdp_bitmap_parse_fastpath_palette_update(decoded_bitmap.data,
                                                    decoded_bitmap.length,
                                                    &palette_roundtrip) == LIBRDP_STATUS_OK);
    PCHECK(palette_roundtrip.count == 4 && palette_roundtrip.entries[1].green == 100);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_init(&decoded_bitmap);
    PCHECK(rdp_bitmap_write_rect(&decoded_bitmap, &bitmap_rect) == LIBRDP_STATUS_OK);
    PCHECK(decoded_bitmap.length == 34);
    bitmap_rect.width = 0;
    PCHECK(rdp_bitmap_write_rect(&decoded_bitmap, &bitmap_rect) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_init(&decoded_bitmap);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 2;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 1;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 24;
    bitmap_rect.data = bitmap_24_data;
    bitmap_rect.data_len = sizeof(bitmap_24_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.length == 16 && decoded_bitmap.data[0] == 7 &&
           decoded_bitmap.data[1] == 8 && decoded_bitmap.data[2] == 9 && decoded_bitmap.data[3] == 0xff);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 1;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 0;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 24;
    bitmap_rect.data = bitmap_24_padded_data;
    bitmap_rect.data_len = sizeof(bitmap_24_padded_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 4 &&
           decoded_bitmap.length == 8 &&
           decoded_bitmap.data[0] == 4 &&
           decoded_bitmap.data[1] == 5 &&
           decoded_bitmap.data[2] == 6 &&
           decoded_bitmap.data[4] == 1 &&
           decoded_bitmap.data[5] == 2 &&
           decoded_bitmap.data[6] == 3);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 2;
    bitmap_rect.height = 1;
    bitmap_rect.dest_right = 1;
    bitmap_rect.bits_per_pixel = 16;
    bitmap_rect.data = bitmap_16_data;
    bitmap_rect.data_len = sizeof(bitmap_16_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.data[0] == 0 && decoded_bitmap.data[1] == 0 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[4] == 0 && decoded_bitmap.data[5] == 255 &&
           decoded_bitmap.data[6] == 0);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 2;
    bitmap_rect.height = 1;
    bitmap_rect.dest_right = 1;
    bitmap_rect.bits_per_pixel = 15;
    bitmap_rect.data = bitmap_15_data;
    bitmap_rect.data_len = sizeof(bitmap_15_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.data[0] == 0 && decoded_bitmap.data[1] == 0 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[4] == 0 && decoded_bitmap.data[5] == 255 &&
           decoded_bitmap.data[6] == 0);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 2;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 1;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 8;
    bitmap_rect.data = bitmap_8_data;
    bitmap_rect.data_len = sizeof(bitmap_8_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) ==
           LIBRDP_STATUS_STATE);
    PCHECK(rdp_bitmap_decode_rect_bgra32_with_palette(&bitmap_rect,
                                                      &palette_update,
                                                      &decoded_bitmap,
                                                      &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.length == 16 &&
           decoded_bitmap.data[0] == 3 && decoded_bitmap.data[1] == 2 &&
           decoded_bitmap.data[2] == 1 && decoded_bitmap.data[4] == 7 &&
           decoded_bitmap.data[5] == 8 && decoded_bitmap.data[6] == 9 &&
           decoded_bitmap.data[8] == 30 && decoded_bitmap.data[9] == 20 &&
           decoded_bitmap.data[10] == 10);
    bitmap_rect.data_len = 3;
    PCHECK(rdp_bitmap_decode_rect_bgra32_with_palette(&bitmap_rect,
                                                      &palette_update,
                                                      &decoded_bitmap,
                                                      &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 3;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 2;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 4;
    bitmap_rect.data = bitmap_4_data;
    bitmap_rect.data_len = sizeof(bitmap_4_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) ==
           LIBRDP_STATUS_STATE);
    PCHECK(rdp_bitmap_decode_rect_bgra32_with_palette(&bitmap_rect,
                                                      &palette_update,
                                                      &decoded_bitmap,
                                                      &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 12 && decoded_bitmap.length == 24 &&
           decoded_bitmap.data[0] == 30 && decoded_bitmap.data[1] == 20 &&
           decoded_bitmap.data[2] == 10 && decoded_bitmap.data[4] == 50 &&
           decoded_bitmap.data[5] == 100 && decoded_bitmap.data[6] == 200 &&
           decoded_bitmap.data[8] == 3 && decoded_bitmap.data[9] == 2 &&
           decoded_bitmap.data[10] == 1);
    bitmap_rect.data_len = sizeof(bitmap_4_data) - 1u;
    PCHECK(rdp_bitmap_decode_rect_bgra32_with_palette(&bitmap_rect,
                                                      &palette_update,
                                                      &decoded_bitmap,
                                                      &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 4;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 3;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 1;
    bitmap_rect.data = bitmap_1_data;
    bitmap_rect.data_len = sizeof(bitmap_1_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32_with_palette(&bitmap_rect,
                                                      &palette_update,
                                                      &decoded_bitmap,
                                                      &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 16 && decoded_bitmap.length == 32 &&
           decoded_bitmap.data[0] == 30 && decoded_bitmap.data[1] == 20 &&
           decoded_bitmap.data[2] == 10 && decoded_bitmap.data[4] == 50 &&
           decoded_bitmap.data[5] == 100 && decoded_bitmap.data[6] == 200 &&
           decoded_bitmap.data[16] == 50 && decoded_bitmap.data[17] == 100 &&
           decoded_bitmap.data[18] == 200);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 2;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 1;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 24;
    bitmap_rect.flags = 0x0401;
    bitmap_rect.data = bitmap_24_rle_color_image;
    bitmap_rect.data_len = sizeof(bitmap_24_rle_color_image);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.length == 16 && decoded_bitmap.data[0] == 1 &&
           decoded_bitmap.data[1] == 2 && decoded_bitmap.data[2] == 3 && decoded_bitmap.data[12] == 10 &&
           decoded_bitmap.data[13] == 11 && decoded_bitmap.data[14] == 12);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 4;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 3;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 24;
    bitmap_rect.flags = 0x0401;
    bitmap_rect.data = bitmap_24_rle_bg_run_cross_row;
    bitmap_rect.data_len = sizeof(bitmap_24_rle_bg_run_cross_row);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 16 && decoded_bitmap.length == 32 &&
           decoded_bitmap.data[16] == 0 && decoded_bitmap.data[17] == 0 &&
           decoded_bitmap.data[18] == 255 && decoded_bitmap.data[20] == 0 &&
           decoded_bitmap.data[21] == 255 && decoded_bitmap.data[22] == 0 &&
           decoded_bitmap.data[24] == 0 && decoded_bitmap.data[25] == 0 &&
           decoded_bitmap.data[26] == 0);
    bitmap_rect.data = bitmap_24_rle_fg_run_cross_row;
    bitmap_rect.data_len = sizeof(bitmap_24_rle_fg_run_cross_row);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 16 && decoded_bitmap.length == 32 &&
           decoded_bitmap.data[0] == 255 && decoded_bitmap.data[1] == 255 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[16] == 0 &&
           decoded_bitmap.data[17] == 0 && decoded_bitmap.data[18] == 0 &&
           decoded_bitmap.data[24] == 255 && decoded_bitmap.data[25] == 255 &&
           decoded_bitmap.data[26] == 255);
    bitmap_rect.data = bitmap_24_rle_fgbg_cross_row;
    bitmap_rect.data_len = sizeof(bitmap_24_rle_fgbg_cross_row);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 16 && decoded_bitmap.length == 32 &&
           decoded_bitmap.data[0] == 255 && decoded_bitmap.data[1] == 255 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[16] == 0 &&
           decoded_bitmap.data[17] == 0 && decoded_bitmap.data[18] == 0);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 4;
    bitmap_rect.height = 1;
    bitmap_rect.dest_right = 3;
    bitmap_rect.bits_per_pixel = 8;
    bitmap_rect.flags = 0x0401;
    bitmap_rect.data = bitmap_8_rle_color_image;
    bitmap_rect.data_len = sizeof(bitmap_8_rle_color_image);
    PCHECK(rdp_bitmap_decode_rect_bgra32_with_palette(&bitmap_rect,
                                                      &palette_update,
                                                      &decoded_bitmap,
                                                      &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 16 && decoded_bitmap.data[0] == 30 && decoded_bitmap.data[1] == 20 &&
           decoded_bitmap.data[2] == 10 && decoded_bitmap.data[4] == 50 &&
           decoded_bitmap.data[5] == 100 && decoded_bitmap.data[6] == 200 &&
           decoded_bitmap.data[12] == 7 && decoded_bitmap.data[13] == 8 &&
           decoded_bitmap.data[14] == 9);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 4;
    bitmap_rect.height = 1;
    bitmap_rect.dest_right = 3;
    bitmap_rect.bits_per_pixel = 16;
    bitmap_rect.flags = 1;
    bitmap_rect.data = bitmap_16_rle_with_header;
    bitmap_rect.data_len = sizeof(bitmap_16_rle_with_header);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 16 && decoded_bitmap.data[0] == 0 && decoded_bitmap.data[1] == 0 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[12] == 0 && decoded_bitmap.data[13] == 0 &&
           decoded_bitmap.data[14] == 255);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 4;
    bitmap_rect.height = 1;
    bitmap_rect.dest_right = 3;
    bitmap_rect.bits_per_pixel = 15;
    bitmap_rect.flags = 1;
    bitmap_rect.data = bitmap_15_rle_with_header;
    bitmap_rect.data_len = sizeof(bitmap_15_rle_with_header);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 16 && decoded_bitmap.data[0] == 0 && decoded_bitmap.data[1] == 0 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[12] == 0 && decoded_bitmap.data[13] == 0 &&
           decoded_bitmap.data[14] == 255);
    bitmap_rect.bits_per_pixel = 14;
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    bitmap_rect.bits_per_pixel = 16;
    bitmap_rect.data_len = 7;
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
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
    PCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len - 1u, &bitmap_update) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_bitmap_parse_update(orders_update_payload, sizeof(orders_update_payload), &bitmap_update) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    memset(&virtual_channel_minimal_set, 0, sizeof(virtual_channel_minimal_set));
    virtual_channel_minimal_set.type = RDP_CAPABILITY_TYPE_VIRTUAL_CHANNEL;
    virtual_channel_minimal_set.length = 8;
    virtual_channel_minimal_set.data = virtual_channel_minimal_data;
    virtual_channel_minimal_set.data_len = sizeof(virtual_channel_minimal_data);
    PCHECK(rdp_slowpath_write_confirm_active(&confirm_active, 0x12345678u, 1004, 800, 600, "librdp") ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_share_control_header(confirm_active.data, confirm_active.length, &slow_header) ==
           LIBRDP_STATUS_OK);
    PCHECK(slow_header.total_length == confirm_active.length);
    PCHECK((slow_header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE);
    PCHECK(slow_header.channel_id == 1004);
    PCHECK(confirm_active.data[6] == 0x78 && confirm_active.data[10] == 0xea);
    confirm_source_len = (uint16_t)(confirm_active.data[12] | ((uint16_t)confirm_active.data[13] << 8));
    confirm_caps_len = (uint16_t)(confirm_active.data[14] | ((uint16_t)confirm_active.data[15] << 8));
    PCHECK(confirm_source_len == 6);
    PCHECK(rdp_capabilities_parse(confirm_active.data + 16u + confirm_source_len,
                                  confirm_caps_len,
                                  &confirm_caps) == LIBRDP_STATUS_OK);
    PCHECK(confirm_caps.count == sizeof(expected_confirm_types) / sizeof(expected_confirm_types[0]));
    PCHECK(confirm_caps_len == 455);
    for (i = 0; i < sizeof(expected_confirm_types) / sizeof(expected_confirm_types[0]); i++)
    {
        PCHECK(confirm_caps.sets[i].type == expected_confirm_types[i]);
        PCHECK(confirm_caps.sets[i].length == expected_confirm_lengths[i]);
    }
    confirm_bitmap_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_BITMAP);
    PCHECK(confirm_bitmap_set != NULL);
    PCHECK(rdp_capability_parse_bitmap(confirm_bitmap_set, &confirm_bitmap) == LIBRDP_STATUS_OK);
    PCHECK(confirm_bitmap.preferred_bits_per_pixel == 32 &&
           confirm_bitmap.desktop_width == 800 &&
           confirm_bitmap.desktop_height == 600 &&
           confirm_bitmap.desktop_resize_flag == 1 &&
           confirm_bitmap.bitmap_compression_flag == 1 &&
           confirm_bitmap.multiple_rectangle_support == 1);
    {
        const rdp_capability_bitmap valid_bitmap = confirm_bitmap;
        rdp_capability_set invalid_bitmap_set = *confirm_bitmap_set;
        uint8_t invalid_bitmap_data[24];

        PCHECK(rdp_capability_parse_bitmap(confirm_caps.sets, &confirm_bitmap) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&confirm_bitmap, &valid_bitmap, sizeof(confirm_bitmap)) == 0);
        memcpy(invalid_bitmap_data, confirm_bitmap_set->data, sizeof(invalid_bitmap_data));
        invalid_bitmap_data[0] = 0;
        invalid_bitmap_data[1] = 0;
        invalid_bitmap_set.data = invalid_bitmap_data;
        PCHECK(rdp_capability_parse_bitmap(&invalid_bitmap_set, &confirm_bitmap) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&confirm_bitmap, &valid_bitmap, sizeof(confirm_bitmap)) == 0);
    }
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_GENERAL);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_general(confirm_set, &confirm_general) == LIBRDP_STATUS_OK);
    PCHECK(confirm_general.os_major_type == 1 &&
           confirm_general.os_minor_type == 3 &&
           confirm_general.protocol_version == 0x0200u &&
           confirm_general.extra_flags == 0x0404u &&
           confirm_general.refresh_rect_support == 1 &&
           confirm_general.suppress_output_support == 1);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_ORDER);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_order(confirm_set, &confirm_order) == LIBRDP_STATUS_OK);
    PCHECK(confirm_order.desktop_save_x_granularity == 1 &&
           confirm_order.desktop_save_y_granularity == 20 &&
           confirm_order.maximum_order_level == 1 &&
           confirm_order.order_flags == 0x002au &&
           confirm_order.desktop_save_size == 230400u &&
           confirm_order.text_ansi_code_page == 65001u);
    for (i = 0; i < sizeof(confirm_order.order_support); i++)
    {
        uint8_t field_bytes = 0;
        const uint8_t expected = rdp_gdi_primary_order_field_bytes((uint8_t)i, &field_bytes) ? 1u : 0u;

        PCHECK(confirm_order.order_support[i] == expected);
    }
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_BITMAP_CACHE_V2);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_bitmap_cache_v2(confirm_set, &confirm_bitmap_cache) == LIBRDP_STATUS_OK);
    PCHECK(confirm_bitmap_cache.cache_flags == 2 &&
           confirm_bitmap_cache.num_cell_caches == 5 &&
           confirm_bitmap_cache.cell_info[0] == 600 &&
           confirm_bitmap_cache.cell_info[1] == 600 &&
           confirm_bitmap_cache.cell_info[2] == 2048 &&
           confirm_bitmap_cache.cell_info[3] == 4096 &&
           confirm_bitmap_cache.cell_info[4] == 2048);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_POINTER);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_pointer(confirm_set, &confirm_pointer) == LIBRDP_STATUS_OK);
    PCHECK(confirm_pointer.color_pointer_flag == 1 &&
           confirm_pointer.color_pointer_cache_size == 128 &&
           confirm_pointer.pointer_cache_size == 128);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_LARGE_POINTER);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_large_pointer(confirm_set, &confirm_large_pointer) == LIBRDP_STATUS_OK);
    PCHECK(confirm_large_pointer.support_flags == 1);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_INPUT);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_input(confirm_set, &confirm_input) == LIBRDP_STATUS_OK);
    PCHECK(confirm_input.input_flags == 0x0115u &&
           confirm_input.keyboard_layout == 0x00000409u &&
           confirm_input.keyboard_type == 4 &&
           confirm_input.keyboard_subtype == 0 &&
           confirm_input.keyboard_function_key == 12);
    {
        const rdp_capability_input valid_input = confirm_input;
        rdp_capability_set invalid_input_set = *confirm_set;
        uint8_t invalid_input_data[84];

        memcpy(invalid_input_data, confirm_set->data, sizeof(invalid_input_data));
        memset(invalid_input_data + 8u, 0, 4u);
        invalid_input_set.data = invalid_input_data;
        PCHECK(rdp_capability_parse_input(&invalid_input_set, &confirm_input) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&confirm_input, &valid_input, sizeof(confirm_input)) == 0);
    }
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_BRUSH);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_brush(confirm_set, &confirm_brush) == LIBRDP_STATUS_OK);
    PCHECK(confirm_brush.support_level == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_GLYPH_CACHE);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_glyph_cache(confirm_set, &confirm_glyph) == LIBRDP_STATUS_OK);
    PCHECK(confirm_glyph.glyph_cache[0].cache_entries == 254 &&
           confirm_glyph.glyph_cache[0].maximum_cell_size == 4 &&
           confirm_glyph.glyph_cache[9].cache_entries == 254 &&
           confirm_glyph.glyph_cache[9].maximum_cell_size == 256 &&
           confirm_glyph.frag_cache_entries == 256 &&
           confirm_glyph.frag_cache_maximum_cell_size == 256 &&
           confirm_glyph.glyph_support_level == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_VIRTUAL_CHANNEL);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_virtual_channel(confirm_set, &confirm_virtual_channel) == LIBRDP_STATUS_OK);
    PCHECK(confirm_virtual_channel.flags == 0 &&
           confirm_virtual_channel.has_chunk_size == 1 &&
           confirm_virtual_channel.chunk_size == 1600);
    PCHECK(rdp_capability_parse_virtual_channel(&virtual_channel_minimal_set, &confirm_virtual_channel) ==
           LIBRDP_STATUS_OK);
    PCHECK(confirm_virtual_channel.flags == 1 &&
           confirm_virtual_channel.has_chunk_size == 0 &&
           confirm_virtual_channel.chunk_size == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_SOUND);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_sound(confirm_set, &confirm_sound) == LIBRDP_STATUS_OK);
    PCHECK(confirm_sound.flags == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_SHARE);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_share(confirm_set, &confirm_share) == LIBRDP_STATUS_OK);
    PCHECK(confirm_share.node_id == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_FONT);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_font(confirm_set, &confirm_font) == LIBRDP_STATUS_OK);
    PCHECK(confirm_font.support_flags == 1);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_CONTROL);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_control(confirm_set, &confirm_control) == LIBRDP_STATUS_OK);
    PCHECK(confirm_control.control_flags == 0 &&
           confirm_control.remote_detach_flag == 0 &&
           confirm_control.control_interest == 2 &&
           confirm_control.detach_interest == 2);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_COLOR_CACHE);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_color_cache(confirm_set, &confirm_color_cache) == LIBRDP_STATUS_OK);
    PCHECK(confirm_color_cache.cache_size == 6);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_GDI_CAPSTYPE_DRAW_NINEGRID_CACHE);
    PCHECK(confirm_set != NULL);
    PCHECK(confirm_set->data_len == 8 &&
           test_read_u32_le(confirm_set->data) == RDP_GDI_NINEGRID_SUPPORT_SUPPORTED_REV2 &&
           test_read_u16_le(confirm_set->data + 4u) == 2560 &&
           test_read_u16_le(confirm_set->data + 6u) == 256);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_GDI_CAPSTYPE_DRAW_GDIPLUS);
    PCHECK(confirm_set == NULL);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_ACTIVATION);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_activation(confirm_set, &confirm_activation) == LIBRDP_STATUS_OK);
    PCHECK(confirm_activation.help_key_flag == 0 &&
           confirm_activation.help_key_index_flag == 0 &&
           confirm_activation.help_extended_key_flag == 0 &&
           confirm_activation.window_manager_key_flag == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_BITMAP_CODECS);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_bitmap_codecs(confirm_set, &confirm_bitmap_codecs) == LIBRDP_STATUS_OK);
    PCHECK(confirm_bitmap_codecs.count == 1 &&
           confirm_bitmap_codecs.codecs[0].codec_id == RDP_NSCODEC_BITMAP_CODEC_ID &&
           confirm_bitmap_codecs.codecs[0].properties_len == RDP_NSCODEC_CAPABILITY_LENGTH &&
           memcmp(confirm_bitmap_codecs.codecs[0].guid, nscodec_guid, sizeof(nscodec_guid)) == 0);
    {
        const rdp_capability_bitmap_codecs valid_codecs = confirm_bitmap_codecs;
        rdp_capability_set invalid_codecs_set = *confirm_set;

        invalid_codecs_set.data_len--;
        invalid_codecs_set.length--;
        PCHECK(rdp_capability_parse_bitmap_codecs(&invalid_codecs_set, &confirm_bitmap_codecs) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&confirm_bitmap_codecs, &valid_codecs, sizeof(confirm_bitmap_codecs)) == 0);
    }
    PCHECK(rdp_nscodec_parse_capability(confirm_bitmap_codecs.codecs[0].properties,
                                        confirm_bitmap_codecs.codecs[0].properties_len,
                                        &confirm_nscodec) == LIBRDP_STATUS_OK);
    PCHECK(confirm_nscodec.allow_dynamic_fidelity == 1 &&
           confirm_nscodec.allow_subsampling == 1 &&
           confirm_nscodec.color_loss_level == 7);
    {
        const rdp_capability_general valid_general = confirm_general;

        PCHECK(rdp_capability_parse_general(confirm_bitmap_set, &confirm_general) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&confirm_general, &valid_general, sizeof(confirm_general)) == 0);
    }
    PCHECK(confirm_caps.sets[0].data[0] == 1 && confirm_caps.sets[0].data[2] == 3 &&
           confirm_caps.sets[0].data[4] == 0x00 && confirm_caps.sets[0].data[5] == 0x02);
    PCHECK(confirm_caps.sets[1].data[0] == 32 && confirm_caps.sets[1].data[8] == 0x20 &&
           confirm_caps.sets[1].data[9] == 0x03 && confirm_caps.sets[1].data[10] == 0x58 &&
           confirm_caps.sets[1].data[11] == 0x02);
    PCHECK(confirm_caps.sets[2].data[30] == 0x2a && confirm_caps.sets[2].data[31] == 0x00);
    PCHECK(confirm_caps.sets[5].data[0] == 1 && confirm_caps.sets[5].data[1] == 0);
    PCHECK(confirm_caps.sets[6].data[0] == 0x15 && confirm_caps.sets[6].data[1] == 0x01 &&
           confirm_caps.sets[6].data[4] == 0x09 && confirm_caps.sets[6].data[5] == 0x04);
    PCHECK(rdp_slowpath_write_client_synchronize(&client_sync, 0x12345678u, 1004) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_sync.data, client_sync.length, &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.share_id == 0x12345678u &&
           data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SYNCHRONIZE &&
           data_pdu.payload_len == 4);
    PCHECK(test_read_u16_le(data_pdu.payload) == 1 && test_read_u16_le(data_pdu.payload + 2) == 1004);
    PCHECK(rdp_slowpath_write_client_control(&client_control, 0x12345678u, 1004, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_control.data, client_control.length, &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL &&
           data_pdu.payload_len == 8 &&
           test_read_u16_le(data_pdu.payload) == 4 &&
           test_read_u16_le(data_pdu.payload + 2) == 0 &&
           test_read_u32_le(data_pdu.payload + 4) == 0);
    client_control.length = 0;
    PCHECK(rdp_slowpath_write_client_control(&client_control, 0x12345678u, 1004, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_control.data, client_control.length, &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL &&
           test_read_u16_le(data_pdu.payload) == 1);
    PCHECK(rdp_slowpath_write_client_control(&client_control, 0x12345678u, 1004, 2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_write_client_persistent_key_list(&client_persistent_keys, 0x12345678u, 1004) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_persistent_keys.data,
                                       client_persistent_keys.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_BITMAP_CACHE_PERSISTENT_LIST &&
           data_pdu.payload_len == 24 &&
           data_pdu.payload[20] == 3);
    for (i = 0; i < 20; i++)
        PCHECK(data_pdu.payload[i] == 0);
    PCHECK(data_pdu.payload[21] == 0 && data_pdu.payload[22] == 0 && data_pdu.payload[23] == 0);
    PCHECK(rdp_slowpath_write_client_font_list(&client_font_list, 0x12345678u, 1004) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_font_list.data, client_font_list.length, &data_pdu) ==
           LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_LIST &&
           data_pdu.payload_len == 8 &&
           test_read_u16_le(data_pdu.payload + 4) == 3 &&
           test_read_u16_le(data_pdu.payload + 6) == 50);
    PCHECK(rdp_slowpath_write_client_keyboard_input(&client_keyboard_input,
                                                    0x12345678u,
                                                    1004,
                                                    0x8000u,
                                                    30) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_keyboard_input.data,
                                       client_keyboard_input.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_INPUT &&
           data_pdu.payload_len == 16 &&
           test_read_u16_le(data_pdu.payload) == 1 &&
           test_read_u16_le(data_pdu.payload + 8) == 4 &&
           test_read_u16_le(data_pdu.payload + 10) == 0x8000u &&
           test_read_u16_le(data_pdu.payload + 12) == 30);
    PCHECK(rdp_slowpath_write_client_keyboard_input(&client_keyboard_input,
                                                    0x12345678u,
                                                    1004,
                                                    0,
                                                    256) == LIBRDP_STATUS_INVALID_ARGUMENT);
    client_keyboard_input.length = 0;
    PCHECK(rdp_slowpath_write_client_unicode_keyboard_input(&client_keyboard_input,
                                                            0x12345678u,
                                                            1004,
                                                            0x8000u,
                                                            0x20acu) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_keyboard_input.data,
                                       client_keyboard_input.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_INPUT &&
           data_pdu.payload_len == 16 &&
           test_read_u16_le(data_pdu.payload + 8) == 5 &&
           test_read_u16_le(data_pdu.payload + 10) == 0x8000u &&
           test_read_u16_le(data_pdu.payload + 12) == 0x20acu);
    PCHECK(rdp_slowpath_write_client_mouse_input(&client_mouse_input,
                                                 0x12345678u,
                                                 1004,
                                                 0x9000u,
                                                 10,
                                                 11) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_mouse_input.data,
                                       client_mouse_input.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_INPUT &&
           data_pdu.payload_len == 16 &&
           test_read_u16_le(data_pdu.payload + 8) == 0x8001u &&
           test_read_u16_le(data_pdu.payload + 10) == 0x9000u &&
           test_read_u16_le(data_pdu.payload + 12) == 10 &&
           test_read_u16_le(data_pdu.payload + 14) == 11);
    client_mouse_input.length = 0;
    PCHECK(rdp_slowpath_write_client_extended_mouse_input(&client_mouse_input,
                                                          0x12345678u,
                                                          1004,
                                                          0x8001u,
                                                          10,
                                                          11) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_mouse_input.data,
                                       client_mouse_input.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_INPUT &&
           data_pdu.payload_len == 16 &&
           test_read_u16_le(data_pdu.payload + 8) == 0x8002u &&
           test_read_u16_le(data_pdu.payload + 10) == 0x8001u &&
           test_read_u16_le(data_pdu.payload + 12) == 10 &&
           test_read_u16_le(data_pdu.payload + 14) == 11);
    PCHECK(rdp_slowpath_write_client_refresh_rect(&client_refresh_rect,
                                                  0x12345678u,
                                                  1004,
                                                  2,
                                                  3,
                                                  800,
                                                  600) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_refresh_rect.data,
                                       client_refresh_rect.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_REFRESH_RECT &&
           data_pdu.payload_len == 12 &&
           data_pdu.payload[0] == 1 &&
           test_read_u16_le(data_pdu.payload + 4) == 2 &&
           test_read_u16_le(data_pdu.payload + 6) == 3 &&
           test_read_u16_le(data_pdu.payload + 8) == 801 &&
           test_read_u16_le(data_pdu.payload + 10) == 602);
    PCHECK(rdp_slowpath_write_client_refresh_rect(&client_refresh_rect,
                                                  0x12345678u,
                                                  1004,
                                                  0xffffu,
                                                  0,
                                                  2,
                                                  1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_write_client_suppress_output(&client_suppress_output,
                                                     0x12345678u,
                                                     1004,
                                                     1,
                                                     2,
                                                     3,
                                                     800,
                                                     600) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_suppress_output.data,
                                       client_suppress_output.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SUPPRESS_OUTPUT &&
           data_pdu.payload_len == 12 &&
           data_pdu.payload[0] == 1 &&
           test_read_u16_le(data_pdu.payload + 4) == 2 &&
           test_read_u16_le(data_pdu.payload + 6) == 3 &&
           test_read_u16_le(data_pdu.payload + 8) == 801 &&
           test_read_u16_le(data_pdu.payload + 10) == 602);
    client_suppress_output.length = 0;
    PCHECK(rdp_slowpath_write_client_suppress_output(&client_suppress_output,
                                                     0x12345678u,
                                                     1004,
                                                     0,
                                                     0,
                                                     0,
                                                     0,
                                                     0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_suppress_output.data,
                                       client_suppress_output.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SUPPRESS_OUTPUT &&
           data_pdu.payload_len == 4 &&
           data_pdu.payload[0] == 0);
    PCHECK(rdp_slowpath_write_client_suppress_output(&client_suppress_output,
                                                     0x12345678u,
                                                     1004,
                                                     1,
                                                     0xffffu,
                                                     0,
                                                     2,
                                                     1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_parse_font_map(font_map_payload, sizeof(font_map_payload), &font_map) == LIBRDP_STATUS_OK);
    PCHECK(font_map.number_entries == 1 && font_map.total_entries == 2 && font_map.map_flags == 3 &&
           font_map.entry_size == 4);
    {
        const rdp_slowpath_font_map valid_font_map = font_map;

        PCHECK(rdp_slowpath_parse_font_map(font_map_payload, sizeof(font_map_payload) - 1u, &font_map) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&font_map, &valid_font_map, sizeof(font_map)) == 0);
    }
    PCHECK(rdp_slowpath_parse_set_error_info(set_error_info_payload,
                                             sizeof(set_error_info_payload),
                                             &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 0x1234u);
    {
        const uint32_t valid_error_info = error_info;

        PCHECK(rdp_slowpath_parse_set_error_info(set_error_info_payload,
                                                 sizeof(set_error_info_payload) - 1u,
                                                 &error_info) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(error_info == valid_error_info);
    }
    PCHECK(rdp_slowpath_parse_save_session_info(save_session_info_payload,
                                                sizeof(save_session_info_payload),
                                                &save_info) == LIBRDP_STATUS_OK);
    PCHECK(save_info.info_type == 1 && save_info.data_len == 2 && save_info.data[0] == 0xaa &&
           save_info.data[1] == 0x55);
    {
        const rdp_slowpath_save_session_info valid_save_info = save_info;

        PCHECK(rdp_slowpath_parse_save_session_info(save_session_info_payload, 3, &save_info) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&save_info, &valid_save_info, sizeof(save_info)) == 0);
    }

    PCHECK(rdp_security_protocol_mask(LIBRDP_SECURITY_STANDARD) == RDP_X224_PROTOCOL_STANDARD);
    PCHECK(rdp_security_protocol_mask(LIBRDP_SECURITY_TLS) == RDP_X224_PROTOCOL_TLS);
    PCHECK(rdp_security_protocol_supported(RDP_X224_PROTOCOL_TLS));
    PCHECK(rdp_security_protocol_supported(RDP_X224_PROTOCOL_NLA));
    PCHECK(rdp_security_protocol_supported(RDP_X224_PROTOCOL_STANDARD));
    PCHECK(rdp_security_protocol_allowed(LIBRDP_SECURITY_AUTO, true, RDP_X224_PROTOCOL_TLS));
    PCHECK(rdp_security_protocol_allowed(LIBRDP_SECURITY_AUTO, true, RDP_X224_PROTOCOL_NLA));
    PCHECK(!rdp_security_protocol_allowed(LIBRDP_SECURITY_AUTO, true, RDP_X224_PROTOCOL_STANDARD));
    PCHECK(!rdp_security_protocol_allowed(LIBRDP_SECURITY_AUTO, false, RDP_X224_PROTOCOL_STANDARD));
    PCHECK(rdp_security_protocol_allowed(LIBRDP_SECURITY_STANDARD, false, RDP_X224_PROTOCOL_STANDARD));
    PCHECK(rdp_security_protocol_allowed(LIBRDP_SECURITY_STANDARD, true, RDP_X224_PROTOCOL_STANDARD));
    PCHECK(!rdp_security_protocol_allowed(LIBRDP_SECURITY_STANDARD, true, RDP_X224_PROTOCOL_TLS));
    PCHECK(!rdp_security_protocol_allowed(LIBRDP_SECURITY_TLS, true, RDP_X224_PROTOCOL_NLA));
    PCHECK(!rdp_security_protocol_allowed(LIBRDP_SECURITY_NLA, true, RDP_X224_PROTOCOL_TLS));
    PCHECK(!rdp_security_protocol_allowed(LIBRDP_SECURITY_TLS, true, 0x80000000u));

    memset(&info, 0, sizeof(info));
    info.domain = "D";
    info.username = "user";
    info.password = "secret";
    PCHECK(rdp_security_write_client_info_pdu(&security, &info) == LIBRDP_STATUS_OK);
    PCHECK(security.length > 200u);
    PCHECK(rdp_security_parse_client_info_pdu(security.data, security.length, &info_summary) == LIBRDP_STATUS_OK);
    PCHECK(info_summary.domain_bytes == 2);
    PCHECK(info_summary.username_bytes == 8);
    PCHECK(info_summary.password_bytes == 12);
    PCHECK((info_summary.flags & 0x00000010u) != 0);
    PCHECK((info_summary.flags & 0x00000008u) != 0);
    security.length = 0;
    no_password_info = info;
    no_password_info.password = NULL;
    PCHECK(rdp_security_write_client_info_pdu(&security, &no_password_info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_parse_client_info_pdu(security.data, security.length, &info_summary) == LIBRDP_STATUS_OK);
    PCHECK(info_summary.password_bytes == 0);
    PCHECK((info_summary.flags & 0x00000008u) == 0);
    for (i = 0; i < sizeof(client_random); i++)
    {
        client_random[i] = (uint8_t)(i + 1u);
        server_random[i] = (uint8_t)(0xa0u + i);
    }
    standard_security_status = rdp_security_standard_client_init(&secure_a,
                                                                 RDP_SECURITY_METHOD_128BIT,
                                                                 client_random,
                                                                 server_random);
    if (standard_security_status == LIBRDP_STATUS_OK)
    {
    PCHECK(secure_a.key_len == 16);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    memcpy(standard_work1, standard_plain1, sizeof(standard_work1));
    memcpy(standard_work2, standard_plain2, sizeof(standard_work2));
    PCHECK(rdp_security_encrypt_payload(&secure_a, standard_work1, sizeof(standard_work1)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_encrypt_payload(&secure_a, standard_work2, sizeof(standard_work2)) == LIBRDP_STATUS_OK);
    PCHECK(memcmp(standard_work1, standard_cipher1, sizeof(standard_cipher1)) == 0);
    PCHECK(memcmp(standard_work2, standard_cipher2, sizeof(standard_cipher2)) == 0);
    rdp_security_standard_clear(&secure_a);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    memcpy(standard_update_work, standard_update_plain, sizeof(standard_update_work));
    secure_a.encrypt_count = 4096;
    PCHECK(rdp_security_encrypt_payload(&secure_a, standard_update_work, sizeof(standard_update_work)) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(standard_update_work, standard_update_cipher, sizeof(standard_update_cipher)) == 0);
    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_client_info_body(&plain_info_body, &info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_mac_signature(&secure_b, plain_info_body.data, plain_info_body.length, signature) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_encrypted_client_info_pdu(&encrypted_info, &secure_a, &info) == LIBRDP_STATUS_OK);
    PCHECK(encrypted_info.length == plain_info_body.length + 12u);
    PCHECK(encrypted_info.data[0] == (uint8_t)(RDP_SEC_INFO_PKT | RDP_SEC_ENCRYPT));
    PCHECK(memcmp(encrypted_info.data + 4, signature, sizeof(signature)) == 0);
    PCHECK(memcmp(encrypted_info.data + 12, plain_info_body.data, plain_info_body.length) != 0);
    PCHECK(rdp_buffer_append(&expected_cipher, plain_info_body.data, plain_info_body.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_encrypt_payload(&secure_b, expected_cipher.data, expected_cipher.length) == LIBRDP_STATUS_OK);
    PCHECK(memcmp(encrypted_info.data + 12, expected_cipher.data, expected_cipher.length) == 0);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_server_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    unwrapped_pdu.length = 0;
    security_flags = 0;
    PCHECK(rdp_security_unwrap_pdu(&secure_b,
                                   encrypted_info.data,
                                   encrypted_info.length,
                                   &unwrapped_pdu,
                                   &security_flags) == LIBRDP_STATUS_OK);
    PCHECK(security_flags == (RDP_SEC_INFO_PKT | RDP_SEC_ENCRYPT));
    PCHECK(unwrapped_pdu.length == plain_info_body.length);
    PCHECK(memcmp(unwrapped_pdu.data, plain_info_body.data, plain_info_body.length) == 0);
    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_encrypted_pdu(&protected_pdu,
                                            &secure_a,
                                            0,
                                            orders_update_payload,
                                            sizeof(orders_update_payload)) == LIBRDP_STATUS_OK);
    PCHECK(protected_pdu.length == sizeof(orders_update_payload) + 12u);
    PCHECK((test_read_u16_le(protected_pdu.data) & RDP_SEC_ENCRYPT) != 0);
    expected_cipher.length = 0;
    PCHECK(rdp_buffer_append(&expected_cipher, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_encrypt_payload(&secure_b, expected_cipher.data, expected_cipher.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(protected_pdu.data + 12, expected_cipher.data, expected_cipher.length) == 0);
    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    protected_pdu.length = 0;
    PCHECK(rdp_security_mac_signature(&secure_a,
                                      orders_update_payload,
                                      sizeof(orders_update_payload),
                                      signature) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_header(&protected_pdu, RDP_SEC_ENCRYPT) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, signature, sizeof(signature)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_decrypt_payload(&secure_a,
                                        protected_pdu.data + 12,
                                        sizeof(orders_update_payload)) == LIBRDP_STATUS_OK);
    unwrapped_pdu.length = 0;
    PCHECK(rdp_security_unwrap_pdu(&secure_b,
                                   protected_pdu.data,
                                   protected_pdu.length,
                                   &unwrapped_pdu,
                                   &security_flags) == LIBRDP_STATUS_OK);
    PCHECK((security_flags & RDP_SEC_ENCRYPT) != 0);
    PCHECK(unwrapped_pdu.length == sizeof(orders_update_payload) &&
           memcmp(unwrapped_pdu.data, orders_update_payload, sizeof(orders_update_payload)) == 0);

    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    protected_pdu.length = 0;
    unwrapped_pdu.length = 0;
    PCHECK(rdp_security_mac_signature(&secure_a,
                                      orders_update_payload,
                                      sizeof(orders_update_payload),
                                      signature) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_header(&protected_pdu, RDP_SEC_ENCRYPT) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, signature, sizeof(signature)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_decrypt_payload(&secure_a,
                                        protected_pdu.data + 12,
                                        sizeof(orders_update_payload)) == LIBRDP_STATUS_OK);
    protected_pdu.data[4] ^= 0x80u;
    PCHECK(rdp_security_unwrap_pdu(&secure_b,
                                   protected_pdu.data,
                                   protected_pdu.length,
                                   &unwrapped_pdu,
                                   &security_flags) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(unwrapped_pdu.length == 0);

    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    protected_pdu.length = 0;
    PCHECK(rdp_security_mac_signature(&secure_a,
                                      orders_update_payload,
                                      sizeof(orders_update_payload),
                                      signature) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_header(&protected_pdu, RDP_SEC_ENCRYPT) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, signature, sizeof(signature)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_decrypt_payload(&secure_a,
                                        protected_pdu.data + 12,
                                        sizeof(orders_update_payload)) == LIBRDP_STATUS_OK);
    protected_pdu.data[protected_pdu.length - 1u] ^= 0x40u;
    PCHECK(rdp_security_unwrap_pdu(&secure_b,
                                   protected_pdu.data,
                                   protected_pdu.length,
                                   &unwrapped_pdu,
                                   &security_flags) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(unwrapped_pdu.length == 0);

    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    protected_pdu.length = 0;
    PCHECK(rdp_security_salted_mac_signature(&secure_a,
                                             orders_update_payload,
                                             sizeof(orders_update_payload),
                                             secure_a.decrypt_count,
                                             signature) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_header(&protected_pdu, RDP_SEC_ENCRYPT | RDP_SEC_SECURE_CHECKSUM) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, signature, sizeof(signature)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_decrypt_payload(&secure_a,
                                        protected_pdu.data + 12,
                                        sizeof(orders_update_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_unwrap_pdu(&secure_b,
                                   protected_pdu.data,
                                   protected_pdu.length,
                                   &unwrapped_pdu,
                                   &security_flags) == LIBRDP_STATUS_OK);
    PCHECK((security_flags & RDP_SEC_SECURE_CHECKSUM) != 0);
    PCHECK(unwrapped_pdu.length == sizeof(orders_update_payload) &&
           memcmp(unwrapped_pdu.data, orders_update_payload, sizeof(orders_update_payload)) == 0);

    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    protected_pdu.length = 0;
    unwrapped_pdu.length = 0;
    PCHECK(rdp_security_salted_mac_signature(&secure_a,
                                             orders_update_payload,
                                             sizeof(orders_update_payload),
                                             secure_a.decrypt_count,
                                             signature) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_header(&protected_pdu, RDP_SEC_ENCRYPT | RDP_SEC_SECURE_CHECKSUM) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, signature, sizeof(signature)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_decrypt_payload(&secure_a,
                                        protected_pdu.data + 12,
                                        sizeof(orders_update_payload)) == LIBRDP_STATUS_OK);
    secure_b.decrypt_count = 1;
    PCHECK(rdp_security_unwrap_pdu(&secure_b,
                                   protected_pdu.data,
                                   protected_pdu.length,
                                   &unwrapped_pdu,
                                   &security_flags) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(unwrapped_pdu.length == 0);

    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    encrypted_fastpath.length = 0;
    decoded_fastpath.length = 0;
    fastpath_used_decoded = 0;
    PCHECK(test_build_encrypted_fastpath(&encrypted_fastpath,
                                         &secure_a,
                                         RDP_FASTPATH_OUTPUT_ENCRYPTED,
                                         fastpath_sync_payload,
                                         sizeof(fastpath_sync_payload)));
    PCHECK(rdp_fastpath_unwrap_security(&secure_b,
                                        1,
                                        encrypted_fastpath.data,
                                        encrypted_fastpath.length,
                                        &decoded_fastpath,
                                        &fastpath_used_decoded) == LIBRDP_STATUS_OK);
    PCHECK(fastpath_used_decoded == 1);
    PCHECK(rdp_fastpath_parse_updates(decoded_fastpath.data, decoded_fastpath.length, &fast_updates) ==
           LIBRDP_STATUS_OK);
    PCHECK(fast_updates.count == 1 &&
           fast_updates.updates[0].update_code == RDP_FASTPATH_UPDATE_SYNCHRONIZE);

    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    encrypted_fastpath.length = 0;
    decoded_fastpath.length = 0;
    fastpath_used_decoded = 1;
    PCHECK(test_build_encrypted_fastpath(&encrypted_fastpath,
                                         &secure_a,
                                         RDP_FASTPATH_OUTPUT_ENCRYPTED,
                                         fastpath_sync_payload,
                                         sizeof(fastpath_sync_payload)));
    encrypted_fastpath.data[3] ^= 0x20u;
    PCHECK(rdp_fastpath_unwrap_security(&secure_b,
                                        1,
                                        encrypted_fastpath.data,
                                        encrypted_fastpath.length,
                                        &decoded_fastpath,
                                        &fastpath_used_decoded) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(fastpath_used_decoded == 0 && decoded_fastpath.length == 0);

    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    encrypted_fastpath.length = 0;
    decoded_fastpath.length = 0;
    fastpath_used_decoded = 1;
    PCHECK(test_build_encrypted_fastpath(&encrypted_fastpath,
                                         &secure_a,
                                         RDP_FASTPATH_OUTPUT_ENCRYPTED,
                                         fastpath_sync_payload,
                                         sizeof(fastpath_sync_payload)));
    encrypted_fastpath.data[encrypted_fastpath.length - 1u] ^= 0x08u;
    PCHECK(rdp_fastpath_unwrap_security(&secure_b,
                                        1,
                                        encrypted_fastpath.data,
                                        encrypted_fastpath.length,
                                        &decoded_fastpath,
                                        &fastpath_used_decoded) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(fastpath_used_decoded == 0 && decoded_fastpath.length == 0);

    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    encrypted_fastpath.length = 0;
    decoded_fastpath.length = 0;
    fastpath_used_decoded = 1;
    PCHECK(test_build_encrypted_fastpath(&encrypted_fastpath,
                                         &secure_a,
                                         RDP_FASTPATH_OUTPUT_ENCRYPTED | RDP_FASTPATH_OUTPUT_SECURE_CHECKSUM,
                                         fastpath_sync_payload,
                                         sizeof(fastpath_sync_payload)));
    secure_b.decrypt_count = 1;
    PCHECK(rdp_fastpath_unwrap_security(&secure_b,
                                        1,
                                        encrypted_fastpath.data,
                                        encrypted_fastpath.length,
                                        &decoded_fastpath,
                                        &fastpath_used_decoded) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(fastpath_used_decoded == 0 && decoded_fastpath.length == 0);

    PCHECK(rdp_security_write_header(&plain_security, RDP_SEC_LICENSE_PKT) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&plain_security, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    security_flags = 0;
    unwrapped_pdu.length = 0;
    PCHECK(rdp_security_unwrap_pdu(NULL,
                                   plain_security.data,
                                   plain_security.length,
                                   &unwrapped_pdu,
                                   &security_flags) == LIBRDP_STATUS_OK);
    PCHECK(security_flags == RDP_SEC_LICENSE_PKT);
    PCHECK(unwrapped_pdu.length == sizeof(orders_update_payload) &&
           memcmp(unwrapped_pdu.data, orders_update_payload, sizeof(orders_update_payload)) == 0);
    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_40BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(secure_a.key_len == 8 && secure_a.sign_key[0] == 0xd1 && secure_a.sign_key[2] == 0x9e);
    rdp_security_standard_clear(&secure_a);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_56BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(secure_a.key_len == 8 && secure_a.sign_key[0] == 0xd1);
    rdp_security_standard_clear(&secure_a);
    }
    else
    {
        PCHECK(standard_security_status == LIBRDP_STATUS_UNSUPPORTED);
    }
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_FIPS,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_UNSUPPORTED);
    PCHECK(rdp_security_write_send_data_request(&send_data, 1004, RDP_MCS_GLOBAL_CHANNEL_ID, security.data,
                                                security.length) == LIBRDP_STATUS_OK);
    PCHECK(send_data.length > security.length);
    PCHECK(send_data.data[0] == 0x64);
    PCHECK(send_data.data[1] == 0x00 && send_data.data[2] == 0x03);
    PCHECK(send_data.data[3] == 0x03 && send_data.data[4] == 0xeb);
    rdp_buffer_free(&security);
    rdp_buffer_init(&security);
    PCHECK(rdp_security_write_exchange_pdu(&security, encrypted_random, sizeof(encrypted_random)) ==
           LIBRDP_STATUS_OK);
    PCHECK(security.length == sizeof(encrypted_random) + 16u);
    PCHECK(test_read_u16_le(security.data) == (RDP_SEC_EXCHANGE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC));
    PCHECK(security.data[4] == (uint8_t)(sizeof(encrypted_random) + 8u));
    memset(client_random, 0x4a, sizeof(client_random));
    PCHECK(rdp_security_parse_server_certificate(server_certificate, sizeof(server_certificate), &public_key) ==
           LIBRDP_STATUS_OK);
    PCHECK(public_key.exponent == 65537u && public_key.bit_len == 1024u && public_key.modulus_len == 128u);
    PCHECK(public_key.modulus_le[0] == 0xeb && public_key.modulus_le[127] == 0xb2);
    PCHECK(rdp_security_encrypt_client_random(&public_key, client_random, &encrypted) == LIBRDP_STATUS_OK);
    PCHECK(encrypted.length == public_key.modulus_len);
    PCHECK(memcmp(encrypted.data, client_random, sizeof(client_random)) != 0);
    rdp_security_public_key_clear(&public_key);
    rdp_buffer_free(&encrypted);
    rdp_buffer_init(&encrypted);
    security.length = 0;
    PCHECK(rdp_buffer_append_u32_le(&security, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&security, 6) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&security, 284) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 0x31415352u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 264) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 2048) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 255) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 65537) == LIBRDP_STATUS_OK);
    for (i = 0; i < 256u; i++)
        PCHECK(rdp_buffer_append_u8(&security, (uint8_t)(1u + (i & 0x7fu))) == LIBRDP_STATUS_OK);
    for (i = 0; i < 8u; i++)
        PCHECK(rdp_buffer_append_u8(&security, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_parse_server_certificate(security.data, security.length, &public_key) ==
           LIBRDP_STATUS_OK);
    PCHECK(public_key.exponent == 65537u && public_key.bit_len == 2048u && public_key.modulus_len == 256u);
    PCHECK(public_key.modulus_le[0] == 1 && public_key.modulus_le[255] == 128);
    rdp_security_public_key_clear(&public_key);
    PCHECK(rdp_buffer_append_u32_le(&x509_chain, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&x509_chain, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&x509_chain, (uint32_t)sizeof(x509_der)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&x509_chain, x509_der, sizeof(x509_der)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_parse_server_certificate(x509_chain.data, x509_chain.length, &public_key) ==
           LIBRDP_STATUS_OK);
    PCHECK(public_key.exponent == 65537u && public_key.bit_len == 1024u && public_key.modulus_len == 128u);
    PCHECK(rdp_security_encrypt_client_random(&public_key, client_random, &encrypted) == LIBRDP_STATUS_OK);
    PCHECK(encrypted.length == public_key.modulus_len);
    rdp_security_public_key_clear(&public_key);
    PCHECK(rdp_security_parse_server_certificate(x509_chain.data, x509_chain.length - 1u, &public_key) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_security_generate_client_random(client_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_parse_server_certificate(server_certificate, sizeof(server_certificate) - 1u, &public_key) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    memset(client_random, 0x7c, sizeof(client_random));
    memset(decrypted_client_random, 0, sizeof(decrypted_client_random));
    encrypted.length = 0;
    PCHECK(rdp_security_generate_server_certificate(&generated_server_key, &generated_server_certificate) ==
           LIBRDP_STATUS_OK);
    PCHECK(generated_server_key != NULL && generated_server_certificate.length > 64u);
    PCHECK(test_read_u32_le(generated_server_certificate.data) == 1u);
    PCHECK(test_read_u16_le(generated_server_certificate.data + 12u) == 6u);
    PCHECK(test_read_u32_le(generated_server_certificate.data + 16u) == 0x31415352u);
    PCHECK(test_read_u32_le(generated_server_certificate.data + 28u) ==
           test_read_u32_le(generated_server_certificate.data + 20u) - 9u);
    PCHECK(generated_server_certificate.length >=
           40u + test_read_u32_le(generated_server_certificate.data + 20u));
    PCHECK(test_read_u16_le(generated_server_certificate.data + 36u +
                            test_read_u32_le(generated_server_certificate.data + 20u)) == 8u);
    PCHECK(test_read_u16_le(generated_server_certificate.data + 38u +
                            test_read_u32_le(generated_server_certificate.data + 20u)) == 72u);
    PCHECK(rdp_security_parse_server_certificate(generated_server_certificate.data,
                                                 generated_server_certificate.length,
                                                 &public_key) == LIBRDP_STATUS_OK);
    PCHECK(public_key.exponent == 65537u && public_key.modulus_len >= 256u);
    PCHECK(rdp_security_encrypt_client_random(&public_key, client_random, &encrypted) == LIBRDP_STATUS_OK);
    PCHECK(encrypted.length == public_key.modulus_len);
    PCHECK(rdp_security_decrypt_private_secret(generated_server_key,
                                               encrypted.data,
                                               encrypted.length,
                                               decrypted_client_random,
                                               sizeof(decrypted_client_random)) == LIBRDP_STATUS_OK);
    PCHECK(memcmp(decrypted_client_random, client_random, sizeof(client_random)) == 0);
    rdp_security_public_key_clear(&public_key);
    rdp_buffer_free(&encrypted);
    rdp_buffer_init(&encrypted);

    PCHECK(rdp_license_parse_error_alert(license, sizeof(license), &alert) == LIBRDP_STATUS_OK);
    PCHECK(alert.error_code == 1 && alert.state_transition == 2 && alert.blob_length == 2 && alert.blob[1] == 8);
    {
        rdp_license_error_alert valid_alert = alert;

        PCHECK(rdp_license_parse_error_alert(license, 15, &alert) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&alert, &valid_alert, sizeof(alert)) == 0);
    }
    PCHECK(rdp_license_parse_preamble(license, sizeof(license), &license_preamble) == LIBRDP_STATUS_OK);
    PCHECK(license_preamble.message_type == RDP_LICENSE_MESSAGE_ERROR_ALERT &&
           license_preamble.payload_len == 14u);
    PCHECK(rdp_license_write_error_alert(&license_packet,
                                         RDP_LICENSE_VERSION_3,
                                         7,
                                         8,
                                         RDP_LICENSE_BLOB_DATA,
                                         "ok",
                                         2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_error_alert(license_packet.data, license_packet.length, &alert) == LIBRDP_STATUS_OK);
    PCHECK(alert.error_code == 7 && alert.state_transition == 8 &&
           alert.blob_type == RDP_LICENSE_BLOB_DATA && alert.blob_length == 2);
    PCHECK(!rdp_license_error_alert_is_terminal_success(&alert));
    {
        rdp_license_error_alert valid_alert = alert;
        rdp_license_preamble valid_license_preamble = license_preamble;

        PCHECK(rdp_buffer_append_u8(&license_packet, 0x7f) == LIBRDP_STATUS_OK);
        PCHECK(rdp_license_parse_preamble(license_packet.data,
                                          license_packet.length,
                                          &license_preamble) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&license_preamble,
                      &valid_license_preamble,
                      sizeof(license_preamble)) == 0);
        license_packet.data[2] = (uint8_t)license_packet.length;
        license_packet.data[3] = 0;
        PCHECK(rdp_license_parse_error_alert(license_packet.data,
                                             license_packet.length,
                                             &alert) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&alert, &valid_alert, sizeof(alert)) == 0);
    }
    license_packet.length = 0;
    PCHECK(rdp_license_write_error_alert(&license_packet,
                                         RDP_LICENSE_VERSION_3,
                                         RDP_LICENSE_ERROR_STATUS_VALID_CLIENT,
                                         RDP_LICENSE_STATE_TRANSITION_NO_TRANSITION,
                                         RDP_LICENSE_BLOB_ERROR,
                                         NULL,
                                         0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_error_alert(license_packet.data,
                                         license_packet.length,
                                         &alert) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_error_alert_is_terminal_success(&alert));
    rdp_license_client_state_init(&license_state);
    PCHECK(rdp_license_client_state_step_error_alert(&license_state,
                                                     &alert) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_COMPLETED &&
           license_state.last_message_type == RDP_LICENSE_MESSAGE_ERROR_ALERT &&
           license_state.last_direction == RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT);
    PCHECK(rdp_license_client_state_step_error_alert(&license_state,
                                                     &alert) == LIBRDP_STATUS_PROTOCOL_ERROR);
    license_packet.length = 0;
    PCHECK(rdp_license_write_binary_blob(&license_packet,
                                         RDP_LICENSE_BLOB_KEY_EXCHANGE_ALG,
                                         "\x01\x00\x00\x00",
                                         4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_binary_blob(license_packet.data,
                                         license_packet.length,
                                         &license_blob) == LIBRDP_STATUS_OK);
    PCHECK(license_blob.type == RDP_LICENSE_BLOB_KEY_EXCHANGE_ALG &&
           license_blob.length == 4 &&
           license_blob.data[0] == 1);
    {
        rdp_license_binary_blob valid_license_blob = license_blob;

        PCHECK(rdp_license_parse_binary_blob(license_packet.data,
                                             license_packet.length - 1u,
                                             &license_blob) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&license_blob, &valid_license_blob, sizeof(license_blob)) == 0);
    }
    license_packet.length = 0;
    PCHECK(rdp_buffer_append_u8(&license_packet, 0xa5) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_preamble(&license_packet,
                                      0x00u,
                                      RDP_LICENSE_VERSION_3,
                                      0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(license_packet.length == 1 && license_packet.data[0] == 0xa5);
    PCHECK(rdp_license_write_binary_blob(&license_packet,
                                         0xffffu,
                                         NULL,
                                         0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(license_packet.length == 1 && license_packet.data[0] == 0xa5);
    PCHECK(rdp_license_write_hardware_id(&license_packet, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(license_packet.length == 1 && license_packet.data[0] == 0xa5);
    license_packet.length = 0;
    PCHECK(test_append_zeroes(&license_payload, 32u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_payload, 0x00060002u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_payload, (uint32_t)sizeof(license_company)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_payload, license_company, sizeof(license_company)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_payload, (uint32_t)sizeof(license_product)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_payload, license_product, sizeof(license_product)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_binary_blob(&license_payload,
                                         RDP_LICENSE_BLOB_KEY_EXCHANGE_ALG,
                                         "\x01\x00\x00\x00",
                                         4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_binary_blob(&license_payload,
                                         RDP_LICENSE_BLOB_CERTIFICATE,
                                         NULL,
                                         0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_payload, 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_binary_blob(&license_payload,
                                         RDP_LICENSE_BLOB_SCOPE,
                                         license_scope,
                                         (uint16_t)sizeof(license_scope)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_preamble(&license_packet,
                                      RDP_LICENSE_MESSAGE_REQUEST,
                                      RDP_LICENSE_VERSION_3,
                                      (uint16_t)license_payload.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_payload.data, license_payload.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_server_request(license_packet.data,
                                            license_packet.length,
                                            &license_request) == LIBRDP_STATUS_OK);
    PCHECK(license_request.product_info.version == 0x00060002u &&
           license_request.key_exchange_list.length == 4 &&
           license_request.scope_list.count == 1 &&
           license_request.scope_list.scopes[0].length == sizeof(license_scope));
    {
        rdp_license_server_request valid_license_request = license_request;

        PCHECK(rdp_license_parse_server_request(license_packet.data,
                                                license_packet.length - 1u,
                                                &license_request) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&license_request,
                      &valid_license_request,
                      sizeof(license_request)) == 0);
    }
    rdp_license_client_state_init(&license_state);
    PCHECK(rdp_license_classify_message(license_packet.data,
                                        license_packet.length,
                                        &license_message_type) == LIBRDP_STATUS_OK);
    PCHECK(license_message_type == RDP_LICENSE_MESSAGE_REQUEST);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         license_message_type) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_SERVER_REQUEST_RECEIVED);
    license_packet.length = 0;
    license_payload.length = 0;
    PCHECK(rdp_buffer_append_u32_le(&license_payload, 0u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_binary_blob(&license_payload,
                                         RDP_LICENSE_BLOB_ENCRYPTED_DATA,
                                         "\xaa\xbb",
                                         2) == LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&license_payload, 16u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_preamble(&license_packet,
                                      RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE,
                                      RDP_LICENSE_VERSION_3,
                                      (uint16_t)license_payload.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_payload.data, license_payload.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_platform_challenge(license_packet.data,
                                                license_packet.length,
                                                &license_challenge) == LIBRDP_STATUS_OK);
    PCHECK(license_challenge.encrypted_challenge.length == 2 &&
           license_challenge.encrypted_challenge.data[1] == 0xbb);
    {
        rdp_license_platform_challenge valid_license_challenge = license_challenge;

        PCHECK(rdp_license_parse_platform_challenge(license_packet.data,
                                                    license_packet.length - 1u,
                                                    &license_challenge) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&license_challenge,
                      &valid_license_challenge,
                      sizeof(license_challenge)) == 0);
    }
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    license_packet.length = 0;
    license_payload.length = 0;
    PCHECK(rdp_license_write_binary_blob(&license_payload,
                                         RDP_LICENSE_BLOB_ENCRYPTED_DATA,
                                         "\x11\x22",
                                         2) == LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&license_payload, 16u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_preamble(&license_packet,
                                      RDP_LICENSE_MESSAGE_NEW_LICENSE,
                                      RDP_LICENSE_VERSION_3,
                                      (uint16_t)license_payload.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_payload.data, license_payload.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_new_or_upgrade(license_packet.data,
                                            license_packet.length,
                                            &license_new) == LIBRDP_STATUS_OK);
    PCHECK(license_new.encrypted_license_info.type == RDP_LICENSE_BLOB_ENCRYPTED_DATA);
    rdp_license_client_state_init(&license_state);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER,
                                         RDP_LICENSE_MESSAGE_INFO) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_INITIAL);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_PLATFORM_CHALLENGE_RECEIVED);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER,
                                         RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE_RESPONSE) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_PLATFORM_CHALLENGE_RESPONSE_SENT);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_NEW_LICENSE) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_COMPLETED);
    rdp_license_client_state_init(&license_state);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_NEW_LICENSE) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_COMPLETED);
    rdp_license_client_state_init(&license_state);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_UPGRADE_LICENSE) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_COMPLETED);
    {
        rdp_license_new_or_upgrade valid_license_new = license_new;

        PCHECK(rdp_license_parse_new_or_upgrade(license_packet.data,
                                                license_packet.length - 1u,
                                                &license_new) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&license_new, &valid_license_new, sizeof(license_new)) == 0);
    }
    license_packet.length = 0;
    PCHECK(rdp_buffer_append_u32_le(&license_packet, 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_packet, (uint32_t)sizeof(license_scope)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_scope, sizeof(license_scope)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_packet, (uint32_t)sizeof(license_company)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_company, sizeof(license_company)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_packet, (uint32_t)sizeof(license_product)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_product, sizeof(license_product)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_packet, (uint32_t)sizeof(license_cal)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_cal, sizeof(license_cal)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_new_license_info(license_packet.data,
                                              license_packet.length,
                                              &license_info) == LIBRDP_STATUS_OK);
    PCHECK(license_info.scope_len == sizeof(license_scope) &&
           license_info.license_info_len == sizeof(license_cal));
    {
        rdp_license_new_license_info valid_license_info = license_info;

        PCHECK(rdp_buffer_append_u8(&license_packet, 0xaau) == LIBRDP_STATUS_OK);
        PCHECK(rdp_license_parse_new_license_info(license_packet.data,
                                                  license_packet.length,
                                                  &license_info) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&license_info, &valid_license_info, sizeof(license_info)) == 0);
        license_packet.length--;
    }
    memset(&license_cert_info, 0, sizeof(license_cert_info));
    license_cert_info.version = 1;
    license_cert_info.license_count = 2;
    license_cert_info.platform_id = 0x03010002u;
    license_cert_info.language_id = 0x0410u;
    license_cert_info.requested_product_id = license_requested_id;
    license_cert_info.requested_product_id_len = sizeof(license_requested_id);
    license_cert_info.adjusted_product_id = license_adjusted_id;
    license_cert_info.adjusted_product_id_len = sizeof(license_adjusted_id);
    license_cert_info.version_info.major_version = 10;
    license_cert_info.version_info.minor_version = 0;
    license_cert_info.version_info.flags = RDP_LICENSE_PRODUCT_INFO_LICENSE_ENFORCED |
                                           RDP_LICENSE_PRODUCT_INFO_RTM_LICENSE;
    license_packet.length = 0;
    PCHECK(rdp_license_write_product_certificate_info(&license_packet,
                                                      &license_cert_info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_product_certificate_info(license_packet.data,
                                                      license_packet.length,
                                                      &parsed_license_cert_info) ==
           LIBRDP_STATUS_OK);
    PCHECK(parsed_license_cert_info.license_count == 2 &&
           parsed_license_cert_info.requested_product_id_len == sizeof(license_requested_id) &&
           parsed_license_cert_info.adjusted_product_id[4] == 'A' &&
           parsed_license_cert_info.version_info.major_version == 10 &&
           (parsed_license_cert_info.version_info.flags & RDP_LICENSE_PRODUCT_INFO_RTM_LICENSE));
    {
        rdp_license_product_certificate_info valid_license_cert_info = parsed_license_cert_info;

        license_packet.data[27] = 2;
        PCHECK(rdp_license_parse_product_certificate_info(license_packet.data,
                                                          license_packet.length,
                                                          &parsed_license_cert_info) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&parsed_license_cert_info,
                      &valid_license_cert_info,
                      sizeof(parsed_license_cert_info)) == 0);
    }
    license_packet.length = 0;

    memset(&license_server_info, 0, sizeof(license_server_info));
    license_server_info.issuer_name = license_issuer_name;
    license_server_info.issuer_name_len = sizeof(license_issuer_name);
    license_server_info.scope = license_issuer_scope;
    license_server_info.scope_len = sizeof(license_issuer_scope);
    PCHECK(rdp_license_write_server_info(&license_packet,
                                         &license_server_info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_server_info(license_packet.data,
                                         license_packet.length,
                                         &parsed_license_server_info) == LIBRDP_STATUS_OK);
    PCHECK(parsed_license_server_info.version == RDP_LICENSE_SERVER_INFO_VERSION_1 &&
           parsed_license_server_info.issuer_name_len == sizeof(license_issuer_name) &&
           parsed_license_server_info.scope_len == sizeof(license_issuer_scope) &&
           !parsed_license_server_info.has_issuer_id);
    {
        rdp_license_server_info valid_license_server_info = parsed_license_server_info;

        license_packet.data[6] = 0;
        PCHECK(rdp_license_parse_server_info(license_packet.data,
                                             license_packet.length,
                                             &parsed_license_server_info) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&parsed_license_server_info,
                      &valid_license_server_info,
                      sizeof(parsed_license_server_info)) == 0);
    }
    license_packet.length = 0;

    license_server_info.issuer_id = license_issuer_id;
    license_server_info.issuer_id_len = sizeof(license_issuer_id);
    license_server_info.has_issuer_id = 1;
    PCHECK(rdp_license_write_server_info(&license_packet,
                                         &license_server_info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_server_info(license_packet.data,
                                         license_packet.length,
                                         &parsed_license_server_info) == LIBRDP_STATUS_OK);
    PCHECK(parsed_license_server_info.version == RDP_LICENSE_SERVER_INFO_VERSION_2 &&
           parsed_license_server_info.has_issuer_id &&
           parsed_license_server_info.issuer_id_len == sizeof(license_issuer_id));
    {
        rdp_license_server_info valid_license_server_info = parsed_license_server_info;

        license_packet.data[10 + sizeof(license_issuer_name) - 1u] = 1;
        PCHECK(rdp_license_parse_server_info(license_packet.data,
                                             license_packet.length,
                                             &parsed_license_server_info) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&parsed_license_server_info,
                      &valid_license_server_info,
                      sizeof(parsed_license_server_info)) == 0);
    }
    license_packet.length = 0;

    PCHECK(rdp_license_write_error_alert(&license_packet,
                                         RDP_LICENSE_VERSION_3,
                                         9,
                                         0,
                                         RDP_LICENSE_BLOB_ERROR,
                                         NULL,
                                         0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_error_alert(license_packet.data,
                                         license_packet.length,
                                         &alert) == LIBRDP_STATUS_OK);
    PCHECK(alert.blob_type == RDP_LICENSE_BLOB_ERROR && alert.blob_length == 0);
    rdp_license_client_state_init(&license_state);
    PCHECK(rdp_license_client_state_step_error_alert(&license_state,
                                                     &alert) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_FAILED &&
           license_state.last_message_type == RDP_LICENSE_MESSAGE_ERROR_ALERT &&
           license_state.last_direction == RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT);
    rdp_license_client_state_init(&license_state);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_ERROR_ALERT) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_FAILED);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_ERROR_ALERT) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    hardware_id.platform_id = 0x01020304u;
    hardware_id.data1 = 1;
    hardware_id.data2 = 2;
    hardware_id.data3 = 3;
    hardware_id.data4 = 4;
    license_packet.length = 0;
    PCHECK(rdp_license_write_hardware_id(&license_packet, &hardware_id) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_hardware_id(license_packet.data,
                                         license_packet.length,
                                         &parsed_hardware_id) == LIBRDP_STATUS_OK);
    PCHECK(parsed_hardware_id.platform_id == 0x01020304u && parsed_hardware_id.data4 == 4);
    {
        rdp_license_hardware_id valid_hardware_id = parsed_hardware_id;

        PCHECK(rdp_license_parse_hardware_id(license_packet.data,
                                             license_packet.length - 1u,
                                             &parsed_hardware_id) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&parsed_hardware_id,
                      &valid_hardware_id,
                      sizeof(parsed_hardware_id)) == 0);
    }
    challenge_response_data.version = 0x0100u;
    challenge_response_data.client_type = 0x0100u;
    challenge_response_data.license_detail_level = 3u;
    challenge_response_data.challenge_len = 2u;
    challenge_response_data.challenge = (const uint8_t*)"\x55\x66";
    license_packet.length = 0;
    PCHECK(rdp_license_write_platform_challenge_response_data(&license_packet,
                                                              &challenge_response_data) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_platform_challenge_response_data(license_packet.data,
                                                              license_packet.length,
                                                              &parsed_challenge_response_data) ==
           LIBRDP_STATUS_OK);
    PCHECK(parsed_challenge_response_data.challenge_len == 2 &&
           parsed_challenge_response_data.challenge[0] == 0x55);
    {
        rdp_license_platform_challenge_response_data valid_challenge_response_data =
            parsed_challenge_response_data;

        PCHECK(rdp_license_parse_platform_challenge_response_data(
                   license_packet.data,
                   license_packet.length - 1u,
                   &parsed_challenge_response_data) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&parsed_challenge_response_data,
                      &valid_challenge_response_data,
                      sizeof(parsed_challenge_response_data)) == 0);
    }
    license_blob.type = RDP_LICENSE_BLOB_RANDOM;
    license_blob.length = 2;
    license_blob.data = (const uint8_t*)"\x01\x02";
    license_request.key_exchange_list.type = RDP_LICENSE_BLOB_CLIENT_USER_NAME;
    license_request.key_exchange_list.length = 5;
    license_request.key_exchange_list.data = (const uint8_t*)"user";
    license_request.server_certificate.type = RDP_LICENSE_BLOB_CLIENT_MACHINE_NAME;
    license_request.server_certificate.length = 5;
    license_request.server_certificate.data = (const uint8_t*)"host";
    memset(client_random, 0x5a, sizeof(client_random));
    license_packet.length = 0;
    PCHECK(rdp_buffer_append_u8(&license_packet, 0xa5) == LIBRDP_STATUS_OK);
    license_bad_blob = license_blob;
    license_bad_blob.type = RDP_LICENSE_BLOB_DATA;
    PCHECK(rdp_license_write_client_new_license_request(&license_packet,
                                                        RDP_LICENSE_VERSION_3,
                                                        RDP_LICENSE_KEY_EXCHANGE_RSA,
                                                        0x03000000u,
                                                        client_random,
                                                        &license_bad_blob,
                                                        &license_request.key_exchange_list,
                                                        &license_request.server_certificate) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(license_packet.length == 1 && license_packet.data[0] == 0xa5);
    license_packet.length = 0;
    PCHECK(rdp_license_write_client_new_license_request(&license_packet,
                                                        RDP_LICENSE_VERSION_3,
                                                        RDP_LICENSE_KEY_EXCHANGE_RSA,
                                                        0x03000000u,
                                                        client_random,
                                                        &license_blob,
                                                        &license_request.key_exchange_list,
                                                        &license_request.server_certificate) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_preamble(license_packet.data,
                                      license_packet.length,
                                      &license_preamble) == LIBRDP_STATUS_OK);
    PCHECK(license_preamble.message_type == RDP_LICENSE_MESSAGE_NEW_LICENSE_REQUEST);
    PCHECK(rdp_license_parse_client_new_license_request(license_packet.data,
                                                        license_packet.length,
                                                        &client_license_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(client_license_request.preferred_key_exchange_alg == RDP_LICENSE_KEY_EXCHANGE_RSA &&
           client_license_request.platform_id == 0x03000000u &&
           client_license_request.encrypted_pre_master.length == 2 &&
           client_license_request.user_name.length == 5 &&
           client_license_request.machine_name.type == RDP_LICENSE_BLOB_CLIENT_MACHINE_NAME);
    rdp_license_client_state_init(&license_state);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_REQUEST) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER,
                                         RDP_LICENSE_MESSAGE_NEW_LICENSE_REQUEST) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_CLIENT_REQUEST_SENT);
    {
        rdp_license_client_new_license_request valid_client_license_request =
            client_license_request;

        license_packet.data[44] = 0xff;
        PCHECK(rdp_license_parse_client_new_license_request(license_packet.data,
                                                            license_packet.length,
                                                            &client_license_request) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&client_license_request,
                      &valid_client_license_request,
                      sizeof(client_license_request)) == 0);
        license_packet.data[44] = RDP_LICENSE_BLOB_RANDOM;
    }
    license_request.scope_list.scopes[0].type = RDP_LICENSE_BLOB_DATA;
    license_request.scope_list.scopes[0].length = (uint16_t)sizeof(license_cal);
    license_request.scope_list.scopes[0].data = license_cal;
    license_challenge.encrypted_challenge.type = RDP_LICENSE_BLOB_ENCRYPTED_DATA;
    license_challenge.encrypted_challenge.length = 20;
    license_challenge.encrypted_challenge.data = client_random;
    license_packet.length = 0;
    PCHECK(rdp_buffer_append_u8(&license_packet, 0xa5) == LIBRDP_STATUS_OK);
    license_bad_blob = license_request.scope_list.scopes[0];
    license_bad_blob.type = RDP_LICENSE_BLOB_SCOPE;
    PCHECK(rdp_license_write_client_info(&license_packet,
                                         RDP_LICENSE_VERSION_3,
                                         RDP_LICENSE_KEY_EXCHANGE_RSA,
                                         0x03000000u,
                                         client_random,
                                         &license_blob,
                                         &license_bad_blob,
                                         &license_challenge.encrypted_challenge,
                                         client_random) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(license_packet.length == 1 && license_packet.data[0] == 0xa5);
    license_packet.length = 0;
    PCHECK(rdp_license_write_client_info(&license_packet,
                                         RDP_LICENSE_VERSION_3,
                                         RDP_LICENSE_KEY_EXCHANGE_RSA,
                                         0x03000000u,
                                         client_random,
                                         &license_blob,
                                         &license_request.scope_list.scopes[0],
                                         &license_challenge.encrypted_challenge,
                                         client_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_preamble(license_packet.data,
                                      license_packet.length,
                                      &license_preamble) == LIBRDP_STATUS_OK);
    PCHECK(license_preamble.message_type == RDP_LICENSE_MESSAGE_INFO);
    PCHECK(rdp_license_parse_client_info(license_packet.data,
                                         license_packet.length,
                                         &client_license_info) == LIBRDP_STATUS_OK);
    PCHECK(client_license_info.preferred_key_exchange_alg == RDP_LICENSE_KEY_EXCHANGE_RSA &&
           client_license_info.license_info.length == sizeof(license_cal) &&
           client_license_info.encrypted_hardware_id.length == 20 &&
           client_license_info.mac[15] == 0x5a);
    {
        rdp_license_client_info valid_client_license_info = client_license_info;

        license_packet.data[48 + license_blob.length] = 0xff;
        PCHECK(rdp_license_parse_client_info(license_packet.data,
                                             license_packet.length,
                                             &client_license_info) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&client_license_info,
                      &valid_client_license_info,
                      sizeof(client_license_info)) == 0);
        license_packet.data[48 + license_blob.length] = RDP_LICENSE_BLOB_DATA;
    }
    license_packet.length = 0;
    PCHECK(rdp_buffer_append_u8(&license_packet, 0xa5) == LIBRDP_STATUS_OK);
    license_bad_blob = license_challenge.encrypted_challenge;
    license_bad_blob.type = RDP_LICENSE_BLOB_DATA;
    PCHECK(rdp_license_write_platform_challenge_response(&license_packet,
                                                         RDP_LICENSE_VERSION_3,
                                                         &license_bad_blob,
                                                         &license_challenge.encrypted_challenge,
                                                         client_random) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(license_packet.length == 1 && license_packet.data[0] == 0xa5);
    license_packet.length = 0;
    PCHECK(rdp_license_write_platform_challenge_response(&license_packet,
                                                         RDP_LICENSE_VERSION_3,
                                                         &license_challenge.encrypted_challenge,
                                                         &license_challenge.encrypted_challenge,
                                                         client_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_preamble(license_packet.data,
                                      license_packet.length,
                                      &license_preamble) == LIBRDP_STATUS_OK);
    PCHECK(license_preamble.message_type == RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE_RESPONSE);
    PCHECK(rdp_license_parse_platform_challenge_response(license_packet.data,
                                                         license_packet.length,
                                                         &client_challenge_response) ==
           LIBRDP_STATUS_OK);
    PCHECK(client_challenge_response.encrypted_response.length == 20 &&
           client_challenge_response.encrypted_hardware_id.length == 20 &&
           client_challenge_response.mac[0] == 0x5a);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER,
                                         RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE_RESPONSE) ==
           LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_PLATFORM_CHALLENGE_RESPONSE_SENT);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_NEW_LICENSE) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_COMPLETED);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_ERROR_ALERT) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    {
        rdp_license_platform_challenge_response valid_client_challenge_response =
            client_challenge_response;

        license_packet.data[4] = 0;
        PCHECK(rdp_license_parse_platform_challenge_response(license_packet.data,
                                                             license_packet.length,
                                                             &client_challenge_response) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&client_challenge_response,
                      &valid_client_challenge_response,
                      sizeof(client_challenge_response)) == 0);
    }
    {
        const uint8_t challenge_plain[] = {0x31, 0x32, 0x33, 0x34};
        rdp_license_crypto_context license_crypto;
        rdp_buffer encrypted_challenge;
        rdp_buffer response_plain;
        rdp_buffer hardware_plain;
        rdp_buffer response_mac_input;
        uint8_t challenge_mac[RDP_LICENSE_MAC_LEN];
        uint8_t response_mac[RDP_LICENSE_MAC_LEN];
        librdp_status license_crypto_status;

        memset(&license_crypto, 0, sizeof(license_crypto));
        rdp_buffer_init(&encrypted_challenge);
        rdp_buffer_init(&response_plain);
        rdp_buffer_init(&hardware_plain);
        rdp_buffer_init(&response_mac_input);
        license_crypto.ready = 1;
        for (i = 0; i < RDP_LICENSE_MAC_LEN; i++)
        {
            license_crypto.encryption_key[i] = (uint8_t)(0x20u + i);
            license_crypto.mac_salt_key[i] = (uint8_t)(0x80u + i);
        }
        for (i = 0; i < RDP_LICENSE_HARDWARE_ID_LEN; i++)
            license_crypto.hardware_id[i] = (uint8_t)(0xc0u + i);

        license_crypto_status = rdp_security_license_crypt(license_crypto.encryption_key,
                                                           challenge_plain,
                                                           sizeof(challenge_plain),
                                                           &encrypted_challenge);
        if (license_crypto_status == LIBRDP_STATUS_UNSUPPORTED)
        {
            PCHECK(encrypted_challenge.length == 0);
        }
        else
        {
            PCHECK(license_crypto_status == LIBRDP_STATUS_OK);
            PCHECK(rdp_security_license_mac(license_crypto.mac_salt_key,
                                            challenge_plain,
                                            sizeof(challenge_plain),
                                            challenge_mac) == LIBRDP_STATUS_OK);
            license_payload.length = 0;
            license_packet.length = 0;
            PCHECK(rdp_buffer_append_u32_le(&license_payload, 0u) == LIBRDP_STATUS_OK);
            PCHECK(rdp_license_write_binary_blob(&license_payload,
                                                 RDP_LICENSE_BLOB_ENCRYPTED_DATA,
                                                 encrypted_challenge.data,
                                                 (uint16_t)encrypted_challenge.length) == LIBRDP_STATUS_OK);
            PCHECK(rdp_buffer_append(&license_payload, challenge_mac, sizeof(challenge_mac)) == LIBRDP_STATUS_OK);
            PCHECK(rdp_license_write_preamble(&license_packet,
                                              RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE,
                                              RDP_LICENSE_VERSION_3,
                                              (uint16_t)license_payload.length) == LIBRDP_STATUS_OK);
            PCHECK(rdp_buffer_append(&license_packet, license_payload.data, license_payload.length) ==
                   LIBRDP_STATUS_OK);
            PCHECK(rdp_license_parse_platform_challenge(license_packet.data,
                                                        license_packet.length,
                                                        &license_challenge) == LIBRDP_STATUS_OK);
            license_payload.length = 0;
            PCHECK(rdp_license_build_platform_challenge_response(&license_crypto,
                                                                 &license_challenge,
                                                                 &license_payload) == LIBRDP_STATUS_OK);
            PCHECK(rdp_license_parse_platform_challenge_response(license_payload.data,
                                                                 license_payload.length,
                                                                 &client_challenge_response) ==
                   LIBRDP_STATUS_OK);
            PCHECK(rdp_security_license_crypt(license_crypto.encryption_key,
                                              client_challenge_response.encrypted_response.data,
                                              client_challenge_response.encrypted_response.length,
                                              &response_plain) == LIBRDP_STATUS_OK);
            PCHECK(rdp_security_license_crypt(license_crypto.encryption_key,
                                              client_challenge_response.encrypted_hardware_id.data,
                                              client_challenge_response.encrypted_hardware_id.length,
                                              &hardware_plain) == LIBRDP_STATUS_OK);
            PCHECK(hardware_plain.length == RDP_LICENSE_HARDWARE_ID_LEN &&
                   memcmp(hardware_plain.data,
                          license_crypto.hardware_id,
                          RDP_LICENSE_HARDWARE_ID_LEN) == 0);
            PCHECK(rdp_license_parse_platform_challenge_response_data(
                       response_plain.data,
                       response_plain.length,
                       &parsed_challenge_response_data) == LIBRDP_STATUS_OK);
            PCHECK(parsed_challenge_response_data.version ==
                       RDP_LICENSE_PLATFORM_CHALLENGE_RESPONSE_VERSION &&
                   parsed_challenge_response_data.client_type == RDP_LICENSE_CLIENT_TYPE_OTHER &&
                   parsed_challenge_response_data.license_detail_level == RDP_LICENSE_DETAIL_LEVEL_DETAIL &&
                   parsed_challenge_response_data.challenge_len == sizeof(challenge_plain) &&
                   memcmp(parsed_challenge_response_data.challenge,
                          challenge_plain,
                          sizeof(challenge_plain)) == 0);
            PCHECK(rdp_buffer_append(&response_mac_input,
                                     response_plain.data,
                                     response_plain.length) == LIBRDP_STATUS_OK);
            PCHECK(rdp_buffer_append(&response_mac_input,
                                     license_crypto.hardware_id,
                                     RDP_LICENSE_HARDWARE_ID_LEN) == LIBRDP_STATUS_OK);
            PCHECK(rdp_security_license_mac(license_crypto.mac_salt_key,
                                            response_mac_input.data,
                                            response_mac_input.length,
                                            response_mac) == LIBRDP_STATUS_OK);
            PCHECK(memcmp(response_mac, client_challenge_response.mac, sizeof(response_mac)) == 0);
            license_packet.data[license_packet.length - 1u] ^= 0x01u;
            PCHECK(rdp_license_parse_platform_challenge(license_packet.data,
                                                        license_packet.length,
                                                        &license_challenge) == LIBRDP_STATUS_OK);
            license_payload.length = 0;
            PCHECK(rdp_license_build_platform_challenge_response(&license_crypto,
                                                                 &license_challenge,
                                                                 &license_payload) ==
                   LIBRDP_STATUS_PROTOCOL_ERROR);
        }
        rdp_buffer_free(&response_mac_input);
        rdp_buffer_free(&hardware_plain);
        rdp_buffer_free(&response_plain);
        rdp_buffer_free(&encrypted_challenge);
        rdp_license_crypto_context_clear(&license_crypto);
    }

    PCHECK(rdp_virtual_channel_parse_packet(channel, sizeof(channel), &vc) == LIBRDP_STATUS_OK);
    PCHECK(vc.length == 3 && vc.flags == 0x10 && vc.payload[2] == 3);
    PCHECK(rdp_virtual_channel_parse_packet(channel_fragment, sizeof(channel_fragment), &vc) == LIBRDP_STATUS_OK);
    PCHECK(vc.length == 8 && vc.flags == RDP_VIRTUAL_CHANNEL_FLAG_FIRST && vc.payload_len == 3 && vc.payload[2] == 3);
    PCHECK(rdp_virtual_channel_write_packet(&channel_packet, dyn_create, sizeof(dyn_create), 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_virtual_channel_parse_packet(channel_packet.data, channel_packet.length, &vc) == LIBRDP_STATUS_OK);
    PCHECK(vc.length == sizeof(dyn_create) && vc.flags == 3 && memcmp(vc.payload, dyn_create, sizeof(dyn_create)) == 0);
    PCHECK(rdp_dynamic_channel_parse_header(dyn_caps, sizeof(dyn_caps), &dyn_header) == LIBRDP_STATUS_OK);
    PCHECK(dyn_header.command == RDP_DYNAMIC_CHANNEL_CMD_CAPABILITIES && dyn_header.channel_id_bytes == 1);
    {
        rdp_dynamic_channel_header valid_dyn_header = dyn_header;

        PCHECK(rdp_dynamic_channel_parse_header(dyn_bad_header, sizeof(dyn_bad_header), &dyn_header) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_header, &valid_dyn_header, sizeof(dyn_header)) == 0);
    }
    PCHECK(rdp_dynamic_channel_parse_capabilities(dyn_caps, sizeof(dyn_caps), &dyn_parsed_caps) ==
           LIBRDP_STATUS_OK);
    PCHECK(dyn_parsed_caps.version == 3 &&
           dyn_parsed_caps.has_priority_charges &&
           dyn_parsed_caps.priority_charge[0] == 936 &&
           dyn_parsed_caps.priority_charge[1] == 3276 &&
           dyn_parsed_caps.priority_charge[2] == 9362 &&
           dyn_parsed_caps.priority_charge[3] == 21845);
    {
        rdp_dynamic_channel_capabilities valid_dyn_caps = dyn_parsed_caps;

        PCHECK(rdp_dynamic_channel_parse_capabilities(dyn_caps_zero,
                                                      sizeof(dyn_caps_zero),
                                                      &dyn_parsed_caps) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_parsed_caps, &valid_dyn_caps, sizeof(dyn_parsed_caps)) == 0);
    }
    PCHECK(rdp_dynamic_channel_select_version(0) == 0 &&
           rdp_dynamic_channel_select_version(1) == 1 &&
           rdp_dynamic_channel_select_version(2) == 2 &&
           rdp_dynamic_channel_select_version(3) == 3 &&
           rdp_dynamic_channel_select_version(4) == 3);
    PCHECK(rdp_dynamic_channel_select_channel_id_bytes(0xffu) == 1 &&
           rdp_dynamic_channel_select_channel_id_bytes(0x100u) == 2 &&
           rdp_dynamic_channel_select_channel_id_bytes(0x10000u) == 4);
    PCHECK(rdp_dynamic_channel_data_pdu_header_size(1) == 2 &&
           rdp_dynamic_channel_data_pdu_header_size(2) == 3 &&
           rdp_dynamic_channel_data_pdu_header_size(3) == 0 &&
           rdp_dynamic_channel_data_first_pdu_header_size(1, 0xffu) == 3 &&
           rdp_dynamic_channel_data_first_pdu_header_size(1, 0x100u) == 4 &&
           rdp_dynamic_channel_data_first_pdu_header_size(1, 0x10000u) == 6);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_capabilities_response(&dyn_response, 1) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 4 && dyn_response.data[0] == 0x50 && dyn_response.data[2] == 1);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_capabilities_response(&dyn_response, 2) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 4 && dyn_response.data[0] == 0x50 && dyn_response.data[2] == 2);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_capabilities_response(&dyn_response, 3) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 4 && dyn_response.data[0] == 0x50 && dyn_response.data[2] == 3);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_capabilities_response(&dyn_response, 4) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_parse_create_request(dyn_create,
                                                    sizeof(dyn_create),
                                                    &dyn_create_request) == LIBRDP_STATUS_OK);
    PCHECK(dyn_create_request.channel_id == 7 && dyn_create_request.channel_id_bytes == 1 &&
           dyn_create_request.priority == 2 &&
           dyn_create_request.name_len == 4 && memcmp(dyn_create_request.name, "ECHO", 4) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_create_request(&dyn_response,
                                                    0x1234u,
                                                    2,
                                                    2,
                                                    "APP",
                                                    3) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 7 && dyn_response.data[0] == 0x19 &&
           test_read_u16_le(dyn_response.data + 1) == 0x1234u &&
           memcmp(dyn_response.data + 3, "APP", 4) == 0);
    PCHECK(rdp_dynamic_channel_parse_create_request(dyn_response.data,
                                                    dyn_response.length,
                                                    &dyn_create_request) == LIBRDP_STATUS_OK);
    PCHECK(dyn_create_request.channel_id == 0x1234u && dyn_create_request.channel_id_bytes == 2 &&
           dyn_create_request.priority == 2 &&
           dyn_create_request.name_len == 3 && memcmp(dyn_create_request.name, "APP", 3) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_create_request(&dyn_response,
                                                    15,
                                                    1,
                                                    3,
                                                    "Microsoft::Windows::RDS::Notify",
                                                    sizeof("Microsoft::Windows::RDS::Notify") - 1u) ==
           LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof("Microsoft::Windows::RDS::Notify") + 2u &&
           dyn_response.data[0] == 0x1c && dyn_response.data[1] == 15);
    PCHECK(rdp_dynamic_channel_parse_create_request(dyn_response.data,
                                                    dyn_response.length,
                                                    &dyn_create_request) == LIBRDP_STATUS_OK);
    PCHECK(dyn_create_request.channel_id == 15 && dyn_create_request.channel_id_bytes == 1 &&
           dyn_create_request.priority == 3 &&
           dyn_create_request.name_len == sizeof("Microsoft::Windows::RDS::Notify") - 1u &&
           memcmp(dyn_create_request.name,
                  "Microsoft::Windows::RDS::Notify",
                  sizeof("Microsoft::Windows::RDS::Notify") - 1u) == 0);
    PCHECK(rdp_dynamic_channel_write_create_request(&dyn_response,
                                                    1,
                                                    1,
                                                    0,
                                                    NULL,
                                                    0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    {
        rdp_dynamic_channel_create_request valid_dyn_create_request = dyn_create_request;

        PCHECK(rdp_dynamic_channel_parse_create_request(dyn_data,
                                                        sizeof(dyn_data),
                                                        &dyn_create_request) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_create_request,
                      &valid_dyn_create_request,
                      sizeof(dyn_create_request)) == 0);
    }
    PCHECK(rdp_dynamic_channel_write_create_response(&dyn_response,
                                                     7,
                                                     1,
                                                     RDP_DYNAMIC_CHANNEL_STATUS_OK) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 6 && dyn_response.data[0] == 0x10 && dyn_response.data[1] == 7 &&
           test_read_u32_le(dyn_response.data + 2) == 0);
    PCHECK(rdp_dynamic_channel_parse_create_response(dyn_response.data,
                                                     dyn_response.length,
                                                     &dyn_create_response) == LIBRDP_STATUS_OK);
    PCHECK(dyn_create_response.channel_id == 7 &&
           dyn_create_response.channel_id_bytes == 1 &&
           dyn_create_response.status_code == RDP_DYNAMIC_CHANNEL_STATUS_OK);
    {
        rdp_dynamic_channel_create_response valid_dyn_create_response = dyn_create_response;

        PCHECK(rdp_dynamic_channel_parse_create_response(dyn_response.data,
                                                         dyn_response.length - 1u,
                                                         &dyn_create_response) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_create_response,
                      &valid_dyn_create_response,
                      sizeof(dyn_create_response)) == 0);
        PCHECK(rdp_dynamic_channel_parse_create_request(dyn_response.data,
                                                        dyn_response.length,
                                                        &dyn_create_request) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_create_response,
                      &valid_dyn_create_response,
                      sizeof(dyn_create_response)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_parse_data(dyn_data, sizeof(dyn_data), &dyn_data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_data_pdu.channel_id == 7 && dyn_data_pdu.data_len == 3 && dyn_data_pdu.data[0] == 0xaa);
    {
        rdp_dynamic_channel_data_pdu valid_dyn_data_pdu = dyn_data_pdu;
        uint8_t high_dyn_data_priority[sizeof(dyn_data)];

        memcpy(high_dyn_data_priority, dyn_data, sizeof(high_dyn_data_priority));
        high_dyn_data_priority[0] = 0x3cu;
        PCHECK(rdp_dynamic_channel_parse_data(high_dyn_data_priority,
                                              sizeof(high_dyn_data_priority),
                                              &dyn_data_pdu) == LIBRDP_STATUS_OK);
        PCHECK(dyn_data_pdu.channel_id == valid_dyn_data_pdu.channel_id &&
               dyn_data_pdu.channel_id_bytes == valid_dyn_data_pdu.channel_id_bytes &&
               dyn_data_pdu.data_len == valid_dyn_data_pdu.data_len &&
               memcmp(dyn_data_pdu.data, valid_dyn_data_pdu.data, dyn_data_pdu.data_len) == 0);
        valid_dyn_data_pdu = dyn_data_pdu;
        PCHECK(rdp_dynamic_channel_parse_data(dyn_create,
                                              sizeof(dyn_create),
                                              &dyn_data_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_data_pdu, &valid_dyn_data_pdu, sizeof(dyn_data_pdu)) == 0);
    }
    PCHECK(rdp_dynamic_channel_parse_data(dyn_data, sizeof(dyn_data), &dyn_data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(rdp_dynamic_channel_write_data(&dyn_response,
                                          dyn_data_pdu.channel_id,
                                          dyn_data_pdu.channel_id_bytes,
                                          dyn_data_pdu.data,
                                          dyn_data_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(dyn_data) && memcmp(dyn_response.data, dyn_data, sizeof(dyn_data)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_data(&dyn_response,
                                          0x00123456u,
                                          4,
                                          dyn_data_pdu.data,
                                          dyn_data_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 8 && dyn_response.data[0] == 0x32 &&
           test_read_u32_le(dyn_response.data + 1) == 0x00123456u &&
           memcmp(dyn_response.data + 5, dyn_data_pdu.data, dyn_data_pdu.data_len) == 0);
    PCHECK(rdp_dynamic_channel_parse_data(dyn_response.data, dyn_response.length, &dyn_data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_data_pdu.channel_id == 0x00123456u &&
           dyn_data_pdu.channel_id_bytes == 4 &&
           dyn_data_pdu.data_len == 3);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_data_ex(&dyn_response,
                                             7,
                                             1,
                                             2,
                                             dyn_data_pdu.data,
                                             dyn_data_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 5 && dyn_response.data[0] == 0x38 && dyn_response.data[1] == 7);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_data_ex(&dyn_response,
                                             7,
                                             1,
                                             3,
                                             dyn_data_pdu.data,
                                             dyn_data_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 5 && dyn_response.data[0] == 0x3c && dyn_response.data[1] == 7);
    PCHECK(rdp_dynamic_channel_parse_data(dyn_response.data, dyn_response.length, &dyn_data_pdu) ==
           LIBRDP_STATUS_OK);
    PCHECK(dyn_data_pdu.channel_id == 7 && dyn_data_pdu.channel_id_bytes == 1 &&
           dyn_data_pdu.data_len == 3);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_data(&dyn_response, 0x100u, 1, dyn_data, sizeof(dyn_data)) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_parse_data_first(dyn_data_first,
                                                sizeof(dyn_data_first),
                                                &dyn_first_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_first_pdu.channel_id == 7 &&
           dyn_first_pdu.channel_id_bytes == 1 &&
           dyn_first_pdu.total_length == 300 &&
           dyn_first_pdu.data_len == 3 &&
           dyn_first_pdu.data[2] == 0xcc);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_write_data_first(&dyn_response,
                                                dyn_first_pdu.channel_id,
                                                dyn_first_pdu.channel_id_bytes,
                                                dyn_first_pdu.total_length,
                                                dyn_first_pdu.data,
                                                dyn_first_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(dyn_data_first) &&
           memcmp(dyn_response.data, dyn_data_first, sizeof(dyn_data_first)) == 0);
    PCHECK(rdp_dynamic_channel_parse_data_first(dyn_data_first,
                                                sizeof(dyn_data_first) - 1u,
                                                &dyn_first_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_first_pdu.data_len == 2);
    {
        uint8_t bad_dyn_data_first[sizeof(dyn_data_first)];
        rdp_dynamic_channel_data_first_pdu valid_dyn_first_pdu = dyn_first_pdu;

        memcpy(bad_dyn_data_first, dyn_data_first, sizeof(bad_dyn_data_first));
        bad_dyn_data_first[2] = 2u;
        bad_dyn_data_first[3] = 0u;
        PCHECK(rdp_dynamic_channel_parse_data_first(bad_dyn_data_first,
                                                    sizeof(bad_dyn_data_first),
                                                    &dyn_first_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_first_pdu, &valid_dyn_first_pdu, sizeof(dyn_first_pdu)) == 0);
        PCHECK(rdp_dynamic_channel_parse_data_first((const uint8_t[]){0x20, 0x07, 0x00},
                                                    3,
                                                    &dyn_first_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_first_pdu, &valid_dyn_first_pdu, sizeof(dyn_first_pdu)) == 0);
    }
    PCHECK(rdp_dynamic_channel_write_data_first(&dyn_response, 7, 1, 0, NULL, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_write_data_first(&dyn_response,
                                                7,
                                                1,
                                                300,
                                                dyn_data_first,
                                                RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_parse_close(dyn_close, sizeof(dyn_close), &dyn_close_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_close_pdu.channel_id == 7 && dyn_close_pdu.channel_id_bytes == 1);
    {
        rdp_dynamic_channel_close_pdu valid_dyn_close_pdu = dyn_close_pdu;

        PCHECK(rdp_dynamic_channel_parse_close(dyn_data,
                                               sizeof(dyn_data),
                                               &dyn_close_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_close_pdu, &valid_dyn_close_pdu, sizeof(dyn_close_pdu)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_write_close(&dyn_response, 0x1234u, 2) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 3 && dyn_response.data[0] == 0x41 &&
           test_read_u16_le(dyn_response.data + 1) == 0x1234u);
    PCHECK(rdp_dynamic_channel_parse_close(dyn_response.data, dyn_response.length, &dyn_close_pdu) ==
           LIBRDP_STATUS_OK);
    PCHECK(dyn_close_pdu.channel_id == 0x1234u && dyn_close_pdu.channel_id_bytes == 2);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_close(&dyn_response, 0x10000u, 2) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_parse_compressed_data(dyn_data_compressed,
                                                     sizeof(dyn_data_compressed),
                                                     &dyn_compressed_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_compressed_pdu.channel_id == 7 &&
           dyn_compressed_pdu.channel_id_bytes == 1 &&
           dyn_compressed_pdu.data_len == 3 &&
           dyn_compressed_pdu.data[0] == 0xe0);
    {
        rdp_dynamic_channel_compressed_data_pdu valid_dyn_compressed_pdu = dyn_compressed_pdu;
        uint8_t high_dyn_compressed_priority[sizeof(dyn_data_compressed)];

        memcpy(high_dyn_compressed_priority, dyn_data_compressed, sizeof(high_dyn_compressed_priority));
        high_dyn_compressed_priority[0] = 0x7cu;
        PCHECK(rdp_dynamic_channel_parse_compressed_data(high_dyn_compressed_priority,
                                                         sizeof(high_dyn_compressed_priority),
                                                         &dyn_compressed_pdu) == LIBRDP_STATUS_OK);
        PCHECK(dyn_compressed_pdu.channel_id == valid_dyn_compressed_pdu.channel_id &&
               dyn_compressed_pdu.channel_id_bytes == valid_dyn_compressed_pdu.channel_id_bytes &&
               dyn_compressed_pdu.data_len == valid_dyn_compressed_pdu.data_len &&
               memcmp(dyn_compressed_pdu.data,
                      valid_dyn_compressed_pdu.data,
                      dyn_compressed_pdu.data_len) == 0);
        valid_dyn_compressed_pdu = dyn_compressed_pdu;
        PCHECK(rdp_dynamic_channel_parse_compressed_data(dyn_data,
                                                         sizeof(dyn_data),
                                                         &dyn_compressed_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_compressed_pdu,
                      &valid_dyn_compressed_pdu,
                      sizeof(dyn_compressed_pdu)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_parse_compressed_data(dyn_data_compressed,
                                                     sizeof(dyn_data_compressed),
                                                     &dyn_compressed_pdu) == LIBRDP_STATUS_OK);
    PCHECK(rdp_dynamic_channel_write_compressed_data(&dyn_response,
                                                     dyn_compressed_pdu.channel_id,
                                                     dyn_compressed_pdu.channel_id_bytes,
                                                     dyn_compressed_pdu.data,
                                                     dyn_compressed_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(dyn_data_compressed) &&
           memcmp(dyn_response.data, dyn_data_compressed, sizeof(dyn_data_compressed)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_compressed_data(&dyn_response,
                                                     7,
                                                     1,
                                                     dyn_compressed_pdu.data,
                                                     1u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_parse_compressed_data_first(dyn_data_first_compressed,
                                                           sizeof(dyn_data_first_compressed),
                                                           &dyn_first_compressed_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_first_compressed_pdu.channel_id == 7 &&
           dyn_first_compressed_pdu.total_length == 300 &&
           dyn_first_compressed_pdu.data_len == 3 &&
           dyn_first_compressed_pdu.data[1] == 0x06);
    {
        uint8_t bad_dyn_first_compressed[sizeof(dyn_data_first_compressed)];
        rdp_dynamic_channel_compressed_data_first_pdu valid_dyn_first_compressed_pdu =
            dyn_first_compressed_pdu;

        memcpy(bad_dyn_first_compressed,
               dyn_data_first_compressed,
               sizeof(bad_dyn_first_compressed));
        bad_dyn_first_compressed[2] = 0u;
        bad_dyn_first_compressed[3] = 0u;
        PCHECK(rdp_dynamic_channel_parse_compressed_data_first(
                   bad_dyn_first_compressed,
                   sizeof(bad_dyn_first_compressed),
                   &dyn_first_compressed_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_first_compressed_pdu,
                      &valid_dyn_first_compressed_pdu,
                      sizeof(dyn_first_compressed_pdu)) == 0);
        bad_dyn_first_compressed[2] = 2u;
        bad_dyn_first_compressed[3] = 0u;
        PCHECK(rdp_dynamic_channel_parse_compressed_data_first(
                   bad_dyn_first_compressed,
                   sizeof(bad_dyn_first_compressed),
                   &dyn_first_compressed_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_first_compressed_pdu,
                      &valid_dyn_first_compressed_pdu,
                      sizeof(dyn_first_compressed_pdu)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_write_compressed_data_first(&dyn_response,
                                                           dyn_first_compressed_pdu.channel_id,
                                                           dyn_first_compressed_pdu.channel_id_bytes,
                                                           dyn_first_compressed_pdu.total_length,
                                                           dyn_first_compressed_pdu.data,
                                                           dyn_first_compressed_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(dyn_data_first_compressed) &&
           memcmp(dyn_response.data, dyn_data_first_compressed, sizeof(dyn_data_first_compressed)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_compressed_data_first(&dyn_response,
                                                           7,
                                                           1,
                                                           1,
                                                           dyn_first_compressed_pdu.data,
                                                           dyn_first_compressed_pdu.data_len) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_parse_soft_sync_request(dyn_soft_sync_request,
                                                       sizeof(dyn_soft_sync_request),
                                                       &dyn_soft_sync) == LIBRDP_STATUS_OK);
    PCHECK(dyn_soft_sync.length == 22 &&
           dyn_soft_sync.flags == (RDP_DYNAMIC_CHANNEL_SOFT_SYNC_TCP_FLUSHED |
                                   RDP_DYNAMIC_CHANNEL_SOFT_SYNC_CHANNEL_LIST_PRESENT) &&
           dyn_soft_sync.tunnel_count == 1);
    {
        uint8_t bad_dyn_soft_sync_request[sizeof(dyn_soft_sync_request)];
        rdp_dynamic_channel_soft_sync_request valid_dyn_soft_sync = dyn_soft_sync;

        memcpy(bad_dyn_soft_sync_request,
               dyn_soft_sync_request,
               sizeof(bad_dyn_soft_sync_request));
        bad_dyn_soft_sync_request[6] = 0u;
        bad_dyn_soft_sync_request[7] = 0u;
        PCHECK(rdp_dynamic_channel_parse_soft_sync_request(
                   bad_dyn_soft_sync_request,
                   sizeof(bad_dyn_soft_sync_request),
                   &dyn_soft_sync) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_soft_sync, &valid_dyn_soft_sync, sizeof(dyn_soft_sync)) == 0);
    }
    PCHECK(rdp_dynamic_channel_soft_sync_request_get_list(&dyn_soft_sync,
                                                          0,
                                                          &dyn_soft_sync_list) == LIBRDP_STATUS_OK);
    PCHECK(dyn_soft_sync_list.tunnel_type == RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE &&
           dyn_soft_sync_list.channel_count == 2);
    {
        uint8_t bad_list[14];
        rdp_dynamic_channel_soft_sync_request bad_soft_sync = dyn_soft_sync;
        rdp_dynamic_channel_soft_sync_channel_list valid_dyn_soft_sync_list =
            dyn_soft_sync_list;

        PCHECK(dyn_soft_sync.lists_len == sizeof(bad_list));
        memcpy(bad_list, dyn_soft_sync.lists, sizeof(bad_list));
        bad_list[0] = 0xffu;
        bad_soft_sync.lists = bad_list;
        PCHECK(rdp_dynamic_channel_soft_sync_request_get_list(&bad_soft_sync,
                                                              0,
                                                              &dyn_soft_sync_list) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_soft_sync_list,
                      &valid_dyn_soft_sync_list,
                      sizeof(dyn_soft_sync_list)) == 0);
        PCHECK(rdp_dynamic_channel_soft_sync_request_get_list(&dyn_soft_sync,
                                                              1,
                                                              &dyn_soft_sync_list) ==
               LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(memcmp(&dyn_soft_sync_list,
                      &valid_dyn_soft_sync_list,
                      sizeof(dyn_soft_sync_list)) == 0);
    }
    PCHECK(rdp_dynamic_channel_soft_sync_channel_list_get_id(&dyn_soft_sync_list,
                                                             0,
                                                             &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 7);
    PCHECK(rdp_dynamic_channel_soft_sync_channel_list_get_id(&dyn_soft_sync_list,
                                                             1,
                                                             &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 0x1234u);
    PCHECK(rdp_dynamic_channel_parse_soft_sync_request(dyn_soft_sync_empty_request,
                                                       sizeof(dyn_soft_sync_empty_request),
                                                       &dyn_soft_sync) == LIBRDP_STATUS_OK);
    PCHECK(dyn_soft_sync.length == 8 &&
           dyn_soft_sync.flags == RDP_DYNAMIC_CHANNEL_SOFT_SYNC_TCP_FLUSHED &&
           dyn_soft_sync.tunnel_count == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_soft_sync_response(&dyn_response, NULL, 0) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 6 &&
           dyn_response.data[0] == (uint8_t)(RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_RESPONSE << 4) &&
           test_read_u32_le(dyn_response.data + 2) == 0);
    PCHECK(rdp_dynamic_channel_parse_soft_sync_response(dyn_response.data,
                                                        dyn_response.length,
                                                        &dyn_soft_sync_response) == LIBRDP_STATUS_OK);
    PCHECK(dyn_soft_sync_response.tunnel_count == 0);
    dyn_response.length = 0;
    error_info = RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY;
    PCHECK(rdp_dynamic_channel_write_soft_sync_response(&dyn_response, &error_info, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_dynamic_channel_parse_soft_sync_response(dyn_response.data,
                                                        dyn_response.length,
                                                        &dyn_soft_sync_response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_dynamic_channel_soft_sync_response_get_tunnel(&dyn_soft_sync_response,
                                                             0,
                                                             &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY);
    {
        uint32_t valid_error_info = error_info;
        rdp_dynamic_channel_soft_sync_response valid_response = dyn_soft_sync_response;

        dyn_response.data[6] = 0xffu;
        PCHECK(rdp_dynamic_channel_parse_soft_sync_response(dyn_response.data,
                                                            dyn_response.length,
                                                            &dyn_soft_sync_response) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&dyn_soft_sync_response,
                      &valid_response,
                      sizeof(dyn_soft_sync_response)) == 0);
        PCHECK(rdp_dynamic_channel_soft_sync_response_get_tunnel(&dyn_soft_sync_response,
                                                                 0,
                                                                 &error_info) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(error_info == valid_error_info);
        dyn_response.data[6] = RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY;
    }
    {
        uint32_t invalid_tunnel = 0x12345678u;

        dyn_response.length = 0;
        PCHECK(rdp_buffer_append_u8(&dyn_response, 0xa5u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_dynamic_channel_write_soft_sync_response(&dyn_response,
                                                            &invalid_tunnel,
                                                            1) == LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(dyn_response.length == 1u && dyn_response.data[0] == 0xa5u);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_mouse_cursor_write_caps_advertise(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 16 &&
           dyn_response.data[0] == RDP_MOUSE_CURSOR_PDU_CS_CAPS_ADVERTISE &&
           dyn_response.data[1] == 0 &&
           test_read_u16_le(dyn_response.data + 2) == 0 &&
           test_read_u32_le(dyn_response.data + 4) == RDP_MOUSE_CURSOR_CAPSET_SIGNATURE &&
           test_read_u32_le(dyn_response.data + 8) == RDP_MOUSE_CURSOR_CAPSET_VERSION1 &&
           test_read_u32_le(dyn_response.data + 12) == RDP_MOUSE_CURSOR_CAPSET_SIZE_VERSION1);
    PCHECK(rdp_mouse_cursor_parse_header(dyn_response.data,
                                         dyn_response.length,
                                         &mouse_cursor_header) == LIBRDP_STATUS_OK);
    PCHECK(mouse_cursor_header.pdu_type == RDP_MOUSE_CURSOR_PDU_CS_CAPS_ADVERTISE &&
           mouse_cursor_header.update_type == 0);
    PCHECK(rdp_mouse_cursor_parse_caps_confirm(mouse_cursor_caps_confirm,
                                               sizeof(mouse_cursor_caps_confirm),
                                               &mouse_cursor_capset) == LIBRDP_STATUS_OK);
    PCHECK(mouse_cursor_capset.signature == RDP_MOUSE_CURSOR_CAPSET_SIGNATURE &&
           mouse_cursor_capset.version == RDP_MOUSE_CURSOR_CAPSET_VERSION1 &&
           mouse_cursor_capset.size == RDP_MOUSE_CURSOR_CAPSET_SIZE_VERSION1);
    {
        rdp_mouse_cursor_capset valid_mouse_cursor_capset = mouse_cursor_capset;

        PCHECK(rdp_mouse_cursor_parse_caps_confirm(mouse_cursor_caps_confirm,
                                                   sizeof(mouse_cursor_caps_confirm) - 1u,
                                                   &mouse_cursor_capset) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&mouse_cursor_capset,
                      &valid_mouse_cursor_capset,
                      sizeof(mouse_cursor_capset)) == 0);
    }
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_hidden,
                                         sizeof(mouse_cursor_hidden),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_NULL);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_default,
                                         sizeof(mouse_cursor_default),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_DEFAULT);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_position,
                                         sizeof(mouse_cursor_position),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_POSITION &&
           pointer_update.x == 0x22 && pointer_update.y == 0x33);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_cached,
                                         sizeof(mouse_cursor_cached),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_CACHED && pointer_update.cache_index == 5);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_shape_32,
                                         sizeof(mouse_cursor_shape_32),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.cache_index == 5 &&
           pointer_update.hot_x == 1 &&
           pointer_update.hot_y == 0 &&
           pointer_update.width == 2 &&
           pointer_update.height == 2 &&
           pointer_update.xor_bpp == 32);
    rdp_buffer_free(&decoded_pointer);
    rdp_buffer_init(&decoded_pointer);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 8 && decoded_pointer.length == 16 && decoded_pointer.data[15] == 0x00);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_large_32,
                                         sizeof(mouse_cursor_large_32),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.cache_index == 5 &&
           pointer_update.width == 2 &&
           pointer_update.height == 2 &&
           pointer_update.xor_bpp == 32);
    {
        rdp_pointer_update valid_mouse_cursor_update = pointer_update;

        PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_shape_32,
                                             sizeof(mouse_cursor_shape_32) - 1u,
                                             &pointer_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&pointer_update,
                      &valid_mouse_cursor_update,
                      sizeof(pointer_update)) == 0);
        PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_shape_bad_width,
                                             sizeof(mouse_cursor_shape_bad_width),
                                             &pointer_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&pointer_update,
                      &valid_mouse_cursor_update,
                      sizeof(pointer_update)) == 0);
        PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_shape_bad_hotspot,
                                             sizeof(mouse_cursor_shape_bad_hotspot),
                                             &pointer_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&pointer_update,
                      &valid_mouse_cursor_update,
                      sizeof(pointer_update)) == 0);
        PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_unknown,
                                             sizeof(mouse_cursor_unknown),
                                             &pointer_update) == LIBRDP_STATUS_UNSUPPORTED);
        PCHECK(memcmp(&pointer_update,
                      &valid_mouse_cursor_update,
                      sizeof(pointer_update)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_init_request(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 16 &&
           dyn_response.data[0] == RDP_CORE_INPUT_SIGNATURE &&
           dyn_response.data[1] == RDP_CORE_INPUT_PDU_CS_INIT_REQUEST &&
           test_read_u16_le(dyn_response.data + 4) == RDP_CORE_INPUT_PROTOCOL_VERSION_100 &&
           test_read_u16_le(dyn_response.data + 6) == RDP_CORE_INPUT_PROTOCOL_VERSION_100);
    PCHECK(rdp_core_input_parse_header(dyn_response.data, dyn_response.length, &core_header) == LIBRDP_STATUS_OK);
    PCHECK(core_header.pdu_type == RDP_CORE_INPUT_PDU_CS_INIT_REQUEST && core_header.event_count == 0);
    {
        rdp_core_input_header valid_core_header = core_header;

        dyn_response.data[3] = 1;
        PCHECK(rdp_core_input_parse_header(dyn_response.data, dyn_response.length, &core_header) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&core_header, &valid_core_header, sizeof(core_header)) == 0);
        dyn_response.data[3] = 0;
    }
    PCHECK(rdp_core_input_parse_init_response(core_response,
                                              sizeof(core_response),
                                              &core_init_response) == LIBRDP_STATUS_OK);
    PCHECK(core_init_response.selected_protocol_version == RDP_CORE_INPUT_PROTOCOL_VERSION_100 &&
           core_init_response.protocol_version_max == RDP_CORE_INPUT_PROTOCOL_VERSION_100);
    PCHECK(rdp_core_input_negotiate(&core_init_response, &core_negotiation) == LIBRDP_STATUS_OK);
    PCHECK(core_negotiation.selected_protocol_version == RDP_CORE_INPUT_PROTOCOL_VERSION_100 &&
           core_negotiation.supports_relative_mouse &&
           core_negotiation.supports_qoe_timestamp);
    {
        rdp_core_input_init_response valid_core_init_response = core_init_response;

        PCHECK(rdp_core_input_parse_init_response(core_response,
                                                  sizeof(core_response) - 1u,
                                                  &core_init_response) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&core_init_response,
                      &valid_core_init_response,
                      sizeof(core_init_response)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_keyboard_event(&dyn_response, 0x1e, 0) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 6 &&
           dyn_response.data[1] == RDP_CORE_INPUT_PDU_CS_KEYBOARD_AND_MOUSE &&
           dyn_response.data[2] == 1 &&
           dyn_response.data[4] == 0 &&
           dyn_response.data[5] == 0x1e);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_keyboard_event(&dyn_response, 0x1e, 1) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.data[4] == RDP_CORE_INPUT_KBDFLAGS_RELEASE);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_mouse_event(&dyn_response, 0x8800u, 10, 11) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 11 &&
           dyn_response.data[4] == (uint8_t)(RDP_CORE_INPUT_EVENT_MOUSE << 5) &&
           test_read_u16_le(dyn_response.data + 5) == 0x8800u &&
           test_read_u16_le(dyn_response.data + 7) == 10 &&
           test_read_u16_le(dyn_response.data + 9) == 11);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_event_count == 1 &&
           core_events[0].type == RDP_CORE_INPUT_EVENT_MOUSE &&
           core_events[0].pointer_flags == 0x8800u &&
           core_events[0].x == 10 &&
           core_events[0].y == 11);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_keyboard_event_ex(&dyn_response,
                                                  0x1d,
                                                  RDP_CORE_INPUT_KBDFLAGS_EXTENDED |
                                                  RDP_CORE_INPUT_KBDFLAGS_RELEASE) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_event_count == 1 &&
           core_events[0].type == RDP_CORE_INPUT_EVENT_SCANCODE &&
           core_events[0].flags == (RDP_CORE_INPUT_KBDFLAGS_EXTENDED |
                                    RDP_CORE_INPUT_KBDFLAGS_RELEASE) &&
           core_events[0].scancode == 0x1d);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_unicode_event(&dyn_response, 0x20ac, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_event_count == 1 &&
           core_events[0].type == RDP_CORE_INPUT_EVENT_UNICODE &&
           core_events[0].unicode_code == 0x20ac);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_sync_event(&dyn_response,
                                           RDP_CORE_INPUT_SYNC_NUM_LOCK |
                                           RDP_CORE_INPUT_SYNC_CAPS_LOCK) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_event_count == 1 &&
           core_events[0].type == RDP_CORE_INPUT_EVENT_SYNC &&
           core_events[0].flags == (RDP_CORE_INPUT_SYNC_NUM_LOCK | RDP_CORE_INPUT_SYNC_CAPS_LOCK));
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_extended_mouse_event(&dyn_response, 0x8001u, 12, 13) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_events[0].type == RDP_CORE_INPUT_EVENT_MOUSEX &&
           core_events[0].pointer_flags == 0x8001u &&
           core_events[0].x == 12 &&
           core_events[0].y == 13);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_relative_mouse_event(&dyn_response, 0x0800u, -3, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_events[0].type == RDP_CORE_INPUT_EVENT_RELMOUSE &&
           core_events[0].pointer_flags == 0x0800u &&
           core_events[0].dx == -3 &&
           core_events[0].dy == 4);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    core_events[0].type = RDP_CORE_INPUT_EVENT_SCANCODE;
    core_events[0].flags = 0;
    core_events[0].scancode = 0x1e;
    core_events[1].type = RDP_CORE_INPUT_EVENT_QOE_TIMESTAMP;
    core_events[1].flags = 0;
    core_events[1].timestamp = 0x12345678u;
    PCHECK(rdp_core_input_write_events(&dyn_response, core_events, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_event_count == 2 &&
           core_events[0].scancode == 0x1e &&
           core_events[1].type == RDP_CORE_INPUT_EVENT_QOE_TIMESTAMP &&
           core_events[1].timestamp == 0x12345678u);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_buffer_append_u8(&dyn_response, 0xa5u) == LIBRDP_STATUS_OK);
    core_events[0].type = RDP_CORE_INPUT_EVENT_SCANCODE;
    core_events[0].flags = 0;
    core_events[0].scancode = 0x1e;
    core_events[1].type = RDP_CORE_INPUT_EVENT_QOE_TIMESTAMP;
    core_events[1].flags = 1;
    core_events[1].timestamp = 0x12345678u;
    PCHECK(rdp_core_input_write_events(&dyn_response,
                                       core_events,
                                       2) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(dyn_response.length == 1 && dyn_response.data[0] == 0xa5u);
    {
        const uint8_t invalid_second_event[] = {
            RDP_CORE_INPUT_SIGNATURE,
            RDP_CORE_INPUT_PDU_CS_KEYBOARD_AND_MOUSE,
            2,
            0,
            0,
            0x1e,
            (uint8_t)((RDP_CORE_INPUT_EVENT_QOE_TIMESTAMP << 5) | 1u),
            0x78,
            0x56,
            0x34,
            0x12
        };

        memset(core_events, 0x5a, sizeof(core_events));
        core_event_count = 77;
        PCHECK(rdp_core_input_parse_events(invalid_second_event,
                                           sizeof(invalid_second_event),
                                           core_events,
                                           8,
                                           &core_event_count) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(core_event_count == 77 && core_events[0].type == 0x5a && core_events[0].scancode == 0x5a);
    }
    PCHECK(rdp_input_channel_parse_header(input_sc_ready_v300,
                                          sizeof(input_sc_ready_v300),
                                          &input_header) == LIBRDP_STATUS_OK);
    PCHECK(input_header.event_id == RDP_INPUT_CHANNEL_EVENT_SC_READY &&
           input_header.pdu_length == sizeof(input_sc_ready_v300));
    {
        rdp_input_channel_header valid_input_header = input_header;

        PCHECK(rdp_input_channel_parse_header(input_sc_ready_v300,
                                              sizeof(input_sc_ready_v300) - 1u,
                                              &input_header) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&input_header, &valid_input_header, sizeof(input_header)) == 0);
    }
    PCHECK(rdp_input_channel_write_header(&dyn_response, 0xffffu, 6) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_input_channel_parse_sc_ready(input_sc_ready_v300,
                                            sizeof(input_sc_ready_v300),
                                            &input_sc_ready) == LIBRDP_STATUS_OK);
    PCHECK(input_sc_ready.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V300 &&
           input_sc_ready.has_supported_features &&
           input_sc_ready.supported_features == RDP_INPUT_CHANNEL_SC_READY_MULTIPEN);
    {
        rdp_input_channel_sc_ready valid_input_sc_ready = input_sc_ready;

        PCHECK(rdp_input_channel_parse_sc_ready(input_sc_ready_v300,
                                                sizeof(input_sc_ready_v300) - 1u,
                                                &input_sc_ready) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&input_sc_ready, &valid_input_sc_ready, sizeof(input_sc_ready)) == 0);
    }
    PCHECK(rdp_input_channel_negotiate_client_ready(&input_sc_ready,
                                                    10,
                                                    0,
                                                    &input_negotiation) == LIBRDP_STATUS_OK);
    PCHECK(input_negotiation.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V300 &&
           input_negotiation.supports_touch &&
           input_negotiation.supports_pen &&
           input_negotiation.disables_timestamp_injection &&
           input_negotiation.max_touch_contacts == 10);
    PCHECK(rdp_input_channel_parse_sc_ready(input_sc_ready_v300_no_pen,
                                            sizeof(input_sc_ready_v300_no_pen),
                                            &input_sc_ready) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_negotiate_client_ready(&input_sc_ready,
                                                    10,
                                                    0,
                                                    &input_negotiation) == LIBRDP_STATUS_OK);
    PCHECK(input_negotiation.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V300 &&
           input_negotiation.supports_touch &&
           !input_negotiation.supports_pen &&
           (input_negotiation.flags & RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN) == 0);
    PCHECK(rdp_input_channel_parse_sc_ready(input_sc_ready_v200,
                                            sizeof(input_sc_ready_v200),
                                            &input_sc_ready) == LIBRDP_STATUS_OK);
    PCHECK(input_sc_ready.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V200 &&
           !input_sc_ready.has_supported_features);
    PCHECK(rdp_input_channel_negotiate_client_ready(&input_sc_ready,
                                                    10,
                                                    0,
                                                    &input_negotiation) == LIBRDP_STATUS_OK);
    PCHECK(input_negotiation.supports_touch &&
           !input_negotiation.supports_pen &&
           (input_negotiation.flags & RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN) == 0);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_input_channel_write_sc_ready(&dyn_response,
                                            RDP_INPUT_CHANNEL_PROTOCOL_V300,
                                            RDP_INPUT_CHANNEL_SC_READY_MULTIPEN,
                                            1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_sc_ready(dyn_response.data,
                                            dyn_response.length,
                                            &input_sc_ready) == LIBRDP_STATUS_OK);
    PCHECK(input_sc_ready.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V300 &&
           input_sc_ready.has_supported_features &&
           input_sc_ready.supported_features == RDP_INPUT_CHANNEL_SC_READY_MULTIPEN);
    PCHECK(rdp_input_channel_write_sc_ready(&dyn_response,
                                            RDP_INPUT_CHANNEL_PROTOCOL_V300,
                                            0,
                                            0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_input_channel_write_cs_ready(&dyn_response,
                                            RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION |
                                            RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN,
                                            RDP_INPUT_CHANNEL_PROTOCOL_V300,
                                            10) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 16 &&
           test_read_u16_le(dyn_response.data) == RDP_INPUT_CHANNEL_EVENT_CS_READY &&
           test_read_u32_le(dyn_response.data + 2) == 16 &&
           test_read_u32_le(dyn_response.data + 6) ==
               (RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION | RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN));
    PCHECK(rdp_input_channel_parse_cs_ready(dyn_response.data,
                                            dyn_response.length,
                                            &input_cs_ready) == LIBRDP_STATUS_OK);
    PCHECK(input_cs_ready.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V300 &&
           input_cs_ready.max_touch_contacts == 10);
    valid_input_cs_ready = input_cs_ready;
    PCHECK(rdp_input_channel_write_cs_ready(&dyn_response,
                                            RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN,
                                            RDP_INPUT_CHANNEL_PROTOCOL_V101,
                                            1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    dyn_response.length = 0;
    PCHECK(rdp_input_channel_write_header(&dyn_response, RDP_INPUT_CHANNEL_EVENT_CS_READY, 16) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&dyn_response,
                                    RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&dyn_response, RDP_INPUT_CHANNEL_PROTOCOL_V100) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&dyn_response, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_cs_ready(dyn_response.data,
                                            dyn_response.length,
                                            &input_cs_ready) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(memcmp(&input_cs_ready, &valid_input_cs_ready, sizeof(input_cs_ready)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_input_channel_write_header(&dyn_response, RDP_INPUT_CHANNEL_EVENT_CS_READY, 16) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&dyn_response, RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&dyn_response, RDP_INPUT_CHANNEL_PROTOCOL_V101) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&dyn_response, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_cs_ready(dyn_response.data,
                                            dyn_response.length,
                                            &input_cs_ready) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(memcmp(&input_cs_ready, &valid_input_cs_ready, sizeof(input_cs_ready)) == 0);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_input_channel_write_suspend(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_empty(dyn_response.data,
                                         dyn_response.length,
                                         RDP_INPUT_CHANNEL_EVENT_SUSPEND_INPUT) == LIBRDP_STATUS_OK);
    dyn_response.length = 0;
    PCHECK(rdp_input_channel_write_resume(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_empty(dyn_response.data,
                                         dyn_response.length,
                                         RDP_INPUT_CHANNEL_EVENT_RESUME_INPUT) == LIBRDP_STATUS_OK);
    dyn_response.length = 0;
    PCHECK(rdp_input_channel_write_dismiss_hovering(&dyn_response, 9) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_dismiss_hovering(dyn_response.data,
                                                    dyn_response.length,
                                                    &input_contact_id) == LIBRDP_STATUS_OK);
    PCHECK(input_contact_id == 9);
    PCHECK(rdp_input_channel_parse_dismiss_hovering(dyn_response.data,
                                                    dyn_response.length - 1u,
                                                    &input_contact_id) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(input_contact_id == 9);
    dyn_response.length = 0;
    memset(&input_touch_contact, 0, sizeof(input_touch_contact));
    input_touch_contact.contact_id = 1;
    input_touch_contact.fields_present = RDP_INPUT_CHANNEL_TOUCH_CONTACTRECT_PRESENT |
                                         RDP_INPUT_CHANNEL_TOUCH_ORIENTATION_PRESENT |
                                         RDP_INPUT_CHANNEL_TOUCH_PRESSURE_PRESENT;
    input_touch_contact.x = 100;
    input_touch_contact.y = 200;
    input_touch_contact.contact_flags = RDP_INPUT_CHANNEL_CONTACT_DOWN |
                                        RDP_INPUT_CHANNEL_CONTACT_INRANGE |
                                        RDP_INPUT_CHANNEL_CONTACT_INCONTACT;
    input_touch_contact.contact_rect_left = -2;
    input_touch_contact.contact_rect_top = -3;
    input_touch_contact.contact_rect_right = 2;
    input_touch_contact.contact_rect_bottom = 3;
    input_touch_contact.orientation = 90;
    input_touch_contact.pressure = 512;
    PCHECK(rdp_input_channel_validate_touch_contact(&input_touch_contact) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_write_touch_contact(&dyn_response, &input_touch_contact) == LIBRDP_STATUS_OK);
    {
        rdp_input_channel_touch_contact touch_contacts[2];

        touch_contacts[0] = input_touch_contact;
        touch_contacts[1] = input_touch_contact;
        channel_packet.length = 0;
        PCHECK(rdp_buffer_append_u8(&channel_packet, 0xa5u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_input_channel_write_touch_frame(&channel_packet,
                                                   0x0102030405060708ull,
                                                   touch_contacts,
                                                   2) == LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(channel_packet.length == 1 && channel_packet.data[0] == 0xa5u);
        touch_contacts[1].contact_id = 2;
        touch_contacts[1].pressure = 1025;
        PCHECK(rdp_input_channel_write_touch_frame(&channel_packet,
                                                   0x0102030405060708ull,
                                                   touch_contacts,
                                                   2) == LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(channel_packet.length == 1 && channel_packet.data[0] == 0xa5u);
    }
    memset(&input_touch_frame, 0, sizeof(input_touch_frame));
    input_touch_frame.contact_count = 1;
    input_touch_frame.frame_offset = 0x0102030405060708ull;
    input_touch_frame.contacts = dyn_response.data;
    input_touch_frame.contacts_len = dyn_response.length;
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_touch_event(&channel_packet, 0x11223344u, &input_touch_frame, 1) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_touch_event(channel_packet.data,
                                               channel_packet.length,
                                               &input_touch_event) == LIBRDP_STATUS_OK);
    PCHECK(input_touch_event.encode_time == 0x11223344u && input_touch_event.frame_count == 1);
    PCHECK(rdp_input_channel_touch_event_get_frame(&input_touch_event,
                                                   0,
                                                   &input_touch_frame) == LIBRDP_STATUS_OK);
    PCHECK(input_touch_frame.contact_count == 1 &&
           input_touch_frame.frame_offset == 0x0102030405060708ull);
    {
        rdp_input_channel_touch_event invalid_touch_event = input_touch_event;
        rdp_input_channel_touch_frame valid_touch_frame = input_touch_frame;

        invalid_touch_event.frames_len--;
        PCHECK(rdp_input_channel_touch_event_get_frame(&invalid_touch_event,
                                                       0,
                                                       &input_touch_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&input_touch_frame, &valid_touch_frame, sizeof(input_touch_frame)) == 0);
    }
    PCHECK(rdp_input_channel_touch_frame_get_contact(&input_touch_frame,
                                                     0,
                                                     &input_touch_contact) == LIBRDP_STATUS_OK);
    PCHECK(input_touch_contact.contact_id == 1 &&
           input_touch_contact.x == 100 &&
           input_touch_contact.y == 200 &&
           input_touch_contact.contact_rect_top == -3 &&
           input_touch_contact.orientation == 90 &&
           input_touch_contact.pressure == 512);
    {
        rdp_input_channel_touch_frame invalid_touch_frame = input_touch_frame;
        rdp_input_channel_touch_contact valid_touch_contact = input_touch_contact;

        invalid_touch_frame.contacts_len--;
        PCHECK(rdp_input_channel_touch_frame_get_contact(&invalid_touch_frame,
                                                         0,
                                                         &input_touch_contact) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&input_touch_contact,
                      &valid_touch_contact,
                      sizeof(input_touch_contact)) == 0);
    }
    {
        rdp_buffer second_contact;
        rdp_input_channel_touch_frame frames[2];

        rdp_buffer_init(&second_contact);
        input_touch_contact.contact_id = 2;
        input_touch_contact.x = 300;
        input_touch_contact.y = 400;
        input_touch_contact.contact_flags = RDP_INPUT_CHANNEL_CONTACT_UPDATE |
                                            RDP_INPUT_CHANNEL_CONTACT_INRANGE |
                                            RDP_INPUT_CHANNEL_CONTACT_INCONTACT;
        input_touch_contact.orientation = 180;
        input_touch_contact.pressure = 900;
        PCHECK(rdp_input_channel_write_touch_contact(&second_contact, &input_touch_contact) ==
               LIBRDP_STATUS_OK);
        memset(frames, 0, sizeof(frames));
        frames[0].contact_count = 1;
        frames[0].frame_offset = 0x0102030405060708ull;
        frames[0].contacts = dyn_response.data;
        frames[0].contacts_len = dyn_response.length;
        frames[1].contact_count = 1;
        frames[1].frame_offset = 0x1112131415161718ull;
        frames[1].contacts = second_contact.data;
        frames[1].contacts_len = second_contact.length;
        channel_packet.length = 0;
        PCHECK(rdp_input_channel_write_touch_event(&channel_packet, 0x11223344u, frames, 2) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_input_channel_parse_touch_event(channel_packet.data,
                                                   channel_packet.length,
                                                   &input_touch_event) == LIBRDP_STATUS_OK);
        PCHECK(input_touch_event.frame_count == 2);
        PCHECK(rdp_input_channel_touch_event_get_frame(&input_touch_event,
                                                       1,
                                                       &input_touch_frame) == LIBRDP_STATUS_OK);
        PCHECK(input_touch_frame.contact_count == 1 &&
               input_touch_frame.frame_offset == 0x1112131415161718ull);
        PCHECK(rdp_input_channel_touch_frame_get_contact(&input_touch_frame,
                                                         0,
                                                         &input_touch_contact) == LIBRDP_STATUS_OK);
        PCHECK(input_touch_contact.contact_id == 2 &&
               input_touch_contact.x == 300 &&
               input_touch_contact.y == 400 &&
               input_touch_contact.orientation == 180 &&
               input_touch_contact.pressure == 900);
        valid_input_touch_event = input_touch_event;
        rdp_buffer_free(&second_contact);
    }
    input_touch_contact.contact_id = 1;
    input_touch_contact.x = 100;
    input_touch_contact.y = 200;
    input_touch_contact.contact_flags = RDP_INPUT_CHANNEL_CONTACT_DOWN |
                                        RDP_INPUT_CHANNEL_CONTACT_INRANGE |
                                        RDP_INPUT_CHANNEL_CONTACT_INCONTACT;
    input_touch_contact.orientation = 90;
    input_touch_contact.pressure = 512;
    {
        rdp_buffer duplicate_contacts;

        rdp_buffer_init(&duplicate_contacts);
        PCHECK(rdp_buffer_append(&duplicate_contacts,
                                 dyn_response.data,
                                 dyn_response.length) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append(&duplicate_contacts,
                                 dyn_response.data,
                                 dyn_response.length) == LIBRDP_STATUS_OK);
        channel_packet.length = 0;
        PCHECK(rdp_input_channel_write_header(&channel_packet,
                                              RDP_INPUT_CHANNEL_EVENT_TOUCH,
                                              (uint32_t)(6u + 4u + 2u + 2u + 8u +
                                                         duplicate_contacts.length)) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0x11223344u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u16_le(&channel_packet, 1) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u16_le(&channel_packet, 2) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0x05060708u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0x01020304u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append(&channel_packet,
                                 duplicate_contacts.data,
                                 duplicate_contacts.length) == LIBRDP_STATUS_OK);
        PCHECK(rdp_input_channel_parse_touch_event(channel_packet.data,
                                                   channel_packet.length,
                                                   &input_touch_event) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&input_touch_event,
                      &valid_input_touch_event,
                      sizeof(input_touch_event)) == 0);
        input_touch_frame.contact_count = 2;
        input_touch_frame.contacts = duplicate_contacts.data;
        input_touch_frame.contacts_len = duplicate_contacts.length;
        channel_packet.length = 0;
        PCHECK(rdp_buffer_append_u8(&channel_packet, 0xa5u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_input_channel_write_touch_event(&channel_packet, 0, &input_touch_frame, 1) ==
               LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(channel_packet.length == 1 && channel_packet.data[0] == 0xa5u);
        rdp_buffer_free(&duplicate_contacts);
    }
    input_touch_frame.contact_count = 2;
    input_touch_frame.contacts = dyn_response.data;
    input_touch_frame.contacts_len = dyn_response.length;
    channel_packet.length = 0;
    PCHECK(rdp_buffer_append_u8(&channel_packet, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_write_touch_event(&channel_packet, 0, &input_touch_frame, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(channel_packet.length == 1 && channel_packet.data[0] == 0xa5u);
    input_touch_frame.contact_count = 1;
    input_touch_frame.contacts = dyn_response.data;
    input_touch_frame.contacts_len = dyn_response.length;
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_touch_event(&channel_packet, 0x11223344u, &input_touch_frame, 1) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&channel_packet, 0xaa) == LIBRDP_STATUS_OK);
    channel_packet.data[2] = (uint8_t)(channel_packet.length & 0xffu);
    channel_packet.data[3] = (uint8_t)((channel_packet.length >> 8) & 0xffu);
    channel_packet.data[4] = (uint8_t)((channel_packet.length >> 16) & 0xffu);
    channel_packet.data[5] = (uint8_t)((channel_packet.length >> 24) & 0xffu);
    PCHECK(rdp_input_channel_parse_touch_event(channel_packet.data,
                                               channel_packet.length,
                                               &input_touch_event) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(memcmp(&input_touch_event,
                  &valid_input_touch_event,
                  sizeof(input_touch_event)) == 0);
    PCHECK(rdp_input_channel_write_touch_event(&channel_packet, 0, NULL, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    memset(&input_touch_frame, 0, sizeof(input_touch_frame));
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_touch_event(&channel_packet, 0, &input_touch_frame, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_header(&channel_packet, RDP_INPUT_CHANNEL_EVENT_TOUCH, 22) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&channel_packet, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_touch_event(channel_packet.data,
                                               channel_packet.length,
                                               &input_touch_event) == LIBRDP_STATUS_PROTOCOL_ERROR);
    input_touch_contact.contact_rect_left = 5;
    input_touch_contact.contact_rect_right = 2;
    PCHECK(rdp_input_channel_write_touch_contact(&dyn_response, &input_touch_contact) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    input_touch_contact.contact_rect_left = -2;
    input_touch_contact.contact_rect_right = 2;
    input_touch_contact.pressure = 1025;
    PCHECK(rdp_input_channel_write_touch_contact(&dyn_response, &input_touch_contact) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    input_touch_contact.pressure = 512;
    input_touch_contact.contact_flags = RDP_INPUT_CHANNEL_CONTACT_DOWN;
    PCHECK(rdp_input_channel_write_touch_contact(&dyn_response, &input_touch_contact) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    dyn_response.length = 0;
    memset(&input_pen_contact, 0, sizeof(input_pen_contact));
    input_pen_contact.device_id = 2;
    input_pen_contact.fields_present = RDP_INPUT_CHANNEL_PEN_FLAGS_PRESENT |
                                       RDP_INPUT_CHANNEL_PEN_PRESSURE_PRESENT |
                                       RDP_INPUT_CHANNEL_PEN_ROTATION_PRESENT |
                                       RDP_INPUT_CHANNEL_PEN_TILTX_PRESENT |
                                       RDP_INPUT_CHANNEL_PEN_TILTY_PRESENT;
    input_pen_contact.x = -20;
    input_pen_contact.y = 30;
    input_pen_contact.contact_flags = RDP_INPUT_CHANNEL_CONTACT_UPDATE |
                                      RDP_INPUT_CHANNEL_CONTACT_INRANGE |
                                      RDP_INPUT_CHANNEL_CONTACT_INCONTACT;
    input_pen_contact.pen_flags = RDP_INPUT_CHANNEL_PEN_BARREL_PRESSED;
    input_pen_contact.pressure = 700;
    input_pen_contact.rotation = 45;
    input_pen_contact.tilt_x = -10;
    input_pen_contact.tilt_y = 20;
    PCHECK(rdp_input_channel_validate_pen_contact(&input_pen_contact) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_write_pen_contact(&dyn_response, &input_pen_contact) == LIBRDP_STATUS_OK);
    {
        rdp_input_channel_pen_contact pen_contacts[2];

        pen_contacts[0] = input_pen_contact;
        pen_contacts[1] = input_pen_contact;
        channel_packet.length = 0;
        PCHECK(rdp_buffer_append_u8(&channel_packet, 0xa5u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_input_channel_write_pen_frame(&channel_packet,
                                                 7,
                                                 pen_contacts,
                                                 2) == LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(channel_packet.length == 1 && channel_packet.data[0] == 0xa5u);
        pen_contacts[1].device_id = 3;
        pen_contacts[1].rotation = 360;
        PCHECK(rdp_input_channel_write_pen_frame(&channel_packet,
                                                 7,
                                                 pen_contacts,
                                                 2) == LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(channel_packet.length == 1 && channel_packet.data[0] == 0xa5u);
    }
    memset(&input_pen_frame, 0, sizeof(input_pen_frame));
    input_pen_frame.contact_count = 1;
    input_pen_frame.frame_offset = 7;
    input_pen_frame.contacts = dyn_response.data;
    input_pen_frame.contacts_len = dyn_response.length;
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_pen_event(&channel_packet, 0x55667788u, &input_pen_frame, 1) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_pen_event(channel_packet.data,
                                             channel_packet.length,
                                             &input_pen_event) == LIBRDP_STATUS_OK);
    PCHECK(input_pen_event.encode_time == 0x55667788u && input_pen_event.frame_count == 1);
    PCHECK(rdp_input_channel_pen_event_get_frame(&input_pen_event,
                                                 0,
                                                 &input_pen_frame) == LIBRDP_STATUS_OK);
    PCHECK(input_pen_frame.contact_count == 1 && input_pen_frame.frame_offset == 7);
    {
        rdp_input_channel_pen_event invalid_pen_event = input_pen_event;
        rdp_input_channel_pen_frame valid_pen_frame = input_pen_frame;

        invalid_pen_event.frames_len--;
        PCHECK(rdp_input_channel_pen_event_get_frame(&invalid_pen_event,
                                                     0,
                                                     &input_pen_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&input_pen_frame, &valid_pen_frame, sizeof(input_pen_frame)) == 0);
    }
    PCHECK(rdp_input_channel_pen_frame_get_contact(&input_pen_frame,
                                                   0,
                                                   &input_pen_contact) == LIBRDP_STATUS_OK);
    PCHECK(input_pen_contact.device_id == 2 &&
           input_pen_contact.x == -20 &&
           input_pen_contact.pen_flags == RDP_INPUT_CHANNEL_PEN_BARREL_PRESSED &&
           input_pen_contact.pressure == 700 &&
           input_pen_contact.rotation == 45 &&
           input_pen_contact.tilt_x == -10 &&
           input_pen_contact.tilt_y == 20);
    {
        rdp_input_channel_pen_frame invalid_pen_frame = input_pen_frame;
        rdp_input_channel_pen_contact valid_pen_contact = input_pen_contact;

        invalid_pen_frame.contacts_len--;
        PCHECK(rdp_input_channel_pen_frame_get_contact(&invalid_pen_frame,
                                                       0,
                                                       &input_pen_contact) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&input_pen_contact,
                      &valid_pen_contact,
                      sizeof(input_pen_contact)) == 0);
    }
    {
        rdp_buffer second_contact;
        rdp_input_channel_pen_frame frames[2];

        rdp_buffer_init(&second_contact);
        input_pen_contact.device_id = 3;
        input_pen_contact.x = 40;
        input_pen_contact.y = 50;
        input_pen_contact.pen_flags = RDP_INPUT_CHANNEL_PEN_ERASER_PRESSED;
        input_pen_contact.pressure = 300;
        input_pen_contact.rotation = 270;
        input_pen_contact.tilt_x = 15;
        input_pen_contact.tilt_y = -25;
        PCHECK(rdp_input_channel_write_pen_contact(&second_contact, &input_pen_contact) ==
               LIBRDP_STATUS_OK);
        memset(frames, 0, sizeof(frames));
        frames[0].contact_count = 1;
        frames[0].frame_offset = 7;
        frames[0].contacts = dyn_response.data;
        frames[0].contacts_len = dyn_response.length;
        frames[1].contact_count = 1;
        frames[1].frame_offset = 11;
        frames[1].contacts = second_contact.data;
        frames[1].contacts_len = second_contact.length;
        channel_packet.length = 0;
        PCHECK(rdp_input_channel_write_pen_event(&channel_packet, 0x55667788u, frames, 2) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_input_channel_parse_pen_event(channel_packet.data,
                                                 channel_packet.length,
                                                 &input_pen_event) == LIBRDP_STATUS_OK);
        PCHECK(input_pen_event.frame_count == 2);
        PCHECK(rdp_input_channel_pen_event_get_frame(&input_pen_event,
                                                     1,
                                                     &input_pen_frame) == LIBRDP_STATUS_OK);
        PCHECK(input_pen_frame.contact_count == 1 && input_pen_frame.frame_offset == 11);
        PCHECK(rdp_input_channel_pen_frame_get_contact(&input_pen_frame,
                                                       0,
                                                       &input_pen_contact) == LIBRDP_STATUS_OK);
        PCHECK(input_pen_contact.device_id == 3 &&
               input_pen_contact.x == 40 &&
               input_pen_contact.y == 50 &&
               input_pen_contact.pen_flags == RDP_INPUT_CHANNEL_PEN_ERASER_PRESSED &&
               input_pen_contact.pressure == 300 &&
               input_pen_contact.rotation == 270 &&
               input_pen_contact.tilt_x == 15 &&
               input_pen_contact.tilt_y == -25);
        valid_input_pen_event = input_pen_event;
        rdp_buffer_free(&second_contact);
    }
    input_pen_contact.device_id = 2;
    input_pen_contact.x = -20;
    input_pen_contact.y = 30;
    input_pen_contact.pen_flags = RDP_INPUT_CHANNEL_PEN_BARREL_PRESSED;
    input_pen_contact.pressure = 700;
    input_pen_contact.rotation = 45;
    input_pen_contact.tilt_x = -10;
    input_pen_contact.tilt_y = 20;
    {
        rdp_buffer duplicate_contacts;

        rdp_buffer_init(&duplicate_contacts);
        PCHECK(rdp_buffer_append(&duplicate_contacts,
                                 dyn_response.data,
                                 dyn_response.length) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append(&duplicate_contacts,
                                 dyn_response.data,
                                 dyn_response.length) == LIBRDP_STATUS_OK);
        channel_packet.length = 0;
        PCHECK(rdp_input_channel_write_header(&channel_packet,
                                              RDP_INPUT_CHANNEL_EVENT_PEN,
                                              (uint32_t)(6u + 4u + 2u + 2u + 8u +
                                                         duplicate_contacts.length)) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0x55667788u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u16_le(&channel_packet, 1) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u16_le(&channel_packet, 2) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u32_le(&channel_packet, 7) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append(&channel_packet,
                                 duplicate_contacts.data,
                                 duplicate_contacts.length) == LIBRDP_STATUS_OK);
        PCHECK(rdp_input_channel_parse_pen_event(channel_packet.data,
                                                 channel_packet.length,
                                                 &input_pen_event) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&input_pen_event,
                      &valid_input_pen_event,
                      sizeof(input_pen_event)) == 0);
        input_pen_frame.contact_count = 2;
        input_pen_frame.contacts = duplicate_contacts.data;
        input_pen_frame.contacts_len = duplicate_contacts.length;
        channel_packet.length = 0;
        PCHECK(rdp_buffer_append_u8(&channel_packet, 0xa5u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_input_channel_write_pen_event(&channel_packet, 0, &input_pen_frame, 1) ==
               LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(channel_packet.length == 1 && channel_packet.data[0] == 0xa5u);
        rdp_buffer_free(&duplicate_contacts);
    }
    input_pen_frame.contact_count = 2;
    input_pen_frame.contacts = dyn_response.data;
    input_pen_frame.contacts_len = dyn_response.length;
    channel_packet.length = 0;
    PCHECK(rdp_buffer_append_u8(&channel_packet, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_write_pen_event(&channel_packet, 0, &input_pen_frame, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(channel_packet.length == 1 && channel_packet.data[0] == 0xa5u);
    input_pen_frame.contact_count = 1;
    input_pen_frame.contacts = dyn_response.data;
    input_pen_frame.contacts_len = dyn_response.length;
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_pen_event(&channel_packet, 0x55667788u, &input_pen_frame, 1) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&channel_packet, 0xbb) == LIBRDP_STATUS_OK);
    channel_packet.data[2] = (uint8_t)(channel_packet.length & 0xffu);
    channel_packet.data[3] = (uint8_t)((channel_packet.length >> 8) & 0xffu);
    channel_packet.data[4] = (uint8_t)((channel_packet.length >> 16) & 0xffu);
    channel_packet.data[5] = (uint8_t)((channel_packet.length >> 24) & 0xffu);
    PCHECK(rdp_input_channel_parse_pen_event(channel_packet.data,
                                             channel_packet.length,
                                             &input_pen_event) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(memcmp(&input_pen_event,
                  &valid_input_pen_event,
                  sizeof(input_pen_event)) == 0);
    PCHECK(rdp_input_channel_write_pen_event(&channel_packet, 0, NULL, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    memset(&input_pen_frame, 0, sizeof(input_pen_frame));
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_pen_event(&channel_packet, 0, &input_pen_frame, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_header(&channel_packet, RDP_INPUT_CHANNEL_EVENT_PEN, 22) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&channel_packet, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&channel_packet, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_pen_event(channel_packet.data,
                                             channel_packet.length,
                                             &input_pen_event) == LIBRDP_STATUS_PROTOCOL_ERROR);
    input_pen_contact.tilt_y = 91;
    PCHECK(rdp_input_channel_write_pen_contact(&dyn_response, &input_pen_contact) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_display_control_parse_caps(display_caps,
                                          sizeof(display_caps),
                                          &display_parsed_caps) == LIBRDP_STATUS_OK);
    PCHECK(display_parsed_caps.max_num_monitors == 16 &&
           display_parsed_caps.max_monitor_area_factor_a == 8192 &&
           display_parsed_caps.max_monitor_area_factor_b == 8192);
    {
        rdp_display_control_caps valid_caps = display_parsed_caps;

        memcpy(display_bad_caps, display_caps, sizeof(display_bad_caps));
        display_bad_caps[8] = 0;
        PCHECK(rdp_display_control_parse_caps(display_bad_caps,
                                              sizeof(display_bad_caps),
                                              &display_parsed_caps) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&display_parsed_caps, &valid_caps, sizeof(display_parsed_caps)) == 0);
        memcpy(display_bad_caps, display_caps, sizeof(display_bad_caps));
        display_bad_caps[8] = 17;
        PCHECK(rdp_display_control_parse_caps(display_bad_caps,
                                              sizeof(display_bad_caps),
                                              &display_parsed_caps) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&display_parsed_caps, &valid_caps, sizeof(display_parsed_caps)) == 0);
        memcpy(display_bad_caps, display_caps, sizeof(display_bad_caps));
        display_bad_caps[12] = 0;
        display_bad_caps[13] = 0;
        PCHECK(rdp_display_control_parse_caps(display_bad_caps,
                                              sizeof(display_bad_caps),
                                              &display_parsed_caps) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&display_parsed_caps, &valid_caps, sizeof(display_parsed_caps)) == 0);
        PCHECK(rdp_display_control_parse_caps(display_caps,
                                              sizeof(display_caps) - 1u,
                                              &display_parsed_caps) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&display_parsed_caps, &valid_caps, sizeof(display_parsed_caps)) == 0);
    }
    PCHECK(rdp_display_control_parse_caps(display_caps,
                                          sizeof(display_caps),
                                          &display_parsed_caps) == LIBRDP_STATUS_OK);
    PCHECK(rdp_display_control_make_single_monitor(&display_monitor, 801, 199) == LIBRDP_STATUS_OK);
    PCHECK(display_monitor.flags == RDP_DISPLAY_CONTROL_MONITOR_PRIMARY &&
           display_monitor.width == 800 &&
           display_monitor.height == 200 &&
           display_monitor.desktop_scale_factor == 100);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, &display_monitor, 1) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 56 &&
           test_read_u32_le(dyn_response.data) == RDP_DISPLAY_CONTROL_PDU_MONITOR_LAYOUT &&
           test_read_u32_le(dyn_response.data + 4) == 56 &&
           test_read_u32_le(dyn_response.data + 8) == RDP_DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE &&
           test_read_u32_le(dyn_response.data + 12) == 1 &&
           test_read_u32_le(dyn_response.data + 16) == RDP_DISPLAY_CONTROL_MONITOR_PRIMARY &&
           test_read_u32_le(dyn_response.data + 28) == 800 &&
           test_read_u32_le(dyn_response.data + 32) == 200);
    PCHECK(rdp_display_control_parse_monitor_layout(dyn_response.data,
                                                    dyn_response.length,
                                                    display_monitors,
                                                    2,
                                                    &display_monitor_count) == LIBRDP_STATUS_OK);
    PCHECK(display_monitor_count == 1 &&
           display_monitors[0].flags == RDP_DISPLAY_CONTROL_MONITOR_PRIMARY &&
           display_monitors[0].width == 800 &&
           display_monitors[0].height == 200);
    memset(display_monitors, 0xa5, sizeof(display_monitors));
    display_monitor_count = 99;
    PCHECK(rdp_display_control_parse_monitor_layout(dyn_response.data,
                                                    dyn_response.length,
                                                    display_monitors,
                                                    LIBRDP_DISPLAY_MAX_MONITORS + 1u,
                                                    &display_monitor_count) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(display_monitor_count == 99 &&
           display_monitors[0].flags == 0xa5a5a5a5u &&
           display_monitors[1].flags == 0xa5a5a5a5u);
    PCHECK(dyn_response.length <= sizeof(display_mutated));
    memcpy(display_mutated, dyn_response.data, dyn_response.length);
    display_mutated[36] = 9;
    memset(display_monitors, 0xa5, sizeof(display_monitors));
    display_monitor_count = 99;
    PCHECK(rdp_display_control_parse_monitor_layout(display_mutated,
                                                    dyn_response.length,
                                                    display_monitors,
                                                    2,
                                                    &display_monitor_count) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(display_monitor_count == 0 &&
           display_monitors[0].flags == 0 &&
           display_monitors[0].width == 0 &&
           display_monitors[1].flags == 0);
    display_monitors[0] = display_monitor;
    display_monitors[1] = display_monitor;
    display_monitors[1].flags = 0;
    display_monitors[1].left = 800;
    display_monitors[1].width = 640;
    display_monitors[1].height = 480;
    display_monitors[1].physical_width = 169;
    display_monitors[1].physical_height = 127;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout_with_caps(&dyn_response,
                                                              display_monitors,
                                                              2,
                                                              &display_parsed_caps) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 96 &&
           test_read_u32_le(dyn_response.data + 12) == 2 &&
           test_read_u32_le(dyn_response.data + 56) == 0 &&
           test_read_u32_le(dyn_response.data + 68) == 640);
    PCHECK(rdp_display_control_parse_monitor_layout_with_caps(dyn_response.data,
                                                              dyn_response.length,
                                                              display_monitors,
                                                              2,
                                                              &display_monitor_count,
                                                              &display_parsed_caps) == LIBRDP_STATUS_OK);
    PCHECK(display_monitor_count == 2 &&
           display_monitors[1].left == 800 &&
           display_monitors[1].width == 640);
    PCHECK(dyn_response.length <= sizeof(display_mutated));
    memcpy(display_mutated, dyn_response.data, dyn_response.length);
    display_mutated[56] = RDP_DISPLAY_CONTROL_MONITOR_PRIMARY;
    PCHECK(rdp_display_control_parse_monitor_layout_with_caps(display_mutated,
                                                              dyn_response.length,
                                                              display_monitors,
                                                              2,
                                                              &display_monitor_count,
                                                              &display_parsed_caps) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    memcpy(display_mutated, dyn_response.data, dyn_response.length);
    display_mutated[60] = 0xbc;
    display_mutated[61] = 0x02;
    display_mutated[62] = 0;
    display_mutated[63] = 0;
    PCHECK(rdp_display_control_parse_monitor_layout_with_caps(display_mutated,
                                                              dyn_response.length,
                                                              display_monitors,
                                                              2,
                                                              &display_monitor_count,
                                                              &display_parsed_caps) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    memcpy(display_mutated, dyn_response.data, dyn_response.length);
    display_mutated[60] = 0xf0u;
    display_mutated[61] = 0xffu;
    display_mutated[62] = 0xffu;
    display_mutated[63] = 0x7fu;
    memset(display_monitors, 0xa5, sizeof(display_monitors));
    display_monitor_count = 99;
    PCHECK(rdp_display_control_parse_monitor_layout_with_caps(display_mutated,
                                                              dyn_response.length,
                                                              display_monitors,
                                                              2,
                                                              &display_monitor_count,
                                                              &display_parsed_caps) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(display_monitor_count == 0 &&
           display_monitors[0].flags == 0 &&
           display_monitors[1].width == 0);
    display_monitors[1].left = 700;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, display_monitors, 2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_monitors[1].left = 800;
    display_monitors[1].left = INT32_MAX - 100;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, display_monitors, 2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_monitors[1].left = 800;
    display_parsed_caps.max_num_monitors = 1;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout_with_caps(&dyn_response,
                                                              display_monitors,
                                                              2,
                                                              &display_parsed_caps) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_parsed_caps.max_num_monitors = 1;
    display_parsed_caps.max_monitor_area_factor_a = 200;
    display_parsed_caps.max_monitor_area_factor_b = 200;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout_with_caps(&dyn_response,
                                                              &display_monitor,
                                                              1,
                                                              &display_parsed_caps) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_parsed_caps.max_monitor_area_factor_a = 8192;
    display_parsed_caps.max_monitor_area_factor_b = 8192;
    display_monitor.left = 1;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, &display_monitor, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_monitor.left = 0;
    display_monitor.device_scale_factor = 120;
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, &display_monitor, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_monitor.device_scale_factor = 100;
    display_monitor.physical_width = 9;
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, &display_monitor, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_monitor.physical_width = 210;
    display_monitor.width = 801;
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, &display_monitor, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_default_caps_advertise(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_default_capsets(graphics_default_capsets,
                                        (uint16_t)(sizeof(graphics_default_capsets) /
                                                   sizeof(graphics_default_capsets[0])),
                                        &graphics_default_capset_count) == LIBRDP_STATUS_OK);
    PCHECK((dyn_response.length == 70u && graphics_default_capset_count == 5u) ||
           (dyn_response.length == 46u && graphics_default_capset_count == 3u) ||
           (dyn_response.length == 34u && graphics_default_capset_count == 2u));
    for (graphics_default_capset_index = 0;
         graphics_default_capset_index < graphics_default_capset_count;
         graphics_default_capset_index++)
    {
        PCHECK(rdp_graphics_capset_is_default_supported(
                   &graphics_default_capsets[graphics_default_capset_index]) != 0);
    }
    graphics_capset = graphics_default_capsets[graphics_default_capset_count - 1u];
    graphics_capset.flags ^= RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED;
    PCHECK(rdp_graphics_capset_is_default_supported(&graphics_capset) == 0);
    graphics_capset = graphics_default_capsets[graphics_default_capset_count - 1u];
    graphics_capset.version = RDP_GRAPHICS_CAPVERSION_106_ERR;
    PCHECK(rdp_graphics_capset_is_default_supported(&graphics_capset) == 0);
    PCHECK(rdp_graphics_default_capsets(graphics_default_capsets,
                                        (uint16_t)(graphics_default_capset_count - 1u),
                                        &graphics_default_capset_count) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(dyn_response.length == 34 || dyn_response.length == 46 || dyn_response.length == 70);
    PCHECK(test_read_u16_le(dyn_response.data) == RDP_GRAPHICS_CMDID_CAPS_ADVERTISE);
    PCHECK(test_read_u32_le(dyn_response.data + 4) == dyn_response.length);
    PCHECK(test_read_u16_le(dyn_response.data + 8) ==
           (dyn_response.length == 70 ? 5 : (dyn_response.length == 46 ? 3 : 2)));
    PCHECK(rdp_graphics_parse_capset(dyn_response.data + 10, 12, &graphics_capset) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_8 &&
           (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0);
    {
        rdp_graphics_capset valid_capset = graphics_capset;

        PCHECK(rdp_graphics_parse_capset(graphics_bad_capset,
                                         sizeof(graphics_bad_capset),
                                         &graphics_capset) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_capset, &valid_capset, sizeof(graphics_capset)) == 0);
    }
    PCHECK(rdp_graphics_parse_capset(dyn_response.data + 22, 12, &graphics_capset) ==
           LIBRDP_STATUS_OK);
    if (dyn_response.length != 34)
    {
        PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_81 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_AVC420_ENABLED) != 0);
        PCHECK(rdp_graphics_parse_capset(dyn_response.data + 34, 12, &graphics_capset) ==
               LIBRDP_STATUS_OK);
        PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_10 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) == 0);
        if (dyn_response.length == 70)
        {
            PCHECK(rdp_graphics_parse_capset(dyn_response.data + 46, 12, &graphics_capset) ==
                   LIBRDP_STATUS_OK);
            PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_106 &&
                   (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0 &&
                   (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) == 0);
            PCHECK(rdp_graphics_parse_capset(dyn_response.data + 58, 12, &graphics_capset) ==
                   LIBRDP_STATUS_OK);
            PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_107 &&
                   (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0 &&
                   (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) == 0);
        }
    }
    else
    {
        PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_10 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) != 0);
    }
    PCHECK(rdp_graphics_default_capsets_for_avc(graphics_default_capsets,
                                                (uint16_t)(sizeof(graphics_default_capsets) /
                                                           sizeof(graphics_default_capsets[0])),
                                                &graphics_default_capset_count,
                                                0) == LIBRDP_STATUS_OK);
    PCHECK(graphics_default_capset_count == 2);
    PCHECK(graphics_default_capsets[1].version == RDP_GRAPHICS_CAPVERSION_10 &&
           (graphics_default_capsets[1].flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) != 0);
    PCHECK(rdp_graphics_capset_is_supported_for_avc(&graphics_default_capsets[1], 0) != 0);
    PCHECK(rdp_graphics_default_capsets_for_avc(graphics_default_capsets,
                                                (uint16_t)(sizeof(graphics_default_capsets) /
                                                           sizeof(graphics_default_capsets[0])),
                                                &graphics_default_capset_count,
                                                RDP_GRAPHICS_AVC_SUPPORT_AVC420) == LIBRDP_STATUS_OK);
    PCHECK(graphics_default_capset_count == 3);
    PCHECK(graphics_default_capsets[1].version == RDP_GRAPHICS_CAPVERSION_81 &&
           (graphics_default_capsets[1].flags & RDP_GRAPHICS_CAPS_FLAG_AVC420_ENABLED) != 0);
    PCHECK(graphics_default_capsets[2].version == RDP_GRAPHICS_CAPVERSION_10 &&
           (graphics_default_capsets[2].flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) != 0);
    PCHECK(rdp_graphics_capset_is_supported_for_avc(&graphics_default_capsets[2],
                                                    RDP_GRAPHICS_AVC_SUPPORT_AVC420) != 0);
    graphics_capset = graphics_default_capsets[1];
    PCHECK(rdp_graphics_capset_is_supported_for_avc(&graphics_capset, 0) == 0);
    PCHECK(rdp_graphics_default_capsets_for_avc(graphics_default_capsets,
                                                (uint16_t)(sizeof(graphics_default_capsets) /
                                                           sizeof(graphics_default_capsets[0])),
                                                &graphics_default_capset_count,
                                                RDP_GRAPHICS_AVC_SUPPORT_AVC420 |
                                                    RDP_GRAPHICS_AVC_SUPPORT_AVC444) == LIBRDP_STATUS_OK);
    PCHECK(graphics_default_capset_count == 4 &&
           graphics_default_capsets[3].version == RDP_GRAPHICS_CAPVERSION_106);
    graphics_capset.version = RDP_GRAPHICS_CAPVERSION_107;
    graphics_capset.flags = RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE;
    PCHECK(rdp_graphics_capset_is_supported_for_avc(&graphics_capset,
                                                    RDP_GRAPHICS_AVC_SUPPORT_AVC420 |
                                                        RDP_GRAPHICS_AVC_SUPPORT_AVC444) == 0);
    PCHECK(rdp_graphics_default_capsets_for_avc(graphics_default_capsets,
                                                (uint16_t)(sizeof(graphics_default_capsets) /
                                                           sizeof(graphics_default_capsets[0])),
                                                &graphics_default_capset_count,
                                                RDP_GRAPHICS_AVC_SUPPORT_ALL) == LIBRDP_STATUS_OK);
    PCHECK(graphics_default_capset_count == 5 &&
           graphics_default_capsets[4].version == RDP_GRAPHICS_CAPVERSION_107 &&
           (graphics_default_capsets[4].flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) == 0);
    PCHECK(rdp_graphics_capset_is_supported_for_avc(&graphics_default_capsets[4],
                                                    RDP_GRAPHICS_AVC_SUPPORT_ALL) != 0);
    PCHECK(rdp_graphics_capset_is_supported_for_avc(&graphics_default_capsets[4],
                                                    RDP_GRAPHICS_AVC_SUPPORT_AVC420) == 0);
    PCHECK(rdp_graphics_default_capsets_for_avc(graphics_default_capsets,
                                                (uint16_t)(sizeof(graphics_default_capsets) /
                                                           sizeof(graphics_default_capsets[0])),
                                                &graphics_default_capset_count,
                                                RDP_GRAPHICS_AVC_SUPPORT_AVC444) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_default_capsets_for_avc(graphics_default_capsets,
                                                (uint16_t)(sizeof(graphics_default_capsets) /
                                                           sizeof(graphics_default_capsets[0])),
                                                &graphics_default_capset_count,
                                                RDP_GRAPHICS_AVC_SUPPORT_AVC420 |
                                                    RDP_GRAPHICS_AVC_SUPPORT_AVC444V2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    dyn_response.length = 0;
    PCHECK(rdp_graphics_write_default_caps_advertise_for_avc(&dyn_response, 0) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 34u);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_buffer_append_u8(&dyn_response, 0xa5) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_write_default_caps_advertise_for_avc(&dyn_response,
                                                             RDP_GRAPHICS_AVC_SUPPORT_ALL << 1u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(dyn_response.length == 1 && dyn_response.data[0] == 0xa5);
    graphics_avc_runtime_support = rdp_avc_runtime_support();
    PCHECK((graphics_avc_runtime_support & ~RDP_GRAPHICS_AVC_SUPPORT_ALL) == 0);
    PCHECK((graphics_avc_runtime_support &
            (RDP_GRAPHICS_AVC_SUPPORT_AVC444 | RDP_GRAPHICS_AVC_SUPPORT_AVC444V2)) == 0 ||
           (graphics_avc_runtime_support & RDP_GRAPHICS_AVC_SUPPORT_AVC420) != 0);
    PCHECK(rdp_graphics_write_default_caps_advertise_for_avc(&dyn_response,
                                                             graphics_avc_runtime_support) ==
           LIBRDP_STATUS_OK);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    graphics_capset = graphics_default_capsets[0];
    PCHECK(rdp_graphics_parse_capset(graphics_capset_v107,
                                     sizeof(graphics_capset_v107),
                                     &graphics_capset) == LIBRDP_STATUS_OK);
    PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_107 &&
           (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SCALEDMAP_DISABLE) != 0);
    PCHECK(rdp_graphics_parse_capset(graphics_capset_unknown_flags,
                                     sizeof(graphics_capset_unknown_flags),
                                     &graphics_capset) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_capset(graphics_capset_conflicting_avc,
                                     sizeof(graphics_capset_conflicting_avc),
                                     &graphics_capset) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_capset(graphics_capset_trailing,
                                     sizeof(graphics_capset_trailing),
                                     &graphics_capset) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_buffer_append_u8(&dyn_response, 0xa5) == LIBRDP_STATUS_OK);
    graphics_capset.version = RDP_GRAPHICS_CAPVERSION_10;
    graphics_capset.flags = RDP_GRAPHICS_CAPS_FLAG_AVC420_ENABLED |
                            RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED;
    PCHECK(rdp_graphics_write_caps_advertise(&dyn_response,
                                             &graphics_capset,
                                             1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(dyn_response.length == 1 && dyn_response.data[0] == 0xa5);
    PCHECK(rdp_graphics_parse_header(graphics_confirm, sizeof(graphics_confirm), &graphics_header) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_header.cmd_id == RDP_GRAPHICS_CMDID_CAPS_CONFIRM);
    {
        rdp_graphics_header valid_header = graphics_header;

        PCHECK(rdp_graphics_parse_header(graphics_confirm,
                                         sizeof(graphics_confirm) - 1u,
                                         &graphics_header) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_header, &valid_header, sizeof(graphics_header)) == 0);
    }
    PCHECK(rdp_graphics_parse_caps_confirm(graphics_confirm, sizeof(graphics_confirm), &graphics_caps_confirm) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_caps_confirm.selected.version == RDP_GRAPHICS_CAPVERSION_8);
    PCHECK((graphics_caps_confirm.selected.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0);
    {
        rdp_graphics_caps_confirm valid_confirm = graphics_caps_confirm;

        PCHECK(rdp_graphics_parse_caps_confirm(graphics_confirm_trailing_capset,
                                               sizeof(graphics_confirm_trailing_capset),
                                               &graphics_caps_confirm) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_caps_confirm, &valid_confirm, sizeof(graphics_caps_confirm)) == 0);
    }
    PCHECK(rdp_graphics_decode_segmented_data(&graphics_decompressor,
                                              graphics_segment_single,
                                              sizeof(graphics_segment_single),
                                              &graphics_decoded) == LIBRDP_STATUS_OK);
    PCHECK(graphics_decoded.length == sizeof(graphics_confirm));
    PCHECK(memcmp(graphics_decoded.data, graphics_confirm, sizeof(graphics_confirm)) == 0);
    graphics_decoded.length = 0;
    PCHECK(rdp_graphics_decode_segmented_data(&graphics_decompressor,
                                              graphics_segment_multipart,
                                              sizeof(graphics_segment_multipart),
                                              &graphics_decoded) == LIBRDP_STATUS_OK);
    PCHECK(graphics_decoded.length == sizeof(graphics_confirm));
    PCHECK(memcmp(graphics_decoded.data, graphics_confirm, sizeof(graphics_confirm)) == 0);
    graphics_decoded.length = 0;
    PCHECK(rdp_graphics_decode_segmented_data(&graphics_decompressor,
                                              graphics_segment_compressed_literal,
                                              sizeof(graphics_segment_compressed_literal),
                                              &graphics_decoded) == LIBRDP_STATUS_OK);
    PCHECK(graphics_decoded.length == 1 && graphics_decoded.data[0] == 0x49);
    graphics_decoded.length = 0;
    PCHECK(rdp_graphics_decode_segmented_data(&graphics_decompressor,
                                              graphics_segment_bad_compression_type,
                                              sizeof(graphics_segment_bad_compression_type),
                                              &graphics_decoded) == LIBRDP_STATUS_PROTOCOL_ERROR);
    {
        uint32_t graphics_history_index = graphics_decompressor.history_index;
        uint32_t graphics_history_filled = graphics_decompressor.history_filled;
        uint32_t graphics_history_last_index =
            graphics_history_index == 0 ? RDP_GRAPHICS_BULK_HISTORY_SIZE - 1u : graphics_history_index - 1u;
        uint8_t graphics_history_last = graphics_decompressor.history[graphics_history_last_index];

        graphics_decoded.length = 0;
        PCHECK(rdp_buffer_append_u8(&graphics_decoded, 0xa5u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_graphics_decode_segmented_data(&graphics_decompressor,
                                                  graphics_segment_multipart_bad_second,
                                                  sizeof(graphics_segment_multipart_bad_second),
                                                  &graphics_decoded) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(graphics_decoded.length == 1u && graphics_decoded.data[0] == 0xa5u);
        PCHECK(graphics_decompressor.history_index == graphics_history_index &&
               graphics_decompressor.history_filled == graphics_history_filled &&
               graphics_decompressor.history[graphics_history_last_index] == graphics_history_last);
    }
    PCHECK(rdp_graphics_parse_caps_confirm(graphics_confirm, sizeof(graphics_confirm) - 1u, &graphics_caps_confirm) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_create_surface(graphics_create_surface,
                                             sizeof(graphics_create_surface),
                                             &graphics_create) == LIBRDP_STATUS_OK);
    PCHECK(graphics_create.surface_id == 0x1234 &&
           graphics_create.width == 1024 &&
           graphics_create.height == 768 &&
           graphics_create.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888);
    {
        rdp_graphics_create_surface valid_create = graphics_create;

        PCHECK(rdp_graphics_parse_create_surface(graphics_create_surface,
                                                 sizeof(graphics_create_surface) - 1u,
                                                 &graphics_create) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_create, &valid_create, sizeof(graphics_create)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_create_surface(&dyn_response,
                                             graphics_create.surface_id,
                                             graphics_create.width,
                                             graphics_create.height,
                                             graphics_create.pixel_format) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_create_surface(dyn_response.data,
                                             dyn_response.length,
                                             &graphics_create) == LIBRDP_STATUS_OK);
    PCHECK(graphics_create.width == 1024 && graphics_create.height == 768);
    PCHECK(rdp_graphics_write_create_surface(&dyn_response,
                                             1,
                                             0,
                                             1,
                                             RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_parse_delete_surface(graphics_delete_surface,
                                             sizeof(graphics_delete_surface),
                                             &graphics_delete) == LIBRDP_STATUS_OK);
    PCHECK(graphics_delete.surface_id == 0x1234);
    {
        rdp_graphics_delete_surface valid_delete = graphics_delete;

        PCHECK(rdp_graphics_parse_delete_surface(graphics_delete_surface,
                                                 sizeof(graphics_delete_surface) - 1u,
                                                 &graphics_delete) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_delete, &valid_delete, sizeof(graphics_delete)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_delete_surface(&dyn_response, graphics_delete.surface_id) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_delete_surface(dyn_response.data,
                                             dyn_response.length,
                                             &graphics_delete) == LIBRDP_STATUS_OK);
    PCHECK(graphics_delete.surface_id == 0x1234);
    PCHECK(rdp_graphics_parse_map_surface_to_output(graphics_map_output,
                                                    sizeof(graphics_map_output),
                                                    &graphics_map) == LIBRDP_STATUS_OK);
    PCHECK(graphics_map.surface_id == 0x1234 &&
           graphics_map.output_origin_x == 10 &&
           graphics_map.output_origin_y == 20);
    {
        rdp_graphics_map_surface_to_output valid_map = graphics_map;
        uint8_t bad_map[20];

        memcpy(bad_map, graphics_map_output, sizeof(bad_map));
        bad_map[11] = 1u;
        PCHECK(rdp_graphics_parse_map_surface_to_output(bad_map,
                                                        sizeof(bad_map),
                                                        &graphics_map) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_map, &valid_map, sizeof(graphics_map)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_map_surface_to_output(&dyn_response,
                                                    graphics_map.surface_id,
                                                    graphics_map.output_origin_x,
                                                    graphics_map.output_origin_y) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_map_surface_to_output(dyn_response.data,
                                                    dyn_response.length,
                                                    &graphics_map) == LIBRDP_STATUS_OK);
    PCHECK(graphics_map.output_origin_x == 10 && graphics_map.output_origin_y == 20);
    PCHECK(rdp_graphics_parse_map_surface_to_scaled_output(graphics_scaled_map_output,
                                                           sizeof(graphics_scaled_map_output),
                                                           &graphics_scaled_map) == LIBRDP_STATUS_OK);
    PCHECK(graphics_scaled_map.surface_id == 0x1234 &&
           graphics_scaled_map.output_origin_x == 10 &&
           graphics_scaled_map.output_origin_y == 20 &&
           graphics_scaled_map.target_width == 1024 &&
           graphics_scaled_map.target_height == 768);
    {
        rdp_graphics_map_surface_to_scaled_output valid_map = graphics_scaled_map;
        uint8_t bad_map[28];

        memcpy(bad_map, graphics_scaled_map_output, sizeof(bad_map));
        bad_map[24] = 0u;
        bad_map[25] = 0u;
        bad_map[26] = 0u;
        bad_map[27] = 0u;
        PCHECK(rdp_graphics_parse_map_surface_to_scaled_output(bad_map,
                                                               sizeof(bad_map),
                                                               &graphics_scaled_map) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_scaled_map, &valid_map, sizeof(graphics_scaled_map)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_map_surface_to_scaled_output(&dyn_response,
                                                           graphics_scaled_map.surface_id,
                                                           graphics_scaled_map.output_origin_x,
                                                           graphics_scaled_map.output_origin_y,
                                                           graphics_scaled_map.target_width,
                                                           graphics_scaled_map.target_height) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_map_surface_to_scaled_output(dyn_response.data,
                                                           dyn_response.length,
                                                           &graphics_scaled_map) == LIBRDP_STATUS_OK);
    PCHECK(graphics_scaled_map.target_width == 1024 && graphics_scaled_map.target_height == 768);
    PCHECK(rdp_graphics_write_map_surface_to_scaled_output(&dyn_response, 1, 0, 0, 0, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_parse_solid_fill(graphics_solid_fill,
                                         sizeof(graphics_solid_fill),
                                         &graphics_solid) == LIBRDP_STATUS_OK);
    PCHECK(graphics_solid.surface_id == 0x1234 &&
           graphics_solid.fill_pixel == 0xff332211u &&
           graphics_solid.rect_count == 1 &&
           graphics_solid.rects_len == 8);
    PCHECK(rdp_graphics_parse_rect16(graphics_solid.rects,
                                     graphics_solid.rects_len,
                                     &graphics_rect) == LIBRDP_STATUS_OK);
    PCHECK(graphics_rect.left == 1 &&
           graphics_rect.top == 2 &&
           graphics_rect.right == 5 &&
           graphics_rect.bottom == 6);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_rect16(&dyn_response, &graphics_rect) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_rect16(dyn_response.data, dyn_response.length, &graphics_rect) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_rect.right == 5 && graphics_rect.bottom == 6);
    {
        rdp_graphics_rect16 valid_rect = graphics_rect;

        PCHECK(rdp_graphics_parse_rect16(graphics_bad_rect,
                                         sizeof(graphics_bad_rect),
                                         &graphics_rect) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_rect, &valid_rect, sizeof(graphics_rect)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_solid_fill(&dyn_response,
                                         graphics_solid.surface_id,
                                         graphics_solid.fill_pixel,
                                         &graphics_rect,
                                         1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_solid_fill(dyn_response.data,
                                         dyn_response.length,
                                         &graphics_solid) == LIBRDP_STATUS_OK);
    PCHECK(graphics_solid.rect_count == 1 && graphics_solid.fill_pixel == 0xff332211u);
    {
        rdp_graphics_solid_fill valid_solid = graphics_solid;

        PCHECK(rdp_graphics_parse_solid_fill(graphics_solid_fill,
                                             sizeof(graphics_solid_fill) - 1u,
                                             &graphics_solid) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_solid, &valid_solid, sizeof(graphics_solid)) == 0);
    }
    PCHECK(rdp_graphics_parse_wire_to_surface_1(graphics_wire_to_surface_1,
                                                sizeof(graphics_wire_to_surface_1),
                                                &graphics_wire1) == LIBRDP_STATUS_OK);
    PCHECK(graphics_wire1.surface_id == 0x1234 &&
           graphics_wire1.codec_id == RDP_GRAPHICS_CODECID_UNCOMPRESSED &&
           graphics_wire1.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888 &&
           graphics_wire1.dest_rect.left == 1 &&
           graphics_wire1.dest_rect.bottom == 4 &&
           graphics_wire1.bitmap_data_length == 16 &&
           graphics_wire1.bitmap_data[15] == 16);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_wire_to_surface_1(&dyn_response,
                                                graphics_wire1.surface_id,
                                                graphics_wire1.codec_id,
                                                graphics_wire1.pixel_format,
                                                &graphics_wire1.dest_rect,
                                                graphics_wire1.bitmap_data,
                                                graphics_wire1.bitmap_data_length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_wire_to_surface_1(dyn_response.data,
                                                dyn_response.length,
                                                &graphics_wire1) == LIBRDP_STATUS_OK);
    PCHECK(graphics_wire1.bitmap_data_length == 16 && graphics_wire1.bitmap_data[0] == 1);
    PCHECK(rdp_graphics_parse_wire_to_surface_1(graphics_wire_to_surface_1_alpha,
                                                sizeof(graphics_wire_to_surface_1_alpha),
                                                &graphics_wire1) == LIBRDP_STATUS_OK);
    PCHECK(graphics_wire1.codec_id == RDP_GRAPHICS_CODECID_ALPHA &&
           graphics_wire1.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_ARGB_8888 &&
           graphics_wire1.dest_rect.right == 2 &&
           graphics_wire1.dest_rect.bottom == 2 &&
           graphics_wire1.bitmap_data_length == 8 &&
           graphics_wire1.bitmap_data[4] == 0x10 &&
           graphics_wire1.bitmap_data[7] == 0xff);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_wire_to_surface_1(&dyn_response,
                                                graphics_wire1.surface_id,
                                                graphics_wire1.codec_id,
                                                graphics_wire1.pixel_format,
                                                &graphics_wire1.dest_rect,
                                                graphics_wire1.bitmap_data,
                                                graphics_wire1.bitmap_data_length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_wire_to_surface_1(dyn_response.data,
                                                dyn_response.length,
                                                &graphics_wire1) == LIBRDP_STATUS_OK);
    PCHECK(graphics_wire1.codec_id == RDP_GRAPHICS_CODECID_ALPHA &&
           graphics_wire1.bitmap_data_length == 8 &&
           graphics_wire1.bitmap_data[5] == 0x20);
    {
        rdp_graphics_wire_to_surface_1 valid_wire1 = graphics_wire1;

        PCHECK(rdp_graphics_parse_wire_to_surface_1(graphics_wire_to_surface_1,
                                                    sizeof(graphics_wire_to_surface_1) - 1u,
                                                    &graphics_wire1) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_wire1, &valid_wire1, sizeof(graphics_wire1)) == 0);
    }
    graphics_zero_rect.left = 10;
    graphics_zero_rect.top = 20;
    graphics_zero_rect.right = 10;
    graphics_zero_rect.bottom = 21;
    PCHECK(rdp_graphics_write_wire_to_surface_1(&dyn_response,
                                                graphics_wire1.surface_id,
                                                graphics_wire1.codec_id,
                                                graphics_wire1.pixel_format,
                                                &graphics_zero_rect,
                                                graphics_wire1.bitmap_data,
                                                graphics_wire1.bitmap_data_length) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_wire_to_surface_1(&dyn_response,
                                                graphics_wire1.surface_id,
                                                RDP_GRAPHICS_CODECID_CAPROGRESSIVE,
                                                graphics_wire1.pixel_format,
                                                &graphics_wire1.dest_rect,
                                                graphics_wire1.bitmap_data,
                                                graphics_wire1.bitmap_data_length) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_parse_wire_to_surface_2(graphics_wire_to_surface_2,
                                                sizeof(graphics_wire_to_surface_2),
                                                &graphics_wire2) == LIBRDP_STATUS_OK);
    PCHECK(graphics_wire2.surface_id == 0x1234 &&
           graphics_wire2.codec_id == RDP_GRAPHICS_CODECID_CAPROGRESSIVE &&
           graphics_wire2.codec_context_id == 0x11223344u &&
           graphics_wire2.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_ARGB_8888 &&
           graphics_wire2.bitmap_data_length == 3 &&
           graphics_wire2.bitmap_data[2] == 0xcc);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_wire_to_surface_2(&dyn_response,
                                                graphics_wire2.surface_id,
                                                graphics_wire2.codec_id,
                                                graphics_wire2.codec_context_id,
                                                graphics_wire2.pixel_format,
                                                graphics_wire2.bitmap_data,
                                                graphics_wire2.bitmap_data_length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_wire_to_surface_2(dyn_response.data,
                                                dyn_response.length,
                                                &graphics_wire2) == LIBRDP_STATUS_OK);
    PCHECK(graphics_wire2.codec_context_id == 0x11223344u && graphics_wire2.bitmap_data[2] == 0xcc);
    {
        rdp_graphics_wire_to_surface_2 valid_wire2 = graphics_wire2;

        PCHECK(rdp_graphics_parse_wire_to_surface_2(graphics_wire_to_surface_2,
                                                    sizeof(graphics_wire_to_surface_2) - 1u,
                                                    &graphics_wire2) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_wire2, &valid_wire2, sizeof(graphics_wire2)) == 0);
    }
    PCHECK(rdp_graphics_write_wire_to_surface_2(&dyn_response,
                                                graphics_wire2.surface_id,
                                                RDP_GRAPHICS_CODECID_CLEARCODEC,
                                                graphics_wire2.codec_context_id,
                                                graphics_wire2.pixel_format,
                                                graphics_wire2.bitmap_data,
                                                graphics_wire2.bitmap_data_length) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_parse_avc420_metablock(graphics_avc420_stream,
                                               sizeof(graphics_avc420_stream) - 4u,
                                               &graphics_avc_meta) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc_meta.rect_count == 1 &&
           graphics_avc_meta.rects_len == 8 &&
           graphics_avc_meta.quant_quality_len == 2);
    PCHECK(rdp_graphics_parse_rect16(graphics_avc_meta.rects,
                                     graphics_avc_meta.rects_len,
                                     &graphics_rect) == LIBRDP_STATUS_OK);
    PCHECK(graphics_rect.left == 0 &&
           graphics_rect.top == 0 &&
           graphics_rect.right == 16 &&
           graphics_rect.bottom == 16);
    PCHECK(rdp_graphics_parse_avc420_quant_quality(graphics_avc_meta.quant_quality,
                                                   graphics_avc_meta.quant_quality_len,
                                                   &graphics_avc_quant) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc_quant.qp_val == 0x45 &&
           graphics_avc_quant.qp == 5 &&
           graphics_avc_quant.r == 1 &&
           graphics_avc_quant.p == 0 &&
           graphics_avc_quant.quality == 100);
    graphics_bad_quant = graphics_avc_quant;
    PCHECK(rdp_graphics_parse_avc420_quant_quality(graphics_avc_quant_bad_qp,
                                                   sizeof(graphics_avc_quant_bad_qp),
                                                   &graphics_bad_quant) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(memcmp(&graphics_bad_quant, &graphics_avc_quant, sizeof(graphics_bad_quant)) == 0);
    PCHECK(rdp_graphics_parse_avc420_quant_quality(graphics_avc_quant_bad_quality,
                                                   sizeof(graphics_avc_quant_bad_quality),
                                                   &graphics_bad_quant) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(memcmp(&graphics_bad_quant, &graphics_avc_quant, sizeof(graphics_bad_quant)) == 0);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc420_quant_quality(&dyn_response,
                                                   &graphics_avc_quant) == LIBRDP_STATUS_OK);
    graphics_avc_quant.qp = 52;
    graphics_avc_quant.qp_val = 52;
    graphics_avc_quant.quality = 100;
    PCHECK(rdp_graphics_write_avc420_quant_quality(&dyn_response,
                                                   &graphics_avc_quant) == LIBRDP_STATUS_INVALID_ARGUMENT);
    graphics_avc_quant.qp = 5;
    graphics_avc_quant.qp_val = 0x45;
    graphics_avc_quant.quality = 101;
    PCHECK(rdp_graphics_write_avc420_quant_quality(&dyn_response,
                                                   &graphics_avc_quant) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(dyn_response.length == 2 &&
           memcmp(dyn_response.data, graphics_avc_meta.quant_quality, 2) == 0);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc420_metablock(&dyn_response,
                                               &graphics_avc_meta) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(graphics_avc420_stream) - 4u &&
           memcmp(dyn_response.data,
                  graphics_avc420_stream,
                  sizeof(graphics_avc420_stream) - 4u) == 0);
    PCHECK(rdp_graphics_parse_avc420_stream(graphics_avc420_stream,
                                            sizeof(graphics_avc420_stream),
                                            &graphics_avc420) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc420.meta.rect_count == 1 &&
           graphics_avc420.bitstream_len == 4 &&
           graphics_avc420.bitstream[3] == 0x65);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc420_stream(&dyn_response,
                                            &graphics_avc420) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(graphics_avc420_stream) &&
           memcmp(dyn_response.data, graphics_avc420_stream, sizeof(graphics_avc420_stream)) == 0);
    {
        rdp_graphics_avc420_stream valid_graphics_avc420 = graphics_avc420;

        PCHECK(rdp_graphics_parse_avc420_stream(graphics_avc420_bad_rect,
                                                sizeof(graphics_avc420_bad_rect),
                                                &graphics_avc420) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_avc420, &valid_graphics_avc420, sizeof(graphics_avc420)) == 0);
        PCHECK(rdp_graphics_parse_avc420_stream(graphics_avc420_empty_bits,
                                                sizeof(graphics_avc420_empty_bits),
                                                &graphics_avc420) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_avc420, &valid_graphics_avc420, sizeof(graphics_avc420)) == 0);
        PCHECK(rdp_graphics_parse_avc420_stream(graphics_avc420_bad_quant,
                                                sizeof(graphics_avc420_bad_quant),
                                                &graphics_avc420) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_avc420, &valid_graphics_avc420, sizeof(graphics_avc420)) == 0);
    }
    PCHECK(rdp_graphics_parse_avc420_stream(graphics_avc420_stream,
                                            sizeof(graphics_avc420_stream),
                                            &graphics_avc420) == LIBRDP_STATUS_OK);
    graphics_avc420_edge = graphics_avc420;
    graphics_avc420_edge.meta.quant_quality = graphics_avc_quant_bad_qp;
    graphics_avc420_edge.meta.quant_quality_len = sizeof(graphics_avc_quant_bad_qp);
    PCHECK(rdp_graphics_write_avc420_stream(&dyn_response,
                                            &graphics_avc420_edge) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_both,
                                            sizeof(graphics_avc444_both),
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc444.lc == RDP_GRAPHICS_AVC444_LC_BOTH &&
           graphics_avc444.stream1_size == sizeof(graphics_avc420_stream) &&
           graphics_avc444.has_stream1 &&
           graphics_avc444.has_stream2 &&
           graphics_avc444.stream2.bitstream[3] == 0x66);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc444_stream(&dyn_response,
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(graphics_avc444_both) &&
           memcmp(dyn_response.data, graphics_avc444_both, sizeof(graphics_avc444_both)) == 0);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_luma,
                                            sizeof(graphics_avc444_luma),
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc444.lc == RDP_GRAPHICS_AVC444_LC_LUMA &&
           graphics_avc444.has_stream1 &&
           !graphics_avc444.has_stream2);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc444_stream(&dyn_response,
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(graphics_avc444_luma) &&
           memcmp(dyn_response.data, graphics_avc444_luma, sizeof(graphics_avc444_luma)) == 0);
    graphics_avc444.has_stream2 = 1;
    PCHECK(rdp_graphics_write_avc444_stream(&dyn_response,
                                            &graphics_avc444) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_chroma,
                                            sizeof(graphics_avc444_chroma),
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc444.lc == RDP_GRAPHICS_AVC444_LC_CHROMA &&
           graphics_avc444.has_stream1 &&
           !graphics_avc444.has_stream2);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc444_stream(&dyn_response,
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(graphics_avc444_chroma) &&
           memcmp(dyn_response.data, graphics_avc444_chroma, sizeof(graphics_avc444_chroma)) == 0);
    graphics_avc444_edge = graphics_avc444;
    graphics_avc444_edge.lc = RDP_GRAPHICS_AVC444_LC_INVALID;
    PCHECK(rdp_graphics_write_avc444_stream(&dyn_response,
                                            &graphics_avc444_edge) == LIBRDP_STATUS_INVALID_ARGUMENT);
    {
        rdp_graphics_avc444_stream valid_graphics_avc444 = graphics_avc444;

        PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_invalid_lc,
                                                sizeof(graphics_avc444_invalid_lc),
                                                &graphics_avc444) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_avc444, &valid_graphics_avc444, sizeof(graphics_avc444)) == 0);
        PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_bad_split,
                                                sizeof(graphics_avc444_bad_split),
                                                &graphics_avc444) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_avc444, &valid_graphics_avc444, sizeof(graphics_avc444)) == 0);
    }
    avc_decoder = rdp_avc_decoder_new();
    PCHECK(avc_decoder != NULL);
    rdp_avc_decoder_reset(avc_decoder);
    rdp_avc_frame_init(&avc_frame);
    graphics_avc420_edge = graphics_avc420;
    graphics_avc420_edge.meta.rect_count = 0;
    PCHECK(rdp_avc_decode_420(avc_decoder,
                              &graphics_avc420_edge,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
    graphics_avc420_edge = graphics_avc420;
    graphics_avc420_edge.meta.rects = graphics_avc_rect_oob;
    graphics_avc420_edge.meta.rects_len = sizeof(graphics_avc_rect_oob);
    PCHECK(rdp_avc_decode_420(avc_decoder,
                              &graphics_avc420_edge,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_avc_decode_420(avc_decoder,
                              &graphics_avc420,
                              0,
                              16,
                              &avc_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
#if !defined(RDP_HAVE_FFMPEG_AVC) && !defined(RDP_HAVE_OPENH264_AVC)
    PCHECK(rdp_avc_decode_420(avc_decoder,
                              &graphics_avc420,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_UNSUPPORTED);
#endif
    graphics_avc_status = rdp_avc_decode_420(avc_decoder,
                                             &graphics_avc420,
                                             16,
                                             16,
                                             &avc_frame);
    if ((graphics_avc_runtime_support & RDP_GRAPHICS_AVC_SUPPORT_AVC420) != 0)
        PCHECK(graphics_avc_status != LIBRDP_STATUS_UNSUPPORTED);
    else
        PCHECK(graphics_avc_status == LIBRDP_STATUS_UNSUPPORTED);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_both,
                                            sizeof(graphics_avc444_both),
                                            &graphics_avc444_edge) == LIBRDP_STATUS_OK);
    graphics_avc444_edge.has_stream1 = 0;
    PCHECK(rdp_avc_decode_444(avc_decoder,
                              RDP_GRAPHICS_CODECID_AVC444,
                              &graphics_avc444_edge,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_both,
                                            sizeof(graphics_avc444_both),
                                            &graphics_avc444_edge) == LIBRDP_STATUS_OK);
    graphics_avc444_edge.stream2.bitstream_len = 0;
    PCHECK(rdp_avc_decode_444(avc_decoder,
                              RDP_GRAPHICS_CODECID_AVC444V2,
                              &graphics_avc444_edge,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_luma,
                                            sizeof(graphics_avc444_luma),
                                            &graphics_avc444_edge) == LIBRDP_STATUS_OK);
    graphics_avc444_edge.has_stream2 = 1;
    graphics_avc444_edge.stream2 = graphics_avc444_edge.stream1;
    PCHECK(rdp_avc_decode_444(avc_decoder,
                              RDP_GRAPHICS_CODECID_AVC444,
                              &graphics_avc444_edge,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_both,
                                            sizeof(graphics_avc444_both),
                                            &graphics_avc444_edge) == LIBRDP_STATUS_OK);
    PCHECK(rdp_avc_decode_444(avc_decoder,
                              0xffffu,
                              &graphics_avc444_edge,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_INVALID_ARGUMENT);
    memset(&graphics_avc444_valid, 0, sizeof(graphics_avc444_valid));
    graphics_avc444_valid.lc = RDP_GRAPHICS_AVC444_LC_LUMA;
    graphics_avc444_valid.has_stream1 = 1;
    graphics_avc444_valid.stream1.meta.rect_count = 1;
    graphics_avc444_valid.stream1.meta.rects = graphics_avc_rect_full_16;
    graphics_avc444_valid.stream1.meta.rects_len = sizeof(graphics_avc_rect_full_16);
    graphics_avc444_valid.stream1.meta.quant_quality = graphics_avc_quant_quality;
    graphics_avc444_valid.stream1.meta.quant_quality_len = sizeof(graphics_avc_quant_quality);
    graphics_avc444_valid.stream1.bitstream = graphics_avc_red_h264;
    graphics_avc444_valid.stream1.bitstream_len = sizeof(graphics_avc_red_h264);
    graphics_avc444_edge = graphics_avc444_valid;
    graphics_avc444_edge.stream1.meta.rect_count = 0;
    PCHECK(rdp_avc_decode_444(avc_decoder,
                              RDP_GRAPHICS_CODECID_AVC444,
                              &graphics_avc444_edge,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
    graphics_avc444_edge = graphics_avc444_valid;
    graphics_avc444_edge.stream1.meta.rects = graphics_avc_rect_oob;
    graphics_avc444_edge.stream1.meta.rects_len = sizeof(graphics_avc_rect_oob);
    PCHECK(rdp_avc_decode_444(avc_decoder,
                              RDP_GRAPHICS_CODECID_AVC444V2,
                              &graphics_avc444_edge,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_PROTOCOL_ERROR);
#if !defined(RDP_HAVE_FFMPEG_AVC) && !defined(RDP_HAVE_OPENH264_AVC)
    PCHECK(rdp_avc_decode_444(avc_decoder,
                              RDP_GRAPHICS_CODECID_AVC444,
                              &graphics_avc444_valid,
                              16,
                              16,
                              &avc_frame) == LIBRDP_STATUS_UNSUPPORTED);
#endif
    graphics_avc_status = rdp_avc_decode_444(avc_decoder,
                                             RDP_GRAPHICS_CODECID_AVC444,
                                             &graphics_avc444_valid,
                                             16,
                                             16,
                                             &avc_frame);
    if ((graphics_avc_runtime_support & RDP_GRAPHICS_AVC_SUPPORT_AVC444) != 0)
        PCHECK(graphics_avc_status == LIBRDP_STATUS_OK ||
               graphics_avc_status == LIBRDP_STATUS_PROTOCOL_ERROR);
    else
        PCHECK(graphics_avc_status == LIBRDP_STATUS_UNSUPPORTED);
    if (graphics_avc_status == LIBRDP_STATUS_OK)
    {
        const uint8_t* pixel = avc_frame.pixels.data;
        int red_delta_bg = (int)pixel[2] - (int)pixel[0];
        int red_delta_gr = (int)pixel[2] - (int)pixel[1];

        PCHECK(avc_frame.width == 16 && avc_frame.height == 16 && avc_frame.stride >= 64u);
        PCHECK(red_delta_bg > 8 && red_delta_gr > 8 && pixel[3] == 0xffu);
    }
    graphics_avc_status = rdp_avc_decode_444(avc_decoder,
                                             RDP_GRAPHICS_CODECID_AVC444V2,
                                             &graphics_avc444_valid,
                                             16,
                                             16,
                                             &avc_frame);
    if ((graphics_avc_runtime_support & RDP_GRAPHICS_AVC_SUPPORT_AVC444V2) != 0)
        PCHECK(graphics_avc_status == LIBRDP_STATUS_OK ||
               graphics_avc_status == LIBRDP_STATUS_PROTOCOL_ERROR);
    else
        PCHECK(graphics_avc_status == LIBRDP_STATUS_UNSUPPORTED);
    {
        uint8_t aux_y[8u * 5u];
        uint8_t aux_u[4u * 3u];
        uint8_t aux_v[4u * 3u];
        uint8_t dst_u[8u * 5u];
        uint8_t dst_v[8u * 5u];
        size_t i = 0;
        rdp_avc_444_chroma_view chroma_view;

        for (i = 0; i < sizeof(aux_y); i++)
            aux_y[i] = (uint8_t)(0x20u + i);
        for (i = 0; i < sizeof(aux_u); i++)
            aux_u[i] = (uint8_t)(0x60u + i);
        for (i = 0; i < sizeof(aux_v); i++)
            aux_v[i] = (uint8_t)(0xa0u + i);
        memset(dst_u, 0xee, sizeof(dst_u));
        memset(dst_v, 0xdd, sizeof(dst_v));
        memset(&chroma_view, 0, sizeof(chroma_view));
        chroma_view.aux_y = aux_y;
        chroma_view.aux_y_stride = 8;
        chroma_view.aux_u = aux_u;
        chroma_view.aux_u_stride = 4;
        chroma_view.aux_v = aux_v;
        chroma_view.aux_v_stride = 4;
        chroma_view.aux_width = 8;
        chroma_view.aux_height = 5;
        chroma_view.rect.left = 0;
        chroma_view.rect.top = 0;
        chroma_view.rect.right = 5;
        chroma_view.rect.bottom = 5;
        chroma_view.dst_u = dst_u;
        chroma_view.dst_u_stride = 8;
        chroma_view.dst_v = dst_v;
        chroma_view.dst_v_stride = 8;
        chroma_view.dst_width = 8;
        chroma_view.dst_height = 5;
        PCHECK(rdp_avc_reconstruct_444_chroma(&chroma_view) == LIBRDP_STATUS_OK);
        PCHECK(dst_u[8u + 0u] == aux_y[0] && dst_u[8u + 4u] == aux_y[4]);
        PCHECK(dst_v[8u + 0u] == aux_y[4u * 8u] && dst_v[8u + 4u] == aux_y[4u * 8u + 4u]);
        PCHECK(dst_u[0u * 8u + 1u] == aux_u[0] && dst_v[0u * 8u + 1u] == aux_v[0]);
        PCHECK(dst_u[2u * 8u + 3u] == aux_u[5] && dst_v[2u * 8u + 3u] == aux_v[5]);
        PCHECK(dst_u[4u * 8u + 1u] == aux_u[8] && dst_v[4u * 8u + 1u] == aux_v[8]);
        chroma_view.aux_v_stride = 1;
        PCHECK(rdp_avc_reconstruct_444_chroma(&chroma_view) == LIBRDP_STATUS_PROTOCOL_ERROR);
        chroma_view.aux_v_stride = 4;
        chroma_view.aux_u_stride = 1;
        PCHECK(rdp_avc_reconstruct_444_chroma(&chroma_view) == LIBRDP_STATUS_PROTOCOL_ERROR);
    }
    {
        uint8_t aux_y[6u * 3u];
        uint8_t aux_u[3u * 2u];
        uint8_t aux_v[3u * 2u];
        uint8_t dst_u[6u * 3u];
        uint8_t dst_v[6u * 3u];
        size_t i = 0;
        rdp_avc_444_chroma_view chroma_view;

        for (i = 0; i < sizeof(aux_y); i++)
            aux_y[i] = (uint8_t)(0x10u + i);
        for (i = 0; i < sizeof(aux_u); i++)
            aux_u[i] = (uint8_t)(0x50u + i);
        for (i = 0; i < sizeof(aux_v); i++)
            aux_v[i] = (uint8_t)(0x90u + i);
        memset(dst_u, 0xee, sizeof(dst_u));
        memset(dst_v, 0xdd, sizeof(dst_v));
        memset(&chroma_view, 0, sizeof(chroma_view));
        chroma_view.aux_y = aux_y;
        chroma_view.aux_y_stride = 6;
        chroma_view.aux_u = aux_u;
        chroma_view.aux_u_stride = 3;
        chroma_view.aux_v = aux_v;
        chroma_view.aux_v_stride = 3;
        chroma_view.aux_width = 6;
        chroma_view.aux_height = 3;
        chroma_view.rect.left = 1;
        chroma_view.rect.top = 0;
        chroma_view.rect.right = 4;
        chroma_view.rect.bottom = 3;
        chroma_view.dst_u = dst_u;
        chroma_view.dst_u_stride = 6;
        chroma_view.dst_v = dst_v;
        chroma_view.dst_v_stride = 6;
        chroma_view.dst_width = 6;
        chroma_view.dst_height = 3;
        PCHECK(rdp_avc_reconstruct_444_chroma(&chroma_view) == LIBRDP_STATUS_OK);
        PCHECK(dst_u[1] == aux_u[0] && dst_v[1] == aux_v[0]);
        PCHECK(dst_u[3] == aux_u[1] && dst_v[3] == aux_v[1]);
        PCHECK(dst_u[2] == 0xeeu && dst_v[2] == 0xddu);
        PCHECK(dst_u[6u + 1u] == aux_y[1] && dst_u[6u + 3u] == aux_y[3]);
        PCHECK(dst_v[6u + 1u] == aux_y[12u + 1u] &&
               dst_v[6u + 3u] == aux_y[12u + 3u]);
    }
    {
        uint8_t aux_y[16u * 4u];
        uint8_t aux_u[8u * 2u];
        uint8_t aux_v[8u * 2u];
        uint8_t dst_u[16u * 4u];
        uint8_t dst_v[16u * 4u];
        size_t i = 0;
        rdp_avc_444v2_chroma_view chroma_view;

        for (i = 0; i < sizeof(aux_y); i++)
            aux_y[i] = (uint8_t)(0x20u + i);
        for (i = 0; i < sizeof(aux_u); i++)
            aux_u[i] = (uint8_t)(0x60u + i);
        for (i = 0; i < sizeof(aux_v); i++)
            aux_v[i] = (uint8_t)(0xa0u + i);
        memset(dst_u, 0xee, sizeof(dst_u));
        memset(dst_v, 0xdd, sizeof(dst_v));
        memset(&chroma_view, 0, sizeof(chroma_view));
        chroma_view.aux_y = aux_y;
        chroma_view.aux_y_stride = 16;
        chroma_view.aux_u = aux_u;
        chroma_view.aux_u_stride = 8;
        chroma_view.aux_v = aux_v;
        chroma_view.aux_v_stride = 8;
        chroma_view.aux_width = 16;
        chroma_view.aux_height = 4;
        chroma_view.rect.left = 2;
        chroma_view.rect.top = 0;
        chroma_view.rect.right = 7;
        chroma_view.rect.bottom = 3;
        chroma_view.dst_u = dst_u;
        chroma_view.dst_u_stride = 16;
        chroma_view.dst_v = dst_v;
        chroma_view.dst_v_stride = 16;
        chroma_view.dst_width = 16;
        chroma_view.dst_height = 4;
        PCHECK(rdp_avc_reconstruct_444v2_chroma(&chroma_view) == LIBRDP_STATUS_OK);
        PCHECK(dst_u[3] == aux_y[1] && dst_v[3] == aux_y[9]);
        PCHECK(dst_u[5] == aux_y[2] && dst_v[5] == aux_y[10]);
        PCHECK(dst_u[16u + 3u] == aux_y[16u + 1u] && dst_v[16u + 3u] == aux_y[16u + 9u]);
        PCHECK(dst_u[16u + 2u] == aux_v[0] && dst_v[16u + 2u] == aux_v[4]);
        PCHECK(dst_u[16u + 4u] == aux_u[1] && dst_v[16u + 4u] == aux_u[5]);
        PCHECK(dst_u[16u + 6u] == aux_v[1] && dst_v[16u + 6u] == aux_v[5]);
        PCHECK(dst_u[0] == 0xeeu && dst_v[0] == 0xddu);
        chroma_view.aux_u_stride = 4;
        PCHECK(rdp_avc_reconstruct_444v2_chroma(&chroma_view) == LIBRDP_STATUS_PROTOCOL_ERROR);
        chroma_view.aux_u_stride = 8;
        chroma_view.aux_v_stride = 4;
        PCHECK(rdp_avc_reconstruct_444v2_chroma(&chroma_view) == LIBRDP_STATUS_PROTOCOL_ERROR);
    }
    {
        uint8_t aux_y[15u * 5u];
        uint8_t aux_u[8u * 3u];
        uint8_t aux_v[8u * 3u];
        uint8_t dst_u[15u * 5u];
        uint8_t dst_v[15u * 5u];
        size_t i = 0;
        rdp_avc_444v2_chroma_view chroma_view;

        for (i = 0; i < sizeof(aux_y); i++)
            aux_y[i] = (uint8_t)(0x10u + i);
        for (i = 0; i < sizeof(aux_u); i++)
            aux_u[i] = (uint8_t)(0x50u + i);
        for (i = 0; i < sizeof(aux_v); i++)
            aux_v[i] = (uint8_t)(0x90u + i);
        memset(dst_u, 0xee, sizeof(dst_u));
        memset(dst_v, 0xdd, sizeof(dst_v));
        memset(&chroma_view, 0, sizeof(chroma_view));
        chroma_view.aux_y = aux_y;
        chroma_view.aux_y_stride = 15;
        chroma_view.aux_u = aux_u;
        chroma_view.aux_u_stride = 8;
        chroma_view.aux_v = aux_v;
        chroma_view.aux_v_stride = 8;
        chroma_view.aux_width = 15;
        chroma_view.aux_height = 5;
        chroma_view.rect.left = 1;
        chroma_view.rect.top = 0;
        chroma_view.rect.right = 8;
        chroma_view.rect.bottom = 5;
        chroma_view.dst_u = dst_u;
        chroma_view.dst_u_stride = 15;
        chroma_view.dst_v = dst_v;
        chroma_view.dst_v_stride = 15;
        chroma_view.dst_width = 15;
        chroma_view.dst_height = 5;
        PCHECK(rdp_avc_reconstruct_444v2_chroma(&chroma_view) == LIBRDP_STATUS_OK);
        PCHECK(dst_u[1] == aux_y[0] && dst_v[1] == aux_y[8]);
        PCHECK(dst_u[3] == aux_y[1] && dst_v[3] == aux_y[9]);
        PCHECK(dst_u[15u + 2u] == aux_v[0] && dst_v[15u + 2u] == aux_v[4]);
        PCHECK(dst_u[15u + 4u] == aux_u[1] && dst_v[15u + 4u] == aux_u[5]);
        PCHECK(dst_u[15u + 6u] == aux_v[1] && dst_v[15u + 6u] == aux_v[5]);
    }
    {
        uint8_t aux_y[4u * 2u] = {0};
        uint8_t aux_u[2u] = {0};
        uint8_t aux_v[2u] = {0};
        uint8_t dst_u[4u * 2u];
        uint8_t dst_v[4u * 2u];
        rdp_avc_444v2_chroma_view chroma_view;

        memset(dst_u, 0x80, sizeof(dst_u));
        memset(dst_v, 0x80, sizeof(dst_v));
        dst_u[0] = 60;
        dst_v[0] = 90;
        aux_y[0] = 10;
        aux_y[2] = 40;
        aux_y[4] = 30;
        aux_y[6] = 70;
        aux_u[0] = 20;
        aux_u[1] = 50;
        aux_v[0] = 80;
        aux_v[1] = 110;
        memset(&chroma_view, 0, sizeof(chroma_view));
        chroma_view.aux_y = aux_y;
        chroma_view.aux_y_stride = 4;
        chroma_view.aux_u = aux_u;
        chroma_view.aux_u_stride = 2;
        chroma_view.aux_v = aux_v;
        chroma_view.aux_v_stride = 2;
        chroma_view.aux_width = 4;
        chroma_view.aux_height = 2;
        chroma_view.rect.left = 0;
        chroma_view.rect.top = 0;
        chroma_view.rect.right = 4;
        chroma_view.rect.bottom = 2;
        chroma_view.dst_u = dst_u;
        chroma_view.dst_u_stride = 4;
        chroma_view.dst_v = dst_v;
        chroma_view.dst_v_stride = 4;
        chroma_view.dst_width = 4;
        chroma_view.dst_height = 2;
        PCHECK(rdp_avc_reconstruct_444v2_chroma(&chroma_view) == LIBRDP_STATUS_OK);
        PCHECK(dst_u[1] == 10 && dst_u[4] == 20 && dst_u[5] == 30 && dst_u[0] == 180);
        PCHECK(dst_v[1] == 40 && dst_v[4] == 50 && dst_v[5] == 70 && dst_v[0] == 200);
    }
    {
        uint8_t aux_y[4u * 2u] = {0};
        uint8_t aux_u[2u] = {0};
        uint8_t aux_v[2u] = {0};
        uint8_t dst_u[4u * 2u];
        uint8_t dst_v[4u * 2u];
        rdp_avc_444v2_chroma_view chroma_view;

        memset(dst_u, 0x80, sizeof(dst_u));
        memset(dst_v, 0x80, sizeof(dst_v));
        dst_u[0] = 60;
        dst_v[0] = 90;
        aux_y[0] = 61;
        aux_y[2] = 91;
        aux_y[4] = 62;
        aux_y[6] = 92;
        aux_u[0] = 63;
        aux_u[1] = 93;
        aux_v[0] = 64;
        aux_v[1] = 94;
        memset(&chroma_view, 0, sizeof(chroma_view));
        chroma_view.aux_y = aux_y;
        chroma_view.aux_y_stride = 4;
        chroma_view.aux_u = aux_u;
        chroma_view.aux_u_stride = 2;
        chroma_view.aux_v = aux_v;
        chroma_view.aux_v_stride = 2;
        chroma_view.aux_width = 4;
        chroma_view.aux_height = 2;
        chroma_view.rect.left = 0;
        chroma_view.rect.top = 0;
        chroma_view.rect.right = 4;
        chroma_view.rect.bottom = 2;
        chroma_view.dst_u = dst_u;
        chroma_view.dst_u_stride = 4;
        chroma_view.dst_v = dst_v;
        chroma_view.dst_v_stride = 4;
        chroma_view.dst_width = 4;
        chroma_view.dst_height = 2;
        PCHECK(rdp_avc_reconstruct_444v2_chroma(&chroma_view) == LIBRDP_STATUS_OK);
        PCHECK(dst_u[0] == 54 && dst_v[0] == 84);
    }
#if defined(RDP_HAVE_FFMPEG_AVC) || defined(RDP_HAVE_OPENH264_AVC)
    {
        uint8_t y_plane[4] = {128, 128, 128, 128};
        uint8_t u_plane[4] = {160, 130, 130, 130};
        uint8_t v_plane[4] = {160, 130, 130, 130};
        const uint8_t* pixel0 = NULL;
        const uint8_t* pixel1 = NULL;

        PCHECK(rdp_avc_yuv444_planes_to_bgra(y_plane,
                                             2,
                                             u_plane,
                                             2,
                                             v_plane,
                                             2,
                                             2,
                                             2,
                                             0,
                                             &avc_frame) == LIBRDP_STATUS_OK);
        pixel0 = avc_frame.pixels.data;
        PCHECK(pixel0[0] == 187 && pixel0[1] == 107 && pixel0[2] == 178 && pixel0[3] == 255);
        PCHECK(rdp_avc_yuv444_planes_to_bgra(y_plane,
                                             2,
                                             u_plane,
                                             2,
                                             v_plane,
                                             2,
                                             2,
                                             2,
                                             1,
                                             &avc_frame) == LIBRDP_STATUS_OK);
        pixel0 = avc_frame.pixels.data;
        pixel1 = avc_frame.pixels.data + 4u;
        PCHECK(pixel0[0] == 255 && pixel0[1] == 48 && pixel0[2] == 255 && pixel0[3] == 255);
        PCHECK(pixel1[0] == 131 && pixel1[1] == 127 && pixel1[2] == 131 && pixel1[3] == 255);
        {
            uint8_t saved[8];
            size_t saved_len = avc_frame.pixels.length;
            uint32_t saved_width = avc_frame.width;
            uint32_t saved_height = avc_frame.height;
            size_t saved_stride = avc_frame.stride;

            memcpy(saved, avc_frame.pixels.data, sizeof(saved));
            PCHECK(rdp_avc_yuv444_planes_to_bgra(y_plane,
                                                 1,
                                                 u_plane,
                                                 2,
                                                 v_plane,
                                                 2,
                                                 2,
                                                 2,
                                                 0,
                                                 &avc_frame) == LIBRDP_STATUS_INVALID_ARGUMENT);
            PCHECK(avc_frame.pixels.length == saved_len &&
                   avc_frame.width == saved_width &&
                   avc_frame.height == saved_height &&
                   avc_frame.stride == saved_stride &&
                   memcmp(avc_frame.pixels.data, saved, sizeof(saved)) == 0);
        }
    }
#endif
    rdp_avc_frame_free(&avc_frame);
    rdp_avc_decoder_free(avc_decoder);
    PCHECK(rdp_graphics_progressive_parse_block(graphics_progressive_stream,
                                                sizeof(graphics_progressive_stream),
                                                &graphics_progressive_block) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_CONTEXT &&
           graphics_progressive_block.length == 10 &&
           graphics_progressive_block.payload_len == 4);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_block(&dyn_response,
                                                graphics_progressive_block.type,
                                                graphics_progressive_block.payload,
                                                (uint32_t)graphics_progressive_block.payload_len) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_block(dyn_response.data,
                                                dyn_response.length,
                                                &graphics_progressive_block) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_CONTEXT &&
           graphics_progressive_block.payload_len == 4);
    {
        rdp_graphics_progressive_block valid_block = graphics_progressive_block;

        PCHECK(rdp_graphics_progressive_parse_block(graphics_progressive_bad_block,
                                                    sizeof(graphics_progressive_bad_block),
                                                    &graphics_progressive_block) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_block,
                      &valid_block,
                      sizeof(graphics_progressive_block)) == 0);
    }
    PCHECK(rdp_graphics_progressive_write_block(&dyn_response, 1, NULL, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_progressive_parse_context(graphics_progressive_stream,
                                                  sizeof(graphics_progressive_stream),
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_context.context_id == 0 &&
           graphics_progressive_context.tile_size == RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE &&
           graphics_progressive_context.flags == 1);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_context(&dyn_response,
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_context(dyn_response.data,
                                                  dyn_response.length,
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_context.flags == 1);
    {
        rdp_graphics_progressive_context valid_context = graphics_progressive_context;

        PCHECK(rdp_graphics_progressive_parse_context(graphics_progressive_stream + 10,
                                                      sizeof(graphics_progressive_stream) - 10u,
                                                      &graphics_progressive_context) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_context,
                      &valid_context,
                      sizeof(graphics_progressive_context)) == 0);
    }
    PCHECK(rdp_graphics_progressive_parse_frame_begin(graphics_progressive_stream + 10,
                                                      sizeof(graphics_progressive_stream) - 10u,
                                                      &graphics_progressive_frame_begin) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_frame_begin.frame_index == 1 &&
           graphics_progressive_frame_begin.region_count == 1);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_frame_begin(&dyn_response,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_frame_begin(dyn_response.data,
                                                      dyn_response.length,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_frame_begin.frame_index == 1);
    {
        rdp_graphics_progressive_frame_begin valid_frame_begin = graphics_progressive_frame_begin;

        PCHECK(rdp_graphics_progressive_parse_frame_begin(graphics_progressive_stream + 10,
                                                          11u,
                                                          &graphics_progressive_frame_begin) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_frame_begin,
                      &valid_frame_begin,
                      sizeof(graphics_progressive_frame_begin)) == 0);
    }
    PCHECK(rdp_graphics_progressive_parse_region(graphics_progressive_stream + 22,
                                                 sizeof(graphics_progressive_stream) - 22u,
                                                 &graphics_progressive_region) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_region.tile_size == RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE &&
           graphics_progressive_region.rect_count == 1 &&
           graphics_progressive_region.quant_count == 1 &&
           graphics_progressive_region.progressive_quant_count == 1 &&
           graphics_progressive_region.tile_count == 1 &&
           graphics_progressive_region.tile_data_size == 25 &&
           graphics_progressive_region.tiles_len == 25);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_region(&dyn_response,
                                                 &graphics_progressive_region) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_region(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_progressive_region) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_region.tiles_len == 25);
    {
        rdp_graphics_progressive_region valid_region = graphics_progressive_region;

        PCHECK(rdp_graphics_progressive_parse_region(graphics_progressive_bad_region,
                                                     sizeof(graphics_progressive_bad_region),
                                                     &graphics_progressive_region) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_region,
                      &valid_region,
                      sizeof(graphics_progressive_region)) == 0);
    }
    PCHECK(rdp_graphics_progressive_parse_region(graphics_progressive_empty_region,
                                                 sizeof(graphics_progressive_empty_region),
                                                 &graphics_progressive_region) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_region.tile_count == 0 &&
           graphics_progressive_region.tile_data_size == 0 &&
           graphics_progressive_region.tiles_len == 0);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_region(&dyn_response,
                                                 &graphics_progressive_region) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data,
                  graphics_progressive_empty_region,
                  sizeof(graphics_progressive_empty_region)) == 0);
    PCHECK(rdp_graphics_progressive_parse_region_rect(graphics_progressive_region_rect,
                                                      sizeof(graphics_progressive_region_rect),
                                                      &graphics_progressive_rect) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_rect.left == 640 &&
           graphics_progressive_rect.top == 288 &&
           graphics_progressive_rect.right == 704 &&
           graphics_progressive_rect.bottom == 320);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_region_rect(&dyn_response,
                                                      &graphics_progressive_rect) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data,
                  graphics_progressive_region_rect,
                  sizeof(graphics_progressive_region_rect)) == 0);
    {
        rdp_graphics_rect16 valid_progressive_rect = graphics_progressive_rect;

        PCHECK(rdp_graphics_progressive_parse_region_rect(graphics_progressive_region_rect_overflow,
                                                          sizeof(graphics_progressive_region_rect_overflow),
                                                          &graphics_progressive_rect) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_rect,
                      &valid_progressive_rect,
                      sizeof(graphics_progressive_rect)) == 0);
        PCHECK(rdp_graphics_progressive_parse_region_rect(graphics_progressive_region_rect,
                                                          sizeof(graphics_progressive_region_rect) - 1u,
                                                          &graphics_progressive_rect) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_rect,
                      &valid_progressive_rect,
                      sizeof(graphics_progressive_rect)) == 0);
    }
    PCHECK(rdp_graphics_progressive_parse_tile_simple(graphics_progressive_stream + 69,
                                                      sizeof(graphics_progressive_stream) - 69u,
                                                      &graphics_progressive_simple) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_simple.block_type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_SIMPLE &&
           graphics_progressive_simple.y_len == 1 &&
           graphics_progressive_simple.cb_len == 1 &&
           graphics_progressive_simple.cr_len == 1 &&
           graphics_progressive_simple.y_data[0] == 0xaa &&
           graphics_progressive_simple.cb_data[0] == 0xbb &&
           graphics_progressive_simple.cr_data[0] == 0xcc);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_tile_simple(&dyn_response,
                                                      &graphics_progressive_simple) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_tile_simple(dyn_response.data,
                                                      dyn_response.length,
                                                      &graphics_progressive_simple) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_simple.y_data[0] == 0xaa);
    {
        rdp_graphics_progressive_tile_simple valid_simple = graphics_progressive_simple;

        PCHECK(rdp_graphics_progressive_parse_tile_simple(graphics_progressive_stream + 69,
                                                          24u,
                                                          &graphics_progressive_simple) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_simple,
                      &valid_simple,
                      sizeof(graphics_progressive_simple)) == 0);
    }
    PCHECK(rdp_graphics_progressive_parse_frame_end(graphics_progressive_stream + 94,
                                                    sizeof(graphics_progressive_stream) - 94u) ==
           LIBRDP_STATUS_OK);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_frame_end(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_frame_end(dyn_response.data,
                                                    dyn_response.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_tile_first(graphics_progressive_tile_first,
                                                     sizeof(graphics_progressive_tile_first),
                                                     &graphics_progressive_first) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_first.block_type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_FIRST &&
           graphics_progressive_first.x_idx == 1 &&
           graphics_progressive_first.y_idx == 2 &&
           graphics_progressive_first.progressive_quality == 0 &&
           graphics_progressive_first.y_data[0] == 0x11 &&
           graphics_progressive_first.cb_data[0] == 0x22 &&
           graphics_progressive_first.cr_data[0] == 0x33);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_tile_first(&dyn_response,
                                                     &graphics_progressive_first) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data,
                  graphics_progressive_tile_first,
                  sizeof(graphics_progressive_tile_first)) == 0);
    {
        rdp_graphics_progressive_tile_first valid_first = graphics_progressive_first;

        PCHECK(rdp_graphics_progressive_parse_tile_first(graphics_progressive_tile_first,
                                                         sizeof(graphics_progressive_tile_first) - 1u,
                                                         &graphics_progressive_first) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_first,
                      &valid_first,
                      sizeof(graphics_progressive_first)) == 0);
    }
    PCHECK(rdp_graphics_progressive_parse_tile_upgrade(graphics_progressive_tile_upgrade,
                                                       sizeof(graphics_progressive_tile_upgrade),
                                                       &graphics_progressive_upgrade) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_upgrade.block_type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_UPGRADE &&
           graphics_progressive_upgrade.x_idx == 3 &&
           graphics_progressive_upgrade.y_idx == 4 &&
           graphics_progressive_upgrade.y_srl_data[0] == 0x11 &&
           graphics_progressive_upgrade.cr_raw_data[0] == 0x66);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_tile_upgrade(&dyn_response,
                                                       &graphics_progressive_upgrade) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data,
                  graphics_progressive_tile_upgrade,
                  sizeof(graphics_progressive_tile_upgrade)) == 0);
    {
        rdp_graphics_progressive_tile_upgrade valid_upgrade = graphics_progressive_upgrade;

        PCHECK(rdp_graphics_progressive_parse_tile_upgrade(graphics_progressive_tile_upgrade,
                                                           sizeof(graphics_progressive_tile_upgrade) - 1u,
                                                           &graphics_progressive_upgrade) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive_upgrade,
                      &valid_upgrade,
                      sizeof(graphics_progressive_upgrade)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_context(&dyn_response,
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_frame_begin(&dyn_response,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_region(graphics_progressive_stream + 22,
                                                 sizeof(graphics_progressive_stream) - 22u,
                                                 &graphics_progressive_region) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_region(&dyn_response,
                                                 &graphics_progressive_region) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_frame_end(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data,
                  graphics_progressive_stream,
                  sizeof(graphics_progressive_stream)) == 0);
    PCHECK(rdp_graphics_progressive_parse_stream(graphics_progressive_stream,
                                                 sizeof(graphics_progressive_stream),
                                                 &graphics_progressive) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive.block_count == 4 &&
           graphics_progressive.known_block_count == 4 &&
           graphics_progressive.region_count == 1 &&
           graphics_progressive.tile_count == 1 &&
           graphics_progressive.simple_tile_count == 1 &&
           graphics_progressive.first_tile_count == 0 &&
           graphics_progressive.upgrade_tile_count == 0 &&
           graphics_progressive.has_sync == 0 &&
           graphics_progressive.has_context &&
           graphics_progressive.has_frame_begin &&
           graphics_progressive.has_frame_end);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_buffer_append(&dyn_response,
                             graphics_progressive_sync,
                             sizeof(graphics_progressive_sync)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&dyn_response,
                             graphics_progressive_stream,
                             sizeof(graphics_progressive_stream)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_stream(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_progressive) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive.block_count == 5 &&
           graphics_progressive.known_block_count == 5 &&
           graphics_progressive.has_sync == 1 &&
           graphics_progressive.has_context == 1 &&
           graphics_progressive.region_count == 1 &&
           graphics_progressive.tile_count == 1);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_buffer_append(&dyn_response,
                             graphics_progressive_bad_sync,
                             sizeof(graphics_progressive_bad_sync)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&dyn_response,
                             graphics_progressive_stream,
                             sizeof(graphics_progressive_stream)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_stream(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_progressive) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_buffer_append(&dyn_response,
                             graphics_progressive_stream + 10u,
                             sizeof(graphics_progressive_stream) - 10u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_stream(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_progressive) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive.block_count == 3 &&
           graphics_progressive.known_block_count == 3 &&
           graphics_progressive.has_sync == 0 &&
           graphics_progressive.has_context == 0 &&
           graphics_progressive.has_frame_begin == 1 &&
           graphics_progressive.has_frame_end == 1 &&
           graphics_progressive.region_count == 1 &&
           graphics_progressive.tile_count == 1);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_context(&dyn_response,
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_region(&dyn_response,
                                                 &graphics_progressive_region) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_frame_end(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_stream(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_progressive) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_context(&dyn_response,
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_frame_begin(&dyn_response,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_frame_begin(&dyn_response,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_stream(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_progressive) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_context(&dyn_response,
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_frame_begin(&dyn_response,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_region(&dyn_response,
                                                 &graphics_progressive_region) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_stream(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_progressive) == LIBRDP_STATUS_PROTOCOL_ERROR);
    graphics_progressive_frame_begin.region_count =
        (uint16_t)(RDP_GRAPHICS_PROGRESSIVE_MAX_REGIONS + 1u);
    PCHECK(rdp_graphics_progressive_write_frame_begin(&dyn_response,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    graphics_progressive_frame_begin.region_count = 1;
    graphics_progressive_region.rect_count =
        (uint16_t)(RDP_GRAPHICS_PROGRESSIVE_MAX_RECTS + 1u);
    PCHECK(rdp_graphics_progressive_write_region(&dyn_response,
                                                 &graphics_progressive_region) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    graphics_progressive_region.rect_count = 1;
    {
        rdp_graphics_progressive_stream graphics_progressive_before = graphics_progressive;

        PCHECK(rdp_graphics_progressive_parse_stream(graphics_progressive_stream,
                                                     sizeof(graphics_progressive_stream) - 1u,
                                                     &graphics_progressive) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_progressive,
                      &graphics_progressive_before,
                      sizeof(graphics_progressive)) == 0);
    }
    PCHECK(rdp_graphics_parse_surface_to_surface(graphics_surface_to_surface,
                                                 sizeof(graphics_surface_to_surface),
                                                 &graphics_surface_copy) == LIBRDP_STATUS_OK);
    PCHECK(graphics_surface_copy.surface_id_src == 0x10 &&
           graphics_surface_copy.surface_id_dest == 0x20 &&
           graphics_surface_copy.rect_src.right == 5 &&
           graphics_surface_copy.dest_points_count == 2 &&
           graphics_surface_copy.dest_points_len == 8);
    PCHECK(rdp_graphics_parse_point16(graphics_surface_copy.dest_points,
                                      graphics_surface_copy.dest_points_len,
                                      &graphics_point) == LIBRDP_STATUS_OK);
    PCHECK(graphics_point.x == 7 && graphics_point.y == 8);
    graphics_points[0] = graphics_point;
    PCHECK(rdp_graphics_parse_point16(graphics_surface_copy.dest_points + 4,
                                      graphics_surface_copy.dest_points_len - 4u,
                                      &graphics_points[1]) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_point16(&dyn_response, &graphics_points[0]) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_point16(dyn_response.data, dyn_response.length, &graphics_point) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_point.x == 7 && graphics_point.y == 8);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_surface_to_surface(&dyn_response,
                                                 graphics_surface_copy.surface_id_src,
                                                 graphics_surface_copy.surface_id_dest,
                                                 &graphics_surface_copy.rect_src,
                                                 graphics_points,
                                                 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_surface_to_surface(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_surface_copy) == LIBRDP_STATUS_OK);
    PCHECK(graphics_surface_copy.dest_points_count == 2 &&
           graphics_surface_copy.rect_src.right == 5);
    {
        rdp_graphics_surface_to_surface valid_surface_copy = graphics_surface_copy;

        PCHECK(rdp_graphics_parse_surface_to_surface(graphics_surface_to_surface,
                                                     sizeof(graphics_surface_to_surface) - 1u,
                                                     &graphics_surface_copy) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_surface_copy,
                      &valid_surface_copy,
                      sizeof(graphics_surface_copy)) == 0);
    }
    PCHECK(rdp_graphics_parse_surface_to_cache(graphics_surface_to_cache,
                                               sizeof(graphics_surface_to_cache),
                                               &graphics_surface_cache) == LIBRDP_STATUS_OK);
    PCHECK(graphics_surface_cache.surface_id == 0x1234 &&
           graphics_surface_cache.cache_key == 0x0102030405060708ull &&
           graphics_surface_cache.cache_slot == 0x42 &&
           graphics_surface_cache.rect_src.left == 1);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_surface_to_cache(&dyn_response,
                                               graphics_surface_cache.surface_id,
                                               graphics_surface_cache.cache_key,
                                               graphics_surface_cache.cache_slot,
                                               &graphics_surface_cache.rect_src) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_surface_to_cache(dyn_response.data,
                                               dyn_response.length,
                                               &graphics_surface_cache) == LIBRDP_STATUS_OK);
    PCHECK(graphics_surface_cache.cache_key == 0x0102030405060708ull);
    {
        rdp_graphics_surface_to_cache valid_surface_cache = graphics_surface_cache;

        PCHECK(rdp_graphics_parse_surface_to_cache(graphics_surface_to_cache,
                                                   sizeof(graphics_surface_to_cache) - 1u,
                                                   &graphics_surface_cache) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_surface_cache,
                      &valid_surface_cache,
                      sizeof(graphics_surface_cache)) == 0);
    }
    PCHECK(rdp_graphics_parse_cache_to_surface(graphics_cache_to_surface,
                                               sizeof(graphics_cache_to_surface),
                                               &graphics_cache_surface) == LIBRDP_STATUS_OK);
    PCHECK(graphics_cache_surface.cache_slot == 0x42 &&
           graphics_cache_surface.surface_id == 0x1234 &&
           graphics_cache_surface.dest_points_count == 2 &&
           graphics_cache_surface.dest_points_len == 8);
    PCHECK(rdp_graphics_parse_point16(graphics_cache_surface.dest_points,
                                      graphics_cache_surface.dest_points_len,
                                      &graphics_points[0]) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_point16(graphics_cache_surface.dest_points + 4,
                                      graphics_cache_surface.dest_points_len - 4u,
                                      &graphics_points[1]) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_cache_to_surface(&dyn_response,
                                               graphics_cache_surface.cache_slot,
                                               graphics_cache_surface.surface_id,
                                               graphics_points,
                                               2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_cache_to_surface(dyn_response.data,
                                               dyn_response.length,
                                               &graphics_cache_surface) == LIBRDP_STATUS_OK);
    PCHECK(graphics_cache_surface.dest_points_count == 2);
    {
        rdp_graphics_cache_to_surface valid_cache_surface = graphics_cache_surface;

        PCHECK(rdp_graphics_parse_cache_to_surface(graphics_cache_to_surface,
                                                   sizeof(graphics_cache_to_surface) - 1u,
                                                   &graphics_cache_surface) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_cache_surface,
                      &valid_cache_surface,
                      sizeof(graphics_cache_surface)) == 0);
    }
    PCHECK(rdp_graphics_parse_evict_cache_entry(graphics_evict_cache,
                                                sizeof(graphics_evict_cache),
                                                &graphics_evict) == LIBRDP_STATUS_OK);
    PCHECK(graphics_evict.cache_slot == 0x42);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_evict_cache_entry(&dyn_response, graphics_evict.cache_slot) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_evict_cache_entry(dyn_response.data,
                                                dyn_response.length,
                                                &graphics_evict) == LIBRDP_STATUS_OK);
    PCHECK(graphics_evict.cache_slot == 0x42);
    {
        rdp_graphics_evict_cache_entry valid_evict = graphics_evict;

        PCHECK(rdp_graphics_parse_evict_cache_entry(graphics_evict_cache,
                                                    sizeof(graphics_evict_cache) - 1u,
                                                    &graphics_evict) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_evict, &valid_evict, sizeof(graphics_evict)) == 0);
    }
    PCHECK(rdp_graphics_parse_delete_encoding_context(graphics_delete_context_pdu,
                                                      sizeof(graphics_delete_context_pdu),
                                                      &graphics_delete_context) == LIBRDP_STATUS_OK);
    PCHECK(graphics_delete_context.surface_id == 0x1234 &&
           graphics_delete_context.codec_context_id == 0x11223344u);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_delete_encoding_context(&dyn_response,
                                                      graphics_delete_context.surface_id,
                                                      graphics_delete_context.codec_context_id) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_delete_encoding_context(dyn_response.data,
                                                      dyn_response.length,
                                                      &graphics_delete_context) == LIBRDP_STATUS_OK);
    PCHECK(graphics_delete_context.codec_context_id == 0x11223344u);
    {
        rdp_graphics_delete_encoding_context valid_delete_context = graphics_delete_context;

        PCHECK(rdp_graphics_parse_delete_encoding_context(graphics_delete_context_pdu,
                                                          sizeof(graphics_delete_context_pdu) - 1u,
                                                          &graphics_delete_context) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_delete_context,
                      &valid_delete_context,
                      sizeof(graphics_delete_context)) == 0);
    }
    PCHECK(rdp_graphics_parse_start_frame(graphics_start_frame,
                                          sizeof(graphics_start_frame),
                                          &graphics_start) == LIBRDP_STATUS_OK);
    PCHECK(graphics_start.timestamp == 0x01020304 && graphics_start.frame_id == 0x11223344);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_start_frame(&dyn_response,
                                          graphics_start.timestamp,
                                          graphics_start.frame_id) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_start_frame(dyn_response.data,
                                          dyn_response.length,
                                          &graphics_start) == LIBRDP_STATUS_OK);
    PCHECK(graphics_start.frame_id == 0x11223344);
    {
        rdp_graphics_start_frame valid_start = graphics_start;

        PCHECK(rdp_graphics_parse_start_frame(graphics_start_frame,
                                              sizeof(graphics_start_frame) - 1u,
                                              &graphics_start) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_start, &valid_start, sizeof(graphics_start)) == 0);
    }
    PCHECK(rdp_graphics_parse_end_frame(graphics_end_frame,
                                        sizeof(graphics_end_frame),
                                        &graphics_end) == LIBRDP_STATUS_OK);
    PCHECK(graphics_end.frame_id == 0x11223344);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_end_frame(&dyn_response, graphics_end.frame_id) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_end_frame(dyn_response.data,
                                        dyn_response.length,
                                        &graphics_end) == LIBRDP_STATUS_OK);
    PCHECK(graphics_end.frame_id == 0x11223344);
    {
        rdp_graphics_end_frame valid_end = graphics_end;

        PCHECK(rdp_graphics_parse_end_frame(graphics_end_frame,
                                            sizeof(graphics_end_frame) - 1u,
                                            &graphics_end) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_end, &valid_end, sizeof(graphics_end)) == 0);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_frame_ack(&dyn_response,
                                        RDP_GRAPHICS_QUEUE_DEPTH_UNAVAILABLE,
                                        graphics_end.frame_id,
                                        7) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 20 &&
           test_read_u16_le(dyn_response.data) == RDP_GRAPHICS_CMDID_FRAME_ACKNOWLEDGE &&
           test_read_u32_le(dyn_response.data + 4) == 20 &&
           test_read_u32_le(dyn_response.data + 12) == graphics_end.frame_id &&
           test_read_u32_le(dyn_response.data + 16) == 7);
    PCHECK(rdp_graphics_parse_frame_ack(dyn_response.data,
                                        dyn_response.length,
                                        &graphics_ack) == LIBRDP_STATUS_OK);
    PCHECK(graphics_ack.queue_depth == RDP_GRAPHICS_QUEUE_DEPTH_UNAVAILABLE &&
           graphics_ack.frame_id == graphics_end.frame_id &&
           graphics_ack.total_frames_decoded == 7);
    {
        rdp_graphics_frame_ack valid_ack = graphics_ack;

        PCHECK(rdp_graphics_parse_frame_ack(dyn_response.data,
                                            dyn_response.length - 1u,
                                            &graphics_ack) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_ack, &valid_ack, sizeof(graphics_ack)) == 0);
    }
    PCHECK(rdp_graphics_write_reset(&graphics_reset_pdu, 1024, 768) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_reset(graphics_reset_pdu.data,
                                    graphics_reset_pdu.length,
                                    &graphics_reset) == LIBRDP_STATUS_OK);
    PCHECK(graphics_reset.width == 1024 &&
           graphics_reset.height == 768 &&
           graphics_reset.monitor_count == 0);
    PCHECK(graphics_reset_pdu.length == 340);
    {
        rdp_graphics_reset valid_reset = graphics_reset;

        PCHECK(rdp_graphics_parse_reset(graphics_reset_pdu.data,
                                        graphics_reset_pdu.length - 1u,
                                        &graphics_reset) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_reset, &valid_reset, sizeof(graphics_reset)) == 0);
        graphics_reset_pdu.data[16] = (uint8_t)((LIBRDP_DISPLAY_MAX_MONITORS + 1u) & 0xffu);
        graphics_reset_pdu.data[17] = (uint8_t)(((LIBRDP_DISPLAY_MAX_MONITORS + 1u) >> 8u) & 0xffu);
        graphics_reset_pdu.data[18] = 0;
        graphics_reset_pdu.data[19] = 0;
        PCHECK(rdp_graphics_parse_reset(graphics_reset_pdu.data,
                                        graphics_reset_pdu.length,
                                        &graphics_reset) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&graphics_reset, &valid_reset, sizeof(graphics_reset)) == 0);
    }
    PCHECK(rdp_graphics_write_reset(&graphics_reset_pdu, 0, 768) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_clearcodec_parse_stream(clear_residual_bitmap,
                                       sizeof(clear_residual_bitmap),
                                       &clear_stream) == LIBRDP_STATUS_OK);
    PCHECK(clear_stream.flags == 0 &&
           clear_stream.seq_number == 0 &&
           clear_stream.payload_len == 16);
    PCHECK(rdp_clearcodec_parse_composite_payload(clear_stream.payload,
                                                  clear_stream.payload_len,
                                                  &clear_payload) == LIBRDP_STATUS_OK);
    PCHECK(clear_payload.residual_len == 4 &&
           clear_payload.bands_len == 0 &&
           clear_payload.subcodec_len == 0);
    {
        rdp_clearcodec_composite_payload valid_clear_payload = clear_payload;

        PCHECK(rdp_clearcodec_parse_composite_payload(clear_stream.payload,
                                                      clear_stream.payload_len - 1u,
                                                      &clear_payload) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&clear_payload,
                      &valid_clear_payload,
                      sizeof(clear_payload)) == 0);
    }
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_residual_bitmap,
                                        sizeof(clear_residual_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 &&
           clear_pixels.length == 16 &&
           clear_pixels.data[0] == 1 &&
           clear_pixels.data[1] == 2 &&
           clear_pixels.data[2] == 3 &&
           clear_pixels.data[3] == 0xff &&
           clear_pixels.data[12] == 1 &&
           clear_pixels.data[15] == 0xff);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_residual_zero_run_bitmap,
                                        sizeof(clear_residual_zero_run_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 1 &&
           clear_pixels.data[1] == 2 &&
           clear_pixels.data[2] == 3 &&
           clear_pixels.data[12] == 1 &&
           clear_pixels.data[15] == 0xff);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_parse_stream(clear_raw_subcodec_bitmap,
                                       sizeof(clear_raw_subcodec_bitmap),
                                       &clear_stream) == LIBRDP_STATUS_OK);
    PCHECK(clear_stream.seq_number == 1);
    PCHECK(rdp_clearcodec_parse_composite_payload(clear_stream.payload,
                                                  clear_stream.payload_len,
                                                  &clear_payload) == LIBRDP_STATUS_OK);
    PCHECK(clear_payload.subcodec_len == 25);
    PCHECK(rdp_clearcodec_parse_subcodec(clear_payload.subcodec,
                                         clear_payload.subcodec_len,
                                         &clear_subcodec) == LIBRDP_STATUS_OK);
    PCHECK(clear_subcodec.x == 0 &&
           clear_subcodec.y == 0 &&
           clear_subcodec.width == 2 &&
           clear_subcodec.height == 2 &&
           clear_subcodec.bitmap_data_len == 12 &&
           clear_subcodec.subcodec_id == RDP_CLEARCODEC_SUBCODEC_RAW);
    {
        rdp_clearcodec_subcodec valid_clear_subcodec = clear_subcodec;

        PCHECK(rdp_clearcodec_parse_subcodec(clear_payload.subcodec,
                                             clear_payload.subcodec_len - 1u,
                                             &clear_subcodec) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&clear_subcodec,
                      &valid_clear_subcodec,
                      sizeof(clear_subcodec)) == 0);
    }
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_raw_subcodec_bitmap,
                                        sizeof(clear_raw_subcodec_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 1 &&
           clear_pixels.data[2] == 3 &&
           clear_pixels.data[4] == 4 &&
           clear_pixels.data[6] == 6 &&
           clear_pixels.data[8] == 7 &&
           clear_pixels.data[10] == 9 &&
           clear_pixels.data[12] == 10 &&
           clear_pixels.data[14] == 12);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_parse_stream(clear_rlex_subcodec_bitmap,
                                       sizeof(clear_rlex_subcodec_bitmap),
                                       &clear_stream) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clearcodec_parse_composite_payload(clear_stream.payload,
                                                  clear_stream.payload_len,
                                                  &clear_payload) == LIBRDP_STATUS_OK);
    PCHECK(clear_payload.subcodec_len == 24);
    PCHECK(rdp_clearcodec_parse_subcodec(clear_payload.subcodec,
                                         clear_payload.subcodec_len,
                                         &clear_subcodec) == LIBRDP_STATUS_OK);
    PCHECK(clear_subcodec.subcodec_id == RDP_CLEARCODEC_SUBCODEC_RLEX &&
           clear_subcodec.bitmap_data_len == 11);
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_rlex_subcodec_bitmap,
                                        sizeof(clear_rlex_subcodec_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 1 &&
           clear_pixels.data[1] == 2 &&
           clear_pixels.data[2] == 3 &&
           clear_pixels.data[4] == 4 &&
           clear_pixels.data[5] == 5 &&
           clear_pixels.data[6] == 6 &&
           clear_pixels.data[8] == 1 &&
           clear_pixels.data[12] == 4);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_nsc_subcodec_bitmap,
                                        sizeof(clear_nsc_subcodec_bitmap),
                                        1,
                                        1,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 4 &&
           clear_pixels.data[0] == 10 &&
           clear_pixels.data[1] == 10 &&
           clear_pixels.data[2] == 10 &&
           clear_pixels.data[3] == 0xff);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_band_miss_bitmap,
                                        sizeof(clear_band_miss_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[4] == 1 &&
           clear_pixels.data[5] == 2 &&
           clear_pixels.data[6] == 3 &&
           clear_pixels.data[12] == 4 &&
           clear_pixels.data[13] == 5 &&
           clear_pixels.data[14] == 6);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_band_hit_bitmap,
                                        sizeof(clear_band_hit_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 1 &&
           clear_pixels.data[1] == 2 &&
           clear_pixels.data[2] == 3 &&
           clear_pixels.data[8] == 4 &&
           clear_pixels.data[9] == 5 &&
           clear_pixels.data[10] == 6);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_missing_band_bitmap,
                                        sizeof(clear_missing_band_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.length == 16 &&
           clear_pixels.data[0] == 0 &&
           clear_pixels.data[8] == 0);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_glyph_store_bitmap,
                                        sizeof(clear_glyph_store_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 9 &&
           clear_pixels.data[1] == 8 &&
           clear_pixels.data[2] == 7 &&
           clear_pixels.data[15] == 0xff);
    PCHECK(rdp_clearcodec_parse_stream(clear_glyph_hit,
                                       sizeof(clear_glyph_hit),
                                       &clear_stream) == LIBRDP_STATUS_OK);
    PCHECK((clear_stream.flags & RDP_CLEARCODEC_FLAG_GLYPH_HIT) != 0 &&
           clear_stream.has_glyph_index &&
           clear_stream.payload_len == 0);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_glyph_hit,
                                        sizeof(clear_glyph_hit),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 9 &&
           clear_pixels.data[2] == 7 &&
           clear_pixels.data[12] == 9 &&
           clear_pixels.data[15] == 0xff);
    clear_saved_len = clear_pixels.length;
    PCHECK(clear_saved_len <= sizeof(clear_saved));
    memcpy(clear_saved, clear_pixels.data, clear_saved_len);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_glyph_hit,
                                        sizeof(clear_glyph_hit),
                                        2,
                                        1,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.length == 8 &&
           clear_pixels.data[0] == 9 &&
           clear_pixels.data[2] == 7 &&
           clear_pixels.data[7] == 0xff);
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_glyph_hit_after_reset,
                                        sizeof(clear_glyph_hit_after_reset),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_glyph_hit,
                                        sizeof(clear_glyph_hit),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.length == clear_saved_len &&
           memcmp(clear_pixels.data, clear_saved, clear_saved_len) == 0);
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_missing_glyph_hit,
                                        sizeof(clear_missing_glyph_hit),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_clearcodec_parse_stream(clear_max_glyph_hit,
                                       sizeof(clear_max_glyph_hit),
                                       &clear_stream) == LIBRDP_STATUS_OK);
    PCHECK(clear_stream.glyph_index == RDP_CLEARCODEC_GLYPH_STORAGE_ENTRIES - 1u);
    {
        rdp_clearcodec_stream valid_clear_stream = clear_stream;

        PCHECK(rdp_clearcodec_parse_stream(clear_bad_glyph_hit,
                                           sizeof(clear_bad_glyph_hit),
                                           &clear_stream) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&clear_stream, &valid_clear_stream, sizeof(clear_stream)) == 0);
    }
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_empty_payload,
                                        sizeof(clear_empty_payload),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_unknown_subcodec_bitmap,
                                        sizeof(clear_unknown_subcodec_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(clear_pixels.length == clear_saved_len &&
           memcmp(clear_pixels.data, clear_saved, clear_saved_len) == 0);
    PCHECK(rdp_clipboard_parse_packet(clip, sizeof(clip), &cb) == LIBRDP_STATUS_OK);
    PCHECK(cb.type == 1 && cb.flags == 2 && cb.payload_len == 3 && cb.payload[0] == 4);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_header(&dyn_response,
                                      RDP_CLIPBOARD_CB_MONITOR_READY,
                                      0,
                                      0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) ==
           LIBRDP_STATUS_OK);
    PCHECK(cb.type == RDP_CLIPBOARD_CB_MONITOR_READY && cb.payload_len == 0);
    PCHECK(rdp_clipboard_write_header(NULL, RDP_CLIPBOARD_CB_MONITOR_READY, 0, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_clipboard_parse_packet(clip_caps, sizeof(clip_caps), &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_capabilities(&cb, &cb_caps) == LIBRDP_STATUS_OK);
    PCHECK(cb_caps.count == 1 && cb_caps.has_general &&
           cb_caps.general.version == RDP_CLIPBOARD_CAPS_VERSION_2 &&
           cb_caps.general.general_flags == (RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES |
                                             RDP_CLIPBOARD_CAP_STREAM_FILECLIP_ENABLED |
                                             RDP_CLIPBOARD_CAP_CAN_LOCK_CLIPDATA));
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_capabilities(&dyn_response,
                                            RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES |
                                            RDP_CLIPBOARD_CAP_STREAM_FILECLIP_ENABLED) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(clip_caps) &&
           test_read_u16_le(dyn_response.data) == RDP_CLIPBOARD_CB_CLIP_CAPS &&
           test_read_u32_le(dyn_response.data + 4) == 16 &&
           test_read_u32_le(dyn_response.data + 20) ==
               (RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES | RDP_CLIPBOARD_CAP_STREAM_FILECLIP_ENABLED));
    PCHECK(rdp_clipboard_parse_packet(clip_format_long, sizeof(clip_format_long), &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_list(&cb, &cb_list) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_format_list_entry_count(&cb_list, 1, &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 4);
    PCHECK(rdp_clipboard_format_list_get_entry(&cb_list, 1, 0, &cb_entry) == LIBRDP_STATUS_OK);
    PCHECK(cb_entry.format_id == 0xc004u && cb_entry.name_len == 12 &&
           memcmp(cb_entry.name, "N\0a\0t\0i\0v\0e\0", 12) == 0);
    PCHECK(rdp_clipboard_format_list_get_entry(&cb_list, 1, 3, &cb_entry) == LIBRDP_STATUS_OK);
    PCHECK(cb_entry.format_id == 0x11u && cb_entry.name_len == 0);
    PCHECK(rdp_clipboard_format_list_get_entry(&cb_list, 1, 4, &cb_entry) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_clipboard_parse_packet(clip_format_short_ascii,
                                      sizeof(clip_format_short_ascii),
                                      &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_list(&cb, &cb_list) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_format_list_entry_count(&cb_list, 0, &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 1);
    PCHECK(rdp_clipboard_format_list_get_entry(&cb_list, 0, 0, &cb_entry) == LIBRDP_STATUS_OK);
    PCHECK(cb_entry.format_id == 0xc0aau && cb_entry.name_len == 6 &&
           memcmp(cb_entry.name, "Custom", 6) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_format_list_response(&dyn_response, 1) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 8 &&
           test_read_u16_le(dyn_response.data) == RDP_CLIPBOARD_CB_FORMAT_LIST_RESPONSE &&
           test_read_u16_le(dyn_response.data + 2) == RDP_CLIPBOARD_CB_RESPONSE_OK &&
           test_read_u32_le(dyn_response.data + 4) == 0);
    dyn_response.length = 0;
    cb_entry.format_id = RDP_CLIPBOARD_FORMAT_UNICODETEXT;
    cb_entry.name = NULL;
    cb_entry.name_len = 0;
    PCHECK(rdp_clipboard_write_format_list(&dyn_response, &cb_entry, 1, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_list(&cb, &cb_list) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_format_list_entry_count(&cb_list, 1, &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 1);
    PCHECK(rdp_clipboard_format_list_get_entry(&cb_list, 1, 0, &cb_entry) == LIBRDP_STATUS_OK);
    PCHECK(cb_entry.format_id == RDP_CLIPBOARD_FORMAT_UNICODETEXT && cb_entry.name_len == 0);
    PCHECK(rdp_clipboard_parse_packet(clip_data_request, sizeof(clip_data_request), &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_data_request(&cb, &cb_data_request) == LIBRDP_STATUS_OK);
    PCHECK(cb_data_request.format_id == RDP_CLIPBOARD_FORMAT_UNICODETEXT);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_format_data_request(&dyn_response,
                                                   RDP_CLIPBOARD_FORMAT_UNICODETEXT) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(clip_data_request) &&
           memcmp(dyn_response.data, clip_data_request, sizeof(clip_data_request)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_format_data_response(&dyn_response, 1, "abc", 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_data_response(&cb, &cb_data_response) == LIBRDP_STATUS_OK);
    PCHECK(cb_data_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_OK &&
           cb_data_response.data_len == 3 &&
           memcmp(cb_data_response.data, "abc", 3) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_format_data_response(&dyn_response, 0, NULL, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_data_response(&cb, &cb_data_response) == LIBRDP_STATUS_OK);
    PCHECK(cb_data_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_FAIL &&
           cb_data_response.data_len == 0);
    PCHECK(rdp_clipboard_write_format_data_response(&dyn_response, 0, "x", 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_clipboard_parse_packet(clip_file_size_request,
                                      sizeof(clip_file_size_request),
                                      &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_file_contents_request(&cb, &cb_file_request) == LIBRDP_STATUS_OK);
    PCHECK(cb_file_request.stream_id == 0x1122u &&
           cb_file_request.lindex == -1 &&
           cb_file_request.flags == RDP_CLIPBOARD_FILECONTENTS_SIZE &&
           cb_file_request.position == 0 &&
           cb_file_request.requested == 8 &&
           !cb_file_request.has_clip_data_id);
    PCHECK(rdp_clipboard_parse_packet(clip_file_range_request,
                                      sizeof(clip_file_range_request),
                                      &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_file_contents_request(&cb, &cb_file_request) == LIBRDP_STATUS_OK);
    PCHECK(cb_file_request.stream_id == 0x2233u &&
           cb_file_request.lindex == 2 &&
           cb_file_request.flags == RDP_CLIPBOARD_FILECONTENTS_RANGE &&
           cb_file_request.position == 0x0000000112345678ull &&
           cb_file_request.requested == 0x40 &&
           cb_file_request.has_clip_data_id &&
           cb_file_request.clip_data_id == 0x99);
    dyn_response.length = 0;
    error_info = 0x99u;
    PCHECK(rdp_clipboard_write_file_contents_request(&dyn_response,
                                                     0x2233u,
                                                     2,
                                                     RDP_CLIPBOARD_FILECONTENTS_RANGE,
                                                     0x0000000112345678ull,
                                                     0x40,
                                                     &error_info) == LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data, clip_file_range_request, sizeof(clip_file_range_request)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_file_contents_request(&dyn_response,
                                                     0x1122u,
                                                     -1,
                                                     RDP_CLIPBOARD_FILECONTENTS_SIZE,
                                                     0,
                                                     8,
                                                     NULL) == LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data, clip_file_size_request, sizeof(clip_file_size_request)) == 0);
    PCHECK(rdp_clipboard_write_file_contents_request(&dyn_response,
                                                     0x1122u,
                                                     -1,
                                                     RDP_CLIPBOARD_FILECONTENTS_SIZE,
                                                     1,
                                                     8,
                                                     NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_clipboard_parse_packet(clip_file_bad_request,
                                      sizeof(clip_file_bad_request),
                                      &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_file_contents_request(&cb, &cb_file_request) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_file_contents_response(&dyn_response, 1, 0x1122u, "data", 4) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_file_contents_response(&cb, &cb_file_response) == LIBRDP_STATUS_OK);
    PCHECK(cb_file_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_OK &&
           cb_file_response.stream_id == 0x1122u &&
           cb_file_response.data_len == 4 &&
           memcmp(cb_file_response.data, "data", 4) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_file_contents_response(&dyn_response, 0, 0x1122u, NULL, 0) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_file_contents_response(&cb, &cb_file_response) == LIBRDP_STATUS_OK);
    PCHECK(cb_file_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_FAIL &&
           cb_file_response.stream_id == 0x1122u &&
           cb_file_response.data_len == 0);
    {
        const uint8_t file_name[] = {'c', 0, 'l', 0, 'i', 0, 'p', 0, '.', 0, 't', 0, 'x', 0, 't', 0};
        rdp_clipboard_file_descriptor file_desc;

        memset(&file_desc, 0, sizeof(file_desc));
        file_desc.name_utf16 = file_name;
        file_desc.name_utf16_len = sizeof(file_name);
        file_desc.size = 0x0000000212345678ull;
        file_desc.attributes = RDP_CLIPBOARD_FILE_ATTRIBUTE_NORMAL;
        dyn_response.length = 0;
        PCHECK(rdp_clipboard_write_hdrop(&dyn_response, &file_desc, 1) == LIBRDP_STATUS_OK);
        PCHECK(dyn_response.length == RDP_CLIPBOARD_DROPFILES_HEADER_SIZE + sizeof(file_name) + 4u);
        PCHECK(test_read_u32_le(dyn_response.data) == RDP_CLIPBOARD_DROPFILES_HEADER_SIZE &&
               test_read_u32_le(dyn_response.data + 16) == 1 &&
               memcmp(dyn_response.data + RDP_CLIPBOARD_DROPFILES_HEADER_SIZE,
                      file_name,
                      sizeof(file_name)) == 0);
        dyn_response.length = 0;
        PCHECK(rdp_clipboard_write_file_group_descriptor_w(&dyn_response, &file_desc, 1) ==
               LIBRDP_STATUS_OK);
        PCHECK(dyn_response.length == 4u + RDP_CLIPBOARD_FILE_DESCRIPTORW_SIZE);
        PCHECK(test_read_u32_le(dyn_response.data) == 1 &&
               test_read_u32_le(dyn_response.data + 4) ==
                   (RDP_CLIPBOARD_FD_ATTRIBUTES | RDP_CLIPBOARD_FD_FILESIZE) &&
               test_read_u32_le(dyn_response.data + 40) == RDP_CLIPBOARD_FILE_ATTRIBUTE_NORMAL &&
               test_read_u32_le(dyn_response.data + 68) == 2u &&
               test_read_u32_le(dyn_response.data + 72) == 0x12345678u &&
               memcmp(dyn_response.data + 76, file_name, sizeof(file_name)) == 0);
        file_desc.name_utf16_len--;
        dyn_response.length = 0;
        PCHECK(rdp_clipboard_write_hdrop(&dyn_response, &file_desc, 1) ==
               LIBRDP_STATUS_INVALID_ARGUMENT);
    }
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_lock(&dyn_response, 0x99887766u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_lock(&cb, &cb_lock) == LIBRDP_STATUS_OK);
    PCHECK(cb_lock.clip_data_id == 0x99887766u);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_unlock(&dyn_response, 0x66554433u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_unlock(&cb, &cb_lock) == LIBRDP_STATUS_OK);
    PCHECK(cb_lock.clip_data_id == 0x66554433u);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_monitor_ready(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 8 &&
           test_read_u16_le(dyn_response.data) == RDP_CLIPBOARD_CB_MONITOR_READY &&
           test_read_u32_le(dyn_response.data + 4) == 0);
    PCHECK(rdp_mcs_parse_send_data_indication(indication_pdu, sizeof(indication_pdu), &indication) ==
           LIBRDP_STATUS_OK);
    PCHECK(indication.initiator == 1004 && indication.channel_id == RDP_MCS_GLOBAL_CHANNEL_ID);
    PCHECK(indication.payload_len == 4 && indication.payload[0] == 1 && indication.payload[3] == 4);
    PCHECK(rdp_mcs_parse_send_data_indication(indication_pdu, sizeof(indication_pdu) - 1u, &indication) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_credssp_begin(false, &cred_state) == LIBRDP_STATUS_OK && cred_state == RDP_CREDSSP_DISABLED);
    PCHECK(rdp_credssp_begin(true, &cred_state) == LIBRDP_STATUS_OK && cred_state == RDP_CREDSSP_NEGOTIATING);
    PCHECK(rdp_credssp_write_ntlm_negotiate(&ntlm_negotiate, "host", "dom") == LIBRDP_STATUS_OK);
    PCHECK(ntlm_negotiate.length == 47);
    PCHECK(memcmp(ntlm_negotiate.data, "NTLMSSP", 7) == 0);
    PCHECK(ntlm_negotiate.data[8] == 1 && ntlm_negotiate.data[16] == 3 && ntlm_negotiate.data[24] == 4);
    PCHECK(memcmp(ntlm_negotiate.data + 40, "DOMHOST", 7) == 0);
    PCHECK(rdp_credssp_write_spnego_ntlm_negotiate(&spnego_negotiate,
                                                   ntlm_negotiate.data,
                                                   ntlm_negotiate.length) == LIBRDP_STATUS_OK);
    PCHECK(spnego_negotiate.length > ntlm_negotiate.length && spnego_negotiate.data[0] == 0x60);
    PCHECK(rdp_credssp_write_ts_request(&ts_request,
                                        6,
                                        spnego_negotiate.data,
                                        spnego_negotiate.length,
                                        NULL,
                                        0,
                                        NULL,
                                        0,
                                        credssp_client_nonce,
                                        sizeof(credssp_client_nonce)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_parse_ts_request(ts_request.data, ts_request.length, &parsed_ts) == LIBRDP_STATUS_OK);
    PCHECK(parsed_ts.version == 6 && parsed_ts.nego_token_len == spnego_negotiate.length);
    PCHECK(memcmp(parsed_ts.nego_token, spnego_negotiate.data, spnego_negotiate.length) == 0);
    PCHECK(parsed_ts.client_nonce_len == sizeof(credssp_client_nonce));
    PCHECK(memcmp(parsed_ts.client_nonce, credssp_client_nonce, sizeof(credssp_client_nonce)) == 0);
    PCHECK(rdp_credssp_parse_ts_request(ts_request.data, ts_request.length - 1u, &parsed_ts) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_credssp_write_negotiate_request(&nla_request, "host", "dom") == LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_parse_ts_request(nla_request.data, nla_request.length, &parsed_ts) == LIBRDP_STATUS_OK);
    PCHECK(parsed_ts.version == 6 && parsed_ts.nego_token_len > 0);
    PCHECK(rdp_credssp_parse_ntlm_challenge(ntlm_challenge_token,
                                            sizeof(ntlm_challenge_token),
                                            &ntlm_challenge) == LIBRDP_STATUS_OK);
    PCHECK(ntlm_challenge.flags == 0x04030201u);
    PCHECK(ntlm_challenge.server_challenge[0] == 0x10 && ntlm_challenge.server_challenge[7] == 0x17);
    PCHECK(ntlm_challenge.target_name_len == 4 && ntlm_challenge.target_info_len == 8);
    PCHECK(rdp_credssp_extract_ntlm_challenge(wrapped_ntlm_challenge,
                                              sizeof(wrapped_ntlm_challenge),
                                              &extracted_ntlm,
                                              &extracted_ntlm_len) == LIBRDP_STATUS_OK);
    PCHECK(extracted_ntlm_len == sizeof(ntlm_challenge_token));
    PCHECK(rdp_credssp_parse_ntlm_challenge(extracted_ntlm, extracted_ntlm_len, &ntlm_challenge) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_parse_ntlm_challenge(ntlm_challenge_token,
                                            sizeof(ntlm_challenge_token) - 1u,
                                            &ntlm_challenge) == LIBRDP_STATUS_PROTOCOL_ERROR);
    memset(&ntlm_v2_challenge, 0, sizeof(ntlm_v2_challenge));
    ntlm_v2_challenge.flags = 0xe2888235u;
    memcpy(ntlm_v2_challenge.server_challenge, ntlm_v2_server_challenge, sizeof(ntlm_v2_server_challenge));
    ntlm_v2_challenge.target_name = ntlm_v2_target_name;
    ntlm_v2_challenge.target_name_len = sizeof(ntlm_v2_target_name);
    ntlm_v2_challenge.target_info = ntlm_v2_target_info;
    ntlm_v2_challenge.target_info_len = sizeof(ntlm_v2_target_info);
    PCHECK(rdp_credssp_write_ntlm_challenge(&ntlm_challenge_written, &ntlm_v2_challenge) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_parse_ntlm_challenge(ntlm_challenge_written.data,
                                            ntlm_challenge_written.length,
                                            &ntlm_challenge) == LIBRDP_STATUS_OK);
    PCHECK(ntlm_challenge.flags == ntlm_v2_challenge.flags);
    PCHECK(memcmp(ntlm_challenge.server_challenge,
                  ntlm_v2_challenge.server_challenge,
                  sizeof(ntlm_challenge.server_challenge)) == 0);
    PCHECK(rdp_credssp_write_spnego_ntlm_challenge(&spnego_challenge_written,
                                                   ntlm_challenge_written.data,
                                                   ntlm_challenge_written.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_extract_ntlm_challenge(spnego_challenge_written.data,
                                              spnego_challenge_written.length,
                                              &extracted_ntlm,
                                              &extracted_ntlm_len) == LIBRDP_STATUS_OK);
    PCHECK(extracted_ntlm_len == ntlm_challenge_written.length);
    ntlm_auth_status = rdp_credssp_write_ntlm_authenticate(&ntlm_authenticate,
                                                           &ntlm_v2_challenge,
                                                           "user",
                                                           "SecREt01",
                                                           "DOMAIN",
                                                           "COMPUTER",
                                                           0x01c334b736d39000ull,
                                                           ntlm_v2_client_challenge,
                                                           ntlm_v2_session_key,
                                                           &ntlm_auth_result);
    if (ntlm_auth_status == LIBRDP_STATUS_UNSUPPORTED)
    {
        PCHECK(ntlm_authenticate.length == 0);
    }
    else
    {
        PCHECK(ntlm_auth_status == LIBRDP_STATUS_OK);
        PCHECK(ntlm_authenticate.length > 88);
        PCHECK(memcmp(ntlm_authenticate.data, "NTLMSSP", 7) == 0);
        PCHECK(test_read_u32_le(ntlm_authenticate.data + 8) == 3);
        lm_len = test_read_u16_le(ntlm_authenticate.data + 12);
        lm_offset = test_read_u32_le(ntlm_authenticate.data + 16);
        nt_len = test_read_u16_le(ntlm_authenticate.data + 20);
        nt_offset = test_read_u32_le(ntlm_authenticate.data + 24);
        key_len = test_read_u16_le(ntlm_authenticate.data + 52);
        key_offset = test_read_u32_le(ntlm_authenticate.data + 56);
        PCHECK(test_read_u32_le(ntlm_authenticate.data + 60) == ntlm_auth_result.flags);
        PCHECK(lm_len == sizeof(ntlm_v2_expected_lm));
        PCHECK(nt_len > sizeof(ntlm_v2_expected_proof));
        PCHECK(key_len == sizeof(ntlm_v2_session_key));
        PCHECK((size_t)lm_offset + lm_len <= ntlm_authenticate.length);
        PCHECK((size_t)nt_offset + nt_len <= ntlm_authenticate.length);
        PCHECK((size_t)key_offset + key_len <= ntlm_authenticate.length);
        PCHECK(memcmp(ntlm_authenticate.data + lm_offset, ntlm_v2_expected_lm, sizeof(ntlm_v2_expected_lm)) == 0);
        PCHECK(memcmp(ntlm_authenticate.data + nt_offset,
                      ntlm_v2_expected_proof,
                      sizeof(ntlm_v2_expected_proof)) == 0);
        PCHECK(memcmp(ntlm_authenticate.data + key_offset,
                      ntlm_v2_expected_encrypted_key,
                      sizeof(ntlm_v2_expected_encrypted_key)) == 0);
        PCHECK(memcmp(ntlm_auth_result.session_key, ntlm_v2_session_key, sizeof(ntlm_v2_session_key)) == 0);
        PCHECK(memcmp(ntlm_authenticate.data + key_offset, ntlm_v2_session_key, sizeof(ntlm_v2_session_key)) != 0);
        PCHECK(rdp_credssp_parse_ntlm_authenticate(ntlm_authenticate.data,
                                                   ntlm_authenticate.length,
                                                   &parsed_ntlm_authenticate) == LIBRDP_STATUS_OK);
        PCHECK(parsed_ntlm_authenticate.nt_response_len == nt_len);
        PCHECK(rdp_credssp_verify_ntlm_authenticate(ntlm_authenticate.data,
                                                    ntlm_authenticate.length,
                                                    &ntlm_v2_challenge,
                                                    "USER",
                                                    "SecREt01",
                                                    &server_auth_result) == LIBRDP_STATUS_OK);
        PCHECK(memcmp(server_auth_result.session_key,
                      ntlm_v2_session_key,
                      sizeof(ntlm_v2_session_key)) == 0);
        PCHECK(rdp_credssp_verify_ntlm_authenticate(ntlm_authenticate.data,
                                                    ntlm_authenticate.length,
                                                    &ntlm_v2_challenge,
                                                    "other",
                                                    "SecREt01",
                                                    &failed_auth_result) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(rdp_credssp_write_spnego_ntlm_authenticate(&spnego_authenticate,
                                                          ntlm_authenticate.data,
                                                          ntlm_authenticate.length) == LIBRDP_STATUS_OK);
        PCHECK(spnego_authenticate.length > ntlm_authenticate.length && spnego_authenticate.data[0] == 0xa1);
        PCHECK(rdp_credssp_ntlm_security_init(&ntlm_security, &ntlm_auth_result) == LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_ntlm_wrap(&ntlm_security, "data", 4, &ntlm_wrapped) == LIBRDP_STATUS_OK);
        PCHECK(ntlm_wrapped.length == 20);
        PCHECK(test_read_u32_le(ntlm_wrapped.data) == 1);
        PCHECK(test_read_u32_le(ntlm_wrapped.data + 12) == 0);
        PCHECK(memcmp(ntlm_wrapped.data, ntlm_expected_wrapped_data, sizeof(ntlm_expected_wrapped_data)) == 0);
        PCHECK(memcmp(ntlm_wrapped.data + 16, "data", 4) != 0);
        PCHECK(ntlm_security.send_seq == 1);
        PCHECK(rdp_credssp_encrypt_public_key_hash(&ntlm_security,
                                                   credssp_client_nonce,
                                                   sizeof(credssp_client_nonce),
                                                   credssp_public_key,
                                                   sizeof(credssp_public_key),
                                                   &pub_key_auth) == LIBRDP_STATUS_OK);
        PCHECK(pub_key_auth.length == 48 && ntlm_security.send_seq == 2);
        server_security = ntlm_security;
        memcpy(server_security.client_signing_key, ntlm_security.server_signing_key, sizeof(server_security.client_signing_key));
        server_security.send_rc4 = ntlm_security.recv_rc4;
        server_security.send_seq = 0;
        PCHECK(test_sha256_three((const uint8_t*)"CredSSP Server-To-Client Binding Hash",
                                 sizeof("CredSSP Server-To-Client Binding Hash"),
                                 credssp_client_nonce,
                                 sizeof(credssp_client_nonce),
                                 credssp_public_key,
                                 sizeof(credssp_public_key),
                                 server_hash));
        PCHECK(rdp_credssp_ntlm_wrap(&server_security,
                                     server_hash,
                                     sizeof(server_hash),
                                     &server_pub_key_auth) == LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_verify_public_key_hash(&ntlm_security,
                                                  credssp_client_nonce,
                                                  sizeof(credssp_client_nonce),
                                                  credssp_public_key,
                                                  sizeof(credssp_public_key),
                                                  server_pub_key_auth.data,
                                                  server_pub_key_auth.length) == LIBRDP_STATUS_OK);
        server_security = ntlm_security;
        memcpy(server_security.client_signing_key, ntlm_security.server_signing_key, sizeof(server_security.client_signing_key));
        server_security.send_rc4 = ntlm_security.recv_rc4;
        server_security.send_seq = ntlm_security.recv_seq;
        PCHECK(rdp_credssp_ntlm_wrap(&server_security, "peer", 4, &ntlm_wrapped) == LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_ntlm_unwrap(&ntlm_security,
                                       ntlm_wrapped.data + 20,
                                       ntlm_wrapped.length - 20,
                                       &ntlm_unwrapped) == LIBRDP_STATUS_OK);
        PCHECK(ntlm_unwrapped.length == 4 && memcmp(ntlm_unwrapped.data, "peer", 4) == 0);
        PCHECK(rdp_credssp_write_password_credentials(&ts_credentials,
                                                      "DOMAIN",
                                                      "user",
                                                      "SecREt01") == LIBRDP_STATUS_OK);
        PCHECK(ts_credentials.length > 32 && ts_credentials.data[0] == 0x30);
        PCHECK(rdp_credssp_encrypt_password_credentials(&ntlm_security,
                                                        "DOMAIN",
                                                        "user",
                                                        "SecREt01",
                                                        &auth_info) == LIBRDP_STATUS_OK);
        PCHECK(auth_info.length == ts_credentials.length + 16u);
        PCHECK(test_read_u32_le(auth_info.data) == 1);
        PCHECK(test_read_u32_le(auth_info.data + 12) == 2);
        PCHECK(memcmp(auth_info.data + 16, ts_credentials.data, ts_credentials.length < 8u ? ts_credentials.length : 8u) !=
               0);
        PCHECK(rdp_credssp_ntlm_security_init(&client_sequence_security, &ntlm_auth_result) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_ntlm_server_security_init(&server_sequence_security, &server_auth_result) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_encrypt_public_key_hash(&client_sequence_security,
                                                   credssp_client_nonce,
                                                   sizeof(credssp_client_nonce),
                                                   credssp_public_key,
                                                   sizeof(credssp_public_key),
                                                   &client_sequence_pub_key_auth) == LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_verify_client_public_key_hash(&server_sequence_security,
                                                         credssp_client_nonce,
                                                         sizeof(credssp_client_nonce),
                                                         credssp_public_key,
                                                         sizeof(credssp_public_key),
                                                         client_sequence_pub_key_auth.data,
                                                         client_sequence_pub_key_auth.length) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_encrypt_server_public_key_hash(&server_sequence_security,
                                                          credssp_client_nonce,
                                                          sizeof(credssp_client_nonce),
                                                          credssp_public_key,
                                                          sizeof(credssp_public_key),
                                                          &server_sequence_pub_key_auth) == LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_verify_public_key_hash(&client_sequence_security,
                                                  credssp_client_nonce,
                                                  sizeof(credssp_client_nonce),
                                                  credssp_public_key,
                                                  sizeof(credssp_public_key),
                                                  server_sequence_pub_key_auth.data,
                                                  server_sequence_pub_key_auth.length) == LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_encrypt_password_credentials(&client_sequence_security,
                                                        "DOMAIN",
                                                        "user",
                                                        "SecREt01",
                                                        &client_sequence_auth_info) == LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_decrypt_password_credentials(&server_sequence_security,
                                                        client_sequence_auth_info.data,
                                                        client_sequence_auth_info.length) == LIBRDP_STATUS_OK);
    }
    rdp_buffer_free(&nla_request);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_free(&channel_packet);
    rdp_buffer_free(&license_payload);
    rdp_buffer_free(&license_packet);
    rdp_buffer_free(&ts_request);
    rdp_buffer_free(&auth_info);
    rdp_buffer_free(&ts_credentials);
    rdp_buffer_free(&client_sequence_auth_info);
    rdp_buffer_free(&server_sequence_pub_key_auth);
    rdp_buffer_free(&client_sequence_pub_key_auth);
    rdp_buffer_free(&server_pub_key_auth);
    rdp_buffer_free(&pub_key_auth);
    rdp_buffer_free(&ntlm_unwrapped);
    rdp_buffer_free(&ntlm_wrapped);
    rdp_buffer_free(&spnego_authenticate);
    rdp_buffer_free(&spnego_challenge_written);
    rdp_buffer_free(&spnego_negotiate);
    rdp_buffer_free(&ntlm_authenticate);
    rdp_buffer_free(&ntlm_challenge_written);
    rdp_buffer_free(&ntlm_negotiate);
    rdp_buffer_free(&x509_chain);
    rdp_buffer_free(&generated_server_certificate);
    EVP_PKEY_free(generated_server_key);
    rdp_clearcodec_context_free(&clear_context);
    rdp_nscodec_context_free(&nscodec_context);
    rdp_graphics_decompressor_free(&graphics_decompressor);
    OPENSSL_cleanse(&failed_auth_result, sizeof(failed_auth_result));
    OPENSSL_cleanse(&server_auth_result, sizeof(server_auth_result));
    OPENSSL_cleanse(&client_sequence_security, sizeof(client_sequence_security));
    OPENSSL_cleanse(&server_sequence_security, sizeof(server_sequence_security));
    rdp_buffer_free(&graphics_reset_pdu);
    rdp_buffer_free(&nscodec_capability_buffer);
    rdp_buffer_free(&nscodec_pixels);
    rdp_buffer_free(&planar_pixels);
    rdp_buffer_free(&graphics_decoded);
    rdp_buffer_free(&rfx_bad_stream);
    rdp_buffer_free(&rfx_stream);
    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_free(&client_suppress_output);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_free(&decoded_pointer);
    rdp_buffer_free(&clear_pixels);
    rdp_buffer_free(&client_mouse_input);
    rdp_buffer_free(&client_keyboard_input);
    rdp_buffer_free(&client_font_list);
    rdp_buffer_free(&client_persistent_keys);
    rdp_buffer_free(&client_control);
    rdp_buffer_free(&client_sync);
    rdp_buffer_free(&expected_cipher);
    rdp_bulk_decompressor_free(&bulk_decompressor);
    rdp_buffer_free(&bulk_decoded);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_free(&encrypted_fastpath);
    rdp_buffer_free(&plain_security);
    rdp_buffer_free(&unwrapped_pdu);
    rdp_buffer_free(&protected_pdu);
    rdp_buffer_free(&plain_info_body);
    rdp_buffer_free(&encrypted_info);
    rdp_buffer_free(&confirm_active);
    rdp_buffer_free(&encrypted);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security);
    return 0;
}

/*
 * Coverage: validates device redirection capabilities, announcements, and IRP
 * parsing for ID lifetime and malformed request boundaries.
 */
