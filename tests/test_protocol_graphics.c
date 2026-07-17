/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: protocol graphics conformance vectors.
 * Coverage: desktop composition, composited remoting, video redirection, optimized video, and GDI order fixtures.
 * Bug classes: malformed graphics PDUs, cache bounds, render tree lifetime, order validation, and coordinate overflow.
 * Determinism: fixtures are synthetic and do not use external services.
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
#include "graphics/gdi_backend.h"
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
#include <librdp/surface.h>

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

static librdp_status test_append_u64_le(rdp_buffer* buffer, uint64_t value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, (uint32_t)(value & 0xffffffffu));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, (uint32_t)(value >> 32u));
    return status;
}

/*
 * Coverage: desktop composition operation headers, toggle orders, surface
 * object metadata, association records, opaque payloads, and lifecycle reset
 * vectors that feed the compositor path.
 * Bug classes: malformed order length, coordinate overflow, stale resource
 * identity, payload truncation, and cleanup ordering regressions.
 */
static int test_desktop_composition_channel(void)
{
    const uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef};
    rdp_desktop_composition_header header;
    rdp_desktop_composition_toggle toggle;
    rdp_desktop_composition_lsurface lsurface;
    rdp_desktop_composition_surfobj surfobj;
    rdp_desktop_composition_assoc assoc;
    rdp_desktop_composition_u64_order u64_order;
    rdp_desktop_composition_u32_order u32_order;
    rdp_desktop_composition_opaque opaque;
    rdp_buffer buffer;

    rdp_buffer_init(&buffer);

    PCHECK(rdp_desktop_composition_operation_valid(RDP_DESKTOP_COMPOSITION_OP_TOGGLE));
    PCHECK(!rdp_desktop_composition_operation_valid(0));
    PCHECK(rdp_desktop_composition_write_header(&buffer,
                                                RDP_DESKTOP_COMPOSITION_OP_TOGGLE,
                                                1u) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 4u &&
           buffer.data[0] == RDP_DESKTOP_COMPOSITION_ALTSEC_HEADER &&
           buffer.data[1] == RDP_DESKTOP_COMPOSITION_OP_TOGGLE &&
           test_read_u16_le(buffer.data + 2u) == 1u);
    buffer.length = 0;
    PCHECK(rdp_desktop_composition_write_header(&buffer, 0xffu, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    memset(&header, 0x5a, sizeof(header));
    {
        rdp_desktop_composition_header valid_header = header;

        PCHECK(rdp_desktop_composition_parse_header(payload, sizeof(payload), &header) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&header, &valid_header, sizeof(header)) == 0);
    }

    PCHECK(rdp_desktop_composition_write_toggle(&buffer,
                                                RDP_DESKTOP_COMPOSITION_EVENT_COMPOSITION_ON) ==
           LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 5u);
    PCHECK(rdp_desktop_composition_parse_toggle(buffer.data, buffer.length, &toggle) ==
           LIBRDP_STATUS_OK);
    PCHECK(toggle.header.size == 1u && toggle.event_type == RDP_DESKTOP_COMPOSITION_EVENT_COMPOSITION_ON);
    {
        rdp_desktop_composition_toggle valid_toggle = toggle;

        buffer.data[4] = 0xffu;
        PCHECK(rdp_desktop_composition_parse_toggle(buffer.data, buffer.length, &toggle) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&toggle, &valid_toggle, sizeof(toggle)) == 0);
    }
    buffer.length = 0;
    PCHECK(rdp_buffer_append_u8(&buffer, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_desktop_composition_write_toggle(&buffer, 0xffu) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 1u && buffer.data[0] == 0xa5u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_desktop_composition_write_lsurface(&buffer,
                                                  1,
                                                  RDP_DESKTOP_COMPOSITION_LSURFACE_COMPOSE_ONCE |
                                                      RDP_DESKTOP_COMPOSITION_LSURFACE_REDIRECTION,
                                                  0x0102030405060708ull,
                                                  1024,
                                                  768,
                                                  0x1112131415161718ull,
                                                  0x2122232425262728ull) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 38u);
    PCHECK(rdp_desktop_composition_parse_lsurface(buffer.data, buffer.length, &lsurface) ==
           LIBRDP_STATUS_OK);
    PCHECK(lsurface.create == 1u &&
           lsurface.flags == (RDP_DESKTOP_COMPOSITION_LSURFACE_COMPOSE_ONCE |
                              RDP_DESKTOP_COMPOSITION_LSURFACE_REDIRECTION) &&
           lsurface.surface_id == 0x0102030405060708ull &&
           lsurface.width == 1024u &&
           lsurface.height == 768u &&
           lsurface.window_id == 0x1112131415161718ull &&
           lsurface.luid == 0x2122232425262728ull);
    {
        rdp_desktop_composition_lsurface valid_lsurface = lsurface;

        buffer.data[14] = 0u;
        buffer.data[15] = 0u;
        buffer.data[16] = 0u;
        buffer.data[17] = 0u;
        PCHECK(rdp_desktop_composition_parse_lsurface(buffer.data, buffer.length, &lsurface) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&lsurface, &valid_lsurface, sizeof(lsurface)) == 0);
    }
    buffer.length = 0;
    PCHECK(rdp_desktop_composition_write_lsurface(&buffer, 1, 0x80, 1, 1, 1, 1, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 0u);
    PCHECK(rdp_desktop_composition_write_lsurface(&buffer, 1, 0, 1, 0, 1, 1, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 0u);
    PCHECK(rdp_desktop_composition_write_lsurface(&buffer,
                                                  0,
                                                  0,
                                                  0x0102030405060708ull,
                                                  0,
                                                  0,
                                                  0x1112131415161718ull,
                                                  0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_desktop_composition_parse_lsurface(buffer.data, buffer.length, &lsurface) ==
           LIBRDP_STATUS_OK);
    PCHECK(lsurface.create == 0u &&
           lsurface.width == 0u &&
           lsurface.height == 0u &&
           lsurface.surface_id == 0x0102030405060708ull);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_desktop_composition_write_surfobj(&buffer,
                                                 0x8f,
                                                 32,
                                                 0x3132333435363738ull,
                                                 64,
                                                 32) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 26u);
    PCHECK(rdp_desktop_composition_parse_surfobj(buffer.data, buffer.length, &surfobj) ==
           LIBRDP_STATUS_OK);
    PCHECK(surfobj.cache_id == 0x8fu &&
           surfobj.surface_bpp == 32u &&
           surfobj.surface_id == 0x3132333435363738ull &&
           surfobj.width == 64u &&
           surfobj.height == 32u);
    {
        rdp_desktop_composition_surfobj valid_surfobj = surfobj;

        buffer.data[18] = 0u;
        buffer.data[19] = 0u;
        buffer.data[20] = 0u;
        buffer.data[21] = 0u;
        PCHECK(rdp_desktop_composition_parse_surfobj(buffer.data, buffer.length, &surfobj) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&surfobj, &valid_surfobj, sizeof(surfobj)) == 0);
        buffer.data[18] = 64u;
        buffer.data[9] = 1u;
        PCHECK(rdp_desktop_composition_parse_surfobj(buffer.data, buffer.length, &surfobj) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&surfobj, &valid_surfobj, sizeof(surfobj)) == 0);
    }
    buffer.length = 0;
    PCHECK(rdp_desktop_composition_write_surfobj(&buffer, 0x8f, 32, 0x3132333435363738ull, 0, 32) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 0u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_desktop_composition_write_assoc(&buffer,
                                               1,
                                               0x4142434445464748ull,
                                               0x5152535455565758ull) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 21u);
    PCHECK(rdp_desktop_composition_parse_assoc(buffer.data, buffer.length, &assoc) ==
           LIBRDP_STATUS_OK);
    PCHECK(assoc.associate == 1u &&
           assoc.logical_surface_id == 0x4142434445464748ull &&
           assoc.redirection_surface_id == 0x5152535455565758ull);
    {
        rdp_desktop_composition_assoc valid_assoc = assoc;

        buffer.data[4] = 2u;
        PCHECK(rdp_desktop_composition_parse_assoc(buffer.data, buffer.length, &assoc) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&assoc, &valid_assoc, sizeof(assoc)) == 0);
    }
    buffer.length = 0;
    PCHECK(rdp_buffer_append_u8(&buffer, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_desktop_composition_write_assoc(&buffer, 2, 1, 2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 1u && buffer.data[0] == 0xa5u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_desktop_composition_write_compref(&buffer, 0x6162636465666768ull) ==
           LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 12u);
    PCHECK(rdp_desktop_composition_parse_compref(buffer.data, buffer.length, &u64_order) ==
           LIBRDP_STATUS_OK);
    PCHECK(u64_order.value == 0x6162636465666768ull);
    {
        rdp_desktop_composition_u64_order valid_u64_order = u64_order;

        PCHECK(rdp_desktop_composition_parse_compref(buffer.data,
                                                     buffer.length - 1u,
                                                     &u64_order) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&u64_order, &valid_u64_order, sizeof(u64_order)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_desktop_composition_write_switch_surfobj(&buffer, 0x44u) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 8u);
    PCHECK(rdp_desktop_composition_parse_switch_surfobj(buffer.data, buffer.length, &u32_order) ==
           LIBRDP_STATUS_OK);
    PCHECK(u32_order.value == 0x44u);
    {
        rdp_desktop_composition_u32_order valid_u32_order = u32_order;

        PCHECK(rdp_desktop_composition_parse_switch_surfobj(buffer.data,
                                                            buffer.length - 1u,
                                                            &u32_order) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&u32_order, &valid_u32_order, sizeof(u32_order)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_desktop_composition_write_opaque(&buffer,
                                                RDP_DESKTOP_COMPOSITION_OP_FLUSH_COMPOSE_ONCE,
                                                payload,
                                                sizeof(payload)) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 8u);
    PCHECK(rdp_desktop_composition_parse_opaque(buffer.data, buffer.length, &opaque) ==
           LIBRDP_STATUS_OK);
    PCHECK(opaque.header.operation == RDP_DESKTOP_COMPOSITION_OP_FLUSH_COMPOSE_ONCE &&
           opaque.payload_len == sizeof(payload) &&
           memcmp(opaque.payload, payload, sizeof(payload)) == 0);
    {
        rdp_desktop_composition_opaque valid_opaque = opaque;

        buffer.data[2] = 0xffu;
        PCHECK(rdp_desktop_composition_parse_opaque(buffer.data, buffer.length, &opaque) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&opaque, &valid_opaque, sizeof(opaque)) == 0);
    }
    buffer.length = 0;
    PCHECK(rdp_buffer_append_u8(&buffer, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_desktop_composition_write_opaque(&buffer, 0xffu, payload, sizeof(payload)) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 1u && buffer.data[0] == 0xa5u);

    rdp_buffer_free(&buffer);
    return 0;
}

/*
 * Coverage: validates composited remoting command streams, render-tree
 * mutations, object lifetime, and damage invalidation vectors.
 */
static int test_composited_remoting_channel(void)
{
    const uint8_t color[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x3f};
    uint8_t surfaces[RDP_COMPOSITED_TEXTURE_SLOT_COUNT * RDP_COMPOSITED_TEXTURE_SLOT_BYTES] = {0};
    uint32_t versions[1] = {RDP_COMPOSITED_PROTOCOL_VERSION};
    uint32_t glyphs[3] = {0x21, 0x22, 0x23};
    rdp_composited_control control;
    rdp_composited_version_reply reply;
    rdp_composited_resource_order resource;
    rdp_composited_duplicate_handle duplicate;
    rdp_composited_u32_target_order u32_order;
    rdp_composited_u64_target_order u64_order;
    rdp_composited_target_order target_order;
    rdp_composited_window_node_bounds bounds_order;
    rdp_composited_window_node_clip clip_order;
    rdp_composited_window_node_source_modifications source_order;
    rdp_composited_margins_order margins_order;
    rdp_composited_color_order color_order;
    rdp_composited_rect_order rect_order;
    rdp_composited_target_window_settings window_settings;
    rdp_composited_render_data render_data;
    rdp_composited_bitmap_pixels bitmap_pixels;
    rdp_composited_bitmap_compressed_pixels compressed_pixels;
    rdp_composited_target_capture_bits capture_bits;
    rdp_composited_meta_capture_bits meta_capture_bits;
    rdp_composited_window_node_create window_node;
    rdp_composited_target_create target;
    rdp_composited_glyph_run glyph_run;
    rdp_composited_gdi_sprite_bitmap sprite;
    rdp_composited_gdi_surface_update surface_update;
    rdp_composited_gdi_dirty dirty;
    rdp_composited_meta_target meta;
    rdp_composited_batch_reader reader;
    rdp_composited_channel_message message;
    rdp_composited_render_tree tree;
    rdp_composited_resolved_view view;
    rdp_composited_render_invalidation collected_invalidations[4];
    const rdp_composited_render_resource* render_resource = NULL;
    const rdp_composited_render_invalidation* invalidation = NULL;
    const rdp_composited_rect_i rect = {1, 2, 301, 402};
    const rdp_composited_rect_i client_rect = {4, 5, 290, 380};
    const rdp_composited_rect_i content_rect = {7, 8, 280, 360};
    const rdp_composited_margins_i margins = {9, 10, 11, 12};
    const uint32_t render_words[3] = {0x01020304u, 0x05060708u, 0x090a0b0cu};
    const uint8_t bitmap_raw[16] = {
        0x10, 0x20, 0x30, 0xff, 0x11, 0x21, 0x31, 0xff,
        0x12, 0x22, 0x32, 0xff, 0x13, 0x23, 0x33, 0xff
    };
    const uint8_t bitmap_indexed[4] = {0, 1, 0, 0};
    const uint8_t bitmap_palette[8] = {0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff};
    const uint8_t compressed_bitmap[8] = {0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a};
    const uint8_t bad_composited_message[4] = {0};
    uint8_t update_param[40] = {0};
    rdp_buffer buffer;
    rdp_buffer batch;
    rdp_buffer wrapped;
    uint32_t i = 0;
    uint32_t before_invalidations = 0;
    uint32_t before_commands = 0;
    uint32_t collected_count = 0;
    uint32_t latest_invalidation = 0;

    rdp_composited_render_tree_init(&tree);
    rdp_composited_render_tree_reset(&tree);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&batch);
    rdp_buffer_init(&wrapped);

    PCHECK(rdp_composited_control_code_valid(RDP_COMPOSITED_CONTROL_OPEN_CHANNEL));
    PCHECK(!rdp_composited_control_code_valid(0x08u));
    PCHECK(rdp_composited_channel_command_known(RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UPDATE_SURFACE));
    PCHECK(rdp_composited_notification_code_valid(RDP_COMPOSITED_MSG_VERSION_REPLY));

    PCHECK(rdp_composited_write_control_fixed(&buffer,
                                              RDP_COMPOSITED_CONTROL_VERSION_REQUEST,
                                              0,
                                              0) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 16u);
    PCHECK(rdp_composited_parse_control(buffer.data, buffer.length, &control) == LIBRDP_STATUS_OK);
    PCHECK(control.control_code == RDP_COMPOSITED_CONTROL_VERSION_REQUEST &&
           control.message_size == 16u);
    buffer.data[4] = 0xffu;
    PCHECK(rdp_composited_parse_control(buffer.data, buffer.length, &control) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    PCHECK(rdp_buffer_append_u8(&buffer, 0x5au) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_write_control_fixed(&buffer,
                                              RDP_COMPOSITED_CONTROL_DATA_ON_CHANNEL,
                                              0,
                                              0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 1u && buffer.data[0] == 0x5au);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_version_reply(&buffer, versions, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_control(buffer.data, buffer.length, &control) == LIBRDP_STATUS_OK);
    PCHECK(control.control_code == RDP_COMPOSITED_CONTROL_CONNECTION_NOTIFICATION);
    PCHECK(rdp_composited_parse_version_reply(control.payload, control.payload_len, &reply) ==
           LIBRDP_STATUS_OK);
    PCHECK(reply.version_count == 1u &&
           rdp_composited_version_reply_has(&reply, RDP_COMPOSITED_PROTOCOL_VERSION));
    ((uint8_t*)control.payload)[8] = RDP_COMPOSITED_MAX_VERSION_COUNT + 1u;
    PCHECK(rdp_composited_parse_version_reply(control.payload, control.payload_len, &reply) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_sync_flush_reply(&buffer, 7u, 0x80004005u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_control(buffer.data, buffer.length, &control) == LIBRDP_STATUS_OK);
    PCHECK(control.control_code == RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION &&
           control.word0 == 7u &&
           control.payload_len == 60u &&
           test_read_u32_le(control.payload) == RDP_COMPOSITED_MSG_SYNC_FLUSH_REPLY &&
           test_read_u32_le(control.payload + 8u) == 0x80004005u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_roundtrip_reply(&buffer, 8u, 0x11223344u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_control(buffer.data, buffer.length, &control) == LIBRDP_STATUS_OK);
    PCHECK(control.control_code == RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION &&
           control.word0 == 8u &&
           control.payload_len == 60u &&
           test_read_u32_le(control.payload) == RDP_COMPOSITED_MSG_ROUNDTRIP_REPLY &&
           test_read_u32_le(control.payload + 8u) == 0x11223344u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_async_flush_reply(&buffer,
                                                  9u,
                                                  0x55667788u,
                                                  0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_control(buffer.data, buffer.length, &control) == LIBRDP_STATUS_OK);
    PCHECK(control.control_code == RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION &&
           control.word0 == 9u &&
           control.payload_len == 60u &&
           test_read_u32_le(control.payload) == RDP_COMPOSITED_MSG_ASYNC_FLUSH_REPLY &&
           test_read_u32_le(control.payload + 8u) == 0x55667788u &&
           test_read_u32_le(control.payload + 12u) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_hardware_tier(&buffer, 10u, 1u, 0x10203040u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_control(buffer.data, buffer.length, &control) == LIBRDP_STATUS_OK);
    PCHECK(control.control_code == RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION &&
           control.word0 == 10u &&
           control.payload_len == 60u &&
           test_read_u32_le(control.payload) == RDP_COMPOSITED_MSG_HARDWARE_TIER &&
           test_read_u32_le(control.payload + 8u) == 1u &&
           test_read_u32_le(control.payload + 12u) == 0x10203040u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_resource_order(&buffer,
                                               RDP_COMPOSITED_CMD_CREATE_RESOURCE,
                                               0x10u,
                                               RDP_COMPOSITED_RESOURCE_WINDOW_NODE) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_resource_order(buffer.data,
                                               buffer.length,
                                               RDP_COMPOSITED_CMD_CREATE_RESOURCE,
                                               &resource) == LIBRDP_STATUS_OK);
    PCHECK(resource.resource == 0x10u && resource.resource_type == RDP_COMPOSITED_RESOURCE_WINDOW_NODE);
    PCHECK(rdp_composited_write_resource_order(&buffer, 0xffffffffu, 1, 2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_buffer_append(&batch, buffer.data, buffer.length) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_duplicate_handle(&buffer, 0x10u, 0x20u, 0x30u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_duplicate_handle(buffer.data, buffer.length, &duplicate) ==
           LIBRDP_STATUS_OK);
    PCHECK(duplicate.original == 0x10u &&
           duplicate.target_channel == 0x20u &&
           duplicate.duplicate == 0x30u);
    PCHECK(rdp_buffer_append(&batch, buffer.data, buffer.length) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_u32_target_order(&buffer,
                                                 RDP_COMPOSITED_CMD_WINDOW_NODE_SET_LOGICAL_SURFACE_IMAGE,
                                                 0x44u,
                                                 0x55u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_u32_target_order(buffer.data,
                                                 buffer.length,
                                                 RDP_COMPOSITED_CMD_WINDOW_NODE_SET_LOGICAL_SURFACE_IMAGE,
                                                 &u32_order) == LIBRDP_STATUS_OK);
    PCHECK(u32_order.target_resource == 0x44u && u32_order.value == 0x55u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_u64_target_order(&buffer,
                                                 RDP_COMPOSITED_CMD_WINDOW_NODE_UPDATE_SPRITE_HANDLE,
                                                 0x44u,
                                                 0x0102030405060708ull) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_u64_target_order(buffer.data,
                                                 buffer.length,
                                                 RDP_COMPOSITED_CMD_WINDOW_NODE_UPDATE_SPRITE_HANDLE,
                                                 &u64_order) == LIBRDP_STATUS_OK);
    PCHECK(u64_order.target_resource == 0x44u && u64_order.value == 0x0102030405060708ull);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_target_order(&buffer,
                                             RDP_COMPOSITED_CMD_WINDOW_NODE_NOTIFY_VISIBLE_REGION,
                                             0x44u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_target_order(buffer.data,
                                             buffer.length,
                                             RDP_COMPOSITED_CMD_WINDOW_NODE_NOTIFY_VISIBLE_REGION,
                                             &target_order) == LIBRDP_STATUS_OK);
    PCHECK(target_order.target_resource == 0x44u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_window_node_bounds(&buffer,
                                                   0x44u,
                                                   &rect,
                                                   &client_rect,
                                                   &content_rect) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_window_node_bounds(buffer.data, buffer.length, &bounds_order) ==
           LIBRDP_STATUS_OK);
    PCHECK(bounds_order.target_resource == 0x44u &&
           bounds_order.window.right == 301 &&
           bounds_order.client.top == 5 &&
           bounds_order.content.bottom == 360);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_window_node_clip(&buffer, 0x44u, 1u, 0x77u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_window_node_clip(buffer.data, buffer.length, &clip_order) ==
           LIBRDP_STATUS_OK);
    PCHECK(clip_order.target_resource == 0x44u &&
           clip_order.for_dirty_accum == 1u &&
           clip_order.clip_resource == 0x77u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_window_node_source_modifications(&buffer,
                                                                 0x44u,
                                                                 2u,
                                                                 0x00112233u,
                                                                 0x44556677u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_window_node_source_modifications(buffer.data,
                                                                 buffer.length,
                                                                 &source_order) ==
           LIBRDP_STATUS_OK);
    PCHECK(source_order.target_resource == 0x44u &&
           source_order.source_modifications == 2u &&
           source_order.high_color_key == 0x44556677u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_margins_order(&buffer,
                                              RDP_COMPOSITED_CMD_WINDOW_NODE_SET_ALPHA_MARGINS,
                                              0x44u,
                                              &margins) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_margins_order(buffer.data,
                                              buffer.length,
                                              RDP_COMPOSITED_CMD_WINDOW_NODE_SET_ALPHA_MARGINS,
                                              &margins_order) == LIBRDP_STATUS_OK);
    PCHECK(margins_order.target_resource == 0x44u &&
           margins_order.margins.left == 9 &&
           margins_order.margins.bottom == 12);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_window_node_create(&buffer,
                                                   0x11u,
                                                   0x0102030405060708ull,
                                                   0x1112131415161718ull,
                                                   2u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_window_node_create(buffer.data, buffer.length, &window_node) ==
           LIBRDP_STATUS_OK);
    PCHECK(window_node.target_resource == 0x11u &&
           window_node.sprite_id == 0x0102030405060708ull &&
           window_node.window_id == 0x1112131415161718ull &&
           window_node.caching_mode == 2u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_target_create(&buffer, 0x12u, 1280u, 720u, color) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_target_create(buffer.data, buffer.length, &target) ==
           LIBRDP_STATUS_OK);
    PCHECK(target.target_resource == 0x12u &&
           target.width == 1280u &&
           target.height == 720u &&
           memcmp(target.clear_color, color, sizeof(color)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_color_order(&buffer,
                                            RDP_COMPOSITED_CMD_TARGET_SET_CLEAR_COLOR,
                                            0x12u,
                                            color) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_color_order(buffer.data,
                                            buffer.length,
                                            RDP_COMPOSITED_CMD_TARGET_SET_CLEAR_COLOR,
                                            &color_order) == LIBRDP_STATUS_OK);
    PCHECK(color_order.target_resource == 0x12u &&
           memcmp(color_order.color, color, sizeof(color)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_rect_order(&buffer,
                                           RDP_COMPOSITED_CMD_TARGET_INVALIDATE,
                                           0x12u,
                                           &rect) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_rect_order(buffer.data,
                                           buffer.length,
                                           RDP_COMPOSITED_CMD_TARGET_INVALIDATE,
                                           &rect_order) == LIBRDP_STATUS_OK);
    PCHECK(rect_order.target_resource == 0x12u &&
           rect_order.rect.left == 1 &&
           rect_order.rect.bottom == 402);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    memset(&window_settings, 0, sizeof(window_settings));
    window_settings.window_rect = rect;
    window_settings.window_layer_type = 2u;
    window_settings.transparency_mode = 3u;
    window_settings.constant_alpha_bits = 0x3f800000u;
    window_settings.is_child = 1u;
    window_settings.is_rtl = 1u;
    window_settings.rendering_enabled = 0u;
    memcpy(window_settings.color_key, color, sizeof(color));
    window_settings.disable_cookie = 0x12345678u;
    PCHECK(rdp_composited_write_target_window_settings(&buffer, 0x12u, &window_settings) ==
           LIBRDP_STATUS_OK);
    memset(&window_settings, 0, sizeof(window_settings));
    PCHECK(rdp_composited_parse_target_window_settings(buffer.data,
                                                       buffer.length,
                                                       &window_settings) == LIBRDP_STATUS_OK);
    PCHECK(window_settings.target_resource == 0x12u &&
           window_settings.window_rect.right == 301 &&
           window_settings.window_layer_type == 2u &&
           window_settings.disable_cookie == 0x12345678u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_render_data(&buffer,
                                            0x18u,
                                            render_words,
                                            sizeof(render_words)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_render_data(buffer.data, buffer.length, &render_data) ==
           LIBRDP_STATUS_OK);
    PCHECK(render_data.target_resource == 0x18u &&
           render_data.data_size == sizeof(render_words) &&
           render_data.data_len == sizeof(render_words));
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_target_capture_bits(&buffer,
                                                    0x12u,
                                                    3u,
                                                    4u,
                                                    320u,
                                                    240u,
                                                    0x57u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_target_capture_bits(buffer.data,
                                                    buffer.length,
                                                    &capture_bits) == LIBRDP_STATUS_OK);
    PCHECK(capture_bits.target_resource == 0x12u &&
           capture_bits.x == 3u &&
           capture_bits.height == 240u &&
           capture_bits.dxgi_format == 0x57u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    update_param[0] = 0x5au;
    PCHECK(rdp_composited_write_meta_capture_bits(&buffer,
                                                  0x17u,
                                                  640u,
                                                  360u,
                                                  0x1122334455667788ull,
                                                  1u,
                                                  update_param) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_meta_capture_bits(buffer.data,
                                                  buffer.length,
                                                  &meta_capture_bits) == LIBRDP_STATUS_OK);
    PCHECK(meta_capture_bits.target_resource == 0x17u &&
           meta_capture_bits.width == 640u &&
           meta_capture_bits.update_id == 0x1122334455667788ull &&
           meta_capture_bits.update_param[0] == 0x5au);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_glyph_run(&buffer, 0x13u, 0x14u, 2, glyphs, 3) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_glyph_run(buffer.data, buffer.length, &glyph_run) ==
           LIBRDP_STATUS_OK);
    PCHECK(glyph_run.target_resource == 0x13u &&
           glyph_run.glyph_cache == 0x14u &&
           glyph_run.glyph_count == 3u &&
           glyph_run.precontrast_level == 2 &&
           glyph_run.glyph_indices_len == 12u);
    PCHECK(rdp_composited_write_glyph_run(&buffer, 0x13u, 0x14u, 7, glyphs, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_gdi_sprite_bitmap(&buffer,
                                                  0x15u,
                                                  0x2122232425262728ull,
                                                  0x3132333435363738ull) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_gdi_sprite_bitmap(buffer.data, buffer.length, &sprite) ==
           LIBRDP_STATUS_OK);
    PCHECK(sprite.target_resource == 0x15u &&
           sprite.sprite_id == 0x2122232425262728ull &&
           sprite.logical_surface_id == 0x3132333435363738ull);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_gdi_surface_update(&buffer, 0x16u, 0x57u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_gdi_surface_update(buffer.data,
                                                   buffer.length,
                                                   &surface_update) == LIBRDP_STATUS_OK);
    PCHECK(surface_update.target_resource == 0x16u && surface_update.dxgi_format == 0x57u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_gdi_dirty(&buffer,
                                          0x16u,
                                          -1,
                                          0x0102030405060708ull) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_gdi_dirty(buffer.data, buffer.length, &dirty) ==
           LIBRDP_STATUS_OK);
    PCHECK(dirty.target_resource == 0x16u &&
           dirty.dirty_flags == -1 &&
           dirty.notification_cookie == 0x0102030405060708ull);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    surfaces[0] = 1u;
    PCHECK(rdp_composited_write_meta_target(&buffer,
                                            RDP_COMPOSITED_CMD_META_TARGET_CREATE,
                                            0x17u,
                                            1u,
                                            0x57u,
                                            1920u,
                                            1080u,
                                            surfaces) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 0xe4u);
    PCHECK(rdp_composited_parse_meta_target(buffer.data,
                                            buffer.length,
                                            RDP_COMPOSITED_CMD_META_TARGET_CREATE,
                                            &meta) == LIBRDP_STATUS_OK);
    PCHECK(meta.target_resource == 0x17u &&
           meta.textures.surface_count == 1u &&
           meta.textures.dxgi_format == 0x57u &&
           meta.textures.width == 1920u &&
           meta.textures.height == 1080u &&
           meta.textures.surfaces[0] == 1u);
    PCHECK(rdp_composited_write_meta_target(&buffer,
                                            RDP_COMPOSITED_CMD_META_TARGET_CREATE,
                                            0x17u,
                                            9u,
                                            0x57u,
                                            1u,
                                            1u,
                                            surfaces) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_batch_init(&reader, batch.data, batch.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_batch_next(&reader, &message) == LIBRDP_STATUS_OK);
    PCHECK(message.control_code == RDP_COMPOSITED_CMD_CREATE_RESOURCE);
    PCHECK(rdp_composited_batch_next(&reader, &message) == LIBRDP_STATUS_OK);
    PCHECK(message.control_code == RDP_COMPOSITED_CMD_DUPLICATE_HANDLE);
    PCHECK(rdp_composited_batch_next(&reader, &message) == LIBRDP_STATUS_AGAIN);
    PCHECK(rdp_composited_render_tree_apply_batch(&tree, batch.data, batch.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(tree.command_count == 2u && tree.resource_count == 2u);
    {
        rdp_composited_render_tree atomic_tree;
        rdp_buffer atomic_batch;

        rdp_composited_render_tree_init(&atomic_tree);
        rdp_buffer_init(&atomic_batch);
        rdp_buffer_free(&buffer);
        rdp_buffer_init(&buffer);
        PCHECK(rdp_composited_write_resource_order(&buffer,
                                                   RDP_COMPOSITED_CMD_CREATE_RESOURCE,
                                                   0x90u,
                                                   RDP_COMPOSITED_RESOURCE_WINDOW_NODE) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append(&atomic_batch, buffer.data, buffer.length) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u32_le(&atomic_batch, 8u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u32_le(&atomic_batch, 0xffffffffu) == LIBRDP_STATUS_OK);
        PCHECK(rdp_composited_render_tree_apply_batch(&atomic_tree,
                                                      atomic_batch.data,
                                                      atomic_batch.length) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(atomic_tree.command_count == 0u &&
               atomic_tree.resource_count == 0u &&
               rdp_composited_render_tree_find(&atomic_tree, 0x90u) == NULL);
        rdp_buffer_free(&atomic_batch);
        rdp_buffer_free(&buffer);
        rdp_buffer_init(&buffer);
    }
    before_commands = tree.command_count;
    memset(&message, 0, sizeof(message));
    message.control_code = RDP_COMPOSITED_CMD_CREATE_RESOURCE;
    message.data = bad_composited_message;
    message.message_size = sizeof(bad_composited_message);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(tree.command_count == before_commands && tree.resource_count == 2u);
    render_resource = rdp_composited_render_tree_find(&tree, 0x10u);
    PCHECK(render_resource && render_resource->resource_type == RDP_COMPOSITED_RESOURCE_WINDOW_NODE);
    render_resource = rdp_composited_render_tree_find(&tree, 0x30u);
    PCHECK(render_resource && render_resource->duplicate_source == 0x10u &&
           render_resource->duplicate_target_channel == 0x20u);
    PCHECK(rdp_composited_write_data_on_channel(&wrapped, 7u, batch.data, batch.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_control(wrapped.data, wrapped.length, &control) == LIBRDP_STATUS_OK);
    PCHECK(control.control_code == RDP_COMPOSITED_CONTROL_DATA_ON_CHANNEL &&
           control.word0 == 7u &&
           control.payload_len == batch.length);
    wrapped.data[7] = 1u;
    PCHECK(rdp_composited_parse_control(wrapped.data, wrapped.length, &control) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&wrapped);
    rdp_buffer_init(&wrapped);
    PCHECK(rdp_buffer_append_u8(&wrapped, 0x5bu) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_write_data_on_channel(&wrapped, 7u, update_param, 3u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(wrapped.length == 1u && wrapped.data[0] == 0x5bu);
    PCHECK(rdp_composited_write_notification(&wrapped,
                                             RDP_COMPOSITED_CONTROL_OPEN_CHANNEL,
                                             7u,
                                             update_param,
                                             4u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(wrapped.length == 1u && wrapped.data[0] == 0x5bu);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_target_create(&buffer, 0x40u, 640u, 480u, color) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x40u);
    PCHECK(render_resource && render_resource->resource_type == RDP_COMPOSITED_RESOURCE_HWND_TARGET &&
           render_resource->width == 640u && render_resource->height == 480u &&
           memcmp(render_resource->clear_color, color, sizeof(color)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_u32_target_order(&buffer,
                                                 RDP_COMPOSITED_CMD_TARGET_SET_ROOT,
                                                 0x40u,
                                                 0x10u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x40u);
    PCHECK(render_resource && render_resource->root_resource == 0x10u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_resource_order(&buffer,
                                               RDP_COMPOSITED_CMD_DELETE_RESOURCE,
                                               0x10u,
                                               RDP_COMPOSITED_RESOURCE_WINDOW_NODE) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_find(&tree, 0x10u) == NULL);
    render_resource = rdp_composited_render_tree_find(&tree, 0x40u);
    PCHECK(render_resource && render_resource->root_resource == 0u);
    render_resource = rdp_composited_render_tree_find(&tree, 0x30u);
    PCHECK(render_resource &&
           render_resource->duplicate_source == 0u &&
           render_resource->duplicate_target_channel == 0u &&
           tree.resource_count == 2u &&
           tree.invalidation_count == 3u);
    invalidation = NULL;
    for (i = 0; i < RDP_COMPOSITED_RENDER_INVALIDATION_LIMIT; i++)
    {
        if (tree.invalidations[i].active && tree.invalidations[i].resource == 0x40u)
        {
            invalidation = &tree.invalidations[i];
            break;
        }
    }
    PCHECK(invalidation &&
           invalidation->generation == 3u &&
           invalidation->rect.left == 0 &&
           invalidation->rect.top == 0 &&
           invalidation->rect.right == 640 &&
           invalidation->rect.bottom == 480);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_window_node_bounds(&buffer,
                                                   0x44u,
                                                   &rect,
                                                   &client_rect,
                                                   &content_rect) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x44u);
    PCHECK(render_resource &&
           render_resource->bounds_valid &&
           render_resource->window_rect.right == 301 &&
           render_resource->client_rect.top == 5 &&
           render_resource->content_rect.bottom == 360);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_u64_target_order(&buffer,
                                                 RDP_COMPOSITED_CMD_WINDOW_NODE_UPDATE_SPRITE_HANDLE,
                                                 0x44u,
                                                 0x2122232425262728ull) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x44u);
    PCHECK(render_resource && render_resource->sprite_id == 0x2122232425262728ull);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_window_node_clip(&buffer, 0x44u, 1u, 0x77u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x44u);
    PCHECK(render_resource &&
           render_resource->sprite_clip_for_dirty_accum == 1u &&
           render_resource->sprite_clip_resource == 0x77u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_resource_order(&buffer,
                                               RDP_COMPOSITED_CMD_DELETE_RESOURCE,
                                               0x77u,
                                               RDP_COMPOSITED_RESOURCE_VISUAL) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x44u);
    PCHECK(render_resource &&
           render_resource->sprite_clip_for_dirty_accum == 0u &&
           render_resource->sprite_clip_resource == 0u &&
           tree.invalidation_count == 7u);
    invalidation = NULL;
    for (i = 0; i < RDP_COMPOSITED_RENDER_INVALIDATION_LIMIT; i++)
    {
        if (tree.invalidations[i].active && tree.invalidations[i].resource == 0x44u)
        {
            invalidation = &tree.invalidations[i];
            break;
        }
    }
    PCHECK(invalidation &&
           invalidation->generation == 7u &&
           invalidation->rect.left == rect.left &&
           invalidation->rect.top == rect.top &&
           invalidation->rect.right == rect.right &&
           invalidation->rect.bottom == rect.bottom);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_window_node_source_modifications(&buffer,
                                                                 0x44u,
                                                                 2u,
                                                                 0x00112233u,
                                                                 0x44556677u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x44u);
    PCHECK(render_resource &&
           render_resource->source_modifications == 2u &&
           render_resource->low_color_key == 0x00112233u &&
           render_resource->high_color_key == 0x44556677u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_margins_order(&buffer,
                                              RDP_COMPOSITED_CMD_WINDOW_NODE_SET_ALPHA_MARGINS,
                                              0x44u,
                                              &margins) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x44u);
    PCHECK(render_resource &&
           render_resource->alpha_margins_valid &&
           render_resource->alpha_margins.bottom == 12);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_u32_target_order(&buffer,
                                                 RDP_COMPOSITED_CMD_WINDOW_NODE_SET_COMPOSE_ONCE,
                                                 0x44u,
                                                 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x44u);
    PCHECK(render_resource && render_resource->compose_once == 1u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_target_order(&buffer,
                                             RDP_COMPOSITED_CMD_WINDOW_NODE_NOTIFY_VISIBLE_REGION,
                                             0x44u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x44u);
    PCHECK(render_resource && render_resource->visible_region_updates == 1u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_target_order(&buffer,
                                             RDP_COMPOSITED_CMD_WINDOW_NODE_DETACH,
                                             0x44u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x44u);
    PCHECK(render_resource &&
           render_resource->detached == 1u &&
           render_resource->detach_count == 1u &&
           render_resource->sprite_clip_resource == 0u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_window_node_bounds(&buffer,
                                                   0x44u,
                                                   &rect,
                                                   &client_rect,
                                                   &content_rect) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x44u);
    PCHECK(render_resource && render_resource->detached == 0u && render_resource->detach_count == 1u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_target_window_settings(&buffer, 0x40u, &window_settings) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x40u);
    PCHECK(render_resource &&
           render_resource->window_layer_type == window_settings.window_layer_type &&
           render_resource->rendering_enabled == 0u &&
           render_resource->disable_cookie == 0x12345678u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_color_order(&buffer,
                                            RDP_COMPOSITED_CMD_TARGET_SET_CLEAR_COLOR,
                                            0x40u,
                                            color) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x40u);
    PCHECK(render_resource && memcmp(render_resource->clear_color, color, sizeof(color)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_rect_order(&buffer,
                                           RDP_COMPOSITED_CMD_TARGET_INVALIDATE,
                                           0x40u,
                                           &rect) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x40u);
    PCHECK(render_resource &&
           render_resource->invalid_rect_valid &&
           render_resource->invalid_rect.bottom == 402 &&
           tree.invalidation_count == 16u &&
           render_resource->invalidation_generation == 16u);
    invalidation = NULL;
    for (i = 0; i < RDP_COMPOSITED_RENDER_INVALIDATION_LIMIT; i++)
    {
        if (tree.invalidations[i].active && tree.invalidations[i].resource == 0x40u)
        {
            invalidation = &tree.invalidations[i];
            break;
        }
    }
    PCHECK(invalidation &&
           invalidation->generation == 16u &&
           invalidation->rect.left == rect.left &&
           invalidation->rect.top == rect.top &&
           invalidation->rect.right == rect.right &&
           invalidation->rect.bottom == rect.bottom);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_render_data(&buffer,
                                            0x18u,
                                            render_words,
                                            sizeof(render_words)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x18u);
    PCHECK(render_resource &&
           render_resource->resource_type == RDP_COMPOSITED_RESOURCE_RENDERDATA &&
           render_resource->render_data_length == sizeof(render_words) &&
           render_resource->render_instruction_count == 3u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_target_capture_bits(&buffer,
                                                    0x40u,
                                                    3u,
                                                    4u,
                                                    320u,
                                                    240u,
                                                    0x57u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x40u);
    PCHECK(render_resource &&
           render_resource->capture_count == 1u &&
           render_resource->capture_x == 3u &&
           render_resource->capture_height == 240u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_meta_capture_bits(&buffer,
                                                  0x17u,
                                                  640u,
                                                  360u,
                                                  0x1122334455667788ull,
                                                  1u,
                                                  update_param) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x17u);
    PCHECK(render_resource &&
           render_resource->meta_capture_count == 1u &&
           render_resource->meta_capture_update_id == 0x1122334455667788ull);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_gdi_sprite_bitmap(&buffer,
                                                  0x16u,
                                                  0x2122232425262728ull,
                                                  0x3132333435363738ull) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_u32_target_order(&buffer,
                                                 RDP_COMPOSITED_CMD_TARGET_SET_ROOT,
                                                 0x40u,
                                                 0x44u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x40u);
    PCHECK(render_resource && render_resource->root_resource == 0x44u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_u32_target_order(&buffer,
                                                 RDP_COMPOSITED_CMD_WINDOW_NODE_SET_LOGICAL_SURFACE_IMAGE,
                                                 0x44u,
                                                 0x16u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x44u);
    PCHECK(render_resource && render_resource->logical_surface_image_resource == 0x16u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_margins_order(&buffer,
                                              RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UPDATE_MARGINS,
                                              0x16u,
                                              &margins) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x16u);
    PCHECK(render_resource &&
           render_resource->sprite_margins_valid &&
           render_resource->sprite_margins.right == 11);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    before_invalidations = tree.invalidation_count;
    PCHECK(rdp_composited_write_gdi_dirty(&buffer,
                                          0x16u,
                                          -1,
                                          0x0102030405060708ull) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x16u);
    PCHECK(render_resource &&
           render_resource->sprite_dirty_count == 1u &&
           render_resource->sprite_dirty_flags == UINT32_MAX &&
           render_resource->sprite_dirty_cookie == 0x0102030405060708ull);
    invalidation = NULL;
    for (i = 0; i < RDP_COMPOSITED_RENDER_INVALIDATION_LIMIT; i++)
    {
        if (tree.invalidations[i].active && tree.invalidations[i].resource == 0x44u)
        {
            invalidation = &tree.invalidations[i];
            break;
        }
    }
    PCHECK(invalidation &&
           invalidation->generation > before_invalidations &&
           invalidation->rect.left == rect.left &&
           invalidation->rect.right == rect.right);
    invalidation = NULL;
    for (i = 0; i < RDP_COMPOSITED_RENDER_INVALIDATION_LIMIT; i++)
    {
        if (tree.invalidations[i].active && tree.invalidations[i].resource == 0x40u)
        {
            invalidation = &tree.invalidations[i];
            break;
        }
    }
    PCHECK(invalidation &&
           invalidation->generation > before_invalidations &&
           invalidation->rect.left == 0 &&
           invalidation->rect.right == 640);
    collected_count = rdp_composited_render_tree_collect_invalidations(&tree,
                                                                       before_invalidations,
                                                                       collected_invalidations,
                                                                       4u,
                                                                       &latest_invalidation);
    PCHECK(collected_count >= 2u &&
           latest_invalidation == tree.invalidation_count &&
           collected_invalidations[0].generation > before_invalidations);
    for (i = 1; i < collected_count; i++)
        PCHECK(collected_invalidations[i].generation > collected_invalidations[i - 1u].generation);
    PCHECK(rdp_composited_render_tree_collect_invalidations(&tree,
                                                           latest_invalidation,
                                                           collected_invalidations,
                                                           4u,
                                                           &latest_invalidation) == 0u);
    PCHECK(latest_invalidation == tree.invalidation_count);
    PCHECK(rdp_composited_render_tree_resolve_view(&tree, 0x40u, &view) ==
           LIBRDP_STATUS_OK);
    PCHECK((view.flags & RDP_COMPOSITED_VIEW_TARGET_PRESENT) != 0 &&
           (view.flags & RDP_COMPOSITED_VIEW_ROOT_PRESENT) != 0 &&
           (view.flags & RDP_COMPOSITED_VIEW_SOURCE_PRESENT) != 0 &&
           (view.flags & RDP_COMPOSITED_VIEW_TARGET_CAPTURE) != 0 &&
           (view.flags & RDP_COMPOSITED_VIEW_SOURCE_DIRTY) != 0);
    PCHECK(view.target_resource == 0x40u &&
           view.root_resource == 0x44u &&
           view.source_resource == 0x16u &&
           view.width == 640u &&
           view.height == 480u &&
           view.capture_count == 1u &&
           view.capture_width == 320u &&
           view.sprite_dirty_cookie == 0x0102030405060708ull &&
           view.target_rect_valid &&
           view.root_rect_valid &&
           view.invalid_rect_valid &&
           view.invalid_rect.right == 640);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_target_order(&buffer,
                                             RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UNMAP_SECTION,
                                             0x16u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x16u);
    PCHECK(render_resource && render_resource->sprite_unmapped == 1u);
    PCHECK(rdp_composited_render_tree_resolve_view(&tree, 0x40u, &view) ==
           LIBRDP_STATUS_OK);
    PCHECK((view.flags & RDP_COMPOSITED_VIEW_SOURCE_UNMAPPED) != 0 &&
           view.source_resource == 0x16u);
    PCHECK(rdp_composited_render_tree_resolve_view(&tree, 0xf0u, &view) ==
           LIBRDP_STATUS_STATE);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    before_invalidations = tree.invalidation_count;
    PCHECK(rdp_composited_write_resource_order(&buffer,
                                               RDP_COMPOSITED_CMD_CREATE_RESOURCE,
                                               0x16u,
                                               RDP_COMPOSITED_RESOURCE_RENDERDATA) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x16u);
    PCHECK(render_resource &&
           render_resource->resource_type == RDP_COMPOSITED_RESOURCE_RENDERDATA &&
           render_resource->sprite_dirty_count == 0u &&
           render_resource->sprite_unmapped == 0u &&
           render_resource->sprite_id == 0u &&
           render_resource->logical_surface_id == 0u);
    PCHECK(rdp_composited_render_tree_resolve_view(&tree, 0x40u, &view) ==
           LIBRDP_STATUS_OK);
    PCHECK((view.flags & RDP_COMPOSITED_VIEW_SOURCE_PRESENT) != 0 &&
           (view.flags & RDP_COMPOSITED_VIEW_SOURCE_DIRTY) == 0 &&
           (view.flags & RDP_COMPOSITED_VIEW_SOURCE_UNMAPPED) == 0 &&
           view.source_resource == 0x16u &&
           view.source_type == RDP_COMPOSITED_RESOURCE_RENDERDATA);
    invalidation = NULL;
    for (i = 0; i < RDP_COMPOSITED_RENDER_INVALIDATION_LIMIT; i++)
    {
        if (tree.invalidations[i].active && tree.invalidations[i].resource == 0x40u)
        {
            invalidation = &tree.invalidations[i];
            break;
        }
    }
    PCHECK(invalidation && invalidation->generation > before_invalidations);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_bitmap_pixels(&buffer,
                                              0x19u,
                                              2u,
                                              2u,
                                              RDP_COMPOSITED_PIXEL_FORMAT_32BPP_BGRA,
                                              8u,
                                              0,
                                              0x4058000000000000ull,
                                              0x4058000000000000ull,
                                              bitmap_raw,
                                              sizeof(bitmap_raw),
                                              NULL,
                                              0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_bitmap_pixels(buffer.data, buffer.length, &bitmap_pixels) ==
           LIBRDP_STATUS_OK);
    PCHECK(bitmap_pixels.target_resource == 0x19u &&
           bitmap_pixels.width == 2u &&
           bitmap_pixels.height == 2u &&
           bitmap_pixels.format == RDP_COMPOSITED_PIXEL_FORMAT_32BPP_BGRA &&
           bitmap_pixels.image_bitmap_len == sizeof(bitmap_raw) &&
           bitmap_pixels.image_bitmap[3] == 0xffu);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x19u);
    PCHECK(tree.bitmap_pixels_count == 1u &&
           tree.skipped_known_count == 0u &&
           render_resource &&
           render_resource->resource_type == RDP_COMPOSITED_RESOURCE_BITMAP_SOURCE &&
           render_resource->width == 2u &&
           render_resource->height == 2u &&
           render_resource->bitmap_payload_length == sizeof(bitmap_raw) &&
           render_resource->bitmap_payload_hash != 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    PCHECK(rdp_composited_write_bitmap_pixels(&buffer,
                                              0x19u,
                                              2u,
                                              1u,
                                              RDP_COMPOSITED_PIXEL_FORMAT_8BPP_INDEXED,
                                              4u,
                                              2u,
                                              0x4058000000000000ull,
                                              0x4058000000000000ull,
                                              bitmap_indexed,
                                              sizeof(bitmap_indexed),
                                              bitmap_palette,
                                              sizeof(bitmap_palette)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_bitmap_pixels(buffer.data, buffer.length, &bitmap_pixels) ==
           LIBRDP_STATUS_OK);
    PCHECK(bitmap_pixels.palette_color_count == 2u &&
           bitmap_pixels.image_palette_len == sizeof(bitmap_palette));
    PCHECK(rdp_composited_write_bitmap_pixels(&buffer,
                                              0x19u,
                                              2u,
                                              1u,
                                              RDP_COMPOSITED_PIXEL_FORMAT_32BPP_BGRA,
                                              8u,
                                              1u,
                                              0,
                                              0,
                                              bitmap_indexed,
                                              sizeof(bitmap_indexed),
                                              bitmap_palette,
                                              4u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_bitmap_compressed_pixels(&buffer,
                                                        0x19u,
                                                        0x4058000000000000ull,
                                                        0x4058000000000000ull,
                                                        compressed_bitmap,
                                                        sizeof(compressed_bitmap)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_bitmap_compressed_pixels(buffer.data,
                                                        buffer.length,
                                                        &compressed_pixels) == LIBRDP_STATUS_OK);
    PCHECK(compressed_pixels.target_resource == 0x19u &&
           compressed_pixels.compressed_image_bitmap_len == sizeof(compressed_bitmap) &&
           compressed_pixels.compressed_image_bitmap[1] == 0x50u);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x19u);
    PCHECK(tree.bitmap_compressed_pixels_count == 1u &&
           tree.skipped_known_count == 0u &&
           render_resource &&
           render_resource->bitmap_compressed == 1u &&
           render_resource->bitmap_payload_length == sizeof(compressed_bitmap) &&
           render_resource->bitmap_payload_hash != 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_channel_message(&buffer,
                                                RDP_COMPOSITED_CMD_VISUAL_GROUP,
                                                NULL,
                                                0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    PCHECK(tree.visual_group_count == 1u && tree.skipped_known_count == 0u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_channel_message(&buffer,
                                                RDP_COMPOSITED_CMD_GLYPH_CACHE_ADD_BITMAPS,
                                                NULL,
                                                0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    PCHECK(tree.glyph_cache_add_count == 1u && tree.skipped_known_count == 0u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_channel_message(&buffer,
                                                RDP_COMPOSITED_CMD_GLYPH_CACHE_REMOVE_BITMAPS,
                                                NULL,
                                                0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    PCHECK(tree.glyph_cache_remove_count == 1u && tree.skipped_known_count == 0u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_channel_message(&buffer,
                                                RDP_COMPOSITED_CMD_GLYPH_RUN_ADD_REALIZATION,
                                                NULL,
                                                0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    PCHECK(tree.glyph_realization_add_count == 1u && tree.skipped_known_count == 0u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_channel_message(&buffer,
                                                RDP_COMPOSITED_CMD_GLYPH_RUN_REMOVE_REALIZATION,
                                                NULL,
                                                0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    PCHECK(tree.glyph_realization_remove_count == 1u && tree.skipped_known_count == 0u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_channel_message(&buffer, 0x12u, update_param, 4u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    PCHECK(tree.extension_command_count == 1u &&
           tree.last_extension_command == 0x12u &&
           tree.last_extension_payload_len == 4u &&
           tree.skipped_known_count == 0u);
    buffer.length = 0;
    PCHECK(rdp_buffer_append_u8(&buffer, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_write_channel_message(&buffer, 0xffffffffu, NULL, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 1u && buffer.data[0] == 0xa5u);
    buffer.length = 0;
    PCHECK(rdp_buffer_append_u32_le(&buffer, 8u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0xffffffffu) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_resource_order(&buffer,
                                               RDP_COMPOSITED_CMD_DELETE_RESOURCE,
                                               0x10u,
                                               RDP_COMPOSITED_RESOURCE_WINDOW_NODE) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_find(&tree, 0x10u) == NULL);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);

    rdp_buffer_free(&wrapped);
    rdp_buffer_free(&batch);
    rdp_buffer_free(&buffer);
    return 0;
}

/*
 * Coverage: validates video redirection presentation, media packet, and
 * stream-state vectors for malformed payload and lifetime bugs.
 */
static int test_video_redirection_channel(void)
{
    const uint8_t guid[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    const uint8_t format[] = {0xde, 0xad, 0xbe, 0xef};
    const uint8_t sample_data[] = {1, 2, 3, 4, 5};
    const uint8_t event_data[] = {9, 8};
    rdp_buffer buffer;
    rdp_buffer payload;
    rdp_buffer nested;
    rdp_video_redirection_header header;
    rdp_video_redirection_capability_message caps;
    rdp_video_redirection_rim_capability rim;
    rdp_video_redirection_playback_ack ack;
    rdp_video_redirection_client_event event;
    rdp_video_redirection_stream stream;
    rdp_video_redirection_presentation presentation;
    rdp_video_redirection_media_type media_type;
    rdp_video_redirection_data_sample data_sample;
    rdp_video_redirection_playback_started started;
    rdp_video_redirection_playback_rate rate;
    rdp_video_redirection_window window;
    rdp_video_redirection_geometry_update geometry_update;
    rdp_video_redirection_geometry_info geometry_info;
    rdp_video_redirection_rect rect;
    rdp_video_redirection_volume volume;
    rdp_video_redirection_format_support_request format_request;
    rdp_video_redirection_format_support_response format_response;
    rdp_video_redirection_topology_response topology_response;
    rdp_video_redirection_source_video_rect source_rect;

#define PCHECK_VIDEO_PARSE_PRESERVES(parse_call, object, saved_object)       \
    do                                                                       \
    {                                                                        \
        (object) = (saved_object);                                           \
        PCHECK((parse_call) == LIBRDP_STATUS_PROTOCOL_ERROR);                \
        PCHECK(memcmp(&(object), &(saved_object), sizeof(object)) == 0);     \
    } while (0)

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);
    rdp_buffer_init(&nested);

    PCHECK(rdp_video_redirection_write_header(&buffer,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              0,
                                              1,
                                              RDP_VIDEO_REDIRECTION_FUNC_EXCHANGE_CAPABILITIES_REQ) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_write_u32_capability(&buffer,
                                                      RDP_VIDEO_REDIRECTION_CAPABILITY_PROTOCOL_VERSION,
                                                      RDP_VIDEO_REDIRECTION_PROTOCOL_VERSION_2) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_write_u32_capability(&buffer,
                                                      RDP_VIDEO_REDIRECTION_CAPABILITY_PLATFORM,
                                                      RDP_VIDEO_REDIRECTION_PLATFORM_MF) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_exchange_capabilities_request(buffer.data,
                                                                     buffer.length,
                                                                     &caps) ==
           LIBRDP_STATUS_OK);
    PCHECK(caps.capabilities.count == 2 &&
           caps.capabilities.capabilities[0].type == RDP_VIDEO_REDIRECTION_CAPABILITY_PROTOCOL_VERSION &&
           test_read_u32_le(caps.capabilities.capabilities[1].data) == RDP_VIDEO_REDIRECTION_PLATFORM_MF);
    PCHECK(rdp_video_redirection_write_exchange_capabilities_request(&payload,
                                                                     2,
                                                                     caps.capabilities.capabilities,
                                                                     caps.capabilities.count) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_exchange_capabilities_request(payload.data,
                                                                     payload.length,
                                                                     &caps) ==
           LIBRDP_STATUS_OK);
    PCHECK(caps.header.message_id == 2 && caps.capabilities.count == 2);
    PCHECK(rdp_video_redirection_write_exchange_capabilities_response(&nested,
                                                                      0,
                                                                      caps.capabilities.capabilities,
                                                                      caps.capabilities.count,
                                                                      0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_exchange_capabilities_response(nested.data,
                                                                      nested.length,
                                                                      &caps) ==
           LIBRDP_STATUS_OK);
    PCHECK(caps.has_result && caps.result == 0);
    {
        rdp_video_redirection_capability_message valid_caps = caps;

        nested.data[3] = 0x40;
        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_exchange_capabilities_response(
                                         nested.data,
                                         nested.length,
                                         &caps),
                                     caps,
                                     valid_caps);
        nested.data[3] = 0x80u;
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_free(&nested);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);
    rdp_buffer_init(&nested);

    PCHECK(rdp_video_redirection_write_rim_capability_request(
               &buffer,
               3,
               RDP_VIDEO_REDIRECTION_RIM_CAPABILITY_VERSION_01) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_rim_capability_request(buffer.data, buffer.length, &rim) ==
           LIBRDP_STATUS_OK);
    PCHECK(rim.header.message_id == 3 && rim.capability == RDP_VIDEO_REDIRECTION_RIM_CAPABILITY_VERSION_01);
    PCHECK(rdp_video_redirection_write_rim_capability_response(&payload,
                                                               rim.header.message_id,
                                                               rim.capability,
                                                               0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_rim_capability_response(payload.data,
                                                               payload.length,
                                                               &rim) ==
           LIBRDP_STATUS_OK);
    PCHECK(rim.has_result && rim.result == 0);
    {
        rdp_video_redirection_rim_capability valid_rim = rim;

        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_rim_capability_response(
                                         payload.data,
                                         payload.length - 1u,
                                         &rim),
                                     rim,
                                     valid_rim);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);

    PCHECK(rdp_video_redirection_write_header(&buffer,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              18,
                                              1,
                                              RDP_VIDEO_REDIRECTION_FUNC_CHECK_FORMAT_SUPPORT_REQ) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, RDP_VIDEO_REDIRECTION_PLATFORM_COOKIE_MF) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0x01020304u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&buffer, format, sizeof(format)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_check_format_support_request(buffer.data,
                                                                     buffer.length,
                                                                     &format_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(format_request.platform_cookie == RDP_VIDEO_REDIRECTION_PLATFORM_COOKIE_MF &&
           format_request.no_rollover_flags == 0x01020304u &&
           format_request.media_type_count == 1u &&
           format_request.media_types_len == sizeof(format) &&
           format_request.media_types[2] == 0xbe);
    {
        rdp_video_redirection_format_support_request valid_request = format_request;

        buffer.data[20] = 0u;
        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_check_format_support_request(
                                         buffer.data,
                                         buffer.length,
                                         &format_request),
                                     format_request,
                                     valid_request);
        buffer.data[20] = 1u;
    }
    PCHECK(rdp_video_redirection_write_check_format_support_response(
               &payload,
               format_request.header.message_id,
               1,
               format_request.platform_cookie,
               0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_check_format_support_response(payload.data,
                                                                      payload.length,
                                                                      &format_response) ==
           LIBRDP_STATUS_OK);
    PCHECK(format_response.format_supported == 1 &&
           format_response.platform_cookie == RDP_VIDEO_REDIRECTION_PLATFORM_COOKIE_MF &&
           format_response.result == 0);
    {
        rdp_video_redirection_format_support_response valid_response = format_response;

        payload.data[8] = 2u;
        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_check_format_support_response(
                                         payload.data,
                                         payload.length,
                                         &format_response),
                                     format_response,
                                     valid_response);
        payload.data[8] = 1u;
    }
    PCHECK(rdp_video_redirection_write_check_format_support_response(&nested, 18, 2, 0, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_free(&nested);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);
    rdp_buffer_init(&nested);

    PCHECK(rdp_video_redirection_write_playback_ack(&buffer, 4, 1, 0x51615u, 0x7e2u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_playback_ack(buffer.data, buffer.length, &ack) ==
           LIBRDP_STATUS_OK);
    PCHECK(ack.stream_id == 1 && ack.data_duration == 0x51615u && ack.data_len == 0x7e2u);
    {
        rdp_video_redirection_playback_ack valid_ack = ack;

        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_playback_ack(buffer.data,
                                                                              buffer.length - 1u,
                                                                              &ack),
                                     ack,
                                     valid_ack);
    }
    PCHECK(rdp_video_redirection_write_client_event(&payload,
                                                    5,
                                                    0,
                                                    RDP_VIDEO_REDIRECTION_CLIENT_EVENT_START_COMPLETED,
                                                    event_data,
                                                    sizeof(event_data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_client_event(payload.data, payload.length, &event) ==
           LIBRDP_STATUS_OK);
    PCHECK(event.event_id == RDP_VIDEO_REDIRECTION_CLIENT_EVENT_START_COMPLETED &&
           event.data_len == sizeof(event_data) &&
           event.data[1] == 8);
    {
        rdp_video_redirection_client_event valid_event = event;

        payload.data[20] = 9;
        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_client_event(payload.data,
                                                                              payload.length,
                                                                              &event),
                                     event,
                                     valid_event);
        payload.data[20] = (uint8_t)sizeof(event_data);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);

    PCHECK(rdp_video_redirection_write_set_channel_params(&buffer, 6, guid, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_set_channel_params(buffer.data, buffer.length, &stream) ==
           LIBRDP_STATUS_OK);
    PCHECK(stream.stream_id == 0 && stream.presentation_id[15] == 15);
    {
        rdp_video_redirection_stream valid_stream = stream;

        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_set_channel_params(
                                         buffer.data,
                                         buffer.length - 1u,
                                         &stream),
                                     stream,
                                     valid_stream);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_redirection_write_new_presentation(&buffer,
                                                        7,
                                                        guid,
                                                        RDP_VIDEO_REDIRECTION_PLATFORM_COOKIE_MF) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_new_presentation(buffer.data,
                                                        buffer.length,
                                                        &presentation) ==
           LIBRDP_STATUS_OK);
    PCHECK(presentation.platform_cookie == RDP_VIDEO_REDIRECTION_PLATFORM_COOKIE_MF);
    {
        rdp_video_redirection_presentation valid_presentation = presentation;

        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_new_presentation(
                                         buffer.data,
                                         buffer.length - 1u,
                                         &presentation),
                                     presentation,
                                     valid_presentation);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_buffer_append(&nested, guid, sizeof(guid)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&nested, guid, sizeof(guid)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&nested, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&nested, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&nested, 0x1000) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&nested, guid, sizeof(guid)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&nested, sizeof(format)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&nested, format, sizeof(format)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_media_type(nested.data, nested.length, &media_type) ==
           LIBRDP_STATUS_OK);
    PCHECK(media_type.format_len == sizeof(format) && media_type.format[0] == 0xde);
    PCHECK(rdp_video_redirection_write_media_type(&payload,
                                                  media_type.major_type,
                                                  media_type.sub_type,
                                                  media_type.fixed_size_samples,
                                                  media_type.temporal_compression,
                                                  media_type.sample_size,
                                                  media_type.format_type,
                                                  media_type.format,
                                                  media_type.format_len) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_media_type(payload.data, payload.length, &media_type) ==
           LIBRDP_STATUS_OK);
    PCHECK(media_type.format_len == sizeof(format) && media_type.format[3] == 0xef);
    {
        rdp_video_redirection_media_type valid_media_type = media_type;

        payload.data[60] = 5u;
        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_media_type(payload.data,
                                                                            payload.length,
                                                                            &media_type),
                                     media_type,
                                     valid_media_type);
        payload.data[60] = (uint8_t)sizeof(format);
    }
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);
    PCHECK(rdp_video_redirection_write_add_stream(&buffer,
                                                  8,
                                                  guid,
                                                  11,
                                                  nested.data,
                                                  (uint32_t)nested.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_add_stream(buffer.data, buffer.length, &stream) ==
           LIBRDP_STATUS_OK);
    PCHECK(stream.stream_id == 11 && stream.data_len == nested.length);
    {
        rdp_video_redirection_stream valid_stream = stream;

        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_add_stream(buffer.data,
                                                                            buffer.length - 1u,
                                                                            &stream),
                                     stream,
                                     valid_stream);
    }
    PCHECK(rdp_video_redirection_write_add_stream(&payload, 8, guid, 11, NULL, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_free(&nested);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);
    rdp_buffer_init(&nested);

    PCHECK(test_append_u64_le(&nested, 0x37u) == LIBRDP_STATUS_OK);
    PCHECK(test_append_u64_le(&nested, 0x38u) == LIBRDP_STATUS_OK);
    PCHECK(test_append_u64_le(&nested, 0x55u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&nested, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&nested, 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&nested, sizeof(sample_data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&nested, sample_data, sizeof(sample_data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_data_sample(nested.data, nested.length, &data_sample) ==
           LIBRDP_STATUS_OK);
    PCHECK(data_sample.sample_end_time == 0x38u &&
           data_sample.data_len == sizeof(sample_data) &&
           data_sample.data[4] == 5);
    PCHECK(rdp_video_redirection_write_data_sample(&payload,
                                                   data_sample.sample_start_time,
                                                   data_sample.sample_end_time,
                                                   data_sample.throttle_duration,
                                                   data_sample.sample_flags,
                                                   data_sample.sample_extensions,
                                                   data_sample.data,
                                                   data_sample.data_len) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_data_sample(payload.data, payload.length, &data_sample) ==
           LIBRDP_STATUS_OK);
    PCHECK(data_sample.sample_start_time == 0x37u &&
           data_sample.data_len == sizeof(sample_data) &&
           data_sample.data[0] == 1);
    {
        rdp_video_redirection_data_sample valid_sample = data_sample;

        payload.data[8] = 0x36u;
        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_data_sample(payload.data,
                                                                             payload.length,
                                                                             &data_sample),
                                     data_sample,
                                     valid_sample);
        payload.data[8] = 0x38u;
    }
    PCHECK(rdp_video_redirection_write_data_sample(&payload,
                                                   0x38u,
                                                   0x37u,
                                                   0,
                                                   0,
                                                   0,
                                                   sample_data,
                                                   sizeof(sample_data)) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);
    PCHECK(rdp_video_redirection_write_sample_message(&buffer,
                                                      9,
                                                      guid,
                                                      11,
                                                      nested.data,
                                                      (uint32_t)nested.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_sample_message(buffer.data, buffer.length, &stream) ==
           LIBRDP_STATUS_OK);
    PCHECK(stream.stream_id == 11 && stream.data_len == nested.length);
    {
        rdp_video_redirection_stream valid_stream = stream;

        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_sample_message(buffer.data,
                                                                                buffer.length - 1u,
                                                                                &stream),
                                     stream,
                                     valid_stream);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&nested);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&nested);

    PCHECK(rdp_video_redirection_write_presentation_only(&buffer,
                                                         10,
                                                         RDP_VIDEO_REDIRECTION_FUNC_SET_TOPOLOGY_REQ,
                                                         guid) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_presentation_only(buffer.data,
                                                         buffer.length,
                                                         RDP_VIDEO_REDIRECTION_FUNC_SET_TOPOLOGY_REQ,
                                                         &presentation) ==
           LIBRDP_STATUS_OK);
    {
        rdp_video_redirection_presentation valid_presentation = presentation;

        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_presentation_only(
                                         buffer.data,
                                         buffer.length - 1u,
                                         RDP_VIDEO_REDIRECTION_FUNC_SET_TOPOLOGY_REQ,
                                         &presentation),
                                     presentation,
                                     valid_presentation);
    }
    PCHECK(rdp_video_redirection_write_set_topology_response(&payload,
                                                             presentation.header.message_id,
                                                             1,
                                                             0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_set_topology_response(payload.data,
                                                             payload.length,
                                                             &topology_response) ==
           LIBRDP_STATUS_OK);
    PCHECK(topology_response.topology_ready == 1 && topology_response.result == 0);
    {
        rdp_video_redirection_topology_response valid_response = topology_response;

        payload.data[8] = 2u;
        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_set_topology_response(
                                         payload.data,
                                         payload.length,
                                         &topology_response),
                                     topology_response,
                                     valid_response);
        payload.data[8] = 1u;
    }
    PCHECK(rdp_video_redirection_write_set_topology_response(&nested, 10, 2, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_free(&nested);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);
    rdp_buffer_init(&nested);

    PCHECK(rdp_video_redirection_write_stream_only(&buffer,
                                                   11,
                                                   RDP_VIDEO_REDIRECTION_FUNC_ON_FLUSH,
                                                   guid,
                                                   11) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_stream_only(buffer.data,
                                                   buffer.length,
                                                   RDP_VIDEO_REDIRECTION_FUNC_ON_FLUSH,
                                                   &stream) == LIBRDP_STATUS_OK);
    {
        rdp_video_redirection_stream valid_stream = stream;

        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_stream_only(
                                         buffer.data,
                                         buffer.length - 1u,
                                         RDP_VIDEO_REDIRECTION_FUNC_ON_FLUSH,
                                         &stream),
                                     stream,
                                     valid_stream);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_redirection_write_playback_started(&buffer,
                                                        12,
                                                        guid,
                                                        0x21e25d8320u,
                                                        1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_playback_started(buffer.data,
                                                        buffer.length,
                                                        &started) == LIBRDP_STATUS_OK);
    PCHECK(started.playback_start_offset == 0x21e25d8320u && started.is_seek == 1);
    {
        rdp_video_redirection_playback_started valid_started = started;

        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_playback_started(
                                         buffer.data,
                                         buffer.length - 1u,
                                         &started),
                                     started,
                                     valid_started);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_redirection_write_playback_rate(&buffer, 13, guid, 0x3f800000u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_playback_rate(buffer.data, buffer.length, &rate) ==
           LIBRDP_STATUS_OK);
    PCHECK(rate.rate_bits == 0x3f800000u);
    {
        rdp_video_redirection_playback_rate valid_rate = rate;

        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_playback_rate(buffer.data,
                                                                               buffer.length - 1u,
                                                                               &rate),
                                     rate,
                                     valid_rate);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_redirection_write_set_video_window(&buffer,
                                                        14,
                                                        guid,
                                                        0x11223344u,
                                                        0x55667788u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_set_video_window(buffer.data, buffer.length, &window) ==
           LIBRDP_STATUS_OK);
    PCHECK(window.video_window_id == 0x11223344u && window.parent_window_id == 0x55667788u);
    {
        rdp_video_redirection_window valid_window = window;

        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_set_video_window(
                                         buffer.data,
                                         buffer.length - 1u,
                                         &window),
                                     window,
                                     valid_window);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    memset(&geometry_info, 0, sizeof(geometry_info));
    geometry_info.video_window_id = 0x11223344u;
    geometry_info.window_state = RDP_VIDEO_REDIRECTION_WINDOW_NEW;
    geometry_info.width = 640;
    geometry_info.height = 480;
    geometry_info.left = 10;
    geometry_info.top = 20;
    geometry_info.client_left = 12;
    geometry_info.client_top = 22;
    PCHECK(rdp_video_redirection_write_geometry_info(&nested, &geometry_info) == LIBRDP_STATUS_OK);
    memset(&geometry_info, 0, sizeof(geometry_info));
    PCHECK(rdp_video_redirection_parse_geometry_info(nested.data,
                                                     nested.length,
                                                     &geometry_info) == LIBRDP_STATUS_OK);
    PCHECK(geometry_info.width == 640 && geometry_info.client_top == 22);
    {
        rdp_video_redirection_geometry_info bad_geometry = geometry_info;
        rdp_video_redirection_geometry_info valid_geometry = geometry_info;

        bad_geometry.window_state = 0x80000000u;
        PCHECK(rdp_video_redirection_write_geometry_info(&payload, &bad_geometry) ==
               LIBRDP_STATUS_INVALID_ARGUMENT);
        bad_geometry = geometry_info;
        bad_geometry.width = 0;
        PCHECK(rdp_video_redirection_write_geometry_info(&payload, &bad_geometry) ==
               LIBRDP_STATUS_INVALID_ARGUMENT);
        bad_geometry = geometry_info;
        bad_geometry.left = UINT32_MAX;
        bad_geometry.width = 2;
        PCHECK(rdp_video_redirection_write_geometry_info(&payload, &bad_geometry) ==
               LIBRDP_STATUS_INVALID_ARGUMENT);
        bad_geometry = valid_geometry;
        ((uint8_t*)nested.data)[8] = 0x80u;
        PCHECK(rdp_video_redirection_parse_geometry_info(nested.data,
                                                         nested.length,
                                                         &bad_geometry) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&bad_geometry, &valid_geometry, sizeof(bad_geometry)) == 0);
        bad_geometry = valid_geometry;
        ((uint8_t*)nested.data)[8] = (uint8_t)RDP_VIDEO_REDIRECTION_WINDOW_NEW;
        ((uint8_t*)nested.data)[28] = 0x01u;
        PCHECK(rdp_video_redirection_parse_geometry_info(nested.data,
                                                         nested.length,
                                                         &bad_geometry) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&bad_geometry, &valid_geometry, sizeof(bad_geometry)) == 0);
        nested.data[28] = 0x00u;
    }
    PCHECK(rdp_video_redirection_write_rect(&payload, 1, 2, 3, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_rect(payload.data, payload.length, &rect) ==
           LIBRDP_STATUS_OK);
    PCHECK(rect.top == 1 && rect.right == 4);
    {
        rdp_video_redirection_rect valid_rect = rect;

        PCHECK(rdp_video_redirection_parse_rect(payload.data, payload.length - 1u, &rect) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&rect, &valid_rect, sizeof(rect)) == 0);
    }
    PCHECK(rdp_video_redirection_write_geometry_update(&buffer,
                                                       15,
                                                       guid,
                                                       nested.data,
                                                       (uint32_t)nested.length,
                                                       payload.data,
                                                       (uint32_t)payload.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_geometry_update(buffer.data,
                                                       buffer.length,
                                                       &geometry_update) == LIBRDP_STATUS_OK);
    PCHECK(geometry_update.geometry_len == nested.length &&
           geometry_update.visible_rect_len == payload.length);
    {
        rdp_video_redirection_geometry_update valid_update = geometry_update;

        PCHECK(rdp_video_redirection_parse_geometry_update(buffer.data,
                                                           buffer.length - 1u,
                                                           &geometry_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&geometry_update, &valid_update, sizeof(geometry_update)) == 0);
    }
    PCHECK(rdp_video_redirection_write_geometry_update(&payload,
                                                       15,
                                                       guid,
                                                       nested.data,
                                                       (uint32_t)nested.length,
                                                       NULL,
                                                       1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_free(&nested);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);
    rdp_buffer_init(&nested);

    PCHECK(rdp_video_redirection_write_stream_volume(&buffer, 16, guid, 0x834u, 1) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_stream_volume(buffer.data, buffer.length, &volume) ==
           LIBRDP_STATUS_OK);
    PCHECK(volume.value == 0x834u && volume.second_value == 1);
    {
        rdp_video_redirection_volume valid_volume = volume;

        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_stream_volume(buffer.data,
                                                                               buffer.length - 1u,
                                                                               &volume),
                                     volume,
                                     valid_volume);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_redirection_write_channel_volume(&buffer, 17, guid, 0x2710u, 2) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_channel_volume(buffer.data, buffer.length, &volume) ==
           LIBRDP_STATUS_OK);
    PCHECK(volume.value == 0x2710u && volume.second_value == 2);
    {
        rdp_video_redirection_volume valid_volume = volume;

        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_channel_volume(buffer.data,
                                                                                buffer.length - 1u,
                                                                                &volume),
                                     volume,
                                     valid_volume);
    }
    PCHECK(rdp_video_redirection_parse_header(buffer.data,
                                              buffer.length,
                                              1,
                                              &header) == LIBRDP_STATUS_OK);
    PCHECK(header.raw_interface_id == RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY);
    {
        rdp_video_redirection_header valid_header = header;

        buffer.data[3] = 0xc0u;
        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_header(buffer.data,
                                                                        buffer.length,
                                                                        1,
                                                                        &header),
                                     header,
                                     valid_header);
        buffer.data[3] = 0x40u;
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_redirection_write_header(&buffer,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              19,
                                              1,
                                              RDP_VIDEO_REDIRECTION_FUNC_SET_SOURCE_VIDEO_RECT) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&buffer, guid, sizeof(guid)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0x3f800000u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0x40000000u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0x40400000u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_source_video_rect(buffer.data,
                                                         buffer.length,
                                                         &source_rect) ==
           LIBRDP_STATUS_OK);
    PCHECK(source_rect.presentation_id[15] == 15 &&
           source_rect.left_bits == 0x3f800000u &&
           source_rect.right_bits == 0x40000000u &&
           source_rect.bottom_bits == 0x40400000u);
    {
        rdp_video_redirection_source_video_rect valid_rect = source_rect;

        PCHECK_VIDEO_PARSE_PRESERVES(rdp_video_redirection_parse_source_video_rect(
                                         buffer.data,
                                         buffer.length - 1u,
                                         &source_rect),
                                     source_rect,
                                     valid_rect);
    }

    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_free(&nested);
#undef PCHECK_VIDEO_PARSE_PRESERVES
    return 0;
}

/*
 * Coverage: validates video optimized remoting control/data vectors and
 * presentation request bounds.
 */
static int test_video_optimized_channel(void)
{
    const uint8_t extra[] = {0x67, 0x42, 0xc0, 0x15};
    const uint8_t sample[] = {0x00, 0x00, 0x01, 0x65, 0x88, 0x80};
    const uint8_t* h264 = rdp_video_optimized_h264_subtype_guid();
    rdp_buffer buffer;
    rdp_buffer payload;
    rdp_video_optimized_header header;
    rdp_video_optimized_presentation_request request;
    rdp_video_optimized_presentation_response response;
    rdp_video_optimized_client_notification notification;
    rdp_video_optimized_framerate_override framerate;
    rdp_video_optimized_video_data video;

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);

    PCHECK(rdp_video_optimized_write_header(&buffer,
                                            RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_REQUEST,
                                            8u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_optimized_parse_header(buffer.data, buffer.length, &header) ==
           LIBRDP_STATUS_OK);
    PCHECK(header.packet_type == RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_REQUEST &&
           header.size == 8u &&
           header.payload_len == 0);
    {
        rdp_video_optimized_header valid_header = header;

        buffer.data[4] = 0xffu;
        PCHECK(rdp_video_optimized_parse_header(buffer.data, buffer.length, &header) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&header, &valid_header, sizeof(header)) == 0);
        buffer.data[4] = RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_REQUEST;
        buffer.data[0] = 9u;
        PCHECK(rdp_video_optimized_parse_header(buffer.data, buffer.length, &header) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&header, &valid_header, sizeof(header)) == 0);
    }
    buffer.length = 0;
    PCHECK(rdp_video_optimized_write_header(&buffer, 0xffffffffu, 8u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);

    PCHECK(rdp_video_optimized_write_presentation_start_request(&buffer,
                                                                3,
                                                                29,
                                                                4800,
                                                                480,
                                                                244,
                                                                480,
                                                                244,
                                                                66609445540u,
                                                                0x80007aba00040222u,
                                                                h264,
                                                                extra,
                                                                sizeof(extra)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_optimized_parse_header(buffer.data, buffer.length, &header) ==
           LIBRDP_STATUS_OK);
    PCHECK(header.size == buffer.length &&
           header.packet_type == RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_REQUEST);
    PCHECK(rdp_video_optimized_parse_presentation_request(buffer.data,
                                                          buffer.length,
                                                          &request) == LIBRDP_STATUS_OK);
    PCHECK(request.presentation_id == 3 &&
           request.command == RDP_VIDEO_OPTIMIZED_COMMAND_START &&
           request.extra_len == sizeof(extra) &&
           request.geometry_mapping_id == 0x80007aba00040222u);
    {
        rdp_video_optimized_presentation_request valid_request = request;

        buffer.data[16] = 0;
        buffer.data[17] = 0;
        buffer.data[18] = 0;
        buffer.data[19] = 0;
        PCHECK(rdp_video_optimized_parse_presentation_request(buffer.data,
                                                              buffer.length,
                                                              &request) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&request, &valid_request, sizeof(request)) == 0);
        buffer.data[16] = 0xc0u;
        buffer.data[17] = 0x12u;
        buffer.data[18] = 0;
        buffer.data[19] = 0;
        buffer.data[28] = 0x81;
        buffer.data[29] = 0x07;
        PCHECK(rdp_video_optimized_parse_presentation_request(buffer.data,
                                                              buffer.length,
                                                              &request) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&request, &valid_request, sizeof(request)) == 0);
    }
    PCHECK(rdp_video_optimized_write_presentation_start_request(
               &payload,
               3,
               29,
               4800,
               480,
               244,
               RDP_VIDEO_OPTIMIZED_MAX_SCALED_WIDTH + 1u,
               244,
               0,
               0,
               h264,
               NULL,
               0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_video_optimized_write_presentation_start_request(
               &payload,
               3,
               29,
               4800,
               0,
               244,
               480,
               244,
               0,
               0,
               h264,
               NULL,
               0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);

    PCHECK(rdp_video_optimized_write_presentation_stop_request(&buffer, 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_optimized_parse_presentation_request(buffer.data,
                                                          buffer.length,
                                                          &request) == LIBRDP_STATUS_OK);
    PCHECK(request.command == RDP_VIDEO_OPTIMIZED_COMMAND_STOP);
    {
        rdp_video_optimized_presentation_request valid_request = request;

        PCHECK(rdp_buffer_append_u8(&buffer, 0) == LIBRDP_STATUS_OK);
        PCHECK(rdp_video_optimized_parse_presentation_request(buffer.data,
                                                              buffer.length,
                                                              &request) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&request, &valid_request, sizeof(request)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_optimized_write_presentation_response(&buffer, 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_optimized_parse_presentation_response(buffer.data,
                                                           buffer.length,
                                                           &response) == LIBRDP_STATUS_OK);
    PCHECK(response.presentation_id == 3 && response.result_flags == 0);
    {
        rdp_video_optimized_presentation_response valid_response = response;

        buffer.data[9] = 1;
        PCHECK(rdp_video_optimized_parse_presentation_response(buffer.data,
                                                               buffer.length,
                                                               &response) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&response, &valid_response, sizeof(response)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_optimized_write_framerate_override(&payload,
                                                        RDP_VIDEO_OPTIMIZED_FRAMERATE_OVERRIDE,
                                                        15) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_optimized_parse_framerate_override(payload.data,
                                                        payload.length,
                                                        &framerate) == LIBRDP_STATUS_OK);
    PCHECK(framerate.flags == RDP_VIDEO_OPTIMIZED_FRAMERATE_OVERRIDE &&
           framerate.desired_frame_rate == 15);
    {
        rdp_video_optimized_framerate_override valid_framerate = framerate;

        payload.data[12] = 1;
        PCHECK(rdp_video_optimized_parse_framerate_override(payload.data,
                                                            payload.length,
                                                            &framerate) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&framerate, &valid_framerate, sizeof(framerate)) == 0);
        payload.data[12] = 0;
    }
    PCHECK(rdp_video_optimized_write_client_notification(
               &buffer,
               3,
               RDP_VIDEO_OPTIMIZED_NOTIFICATION_FRAMERATE_OVERRIDE,
               payload.data,
               (uint32_t)payload.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_optimized_parse_client_notification(buffer.data,
                                                         buffer.length,
                                                         &notification) == LIBRDP_STATUS_OK);
    PCHECK(notification.notification_type == RDP_VIDEO_OPTIMIZED_NOTIFICATION_FRAMERATE_OVERRIDE &&
           notification.data_len == 16u);
    {
        rdp_video_optimized_client_notification valid_notification = notification;

        buffer.data[14] = 15u;
        PCHECK(rdp_video_optimized_parse_client_notification(buffer.data,
                                                             buffer.length,
                                                             &notification) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&notification, &valid_notification, sizeof(notification)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);

    PCHECK(rdp_video_optimized_write_client_notification(&buffer,
                                                         3,
                                                         RDP_VIDEO_OPTIMIZED_NOTIFICATION_NETWORK_ERROR,
                                                         NULL,
                                                         0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_optimized_parse_client_notification(buffer.data,
                                                         buffer.length,
                                                         &notification) == LIBRDP_STATUS_OK);
    PCHECK(notification.notification_type == RDP_VIDEO_OPTIMIZED_NOTIFICATION_NETWORK_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_optimized_write_video_data(
               &buffer,
               3,
               RDP_VIDEO_OPTIMIZED_DATA_FLAG_HAS_TIMESTAMPS | RDP_VIDEO_OPTIMIZED_DATA_FLAG_KEYFRAME,
               444103u,
               0,
               1,
               1,
               1,
               sample,
               sizeof(sample)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_optimized_parse_video_data(buffer.data, buffer.length, &video) ==
           LIBRDP_STATUS_OK);
    PCHECK(video.timestamp == 444103u &&
           video.sample_len == sizeof(sample) &&
           video.sample[3] == 0x65);
    {
        rdp_video_optimized_video_data valid_video = video;

        buffer.data[28] = 2;
        PCHECK(rdp_video_optimized_parse_video_data(buffer.data, buffer.length, &video) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&video, &valid_video, sizeof(video)) == 0);
    }
    PCHECK(rdp_video_optimized_write_video_data(&payload,
                                                3,
                                                RDP_VIDEO_OPTIMIZED_DATA_FLAG_KEYFRAME,
                                                0,
                                                0,
                                                2,
                                                1,
                                                1,
                                                sample,
                                                sizeof(sample)) == LIBRDP_STATUS_INVALID_ARGUMENT);

    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    return 0;
}

/*
 * Coverage: validates GDI order parsing and rendering vectors across cache,
 * brush, glyph, bitmap, and raster-operation edge cases.
 */
static int test_gdi_orders(void)
{
    const uint8_t secondary_payload[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    const uint8_t cache_bitmap_payload[] = {
        1u, 0u, 2u, 2u, 32u, 16u, 0u, 5u, 0u,
        0x10u, 0x20u, 0x30u, 0xffu,
        0x11u, 0x21u, 0x31u, 0xffu,
        0x12u, 0x22u, 0x32u, 0xffu,
        0x13u, 0x23u, 0x33u, 0xffu
    };
    const uint8_t cache_bitmap_compressed_payload[] = {
        2u, 0u, 2u, 2u, 24u, 12u, 0u, 6u, 0u,
        0u, 0u, 4u, 0u, 0u, 0u, 8u, 0u,
        0x00u, 0x01u, 0x02u, 0x03u
    };
    const uint8_t cache_bitmap_v2_payload[] = {
        2u,
        2u,
        16u,
        7u,
        0x20u, 0x30u, 0x40u, 0xffu,
        0x21u, 0x31u, 0x41u, 0xffu,
        0x22u, 0x32u, 0x42u, 0xffu,
        0x23u, 0x33u, 0x43u, 0xffu
    };
    const uint8_t cache_bitmap_v2_compressed_payload[] = {
        2u,
        2u,
        4u,
        8u,
        0x00u, 0x01u, 0x02u, 0x03u
    };
    const uint8_t cache_bitmap_v3_payload[] = {
        9u, 0u,
        0x44u, 0x33u, 0x22u, 0x11u,
        0x88u, 0x77u, 0x66u, 0x55u,
        32u, 0u, 0u, RDP_SURFACE_CODEC_NONE,
        2u, 0u,
        2u, 0u,
        16u, 0u, 0u, 0u,
        0x30u, 0x40u, 0x50u, 0xffu,
        0x31u, 0x41u, 0x51u, 0xffu,
        0x32u, 0x42u, 0x52u, 0xffu,
        0x33u, 0x43u, 0x53u, 0xffu
    };
    const uint8_t cache_bitmap_v3_wait_payload[] = {
        0xffu, 0x7fu,
        0x04u, 0x03u, 0x02u, 0x01u,
        0x08u, 0x07u, 0x06u, 0x05u,
        32u, 0u, 0u, RDP_SURFACE_CODEC_NONE,
        1u, 0u,
        1u, 0u,
        4u, 0u, 0u, 0u,
        0xaau, 0xbbu, 0xccu, 0xffu
    };
    const uint8_t cache_bitmap_v3_rfx_payload[] = {
        10u, 0u,
        0x14u, 0x13u, 0x12u, 0x11u,
        0x18u, 0x17u, 0x16u, 0x15u,
        32u, 0u, 0u, RDP_SURFACE_CODEC_REMOTEFX,
        64u, 0u,
        64u, 0u,
        4u, 0u, 0u, 0u,
        0xc0u, 0xccu, 0x06u, 0x00u
    };
    const uint8_t cache_brush_mono_payload[] = {
        3u, RDP_GDI_BMF_1BPP, 8u, 8u, 0u, 8u,
        0x01u, 0x02u, 0x04u, 0x08u, 0x10u, 0x20u, 0x40u, 0x80u
    };
    const uint8_t cache_brush_color_payload[] = {
        4u, RDP_GDI_BMF_24BPP, 8u, 8u, 0u, 28u,
        0x00u, 0x55u, 0xaau, 0xffu,
        0x00u, 0x55u, 0xaau, 0xffu,
        0x00u, 0x55u, 0xaau, 0xffu,
        0x00u, 0x55u, 0xaau, 0xffu,
        0x01u, 0x02u, 0x03u,
        0x04u, 0x05u, 0x06u,
        0x07u, 0x08u, 0x09u,
        0x0au, 0x0bu, 0x0cu
    };
    const uint8_t cache_brush_bad_payload[] = {
        RDP_GDI_BRUSH_CACHE_ENTRIES, RDP_GDI_BMF_1BPP, 8u, 8u, 0u, 8u,
        0x01u, 0x02u, 0x04u, 0x08u, 0x10u, 0x20u, 0x40u, 0x80u
    };
    const uint8_t cache_glyph_v1_payload[] = {
        1u, 1u,
        2u, 0u,
        0u, 0u,
        0u, 0u,
        8u, 0u,
        2u, 0u,
        0x80u, 0x40u, 0u, 0u,
        'A', 0u
    };
    const uint8_t cache_glyph_v2_payload[] = {
        3u,
        1u,
        2u,
        8u,
        1u,
        0x80u, 0u, 0u, 0u,
        'B', 0u
    };
    const uint8_t primary_order[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_DSTBLT,
        0x0cu,
        0xaau,
        0xbbu
    };
    const uint8_t primary_bounds[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_BOUNDS | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_OPAQUERECT,
        0x0fu,
        0x03u,
        0x34u,
        0x12u,
        0x78u,
        0x56u,
        0xdeu,
        0xadu
    };
    const uint8_t render_opaque[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_OPAQUERECT,
        0x1fu,
        0x02u, 0x00u,
        0x03u, 0x00u,
        0x04u, 0x00u,
        0x05u, 0x00u,
        0x11u, 0x22u, 0x33u
    };
    const uint8_t render_opaque_delta[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_DELTA_COORDINATES,
        0x03u,
        0xfeu,
        0x04u
    };
    const uint8_t render_scrblt[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_SCRBLT,
        0x7fu,
        0x10u, 0x00u,
        0x20u, 0x00u,
        0x30u, 0x00u,
        0x40u, 0x00u,
        0xccu,
        0x01u, 0x00u,
        0x02u, 0x00u
    };
    const uint8_t render_dstblt_bounds[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE | RDP_GDI_TS_BOUNDS,
        RDP_GDI_ORDER_DSTBLT,
        0x1fu,
        0x0fu,
        0x01u, 0x00u,
        0x02u, 0x00u,
        0x08u, 0x00u,
        0x09u, 0x00u,
        0x04u, 0x00u,
        0x05u, 0x00u,
        0x06u, 0x00u,
        0x07u, 0x00u,
        0xffu
    };
    const uint8_t render_patblt[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_PATBLT,
        0x7fu, 0x00u,
        0x09u, 0x00u,
        0x0au, 0x00u,
        0x0bu, 0x00u,
        0x0cu, 0x00u,
        0xf0u,
        0x01u, 0x02u, 0x03u,
        0x21u, 0x22u, 0x23u
    };
    const uint8_t render_patblt_pattern[] = {
        RDP_GDI_TS_STANDARD,
        0xffu, 0x0fu,
        0x01u, 0x00u,
        0x02u, 0x00u,
        0x03u, 0x00u,
        0x04u, 0x00u,
        0xf0u,
        0x10u, 0x20u, 0x30u,
        0x40u, 0x50u, 0x60u,
        0x05u, 0x00u,
        0x06u, 0x00u,
        0x03u,
        0xaau,
        0x55u, 0xaau, 0x55u, 0xaau, 0x55u, 0xaau, 0x55u
    };
    const uint8_t render_memblt[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_MEMBLT,
        0xffu, 0x01u,
        0x03u, 0x02u,
        0x01u, 0x00u,
        0x02u, 0x00u,
        0x03u, 0x00u,
        0x04u, 0x00u,
        0xccu,
        0x05u, 0x00u,
        0x06u, 0x00u,
        0x34u, 0x12u
    };
    const uint8_t render_memblt_bad_width[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_MEMBLT,
        0xffu, 0x01u,
        0x03u, 0x02u,
        0x01u, 0x00u,
        0x02u, 0x00u,
        0xffu, 0xffu,
        0x04u, 0x00u,
        0xccu,
        0x05u, 0x00u,
        0x06u, 0x00u,
        0x34u, 0x12u
    };
    const uint8_t render_mem3blt[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_MEM3BLT,
        0xffu, 0xffu, 0x00u,
        0x04u, 0x03u,
        0x11u, 0x00u,
        0x12u, 0x00u,
        0x13u, 0x00u,
        0x14u, 0x00u,
        0xb8u,
        0x15u, 0x00u,
        0x16u, 0x00u,
        0x10u, 0x20u, 0x30u,
        0x40u, 0x50u, 0x60u,
        0x02u, 0x00u,
        0x03u, 0x00u,
        0x03u,
        0xaau,
        0x55u, 0xaau, 0x55u, 0xaau, 0x55u, 0xaau, 0x55u,
        0x78u, 0x56u
    };
    const uint8_t render_mem3blt_bad_height[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_MEM3BLT,
        0xffu, 0xffu, 0x00u,
        0x04u, 0x03u,
        0x11u, 0x00u,
        0x12u, 0x00u,
        0x13u, 0x00u,
        0xffu, 0xffu,
        0xb8u,
        0x15u, 0x00u,
        0x16u, 0x00u,
        0x10u, 0x20u, 0x30u,
        0x40u, 0x50u, 0x60u,
        0x02u, 0x00u,
        0x03u, 0x00u,
        0x03u,
        0xaau,
        0x55u, 0xaau, 0x55u, 0xaau, 0x55u, 0xaau, 0x55u,
        0x78u, 0x56u
    };
    const uint8_t render_lineto[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_LINETO,
        0xffu, 0x03u,
        0x01u, 0x00u,
        0x02u, 0x00u,
        0x03u, 0x00u,
        0x04u, 0x00u,
        0x05u, 0x00u,
        0x06u, 0x07u, 0x08u,
        13u,
        0x00u,
        0x01u,
        0x31u, 0x32u, 0x33u
    };
    const uint8_t render_lineto_dash[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_LINETO,
        0xffu, 0x03u,
        0x01u, 0x00u,
        0x02u, 0x00u,
        0x03u, 0x00u,
        0x0cu, 0x00u,
        0x02u, 0x00u,
        0x06u, 0x07u, 0x08u,
        13u,
        0x01u,
        0x01u,
        0x31u, 0x32u, 0x33u
    };
    const uint8_t render_polyline[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_POLYLINE,
        0x7fu,
        0x0au, 0x00u,
        0x0bu, 0x00u,
        13u,
        0x00u, 0x00u,
        0x01u, 0x02u, 0x03u,
        2u,
        3u,
        0x60u,
        0x02u,
        0x03u
    };
    const uint8_t render_polygon_sc[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_POLYGON_SC,
        0x7fu,
        0x14u, 0x00u,
        0x14u, 0x00u,
        13u,
        1u,
        0x44u, 0x55u, 0x66u,
        3u,
        4u,
        0x64u,
        0x04u,
        0x04u,
        0x7cu
    };
    const uint8_t render_polygon_cb[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_POLYGON_CB,
        0xffu, 0x1fu,
        0x1eu, 0x00u,
        0x1eu, 0x00u,
        0x8du,
        1u,
        0x10u, 0x20u, 0x30u,
        0x40u, 0x50u, 0x60u,
        0x05u, 0x00u,
        0x06u, 0x00u,
        0x03u,
        0xaau,
        0x55u, 0xaau, 0x55u, 0xaau, 0x55u, 0xaau, 0x55u,
        3u,
        4u,
        0x64u,
        0x04u,
        0x04u,
        0x7cu
    };
    const uint8_t render_ellipse_sc[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_ELLIPSE_SC,
        0x7fu,
        0x05u, 0x00u,
        0x06u, 0x00u,
        0x0au, 0x00u,
        0x0cu, 0x00u,
        13u,
        1u,
        0x88u, 0x99u, 0xaau
    };
    const uint8_t render_ellipse_cb[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_ELLIPSE_CB,
        0xffu, 0x1fu,
        0x05u, 0x00u,
        0x06u, 0x00u,
        0x0au, 0x00u,
        0x0cu, 0x00u,
        0x8du,
        1u,
        0x10u, 0x20u, 0x30u,
        0x40u, 0x50u, 0x60u,
        0x02u, 0x00u,
        0x03u, 0x00u,
        0x02u,
        0x04u,
        0x55u, 0xaau, 0x55u, 0xaau, 0x55u, 0xaau, 0x55u
    };
    const uint8_t render_multi_dstblt[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_MULTIDSTBLT,
        0x7fu,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0xffu,
        2u,
        7u, 0x00u,
        0x06u,
        0x02u, 0x03u, 0x04u, 0x05u,
        0x0au, 0x06u
    };
    const uint8_t render_multi_scrblt[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_MULTISCRBLT,
        0xffu, 0x01u,
        0x02u, 0x00u,
        0x03u, 0x00u,
        0x04u, 0x00u,
        0x05u, 0x00u,
        0xccu,
        0x14u, 0x00u,
        0x1eu, 0x00u,
        2u,
        7u, 0x00u,
        0x06u,
        0x02u, 0x03u, 0x04u, 0x05u,
        0x0au, 0x06u
    };
    const uint8_t render_multi_patblt[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_MULTIPATBLT,
        0xffu, 0x3fu,
        0x01u, 0x00u,
        0x02u, 0x00u,
        0x03u, 0x00u,
        0x04u, 0x00u,
        0xf0u,
        0x10u, 0x20u, 0x30u,
        0x40u, 0x50u, 0x60u,
        0x05u, 0x00u,
        0x06u, 0x00u,
        0x03u,
        0xaau,
        0x55u, 0xaau, 0x55u, 0xaau, 0x55u, 0xaau, 0x55u,
        2u,
        7u, 0x00u,
        0x06u,
        0x02u, 0x03u, 0x04u, 0x05u,
        0x0au, 0x06u
    };
    const uint8_t render_multi_opaque[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_MULTIOPAQUERECT,
        0xffu, 0x01u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x11u, 0x22u, 0x33u,
        2u,
        7u, 0x00u,
        0x06u,
        0x02u, 0x03u, 0x04u, 0x05u,
        0x0au, 0x06u
    };
    const uint8_t render_save_bitmap[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_SAVEBITMAP,
        0x3fu,
        0x78u, 0x56u, 0x34u, 0x12u,
        0x02u, 0x00u,
        0x03u, 0x00u,
        0x06u, 0x00u,
        0x08u, 0x00u,
        0x00u
    };
    const uint8_t render_draw_ninegrid[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_BOUNDS | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_DRAWNINEGRID,
        0x1fu,
        0x0fu,
        0x0au, 0x00u,
        0x14u, 0x00u,
        0x1du, 0x00u,
        0x27u, 0x00u,
        0x01u, 0x00u,
        0x02u, 0x00u,
        0x08u, 0x00u,
        0x09u, 0x00u,
        0x34u, 0x12u
    };
    const uint8_t render_multi_draw_ninegrid[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_MULTI_DRAWNINEGRID,
        0x7fu,
        0x00u, 0x00u,
        0x01u, 0x00u,
        0x08u, 0x00u,
        0x09u, 0x00u,
        0x78u, 0x56u,
        2u,
        9u, 0x00u,
        0x00u,
        1u, 2u, 3u, 4u,
        5u, 6u, 7u, 8u
    };
    const uint8_t render_glyph_index[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_GLYPH_INDEX,
        0xffu, 0x3fu, 0x38u,
        1u,
        RDP_GDI_GLYPH_SO_HORIZONTAL,
        0u,
        0u,
        0x01u, 0x02u, 0x03u,
        0x04u, 0x05u, 0x06u,
        0u, 0u,
        0u, 0u,
        20u, 0u,
        10u, 0u,
        0u, 0u,
        0u, 0u,
        20u, 0u,
        10u, 0u,
        1u, 0u,
        2u, 0u,
        1u,
        2u
    };
    const uint8_t render_fast_index[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_FAST_INDEX,
        0xffu, 0x7fu,
        1u,
        5u, RDP_GDI_GLYPH_SO_HORIZONTAL,
        0x01u, 0x02u, 0x03u,
        0x04u, 0x05u, 0x06u,
        0u, 0u,
        0u, 0u,
        20u, 0u,
        10u, 0u,
        0u, 0u,
        0u, 0u,
        20u, 0u,
        10u, 0u,
        1u, 0u,
        2u, 0u,
        1u,
        2u
    };
    const uint8_t render_fast_glyph[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_FAST_GLYPH,
        0xffu, 0x7fu,
        1u,
        5u, RDP_GDI_GLYPH_SO_HORIZONTAL,
        0x01u, 0x02u, 0x03u,
        0x04u, 0x05u, 0x06u,
        0u, 0u,
        0u, 0u,
        20u, 0u,
        10u, 0u,
        0u, 0u,
        0u, 0u,
        20u, 0u,
        10u, 0u,
        1u, 0u,
        2u, 0u,
        9u,
        4u,
        0u,
        0u,
        8u,
        1u,
        0x80u, 0u, 0u, 0u
    };
    const uint8_t render_rejected[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        0x1fu
    };
    const uint8_t create_ninegrid_payload[] = {
        32u,
        0x34u, 0x12u,
        0x01u, 0x00u, 0x00u, 0x00u,
        0x02u, 0x00u,
        0x03u, 0x00u,
        0x04u, 0x00u,
        0x05u, 0x00u,
        0xccu, 0xbbu, 0xaau, 0x00u
    };
    const uint8_t bad_bounds[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_BOUNDS | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_OPAQUERECT,
        0x01u,
        0x11u
    };
    const uint8_t altsec_order[] = {
        (uint8_t)((RDP_GDI_ALTSEC_SWITCH_SURFACE << 2u) | RDP_GDI_TS_SECONDARY),
        0x34u,
        0x12u
    };
    const uint8_t create_offscreen_payload[] = {
        0x45u, 0x80u,
        0x20u, 0x00u,
        0x10u, 0x00u,
        0x02u, 0x00u,
        0x01u, 0x00u,
        0xffu, 0x7fu
    };
    const uint8_t frame_marker_payload[] = {
        0x01u, 0x00u, 0x00u, 0x00u
    };
    const uint8_t stream_first_payload[] = {
        0x00u,
        32u,
        0x02u, 0x00u,
        0x02u, 0x00u,
        0x01u, 0x00u,
        0x08u, 0x00u,
        0x04u, 0x00u,
        0x10u, 0x20u, 0x30u, 0xffu
    };
    const uint8_t stream_next_payload[] = {
        RDP_GDI_STREAM_BITMAP_END,
        0x02u, 0x00u,
        0x04u, 0x00u,
        0x11u, 0x21u, 0x31u, 0xffu
    };
    const uint8_t stream_first_v2_payload[] = {
        RDP_GDI_STREAM_BITMAP_END | RDP_GDI_STREAM_BITMAP_V2,
        24u,
        0x03u, 0x00u,
        0x01u, 0x00u,
        0x01u, 0x00u,
        0x03u, 0x00u, 0x00u, 0x00u,
        0x03u, 0x00u,
        0x01u, 0x02u, 0x03u
    };
    const uint8_t slow_zero_with_data[] = {
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0xffu
    };
    const uint8_t fast_zero_with_data[] = {
        0x00u, 0x00u,
        0xffu
    };
    rdp_buffer secondary;
    rdp_buffer slow;
    rdp_buffer fast;
    rdp_buffer mixed;
    rdp_buffer payload;
    rdp_buffer capability;
    rdp_gdi_orders_update update;
    rdp_gdi_order_list list;
    rdp_gdi_primary_order_header primary;
    rdp_gdi_secondary_order_header secondary_header;
    rdp_gdi_cache_bitmap_order cache_bitmap;
    rdp_gdi_cache_color_table_order cache_color_table;
    rdp_gdi_cache_brush_order cache_brush;
    rdp_gdi_cache_glyph_order cache_glyph;
    rdp_gdi_altsec_order_header altsec;
    rdp_gdi_bitmap_cache_error bitmap_error;
    rdp_gdi_bitmap_cache_error parsed_error;
    rdp_gdi_color_cache_capability color;
    rdp_gdi_ninegrid_capability ninegrid;
    rdp_gdi_create_ninegrid_bitmap_order create_ninegrid;
    rdp_gdi_create_offscreen_bitmap_order create_offscreen;
    rdp_gdi_switch_surface_order switch_surface;
    rdp_gdi_frame_marker_order frame_marker;
    rdp_gdi_stream_bitmap_first_order stream_first;
    rdp_gdi_stream_bitmap_next_order stream_next;
    rdp_gdi_gdiplus_capability gdiplus;
    rdp_gdi_render_state render_state;
    rdp_gdi_render_state render_state_before_error;
    rdp_gdi_render_op render_op;
    size_t render_consumed = 0;
    uint32_t flags = 0;
    size_t i = 0;

    rdp_buffer_init(&secondary);
    rdp_buffer_init(&slow);
    rdp_buffer_init(&fast);
    rdp_buffer_init(&mixed);
    rdp_buffer_init(&payload);
    rdp_buffer_init(&capability);

    PCHECK(rdp_gdi_write_secondary_order(&secondary,
                                         0x0400u,
                                         RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED,
                                         secondary_payload,
                                         sizeof(secondary_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_write_secondary_order(&payload,
                                         0,
                                         RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED,
                                         secondary_payload,
                                         6) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_gdi_parse_secondary_order(secondary.data,
                                         secondary.length,
                                         &secondary_header) == LIBRDP_STATUS_OK);
    PCHECK(secondary_header.actual_length == secondary.length &&
           secondary_header.payload_len == sizeof(secondary_payload) &&
           secondary_header.order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED);
    {
        const uint8_t invalid_secondary_header[] = {
            RDP_GDI_TS_STANDARD | RDP_GDI_TS_SECONDARY,
            0x00u, 0x00u,
            0x00u, 0x00u,
            0xffu
        };
        rdp_gdi_secondary_order_header valid_secondary_header = secondary_header;

        PCHECK(rdp_gdi_parse_secondary_order(invalid_secondary_header,
                                             sizeof(invalid_secondary_header),
                                             &secondary_header) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&secondary_header,
                      &valid_secondary_header,
                      sizeof(secondary_header)) == 0);
    }
    PCHECK(rdp_gdi_parse_cache_bitmap_order(&secondary_header, &cache_bitmap) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&secondary);
    rdp_buffer_init(&secondary);
    PCHECK(rdp_gdi_write_secondary_order(&secondary,
                                         0,
                                         RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED,
                                         cache_bitmap_payload,
                                         sizeof(cache_bitmap_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_secondary_order(secondary.data,
                                         secondary.length,
                                         &secondary_header) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_cache_bitmap_order(&secondary_header, &cache_bitmap) == LIBRDP_STATUS_OK);
    PCHECK(cache_bitmap.cache_id == 1 &&
           cache_bitmap.cache_index == 5 &&
           cache_bitmap.width == 2 &&
           cache_bitmap.height == 2 &&
           cache_bitmap.bits_per_pixel == 32 &&
           cache_bitmap.bitmap_data_len == 16 &&
           cache_bitmap.bitmap_data[0] == 0x10u &&
           !cache_bitmap.compressed);
    rdp_buffer_free(&secondary);
    rdp_buffer_init(&secondary);
    PCHECK(rdp_gdi_write_secondary_order(&secondary,
                                         0,
                                         RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED,
                                         cache_bitmap_compressed_payload,
                                         sizeof(cache_bitmap_compressed_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_secondary_order(secondary.data,
                                         secondary.length,
                                         &secondary_header) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_cache_bitmap_order(&secondary_header, &cache_bitmap) == LIBRDP_STATUS_OK);
    PCHECK(cache_bitmap.cache_id == 2 &&
           cache_bitmap.cache_index == 6 &&
           cache_bitmap.compressed &&
           cache_bitmap.has_compression_header &&
           cache_bitmap.bitmap_data_includes_compression_header &&
           cache_bitmap.bitmap_data_len == 12 &&
           cache_bitmap.compression_header[2] == 4u);
    rdp_buffer_free(&secondary);
    rdp_buffer_init(&secondary);
    PCHECK(rdp_gdi_write_secondary_order(&secondary,
                                         (uint16_t)(1u | (6u << 3u)),
                                         RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED_REV2,
                                         cache_bitmap_v2_payload,
                                         sizeof(cache_bitmap_v2_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_secondary_order(secondary.data,
                                         secondary.length,
                                         &secondary_header) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_cache_bitmap_order(&secondary_header, &cache_bitmap) == LIBRDP_STATUS_OK);
    PCHECK(cache_bitmap.cache_id == 1 &&
           cache_bitmap.cache_index == 7 &&
           cache_bitmap.bits_per_pixel == 32 &&
           cache_bitmap.width == 2 &&
           cache_bitmap.height == 2 &&
           !cache_bitmap.compressed &&
           cache_bitmap.bitmap_data_len == 16 &&
           cache_bitmap.bitmap_data[0] == 0x20u);
    {
        rdp_gdi_cache_bitmap_order valid_cache_bitmap = cache_bitmap;

        rdp_buffer_free(&secondary);
        rdp_buffer_init(&secondary);
        PCHECK(rdp_gdi_write_secondary_order(&secondary,
                                             (uint16_t)(1u | (6u << 3u) | (0x04u << 7u)),
                                             RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED_REV2,
                                             cache_bitmap_v2_payload,
                                             sizeof(cache_bitmap_v2_payload)) == LIBRDP_STATUS_OK);
        PCHECK(rdp_gdi_parse_secondary_order(secondary.data,
                                             secondary.length,
                                             &secondary_header) == LIBRDP_STATUS_OK);
        PCHECK(rdp_gdi_parse_cache_bitmap_order(&secondary_header, &cache_bitmap) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&cache_bitmap, &valid_cache_bitmap, sizeof(cache_bitmap)) == 0);
    }
    rdp_buffer_free(&secondary);
    rdp_buffer_init(&secondary);
    PCHECK(rdp_gdi_write_secondary_order(&secondary,
                                         (uint16_t)(2u | (5u << 3u) |
                                                    (RDP_GDI_CBR2_NO_BITMAP_COMPRESSION_HEADER << 7u)),
                                         RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV2,
                                         cache_bitmap_v2_compressed_payload,
                                         sizeof(cache_bitmap_v2_compressed_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_secondary_order(secondary.data,
                                         secondary.length,
                                         &secondary_header) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_cache_bitmap_order(&secondary_header, &cache_bitmap) == LIBRDP_STATUS_OK);
    PCHECK(cache_bitmap.cache_id == 2 &&
           cache_bitmap.cache_index == 8 &&
           cache_bitmap.bits_per_pixel == 24 &&
           cache_bitmap.compressed &&
           !cache_bitmap.has_compression_header &&
           !cache_bitmap.bitmap_data_includes_compression_header &&
           cache_bitmap.bitmap_data_len == 4);
    rdp_buffer_free(&secondary);
    rdp_buffer_init(&secondary);
    PCHECK(rdp_gdi_write_secondary_order(&secondary,
                                         (uint16_t)(2u | (6u << 3u) |
                                                    (RDP_GDI_CBR3_IGNORABLE_FLAG << 7u)),
                                         RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV3,
                                         cache_bitmap_v3_payload,
                                         sizeof(cache_bitmap_v3_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_secondary_order(secondary.data,
                                         secondary.length,
                                         &secondary_header) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_cache_bitmap_order(&secondary_header, &cache_bitmap) == LIBRDP_STATUS_OK);
    PCHECK(cache_bitmap.rev3 &&
           cache_bitmap.cache_id == 2 &&
           cache_bitmap.cache_index == 9 &&
           cache_bitmap.key1 == 0x11223344u &&
           cache_bitmap.key2 == 0x55667788u &&
           cache_bitmap.bits_per_pixel == 32 &&
           cache_bitmap.codec_id == RDP_SURFACE_CODEC_NONE &&
           cache_bitmap.width == 2 &&
           cache_bitmap.height == 2 &&
           !cache_bitmap.compressed &&
           cache_bitmap.bitmap_data_len == 16 &&
           cache_bitmap.bitmap_data[0] == 0x30u);
    rdp_buffer_free(&secondary);
    rdp_buffer_init(&secondary);
    PCHECK(rdp_gdi_write_secondary_order(&secondary,
                                         (uint16_t)(2u | (6u << 3u) |
                                                    ((RDP_GDI_CBR3_IGNORABLE_FLAG |
                                                      RDP_GDI_CBR3_DO_NOT_CACHE) << 7u)),
                                         RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV3,
                                         cache_bitmap_v3_wait_payload,
                                         sizeof(cache_bitmap_v3_wait_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_secondary_order(secondary.data,
                                         secondary.length,
                                         &secondary_header) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_cache_bitmap_order(&secondary_header, &cache_bitmap) == LIBRDP_STATUS_OK);
    PCHECK(cache_bitmap.rev3 &&
           cache_bitmap.cache_id == 2 &&
           cache_bitmap.cache_index == RDP_GDI_BITMAP_CACHE_WAITING_LIST_INDEX &&
           cache_bitmap.do_not_cache &&
           cache_bitmap.codec_id == RDP_SURFACE_CODEC_NONE &&
           cache_bitmap.bitmap_data_len == 4);
    rdp_buffer_free(&secondary);
    rdp_buffer_init(&secondary);
    PCHECK(rdp_gdi_write_secondary_order(&secondary,
                                         (uint16_t)(2u | (6u << 3u) |
                                                    (RDP_GDI_CBR3_IGNORABLE_FLAG << 7u)),
                                         RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV3,
                                         cache_bitmap_v3_rfx_payload,
                                         sizeof(cache_bitmap_v3_rfx_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_secondary_order(secondary.data,
                                         secondary.length,
                                         &secondary_header) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_cache_bitmap_order(&secondary_header, &cache_bitmap) == LIBRDP_STATUS_OK);
    PCHECK(cache_bitmap.rev3 &&
           cache_bitmap.cache_id == 2 &&
           cache_bitmap.cache_index == 10 &&
           cache_bitmap.key1 == 0x11121314u &&
           cache_bitmap.key2 == 0x15161718u &&
           cache_bitmap.codec_id == RDP_SURFACE_CODEC_REMOTEFX &&
           cache_bitmap.compressed &&
           cache_bitmap.width == 64 &&
           cache_bitmap.height == 64 &&
           cache_bitmap.bitmap_data_len == 4);
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);
    PCHECK(rdp_buffer_append_u8(&payload, 9u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&payload, RDP_BITMAP_PALETTE_MAX_ENTRIES) == LIBRDP_STATUS_OK);
    for (i = 0; i < RDP_BITMAP_PALETTE_MAX_ENTRIES; i++)
    {
        PCHECK(rdp_buffer_append_u8(&payload, (uint8_t)i) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u8(&payload, (uint8_t)(255u - i)) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u8(&payload, (uint8_t)(i ^ 0x55u)) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append_u8(&payload, 0u) == LIBRDP_STATUS_OK);
    }
    rdp_buffer_free(&secondary);
    rdp_buffer_init(&secondary);
    PCHECK(rdp_gdi_write_secondary_order(&secondary,
                                         0,
                                         RDP_GDI_SECONDARY_CACHE_COLOR_TABLE,
                                         payload.data,
                                         payload.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_secondary_order(secondary.data,
                                         secondary.length,
                                         &secondary_header) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_cache_color_table_order(&secondary_header, &cache_color_table) ==
           LIBRDP_STATUS_OK);
    PCHECK(cache_color_table.cache_index == 9 &&
           cache_color_table.palette.count == RDP_BITMAP_PALETTE_MAX_ENTRIES &&
           cache_color_table.palette.entries[3].blue == 3u &&
           cache_color_table.palette.entries[3].green == 252u &&
           cache_color_table.palette.entries[3].red == 0x56u);
    {
        rdp_gdi_cache_color_table_order valid_cache_color_table = cache_color_table;
        rdp_gdi_secondary_order_header invalid_color_table_header = secondary_header;

        invalid_color_table_header.payload_len--;
        PCHECK(rdp_gdi_parse_cache_color_table_order(&invalid_color_table_header,
                                                     &cache_color_table) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&cache_color_table,
                      &valid_cache_color_table,
                      sizeof(cache_color_table)) == 0);
    }

    rdp_buffer_free(&secondary);
    rdp_buffer_init(&secondary);
    PCHECK(rdp_gdi_write_secondary_order(&secondary,
                                         0,
                                         RDP_GDI_SECONDARY_CACHE_BRUSH,
                                         cache_brush_mono_payload,
                                         sizeof(cache_brush_mono_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_secondary_order(secondary.data,
                                         secondary.length,
                                         &secondary_header) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_cache_brush_order(&secondary_header, &cache_brush) == LIBRDP_STATUS_OK);
    PCHECK(cache_brush.cache_entry == 3 &&
           cache_brush.bitmap_format == RDP_GDI_BMF_1BPP &&
           cache_brush.width == 8 &&
           cache_brush.height == 8 &&
           cache_brush.brush_data_len == 8 &&
           cache_brush.brush_data[7] == 0x80u);

    rdp_buffer_free(&secondary);
    rdp_buffer_init(&secondary);
    PCHECK(rdp_gdi_write_secondary_order(&secondary,
                                         0,
                                         RDP_GDI_SECONDARY_CACHE_BRUSH,
                                         cache_brush_color_payload,
                                         sizeof(cache_brush_color_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_secondary_order(secondary.data,
                                         secondary.length,
                                         &secondary_header) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_cache_brush_order(&secondary_header, &cache_brush) == LIBRDP_STATUS_OK);
    PCHECK(cache_brush.cache_entry == 4 &&
           cache_brush.bitmap_format == RDP_GDI_BMF_24BPP &&
           cache_brush.brush_data_len == 28 &&
           cache_brush.brush_data[16] == 0x01u &&
           cache_brush.brush_data[27] == 0x0cu);
    {
        rdp_gdi_cache_brush_order valid_cache_brush = cache_brush;

        rdp_buffer_free(&secondary);
        rdp_buffer_init(&secondary);
        PCHECK(rdp_gdi_write_secondary_order(&secondary,
                                             0,
                                             RDP_GDI_SECONDARY_CACHE_BRUSH,
                                             cache_brush_bad_payload,
                                             sizeof(cache_brush_bad_payload)) == LIBRDP_STATUS_OK);
        PCHECK(rdp_gdi_parse_secondary_order(secondary.data,
                                             secondary.length,
                                             &secondary_header) == LIBRDP_STATUS_OK);
        PCHECK(rdp_gdi_parse_cache_brush_order(&secondary_header, &cache_brush) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&cache_brush, &valid_cache_brush, sizeof(cache_brush)) == 0);
    }

    rdp_buffer_free(&secondary);
    rdp_buffer_init(&secondary);
    PCHECK(rdp_gdi_write_secondary_order(&secondary,
                                         RDP_GDI_CACHE_GLYPH_UNICODE_PRESENT,
                                         RDP_GDI_SECONDARY_CACHE_GLYPH,
                                         cache_glyph_v1_payload,
                                         sizeof(cache_glyph_v1_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_secondary_order(secondary.data,
                                         secondary.length,
                                         &secondary_header) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_cache_glyph_order(&secondary_header, &cache_glyph) == LIBRDP_STATUS_OK);
    PCHECK(cache_glyph.version == 1 &&
           cache_glyph.cache_id == 1 &&
           cache_glyph.glyph_count == 1 &&
           cache_glyph.glyphs[0].cache_index == 2 &&
           cache_glyph.glyphs[0].width == 8 &&
           cache_glyph.glyphs[0].height == 2 &&
           cache_glyph.glyphs[0].bitmap_len == 4 &&
           cache_glyph.glyphs[0].bitmap[1] == 0x40u &&
           cache_glyph.glyphs[0].has_unicode &&
           cache_glyph.glyphs[0].unicode_codepoint == 'A');

    rdp_buffer_free(&secondary);
    rdp_buffer_init(&secondary);
    PCHECK(rdp_gdi_write_secondary_order(&secondary,
                                         (uint16_t)(1u |
                                                    RDP_GDI_CACHE_GLYPH_UNICODE_PRESENT |
                                                    (1u << 8u)),
                                         RDP_GDI_SECONDARY_CACHE_GLYPH,
                                         cache_glyph_v2_payload,
                                         sizeof(cache_glyph_v2_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_secondary_order(secondary.data,
                                         secondary.length,
                                         &secondary_header) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_cache_glyph_order(&secondary_header, &cache_glyph) == LIBRDP_STATUS_OK);
    PCHECK(cache_glyph.version == 2 &&
           cache_glyph.cache_id == 1 &&
           cache_glyph.glyph_count == 1 &&
           cache_glyph.glyphs[0].cache_index == 3 &&
           cache_glyph.glyphs[0].x == 1 &&
           cache_glyph.glyphs[0].y == 2 &&
           cache_glyph.glyphs[0].width == 8 &&
           cache_glyph.glyphs[0].height == 1 &&
           cache_glyph.glyphs[0].bitmap_len == 4 &&
           cache_glyph.glyphs[0].has_unicode &&
           cache_glyph.glyphs[0].unicode_codepoint == 'B');
    {
        rdp_gdi_cache_glyph_order valid_cache_glyph = cache_glyph;
        rdp_gdi_secondary_order_header invalid_glyph_header = secondary_header;

        invalid_glyph_header.payload_len--;
        PCHECK(rdp_gdi_parse_cache_glyph_order(&invalid_glyph_header, &cache_glyph) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&cache_glyph, &valid_cache_glyph, sizeof(cache_glyph)) == 0);
    }

    PCHECK(rdp_gdi_write_slow_orders_update_payload(&slow,
                                                    1,
                                                    secondary.data,
                                                    secondary.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_slow_orders_update_payload(slow.data,
                                                    slow.length,
                                                    &update) == LIBRDP_STATUS_OK);
    PCHECK(update.update_type == RDP_GDI_UPDATE_TYPE_ORDERS &&
           update.number_orders == 1 &&
           update.order_data_len == secondary.length);
    PCHECK(rdp_gdi_parse_order_list(update.order_data,
                                    update.order_data_len,
                                    update.number_orders,
                                    RDP_GDI_ORDER_PATBLT,
                                    &list) == LIBRDP_STATUS_OK);
    PCHECK(list.count == 1 &&
           list.orders[0].kind == RDP_GDI_ORDER_KIND_SECONDARY &&
           list.orders[0].length == secondary.length);

    PCHECK(rdp_gdi_write_fast_orders_update_payload(&fast,
                                                    1,
                                                    secondary.data,
                                                    secondary.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_fast_orders_update_payload(fast.data,
                                                    fast.length,
                                                    &update) == LIBRDP_STATUS_OK);
    PCHECK(update.number_orders == 1 && update.order_data_len == secondary.length);
    {
        const uint16_t too_many = (uint16_t)(RDP_GDI_MAX_ORDERS + 1u);
        const uint8_t huge_payload = 0x5au;
        rdp_gdi_orders_update valid_update = update;
        const uint8_t slow_too_many[] = {
            0x00u, 0x00u,
            0x00u, 0x00u,
            (uint8_t)(too_many & 0xffu), (uint8_t)(too_many >> 8u),
            0x00u, 0x00u
        };
        const uint8_t fast_too_many[] = {
            (uint8_t)(too_many & 0xffu), (uint8_t)(too_many >> 8u)
        };

        PCHECK(rdp_gdi_parse_slow_orders_update_payload(slow_too_many,
                                                        sizeof(slow_too_many),
                                                        &update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&update, &valid_update, sizeof(update)) == 0);
        PCHECK(rdp_gdi_parse_fast_orders_update_payload(fast_too_many,
                                                        sizeof(fast_too_many),
                                                        &update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&update, &valid_update, sizeof(update)) == 0);
        PCHECK(rdp_gdi_parse_slow_orders_update_payload(slow_zero_with_data,
                                                        sizeof(slow_zero_with_data),
                                                        &update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&update, &valid_update, sizeof(update)) == 0);
        PCHECK(rdp_gdi_parse_fast_orders_update_payload(fast_zero_with_data,
                                                        sizeof(fast_zero_with_data),
                                                        &update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&update, &valid_update, sizeof(update)) == 0);
        PCHECK(rdp_gdi_write_slow_orders_update_payload(&slow,
                                                        too_many,
                                                        secondary.data,
                                                        secondary.length) == LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(rdp_gdi_write_fast_orders_update_payload(&fast,
                                                        too_many,
                                                        secondary.data,
                                                        secondary.length) == LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(rdp_gdi_write_slow_orders_update_payload(&slow,
                                                        0,
                                                        secondary.data,
                                                        secondary.length) == LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(rdp_gdi_write_fast_orders_update_payload(&fast,
                                                        0,
                                                        secondary.data,
                                                        secondary.length) == LIBRDP_STATUS_INVALID_ARGUMENT);
        payload.length = 0;
        PCHECK(rdp_buffer_append_u8(&payload, 0xa5u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_gdi_write_slow_orders_update_payload(&payload,
                                                        1,
                                                        &huge_payload,
                                                        (size_t)-1) == LIBRDP_STATUS_NO_MEMORY);
        PCHECK(payload.length == 1 && payload.data[0] == 0xa5u);
        PCHECK(rdp_gdi_write_fast_orders_update_payload(&payload,
                                                        1,
                                                        &huge_payload,
                                                        (size_t)-1) == LIBRDP_STATUS_NO_MEMORY);
        PCHECK(payload.length == 1 && payload.data[0] == 0xa5u);
        PCHECK(rdp_gdi_write_primary_order(&payload,
                                           RDP_GDI_ORDER_DSTBLT,
                                           RDP_GDI_ORDER_DSTBLT,
                                           RDP_GDI_TS_STANDARD,
                                           0,
                                           NULL,
                                           0,
                                           &huge_payload,
                                           (size_t)-1) == LIBRDP_STATUS_NO_MEMORY);
        PCHECK(payload.length == 1 && payload.data[0] == 0xa5u);
    }

    PCHECK(rdp_gdi_parse_primary_order(primary_order,
                                       sizeof(primary_order),
                                       RDP_GDI_ORDER_PATBLT,
                                       &primary) == LIBRDP_STATUS_OK);
    PCHECK(primary.order_type == RDP_GDI_ORDER_DSTBLT &&
           primary.field_flags == 0x0cu &&
           primary.payload_len == 2u &&
           primary.payload[0] == 0xaau);
    payload.length = 0;
    PCHECK(rdp_gdi_write_primary_order(&payload,
                                       RDP_GDI_ORDER_PATBLT,
                                       RDP_GDI_ORDER_DSTBLT,
                                       RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
                                       0x0cu,
                                       NULL,
                                       0,
                                       primary_order + 3u,
                                       2u) == LIBRDP_STATUS_OK);
    PCHECK(payload.length == sizeof(primary_order) &&
           memcmp(payload.data, primary_order, sizeof(primary_order)) == 0);
    payload.length = 0;
    PCHECK(rdp_gdi_parse_primary_order(primary_bounds,
                                       sizeof(primary_bounds),
                                       RDP_GDI_ORDER_PATBLT,
                                       &primary) == LIBRDP_STATUS_OK);
    PCHECK(primary.order_type == RDP_GDI_ORDER_OPAQUERECT &&
           primary.bounds_flags == 0x03u &&
           primary.bounds_len == 5u &&
           primary.payload_len == 2u);
    {
        rdp_gdi_primary_order_header valid_primary = primary;

        PCHECK(rdp_gdi_parse_primary_order(bad_bounds,
                                           sizeof(bad_bounds),
                                           RDP_GDI_ORDER_PATBLT,
                                           &primary) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&primary, &valid_primary, sizeof(primary)) == 0);
    }
    PCHECK(rdp_gdi_write_primary_order(&payload,
                                       RDP_GDI_ORDER_PATBLT,
                                       RDP_GDI_ORDER_OPAQUERECT,
                                       RDP_GDI_TS_STANDARD | RDP_GDI_TS_BOUNDS |
                                           RDP_GDI_TS_TYPE_CHANGE,
                                       0x0fu,
                                       primary_bounds + 3u,
                                       5u,
                                       primary_bounds + 8u,
                                       2u) == LIBRDP_STATUS_OK);
    PCHECK(payload.length == sizeof(primary_bounds) &&
           memcmp(payload.data, primary_bounds, sizeof(primary_bounds)) == 0);
    payload.length = 0;
    PCHECK(rdp_gdi_write_primary_order(&payload,
                                       RDP_GDI_ORDER_PATBLT,
                                       RDP_GDI_ORDER_OPAQUERECT,
                                       RDP_GDI_TS_STANDARD | RDP_GDI_TS_BOUNDS |
                                           RDP_GDI_TS_TYPE_CHANGE,
                                       0x01u,
                                       bad_bounds + 3u,
                                       1u,
                                       NULL,
                                       0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_gdi_render_state_init(&render_state);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_opaque,
                                               sizeof(render_opaque),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_opaque) &&
           render_op.kind == RDP_GDI_RENDER_OP_OPAQUE_RECT &&
           render_op.rect.x == 2 &&
           render_op.rect.y == 3 &&
           render_op.rect.width == 4 &&
           render_op.rect.height == 5 &&
           render_op.color == 0x00332211u);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_opaque_delta,
                                               sizeof(render_opaque_delta),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_opaque_delta) &&
           render_op.kind == RDP_GDI_RENDER_OP_OPAQUE_RECT &&
           render_op.rect.x == 0 &&
           render_op.rect.y == 7 &&
           render_op.rect.width == 4 &&
           render_op.rect.height == 5 &&
           render_op.color == 0x00332211u);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_scrblt,
                                               sizeof(render_scrblt),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_scrblt) &&
           render_op.kind == RDP_GDI_RENDER_OP_SCRBLT &&
           render_op.rop == 0xccu &&
           render_op.src_x == 1 &&
           render_op.src_y == 2 &&
           render_op.rect.width == 48 &&
           render_op.rect.height == 64);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_dstblt_bounds,
                                               sizeof(render_dstblt_bounds),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_dstblt_bounds) &&
           render_op.kind == RDP_GDI_RENDER_OP_DSTBLT &&
           render_op.rop == 0xffu &&
           render_op.bounds.present &&
           render_op.bounds.left == 1 &&
           render_op.bounds.top == 2 &&
           render_op.bounds.right == 8 &&
           render_op.bounds.bottom == 9 &&
           render_op.rect.x == 4 &&
           render_op.rect.y == 5 &&
           render_op.rect.width == 6 &&
           render_op.rect.height == 7);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_patblt,
                                               sizeof(render_patblt),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_patblt) &&
           render_op.kind == RDP_GDI_RENDER_OP_PATBLT &&
           render_op.rop == 0xf0u &&
           render_op.color == 0x00232221u &&
           render_op.back_color == 0x00030201u &&
           render_op.rect.x == 9 &&
           render_op.rect.y == 10 &&
           render_op.rect.width == 11 &&
           render_op.rect.height == 12 &&
           render_op.brush_style == 0);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_patblt_pattern,
                                               sizeof(render_patblt_pattern),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_patblt_pattern) &&
           render_op.kind == RDP_GDI_RENDER_OP_PATBLT &&
           render_op.color == 0x00605040u &&
           render_op.back_color == 0x00302010u &&
           render_op.rect.x == 1 &&
           render_op.rect.y == 2 &&
           render_op.rect.width == 3 &&
           render_op.rect.height == 4 &&
           render_op.brush_x == 5 &&
           render_op.brush_y == 6 &&
           render_op.brush_style == 3 &&
           render_op.brush_hatch == 0xaau &&
           render_op.brush_extra[0] == 0x55u &&
           render_op.brush_extra[6] == 0x55u);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_memblt,
                                               sizeof(render_memblt),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_memblt) &&
           render_op.kind == RDP_GDI_RENDER_OP_MEMBLT &&
           render_op.cache_id == 3 &&
           render_op.color_index == 2 &&
           render_op.cache_index == 0x1234u &&
           render_op.rop == 0xccu &&
           render_op.rect.x == 1 &&
           render_op.rect.y == 2 &&
           render_op.rect.width == 3 &&
           render_op.rect.height == 4 &&
           render_op.src_x == 5 &&
           render_op.src_y == 6);
    render_state_before_error = render_state;
    {
        rdp_gdi_render_op valid_render_op = render_op;
        size_t valid_render_consumed = render_consumed;

        PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                                   render_memblt_bad_width,
                                                   sizeof(render_memblt_bad_width),
                                                   &render_op,
                                                   &render_consumed) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&render_state, &render_state_before_error, sizeof(render_state)) == 0);
        PCHECK(memcmp(&render_op, &valid_render_op, sizeof(render_op)) == 0);
        PCHECK(render_consumed == valid_render_consumed);
    }
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_mem3blt,
                                               sizeof(render_mem3blt),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_mem3blt) &&
           render_op.kind == RDP_GDI_RENDER_OP_MEM3BLT &&
           render_op.cache_id == 4 &&
           render_op.color_index == 3 &&
           render_op.cache_index == 0x5678u &&
           render_op.rop == 0xb8u &&
           render_op.color == 0x00605040u &&
           render_op.back_color == 0x00302010u &&
           render_op.rect.x == 17 &&
           render_op.rect.y == 18 &&
           render_op.rect.width == 19 &&
           render_op.rect.height == 20 &&
           render_op.src_x == 21 &&
           render_op.src_y == 22 &&
           render_op.brush_style == 3 &&
           render_op.brush_hatch == 0xaau &&
           render_op.brush_extra[6] == 0x55u);
    render_state_before_error = render_state;
    {
        rdp_gdi_render_op valid_render_op = render_op;
        size_t valid_render_consumed = render_consumed;

        PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                                   render_mem3blt_bad_height,
                                                   sizeof(render_mem3blt_bad_height),
                                                   &render_op,
                                                   &render_consumed) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&render_state, &render_state_before_error, sizeof(render_state)) == 0);
        PCHECK(memcmp(&render_op, &valid_render_op, sizeof(render_op)) == 0);
        PCHECK(render_consumed == valid_render_consumed);
    }
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_lineto,
                                               sizeof(render_lineto),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_lineto) &&
           render_op.kind == RDP_GDI_RENDER_OP_LINE &&
           render_op.rop == 13u &&
           render_op.color == 0x00333231u &&
           render_op.rect.x == 2 &&
           render_op.rect.y == 3 &&
           render_op.end_x == 4 &&
           render_op.end_y == 5 &&
           render_op.pen_width == 1);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_lineto_dash,
                                               sizeof(render_lineto_dash),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_lineto_dash) &&
           render_op.kind == RDP_GDI_RENDER_OP_LINE &&
           render_op.pen_style == 1u &&
           render_op.pen_width == 1u &&
           render_op.rect.x == 2 &&
           render_op.end_x == 12);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_polyline,
                                               sizeof(render_polyline),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_polyline) &&
           render_op.kind == RDP_GDI_RENDER_OP_POLYLINE &&
           render_op.rop == 13u &&
           render_op.color == 0x00030201u &&
           render_op.rect.x == 10 &&
           render_op.rect.y == 11 &&
           render_op.point_count == 2 &&
           render_op.points[0].x == 2 &&
           render_op.points[0].y == 0 &&
           render_op.points[1].x == 0 &&
           render_op.points[1].y == 3);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_polygon_sc,
                                               sizeof(render_polygon_sc),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_polygon_sc) &&
           render_op.kind == RDP_GDI_RENDER_OP_POLYGON_SC &&
           render_op.rop == 13u &&
           render_op.fill_mode == 1u &&
           render_op.color == 0x00665544u &&
           render_op.rect.x == 20 &&
           render_op.rect.y == 20 &&
           render_op.point_count == 3 &&
           render_op.points[2].x == -4 &&
           render_op.points[2].y == 0);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_polygon_cb,
                                               sizeof(render_polygon_cb),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_polygon_cb) &&
           render_op.kind == RDP_GDI_RENDER_OP_POLYGON_CB &&
           render_op.rop == 13u &&
           render_op.transparent_background &&
           render_op.fill_mode == 1u &&
           render_op.back_color == 0x00302010u &&
           render_op.color == 0x00605040u &&
           render_op.brush_x == 5 &&
           render_op.brush_y == 6 &&
           render_op.brush_style == 3 &&
           render_op.brush_hatch == 0xaau &&
           render_op.brush_extra[6] == 0x55u &&
           render_op.point_count == 3 &&
           render_op.points[2].x == -4 &&
           render_op.points[2].y == 0);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_ellipse_sc,
                                               sizeof(render_ellipse_sc),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_ellipse_sc) &&
           render_op.kind == RDP_GDI_RENDER_OP_ELLIPSE_SC &&
           render_op.rop == 13u &&
           render_op.fill_mode == 1u &&
           render_op.color == 0x00aa9988u &&
           render_op.rect.x == 5 &&
           render_op.rect.y == 6 &&
           render_op.rect.width == 6 &&
           render_op.rect.height == 7);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_ellipse_cb,
                                               sizeof(render_ellipse_cb),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_ellipse_cb) &&
           render_op.kind == RDP_GDI_RENDER_OP_ELLIPSE_CB &&
           render_op.rop == 13u &&
           render_op.transparent_background &&
           render_op.fill_mode == 1u &&
           render_op.back_color == 0x00302010u &&
           render_op.color == 0x00605040u &&
           render_op.rect.x == 5 &&
           render_op.rect.y == 6 &&
           render_op.rect.width == 6 &&
           render_op.rect.height == 7 &&
           render_op.brush_x == 2 &&
           render_op.brush_y == 3 &&
           render_op.brush_style == 2 &&
           render_op.brush_hatch == 4 &&
           render_op.brush_extra[6] == 0x55u);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_multi_dstblt,
                                               sizeof(render_multi_dstblt),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_multi_dstblt) &&
           render_op.kind == RDP_GDI_RENDER_OP_MULTIDSTBLT &&
           render_op.rop == 0xffu &&
           render_op.rect_count == 2 &&
           render_op.rects[0].x == 2 &&
           render_op.rects[0].y == 3 &&
           render_op.rects[0].width == 4 &&
           render_op.rects[0].height == 5 &&
           render_op.rects[1].x == 12 &&
           render_op.rects[1].y == 3 &&
           render_op.rects[1].width == 4 &&
           render_op.rects[1].height == 6);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_multi_scrblt,
                                               sizeof(render_multi_scrblt),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_multi_scrblt) &&
           render_op.kind == RDP_GDI_RENDER_OP_MULTISCRBLT &&
           render_op.rop == 0xccu &&
           render_op.src_x == 20 &&
           render_op.src_y == 30 &&
           render_op.rect_count == 2 &&
           render_op.rects[1].x == 12 &&
           render_op.rects[1].height == 6);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_multi_patblt,
                                               sizeof(render_multi_patblt),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_multi_patblt) &&
           render_op.kind == RDP_GDI_RENDER_OP_MULTIPATBLT &&
           render_op.rop == 0xf0u &&
           render_op.back_color == 0x00302010u &&
           render_op.color == 0x00605040u &&
           render_op.brush_x == 5 &&
           render_op.brush_y == 6 &&
           render_op.brush_style == 3 &&
           render_op.brush_hatch == 0xaau &&
           render_op.brush_extra[6] == 0x55u &&
           render_op.rect_count == 2 &&
           render_op.rects[0].x == 2 &&
           render_op.rects[1].x == 12 &&
           render_op.rects[1].height == 6);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_multi_opaque,
                                               sizeof(render_multi_opaque),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_multi_opaque) &&
           render_op.kind == RDP_GDI_RENDER_OP_MULTIOPAQUE_RECT &&
           render_op.color == 0x00332211u &&
           render_op.rect_count == 2 &&
           render_op.rects[1].x == 12 &&
           render_op.rects[1].height == 6);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_save_bitmap,
                                               sizeof(render_save_bitmap),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_save_bitmap) &&
           render_op.kind == RDP_GDI_RENDER_OP_SAVE_BITMAP &&
           render_op.bitmap_id == 0x12345678u &&
           render_op.operation == 0u &&
           render_op.rect.x == 2 &&
           render_op.rect.y == 3 &&
           render_op.rect.width == 5 &&
           render_op.rect.height == 6);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_draw_ninegrid,
                                               sizeof(render_draw_ninegrid),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_draw_ninegrid) &&
           render_op.kind == RDP_GDI_RENDER_OP_DRAW_NINEGRID &&
           render_op.bitmap_id == 0x1234u &&
           render_op.src_left == 1 &&
           render_op.src_top == 2 &&
           render_op.src_right == 8 &&
           render_op.src_bottom == 9 &&
           render_op.rect.x == 10 &&
           render_op.rect.y == 20 &&
           render_op.rect.width == 20 &&
           render_op.rect.height == 20);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_multi_draw_ninegrid,
                                               sizeof(render_multi_draw_ninegrid),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_multi_draw_ninegrid) &&
           render_op.kind == RDP_GDI_RENDER_OP_MULTI_DRAW_NINEGRID &&
           render_op.bitmap_id == 0x5678u &&
           render_op.src_left == 0 &&
           render_op.src_top == 1 &&
           render_op.src_right == 8 &&
           render_op.src_bottom == 9 &&
           render_op.rect_count == 2 &&
           render_op.rects[0].x == 1 &&
           render_op.rects[0].y == 2 &&
           render_op.rects[0].width == 3 &&
           render_op.rects[0].height == 4 &&
           render_op.rects[1].x == 6 &&
           render_op.rects[1].y == 8 &&
           render_op.rects[1].width == 7 &&
           render_op.rects[1].height == 8);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_glyph_index,
                                               sizeof(render_glyph_index),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_glyph_index) &&
           render_op.kind == RDP_GDI_RENDER_OP_GLYPH &&
           render_op.order_type == RDP_GDI_ORDER_GLYPH_INDEX &&
           render_op.cache_id == 1 &&
           render_op.glyph_flags == RDP_GDI_GLYPH_SO_HORIZONTAL &&
           render_op.glyph_data_len == 1 &&
           render_op.glyph_data[0] == 2u &&
           render_op.glyph_back_rect.width == 21 &&
           render_op.rect.height == 11 &&
           render_op.color == 0x00060504u &&
           render_op.back_color == 0x00030201u);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_fast_index,
                                               sizeof(render_fast_index),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_fast_index) &&
           render_op.kind == RDP_GDI_RENDER_OP_GLYPH &&
           render_op.order_type == RDP_GDI_ORDER_FAST_INDEX &&
           render_op.cache_id == 1 &&
           render_op.glyph_char_inc == 5 &&
           render_op.glyph_data_len == 1 &&
           render_op.glyph_data[0] == 2u &&
           !render_op.inline_glyph_present);
    PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                               render_fast_glyph,
                                               sizeof(render_fast_glyph),
                                               &render_op,
                                               &render_consumed) == LIBRDP_STATUS_OK);
    PCHECK(render_consumed == sizeof(render_fast_glyph) &&
           render_op.kind == RDP_GDI_RENDER_OP_GLYPH &&
           render_op.order_type == RDP_GDI_ORDER_FAST_GLYPH &&
           render_op.inline_glyph_present &&
           render_op.inline_glyph_cache_index == 4 &&
           render_op.inline_glyph_width == 8 &&
           render_op.inline_glyph_height == 1 &&
           render_op.inline_glyph_bitmap_len == 4 &&
           render_op.glyph_data_len == 1 &&
           render_op.glyph_data[0] == 4u);
    render_state_before_error = render_state;
    {
        rdp_gdi_render_op valid_render_op = render_op;
        size_t valid_render_consumed = render_consumed;

        PCHECK(rdp_gdi_decode_primary_render_order(&render_state,
                                                   render_rejected,
                                                   sizeof(render_rejected),
                                                   &render_op,
                                                   &render_consumed) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&render_state, &render_state_before_error, sizeof(render_state)) == 0);
        PCHECK(memcmp(&render_op, &valid_render_op, sizeof(render_op)) == 0);
        PCHECK(render_consumed == valid_render_consumed);
    }
    PCHECK(rdp_gdi_parse_altsec_order(altsec_order,
                                      sizeof(altsec_order),
                                      &altsec) == LIBRDP_STATUS_OK);
    PCHECK(altsec.order_type == RDP_GDI_ALTSEC_SWITCH_SURFACE &&
           altsec.payload_len == 2u &&
           altsec.actual_length == sizeof(altsec_order));
    {
        const uint8_t invalid_altsec[] = {0xffu};
        const uint8_t window_altsec[] = {
            (uint8_t)((RDP_GDI_ALTSEC_WINDOW << 2u) | RDP_GDI_TS_SECONDARY),
            0x08u,
            0x00u,
            0x00u,
            0x00u,
            0x00u,
            0x04u,
            0x12u
        };
        const uint8_t invalid_window_altsec[] = {
            (uint8_t)((RDP_GDI_ALTSEC_WINDOW << 2u) | RDP_GDI_TS_SECONDARY),
            0x20u,
            0x00u
        };
        const uint8_t compdesk_altsec[] = {
            (uint8_t)((RDP_GDI_ALTSEC_COMPDESK_FIRST << 2u) | RDP_GDI_TS_SECONDARY)
        };
        const uint8_t gdiplus_first_altsec[] = {
            (uint8_t)((RDP_GDI_ALTSEC_DRAW_GDIPLUS_FIRST << 2u) | RDP_GDI_TS_SECONDARY),
            0x03u,
            0x00u,
            0x03u,
            0x00u,
            0x00u,
            0x00u,
            0x03u,
            0x00u,
            0x00u,
            0x00u,
            0xaau,
            0xbbu,
            0xccu
        };
        const uint8_t gdiplus_cache_next_altsec[] = {
            (uint8_t)((RDP_GDI_ALTSEC_DRAW_GDIPLUS_CACHE_NEXT << 2u) | RDP_GDI_TS_SECONDARY),
            0x01u,
            0x02u,
            0x00u,
            0x03u,
            0x00u,
            0x02u,
            0x00u,
            0xddu,
            0xeeu
        };
        rdp_gdi_altsec_order_header valid_altsec = altsec;
        rdp_gdi_window_order window_order;
        rdp_gdi_gdiplus_order gdiplus_order;

        PCHECK(rdp_gdi_parse_altsec_order(invalid_altsec,
                                          sizeof(invalid_altsec),
                                          &altsec) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&altsec, &valid_altsec, sizeof(altsec)) == 0);
        PCHECK(rdp_gdi_parse_altsec_order(invalid_window_altsec,
                                          sizeof(invalid_window_altsec),
                                          &altsec) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&altsec, &valid_altsec, sizeof(altsec)) == 0);
        PCHECK(rdp_gdi_parse_altsec_order(window_altsec,
                                          sizeof(window_altsec),
                                          &altsec) == LIBRDP_STATUS_OK);
        PCHECK(altsec.order_type == RDP_GDI_ALTSEC_WINDOW &&
               altsec.payload_len == sizeof(window_altsec) - 1u &&
               altsec.actual_length == sizeof(window_altsec));
        PCHECK(rdp_gdi_parse_window_order(&altsec, &window_order) == LIBRDP_STATUS_OK);
        PCHECK(window_order.order_size == 8u &&
               window_order.flags == 0x04000000u &&
               window_order.data_len == 1u &&
               window_order.data[0] == 0x12u);
        PCHECK(rdp_gdi_parse_altsec_order(compdesk_altsec,
                                          sizeof(compdesk_altsec),
                                          &altsec) == LIBRDP_STATUS_OK);
        PCHECK(altsec.order_type == RDP_GDI_ALTSEC_COMPDESK_FIRST &&
               altsec.payload_len == 0 &&
               altsec.actual_length == sizeof(compdesk_altsec));
        PCHECK(rdp_gdi_parse_altsec_order(gdiplus_first_altsec,
                                          sizeof(gdiplus_first_altsec),
                                          &altsec) == LIBRDP_STATUS_OK);
        PCHECK(altsec.order_type == RDP_GDI_ALTSEC_DRAW_GDIPLUS_FIRST &&
               altsec.payload_len == sizeof(gdiplus_first_altsec) - 1u);
        PCHECK(rdp_gdi_parse_gdiplus_order(&altsec, &gdiplus_order) == LIBRDP_STATUS_OK);
        PCHECK(gdiplus_order.order_type == RDP_GDI_ALTSEC_DRAW_GDIPLUS_FIRST &&
               gdiplus_order.data_len == 3u &&
               gdiplus_order.total_size == 3u &&
               gdiplus_order.total_emf_size == 3u &&
               gdiplus_order.data[0] == 0xaau &&
               gdiplus_order.data[1] == 0xbbu &&
               gdiplus_order.data[2] == 0xccu);
        PCHECK(rdp_gdi_parse_altsec_order(gdiplus_cache_next_altsec,
                                          sizeof(gdiplus_cache_next_altsec),
                                          &altsec) == LIBRDP_STATUS_OK);
        PCHECK(altsec.order_type == RDP_GDI_ALTSEC_DRAW_GDIPLUS_CACHE_NEXT &&
               altsec.actual_length == sizeof(gdiplus_cache_next_altsec));
        PCHECK(rdp_gdi_parse_gdiplus_order(&altsec, &gdiplus_order) == LIBRDP_STATUS_OK);
        PCHECK(gdiplus_order.order_type == RDP_GDI_ALTSEC_DRAW_GDIPLUS_CACHE_NEXT &&
               gdiplus_order.cache_type == 1u &&
               gdiplus_order.cache_index == 2u &&
               gdiplus_order.total_size == 3u &&
               gdiplus_order.total_emf_size == 0u &&
               gdiplus_order.data_len == 2u &&
               gdiplus_order.data[0] == 0xddu &&
               gdiplus_order.data[1] == 0xeeu);
        mixed.length = 0;
        PCHECK(rdp_buffer_append(&mixed, window_altsec, sizeof(window_altsec)) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append(&mixed, render_opaque, sizeof(render_opaque)) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_gdi_parse_order_list(mixed.data,
                                        mixed.length,
                                        2,
                                        RDP_GDI_ORDER_PATBLT,
                                        &list) == LIBRDP_STATUS_OK);
        PCHECK(list.count == 2 &&
               list.orders[0].kind == RDP_GDI_ORDER_KIND_ALTSEC &&
               list.orders[0].order_type == RDP_GDI_ALTSEC_WINDOW &&
               list.orders[1].kind == RDP_GDI_ORDER_KIND_PRIMARY);
        mixed.length = 0;
        altsec = valid_altsec;
    }
    PCHECK(rdp_gdi_parse_switch_surface_order(&altsec, &switch_surface) == LIBRDP_STATUS_OK);
    PCHECK(switch_surface.bitmap_id == 0x1234u);
    payload.length = 0;
    PCHECK(rdp_gdi_write_switch_surface_order(&payload, &switch_surface) == LIBRDP_STATUS_OK);
    PCHECK(payload.length == 2u &&
           memcmp(payload.data, altsec_order + 1u, 2u) == 0);
    {
        rdp_gdi_switch_surface_order valid_switch_surface = switch_surface;

        altsec.payload_len = 1u;
        PCHECK(rdp_gdi_parse_switch_surface_order(&altsec, &switch_surface) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&switch_surface, &valid_switch_surface, sizeof(switch_surface)) == 0);
        altsec.payload_len = 2u;
    }
    payload.length = 0;
    PCHECK(rdp_gdi_write_altsec_order(&payload,
                                      RDP_GDI_ALTSEC_SWITCH_SURFACE,
                                      altsec_order + 1u,
                                      2u) == LIBRDP_STATUS_OK);
    PCHECK(payload.length == sizeof(altsec_order) &&
           memcmp(payload.data, altsec_order, sizeof(altsec_order)) == 0);
    payload.length = 0;
    PCHECK(rdp_buffer_append_u8(&payload, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_write_altsec_order(&payload,
                                      RDP_GDI_ALTSEC_SWITCH_SURFACE,
                                      altsec_order + 1u,
                                      (size_t)-1) == LIBRDP_STATUS_NO_MEMORY);
    PCHECK(payload.length == 1u && payload.data[0] == 0xa5u);
    payload.length = 0;
    PCHECK(rdp_gdi_write_altsec_order(&payload,
                                      RDP_GDI_ALTSEC_CREATE_OFFSCREEN_BITMAP,
                                      create_offscreen_payload,
                                      sizeof(create_offscreen_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_altsec_order(payload.data,
                                      payload.length,
                                      &altsec) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_create_offscreen_bitmap_order(&altsec, &create_offscreen) ==
           LIBRDP_STATUS_OK);
    PCHECK(create_offscreen.bitmap_id == 0x45u &&
           create_offscreen.width == 32u &&
           create_offscreen.height == 16u &&
           create_offscreen.delete_count == 2u &&
           create_offscreen.delete_indices[0] == 1u &&
           create_offscreen.delete_indices[1] == 0x7fffu);
    payload.length = 0;
    PCHECK(rdp_gdi_write_create_offscreen_bitmap_order(&payload, &create_offscreen) ==
           LIBRDP_STATUS_OK);
    PCHECK(payload.length == sizeof(create_offscreen_payload) &&
           memcmp(payload.data, create_offscreen_payload, sizeof(create_offscreen_payload)) == 0);
    payload.data[2] = 0;
    payload.data[3] = 0;
    altsec.payload = payload.data;
    altsec.payload_len = payload.length;
    altsec.order_type = RDP_GDI_ALTSEC_CREATE_OFFSCREEN_BITMAP;
    {
        rdp_gdi_create_offscreen_bitmap_order valid_create_offscreen = create_offscreen;

        PCHECK(rdp_gdi_parse_create_offscreen_bitmap_order(&altsec, &create_offscreen) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&create_offscreen,
                      &valid_create_offscreen,
                      sizeof(create_offscreen)) == 0);
    }
    payload.length = 0;
    PCHECK(rdp_gdi_write_altsec_order(&payload,
                                      RDP_GDI_ALTSEC_FRAME_MARKER,
                                      frame_marker_payload,
                                      sizeof(frame_marker_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_altsec_order(payload.data,
                                      payload.length,
                                      &altsec) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_frame_marker_order(&altsec, &frame_marker) == LIBRDP_STATUS_OK);
    PCHECK(frame_marker.action == 1u);
    payload.length = 0;
    PCHECK(rdp_gdi_write_frame_marker_order(&payload, &frame_marker) == LIBRDP_STATUS_OK);
    PCHECK(payload.length == sizeof(frame_marker_payload) &&
           memcmp(payload.data, frame_marker_payload, sizeof(frame_marker_payload)) == 0);
    {
        rdp_gdi_frame_marker_order valid_frame_marker = frame_marker;

        altsec.payload_len = 3u;
        PCHECK(rdp_gdi_parse_frame_marker_order(&altsec, &frame_marker) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&frame_marker, &valid_frame_marker, sizeof(frame_marker)) == 0);
    }
    payload.length = 0;
    PCHECK(rdp_gdi_write_altsec_order(&payload,
                                      RDP_GDI_ALTSEC_STREAM_BITMAP_FIRST,
                                      stream_first_payload,
                                      sizeof(stream_first_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_altsec_order(payload.data,
                                      payload.length,
                                      &altsec) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_stream_bitmap_first_order(&altsec, &stream_first) ==
           LIBRDP_STATUS_OK);
    PCHECK(stream_first.flags == 0u &&
           stream_first.bits_per_pixel == 32u &&
           stream_first.bitmap_type == 2u &&
           stream_first.width == 2u &&
           stream_first.height == 1u &&
           stream_first.bitmap_size == 8u &&
           stream_first.bitmap_block_len == 4u &&
           memcmp(stream_first.bitmap_block, stream_first_payload + 12u, 4u) == 0);
    payload.length = 0;
    PCHECK(rdp_gdi_write_stream_bitmap_first_order(&payload, &stream_first) ==
           LIBRDP_STATUS_OK);
    PCHECK(payload.length == sizeof(stream_first_payload) &&
           memcmp(payload.data, stream_first_payload, sizeof(stream_first_payload)) == 0);
    payload.data[8] = 0;
    payload.data[9] = 0;
    altsec.payload = payload.data;
    altsec.payload_len = payload.length;
    altsec.order_type = RDP_GDI_ALTSEC_STREAM_BITMAP_FIRST;
    {
        rdp_gdi_stream_bitmap_first_order valid_stream_first = stream_first;

        PCHECK(rdp_gdi_parse_stream_bitmap_first_order(&altsec, &stream_first) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&stream_first, &valid_stream_first, sizeof(stream_first)) == 0);
    }
    payload.length = 0;
    PCHECK(rdp_gdi_write_altsec_order(&payload,
                                      RDP_GDI_ALTSEC_STREAM_BITMAP_NEXT,
                                      stream_next_payload,
                                      sizeof(stream_next_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_altsec_order(payload.data,
                                      payload.length,
                                      &altsec) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_stream_bitmap_next_order(&altsec, &stream_next) ==
           LIBRDP_STATUS_OK);
    PCHECK(stream_next.flags == RDP_GDI_STREAM_BITMAP_END &&
           stream_next.bitmap_type == 2u &&
           stream_next.bitmap_block_len == 4u &&
           memcmp(stream_next.bitmap_block, stream_next_payload + 5u, 4u) == 0);
    {
        rdp_gdi_stream_bitmap_next_order valid_stream_next = stream_next;
        rdp_gdi_altsec_order_header invalid_next = altsec;

        invalid_next.payload_len--;
        PCHECK(rdp_gdi_parse_stream_bitmap_next_order(&invalid_next, &stream_next) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&stream_next, &valid_stream_next, sizeof(stream_next)) == 0);
    }
    payload.length = 0;
    PCHECK(rdp_gdi_write_stream_bitmap_next_order(&payload, &stream_next) ==
           LIBRDP_STATUS_OK);
    PCHECK(payload.length == sizeof(stream_next_payload) &&
           memcmp(payload.data, stream_next_payload, sizeof(stream_next_payload)) == 0);
    payload.length = 0;
    PCHECK(rdp_gdi_write_altsec_order(&payload,
                                      RDP_GDI_ALTSEC_STREAM_BITMAP_FIRST,
                                      stream_first_v2_payload,
                                      sizeof(stream_first_v2_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_altsec_order(payload.data,
                                      payload.length,
                                      &altsec) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_stream_bitmap_first_order(&altsec, &stream_first) ==
           LIBRDP_STATUS_OK);
    PCHECK((stream_first.flags & RDP_GDI_STREAM_BITMAP_V2) != 0 &&
           (stream_first.flags & RDP_GDI_STREAM_BITMAP_END) != 0 &&
           stream_first.bits_per_pixel == 24u &&
           stream_first.bitmap_type == 3u &&
           stream_first.width == 1u &&
           stream_first.height == 1u &&
           stream_first.bitmap_size == 3u &&
           stream_first.bitmap_block_len == 3u);
    payload.length = 0;
    PCHECK(rdp_gdi_write_stream_bitmap_first_order(&payload, &stream_first) ==
           LIBRDP_STATUS_OK);
    PCHECK(payload.length == sizeof(stream_first_v2_payload) &&
           memcmp(payload.data, stream_first_v2_payload, sizeof(stream_first_v2_payload)) == 0);
    payload.length = 0;
    PCHECK(rdp_gdi_write_altsec_order(&payload,
                                      RDP_GDI_ALTSEC_CREATE_NINEGRID_BITMAP,
                                      create_ninegrid_payload,
                                      sizeof(create_ninegrid_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_altsec_order(payload.data,
                                      payload.length,
                                      &altsec) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_create_ninegrid_bitmap_order(&altsec, &create_ninegrid) ==
           LIBRDP_STATUS_OK);
    PCHECK(create_ninegrid.bits_per_pixel == 32 &&
           create_ninegrid.bitmap_id == 0x1234u &&
           create_ninegrid.info.flags == 1u &&
           create_ninegrid.info.left_width == 2u &&
           create_ninegrid.info.right_width == 3u &&
           create_ninegrid.info.top_height == 4u &&
           create_ninegrid.info.bottom_height == 5u &&
           create_ninegrid.info.transparent_color == 0x00aabbccu);
    payload.length = 0;
    PCHECK(rdp_gdi_write_create_ninegrid_bitmap_order(&payload, &create_ninegrid) ==
           LIBRDP_STATUS_OK);
    PCHECK(payload.length == sizeof(create_ninegrid_payload) &&
           memcmp(payload.data, create_ninegrid_payload, sizeof(create_ninegrid_payload)) == 0);
    payload.data[0] = 0;
    altsec.payload = payload.data;
    altsec.payload_len = payload.length;
    altsec.order_type = RDP_GDI_ALTSEC_CREATE_NINEGRID_BITMAP;
    {
        rdp_gdi_create_ninegrid_bitmap_order valid_create_ninegrid = create_ninegrid;

        PCHECK(rdp_gdi_parse_create_ninegrid_bitmap_order(&altsec, &create_ninegrid) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&create_ninegrid,
                      &valid_create_ninegrid,
                      sizeof(create_ninegrid)) == 0);
    }
    payload.length = 0;

    PCHECK(rdp_buffer_append(&mixed, secondary.data, secondary.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&mixed, altsec_order, sizeof(altsec_order)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_order_list(mixed.data,
                                    mixed.length,
                                    2,
                                    RDP_GDI_ORDER_PATBLT,
                                    &list) == LIBRDP_STATUS_OK);
    PCHECK(list.count == 2 &&
           list.orders[0].kind == RDP_GDI_ORDER_KIND_SECONDARY &&
           list.orders[1].kind == RDP_GDI_ORDER_KIND_ALTSEC);
    mixed.length = 0;
    PCHECK(rdp_buffer_append(&mixed, altsec_order, sizeof(altsec_order)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&mixed, render_opaque, sizeof(render_opaque)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_order_list(mixed.data,
                                    mixed.length,
                                    2,
                                    RDP_GDI_ORDER_PATBLT,
                                    &list) == LIBRDP_STATUS_OK);
    PCHECK(list.count == 2 &&
           list.orders[0].kind == RDP_GDI_ORDER_KIND_ALTSEC &&
           list.orders[0].length == sizeof(altsec_order) &&
           list.orders[1].kind == RDP_GDI_ORDER_KIND_PRIMARY &&
           list.orders[1].order_type == RDP_GDI_ORDER_OPAQUERECT);
    mixed.length = 0;
    PCHECK(rdp_buffer_append(&mixed, render_opaque, sizeof(render_opaque)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&mixed, secondary.data, secondary.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_order_list(mixed.data,
                                    mixed.length,
                                    2,
                                    RDP_GDI_ORDER_PATBLT,
                                    &list) == LIBRDP_STATUS_OK);
    PCHECK(list.count == 2 &&
           list.orders[0].kind == RDP_GDI_ORDER_KIND_PRIMARY &&
           list.orders[0].order_type == RDP_GDI_ORDER_OPAQUERECT &&
           list.orders[0].length == sizeof(render_opaque) &&
           list.orders[1].kind == RDP_GDI_ORDER_KIND_SECONDARY &&
           list.orders[1].length == secondary.length);
    {
        rdp_gdi_order_list valid_list = list;

        PCHECK(rdp_gdi_parse_order_list(mixed.data,
                                        mixed.length - 1u,
                                        2,
                                        RDP_GDI_ORDER_PATBLT,
                                        &list) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&list, &valid_list, sizeof(list)) == 0);
    }
    PCHECK(rdp_gdi_parse_order_list(NULL, 0, 0, RDP_GDI_ORDER_PATBLT, &list) == LIBRDP_STATUS_OK);

    memset(&bitmap_error, 0, sizeof(bitmap_error));
    bitmap_error.count = 2;
    bitmap_error.infos[0].cache_id = 1;
    bitmap_error.infos[0].flags = RDP_GDI_BITMAP_CACHE_ERROR_FLUSH_CACHE;
    bitmap_error.infos[0].new_num_entries = 128;
    bitmap_error.infos[1].cache_id = 2;
    bitmap_error.infos[1].flags = RDP_GDI_BITMAP_CACHE_ERROR_NEWNUMENTRIES_VALID;
    bitmap_error.infos[1].new_num_entries = 256;
    PCHECK(rdp_gdi_write_bitmap_cache_error_payload(&payload, &bitmap_error) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_bitmap_cache_error_payload(payload.data,
                                                    payload.length,
                                                    &parsed_error) == LIBRDP_STATUS_OK);
    PCHECK(parsed_error.count == 2 &&
           parsed_error.infos[1].cache_id == 2 &&
           parsed_error.infos[1].new_num_entries == 256);
    {
        rdp_gdi_bitmap_cache_error valid_error = parsed_error;

        payload.data[5] = 0x80u;
        PCHECK(rdp_gdi_parse_bitmap_cache_error_payload(payload.data,
                                                        payload.length,
                                                        &parsed_error) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&parsed_error, &valid_error, sizeof(parsed_error)) == 0);
        payload.data[5] = RDP_GDI_BITMAP_CACHE_ERROR_NEWNUMENTRIES_VALID;
    }
    payload.length = 0;
    PCHECK(rdp_buffer_append_u8(&payload, 0xa5u) == LIBRDP_STATUS_OK);
    bitmap_error.infos[1].flags = 0x80u;
    PCHECK(rdp_gdi_write_bitmap_cache_error_payload(&payload, &bitmap_error) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(payload.length == 1u && payload.data[0] == 0xa5u);
    bitmap_error.infos[1].flags = RDP_GDI_BITMAP_CACHE_ERROR_NEWNUMENTRIES_VALID;
    payload.length = 0;
    PCHECK(rdp_gdi_write_bitmap_cache_error_payload(&payload, &bitmap_error) == LIBRDP_STATUS_OK);
    payload.length = 0;
    PCHECK(rdp_gdi_write_cache_error_flags(&payload,
                                           RDP_GDI_OFFSCREEN_CACHE_ERROR_FLUSH_AND_DISABLE) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_cache_error_flags(payload.data,
                                           payload.length,
                                           RDP_GDI_OFFSCREEN_CACHE_ERROR_FLUSH_AND_DISABLE,
                                           &flags) == LIBRDP_STATUS_OK);
    PCHECK(flags == RDP_GDI_OFFSCREEN_CACHE_ERROR_FLUSH_AND_DISABLE);
    PCHECK(rdp_gdi_parse_cache_error_flags(payload.data,
                                           payload.length,
                                           RDP_GDI_GDIPLUS_CACHE_ERROR_FLUSH_AND_DISABLE + 1u,
                                           &flags) == LIBRDP_STATUS_PROTOCOL_ERROR);

    color.color_table_cache_size = 6;
    PCHECK(rdp_gdi_write_color_cache_capability(&capability, &color) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_color_cache_capability(capability.data,
                                                capability.length,
                                                &color) == LIBRDP_STATUS_OK);
    PCHECK(color.color_table_cache_size == 6);
    {
        rdp_gdi_color_cache_capability valid_color = color;

        capability.data[0] = 0xffu;
        PCHECK(rdp_gdi_parse_color_cache_capability(capability.data,
                                                    capability.length,
                                                    &color) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&color, &valid_color, sizeof(color)) == 0);
    }
    rdp_buffer_free(&capability);
    rdp_buffer_init(&capability);

    ninegrid.support_level = RDP_GDI_NINEGRID_SUPPORT_SUPPORTED_REV2;
    ninegrid.cache_size = 2560;
    ninegrid.cache_entries = 256;
    PCHECK(rdp_gdi_write_ninegrid_capability(&capability, &ninegrid) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_ninegrid_capability(capability.data,
                                             capability.length,
                                             &ninegrid) == LIBRDP_STATUS_OK);
    PCHECK(ninegrid.support_level == RDP_GDI_NINEGRID_SUPPORT_SUPPORTED_REV2 &&
           ninegrid.cache_size == 2560 &&
           ninegrid.cache_entries == 256);
    {
        rdp_gdi_ninegrid_capability valid_ninegrid = ninegrid;

        capability.data[8] = 1;
        capability.data[9] = 10;
        PCHECK(rdp_gdi_parse_ninegrid_capability(capability.data,
                                                 capability.length,
                                                 &ninegrid) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&ninegrid, &valid_ninegrid, sizeof(ninegrid)) == 0);
    }
    rdp_buffer_free(&capability);
    rdp_buffer_init(&capability);

    memset(&gdiplus, 0, sizeof(gdiplus));
    gdiplus.support_level = RDP_GDI_GDIPLUS_SUPPORT_SUPPORTED;
    gdiplus.version = 1;
    gdiplus.cache_level = RDP_GDI_GDIPLUS_CACHE_LEVEL_ONE;
    for (i = 0; i < 5u; i++)
    {
        static const uint16_t entries[5] = {10u, 5u, 5u, 10u, 2u};

        gdiplus.cache_entries[i] = entries[i];
    }
    gdiplus.cache_chunk_size[0] = 512;
    gdiplus.cache_chunk_size[1] = 2048;
    gdiplus.cache_chunk_size[2] = 1024;
    gdiplus.cache_chunk_size[3] = 64;
    gdiplus.image_cache_properties[0] = 4096;
    gdiplus.image_cache_properties[1] = 256;
    gdiplus.image_cache_properties[2] = 128;
    PCHECK(rdp_gdi_write_gdiplus_capability(&capability, &gdiplus) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_gdiplus_capability(capability.data,
                                            capability.length,
                                            &gdiplus) == LIBRDP_STATUS_OK);
    PCHECK(gdiplus.support_level == RDP_GDI_GDIPLUS_SUPPORT_SUPPORTED &&
           gdiplus.cache_entries[0] == 10 &&
           gdiplus.cache_chunk_size[1] == 2048 &&
           gdiplus.image_cache_properties[2] == 128);
    {
        rdp_gdi_gdiplus_capability valid_gdiplus = gdiplus;

        capability.data[16] = 11;
        capability.data[17] = 0;
        PCHECK(rdp_gdi_parse_gdiplus_capability(capability.data,
                                                capability.length,
                                                &gdiplus) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&gdiplus, &valid_gdiplus, sizeof(gdiplus)) == 0);
    }

    rdp_buffer_free(&capability);
    rdp_buffer_free(&payload);
    rdp_buffer_free(&mixed);
    rdp_buffer_free(&fast);
    rdp_buffer_free(&slow);
    rdp_buffer_free(&secondary);
    return 0;
}

/*
 * Coverage: exercises the normalized GDI raster backend contract on software
 * and any native backends compiled into this build. The checks catch BGRA
 * byte-order drift, unchecked rectangle bounds, and backend availability
 * mismatches without requiring a display server.
 */
static int test_gdi_backends(void)
{
    rdp_gdi_backend_caps caps;
    rdp_gdi_backend_point triangle[3];
    librdp_surface* surface = NULL;
    const uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t dirty_left = UINT32_MAX;
    uint32_t dirty_top = UINT32_MAX;
    uint32_t dirty_right = 0;
    uint32_t dirty_bottom = 0;
    librdp_status cairo_status = LIBRDP_STATUS_OK;
    librdp_status quartz_status = LIBRDP_STATUS_OK;
    static const uint8_t source_pixels[] = {
        0x10u, 0x20u, 0x30u, 0xffu,
        0x11u, 0x21u, 0x31u, 0xffu,
        0x12u, 0x22u, 0x32u, 0xffu,
        0x13u, 0x23u, 0x33u, 0xffu
    };
    static const uint8_t gdiplus_stream[] = {
        0x09u, 0x40u, 0x00u, 0x00u, 0x10u, 0x00u, 0x00u, 0x00u,
        0x04u, 0x00u, 0x00u, 0x00u, 0x03u, 0x02u, 0x01u, 0xffu,
        0x0au, 0x40u, 0x00u, 0xc0u, 0x1cu, 0x00u, 0x00u, 0x00u,
        0x10u, 0x00u, 0x00u, 0x00u, 0x33u, 0x22u, 0x11u, 0xffu,
        0x01u, 0x00u, 0x00u, 0x00u, 0x01u, 0x00u, 0x01u, 0x00u,
        0x02u, 0x00u, 0x02u, 0x00u, 0x0eu, 0x40u, 0x00u, 0xc0u,
        0x18u, 0x00u, 0x00u, 0x00u, 0x0cu, 0x00u, 0x00u, 0x00u,
        0x66u, 0x55u, 0x44u, 0xffu, 0x03u, 0x00u, 0x03u, 0x00u,
        0x02u, 0x00u, 0x02u, 0x00u,
        0x0bu, 0x40u, 0x00u, 0xc0u, 0x1cu, 0x00u, 0x00u, 0x00u,
        0x10u, 0x00u, 0x00u, 0x00u, 0x77u, 0x66u, 0x55u, 0xffu,
        0x01u, 0x00u, 0x00u, 0x00u, 0x04u, 0x00u, 0x00u, 0x00u,
        0x01u, 0x00u, 0x01u, 0x00u,
        0x0cu, 0x40u, 0x00u, 0xc0u, 0x20u, 0x00u, 0x00u, 0x00u,
        0x14u, 0x00u, 0x00u, 0x00u, 0xaau, 0x99u, 0x88u, 0xffu,
        0x03u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x03u, 0x00u,
        0x04u, 0x00u, 0x03u, 0x00u, 0x00u, 0x00u, 0x05u, 0x00u,
        0x0du, 0x40u, 0x00u, 0xc0u, 0x1cu, 0x00u, 0x00u, 0x00u,
        0x10u, 0x00u, 0x00u, 0x00u, 0x44u, 0x33u, 0x22u, 0xffu,
        0x02u, 0x00u, 0x00u, 0x00u, 0x05u, 0x00u, 0x00u, 0x00u,
        0x05u, 0x00u, 0x05u, 0x00u,
        0x0fu, 0x40u, 0x00u, 0xc0u, 0x18u, 0x00u, 0x00u, 0x00u,
        0x0cu, 0x00u, 0x00u, 0x00u, 0x10u, 0x20u, 0x30u, 0xffu,
        0x03u, 0x00u, 0x03u, 0x00u, 0x02u, 0x00u, 0x02u, 0x00u
    };
    uint32_t records = 0;
    uint32_t rasterized = 0;
    uint32_t unsupported = 0;

    surface = librdp_surface_new(6, 6, LIBRDP_PIXEL_FORMAT_BGRA32);
    PCHECK(surface != NULL);
    PCHECK(rdp_gdi_backend_query(RDP_GDI_BACKEND_SOFTWARE, &caps) == LIBRDP_STATUS_OK);
    PCHECK(caps.name && strcmp(caps.name, "software") == 0);
    PCHECK((caps.caps & RDP_GDI_BACKEND_CAP_FILL_RECT) != 0 &&
           (caps.caps & RDP_GDI_BACKEND_CAP_BLIT_BGRA32) != 0 &&
           (caps.caps & RDP_GDI_BACKEND_CAP_COPY_RECT) != 0 &&
           (caps.caps & RDP_GDI_BACKEND_CAP_DRAW_LINE) != 0 &&
           (caps.caps & RDP_GDI_BACKEND_CAP_FILL_POLYGON) != 0 &&
           (caps.caps & RDP_GDI_BACKEND_CAP_FILL_ELLIPSE) != 0 &&
           (caps.caps & RDP_GDI_BACKEND_CAP_DRAW_ELLIPSE) != 0 &&
           (caps.caps & RDP_GDI_BACKEND_CAP_GDIPLUS_STREAM) != 0 &&
           (caps.caps & RDP_GDI_BACKEND_CAP_GDIPLUS_PARTIAL_VISUALS) == 0 &&
           (caps.caps & RDP_GDI_BACKEND_CAP_GDIPLUS_COMPLETE_VISUALS) != 0);
    PCHECK(rdp_gdi_backend_fill_rect(RDP_GDI_BACKEND_SOFTWARE,
                                     surface,
                                     0,
                                     0,
                                     1,
                                     1,
                                     0x80ff0000u) == LIBRDP_STATUS_OK);
    pixels = librdp_surface_pixels(surface);
    stride = librdp_surface_stride(surface);
    PCHECK(pixels != NULL && stride >= 24u);
    PCHECK(pixels[0] == 0x00u && pixels[1] == 0x00u &&
           (pixels[2] == 0x80u || pixels[2] == 0x81u) && pixels[3] == 0xffu);
    PCHECK(rdp_gdi_backend_fill_rect(RDP_GDI_BACKEND_SOFTWARE,
                                     surface,
                                     1,
                                     2,
                                     3,
                                     2,
                                     0x112233u) == LIBRDP_STATUS_OK);
    pixels = librdp_surface_pixels(surface);
    stride = librdp_surface_stride(surface);
    PCHECK(pixels != NULL && stride >= 24u);
    PCHECK(pixels[(2u * stride) + 4u] == 0x33u &&
           pixels[(2u * stride) + 5u] == 0x22u &&
           pixels[(2u * stride) + 6u] == 0x11u &&
           pixels[(2u * stride) + 7u] == 0xffu);
    PCHECK(rdp_gdi_backend_blit_bgra32(RDP_GDI_BACKEND_SOFTWARE,
                                       surface,
                                       0,
                                       0,
                                       2,
                                       2,
                                       source_pixels,
                                       8) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_backend_copy_rect(RDP_GDI_BACKEND_SOFTWARE,
                                     surface,
                                     0,
                                     0,
                                     3,
                                     0,
                                     2,
                                     2) == LIBRDP_STATUS_OK);
    pixels = librdp_surface_pixels(surface);
    PCHECK(pixels[(0u * stride) + (3u * 4u) + 0u] == 0x10u &&
           pixels[(0u * stride) + (3u * 4u) + 1u] == 0x20u &&
           pixels[(0u * stride) + (3u * 4u) + 2u] == 0x30u &&
           pixels[(1u * stride) + (4u * 4u) + 0u] == 0x13u);
    dirty_left = UINT32_MAX;
    dirty_top = UINT32_MAX;
    dirty_right = 0;
    dirty_bottom = 0;
    PCHECK(rdp_gdi_backend_draw_line(RDP_GDI_BACKEND_SOFTWARE,
                                     surface,
                                     0,
                                     5,
                                     5,
                                     5,
                                     1,
                                     0xabcdefu,
                                     NULL,
                                     &dirty_left,
                                     &dirty_top,
                                     &dirty_right,
                                     &dirty_bottom) == LIBRDP_STATUS_OK);
    pixels = librdp_surface_pixels(surface);
    PCHECK(dirty_left == 0 && dirty_top == 5 && dirty_right == 6 && dirty_bottom == 6);
    PCHECK(pixels[(5u * stride) + 0u] == 0xefu &&
           pixels[(5u * stride) + 1u] == 0xcdu &&
           pixels[(5u * stride) + 2u] == 0xabu);
    triangle[0].x = 0;
    triangle[0].y = 0;
    triangle[1].x = 3;
    triangle[1].y = 0;
    triangle[2].x = 0;
    triangle[2].y = 3;
    dirty_left = UINT32_MAX;
    dirty_top = UINT32_MAX;
    dirty_right = 0;
    dirty_bottom = 0;
    PCHECK(rdp_gdi_backend_fill_polygon(RDP_GDI_BACKEND_SOFTWARE,
                                        surface,
                                        triangle,
                                        3,
                                        1,
                                        0x010203u,
                                        NULL,
                                        &dirty_left,
                                        &dirty_top,
                                        &dirty_right,
                                        &dirty_bottom) == LIBRDP_STATUS_OK);
    PCHECK(dirty_left == 0 && dirty_top == 0 && dirty_right >= 2 && dirty_bottom >= 2);
    PCHECK(rdp_gdi_backend_fill_ellipse(RDP_GDI_BACKEND_SOFTWARE,
                                        surface,
                                        3,
                                        3,
                                        3,
                                        3,
                                        0x665544u,
                                        NULL) == LIBRDP_STATUS_OK);
    pixels = librdp_surface_pixels(surface);
    PCHECK(pixels[(4u * stride) + (4u * 4u) + 0u] == 0x44u &&
           pixels[(4u * stride) + (4u * 4u) + 1u] == 0x55u &&
           pixels[(4u * stride) + (4u * 4u) + 2u] == 0x66u);
    PCHECK(rdp_gdi_backend_draw_ellipse(RDP_GDI_BACKEND_SOFTWARE,
                                        surface,
                                        0,
                                        0,
                                        4,
                                        4,
                                        1,
                                        0x123456u,
                                        NULL) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_backend_render_gdiplus_stream(RDP_GDI_BACKEND_SOFTWARE,
                                                 surface,
                                                 gdiplus_stream,
                                                 sizeof(gdiplus_stream),
                                                 &records,
                                                 &rasterized,
                                                 &unsupported) == LIBRDP_STATUS_OK);
    PCHECK(records == 7 && rasterized == 7 && unsupported == 0);
    pixels = librdp_surface_pixels(surface);
    PCHECK(pixels[0] == 0x03u && pixels[1] == 0x02u && pixels[2] == 0x01u);
    PCHECK(pixels[(4u * 4u) + 0u] == 0x77u &&
           pixels[(4u * 4u) + 1u] == 0x66u &&
           pixels[(4u * 4u) + 2u] == 0x55u);
    PCHECK(pixels[(1u * stride) + (1u * 4u) + 0u] == 0x33u &&
           pixels[(1u * stride) + (1u * 4u) + 1u] == 0x22u &&
           pixels[(1u * stride) + (1u * 4u) + 2u] == 0x11u);
    PCHECK(pixels[(4u * stride) + 0u] == 0xaau &&
           pixels[(4u * stride) + 1u] == 0x99u &&
           pixels[(4u * stride) + 2u] == 0x88u);
    PCHECK(pixels[(5u * 4u) + 0u] == 0x44u &&
           pixels[(5u * 4u) + 1u] == 0x33u &&
           pixels[(5u * 4u) + 2u] == 0x22u);
    PCHECK(rdp_gdi_backend_fill_rect(RDP_GDI_BACKEND_SOFTWARE,
                                     surface,
                                     5,
                                     5,
                                     2,
                                     1,
                                     0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    librdp_surface_free(surface);

    cairo_status = rdp_gdi_backend_query(RDP_GDI_BACKEND_CAIRO, &caps);
    PCHECK(cairo_status == LIBRDP_STATUS_OK || cairo_status == LIBRDP_STATUS_UNSUPPORTED);
    if (cairo_status == LIBRDP_STATUS_OK)
    {
        surface = librdp_surface_new(4, 4, LIBRDP_PIXEL_FORMAT_BGRA32);
        PCHECK(surface != NULL);
        PCHECK((caps.caps & RDP_GDI_BACKEND_CAP_FILL_ELLIPSE) != 0);
        PCHECK((caps.caps & RDP_GDI_BACKEND_CAP_GDIPLUS_STREAM) != 0);
        PCHECK((caps.caps & RDP_GDI_BACKEND_CAP_GDIPLUS_PARTIAL_VISUALS) == 0);
        PCHECK((caps.caps & RDP_GDI_BACKEND_CAP_GDIPLUS_COMPLETE_VISUALS) != 0);
        PCHECK(rdp_gdi_backend_fill_rect(RDP_GDI_BACKEND_CAIRO,
                                         surface,
                                         0,
                                         0,
                                         2,
                                         2,
                                         0x445566u) == LIBRDP_STATUS_OK);
        pixels = librdp_surface_pixels(surface);
        PCHECK(pixels != NULL &&
               pixels[0] == 0x66u &&
               pixels[1] == 0x55u &&
               pixels[2] == 0x44u &&
               pixels[3] == 0xffu);
        PCHECK(rdp_gdi_backend_blit_bgra32(RDP_GDI_BACKEND_CAIRO,
                                           surface,
                                           2,
                                           2,
                                           2,
                                           2,
                                           source_pixels,
                                           8) == LIBRDP_STATUS_OK);
        pixels = librdp_surface_pixels(surface);
        stride = librdp_surface_stride(surface);
        PCHECK(pixels[(2u * stride) + (2u * 4u) + 0u] == 0x10u &&
               pixels[(2u * stride) + (2u * 4u) + 1u] == 0x20u &&
               pixels[(2u * stride) + (2u * 4u) + 2u] == 0x30u);
        librdp_surface_free(surface);
        surface = NULL;
    }

    quartz_status = rdp_gdi_backend_query(RDP_GDI_BACKEND_QUARTZ, &caps);
    PCHECK(quartz_status == LIBRDP_STATUS_OK || quartz_status == LIBRDP_STATUS_UNSUPPORTED);
    if (quartz_status == LIBRDP_STATUS_OK)
    {
        surface = librdp_surface_new(4, 4, LIBRDP_PIXEL_FORMAT_BGRA32);
        PCHECK(surface != NULL);
        PCHECK((caps.caps & RDP_GDI_BACKEND_CAP_GDIPLUS_STREAM) != 0);
        PCHECK((caps.caps & RDP_GDI_BACKEND_CAP_GDIPLUS_PARTIAL_VISUALS) == 0);
        PCHECK((caps.caps & RDP_GDI_BACKEND_CAP_GDIPLUS_COMPLETE_VISUALS) != 0);
        PCHECK(rdp_gdi_backend_fill_rect(RDP_GDI_BACKEND_QUARTZ,
                                         surface,
                                         0,
                                         0,
                                         2,
                                         2,
                                         0x778899u) == LIBRDP_STATUS_OK);
        pixels = librdp_surface_pixels(surface);
        PCHECK(pixels != NULL &&
               pixels[0] == 0x99u &&
               pixels[1] == 0x88u &&
               pixels[2] == 0x77u &&
               pixels[3] == 0xffu);
        librdp_surface_free(surface);
    }
    PCHECK(rdp_gdi_backend_query(rdp_gdi_backend_default(), &caps) == LIBRDP_STATUS_OK);
    return 0;
}


int test_protocol_graphics_vectors(void)
{
    if (test_desktop_composition_channel() != 0)
        return 1;
    if (test_composited_remoting_channel() != 0)
        return 1;
    if (test_video_redirection_channel() != 0)
        return 1;
    if (test_video_optimized_channel() != 0)
        return 1;
    if (test_gdi_backends() != 0)
        return 1;
    if (test_gdi_orders() != 0)
        return 1;
    return 0;
}
