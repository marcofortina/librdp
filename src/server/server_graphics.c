/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: server framebuffer, graphics output, and desktop composition.
 * Invariants: state transitions and wire behavior are preserved from the
 * server orchestrator; cross-domain calls use private module contracts.
 * Ownership: server and peer objects own retained state; input payloads are
 * borrowed for the duration of each call.
 * Threading: callers serialize access to each listener and peer.
 * Trust boundary: remote protocol data is validated before state is committed.
 */

#include "server/server_graphics.h"

#include "server/server_extensions.h"
#include "server/server_features.h"
#include "server/server_peer.h"
#include "server/server_protocol.h"
#include "server/server_security.h"

#include "common/buffer.h"
#include "common/charset.h"
#include "common/stream.h"
#include "common/trace.h"
#include "channels/audio_input.h"
#include "channels/audio_output.h"
#include "channels/auth_redirection.h"
#include "channels/composited_remoting.h"
#include "channels/core_input.h"
#include "channels/desktop_composition.h"
#include "channels/device_redirection.h"
#include "channels/display_control.h"
#include "channels/dynamic_channel.h"
#include "channels/echo_channel.h"
#include "channels/graphics_pipeline.h"
#include "channels/input_channel.h"
#include "channels/mouse_cursor.h"
#include "channels/multiparty.h"
#include "channels/pnp_redirection.h"
#include "channels/remote_programs.h"
#include "channels/telemetry.h"
#include "channels/usb_redirection.h"
#include "channels/video_capture.h"
#include "channels/video_optimized.h"
#include "channels/video_redirection.h"
#include "channels/webauthn_channel.h"
#include "clipboard/clipboard.h"
#include "graphics/bitmap.h"
#include "graphics/gdi_orders.h"
#include "licensing/licensing.h"
#include "nla/credssp.h"
#include "platform/socket.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"
#include "transport/udp_transport.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509err.h>
#include <ctype.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

void rdp_server_graphics_frame_state_reset(librdp_server_peer* peer)
{
    if (!peer)
        return;
    peer->graphics_next_frame_id = 1u;
    peer->graphics_last_sent_frame_id = 0;
    peer->graphics_last_ack_frame_id = 0;
    peer->graphics_total_acked_frames = 0;
    peer->graphics_pending_frames = 0;
    peer->graphics_open_frame_id = 0;
    peer->graphics_frame_open = 0;
    if (peer->graphics_frame_queue_limit == 0)
        peer->graphics_frame_queue_limit = RDP_SERVER_GRAPHICS_FRAME_QUEUE_LIMIT_DEFAULT;
}

static void rdp_server_emit_surface_event(librdp_server_peer* peer,
                                          uint32_t x,
                                          uint32_t y,
                                          uint32_t width,
                                          uint32_t height)
{
    librdp_server_event event;

    if (!peer || librdp_server_event_init(&event) != LIBRDP_STATUS_OK)
        return;
    event.type = LIBRDP_SERVER_EVENT_SURFACE;
    event.x = x;
    event.y = y;
    event.width = width;
    event.height = height;
    rdp_server_emit_event(peer, &event);
}

static int rdp_server_rect_valid(const librdp_server_peer* peer,
                                 uint32_t x,
                                 uint32_t y,
                                 uint32_t width,
                                 uint32_t height)
{
    if (!peer || width == 0 || height == 0)
        return 0;
    if (x >= peer->width || y >= peer->height)
        return 0;
    if (width > (uint32_t)peer->width - x || height > (uint32_t)peer->height - y)
        return 0;
    return 1;
}

librdp_status rdp_server_surface_set_dimensions(librdp_server_peer* peer,
                                                uint32_t width,
                                                uint32_t height)
{
    uint8_t* pixels = NULL;
    size_t stride = 0;
    size_t total = 0;

    if (!peer ||
        width < RDP_SERVER_MIN_DESKTOP_SIZE ||
        height < RDP_SERVER_MIN_DESKTOP_SIZE ||
        width > RDP_SERVER_MAX_DESKTOP_SIZE ||
        height > RDP_SERVER_MAX_DESKTOP_SIZE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    stride = width * 4u;
    if (height > SIZE_MAX / stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    total = stride * height;
    pixels = (uint8_t*)calloc(1u, total);
    if (!pixels)
        return LIBRDP_STATUS_NO_MEMORY;
    free(peer->framebuffer);
    peer->framebuffer = pixels;
    peer->framebuffer_len = total;
    peer->framebuffer_stride = stride;
    peer->width = (uint16_t)width;
    peer->height = (uint16_t)height;
    peer->surface_repaint_pending = 1u;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_surface_ensure(librdp_server_peer* peer)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->framebuffer)
        return LIBRDP_STATUS_OK;
    return rdp_server_surface_set_dimensions(peer, peer->width, peer->height);
}

/*
 * Serialize one already-bounded BGRA tile as an uncompressed slow-path bitmap
 * update. The caller owns tiling and MCS payload sizing; this helper validates
 * 16-bit wire coordinates, copies rows bottom-up as required by bitmap updates,
 * and fails without partially mutating peer state when any nested writer rejects
 * the tile.
 */
static librdp_status rdp_server_present_tile(librdp_server_peer* peer,
                                             uint32_t x,
                                             uint32_t y,
                                             uint32_t width,
                                             uint32_t height)
{
    rdp_buffer raw;
    rdp_buffer update;
    rdp_bitmap_rect rect;
    size_t dst_stride = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&raw);
    rdp_buffer_init(&update);
    if (!rdp_server_rect_valid(peer, x, y, width, height) ||
        width > 0xffffu ||
        height > 0xffffu ||
        x + width - 1u > 0xffffu ||
        y + height - 1u > 0xffffu)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.surface.tile.invalid",
                        "x=%u y=%u width=%u height=%u peer_width=%u peer_height=%u",
                        x,
                        y,
                        width,
                        height,
                        peer ? peer->width : 0,
                        peer ? peer->height : 0);
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
        goto out;
    }
    dst_stride = width * 4u;
    if (height > SIZE_MAX / dst_stride)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.surface.tile.overflow",
                        "width=%u height=%u stride=%u",
                        width,
                        height,
                        (unsigned)dst_stride);
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
        goto out;
    }
    status = rdp_buffer_reserve(&raw, dst_stride * height);
    if (status != LIBRDP_STATUS_OK)
        goto out;
    raw.length = dst_stride * height;
    for (uint32_t row = 0; row < height; row++)
    {
        const uint8_t* src = peer->framebuffer +
                             ((size_t)(y + height - 1u - row) * peer->framebuffer_stride) +
                             ((size_t)x * 4u);
        uint8_t* dst = raw.data + ((size_t)row * dst_stride);

        memcpy(dst, src, dst_stride);
    }
    memset(&rect, 0, sizeof(rect));
    rect.dest_left = (uint16_t)x;
    rect.dest_top = (uint16_t)y;
    rect.dest_right = (uint16_t)(x + width - 1u);
    rect.dest_bottom = (uint16_t)(y + height - 1u);
    rect.width = (uint16_t)width;
    rect.height = (uint16_t)height;
    rect.bits_per_pixel = 32;
    rect.flags = 0;
    rect.data = raw.data;
    rect.data_len = (uint32_t)raw.length;
    status = rdp_bitmap_write_update(&update, &rect, 1);
    if (status != LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.surface.tile.bitmap_failed",
                        "status=%s x=%u y=%u width=%u height=%u raw_len=%u",
                        librdp_status_name(status),
                        x,
                        y,
                        width,
                        height,
                        (unsigned)raw.length);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_buffer slowpath;

        rdp_buffer_init(&slowpath);
        status = rdp_slowpath_write_data_pdu(&slowpath,
                                             peer->share_id,
                                             (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                             RDP_SLOWPATH_DATA_PDU_UPDATE,
                                             update.data,
                                             update.length);
        if (status != LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "server.surface.tile.slowpath_failed",
                            "status=%s x=%u y=%u width=%u height=%u update_len=%u",
                            librdp_status_name(status),
                            x,
                            y,
                            width,
                            height,
                            (unsigned)update.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_send_slowpath(peer, &slowpath);
        if (status != LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "server.surface.tile.send_failed",
                            "status=%s x=%u y=%u width=%u height=%u slowpath_len=%u",
                            librdp_status_name(status),
                            x,
                            y,
                            width,
                            height,
                            (unsigned)slowpath.length);
        rdp_buffer_free(&slowpath);
    }

out:
    rdp_buffer_free(&update);
    rdp_buffer_free(&raw);
    return status;
}

/*
 * Present a dirty rectangle by splitting it into MCS-sized bitmap tiles. The
 * limiting budget is the T.125 SendDataIndication payload size, so the tile
 * planner accounts for bitmap-update and slow-path headers before choosing
 * horizontal and vertical chunks. Any failed tile aborts the presentation and
 * leaves the stored framebuffer intact for a later retry.
 */
static librdp_status rdp_server_surface_present_rect(librdp_server_peer* peer,
                                                     uint32_t x,
                                                     uint32_t y,
                                                     uint32_t width,
                                                     uint32_t height)
{
    const size_t max_mcs_payload = 0x7fffu;
    const size_t bitmap_update_overhead = 22u;
    const size_t slowpath_data_overhead = 18u;
    size_t security_overhead = 0;
    size_t max_raw_tile = 0;
    uint32_t max_tile_width = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE || peer->updates_suppressed)
        return LIBRDP_STATUS_STATE;
    status = rdp_server_surface_ensure(peer);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!rdp_server_rect_valid(peer, x, y, width, height))
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.surface.present.invalid",
                        "x=%u y=%u width=%u height=%u peer_width=%u peer_height=%u",
                        x,
                        y,
                        width,
                        height,
                        peer->width,
                        peer->height);
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    security_overhead = rdp_server_outbound_security_overhead(peer);
    if (max_mcs_payload <= bitmap_update_overhead + slowpath_data_overhead + security_overhead)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    max_raw_tile = max_mcs_payload - bitmap_update_overhead - slowpath_data_overhead - security_overhead;
    max_tile_width = (uint32_t)(max_raw_tile / 4u);
    if (max_tile_width == 0 || width > UINT32_MAX - x || height > UINT32_MAX - y)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "server.surface.present.start",
                          "x=%u y=%u width=%u height=%u max_tile_width=%u peer_width=%u peer_height=%u",
                          x,
                          y,
                          width,
                          height,
                          max_tile_width,
                          peer->width,
                          peer->height);
    for (uint32_t column = 0; column < width; column += max_tile_width)
    {
        uint32_t tile_width = width - column;
        uint32_t rows_per_tile = 0;

        if (tile_width > max_tile_width)
            tile_width = max_tile_width;
        rows_per_tile = (uint32_t)(max_raw_tile / ((size_t)tile_width * 4u));
        if (rows_per_tile == 0)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        for (uint32_t row = 0; row < height; row += rows_per_tile)
        {
            uint32_t tile_height = height - row;

            if (tile_height > rows_per_tile)
                tile_height = rows_per_tile;
            status = rdp_server_present_tile(peer, x + column, y + row, tile_width, tile_height);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "server.surface.present.failed",
                                "status=%s column=%u row=%u tile_width=%u tile_height=%u",
                                librdp_status_name(status),
                                column,
                                row,
                                tile_width,
                                tile_height);
                return status;
            }
        }
    }
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "server.surface.present.done",
                          "x=%u y=%u width=%u height=%u",
                          x,
                          y,
                          width,
                          height);
    if (x == 0 && y == 0 && width == peer->width && height == peer->height)
        peer->surface_repaint_pending = 0;
    rdp_server_metric_add(&peer->metrics.surface_updates, 1u);
    rdp_server_emit_surface_event(peer, x, y, width, height);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_server_surface_flush_repaint(librdp_server_peer* peer)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!peer->surface_repaint_pending || !peer->framebuffer || peer->updates_suppressed)
        return LIBRDP_STATUS_OK;
    return rdp_server_surface_present_rect(peer, 0, 0, peer->width, peer->height);
}

librdp_status rdp_server_handle_refresh_rect(librdp_server_peer* peer,
                                                    const uint8_t* payload,
                                                    size_t payload_len)
{
    rdp_stream stream;
    uint16_t count = 0;
    uint16_t pad = 0;

    if (!peer || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, payload, payload_len);
    if (rdp_stream_read_u16_le(&stream, &count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pad) != LIBRDP_STATUS_OK ||
        count > 64u ||
        pad != 0 ||
        rdp_stream_remaining(&stream) != (size_t)count * 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (uint16_t i = 0; i < count; i++)
    {
        librdp_server_input_event event;
        uint16_t left = 0;
        uint16_t top = 0;
        uint16_t right = 0;
        uint16_t bottom = 0;
        librdp_status status = LIBRDP_STATUS_OK;

        if (librdp_server_input_event_init(&event) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &left) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &top) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &right) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &bottom) != LIBRDP_STATUS_OK ||
            right < left ||
            bottom < top)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        event.type = LIBRDP_SERVER_INPUT_REFRESH_RECT;
        event.x = left;
        event.y = top;
        event.width = (uint16_t)(right - left + 1u);
        event.height = (uint16_t)(bottom - top + 1u);
        rdp_server_emit_input(peer, &event);
        if (peer->framebuffer && !peer->updates_suppressed &&
            rdp_server_rect_valid(peer, event.x, event.y, event.width, event.height))
        {
            status = rdp_server_surface_present_rect(peer, event.x, event.y, event.width, event.height);
            if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_STATE)
                return status;
        }
    }
    return LIBRDP_STATUS_OK;
}

uint32_t librdp_server_peer_desktop_width(const librdp_server_peer* peer)
{
    return peer ? peer->width : 0;
}

uint32_t librdp_server_peer_desktop_height(const librdp_server_peer* peer)
{
    return peer ? peer->height : 0;
}

librdp_status librdp_server_peer_surface_resize(librdp_server_peer* peer, uint32_t width, uint32_t height)
{
    librdp_status status = LIBRDP_STATUS_OK;
    int was_active = 0;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    was_active = peer->state == LIBRDP_SERVER_PEER_ACTIVE;
    status = rdp_server_surface_set_dimensions(peer, width, height);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.surface.resize",
                                 "surface resize rejected");
        return status;
    }
    rdp_server_emit_surface_event(peer, 0, 0, width, height);
    if (was_active)
    {
        status = rdp_server_send_deactivate_all(peer);
        if (status == LIBRDP_STATUS_OK)
        {
            peer->confirm_active_seen = 0;
            peer->synchronize_seen = 0;
            peer->control_cooperate_seen = 0;
            peer->control_seen = 0;
            peer->font_list_seen = 0;
            status = rdp_server_send_demand_active(peer);
        }
        if (status != LIBRDP_STATUS_OK)
            rdp_server_record_status(peer,
                                     status,
                                     rdp_server_component_for_status(status),
                                     "server.surface.resize",
                                     "reactivation failed");
    }
    return status;
}

librdp_status librdp_server_peer_surface_blit_bgra32(librdp_server_peer* peer,
                                                     uint32_t x,
                                                     uint32_t y,
                                                     uint32_t width,
                                                     uint32_t height,
                                                     size_t stride,
                                                     const uint8_t* pixels)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !pixels || stride < (size_t)width * 4u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_server_surface_ensure(peer);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.surface.blit",
                                 "surface allocation failed");
        return status;
    }
    if (!rdp_server_rect_valid(peer, x, y, width, height))
    {
        rdp_server_record_status(peer,
                                 LIBRDP_STATUS_INVALID_ARGUMENT,
                                 LIBRDP_ERROR_COMPONENT_PROTOCOL,
                                 "server.surface.blit",
                                 "surface rectangle rejected");
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    for (uint32_t row = 0; row < height; row++)
    {
        const uint8_t* src = pixels + ((size_t)row * stride);
        uint8_t* dst = peer->framebuffer + ((size_t)(y + row) * peer->framebuffer_stride) + ((size_t)x * 4u);

        memcpy(dst, src, (size_t)width * 4u);
    }
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_surface_present(librdp_server_peer* peer,
                                                 uint32_t x,
                                                 uint32_t y,
                                                 uint32_t width,
                                                 uint32_t height)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (peer && peer->state == LIBRDP_SERVER_PEER_ACTIVE &&
        peer->updates_suppressed &&
        rdp_server_rect_valid(peer, x, y, width, height))
    {
        peer->surface_repaint_pending = 1u;
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.surface.present.deferred",
                        "x=%u y=%u width=%u height=%u",
                        x,
                        y,
                        width,
                        height);
        return LIBRDP_STATUS_OK;
    }
    status = rdp_server_surface_present_rect(peer, x, y, width, height);

    if (peer && status != LIBRDP_STATUS_OK)
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.surface.present",
                                 "surface presentation failed");
    return status;
}

librdp_status librdp_server_peer_send_echo_response(librdp_server_peer* peer,
                                                    uint32_t dynamic_channel_id,
                                                    const void* payload_data,
                                                    size_t payload_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_echo_channel_write_response(&payload, payload_data, payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer, dynamic_channel_id, RDP_ECHO_CHANNEL_NAME, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_display_single_monitor_layout(librdp_server_peer* peer,
                                                                    uint32_t dynamic_channel_id,
                                                                    uint32_t width,
                                                                    uint32_t height)
{
    rdp_display_control_monitor monitor;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_display_control_make_single_monitor(&monitor, width, height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_display_control_write_monitor_layout(&payload, &monitor, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_DISPLAY_CONTROL_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_graphics_default_caps(librdp_server_peer* peer,
                                                            uint32_t dynamic_channel_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_graphics_write_default_caps_advertise_for_avc(&payload, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_GRAPHICS_PIPELINE_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_graphics_bitmap_bgra32(librdp_server_peer* peer,
                                                             uint32_t dynamic_channel_id,
                                                             uint16_t surface_id,
                                                             uint32_t x,
                                                             uint32_t y,
                                                             uint32_t width,
                                                             uint32_t height,
                                                             uint32_t stride,
                                                             const void* pixels)
{
    const uint8_t* src = (const uint8_t*)pixels;
    rdp_graphics_rect16 dest_rect;
    rdp_buffer bitmap;
    rdp_buffer payload;
    size_t row_bytes = 0;
    size_t total_bytes = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !pixels || width == 0 || height == 0 || x > UINT16_MAX || y > UINT16_MAX ||
        width > UINT16_MAX || height > UINT16_MAX || width > UINT16_MAX - x ||
        height > UINT16_MAX - y)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    row_bytes = (size_t)width * 4u;
    if (stride < row_bytes || height > SIZE_MAX / row_bytes)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    total_bytes = row_bytes * (size_t)height;
    if (total_bytes > UINT32_MAX)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;

    dest_rect.left = (uint16_t)x;
    dest_rect.top = (uint16_t)y;
    dest_rect.right = (uint16_t)(x + width);
    dest_rect.bottom = (uint16_t)(y + height);
    rdp_buffer_init(&bitmap);
    rdp_buffer_init(&payload);
    for (uint32_t row = 0; status == LIBRDP_STATUS_OK && row < height; row++)
        status = rdp_buffer_append(&bitmap, src + ((size_t)row * stride), row_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_graphics_write_wire_to_surface_1(&payload,
                                                      surface_id,
                                                      RDP_GRAPHICS_CODECID_UNCOMPRESSED,
                                                      RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                                      &dest_rect,
                                                      bitmap.data,
                                                      (uint32_t)bitmap.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_GRAPHICS_PIPELINE_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    rdp_buffer_free(&bitmap);
    return status;
}

librdp_status librdp_server_peer_send_graphics_create_surface(librdp_server_peer* peer,
                                                              uint32_t dynamic_channel_id,
                                                              uint16_t surface_id,
                                                              uint16_t width,
                                                              uint16_t height,
                                                              uint8_t pixel_format)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_graphics_write_create_surface(&payload, surface_id, width, height, pixel_format);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_GRAPHICS_PIPELINE_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_graphics_delete_surface(librdp_server_peer* peer,
                                                              uint32_t dynamic_channel_id,
                                                              uint16_t surface_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_graphics_write_delete_surface(&payload, surface_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_GRAPHICS_PIPELINE_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_graphics_reset(librdp_server_peer* peer,
                                                     uint32_t dynamic_channel_id,
                                                     uint32_t width,
                                                     uint32_t height)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_graphics_write_reset(&payload, width, height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_GRAPHICS_PIPELINE_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_set_graphics_frame_queue_limit(librdp_server_peer* peer,
                                                                uint32_t frame_limit)
{
    if (!peer || frame_limit == 0 || frame_limit > RDP_SERVER_GRAPHICS_FRAME_QUEUE_LIMIT_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->graphics_pending_frames > frame_limit)
        return LIBRDP_STATUS_STATE;
    peer->graphics_frame_queue_limit = frame_limit;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_get_graphics_frame_state(const librdp_server_peer* peer,
                                                          uint32_t* pending_frames,
                                                          uint32_t* frame_limit,
                                                          uint32_t* last_ack_frame_id)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (pending_frames)
        *pending_frames = peer->graphics_pending_frames;
    if (frame_limit)
        *frame_limit = peer->graphics_frame_queue_limit
                           ? peer->graphics_frame_queue_limit
                           : RDP_SERVER_GRAPHICS_FRAME_QUEUE_LIMIT_DEFAULT;
    if (last_ack_frame_id)
        *last_ack_frame_id = peer->graphics_last_ack_frame_id;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_send_graphics_start_frame(librdp_server_peer* peer,
                                                           uint32_t dynamic_channel_id,
                                                           uint32_t timestamp,
                                                           uint32_t* frame_id)
{
    rdp_buffer payload;
    uint32_t next_frame_id = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !frame_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *frame_id = 0;
    if (peer->graphics_frame_open)
        return LIBRDP_STATUS_STATE;
    if (peer->graphics_frame_queue_limit == 0)
        peer->graphics_frame_queue_limit = RDP_SERVER_GRAPHICS_FRAME_QUEUE_LIMIT_DEFAULT;
    if (peer->graphics_pending_frames >= peer->graphics_frame_queue_limit ||
        peer->graphics_next_frame_id == UINT32_MAX)
    {
        rdp_server_metric_add(&peer->metrics.limits_rejected, 1u);
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    next_frame_id = peer->graphics_next_frame_id ? peer->graphics_next_frame_id : 1u;

    rdp_buffer_init(&payload);
    status = rdp_graphics_write_start_frame(&payload, timestamp, next_frame_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_GRAPHICS_PIPELINE_CHANNEL_NAME,
                                                      &payload);
    if (status == LIBRDP_STATUS_OK)
    {
        peer->graphics_open_frame_id = next_frame_id;
        peer->graphics_frame_open = 1u;
        peer->graphics_last_sent_frame_id = next_frame_id;
        peer->graphics_next_frame_id = next_frame_id + 1u;
        *frame_id = next_frame_id;
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.gfx.frame.start",
                        "frame_id=%u pending=%u",
                        next_frame_id,
                        peer->graphics_pending_frames);
    }
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_graphics_end_frame(librdp_server_peer* peer,
                                                         uint32_t dynamic_channel_id,
                                                         uint32_t frame_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || frame_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!peer->graphics_frame_open || peer->graphics_open_frame_id != frame_id)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&payload);
    status = rdp_graphics_write_end_frame(&payload, frame_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_GRAPHICS_PIPELINE_CHANNEL_NAME,
                                                      &payload);
    if (status == LIBRDP_STATUS_OK)
    {
        peer->graphics_frame_open = 0;
        peer->graphics_open_frame_id = 0;
        peer->graphics_pending_frames++;
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.gfx.frame.end",
                        "frame_id=%u pending=%u",
                        frame_id,
                        peer->graphics_pending_frames);
    }
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_core_input_init(librdp_server_peer* peer, uint32_t dynamic_channel_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_core_input_write_init_request(&payload);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_CORE_INPUT_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_touch_ready(librdp_server_peer* peer,
                                                  uint32_t dynamic_channel_id,
                                                  uint32_t protocol_version,
                                                  uint32_t supported_features,
                                                  int has_supported_features)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_input_channel_write_sc_ready(&payload,
                                              protocol_version,
                                              supported_features,
                                              has_supported_features ? 1u : 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_INPUT_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_mouse_cursor_caps(librdp_server_peer* peer,
                                                        uint32_t dynamic_channel_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_mouse_cursor_write_caps_advertise(&payload);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_MOUSE_CURSOR_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_server_peer_send_desktop_composition_payload(librdp_server_peer* peer,
                                                                      const rdp_buffer* order_payload)
{
    rdp_buffer order;
    rdp_buffer update;
    rdp_buffer slowpath;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !order_payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE || peer->updates_suppressed)
        return LIBRDP_STATUS_STATE;
    rdp_buffer_init(&order);
    rdp_buffer_init(&update);
    rdp_buffer_init(&slowpath);
    status = rdp_gdi_write_altsec_order(&order,
                                        RDP_GDI_ALTSEC_COMPDESK_FIRST,
                                        order_payload->data,
                                        order_payload->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gdi_write_slow_orders_update_payload(&update, 1, order.data, order.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_data_pdu(&slowpath,
                                             peer->share_id,
                                             (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                             RDP_SLOWPATH_DATA_PDU_UPDATE,
                                             update.data,
                                             update.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_slowpath(peer, &slowpath);
    rdp_buffer_free(&slowpath);
    rdp_buffer_free(&update);
    rdp_buffer_free(&order);
    return status;
}

librdp_status librdp_server_peer_send_desktop_composition_toggle(librdp_server_peer* peer,
                                                                 uint8_t event_type)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_desktop_composition_write_toggle(&payload, event_type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_peer_send_desktop_composition_payload(peer, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_desktop_composition_lsurface(librdp_server_peer* peer,
                                                                   int create,
                                                                   uint8_t flags,
                                                                   uint64_t surface_id,
                                                                   uint32_t width,
                                                                   uint32_t height,
                                                                   uint64_t window_id,
                                                                   uint64_t luid)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_desktop_composition_write_lsurface(&payload,
                                                    create ? 1u : 0u,
                                                    flags,
                                                    surface_id,
                                                    width,
                                                    height,
                                                    window_id,
                                                    luid);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_peer_send_desktop_composition_payload(peer, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_desktop_composition_start(librdp_server_peer* peer)
{
    rdp_buffer order;
    rdp_buffer update;
    rdp_buffer slowpath;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE || peer->updates_suppressed)
        return LIBRDP_STATUS_STATE;
    rdp_buffer_init(&order);
    rdp_buffer_init(&update);
    rdp_buffer_init(&slowpath);
    status = rdp_gdi_write_altsec_order(&order, RDP_GDI_ALTSEC_COMPDESK_FIRST, NULL, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gdi_write_slow_orders_update_payload(&update, 1, order.data, order.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_data_pdu(&slowpath,
                                             peer->share_id,
                                             (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                             RDP_SLOWPATH_DATA_PDU_UPDATE,
                                             update.data,
                                             update.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_slowpath(peer, &slowpath);
    if (status != LIBRDP_STATUS_OK)
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.desktop_composition.start",
                                 "desktop composition order send failed");
    rdp_buffer_free(&slowpath);
    rdp_buffer_free(&update);
    rdp_buffer_free(&order);
    return status;
}

librdp_status rdp_server_graphics_handle_frame_ack(librdp_server_peer* peer,
                                                          const uint8_t* data,
                                                          size_t data_len)
{
    rdp_graphics_header header;
    rdp_graphics_frame_ack ack;
    uint32_t acked_delta = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_graphics_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header.cmd_id != RDP_GRAPHICS_CMDID_FRAME_ACKNOWLEDGE)
        return LIBRDP_STATUS_OK;
    status = rdp_graphics_parse_frame_ack(data, data_len, &ack);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (ack.frame_id > peer->graphics_last_sent_frame_id ||
        (ack.frame_id == 0 && peer->graphics_last_sent_frame_id != 0))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (ack.frame_id > peer->graphics_last_ack_frame_id)
    {
        acked_delta = ack.frame_id - peer->graphics_last_ack_frame_id;
        peer->graphics_pending_frames = acked_delta >= peer->graphics_pending_frames
                                             ? 0
                                             : peer->graphics_pending_frames - acked_delta;
        peer->graphics_last_ack_frame_id = ack.frame_id;
    }
    peer->graphics_total_acked_frames = ack.total_frames_decoded;
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "server.gfx.frame.ack",
                    "frame_id=%u pending=%u queue_depth=%u decoded=%u",
                    ack.frame_id,
                    peer->graphics_pending_frames,
                    ack.queue_depth,
                    ack.total_frames_decoded);
    return LIBRDP_STATUS_OK;
}
