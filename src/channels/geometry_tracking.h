/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: geometry tracking virtual-channel parser and writer declarations.
 * Invariants: declared message and region lengths are exact, rectangle counts
 * are bounded by their buffers, and coordinate rectangles are non-inverted.
 * Ownership: parsed buffers remain borrowed from the input for the call-site
 * lifetime; writers append to caller-owned buffers.
 * Threading: these stateless helpers are reentrant.
 * Trust boundary: every field originates from an untrusted dynamic channel.
 */

#ifndef RDP_CHANNELS_GEOMETRY_TRACKING_H
#define RDP_CHANNELS_GEOMETRY_TRACKING_H

#include <librdp/error.h>

#include "common/buffer.h"

#include <stddef.h>
#include <stdint.h>

#define RDP_GEOMETRY_TRACKING_CHANNEL_NAME "Microsoft::Windows::RDS::Geometry::v08.01"
#define RDP_GEOMETRY_TRACKING_VERSION_1 0x00000001u
#define RDP_GEOMETRY_TRACKING_UPDATE 0x00000001u
#define RDP_GEOMETRY_TRACKING_CLEAR 0x00000002u
#define RDP_GEOMETRY_TRACKING_TYPE_REGION 0x00000002u
#define RDP_GEOMETRY_TRACKING_REGION_HEADER_SIZE 32u
#define RDP_GEOMETRY_TRACKING_REGION_TYPE_RECTANGLES 1u
#define RDP_GEOMETRY_TRACKING_FIXED_SIZE 72u

typedef struct rdp_geometry_tracking_rect
{
    int32_t left;
    int32_t top;
    int32_t right;
    int32_t bottom;
} rdp_geometry_tracking_rect;

typedef struct rdp_geometry_tracking_packet
{
    uint32_t declared_length;
    uint32_t version;
    uint64_t mapping_id;
    uint32_t update_type;
    uint32_t flags;
    uint64_t top_level_id;
    rdp_geometry_tracking_rect local_bounds;
    rdp_geometry_tracking_rect top_level_bounds;
    uint32_t geometry_type;
    uint32_t geometry_buffer_len;
    const uint8_t* geometry_buffer;
    uint32_t region_header_size;
    uint32_t region_type;
    uint32_t rect_count;
    uint32_t region_data_size;
    rdp_geometry_tracking_rect region_bounds;
    const uint8_t* rect_data;
} rdp_geometry_tracking_packet;

librdp_status rdp_geometry_tracking_parse(const void* data,
                                          size_t length,
                                          rdp_geometry_tracking_packet* packet);
librdp_status rdp_geometry_tracking_get_rect(const rdp_geometry_tracking_packet* packet,
                                             uint32_t index,
                                             rdp_geometry_tracking_rect* rect);
librdp_status rdp_geometry_tracking_write_update(
    rdp_buffer* buffer,
    uint64_t mapping_id,
    uint64_t top_level_id,
    const rdp_geometry_tracking_rect* local_bounds,
    const rdp_geometry_tracking_rect* top_level_bounds,
    const rdp_geometry_tracking_rect* region_bounds,
    const rdp_geometry_tracking_rect* rects,
    uint32_t rect_count);
librdp_status rdp_geometry_tracking_write_clear(rdp_buffer* buffer,
                                                uint64_t mapping_id);

#endif
