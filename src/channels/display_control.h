/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: display control channel parser and writer declarations.
 * Invariants: channel payload lengths, message identifiers, and negotiated
 * capabilities must be validated before state changes.
 * Ownership: parsed packet structs remain caller-owned unless a session
 * explicitly stores a copy.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths are local policy inputs.
 */


#ifndef RDP_CHANNELS_DISPLAY_CONTROL_H
#define RDP_CHANNELS_DISPLAY_CONTROL_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_DISPLAY_CONTROL_CHANNEL_NAME "Microsoft::Windows::RDS::DisplayControl"
#define RDP_DISPLAY_CONTROL_PDU_MONITOR_LAYOUT 0x00000002u
#define RDP_DISPLAY_CONTROL_PDU_CAPS 0x00000005u
#define RDP_DISPLAY_CONTROL_MONITOR_PRIMARY 0x00000001u
#define RDP_DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE 40u

typedef struct rdp_display_control_caps
{
    uint32_t max_num_monitors;
    uint32_t max_monitor_area_factor_a;
    uint32_t max_monitor_area_factor_b;
} rdp_display_control_caps;

typedef struct rdp_display_control_monitor
{
    uint32_t flags;
    int32_t left;
    int32_t top;
    uint32_t width;
    uint32_t height;
    uint32_t physical_width;
    uint32_t physical_height;
    uint32_t orientation;
    uint32_t desktop_scale_factor;
    uint32_t device_scale_factor;
} rdp_display_control_monitor;

librdp_status rdp_display_control_parse_caps(const void* data,
                                             size_t length,
                                             rdp_display_control_caps* caps);
librdp_status rdp_display_control_make_single_monitor(rdp_display_control_monitor* monitor,
                                                      uint32_t width,
                                                      uint32_t height);
librdp_status rdp_display_control_parse_monitor_layout(const void* data,
                                                       size_t length,
                                                       rdp_display_control_monitor* monitors,
                                                       uint32_t monitor_capacity,
                                                       uint32_t* monitor_count);
librdp_status rdp_display_control_parse_monitor_layout_with_caps(const void* data,
                                                                 size_t length,
                                                                 rdp_display_control_monitor* monitors,
                                                                 uint32_t monitor_capacity,
                                                                 uint32_t* monitor_count,
                                                                 const rdp_display_control_caps* caps);
librdp_status rdp_display_control_write_monitor_layout(rdp_buffer* buffer,
                                                       const rdp_display_control_monitor* monitors,
                                                       uint32_t monitor_count);
librdp_status rdp_display_control_write_monitor_layout_with_caps(rdp_buffer* buffer,
                                                                 const rdp_display_control_monitor* monitors,
                                                                 uint32_t monitor_count,
                                                                 const rdp_display_control_caps* caps);

#endif
