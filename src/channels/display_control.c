/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: display layout and monitor control channel support.
 * Invariants: channel payload lengths and negotiated capabilities are checked
 * before state changes or callbacks.
 * Ownership: parsed channel objects are caller-owned unless the session stores
 * an explicit copy.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths remain local policy inputs.
 */


#include "channels/display_control.h"

#include "common/stream.h"

#include <librdp/session.h>

#include <string.h>

#define RDP_DISPLAY_CONTROL_MIN_DIMENSION 200u
#define RDP_DISPLAY_CONTROL_MAX_DIMENSION 8192u
#define RDP_DISPLAY_CONTROL_MIN_PHYSICAL_MM 10u
#define RDP_DISPLAY_CONTROL_MAX_PHYSICAL_MM 10000u
#define RDP_DISPLAY_CONTROL_MAX_MONITORS LIBRDP_DISPLAY_MAX_MONITORS

static uint32_t rdp_display_control_clamp_dimension(uint32_t value, int even)
{
    if (value < RDP_DISPLAY_CONTROL_MIN_DIMENSION)
        value = RDP_DISPLAY_CONTROL_MIN_DIMENSION;
    if (value > RDP_DISPLAY_CONTROL_MAX_DIMENSION)
        value = RDP_DISPLAY_CONTROL_MAX_DIMENSION;
    if (even && (value & 1u) != 0)
        value--;
    if (value < RDP_DISPLAY_CONTROL_MIN_DIMENSION)
        value = RDP_DISPLAY_CONTROL_MIN_DIMENSION;
    return value;
}

static uint32_t rdp_display_control_pixels_to_mm(uint32_t pixels)
{
    uint32_t mm = (uint32_t)(((uint64_t)pixels * 254u) / 960u);

    if (mm < 10u)
        return 10u;
    if (mm > 10000u)
        return 10000u;
    return mm;
}

static int rdp_display_control_valid_orientation(uint32_t orientation)
{
    return orientation == 0 || orientation == 90 || orientation == 180 || orientation == 270;
}

static int rdp_display_control_valid_device_scale(uint32_t scale)
{
    return scale == 100 || scale == 140 || scale == 180;
}

static int rdp_display_control_valid_physical_size(uint32_t millimeters)
{
    return millimeters == 0 ||
           (millimeters >= RDP_DISPLAY_CONTROL_MIN_PHYSICAL_MM &&
            millimeters <= RDP_DISPLAY_CONTROL_MAX_PHYSICAL_MM);
}

static int rdp_display_control_caps_valid(const rdp_display_control_caps* caps)
{
    if (!caps)
        return 0;
    return caps->max_num_monitors > 0 &&
           caps->max_num_monitors <= RDP_DISPLAY_CONTROL_MAX_MONITORS &&
           caps->max_monitor_area_factor_a > 0 &&
           caps->max_monitor_area_factor_a <= RDP_DISPLAY_CONTROL_MAX_DIMENSION &&
           caps->max_monitor_area_factor_b > 0 &&
           caps->max_monitor_area_factor_b <= RDP_DISPLAY_CONTROL_MAX_DIMENSION;
}

static int rdp_display_control_monitors_overlap(const rdp_display_control_monitor* a,
                                                const rdp_display_control_monitor* b)
{
    int64_t a_left = a->left;
    int64_t a_top = a->top;
    int64_t a_right = a_left + (int64_t)a->width;
    int64_t a_bottom = a_top + (int64_t)a->height;
    int64_t b_left = b->left;
    int64_t b_top = b->top;
    int64_t b_right = b_left + (int64_t)b->width;
    int64_t b_bottom = b_top + (int64_t)b->height;

    return a_left < b_right && b_left < a_right && a_top < b_bottom && b_top < a_bottom;
}

static int rdp_display_control_monitor_rect_valid(const rdp_display_control_monitor* monitor)
{
    int64_t right = 0;
    int64_t bottom = 0;

    if (!monitor)
        return 0;
    right = (int64_t)monitor->left + (int64_t)monitor->width;
    bottom = (int64_t)monitor->top + (int64_t)monitor->height;
    return right <= INT32_MAX && bottom <= INT32_MAX;
}

/*
 * Validate a display-control monitor layout before it is sent or accepted.
 * The function enforces primary-monitor, overlap, scale, orientation, and
 * server-capability invariants so invalid resize state fails locally.
 */
static librdp_status rdp_display_control_validate_layout(const rdp_display_control_monitor* monitors,
                                                         uint32_t monitor_count,
                                                         const rdp_display_control_caps* caps)
{
    uint32_t i = 0;
    uint32_t primary_count = 0;
    uint64_t area = 0;
    uint64_t max_area = 0;

    if (!monitors || monitor_count == 0 || monitor_count > RDP_DISPLAY_CONTROL_MAX_MONITORS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (caps)
    {
        if (!rdp_display_control_caps_valid(caps))
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        if (monitor_count > caps->max_num_monitors)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    for (i = 0; i < monitor_count; i++)
    {
        if ((monitors[i].flags & ~RDP_DISPLAY_CONTROL_MONITOR_PRIMARY) != 0)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        for (uint32_t j = i + 1u; j < monitor_count; j++)
        {
            if (rdp_display_control_monitors_overlap(&monitors[i], &monitors[j]))
                return LIBRDP_STATUS_INVALID_ARGUMENT;
        }
        if ((monitors[i].flags & RDP_DISPLAY_CONTROL_MONITOR_PRIMARY) != 0)
        {
            primary_count++;
            if (monitors[i].left != 0 || monitors[i].top != 0)
                return LIBRDP_STATUS_INVALID_ARGUMENT;
        }
        if (monitors[i].width < RDP_DISPLAY_CONTROL_MIN_DIMENSION ||
            monitors[i].width > RDP_DISPLAY_CONTROL_MAX_DIMENSION ||
            monitors[i].height < RDP_DISPLAY_CONTROL_MIN_DIMENSION ||
            monitors[i].height > RDP_DISPLAY_CONTROL_MAX_DIMENSION ||
            (monitors[i].width & 1u) != 0 ||
            !rdp_display_control_monitor_rect_valid(&monitors[i]) ||
            !rdp_display_control_valid_physical_size(monitors[i].physical_width) ||
            !rdp_display_control_valid_physical_size(monitors[i].physical_height) ||
            !rdp_display_control_valid_orientation(monitors[i].orientation) ||
            monitors[i].desktop_scale_factor < 100 ||
            monitors[i].desktop_scale_factor > 500 ||
            !rdp_display_control_valid_device_scale(monitors[i].device_scale_factor))
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        area += (uint64_t)monitors[i].width * (uint64_t)monitors[i].height;
    }
    if (primary_count != 1)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (caps && caps->max_num_monitors != 0 &&
        caps->max_monitor_area_factor_a != 0 &&
        caps->max_monitor_area_factor_b != 0)
    {
        max_area = (uint64_t)caps->max_num_monitors *
                   (uint64_t)caps->max_monitor_area_factor_a *
                   (uint64_t)caps->max_monitor_area_factor_b;
        if (area > max_area)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_display_control_parse_caps(const void* data,
                                             size_t length,
                                             rdp_display_control_caps* caps)
{
    rdp_display_control_caps parsed;
    rdp_stream stream;
    uint32_t pdu_type = 0;
    uint32_t pdu_length = 0;

    if (!data || !caps)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &pdu_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &pdu_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (pdu_type != RDP_DISPLAY_CONTROL_PDU_CAPS || pdu_length < 20u || pdu_length > length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (pdu_length != length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u32_le(&stream, &parsed.max_num_monitors) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.max_monitor_area_factor_a) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.max_monitor_area_factor_b) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_display_control_caps_valid(&parsed))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *caps = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_display_control_make_single_monitor(rdp_display_control_monitor* monitor,
                                                      uint32_t width,
                                                      uint32_t height)
{
    if (!monitor || width == 0 || height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(monitor, 0, sizeof(*monitor));
    width = rdp_display_control_clamp_dimension(width, 1);
    height = rdp_display_control_clamp_dimension(height, 0);
    monitor->flags = RDP_DISPLAY_CONTROL_MONITOR_PRIMARY;
    monitor->width = width;
    monitor->height = height;
    monitor->physical_width = rdp_display_control_pixels_to_mm(width);
    monitor->physical_height = rdp_display_control_pixels_to_mm(height);
    monitor->desktop_scale_factor = 100;
    monitor->device_scale_factor = 100;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_display_control_parse_monitor_layout(const void* data,
                                                       size_t length,
                                                       rdp_display_control_monitor* monitors,
                                                       uint32_t monitor_capacity,
                                                       uint32_t* monitor_count)
{
    return rdp_display_control_parse_monitor_layout_with_caps(data,
                                                              length,
                                                              monitors,
                                                              monitor_capacity,
                                                              monitor_count,
                                                              NULL);
}

/*
 * Parse a monitor-layout PDU and validate it against optional server caps.
 * Output entries are zeroed before parsing, and malformed length/count/layout
 * state is rejected without exposing partially trusted monitor data.
 */
librdp_status rdp_display_control_parse_monitor_layout_with_caps(const void* data,
                                                                 size_t length,
                                                                 rdp_display_control_monitor* monitors,
                                                                 uint32_t monitor_capacity,
                                                                 uint32_t* monitor_count,
                                                                 const rdp_display_control_caps* caps)
{
    rdp_stream stream;
    uint32_t pdu_type = 0;
    uint32_t pdu_length = 0;
    uint32_t monitor_layout_size = 0;
    uint32_t count = 0;
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !monitors || !monitor_count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (monitor_capacity == 0 || monitor_capacity > RDP_DISPLAY_CONTROL_MAX_MONITORS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(monitors, 0, sizeof(*monitors) * monitor_capacity);
    *monitor_count = 0;
    if (length < 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &pdu_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &pdu_length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &monitor_layout_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &count) != LIBRDP_STATUS_OK)
    {
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto fail;
    }
    if (pdu_type != RDP_DISPLAY_CONTROL_PDU_MONITOR_LAYOUT ||
        pdu_length != length ||
        monitor_layout_size != RDP_DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE ||
        count == 0 ||
        count > monitor_capacity ||
        count > RDP_DISPLAY_CONTROL_MAX_MONITORS ||
        pdu_length != 16u + RDP_DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE * count)
    {
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto fail;
    }

    for (i = 0; i < count; i++)
    {
        uint32_t left = 0;
        uint32_t top = 0;

        if (rdp_stream_read_u32_le(&stream, &monitors[i].flags) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &left) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &top) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &monitors[i].width) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &monitors[i].height) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &monitors[i].physical_width) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &monitors[i].physical_height) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &monitors[i].orientation) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &monitors[i].desktop_scale_factor) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &monitors[i].device_scale_factor) != LIBRDP_STATUS_OK)
        {
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            goto fail;
        }
        monitors[i].left = (int32_t)left;
        monitors[i].top = (int32_t)top;
    }
    if (rdp_stream_remaining(&stream) != 0)
    {
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto fail;
    }
    status = rdp_display_control_validate_layout(monitors, count, caps);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    *monitor_count = count;
    return LIBRDP_STATUS_OK;

fail:
    memset(monitors, 0, sizeof(*monitors) * monitor_capacity);
    *monitor_count = 0;
    return status;
}

librdp_status rdp_display_control_write_monitor_layout(rdp_buffer* buffer,
                                                       const rdp_display_control_monitor* monitors,
                                                       uint32_t monitor_count)
{
    return rdp_display_control_write_monitor_layout_with_caps(buffer, monitors, monitor_count, NULL);
}

librdp_status rdp_display_control_write_monitor_layout_with_caps(rdp_buffer* buffer,
                                                                 const rdp_display_control_monitor* monitors,
                                                                 uint32_t monitor_count,
                                                                 const rdp_display_control_caps* caps)
{
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_display_control_validate_layout(monitors, monitor_count, caps);
    if (status != LIBRDP_STATUS_OK)
        return status;

    status = rdp_buffer_append_u32_le(buffer, RDP_DISPLAY_CONTROL_PDU_MONITOR_LAYOUT);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer,
                                          16u + RDP_DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE * monitor_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, RDP_DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, monitor_count);
    for (i = 0; status == LIBRDP_STATUS_OK && i < monitor_count; i++)
    {
        status = rdp_buffer_append_u32_le(buffer, monitors[i].flags);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, (uint32_t)monitors[i].left);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, (uint32_t)monitors[i].top);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, monitors[i].width);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, monitors[i].height);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, monitors[i].physical_width);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, monitors[i].physical_height);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, monitors[i].orientation);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, monitors[i].desktop_scale_factor);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, monitors[i].device_scale_factor);
    }
    return status;
}
