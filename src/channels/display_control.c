#include "channels/display_control.h"

#include "common/stream.h"

#include <string.h>

#define RDP_DISPLAY_CONTROL_MIN_DIMENSION 200u
#define RDP_DISPLAY_CONTROL_MAX_DIMENSION 8192u
#define RDP_DISPLAY_CONTROL_MAX_MONITORS 16u

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

librdp_status rdp_display_control_parse_caps(const void* data,
                                             size_t length,
                                             rdp_display_control_caps* caps)
{
    rdp_stream stream;
    uint32_t pdu_type = 0;
    uint32_t pdu_length = 0;

    if (!data || !caps)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(caps, 0, sizeof(*caps));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &pdu_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &pdu_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (pdu_type != RDP_DISPLAY_CONTROL_PDU_CAPS || pdu_length < 20u || pdu_length > length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u32_le(&stream, &caps->max_num_monitors) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &caps->max_monitor_area_factor_a) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &caps->max_monitor_area_factor_b) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
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

librdp_status rdp_display_control_write_monitor_layout(rdp_buffer* buffer,
                                                       const rdp_display_control_monitor* monitors,
                                                       uint32_t monitor_count)
{
    uint32_t i = 0;
    uint32_t primary_count = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !monitors || monitor_count == 0 || monitor_count > RDP_DISPLAY_CONTROL_MAX_MONITORS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < monitor_count; i++)
    {
        if ((monitors[i].flags & RDP_DISPLAY_CONTROL_MONITOR_PRIMARY) != 0)
            primary_count++;
        if (monitors[i].width < RDP_DISPLAY_CONTROL_MIN_DIMENSION ||
            monitors[i].width > RDP_DISPLAY_CONTROL_MAX_DIMENSION ||
            monitors[i].height < RDP_DISPLAY_CONTROL_MIN_DIMENSION ||
            monitors[i].height > RDP_DISPLAY_CONTROL_MAX_DIMENSION ||
            (monitors[i].width & 1u) != 0 ||
            (monitors[i].orientation != 0 && monitors[i].orientation != 90 &&
             monitors[i].orientation != 180 && monitors[i].orientation != 270))
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    if (primary_count != 1)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

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
