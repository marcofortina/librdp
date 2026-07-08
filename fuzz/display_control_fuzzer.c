#include "channels/display_control.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_display_control_caps caps = {0};
    rdp_display_control_monitor monitor;
    rdp_display_control_monitor monitors[2];
    rdp_buffer layout;

    (void)rdp_display_control_parse_caps(data, size, &caps);
    rdp_buffer_init(&layout);
    if (rdp_display_control_make_single_monitor(&monitor,
                                                size > 0 ? (uint32_t)data[0] * 64u : 1024u,
                                                size > 1 ? (uint32_t)data[1] * 64u : 768u) == LIBRDP_STATUS_OK)
    {
        (void)rdp_display_control_write_monitor_layout(&layout, &monitor, 1);
        layout.length = 0;
        monitors[0] = monitor;
        monitors[1] = monitor;
        monitors[1].flags = 0;
        monitors[1].left = (int32_t)monitor.width;
        (void)rdp_display_control_write_monitor_layout_with_caps(&layout, monitors, 2, &caps);
    }
    rdp_buffer_free(&layout);
    return 0;
}
