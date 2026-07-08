#include "channels/mouse_cursor.h"

#include "common/buffer.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_mouse_cursor_header header;
    rdp_mouse_cursor_capset capset;
    rdp_pointer_update update;
    rdp_buffer response;
    rdp_buffer decoded;
    size_t stride = 0;

    rdp_buffer_init(&response);
    rdp_buffer_init(&decoded);
    (void)rdp_mouse_cursor_parse_header(data, size, &header);
    (void)rdp_mouse_cursor_parse_caps_confirm(data, size, &capset);
    if (rdp_mouse_cursor_parse_update(data, size, &update) == LIBRDP_STATUS_OK)
        (void)rdp_pointer_decode_bgra32(&update, &decoded, &stride);
    (void)rdp_mouse_cursor_write_caps_advertise(&response);
    rdp_buffer_free(&decoded);
    rdp_buffer_free(&response);
    return 0;
}
