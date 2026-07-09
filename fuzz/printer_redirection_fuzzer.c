#include "channels/printer_redirection.h"

#include "channels/device_redirection.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_printer_redirection_announce announce;
    rdp_printer_redirection_cache_event event;
    rdp_printer_redirection_xps_mode mode;
    rdp_buffer buffer;
    const char port_name[8] = {'P', 'R', 'N', 0, 0, 0, 0, 0};
    const uint8_t name_utf16[] = {'P', 0, 0, 0};
    uint32_t bounded_data = size < 64u ? (uint32_t)size : 64u;

    (void)rdp_printer_redirection_parse_announce_data(data, size, &announce);
    (void)rdp_printer_redirection_parse_cache_event(data, size, &event);
    (void)rdp_printer_redirection_parse_xps_mode(data, size, &mode);

    rdp_buffer_init(&buffer);
    announce.flags = RDP_PRINTER_REDIRECTION_ANNOUNCE_FLAG_DEFAULT;
    announce.code_page = 0;
    announce.pnp_name = NULL;
    announce.pnp_name_len = 0;
    announce.driver_name = (const uint8_t*)"D\0\0";
    announce.driver_name_len = 4;
    announce.printer_name = (const uint8_t*)"P\0\0";
    announce.printer_name_len = 4;
    announce.cached_fields = data;
    announce.cached_fields_len = size < 64u ? (uint32_t)size : 64u;
    (void)rdp_printer_redirection_write_announce_data(&buffer, &announce);
    buffer.length = 0;
    (void)rdp_printer_redirection_write_cache_add(&buffer,
                                                  port_name,
                                                  NULL,
                                                  0,
                                                  name_utf16,
                                                  sizeof(name_utf16),
                                                  name_utf16,
                                                  sizeof(name_utf16),
                                                  data,
                                                  bounded_data);
    buffer.length = 0;
    (void)rdp_printer_redirection_write_cache_update(&buffer, name_utf16, sizeof(name_utf16), data, bounded_data);
    buffer.length = 0;
    (void)rdp_printer_redirection_write_cache_delete(&buffer, name_utf16, sizeof(name_utf16));
    buffer.length = 0;
    (void)rdp_printer_redirection_write_cache_rename(&buffer,
                                                     name_utf16,
                                                     sizeof(name_utf16),
                                                     name_utf16,
                                                     sizeof(name_utf16));
    buffer.length = 0;
    (void)rdp_printer_redirection_write_xps_mode(&buffer, 1, 0);
    buffer.length = 0;
    (void)rdp_printer_redirection_write_create_response(&buffer, 1, 2, 0, 3);
    buffer.length = 0;
    (void)rdp_printer_redirection_write_close_response(&buffer, 1, 2, 0);
    buffer.length = 0;
    (void)rdp_printer_redirection_write_write_response(&buffer, 1, 2, 0, 4);
    buffer.length = 0;
    (void)rdp_printer_redirection_write_device_control_response(&buffer, 1, 2, 0);
    rdp_buffer_free(&buffer);
    return 0;
}
