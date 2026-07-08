#include "channels/filesystem_redirection.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_filesystem_redirection_create_request create_request;
    rdp_device_redirection_io_request close_request;
    rdp_filesystem_redirection_read_request read_request;
    rdp_filesystem_redirection_write_request write_request;
    rdp_filesystem_redirection_control_request control_request;
    rdp_filesystem_redirection_information_request information_request;
    rdp_filesystem_redirection_query_directory_request directory_request;
    rdp_filesystem_redirection_notify_change_request notify_request;
    rdp_filesystem_redirection_lock_request lock_request;
    rdp_filesystem_redirection_create_response create_response;
    rdp_filesystem_redirection_length_response length_response;
    rdp_buffer buffer;

    (void)rdp_filesystem_redirection_parse_create_request(data, size, &create_request);
    (void)rdp_filesystem_redirection_parse_close_request(data, size, &close_request);
    (void)rdp_filesystem_redirection_parse_read_request(data, size, &read_request);
    (void)rdp_filesystem_redirection_parse_write_request(data, size, &write_request);
    (void)rdp_filesystem_redirection_parse_control_request(data, size, &control_request);
    (void)rdp_filesystem_redirection_parse_query_volume_request(data, size, &information_request);
    (void)rdp_filesystem_redirection_parse_set_volume_request(data, size, &information_request);
    (void)rdp_filesystem_redirection_parse_query_information_request(data, size, &information_request);
    (void)rdp_filesystem_redirection_parse_set_information_request(data, size, &information_request);
    (void)rdp_filesystem_redirection_parse_query_directory_request(data, size, &directory_request);
    (void)rdp_filesystem_redirection_parse_notify_change_request(data, size, &notify_request);
    (void)rdp_filesystem_redirection_parse_lock_request(data, size, &lock_request);
    (void)rdp_filesystem_redirection_parse_create_response(data, size, &create_response);
    (void)rdp_filesystem_redirection_parse_length_response(data, size, &length_response);

    rdp_buffer_init(&buffer);
    (void)rdp_filesystem_redirection_write_create_response(&buffer, 1, 2, 0, 3, 1);
    buffer.length = 0;
    (void)rdp_filesystem_redirection_write_close_response(&buffer, 1, 2, 0);
    buffer.length = 0;
    (void)rdp_filesystem_redirection_write_read_response(&buffer, 1, 2, 0, data, size < 64u ? (uint32_t)size : 64u);
    buffer.length = 0;
    (void)rdp_filesystem_redirection_write_write_response(&buffer, 1, 2, 0, (uint32_t)(size & 0xffffffffu));
    buffer.length = 0;
    (void)rdp_filesystem_redirection_write_buffer_response(&buffer, 1, 2, 0, data, size < 64u ? (uint32_t)size : 64u);
    buffer.length = 0;
    (void)rdp_filesystem_redirection_write_length_response(&buffer, 1, 2, 0, (uint32_t)(size & 0xffffffffu));
    buffer.length = 0;
    (void)rdp_filesystem_redirection_write_lock_response(&buffer, 1, 2, 0);
    rdp_buffer_free(&buffer);
    return 0;
}
