#include "transport/multitransport.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_multitransport_header header;
    rdp_multitransport_subheader subheader;
    rdp_multitransport_create_request request;
    rdp_multitransport_create_response response;
    rdp_multitransport_data tunnel_data;
    rdp_buffer buffer;
    rdp_buffer subheader_bytes;
    uint8_t cookie[RDP_MULTITRANSPORT_COOKIE_LENGTH] = {0};

    (void)rdp_multitransport_parse_header(data, size, &header);
    (void)rdp_multitransport_parse_subheader(data, size, &subheader);
    (void)rdp_multitransport_parse_create_request(data, size, &request);
    (void)rdp_multitransport_parse_create_response(data, size, &response);
    (void)rdp_multitransport_parse_data(data, size, &tunnel_data);

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&subheader_bytes);
    (void)rdp_multitransport_write_create_request(&buffer, 1, cookie);
    buffer.length = 0;
    (void)rdp_multitransport_write_create_response(&buffer, 0);
    buffer.length = 0;
    (void)rdp_multitransport_write_subheader(&subheader_bytes,
                                             RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_REQUEST,
                                             data,
                                             size < 16u ? size : 16u);
    (void)rdp_multitransport_write_data(&buffer,
                                        subheader_bytes.data,
                                        subheader_bytes.length,
                                        data,
                                        size < 64u ? size : 64u);
    rdp_buffer_free(&subheader_bytes);
    rdp_buffer_free(&buffer);
    return 0;
}
