#ifndef RDP_PROTOCOL_MCS_H
#define RDP_PROTOCOL_MCS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"
#include "common/stream.h"

typedef struct rdp_mcs_connect_response
{
    bool has_result;
    uint8_t result;
} rdp_mcs_connect_response;

librdp_status rdp_mcs_write_ber_length(rdp_buffer* buffer, size_t length);
librdp_status rdp_mcs_write_ber_integer(rdp_buffer* buffer, uint32_t value);
librdp_status rdp_mcs_write_connect_initial(rdp_buffer* buffer, const void* gcc_data, size_t gcc_data_len);
librdp_status rdp_mcs_read_ber_length(rdp_stream* stream, size_t* length);
librdp_status rdp_mcs_parse_connect_response(const void* data, size_t length, rdp_mcs_connect_response* response);

#endif
