#ifndef RDP_PROTOCOL_FASTPATH_H
#define RDP_PROTOCOL_FASTPATH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

typedef struct rdp_fastpath_header
{
    uint8_t action;
    uint8_t security_flags;
    uint16_t length;
    size_t header_length;
    bool long_length;
} rdp_fastpath_header;

librdp_status rdp_fastpath_parse_header(const void* data, size_t length, rdp_fastpath_header* header);

#endif
