#ifndef RDP_PROTOCOL_GCC_H
#define RDP_PROTOCOL_GCC_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/stream.h"

typedef struct rdp_gcc_user_data_block
{
    uint16_t type;
    uint16_t length;
    const uint8_t* payload;
    size_t payload_len;
} rdp_gcc_user_data_block;

librdp_status rdp_gcc_read_user_data_block(rdp_stream* stream, rdp_gcc_user_data_block* block);

#endif
