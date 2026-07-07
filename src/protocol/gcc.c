#include "protocol/gcc.h"

#include <string.h>

librdp_status rdp_gcc_read_user_data_block(rdp_stream* stream, rdp_gcc_user_data_block* block)
{
    if (!stream || !block)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_remaining(stream) < 4)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(block, 0, sizeof(*block));
    if (rdp_stream_read_u16_le(stream, &block->type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &block->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (block->length < 4 || rdp_stream_remaining(stream) < (size_t)block->length - 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    block->payload_len = (size_t)block->length - 4u;
    return rdp_stream_read_bytes(stream, &block->payload, block->payload_len);
}
