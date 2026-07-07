#include "protocol/slowpath.h"

#include "common/stream.h"

#include <string.h>

librdp_status rdp_slowpath_parse_share_control_header(const void* data,
                                                      size_t length,
                                                      rdp_slowpath_share_control_header* header)
{
    rdp_stream stream;

    if (!data || !header || length < 6)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &header->total_length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->pdu_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->channel_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header->total_length < 6 || header->total_length > length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}
