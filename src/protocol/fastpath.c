#include "protocol/fastpath.h"

#include "common/stream.h"

#include <string.h>

librdp_status rdp_fastpath_parse_header(const void* data, size_t length, rdp_fastpath_header* header)
{
    const uint8_t* p = (const uint8_t*)data;
    uint16_t packet_length = 0;

    if (!data || !header || length < 2)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(header, 0, sizeof(*header));
    header->action = (uint8_t)(p[0] & 0x03u);
    header->security_flags = (uint8_t)((p[0] >> 6) & 0x03u);

    if ((p[1] & 0x80u) != 0)
    {
        if (length < 3)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        packet_length = (uint16_t)(((uint16_t)(p[1] & 0x7fu) << 8) | p[2]);
        header->header_length = 3;
        header->long_length = true;
    }
    else
    {
        packet_length = p[1];
        header->header_length = 2;
    }

    if (packet_length < header->header_length || packet_length > length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    header->length = packet_length;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_fastpath_parse_updates(const void* data, size_t length, rdp_fastpath_update_list* updates)
{
    rdp_fastpath_header header;
    rdp_stream stream;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !updates)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(updates, 0, sizeof(*updates));
    status = rdp_fastpath_parse_header(data, length, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header.action != RDP_FASTPATH_OUTPUT_ACTION_FASTPATH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.security_flags != 0)
        return LIBRDP_STATUS_UNSUPPORTED;

    rdp_stream_init(&stream, data, header.length);
    if (rdp_stream_skip(&stream, header.header_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    while (rdp_stream_remaining(&stream) > 0)
    {
        rdp_fastpath_update* update = NULL;
        uint8_t update_header = 0;
        uint16_t size = 0;

        if (updates->count >= RDP_FASTPATH_MAX_UPDATES)
            return LIBRDP_STATUS_UNSUPPORTED;
        update = &updates->updates[updates->count];

        if (rdp_stream_read_u8(&stream, &update_header) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        update->update_code = (uint8_t)(update_header & 0x0fu);
        update->fragmentation = (uint8_t)((update_header >> 4) & 0x03u);
        update->compression = (uint8_t)((update_header >> 6) & 0x03u);
        if (update->compression == RDP_FASTPATH_OUTPUT_COMPRESSION_USED &&
            rdp_stream_read_u8(&stream, &update->compression_flags) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_stream_read_u16_le(&stream, &size) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (size > rdp_stream_remaining(&stream))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        update->data_len = size;
        if (size > 0 && rdp_stream_read_bytes(&stream, &update->data, size) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        updates->count++;
    }

    return LIBRDP_STATUS_OK;
}
