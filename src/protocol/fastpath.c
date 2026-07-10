#include "protocol/fastpath.h"

#include "common/stream.h"

#include <string.h>

static int rdp_fastpath_valid_action(uint8_t action)
{
    return action == RDP_FASTPATH_OUTPUT_ACTION_FASTPATH ||
           action == RDP_FASTPATH_OUTPUT_ACTION_X224;
}

static int rdp_fastpath_valid_update_code(uint8_t update_code)
{
    return update_code == RDP_FASTPATH_UPDATE_ORDERS ||
           update_code == RDP_FASTPATH_UPDATE_BITMAP ||
           update_code == RDP_FASTPATH_UPDATE_PALETTE ||
           update_code == RDP_FASTPATH_UPDATE_SYNCHRONIZE ||
           update_code == RDP_FASTPATH_UPDATE_SURFACE_COMMANDS ||
           update_code == RDP_FASTPATH_UPDATE_POINTER_NULL ||
           update_code == RDP_FASTPATH_UPDATE_POINTER_DEFAULT ||
           update_code == RDP_FASTPATH_UPDATE_POINTER_POSITION ||
           update_code == RDP_FASTPATH_UPDATE_POINTER_COLOR ||
           update_code == RDP_FASTPATH_UPDATE_POINTER_CACHED ||
           update_code == RDP_FASTPATH_UPDATE_POINTER_NEW ||
           update_code == RDP_FASTPATH_UPDATE_POINTER_LARGE;
}

librdp_status rdp_fastpath_parse_header(const void* data, size_t length, rdp_fastpath_header* header)
{
    const uint8_t* p = (const uint8_t*)data;
    uint16_t packet_length = 0;

    if (!data || !header || length < 2)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(header, 0, sizeof(*header));
    header->action = (uint8_t)(p[0] & 0x03u);
    header->security_flags = (uint8_t)((p[0] >> 6) & 0x03u);
    if (!rdp_fastpath_valid_action(header->action))
        return LIBRDP_STATUS_PROTOCOL_ERROR;

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

librdp_status rdp_fastpath_write_header(rdp_buffer* buffer,
                                        uint8_t action,
                                        uint8_t security_flags,
                                        size_t payload_len)
{
    size_t packet_length = payload_len + 2u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_fastpath_valid_action(action) || security_flags > 3u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (packet_length > 127u)
        packet_length = payload_len + 3u;
    if (packet_length > 0x7fffu || packet_length < payload_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, (uint8_t)(action | (uint8_t)(security_flags << 6)));
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (packet_length <= 127u)
        return rdp_buffer_append_u8(buffer, (uint8_t)packet_length);
    status = rdp_buffer_append_u8(buffer, (uint8_t)(0x80u | ((packet_length >> 8u) & 0x7fu)));
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, (uint8_t)(packet_length & 0xffu));
}

librdp_status rdp_fastpath_write_update(rdp_buffer* buffer,
                                        uint8_t update_code,
                                        uint8_t fragmentation,
                                        uint8_t compression,
                                        uint8_t compression_flags,
                                        const void* data,
                                        size_t data_len)
{
    uint8_t update_header = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_fastpath_valid_update_code(update_code) ||
        fragmentation > RDP_FASTPATH_FRAGMENT_NEXT ||
        (compression != 0 && compression != RDP_FASTPATH_OUTPUT_COMPRESSION_USED) ||
        (!data && data_len > 0) || data_len > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (update_code == RDP_FASTPATH_UPDATE_SYNCHRONIZE &&
        (fragmentation != RDP_FASTPATH_FRAGMENT_SINGLE || compression != 0 || data_len != 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    update_header = (uint8_t)(update_code |
                              (uint8_t)(fragmentation << 4) |
                              (uint8_t)(compression << 6));
    status = rdp_buffer_append_u8(buffer, update_header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (compression == RDP_FASTPATH_OUTPUT_COMPRESSION_USED)
    {
        status = rdp_buffer_append_u8(buffer, compression_flags);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, data_len);
}

librdp_status rdp_fastpath_write_updates(rdp_buffer* buffer,
                                         const rdp_fastpath_update* updates,
                                         uint16_t count)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t i = 0;

    if (!buffer || (!updates && count > 0) || count > RDP_FASTPATH_MAX_UPDATES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    for (i = 0; i < count && status == LIBRDP_STATUS_OK; i++)
    {
        status = rdp_fastpath_write_update(&payload,
                                           updates[i].update_code,
                                           updates[i].fragmentation,
                                           updates[i].compression,
                                           updates[i].compression_flags,
                                           updates[i].data,
                                           updates[i].data_len);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_fastpath_write_header(buffer,
                                           RDP_FASTPATH_OUTPUT_ACTION_FASTPATH,
                                           0,
                                           payload.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, payload.data, payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_fastpath_parse_updates_payload(const void* data,
                                                 size_t length,
                                                 rdp_fastpath_update_list* updates)
{
    rdp_stream stream;

    if (!data || !updates)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(updates, 0, sizeof(*updates));
    rdp_stream_init(&stream, data, length);

    while (rdp_stream_remaining(&stream) > 0)
    {
        rdp_fastpath_update* update = NULL;
        uint8_t update_header = 0;
        uint16_t size = 0;

        if (updates->count >= RDP_FASTPATH_MAX_UPDATES)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        update = &updates->updates[updates->count];

        if (rdp_stream_read_u8(&stream, &update_header) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        update->update_code = (uint8_t)(update_header & 0x0fu);
        update->fragmentation = (uint8_t)((update_header >> 4) & 0x03u);
        update->compression = (uint8_t)((update_header >> 6) & 0x03u);
        if (update->compression != 0 && update->compression != RDP_FASTPATH_OUTPUT_COMPRESSION_USED)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (update->compression == RDP_FASTPATH_OUTPUT_COMPRESSION_USED &&
            rdp_stream_read_u8(&stream, &update->compression_flags) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_stream_read_u16_le(&stream, &size) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (size > rdp_stream_remaining(&stream))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (update->update_code == RDP_FASTPATH_UPDATE_SYNCHRONIZE &&
            (update->fragmentation != RDP_FASTPATH_FRAGMENT_SINGLE ||
             update->compression != 0 ||
             size != 0))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        update->data_len = size;
        if (size > 0 && rdp_stream_read_bytes(&stream, &update->data, size) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        updates->count++;
    }

    return LIBRDP_STATUS_OK;
}

librdp_status rdp_fastpath_parse_updates(const void* data, size_t length, rdp_fastpath_update_list* updates)
{
    rdp_fastpath_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !updates)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_fastpath_parse_header(data, length, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header.action != RDP_FASTPATH_OUTPUT_ACTION_FASTPATH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.security_flags != 0)
        return LIBRDP_STATUS_STATE;

    return rdp_fastpath_parse_updates_payload((const uint8_t*)data + header.header_length,
                                              header.length - header.header_length,
                                              updates);
}
