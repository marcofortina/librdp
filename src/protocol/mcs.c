#include "protocol/mcs.h"

#include <string.h>

librdp_status rdp_mcs_read_ber_length(rdp_stream* stream, size_t* length)
{
    uint8_t first = 0;
    uint8_t count = 0;
    size_t value = 0;
    uint8_t i = 0;

    if (!stream || !length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u8(stream, &first) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((first & 0x80u) == 0)
    {
        *length = first;
        return LIBRDP_STATUS_OK;
    }

    count = (uint8_t)(first & 0x7fu);
    if (count == 0 || count > sizeof(size_t) || rdp_stream_remaining(stream) < count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    for (i = 0; i < count; i++)
    {
        uint8_t byte = 0;
        if (rdp_stream_read_u8(stream, &byte) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        value = (value << 8) | byte;
    }

    *length = value;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_mcs_parse_connect_response(const void* data, size_t length, rdp_mcs_connect_response* response)
{
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(response, 0, sizeof(*response));
    rdp_stream_init(&stream, data, length);
    while (rdp_stream_remaining(&stream) >= 2)
    {
        uint8_t tag = 0;
        size_t item_len = 0;
        const uint8_t* payload = NULL;

        if (rdp_stream_read_u8(&stream, &tag) != LIBRDP_STATUS_OK ||
            rdp_mcs_read_ber_length(&stream, &item_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_stream_remaining(&stream) < item_len)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_stream_read_bytes(&stream, &payload, item_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;

        if (tag == 0x0a && item_len == 1)
        {
            response->has_result = true;
            response->result = payload[0];
        }
    }

    return response->has_result ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}
