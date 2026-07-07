#include "clipboard/clipboard.h"

#include "common/stream.h"

#include <string.h>

librdp_status rdp_clipboard_parse_packet(const void* data, size_t length, rdp_clipboard_packet* packet)
{
    rdp_stream stream;

    if (!data || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(packet, 0, sizeof(*packet));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &packet->type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &packet->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &packet->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((size_t)packet->length > rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    packet->payload_len = packet->length;
    return rdp_stream_read_bytes(&stream, &packet->payload, packet->payload_len);
}
