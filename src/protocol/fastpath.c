#include "protocol/fastpath.h"

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
