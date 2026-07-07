#include "protocol/capabilities.h"

#include "common/stream.h"

#include <string.h>

librdp_status rdp_capabilities_parse(const void* data, size_t length, rdp_capability_list* list)
{
    rdp_stream stream;
    uint16_t count = 0;
    uint16_t pad = 0;
    uint16_t i = 0;

    if (!data || !list)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(list, 0, sizeof(*list));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pad) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    (void)pad;

    if (count > RDP_CAPABILITY_MAX_SETS)
        return LIBRDP_STATUS_UNSUPPORTED;

    for (i = 0; i < count; i++)
    {
        rdp_capability_set* set = &list->sets[i];
        if (rdp_stream_read_u16_le(&stream, &set->type) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &set->length) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (set->length < 4 || rdp_stream_remaining(&stream) < (size_t)set->length - 4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        set->data_len = (size_t)set->length - 4u;
        if (rdp_stream_read_bytes(&stream, &set->data, set->data_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }

    list->count = count;
    return LIBRDP_STATUS_OK;
}
