#include "licensing/licensing.h"

#include "common/stream.h"

#include <string.h>

librdp_status rdp_license_parse_error_alert(const void* data, size_t length, rdp_license_error_alert* alert)
{
    rdp_stream stream;

    if (!data || !alert)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(alert, 0, sizeof(*alert));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &alert->message_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &alert->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &alert->length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &alert->error_code) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &alert->state_transition) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &alert->blob_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &alert->blob_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (alert->length < 16 || alert->length > length || rdp_stream_remaining(&stream) < alert->blob_length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &alert->blob, alert->blob_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}
