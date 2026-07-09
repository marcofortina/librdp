#include "protocol/session_selection.h"

#include "common/stream.h"

#include <string.h>

librdp_status rdp_session_selection_parse_pdu(const void* data,
                                              size_t length,
                                              rdp_session_selection_pdu* pdu)
{
    rdp_stream stream;
    uint32_t expected = 0;

    if (!data || !pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_SESSION_SELECTION_V1_LENGTH || length > UINT32_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(pdu, 0, sizeof(*pdu));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &pdu->cb_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &pdu->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &pdu->version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &pdu->id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (pdu->cb_size != length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (pdu->cb_size == RDP_SESSION_SELECTION_V1_LENGTH)
    {
        if (pdu->version != RDP_SESSION_SELECTION_VERSION1 || rdp_stream_remaining(&stream) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        return LIBRDP_STATUS_OK;
    }

    if (pdu->cb_size < RDP_SESSION_SELECTION_V2_HEADER_LENGTH ||
        pdu->version != RDP_SESSION_SELECTION_VERSION2 ||
        rdp_stream_read_u16_le(&stream, &pdu->text_chars) != LIBRDP_STATUS_OK ||
        pdu->text_chars > RDP_SESSION_SELECTION_MAX_TEXT_CHARS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    expected = RDP_SESSION_SELECTION_V2_HEADER_LENGTH + ((uint32_t)pdu->text_chars * 2u);
    if (pdu->cb_size != expected)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &pdu->text_utf16le, (size_t)pdu->text_chars * 2u) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_session_selection_write_v1(rdp_buffer* buffer, uint32_t id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, RDP_SESSION_SELECTION_V1_LENGTH);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, RDP_SESSION_SELECTION_VERSION1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, id);
}

librdp_status rdp_session_selection_write_v2(rdp_buffer* buffer,
                                             uint32_t id,
                                             const void* text_utf16le,
                                             uint16_t text_chars)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t byte_len = (uint32_t)text_chars * 2u;
    uint32_t cb_size = RDP_SESSION_SELECTION_V2_HEADER_LENGTH + byte_len;

    if (!buffer || (!text_utf16le && text_chars > 0) ||
        text_chars > RDP_SESSION_SELECTION_MAX_TEXT_CHARS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u32_le(buffer, cb_size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, RDP_SESSION_SELECTION_VERSION2);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, text_chars);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, text_utf16le, byte_len);
}
