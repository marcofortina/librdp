#include "channels/core_input.h"

#include "common/stream.h"

#include <string.h>

static librdp_status rdp_core_input_write_header(rdp_buffer* buffer, uint8_t pdu_type, uint8_t event_count)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u8(buffer, RDP_CORE_INPUT_SIGNATURE);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, pdu_type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, event_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    return status;
}

static uint8_t rdp_core_input_pack_event(uint8_t type, uint8_t flags)
{
    return (uint8_t)(((type & 0x07u) << 5) | (flags & 0x1fu));
}

librdp_status rdp_core_input_parse_header(const void* data,
                                          size_t length,
                                          rdp_core_input_header* header)
{
    const uint8_t* bytes = (const uint8_t*)data;

    if (!data || !header || length < 4)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(header, 0, sizeof(*header));
    header->signature = bytes[0];
    header->pdu_type = bytes[1];
    header->event_count = bytes[2];
    header->padding = bytes[3];
    if (header->signature != RDP_CORE_INPUT_SIGNATURE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header->pdu_type != RDP_CORE_INPUT_PDU_CS_INIT_REQUEST &&
        header->pdu_type != RDP_CORE_INPUT_PDU_SC_INIT_RESPONSE &&
        header->pdu_type != RDP_CORE_INPUT_PDU_CS_KEYBOARD_AND_MOUSE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header->pdu_type != RDP_CORE_INPUT_PDU_CS_KEYBOARD_AND_MOUSE && header->event_count != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_core_input_write_init_request(rdp_buffer* buffer)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_core_input_write_header(buffer, RDP_CORE_INPUT_PDU_CS_INIT_REQUEST, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, RDP_CORE_INPUT_PROTOCOL_VERSION_100);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, RDP_CORE_INPUT_PROTOCOL_VERSION_100);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    return status;
}

librdp_status rdp_core_input_parse_init_response(const void* data,
                                                 size_t length,
                                                 rdp_core_input_init_response* response)
{
    rdp_stream stream;
    rdp_core_input_header header;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 16)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_core_input_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.pdu_type != RDP_CORE_INPUT_PDU_SC_INIT_RESPONSE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(response, 0, sizeof(*response));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &response->selected_protocol_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &response->protocol_version_max) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (response->selected_protocol_version != RDP_CORE_INPUT_PROTOCOL_VERSION_100)
        return LIBRDP_STATUS_UNSUPPORTED;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_core_input_write_keyboard_event(rdp_buffer* buffer, uint8_t scancode, uint8_t released)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_core_input_write_header(buffer, RDP_CORE_INPUT_PDU_CS_KEYBOARD_AND_MOUSE, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer,
                                      rdp_core_input_pack_event(RDP_CORE_INPUT_EVENT_SCANCODE,
                                                                released ? RDP_CORE_INPUT_KBDFLAGS_RELEASE : 0));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, scancode);
    return status;
}

librdp_status rdp_core_input_write_mouse_event(rdp_buffer* buffer, uint16_t pointer_flags, uint16_t x, uint16_t y)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_core_input_write_header(buffer, RDP_CORE_INPUT_PDU_CS_KEYBOARD_AND_MOUSE, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, rdp_core_input_pack_event(RDP_CORE_INPUT_EVENT_MOUSE, 0));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, pointer_flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, x);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, y);
    return status;
}
