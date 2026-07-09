#include "transport/multitransport.h"

#include "common/stream.h"

#include <limits.h>
#include <string.h>

static int rdp_multitransport_valid_action(uint8_t action)
{
    return action == RDP_MULTITRANSPORT_ACTION_CREATE_REQUEST ||
           action == RDP_MULTITRANSPORT_ACTION_CREATE_RESPONSE ||
           action == RDP_MULTITRANSPORT_ACTION_DATA;
}

static int rdp_multitransport_valid_subheader_type(uint8_t type)
{
    return type == RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_REQUEST ||
           type == RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_RESPONSE;
}

librdp_status rdp_multitransport_parse_header(const void* data,
                                              size_t length,
                                              rdp_multitransport_header* header)
{
    rdp_stream stream;
    uint8_t action_flags = 0;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_MULTITRANSPORT_HEADER_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &action_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->payload_length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &header->header_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->action = action_flags & 0x0fu;
    header->flags = (uint8_t)(action_flags >> 4);
    if (!rdp_multitransport_valid_action(header->action) ||
        header->flags != 0 ||
        header->header_length < RDP_MULTITRANSPORT_HEADER_LENGTH ||
        header->header_length > length ||
        (size_t)header->payload_length != length - header->header_length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header->header_length > RDP_MULTITRANSPORT_HEADER_LENGTH)
    {
        header->subheaders_len = (size_t)header->header_length - RDP_MULTITRANSPORT_HEADER_LENGTH;
        if (rdp_stream_read_bytes(&stream, &header->subheaders, header->subheaders_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    header->payload = (const uint8_t*)data + header->header_length;
    header->payload_len = header->payload_length;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multitransport_write_header(rdp_buffer* buffer,
                                              uint8_t action,
                                              const void* subheaders,
                                              size_t subheaders_len,
                                              size_t payload_len)
{
    uint8_t action_flags = 0;
    size_t header_len = RDP_MULTITRANSPORT_HEADER_LENGTH + subheaders_len;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_multitransport_valid_action(action) ||
        (!subheaders && subheaders_len > 0) ||
        header_len > UINT8_MAX ||
        payload_len > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    action_flags = action;
    status = rdp_buffer_append_u8(buffer, action_flags);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, (uint16_t)payload_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, (uint8_t)header_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, subheaders, subheaders_len);
}

librdp_status rdp_multitransport_parse_subheader(const void* data,
                                                 size_t length,
                                                 rdp_multitransport_subheader* subheader)
{
    rdp_stream stream;

    if (!data || !subheader)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(subheader, 0, sizeof(*subheader));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &subheader->length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &subheader->type) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (subheader->length < 2u ||
        subheader->length > length ||
        !rdp_multitransport_valid_subheader_type(subheader->type))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    subheader->data = (const uint8_t*)data + 2u;
    subheader->data_len = (size_t)subheader->length - 2u;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multitransport_write_subheader(rdp_buffer* buffer,
                                                 uint8_t type,
                                                 const void* data,
                                                 size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_multitransport_valid_subheader_type(type) ||
        (!data && data_len > 0) || data_len > UINT8_MAX - 2u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, (uint8_t)(data_len + 2u));
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, type);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, data_len);
}

librdp_status rdp_multitransport_write_create_request(rdp_buffer* buffer,
                                                      uint32_t request_id,
                                                      const uint8_t security_cookie[RDP_MULTITRANSPORT_COOKIE_LENGTH])
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !security_cookie)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_multitransport_write_header(buffer,
                                             RDP_MULTITRANSPORT_ACTION_CREATE_REQUEST,
                                             NULL,
                                             0,
                                             24u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, request_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, security_cookie, RDP_MULTITRANSPORT_COOKIE_LENGTH);
}

librdp_status rdp_multitransport_parse_create_request(
    const void* data,
    size_t length,
    rdp_multitransport_create_request* request)
{
    rdp_stream stream;
    const uint8_t* cookie = NULL;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_multitransport_parse_header(data, length, &request->header) != LIBRDP_STATUS_OK ||
        request->header.action != RDP_MULTITRANSPORT_ACTION_CREATE_REQUEST ||
        request->header.header_length != RDP_MULTITRANSPORT_HEADER_LENGTH ||
        request->header.payload_len != 24u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, request->header.payload, request->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &request->request_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->reserved) != LIBRDP_STATUS_OK ||
        request->reserved != 0 ||
        rdp_stream_read_bytes(&stream, &cookie, RDP_MULTITRANSPORT_COOKIE_LENGTH) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(request->security_cookie, cookie, RDP_MULTITRANSPORT_COOKIE_LENGTH);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multitransport_write_create_response(rdp_buffer* buffer, uint32_t hresult)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_multitransport_write_header(buffer,
                                             RDP_MULTITRANSPORT_ACTION_CREATE_RESPONSE,
                                             NULL,
                                             0,
                                             4u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, hresult);
}

librdp_status rdp_multitransport_parse_create_response(
    const void* data,
    size_t length,
    rdp_multitransport_create_response* response)
{
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(response, 0, sizeof(*response));
    if (rdp_multitransport_parse_header(data, length, &response->header) != LIBRDP_STATUS_OK ||
        response->header.action != RDP_MULTITRANSPORT_ACTION_CREATE_RESPONSE ||
        response->header.header_length != RDP_MULTITRANSPORT_HEADER_LENGTH ||
        response->header.payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, response->header.payload, response->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &response->hresult) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multitransport_write_data(rdp_buffer* buffer,
                                            const void* subheaders,
                                            size_t subheaders_len,
                                            const void* data,
                                            size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_multitransport_write_header(buffer,
                                             RDP_MULTITRANSPORT_ACTION_DATA,
                                             subheaders,
                                             subheaders_len,
                                             data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, data_len);
}

librdp_status rdp_multitransport_parse_data(const void* data,
                                            size_t length,
                                            rdp_multitransport_data* tunnel_data)
{
    if (!data || !tunnel_data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(tunnel_data, 0, sizeof(*tunnel_data));
    if (rdp_multitransport_parse_header(data, length, &tunnel_data->header) != LIBRDP_STATUS_OK ||
        tunnel_data->header.action != RDP_MULTITRANSPORT_ACTION_DATA)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    tunnel_data->data = tunnel_data->header.payload;
    tunnel_data->data_len = tunnel_data->header.payload_len;
    return LIBRDP_STATUS_OK;
}
