#include "channels/smartcard_redirection.h"

#include "common/stream.h"

#include <string.h>

static int rdp_smartcard_redirection_scope_valid(uint32_t scope)
{
    return scope == RDP_SMARTCARD_REDIRECTION_SCOPE_USER ||
           scope == RDP_SMARTCARD_REDIRECTION_SCOPE_TERMINAL ||
           scope == RDP_SMARTCARD_REDIRECTION_SCOPE_SYSTEM;
}

int rdp_smartcard_redirection_ioctl_valid(uint32_t io_control_code)
{
    switch (io_control_code)
    {
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ESTABLISHCONTEXT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_RELEASECONTEXT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ISVALIDCONTEXT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERGROUPSA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERGROUPSW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERSA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERSW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERGROUPA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERGROUPW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERGROUPA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERGROUPW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ADDREADERTOGROUPA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ADDREADERTOGROUPW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_REMOVEREADERFROMGROUPA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_REMOVEREADERFROMGROUPW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETSTATUSCHANGEA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETSTATUSCHANGEW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_CANCEL:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_CONNECTA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_CONNECTW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_RECONNECT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_DISCONNECT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_BEGINTRANSACTION:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ENDTRANSACTION:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_STATE:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_STATUSA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_STATUSW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_TRANSMIT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_CONTROL:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETATTRIB:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_SETATTRIB:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ACCESSSTARTEDEVENT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSBYATRA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSBYATRW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_READCACHEA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_READCACHEW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_WRITECACHEA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_WRITECACHEW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETTRANSMITCOUNT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETREADERICON:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETDEVICETYPEID:
            return 1;
        default:
            return 0;
    }
}

librdp_status rdp_smartcard_redirection_parse_device_control_request(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_device_control_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_SMARTCARD_REDIRECTION_DEVICE_CONTROL_REQUEST_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(request, 0, sizeof(*request));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &request->output_buffer_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->input_buffer_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->io_control_code) != LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 20u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_ioctl_valid(request->io_control_code) ||
        request->input_buffer_len != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    request->input_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &request->input, request->input_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_device_control_request(
    rdp_buffer* buffer,
    uint32_t output_buffer_len,
    uint32_t io_control_code,
    const void* input,
    uint32_t input_len)
{
    static const uint8_t padding[20] = {0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!input && input_len > 0) ||
        !rdp_smartcard_redirection_ioctl_valid(io_control_code))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, output_buffer_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, input_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, io_control_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, padding, sizeof(padding));
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, input, input_len);
}

librdp_status rdp_smartcard_redirection_parse_device_control_response(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_device_control_response* response)
{
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(response, 0, sizeof(*response));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &response->output_buffer_len) != LIBRDP_STATUS_OK ||
        response->output_buffer_len != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    response->output_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &response->output, response->output_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_device_control_response(
    rdp_buffer* buffer,
    const void* output,
    uint32_t output_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!output && output_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, output_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, output, output_len);
}

librdp_status rdp_smartcard_redirection_parse_establish_context_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_establish_context_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &call->scope) != LIBRDP_STATUS_OK ||
        !rdp_smartcard_redirection_scope_valid(call->scope))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_establish_context_call(
    rdp_buffer* buffer,
    uint32_t scope)
{
    if (!buffer || !rdp_smartcard_redirection_scope_valid(scope))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u32_le(buffer, scope);
}

librdp_status rdp_smartcard_redirection_parse_context(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_context* context)
{
    rdp_stream stream;

    if (!data || !context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(context, 0, sizeof(*context));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &context->length) != LIBRDP_STATUS_OK ||
        context->length > RDP_SMARTCARD_REDIRECTION_CONTEXT_MAX_LENGTH ||
        context->length != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &context->data, context->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_context(
    rdp_buffer* buffer,
    const void* data,
    uint32_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && length > 0) ||
        length > RDP_SMARTCARD_REDIRECTION_CONTEXT_MAX_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, length);
}

librdp_status rdp_smartcard_redirection_parse_long_return(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_long_return* result)
{
    rdp_stream stream;

    if (!data || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(result, 0, sizeof(*result));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &result->return_code) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_long_return(
    rdp_buffer* buffer,
    uint32_t return_code)
{
    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u32_le(buffer, return_code);
}
