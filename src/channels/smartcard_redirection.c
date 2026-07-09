#include "channels/smartcard_redirection.h"

#include "common/stream.h"

#include <string.h>

static int rdp_smartcard_redirection_scope_valid(uint32_t scope)
{
    return scope == RDP_SMARTCARD_REDIRECTION_SCOPE_USER ||
           scope == RDP_SMARTCARD_REDIRECTION_SCOPE_TERMINAL ||
           scope == RDP_SMARTCARD_REDIRECTION_SCOPE_SYSTEM;
}

int rdp_smartcard_redirection_share_mode_valid(uint32_t share_mode)
{
    return share_mode == RDP_SMARTCARD_REDIRECTION_SHARE_EXCLUSIVE ||
           share_mode == RDP_SMARTCARD_REDIRECTION_SHARE_SHARED ||
           share_mode == RDP_SMARTCARD_REDIRECTION_SHARE_DIRECT;
}

int rdp_smartcard_redirection_protocol_mask_valid(uint32_t protocols)
{
    uint32_t base = protocols & ~RDP_SMARTCARD_REDIRECTION_PROTOCOL_DEFAULT;

    return base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED ||
           base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0 ||
           base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1 ||
           base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_TX ||
           base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_RAW;
}

int rdp_smartcard_redirection_bool_valid(uint32_t value)
{
    return value <= 1u;
}

int rdp_smartcard_redirection_disposition_valid(uint32_t disposition)
{
    return disposition <= RDP_SMARTCARD_REDIRECTION_EJECT_CARD;
}

int rdp_smartcard_redirection_initialization_valid(uint32_t initialization)
{
    return initialization <= RDP_SMARTCARD_REDIRECTION_UNPOWER_CARD;
}

static librdp_status rdp_smartcard_redirection_read_context(
    rdp_stream* stream,
    rdp_smartcard_redirection_context* context)
{
    if (!stream || !context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(context, 0, sizeof(*context));
    if (rdp_stream_read_u32_le(stream, &context->length) != LIBRDP_STATUS_OK ||
        context->length > RDP_SMARTCARD_REDIRECTION_CONTEXT_MAX_LENGTH ||
        context->length > rdp_stream_remaining(stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(stream, &context->data, context->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_smartcard_redirection_read_handle(
    rdp_stream* stream,
    rdp_smartcard_redirection_handle* handle)
{
    if (!stream || !handle)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(handle, 0, sizeof(*handle));
    if (rdp_smartcard_redirection_read_context(stream, &handle->context) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &handle->length) != LIBRDP_STATUS_OK ||
        handle->length > RDP_SMARTCARD_REDIRECTION_CONTEXT_MAX_LENGTH ||
        handle->length > rdp_stream_remaining(stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(stream, &handle->data, handle->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_smartcard_redirection_write_opaque(
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
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_context(&stream, context) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_context(
    rdp_buffer* buffer,
    const void* data,
    uint32_t length)
{
    return rdp_smartcard_redirection_write_opaque(buffer, data, length);
}

librdp_status rdp_smartcard_redirection_parse_handle(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_handle* handle)
{
    rdp_stream stream;

    if (!data || !handle)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_handle(&stream, handle) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_handle(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_smartcard_redirection_write_opaque(buffer, context, context_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_smartcard_redirection_write_opaque(buffer, handle, handle_len);
}

librdp_status rdp_smartcard_redirection_parse_scard_io_request(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_scard_io_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(request, 0, sizeof(*request));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &request->protocol) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->extra_bytes_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_protocol_mask_valid(request->protocol) ||
        request->extra_bytes_len > RDP_SMARTCARD_REDIRECTION_IO_REQUEST_MAX_EXTRA ||
        request->extra_bytes_len != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &request->extra_bytes, request->extra_bytes_len) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_scard_io_request(
    rdp_buffer* buffer,
    uint32_t protocol,
    const void* extra_bytes,
    uint32_t extra_bytes_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!extra_bytes && extra_bytes_len > 0) ||
        !rdp_smartcard_redirection_protocol_mask_valid(protocol) ||
        extra_bytes_len > RDP_SMARTCARD_REDIRECTION_IO_REQUEST_MAX_EXTRA)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, protocol);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, extra_bytes_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, extra_bytes, extra_bytes_len);
}

librdp_status rdp_smartcard_redirection_parse_connect_common(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_connect_common* common)
{
    rdp_stream stream;

    if (!data || !common)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(common, 0, sizeof(*common));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_context(&stream, &common->context) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &common->share_mode) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &common->preferred_protocols) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_share_mode_valid(common->share_mode) ||
        !rdp_smartcard_redirection_protocol_mask_valid(common->preferred_protocols))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_connect_common(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    uint32_t share_mode,
    uint32_t preferred_protocols)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_smartcard_redirection_share_mode_valid(share_mode) ||
        !rdp_smartcard_redirection_protocol_mask_valid(preferred_protocols))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_opaque(buffer, context, context_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, share_mode);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, preferred_protocols);
}

librdp_status rdp_smartcard_redirection_parse_reconnect_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_reconnect_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_handle(&stream, &call->handle) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->share_mode) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->preferred_protocols) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->initialization) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_share_mode_valid(call->share_mode) ||
        !rdp_smartcard_redirection_protocol_mask_valid(call->preferred_protocols) ||
        !rdp_smartcard_redirection_initialization_valid(call->initialization))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_reconnect_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t share_mode,
    uint32_t preferred_protocols,
    uint32_t initialization)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_smartcard_redirection_share_mode_valid(share_mode) ||
        !rdp_smartcard_redirection_protocol_mask_valid(preferred_protocols) ||
        !rdp_smartcard_redirection_initialization_valid(initialization))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_handle(buffer, context, context_len, handle, handle_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, share_mode);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, preferred_protocols);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, initialization);
}

librdp_status rdp_smartcard_redirection_parse_handle_disposition_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_handle_disposition_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_handle(&stream, &call->handle) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->disposition) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_disposition_valid(call->disposition))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_handle_disposition_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t disposition)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_smartcard_redirection_disposition_valid(disposition))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_handle(buffer, context, context_len, handle, handle_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, disposition);
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

librdp_status rdp_smartcard_redirection_parse_count_return(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_count_return* result)
{
    rdp_stream stream;

    if (!data || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(result, 0, sizeof(*result));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &result->return_code) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &result->value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_count_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    uint32_t value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, return_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, value);
}

librdp_status rdp_smartcard_redirection_parse_buffer_return(
    const void* data,
    size_t length,
    uint32_t max_data_len,
    rdp_smartcard_redirection_buffer_return* result)
{
    rdp_stream stream;

    if (!data || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(result, 0, sizeof(*result));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &result->return_code) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &result->data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (result->data_len > max_data_len || result->data_len != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &result->data, result->data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_buffer_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    const void* data,
    uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0) ||
        data_len > RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, return_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, data_len);
}
