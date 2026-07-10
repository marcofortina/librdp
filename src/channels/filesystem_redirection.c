#include "channels/filesystem_redirection.h"

#include "common/stream.h"

#include <string.h>

#define RDP_FILESYSTEM_REDIRECTION_REQUEST_BASE_LENGTH 56u
#define RDP_FILESYSTEM_REDIRECTION_CREATE_FIXED_PAYLOAD 32u
#define RDP_FILESYSTEM_REDIRECTION_READ_WRITE_FIXED_PAYLOAD 32u
#define RDP_FILESYSTEM_REDIRECTION_INFO_FIXED_PAYLOAD 32u
#define RDP_FILESYSTEM_REDIRECTION_LOCK_FIXED_PAYLOAD 32u
#define RDP_FILESYSTEM_REDIRECTION_SECURITY_FIXED_PAYLOAD 32u

static librdp_status rdp_filesystem_read_u64_le(rdp_stream* stream, uint64_t* value)
{
    const uint8_t* p = NULL;

    if (!stream || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_bytes(stream, &p, 8u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
             ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
             ((uint64_t)p[7] << 56);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_filesystem_append_u64_le(rdp_buffer* buffer, uint64_t value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, (uint32_t)(value & 0xffffffffu));
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, (uint32_t)((value >> 32) & 0xffffffffu));
}

static librdp_status rdp_filesystem_append_zeroes(rdp_buffer* buffer, size_t count)
{
    static const uint8_t zeroes[32] = {0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (count > 0)
    {
        size_t chunk = count > sizeof(zeroes) ? sizeof(zeroes) : count;
        status = rdp_buffer_append(buffer, zeroes, chunk);
        if (status != LIBRDP_STATUS_OK)
            return status;
        count -= chunk;
    }
    return LIBRDP_STATUS_OK;
}

static int rdp_filesystem_utf16le_null_terminated(const uint8_t* data, uint32_t length)
{
    if (!data || length < 2u || (length & 1u) != 0)
        return 0;
    return data[length - 2u] == 0 && data[length - 1u] == 0;
}

static int rdp_filesystem_major_information(uint32_t major_function)
{
    return major_function == RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION ||
           major_function == RDP_DEVICE_REDIRECTION_IRP_SET_INFORMATION ||
           major_function == RDP_DEVICE_REDIRECTION_IRP_QUERY_VOLUME_INFORMATION ||
           major_function == RDP_DEVICE_REDIRECTION_IRP_SET_VOLUME_INFORMATION;
}

static int rdp_filesystem_major_security(uint32_t major_function)
{
    return major_function == RDP_DEVICE_REDIRECTION_IRP_QUERY_SECURITY ||
           major_function == RDP_DEVICE_REDIRECTION_IRP_SET_SECURITY;
}

static librdp_status rdp_filesystem_parse_io_request(const void* data,
                                                     size_t length,
                                                     uint32_t major,
                                                     uint32_t minor,
                                                     rdp_device_redirection_io_request* request,
                                                     rdp_stream* payload)
{
    if (!data || !request || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 24u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_device_redirection_parse_io_request(data, length, request) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->major_function != major)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (major == RDP_DEVICE_REDIRECTION_IRP_DIRECTORY_CONTROL)
    {
        if (request->minor_function != minor)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    else if (request->minor_function != 0)
    {
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    rdp_stream_init(payload, request->payload, request->payload_len);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_filesystem_parse_information_request(
    const void* data,
    size_t length,
    uint32_t major,
    rdp_filesystem_redirection_information_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_filesystem_parse_io_request(data, length, major, 0, &request->io, &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->io.payload_len < RDP_FILESYSTEM_REDIRECTION_INFO_FIXED_PAYLOAD ||
        rdp_stream_read_u32_le(&stream, &request->information_class) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->length) != LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 24u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->length != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &request->buffer, request->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_filesystem_write_completion_header(rdp_buffer* buffer,
                                                            uint32_t device_id,
                                                            uint32_t completion_id,
                                                            uint32_t io_status)
{
    return rdp_device_redirection_write_io_completion(buffer, device_id, completion_id, io_status, NULL, 0);
}

static librdp_status rdp_filesystem_parse_padding_response(const void* data,
                                                           size_t length,
                                                           size_t padding_len,
                                                           rdp_device_redirection_io_completion* response)
{
    size_t i = 0;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 16u + padding_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(response, 0, sizeof(*response));
    if (rdp_device_redirection_parse_io_completion(data, length, response) != LIBRDP_STATUS_OK ||
        response->payload_len != padding_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < padding_len; i++)
    {
        if (response->payload[i] != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_filesystem_write_request_header(rdp_buffer* buffer,
                                                         uint32_t device_id,
                                                         uint32_t file_id,
                                                         uint32_t completion_id,
                                                         uint32_t major_function,
                                                         uint32_t minor_function)
{
    return rdp_device_redirection_write_io_request(buffer,
                                                   device_id,
                                                   file_id,
                                                   completion_id,
                                                   major_function,
                                                   minor_function,
                                                   NULL,
                                                   0);
}

librdp_status rdp_filesystem_redirection_parse_create_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_create_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_filesystem_parse_io_request(data,
                                        length,
                                        RDP_DEVICE_REDIRECTION_IRP_CREATE,
                                        0,
                                        &request->io,
                                        &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->io.payload_len < RDP_FILESYSTEM_REDIRECTION_CREATE_FIXED_PAYLOAD ||
        rdp_stream_read_u32_le(&stream, &request->desired_access) != LIBRDP_STATUS_OK ||
        rdp_filesystem_read_u64_le(&stream, &request->allocation_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->file_attributes) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->shared_access) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->create_disposition) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->create_options) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->path_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->path_len != rdp_stream_remaining(&stream) ||
        !rdp_filesystem_utf16le_null_terminated(stream.data + stream.position, request->path_len))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &request->path, request->path_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_filesystem_redirection_parse_close_request(
    const void* data,
    size_t length,
    rdp_device_redirection_io_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_filesystem_parse_io_request(data,
                                        length,
                                        RDP_DEVICE_REDIRECTION_IRP_CLOSE,
                                        0,
                                        request,
                                        &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->payload_len != 32u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_stream_skip(&stream, 32u);
}

librdp_status rdp_filesystem_redirection_parse_read_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_read_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_filesystem_parse_io_request(data,
                                        length,
                                        RDP_DEVICE_REDIRECTION_IRP_READ,
                                        0,
                                        &request->io,
                                        &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->io.payload_len != RDP_FILESYSTEM_REDIRECTION_READ_WRITE_FIXED_PAYLOAD ||
        rdp_stream_read_u32_le(&stream, &request->length) != LIBRDP_STATUS_OK ||
        rdp_filesystem_read_u64_le(&stream, &request->offset) != LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 20u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_filesystem_redirection_parse_write_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_write_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_filesystem_parse_io_request(data,
                                        length,
                                        RDP_DEVICE_REDIRECTION_IRP_WRITE,
                                        0,
                                        &request->io,
                                        &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->io.payload_len < RDP_FILESYSTEM_REDIRECTION_READ_WRITE_FIXED_PAYLOAD ||
        rdp_stream_read_u32_le(&stream, &request->length) != LIBRDP_STATUS_OK ||
        rdp_filesystem_read_u64_le(&stream, &request->offset) != LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 20u) != LIBRDP_STATUS_OK ||
        request->length != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &request->data, request->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_filesystem_redirection_parse_control_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_control_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_filesystem_parse_io_request(data,
                                        length,
                                        RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL,
                                        0,
                                        &request->io,
                                        &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->io.payload_len < RDP_FILESYSTEM_REDIRECTION_REQUEST_BASE_LENGTH - 24u ||
        rdp_stream_read_u32_le(&stream, &request->output_buffer_length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->input_buffer_length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->io_control_code) != LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 20u) != LIBRDP_STATUS_OK ||
        request->input_buffer_length != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &request->input_buffer, request->input_buffer_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_filesystem_redirection_parse_query_volume_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_information_request* request)
{
    return rdp_filesystem_parse_information_request(data,
                                                    length,
                                                    RDP_DEVICE_REDIRECTION_IRP_QUERY_VOLUME_INFORMATION,
                                                    request);
}

librdp_status rdp_filesystem_redirection_parse_set_volume_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_information_request* request)
{
    return rdp_filesystem_parse_information_request(data,
                                                    length,
                                                    RDP_DEVICE_REDIRECTION_IRP_SET_VOLUME_INFORMATION,
                                                    request);
}

librdp_status rdp_filesystem_redirection_parse_query_information_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_information_request* request)
{
    return rdp_filesystem_parse_information_request(data,
                                                    length,
                                                    RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION,
                                                    request);
}

librdp_status rdp_filesystem_redirection_parse_set_information_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_information_request* request)
{
    return rdp_filesystem_parse_information_request(data,
                                                    length,
                                                    RDP_DEVICE_REDIRECTION_IRP_SET_INFORMATION,
                                                    request);
}

librdp_status rdp_filesystem_redirection_parse_query_directory_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_query_directory_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_filesystem_parse_io_request(data,
                                        length,
                                        RDP_DEVICE_REDIRECTION_IRP_DIRECTORY_CONTROL,
                                        RDP_FILESYSTEM_REDIRECTION_MINOR_QUERY_DIRECTORY,
                                        &request->io,
                                        &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->io.payload_len < RDP_FILESYSTEM_REDIRECTION_REQUEST_BASE_LENGTH - 24u ||
        rdp_stream_read_u32_le(&stream, &request->information_class) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &request->initial_query) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->path_len) != LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 23u) != LIBRDP_STATUS_OK ||
        request->path_len != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->path_len != 0 &&
        !rdp_filesystem_utf16le_null_terminated(stream.data + stream.position, request->path_len))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &request->path, request->path_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_filesystem_redirection_parse_notify_change_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_notify_change_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_filesystem_parse_io_request(data,
                                        length,
                                        RDP_DEVICE_REDIRECTION_IRP_DIRECTORY_CONTROL,
                                        RDP_FILESYSTEM_REDIRECTION_MINOR_NOTIFY_CHANGE_DIRECTORY,
                                        &request->io,
                                        &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->io.payload_len != RDP_FILESYSTEM_REDIRECTION_REQUEST_BASE_LENGTH - 24u ||
        rdp_stream_read_u8(&stream, &request->watch_tree) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->completion_filter) != LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 27u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_filesystem_redirection_parse_lock_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_lock_request* request)
{
    rdp_stream stream;
    uint32_t i = 0;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_filesystem_parse_io_request(data,
                                        length,
                                        RDP_DEVICE_REDIRECTION_IRP_LOCK_CONTROL,
                                        0,
                                        &request->io,
                                        &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->io.payload_len < RDP_FILESYSTEM_REDIRECTION_LOCK_FIXED_PAYLOAD ||
        rdp_stream_read_u32_le(&stream, &request->operation) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->lock_count) != LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 20u) != LIBRDP_STATUS_OK ||
        request->lock_count > RDP_FILESYSTEM_REDIRECTION_MAX_LOCKS ||
        rdp_stream_remaining(&stream) != (size_t)request->lock_count * 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->operation != RDP_FILESYSTEM_REDIRECTION_LOWIO_SHAREDLOCK &&
        request->operation != RDP_FILESYSTEM_REDIRECTION_LOWIO_EXCLUSIVELOCK &&
        request->operation != RDP_FILESYSTEM_REDIRECTION_LOWIO_UNLOCK &&
        request->operation != RDP_FILESYSTEM_REDIRECTION_LOWIO_UNLOCK_MULTIPLE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < request->lock_count; i++)
    {
        if (rdp_filesystem_read_u64_le(&stream, &request->locks[i].length) != LIBRDP_STATUS_OK ||
            rdp_filesystem_read_u64_le(&stream, &request->locks[i].offset) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_filesystem_parse_security_request(
    const void* data,
    size_t length,
    uint32_t major,
    rdp_filesystem_redirection_security_request* request)
{
    rdp_stream stream;

    if (!data || !request || !rdp_filesystem_major_security(major))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_filesystem_parse_io_request(data, length, major, 0, &request->io, &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->io.payload_len < RDP_FILESYSTEM_REDIRECTION_SECURITY_FIXED_PAYLOAD)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (major == RDP_DEVICE_REDIRECTION_IRP_QUERY_SECURITY)
    {
        if (rdp_stream_read_u32_le(&stream, &request->length) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &request->security_information) != LIBRDP_STATUS_OK ||
            rdp_stream_skip(&stream, 24u) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_stream_remaining(&stream) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        return LIBRDP_STATUS_OK;
    }
    if (rdp_stream_read_u32_le(&stream, &request->security_information) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->length) != LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 24u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->length != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &request->buffer, request->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_filesystem_redirection_parse_query_security_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_security_request* request)
{
    return rdp_filesystem_parse_security_request(data,
                                                 length,
                                                 RDP_DEVICE_REDIRECTION_IRP_QUERY_SECURITY,
                                                 request);
}

librdp_status rdp_filesystem_redirection_parse_set_security_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_security_request* request)
{
    return rdp_filesystem_parse_security_request(data,
                                                 length,
                                                 RDP_DEVICE_REDIRECTION_IRP_SET_SECURITY,
                                                 request);
}

librdp_status rdp_filesystem_redirection_write_create_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint32_t desired_access,
    uint64_t allocation_size,
    uint32_t file_attributes,
    uint32_t shared_access,
    uint32_t create_disposition,
    uint32_t create_options,
    const void* path,
    uint32_t path_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    const uint8_t* path_bytes = (const uint8_t*)path;

    if (!buffer || !rdp_filesystem_utf16le_null_terminated(path_bytes, path_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_write_request_header(buffer,
                                                 device_id,
                                                 file_id,
                                                 completion_id,
                                                 RDP_DEVICE_REDIRECTION_IRP_CREATE,
                                                 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, desired_access);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_filesystem_append_u64_le(buffer, allocation_size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, file_attributes);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, shared_access);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, create_disposition);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, create_options);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, path_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, path_bytes, path_len);
}

librdp_status rdp_filesystem_redirection_write_close_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_filesystem_write_request_header(buffer,
                                                 device_id,
                                                 file_id,
                                                 completion_id,
                                                 RDP_DEVICE_REDIRECTION_IRP_CLOSE,
                                                 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_filesystem_append_zeroes(buffer, 32u);
}

librdp_status rdp_filesystem_redirection_write_read_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint32_t length,
    uint64_t offset)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_filesystem_write_request_header(buffer,
                                                 device_id,
                                                 file_id,
                                                 completion_id,
                                                 RDP_DEVICE_REDIRECTION_IRP_READ,
                                                 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_filesystem_append_u64_le(buffer, offset);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_filesystem_append_zeroes(buffer, 20u);
}

librdp_status rdp_filesystem_redirection_write_write_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint64_t offset,
    const void* data,
    uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_write_request_header(buffer,
                                                 device_id,
                                                 file_id,
                                                 completion_id,
                                                 RDP_DEVICE_REDIRECTION_IRP_WRITE,
                                                 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_filesystem_append_u64_le(buffer, offset);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_filesystem_append_zeroes(buffer, 20u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, data_len);
}

librdp_status rdp_filesystem_redirection_write_control_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint32_t output_buffer_length,
    uint32_t io_control_code,
    const void* input,
    uint32_t input_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!input && input_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_write_request_header(buffer,
                                                 device_id,
                                                 file_id,
                                                 completion_id,
                                                 RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL,
                                                 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, output_buffer_length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, input_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, io_control_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_filesystem_append_zeroes(buffer, 20u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, input, input_len);
}

librdp_status rdp_filesystem_redirection_write_information_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint32_t major_function,
    uint32_t information_class,
    const void* data,
    uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0) || !rdp_filesystem_major_information(major_function))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_write_request_header(buffer, device_id, file_id, completion_id, major_function, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, information_class);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_filesystem_append_zeroes(buffer, 24u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, data_len);
}

librdp_status rdp_filesystem_redirection_write_query_directory_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint32_t information_class,
    uint8_t initial_query,
    const void* path,
    uint32_t path_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    const uint8_t* path_bytes = (const uint8_t*)path;

    if (!buffer || initial_query > 1u ||
        (path_len > 0 && !rdp_filesystem_utf16le_null_terminated(path_bytes, path_len)))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_write_request_header(buffer,
                                                 device_id,
                                                 file_id,
                                                 completion_id,
                                                 RDP_DEVICE_REDIRECTION_IRP_DIRECTORY_CONTROL,
                                                 RDP_FILESYSTEM_REDIRECTION_MINOR_QUERY_DIRECTORY);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, information_class);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, initial_query);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, path_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_filesystem_append_zeroes(buffer, 23u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, path_bytes, path_len);
}

librdp_status rdp_filesystem_redirection_write_notify_change_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint8_t watch_tree,
    uint32_t completion_filter)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || watch_tree > 1u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_write_request_header(buffer,
                                                 device_id,
                                                 file_id,
                                                 completion_id,
                                                 RDP_DEVICE_REDIRECTION_IRP_DIRECTORY_CONTROL,
                                                 RDP_FILESYSTEM_REDIRECTION_MINOR_NOTIFY_CHANGE_DIRECTORY);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, watch_tree);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, completion_filter);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_filesystem_append_zeroes(buffer, 27u);
}

librdp_status rdp_filesystem_redirection_write_lock_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint32_t operation,
    uint32_t flags,
    const rdp_filesystem_redirection_lock_info* locks,
    uint32_t lock_count)
{
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (lock_count > 0 && !locks) || lock_count > RDP_FILESYSTEM_REDIRECTION_MAX_LOCKS ||
        (operation != RDP_FILESYSTEM_REDIRECTION_LOWIO_SHAREDLOCK &&
         operation != RDP_FILESYSTEM_REDIRECTION_LOWIO_EXCLUSIVELOCK &&
         operation != RDP_FILESYSTEM_REDIRECTION_LOWIO_UNLOCK &&
         operation != RDP_FILESYSTEM_REDIRECTION_LOWIO_UNLOCK_MULTIPLE))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_write_request_header(buffer,
                                                 device_id,
                                                 file_id,
                                                 completion_id,
                                                 RDP_DEVICE_REDIRECTION_IRP_LOCK_CONTROL,
                                                 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, operation);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, flags);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, lock_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_filesystem_append_zeroes(buffer, 20u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < lock_count; i++)
    {
        status = rdp_filesystem_append_u64_le(buffer, locks[i].length);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_filesystem_append_u64_le(buffer, locks[i].offset);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_filesystem_redirection_write_security_request(rdp_buffer* buffer,
                                                                uint32_t device_id,
                                                                uint32_t file_id,
                                                                uint32_t completion_id,
                                                                uint32_t major_function,
                                                                uint32_t security_information,
                                                                const void* data,
                                                                uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_filesystem_major_security(major_function))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (major_function == RDP_DEVICE_REDIRECTION_IRP_QUERY_SECURITY && data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (major_function == RDP_DEVICE_REDIRECTION_IRP_SET_SECURITY && !data && data_len > 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_write_request_header(buffer,
                                                 device_id,
                                                 file_id,
                                                 completion_id,
                                                 major_function,
                                                 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (major_function == RDP_DEVICE_REDIRECTION_IRP_QUERY_SECURITY)
    {
        status = rdp_buffer_append_u32_le(buffer, data_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append_u32_le(buffer, security_information);
    }
    else
    {
        status = rdp_buffer_append_u32_le(buffer, security_information);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append_u32_le(buffer, data_len);
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_filesystem_append_zeroes(buffer, 24u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (major_function == RDP_DEVICE_REDIRECTION_IRP_SET_SECURITY)
        return rdp_buffer_append(buffer, data, data_len);
    return LIBRDP_STATUS_OK;
}

int rdp_filesystem_redirection_fsctl_supported(uint32_t code)
{
    return code == RDP_FILESYSTEM_REDIRECTION_FSCTL_GET_COMPRESSION ||
           code == RDP_FILESYSTEM_REDIRECTION_FSCTL_SET_COMPRESSION ||
           code == RDP_FILESYSTEM_REDIRECTION_FSCTL_SET_SPARSE ||
           code == RDP_FILESYSTEM_REDIRECTION_FSCTL_SET_ZERO_DATA ||
           code == RDP_FILESYSTEM_REDIRECTION_FSCTL_QUERY_ALLOCATED_RANGES;
}

librdp_status rdp_filesystem_redirection_write_create_response(rdp_buffer* buffer,
                                                               uint32_t device_id,
                                                               uint32_t completion_id,
                                                               uint32_t io_status,
                                                               uint32_t file_id,
                                                               uint8_t information)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_write_completion_header(buffer, device_id, completion_id, io_status);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, file_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, information);
}

librdp_status rdp_filesystem_redirection_parse_create_response(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_create_response* response)
{
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 21u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(response, 0, sizeof(*response));
    if (rdp_device_redirection_parse_io_completion(data, length, &response->io) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, response->io.payload, response->io.payload_len);
    if (response->io.payload_len != 5u ||
        rdp_stream_read_u32_le(&stream, &response->file_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &response->information) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_filesystem_redirection_write_close_response(rdp_buffer* buffer,
                                                              uint32_t device_id,
                                                              uint32_t completion_id,
                                                              uint32_t io_status)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_write_completion_header(buffer, device_id, completion_id, io_status);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, 0);
}

librdp_status rdp_filesystem_redirection_parse_close_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response)
{
    return rdp_filesystem_parse_padding_response(data, length, 4u, response);
}

librdp_status rdp_filesystem_redirection_write_read_response(rdp_buffer* buffer,
                                                             uint32_t device_id,
                                                             uint32_t completion_id,
                                                             uint32_t io_status,
                                                             const void* data,
                                                             uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_write_completion_header(buffer, device_id, completion_id, io_status);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, data_len);
}

librdp_status rdp_filesystem_redirection_write_write_response(rdp_buffer* buffer,
                                                              uint32_t device_id,
                                                              uint32_t completion_id,
                                                              uint32_t io_status,
                                                              uint32_t written)
{
    return rdp_filesystem_redirection_write_length_response(buffer,
                                                            device_id,
                                                            completion_id,
                                                            io_status,
                                                            written);
}

librdp_status rdp_filesystem_redirection_write_buffer_response(rdp_buffer* buffer,
                                                               uint32_t device_id,
                                                               uint32_t completion_id,
                                                               uint32_t io_status,
                                                               const void* data,
                                                               uint32_t data_len)
{
    return rdp_filesystem_redirection_write_read_response(buffer,
                                                          device_id,
                                                          completion_id,
                                                          io_status,
                                                          data,
                                                          data_len);
}

librdp_status rdp_filesystem_redirection_write_length_response(rdp_buffer* buffer,
                                                               uint32_t device_id,
                                                               uint32_t completion_id,
                                                               uint32_t io_status,
                                                               uint32_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_write_completion_header(buffer, device_id, completion_id, io_status);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, length);
}

librdp_status rdp_filesystem_redirection_parse_length_response(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_length_response* response)
{
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(response, 0, sizeof(*response));
    if (rdp_device_redirection_parse_io_completion(data, length, &response->io) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, response->io.payload, response->io.payload_len);
    if (response->io.payload_len < 4u || rdp_stream_read_u32_le(&stream, &response->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) != 0 && response->length != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    response->buffer_len = rdp_stream_remaining(&stream);
    if (response->buffer_len > 0 &&
        rdp_stream_read_bytes(&stream, &response->buffer, response->buffer_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_filesystem_redirection_write_lock_response(rdp_buffer* buffer,
                                                             uint32_t device_id,
                                                             uint32_t completion_id,
                                                             uint32_t io_status)
{
    static const uint8_t padding[5] = {0, 0, 0, 0, 0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_write_completion_header(buffer, device_id, completion_id, io_status);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, padding, sizeof(padding));
}

librdp_status rdp_filesystem_redirection_parse_lock_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response)
{
    return rdp_filesystem_parse_padding_response(data, length, 5u, response);
}
