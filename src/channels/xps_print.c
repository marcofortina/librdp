#include "channels/xps_print.h"

#include "common/stream.h"

#include <limits.h>
#include <string.h>

static int rdp_xps_print_valid_null_flag(uint8_t flag)
{
    return flag == RDP_XPS_PRINT_NULL_ABSENT || flag == RDP_XPS_PRINT_NULL_PRESENT;
}

static int rdp_xps_print_valid_property(uint32_t property_type, uint32_t value_len)
{
    if (property_type == RDP_XPS_PRINT_PROPERTY_INT32)
        return value_len == 4u;
    if (property_type == RDP_XPS_PRINT_PROPERTY_INT64)
        return value_len == 8u;
    if (property_type == RDP_XPS_PRINT_PROPERTY_INT8)
        return value_len == 1u;
    return property_type == RDP_XPS_PRINT_PROPERTY_BUFFER;
}

librdp_status rdp_xps_print_parse_header(const void* data,
                                         size_t length,
                                         uint8_t has_function_id,
                                         rdp_xps_print_header* header)
{
    rdp_stream stream;
    size_t fixed_len = has_function_id ? 12u : 8u;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < fixed_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &header->interface_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &header->message_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->has_function_id = has_function_id ? 1u : 0u;
    if (has_function_id &&
        rdp_stream_read_u32_le(&stream, &header->function_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->payload = (const uint8_t*)data + fixed_len;
    header->payload_len = length - fixed_len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_xps_print_write_header(rdp_buffer* buffer,
                                         uint32_t interface_id,
                                         uint32_t message_id,
                                         uint8_t has_function_id,
                                         uint32_t function_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, interface_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, message_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (has_function_id)
        return rdp_buffer_append_u32_le(buffer, function_id);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_xps_print_parse_interface_query(const void* data,
                                                  size_t length,
                                                  rdp_xps_print_interface_query* query)
{
    const uint8_t* guid = NULL;
    rdp_stream stream;

    if (!data || !query)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(query, 0, sizeof(*query));
    if (rdp_xps_print_parse_header(data, length, 1, &query->header) != LIBRDP_STATUS_OK ||
        query->header.function_id != RDP_XPS_PRINT_FUNC_QUERY_INTERFACE ||
        query->header.payload_len != 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, query->header.payload, query->header.payload_len);
    if (rdp_stream_read_bytes(&stream, &guid, 16u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(query->guid, guid, 16u);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_xps_print_write_interface_query_response(rdp_buffer* buffer,
                                                           uint32_t interface_id,
                                                           uint32_t message_id,
                                                           const uint32_t* new_interface_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_xps_print_write_header(buffer, interface_id, message_id, 0, 0);
    if (status != LIBRDP_STATUS_OK || !new_interface_id)
        return status;
    return rdp_buffer_append_u32_le(buffer, *new_interface_id);
}

librdp_status rdp_xps_print_parse_interface_query_response(
    const void* data,
    size_t length,
    rdp_xps_print_interface_query_response* response)
{
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(response, 0, sizeof(*response));
    if (rdp_xps_print_parse_header(data, length, 0, &response->header) != LIBRDP_STATUS_OK ||
        (response->header.payload_len != 0 && response->header.payload_len != 4u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (response->header.payload_len == 4u)
    {
        rdp_stream_init(&stream, response->header.payload, response->header.payload_len);
        if (rdp_stream_read_u32_le(&stream, &response->new_interface_id) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        response->has_new_interface_id = 1;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_xps_print_parse_release(const void* data, size_t length, rdp_xps_print_header* header)
{
    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_xps_print_parse_header(data, length, 1, header) != LIBRDP_STATUS_OK ||
        header->function_id != RDP_XPS_PRINT_FUNC_RELEASE ||
        header->payload_len != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_xps_print_parse_xml_document(const void* data,
                                               size_t length,
                                               rdp_xps_print_xml_document* document)
{
    rdp_stream stream;

    if (!data || !document)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(document, 0, sizeof(*document));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &document->size) != LIBRDP_STATUS_OK ||
        document->size > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &document->data, document->size) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_xps_print_write_xml_document(rdp_buffer* buffer, const void* data, uint32_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, length);
}

librdp_status rdp_xps_print_parse_device_capability(const void* data,
                                                    size_t length,
                                                    rdp_xps_print_device_capability* capability)
{
    rdp_stream stream;
    uint16_t data_len2 = 0;

    if (!data || !capability)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(capability, 0, sizeof(*capability));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &capability->return_value) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &capability->error_code) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &capability->data_len) != LIBRDP_STATUS_OK ||
        capability->data_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &capability->data, capability->data_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &data_len2) != LIBRDP_STATUS_OK ||
        data_len2 != capability->data_len ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_xps_print_write_device_capability(rdp_buffer* buffer,
                                                    uint32_t return_value,
                                                    uint32_t error_code,
                                                    const void* data,
                                                    uint16_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, return_value);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, error_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, data, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u16_le(buffer, data_len);
}

librdp_status rdp_xps_print_parse_printer_property(const void* data,
                                                   size_t length,
                                                   rdp_xps_print_printer_property* property)
{
    rdp_stream stream;

    if (!data || !property)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(property, 0, sizeof(*property));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &property->property_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &property->name_len) != LIBRDP_STATUS_OK ||
        property->name_len > rdp_stream_remaining(&stream) ||
        (property->name_len & 1u) != 0 ||
        rdp_stream_read_bytes(&stream, &property->name, property->name_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &property->value_len) != LIBRDP_STATUS_OK ||
        property->value_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &property->value, property->value_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0 ||
        !rdp_xps_print_valid_property(property->property_type, property->value_len))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_xps_print_write_printer_property(rdp_buffer* buffer,
                                                   uint32_t property_type,
                                                   const void* name,
                                                   uint32_t name_len,
                                                   const void* value,
                                                   uint32_t value_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!name && name_len > 0) || (!value && value_len > 0) ||
        (name_len & 1u) != 0 || !rdp_xps_print_valid_property(property_type, value_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, property_type);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, name, name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, value_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, value, value_len);
}

librdp_status rdp_xps_print_parse_u32_request(const void* data,
                                              size_t length,
                                              uint32_t function_id,
                                              rdp_xps_print_u32_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_xps_print_parse_header(data, length, 1, &request->header) != LIBRDP_STATUS_OK ||
        request->header.interface_id != RDP_XPS_PRINT_INTERFACE_DEFAULT ||
        request->header.function_id != function_id ||
        request->header.payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, request->header.payload, request->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &request->value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_xps_print_write_result(rdp_buffer* buffer,
                                         uint32_t interface_id,
                                         uint32_t message_id,
                                         uint32_t result)
{
    librdp_status status = rdp_xps_print_write_header(buffer, interface_id, message_id, 0, 0);

    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, result);
}

librdp_status rdp_xps_print_parse_result(const void* data, size_t length, rdp_xps_print_result* result)
{
    rdp_stream stream;

    if (!data || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));
    if (rdp_xps_print_parse_header(data, length, 0, &result->header) != LIBRDP_STATUS_OK ||
        result->header.payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, result->header.payload, result->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &result->result) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_xps_print_write_versions_response(rdp_buffer* buffer,
                                                    uint32_t interface_id,
                                                    uint32_t message_id,
                                                    const uint32_t* versions,
                                                    uint32_t version_count,
                                                    uint32_t result)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!versions && version_count > 0) || version_count > (UINT32_MAX / 4u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_xps_print_write_header(buffer, interface_id, message_id, 0, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, version_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (uint32_t i = 0; i < version_count; i++)
    {
        status = rdp_buffer_append_u32_le(buffer, versions[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return rdp_buffer_append_u32_le(buffer, result);
}

librdp_status rdp_xps_print_parse_versions_response(const void* data,
                                                    size_t length,
                                                    rdp_xps_print_versions_response* response)
{
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(response, 0, sizeof(*response));
    if (rdp_xps_print_parse_header(data, length, 0, &response->header) != LIBRDP_STATUS_OK ||
        response->header.payload_len < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, response->header.payload, response->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &response->version_count) != LIBRDP_STATUS_OK ||
        (size_t)response->version_count * 4u > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &response->versions, (size_t)response->version_count * 4u) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &response->result) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_xps_print_write_blob_result(rdp_buffer* buffer,
                                              uint32_t interface_id,
                                              uint32_t message_id,
                                              const void* data,
                                              uint32_t data_len,
                                              uint32_t result)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_xps_print_write_header(buffer, interface_id, message_id, 0, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, data, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, result);
}

librdp_status rdp_xps_print_parse_blob_result(const void* data,
                                              size_t length,
                                              rdp_xps_print_blob_result* result)
{
    rdp_stream stream;

    if (!data || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));
    if (rdp_xps_print_parse_header(data, length, 0, &result->header) != LIBRDP_STATUS_OK ||
        result->header.payload_len < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, result->header.payload, result->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &result->data_len) != LIBRDP_STATUS_OK ||
        result->data_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &result->data, result->data_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &result->result) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_xps_print_write_optional_blob_result(rdp_buffer* buffer,
                                                       uint32_t interface_id,
                                                       uint32_t message_id,
                                                       const void* data,
                                                       size_t data_len,
                                                       uint8_t null_flag,
                                                       uint32_t result)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_xps_print_valid_null_flag(null_flag) ||
        (null_flag == RDP_XPS_PRINT_NULL_PRESENT && (!data && data_len > 0)) ||
        (null_flag == RDP_XPS_PRINT_NULL_ABSENT && data_len != 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_xps_print_write_header(buffer, interface_id, message_id, 0, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, null_flag);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, data, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, result);
}

librdp_status rdp_xps_print_parse_optional_blob_result(
    const void* data,
    size_t length,
    rdp_xps_print_optional_blob_result* result)
{
    rdp_stream stream;

    if (!data || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));
    if (rdp_xps_print_parse_header(data, length, 0, &result->header) != LIBRDP_STATUS_OK ||
        result->header.payload_len < 5u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, result->header.payload, result->header.payload_len);
    if (rdp_stream_read_u8(&stream, &result->null_flag) != LIBRDP_STATUS_OK ||
        !rdp_xps_print_valid_null_flag(result->null_flag) ||
        rdp_stream_remaining(&stream) < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    result->data_len = rdp_stream_remaining(&stream) - 4u;
    if (result->null_flag == RDP_XPS_PRINT_NULL_ABSENT && result->data_len != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &result->data, result->data_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &result->result) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}
