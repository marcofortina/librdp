#include "channels/usb_redirection.h"

#include "common/stream.h"

#include <limits.h>
#include <string.h>

#define RDP_USB_REDIRECTION_BASE_HEADER_LENGTH 8u
#define RDP_USB_REDIRECTION_FUNCTION_HEADER_LENGTH 12u
#define RDP_USB_REDIRECTION_URB_HEADER_LENGTH 8u

static int rdp_usb_redirection_valid_mask(uint8_t mask)
{
    return mask == RDP_USB_REDIRECTION_MASK_NONE ||
           mask == RDP_USB_REDIRECTION_MASK_PROXY ||
           mask == RDP_USB_REDIRECTION_MASK_STUB;
}

static int rdp_usb_redirection_valid_utf16_string(const uint8_t* data, uint32_t length, int required)
{
    if (length == 0)
        return !required;
    if (!data || (length & 1u) != 0 || length < 2u)
        return 0;
    return data[length - 2u] == 0 && data[length - 1u] == 0;
}

static int rdp_usb_redirection_valid_utf16_blob(const uint8_t* data, uint32_t length)
{
    if (length == 0)
        return 1;
    return data && (length & 1u) == 0;
}

static int rdp_usb_redirection_chars_to_bytes(uint32_t chars, uint32_t* bytes)
{
    if (!bytes || chars > UINT32_MAX / 2u)
        return 0;
    *bytes = chars * 2u;
    return 1;
}

static librdp_status rdp_usb_redirection_expect_header(const void* data,
                                                       size_t length,
                                                       uint32_t expected_interface_id,
                                                       uint8_t expected_mask,
                                                       uint32_t expected_function_id,
                                                       rdp_usb_redirection_header* header)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_usb_redirection_parse_header(data, length, 1, header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header->interface_id != expected_interface_id ||
        header->mask != expected_mask ||
        header->function_id != expected_function_id)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_usb_redirection_append_utf16_chars(rdp_buffer* buffer,
                                                            const uint8_t* data,
                                                            uint32_t length,
                                                            int required)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_usb_redirection_valid_utf16_string(data, length, required))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, length / 2u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, length);
}

static librdp_status rdp_usb_redirection_append_utf16_blob_chars(rdp_buffer* buffer,
                                                                 const uint8_t* data,
                                                                 uint32_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_usb_redirection_valid_utf16_blob(data, length))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, length / 2u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, length);
}

static librdp_status rdp_usb_redirection_read_counted_utf16_chars(rdp_stream* stream,
                                                                  uint32_t* byte_len,
                                                                  const uint8_t** data,
                                                                  int required)
{
    uint32_t chars = 0;

    if (!stream || !byte_len || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *byte_len = 0;
    *data = NULL;
    if (rdp_stream_read_u32_le(stream, &chars) != LIBRDP_STATUS_OK ||
        !rdp_usb_redirection_chars_to_bytes(chars, byte_len) ||
        *byte_len > rdp_stream_remaining(stream) ||
        rdp_stream_read_bytes(stream, data, *byte_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_usb_redirection_valid_utf16_string(*data, *byte_len, required))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_usb_redirection_read_counted_utf16_blob_chars(rdp_stream* stream,
                                                                       uint32_t* byte_len,
                                                                       const uint8_t** data)
{
    uint32_t chars = 0;

    if (!stream || !byte_len || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *byte_len = 0;
    *data = NULL;
    if (rdp_stream_read_u32_le(stream, &chars) != LIBRDP_STATUS_OK ||
        !rdp_usb_redirection_chars_to_bytes(chars, byte_len) ||
        *byte_len > rdp_stream_remaining(stream) ||
        rdp_stream_read_bytes(stream, data, *byte_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_usb_redirection_valid_utf16_blob(*data, *byte_len))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_usb_redirection_parse_header(const void* data,
                                               size_t length,
                                               int has_function_id,
                                               rdp_usb_redirection_header* header)
{
    rdp_stream stream;
    uint32_t packed = 0;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_USB_REDIRECTION_BASE_HEADER_LENGTH ||
        (has_function_id && length < RDP_USB_REDIRECTION_FUNCTION_HEADER_LENGTH))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &packed) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &header->message_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->interface_id = packed & RDP_USB_REDIRECTION_INTERFACE_ID_MASK;
    header->mask = (uint8_t)(packed >> 30);
    if (!rdp_usb_redirection_valid_mask(header->mask))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (has_function_id)
    {
        if (rdp_stream_read_u32_le(&stream, &header->function_id) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        header->has_function_id = 1;
    }
    header->payload = data ? ((const uint8_t*)data + stream.position) : NULL;
    header->payload_len = rdp_stream_remaining(&stream);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_usb_redirection_write_header(rdp_buffer* buffer,
                                               uint32_t interface_id,
                                               uint8_t mask,
                                               uint32_t message_id,
                                               int has_function_id,
                                               uint32_t function_id)
{
    uint32_t packed = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || interface_id > RDP_USB_REDIRECTION_INTERFACE_ID_MASK ||
        !rdp_usb_redirection_valid_mask(mask))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    packed = interface_id | ((uint32_t)mask << 30);
    status = rdp_buffer_append_u32_le(buffer, packed);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, message_id);
    if (status != LIBRDP_STATUS_OK || !has_function_id)
        return status;
    return rdp_buffer_append_u32_le(buffer, function_id);
}

librdp_status rdp_usb_redirection_parse_capability_request(
    const void* data,
    size_t length,
    rdp_usb_redirection_capability_exchange* exchange)
{
    rdp_stream stream;

    if (!data || !exchange)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(exchange, 0, sizeof(*exchange));
    if (rdp_usb_redirection_expect_header(data,
                                          length,
                                          RDP_USB_REDIRECTION_INTERFACE_CAPABILITIES,
                                          RDP_USB_REDIRECTION_MASK_NONE,
                                          RDP_USB_REDIRECTION_FN_EXCHANGE_CAPABILITY,
                                          &exchange->header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (exchange->header.payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, exchange->header.payload, exchange->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &exchange->capability_value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return exchange->capability_value == RDP_USB_REDIRECTION_CAPABILITY_VERSION_01 ?
        LIBRDP_STATUS_OK :
        LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_usb_redirection_write_capability_response(rdp_buffer* buffer,
                                                            uint32_t message_id,
                                                            uint32_t capability_value,
                                                            uint32_t result)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || capability_value != RDP_USB_REDIRECTION_CAPABILITY_VERSION_01)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_usb_redirection_write_header(buffer,
                                              RDP_USB_REDIRECTION_INTERFACE_CAPABILITIES,
                                              RDP_USB_REDIRECTION_MASK_NONE,
                                              message_id,
                                              0,
                                              0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, capability_value);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, result);
}

librdp_status rdp_usb_redirection_write_add_virtual_channel(rdp_buffer* buffer,
                                                            uint32_t message_id)
{
    return rdp_usb_redirection_write_header(buffer,
                                            RDP_USB_REDIRECTION_INTERFACE_DEVICE_SINK,
                                            RDP_USB_REDIRECTION_MASK_PROXY,
                                            message_id,
                                            1,
                                            RDP_USB_REDIRECTION_FN_ADD_VIRTUAL_CHANNEL);
}

librdp_status rdp_usb_redirection_parse_channel_created(const void* data,
                                                        size_t length,
                                                        uint32_t expected_interface_id,
                                                        rdp_usb_redirection_channel_created* created)
{
    rdp_stream stream;

    if (!data || !created)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(created, 0, sizeof(*created));
    if (rdp_usb_redirection_expect_header(data,
                                          length,
                                          expected_interface_id,
                                          RDP_USB_REDIRECTION_MASK_PROXY,
                                          RDP_USB_REDIRECTION_FN_CHANNEL_CREATED,
                                          &created->header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (created->header.payload_len != 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, created->header.payload, created->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &created->major_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &created->minor_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &created->capabilities) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (created->major_version != RDP_USB_REDIRECTION_VERSION_MAJOR ||
        created->minor_version != RDP_USB_REDIRECTION_VERSION_MINOR)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_usb_redirection_write_channel_created(rdp_buffer* buffer,
                                                        uint32_t interface_id,
                                                        uint32_t message_id,
                                                        uint32_t capabilities)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_usb_redirection_write_header(buffer,
                                              interface_id,
                                              RDP_USB_REDIRECTION_MASK_PROXY,
                                              message_id,
                                              1,
                                              RDP_USB_REDIRECTION_FN_CHANNEL_CREATED);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, RDP_USB_REDIRECTION_VERSION_MAJOR);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, RDP_USB_REDIRECTION_VERSION_MINOR);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, capabilities);
}

librdp_status rdp_usb_redirection_parse_device_capabilities(
    const void* data,
    size_t length,
    rdp_usb_redirection_device_capabilities* capabilities)
{
    rdp_stream stream;

    if (!data || !capabilities)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != RDP_USB_REDIRECTION_DEVICE_CAPABILITIES_SIZE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(capabilities, 0, sizeof(*capabilities));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &capabilities->cb_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &capabilities->usb_bus_interface_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &capabilities->usbdi_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &capabilities->supported_usb_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &capabilities->hcd_capabilities) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &capabilities->device_is_high_speed) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &capabilities->no_ack_isoch_write_jitter_buffer_size_ms) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (capabilities->cb_size != RDP_USB_REDIRECTION_DEVICE_CAPABILITIES_SIZE ||
        capabilities->usb_bus_interface_version > 2u ||
        (capabilities->usbdi_version != 0x00000500u && capabilities->usbdi_version != 0x00000600u) ||
        (capabilities->supported_usb_version != 0x00000100u &&
         capabilities->supported_usb_version != 0x00000110u &&
         capabilities->supported_usb_version != 0x00000200u) ||
        capabilities->hcd_capabilities != 0 ||
        capabilities->device_is_high_speed > 1u ||
        (capabilities->usb_bus_interface_version == 0 && capabilities->device_is_high_speed != 0))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_usb_redirection_write_device_capabilities(
    rdp_buffer* buffer,
    const rdp_usb_redirection_device_capabilities* capabilities)
{
    librdp_status status = LIBRDP_STATUS_OK;
    rdp_usb_redirection_device_capabilities parsed;
    rdp_buffer temp;

    if (!buffer || !capabilities)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&temp);
    status = rdp_buffer_append_u32_le(&temp, capabilities->cb_size);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&temp, capabilities->usb_bus_interface_version);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&temp, capabilities->usbdi_version);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&temp, capabilities->supported_usb_version);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&temp, capabilities->hcd_capabilities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&temp, capabilities->device_is_high_speed);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&temp, capabilities->no_ack_isoch_write_jitter_buffer_size_ms);
    if (status == LIBRDP_STATUS_OK &&
        (temp.length != RDP_USB_REDIRECTION_DEVICE_CAPABILITIES_SIZE ||
         rdp_usb_redirection_parse_device_capabilities(temp.data, temp.length, &parsed) != LIBRDP_STATUS_OK))
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, temp.data, temp.length);
    rdp_buffer_free(&temp);
    return status;
}

librdp_status rdp_usb_redirection_write_add_device(rdp_buffer* buffer,
                                                   uint32_t message_id,
                                                   uint32_t usb_device,
                                                   const uint8_t* device_instance_id,
                                                   uint32_t device_instance_id_len,
                                                   const uint8_t* hardware_ids,
                                                   uint32_t hardware_ids_len,
                                                   const uint8_t* compatibility_ids,
                                                   uint32_t compatibility_ids_len,
                                                   const uint8_t* container_id,
                                                   uint32_t container_id_len,
                                                   const rdp_usb_redirection_device_capabilities* capabilities)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !capabilities || usb_device > RDP_USB_REDIRECTION_INTERFACE_ID_MASK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_usb_redirection_write_header(buffer,
                                              RDP_USB_REDIRECTION_INTERFACE_DEVICE_SINK,
                                              RDP_USB_REDIRECTION_MASK_PROXY,
                                              message_id,
                                              1,
                                              RDP_USB_REDIRECTION_FN_ADD_DEVICE);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, 1u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, usb_device);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_usb_redirection_append_utf16_chars(buffer, device_instance_id, device_instance_id_len, 1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_usb_redirection_append_utf16_blob_chars(buffer, hardware_ids, hardware_ids_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_usb_redirection_append_utf16_blob_chars(buffer, compatibility_ids, compatibility_ids_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_usb_redirection_append_utf16_chars(buffer, container_id, container_id_len, 1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_usb_redirection_write_device_capabilities(buffer, capabilities);
}

librdp_status rdp_usb_redirection_parse_add_device(const void* data,
                                                   size_t length,
                                                   rdp_usb_redirection_add_device* device)
{
    rdp_stream stream;
    const uint8_t* cap_data = NULL;

    if (!data || !device)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(device, 0, sizeof(*device));
    if (rdp_usb_redirection_expect_header(data,
                                          length,
                                          RDP_USB_REDIRECTION_INTERFACE_DEVICE_SINK,
                                          RDP_USB_REDIRECTION_MASK_PROXY,
                                          RDP_USB_REDIRECTION_FN_ADD_DEVICE,
                                          &device->header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, device->header.payload, device->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &device->num_usb_device) != LIBRDP_STATUS_OK ||
        device->num_usb_device != 1u ||
        rdp_stream_read_u32_le(&stream, &device->usb_device) != LIBRDP_STATUS_OK ||
        rdp_usb_redirection_read_counted_utf16_chars(&stream,
                                                     &device->device_instance_id_len,
                                                     &device->device_instance_id,
                                                     1) != LIBRDP_STATUS_OK ||
        rdp_usb_redirection_read_counted_utf16_blob_chars(&stream,
                                                          &device->hardware_ids_len,
                                                          &device->hardware_ids) != LIBRDP_STATUS_OK ||
        rdp_usb_redirection_read_counted_utf16_blob_chars(&stream,
                                                          &device->compatibility_ids_len,
                                                          &device->compatibility_ids) != LIBRDP_STATUS_OK ||
        rdp_usb_redirection_read_counted_utf16_chars(&stream,
                                                     &device->container_id_len,
                                                     &device->container_id,
                                                     1) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream,
                              &cap_data,
                              RDP_USB_REDIRECTION_DEVICE_CAPABILITIES_SIZE) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_usb_redirection_parse_device_capabilities(cap_data,
                                                         RDP_USB_REDIRECTION_DEVICE_CAPABILITIES_SIZE,
                                                         &device->capabilities);
}

librdp_status rdp_usb_redirection_parse_register_callback(
    const void* data,
    size_t length,
    rdp_usb_redirection_register_callback* callback)
{
    rdp_stream stream;

    if (!data || !callback)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(callback, 0, sizeof(*callback));
    if (rdp_usb_redirection_parse_header(data, length, 1, &callback->header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (callback->header.mask != RDP_USB_REDIRECTION_MASK_PROXY ||
        callback->header.function_id != RDP_USB_REDIRECTION_FN_REGISTER_REQUEST_CALLBACK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, callback->header.payload, callback->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &callback->num_request_completion) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (callback->num_request_completion > 0)
    {
        if (rdp_stream_read_u32_le(&stream, &callback->request_completion) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        callback->has_request_completion = 1;
    }
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_usb_redirection_parse_cancel_request(const void* data,
                                                       size_t length,
                                                       rdp_usb_redirection_cancel_request* cancel)
{
    rdp_stream stream;

    if (!data || !cancel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(cancel, 0, sizeof(*cancel));
    if (rdp_usb_redirection_parse_header(data, length, 1, &cancel->header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (cancel->header.mask != RDP_USB_REDIRECTION_MASK_PROXY ||
        cancel->header.function_id != RDP_USB_REDIRECTION_FN_CANCEL_REQUEST ||
        cancel->header.payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, cancel->header.payload, cancel->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &cancel->request_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_usb_redirection_parse_io_control(const void* data,
                                                   size_t length,
                                                   uint32_t expected_function_id,
                                                   rdp_usb_redirection_io_control* control)
{
    rdp_stream stream;

    if (!data || !control ||
        (expected_function_id != RDP_USB_REDIRECTION_FN_IO_CONTROL &&
         expected_function_id != RDP_USB_REDIRECTION_FN_INTERNAL_IO_CONTROL))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(control, 0, sizeof(*control));
    if (rdp_usb_redirection_parse_header(data, length, 1, &control->header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (control->header.mask != RDP_USB_REDIRECTION_MASK_PROXY ||
        control->header.function_id != expected_function_id ||
        control->header.payload_len < 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, control->header.payload, control->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &control->io_control_code) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &control->input_buffer_len) != LIBRDP_STATUS_OK ||
        control->input_buffer_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &control->input_buffer, control->input_buffer_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &control->output_buffer_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &control->request_id) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_usb_redirection_parse_query_device_text(
    const void* data,
    size_t length,
    rdp_usb_redirection_query_device_text* query)
{
    rdp_stream stream;

    if (!data || !query)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(query, 0, sizeof(*query));
    if (rdp_usb_redirection_parse_header(data, length, 1, &query->header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (query->header.mask != RDP_USB_REDIRECTION_MASK_PROXY ||
        query->header.function_id != RDP_USB_REDIRECTION_FN_QUERY_DEVICE_TEXT ||
        query->header.payload_len != 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, query->header.payload, query->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &query->text_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &query->locale_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_usb_redirection_parse_urb_header(const void* data,
                                                   size_t length,
                                                   rdp_usb_redirection_urb_header* header)
{
    rdp_stream stream;
    uint32_t request = 0;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_USB_REDIRECTION_URB_HEADER_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &header->size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->function) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header->size < RDP_USB_REDIRECTION_URB_HEADER_LENGTH ||
        header->size > length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->request_id = request & 0x7fffffffu;
    header->no_ack = (uint8_t)((request >> 31) & 1u);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_usb_redirection_parse_transfer(const void* data,
                                                 size_t length,
                                                 uint32_t expected_function_id,
                                                 rdp_usb_redirection_transfer* transfer)
{
    rdp_stream stream;

    if (!data || !transfer ||
        (expected_function_id != RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST &&
         expected_function_id != RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(transfer, 0, sizeof(*transfer));
    if (rdp_usb_redirection_parse_header(data, length, 1, &transfer->header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (transfer->header.mask != RDP_USB_REDIRECTION_MASK_PROXY ||
        transfer->header.function_id != expected_function_id ||
        transfer->header.payload_len < 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, transfer->header.payload, transfer->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &transfer->cb_ts_urb) != LIBRDP_STATUS_OK ||
        transfer->cb_ts_urb > rdp_stream_remaining(&stream) ||
        transfer->cb_ts_urb < RDP_USB_REDIRECTION_URB_HEADER_LENGTH ||
        rdp_stream_read_bytes(&stream, &transfer->ts_urb, transfer->cb_ts_urb) != LIBRDP_STATUS_OK ||
        rdp_usb_redirection_parse_urb_header(transfer->ts_urb,
                                             transfer->cb_ts_urb,
                                             &transfer->urb) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &transfer->output_buffer_size) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (expected_function_id == RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST)
    {
        if (rdp_stream_remaining(&stream) > UINT32_MAX ||
            rdp_stream_remaining(&stream) != transfer->output_buffer_size ||
            rdp_stream_read_bytes(&stream,
                                  &transfer->output_buffer,
                                  transfer->output_buffer_size) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        transfer->output_buffer_len = transfer->output_buffer_size;
    }
    else if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_usb_redirection_parse_retract_device(
    const void* data,
    size_t length,
    rdp_usb_redirection_retract_device* retract)
{
    rdp_stream stream;

    if (!data || !retract)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(retract, 0, sizeof(*retract));
    if (rdp_usb_redirection_parse_header(data, length, 1, &retract->header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (retract->header.mask != RDP_USB_REDIRECTION_MASK_PROXY ||
        retract->header.function_id != RDP_USB_REDIRECTION_FN_RETRACT_DEVICE ||
        retract->header.payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, retract->header.payload, retract->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &retract->reason) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return retract->reason == RDP_USB_REDIRECTION_RETRACT_BLOCKED_BY_POLICY ?
        LIBRDP_STATUS_OK :
        LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_usb_redirection_write_query_device_text_response(rdp_buffer* buffer,
                                                                   uint32_t interface_id,
                                                                   uint32_t message_id,
                                                                   const uint8_t* description,
                                                                   uint32_t description_len,
                                                                   uint32_t hresult)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_usb_redirection_valid_utf16_string(description, description_len, 1))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_usb_redirection_write_header(buffer,
                                              interface_id,
                                              RDP_USB_REDIRECTION_MASK_STUB,
                                              message_id,
                                              0,
                                              0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, description_len / 2u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, description, description_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, hresult);
}

librdp_status rdp_usb_redirection_write_io_control_completion(
    rdp_buffer* buffer,
    uint32_t request_completion_interface_id,
    uint32_t message_id,
    const rdp_usb_redirection_io_completion* completion)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !completion ||
        (!completion->output_buffer && completion->output_buffer_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_usb_redirection_write_header(buffer,
                                              request_completion_interface_id,
                                              RDP_USB_REDIRECTION_MASK_PROXY,
                                              message_id,
                                              1,
                                              RDP_USB_REDIRECTION_FN_IOCONTROL_COMPLETION);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, completion->request_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, completion->hresult);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, completion->information);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, completion->output_buffer_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, completion->output_buffer, completion->output_buffer_len);
}

static librdp_status rdp_usb_redirection_write_urb_completion_common(
    rdp_buffer* buffer,
    uint32_t request_completion_interface_id,
    uint32_t message_id,
    uint32_t function_id,
    const rdp_usb_redirection_urb_completion* completion)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !completion ||
        (!completion->ts_urb_result && completion->cb_ts_urb_result > 0) ||
        (!completion->output_buffer && completion->output_buffer_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_usb_redirection_write_header(buffer,
                                              request_completion_interface_id,
                                              RDP_USB_REDIRECTION_MASK_PROXY,
                                              message_id,
                                              1,
                                              function_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, completion->request_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, completion->cb_ts_urb_result);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, completion->ts_urb_result, completion->cb_ts_urb_result);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, completion->hresult);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, completion->output_buffer_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (function_id == RDP_USB_REDIRECTION_FN_URB_COMPLETION_NO_DATA)
        return completion->output_buffer_len == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append(buffer, completion->output_buffer, completion->output_buffer_len);
}

librdp_status rdp_usb_redirection_write_urb_completion(
    rdp_buffer* buffer,
    uint32_t request_completion_interface_id,
    uint32_t message_id,
    const rdp_usb_redirection_urb_completion* completion)
{
    return rdp_usb_redirection_write_urb_completion_common(buffer,
                                                           request_completion_interface_id,
                                                           message_id,
                                                           RDP_USB_REDIRECTION_FN_URB_COMPLETION,
                                                           completion);
}

librdp_status rdp_usb_redirection_write_urb_completion_no_data(
    rdp_buffer* buffer,
    uint32_t request_completion_interface_id,
    uint32_t message_id,
    const rdp_usb_redirection_urb_completion* completion)
{
    return rdp_usb_redirection_write_urb_completion_common(buffer,
                                                           request_completion_interface_id,
                                                           message_id,
                                                           RDP_USB_REDIRECTION_FN_URB_COMPLETION_NO_DATA,
                                                           completion);
}
