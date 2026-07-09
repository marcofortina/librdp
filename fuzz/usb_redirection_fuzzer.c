#include "channels/usb_redirection.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_usb_redirection_header header;
    rdp_usb_redirection_capability_exchange exchange;
    rdp_usb_redirection_channel_created created;
    rdp_usb_redirection_device_capabilities capabilities;
    rdp_usb_redirection_add_device device;
    rdp_usb_redirection_register_callback callback;
    rdp_usb_redirection_cancel_request cancel;
    rdp_usb_redirection_io_control control;
    rdp_usb_redirection_query_device_text query;
    rdp_usb_redirection_urb_header urb;
    rdp_usb_redirection_transfer transfer;
    rdp_usb_redirection_retract_device retract;
    rdp_usb_redirection_io_completion io_completion;
    rdp_usb_redirection_urb_completion urb_completion;
    rdp_buffer buffer;
    uint32_t bounded = size < 32u ? (uint32_t)size : 32u;
    const uint8_t text[] = {'D', 0, 0, 0};
    const uint8_t instance[] = {'U', 0, 'S', 0, 'B', 0, 0, 0};
    const uint8_t compat[] = {'U', 0, 'S', 0, 'B', 0, 0, 0, 0, 0};
    const uint8_t container[] = {'{', 0, '0', 0, '}', 0, 0, 0};

    (void)rdp_usb_redirection_parse_header(data, size, 0, &header);
    (void)rdp_usb_redirection_parse_header(data, size, 1, &header);
    (void)rdp_usb_redirection_parse_capability_request(data, size, &exchange);
    (void)rdp_usb_redirection_parse_channel_created(data,
                                                    size,
                                                    RDP_USB_REDIRECTION_INTERFACE_CHANNEL_NOTIFY_CLIENT,
                                                    &created);
    (void)rdp_usb_redirection_parse_channel_created(data,
                                                    size,
                                                    RDP_USB_REDIRECTION_INTERFACE_CHANNEL_NOTIFY_SERVER,
                                                    &created);
    (void)rdp_usb_redirection_parse_device_capabilities(data, size, &capabilities);
    (void)rdp_usb_redirection_parse_add_device(data, size, &device);
    (void)rdp_usb_redirection_parse_register_callback(data, size, &callback);
    (void)rdp_usb_redirection_parse_cancel_request(data, size, &cancel);
    (void)rdp_usb_redirection_parse_io_control(data, size, RDP_USB_REDIRECTION_FN_IO_CONTROL, &control);
    (void)rdp_usb_redirection_parse_io_control(data, size, RDP_USB_REDIRECTION_FN_INTERNAL_IO_CONTROL, &control);
    (void)rdp_usb_redirection_parse_query_device_text(data, size, &query);
    (void)rdp_usb_redirection_parse_urb_header(data, size, &urb);
    (void)rdp_usb_redirection_parse_transfer(data, size, RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST, &transfer);
    (void)rdp_usb_redirection_parse_transfer(data, size, RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST, &transfer);
    (void)rdp_usb_redirection_parse_retract_device(data, size, &retract);
    (void)rdp_usb_redirection_parse_io_control_completion(data, size, &io_completion);
    (void)rdp_usb_redirection_parse_urb_completion(data,
                                                   size,
                                                   RDP_USB_REDIRECTION_FN_URB_COMPLETION,
                                                   &urb_completion);
    (void)rdp_usb_redirection_parse_urb_completion(data,
                                                   size,
                                                   RDP_USB_REDIRECTION_FN_URB_COMPLETION_NO_DATA,
                                                   &urb_completion);

    rdp_buffer_init(&buffer);
    (void)rdp_usb_redirection_write_capability_request(&buffer,
                                                       1,
                                                       RDP_USB_REDIRECTION_CAPABILITY_VERSION_01);
    buffer.length = 0;
    (void)rdp_usb_redirection_write_capability_response(&buffer, 1, RDP_USB_REDIRECTION_CAPABILITY_VERSION_01, 0);
    buffer.length = 0;
    (void)rdp_usb_redirection_write_add_virtual_channel(&buffer, 2);
    buffer.length = 0;
    (void)rdp_usb_redirection_write_channel_created(&buffer,
                                                    RDP_USB_REDIRECTION_INTERFACE_CHANNEL_NOTIFY_SERVER,
                                                    3,
                                                    0);
    buffer.length = 0;
    capabilities.cb_size = RDP_USB_REDIRECTION_DEVICE_CAPABILITIES_SIZE;
    capabilities.usb_bus_interface_version = 2;
    capabilities.usbdi_version = 0x00000600u;
    capabilities.supported_usb_version = 0x00000200u;
    capabilities.hcd_capabilities = 0;
    capabilities.device_is_high_speed = 1;
    capabilities.no_ack_isoch_write_jitter_buffer_size_ms = 0;
    (void)rdp_usb_redirection_write_add_device(&buffer,
                                               4,
                                               5,
                                               instance,
                                               (uint32_t)sizeof(instance),
                                               NULL,
                                               0,
                                               compat,
                                               (uint32_t)sizeof(compat),
                                               container,
                                               (uint32_t)sizeof(container),
                                               &capabilities);
    buffer.length = 0;
    (void)rdp_usb_redirection_write_register_callback(&buffer, 7, 8, 9, size > 0 ? data[0] & 1 : 0);
    buffer.length = 0;
    (void)rdp_usb_redirection_write_cancel_request(&buffer, 7, 9, (uint32_t)size);
    buffer.length = 0;
    (void)rdp_usb_redirection_write_io_control(&buffer,
                                               7,
                                               10,
                                               RDP_USB_REDIRECTION_FN_IO_CONTROL,
                                               0x220003u,
                                               data,
                                               bounded,
                                               bounded,
                                               (uint32_t)size);
    buffer.length = 0;
    (void)rdp_usb_redirection_write_io_control(&buffer,
                                               7,
                                               10,
                                               RDP_USB_REDIRECTION_FN_INTERNAL_IO_CONTROL,
                                               0x220004u,
                                               data,
                                               bounded,
                                               bounded,
                                               (uint32_t)size);
    buffer.length = 0;
    (void)rdp_usb_redirection_write_query_device_text(&buffer, 7, 11, 1, 0x409);
    buffer.length = 0;
    (void)rdp_usb_redirection_write_urb_header(&buffer, 8, 0x0008u, (uint32_t)size & 0x7fffffffu, 0);
    buffer.length = 0;
    (void)rdp_usb_redirection_write_transfer_in_request(&buffer,
                                                        7,
                                                        12,
                                                        0x0008u,
                                                        (uint32_t)size & 0x7fffffffu,
                                                        0,
                                                        bounded);
    buffer.length = 0;
    (void)rdp_usb_redirection_write_transfer_out_request(&buffer,
                                                         7,
                                                         13,
                                                         0x0009u,
                                                         (uint32_t)size & 0x7fffffffu,
                                                         0,
                                                         data,
                                                         bounded);
    buffer.length = 0;
    (void)rdp_usb_redirection_write_retract_device(&buffer,
                                                   7,
                                                   14,
                                                   RDP_USB_REDIRECTION_RETRACT_BLOCKED_BY_POLICY);
    buffer.length = 0;
    (void)rdp_usb_redirection_write_query_device_text_response(&buffer,
                                                               5,
                                                               6,
                                                               text,
                                                               (uint32_t)sizeof(text),
                                                               0);
    buffer.length = 0;
    io_completion.request_id = 7;
    io_completion.hresult = 0;
    io_completion.information = bounded;
    io_completion.output_buffer = data;
    io_completion.output_buffer_len = io_completion.information;
    (void)rdp_usb_redirection_write_io_control_completion(&buffer, 9, 10, &io_completion);
    (void)rdp_usb_redirection_parse_io_control_completion(buffer.data, buffer.length, &io_completion);
    buffer.length = 0;
    urb_completion.request_id = 11;
    urb_completion.ts_urb_result = data;
    urb_completion.cb_ts_urb_result = bounded;
    urb_completion.hresult = 0;
    urb_completion.output_buffer = data;
    urb_completion.output_buffer_len = size < 16u ? (uint32_t)size : 16u;
    (void)rdp_usb_redirection_write_urb_completion(&buffer, 9, 12, &urb_completion);
    (void)rdp_usb_redirection_parse_urb_completion(buffer.data,
                                                   buffer.length,
                                                   RDP_USB_REDIRECTION_FN_URB_COMPLETION,
                                                   &urb_completion);
    buffer.length = 0;
    urb_completion.output_buffer_len = 0;
    (void)rdp_usb_redirection_write_urb_completion_no_data(&buffer, 9, 13, &urb_completion);
    (void)rdp_usb_redirection_parse_urb_completion(buffer.data,
                                                   buffer.length,
                                                   RDP_USB_REDIRECTION_FN_URB_COMPLETION_NO_DATA,
                                                   &urb_completion);
    rdp_buffer_free(&buffer);
    return 0;
}
