#ifndef RDP_CHANNELS_USB_REDIRECTION_H
#define RDP_CHANNELS_USB_REDIRECTION_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_USB_REDIRECTION_INTERFACE_CAPABILITIES 0x00000000u
#define RDP_USB_REDIRECTION_INTERFACE_DEVICE_SINK 0x00000001u
#define RDP_USB_REDIRECTION_INTERFACE_CHANNEL_NOTIFY_CLIENT 0x00000002u
#define RDP_USB_REDIRECTION_INTERFACE_CHANNEL_NOTIFY_SERVER 0x00000003u
#define RDP_USB_REDIRECTION_INTERFACE_ID_MASK 0x3fffffffu

#define RDP_USB_REDIRECTION_MASK_NONE 0x0u
#define RDP_USB_REDIRECTION_MASK_PROXY 0x1u
#define RDP_USB_REDIRECTION_MASK_STUB 0x2u

#define RDP_USB_REDIRECTION_FN_RIMCALL_RELEASE 0x00000001u
#define RDP_USB_REDIRECTION_FN_RIMCALL_QUERYINTERFACE 0x00000002u
#define RDP_USB_REDIRECTION_FN_EXCHANGE_CAPABILITY 0x00000100u
#define RDP_USB_REDIRECTION_FN_IOCONTROL_COMPLETION 0x00000100u
#define RDP_USB_REDIRECTION_FN_URB_COMPLETION 0x00000101u
#define RDP_USB_REDIRECTION_FN_URB_COMPLETION_NO_DATA 0x00000102u
#define RDP_USB_REDIRECTION_FN_CANCEL_REQUEST 0x00000100u
#define RDP_USB_REDIRECTION_FN_REGISTER_REQUEST_CALLBACK 0x00000101u
#define RDP_USB_REDIRECTION_FN_IO_CONTROL 0x00000102u
#define RDP_USB_REDIRECTION_FN_INTERNAL_IO_CONTROL 0x00000103u
#define RDP_USB_REDIRECTION_FN_QUERY_DEVICE_TEXT 0x00000104u
#define RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST 0x00000105u
#define RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST 0x00000106u
#define RDP_USB_REDIRECTION_FN_RETRACT_DEVICE 0x00000107u
#define RDP_USB_REDIRECTION_FN_ADD_VIRTUAL_CHANNEL 0x00000100u
#define RDP_USB_REDIRECTION_FN_ADD_DEVICE 0x00000101u
#define RDP_USB_REDIRECTION_FN_CHANNEL_CREATED 0x00000100u

#define RDP_USB_REDIRECTION_CAPABILITY_VERSION_01 0x00000001u
#define RDP_USB_REDIRECTION_VERSION_MAJOR 0x00000001u
#define RDP_USB_REDIRECTION_VERSION_MINOR 0x00000000u
#define RDP_USB_REDIRECTION_DEVICE_CAPABILITIES_SIZE 28u
#define RDP_USB_REDIRECTION_RETRACT_BLOCKED_BY_POLICY 0x00000001u

#define RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_SUBMIT_URB 0x00220003u
#define RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_RESET_PORT 0x00220007u
#define RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_GET_PORT_STATUS 0x00220013u
#define RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_CYCLE_PORT 0x0022001fu
#define RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_SUBMIT_IDLE_NOTIFICATION 0x00220027u
#define RDP_USB_REDIRECTION_IOCTL_QUERY_BUS_TIME 0x00224000u

#define RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS 0x00000000u
#define RDP_USB_REDIRECTION_USBD_STATUS_NOT_SUPPORTED 0xc0000e00u
#define RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER 0x80000300u

typedef struct rdp_usb_redirection_header
{
    uint32_t interface_id;
    uint8_t mask;
    uint32_t message_id;
    uint8_t has_function_id;
    uint32_t function_id;
    const uint8_t* payload;
    size_t payload_len;
} rdp_usb_redirection_header;

typedef struct rdp_usb_redirection_capability_exchange
{
    rdp_usb_redirection_header header;
    uint32_t capability_value;
    uint32_t result;
} rdp_usb_redirection_capability_exchange;

typedef struct rdp_usb_redirection_channel_created
{
    rdp_usb_redirection_header header;
    uint32_t major_version;
    uint32_t minor_version;
    uint32_t capabilities;
} rdp_usb_redirection_channel_created;

typedef struct rdp_usb_redirection_device_capabilities
{
    uint32_t cb_size;
    uint32_t usb_bus_interface_version;
    uint32_t usbdi_version;
    uint32_t supported_usb_version;
    uint32_t hcd_capabilities;
    uint32_t device_is_high_speed;
    uint32_t no_ack_isoch_write_jitter_buffer_size_ms;
} rdp_usb_redirection_device_capabilities;

typedef struct rdp_usb_redirection_add_device
{
    rdp_usb_redirection_header header;
    uint32_t num_usb_device;
    uint32_t usb_device;
    const uint8_t* device_instance_id;
    uint32_t device_instance_id_len;
    const uint8_t* hardware_ids;
    uint32_t hardware_ids_len;
    const uint8_t* compatibility_ids;
    uint32_t compatibility_ids_len;
    const uint8_t* container_id;
    uint32_t container_id_len;
    rdp_usb_redirection_device_capabilities capabilities;
} rdp_usb_redirection_add_device;

typedef struct rdp_usb_redirection_register_callback
{
    rdp_usb_redirection_header header;
    uint32_t num_request_completion;
    uint32_t request_completion;
    uint8_t has_request_completion;
} rdp_usb_redirection_register_callback;

typedef struct rdp_usb_redirection_cancel_request
{
    rdp_usb_redirection_header header;
    uint32_t request_id;
} rdp_usb_redirection_cancel_request;

typedef struct rdp_usb_redirection_io_control
{
    rdp_usb_redirection_header header;
    uint32_t io_control_code;
    const uint8_t* input_buffer;
    uint32_t input_buffer_len;
    uint32_t output_buffer_size;
    uint32_t request_id;
} rdp_usb_redirection_io_control;

typedef struct rdp_usb_redirection_query_device_text
{
    rdp_usb_redirection_header header;
    uint32_t text_type;
    uint32_t locale_id;
} rdp_usb_redirection_query_device_text;

typedef struct rdp_usb_redirection_urb_header
{
    uint16_t size;
    uint16_t function;
    uint32_t request_id;
    uint8_t no_ack;
} rdp_usb_redirection_urb_header;

typedef struct rdp_usb_redirection_transfer
{
    rdp_usb_redirection_header header;
    uint32_t cb_ts_urb;
    const uint8_t* ts_urb;
    rdp_usb_redirection_urb_header urb;
    uint32_t output_buffer_size;
    const uint8_t* output_buffer;
    uint32_t output_buffer_len;
} rdp_usb_redirection_transfer;

typedef struct rdp_usb_redirection_retract_device
{
    rdp_usb_redirection_header header;
    uint32_t reason;
} rdp_usb_redirection_retract_device;

typedef struct rdp_usb_redirection_io_completion
{
    uint32_t request_id;
    uint32_t hresult;
    uint32_t information;
    const uint8_t* output_buffer;
    uint32_t output_buffer_len;
} rdp_usb_redirection_io_completion;

typedef struct rdp_usb_redirection_urb_completion
{
    uint32_t request_id;
    const uint8_t* ts_urb_result;
    uint32_t cb_ts_urb_result;
    uint32_t hresult;
    const uint8_t* output_buffer;
    uint32_t output_buffer_len;
} rdp_usb_redirection_urb_completion;

librdp_status rdp_usb_redirection_parse_header(const void* data,
                                               size_t length,
                                               int has_function_id,
                                               rdp_usb_redirection_header* header);
librdp_status rdp_usb_redirection_write_header(rdp_buffer* buffer,
                                               uint32_t interface_id,
                                               uint8_t mask,
                                               uint32_t message_id,
                                               int has_function_id,
                                               uint32_t function_id);
librdp_status rdp_usb_redirection_parse_capability_request(
    const void* data,
    size_t length,
    rdp_usb_redirection_capability_exchange* exchange);
librdp_status rdp_usb_redirection_write_capability_request(rdp_buffer* buffer,
                                                           uint32_t message_id,
                                                           uint32_t capability_value);
librdp_status rdp_usb_redirection_write_capability_response(rdp_buffer* buffer,
                                                            uint32_t message_id,
                                                            uint32_t capability_value,
                                                            uint32_t result);
librdp_status rdp_usb_redirection_write_add_virtual_channel(rdp_buffer* buffer,
                                                            uint32_t message_id);
librdp_status rdp_usb_redirection_parse_channel_created(const void* data,
                                                        size_t length,
                                                        uint32_t expected_interface_id,
                                                        rdp_usb_redirection_channel_created* created);
librdp_status rdp_usb_redirection_write_channel_created(rdp_buffer* buffer,
                                                        uint32_t interface_id,
                                                        uint32_t message_id,
                                                        uint32_t capabilities);
librdp_status rdp_usb_redirection_parse_device_capabilities(
    const void* data,
    size_t length,
    rdp_usb_redirection_device_capabilities* capabilities);
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
                                                   const rdp_usb_redirection_device_capabilities* capabilities);
librdp_status rdp_usb_redirection_parse_add_device(const void* data,
                                                   size_t length,
                                                   rdp_usb_redirection_add_device* device);
librdp_status rdp_usb_redirection_parse_register_callback(
    const void* data,
    size_t length,
    rdp_usb_redirection_register_callback* callback);
librdp_status rdp_usb_redirection_write_register_callback(
    rdp_buffer* buffer,
    uint32_t interface_id,
    uint32_t message_id,
    uint32_t request_completion_interface_id,
    int has_request_completion);
librdp_status rdp_usb_redirection_parse_cancel_request(const void* data,
                                                       size_t length,
                                                       rdp_usb_redirection_cancel_request* cancel);
librdp_status rdp_usb_redirection_write_cancel_request(rdp_buffer* buffer,
                                                       uint32_t interface_id,
                                                       uint32_t message_id,
                                                       uint32_t request_id);
librdp_status rdp_usb_redirection_parse_io_control(const void* data,
                                                   size_t length,
                                                   uint32_t expected_function_id,
                                                   rdp_usb_redirection_io_control* control);
librdp_status rdp_usb_redirection_write_io_control(rdp_buffer* buffer,
                                                   uint32_t interface_id,
                                                   uint32_t message_id,
                                                   uint32_t function_id,
                                                   uint32_t io_control_code,
                                                   const void* input_buffer,
                                                   uint32_t input_buffer_len,
                                                   uint32_t output_buffer_size,
                                                   uint32_t request_id);
librdp_status rdp_usb_redirection_parse_query_device_text(
    const void* data,
    size_t length,
    rdp_usb_redirection_query_device_text* query);
librdp_status rdp_usb_redirection_write_query_device_text(rdp_buffer* buffer,
                                                          uint32_t interface_id,
                                                          uint32_t message_id,
                                                          uint32_t text_type,
                                                          uint32_t locale_id);
librdp_status rdp_usb_redirection_parse_urb_header(const void* data,
                                                   size_t length,
                                                   rdp_usb_redirection_urb_header* header);
librdp_status rdp_usb_redirection_write_urb_header(rdp_buffer* buffer,
                                                   uint16_t size,
                                                   uint16_t function,
                                                   uint32_t request_id,
                                                   uint8_t no_ack);
librdp_status rdp_usb_redirection_parse_transfer(const void* data,
                                                 size_t length,
                                                 uint32_t expected_function_id,
                                                 rdp_usb_redirection_transfer* transfer);
librdp_status rdp_usb_redirection_write_transfer_in_request(rdp_buffer* buffer,
                                                            uint32_t interface_id,
                                                            uint32_t message_id,
                                                            uint16_t urb_function,
                                                            uint32_t request_id,
                                                            uint8_t no_ack,
                                                            uint32_t output_buffer_size);
librdp_status rdp_usb_redirection_write_transfer_out_request(rdp_buffer* buffer,
                                                             uint32_t interface_id,
                                                             uint32_t message_id,
                                                             uint16_t urb_function,
                                                             uint32_t request_id,
                                                             uint8_t no_ack,
                                                             const void* output_buffer,
                                                             uint32_t output_buffer_len);
librdp_status rdp_usb_redirection_parse_retract_device(
    const void* data,
    size_t length,
    rdp_usb_redirection_retract_device* retract);
librdp_status rdp_usb_redirection_write_retract_device(rdp_buffer* buffer,
                                                       uint32_t interface_id,
                                                       uint32_t message_id,
                                                       uint32_t reason);
librdp_status rdp_usb_redirection_write_query_device_text_response(rdp_buffer* buffer,
                                                                   uint32_t interface_id,
                                                                   uint32_t message_id,
                                                                   const uint8_t* description,
                                                                   uint32_t description_len,
                                                                   uint32_t hresult);
librdp_status rdp_usb_redirection_write_io_control_completion(
    rdp_buffer* buffer,
    uint32_t request_completion_interface_id,
    uint32_t message_id,
    const rdp_usb_redirection_io_completion* completion);
librdp_status rdp_usb_redirection_write_urb_completion(
    rdp_buffer* buffer,
    uint32_t request_completion_interface_id,
    uint32_t message_id,
    const rdp_usb_redirection_urb_completion* completion);
librdp_status rdp_usb_redirection_write_urb_completion_no_data(
    rdp_buffer* buffer,
    uint32_t request_completion_interface_id,
    uint32_t message_id,
    const rdp_usb_redirection_urb_completion* completion);

#endif
