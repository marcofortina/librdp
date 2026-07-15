/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: protocol device-channel conformance vectors.
 * Coverage: USB redirection and PNP redirection parser/serializer fixtures.
 * Bug classes: malformed device metadata, descriptor bounds, URB framing, and
 * request/response length validation.
 * Determinism: fixtures are synthetic and do not enumerate host devices.
 */

#include "channels/pnp_redirection.h"
#include "channels/usb_redirection.h"
#include "common/buffer.h"

#include <stdio.h>
#include <string.h>

#define PCHECK(expr)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

/*
 * Coverage: validates USB descriptor, URB, transfer, and completion vectors
 * with direction, length, and endpoint edge cases.
 */
static int test_usb_redirection_channel(void)
{
    const uint8_t text[] = {'D', 0, 0, 0};
    const uint8_t instance[] = {'U', 0, 'S', 0, 'B', 0, 0, 0};
    const uint8_t ids[] = {'I', 0, 'D', 0, 0, 0, 0, 0};
    const uint8_t container[] = {'{', 0, '1', 0, '}', 0, 0, 0};
    const uint8_t payload[] = {1, 2, 3, 4};
    const uint8_t urb_result[] = {8, 0, 0, 0, 0, 0, 0, 0};
    rdp_buffer buffer;
    rdp_buffer packet;
    rdp_usb_redirection_header header;
    rdp_usb_redirection_capability_exchange exchange;
    rdp_usb_redirection_channel_created created;
    rdp_usb_redirection_device_capabilities capabilities;
    rdp_usb_redirection_add_device device;
    rdp_usb_redirection_register_callback callback;
    rdp_usb_redirection_cancel_request cancel;
    rdp_usb_redirection_io_control control;
    rdp_usb_redirection_query_device_text query;
    rdp_usb_redirection_transfer transfer;
    rdp_usb_redirection_retract_device retract;
    rdp_usb_redirection_io_completion io_completion;
    rdp_usb_redirection_urb_completion urb_completion;

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_usb_redirection_write_header(&buffer,
                                            9,
                                            RDP_USB_REDIRECTION_MASK_PROXY,
                                            0x11223344u,
                                            1,
                                            RDP_USB_REDIRECTION_FN_IO_CONTROL) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_header(buffer.data, buffer.length, 1, &header) == LIBRDP_STATUS_OK);
    PCHECK(header.interface_id == 9);
    PCHECK(header.mask == RDP_USB_REDIRECTION_MASK_PROXY);
    PCHECK(header.message_id == 0x11223344u);
    PCHECK(header.function_id == RDP_USB_REDIRECTION_FN_IO_CONTROL);
    buffer.data[3] = 0xffu;
    PCHECK(rdp_usb_redirection_parse_header(buffer.data, buffer.length, 1, &header) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_capability_request(&packet,
                                                        1,
                                                        RDP_USB_REDIRECTION_CAPABILITY_VERSION_01) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_capability_request(packet.data, packet.length, &exchange) ==
           LIBRDP_STATUS_OK);
    PCHECK(exchange.capability_value == RDP_USB_REDIRECTION_CAPABILITY_VERSION_01);
    PCHECK(rdp_usb_redirection_write_capability_request(&buffer, 1, 2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_usb_redirection_write_capability_response(&buffer,
                                                         exchange.header.message_id,
                                                         exchange.capability_value,
                                                         0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_header(buffer.data, buffer.length, 0, &header) == LIBRDP_STATUS_OK);
    PCHECK(header.mask == RDP_USB_REDIRECTION_MASK_NONE && header.payload_len == 8u);
    rdp_buffer_free(&packet);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&packet);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_add_virtual_channel(&buffer, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_header(buffer.data, buffer.length, 1, &header) == LIBRDP_STATUS_OK);
    PCHECK(header.function_id == RDP_USB_REDIRECTION_FN_ADD_VIRTUAL_CHANNEL);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_channel_created(&buffer,
                                                     RDP_USB_REDIRECTION_INTERFACE_CHANNEL_NOTIFY_SERVER,
                                                     3,
                                                     0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_channel_created(buffer.data,
                                                     buffer.length,
                                                     RDP_USB_REDIRECTION_INTERFACE_CHANNEL_NOTIFY_SERVER,
                                                     &created) == LIBRDP_STATUS_OK);
    PCHECK(created.major_version == RDP_USB_REDIRECTION_VERSION_MAJOR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    capabilities.cb_size = RDP_USB_REDIRECTION_DEVICE_CAPABILITIES_SIZE;
    capabilities.usb_bus_interface_version = 2;
    capabilities.usbdi_version = 0x00000600u;
    capabilities.supported_usb_version = 0x00000200u;
    capabilities.hcd_capabilities = 0;
    capabilities.device_is_high_speed = 1;
    capabilities.no_ack_isoch_write_jitter_buffer_size_ms = 0;
    PCHECK(rdp_usb_redirection_write_add_device(&buffer,
                                                4,
                                                7,
                                                instance,
                                                (uint32_t)sizeof(instance),
                                                ids,
                                                (uint32_t)sizeof(ids),
                                                ids,
                                                (uint32_t)sizeof(ids),
                                                container,
                                                (uint32_t)sizeof(container),
                                                &capabilities) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_add_device(buffer.data, buffer.length, &device) == LIBRDP_STATUS_OK);
    PCHECK(device.num_usb_device == 1 && device.usb_device == 7);
    PCHECK(device.device_instance_id_len == sizeof(instance));
    PCHECK(device.capabilities.supported_usb_version == 0x00000200u);
    capabilities.usb_bus_interface_version = 0;
    PCHECK(rdp_usb_redirection_write_add_device(&packet,
                                                4,
                                                7,
                                                instance,
                                                (uint32_t)sizeof(instance),
                                                NULL,
                                                0,
                                                ids,
                                                (uint32_t)sizeof(ids),
                                                container,
                                                (uint32_t)sizeof(container),
                                                &capabilities) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_register_callback(&buffer, 7, 8, 9, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_register_callback(buffer.data, buffer.length, &callback) ==
           LIBRDP_STATUS_OK);
    PCHECK(callback.has_request_completion && callback.request_completion == 9);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_register_callback(&buffer, 7, 8, 0, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_register_callback(buffer.data, buffer.length, &callback) ==
           LIBRDP_STATUS_OK);
    PCHECK(!callback.has_request_completion && callback.num_request_completion == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_cancel_request(&buffer, 7, 9, 55) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_cancel_request(buffer.data, buffer.length, &cancel) == LIBRDP_STATUS_OK);
    PCHECK(cancel.request_id == 55);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_io_control(&buffer,
                                                7,
                                                10,
                                                RDP_USB_REDIRECTION_FN_IO_CONTROL,
                                                RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_SUBMIT_URB,
                                                payload,
                                                (uint32_t)sizeof(payload),
                                                16,
                                                56) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_io_control(buffer.data,
                                                buffer.length,
                                                RDP_USB_REDIRECTION_FN_IO_CONTROL,
                                                &control) == LIBRDP_STATUS_OK);
    PCHECK(control.io_control_code == RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_SUBMIT_URB &&
           control.request_id == 56);
    PCHECK(control.input_buffer_len == sizeof(payload) &&
           memcmp(control.input_buffer, payload, sizeof(payload)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_io_control(&buffer,
                                                7,
                                                10,
                                                RDP_USB_REDIRECTION_FN_INTERNAL_IO_CONTROL,
                                                0x220004u,
                                                NULL,
                                                0,
                                                0,
                                                57) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_io_control(buffer.data,
                                                buffer.length,
                                                RDP_USB_REDIRECTION_FN_INTERNAL_IO_CONTROL,
                                                &control) == LIBRDP_STATUS_OK);
    PCHECK(control.input_buffer_len == 0 && control.output_buffer_size == 0 && control.request_id == 57);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_io_control(&buffer,
                                                7,
                                                10,
                                                0,
                                                0,
                                                NULL,
                                                1,
                                                0,
                                                0) == LIBRDP_STATUS_INVALID_ARGUMENT);

    PCHECK(rdp_usb_redirection_write_query_device_text(&buffer, 7, 11, 1, 0x409) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_query_device_text(buffer.data, buffer.length, &query) ==
           LIBRDP_STATUS_OK);
    PCHECK(query.text_type == 1 && query.locale_id == 0x409);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_transfer_in_request(&buffer,
                                                         7,
                                                         12,
                                                         0x0008u,
                                                         99,
                                                         0,
                                                         64) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST,
                                              &transfer) == LIBRDP_STATUS_OK);
    PCHECK(transfer.urb.request_id == 99 && transfer.output_buffer_size == 64);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_header(&buffer,
                                            7,
                                            RDP_USB_REDIRECTION_MASK_PROXY,
                                            12,
                                            1,
                                            RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 12) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 8) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 0x0008u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 99) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 64) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST,
                                              &transfer) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_urb_header(&buffer, 8, 0x0008u, 99, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_urb_header(buffer.data, buffer.length, &transfer.urb) ==
           LIBRDP_STATUS_OK);
    PCHECK(transfer.urb.size == 8 && transfer.urb.function == 0x0008u);
    PCHECK(rdp_usb_redirection_write_urb_header(&packet, 9, 0x0008u, 99, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_transfer_out_request(&buffer,
                                                          7,
                                                          13,
                                                          0x0009u,
                                                          100,
                                                          1,
                                                          payload,
                                                          (uint32_t)sizeof(payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST,
                                              &transfer) == LIBRDP_STATUS_OK);
    PCHECK(transfer.urb.no_ack && transfer.output_buffer_len == sizeof(payload));
    PCHECK(memcmp(transfer.output_buffer, payload, sizeof(payload)) == 0);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length - 1u,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST,
                                              &transfer) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_header(&buffer,
                                            7,
                                            RDP_USB_REDIRECTION_MASK_PROXY,
                                            21,
                                            1,
                                            RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 24) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 24) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, RDP_USB_REDIRECTION_URB_BULK_OR_INTERRUPT_TRANSFER) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 101) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0x01) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0x02) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, (uint32_t)sizeof(payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&buffer, payload, sizeof(payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST,
                                              &transfer) == LIBRDP_STATUS_OK);
    PCHECK(transfer.cb_ts_urb == 24 &&
           transfer.urb.size == 24 &&
           transfer.urb.function == RDP_USB_REDIRECTION_URB_BULK_OR_INTERRUPT_TRANSFER &&
           transfer.output_buffer_len == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_header(&buffer,
                                            7,
                                            RDP_USB_REDIRECTION_MASK_PROXY,
                                            22,
                                            1,
                                            RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 28) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 28) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 102) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 0x80) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 6) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 0x0100) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 18) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 18) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST,
                                              &transfer) == LIBRDP_STATUS_OK);
    PCHECK(transfer.cb_ts_urb == 28 &&
           transfer.urb.size == 28 &&
           transfer.urb.function == RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER &&
           transfer.output_buffer_size == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_header(&buffer,
                                            7,
                                            RDP_USB_REDIRECTION_MASK_PROXY,
                                            23,
                                            1,
                                            RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 34) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 34) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, RDP_USB_REDIRECTION_URB_SELECT_CONFIGURATION) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 103) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 12) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 9) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 34) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST,
                                              &transfer) == LIBRDP_STATUS_OK);
    PCHECK(transfer.cb_ts_urb == 34 &&
           transfer.urb.function == RDP_USB_REDIRECTION_URB_SELECT_CONFIGURATION &&
           transfer.urb.request_id == 103);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length - 1u,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST,
                                              &transfer) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_header(&buffer,
                                            7,
                                            RDP_USB_REDIRECTION_MASK_PROXY,
                                            24,
                                            1,
                                            RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 16) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 16) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, RDP_USB_REDIRECTION_URB_GET_DESCRIPTOR_FROM_DEVICE) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 104) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 0x0409) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 18) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST,
                                              &transfer) == LIBRDP_STATUS_OK);
    PCHECK(transfer.urb.function == RDP_USB_REDIRECTION_URB_GET_DESCRIPTOR_FROM_DEVICE &&
           transfer.urb.request_id == 104);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_header(&buffer,
                                            7,
                                            RDP_USB_REDIRECTION_MASK_PROXY,
                                            25,
                                            1,
                                            RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 24) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 24) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, RDP_USB_REDIRECTION_URB_VENDOR_INTERFACE) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 105) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, RDP_USB_REDIRECTION_TRANSFER_DIRECTION) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 0x22) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 0x0102) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 8) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST,
                                              &transfer) == LIBRDP_STATUS_OK);
    PCHECK(transfer.urb.function == RDP_USB_REDIRECTION_URB_VENDOR_INTERFACE &&
           transfer.urb.request_id == 105);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_header(&buffer,
                                            7,
                                            RDP_USB_REDIRECTION_MASK_PROXY,
                                            26,
                                            1,
                                            RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 48) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 48) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, RDP_USB_REDIRECTION_URB_ISOCH_TRANSFER) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 106) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, RDP_USB_REDIRECTION_TRANSFER_DIRECTION) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 8) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 8) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 8) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 16) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST,
                                              &transfer) == LIBRDP_STATUS_OK);
    PCHECK(transfer.urb.function == RDP_USB_REDIRECTION_URB_ISOCH_TRANSFER &&
           transfer.urb.request_id == 106 &&
           transfer.cb_ts_urb == 48);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length - 1u,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST,
                                              &transfer) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_header(&buffer,
                                            7,
                                            RDP_USB_REDIRECTION_MASK_PROXY,
                                            27,
                                            1,
                                            RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 20) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 20) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, RDP_USB_REDIRECTION_URB_GET_OS_FEATURE_DESCRIPTOR_REQUEST) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 107) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 5) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 40) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST,
                                              &transfer) == LIBRDP_STATUS_OK);
    PCHECK(transfer.urb.function == RDP_USB_REDIRECTION_URB_GET_OS_FEATURE_DESCRIPTOR_REQUEST &&
           transfer.urb.request_id == 107 &&
           transfer.cb_ts_urb == 20);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_transfer_out_request(&buffer, 7, 13, 0x0009u, 100, 0, NULL, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);

    PCHECK(rdp_usb_redirection_write_retract_device(&buffer,
                                                    7,
                                                    14,
                                                    RDP_USB_REDIRECTION_RETRACT_BLOCKED_BY_POLICY) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_retract_device(buffer.data, buffer.length, &retract) ==
           LIBRDP_STATUS_OK);
    PCHECK(retract.reason == RDP_USB_REDIRECTION_RETRACT_BLOCKED_BY_POLICY);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_query_device_text_response(&buffer,
                                                                7,
                                                                15,
                                                                text,
                                                                (uint32_t)sizeof(text),
                                                                0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_header(buffer.data, buffer.length, 0, &header) == LIBRDP_STATUS_OK);
    PCHECK(header.mask == RDP_USB_REDIRECTION_MASK_STUB);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    io_completion.request_id = 1;
    io_completion.hresult = 0;
    io_completion.information = sizeof(payload);
    io_completion.output_buffer = payload;
    io_completion.output_buffer_len = sizeof(payload);
    PCHECK(rdp_usb_redirection_write_io_control_completion(&buffer, 9, 16, &io_completion) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_header(buffer.data, buffer.length, 1, &header) == LIBRDP_STATUS_OK);
    PCHECK(header.function_id == RDP_USB_REDIRECTION_FN_IOCONTROL_COMPLETION);
    memset(&io_completion, 0, sizeof(io_completion));
    PCHECK(rdp_usb_redirection_parse_io_control_completion(buffer.data,
                                                           buffer.length,
                                                           &io_completion) == LIBRDP_STATUS_OK);
    PCHECK(io_completion.request_id == 1 &&
           io_completion.hresult == 0 &&
           io_completion.information == sizeof(payload) &&
           io_completion.output_buffer_len == sizeof(payload) &&
           memcmp(io_completion.output_buffer, payload, sizeof(payload)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    urb_completion.request_id = 2;
    urb_completion.ts_urb_result = payload;
    urb_completion.cb_ts_urb_result = sizeof(payload);
    urb_completion.hresult = 0;
    urb_completion.output_buffer = payload;
    urb_completion.output_buffer_len = sizeof(payload);
    PCHECK(rdp_usb_redirection_write_urb_completion(&buffer, 9, 17, &urb_completion) ==
           LIBRDP_STATUS_OK);
    memset(&urb_completion, 0, sizeof(urb_completion));
    PCHECK(rdp_usb_redirection_parse_urb_completion(buffer.data,
                                                    buffer.length,
                                                    RDP_USB_REDIRECTION_FN_URB_COMPLETION,
                                                    &urb_completion) == LIBRDP_STATUS_OK);
    PCHECK(urb_completion.request_id == 2 &&
           urb_completion.cb_ts_urb_result == sizeof(payload) &&
           urb_completion.hresult == 0 &&
           urb_completion.output_buffer_len == sizeof(payload) &&
           memcmp(urb_completion.ts_urb_result, payload, sizeof(payload)) == 0 &&
           memcmp(urb_completion.output_buffer, payload, sizeof(payload)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    urb_completion.output_buffer_len = 0;
    urb_completion.ts_urb_result = urb_result;
    urb_completion.cb_ts_urb_result = sizeof(urb_result);
    PCHECK(rdp_usb_redirection_write_urb_completion_no_data(&buffer, 9, 18, &urb_completion) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_header(buffer.data, buffer.length, 1, &header) == LIBRDP_STATUS_OK);
    PCHECK(header.function_id == RDP_USB_REDIRECTION_FN_URB_COMPLETION_NO_DATA);
    PCHECK(header.payload_len == 24u);
    PCHECK(header.payload[4] == sizeof(urb_result));
    PCHECK(memcmp(header.payload + 8u, urb_result, sizeof(urb_result)) == 0);
    memset(&urb_completion, 0, sizeof(urb_completion));
    PCHECK(rdp_usb_redirection_parse_urb_completion(buffer.data,
                                                    buffer.length,
                                                    RDP_USB_REDIRECTION_FN_URB_COMPLETION_NO_DATA,
                                                    &urb_completion) == LIBRDP_STATUS_OK);
    PCHECK(urb_completion.request_id == 2 &&
           urb_completion.cb_ts_urb_result == sizeof(urb_result) &&
           urb_completion.output_buffer_len == 0 &&
           memcmp(urb_completion.ts_urb_result, urb_result, sizeof(urb_result)) == 0);
    PCHECK(rdp_usb_redirection_parse_urb_completion(buffer.data,
                                                    buffer.length,
                                                    RDP_USB_REDIRECTION_FN_URB_COMPLETION,
                                                    &urb_completion) == LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&packet);
    rdp_buffer_free(&buffer);
    return 0;
}

/*
 * Coverage: validates PNP device descriptions, capabilities, and request
 * vectors for host-device mapping and malformed metadata.
 */
static int test_pnp_redirection_channel(void)
{
    const uint8_t hwid[] = {'H', 0, 'W', 0, 0, 0, 0, 0};
    const uint8_t desc[] = {'D', 0, 'e', 0, 'v', 0};
    const uint8_t data[] = {9, 8, 7, 6};
    uint8_t guid[16] = {0x10, 0x20, 0x30, 0x40};
    rdp_buffer buffer;
    rdp_buffer packet;
    rdp_pnp_redirection_info_header info;
    rdp_pnp_redirection_version version;
    rdp_pnp_redirection_device_description device;
    rdp_pnp_redirection_device_addition addition;
    rdp_pnp_redirection_device_removal removal;
    rdp_pnp_redirection_server_io_header server_header;
    rdp_pnp_redirection_client_io_header client_header;
    rdp_pnp_redirection_io_version io_version;
    rdp_pnp_redirection_create_request create_request;
    rdp_pnp_redirection_read_request read_request;
    rdp_pnp_redirection_write_request write_request;
    rdp_pnp_redirection_control_request control_request;
    rdp_pnp_redirection_cancel_request cancel_request;
    rdp_pnp_redirection_custom_event event;
    rdp_pnp_redirection_status_reply status_reply;
    rdp_pnp_redirection_read_reply read_reply;
    rdp_pnp_redirection_write_reply write_reply;
    rdp_pnp_redirection_control_reply control_reply;

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);
    memset(&device, 0, sizeof(device));

    PCHECK(rdp_pnp_redirection_write_version(&buffer,
                                             1,
                                             0,
                                             RDP_PNP_REDIRECTION_CAP_DYNAMIC_DEVICES) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_version(buffer.data, buffer.length, &version) == LIBRDP_STATUS_OK);
    PCHECK(version.major_version == 1 && version.capabilities == RDP_PNP_REDIRECTION_CAP_DYNAMIC_DEVICES);
    buffer.data[0] = 1;
    PCHECK(rdp_pnp_redirection_parse_version(buffer.data, buffer.length, &version) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_pnp_redirection_write_authenticated(&buffer) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_authenticated(buffer.data, buffer.length, &info) == LIBRDP_STATUS_OK);
    PCHECK(info.packet_id == RDP_PNP_REDIRECTION_INFO_SERVER_LOGON && info.payload_len == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    device.client_device_id = 0x44;
    device.hardware_id = hwid;
    device.hardware_id_len = sizeof(hwid);
    device.compatibility_id = hwid;
    device.compatibility_id_len = sizeof(hwid);
    device.device_description = desc;
    device.device_description_len = sizeof(desc);
    device.custom_flag = RDP_PNP_REDIRECTION_CUSTOM_FLAG_OPTIONAL_1;
    device.container_id = guid;
    device.container_id_len = sizeof(guid);
    device.has_container_id = 1;
    device.device_caps = RDP_PNP_REDIRECTION_DEVCAPS_REMOVABLE |
                         RDP_PNP_REDIRECTION_DEVCAPS_SURPRISEREMOVALOK;
    device.has_device_caps = 1;
    PCHECK(rdp_pnp_redirection_write_device_addition(&buffer, &device, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_device_addition(buffer.data, buffer.length, &addition) ==
           LIBRDP_STATUS_OK);
    PCHECK(addition.device_count == 1);
    PCHECK(addition.devices[0].client_device_id == 0x44);
    PCHECK(addition.devices[0].has_container_id && addition.devices[0].has_device_caps);
    PCHECK(addition.devices[0].hardware_id_len == sizeof(hwid));
    PCHECK(rdp_pnp_redirection_parse_device_addition(buffer.data,
                                                     buffer.length - 1u,
                                                     &addition) == LIBRDP_STATUS_PROTOCOL_ERROR);
    device.interface_guids = guid;
    device.interface_guids_len = 4;
    PCHECK(rdp_pnp_redirection_write_device_addition(&packet, &device, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_pnp_redirection_write_device_removal(&buffer, 0x44) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_device_removal(buffer.data, buffer.length, &removal) ==
           LIBRDP_STATUS_OK);
    PCHECK(removal.client_device_id == 0x44);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_pnp_redirection_write_server_io_header(&packet,
                                                      0x00a1b2u,
                                                      7,
                                                      RDP_PNP_REDIRECTION_IO_CAPABILITIES_REQUEST) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_server_io_header(packet.data, packet.length, &server_header) ==
           LIBRDP_STATUS_OK);
    PCHECK(server_header.request_id == 0x00a1b2u && server_header.unused == 7);
    PCHECK(rdp_pnp_redirection_write_server_io_header(&packet,
                                                      0x01000000u,
                                                      0,
                                                      RDP_PNP_REDIRECTION_IO_READ_REQUEST) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_pnp_redirection_write_server_io_header(&packet, 1, 0, 0xffffffffu) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    PCHECK(rdp_pnp_redirection_write_client_io_header(&packet,
                                                      0x00a1b2u,
                                                      RDP_PNP_REDIRECTION_PACKET_RESPONSE) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_client_io_header(packet.data, packet.length, &client_header) ==
           LIBRDP_STATUS_OK);
    PCHECK(client_header.request_id == 0x00a1b2u &&
           client_header.packet_type == RDP_PNP_REDIRECTION_PACKET_RESPONSE &&
           client_header.payload_len == 0);
    packet.length = 0;
    PCHECK(rdp_pnp_redirection_write_client_io_header(&packet, 0x01000000u, 0xffu) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);

    PCHECK(rdp_pnp_redirection_write_capabilities_request(&buffer,
                                                          0x00a1b2u,
                                                          0,
                                                          RDP_PNP_REDIRECTION_IO_VERSION_6) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_capabilities_request(buffer.data, buffer.length, &io_version) ==
           LIBRDP_STATUS_OK);
    PCHECK(io_version.header.request_id == 0x00a1b2u);
    PCHECK(rdp_pnp_redirection_write_capabilities_request(&packet, 0, 0, 0xffffu) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_pnp_redirection_write_capabilities_reply(&packet,
                                                        io_version.header.request_id,
                                                        io_version.version) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_client_io_header(packet.data, packet.length, &client_header) ==
           LIBRDP_STATUS_OK);
    PCHECK(client_header.request_id == 0x00a1b2u && client_header.payload_len == 2u);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_pnp_redirection_write_create_request(&buffer,
                                                    1,
                                                    0,
                                                    0x44,
                                                    0xc0000000u,
                                                    3,
                                                    3,
                                                    0x40) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_create_request(buffer.data, buffer.length, &create_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(create_request.device_id == 0x44 && create_request.desired_access == 0xc0000000u);
    PCHECK(rdp_pnp_redirection_write_status_reply(&packet, 1, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_status_reply(packet.data, packet.length, &status_reply) ==
           LIBRDP_STATUS_OK);
    PCHECK(status_reply.header.request_id == 1 && status_reply.result == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_pnp_redirection_write_read_request(&buffer, 2, 0, 32, 0, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_read_request(buffer.data, buffer.length, &read_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(read_request.bytes_to_read == 32 && read_request.offset_low == 4);
    PCHECK(rdp_pnp_redirection_write_read_reply(&packet, 2, 0, data, sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_read_reply(packet.data, packet.length, &read_reply) ==
           LIBRDP_STATUS_OK);
    PCHECK(read_reply.header.request_id == 2 && read_reply.result == 0 &&
           read_reply.data_len == sizeof(data) && memcmp(read_reply.data, data, sizeof(data)) == 0);
    packet.data[packet.length - 1u] = 0xffu;
    PCHECK(rdp_pnp_redirection_parse_read_reply(packet.data, packet.length, &read_reply) ==
           LIBRDP_STATUS_OK);
    packet.length--;
    PCHECK(rdp_pnp_redirection_parse_read_reply(packet.data, packet.length, &read_reply) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_pnp_redirection_write_write_request(&buffer, 3, 0, 0, 8, data, sizeof(data)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_write_request(buffer.data, buffer.length, &write_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(write_request.bytes_to_write == sizeof(data) && write_request.offset_low == 8);
    PCHECK(memcmp(write_request.data, data, sizeof(data)) == 0);
    PCHECK(rdp_pnp_redirection_write_write_request(&packet, 3, 0, 0, 8, NULL, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_pnp_redirection_write_write_reply(&packet, 3, 0, sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_write_reply(packet.data, packet.length, &write_reply) ==
           LIBRDP_STATUS_OK);
    PCHECK(write_reply.header.request_id == 3 && write_reply.result == 0 &&
           write_reply.bytes_written == sizeof(data));
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_pnp_redirection_write_control_request(&buffer, 4, 0, 0x1020, data, 2, 4, data, 4) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_control_request(buffer.data, buffer.length, &control_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(control_request.input_len == 2 && control_request.actual_output_len == 4);
    PCHECK(control_request.io_code == 0x1020 && memcmp(control_request.output, data, 4) == 0);
    PCHECK(rdp_pnp_redirection_write_control_request(&packet, 4, 0, 0x1020, data, 2, 1, data, 2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_pnp_redirection_write_control_reply(&packet, 4, 0, data, sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_control_reply(packet.data, packet.length, &control_reply) ==
           LIBRDP_STATUS_OK);
    PCHECK(control_reply.header.request_id == 4 && control_reply.result == 0 &&
           control_reply.data_len == sizeof(data) &&
           memcmp(control_reply.data, data, sizeof(data)) == 0);
    packet.data[8] = 0xffu;
    PCHECK(rdp_pnp_redirection_parse_control_reply(packet.data, packet.length, &control_reply) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_pnp_redirection_write_cancel_request(&buffer, 5, 0, 0, 0x070809u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_cancel_request(buffer.data, buffer.length, &cancel_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(cancel_request.id_to_cancel == 0x070809u);
    PCHECK(rdp_pnp_redirection_write_cancel_request(&packet, 5, 0, 0, 0x01000000u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_pnp_redirection_write_custom_event(&buffer, guid, data, sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_custom_event(buffer.data, buffer.length, &event) == LIBRDP_STATUS_OK);
    PCHECK(event.header.packet_type == RDP_PNP_REDIRECTION_PACKET_CUSTOM_EVENT);
    PCHECK(event.data_len == sizeof(data));
    PCHECK(memcmp(event.event_guid, guid, sizeof(guid)) == 0);
    buffer.data[3] = 0xffu;
    PCHECK(rdp_pnp_redirection_parse_custom_event(buffer.data, buffer.length, &event) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_pnp_redirection_parse_server_io_header(data, sizeof(data), &server_header) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&packet);
    rdp_buffer_free(&buffer);
    return 0;
}


int test_protocol_devices(void)
{
    if (test_usb_redirection_channel() != 0)
        return 1;
    if (test_pnp_redirection_channel() != 0)
        return 1;
    return 0;
}
