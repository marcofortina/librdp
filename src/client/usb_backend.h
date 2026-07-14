/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal USB backend transfer boundary.
 * Invariants: blocking USB operations are represented as cancellable backend
 * transfers and are bounded by a caller-supplied timeout.
 * Ownership: callers own device handles and data buffers; the backend owns
 * temporary transfer buffers until completion or cancellation.
 * Threading: functions are synchronous to the session thread but drive libusb
 * asynchronous transfers internally so timeout cancellation is deterministic.
 * Trust boundary: transfer parameters originate from validated URBDRC payloads
 * and are clamped before entering the backend.
 */

#ifndef RDP_CLIENT_USB_BACKEND_H
#define RDP_CLIENT_USB_BACKEND_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#ifdef RDP_HAVE_LIBUSB
#include <libusb-1.0/libusb.h>

uint32_t rdp_usb_backend_libusb_status(int rc);
uint32_t rdp_usb_backend_transfer_status(enum libusb_transfer_status status);

typedef struct rdp_usb_backend_device
{
    uint8_t active;
    uint32_t interface_id;
    libusb_device_handle* handle;
    struct libusb_device_descriptor descriptor;
    uint8_t bus_number;
    uint8_t device_address;
    uint8_t claimed_interfaces[32];
} rdp_usb_backend_device;

typedef struct rdp_usb_backend_iso_packet
{
    uint32_t length;
    uint32_t actual_length;
    uint32_t status;
} rdp_usb_backend_iso_packet;

typedef struct rdp_usb_backend_open_request
{
    uint32_t first;
    uint32_t second;
    uint32_t interface_id;
    int bus_mode;
    int allow_hid;
    int allow_mass_storage;
} rdp_usb_backend_open_request;

typedef struct rdp_usb_backend_match
{
    uint16_t vendor_id;
    uint16_t product_id;
    uint8_t device_class;
    uint8_t bus_number;
    uint8_t device_address;
} rdp_usb_backend_match;

void rdp_usb_backend_release_device(rdp_usb_backend_device* device);
void rdp_usb_backend_release_devices(rdp_usb_backend_device* devices, size_t count);
void rdp_usb_backend_context_exit(libusb_context** context);
librdp_status rdp_usb_backend_open_device(libusb_context** context,
                                          const rdp_usb_backend_open_request* request,
                                          rdp_usb_backend_device* out,
                                          rdp_usb_backend_match* match);
uint32_t rdp_usb_backend_reset_device(rdp_usb_backend_device* device);
uint32_t rdp_usb_backend_claim_endpoint(rdp_usb_backend_device* device,
                                        uint8_t endpoint,
                                        uint8_t* transfer_type);
uint32_t rdp_usb_backend_select_interface(rdp_usb_backend_device* device,
                                          uint8_t interface_number,
                                          uint8_t alternate_setting);
uint32_t rdp_usb_backend_control_transfer(libusb_context* context,
                                          libusb_device_handle* handle,
                                          uint8_t request_type,
                                          uint8_t request,
                                          uint16_t value,
                                          uint16_t index,
                                          uint8_t* data,
                                          uint32_t length,
                                          uint32_t timeout_ms,
                                          uint32_t* actual_length);
uint32_t rdp_usb_backend_bulk_or_interrupt_transfer(libusb_context* context,
                                                    libusb_device_handle* handle,
                                                    uint8_t endpoint,
                                                    uint8_t transfer_type,
                                                    uint8_t* data,
                                                    uint32_t length,
                                                    uint32_t timeout_ms,
                                                    uint32_t* actual_length);
uint32_t rdp_usb_backend_iso_transfer(libusb_context* context,
                                      libusb_device_handle* handle,
                                      uint8_t endpoint,
                                      uint8_t* data,
                                      uint32_t length,
                                      rdp_usb_backend_iso_packet* packets,
                                      uint32_t packet_count,
                                      uint32_t timeout_ms,
                                      uint32_t* actual_length);
#endif

#endif
