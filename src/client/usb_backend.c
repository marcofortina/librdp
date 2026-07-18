/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: USB backend transfer implementation.
 * Invariants: control, bulk, and interrupt transfers are submitted through
 * libusb asynchronous APIs and cancelled when the configured timeout expires.
 * Ownership: temporary buffers are released on every return path, and caller
 * output buffers are written only after successful completion.
 * Threading: libusb events are pumped by the calling session thread; no global
 * backend state is retained.
 * Trust boundary: backend functions receive already-parsed packet fields and
 * return protocol-neutral URBDRC status values.
 */

#include "client/usb_backend.h"

#ifdef RDP_HAVE_LIBUSB

#include "channels/usb_redirection.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/time.h>
#include <time.h>

typedef struct rdp_usb_backend_async_state
{
    int completed;
    enum libusb_transfer_status transfer_status;
    int actual_length;
} rdp_usb_backend_async_state;

static uint64_t rdp_usb_backend_now_ms(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return ((uint64_t)now.tv_sec * 1000u) + ((uint64_t)now.tv_nsec / 1000000u);
}

static void LIBUSB_CALL rdp_usb_backend_transfer_callback(struct libusb_transfer* transfer)
{
    rdp_usb_backend_async_state* state =
        transfer ? (rdp_usb_backend_async_state*)transfer->user_data : NULL;

    if (!state)
        return;
    state->transfer_status = transfer->status;
    state->actual_length = transfer->actual_length;
    state->completed = 1;
}

uint32_t rdp_usb_backend_libusb_status(int rc)
{
    switch (rc)
    {
        case LIBUSB_SUCCESS:
            return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
        case LIBUSB_ERROR_TIMEOUT:
            return RDP_USB_REDIRECTION_USBD_STATUS_TIMEOUT;
        case LIBUSB_ERROR_NO_DEVICE:
            return RDP_USB_REDIRECTION_USBD_STATUS_DEVICE_GONE;
        case LIBUSB_ERROR_PIPE:
            return RDP_USB_REDIRECTION_USBD_STATUS_STALL_PID;
        case LIBUSB_ERROR_OVERFLOW:
            return RDP_USB_REDIRECTION_USBD_STATUS_DATA_OVERRUN;
        case LIBUSB_ERROR_NO_MEM:
            return RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
        case LIBUSB_ERROR_INVALID_PARAM:
            return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
        default:
            return RDP_USB_REDIRECTION_USBD_STATUS_DEV_NOT_RESPONDING;
    }
}

uint32_t rdp_usb_backend_transfer_status(enum libusb_transfer_status status)
{
    switch (status)
    {
        case LIBUSB_TRANSFER_COMPLETED:
            return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
        case LIBUSB_TRANSFER_TIMED_OUT:
        case LIBUSB_TRANSFER_CANCELLED:
            return RDP_USB_REDIRECTION_USBD_STATUS_TIMEOUT;
        case LIBUSB_TRANSFER_STALL:
            return RDP_USB_REDIRECTION_USBD_STATUS_STALL_PID;
        case LIBUSB_TRANSFER_NO_DEVICE:
            return RDP_USB_REDIRECTION_USBD_STATUS_DEVICE_GONE;
        case LIBUSB_TRANSFER_OVERFLOW:
            return RDP_USB_REDIRECTION_USBD_STATUS_DATA_OVERRUN;
        default:
            return RDP_USB_REDIRECTION_USBD_STATUS_DEV_NOT_RESPONDING;
    }
}

void rdp_usb_backend_release_device(rdp_usb_backend_device* device)
{
    if (!device)
        return;
    if (device->handle)
    {
        for (size_t i = 0; i < sizeof(device->claimed_interfaces); i++)
        {
            if (device->claimed_interfaces[i])
                (void)libusb_release_interface(device->handle, (int)i);
        }
        libusb_close(device->handle);
    }
    memset(device, 0, sizeof(*device));
}

void rdp_usb_backend_release_devices(rdp_usb_backend_device* devices, size_t count)
{
    if (!devices)
        return;
    for (size_t i = 0; i < count; i++)
        rdp_usb_backend_release_device(&devices[i]);
}

void rdp_usb_backend_context_exit(libusb_context** context)
{
    if (!context || !*context)
        return;
    libusb_exit(*context);
    *context = NULL;
}

static int rdp_usb_backend_default_init(void* user_data, libusb_context** context)
{
    (void)user_data;
    return libusb_init(context);
}

static ssize_t rdp_usb_backend_default_get_device_list(void* user_data,
                                                       libusb_context* context,
                                                       libusb_device*** list)
{
    (void)user_data;
    return libusb_get_device_list(context, list);
}

static void rdp_usb_backend_default_free_device_list(void* user_data,
                                                     libusb_device** list,
                                                     int unref_devices)
{
    (void)user_data;
    libusb_free_device_list(list, unref_devices);
}

static int rdp_usb_backend_default_get_device_descriptor(
    void* user_data,
    libusb_device* device,
    struct libusb_device_descriptor* descriptor)
{
    (void)user_data;
    return libusb_get_device_descriptor(device, descriptor);
}

static uint8_t rdp_usb_backend_default_get_bus_number(void* user_data,
                                                      libusb_device* device)
{
    (void)user_data;
    return libusb_get_bus_number(device);
}

static uint8_t rdp_usb_backend_default_get_device_address(void* user_data,
                                                          libusb_device* device)
{
    (void)user_data;
    return libusb_get_device_address(device);
}

static int rdp_usb_backend_default_get_config_descriptor(
    void* user_data,
    libusb_device* device,
    uint8_t index,
    struct libusb_config_descriptor** config)
{
    (void)user_data;
    return libusb_get_config_descriptor(device, index, config);
}

static void rdp_usb_backend_default_free_config_descriptor(
    void* user_data,
    struct libusb_config_descriptor* config)
{
    (void)user_data;
    libusb_free_config_descriptor(config);
}

static int rdp_usb_backend_default_open(void* user_data,
                                        libusb_device* device,
                                        libusb_device_handle** handle)
{
    (void)user_data;
    return libusb_open(device, handle);
}

static const rdp_usb_backend_open_ops RDP_USB_BACKEND_DEFAULT_OPEN_OPS = {
    NULL,
    rdp_usb_backend_default_init,
    rdp_usb_backend_default_get_device_list,
    rdp_usb_backend_default_free_device_list,
    rdp_usb_backend_default_get_device_descriptor,
    rdp_usb_backend_default_get_bus_number,
    rdp_usb_backend_default_get_device_address,
    rdp_usb_backend_default_get_config_descriptor,
    rdp_usb_backend_default_free_config_descriptor,
    rdp_usb_backend_default_open
};

static int rdp_usb_backend_open_ops_valid(const rdp_usb_backend_open_ops* ops)
{
    return ops && ops->init && ops->get_device_list && ops->free_device_list &&
           ops->get_device_descriptor && ops->get_bus_number &&
           ops->get_device_address && ops->get_config_descriptor &&
           ops->free_config_descriptor && ops->open;
}

static librdp_status rdp_usb_backend_open_error(int rc)
{
    return rc == LIBUSB_ERROR_NO_DEVICE ? LIBRDP_STATUS_CLOSED :
                                         LIBRDP_STATUS_IO_ERROR;
}

static void rdp_usb_backend_match_init(rdp_usb_backend_match* match,
                                       libusb_device* device,
                                       const struct libusb_device_descriptor* descriptor,
                                       const rdp_usb_backend_open_ops* ops)
{
    if (!match || !device || !descriptor || !ops)
        return;
    memset(match, 0, sizeof(*match));
    match->vendor_id = descriptor->idVendor;
    match->product_id = descriptor->idProduct;
    match->device_class = descriptor->bDeviceClass;
    match->bus_number = ops->get_bus_number(ops->user_data, device);
    match->device_address = ops->get_device_address(ops->user_data, device);
}

/*
 * Inspect every configuration before authorization. A missing or malformed
 * descriptor is an authorization failure because an unseen interface class
 * cannot safely pass a default-deny policy.
 */
static librdp_status rdp_usb_backend_check_class_policy(
    const rdp_usb_backend_open_request* request,
    libusb_device* device,
    const struct libusb_device_descriptor* descriptor,
    const rdp_usb_backend_open_ops* ops)
{
    uint8_t config_index = 0;

    if (!request || !device || !descriptor || !ops)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (descriptor->bDeviceClass == LIBUSB_CLASS_HID && !request->allow_hid)
        return LIBRDP_STATUS_STATE;
    if (descriptor->bDeviceClass == LIBUSB_CLASS_MASS_STORAGE && !request->allow_mass_storage)
        return LIBRDP_STATUS_STATE;
    if (descriptor->bNumConfigurations == 0)
        return LIBRDP_STATUS_IO_ERROR;

    for (config_index = 0; config_index < descriptor->bNumConfigurations; config_index++)
    {
        struct libusb_config_descriptor* config = NULL;
        int rc = ops->get_config_descriptor(ops->user_data,
                                            device,
                                            config_index,
                                            &config);

        if (rc != LIBUSB_SUCCESS || !config ||
            (config->bNumInterfaces > 0 && !config->interface))
        {
            if (config)
                ops->free_config_descriptor(ops->user_data, config);
            return rc == LIBUSB_SUCCESS ? LIBRDP_STATUS_IO_ERROR :
                                         rdp_usb_backend_open_error(rc);
        }
        for (uint8_t i = 0; i < config->bNumInterfaces; i++)
        {
            const struct libusb_interface* iface = &config->interface[i];

            if (iface->num_altsetting < 0 ||
                (iface->num_altsetting > 0 && !iface->altsetting))
            {
                ops->free_config_descriptor(ops->user_data, config);
                return LIBRDP_STATUS_IO_ERROR;
            }
            for (int j = 0; j < iface->num_altsetting; j++)
            {
                const struct libusb_interface_descriptor* alt = &iface->altsetting[j];

                if ((alt->bInterfaceClass == LIBUSB_CLASS_HID && !request->allow_hid) ||
                    (alt->bInterfaceClass == LIBUSB_CLASS_MASS_STORAGE &&
                     !request->allow_mass_storage))
                {
                    ops->free_config_descriptor(ops->user_data, config);
                    return LIBRDP_STATUS_STATE;
                }
            }
        }
        ops->free_config_descriptor(ops->user_data, config);
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Resolve a user-approved USB selector to an opened libusb handle. The backend
 * applies class allowlists before opening so the session dispatcher never owns
 * a handle to a denied HID or mass-storage device.
 */
librdp_status rdp_usb_backend_open_device(libusb_context** context,
                                          const rdp_usb_backend_open_request* request,
                                          rdp_usb_backend_device* out,
                                          rdp_usb_backend_match* match)
{
    return rdp_usb_backend_open_device_with_ops(context,
                                                request,
                                                out,
                                                match,
                                                &RDP_USB_BACKEND_DEFAULT_OPEN_OPS);
}

librdp_status rdp_usb_backend_open_device_with_ops(
    libusb_context** context,
    const rdp_usb_backend_open_request* request,
    rdp_usb_backend_device* out,
    rdp_usb_backend_match* match,
    const rdp_usb_backend_open_ops* ops)
{
    libusb_device** list = NULL;
    ssize_t count = 0;
    librdp_status status = LIBRDP_STATUS_IO_ERROR;

    if (!context || !request || !out || !rdp_usb_backend_open_ops_valid(ops))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!*context)
    {
        if (ops->init(ops->user_data, context) != LIBUSB_SUCCESS || !*context)
            return LIBRDP_STATUS_IO_ERROR;
    }
    count = ops->get_device_list(ops->user_data, *context, &list);
    if (count < 0)
        return LIBRDP_STATUS_IO_ERROR;
    for (ssize_t i = 0; i < count; i++)
    {
        libusb_device* device = list[i];
        struct libusb_device_descriptor descriptor;
        int matched = 0;

        libusb_device_handle* handle = NULL;
        int open_rc = 0;

        if (ops->get_device_descriptor(ops->user_data, device, &descriptor) != LIBUSB_SUCCESS)
            continue;
        if (request->bus_mode)
        {
            matched = ops->get_bus_number(ops->user_data, device) == request->first &&
                      ops->get_device_address(ops->user_data, device) == request->second;
        }
        else
        {
            matched = descriptor.idVendor == request->first &&
                      descriptor.idProduct == request->second;
        }
        if (!matched)
            continue;
        rdp_usb_backend_match_init(match, device, &descriptor, ops);
        status = rdp_usb_backend_check_class_policy(request, device, &descriptor, ops);
        if (status != LIBRDP_STATUS_OK)
            break;
        open_rc = ops->open(ops->user_data, device, &handle);
        if (open_rc != LIBUSB_SUCCESS || !handle)
        {
            status = open_rc == LIBUSB_SUCCESS ? LIBRDP_STATUS_IO_ERROR :
                                                rdp_usb_backend_open_error(open_rc);
            break;
        }

        out->handle = handle;
        out->interface_id = request->interface_id;
        out->descriptor = descriptor;
        out->bus_number = ops->get_bus_number(ops->user_data, device);
        out->device_address = ops->get_device_address(ops->user_data, device);
        out->active = 1;
        status = LIBRDP_STATUS_OK;
        break;
    }
    ops->free_device_list(ops->user_data, list, 1);
    return status;
}

uint32_t rdp_usb_backend_reset_device(rdp_usb_backend_device* device)
{
    int rc = 0;

    if (!device || !device->handle)
        return RDP_USB_REDIRECTION_USBD_STATUS_DEVICE_GONE;
    rc = libusb_reset_device(device->handle);
    return rc == LIBUSB_SUCCESS ? RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS :
                                  rdp_usb_backend_libusb_status(rc);
}

uint32_t rdp_usb_backend_claim_endpoint(rdp_usb_backend_device* device,
                                        uint8_t endpoint,
                                        uint8_t* transfer_type)
{
    libusb_device* usb_device = NULL;
    struct libusb_config_descriptor* config = NULL;
    int found = 0;
    int interface_number = -1;
    int type = LIBUSB_TRANSFER_TYPE_BULK;
    int rc = 0;

    if (!device || !device->handle || !transfer_type)
        return RDP_USB_REDIRECTION_USBD_STATUS_DEVICE_GONE;
    usb_device = libusb_get_device(device->handle);
    rc = libusb_get_active_config_descriptor(usb_device, &config);
    if (rc != LIBUSB_SUCCESS)
        return rdp_usb_backend_libusb_status(rc);
    for (uint8_t i = 0; i < config->bNumInterfaces && !found; i++)
    {
        const struct libusb_interface* iface = &config->interface[i];

        for (int j = 0; j < iface->num_altsetting && !found; j++)
        {
            const struct libusb_interface_descriptor* alt = &iface->altsetting[j];

            for (uint8_t k = 0; k < alt->bNumEndpoints; k++)
            {
                const struct libusb_endpoint_descriptor* ep = &alt->endpoint[k];

                if (ep->bEndpointAddress == endpoint)
                {
                    interface_number = alt->bInterfaceNumber;
                    type = ep->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK;
                    found = 1;
                    break;
                }
            }
        }
    }
    libusb_free_config_descriptor(config);
    if (!found || interface_number < 0 || interface_number >= (int)sizeof(device->claimed_interfaces))
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    if (!device->claimed_interfaces[interface_number])
    {
        if (libusb_kernel_driver_active(device->handle, interface_number) == 1)
            (void)libusb_detach_kernel_driver(device->handle, interface_number);
        rc = libusb_claim_interface(device->handle, interface_number);
        if (rc != LIBUSB_SUCCESS)
            return rdp_usb_backend_libusb_status(rc);
        device->claimed_interfaces[interface_number] = 1;
    }
    *transfer_type = (uint8_t)type;
    return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
}

uint32_t rdp_usb_backend_select_interface(rdp_usb_backend_device* device,
                                          uint8_t interface_number,
                                          uint8_t alternate_setting)
{
    int rc = 0;

    if (!device || !device->handle || interface_number >= sizeof(device->claimed_interfaces))
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    if (!device->claimed_interfaces[interface_number])
    {
        if (libusb_kernel_driver_active(device->handle, interface_number) == 1)
            (void)libusb_detach_kernel_driver(device->handle, interface_number);
        rc = libusb_claim_interface(device->handle, interface_number);
        if (rc != LIBUSB_SUCCESS)
            return rdp_usb_backend_libusb_status(rc);
        device->claimed_interfaces[interface_number] = 1;
    }
    rc = libusb_set_interface_alt_setting(device->handle,
                                          interface_number,
                                          alternate_setting);
    return rc == LIBUSB_SUCCESS ? RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS :
                                  rdp_usb_backend_libusb_status(rc);
}

/*
 * Pump a submitted libusb transfer until callback completion or timeout.
 * Timeout cancellation is followed by event handling until libusb reports the
 * cancellation, so transfer storage can be freed deterministically.
 */
static uint32_t rdp_usb_backend_wait_transfer(libusb_context* context,
                                              struct libusb_transfer* transfer,
                                              rdp_usb_backend_async_state* state,
                                              uint32_t timeout_ms)
{
    uint64_t start_ms = 0;
    int rc = 0;

    if (!context || !transfer || !state)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    start_ms = rdp_usb_backend_now_ms();
    rc = libusb_submit_transfer(transfer);
    if (rc != LIBUSB_SUCCESS)
        return rdp_usb_backend_libusb_status(rc);
    while (!state->completed)
    {
        struct timeval tv;
        uint64_t now_ms = rdp_usb_backend_now_ms();

        if (timeout_ms > 0 && now_ms - start_ms >= timeout_ms)
        {
            (void)libusb_cancel_transfer(transfer);
            while (!state->completed)
            {
                tv.tv_sec = 0;
                tv.tv_usec = 10000;
                rc = libusb_handle_events_timeout_completed(context, &tv, &state->completed);
                if (rc != LIBUSB_SUCCESS && rc != LIBUSB_ERROR_INTERRUPTED)
                    return rdp_usb_backend_libusb_status(rc);
            }
            return RDP_USB_REDIRECTION_USBD_STATUS_TIMEOUT;
        }
        tv.tv_sec = 0;
        tv.tv_usec = 10000;
        rc = libusb_handle_events_timeout_completed(context, &tv, &state->completed);
        if (rc != LIBUSB_SUCCESS && rc != LIBUSB_ERROR_INTERRUPTED)
            return rdp_usb_backend_libusb_status(rc);
    }
    return rdp_usb_backend_transfer_status(state->transfer_status);
}

uint32_t rdp_usb_backend_control_transfer(libusb_context* context,
                                          libusb_device_handle* handle,
                                          uint8_t request_type,
                                          uint8_t request,
                                          uint16_t value,
                                          uint16_t index,
                                          uint8_t* data,
                                          uint32_t length,
                                          uint32_t timeout_ms,
                                          uint32_t* actual_length)
{
    struct libusb_transfer* transfer = NULL;
    rdp_usb_backend_async_state state;
    uint8_t* buffer = NULL;
    uint32_t status = RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
    size_t total = 0;

    if (!context || !handle || (!data && length > 0) || !actual_length || length > UINT16_MAX)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    *actual_length = 0;
    total = LIBUSB_CONTROL_SETUP_SIZE + (size_t)length;
    buffer = (uint8_t*)calloc(1, total ? total : 1u);
    if (!buffer)
        return RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
    transfer = libusb_alloc_transfer(0);
    if (!transfer)
    {
        free(buffer);
        return RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
    }
    libusb_fill_control_setup(buffer, request_type, request, value, index, (uint16_t)length);
    if ((request_type & LIBUSB_ENDPOINT_IN) == 0 && length > 0)
        memcpy(buffer + LIBUSB_CONTROL_SETUP_SIZE, data, length);
    memset(&state, 0, sizeof(state));
    libusb_fill_control_transfer(transfer,
                                 handle,
                                 buffer,
                                 rdp_usb_backend_transfer_callback,
                                 &state,
                                 timeout_ms);
    status = rdp_usb_backend_wait_transfer(context, transfer, &state, timeout_ms);
    if (status == RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
    {
        if (state.actual_length > 0 && (request_type & LIBUSB_ENDPOINT_IN) != 0)
        {
            uint32_t actual = (uint32_t)state.actual_length;

            if (actual > length)
                actual = length;
            memcpy(data, libusb_control_transfer_get_data(transfer), actual);
            *actual_length = actual;
        }
        else if ((request_type & LIBUSB_ENDPOINT_IN) == 0)
        {
            *actual_length = (uint32_t)state.actual_length;
        }
    }
    libusb_free_transfer(transfer);
    free(buffer);
    return status;
}

uint32_t rdp_usb_backend_bulk_or_interrupt_transfer(libusb_context* context,
                                                    libusb_device_handle* handle,
                                                    uint8_t endpoint,
                                                    uint8_t transfer_type,
                                                    uint8_t* data,
                                                    uint32_t length,
                                                    uint32_t timeout_ms,
                                                    uint32_t* actual_length)
{
    struct libusb_transfer* transfer = NULL;
    rdp_usb_backend_async_state state;
    uint32_t status = RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;

    if (!context || !handle || (!data && length > 0) || !actual_length || length > INT32_MAX)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    *actual_length = 0;
    transfer = libusb_alloc_transfer(0);
    if (!transfer)
        return RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
    memset(&state, 0, sizeof(state));
    if (transfer_type == LIBUSB_TRANSFER_TYPE_INTERRUPT)
        libusb_fill_interrupt_transfer(transfer,
                                       handle,
                                       endpoint,
                                       data,
                                       (int)length,
                                       rdp_usb_backend_transfer_callback,
                                       &state,
                                       timeout_ms);
    else
        libusb_fill_bulk_transfer(transfer,
                                  handle,
                                  endpoint,
                                  data,
                                  (int)length,
                                  rdp_usb_backend_transfer_callback,
                                  &state,
                                  timeout_ms);
    status = rdp_usb_backend_wait_transfer(context, transfer, &state, timeout_ms);
    if (status == RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS && state.actual_length >= 0)
        *actual_length = (uint32_t)state.actual_length;
    libusb_free_transfer(transfer);
    return status;
}

/*
 * libusb lays isochronous packets out consecutively according to each packet
 * length. Requiring the wire offsets to describe that same canonical layout
 * prevents gaps, overlap, and aggregate lengths that escape the transfer
 * buffer even when every packet length is individually in range.
 */
uint32_t rdp_usb_backend_validate_iso_layout(
    uint32_t length,
    const rdp_usb_backend_iso_packet* packets,
    uint32_t packet_count)
{
    uint32_t expected_offset = 0;

    if (!packets || packet_count == 0 || packet_count > (uint32_t)INT_MAX ||
        length > (uint32_t)INT_MAX)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    for (uint32_t i = 0; i < packet_count; i++)
    {
        if (packets[i].offset != expected_offset ||
            packets[i].length > length - expected_offset)
            return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
        expected_offset += packets[i].length;
    }
    return expected_offset == length ? RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS :
                                       RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
}

uint32_t rdp_usb_backend_iso_transfer(libusb_context* context,
                                      libusb_device_handle* handle,
                                      uint8_t endpoint,
                                      uint8_t* data,
                                      uint32_t length,
                                      rdp_usb_backend_iso_packet* packets,
                                      uint32_t packet_count,
                                      uint32_t timeout_ms,
                                      uint32_t* actual_length)
{
    struct libusb_transfer* transfer = NULL;
    rdp_usb_backend_async_state state;
    uint32_t status = RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
    uint32_t actual_total = 0;

    if (!context || !handle || (!data && length > 0) || !packets || packet_count == 0 ||
        packet_count > (uint32_t)INT_MAX || length > (uint32_t)INT_MAX || !actual_length)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    *actual_length = 0;
    status = rdp_usb_backend_validate_iso_layout(length, packets, packet_count);
    if (status != RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
        return status;
    transfer = libusb_alloc_transfer((int)packet_count);
    if (!transfer)
        return RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
    memset(&state, 0, sizeof(state));
    libusb_fill_iso_transfer(transfer,
                             handle,
                             endpoint,
                             data,
                             (int)length,
                             (int)packet_count,
                             rdp_usb_backend_transfer_callback,
                             &state,
                             timeout_ms);
    for (uint32_t i = 0; i < packet_count; i++)
    {
        packets[i].actual_length = 0;
        packets[i].status = RDP_USB_REDIRECTION_USBD_STATUS_DEV_NOT_RESPONDING;
        transfer->iso_packet_desc[i].length = (unsigned int)packets[i].length;
        transfer->iso_packet_desc[i].actual_length = 0;
    }
    status = rdp_usb_backend_wait_transfer(context, transfer, &state, timeout_ms);
    if (status == RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
    {
        actual_total = 0;
        for (uint32_t i = 0; i < packet_count; i++)
        {
            uint32_t packet_status =
                rdp_usb_backend_transfer_status(transfer->iso_packet_desc[i].status);
            uint32_t packet_len = (uint32_t)transfer->iso_packet_desc[i].actual_length;
            unsigned char* packet_buffer =
                libusb_get_iso_packet_buffer_simple(transfer, (unsigned int)i);

            packets[i].status = packet_status;
            packets[i].actual_length = packet_len;
            if (packet_status == RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS &&
                packet_len <= length - actual_total)
            {
                if (packet_len > 0 && data && packet_buffer &&
                    packet_buffer != data + actual_total)
                    memmove(data + actual_total, packet_buffer, packet_len);
                actual_total += packet_len;
            }
        }
        *actual_length = actual_total;
    }
    libusb_free_transfer(transfer);
    return status;
}

#endif
