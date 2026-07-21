/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic USB redirection lifecycle smoke.
 * Coverage: every URB function accepted by the client dispatcher, asynchronous
 * completion, timeout, cancellation, unplug, retract, and close races.
 * Bug classes: parser/backend drift, skipped URB branches, worker lifetime
 * errors, incomplete cancellation, and host-device dependencies in tests.
 * Determinism: the provider is in-process and never enumerates host USB devices.
 */

#include <librdp/librdp.h>

#include "channels/usb_redirection.h"
#include "client/session_internal.h"
#include "client/usb_backend.h"
#include "common/buffer.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define CHECK(expr)                                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

#define TEST_USB_INTERFACE_ID 9u

typedef enum test_usb_virtual_mode
{
    TEST_USB_VIRTUAL_SUCCESS = 0,
    TEST_USB_VIRTUAL_TIMEOUT = 1,
    TEST_USB_VIRTUAL_WAIT_CANCEL = 2,
    TEST_USB_VIRTUAL_UNPLUG = 3
} test_usb_virtual_mode;

typedef struct test_usb_virtual_provider
{
    atomic_int mode;
    atomic_uint active;
    atomic_uint cancel_observed;
    atomic_uint release_calls;
    atomic_uint reset_calls;
    atomic_uint configuration_calls;
    atomic_uint interface_info_calls;
    atomic_uint select_interface_calls;
    atomic_uint claim_endpoint_calls;
    atomic_uint clear_halt_calls;
    atomic_uint descriptor_calls;
    atomic_uint control_calls;
    atomic_uint bulk_calls;
    atomic_uint iso_calls;
    atomic_uint timeout_calls;
    atomic_uint unplug_calls;
    atomic_uint delay_ms;
} test_usb_virtual_provider;

static void test_usb_virtual_sleep_ms(uint32_t delay_ms)
{
    struct timespec requested;
    struct timespec remaining;

    requested.tv_sec = (time_t)(delay_ms / 1000u);
    requested.tv_nsec = (long)((delay_ms % 1000u) * 1000000u);
    while (nanosleep(&requested, &remaining) != 0 && errno == EINTR)
        requested = remaining;
}

static uint32_t test_usb_virtual_terminal_status(
    test_usb_virtual_provider* provider,
    const rdp_usb_backend_wait_control* control)
{
    test_usb_virtual_mode mode;
    uint32_t delay_ms = 0;

    if (!provider)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    mode = (test_usb_virtual_mode)atomic_load_explicit(&provider->mode,
                                                       memory_order_acquire);
    if (mode == TEST_USB_VIRTUAL_TIMEOUT)
    {
        atomic_fetch_add_explicit(&provider->timeout_calls, 1u,
                                  memory_order_relaxed);
        return RDP_USB_REDIRECTION_USBD_STATUS_TIMEOUT;
    }
    if (mode == TEST_USB_VIRTUAL_UNPLUG)
    {
        atomic_fetch_add_explicit(&provider->unplug_calls, 1u,
                                  memory_order_relaxed);
        return RDP_USB_REDIRECTION_USBD_STATUS_DEVICE_GONE;
    }
    if (mode == TEST_USB_VIRTUAL_WAIT_CANCEL)
    {
        atomic_store_explicit(&provider->active, 1u, memory_order_release);
        for (uint32_t waited_ms = 0; waited_ms < 2000u; waited_ms++)
        {
            if (control && control->is_cancelled &&
                control->is_cancelled(control->user_data))
            {
                atomic_fetch_add_explicit(&provider->cancel_observed, 1u,
                                          memory_order_relaxed);
                atomic_store_explicit(&provider->active, 0u,
                                      memory_order_release);
                return RDP_USB_REDIRECTION_USBD_STATUS_TIMEOUT;
            }
            test_usb_virtual_sleep_ms(1u);
        }
        atomic_store_explicit(&provider->active, 0u, memory_order_release);
        return RDP_USB_REDIRECTION_USBD_STATUS_DEV_NOT_RESPONDING;
    }
    delay_ms = atomic_load_explicit(&provider->delay_ms,
                                    memory_order_acquire);
    if (delay_ms > 0)
        test_usb_virtual_sleep_ms(delay_ms);
    return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
}

static void test_usb_virtual_release(void* user_data,
                                     rdp_usb_backend_device* device)
{
    test_usb_virtual_provider* provider =
        (test_usb_virtual_provider*)user_data;

    (void)device;
    if (provider)
        atomic_fetch_add_explicit(&provider->release_calls, 1u,
                                  memory_order_relaxed);
}

static uint32_t test_usb_virtual_reset(void* user_data,
                                       rdp_usb_backend_device* device)
{
    test_usb_virtual_provider* provider =
        (test_usb_virtual_provider*)user_data;

    (void)device;
    if (!provider)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    atomic_fetch_add_explicit(&provider->reset_calls, 1u,
                              memory_order_relaxed);
    return test_usb_virtual_terminal_status(provider, NULL);
}

static uint32_t test_usb_virtual_set_configuration(
    void* user_data,
    rdp_usb_backend_device* device,
    uint8_t configuration)
{
    test_usb_virtual_provider* provider =
        (test_usb_virtual_provider*)user_data;

    (void)device;
    if (!provider || configuration != 1u)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    atomic_fetch_add_explicit(&provider->configuration_calls, 1u,
                              memory_order_relaxed);
    return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
}

static uint32_t test_usb_virtual_get_interface_info(
    void* user_data,
    rdp_usb_backend_device* device,
    uint8_t interface_number,
    uint8_t alternate_setting,
    rdp_usb_backend_interface_info* info)
{
    test_usb_virtual_provider* provider =
        (test_usb_virtual_provider*)user_data;

    (void)device;
    if (!provider || !info || interface_number != 0u ||
        alternate_setting != 0u)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    memset(info, 0, sizeof(*info));
    info->interface_number = 0u;
    info->alternate_setting = 0u;
    info->interface_class = LIBUSB_CLASS_VENDOR_SPEC;
    info->endpoint_count = 3u;
    info->endpoints[0].max_packet_size = 64u;
    info->endpoints[0].address = 0x81u;
    info->endpoints[0].transfer_type = LIBUSB_TRANSFER_TYPE_BULK;
    info->endpoints[1].max_packet_size = 16u;
    info->endpoints[1].address = 0x82u;
    info->endpoints[1].interval = 1u;
    info->endpoints[1].transfer_type = LIBUSB_TRANSFER_TYPE_INTERRUPT;
    info->endpoints[2].max_packet_size = 256u;
    info->endpoints[2].address = 0x83u;
    info->endpoints[2].interval = 1u;
    info->endpoints[2].transfer_type = LIBUSB_TRANSFER_TYPE_ISOCHRONOUS;
    atomic_fetch_add_explicit(&provider->interface_info_calls, 1u,
                              memory_order_relaxed);
    return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
}

static uint32_t test_usb_virtual_select_interface(
    void* user_data,
    rdp_usb_backend_device* device,
    uint8_t interface_number,
    uint8_t alternate_setting)
{
    test_usb_virtual_provider* provider =
        (test_usb_virtual_provider*)user_data;

    (void)device;
    if (!provider || interface_number != 0u || alternate_setting != 0u)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    atomic_fetch_add_explicit(&provider->select_interface_calls, 1u,
                              memory_order_relaxed);
    return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
}

static uint32_t test_usb_virtual_claim_endpoint(
    void* user_data,
    rdp_usb_backend_device* device,
    uint8_t endpoint,
    uint8_t* transfer_type)
{
    test_usb_virtual_provider* provider =
        (test_usb_virtual_provider*)user_data;
    uint32_t status = RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;

    (void)device;
    if (!provider || !transfer_type)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    atomic_fetch_add_explicit(&provider->claim_endpoint_calls, 1u,
                              memory_order_relaxed);
    status = test_usb_virtual_terminal_status(provider, NULL);
    if (status != RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
        return status;
    if (endpoint == 0x83u)
        *transfer_type = LIBUSB_TRANSFER_TYPE_ISOCHRONOUS;
    else if (endpoint == 0x82u)
        *transfer_type = LIBUSB_TRANSFER_TYPE_INTERRUPT;
    else
        *transfer_type = LIBUSB_TRANSFER_TYPE_BULK;
    return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
}

static uint32_t test_usb_virtual_clear_halt(void* user_data,
                                            rdp_usb_backend_device* device,
                                            uint8_t endpoint)
{
    test_usb_virtual_provider* provider =
        (test_usb_virtual_provider*)user_data;

    (void)device;
    if (!provider || endpoint == 0u)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    atomic_fetch_add_explicit(&provider->clear_halt_calls, 1u,
                              memory_order_relaxed);
    return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
}

static int test_usb_virtual_read_ascii_descriptor(
    void* user_data,
    rdp_usb_backend_device* device,
    uint8_t descriptor_index,
    char* out,
    size_t out_len)
{
    test_usb_virtual_provider* provider =
        (test_usb_virtual_provider*)user_data;
    const char* value = "virtual";
    size_t value_len = strlen(value);

    (void)device;
    if (!provider || descriptor_index == 0u || !out ||
        out_len <= value_len)
        return 0;
    memcpy(out, value, value_len + 1u);
    atomic_fetch_add_explicit(&provider->descriptor_calls, 1u,
                              memory_order_relaxed);
    return 1;
}

static uint32_t test_usb_virtual_control_transfer(
    void* user_data,
    rdp_usb_backend_device* device,
    uint8_t request_type,
    uint8_t request,
    uint16_t value,
    uint16_t index,
    uint8_t* data,
    uint32_t length,
    uint32_t timeout_ms,
    const rdp_usb_backend_wait_control* control,
    uint32_t* actual_length)
{
    test_usb_virtual_provider* provider =
        (test_usb_virtual_provider*)user_data;
    uint32_t status = RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;

    (void)device;
    (void)index;
    (void)timeout_ms;
    if (!provider || (!data && length > 0) || !actual_length)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    atomic_fetch_add_explicit(&provider->control_calls, 1u,
                              memory_order_relaxed);
    *actual_length = 0u;
    status = test_usb_virtual_terminal_status(provider, control);
    if (status != RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
        return status;
    if ((request_type & LIBUSB_ENDPOINT_IN) != 0 && length > 0)
    {
        for (uint32_t i = 0; i < length; i++)
            data[i] = (uint8_t)(0x40u + (i & 0x1fu));
        if (request == LIBUSB_REQUEST_GET_DESCRIPTOR && value == 0x03eeu &&
            length >= 18u)
            data[16] = 0x5au;
    }
    *actual_length = length;
    return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
}

static uint32_t test_usb_virtual_bulk_or_interrupt_transfer(
    void* user_data,
    rdp_usb_backend_device* device,
    uint8_t endpoint,
    uint8_t transfer_type,
    uint8_t* data,
    uint32_t length,
    uint32_t timeout_ms,
    const rdp_usb_backend_wait_control* control,
    uint32_t* actual_length)
{
    test_usb_virtual_provider* provider =
        (test_usb_virtual_provider*)user_data;
    uint32_t status = RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;

    (void)device;
    (void)transfer_type;
    (void)timeout_ms;
    if (!provider || endpoint == 0u || (!data && length > 0) ||
        !actual_length)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    atomic_fetch_add_explicit(&provider->bulk_calls, 1u,
                              memory_order_relaxed);
    *actual_length = 0u;
    status = test_usb_virtual_terminal_status(provider, control);
    if (status != RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
        return status;
    if ((endpoint & LIBUSB_ENDPOINT_IN) != 0)
    {
        for (uint32_t i = 0; i < length; i++)
            data[i] = (uint8_t)(0x80u + (i & 0x1fu));
    }
    *actual_length = length;
    return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
}

static uint32_t test_usb_virtual_iso_transfer(
    void* user_data,
    rdp_usb_backend_device* device,
    uint8_t endpoint,
    uint8_t* data,
    uint32_t length,
    rdp_usb_backend_iso_packet* packets,
    uint32_t packet_count,
    uint32_t timeout_ms,
    const rdp_usb_backend_wait_control* control,
    uint32_t* actual_length)
{
    test_usb_virtual_provider* provider =
        (test_usb_virtual_provider*)user_data;
    uint32_t status = RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;

    (void)device;
    (void)timeout_ms;
    if (!provider || endpoint == 0u || (!data && length > 0) || !packets ||
        packet_count == 0u || !actual_length)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    atomic_fetch_add_explicit(&provider->iso_calls, 1u,
                              memory_order_relaxed);
    *actual_length = 0u;
    status = test_usb_virtual_terminal_status(provider, control);
    if (status != RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
        return status;
    for (uint32_t i = 0; i < packet_count; i++)
    {
        packets[i].actual_length = packets[i].length;
        packets[i].status = RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
    }
    if ((endpoint & LIBUSB_ENDPOINT_IN) != 0)
    {
        for (uint32_t i = 0; i < length; i++)
            data[i] = (uint8_t)(0xc0u + (i & 0x1fu));
    }
    *actual_length = length;
    return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
}

static const rdp_usb_backend_device_ops TEST_USB_VIRTUAL_OPS = {
    test_usb_virtual_release,
    test_usb_virtual_reset,
    test_usb_virtual_set_configuration,
    test_usb_virtual_get_interface_info,
    test_usb_virtual_select_interface,
    test_usb_virtual_claim_endpoint,
    test_usb_virtual_clear_halt,
    test_usb_virtual_read_ascii_descriptor,
    test_usb_virtual_control_transfer,
    test_usb_virtual_bulk_or_interrupt_transfer,
    test_usb_virtual_iso_transfer
};

static void test_usb_virtual_provider_init(test_usb_virtual_provider* provider)
{
    memset(provider, 0, sizeof(*provider));
    atomic_init(&provider->mode, TEST_USB_VIRTUAL_SUCCESS);
    atomic_init(&provider->active, 0u);
    atomic_init(&provider->cancel_observed, 0u);
    atomic_init(&provider->release_calls, 0u);
    atomic_init(&provider->reset_calls, 0u);
    atomic_init(&provider->configuration_calls, 0u);
    atomic_init(&provider->interface_info_calls, 0u);
    atomic_init(&provider->select_interface_calls, 0u);
    atomic_init(&provider->claim_endpoint_calls, 0u);
    atomic_init(&provider->clear_halt_calls, 0u);
    atomic_init(&provider->descriptor_calls, 0u);
    atomic_init(&provider->control_calls, 0u);
    atomic_init(&provider->bulk_calls, 0u);
    atomic_init(&provider->iso_calls, 0u);
    atomic_init(&provider->timeout_calls, 0u);
    atomic_init(&provider->unplug_calls, 0u);
    atomic_init(&provider->delay_ms, 0u);
}

static void test_usb_virtual_attach(librdp_session* session,
                                    test_usb_virtual_provider* provider)
{
    rdp_usb_backend_device* device = &session->usb_devices[0];

    memset(device, 0, sizeof(*device));
    device->active = 1u;
    device->interface_id = TEST_USB_INTERFACE_ID;
    device->descriptor.idVendor = 0x1209u;
    device->descriptor.idProduct = 0x0001u;
    device->descriptor.bcdUSB = 0x0200u;
    device->descriptor.bcdDevice = 0x0100u;
    device->descriptor.bDeviceClass = LIBUSB_CLASS_VENDOR_SPEC;
    device->descriptor.iManufacturer = 1u;
    device->descriptor.iProduct = 2u;
    device->descriptor.iSerialNumber = 3u;
    device->descriptor.bNumConfigurations = 1u;
    device->bus_number = 1u;
    device->device_address = 1u;
    device->ops = &TEST_USB_VIRTUAL_OPS;
    device->ops_user_data = provider;
    session->usb_redirection_ready = 1u;
}

static librdp_status test_usb_virtual_append_ms_interface(
    rdp_buffer* payload)
{
    librdp_status status = rdp_buffer_append_u32_le(payload, 0u);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(payload, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(payload, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(payload, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(payload, 0u);
    return status;
}

/*
 * Build the smallest structurally valid payload for every URB accepted by the
 * runtime dispatcher. The corpus exercises per-function length checks and
 * direction-specific fields without relying on captured device traffic.
 */
static librdp_status test_usb_virtual_build_urb_payload(
    uint16_t function,
    rdp_buffer* payload,
    uint32_t* transfer_function)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t descriptor_get = 0u;

    if (!payload || !transfer_function)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *transfer_function = RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST;
    switch (function)
    {
        case RDP_USB_REDIRECTION_URB_SELECT_CONFIGURATION:
            status = rdp_buffer_append_u8(payload, 1u);
            for (unsigned int i = 0; status == LIBRDP_STATUS_OK && i < 3u; i++)
                status = rdp_buffer_append_u8(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 1u);
            if (status == LIBRDP_STATUS_OK)
                status = test_usb_virtual_append_ms_interface(payload);
            if (status == LIBRDP_STATUS_OK)
            {
                static const uint8_t configuration[] = {
                    9u, 2u, 9u, 0u, 1u, 1u
                };

                status = rdp_buffer_append(payload,
                                           configuration,
                                           sizeof(configuration));
            }
            break;
        case RDP_USB_REDIRECTION_URB_SELECT_INTERFACE:
            status = rdp_buffer_append_u32_le(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = test_usb_virtual_append_ms_interface(payload);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 0u);
            break;
        case RDP_USB_REDIRECTION_URB_PIPE_REQUEST:
        case RDP_USB_REDIRECTION_URB_SYNC_RESET_PIPE_AND_CLEAR_STALL:
        case RDP_USB_REDIRECTION_URB_SYNC_RESET_PIPE:
        case RDP_USB_REDIRECTION_URB_SYNC_CLEAR_STALL:
            status = rdp_buffer_append_u32_le(payload, 1u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 0u);
            break;
        case RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER:
        case RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER_EX:
            status = rdp_buffer_append_u32_le(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(
                    payload, RDP_USB_REDIRECTION_TRANSFER_DIRECTION);
            if (status == LIBRDP_STATUS_OK &&
                function == RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER_EX)
                status = rdp_buffer_append_u32_le(payload, 25u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u8(payload, LIBUSB_ENDPOINT_IN);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u8(payload, 0x55u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(payload, 0x0102u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(payload, 0x0304u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(payload, 4u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 4u);
            break;
        case RDP_USB_REDIRECTION_URB_GET_DESCRIPTOR_FROM_DEVICE:
        case RDP_USB_REDIRECTION_URB_GET_DESCRIPTOR_FROM_INTERFACE:
        case RDP_USB_REDIRECTION_URB_GET_DESCRIPTOR_FROM_ENDPOINT:
            descriptor_get = 1u;
            /* fall through */
        case RDP_USB_REDIRECTION_URB_SET_DESCRIPTOR_TO_DEVICE:
        case RDP_USB_REDIRECTION_URB_SET_DESCRIPTOR_TO_INTERFACE:
        case RDP_USB_REDIRECTION_URB_SET_DESCRIPTOR_TO_ENDPOINT:
            if (!descriptor_get)
                *transfer_function =
                    RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST;
            status = rdp_buffer_append_u8(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u8(payload, 1u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 4u);
            if (status == LIBRDP_STATUS_OK && !descriptor_get)
            {
                static const uint8_t descriptor[] = {1u, 2u, 3u, 4u};

                status = rdp_buffer_append(payload, descriptor,
                                           sizeof(descriptor));
            }
            break;
        case RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_DEVICE:
        case RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_INTERFACE:
        case RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_ENDPOINT:
        case RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_OTHER:
        case RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_DEVICE:
        case RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_INTERFACE:
        case RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_ENDPOINT:
        case RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_OTHER:
            *transfer_function =
                RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST;
            status = rdp_buffer_append_u16_le(payload, 1u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 0u);
            break;
        case RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_DEVICE:
        case RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_INTERFACE:
        case RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_ENDPOINT:
        case RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_OTHER:
        case RDP_USB_REDIRECTION_URB_CONTROL_GET_INTERFACE_REQUEST:
            status = rdp_buffer_append_u16_le(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 4u);
            break;
        case RDP_USB_REDIRECTION_URB_VENDOR_DEVICE:
        case RDP_USB_REDIRECTION_URB_VENDOR_INTERFACE:
        case RDP_USB_REDIRECTION_URB_VENDOR_ENDPOINT:
        case RDP_USB_REDIRECTION_URB_VENDOR_OTHER:
        case RDP_USB_REDIRECTION_URB_CLASS_DEVICE:
        case RDP_USB_REDIRECTION_URB_CLASS_INTERFACE:
        case RDP_USB_REDIRECTION_URB_CLASS_ENDPOINT:
        case RDP_USB_REDIRECTION_URB_CLASS_OTHER:
            status = rdp_buffer_append_u32_le(
                payload, RDP_USB_REDIRECTION_TRANSFER_DIRECTION);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u8(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u8(payload, 0x44u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(payload, 0x0102u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(payload, 0x0304u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 4u);
            break;
        case RDP_USB_REDIRECTION_URB_CONTROL_GET_CONFIGURATION_REQUEST:
            status = rdp_buffer_append_u32_le(payload, 4u);
            break;
        case RDP_USB_REDIRECTION_URB_BULK_OR_INTERRUPT_TRANSFER:
            status = rdp_buffer_append_u32_le(payload, 1u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(
                    payload, RDP_USB_REDIRECTION_TRANSFER_DIRECTION);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 4u);
            break;
        case RDP_USB_REDIRECTION_URB_ISOCH_TRANSFER:
            status = rdp_buffer_append_u32_le(payload, 3u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(
                    payload, RDP_USB_REDIRECTION_TRANSFER_DIRECTION);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 1u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 1u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 4u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 4u);
            break;
        case RDP_USB_REDIRECTION_URB_GET_OS_FEATURE_DESCRIPTOR_REQUEST:
            status = rdp_buffer_append_u8(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u8(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u8(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(payload, 4u);
            for (unsigned int i = 0; status == LIBRDP_STATUS_OK && i < 3u; i++)
                status = rdp_buffer_append_u8(payload, 0u);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(payload, 4u);
            break;
        case RDP_USB_REDIRECTION_URB_GET_CURRENT_FRAME_NUMBER:
            break;
        default:
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
    }
    return status;
}

static librdp_status test_usb_virtual_write_transfer(
    rdp_buffer* packet,
    uint16_t function,
    uint32_t request_id)
{
    rdp_buffer payload;
    rdp_buffer urb;
    uint32_t transfer_function = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    rdp_buffer_init(&urb);
    status = test_usb_virtual_build_urb_payload(function,
                                                &payload,
                                                &transfer_function);
    if (status == LIBRDP_STATUS_OK &&
        payload.length > UINT16_MAX - 8u)
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(
            &urb, (uint16_t)(8u + payload.length));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&urb, function);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&urb, request_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&urb, payload.data, payload.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_usb_redirection_write_header(
            packet, TEST_USB_INTERFACE_ID, RDP_USB_REDIRECTION_MASK_PROXY,
            request_id, 1, transfer_function);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(packet, (uint32_t)urb.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(packet, urb.data, urb.length);
    rdp_buffer_free(&urb);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status test_usb_virtual_write_control_out(
    rdp_buffer* packet,
    uint32_t request_id,
    uint16_t payload_len)
{
    rdp_buffer payload;
    rdp_buffer urb;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    rdp_buffer_init(&urb);
    status = rdp_buffer_append_u32_le(&payload, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&payload, LIBUSB_ENDPOINT_OUT);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&payload, 0x55u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 0x0102u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 0x0304u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, payload_len);
    for (uint16_t index = 0u;
         status == LIBRDP_STATUS_OK && index < payload_len;
         index++)
        status = rdp_buffer_append_u8(&payload, (uint8_t)(0xa0u + index));
    if (status == LIBRDP_STATUS_OK &&
        payload.length > UINT16_MAX - 8u)
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(
            &urb,
            (uint16_t)(8u + payload.length));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(
            &urb,
            RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&urb, request_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&urb, payload.data, payload.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_usb_redirection_write_header(
            packet,
            TEST_USB_INTERFACE_ID,
            RDP_USB_REDIRECTION_MASK_PROXY,
            request_id,
            1,
            RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(packet, (uint32_t)urb.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(packet, urb.data, urb.length);
    rdp_buffer_free(&urb);
    rdp_buffer_free(&payload);
    return status;
}

static int test_usb_virtual_drain(librdp_session* session,
                                  uint32_t timeout_ms)
{
    uint32_t waited_ms = 0u;

    while (rdp_session_usb_outstanding_requests(session) > 0u &&
           waited_ms < timeout_ms)
    {
        test_usb_virtual_sleep_ms(1u);
        if (rdp_session_usb_dispatch_completions(session) !=
            LIBRDP_STATUS_OK)
            return 0;
        waited_ms++;
    }
    return rdp_session_usb_outstanding_requests(session) == 0u;
}

static int test_usb_virtual_wait_active(
    const test_usb_virtual_provider* provider)
{
    for (uint32_t waited_ms = 0; waited_ms < 1000u; waited_ms++)
    {
        if (atomic_load_explicit(&provider->active,
                                 memory_order_acquire) != 0u)
            return 1;
        test_usb_virtual_sleep_ms(1u);
    }
    return 0;
}

/*
 * Drive every advertised URB through the worker and provider boundary, then
 * cover timeout, cancellation, unplug, retract and release ordering. Counter
 * assertions detect dispatch omissions and accidental fallback to libusb.
 */
static int test_usb_virtual_all_urbs(void)
{
    static const uint16_t functions[] = {
        RDP_USB_REDIRECTION_URB_SELECT_CONFIGURATION,
        RDP_USB_REDIRECTION_URB_SELECT_INTERFACE,
        RDP_USB_REDIRECTION_URB_PIPE_REQUEST,
        RDP_USB_REDIRECTION_URB_GET_CURRENT_FRAME_NUMBER,
        RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER,
        RDP_USB_REDIRECTION_URB_BULK_OR_INTERRUPT_TRANSFER,
        RDP_USB_REDIRECTION_URB_ISOCH_TRANSFER,
        RDP_USB_REDIRECTION_URB_GET_DESCRIPTOR_FROM_DEVICE,
        RDP_USB_REDIRECTION_URB_SET_DESCRIPTOR_TO_DEVICE,
        RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_DEVICE,
        RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_INTERFACE,
        RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_ENDPOINT,
        RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_DEVICE,
        RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_INTERFACE,
        RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_ENDPOINT,
        RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_DEVICE,
        RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_INTERFACE,
        RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_ENDPOINT,
        RDP_USB_REDIRECTION_URB_VENDOR_DEVICE,
        RDP_USB_REDIRECTION_URB_VENDOR_INTERFACE,
        RDP_USB_REDIRECTION_URB_VENDOR_ENDPOINT,
        RDP_USB_REDIRECTION_URB_CLASS_DEVICE,
        RDP_USB_REDIRECTION_URB_CLASS_INTERFACE,
        RDP_USB_REDIRECTION_URB_CLASS_ENDPOINT,
        RDP_USB_REDIRECTION_URB_SYNC_RESET_PIPE_AND_CLEAR_STALL,
        RDP_USB_REDIRECTION_URB_CLASS_OTHER,
        RDP_USB_REDIRECTION_URB_VENDOR_OTHER,
        RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_OTHER,
        RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_OTHER,
        RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_OTHER,
        RDP_USB_REDIRECTION_URB_GET_DESCRIPTOR_FROM_ENDPOINT,
        RDP_USB_REDIRECTION_URB_SET_DESCRIPTOR_TO_ENDPOINT,
        RDP_USB_REDIRECTION_URB_CONTROL_GET_CONFIGURATION_REQUEST,
        RDP_USB_REDIRECTION_URB_CONTROL_GET_INTERFACE_REQUEST,
        RDP_USB_REDIRECTION_URB_GET_DESCRIPTOR_FROM_INTERFACE,
        RDP_USB_REDIRECTION_URB_SET_DESCRIPTOR_TO_INTERFACE,
        RDP_USB_REDIRECTION_URB_GET_OS_FEATURE_DESCRIPTOR_REQUEST,
        RDP_USB_REDIRECTION_URB_SYNC_RESET_PIPE,
        RDP_USB_REDIRECTION_URB_SYNC_CLEAR_STALL,
        RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER_EX
    };
    test_usb_virtual_provider provider;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    rdp_buffer packet;
    uint32_t request_id = 1u;
    uint32_t reset_message_id = 0u;
    uint32_t reset_request_id = 0u;

    test_usb_virtual_provider_init(&provider);
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    test_usb_virtual_attach(session, &provider);
    rdp_buffer_init(&packet);
    for (size_t i = 0; i < sizeof(functions) / sizeof(functions[0]); i++)
    {
        librdp_status write_status;

        packet.length = 0u;
        write_status = test_usb_virtual_write_transfer(&packet,
                                                       functions[i],
                                                       request_id++);
        if (write_status != LIBRDP_STATUS_OK)
            fprintf(stderr, "cannot build URB function=0x%04x status=%s\n",
                    functions[i], librdp_status_name(write_status));
        CHECK(write_status == LIBRDP_STATUS_OK);
        CHECK(rdp_session_handle_usb_redirection_message(
                  session, packet.data, packet.length) ==
              LIBRDP_STATUS_OK);
        CHECK(test_usb_virtual_drain(session, 1000u));
    }
    CHECK(atomic_load_explicit(&provider.configuration_calls,
                               memory_order_relaxed) == 1u);
    CHECK(atomic_load_explicit(&provider.select_interface_calls,
                               memory_order_relaxed) == 2u);
    CHECK(atomic_load_explicit(&provider.interface_info_calls,
                               memory_order_relaxed) == 2u);
    CHECK(atomic_load_explicit(&provider.claim_endpoint_calls,
                               memory_order_relaxed) == 2u);
    CHECK(atomic_load_explicit(&provider.clear_halt_calls,
                               memory_order_relaxed) == 3u);
    CHECK(atomic_load_explicit(&provider.control_calls,
                               memory_order_relaxed) == 32u);
    CHECK(atomic_load_explicit(&provider.bulk_calls,
                               memory_order_relaxed) == 1u);
    CHECK(atomic_load_explicit(&provider.iso_calls,
                               memory_order_relaxed) == 1u);

    packet.length = 0u;
    reset_message_id = request_id++;
    reset_request_id = request_id++;
    CHECK(rdp_usb_redirection_write_io_control(
              &packet, TEST_USB_INTERFACE_ID, reset_message_id,
              RDP_USB_REDIRECTION_FN_IO_CONTROL,
              RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_RESET_PORT,
              NULL, 0u, 0u, reset_request_id) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_usb_redirection_message(
              session, packet.data, packet.length) == LIBRDP_STATUS_OK);
    CHECK(atomic_load_explicit(&provider.reset_calls,
                               memory_order_relaxed) == 1u);

    atomic_store_explicit(&provider.delay_ms, 25u, memory_order_release);
    packet.length = 0u;
    CHECK(test_usb_virtual_write_transfer(
              &packet, RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER,
              request_id++) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_usb_redirection_message(
              session, packet.data, packet.length) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_usb_outstanding_requests(session) > 0u);
    CHECK(test_usb_virtual_drain(session, 1000u));
    atomic_store_explicit(&provider.delay_ms, 0u, memory_order_release);

    atomic_store_explicit(&provider.mode, TEST_USB_VIRTUAL_TIMEOUT,
                          memory_order_release);
    packet.length = 0u;
    CHECK(test_usb_virtual_write_transfer(
              &packet, RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER,
              request_id++) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_usb_redirection_message(
              session, packet.data, packet.length) == LIBRDP_STATUS_OK);
    CHECK(test_usb_virtual_drain(session, 1000u));
    CHECK(atomic_load_explicit(&provider.timeout_calls,
                               memory_order_relaxed) == 1u);

    atomic_store_explicit(&provider.mode, TEST_USB_VIRTUAL_WAIT_CANCEL,
                          memory_order_release);
    packet.length = 0u;
    CHECK(test_usb_virtual_write_transfer(
              &packet, RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER,
              request_id) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_usb_redirection_message(
              session, packet.data, packet.length) == LIBRDP_STATUS_OK);
    CHECK(test_usb_virtual_wait_active(&provider));
    packet.length = 0u;
    CHECK(rdp_usb_redirection_write_cancel_request(
              &packet, TEST_USB_INTERFACE_ID, request_id + 1u,
              request_id) == LIBRDP_STATUS_OK);
    request_id += 2u;
    CHECK(rdp_session_handle_usb_redirection_message(
              session, packet.data, packet.length) == LIBRDP_STATUS_OK);
    CHECK(test_usb_virtual_drain(session, 1000u));
    CHECK(atomic_load_explicit(&provider.cancel_observed,
                               memory_order_relaxed) == 1u);

    atomic_store_explicit(&provider.mode, TEST_USB_VIRTUAL_UNPLUG,
                          memory_order_release);
    packet.length = 0u;
    CHECK(test_usb_virtual_write_transfer(
              &packet, RDP_USB_REDIRECTION_URB_BULK_OR_INTERRUPT_TRANSFER,
              request_id++) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_usb_redirection_message(
              session, packet.data, packet.length) == LIBRDP_STATUS_OK);
    CHECK(test_usb_virtual_drain(session, 1000u));
    CHECK(atomic_load_explicit(&provider.unplug_calls,
                               memory_order_relaxed) == 1u);

    atomic_store_explicit(&provider.mode, TEST_USB_VIRTUAL_SUCCESS,
                          memory_order_release);
    packet.length = 0u;
    CHECK(rdp_usb_redirection_write_retract_device(
              &packet, TEST_USB_INTERFACE_ID, request_id++,
              RDP_USB_REDIRECTION_RETRACT_BLOCKED_BY_POLICY) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_usb_redirection_message(
              session, packet.data, packet.length) == LIBRDP_STATUS_OK);
    CHECK(atomic_load_explicit(&provider.release_calls,
                               memory_order_relaxed) == 1u);
    rdp_buffer_free(&packet);
    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}

static int test_usb_virtual_close_race(void)
{
    test_usb_virtual_provider provider;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    rdp_buffer packet;

    test_usb_virtual_provider_init(&provider);
    atomic_store_explicit(&provider.mode, TEST_USB_VIRTUAL_WAIT_CANCEL,
                          memory_order_release);
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    test_usb_virtual_attach(session, &provider);
    rdp_buffer_init(&packet);
    CHECK(test_usb_virtual_write_transfer(
              &packet, RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER, 1u) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_usb_redirection_message(
              session, packet.data, packet.length) == LIBRDP_STATUS_OK);
    CHECK(test_usb_virtual_wait_active(&provider));
    librdp_session_free(session);
    CHECK(atomic_load_explicit(&provider.cancel_observed,
                               memory_order_relaxed) == 1u);
    CHECK(atomic_load_explicit(&provider.release_calls,
                               memory_order_relaxed) == 1u);
    rdp_buffer_free(&packet);
    librdp_settings_free(settings);
    return 0;
}

/*
 * Accept one complete URB exactly at the device byte and pending-request caps.
 * A trailing byte and a second in-flight URB must be rejected before backend
 * execution, counted once each, and leave the first request cancellable.
 */
static int test_usb_virtual_limit_boundaries(void)
{
    test_usb_virtual_provider provider;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_limits limits;
    librdp_metrics metrics;
    rdp_buffer packet;
    rdp_buffer oversized;
    rdp_buffer cancel;
    const uint32_t first_request_id = 1u;

    test_usb_virtual_provider_init(&provider);
    rdp_buffer_init(&packet);
    rdp_buffer_init(&oversized);
    rdp_buffer_init(&cancel);
    CHECK(test_usb_virtual_write_control_out(
              &packet,
              first_request_id,
              1u) == LIBRDP_STATUS_OK);
    CHECK(test_usb_virtual_write_control_out(
              &oversized,
              first_request_id + 1u,
              2u) == LIBRDP_STATUS_OK);
    CHECK(oversized.length == packet.length + 1u);
    CHECK(packet.length < UINT32_MAX);

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_limits_init(&limits) == LIBRDP_STATUS_OK);
    limits.device_io_bytes = (uint32_t)packet.length;
    limits.pending_requests = 1u;
    CHECK(librdp_settings_set_limits(settings, &limits) ==
          LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    test_usb_virtual_attach(session, &provider);

    CHECK(rdp_session_handle_usb_redirection_message(
              session,
              oversized.data,
              oversized.length) == LIBRDP_STATUS_LIMIT_EXCEEDED);

    atomic_store_explicit(&provider.mode,
                          TEST_USB_VIRTUAL_WAIT_CANCEL,
                          memory_order_release);
    CHECK(rdp_session_handle_usb_redirection_message(
              session,
              packet.data,
              packet.length) == LIBRDP_STATUS_OK);
    CHECK(test_usb_virtual_wait_active(&provider));

    oversized.length = 0u;
    CHECK(test_usb_virtual_write_control_out(
              &oversized,
              first_request_id + 1u,
              1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_usb_redirection_message(
              session,
              oversized.data,
              oversized.length) == LIBRDP_STATUS_LIMIT_EXCEEDED);

    CHECK(rdp_usb_redirection_write_cancel_request(
              &cancel,
              TEST_USB_INTERFACE_ID,
              first_request_id + 2u,
              first_request_id) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_usb_redirection_message(
              session,
              cancel.data,
              cancel.length) == LIBRDP_STATUS_OK);
    CHECK(test_usb_virtual_drain(session, 1000u));
    CHECK(atomic_load_explicit(&provider.cancel_observed,
                               memory_order_relaxed) == 1u);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(metrics.limits_rejected == 2u);

    rdp_buffer_free(&cancel);
    rdp_buffer_free(&oversized);
    rdp_buffer_free(&packet);
    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}

int main(void)
{
    if (test_usb_virtual_all_urbs() != 0 ||
        test_usb_virtual_limit_boundaries() != 0)
        return 1;
    return test_usb_virtual_close_race();
}
