/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: core backend boundary fixtures.
 * Coverage: smartcard mock, printer backend, and USB backend boundary tests.
 * Bug classes: blocking provider timeout, cancellation, null argument handling,
 * native status mapping, and backend ownership cleanup.
 * Determinism: fixtures use in-process mocks and do not require host devices.
 */

#include <librdp/librdp.h>

#include "channels/usb_redirection.h"
#include "client/printer_backend.h"
#include "client/session_internal.h"
#include "client/smartcard_backend.h"
#include "client/usb_backend.h"

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

static void test_backend_sleep_ms(uint32_t timeout_ms)
{
    struct timespec requested;
    struct timespec remaining;

    requested.tv_sec = (time_t)(timeout_ms / 1000u);
    requested.tv_nsec = (long)((timeout_ms % 1000u) * 1000000u);
    while (nanosleep(&requested, &remaining) != 0 && errno == EINTR)
        requested = remaining;
}

static int wait_backend_atomic_uint_gt(const atomic_uint* value, unsigned int baseline, uint32_t timeout_ms)
{
    uint32_t waited_ms = 0;

    if (!value)
        return 0;
    while (waited_ms <= timeout_ms)
    {
        if (atomic_load_explicit(value, memory_order_relaxed) > baseline)
            return 1;
        test_backend_sleep_ms(5u);
        waited_ms += 5u;
    }
    return 0;
}

/*
 * Coverage: exercises the smartcard backend boundary without a real reader.
 * Bug classes: provider timeout, cancellation, reconnect after cancellation,
 * output ownership, and APDU response bounds.
 */
static int test_smartcard_backend_mock(void)
{
    rdp_smartcard_backend backend;
    rdp_smartcard_mock_backend mock;
    SCARDCONTEXT context = 0;
    SCARDHANDLE handle = 0;
    DWORD active_protocol = 0;
    SCARD_READERSTATE state;
    SCARD_IO_REQUEST send_pci;
    SCARD_IO_REQUEST recv_pci;
    uint8_t apdu[] = {0x00u, 0x84u, 0x00u, 0x00u, 0x00u};
    uint8_t response[8];
    DWORD response_len = 0;
    unsigned int cancel_calls = 0;
    unsigned int disconnect_calls = 0;

    memset(&state, 0, sizeof(state));
    memset(&send_pci, 0, sizeof(send_pci));
    memset(&recv_pci, 0, sizeof(recv_pci));
    memset(response, 0, sizeof(response));
    rdp_smartcard_mock_backend_init(&mock);
    rdp_smartcard_backend_init_mock(&backend, &mock);
    rdp_smartcard_backend_set_timeout(&backend, 25u);

    CHECK(rdp_smartcard_backend_establish_context(&backend, 0, &context) == SCARD_S_SUCCESS);
    CHECK(context == mock.next_context);
    CHECK(rdp_smartcard_backend_connect(&backend,
                                        context,
                                        "Mock Reader 0",
                                        0,
                                        0,
                                        &handle,
                                        &active_protocol) == SCARD_S_SUCCESS);
    CHECK(handle == mock.next_handle);
    CHECK(active_protocol == mock.next_protocol);
    CHECK(atomic_load_explicit(&mock.connect_calls, memory_order_relaxed) == 1u);

    state.szReader = "Mock Reader 0";
    CHECK(rdp_smartcard_backend_get_status_change(&backend, context, 0, &state, 1) == SCARD_S_SUCCESS);
    CHECK(state.dwEventState == mock.next_state);
    CHECK(atomic_load_explicit(&mock.status_change_calls, memory_order_relaxed) == 1u);

    response_len = sizeof(response);
    send_pci.dwProtocol = mock.next_protocol;
    recv_pci.dwProtocol = mock.next_protocol;
    CHECK(rdp_smartcard_backend_transmit(&backend,
                                         context,
                                         handle,
                                         &send_pci,
                                         apdu,
                                         (DWORD)sizeof(apdu),
                                         &recv_pci,
                                         response,
                                         &response_len) == SCARD_S_SUCCESS);
    CHECK(response_len == mock.transmit_response_len);
    CHECK(memcmp(response, mock.transmit_response, response_len) == 0);
    CHECK(atomic_load_explicit(&mock.transmit_calls, memory_order_relaxed) == 1u);
    response_len = sizeof(response);
    CHECK(rdp_smartcard_backend_transmit(&backend,
                                         context,
                                         handle,
                                         &send_pci,
                                         NULL,
                                         0,
                                         &recv_pci,
                                         response,
                                         &response_len) == SCARD_S_SUCCESS);
    CHECK(response_len == mock.transmit_response_len);

    atomic_store_explicit(&mock.cancelled, 0u, memory_order_release);
    mock.hang_status_change_ms = 250u;
    CHECK(rdp_smartcard_backend_get_status_change(&backend, context, 250u, &state, 1) == SCARD_E_TIMEOUT);
    CHECK(atomic_load_explicit(&mock.cancel_calls, memory_order_relaxed) >= 1u);
    test_backend_sleep_ms(50u);

    atomic_store_explicit(&mock.cancelled, 0u, memory_order_release);
    mock.hang_status_change_ms = 0;
    mock.hang_transmit_ms = 250u;
    response_len = sizeof(response);
    CHECK(rdp_smartcard_backend_transmit(&backend,
                                         context,
                                         handle,
                                         &send_pci,
                                         apdu,
                                         (DWORD)sizeof(apdu),
                                         &recv_pci,
                                         response,
                                         &response_len) == SCARD_E_TIMEOUT);
    CHECK(response_len == 0);
    CHECK(atomic_load_explicit(&mock.cancel_calls, memory_order_relaxed) >= 2u);
    test_backend_sleep_ms(50u);

    atomic_store_explicit(&mock.cancelled, 0u, memory_order_release);
    mock.hang_transmit_ms = 0;
    mock.hang_connect_ms = 250u;
    cancel_calls = atomic_load_explicit(&mock.cancel_calls, memory_order_relaxed);
    disconnect_calls = atomic_load_explicit(&mock.disconnect_calls, memory_order_relaxed);
    handle = (SCARDHANDLE)99u;
    active_protocol = 99u;
    CHECK(rdp_smartcard_backend_connect(&backend,
                                        context,
                                        "Mock Reader 0",
                                        0,
                                        0,
                                        &handle,
                                        &active_protocol) == SCARD_E_TIMEOUT);
    CHECK(handle == 0);
    CHECK(active_protocol == 0);
    CHECK(atomic_load_explicit(&mock.connect_calls, memory_order_relaxed) == 2u);
    CHECK(atomic_load_explicit(&mock.cancel_calls, memory_order_relaxed) > cancel_calls);
    CHECK(wait_backend_atomic_uint_gt(&mock.disconnect_calls, disconnect_calls, 500u));

    atomic_store_explicit(&mock.cancelled, 0u, memory_order_release);
    mock.hang_connect_ms = 0;
    active_protocol = 0;
    handle = mock.next_handle;
    CHECK(rdp_smartcard_backend_reconnect(&backend, handle, 0, 0, 0, &active_protocol) == SCARD_S_SUCCESS);
    CHECK(active_protocol == mock.next_protocol);
    CHECK(rdp_smartcard_backend_disconnect(&backend, handle, 0) == SCARD_S_SUCCESS);
    CHECK(rdp_smartcard_backend_release_context(&backend, context) == SCARD_S_SUCCESS);
    return 0;
}

/*
 * Coverage: validates the printer backend queue boundary without contacting a
 * host print service. It catches malformed CUPS selectors and null spool paths
 * before any asynchronous worker can be created.
 */
static int test_printer_backend_boundary(void)
{
    static const uint32_t device_invalid_parameter = 0xc000000du;

    CHECK(!rdp_printer_backend_output_is_cups(NULL));
    CHECK(!rdp_printer_backend_output_is_cups(""));
    CHECK(!rdp_printer_backend_output_is_cups("file:/tmp/out"));
    CHECK(rdp_printer_backend_output_is_cups("cups"));
    CHECK(rdp_printer_backend_output_is_cups("cups:Office"));
    CHECK(rdp_printer_backend_submit_cups_async(0, "file:/tmp/out", "title", "/tmp/spool", 0) ==
          device_invalid_parameter);
    CHECK(rdp_printer_backend_submit_cups_async(0, "cups", "title", NULL, 0) ==
          device_invalid_parameter);
    return 0;
}

#ifdef RDP_HAVE_LIBUSB
typedef struct test_usb_open_mock
{
    int context_token;
    int device_token;
    int handle_token;
    libusb_device* devices[2];
    struct libusb_device_descriptor descriptor;
    struct libusb_config_descriptor config;
    struct libusb_interface interface_value;
    struct libusb_interface_descriptor alternate;
    int config_result;
    int open_result;
    unsigned config_calls;
    unsigned config_frees;
    unsigned open_calls;
} test_usb_open_mock;

static int test_usb_open_init(void* user_data, libusb_context** context)
{
    test_usb_open_mock* mock = (test_usb_open_mock*)user_data;

    if (!mock || !context)
        return LIBUSB_ERROR_INVALID_PARAM;
    *context = (libusb_context*)(void*)&mock->context_token;
    return LIBUSB_SUCCESS;
}

static ssize_t test_usb_open_get_device_list(void* user_data,
                                             libusb_context* context,
                                             libusb_device*** list)
{
    test_usb_open_mock* mock = (test_usb_open_mock*)user_data;

    if (!mock || !context || !list)
        return LIBUSB_ERROR_INVALID_PARAM;
    *list = mock->devices;
    return 1;
}

static void test_usb_open_free_device_list(void* user_data,
                                           libusb_device** list,
                                           int unref_devices)
{
    (void)user_data;
    (void)list;
    (void)unref_devices;
}

static int test_usb_open_get_device_descriptor(
    void* user_data,
    libusb_device* device,
    struct libusb_device_descriptor* descriptor)
{
    test_usb_open_mock* mock = (test_usb_open_mock*)user_data;

    if (!mock || device != mock->devices[0] || !descriptor)
        return LIBUSB_ERROR_INVALID_PARAM;
    *descriptor = mock->descriptor;
    return LIBUSB_SUCCESS;
}

static uint8_t test_usb_open_get_bus_number(void* user_data, libusb_device* device)
{
    test_usb_open_mock* mock = (test_usb_open_mock*)user_data;

    return mock && device == mock->devices[0] ? 3u : 0u;
}

static uint8_t test_usb_open_get_device_address(void* user_data, libusb_device* device)
{
    test_usb_open_mock* mock = (test_usb_open_mock*)user_data;

    return mock && device == mock->devices[0] ? 7u : 0u;
}

static int test_usb_open_get_config_descriptor(
    void* user_data,
    libusb_device* device,
    uint8_t index,
    struct libusb_config_descriptor** config)
{
    test_usb_open_mock* mock = (test_usb_open_mock*)user_data;

    if (!mock || device != mock->devices[0] || !config || index != 0u)
        return LIBUSB_ERROR_INVALID_PARAM;
    mock->config_calls++;
    if (mock->config_result != LIBUSB_SUCCESS)
        return mock->config_result;
    *config = &mock->config;
    return LIBUSB_SUCCESS;
}

static void test_usb_open_free_config_descriptor(
    void* user_data,
    struct libusb_config_descriptor* config)
{
    test_usb_open_mock* mock = (test_usb_open_mock*)user_data;

    if (mock && config == &mock->config)
        mock->config_frees++;
}

static int test_usb_open_device(void* user_data,
                                libusb_device* device,
                                libusb_device_handle** handle)
{
    test_usb_open_mock* mock = (test_usb_open_mock*)user_data;

    if (!mock || device != mock->devices[0] || !handle)
        return LIBUSB_ERROR_INVALID_PARAM;
    mock->open_calls++;
    if (mock->open_result != LIBUSB_SUCCESS)
        return mock->open_result;
    *handle = (libusb_device_handle*)(void*)&mock->handle_token;
    return LIBUSB_SUCCESS;
}

static rdp_usb_backend_open_ops test_usb_open_ops(test_usb_open_mock* mock)
{
    rdp_usb_backend_open_ops ops;

    memset(&ops, 0, sizeof(ops));
    ops.user_data = mock;
    ops.init = test_usb_open_init;
    ops.get_device_list = test_usb_open_get_device_list;
    ops.free_device_list = test_usb_open_free_device_list;
    ops.get_device_descriptor = test_usb_open_get_device_descriptor;
    ops.get_bus_number = test_usb_open_get_bus_number;
    ops.get_device_address = test_usb_open_get_device_address;
    ops.get_config_descriptor = test_usb_open_get_config_descriptor;
    ops.free_config_descriptor = test_usb_open_free_config_descriptor;
    ops.open = test_usb_open_device;
    return ops;
}

static void test_usb_open_mock_init(test_usb_open_mock* mock)
{
    if (!mock)
        return;
    memset(mock, 0, sizeof(*mock));
    mock->devices[0] = (libusb_device*)(void*)&mock->device_token;
    mock->descriptor.idVendor = 0x1234u;
    mock->descriptor.idProduct = 0x5678u;
    mock->descriptor.bDeviceClass = LIBUSB_CLASS_VENDOR_SPEC;
    mock->descriptor.bNumConfigurations = 1u;
    mock->config.bNumInterfaces = 1u;
    mock->config.interface = &mock->interface_value;
    mock->interface_value.num_altsetting = 1;
    mock->interface_value.altsetting = &mock->alternate;
    mock->alternate.bInterfaceClass = LIBUSB_CLASS_VENDOR_SPEC;
    mock->config_result = LIBUSB_SUCCESS;
    mock->open_result = LIBUSB_SUCCESS;
}

/*
 * Coverage: runs USB discovery and authorization through an injected provider
 * so class denial, unreadable descriptors, permission failures, and unplug
 * races are verified without host USB devices.
 */
static int test_usb_open_fail_closed(void)
{
    test_usb_open_mock mock;
    rdp_usb_backend_open_ops ops;
    rdp_usb_backend_open_request request;
    rdp_usb_backend_device device;
    rdp_usb_backend_match match;
    libusb_context* context = NULL;

    memset(&request, 0, sizeof(request));
    request.first = 0x1234u;
    request.second = 0x5678u;
    request.interface_id = 9u;

    test_usb_open_mock_init(&mock);
    ops = test_usb_open_ops(&mock);
    mock.descriptor.bDeviceClass = LIBUSB_CLASS_MASS_STORAGE;
    memset(&device, 0xa5, sizeof(device));
    CHECK(rdp_usb_backend_open_device_with_ops(&context,
                                               &request,
                                               &device,
                                               &match,
                                               &ops) == LIBRDP_STATUS_STATE);
    CHECK(!device.active && device.handle == NULL && mock.open_calls == 0u);

    context = NULL;
    test_usb_open_mock_init(&mock);
    ops = test_usb_open_ops(&mock);
    mock.alternate.bInterfaceClass = LIBUSB_CLASS_HID;
    CHECK(rdp_usb_backend_open_device_with_ops(&context,
                                               &request,
                                               &device,
                                               &match,
                                               &ops) == LIBRDP_STATUS_STATE);
    CHECK(!device.active && device.handle == NULL);
    CHECK(mock.config_calls == 1u && mock.config_frees == 1u && mock.open_calls == 0u);

    context = NULL;
    test_usb_open_mock_init(&mock);
    ops = test_usb_open_ops(&mock);
    mock.config_result = LIBUSB_ERROR_IO;
    CHECK(rdp_usb_backend_open_device_with_ops(&context,
                                               &request,
                                               &device,
                                               &match,
                                               &ops) == LIBRDP_STATUS_IO_ERROR);
    CHECK(!device.active && device.handle == NULL);
    CHECK(mock.config_calls == 1u && mock.open_calls == 0u);

    context = NULL;
    test_usb_open_mock_init(&mock);
    ops = test_usb_open_ops(&mock);
    mock.open_result = LIBUSB_ERROR_ACCESS;
    CHECK(rdp_usb_backend_open_device_with_ops(&context,
                                               &request,
                                               &device,
                                               &match,
                                               &ops) == LIBRDP_STATUS_IO_ERROR);
    CHECK(!device.active && device.handle == NULL && mock.open_calls == 1u);

    context = NULL;
    test_usb_open_mock_init(&mock);
    ops = test_usb_open_ops(&mock);
    mock.open_result = LIBUSB_ERROR_NO_DEVICE;
    CHECK(rdp_usb_backend_open_device_with_ops(&context,
                                               &request,
                                               &device,
                                               &match,
                                               &ops) == LIBRDP_STATUS_CLOSED);
    CHECK(!device.active && device.handle == NULL && mock.open_calls == 1u);

    context = NULL;
    test_usb_open_mock_init(&mock);
    ops = test_usb_open_ops(&mock);
    CHECK(rdp_usb_backend_open_device_with_ops(&context,
                                               &request,
                                               &device,
                                               &match,
                                               &ops) == LIBRDP_STATUS_OK);
    CHECK(device.active && device.handle != NULL && mock.open_calls == 1u);
    CHECK(device.interface_id == request.interface_id);
    CHECK(match.vendor_id == 0x1234u && match.product_id == 0x5678u);
    memset(&device, 0, sizeof(device));
    return 0;
}

/*
 * Coverage: verifies the canonical packet layout required by libusb and
 * catches aggregate overflow, overlap, gaps, and trailing unassigned bytes
 * before any transfer can be allocated or submitted.
 */
static int test_usb_iso_layout(void)
{
    rdp_usb_backend_iso_packet packets[2];
    uint32_t original_actual = 0;
    uint32_t original_status = 0;

    memset(packets, 0, sizeof(packets));
    packets[0].offset = 0u;
    packets[0].length = 6u;
    packets[0].actual_length = 11u;
    packets[0].status = 12u;
    packets[1].offset = 6u;
    packets[1].length = 4u;
    packets[1].actual_length = 13u;
    packets[1].status = 14u;
    CHECK(rdp_usb_backend_validate_iso_layout(10u, packets, 2u) ==
          RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS);

    original_actual = packets[1].actual_length;
    original_status = packets[1].status;
    packets[1].length = 6u;
    CHECK(rdp_usb_backend_validate_iso_layout(10u, packets, 2u) ==
          RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER);
    CHECK(packets[1].actual_length == original_actual &&
          packets[1].status == original_status);

    packets[0].length = 4u;
    packets[1].offset = 5u;
    packets[1].length = 5u;
    CHECK(rdp_usb_backend_validate_iso_layout(10u, packets, 2u) ==
          RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER);

    packets[0].length = 6u;
    packets[1].offset = 5u;
    packets[1].length = 5u;
    CHECK(rdp_usb_backend_validate_iso_layout(10u, packets, 2u) ==
          RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER);

    packets[0].length = 4u;
    packets[1].offset = 4u;
    packets[1].length = 4u;
    CHECK(rdp_usb_backend_validate_iso_layout(10u, packets, 2u) ==
          RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER);

    packets[0].offset = 0u;
    packets[0].length = UINT32_MAX;
    packets[1].offset = UINT32_MAX;
    packets[1].length = 1u;
    CHECK(rdp_usb_backend_validate_iso_layout(UINT32_MAX, packets, 2u) ==
          RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER);
    CHECK(rdp_usb_backend_validate_iso_layout(0u, NULL, 0u) ==
          RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER);
    return 0;
}

typedef enum test_usb_wait_scenario
{
    TEST_USB_WAIT_EVENT_ERROR = 0,
    TEST_USB_WAIT_TIMEOUT = 1,
    TEST_USB_WAIT_CANCEL = 2,
    TEST_USB_WAIT_UNPLUG = 3
} test_usb_wait_scenario;

typedef struct test_usb_wait_mock
{
    test_usb_wait_scenario scenario;
    struct libusb_transfer* transfer;
    uint64_t now_ms;
    unsigned submit_calls;
    unsigned cancel_calls;
    unsigned event_calls;
    int in_flight;
} test_usb_wait_mock;

static void LIBUSB_CALL test_usb_wait_callback(struct libusb_transfer* transfer)
{
    rdp_usb_backend_wait_state* state =
        transfer ? (rdp_usb_backend_wait_state*)transfer->user_data : NULL;

    if (!state)
        return;
    state->transfer_status = transfer->status;
    state->actual_length = transfer->actual_length;
    state->completed = 1;
}

static int test_usb_wait_submit(void* user_data, struct libusb_transfer* transfer)
{
    test_usb_wait_mock* mock = (test_usb_wait_mock*)user_data;

    if (!mock || !transfer)
        return LIBUSB_ERROR_INVALID_PARAM;
    mock->submit_calls++;
    mock->transfer = transfer;
    mock->in_flight = 1;
    return LIBUSB_SUCCESS;
}

static int test_usb_wait_cancel(void* user_data, struct libusb_transfer* transfer)
{
    test_usb_wait_mock* mock = (test_usb_wait_mock*)user_data;

    if (!mock || transfer != mock->transfer || !mock->in_flight)
        return LIBUSB_ERROR_NOT_FOUND;
    mock->cancel_calls++;
    return LIBUSB_SUCCESS;
}

static int test_usb_wait_handle_events(void* user_data,
                                       libusb_context* context,
                                       struct timeval* timeout,
                                       int* completed)
{
    test_usb_wait_mock* mock = (test_usb_wait_mock*)user_data;

    (void)context;
    (void)timeout;
    if (!mock || !mock->transfer || !completed)
        return LIBUSB_ERROR_INVALID_PARAM;
    mock->event_calls++;
    if (mock->scenario == TEST_USB_WAIT_EVENT_ERROR && mock->event_calls == 1u)
        return LIBUSB_ERROR_IO;
    if (mock->scenario == TEST_USB_WAIT_UNPLUG)
        mock->transfer->status = LIBUSB_TRANSFER_NO_DEVICE;
    else
        mock->transfer->status = LIBUSB_TRANSFER_CANCELLED;
    mock->transfer->actual_length = 0;
    mock->in_flight = 0;
    mock->transfer->callback(mock->transfer);
    *completed = 1;
    return LIBUSB_SUCCESS;
}

static uint64_t test_usb_wait_now_ms(void* user_data)
{
    test_usb_wait_mock* mock = (test_usb_wait_mock*)user_data;
    uint64_t now = 0;

    if (!mock)
        return 0;
    now = mock->now_ms;
    mock->now_ms += 20u;
    return now;
}

static int test_usb_wait_is_cancelled(void* user_data)
{
    const test_usb_wait_mock* mock = (const test_usb_wait_mock*)user_data;

    return mock && mock->scenario == TEST_USB_WAIT_CANCEL;
}

static uint32_t test_usb_wait_run(test_usb_wait_scenario scenario,
                                  test_usb_wait_mock* mock)
{
    rdp_usb_backend_transfer_ops ops;
    rdp_usb_backend_wait_control control;
    rdp_usb_backend_wait_state state;
    libusb_context* context = (libusb_context*)(void*)mock;
    struct libusb_transfer* transfer = NULL;
    uint32_t status = 0;

    if (!mock)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    memset(mock, 0, sizeof(*mock));
    mock->scenario = scenario;
    memset(&ops, 0, sizeof(ops));
    ops.user_data = mock;
    ops.submit = test_usb_wait_submit;
    ops.cancel = test_usb_wait_cancel;
    ops.handle_events = test_usb_wait_handle_events;
    ops.now_ms = test_usb_wait_now_ms;
    memset(&control, 0, sizeof(control));
    control.user_data = mock;
    control.is_cancelled = test_usb_wait_is_cancelled;
    memset(&state, 0, sizeof(state));
    transfer = libusb_alloc_transfer(0);
    if (!transfer)
        return RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
    transfer->callback = test_usb_wait_callback;
    transfer->user_data = &state;
    status = rdp_usb_backend_wait_transfer_with_ops(context,
                                                    transfer,
                                                    &state,
                                                    scenario == TEST_USB_WAIT_TIMEOUT ? 10u : 100u,
                                                    &control,
                                                    &ops);
    CHECK(!mock->in_flight && state.completed);
    libusb_free_transfer(transfer);
    return status;
}

/*
 * Coverage: models timeout, explicit cancellation, one event-loop failure,
 * and device unplug. Every submitted transfer reaches its callback before the
 * test releases storage, including the event-error path.
 */
static int test_usb_transfer_terminal_lifecycle(void)
{
    test_usb_wait_mock mock;

    CHECK(test_usb_wait_run(TEST_USB_WAIT_EVENT_ERROR, &mock) ==
          RDP_USB_REDIRECTION_USBD_STATUS_DEV_NOT_RESPONDING);
    CHECK(mock.submit_calls == 1u && mock.cancel_calls == 1u &&
          mock.event_calls == 2u);
    CHECK(test_usb_wait_run(TEST_USB_WAIT_TIMEOUT, &mock) ==
          RDP_USB_REDIRECTION_USBD_STATUS_TIMEOUT);
    CHECK(mock.submit_calls == 1u && mock.cancel_calls == 1u);
    CHECK(test_usb_wait_run(TEST_USB_WAIT_CANCEL, &mock) ==
          RDP_USB_REDIRECTION_USBD_STATUS_TIMEOUT);
    CHECK(mock.submit_calls == 1u && mock.cancel_calls == 1u);
    CHECK(test_usb_wait_run(TEST_USB_WAIT_UNPLUG, &mock) ==
          RDP_USB_REDIRECTION_USBD_STATUS_DEVICE_GONE);
    CHECK(mock.submit_calls == 1u && mock.cancel_calls == 0u);
    return 0;
}

/*
 * Coverage: queues a wire-valid URB through the session boundary and verifies
 * that completion is collected through the owner-thread dispatcher. No USB
 * device is required; the worker reports the absent interface asynchronously.
 */
static int test_usb_session_worker(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    rdp_buffer packet;
    uint32_t waited_ms = 0;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    rdp_buffer_init(&packet);
    CHECK(rdp_usb_redirection_write_transfer_in_request(
              &packet,
              9u,
              1u,
              RDP_USB_REDIRECTION_URB_GET_CURRENT_FRAME_NUMBER,
              77u,
              0u,
              4u) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_usb_redirection_message(session,
                                                     packet.data,
                                                     packet.length) ==
          LIBRDP_STATUS_OK);
    while (rdp_session_usb_outstanding_requests(session) > 0 && waited_ms < 1000u)
    {
        test_backend_sleep_ms(5u);
        CHECK(rdp_session_usb_dispatch_completions(session) == LIBRDP_STATUS_OK);
        waited_ms += 5u;
    }
    CHECK(rdp_session_usb_outstanding_requests(session) == 0);
    rdp_buffer_free(&packet);
    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}
#endif

static int test_usb_backend_boundary(void)
{
#ifdef RDP_HAVE_LIBUSB
    rdp_usb_backend_iso_packet packet;
    rdp_usb_backend_device device;
    rdp_usb_backend_open_request open_request;
    libusb_context* context = NULL;
    uint8_t transfer_type = 0;
    uint32_t actual = 0;

    memset(&device, 0, sizeof(device));
    memset(&packet, 0, sizeof(packet));
    memset(&open_request, 0, sizeof(open_request));
    packet.length = 1;
    rdp_usb_backend_release_device(NULL);
    rdp_usb_backend_release_devices(NULL, 1);
    rdp_usb_backend_context_exit(NULL);
    rdp_usb_backend_context_exit(&context);
    rdp_usb_backend_release_device(&device);
    CHECK(rdp_usb_backend_open_device(NULL, &open_request, &device, NULL) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(rdp_usb_backend_open_device(&context, NULL, &device, NULL) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(rdp_usb_backend_open_device(&context, &open_request, NULL, NULL) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(rdp_usb_backend_reset_device(NULL) == RDP_USB_REDIRECTION_USBD_STATUS_DEVICE_GONE);
    CHECK(rdp_usb_backend_reset_device(&device) == RDP_USB_REDIRECTION_USBD_STATUS_DEVICE_GONE);
    CHECK(rdp_usb_backend_claim_endpoint(NULL, 0, &transfer_type) ==
          RDP_USB_REDIRECTION_USBD_STATUS_DEVICE_GONE);
    CHECK(rdp_usb_backend_claim_endpoint(&device, 0, &transfer_type) ==
          RDP_USB_REDIRECTION_USBD_STATUS_DEVICE_GONE);
    CHECK(rdp_usb_backend_select_interface(NULL, 0, 0) ==
          RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER);
    CHECK(rdp_usb_backend_select_interface(&device, 0, 0) ==
          RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER);
    CHECK(rdp_usb_backend_libusb_status(LIBUSB_SUCCESS) ==
          RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS);
    CHECK(rdp_usb_backend_libusb_status(LIBUSB_ERROR_TIMEOUT) ==
          RDP_USB_REDIRECTION_USBD_STATUS_TIMEOUT);
    CHECK(rdp_usb_backend_libusb_status(LIBUSB_ERROR_NO_DEVICE) ==
          RDP_USB_REDIRECTION_USBD_STATUS_DEVICE_GONE);
    CHECK(rdp_usb_backend_libusb_status(LIBUSB_ERROR_PIPE) ==
          RDP_USB_REDIRECTION_USBD_STATUS_STALL_PID);
    CHECK(rdp_usb_backend_transfer_status(LIBUSB_TRANSFER_CANCELLED) ==
          RDP_USB_REDIRECTION_USBD_STATUS_TIMEOUT);
    CHECK(rdp_usb_backend_transfer_status(LIBUSB_TRANSFER_NO_DEVICE) ==
          RDP_USB_REDIRECTION_USBD_STATUS_DEVICE_GONE);
    CHECK(rdp_usb_backend_transfer_status(LIBUSB_TRANSFER_STALL) ==
          RDP_USB_REDIRECTION_USBD_STATUS_STALL_PID);
    CHECK(rdp_usb_backend_control_transfer(NULL,
                                           NULL,
                                           0,
                                           0,
                                           0,
                                           0,
                                           NULL,
                                           0,
                                           1,
                                           NULL,
                                           &actual) ==
          RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER);
    CHECK(rdp_usb_backend_bulk_or_interrupt_transfer(NULL,
                                                     NULL,
                                                     0,
                                                     LIBUSB_TRANSFER_TYPE_BULK,
                                                     NULL,
                                                     0,
                                                     1,
                                                     NULL,
                                                     &actual) ==
          RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER);
    CHECK(rdp_usb_backend_iso_transfer(NULL,
                                       NULL,
                                       0,
                                       NULL,
                                       0,
                                       &packet,
                                       1,
                                       1,
                                       NULL,
                                       &actual) ==
          RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER);
#endif
    return 0;
}

int test_core_devices(void)
{
    if (test_smartcard_backend_mock() != 0)
        return 1;
    if (test_printer_backend_boundary() != 0)
        return 1;
#ifdef RDP_HAVE_LIBUSB
    if (test_usb_open_fail_closed() != 0)
        return 1;
    if (test_usb_iso_layout() != 0)
        return 1;
    if (test_usb_transfer_terminal_lifecycle() != 0)
        return 1;
    if (test_usb_session_worker() != 0)
        return 1;
#endif
    if (test_usb_backend_boundary() != 0)
        return 1;
    return 0;
}
