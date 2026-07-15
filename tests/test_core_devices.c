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
                                           &actual) ==
          RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER);
    CHECK(rdp_usb_backend_bulk_or_interrupt_transfer(NULL,
                                                     NULL,
                                                     0,
                                                     LIBUSB_TRANSFER_TYPE_BULK,
                                                     NULL,
                                                     0,
                                                     1,
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
    if (test_usb_backend_boundary() != 0)
        return 1;
    return 0;
}
