/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: core public API, trace, settings, surface, input, and session
 * lifecycle tests.
 * Coverage: fixture code builds handshake, bitmap, GDI, and event vectors
 * without network dependencies except local sockets.
 * Bug classes: bounds, ownership, callback lifetime, trace filtering, state
 * transitions, and malformed local fixtures.
 * Determinism: tests are self-contained and avoid external services unless
 * using local loopback fixtures.
 */


#include <librdp/librdp.h>

#include "common/buffer.h"
#include "common/charset.h"
#include "common/stream.h"
#include "common/trace.h"
#include "client/settings_internal.h"
#include "client/smartcard_backend.h"
#include "client/usb_backend.h"
#include "clipboard/clipboard.h"
#include "channels/display_control.h"
#include "channels/dynamic_channel.h"
#include "channels/usb_redirection.h"
#include "channels/virtual_channel.h"
#include "graphics/gdi_orders.h"
#include "input/input.h"
#include "licensing/licensing.h"
#include "protocol/mcs.h"
#include "protocol/pointer.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expr)                                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

#define DVC_SCENARIO_NORMAL 0
#define DVC_SCENARIO_DUPLICATE_CREATE 1
#define DVC_SCENARIO_CLOSE_PENDING_FRAGMENT 2
#define DVC_SCENARIO_DATA_BEFORE_CREATE 3
#define DVC_SCENARIO_EMPTY_CONTINUATION 4
#define DVC_SCENARIO_NESTED_DATA_FIRST 5
#define DVC_SCENARIO_WEBAUTHN_CREATE_CLOSE 6
#define DVC_SCENARIO_EMPTY_COMPRESSED_FIRST 7
#define DVC_SCENARIO_EMPTY_COMPRESSED_CONTINUATION 8
#define DVC_SCENARIO_SOFT_SYNC_TUNNEL_REQUEST 9
#define DVC_SCENARIO_DISPLAY_CONTROL_CAPS_REJECT_LAYOUT 10

#define GDI_SCENARIO_NORMAL 0
#define GDI_SCENARIO_UNSUPPORTED_ALTSEC 1

#define CLIPBOARD_SCENARIO_NONE 0
#define CLIPBOARD_SCENARIO_UNMATCHED_RESPONSES 1

typedef struct event_counter
{
    int states;
    int surfaces;
    int keys;
    int mouse;
    int pointer;
    int clipboard_formats;
    int clipboard_data;
    int clipboard_requests;
    int clipboard_file_contents;
    int channel_open;
    int channel_data;
    int channel_close;
    librdp_channel_id last_channel_id;
    size_t last_channel_data_len;
    char last_channel_data[32];
    int audio_output_formats;
    int audio_output_data;
    int audio_output_close;
    int audio_input_formats;
    int audio_input_open;
    int video_capture_open;
    int video_capture_sample_request;
    int video_capture_close;
    int disconnected;
} event_counter;

typedef struct event_envelope_capture
{
    int count;
    int state;
    int surface;
    int disconnected;
    int invalid;
} event_envelope_capture;

typedef struct domain_event_capture
{
    int graphics;
    int pointer;
    int channel;
    int clipboard;
    int audio;
    int video;
    int reentrant_metrics;
    int invalid;
} domain_event_capture;

typedef struct graphics_update_capture
{
    int pixel_rect;
    int desktop_resize;
    int surface_create;
    int surface_destroy;
    int frame_begin;
    int frame_end;
    int borrowed_pixels;
    int invalid;
} graphics_update_capture;

typedef struct trace_capture
{
    uint64_t count;
    uint64_t last_sequence;
    int saw_connect_start;
    int saw_protocol;
    int saw_ids;
    int saw_line;
} trace_capture;

typedef struct secure_string_capture
{
    uint32_t calls;
    uint32_t failed;
    size_t last_length;
} secure_string_capture;

typedef struct credentials_provider_capture
{
    uint32_t calls;
    uint32_t fail;
} credentials_provider_capture;

typedef struct cancel_thread_capture
{
    librdp_session* session;
    unsigned delay_ms;
    librdp_status status;
} cancel_thread_capture;

typedef struct owner_thread_capture
{
    librdp_session* session;
    librdp_status status;
} owner_thread_capture;

/*
 * Coverage: validates protocol parser and writer vectors for handshake,
 * channel framing, graphics codecs, device channels, and malformed PDUs.
 */
int test_protocol(void);
/*
 * Coverage: validates TCP/TLS transport setup, local socket I/O, timeout
 * handling, EOF behavior, and transport-owned resource lifetime.
 */
int test_transport(void);

static void on_event(librdp_session* session, const librdp_event* event, void* user_data)
{
    event_counter* counter = (event_counter*)user_data;
    (void)session;

    if (!event || !counter)
        return;

    switch (event->type)
    {
        case LIBRDP_EVENT_STATE_CHANGED:
            counter->states++;
            break;
        case LIBRDP_EVENT_SURFACE_INVALIDATED:
            counter->surfaces++;
            break;
        case LIBRDP_EVENT_KEY_SENT:
            counter->keys++;
            break;
        case LIBRDP_EVENT_MOUSE_SENT:
            counter->mouse++;
            break;
        case LIBRDP_EVENT_POINTER:
            counter->pointer++;
            break;
        case LIBRDP_EVENT_CLIPBOARD_FORMATS:
            counter->clipboard_formats++;
            break;
        case LIBRDP_EVENT_CLIPBOARD_DATA:
            counter->clipboard_data++;
            break;
        case LIBRDP_EVENT_CLIPBOARD_REQUEST:
            counter->clipboard_requests++;
            break;
        case LIBRDP_EVENT_CLIPBOARD_FILE_CONTENTS:
            counter->clipboard_file_contents++;
            break;
        case LIBRDP_EVENT_CHANNEL_OPEN:
            counter->channel_open++;
            counter->last_channel_id = event->data.channel_open.channel_id;
            break;
        case LIBRDP_EVENT_CHANNEL_DATA:
            counter->channel_data++;
            counter->last_channel_id = event->data.channel_data.channel_id;
            counter->last_channel_data_len = event->data.channel_data.data_len;
            if (event->data.channel_data.data_len == 0)
            {
                counter->last_channel_data[0] = '\0';
            }
            else if (event->data.channel_data.data_len < sizeof(counter->last_channel_data) &&
                     event->data.channel_data.data)
            {
                memcpy(counter->last_channel_data,
                       event->data.channel_data.data,
                       event->data.channel_data.data_len);
                counter->last_channel_data[event->data.channel_data.data_len] = '\0';
            }
            break;
        case LIBRDP_EVENT_CHANNEL_CLOSE:
            counter->channel_close++;
            counter->last_channel_id = event->data.channel_close.channel_id;
            break;
        case LIBRDP_EVENT_AUDIO_OUTPUT_FORMATS:
            counter->audio_output_formats++;
            break;
        case LIBRDP_EVENT_AUDIO_OUTPUT_DATA:
            counter->audio_output_data++;
            break;
        case LIBRDP_EVENT_AUDIO_OUTPUT_CLOSE:
            counter->audio_output_close++;
            break;
        case LIBRDP_EVENT_AUDIO_INPUT_FORMATS:
            counter->audio_input_formats++;
            break;
        case LIBRDP_EVENT_AUDIO_INPUT_OPEN:
            counter->audio_input_open++;
            break;
        case LIBRDP_EVENT_VIDEO_CAPTURE_OPEN:
            counter->video_capture_open++;
            break;
        case LIBRDP_EVENT_VIDEO_CAPTURE_SAMPLE_REQUEST:
            counter->video_capture_sample_request++;
            break;
        case LIBRDP_EVENT_VIDEO_CAPTURE_CLOSE:
            counter->video_capture_close++;
            break;
        case LIBRDP_EVENT_DISCONNECTED:
            counter->disconnected++;
            break;
        default:
            break;
    }
}

static void on_event_envelope(librdp_session* session, const librdp_event_envelope* envelope, void* user_data)
{
    event_envelope_capture* capture = (event_envelope_capture*)user_data;
    (void)session;

    if (!capture || !envelope || envelope->version != LIBRDP_EVENT_ENVELOPE_VERSION ||
        envelope->size < sizeof(*envelope) || !envelope->legacy_event ||
        envelope->legacy_event->type != envelope->type)
    {
        if (capture)
            capture->invalid++;
        return;
    }
    capture->count++;
    switch (envelope->type)
    {
        case LIBRDP_EVENT_STATE_CHANGED:
            capture->state += envelope->payload && envelope->payload_size == sizeof(envelope->legacy_event->data.state);
            break;
        case LIBRDP_EVENT_SURFACE_INVALIDATED:
            capture->surface += envelope->payload && envelope->payload_size == sizeof(librdp_rect);
            break;
        case LIBRDP_EVENT_DISCONNECTED:
            capture->disconnected += envelope->payload == NULL && envelope->payload_size == 0;
            break;
        default:
            break;
    }
}

static void on_domain_event(librdp_session* session, const librdp_event_envelope* envelope, void* user_data)
{
    domain_event_capture* capture = (domain_event_capture*)user_data;
    librdp_metrics metrics;

    if (!capture || !envelope || envelope->version != LIBRDP_EVENT_ENVELOPE_VERSION ||
        envelope->size < sizeof(*envelope) || !envelope->legacy_event ||
        envelope->legacy_event->type != envelope->type)
    {
        if (capture)
            capture->invalid++;
        return;
    }
    if (librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK &&
        librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_OK)
        capture->reentrant_metrics++;

    switch (envelope->type)
    {
        case LIBRDP_EVENT_SURFACE_INVALIDATED:
            capture->graphics += envelope->payload && envelope->payload_size == sizeof(librdp_rect);
            break;
        case LIBRDP_EVENT_POINTER:
            capture->pointer += envelope->payload && envelope->payload_size == sizeof(librdp_pointer_event);
            break;
        case LIBRDP_EVENT_CHANNEL_OPEN:
        case LIBRDP_EVENT_CHANNEL_DATA:
        case LIBRDP_EVENT_CHANNEL_CLOSE:
            capture->channel++;
            break;
        case LIBRDP_EVENT_CLIPBOARD_FORMATS:
        case LIBRDP_EVENT_CLIPBOARD_DATA:
        case LIBRDP_EVENT_CLIPBOARD_REQUEST:
        case LIBRDP_EVENT_CLIPBOARD_FILE_CONTENTS:
            capture->clipboard++;
            break;
        case LIBRDP_EVENT_AUDIO_OUTPUT_FORMATS:
        case LIBRDP_EVENT_AUDIO_OUTPUT_DATA:
        case LIBRDP_EVENT_AUDIO_OUTPUT_CLOSE:
        case LIBRDP_EVENT_AUDIO_INPUT_FORMATS:
        case LIBRDP_EVENT_AUDIO_INPUT_OPEN:
            capture->audio++;
            break;
        case LIBRDP_EVENT_VIDEO_CAPTURE_OPEN:
        case LIBRDP_EVENT_VIDEO_CAPTURE_SAMPLE_REQUEST:
        case LIBRDP_EVENT_VIDEO_CAPTURE_CLOSE:
            capture->video++;
            break;
        default:
            capture->invalid++;
            break;
    }
}

static void on_graphics_update(librdp_session* session, const librdp_graphics_update* update, void* user_data)
{
    graphics_update_capture* capture = (graphics_update_capture*)user_data;
    (void)session;

    if (!capture || !update || update->version != LIBRDP_GRAPHICS_UPDATE_VERSION ||
        update->size < sizeof(*update))
    {
        if (capture)
            capture->invalid++;
        return;
    }

    switch (update->type)
    {
        case LIBRDP_GRAPHICS_UPDATE_PIXEL_RECT:
            capture->pixel_rect++;
            if (update->format == LIBRDP_PIXEL_FORMAT_BGRA32 && update->pixels &&
                update->stride >= (size_t)update->rect.width * 4u &&
                update->rect.x + update->rect.width <= update->desktop_width &&
                update->rect.y + update->rect.height <= update->desktop_height)
                capture->borrowed_pixels++;
            else
                capture->invalid++;
            break;
        case LIBRDP_GRAPHICS_UPDATE_DESKTOP_RESIZE:
            capture->desktop_resize++;
            break;
        case LIBRDP_GRAPHICS_UPDATE_SURFACE_CREATE:
            capture->surface_create++;
            break;
        case LIBRDP_GRAPHICS_UPDATE_SURFACE_DESTROY:
            capture->surface_destroy++;
            break;
        case LIBRDP_GRAPHICS_UPDATE_FRAME_BEGIN:
            capture->frame_begin++;
            break;
        case LIBRDP_GRAPHICS_UPDATE_FRAME_END:
            capture->frame_end++;
            break;
        default:
            capture->invalid++;
            break;
    }
}

/*
 * The cancel regression needs one real blocked dispatch thread without using
 * external endpoints. The helper waits briefly, requests public cancellation,
 * and leaves all session teardown to the owner thread.
 */
static void* cancel_thread_main(void* user_data)
{
    cancel_thread_capture* capture = (cancel_thread_capture*)user_data;
    struct timespec ts;

    ts.tv_sec = 0;
    ts.tv_nsec = (long)capture->delay_ms * 1000000L;
    (void)nanosleep(&ts, NULL);
    capture->status = librdp_session_cancel(capture->session);
    return NULL;
}

static void* owner_thread_main(void* user_data)
{
    owner_thread_capture* capture = (owner_thread_capture*)user_data;

    if (!capture)
        return NULL;
    capture->status = librdp_session_refresh(capture->session, 0, 0, 1, 1);
    return NULL;
}

static void on_trace(librdp_session* session, const librdp_trace_record* record, void* user_data)
{
    trace_capture* capture = (trace_capture*)user_data;

    if (!session || !record || !capture)
        return;
    capture->count++;
    if (record->sequence > capture->last_sequence)
        capture->last_sequence = record->sequence;
    if (record->event && strcmp(record->event, "client.connect.start") == 0)
        capture->saw_connect_start = 1;
    if (record->category && strcmp(record->category, "protocol") == 0)
        capture->saw_protocol = 1;
    if (record->session_id && strcmp(record->session_id, "session-1") == 0 &&
        record->connection_id && strcmp(record->connection_id, "connection-1") == 0 &&
        record->trace_id && strcmp(record->trace_id, "trace-1") == 0)
        capture->saw_ids = 1;
    if (record->line && strstr(record->line, "trace_id=trace-1") != NULL)
        capture->saw_line = 1;
}

static void on_secure_string_cleanse(const void* data, size_t length, void* user_data)
{
    secure_string_capture* capture = (secure_string_capture*)user_data;
    const uint8_t* bytes = (const uint8_t*)data;
    size_t i = 0;

    if (!capture || !bytes || length == 0)
        return;
    capture->calls++;
    capture->last_length = length;
    for (i = 0; i < length; i++)
    {
        if (bytes[i] != 0)
            capture->failed++;
    }
}

static void test_sleep_ms(uint32_t timeout_ms)
{
    struct timespec requested;
    struct timespec remaining;

    requested.tv_sec = (time_t)(timeout_ms / 1000u);
    requested.tv_nsec = (long)((timeout_ms % 1000u) * 1000000u);
    while (nanosleep(&requested, &remaining) != 0 && errno == EINTR)
        requested = remaining;
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
    test_sleep_ms(50u);

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
    test_sleep_ms(50u);

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
    test_sleep_ms(50u);
    CHECK(atomic_load_explicit(&mock.disconnect_calls, memory_order_relaxed) > disconnect_calls);

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

static int test_usb_backend_boundary(void)
{
#ifdef RDP_HAVE_LIBUSB
    rdp_usb_backend_iso_packet packet;
    uint32_t actual = 0;

    memset(&packet, 0, sizeof(packet));
    packet.length = 1;
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

static librdp_status on_credentials_provider(librdp_credentials* credentials, void* user_data)
{
    credentials_provider_capture* capture = (credentials_provider_capture*)user_data;

    if (capture)
    {
        capture->calls++;
        if (capture->fail)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    return librdp_credentials_set(credentials, "provider-user", "provider-pass", "provider-domain");
}

static librdp_tls_certificate_decision core_tls_certificate_callback(const librdp_tls_certificate_info* certificate,
                                                                    void* user_data)
{
    (void)certificate;
    (void)user_data;
    return LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT;
}

static int capture_stderr(void (*fn)(void), char* out, size_t out_len)
{
    int pipe_fds[2] = {-1, -1};
    int saved = -1;
    ssize_t got = 0;

    if (pipe(pipe_fds) != 0)
        return 0;
    saved = dup(STDERR_FILENO);
    if (saved < 0)
        return 0;
    if (dup2(pipe_fds[1], STDERR_FILENO) < 0)
        return 0;
    close(pipe_fds[1]);

    fn();
    fflush(stderr);

    if (dup2(saved, STDERR_FILENO) < 0)
        return 0;
    close(saved);

    got = read(pipe_fds[0], out, out_len - 1);
    close(pipe_fds[0]);
    if (got < 0)
        got = 0;
    out[got] = '\0';
    return 1;
}

static int read_exact_fd(int fd, void* data, size_t length)
{
    uint8_t* out = (uint8_t*)data;
    size_t offset = 0;

    while (offset < length)
    {
        ssize_t got = read(fd, out + offset, length - offset);
        if (got <= 0)
            return 0;
        offset += (size_t)got;
    }

    return 1;
}

static int write_exact_fd(int fd, const void* data, size_t length)
{
    const uint8_t* in = (const uint8_t*)data;
    size_t offset = 0;

    while (offset < length)
    {
        ssize_t wrote = write(fd, in + offset, length - offset);
        if (wrote <= 0)
            return 0;
        offset += (size_t)wrote;
    }

    return 1;
}

static int append_ber_length(rdp_buffer* buffer, size_t length)
{
    if (length < 0x80u)
        return rdp_buffer_append_u8(buffer, (uint8_t)length) == LIBRDP_STATUS_OK;
    if (length <= 0xffu)
        return rdp_buffer_append_u8(buffer, 0x81) == LIBRDP_STATUS_OK &&
               rdp_buffer_append_u8(buffer, (uint8_t)length) == LIBRDP_STATUS_OK;
    if (length <= 0xffffu)
        return rdp_buffer_append_u8(buffer, 0x82) == LIBRDP_STATUS_OK &&
               rdp_buffer_append_u16_be(buffer, (uint16_t)length) == LIBRDP_STATUS_OK;
    return 0;
}

static int append_per_length(rdp_buffer* buffer, size_t length)
{
    if (length > 0x7fffu)
        return 0;
    if (length > 0x7fu)
        return rdp_buffer_append_u16_be(buffer, (uint16_t)(length | 0x8000u)) == LIBRDP_STATUS_OK;
    return rdp_buffer_append_u8(buffer, (uint8_t)length) == LIBRDP_STATUS_OK;
}

static int read_per_length_from_stream(rdp_stream* stream, size_t* length)
{
    uint8_t first = 0;

    if (!stream || !length)
        return 0;
    if (rdp_stream_read_u8(stream, &first) != LIBRDP_STATUS_OK)
        return 0;
    if ((first & 0x80u) == 0)
    {
        *length = first;
        return 1;
    }
    {
        uint8_t second = 0;

        if (rdp_stream_read_u8(stream, &second) != LIBRDP_STATUS_OK)
            return 0;
        *length = (size_t)(((uint16_t)(first & 0x7fu) << 8) | second);
        return 1;
    }
}

static int append_gcc_block(rdp_buffer* buffer, uint16_t type, const rdp_buffer* payload)
{
    size_t total = 0;

    if (!buffer || !payload)
        return 0;
    total = payload->length + 4u;
    if (total > 0xffffu)
        return 0;
    return rdp_buffer_append_u16_le(buffer, type) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u16_le(buffer, (uint16_t)total) == LIBRDP_STATUS_OK &&
           rdp_buffer_append(buffer, payload->data, payload->length) == LIBRDP_STATUS_OK;
}

/*
 * Fixture: builds a deterministic MCS/GCC connect response with security
 * blocks and certificate bytes. It validates handshake parsers, length fields,
 * and encrypted-path setup without using a real server.
 */
static int build_server_connect_response(rdp_buffer* out, int encrypted, int extra_static_channel)
{
    static const uint8_t oid[] = {5, 0, 20, 124, 0, 1};
    static const uint8_t key[] = {'M', 'c', 'D', 'n'};
    static const uint8_t server_random[32] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
    };
    static const uint8_t server_certificate[] = {
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x9c, 0x00, 0x52, 0x53, 0x41, 0x31, 0x88, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0xeb, 0x63, 0x25, 0x72, 0xe3, 0xeb, 0x4e, 0x15, 0x13, 0x3c, 0x7b, 0x9c,
        0x5c, 0x66, 0x61, 0x89, 0x0f, 0x7f, 0x79, 0x1a, 0x93, 0x75, 0x9c, 0xe2,
        0x98, 0xeb, 0xa5, 0xa6, 0x73, 0xd2, 0xc7, 0x14, 0x2c, 0x5a, 0x57, 0x10,
        0x48, 0x3b, 0x04, 0x69, 0xaf, 0x52, 0x86, 0x58, 0xe3, 0xf7, 0x05, 0xcf,
        0x22, 0x0f, 0x6e, 0x25, 0x41, 0xe0, 0x3a, 0x26, 0x62, 0x2f, 0x31, 0xcf,
        0xd5, 0x97, 0xd3, 0xa0, 0x93, 0x73, 0x4c, 0x9b, 0xc1, 0x9c, 0x2a, 0x30,
        0x66, 0x7f, 0x61, 0x25, 0x67, 0xab, 0xd3, 0xe7, 0xe2, 0x7f, 0x5e, 0x57,
        0x2a, 0x3a, 0x2b, 0x9c, 0x4f, 0x4e, 0x2c, 0xba, 0x8e, 0xf0, 0x93, 0x29,
        0x3f, 0xf7, 0xca, 0x9e, 0x46, 0xd4, 0x1e, 0x11, 0x96, 0x84, 0xef, 0x2d,
        0xa9, 0x57, 0x3d, 0x8b, 0x9b, 0x27, 0x90, 0x5b, 0x98, 0x9d, 0x5b, 0x80,
        0x64, 0x24, 0x76, 0xc0, 0xba, 0x8d, 0xe4, 0xb2, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    rdp_buffer core;
    rdp_buffer security;
    rdp_buffer network;
    rdp_buffer blocks;
    rdp_buffer gcc;
    rdp_buffer content;
    rdp_buffer mcs;
    size_t total = 0;
    int ok = 0;

    rdp_buffer_init(&core);
    rdp_buffer_init(&security);
    rdp_buffer_init(&network);
    rdp_buffer_init(&blocks);
    rdp_buffer_init(&gcc);
    rdp_buffer_init(&content);
    rdp_buffer_init(&mcs);

    ok = rdp_buffer_append_u32_le(&core, 0x00080004u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&core, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&core, 0) == LIBRDP_STATUS_OK &&
         append_gcc_block(&blocks, 0x0c01u, &core);
    if (ok)
    {
        ok = rdp_buffer_append_u32_le(&security, encrypted ? RDP_SECURITY_METHOD_128BIT : 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u32_le(&security, encrypted ? 3u : 0) == LIBRDP_STATUS_OK;
        if (ok && encrypted)
            ok = rdp_buffer_append_u32_le(&security, (uint32_t)sizeof(server_random)) == LIBRDP_STATUS_OK &&
                 rdp_buffer_append_u32_le(&security, (uint32_t)sizeof(server_certificate)) == LIBRDP_STATUS_OK &&
                 rdp_buffer_append(&security, server_random, sizeof(server_random)) == LIBRDP_STATUS_OK &&
                 rdp_buffer_append(&security, server_certificate, sizeof(server_certificate)) == LIBRDP_STATUS_OK;
        if (ok)
            ok = append_gcc_block(&blocks, 0x0c02u, &security);
    }
    if (ok)
    {
        ok = rdp_buffer_append_u16_le(&network, 1003) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&network, extra_static_channel ? 3u : 1u) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&network, 1004) == LIBRDP_STATUS_OK;
        if (ok && extra_static_channel)
            ok = rdp_buffer_append_u16_le(&network, 1005) == LIBRDP_STATUS_OK &&
                 rdp_buffer_append_u16_le(&network, 1006) == LIBRDP_STATUS_OK;
        if (ok)
            ok = append_gcc_block(&blocks, 0x0c03u, &network);
    }

    if (ok)
        ok = rdp_buffer_append_u8(&gcc, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(&gcc, oid, sizeof(oid)) == LIBRDP_STATUS_OK &&
             append_per_length(&gcc, blocks.length + 14u) &&
             rdp_buffer_append_u8(&gcc, 0x14) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&gcc, 3) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&gcc, 1) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&gcc, 42) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&gcc, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&gcc, 1) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&gcc, 0xc0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&gcc, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(&gcc, key, sizeof(key)) == LIBRDP_STATUS_OK &&
             append_per_length(&gcc, blocks.length) &&
             rdp_buffer_append(&gcc, blocks.data, blocks.length) == LIBRDP_STATUS_OK;
    if (ok)
        ok = rdp_buffer_append_u8(&content, 0x0a) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&content, 0x01) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&content, 0x00) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&content, 0x04) == LIBRDP_STATUS_OK &&
             append_ber_length(&content, gcc.length) &&
             rdp_buffer_append(&content, gcc.data, gcc.length) == LIBRDP_STATUS_OK;
    if (ok)
        ok = rdp_buffer_append_u8(&mcs, 0x7f) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&mcs, 0x66) == LIBRDP_STATUS_OK &&
             append_ber_length(&mcs, content.length) &&
             rdp_buffer_append(&mcs, content.data, content.length) == LIBRDP_STATUS_OK;
    total = mcs.length + 7u;
    if (ok && total <= 0xffffu)
        ok = rdp_buffer_append_u8(out, 0x03) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x00) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(out, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x02) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0xf0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x80) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(out, mcs.data, mcs.length) == LIBRDP_STATUS_OK;

    rdp_buffer_free(&mcs);
    rdp_buffer_free(&content);
    rdp_buffer_free(&gcc);
    rdp_buffer_free(&blocks);
    rdp_buffer_free(&network);
    rdp_buffer_free(&security);
    rdp_buffer_free(&core);
    return ok;
}

static int read_security_payload(const uint8_t* input, size_t input_len, const uint8_t** payload, size_t* payload_len)
{
    size_t pos = 0;
    size_t length = 0;

    if (!input || input_len < 14 || !payload || !payload_len)
        return 0;
    pos = 4;
    if (input[pos++] != 0x02 || input[pos++] != 0xf0 || input[pos++] != 0x80)
        return 0;
    if (input[pos++] != 0x64)
        return 0;
    pos += 5;
    if (pos >= input_len)
        return 0;
    length = input[pos++];
    if ((length & 0x80u) != 0)
    {
        if (pos >= input_len)
            return 0;
        length = ((length & 0x7fu) << 8) | input[pos++];
    }
    if (length > input_len - pos)
        return 0;
    *payload = input + pos;
    *payload_len = length;
    return 1;
}

static int validate_security_exchange(const uint8_t* input, size_t input_len)
{
    const uint8_t* payload = NULL;
    size_t payload_len = 0;
    uint32_t random_len = 0;

    if (!read_security_payload(input, input_len, &payload, &payload_len) || payload_len < 16)
        return 0;
    random_len = (uint32_t)payload[4] | ((uint32_t)payload[5] << 8) | ((uint32_t)payload[6] << 16) |
                 ((uint32_t)payload[7] << 24);
    return ((uint16_t)payload[0] | ((uint16_t)payload[1] << 8)) ==
               (RDP_SEC_EXCHANGE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC) &&
           payload[2] == 0 && payload[3] == 0 &&
           random_len == 136u && payload_len == 144u;
}

static int validate_encrypted_client_info(const uint8_t* input, size_t input_len)
{
    const uint8_t* payload = NULL;
    size_t payload_len = 0;
    uint8_t flags = (uint8_t)(RDP_SEC_INFO_PKT | RDP_SEC_ENCRYPT);

    if (!read_security_payload(input, input_len, &payload, &payload_len) || payload_len < 20)
        return 0;
    return payload[0] == flags && payload[1] == 0 && payload[2] == 0 && payload[3] == 0;
}

static int build_demand_active_packet(rdp_buffer* out)
{
    rdp_buffer caps;
    rdp_buffer slow;
    rdp_buffer mcs;
    const char source[] = {'s', 'r', 'v'};
    size_t total = 0;
    int ok = 0;

    rdp_buffer_init(&caps);
    rdp_buffer_init(&slow);
    rdp_buffer_init(&mcs);

    ok = rdp_buffer_append_u16_le(&caps, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 8) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&caps, 0) == LIBRDP_STATUS_OK;
    total = 6u + 4u + 2u + 2u + sizeof(source) + caps.length + 4u;
    if (ok)
        ok = rdp_buffer_append_u16_le(&slow, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, (uint16_t)(RDP_SLOWPATH_PDU_VERSION | RDP_SLOWPATH_PDU_TYPE_DEMAND_ACTIVE)) ==
                 LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, 1002) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u32_le(&slow, 0x10203040u) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, (uint16_t)sizeof(source)) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, (uint16_t)caps.length) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(&slow, source, sizeof(source)) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(&slow, caps.data, caps.length) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u32_le(&slow, 0) == LIBRDP_STATUS_OK;
    if (ok)
        ok = rdp_buffer_append_u8(&mcs, 0x68) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, 3) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&mcs, 0x70) == LIBRDP_STATUS_OK &&
             append_per_length(&mcs, slow.length) &&
             rdp_buffer_append(&mcs, slow.data, slow.length) == LIBRDP_STATUS_OK;
    total = mcs.length + 7u;
    if (ok)
        ok = rdp_buffer_append_u8(out, 0x03) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x00) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(out, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x02) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0xf0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x80) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(out, mcs.data, mcs.length) == LIBRDP_STATUS_OK;

    rdp_buffer_free(&mcs);
    rdp_buffer_free(&slow);
    rdp_buffer_free(&caps);
    return ok;
}

static int build_license_new_packet(rdp_buffer* out)
{
    static const uint8_t license_data[] = {0x11, 0x22, 0x33, 0x44};
    static const uint8_t license_mac[16] = {0};
    rdp_buffer license;
    rdp_buffer mcs;
    size_t total = 0;
    int ok = 0;

    rdp_buffer_init(&license);
    rdp_buffer_init(&mcs);
    ok = rdp_license_write_preamble(&license,
                                    RDP_LICENSE_MESSAGE_NEW_LICENSE,
                                    RDP_LICENSE_VERSION_3,
                                    (uint16_t)(4u + sizeof(license_data) + sizeof(license_mac))) == LIBRDP_STATUS_OK &&
         rdp_license_write_binary_blob(&license,
                                       RDP_LICENSE_BLOB_ENCRYPTED_DATA,
                                       license_data,
                                       (uint16_t)sizeof(license_data)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&license, license_mac, sizeof(license_mac)) == LIBRDP_STATUS_OK;
    if (ok)
        ok = rdp_buffer_append_u8(&mcs, 0x68) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, 3) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&mcs, 0x70) == LIBRDP_STATUS_OK &&
             append_per_length(&mcs, license.length) &&
             rdp_buffer_append(&mcs, license.data, license.length) == LIBRDP_STATUS_OK;
    total = mcs.length + 7u;
    if (ok)
        ok = rdp_buffer_append_u8(out, 0x03) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x00) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(out, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x02) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0xf0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x80) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(out, mcs.data, mcs.length) == LIBRDP_STATUS_OK;

    rdp_buffer_free(&mcs);
    rdp_buffer_free(&license);
    return ok;
}

static int validate_confirm_active(const uint8_t* input, size_t input_len)
{
    const uint8_t* payload = NULL;
    size_t payload_len = 0;
    rdp_slowpath_share_control_header header;

    if (!read_security_payload(input, input_len, &payload, &payload_len))
        return 0;
    if (rdp_slowpath_parse_share_control_header(payload, payload_len, &header) != LIBRDP_STATUS_OK)
        return 0;
    return (header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE && header.channel_id == 1004 &&
           payload_len >= 16 && payload[6] == 0x40 && payload[7] == 0x30 && payload[8] == 0x20 &&
           payload[9] == 0x10;
}

/*
 * Fixture: builds bitmap update payloads with explicit rectangle and pixel
 * lengths. It targets surface invalidation, bounds checks, and malformed
 * bitmap update handling.
 */
static int build_bitmap_update_packet(rdp_buffer* out)
{
    static const uint8_t pixels[] = {
        1,  2,  3,  4,  5,  6,  7,  8,
        9,  10, 11, 12, 13, 14, 15, 16
    };
    rdp_buffer payload;
    rdp_buffer slow;
    rdp_buffer mcs;
    size_t total = 0;
    int ok = 0;

    rdp_buffer_init(&payload);
    rdp_buffer_init(&slow);
    rdp_buffer_init(&mcs);

    ok = rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 2) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 2) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 32) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&payload, (uint32_t)sizeof(pixels)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&payload, pixels, sizeof(pixels)) == LIBRDP_STATUS_OK;
    total = payload.length + 18u;
    if (ok)
        ok = rdp_buffer_append_u16_le(&slow, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, (uint16_t)(RDP_SLOWPATH_PDU_VERSION | RDP_SLOWPATH_PDU_TYPE_DATA)) ==
                 LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, 1004) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u32_le(&slow, 0x10203040u) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, 1) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, (uint16_t)payload.length) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, RDP_SLOWPATH_DATA_PDU_UPDATE) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(&slow, payload.data, payload.length) == LIBRDP_STATUS_OK;
    if (ok)
        ok = rdp_buffer_append_u8(&mcs, 0x68) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, 3) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&mcs, 0x70) == LIBRDP_STATUS_OK &&
             append_per_length(&mcs, slow.length) &&
             rdp_buffer_append(&mcs, slow.data, slow.length) == LIBRDP_STATUS_OK;
    total = mcs.length + 7u;
    if (ok)
        ok = rdp_buffer_append_u8(out, 0x03) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x00) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(out, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x02) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0xf0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x80) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(out, mcs.data, mcs.length) == LIBRDP_STATUS_OK;

    rdp_buffer_free(&mcs);
    rdp_buffer_free(&slow);
    rdp_buffer_free(&payload);
    return ok;
}

/*
 * Fixture: builds a slow-path GDI orders update with cache and render
 * operations. It exercises order sequencing, cache lifetime, and renderer
 * bounds handling.
 */
static int build_gdi_update_packet_from_orders(rdp_buffer* out,
                                               const void* order_data,
                                               size_t order_data_len,
                                               uint16_t order_count)
{
    rdp_buffer payload;
    rdp_buffer slow;
    rdp_buffer mcs;
    size_t total = 0;
    int ok = 0;

    if (!out || (!order_data && order_data_len > 0))
        return 0;

    rdp_buffer_init(&payload);
    rdp_buffer_init(&slow);
    rdp_buffer_init(&mcs);

    ok = rdp_gdi_write_slow_orders_update_payload(&payload,
                                                  order_count,
                                                  order_data,
                                                  order_data_len) == LIBRDP_STATUS_OK;
    total = payload.length + 18u;
    if (ok)
        ok = rdp_buffer_append_u16_le(&slow, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, (uint16_t)(RDP_SLOWPATH_PDU_VERSION | RDP_SLOWPATH_PDU_TYPE_DATA)) ==
                 LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, 1004) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u32_le(&slow, 0x10203040u) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, 1) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, (uint16_t)payload.length) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, RDP_SLOWPATH_DATA_PDU_UPDATE) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(&slow, payload.data, payload.length) == LIBRDP_STATUS_OK;
    if (ok)
        ok = rdp_buffer_append_u8(&mcs, 0x68) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, 3) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&mcs, 0x70) == LIBRDP_STATUS_OK &&
             append_per_length(&mcs, slow.length) &&
             rdp_buffer_append(&mcs, slow.data, slow.length) == LIBRDP_STATUS_OK;
    total = mcs.length + 7u;
    if (ok)
        ok = rdp_buffer_append_u8(out, 0x03) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x00) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(out, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x02) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0xf0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x80) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(out, mcs.data, mcs.length) == LIBRDP_STATUS_OK;

    rdp_buffer_free(&mcs);
    rdp_buffer_free(&slow);
    rdp_buffer_free(&payload);
    return ok;
}

static int build_gdi_orders_update_packet(rdp_buffer* out)
{
    static const uint8_t render_opaque[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_OPAQUERECT,
        0x1fu,
        0x02u, 0x00u,
        0x03u, 0x00u,
        0x04u, 0x00u,
        0x05u, 0x00u,
        0x11u, 0x22u, 0x33u
    };
    static const uint8_t render_scrblt[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_SCRBLT,
        0x7fu,
        0x08u, 0x00u,
        0x03u, 0x00u,
        0x04u, 0x00u,
        0x05u, 0x00u,
        0xccu,
        0x02u, 0x00u,
        0x03u, 0x00u
    };
    static const uint8_t render_patblt[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_PATBLT,
        0x7fu, 0x00u,
        0x0cu, 0x00u,
        0x04u, 0x00u,
        0x03u, 0x00u,
        0x02u, 0x00u,
        0xf0u,
        0x01u, 0x02u, 0x03u,
        0x44u, 0x55u, 0x66u
    };
    static const uint8_t render_lineto[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_LINETO,
        0xffu, 0x03u,
        0x00u, 0x00u,
        0x10u, 0x00u,
        0x06u, 0x00u,
        0x14u, 0x00u,
        0x06u, 0x00u,
        0x00u, 0x00u, 0x00u,
        13u,
        0x00u,
        0x01u,
        0x31u, 0x32u, 0x33u
    };
    rdp_buffer orders;
    int ok = 0;

    rdp_buffer_init(&orders);

    ok = rdp_buffer_append(&orders, render_opaque, sizeof(render_opaque)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, render_scrblt, sizeof(render_scrblt)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, render_patblt, sizeof(render_patblt)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, render_lineto, sizeof(render_lineto)) == LIBRDP_STATUS_OK &&
         build_gdi_update_packet_from_orders(out, orders.data, orders.length, 4);

    rdp_buffer_free(&orders);
    return ok;
}

static int build_gdi_unsupported_altsec_update_packet(rdp_buffer* out)
{
    static const uint8_t gdiplus_first_altsec[] = {
        (uint8_t)((RDP_GDI_ALTSEC_DRAW_GDIPLUS_FIRST << 2u) | RDP_GDI_TS_SECONDARY),
        0x03u,
        0x00u,
        0x03u,
        0x00u,
        0x00u,
        0x00u,
        0x03u,
        0x00u,
        0x00u,
        0x00u,
        0xaau,
        0xbbu,
        0xccu
    };

    return build_gdi_update_packet_from_orders(out,
                                               gdiplus_first_altsec,
                                               sizeof(gdiplus_first_altsec),
                                               1);
}

static int build_set_error_info_packet(rdp_buffer* out, uint32_t error_info)
{
    rdp_buffer payload;
    rdp_buffer slow;
    rdp_buffer mcs;
    size_t total = 0;
    int ok = 0;

    rdp_buffer_init(&payload);
    rdp_buffer_init(&slow);
    rdp_buffer_init(&mcs);

    ok = rdp_buffer_append_u32_le(&payload, error_info) == LIBRDP_STATUS_OK;
    total = payload.length + 18u;
    if (ok)
        ok = rdp_buffer_append_u16_le(&slow, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, (uint16_t)(RDP_SLOWPATH_PDU_VERSION | RDP_SLOWPATH_PDU_TYPE_DATA)) ==
                 LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, 1004) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u32_le(&slow, 0x10203040u) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, 1) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, (uint16_t)payload.length) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, RDP_SLOWPATH_DATA_PDU_SET_ERROR_INFO) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(&slow, payload.data, payload.length) == LIBRDP_STATUS_OK;
    if (ok)
        ok = rdp_buffer_append_u8(&mcs, 0x68) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, 3) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&mcs, 0x70) == LIBRDP_STATUS_OK &&
             append_per_length(&mcs, slow.length) &&
             rdp_buffer_append(&mcs, slow.data, slow.length) == LIBRDP_STATUS_OK;
    total = mcs.length + 7u;
    if (ok)
        ok = rdp_buffer_append_u8(out, 0x03) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x00) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(out, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x02) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0xf0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x80) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(out, mcs.data, mcs.length) == LIBRDP_STATUS_OK;

    rdp_buffer_free(&mcs);
    rdp_buffer_free(&slow);
    rdp_buffer_free(&payload);
    return ok;
}

static int build_static_channel_fragment_packet(rdp_buffer* out,
                                                const void* data,
                                                size_t data_len,
                                                uint32_t total_len,
                                                uint32_t flags,
                                                uint16_t channel_id)
{
    rdp_buffer channel;
    rdp_buffer mcs;
    size_t total = 0;
    int ok = 0;

    if (!out || (!data && data_len > 0))
        return 0;
    rdp_buffer_init(&channel);
    rdp_buffer_init(&mcs);

    ok = rdp_buffer_append_u32_le(&channel, total_len) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&channel, flags) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&channel, data, data_len) == LIBRDP_STATUS_OK;
    if (ok)
        ok = rdp_buffer_append_u8(&mcs, 0x68) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, 3) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, channel_id) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&mcs, 0x70) == LIBRDP_STATUS_OK &&
             append_per_length(&mcs, channel.length) &&
             rdp_buffer_append(&mcs, channel.data, channel.length) == LIBRDP_STATUS_OK;
    total = mcs.length + 7u;
    if (ok)
        ok = rdp_buffer_append_u8(out, 0x03) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x00) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(out, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x02) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0xf0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x80) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(out, mcs.data, mcs.length) == LIBRDP_STATUS_OK;

    rdp_buffer_free(&mcs);
    rdp_buffer_free(&channel);
    return ok;
}

static int build_static_channel_packet(rdp_buffer* out, const rdp_buffer* payload, uint16_t channel_id)
{
    if (!payload)
        return 0;
    return build_static_channel_fragment_packet(out,
                                                payload->data,
                                                payload->length,
                                                (uint32_t)payload->length,
                                                RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST |
                                                    RDP_VIRTUAL_CHANNEL_FLAG_SHOW_PROTOCOL,
                                                channel_id);
}

static int build_clipboard_unmatched_response_packets(rdp_buffer* data_response_out,
                                                      rdp_buffer* file_response_out)
{
    static const uint8_t data_payload[] = {'l', 'a', 't', 'e'};
    rdp_buffer clipboard;
    int ok = 0;

    if (!data_response_out || !file_response_out)
        return 0;

    rdp_buffer_init(&clipboard);
    ok = rdp_clipboard_write_format_data_response(&clipboard,
                                                  1,
                                                  data_payload,
                                                  sizeof(data_payload)) == LIBRDP_STATUS_OK &&
         build_static_channel_packet(data_response_out, &clipboard, 1005);
    rdp_buffer_free(&clipboard);
    if (!ok)
        return 0;

    rdp_buffer_init(&clipboard);
    ok = rdp_clipboard_write_file_contents_response(&clipboard,
                                                    1,
                                                    0x11223344u,
                                                    data_payload,
                                                    sizeof(data_payload)) == LIBRDP_STATUS_OK &&
         build_static_channel_packet(file_response_out, &clipboard, 1005);
    rdp_buffer_free(&clipboard);
    return ok;
}

static int build_application_static_channel_first_packet(rdp_buffer* out)
{
    static const uint8_t data[] = {'s', 't', 'a', 't'};

    return build_static_channel_fragment_packet(out,
                                                data,
                                                sizeof(data),
                                                8u,
                                                RDP_VIRTUAL_CHANNEL_FLAG_FIRST |
                                                    RDP_VIRTUAL_CHANNEL_FLAG_SHOW_PROTOCOL,
                                                1006);
}

static int build_application_static_channel_last_packet(rdp_buffer* out)
{
    static const uint8_t data[] = {'c', 'h', 'a', 'n'};

    return build_static_channel_fragment_packet(out,
                                                data,
                                                sizeof(data),
                                                8u,
                                                RDP_VIRTUAL_CHANNEL_FLAG_LAST |
                                                    RDP_VIRTUAL_CHANNEL_FLAG_SHOW_PROTOCOL,
                                                1006);
}

static int build_dynamic_channel_create_named_packet(rdp_buffer* out, const char* name)
{
    rdp_buffer payload;
    size_t name_len = 0;
    int ok = 0;

    if (!out || !name)
        return 0;
    name_len = strlen(name);
    if (name_len == 0)
        return 0;

    rdp_buffer_init(&payload);
    ok = rdp_buffer_append_u8(&payload,
                              (uint8_t)((RDP_DYNAMIC_CHANNEL_CMD_CREATE << 4) |
                                        (LIBRDP_CHANNEL_PRIORITY_MEDIUM << 2))) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 7) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&payload, name, name_len + 1u) == LIBRDP_STATUS_OK &&
         build_static_channel_packet(out, &payload, 1004);
    rdp_buffer_free(&payload);
    return ok;
}

static int build_dynamic_channel_create_packet(rdp_buffer* out)
{
    return build_dynamic_channel_create_named_packet(out, "ECHO");
}

static int build_dynamic_channel_create_webauthn_packet(rdp_buffer* out)
{
    return build_dynamic_channel_create_named_packet(out, "WebAuthN_Channel");
}

static int build_dynamic_channel_create_display_control_packet(rdp_buffer* out)
{
    return build_dynamic_channel_create_named_packet(out, "Microsoft::Windows::RDS::DisplayControl");
}

static int build_dynamic_channel_data_first_packet(rdp_buffer* out)
{
    static const uint8_t data[] = {'a', 'b', 'c', 'd'};
    rdp_buffer payload;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = rdp_dynamic_channel_write_data_first(&payload, 7, 1, 8, data, sizeof(data)) == LIBRDP_STATUS_OK &&
         build_static_channel_packet(out, &payload, 1004);
    rdp_buffer_free(&payload);
    return ok;
}

static int build_dynamic_channel_data_packet(rdp_buffer* out)
{
    static const uint8_t data[] = {'e', 'f', 'g', 'h'};
    rdp_buffer payload;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = rdp_dynamic_channel_write_data(&payload, 7, 1, data, sizeof(data)) == LIBRDP_STATUS_OK &&
         build_static_channel_packet(out, &payload, 1004);
    rdp_buffer_free(&payload);
    return ok;
}

static int build_dynamic_channel_empty_data_packet(rdp_buffer* out)
{
    rdp_buffer payload;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = rdp_dynamic_channel_write_data(&payload, 7, 1, NULL, 0) == LIBRDP_STATUS_OK &&
         build_static_channel_packet(out, &payload, 1004);
    rdp_buffer_free(&payload);
    return ok;
}

static int build_dynamic_channel_empty_compressed_data_first_packet(rdp_buffer* out)
{
    static const uint8_t data[] = {0xe0u, 0x04u};
    rdp_buffer payload;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = rdp_dynamic_channel_write_compressed_data_first(&payload, 7, 1, 8, data, sizeof(data)) ==
             LIBRDP_STATUS_OK &&
         build_static_channel_packet(out, &payload, 1004);
    rdp_buffer_free(&payload);
    return ok;
}

static int build_dynamic_channel_compressed_data_first_packet(rdp_buffer* out)
{
    static const uint8_t data[] = {0xe0u, 0x04u, 'a', 'b', 'c', 'd'};
    rdp_buffer payload;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = rdp_dynamic_channel_write_compressed_data_first(&payload, 7, 1, 8, data, sizeof(data)) ==
             LIBRDP_STATUS_OK &&
         build_static_channel_packet(out, &payload, 1004);
    rdp_buffer_free(&payload);
    return ok;
}

static int build_dynamic_channel_empty_compressed_data_packet(rdp_buffer* out)
{
    static const uint8_t data[] = {0xe0u, 0x04u};
    rdp_buffer payload;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = rdp_dynamic_channel_write_compressed_data(&payload, 7, 1, data, sizeof(data)) ==
             LIBRDP_STATUS_OK &&
         build_static_channel_packet(out, &payload, 1004);
    rdp_buffer_free(&payload);
    return ok;
}

static int build_dynamic_channel_display_control_caps_packet(rdp_buffer* out)
{
    rdp_buffer caps;
    rdp_buffer payload;
    int ok = 0;

    rdp_buffer_init(&caps);
    rdp_buffer_init(&payload);
    ok = rdp_buffer_append_u32_le(&caps, RDP_DISPLAY_CONTROL_PDU_CAPS) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&caps, 20u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&caps, 1u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&caps, 8192u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&caps, 8192u) == LIBRDP_STATUS_OK &&
         rdp_dynamic_channel_write_data(&payload, 7, 1, caps.data, caps.length) == LIBRDP_STATUS_OK &&
         build_static_channel_packet(out, &payload, 1004);
    rdp_buffer_free(&payload);
    rdp_buffer_free(&caps);
    return ok;
}

static int build_dynamic_channel_close_packet(rdp_buffer* out)
{
    rdp_buffer payload;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = rdp_dynamic_channel_write_close(&payload, 7, 1) == LIBRDP_STATUS_OK &&
         build_static_channel_packet(out, &payload, 1004);
    rdp_buffer_free(&payload);
    return ok;
}

static int build_dynamic_channel_soft_sync_tunnel_request_packet(rdp_buffer* out)
{
    rdp_buffer payload;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = rdp_buffer_append_u8(&payload,
                              (uint8_t)(RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_REQUEST << 4)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&payload, 22u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload,
                                  RDP_DYNAMIC_CHANNEL_SOFT_SYNC_TCP_FLUSHED |
                                      RDP_DYNAMIC_CHANNEL_SOFT_SYNC_CHANNEL_LIST_PRESENT) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 1u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&payload, RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 2u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&payload, 7u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&payload, 0x1234u) == LIBRDP_STATUS_OK &&
         build_static_channel_packet(out, &payload, 1004);
    rdp_buffer_free(&payload);
    return ok;
}

static int build_dynamic_channel_create_response_packet(rdp_buffer* out, uint32_t channel_id)
{
    rdp_buffer payload;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = rdp_dynamic_channel_write_create_response(&payload,
                                                   channel_id,
                                                   rdp_dynamic_channel_select_channel_id_bytes(channel_id),
                                                   RDP_DYNAMIC_CHANNEL_STATUS_OK) == LIBRDP_STATUS_OK &&
         build_static_channel_packet(out, &payload, 1004);
    rdp_buffer_free(&payload);
    return ok;
}

static int read_tpkt_fd(int fd, uint8_t* data, size_t capacity, size_t* length)
{
    uint16_t total = 0;

    if (!data || capacity < 4 || !length)
        return 0;
    if (!read_exact_fd(fd, data, 4))
        return 0;
    total = (uint16_t)(((uint16_t)data[2] << 8) | data[3]);
    if (data[0] != 3 || data[1] != 0 || total < 4 || total > capacity)
        return 0;
    if (!read_exact_fd(fd, data + 4, (size_t)total - 4u))
        return 0;
    *length = total;
    return 1;
}

static int parse_client_dynamic_channel_payload(const uint8_t* input,
                                                size_t input_len,
                                                uint16_t expected_channel_id,
                                                rdp_virtual_channel_packet* packet)
{
    rdp_tpkt tpkt;
    rdp_stream stream;
    const uint8_t* x224_payload = NULL;
    const uint8_t* channel_payload = NULL;
    size_t x224_payload_len = 0;
    size_t channel_payload_len = 0;
    uint8_t domain_choice = 0;
    uint8_t data_priority = 0;
    uint16_t user_delta = 0;
    uint16_t channel_id = 0;

    if (!input || !packet)
        return 0;
    if (rdp_tpkt_parse(input, input_len, &tpkt) != LIBRDP_STATUS_OK ||
        rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_payload, &x224_payload_len) !=
            LIBRDP_STATUS_OK)
        return 0;

    rdp_stream_init(&stream, x224_payload, x224_payload_len);
    if (rdp_stream_read_u8(&stream, &domain_choice) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_be(&stream, &user_delta) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_be(&stream, &channel_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &data_priority) != LIBRDP_STATUS_OK ||
        !read_per_length_from_stream(&stream, &channel_payload_len))
    {
        return 0;
    }
    if (domain_choice != (uint8_t)(25u << 2) ||
        user_delta > UINT16_MAX - RDP_MCS_BASE_CHANNEL_ID ||
        channel_id != expected_channel_id ||
        data_priority != 0x70 ||
        channel_payload_len != rdp_stream_remaining(&stream))
    {
        return 0;
    }
    if (rdp_stream_read_bytes(&stream, &channel_payload, channel_payload_len) != LIBRDP_STATUS_OK)
        return 0;
    return rdp_virtual_channel_parse_packet(channel_payload, channel_payload_len, packet) == LIBRDP_STATUS_OK;
}

static int read_soft_sync_response_fd(int fd, uint8_t* input, size_t capacity, uint16_t expected_channel_id)
{
    for (size_t attempt = 0; attempt < 8u; attempt++)
    {
        size_t input_len = 0;
        rdp_virtual_channel_packet response_packet;
        rdp_dynamic_channel_soft_sync_response soft_sync_response;

        if (!read_tpkt_fd(fd, input, capacity, &input_len))
            return 0;
        if (!parse_client_dynamic_channel_payload(input,
                                                  input_len,
                                                  expected_channel_id,
                                                  &response_packet))
            continue;
        if (rdp_dynamic_channel_parse_soft_sync_response(response_packet.payload,
                                                        response_packet.payload_len,
                                                        &soft_sync_response) == LIBRDP_STATUS_OK)
            return soft_sync_response.tunnel_count == 0;
    }
    return 0;
}

static int reserve_closed_loopback_port(uint16_t* port)
{
    int fd = -1;
    struct sockaddr_in addr;
    socklen_t addr_len = (socklen_t)sizeof(addr);

    if (!port)
        return 0;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        getsockname(fd, (struct sockaddr*)&addr, &addr_len) != 0)
    {
        close(fd);
        return 0;
    }
    *port = ntohs(addr.sin_port);
    close(fd);
    return 1;
}

/*
 * Fixture: starts a local handshake peer that feeds deterministic protocol
 * bytes to the client session. It isolates connection state-machine coverage
 * from external network and credential dependencies.
 */
static int start_handshake_server_full(uint16_t* port,
                                       pid_t* child_pid,
                                       int encrypted,
                                       uint32_t error_info,
                                       int extra_static_channel,
                                       int client_dynamic_channel_open_response,
                                       int connection_count,
                                       int dynamic_channel_scenario,
                                       int gdi_scenario,
                                       int send_license_new,
                                       int clipboard_scenario)
{
    int fd = -1;
    struct sockaddr_in addr;
    socklen_t addr_len = (socklen_t)sizeof(addr);

    if (!port || !child_pid)
        return 0;
    if (connection_count <= 0 || connection_count > 4)
        return 0;
    if (gdi_scenario != GDI_SCENARIO_NORMAL &&
        gdi_scenario != GDI_SCENARIO_UNSUPPORTED_ALTSEC)
        return 0;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        getsockname(fd, (struct sockaddr*)&addr, &addr_len) != 0 ||
        listen(fd, connection_count) != 0)
    {
        close(fd);
        return 0;
    }

    *port = ntohs(addr.sin_port);
    *child_pid = fork();
    if (*child_pid < 0)
    {
        close(fd);
        return 0;
    }

    if (*child_pid == 0)
    {
        const uint8_t response[] = {
            0x03, 0x00, 0x00, 0x13,
            0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x08, 0x00,
            0x00, 0x00, 0x00, 0x00
        };
        const uint8_t attach_confirm[] = {
            0x03, 0x00, 0x00, 0x0b,
            0x02, 0xf0, 0x80,
            0x2e, 0x00, 0x00, 0x03
        };
        const uint8_t join_user_confirm[] = {
            0x03, 0x00, 0x00, 0x0f,
            0x02, 0xf0, 0x80,
            0x3e, 0x00, 0x00, 0x03, 0x03, 0xec, 0x03, 0xec
        };
        const uint8_t join_global_confirm[] = {
            0x03, 0x00, 0x00, 0x0f,
            0x02, 0xf0, 0x80,
            0x3e, 0x00, 0x00, 0x03, 0x03, 0xeb, 0x03, 0xeb
        };
        const uint8_t join_clipboard_confirm[] = {
            0x03, 0x00, 0x00, 0x0f,
            0x02, 0xf0, 0x80,
            0x3e, 0x00, 0x00, 0x03, 0x03, 0xed, 0x03, 0xed
        };
        const uint8_t join_static_confirm[] = {
            0x03, 0x00, 0x00, 0x0f,
            0x02, 0xf0, 0x80,
            0x3e, 0x00, 0x00, 0x03, 0x03, 0xee, 0x03, 0xee
        };
        struct timespec ts;
        int connection = 0;

        for (connection = 0; connection < connection_count; connection++)
        {
            uint8_t input[4096];
            size_t input_len = 0;
            rdp_buffer mcs_response;
            rdp_buffer license_new;
            rdp_buffer demand_active;
            rdp_buffer bitmap_update;
            rdp_buffer gdi_orders_update;
            rdp_buffer dvc_create;
            rdp_buffer dvc_data_first;
            rdp_buffer dvc_data;
            rdp_buffer dvc_empty_data;
            rdp_buffer dvc_close;
            rdp_buffer dvc_create_response;
            rdp_buffer dvc_soft_sync;
            rdp_buffer clipboard_data_response;
            rdp_buffer clipboard_file_response;
            rdp_buffer static_first;
            rdp_buffer static_last;
            rdp_buffer error_update;
            int client = accept(fd, NULL, NULL);

            rdp_buffer_init(&mcs_response);
            rdp_buffer_init(&license_new);
            rdp_buffer_init(&demand_active);
            rdp_buffer_init(&bitmap_update);
            rdp_buffer_init(&gdi_orders_update);
            rdp_buffer_init(&dvc_create);
            rdp_buffer_init(&dvc_data_first);
            rdp_buffer_init(&dvc_data);
            rdp_buffer_init(&dvc_empty_data);
            rdp_buffer_init(&dvc_close);
            rdp_buffer_init(&dvc_create_response);
            rdp_buffer_init(&dvc_soft_sync);
            rdp_buffer_init(&clipboard_data_response);
            rdp_buffer_init(&clipboard_file_response);
            rdp_buffer_init(&static_first);
            rdp_buffer_init(&static_last);
            rdp_buffer_init(&error_update);
            if (client < 0)
                _exit(6);
            if (!build_server_connect_response(&mcs_response, encrypted, extra_static_channel))
                _exit(1);
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)write_exact_fd(client, response, sizeof(response));
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)write_exact_fd(client, mcs_response.data, mcs_response.length);
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)write_exact_fd(client, attach_confirm, sizeof(attach_confirm));
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)write_exact_fd(client, join_user_confirm, sizeof(join_user_confirm));
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)write_exact_fd(client, join_global_confirm, sizeof(join_global_confirm));
            if (extra_static_channel)
            {
                (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
                (void)write_exact_fd(client, join_clipboard_confirm, sizeof(join_clipboard_confirm));
                (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
                (void)write_exact_fd(client, join_static_confirm, sizeof(join_static_confirm));
            }
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            if (encrypted)
            {
                if (!validate_security_exchange(input, input_len))
                    _exit(2);
                if (!read_tpkt_fd(client, input, sizeof(input), &input_len) ||
                    !validate_encrypted_client_info(input, input_len))
                    _exit(3);
            }
            else
            {
                if (send_license_new &&
                    (!build_license_new_packet(&license_new) ||
                     !write_exact_fd(client, license_new.data, license_new.length)))
                    _exit(4);
                if (!build_demand_active_packet(&demand_active) ||
                    !write_exact_fd(client, demand_active.data, demand_active.length) ||
                    !read_tpkt_fd(client, input, sizeof(input), &input_len) ||
                    !validate_confirm_active(input, input_len))
                    _exit(4);
                if (error_info != 0)
                {
                    if (!build_set_error_info_packet(&error_update, error_info) ||
                        !write_exact_fd(client, error_update.data, error_update.length))
                        _exit(5);
                }
                else
                {
                    if (!build_bitmap_update_packet(&bitmap_update) ||
                        !write_exact_fd(client, bitmap_update.data, bitmap_update.length) ||
                        !((gdi_scenario == GDI_SCENARIO_UNSUPPORTED_ALTSEC) ?
                              build_gdi_unsupported_altsec_update_packet(&gdi_orders_update) :
                              build_gdi_orders_update_packet(&gdi_orders_update)) ||
                        !write_exact_fd(client, gdi_orders_update.data, gdi_orders_update.length) ||
                        (gdi_scenario == GDI_SCENARIO_NORMAL &&
                         extra_static_channel &&
                         (!build_application_static_channel_first_packet(&static_first) ||
                          !write_exact_fd(client, static_first.data, static_first.length) ||
                          !build_application_static_channel_last_packet(&static_last) ||
                          !write_exact_fd(client, static_last.data, static_last.length))))
                    {
                        _exit(5);
                    }
                    if (gdi_scenario == GDI_SCENARIO_UNSUPPORTED_ALTSEC)
                        goto done_connection;
                    if (clipboard_scenario == CLIPBOARD_SCENARIO_UNMATCHED_RESPONSES)
                    {
                        if (!extra_static_channel ||
                            !build_clipboard_unmatched_response_packets(&clipboard_data_response,
                                                                        &clipboard_file_response) ||
                            !write_exact_fd(client,
                                            clipboard_data_response.data,
                                            clipboard_data_response.length) ||
                            !write_exact_fd(client,
                                            clipboard_file_response.data,
                                            clipboard_file_response.length))
                        {
                            _exit(5);
                        }
                    }
                    if (dynamic_channel_scenario == DVC_SCENARIO_DATA_BEFORE_CREATE)
                    {
                        if (!build_dynamic_channel_data_packet(&dvc_data) ||
                            !write_exact_fd(client, dvc_data.data, dvc_data.length))
                        {
                            _exit(5);
                        }
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_WEBAUTHN_CREATE_CLOSE)
                    {
                        if (!build_dynamic_channel_create_webauthn_packet(&dvc_create) ||
                            !write_exact_fd(client, dvc_create.data, dvc_create.length) ||
                            !build_dynamic_channel_close_packet(&dvc_close) ||
                            !write_exact_fd(client, dvc_close.data, dvc_close.length))
                        {
                            _exit(5);
                        }
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_SOFT_SYNC_TUNNEL_REQUEST)
                    {
                        if (!build_dynamic_channel_soft_sync_tunnel_request_packet(&dvc_soft_sync) ||
                            !write_exact_fd(client, dvc_soft_sync.data, dvc_soft_sync.length) ||
                            !read_soft_sync_response_fd(client, input, sizeof(input), 1004))
                        {
                            _exit(5);
                        }
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_DISPLAY_CONTROL_CAPS_REJECT_LAYOUT)
                    {
                        if (!build_dynamic_channel_create_display_control_packet(&dvc_create) ||
                            !write_exact_fd(client, dvc_create.data, dvc_create.length))
                        {
                            _exit(5);
                        }
                    }
                    else if (!build_dynamic_channel_create_packet(&dvc_create) ||
                             !write_exact_fd(client, dvc_create.data, dvc_create.length))
                    {
                        _exit(5);
                    }
                    if (dynamic_channel_scenario == DVC_SCENARIO_DUPLICATE_CREATE)
                    {
                        if (!write_exact_fd(client, dvc_create.data, dvc_create.length))
                            _exit(5);
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_CLOSE_PENDING_FRAGMENT)
                    {
                        if (!build_dynamic_channel_data_first_packet(&dvc_data_first) ||
                            !write_exact_fd(client, dvc_data_first.data, dvc_data_first.length) ||
                            !build_dynamic_channel_close_packet(&dvc_close) ||
                            !write_exact_fd(client, dvc_close.data, dvc_close.length))
                        {
                            _exit(5);
                        }
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_EMPTY_CONTINUATION)
                    {
                        if (!build_dynamic_channel_data_first_packet(&dvc_data_first) ||
                            !write_exact_fd(client, dvc_data_first.data, dvc_data_first.length) ||
                            !build_dynamic_channel_empty_data_packet(&dvc_empty_data) ||
                            !write_exact_fd(client, dvc_empty_data.data, dvc_empty_data.length))
                        {
                            _exit(5);
                        }
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_NESTED_DATA_FIRST)
                    {
                        if (!build_dynamic_channel_data_first_packet(&dvc_data_first) ||
                            !write_exact_fd(client, dvc_data_first.data, dvc_data_first.length) ||
                            !write_exact_fd(client, dvc_data_first.data, dvc_data_first.length))
                        {
                            _exit(5);
                        }
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_EMPTY_COMPRESSED_FIRST)
                    {
                        if (!build_dynamic_channel_empty_compressed_data_first_packet(&dvc_data_first) ||
                            !write_exact_fd(client, dvc_data_first.data, dvc_data_first.length))
                        {
                            _exit(5);
                        }
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_EMPTY_COMPRESSED_CONTINUATION)
                    {
                        if (!build_dynamic_channel_compressed_data_first_packet(&dvc_data_first) ||
                            !write_exact_fd(client, dvc_data_first.data, dvc_data_first.length) ||
                            !build_dynamic_channel_empty_compressed_data_packet(&dvc_data) ||
                            !write_exact_fd(client, dvc_data.data, dvc_data.length))
                        {
                            _exit(5);
                        }
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_DISPLAY_CONTROL_CAPS_REJECT_LAYOUT)
                    {
                        if (!build_dynamic_channel_display_control_caps_packet(&dvc_data) ||
                            !write_exact_fd(client, dvc_data.data, dvc_data.length))
                        {
                            _exit(5);
                        }
                    }
                    else if (dynamic_channel_scenario != DVC_SCENARIO_SOFT_SYNC_TUNNEL_REQUEST &&
                             (!build_dynamic_channel_data_first_packet(&dvc_data_first) ||
                              !write_exact_fd(client, dvc_data_first.data, dvc_data_first.length) ||
                              !build_dynamic_channel_data_packet(&dvc_data) ||
                              !write_exact_fd(client, dvc_data.data, dvc_data.length) ||
                              !build_dynamic_channel_close_packet(&dvc_close) ||
                              !write_exact_fd(client, dvc_close.data, dvc_close.length) ||
                              (client_dynamic_channel_open_response &&
                               (!read_tpkt_fd(client, input, sizeof(input), &input_len) ||
                                !build_dynamic_channel_create_response_packet(&dvc_create_response, 1u) ||
                                !write_exact_fd(client,
                                                dvc_create_response.data,
                                                dvc_create_response.length)))))
                    {
                        _exit(5);
                    }
                }
            }
done_connection:
            ts.tv_sec = 1;
            ts.tv_nsec = 0;
            (void)nanosleep(&ts, NULL);
            close(client);
            rdp_buffer_free(&error_update);
            rdp_buffer_free(&static_last);
            rdp_buffer_free(&static_first);
            rdp_buffer_free(&clipboard_file_response);
            rdp_buffer_free(&clipboard_data_response);
            rdp_buffer_free(&dvc_close);
            rdp_buffer_free(&dvc_create_response);
            rdp_buffer_free(&dvc_soft_sync);
            rdp_buffer_free(&dvc_empty_data);
            rdp_buffer_free(&dvc_data);
            rdp_buffer_free(&dvc_data_first);
            rdp_buffer_free(&dvc_create);
            rdp_buffer_free(&gdi_orders_update);
            rdp_buffer_free(&bitmap_update);
            rdp_buffer_free(&demand_active);
            rdp_buffer_free(&license_new);
            rdp_buffer_free(&mcs_response);
        }
        close(fd);
        _exit(0);
    }

    close(fd);
    return 1;
}

static int start_handshake_server_multi(uint16_t* port,
                                        pid_t* child_pid,
                                        int encrypted,
                                        uint32_t error_info,
                                        int extra_static_channel,
                                        int client_dynamic_channel_open_response,
                                        int connection_count,
                                        int dynamic_channel_scenario,
                                        int send_license_new,
                                        int clipboard_scenario)
{
    return start_handshake_server_full(port,
                                       child_pid,
                                       encrypted,
                                       error_info,
                                       extra_static_channel,
                                       client_dynamic_channel_open_response,
                                       connection_count,
                                       dynamic_channel_scenario,
                                       GDI_SCENARIO_NORMAL,
                                       send_license_new,
                                       clipboard_scenario);
}

static int start_handshake_server_ex(uint16_t* port,
                                     pid_t* child_pid,
                                     int encrypted,
                                     uint32_t error_info,
                                     int extra_static_channel,
                                     int client_dynamic_channel_open_response)
{
    return start_handshake_server_multi(port,
                                        child_pid,
                                        encrypted,
                                        error_info,
                                        extra_static_channel,
                                        client_dynamic_channel_open_response,
                                        1,
                                        DVC_SCENARIO_NORMAL,
                                        0,
                                        CLIPBOARD_SCENARIO_NONE);
}

static int start_handshake_server(uint16_t* port, pid_t* child_pid, int encrypted, uint32_t error_info)
{
    return start_handshake_server_ex(port, child_pid, encrypted, error_info, 0, 0);
}

static int test_static_channels(void)
{
    librdp_settings* settings = NULL;
    librdp_settings* copy = NULL;
    librdp_session* session = NULL;
    librdp_static_channel_info info;
    librdp_static_channel_info infos[2];
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t count = 0;

    memset(&counter, 0, sizeof(counter));
    CHECK(librdp_static_channel_info_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_static_channel_info_init(&info) == LIBRDP_STATUS_OK);
    CHECK(info.version == LIBRDP_STATIC_CHANNEL_INFO_VERSION);
    CHECK(info.size == sizeof(info));

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_add_static_channel(NULL,
                                             "STAT",
                                             LIBRDP_STATIC_CHANNEL_DEFAULT_FLAGS) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_static_channel(settings, NULL, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_static_channel(settings, "", 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_static_channel(settings, "12345678", 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_static_channel(settings, "drdynvc", 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_static_channel(settings, "STAT", 0) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_static_channel(settings, "stat", 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_static_channel_count(NULL) == 0);
    CHECK(librdp_settings_static_channel_count(settings) == 1);
    CHECK(librdp_settings_static_channel_info(NULL, 0, &info) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_static_channel_info(settings, 1, &info) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_static_channel_info(settings, 0, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_static_channel_info_init(&info) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_static_channel_info(settings, 0, &info) == LIBRDP_STATUS_OK);
    CHECK(info.channel_id == 0);
    CHECK(info.flags == LIBRDP_STATIC_CHANNEL_DEFAULT_FLAGS);
    CHECK(info.active == 0);
    CHECK(info.name_len == 4 && strcmp(info.name, "STAT") == 0);

    copy = librdp_settings_clone(settings);
    CHECK(copy != NULL);
    CHECK(librdp_settings_static_channel_count(copy) == 1);
    librdp_settings_free(copy);
    copy = NULL;

    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_ex(&test_port, &server_pid, 0, 0, 1, 0));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);
    CHECK(librdp_session_static_channel_list(NULL, NULL, 0, &count) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_static_channel_list(session, NULL, 1, &count) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_static_channel_list(session, NULL, 0, &count) == LIBRDP_STATUS_OK);
    CHECK(count == 0);
    CHECK(librdp_session_static_channel_send(session, "STAT", "pong", 4) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_open == 1);
    CHECK(counter.last_channel_id == 1006);
    CHECK(librdp_session_static_channel_list(session, NULL, 0, &count) == LIBRDP_STATUS_OK);
    CHECK(count == 1);
    CHECK(librdp_static_channel_info_init(&infos[0]) == LIBRDP_STATUS_OK);
    CHECK(librdp_static_channel_info_init(&infos[1]) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_static_channel_list(session, infos, 2, &count) == LIBRDP_STATUS_OK);
    CHECK(count == 1);
    CHECK(infos[0].channel_id == 1006);
    CHECK(infos[0].active == 1);
    CHECK(infos[0].flags == LIBRDP_STATIC_CHANNEL_DEFAULT_FLAGS);
    CHECK(infos[0].name_len == 4 && strcmp(infos[0].name, "STAT") == 0);
    CHECK(librdp_session_static_channel_send(session, NULL, "pong", 4) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_static_channel_send(session, "STAT", NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_static_channel_send(session, "NOPE", "pong", 4) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);
    CHECK(librdp_session_static_channel_send(session, "STAT", "pong", 4) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_data == 0);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_data == 1);
    CHECK(counter.last_channel_id == 1006);
    CHECK(counter.last_channel_data_len == 8);
    CHECK(memcmp(counter.last_channel_data, "statchan", 8) == 0);
    librdp_session_free(session);
    session = NULL;
    if (server_pid > 0)
    {
        CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
        CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    }
    librdp_settings_free(settings);
    return 0;
}

/*
 * Coverage: validates clipboard request correlation. A server may deliver
 * syntactically valid response PDUs after a local cancel or without a matching
 * request; those bytes must not become public clipboard events with zeroed
 * metadata.
 */
static int test_clipboard_unmatched_responses(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t i = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_add_static_channel(settings, "STAT", 0) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       1,
                                       0,
                                       1,
                                       DVC_SCENARIO_NORMAL,
                                       0,
                                       CLIPBOARD_SCENARIO_UNMATCHED_RESPONSES));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 10u; i++)
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.clipboard_data == 0);
    CHECK(counter.clipboard_file_contents == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

static void trace_default_event(void)
{
    rdp_trace_reset_for_tests();
    rdp_trace_event(RDP_TRACE_CLIENT, "client.test", "value=1");
}

static void trace_enabled_event(void)
{
    setenv("LIBRDP_TRACE_CLIENT", "yes", 1);
    rdp_trace_reset_for_tests();
    rdp_trace_event(RDP_TRACE_CLIENT, "client.test", "value=1");
    unsetenv("LIBRDP_TRACE_CLIENT");
}

static void trace_protocol_hexdump(void)
{
    const uint8_t bytes[] = {0x41, 0x42, 0x00, 0x43};
    setenv("LIBRDP_TRACE_PROTOCOL", "ON", 1);
    setenv("LIBRDP_TRACE_LEVEL", "trace", 1);
    setenv("LIBRDP_TRACE_HEX_BYTES", "2", 1);
    rdp_trace_reset_for_tests();
    rdp_trace_hexdump("rdp.fastpath.pdu", RDP_TRACE_SENSITIVITY_HEADER, bytes, sizeof(bytes));
    unsetenv("LIBRDP_TRACE_PROTOCOL");
    unsetenv("LIBRDP_TRACE_LEVEL");
    unsetenv("LIBRDP_TRACE_HEX_BYTES");
}

static void trace_sensitive_hexdumps(void)
{
    const uint8_t password[] = "HDR:LIBRDP_PASSWORD_CANARY";
    const uint8_t token[] = "HDR:LIBRDP_CREDSSP_TOKEN_CANARY";
    const uint8_t clipboard[] = "HDR:LIBRDP_CLIPBOARD_CANARY";
    const uint8_t input[] = "HDR:LIBRDP_INPUT_CANARY";
    const uint8_t apdu[] = "HDR:LIBRDP_APDU_CANARY";
    const uint8_t usb[] = "HDR:LIBRDP_USB_CANARY";
    const uint8_t media[] = "HDR:LIBRDP_MEDIA_CANARY";

    setenv("LIBRDP_TRACE_PROTOCOL", "1", 1);
    setenv("LIBRDP_TRACE_LEVEL", "trace", 1);
    setenv("LIBRDP_TRACE_HEX_BYTES", "96", 1);
    unsetenv("LIBRDP_TRACE_UNSAFE");
    rdp_trace_reset_for_tests();
    rdp_trace_hexdump("rdp.client_info.pdu", RDP_TRACE_SENSITIVITY_AUTH, password, sizeof(password) - 1u);
    rdp_trace_hexdump("credssp.token", RDP_TRACE_SENSITIVITY_AUTH, token, sizeof(token) - 1u);
    rdp_trace_hexdump("client.clipboard.pdu",
                      RDP_TRACE_SENSITIVITY_CLIPBOARD,
                      clipboard,
                      sizeof(clipboard) - 1u);
    rdp_trace_hexdump("client.input.send", RDP_TRACE_SENSITIVITY_INPUT, input, sizeof(input) - 1u);
    rdp_trace_hexdump("client.smartcard.apdu", RDP_TRACE_SENSITIVITY_APDU, apdu, sizeof(apdu) - 1u);
    rdp_trace_hexdump("client.usb.urb", RDP_TRACE_SENSITIVITY_USB, usb, sizeof(usb) - 1u);
    rdp_trace_hexdump("client.media.pdu", RDP_TRACE_SENSITIVITY_VIDEO, media, sizeof(media) - 1u);
    unsetenv("LIBRDP_TRACE_PROTOCOL");
    unsetenv("LIBRDP_TRACE_LEVEL");
    unsetenv("LIBRDP_TRACE_HEX_BYTES");
}

static void trace_sensitive_hexdumps_unsafe(void)
{
    const uint8_t password[] = "HDR:LIBRDP_PASSWORD_CANARY";
    const uint8_t input[] = "HDR:LIBRDP_INPUT_CANARY";

    setenv("LIBRDP_TRACE_PROTOCOL", "1", 1);
    setenv("LIBRDP_TRACE_LEVEL", "trace", 1);
    setenv("LIBRDP_TRACE_HEX_BYTES", "96", 1);
    setenv("LIBRDP_TRACE_UNSAFE", "1", 1);
    rdp_trace_reset_for_tests();
    rdp_trace_hexdump("rdp.client_info.pdu", RDP_TRACE_SENSITIVITY_AUTH, password, sizeof(password) - 1u);
    rdp_trace_hexdump("client.input.send", RDP_TRACE_SENSITIVITY_INPUT, input, sizeof(input) - 1u);
    unsetenv("LIBRDP_TRACE_PROTOCOL");
    unsetenv("LIBRDP_TRACE_LEVEL");
    unsetenv("LIBRDP_TRACE_HEX_BYTES");
    unsetenv("LIBRDP_TRACE_UNSAFE");
}

static void trace_level_filtered_event(void)
{
    setenv("LIBRDP_TRACE_CLIENT", "1", 1);
    setenv("LIBRDP_TRACE_LEVEL", "info", 1);
    rdp_trace_reset_for_tests();
    rdp_trace_event_level(RDP_TRACE_CLIENT, RDP_TRACE_LEVEL_DEBUG, "client.debug", "value=1");
    unsetenv("LIBRDP_TRACE_CLIENT");
    unsetenv("LIBRDP_TRACE_LEVEL");
}

static void trace_level_debug_event(void)
{
    setenv("LIBRDP_TRACE_CLIENT", "1", 1);
    setenv("LIBRDP_TRACE_LEVEL", "debug", 1);
    rdp_trace_reset_for_tests();
    rdp_trace_event_level(RDP_TRACE_CLIENT, RDP_TRACE_LEVEL_DEBUG, "client.debug", "value=1");
    unsetenv("LIBRDP_TRACE_CLIENT");
    unsetenv("LIBRDP_TRACE_LEVEL");
}

/*
 * Coverage: validates trace environment parsing, category filtering, monotonic
 * formatting, redaction boundaries, and bounded hexdump behavior.
 */
static int test_trace(void)
{
    char output[4096];

    CHECK(rdp_trace_parse_bool_value("1"));
    CHECK(rdp_trace_parse_bool_value("true"));
    CHECK(rdp_trace_parse_bool_value("TRUE"));
    CHECK(rdp_trace_parse_bool_value("yes"));
    CHECK(rdp_trace_parse_bool_value("YES"));
    CHECK(rdp_trace_parse_bool_value("on"));
    CHECK(rdp_trace_parse_bool_value("ON"));
    CHECK(!rdp_trace_parse_bool_value("0"));
    CHECK(!rdp_trace_parse_bool_value("maybe"));
    CHECK(rdp_trace_parse_hex_limit_value("32") == 32);
    CHECK(rdp_trace_parse_hex_limit_value("bad") == 0);
    CHECK(rdp_trace_parse_hex_limit_value("") == 0);
    CHECK(rdp_trace_parse_level_value(NULL) == RDP_TRACE_LEVEL_INFO);
    CHECK(rdp_trace_parse_level_value("") == RDP_TRACE_LEVEL_INFO);
    CHECK(rdp_trace_parse_level_value("error") == RDP_TRACE_LEVEL_ERROR);
    CHECK(rdp_trace_parse_level_value("WARN") == RDP_TRACE_LEVEL_WARN);
    CHECK(rdp_trace_parse_level_value("info") == RDP_TRACE_LEVEL_INFO);
    CHECK(rdp_trace_parse_level_value("debug") == RDP_TRACE_LEVEL_DEBUG);
    CHECK(rdp_trace_parse_level_value("TRACE") == RDP_TRACE_LEVEL_TRACE);
    CHECK(rdp_trace_parse_level_value("bad") == RDP_TRACE_LEVEL_INFO);

    unsetenv("LIBRDP_TRACE_CLIENT");
    unsetenv("LIBRDP_TRACE_LEVEL");
    rdp_trace_reset_for_tests();
    CHECK(!rdp_trace_enabled(RDP_TRACE_CLIENT));
    setenv("LIBRDP_TRACE_CLIENT", "true", 1);
    rdp_trace_refresh_from_env();
    CHECK(rdp_trace_enabled(RDP_TRACE_CLIENT));
    unsetenv("LIBRDP_TRACE_CLIENT");
    rdp_trace_refresh_from_env();
    CHECK(!rdp_trace_enabled(RDP_TRACE_CLIENT));
    CHECK(capture_stderr(trace_default_event, output, sizeof(output)));
    CHECK(output[0] == '\0');

    CHECK(capture_stderr(trace_enabled_event, output, sizeof(output)));
    CHECK(strstr(output, "librdp trace seq=1 ") != NULL);
    CHECK(strstr(output, "category=client event=client.test") != NULL);
    CHECK(strstr(output, "message=\"value=1\"") != NULL);

    setenv("LIBRDP_TRACE_TRANSPORT", "1", 1);
    rdp_trace_reset_for_tests();
    CHECK(rdp_trace_enabled(RDP_TRACE_TRANSPORT));
    CHECK(!rdp_trace_enabled(RDP_TRACE_CLIENT));
    CHECK(rdp_trace_enabled_level(RDP_TRACE_TRANSPORT, RDP_TRACE_LEVEL_INFO));
    CHECK(!rdp_trace_enabled_level(RDP_TRACE_TRANSPORT, RDP_TRACE_LEVEL_DEBUG));
    unsetenv("LIBRDP_TRACE_TRANSPORT");

    CHECK(capture_stderr(trace_level_filtered_event, output, sizeof(output)));
    CHECK(output[0] == '\0');
    CHECK(capture_stderr(trace_level_debug_event, output, sizeof(output)));
    CHECK(strstr(output, "category=client event=client.debug level=debug") != NULL);

    CHECK(capture_stderr(trace_protocol_hexdump, output, sizeof(output)));
    CHECK(strstr(output, "category=protocol event=rdp.fastpath.pdu") != NULL);
    CHECK(strstr(output, "level=trace") != NULL);
    CHECK(strstr(output, "payload_len=4 dumped=2 hex=4142 ascii=\"AB\"") != NULL);
    CHECK(strstr(output, "sensitivity=header redacted=0 unsafe=0") != NULL);

    CHECK(capture_stderr(trace_sensitive_hexdumps, output, sizeof(output)));
    CHECK(strstr(output, "sensitivity=auth redacted=1 unsafe=0") != NULL);
    CHECK(strstr(output, "sensitivity=input redacted=1 unsafe=0") != NULL);
    CHECK(strstr(output, "LIBRDP_PASSWORD_CANARY") == NULL);
    CHECK(strstr(output, "LIBRDP_CREDSSP_TOKEN_CANARY") == NULL);
    CHECK(strstr(output, "LIBRDP_CLIPBOARD_CANARY") == NULL);
    CHECK(strstr(output, "LIBRDP_INPUT_CANARY") == NULL);
    CHECK(strstr(output, "LIBRDP_APDU_CANARY") == NULL);
    CHECK(strstr(output, "LIBRDP_USB_CANARY") == NULL);
    CHECK(strstr(output, "LIBRDP_MEDIA_CANARY") == NULL);
    CHECK(strstr(output, "4c49425244505f50415353574f52445f43414e415259") == NULL);
    CHECK(strstr(output, "4c49425244505f494e5055545f43414e415259") == NULL);

    CHECK(capture_stderr(trace_sensitive_hexdumps_unsafe, output, sizeof(output)));
    CHECK(strstr(output, "sensitivity=auth redacted=0 unsafe=1") != NULL);
    CHECK(strstr(output, "LIBRDP_PASSWORD_CANARY") != NULL);
    CHECK(strstr(output, "LIBRDP_INPUT_CANARY") != NULL);
    return 0;
}

static int test_buffer_stream(void)
{
    rdp_buffer buffer;
    rdp_stream stream;
    uint8_t u8 = 0;
    uint16_t u16 = 0;
    uint32_t u32 = 0;
    const uint8_t* raw = NULL;

    rdp_buffer_init(&buffer);
    CHECK(rdp_buffer_reserve(NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(rdp_buffer_reserve(&buffer, 32) == LIBRDP_STATUS_OK);
    CHECK(buffer.capacity >= 32);
    CHECK(buffer.length == 0);
    CHECK(rdp_buffer_append_u8(&buffer, 0x11) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u16_le(&buffer, 0x2233) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u16_be(&buffer, 0x4455) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&buffer, 0x66778899u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_be(&buffer, 0xaabbccddu) == LIBRDP_STATUS_OK);
    CHECK(buffer.length == 13);

    rdp_stream_init(&stream, buffer.data, buffer.length);
    CHECK(rdp_stream_read_u8(&stream, &u8) == LIBRDP_STATUS_OK && u8 == 0x11);
    CHECK(rdp_stream_read_u16_le(&stream, &u16) == LIBRDP_STATUS_OK && u16 == 0x2233);
    CHECK(rdp_stream_read_u16_be(&stream, &u16) == LIBRDP_STATUS_OK && u16 == 0x4455);
    CHECK(rdp_stream_read_u32_le(&stream, &u32) == LIBRDP_STATUS_OK && u32 == 0x66778899u);
    CHECK(rdp_stream_read_u32_be(&stream, &u32) == LIBRDP_STATUS_OK && u32 == 0xaabbccddu);
    CHECK(rdp_stream_read_u8(&stream, &u8) == LIBRDP_STATUS_PROTOCOL_ERROR);

    CHECK(rdp_buffer_consume(&buffer, 3) == LIBRDP_STATUS_OK);
    CHECK(buffer.length == 10);
    rdp_stream_init(&stream, buffer.data, buffer.length);
    CHECK(rdp_stream_read_bytes(&stream, &raw, 2) == LIBRDP_STATUS_OK);
    CHECK(raw[0] == 0x44 && raw[1] == 0x55);
    CHECK(rdp_stream_skip(&stream, 100) == LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    CHECK(rdp_buffer_append_u8(&buffer, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u8(&buffer, 1) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u8(&buffer, 2) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u8(&buffer, 3) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u8(&buffer, 4) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u8(&buffer, 5) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append(&buffer, buffer.data + 1u, 4u) == LIBRDP_STATUS_OK);
    CHECK(buffer.length == 10u);
    CHECK(buffer.data[6] == 1u && buffer.data[7] == 2u && buffer.data[8] == 3u && buffer.data[9] == 4u);
    buffer.length = 0;
    CHECK(rdp_buffer_append(&buffer, buffer.data + 6u, 4u) == LIBRDP_STATUS_OK);
    CHECK(buffer.length == 4u);
    CHECK(buffer.data[0] == 1u && buffer.data[1] == 2u && buffer.data[2] == 3u && buffer.data[3] == 4u);

    rdp_buffer_free(&buffer);
    return 0;
}

static int test_charset(void)
{
    static const uint8_t utf16_expected[] = {
        0x41, 0x00, 0xe9, 0x00, 0x3d, 0xd8, 0x00, 0xde, 0x00, 0x00
    };
    static const uint8_t utf16_input[] = {
        0x41, 0x00, 0xe9, 0x00, 0x3d, 0xd8, 0x00, 0xde, 0x00, 0x00, 0x42, 0x00
    };
    rdp_buffer buffer;
    char* utf8 = NULL;
    size_t utf8_len = 0;
    uint8_t* utf16 = NULL;
    size_t utf16_len = 0;

    rdp_buffer_init(&buffer);
    CHECK(rdp_charset_utf8_to_utf16le_buffer("A\303\251\360\237\230\200", 1, &buffer) ==
          LIBRDP_STATUS_OK);
    CHECK(buffer.length == sizeof(utf16_expected));
    CHECK(memcmp(buffer.data, utf16_expected, sizeof(utf16_expected)) == 0);
    rdp_buffer_free(&buffer);

    CHECK(rdp_charset_utf16le_to_utf8_alloc(utf16_input, sizeof(utf16_input), 1, &utf8, &utf8_len) ==
          LIBRDP_STATUS_OK);
    CHECK(utf8_len == 7);
    CHECK(memcmp(utf8, "A\303\251\360\237\230\200", utf8_len) == 0);
    free(utf8);

    CHECK(rdp_charset_utf8_bytes_to_utf16le_alloc((const uint8_t*)"AB", 2, 0, &utf16, &utf16_len) ==
          LIBRDP_STATUS_OK);
    CHECK(utf16_len == 4);
    CHECK(utf16[0] == 'A' && utf16[1] == 0 && utf16[2] == 'B' && utf16[3] == 0);
    free(utf16);
    return 0;
}

static int test_pointer_decode(void)
{
    rdp_pointer_update update;
    rdp_buffer output;
    size_t stride = 0;
    const uint8_t xor_mask[12] = {
        0, 0, 0, 0,
        0xff, 0xff, 0xff, 0,
        0, 0, 0, 0
    };
    const uint8_t and_mask[2] = {0xe0, 0};
    const uint8_t xor_mask_24[4] = {0xff, 0xff, 0xff, 0};
    const uint8_t and_mask_24[2] = {0x80, 0};

    memset(&update, 0, sizeof(update));
    rdp_buffer_init(&output);
    update.kind = RDP_POINTER_UPDATE_KIND_SHAPE;
    update.width = 3;
    update.height = 1;
    update.xor_bpp = 32;
    update.xor_mask = xor_mask;
    update.xor_mask_len = sizeof(xor_mask);
    update.and_mask = and_mask;
    update.and_mask_len = sizeof(and_mask);

    CHECK(rdp_pointer_decode_bgra32(&update, &output, &stride) == LIBRDP_STATUS_OK);
    CHECK(stride == 12);
    CHECK(output.length == 12);
    CHECK(output.data[0] == 0 && output.data[1] == 0 && output.data[2] == 0 && output.data[3] == 0);
    CHECK(output.data[4] == 0 && output.data[5] == 0 && output.data[6] == 0 && output.data[7] == 0xff);
    CHECK(output.data[8] == 0 && output.data[9] == 0 && output.data[10] == 0 && output.data[11] == 0);

    rdp_buffer_free(&output);
    rdp_buffer_init(&output);
    memset(&update, 0, sizeof(update));
    update.kind = RDP_POINTER_UPDATE_KIND_SHAPE;
    update.width = 1;
    update.height = 1;
    update.xor_bpp = 24;
    update.xor_mask = xor_mask_24;
    update.xor_mask_len = sizeof(xor_mask_24);
    update.and_mask = and_mask_24;
    update.and_mask_len = sizeof(and_mask_24);

    CHECK(rdp_pointer_decode_bgra32(&update, &output, &stride) == LIBRDP_STATUS_OK);
    CHECK(stride == 4);
    CHECK(output.length == 4);
    CHECK(output.data[0] == 0 && output.data[1] == 0 && output.data[2] == 0 && output.data[3] == 0xff);
    rdp_buffer_free(&output);
    return 0;
}

/*
 * Coverage: exercises public settings, surface, input, callback, clipboard,
 * channel, audio, video, and session lifecycle APIs together to catch
 * ownership and state regressions.
 */
static int test_settings_surface_input_session(void)
{
    librdp_settings* settings = NULL;
    librdp_settings* copy = NULL;
    librdp_surface* surface = NULL;
    librdp_session* session = NULL;
    librdp_client* client = NULL;
    librdp_client_config client_config;
    const librdp_surface* session_surface = NULL;
    librdp_surface_mapping surface_map;
    librdp_surface_mapping surface_map2;
    uint8_t pixels[16] = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16
    };
    const uint8_t* out = NULL;
    uint16_t flags = 0;
    librdp_key_event key = {
        .scancode = 30,
        .state = LIBRDP_KEY_PRESSED,
        .flags = 0,
        .unicode = 0
    };
    librdp_mouse_event mouse = {10, 11, LIBRDP_MOUSE_BUTTON_LEFT, LIBRDP_MOUSE_PRESSED};
    librdp_display_monitor display_monitors[2];
    librdp_touch_contact touch_contact;
    librdp_touch_frame touch_frame;
    librdp_pen_contact pen_contact;
    librdp_pen_frame pen_frame;
    librdp_feature_status feature_status;
    librdp_tls_policy tls_policy;
    librdp_tls_policy tls_policy_out;
    const struct
    {
        librdp_status status;
        const char* name;
    } status_cases[] = {
        {LIBRDP_STATUS_OK, "ok"},
        {LIBRDP_STATUS_INVALID_ARGUMENT, "invalid_argument"},
        {LIBRDP_STATUS_NO_MEMORY, "no_memory"},
        {LIBRDP_STATUS_IO_ERROR, "io_error"},
        {LIBRDP_STATUS_PROTOCOL_ERROR, "protocol_error"},
        {LIBRDP_STATUS_UNSUPPORTED, "unsupported"},
        {LIBRDP_STATUS_TIMEOUT, "timeout"},
        {LIBRDP_STATUS_CLOSED, "closed"},
        {LIBRDP_STATUS_AGAIN, "again"},
        {LIBRDP_STATUS_STATE, "state"},
        {LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED, "tls_certificate_rejected"},
        {LIBRDP_STATUS_TLS_HOSTNAME_MISMATCH, "tls_hostname_mismatch"},
        {LIBRDP_STATUS_TLS_HANDSHAKE_FAILED, "tls_handshake_failed"},
        {LIBRDP_STATUS_SECURITY_DOWNGRADE, "security_downgrade"},
        {LIBRDP_STATUS_LIMIT_EXCEEDED, "limit_exceeded"},
        {LIBRDP_STATUS_CANCELLED, "cancelled"}
    };
    librdp_credentials credentials;
    librdp_error_info error_info;
    const librdp_error* session_error = NULL;
    librdp_drive_policy drive_policy;
    librdp_drive_policy drive_policy_out;
    librdp_usb_policy usb_policy;
    librdp_usb_policy usb_policy_out;
    librdp_limits limits;
    librdp_limits limits_out;
    librdp_metrics metrics;
    librdp_event_envelope envelope;
    librdp_trace_policy trace_policy;
    librdp_channel_info channel_info;
    librdp_channel_info channel_infos[2];
    librdp_channel_send_options channel_send_options;
    librdp_channel_handle channel_handle = 0;
    librdp_channel_handle client_channel_handle = 0;
    trace_capture trace;
    event_envelope_capture envelope_capture;
    domain_event_capture domain_capture;
    graphics_update_capture graphics_capture;
    secure_string_capture secure_capture;
    credentials_provider_capture credentials_capture;
    cancel_thread_capture cancel_capture;
    owner_thread_capture owner_capture;
    pthread_t cancel_thread;
    pthread_t owner_thread;
    char trace_file_path[] = "/tmp/librdp-trace-XXXXXX";
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    int trace_fd = -1;
    int next_timeout = 0;
    struct pollfd session_pfds[3];
    size_t session_pfd_count = 0;
    size_t channel_count = 0;

    memset(&counter, 0, sizeof(counter));
    memset(&envelope_capture, 0, sizeof(envelope_capture));
    memset(&domain_capture, 0, sizeof(domain_capture));
    memset(&graphics_capture, 0, sizeof(graphics_capture));
    memset(&trace, 0, sizeof(trace));
    memset(&secure_capture, 0, sizeof(secure_capture));
    memset(&credentials_capture, 0, sizeof(credentials_capture));
    memset(&cancel_capture, 0, sizeof(cancel_capture));
    memset(&owner_capture, 0, sizeof(owner_capture));

    for (size_t i = 0; i < sizeof(status_cases) / sizeof(status_cases[0]); i++)
    {
        CHECK(strcmp(librdp_status_name(status_cases[i].status), status_cases[i].name) == 0);
        CHECK(strcmp(librdp_status_string(status_cases[i].status), status_cases[i].name) == 0);
        CHECK(librdp_status_description(status_cases[i].status) != NULL);
        CHECK(librdp_status_description(status_cases[i].status)[0] != '\0');
    }
    CHECK(strcmp(librdp_status_name((librdp_status)-1000), "unknown") == 0);
    CHECK(strcmp(librdp_status_string((librdp_status)-1000), "unknown") == 0);
    CHECK(strcmp(librdp_status_description((librdp_status)-1000), "Unknown status code.") == 0);
    CHECK(librdp_error_info_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
    CHECK(error_info.version == LIBRDP_ERROR_INFO_VERSION);
    CHECK(error_info.status == LIBRDP_STATUS_OK);
    CHECK(error_info.component == LIBRDP_ERROR_COMPONENT_NONE);
    CHECK(librdp_error_copy_info(NULL, &error_info) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(strcmp(librdp_error_component_name(LIBRDP_ERROR_COMPONENT_CLIENT), "client") == 0);
    CHECK(strcmp(librdp_error_component_name(LIBRDP_ERROR_COMPONENT_TRANSPORT), "transport") == 0);
    CHECK(strcmp(librdp_error_component_name((librdp_error_component)1000), "unknown") == 0);
    CHECK(librdp_event_envelope_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_event_envelope_init(&envelope) == LIBRDP_STATUS_OK);
    CHECK(envelope.version == LIBRDP_EVENT_ENVELOPE_VERSION);
    CHECK(envelope.size == sizeof(envelope));
    CHECK(librdp_channel_info_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_channel_info_init(&channel_info) == LIBRDP_STATUS_OK);
    CHECK(channel_info.version == LIBRDP_CHANNEL_INFO_VERSION);
    CHECK(channel_info.size == sizeof(channel_info));
    CHECK(librdp_channel_send_options_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_channel_send_options_init(&channel_send_options) == LIBRDP_STATUS_OK);
    CHECK(channel_send_options.version == LIBRDP_CHANNEL_SEND_OPTIONS_VERSION);
    CHECK(channel_send_options.size == sizeof(channel_send_options));
    CHECK(channel_send_options.priority == LIBRDP_CHANNEL_PRIORITY_LOW);
    CHECK(librdp_client_config_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_client_config_init(&client_config) == LIBRDP_STATUS_OK);
    CHECK(client_config.version == LIBRDP_CLIENT_CONFIG_VERSION);
    CHECK(client_config.port == 3389);
    CHECK(client_config.width == 1024);
    CHECK(client_config.height == 768);
    CHECK(client_config.security == LIBRDP_SECURITY_AUTO);
    CHECK(librdp_client_new(NULL) == NULL);
    client = librdp_client_new(&client_config);
    CHECK(client != NULL);
    CHECK(librdp_client_settings(NULL) == NULL);
    CHECK(librdp_client_session(NULL) == NULL);
    CHECK(librdp_client_settings(client) != NULL);
    CHECK(librdp_client_session(client) != NULL);
    CHECK(librdp_client_state(NULL) == LIBRDP_SESSION_FAILED);
    CHECK(librdp_client_lifecycle(NULL) == LIBRDP_LIFECYCLE_FAILED);
    CHECK(librdp_client_state(client) == LIBRDP_SESSION_IDLE);
    CHECK(librdp_client_lifecycle(client) == LIBRDP_LIFECYCLE_NEW);
    CHECK(librdp_client_dispatch(client, 0) == LIBRDP_STATUS_STATE);
    CHECK(librdp_client_cancel(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_client_reconnect(NULL, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_client_reconnect(client, NULL) == LIBRDP_STATUS_STATE);
    CHECK(librdp_client_connect(client) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_error_copy_info(librdp_session_last_error(librdp_client_session(client)), &error_info) ==
          LIBRDP_STATUS_OK);
    CHECK(error_info.status == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(error_info.component == LIBRDP_ERROR_COMPONENT_CLIENT);
    CHECK(librdp_client_state(client) == LIBRDP_SESSION_IDLE);
    CHECK(librdp_client_reconnect(client, NULL) == LIBRDP_STATUS_STATE);
    CHECK(librdp_client_disconnect(client) == LIBRDP_STATUS_OK);
    librdp_client_free(client);
    client = NULL;
    client_config.target = "127.0.0.1";
    client_config.username = "user";
    client_config.password = "replacement";
    client_config.width = 800;
    client_config.height = 600;
    client_config.security = LIBRDP_SECURITY_STANDARD;
    client = librdp_client_new(&client_config);
    CHECK(client != NULL);
    CHECK(strcmp(librdp_settings_target(librdp_client_settings(client)), "127.0.0.1") == 0);
    CHECK(librdp_settings_width(librdp_client_settings(client)) == 800);
    CHECK(librdp_settings_height(librdp_client_settings(client)) == 600);
    librdp_client_free(client);
    client = NULL;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_limits_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_limits_init(&limits) == LIBRDP_STATUS_OK);
    CHECK(limits.version == LIBRDP_LIMITS_VERSION);
    CHECK(limits.size == sizeof(limits));
    CHECK(limits.dynamic_channel_message_bytes == 64u * 1024u * 1024u);
    CHECK(librdp_settings_get_limits(NULL, &limits_out) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_limits(settings, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_limits(settings, &limits_out) == LIBRDP_STATUS_OK);
    CHECK(limits_out.surface_max_dimension == 8192u);
    limits_out.surface_max_dimension = 512u;
    CHECK(librdp_settings_set_limits(settings, &limits_out) == LIBRDP_STATUS_INVALID_ARGUMENT);
    limits_out.surface_max_dimension = 1024u;
    CHECK(librdp_settings_set_limits(settings, &limits_out) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_desktop_size(settings, 1200, 768) == LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(librdp_settings_set_limits(settings, NULL) == LIBRDP_STATUS_OK);
    CHECK(librdp_tls_policy_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_tls_policy(NULL, &tls_policy_out) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_tls_policy(settings, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_tls_policy(settings, &tls_policy_out) == LIBRDP_STATUS_OK);
    CHECK(tls_policy_out.version == LIBRDP_TLS_POLICY_VERSION);
    CHECK(tls_policy_out.mode == LIBRDP_TLS_POLICY_STRICT);
    CHECK(tls_policy_out.use_system_store == 1);
    CHECK(tls_policy_out.pinned_sha256 == NULL);
    CHECK(tls_policy_out.certificate_callback == NULL);
    CHECK(librdp_tls_policy_init(&tls_policy) == LIBRDP_STATUS_OK);
    tls_policy.mode = LIBRDP_TLS_POLICY_PINNED_FINGERPRINT;
    tls_policy.pinned_sha256 =
        "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:"
        "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";
    CHECK(librdp_settings_set_tls_policy(settings, &tls_policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_get_tls_policy(settings, &tls_policy_out) == LIBRDP_STATUS_OK);
    CHECK(tls_policy_out.mode == LIBRDP_TLS_POLICY_PINNED_FINGERPRINT);
    CHECK(tls_policy_out.use_system_store == 1);
    CHECK(strcmp(tls_policy_out.pinned_sha256,
                 "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899") == 0);
    tls_policy.mode = LIBRDP_TLS_POLICY_TOFU;
    tls_policy.pinned_sha256 = NULL;
    tls_policy.certificate_callback = NULL;
    CHECK(librdp_settings_set_tls_policy(settings, &tls_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_trace_policy_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_trace_policy_init(&trace_policy) == LIBRDP_STATUS_OK);
    CHECK(trace_policy.version == LIBRDP_TRACE_POLICY_VERSION);
    CHECK(trace_policy.categories == LIBRDP_TRACE_CATEGORY_ALL);
    CHECK(trace_policy.level == LIBRDP_TRACE_LEVEL_INFO);
    CHECK(trace_policy.sink == LIBRDP_TRACE_SINK_STDERR);
    tls_policy.certificate_callback = core_tls_certificate_callback;
    tls_policy.certificate_callback_user_data = &counter;
    CHECK(librdp_settings_set_tls_policy(settings, &tls_policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_get_tls_policy(settings, &tls_policy_out) == LIBRDP_STATUS_OK);
    CHECK(tls_policy_out.mode == LIBRDP_TLS_POLICY_TOFU);
    CHECK(tls_policy_out.certificate_callback == core_tls_certificate_callback);
    CHECK(tls_policy_out.certificate_callback_user_data == &counter);
    CHECK(librdp_settings_set_tls_policy(settings, NULL) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_get_tls_policy(settings, &tls_policy_out) == LIBRDP_STATUS_OK);
    CHECK(tls_policy_out.mode == LIBRDP_TLS_POLICY_STRICT);
    CHECK(tls_policy_out.use_system_store == 1);
    CHECK(tls_policy_out.pinned_sha256 == NULL);
    CHECK(librdp_tls_policy_init(&tls_policy) == LIBRDP_STATUS_OK);
    tls_policy.mode = LIBRDP_TLS_POLICY_PINNED_FINGERPRINT;
    tls_policy.pinned_sha256 = "not-a-sha256";
    CHECK(librdp_settings_set_tls_policy(settings, &tls_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_port(settings) == 3389);
    CHECK(librdp_settings_width(settings) == 1024);
    CHECK(librdp_settings_height(settings) == 768);
    {
        librdp_session* no_target_session = librdp_session_new(settings);

        CHECK(no_target_session != NULL);
        CHECK(librdp_session_connect(no_target_session) == LIBRDP_STATUS_INVALID_ARGUMENT);
        CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
        CHECK(librdp_error_copy_info(librdp_session_last_error(no_target_session), &error_info) ==
              LIBRDP_STATUS_OK);
        CHECK(error_info.status == LIBRDP_STATUS_INVALID_ARGUMENT);
        CHECK(error_info.component == LIBRDP_ERROR_COMPONENT_CLIENT);
        CHECK(error_info.os_errno == 0);
        CHECK(error_info.phase != NULL && strcmp(error_info.phase, "client.connect.validate") == 0);
        CHECK(error_info.message != NULL && strstr(error_info.message, "target") != NULL);
        librdp_session_clear_last_error(no_target_session);
        CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
        CHECK(librdp_error_copy_info(librdp_session_last_error(no_target_session), &error_info) ==
              LIBRDP_STATUS_OK);
        CHECK(error_info.status == LIBRDP_STATUS_OK);
        CHECK(error_info.component == LIBRDP_ERROR_COMPONENT_NONE);
        librdp_session_free(no_target_session);
        librdp_session_clear_last_error(NULL);
    }
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_username(settings, "user") == LIBRDP_STATUS_OK);
    rdp_settings_secure_string_observer_for_tests(on_secure_string_cleanse, &secure_capture);
    CHECK(librdp_settings_set_password(settings, "secret") == LIBRDP_STATUS_OK);
    CHECK(secure_capture.calls == 0);
    CHECK(librdp_settings_set_password(settings, "replacement") == LIBRDP_STATUS_OK);
    CHECK(secure_capture.calls == 1);
    CHECK(secure_capture.failed == 0);
    CHECK(secure_capture.last_length == sizeof("secret"));
    CHECK(librdp_settings_set_password(settings, NULL) == LIBRDP_STATUS_OK);
    CHECK(secure_capture.calls == 2);
    CHECK(secure_capture.failed == 0);
    CHECK(secure_capture.last_length == sizeof("replacement"));
    CHECK(librdp_credentials_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_credentials_init(&credentials) == LIBRDP_STATUS_OK);
    CHECK(credentials.version == LIBRDP_CREDENTIALS_VERSION);
    CHECK(credentials.size == sizeof(credentials));
    CHECK(librdp_credentials_set(NULL, "bulk-user", "bulk-pass", "bulk-domain") ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_credentials_set(&credentials, "bulk-user", "bulk-pass", "bulk-domain") ==
          LIBRDP_STATUS_OK);
    CHECK(strcmp(credentials.username, "bulk-user") == 0);
    CHECK(strcmp(credentials.password, "bulk-pass") == 0);
    CHECK(strcmp(credentials.domain, "bulk-domain") == 0);
    CHECK(librdp_settings_set_credentials(NULL, &credentials) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_credentials(settings, &credentials) == LIBRDP_STATUS_OK);
    CHECK(strcmp(librdp_settings_username(settings), "bulk-user") == 0);
    CHECK(strcmp(rdp_settings_password_internal(settings), "bulk-pass") == 0);
    CHECK(strcmp(librdp_settings_domain(settings), "bulk-domain") == 0);
    CHECK(librdp_settings_set_credentials(settings, NULL) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_username(settings) == NULL);
    CHECK(rdp_settings_password_internal(settings) == NULL);
    CHECK(librdp_settings_domain(settings) == NULL);
    librdp_credentials_clear(&credentials);
    CHECK(credentials.username == NULL);
    CHECK(credentials.password == NULL);
    CHECK(credentials.domain == NULL);
    CHECK(secure_capture.failed == 0);
    CHECK(librdp_settings_set_username(settings, "user") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_password(settings, "secret") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_domain(settings, "domain") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_port(settings, 3390) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_desktop_size(settings, 64, 48) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_TLS) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_drive_count(settings) == 0);
    CHECK(librdp_settings_add_drive(settings, "C:", "/tmp") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_drive_count(settings) == 1);
    CHECK(strcmp(librdp_settings_drive_name(settings, 0), "C:") == 0);
    CHECK(strcmp(librdp_settings_drive_path(settings, 0), "/tmp") == 0);
    CHECK(librdp_settings_drive_name(settings, 1) == NULL);
    CHECK(librdp_settings_drive_path(settings, 1) == NULL);
    CHECK(librdp_drive_policy_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_drive_policy_init(&drive_policy) == LIBRDP_STATUS_OK);
    CHECK(drive_policy.version == LIBRDP_DRIVE_POLICY_VERSION);
    CHECK(drive_policy.size == sizeof(drive_policy));
    CHECK(drive_policy.read_only == 1);
    CHECK(drive_policy.deny_device_files == 1);
    CHECK(drive_policy.deny_symlink_escape == 1);
    CHECK(drive_policy.deny_dotfiles == 1);
    CHECK(drive_policy.max_open_handles > 0);
    CHECK(librdp_settings_get_drive_policy(NULL, 0, &drive_policy_out) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_drive_policy(settings, 1, &drive_policy_out) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_drive_policy(settings, 0, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_drive_policy(settings, 0, &drive_policy_out) == LIBRDP_STATUS_OK);
    CHECK(drive_policy_out.read_only == 1);
    drive_policy.read_only = 0;
    drive_policy.max_file_size = 65536u;
    drive_policy.max_open_handles = 2u;
    CHECK(librdp_settings_set_drive_policy(NULL, 0, &drive_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_drive_policy(settings, 1, &drive_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_drive_policy(settings, 0, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    drive_policy.version = 0;
    CHECK(librdp_settings_set_drive_policy(settings, 0, &drive_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_drive_policy_init(&drive_policy) == LIBRDP_STATUS_OK);
    drive_policy.read_only = 0;
    drive_policy.max_file_size = 65536u;
    drive_policy.max_open_handles = 2u;
    CHECK(librdp_settings_set_drive_policy(settings, 0, &drive_policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_get_drive_policy(settings, 0, &drive_policy_out) == LIBRDP_STATUS_OK);
    CHECK(drive_policy_out.read_only == 0);
    CHECK(drive_policy_out.max_file_size == 65536u);
    CHECK(drive_policy_out.max_open_handles == 2u);
    librdp_usb_policy_init(NULL);
    librdp_usb_policy_init(&usb_policy);
    CHECK(usb_policy.version == LIBRDP_USB_POLICY_VERSION);
    CHECK(usb_policy.size == sizeof(usb_policy));
    CHECK(usb_policy.require_explicit_consent == 1);
    CHECK(usb_policy.allow_hid == 0);
    CHECK(usb_policy.allow_mass_storage == 0);
    CHECK(usb_policy.max_transfer_ms > 0);
    CHECK(librdp_settings_get_usb_policy(NULL, &usb_policy_out) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_usb_policy(settings, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_usb_policy(settings, &usb_policy_out) == LIBRDP_STATUS_OK);
    CHECK(usb_policy_out.require_explicit_consent == 1);
    CHECK(usb_policy_out.allow_hid == 0);
    CHECK(usb_policy_out.allow_mass_storage == 0);
    CHECK(librdp_settings_set_usb_policy(NULL, &usb_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_usb_policy(settings, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    usb_policy.version = 0;
    CHECK(librdp_settings_set_usb_policy(settings, &usb_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    librdp_usb_policy_init(&usb_policy);
    usb_policy.max_transfer_ms = 60001u;
    CHECK(librdp_settings_set_usb_policy(settings, &usb_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    librdp_usb_policy_init(&usb_policy);
    usb_policy.require_explicit_consent = 1;
    usb_policy.allow_hid = 1;
    usb_policy.allow_mass_storage = 1;
    usb_policy.max_transfer_ms = 0;
    CHECK(librdp_settings_set_usb_policy(settings, &usb_policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_get_usb_policy(settings, &usb_policy_out) == LIBRDP_STATUS_OK);
    CHECK(usb_policy_out.require_explicit_consent == 1);
    CHECK(usb_policy_out.allow_hid == 1);
    CHECK(usb_policy_out.allow_mass_storage == 1);
    CHECK(usb_policy_out.max_transfer_ms > 0);
    CHECK(librdp_settings_serial_port_count(settings) == 0);
    CHECK(librdp_settings_add_serial_port(settings, "COM1:", "/dev/ttyS0") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_serial_port_count(settings) == 1);
    CHECK(strcmp(librdp_settings_serial_port_name(settings, 0), "COM1:") == 0);
    CHECK(strcmp(librdp_settings_serial_port_path(settings, 0), "/dev/ttyS0") == 0);
    CHECK(librdp_settings_serial_port_name(settings, 1) == NULL);
    CHECK(librdp_settings_serial_port_path(settings, 1) == NULL);
    CHECK(librdp_settings_parallel_port_count(settings) == 0);
    CHECK(librdp_settings_add_parallel_port(settings, "LPT1:", "/tmp/lpt1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_parallel_port_count(settings) == 1);
    CHECK(strcmp(librdp_settings_parallel_port_name(settings, 0), "LPT1:") == 0);
    CHECK(strcmp(librdp_settings_parallel_port_path(settings, 0), "/tmp/lpt1") == 0);
    CHECK(librdp_settings_parallel_port_name(settings, 1) == NULL);
    CHECK(librdp_settings_parallel_port_path(settings, 1) == NULL);
    CHECK(librdp_settings_printer_count(settings) == 0);
    CHECK(librdp_settings_add_printer(settings, "Print", "Generic", "/tmp") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_printer_count(settings) == 1);
    CHECK(strcmp(librdp_settings_printer_name(settings, 0), "Print") == 0);
    CHECK(strcmp(librdp_settings_printer_driver(settings, 0), "Generic") == 0);
    CHECK(strcmp(librdp_settings_printer_output_path(settings, 0), "/tmp") == 0);
    CHECK(librdp_settings_printer_name(settings, 1) == NULL);
    CHECK(librdp_settings_printer_driver(settings, 1) == NULL);
    CHECK(librdp_settings_printer_output_path(settings, 1) == NULL);
    CHECK(librdp_settings_get_feature_status(NULL,
                                             LIBRDP_FEATURE_AUDIO_OUTPUT,
                                             &feature_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_feature_status(settings,
                                             (librdp_feature)0,
                                             &feature_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_feature_status(settings,
                                             (librdp_feature)0x80000000u,
                                             &feature_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_AUDIO_OUTPUT,
                                             NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_AUDIO_OUTPUT,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.feature == LIBRDP_FEATURE_AUDIO_OUTPUT);
    CHECK(!feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_REQUESTED);
    CHECK(!librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_AUDIO_OUTPUT));
    CHECK(librdp_settings_enable_feature(settings,
                                         (librdp_feature)(LIBRDP_FEATURE_AUDIO_OUTPUT |
                                                         LIBRDP_FEATURE_VIDEO),
                                         1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_feature_enabled(settings,
                                          (librdp_feature)(LIBRDP_FEATURE_AUDIO_OUTPUT |
                                                          LIBRDP_FEATURE_VIDEO)));
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_OUTPUT, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_INPUT, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_VIDEO, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_CAMERA, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_SMARTCARD, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_USB, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_PNP, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_WEBAUTHN, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_RAIL, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_CR2, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_ECHO, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_TELEMETRY, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_MULTITRANSPORT, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_DESKTOP_COMPOSITION, 1) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_AUDIO_OUTPUT));
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_AUDIO_OUTPUT,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             (librdp_feature)(LIBRDP_FEATURE_AUDIO_OUTPUT |
                                                             LIBRDP_FEATURE_VIDEO),
                                             &feature_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_OUTPUT, 0) == LIBRDP_STATUS_OK);
    CHECK(!librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_AUDIO_OUTPUT));
    CHECK(librdp_settings_set_audio_output_device(settings, "pipewire") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_OUTPUT, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_AUDIO_OUTPUT,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_OUTPUT, 0) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_audio_input_device(settings, "pipewire") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_video_output_path(settings, "/tmp/video.bin") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_camera(settings, "device=/dev/video0") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_smartcard(settings, "pcsc") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_usb_device(settings, "1234:5678") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_pnp_device(settings,
                                         "LIBRDP\\PNP\\TEST_DEVICE",
                                         "LIBRDP\\PNP\\TEST",
                                         "Host test device",
                                         LIBRDP_PNP_DEVICE_CAP_REMOVABLE |
                                             LIBRDP_PNP_DEVICE_CAP_SURPRISE_REMOVAL_OK) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_webauthn_provider(settings, "mock=/tmp/auth.json") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_rail_app(settings, "notepad.exe") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_echo_payload(settings, "probe") == LIBRDP_STATUS_OK);
    CHECK(strcmp(librdp_settings_audio_output_device(settings), "pipewire") == 0);
    CHECK(strcmp(librdp_settings_audio_input_device(settings), "pipewire") == 0);
    CHECK(strcmp(librdp_settings_video_output_path(settings), "/tmp/video.bin") == 0);
    CHECK(librdp_settings_camera_count(settings) == 1);
    CHECK(strcmp(librdp_settings_camera_source(settings, 0), "device=/dev/video0") == 0);
    CHECK(librdp_settings_camera_source(settings, 1) == NULL);
    CHECK(librdp_settings_smartcard_count(settings) == 1);
    CHECK(strcmp(librdp_settings_smartcard_source(settings, 0), "pcsc") == 0);
    CHECK(librdp_settings_smartcard_source(settings, 1) == NULL);
    CHECK(librdp_settings_usb_device_count(settings) == 1);
    CHECK(strcmp(librdp_settings_usb_device_selector(settings, 0), "1234:5678") == 0);
    CHECK(librdp_settings_usb_device_selector(settings, 1) == NULL);
    CHECK(librdp_settings_pnp_device_count(settings) == 1);
    CHECK(strcmp(librdp_settings_pnp_device_hardware_id(settings, 0), "LIBRDP\\PNP\\TEST_DEVICE") == 0);
    CHECK(strcmp(librdp_settings_pnp_device_compatibility_id(settings, 0), "LIBRDP\\PNP\\TEST") == 0);
    CHECK(strcmp(librdp_settings_pnp_device_description(settings, 0), "Host test device") == 0);
    CHECK(librdp_settings_pnp_device_caps(settings, 0) ==
          (LIBRDP_PNP_DEVICE_CAP_REMOVABLE | LIBRDP_PNP_DEVICE_CAP_SURPRISE_REMOVAL_OK));
    CHECK(librdp_settings_pnp_device_hardware_id(settings, 1) == NULL);
    CHECK(librdp_settings_pnp_device_compatibility_id(settings, 1) == NULL);
    CHECK(librdp_settings_pnp_device_description(settings, 1) == NULL);
    CHECK(librdp_settings_pnp_device_caps(settings, 1) == 0);
    CHECK(strcmp(librdp_settings_webauthn_provider(settings), "mock=/tmp/auth.json") == 0);
    CHECK(librdp_settings_rail_app_count(settings) == 1);
    CHECK(strcmp(librdp_settings_rail_app(settings, 0), "notepad.exe") == 0);
    CHECK(librdp_settings_rail_app(settings, 1) == NULL);
    CHECK(strcmp(librdp_settings_echo_payload(settings), "probe") == 0);
    CHECK(librdp_settings_set_port(settings, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_desktop_size(settings, 0, 48) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_security_mode(settings, (librdp_security_mode)99) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_drive(settings, "", "/tmp") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_drive(settings, "BAD/NAME", "/tmp") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_drive(settings, "D:", "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_serial_port(settings, "", "/dev/ttyS1") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_serial_port(settings, "BAD/COM", "/dev/ttyS1") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_serial_port(settings, "COM2:", "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_parallel_port(settings, "", "/tmp/lpt2") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_parallel_port(settings, "BAD/LPT", "/tmp/lpt2") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_parallel_port(settings, "LPT2:", "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_printer(settings, "", "Generic", "/tmp") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_printer(settings, "Print", "", "/tmp") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_printer(settings, "Print", "Generic", "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_enable_feature(settings, (librdp_feature)0, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_enable_feature(settings,
                                         (librdp_feature)0x80000000u,
                                         1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(!librdp_settings_feature_enabled(settings, (librdp_feature)0x80000000u));
    CHECK(!librdp_settings_feature_enabled(settings,
                                           (librdp_feature)(LIBRDP_FEATURE_AUDIO_INPUT |
                                                           0x80000000u)));
    CHECK(librdp_settings_set_audio_output_device(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_audio_input_device(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_video_output_path(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_camera(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_smartcard(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_usb_device(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_pnp_device(settings,
                                         "",
                                         "LIBRDP\\PNP\\BAD",
                                         "bad",
                                         0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_pnp_device(settings,
                                         "LIBRDP\\PNP\\BAD",
                                         "",
                                         "bad",
                                         0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_pnp_device(settings,
                                         "LIBRDP\\PNP\\BAD",
                                         "LIBRDP\\PNP\\BAD",
                                         "",
                                         0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_pnp_device(settings,
                                         "LIBRDP\\PNP\\BAD",
                                         "LIBRDP\\PNP\\BAD",
                                         "bad",
                                         0x80000000u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_webauthn_provider(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_webauthn_provider(settings, "fido2") == LIBRDP_STATUS_OK);
    CHECK(strcmp(librdp_settings_webauthn_provider(settings), "fido2") == 0);
    CHECK(librdp_settings_set_webauthn_provider(settings, "fido2=/dev/hidraw0") == LIBRDP_STATUS_OK);
    CHECK(strcmp(librdp_settings_webauthn_provider(settings), "fido2=/dev/hidraw0") == 0);
    CHECK(librdp_settings_set_webauthn_provider(settings, "mock=/tmp/auth.json") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_rail_app(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_echo_payload(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_TELEMETRY,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_PARSER_ONLY);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_MULTITRANSPORT,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_PARSER_ONLY);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_DESKTOP_COMPOSITION,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_PARSER_ONLY);
    CHECK(librdp_tls_policy_init(&tls_policy) == LIBRDP_STATUS_OK);
    tls_policy.mode = LIBRDP_TLS_POLICY_PINNED_FINGERPRINT;
    tls_policy.use_system_store = 0;
    tls_policy.pinned_sha256 = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    CHECK(librdp_settings_set_tls_policy(settings, &tls_policy) == LIBRDP_STATUS_OK);

    copy = librdp_settings_clone(settings);
    CHECK(copy != NULL);
    CHECK(strcmp(librdp_settings_target(copy), "127.0.0.1") == 0);
    CHECK(strcmp(librdp_settings_username(copy), "user") == 0);
    CHECK(strcmp(librdp_settings_domain(copy), "domain") == 0);
    CHECK(librdp_settings_security_mode(copy) == LIBRDP_SECURITY_TLS);
    CHECK(librdp_settings_get_tls_policy(copy, &tls_policy_out) == LIBRDP_STATUS_OK);
    CHECK(tls_policy_out.mode == LIBRDP_TLS_POLICY_PINNED_FINGERPRINT);
    CHECK(tls_policy_out.use_system_store == 0);
    CHECK(strcmp(tls_policy_out.pinned_sha256,
                 "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff") == 0);
    CHECK(librdp_settings_drive_count(copy) == 1);
    CHECK(strcmp(librdp_settings_drive_name(copy, 0), "C:") == 0);
    CHECK(strcmp(librdp_settings_drive_path(copy, 0), "/tmp") == 0);
    CHECK(librdp_settings_get_drive_policy(copy, 0, &drive_policy_out) == LIBRDP_STATUS_OK);
    CHECK(drive_policy_out.read_only == 0);
    CHECK(drive_policy_out.max_file_size == 65536u);
    CHECK(drive_policy_out.max_open_handles == 2u);
    CHECK(librdp_settings_get_usb_policy(copy, &usb_policy_out) == LIBRDP_STATUS_OK);
    CHECK(usb_policy_out.require_explicit_consent == 1);
    CHECK(usb_policy_out.allow_hid == 1);
    CHECK(usb_policy_out.allow_mass_storage == 1);
    CHECK(librdp_settings_serial_port_count(copy) == 1);
    CHECK(strcmp(librdp_settings_serial_port_name(copy, 0), "COM1:") == 0);
    CHECK(strcmp(librdp_settings_serial_port_path(copy, 0), "/dev/ttyS0") == 0);
    CHECK(librdp_settings_parallel_port_count(copy) == 1);
    CHECK(strcmp(librdp_settings_parallel_port_name(copy, 0), "LPT1:") == 0);
    CHECK(strcmp(librdp_settings_parallel_port_path(copy, 0), "/tmp/lpt1") == 0);
    CHECK(librdp_settings_printer_count(copy) == 1);
    CHECK(strcmp(librdp_settings_printer_name(copy, 0), "Print") == 0);
    CHECK(strcmp(librdp_settings_printer_driver(copy, 0), "Generic") == 0);
    CHECK(strcmp(librdp_settings_printer_output_path(copy, 0), "/tmp") == 0);
    CHECK(librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_AUDIO_INPUT));
    CHECK(librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_CAMERA));
    CHECK(librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_TELEMETRY));
    CHECK(librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_MULTITRANSPORT));
    CHECK(librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_DESKTOP_COMPOSITION));
    CHECK(!librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_AUDIO_OUTPUT));
    CHECK(strcmp(librdp_settings_audio_output_device(copy), "pipewire") == 0);
    CHECK(strcmp(librdp_settings_audio_input_device(copy), "pipewire") == 0);
    CHECK(strcmp(librdp_settings_video_output_path(copy), "/tmp/video.bin") == 0);
    CHECK(strcmp(librdp_settings_camera_source(copy, 0), "device=/dev/video0") == 0);
    CHECK(strcmp(librdp_settings_smartcard_source(copy, 0), "pcsc") == 0);
    CHECK(strcmp(librdp_settings_usb_device_selector(copy, 0), "1234:5678") == 0);
    CHECK(librdp_settings_pnp_device_count(copy) == 1);
    CHECK(strcmp(librdp_settings_pnp_device_hardware_id(copy, 0), "LIBRDP\\PNP\\TEST_DEVICE") == 0);
    CHECK(strcmp(librdp_settings_pnp_device_compatibility_id(copy, 0), "LIBRDP\\PNP\\TEST") == 0);
    CHECK(strcmp(librdp_settings_pnp_device_description(copy, 0), "Host test device") == 0);
    CHECK(librdp_settings_pnp_device_caps(copy, 0) ==
          (LIBRDP_PNP_DEVICE_CAP_REMOVABLE | LIBRDP_PNP_DEVICE_CAP_SURPRISE_REMOVAL_OK));
    CHECK(strcmp(librdp_settings_webauthn_provider(copy), "mock=/tmp/auth.json") == 0);
    CHECK(strcmp(librdp_settings_rail_app(copy, 0), "notepad.exe") == 0);
    CHECK(strcmp(librdp_settings_echo_payload(copy), "probe") == 0);

    surface = librdp_surface_new(4, 4, LIBRDP_PIXEL_FORMAT_BGRA32);
    CHECK(surface != NULL);
    CHECK(librdp_surface_format(surface) == LIBRDP_PIXEL_FORMAT_BGRA32);
    CHECK(librdp_surface_stride(surface) == 16);
    CHECK(librdp_surface_blit_bgra32(surface, 1, 1, 2, 2, pixels, 8) == LIBRDP_STATUS_OK);
    CHECK(librdp_surface_blit_bgra32(surface, 3, 3, 2, 2, pixels, 8) == LIBRDP_STATUS_INVALID_ARGUMENT);
    out = librdp_surface_pixels(surface);
    CHECK(out[((size_t)1 * 16) + 4] == 1);
    CHECK(librdp_surface_mapping_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_surface_mapping_init(&surface_map) == LIBRDP_STATUS_OK);
    CHECK(surface_map.version == LIBRDP_SURFACE_MAPPING_VERSION);
    CHECK(librdp_surface_map(NULL, LIBRDP_SURFACE_ACCESS_READ, &surface_map) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_surface_map(surface, (librdp_surface_access)99, &surface_map) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_READ, &surface_map) == LIBRDP_STATUS_OK);
    CHECK(surface_map.pixels == librdp_surface_pixels(surface));
    CHECK(surface_map.writable_pixels == NULL);
    CHECK(surface_map.width == 4 && surface_map.height == 4 && surface_map.stride == 16);
    CHECK(librdp_surface_resize(surface, 2, 2) == LIBRDP_STATUS_STATE);
    CHECK(librdp_surface_blit_bgra32(surface, 0, 0, 1, 1, pixels, 4) == LIBRDP_STATUS_STATE);
    CHECK(librdp_surface_mapping_init(&surface_map2) == LIBRDP_STATUS_OK);
    CHECK(librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_READ, &surface_map2) == LIBRDP_STATUS_OK);
    CHECK(librdp_surface_unmap(surface, &surface_map2) == LIBRDP_STATUS_OK);
    CHECK(librdp_surface_unmap(surface, &surface_map) == LIBRDP_STATUS_OK);
    CHECK(surface_map.pixels == NULL);
    CHECK(librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_WRITE, &surface_map) == LIBRDP_STATUS_OK);
    CHECK(surface_map.writable_pixels != NULL);
    surface_map.writable_pixels[0] = 0xaau;
    CHECK(librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_READ, &surface_map2) == LIBRDP_STATUS_STATE);
    CHECK(librdp_surface_unmap(surface, &surface_map) == LIBRDP_STATUS_OK);
    CHECK(librdp_surface_pixels(surface)[0] == 0xaau);
    CHECK(librdp_surface_resize(surface, 2, 2) == LIBRDP_STATUS_OK);
    CHECK(librdp_surface_width(surface) == 2);
    CHECK(librdp_surface_pixels_mut(surface) != NULL);
    librdp_surface_free(surface);

    CHECK(rdp_input_make_keyboard_flags(&key, &flags) == LIBRDP_STATUS_OK && flags == 0);
    key.flags = LIBRDP_KEY_FLAG_EXTENDED;
    CHECK(rdp_input_make_keyboard_flags(&key, &flags) == LIBRDP_STATUS_OK && flags == 0x0100u);
    key.flags = 0;
    key.state = LIBRDP_KEY_RELEASED;
    CHECK(rdp_input_make_keyboard_flags(&key, &flags) == LIBRDP_STATUS_OK && flags == 0x8000u);
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x9000u);
    mouse.state = LIBRDP_MOUSE_RELEASED;
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x1000u);
    mouse.state = LIBRDP_MOUSE_MOVED;
    mouse.button = LIBRDP_MOUSE_BUTTON_NONE;
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x0800u);
    mouse.state = LIBRDP_MOUSE_PRESSED;
    mouse.button = LIBRDP_MOUSE_BUTTON_WHEEL_DOWN;
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x0388u);
    mouse.button = LIBRDP_MOUSE_BUTTON_WHEEL_LEFT;
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x0588u);
    mouse.button = LIBRDP_MOUSE_BUTTON_X1;
    CHECK(rdp_input_mouse_uses_extended(&mouse));
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x8001u);
    mouse.button = LIBRDP_MOUSE_BUTTON_LEFT;

    memset(display_monitors, 0, sizeof(display_monitors));
    display_monitors[0].flags = LIBRDP_DISPLAY_MONITOR_PRIMARY;
    display_monitors[0].width = 800;
    display_monitors[0].height = 600;
    display_monitors[0].physical_width = 210;
    display_monitors[0].physical_height = 158;
    display_monitors[0].desktop_scale_factor = 100;
    display_monitors[0].device_scale_factor = 100;
    display_monitors[1].left = 800;
    display_monitors[1].width = 640;
    display_monitors[1].height = 480;
    display_monitors[1].physical_width = 169;
    display_monitors[1].physical_height = 127;
    display_monitors[1].desktop_scale_factor = 100;
    display_monitors[1].device_scale_factor = 100;
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    session_error = librdp_session_last_error(session);
    CHECK(session_error != NULL);
    CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_error_copy_info(session_error, &error_info) == LIBRDP_STATUS_OK);
    CHECK(error_info.status == LIBRDP_STATUS_OK);
    CHECK(error_info.component == LIBRDP_ERROR_COMPONENT_NONE);
    CHECK(error_info.phase == NULL);
    CHECK(librdp_session_last_error(NULL) == NULL);
    CHECK(librdp_session_get_lifecycle(NULL) == LIBRDP_LIFECYCLE_FAILED);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_NEW);
    CHECK(librdp_metrics_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.version == LIBRDP_METRICS_VERSION);
    CHECK(metrics.size == sizeof(metrics));
    CHECK(librdp_session_get_metrics(NULL, &metrics) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_get_metrics(session, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    metrics.size = 0;
    CHECK(librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.limits_rejected == 0);
    CHECK(librdp_session_reset_metrics(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_reset_metrics(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_set_trace_policy(NULL, &trace_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = NULL;
    CHECK(librdp_session_set_trace_policy(session, &trace_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    trace_policy.callback = on_trace;
    trace_policy.callback_user_data = &trace;
    trace_policy.categories = 0x80000000u;
    CHECK(librdp_session_set_trace_policy(session, &trace_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.hex_bytes = 32;
    trace_policy.session_id = "session-1";
    trace_policy.connection_id = "connection-1";
    trace_policy.trace_id = "trace-1";
    CHECK(librdp_session_set_trace_policy(session, &trace_policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_set_trace_policy(session, NULL) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_feature_status(NULL,
                                            LIBRDP_FEATURE_TELEMETRY,
                                            &feature_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_get_feature_status(session,
                                            (librdp_feature)(LIBRDP_FEATURE_AUDIO_INPUT |
                                                            LIBRDP_FEATURE_VIDEO),
                                            &feature_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_AUDIO_INPUT,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_TELEMETRY,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_PARSER_ONLY);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_MULTITRANSPORT,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_PARSER_ONLY);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_DESKTOP_COMPOSITION,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_PARSER_ONLY);
    CHECK(librdp_session_set_display_layout(NULL, display_monitors, 1) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_set_display_layout(session, NULL, 1) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_set_display_layout(session, display_monitors, 0) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_set_display_layout(session,
                                            display_monitors,
                                            LIBRDP_DISPLAY_MAX_MONITORS + 1u) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_set_display_layout(session, display_monitors, 2) == LIBRDP_STATUS_OK);
    display_monitors[1].left = 700;
    CHECK(librdp_session_set_display_layout(session, display_monitors, 2) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    display_monitors[1].left = 800;
    CHECK(librdp_session_refresh(session, 0, 0, 1, 1) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_clipboard_set_data(session,
                                            LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT,
                                            "t\0e\0x\0t\0\0",
                                            10) == LIBRDP_STATUS_OK);
    {
        char path[] = "/tmp/librdp-clip-XXXXXX";
        int fd = mkstemp(path);
        librdp_clipboard_file file;

        CHECK(fd >= 0);
        CHECK(write(fd, "abcdef", 6) == 6);
        CHECK(close(fd) == 0);
        memset(&file, 0, sizeof(file));
        file.path = path;
        file.name = "clip.txt";
        CHECK(librdp_session_clipboard_set_files(session, &file, 1) == LIBRDP_STATUS_OK);
        CHECK(librdp_session_clipboard_set_files(NULL, &file, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
        CHECK(librdp_session_clipboard_set_files(session, NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
        CHECK(librdp_session_clipboard_set_files(session, &file, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
        CHECK(unlink(path) == 0);
        CHECK(librdp_session_clipboard_set_files(session, &file, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    }
    CHECK(librdp_session_clipboard_request_data(session,
                                                LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_clipboard_request_file_size(session, 1, 0) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_clipboard_request_file_range(session, 2, 0, 4, 16) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_clipboard_request_file_size(NULL, 1, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_clipboard_request_file_size(session, 0, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_clipboard_request_file_range(session, 2, 0, 0, 0) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_clipboard_clear(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_clipboard_set_data(NULL,
                                            LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT,
                                            "x",
                                            1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_clipboard_set_data(session, 0, "x", 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_clipboard_request_data(session, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_send(NULL, 1, "x", 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_send(session, 0, "x", 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_send(session, 1, NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_send(session, 1, "x", 1) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_channel_close(NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_close(session, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_close(session, 1) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_audio_input_open_reply(NULL, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_audio_input_open_reply(session, 0) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_audio_input_send_data(NULL, "x", 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_audio_input_send_data(session, NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_audio_input_send_data(session, "x", 1) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_audio_input_send_format_change(NULL, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_audio_input_send_format_change(session, 0) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_video_capture_send_sample(NULL, 0, "x", 1) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_video_capture_send_sample(session, 0, NULL, 1) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_video_capture_send_sample(session, 0, "x", 1) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_video_capture_send_error(NULL,
                                                  0,
                                                  LIBRDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_video_capture_send_error(session,
                                                  0,
                                                  LIBRDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED) ==
          LIBRDP_STATUS_STATE);
    memset(&touch_contact, 0, sizeof(touch_contact));
    touch_contact.contact_id = 1;
    touch_contact.x = 100;
    touch_contact.y = 120;
    touch_contact.contact_flags = LIBRDP_CONTACT_DOWN | LIBRDP_CONTACT_INRANGE | LIBRDP_CONTACT_INCONTACT;
    touch_frame.contact_count = 1;
    touch_frame.frame_offset = 0;
    touch_frame.contacts = &touch_contact;
    CHECK(librdp_session_send_touch(NULL, 1, &touch_frame, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_send_touch(session, 1, NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_send_touch(session, 1, &touch_frame, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_send_touch(session, 1, &touch_frame, 1) == LIBRDP_STATUS_STATE);
    touch_contact.contact_flags = LIBRDP_CONTACT_DOWN;
    CHECK(librdp_session_send_touch(session, 1, &touch_frame, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    touch_contact.contact_flags = LIBRDP_CONTACT_DOWN | LIBRDP_CONTACT_INRANGE | LIBRDP_CONTACT_INCONTACT;
    {
        librdp_touch_contact duplicate_touch[2];

        duplicate_touch[0] = touch_contact;
        duplicate_touch[1] = touch_contact;
        touch_frame.contacts = duplicate_touch;
        touch_frame.contact_count = 2;
        CHECK(librdp_session_send_touch(session, 1, &touch_frame, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
        touch_frame.contacts = &touch_contact;
        touch_frame.contact_count = 1;
    }
    memset(&pen_contact, 0, sizeof(pen_contact));
    pen_contact.device_id = 1;
    pen_contact.fields_present = LIBRDP_PEN_PRESSURE_PRESENT;
    pen_contact.x = 100;
    pen_contact.y = 120;
    pen_contact.contact_flags = LIBRDP_CONTACT_DOWN | LIBRDP_CONTACT_INRANGE | LIBRDP_CONTACT_INCONTACT;
    pen_contact.pressure = 512;
    pen_frame.contact_count = 1;
    pen_frame.frame_offset = 0;
    pen_frame.contacts = &pen_contact;
    CHECK(librdp_session_send_pen(NULL, 1, &pen_frame, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_send_pen(session, 1, NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_send_pen(session, 1, &pen_frame, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_send_pen(session, 1, &pen_frame, 1) == LIBRDP_STATUS_STATE);
    pen_contact.pressure = 1025u;
    CHECK(librdp_session_send_pen(session, 1, &pen_frame, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    pen_contact.pressure = 512u;
    {
        librdp_pen_contact duplicate_pen[2];

        duplicate_pen[0] = pen_contact;
        duplicate_pen[1] = pen_contact;
        pen_frame.contacts = duplicate_pen;
        pen_frame.contact_count = 2;
        CHECK(librdp_session_send_pen(session, 1, &pen_frame, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
        pen_frame.contacts = &pen_contact;
        pen_frame.contact_count = 1;
    }
    CHECK(librdp_session_dismiss_touch(NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_dismiss_touch(session, 1) == LIBRDP_STATUS_STATE);
    librdp_session_free(session);
    session = NULL;
    CHECK(librdp_limits_init(&limits) == LIBRDP_STATUS_OK);
    limits.dynamic_channel_message_bytes = 4;
    CHECK(librdp_settings_set_limits(settings, &limits) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(librdp_session_clipboard_set_data(session, LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT, "abcdef", 6) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.limits_rejected == 1);
    CHECK(librdp_session_reset_metrics(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.limits_rejected == 0);
    librdp_session_free(session);
    session = NULL;
    CHECK(librdp_settings_set_limits(settings, NULL) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_credentials_provider(settings,
                                                   on_credentials_provider,
                                                   &credentials_capture) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_ex(&test_port, &server_pid, 0, 0, 0, 1));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    librdp_session_free(session);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_graphics_callback(NULL, on_domain_event, &domain_capture);
    librdp_session_set_pointer_callback(NULL, on_domain_event, &domain_capture);
    librdp_session_set_channel_callback(NULL, on_domain_event, &domain_capture);
    librdp_session_set_clipboard_callback(NULL, on_domain_event, &domain_capture);
    librdp_session_set_audio_callback(NULL, on_domain_event, &domain_capture);
    librdp_session_set_video_callback(NULL, on_domain_event, &domain_capture);
    librdp_session_set_graphics_update_callback(NULL, on_graphics_update, &graphics_capture);
    librdp_session_set_event_callback(session, on_event, &counter);
    librdp_session_set_event_envelope_callback(session, on_event_envelope, &envelope_capture);
    librdp_session_set_graphics_callback(session, on_domain_event, &domain_capture);
    librdp_session_set_pointer_callback(session, on_domain_event, &domain_capture);
    librdp_session_set_channel_callback(session, on_domain_event, &domain_capture);
    librdp_session_set_clipboard_callback(session, on_domain_event, &domain_capture);
    librdp_session_set_audio_callback(session, on_domain_event, &domain_capture);
    librdp_session_set_video_callback(session, on_domain_event, &domain_capture);
    librdp_session_set_graphics_update_callback(session, on_graphics_update, &graphics_capture);
    memset(&trace, 0, sizeof(trace));
    CHECK(librdp_trace_policy_init(&trace_policy) == LIBRDP_STATUS_OK);
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = on_trace;
    trace_policy.callback_user_data = &trace;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.hex_bytes = 32;
    trace_policy.session_id = "session-1";
    trace_policy.connection_id = "connection-1";
    trace_policy.trace_id = "trace-1";
    CHECK(librdp_session_set_trace_policy(session, &trace_policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(credentials_capture.calls == 1);
    CHECK(secure_capture.failed == 0);
    CHECK(trace.count > 0);
    CHECK(trace.last_sequence == trace.count);
    CHECK(trace.saw_connect_start);
    CHECK(trace.saw_protocol);
    CHECK(trace.saw_ids);
    CHECK(trace.saw_line);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_ACTIVATING);
    CHECK(counter.states == 2);
    CHECK(envelope_capture.invalid == 0);
    CHECK(envelope_capture.state == 2);
    CHECK(counter.surfaces == 1);
    CHECK(envelope_capture.surface == 1);
    CHECK(counter.pointer >= 1);
    CHECK(domain_capture.invalid == 0);
    CHECK(domain_capture.graphics == counter.surfaces);
    CHECK(domain_capture.pointer == counter.pointer);
    CHECK(domain_capture.channel == 0);
    CHECK(domain_capture.clipboard == 0);
    CHECK(domain_capture.audio == 0);
    CHECK(domain_capture.video == 0);
    CHECK(domain_capture.reentrant_metrics == domain_capture.graphics + domain_capture.pointer);
    CHECK(graphics_capture.invalid == 0);
    CHECK(graphics_capture.pixel_rect == counter.surfaces);
    CHECK(graphics_capture.borrowed_pixels == graphics_capture.pixel_rect);
    CHECK(graphics_capture.desktop_resize == 0);
    CHECK(graphics_capture.surface_create == 0);
    CHECK(graphics_capture.surface_destroy == 0);
    CHECK(librdp_session_channel_list(session, NULL, 1, &channel_count) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_list(session, NULL, 0, &channel_count) == LIBRDP_STATUS_OK);
    CHECK(channel_count == 0);
    owner_capture.session = session;
    owner_capture.status = LIBRDP_STATUS_OK;
    CHECK(pthread_create(&owner_thread, NULL, owner_thread_main, &owner_capture) == 0);
    CHECK(pthread_join(owner_thread, NULL) == 0);
    CHECK(owner_capture.status == LIBRDP_STATUS_STATE);
    CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_error_copy_info(librdp_session_last_error(session), &error_info) == LIBRDP_STATUS_OK);
    CHECK(error_info.status == LIBRDP_STATUS_STATE);
    CHECK(error_info.phase != NULL && strcmp(error_info.phase, "client.refresh.owner") == 0);
    session_surface = librdp_session_get_surface(session);
    CHECK(session_surface != NULL);
    CHECK(librdp_surface_width(session_surface) == 64);
    CHECK(librdp_session_get_pollfds(NULL, NULL, 0, &session_pfd_count) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_get_pollfds(session, NULL, 0, &session_pfd_count) == LIBRDP_STATUS_OK);
    CHECK(session_pfd_count == 2);
    CHECK(librdp_session_get_pollfds(session, session_pfds, 0, &session_pfd_count) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_get_pollfds(session, session_pfds, 2, &session_pfd_count) == LIBRDP_STATUS_OK);
    CHECK(session_pfd_count == 2);
    CHECK(session_pfds[0].fd >= 0);
    CHECK(session_pfds[1].fd >= 0);
    CHECK((session_pfds[0].events & POLLIN) != 0);
    CHECK((session_pfds[1].events & POLLIN) != 0);
    CHECK(librdp_session_get_next_timeout(session, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_get_next_timeout(session, &next_timeout) == LIBRDP_STATUS_OK);
    CHECK(next_timeout == -1);
    CHECK(librdp_session_notify_poll(session, NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    session_pfds[0].revents = 0;
    CHECK(librdp_session_notify_poll(session, session_pfds, session_pfd_count) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_dispatch_pending(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_ACTIVATING);
    {
        int poll_rc = 0;

        do
        {
            poll_rc = poll(session_pfds, (nfds_t)session_pfd_count, 1000);
        } while (poll_rc < 0 && errno == EINTR);
        CHECK(poll_rc > 0);
    }
    CHECK(librdp_session_notify_poll(session, session_pfds, session_pfd_count) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_next_timeout(session, &next_timeout) == LIBRDP_STATUS_OK);
    CHECK(next_timeout == 0);
    CHECK(librdp_session_dispatch_pending(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_ACTIVE);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.surfaces == 2);
    CHECK(domain_capture.graphics == counter.surfaces);
    CHECK(graphics_capture.pixel_rect == counter.surfaces);
    CHECK(graphics_capture.borrowed_pixels == graphics_capture.pixel_rect);
    session_surface = librdp_session_get_surface(session);
    CHECK(session_surface != NULL);
    out = librdp_surface_pixels(session_surface);
    CHECK(out[0] == 9 && out[1] == 10 && out[2] == 11 && out[3] == 12);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.surfaces == 6);
    CHECK(domain_capture.graphics == counter.surfaces);
    CHECK(graphics_capture.pixel_rect == counter.surfaces);
    CHECK(graphics_capture.borrowed_pixels == graphics_capture.pixel_rect);
    session_surface = librdp_session_get_surface(session);
    CHECK(session_surface != NULL);
    out = librdp_surface_pixels(session_surface);
    CHECK(out[((size_t)3 * librdp_surface_stride(session_surface)) + ((size_t)2 * 4u) + 0u] == 0x11u);
    CHECK(out[((size_t)3 * librdp_surface_stride(session_surface)) + ((size_t)2 * 4u) + 1u] == 0x22u);
    CHECK(out[((size_t)3 * librdp_surface_stride(session_surface)) + ((size_t)2 * 4u) + 2u] == 0x33u);
    CHECK(out[((size_t)3 * librdp_surface_stride(session_surface)) + ((size_t)2 * 4u) + 3u] == 0xffu);
    CHECK(out[((size_t)3 * librdp_surface_stride(session_surface)) + ((size_t)8 * 4u) + 0u] == 0x11u);
    CHECK(out[((size_t)3 * librdp_surface_stride(session_surface)) + ((size_t)8 * 4u) + 1u] == 0x22u);
    CHECK(out[((size_t)3 * librdp_surface_stride(session_surface)) + ((size_t)8 * 4u) + 2u] == 0x33u);
    CHECK(out[((size_t)3 * librdp_surface_stride(session_surface)) + ((size_t)8 * 4u) + 3u] == 0xffu);
    CHECK(out[((size_t)4 * librdp_surface_stride(session_surface)) + ((size_t)12 * 4u) + 0u] == 0x44u);
    CHECK(out[((size_t)4 * librdp_surface_stride(session_surface)) + ((size_t)12 * 4u) + 1u] == 0x55u);
    CHECK(out[((size_t)4 * librdp_surface_stride(session_surface)) + ((size_t)12 * 4u) + 2u] == 0x66u);
    CHECK(out[((size_t)4 * librdp_surface_stride(session_surface)) + ((size_t)12 * 4u) + 3u] == 0xffu);
    CHECK(out[((size_t)6 * librdp_surface_stride(session_surface)) + ((size_t)16 * 4u) + 0u] == 0x31u);
    CHECK(out[((size_t)6 * librdp_surface_stride(session_surface)) + ((size_t)16 * 4u) + 1u] == 0x32u);
    CHECK(out[((size_t)6 * librdp_surface_stride(session_surface)) + ((size_t)16 * 4u) + 2u] == 0x33u);
    CHECK(out[((size_t)6 * librdp_surface_stride(session_surface)) + ((size_t)16 * 4u) + 3u] == 0xffu);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_open == 1);
    CHECK(domain_capture.channel == 1);
    CHECK(counter.last_channel_id == 7);
    CHECK(librdp_session_channel_handle_for_id(session, counter.last_channel_id, &channel_handle) ==
          LIBRDP_STATUS_OK);
    CHECK(channel_handle != 0);
    CHECK(librdp_channel_info_init(&channel_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_channel_get_info(session, channel_handle, &channel_info) == LIBRDP_STATUS_OK);
    CHECK(channel_info.handle == channel_handle);
    CHECK(channel_info.channel_id == 7);
    CHECK(channel_info.priority == LIBRDP_CHANNEL_PRIORITY_MEDIUM);
    CHECK(channel_info.active == 1);
    CHECK(channel_info.application_owned == 1);
    CHECK(channel_info.name_len == 4 && strcmp(channel_info.name, "ECHO") == 0);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_ECHO,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(feature_status.negotiated && feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_channel_info_init(&channel_infos[0]) == LIBRDP_STATUS_OK);
    CHECK(librdp_channel_info_init(&channel_infos[1]) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_channel_list(session, channel_infos, 2, &channel_count) == LIBRDP_STATUS_OK);
    CHECK(channel_count == 1);
    CHECK(channel_infos[0].handle == channel_handle);
    CHECK(librdp_channel_send_options_init(&channel_send_options) == LIBRDP_STATUS_OK);
    channel_send_options.handle = channel_handle;
    channel_send_options.priority = LIBRDP_CHANNEL_PRIORITY_HIGH;
    CHECK(librdp_session_channel_send_ex(session, &channel_send_options, "ping", 4) == LIBRDP_STATUS_OK);
    channel_send_options.priority = (librdp_channel_priority)3;
    CHECK(librdp_session_channel_send_ex(session, &channel_send_options, "ping", 4) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    channel_send_options.priority = LIBRDP_CHANNEL_PRIORITY_LOW;
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_data == 0);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_data == 1);
    CHECK(domain_capture.channel == 2);
    CHECK(counter.last_channel_id == 7);
    CHECK(counter.last_channel_data_len == 8);
    CHECK(memcmp(counter.last_channel_data, "abcdefgh", 8) == 0);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_close == 1);
    CHECK(domain_capture.channel == 3);
    CHECK(librdp_session_channel_get_info(session, channel_handle, &channel_info) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_channel_send_ex(session, &channel_send_options, "ping", 4) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_channel_close_handle(session, channel_handle) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_channel_list(session, NULL, 0, &channel_count) == LIBRDP_STATUS_OK);
    CHECK(channel_count == 0);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_ECHO,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(librdp_session_channel_open(NULL,
                                      "APPCHAN",
                                      LIBRDP_CHANNEL_PRIORITY_LOW,
                                      &client_channel_handle) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_open(session,
                                      NULL,
                                      LIBRDP_CHANNEL_PRIORITY_LOW,
                                      &client_channel_handle) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_open(session,
                                      "",
                                      LIBRDP_CHANNEL_PRIORITY_LOW,
                                      &client_channel_handle) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_open(session,
                                      "APPCHAN",
                                      (librdp_channel_priority)3,
                                      &client_channel_handle) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_open(session,
                                      "APPCHAN",
                                      LIBRDP_CHANNEL_PRIORITY_HIGH,
                                      &client_channel_handle) == LIBRDP_STATUS_OK);
    CHECK(client_channel_handle != 0);
    CHECK(librdp_channel_info_init(&channel_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_channel_get_info(session, client_channel_handle, &channel_info) == LIBRDP_STATUS_OK);
    CHECK(channel_info.handle == client_channel_handle);
    CHECK(channel_info.channel_id == 1);
    CHECK(channel_info.priority == LIBRDP_CHANNEL_PRIORITY_HIGH);
    CHECK(channel_info.active == 0);
    CHECK(channel_info.application_owned == 1);
    CHECK(channel_info.name_len == 7 && strcmp(channel_info.name, "APPCHAN") == 0);
    channel_send_options.handle = client_channel_handle;
    channel_send_options.priority = LIBRDP_CHANNEL_PRIORITY_LOW;
    CHECK(librdp_session_channel_send_ex(session, &channel_send_options, "ping", 4) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_channel_list(session, NULL, 0, &channel_count) == LIBRDP_STATUS_OK);
    CHECK(channel_count == 0);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_open == 2);
    CHECK(domain_capture.channel == 4);
    CHECK(counter.last_channel_id == 1);
    CHECK(librdp_session_channel_get_info(session, client_channel_handle, &channel_info) == LIBRDP_STATUS_OK);
    CHECK(channel_info.active == 1);
    CHECK(librdp_session_channel_list(session, channel_infos, 2, &channel_count) == LIBRDP_STATUS_OK);
    CHECK(channel_count == 1);
    CHECK(channel_infos[0].handle == client_channel_handle);
    CHECK(librdp_session_refresh(session, 0, 0, 64, 48) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_refresh(session, 0, 0, 0, 48) == LIBRDP_STATUS_INVALID_ARGUMENT);
    key.state = LIBRDP_KEY_PRESSED;
    CHECK(librdp_session_send_key(session, &key) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_send_mouse(session, &mouse) == LIBRDP_STATUS_OK);
    CHECK(trace.last_sequence == trace.count);
    CHECK(counter.keys == 1);
    CHECK(counter.mouse == 1);
    CHECK(librdp_session_resize(session, 80, 60) == LIBRDP_STATUS_OK);
    CHECK(counter.surfaces == 6);
    CHECK(counter.pointer >= 1);
    session_surface = librdp_session_get_surface(session);
    CHECK(session_surface != NULL);
    CHECK(librdp_surface_width(session_surface) == 64);
    CHECK(librdp_surface_height(session_surface) == 48);
    trace_fd = mkstemp(trace_file_path);
    CHECK(trace_fd >= 0);
    CHECK(close(trace_fd) == 0);
    CHECK(librdp_trace_policy_init(&trace_policy) == LIBRDP_STATUS_OK);
    trace_policy.sink = LIBRDP_TRACE_SINK_FILE;
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_CLIENT;
    trace_policy.level = LIBRDP_TRACE_LEVEL_DEBUG;
    trace_policy.file_path = trace_file_path;
    trace_policy.trace_id = "file-trace";
    CHECK(librdp_session_set_trace_policy(session, &trace_policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_disconnect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_DISCONNECTED);
    CHECK(counter.disconnected == 1);
    CHECK(envelope_capture.disconnected == 1);
    {
        char file_trace[1024];
        int fd = open(trace_file_path, O_RDONLY);
        ssize_t got = 0;

        CHECK(fd >= 0);
        got = read(fd, file_trace, sizeof(file_trace) - 1u);
        CHECK(got > 0);
        file_trace[(size_t)got] = '\0';
        CHECK(close(fd) == 0);
        CHECK(strstr(file_trace, "client.disconnect.start") != NULL);
        CHECK(strstr(file_trace, "trace_id=file-trace") != NULL);
    }
    librdp_session_free(session);
    session = NULL;
    CHECK(librdp_settings_set_credentials_provider(settings, NULL, NULL) == LIBRDP_STATUS_OK);
    CHECK(unlink(trace_file_path) == 0);
    if (server_pid > 0)
    {
        CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
        CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    }

    credentials_capture.fail = 1;
    CHECK(librdp_settings_set_credentials_provider(settings,
                                                   on_credentials_provider,
                                                   &credentials_capture) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_error_copy_info(librdp_session_last_error(session), &error_info) == LIBRDP_STATUS_OK);
    CHECK(error_info.status == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(error_info.component == LIBRDP_ERROR_COMPONENT_CLIENT);
    CHECK(error_info.phase != NULL && strcmp(error_info.phase, "client.credentials") == 0);
    CHECK(error_info.message != NULL && strstr(error_info.message, "provider") != NULL);
    CHECK(error_info.message == NULL || strstr(error_info.message, "Welcome1") == NULL);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_FAILED);
    CHECK(credentials_capture.calls == 2);
    librdp_session_free(session);
    session = NULL;
    credentials_capture.fail = 0;
    CHECK(librdp_settings_set_credentials_provider(settings, NULL, NULL) == LIBRDP_STATUS_OK);

    memset(&counter, 0, sizeof(counter));
    server_pid = -1;
    child_status = 0;
    CHECK(start_handshake_server(&test_port, &server_pid, 0, 0x1234u));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_FAILED);
    librdp_session_free(session);
    if (server_pid > 0)
    {
        CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
        CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    }

    memset(&counter, 0, sizeof(counter));
    server_pid = -1;
    child_status = 0;
    CHECK(start_handshake_server(&test_port, &server_pid, 1, 0));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_ACTIVATING);
    CHECK(counter.states == 2);
    cancel_capture.session = session;
    cancel_capture.delay_ms = 50;
    cancel_capture.status = LIBRDP_STATUS_AGAIN;
    CHECK(pthread_create(&cancel_thread, NULL, cancel_thread_main, &cancel_capture) == 0);
    CHECK(librdp_session_run_once(session, 5000) == LIBRDP_STATUS_CANCELLED);
    CHECK(pthread_join(cancel_thread, NULL) == 0);
    CHECK(cancel_capture.status == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CANCELLED);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_DISCONNECTED);
    CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_error_copy_info(librdp_session_last_error(session), &error_info) == LIBRDP_STATUS_OK);
    CHECK(error_info.status == LIBRDP_STATUS_CANCELLED);
    librdp_session_free(session);
    if (server_pid > 0)
    {
        CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
        CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    }

    librdp_settings_free(copy);
    librdp_settings_free(settings);
    CHECK(secure_capture.calls >= 3);
    CHECK(secure_capture.failed == 0);
    rdp_settings_secure_string_observer_for_tests(NULL, NULL);
    return 0;
}

static int test_reconnect_policy(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_reconnect_policy policy;
    librdp_reconnect_policy bad_policy;
    librdp_metrics metrics;
    librdp_error_info error_info;
    uint16_t closed_port = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    CHECK(librdp_reconnect_policy_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_reconnect_policy_init(&policy) == LIBRDP_STATUS_OK);
    CHECK(policy.version == LIBRDP_RECONNECT_POLICY_VERSION);
    CHECK(policy.size == sizeof(policy));
    CHECK(policy.max_attempts == 1);
    CHECK(policy.initial_delay_ms == 0);
    CHECK(policy.max_delay_ms == 0);
    CHECK(reserve_closed_loopback_port(&closed_port));

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_port(settings, closed_port) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_reconnect(NULL, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_reconnect(session, NULL) == LIBRDP_STATUS_STATE);

    status = librdp_session_connect(session);
    CHECK(status != LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_FAILED);

    bad_policy = policy;
    bad_policy.version = 0;
    CHECK(librdp_session_reconnect(session, &bad_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    bad_policy = policy;
    bad_policy.size = offsetof(librdp_reconnect_policy, max_delay_ms);
    CHECK(librdp_session_reconnect(session, &bad_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    bad_policy = policy;
    bad_policy.max_attempts = 0;
    CHECK(librdp_session_reconnect(session, &bad_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    bad_policy = policy;
    bad_policy.max_attempts = 65;
    CHECK(librdp_session_reconnect(session, &bad_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);

    policy.max_attempts = 2;
    policy.initial_delay_ms = 0;
    policy.max_delay_ms = 0;
    status = librdp_session_reconnect(session, &policy);
    CHECK(status != LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_FAILED);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.reconnects == 1);
    CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_error_copy_info(librdp_session_last_error(session), &error_info) == LIBRDP_STATUS_OK);
    CHECK(error_info.status != LIBRDP_STATUS_OK);

    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}

/*
 * Coverage: validates reconnect success against a deterministic loopback peer
 * that accepts two handshakes on the same listener. It catches stale state,
 * missed activation transitions, and reconnect metrics drift without requiring
 * an external desktop endpoint.
 */
static int test_reconnect_success(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_reconnect_policy policy;
    librdp_metrics metrics;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t i = 0;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       2,
                                       DVC_SCENARIO_NORMAL,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_ACTIVE);
    for (i = 0; i < 6u; i++)
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);

    CHECK(librdp_reconnect_policy_init(&policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_reconnect(session, &policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_ACTIVE);
    for (i = 0; i < 6u; i++)
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.reconnects == 1);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates dynamic-channel state rejects duplicate server-created
 * channel identifiers before overwriting the existing table entry. It catches
 * handle lifetime corruption and parser/state-machine drift.
 */
static int test_dynamic_channel_duplicate_create(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_DUPLICATE_CREATE,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates that closing a dynamic virtual channel while reassembly
 * is pending drops the partial payload, emits close, and does not expose stale
 * channel handles or data events.
 */
static int test_dynamic_channel_close_pending_fragment(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t channel_count = 99u;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_CLOSE_PENDING_FRAGMENT,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (size_t i = 0; i < 7u && counter.channel_close == 0; i++)
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_open == 1);
    CHECK(counter.channel_data == 0);
    CHECK(counter.channel_close == 1);
    CHECK(counter.last_channel_id == 7);
    CHECK(librdp_session_channel_list(session, NULL, 0, &channel_count) == LIBRDP_STATUS_OK);
    CHECK(channel_count == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: rejects zero-length DVC continuation fragments while a message is
 * pending. It catches stalled reassembly that would keep channel state alive
 * without advancing toward the declared message length.
 */
static int test_dynamic_channel_empty_continuation(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_EMPTY_CONTINUATION,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 7u && status == LIBRDP_STATUS_OK; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(counter.channel_open == 1);
    CHECK(counter.channel_data == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: rejects a new DVC DATA_FIRST while a previous fragmented message
 * is incomplete. It prevents out-of-order traffic from silently replacing the
 * pending payload and corrupting channel message boundaries.
 */
static int test_dynamic_channel_nested_data_first(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_NESTED_DATA_FIRST,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 7u && status == LIBRDP_STATUS_OK; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(counter.channel_open == 1);
    CHECK(counter.channel_data == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

static int run_dynamic_channel_protocol_error_scenario(int scenario)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       scenario,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 7u && status == LIBRDP_STATUS_OK; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(counter.channel_open == 1);
    CHECK(counter.channel_data == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: compressed DVC fragments must make forward progress after
 * decompression. It catches zero-output bulk segments that would otherwise
 * leave a fragmented message pending forever.
 */
static int test_dynamic_channel_empty_compressed_fragments(void)
{
    if (run_dynamic_channel_protocol_error_scenario(DVC_SCENARIO_EMPTY_COMPRESSED_FIRST) != 0)
        return 1;
    return run_dynamic_channel_protocol_error_scenario(DVC_SCENARIO_EMPTY_COMPRESSED_CONTINUATION);
}

/*
 * Coverage: validates that a DVC soft-sync tunnel request falls back to TCP
 * when the multitransport runtime is parser-only. It catches accidental
 * negotiation of RDPEUDP/RDPEMT paths that cannot create a real side transport.
 */
static int test_dynamic_channel_soft_sync_runtime_fallback(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status feature_status;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_MULTITRANSPORT, 1) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_SOFT_SYNC_TUNNEL_REQUEST,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 4u && status == LIBRDP_STATUS_OK; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_MULTITRANSPORT,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_PARSER_ONLY);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates that Display Control capability rejection of a pending
 * local monitor layout does not fail the RDP session. It catches resize paths
 * that treat server capability limits as fatal protocol errors.
 */
static int test_display_control_caps_reject_pending_layout(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_display_monitor monitors[2];
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    memset(monitors, 0, sizeof(monitors));
    monitors[0].flags = LIBRDP_DISPLAY_MONITOR_PRIMARY;
    monitors[0].width = 800;
    monitors[0].height = 600;
    monitors[0].physical_width = 210;
    monitors[0].physical_height = 158;
    monitors[0].desktop_scale_factor = 100;
    monitors[0].device_scale_factor = 100;
    monitors[1].left = 800;
    monitors[1].width = 640;
    monitors[1].height = 480;
    monitors[1].physical_width = 169;
    monitors[1].physical_height = 127;
    monitors[1].desktop_scale_factor = 100;
    monitors[1].device_scale_factor = 100;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_DISPLAY_CONTROL_CAPS_REJECT_LAYOUT,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(librdp_session_set_display_layout(session, monitors, 2) == LIBRDP_STATUS_OK);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 5u && status == LIBRDP_STATUS_OK; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates that dynamic channel data cannot arrive before the
 * channel create handshake. It catches out-of-order DVC sequencing that would
 * otherwise hide malformed server traffic and lose channel metrics.
 */
static int test_dynamic_channel_data_before_create(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_DATA_BEFORE_CREATE,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 5u && status == LIBRDP_STATUS_OK; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(counter.channel_open == 0);
    CHECK(counter.channel_data == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: WebAuthn is an internal DVC and must drive the public feature
 * status from its own channel lifecycle, not from auth-redirection state or
 * public application-channel events.
 */
static int test_webauthn_feature_status_channel_lifecycle(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status feature_status;
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t i = 0;
    int saw_active = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_WEBAUTHN, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_webauthn_provider(settings, "mock=/tmp/librdp-webauthn-test.cbor") ==
          LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_WEBAUTHN_CREATE_CLOSE,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_WEBAUTHN,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);

    for (i = 0; i < 8u && !saw_active; i++)
    {
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
        CHECK(librdp_session_get_feature_status(session,
                                                LIBRDP_FEATURE_WEBAUTHN,
                                                &feature_status) == LIBRDP_STATUS_OK);
        if (feature_status.active)
            saw_active = 1;
    }
    CHECK(saw_active);
    CHECK(feature_status.negotiated && feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(counter.channel_open == 0);

    for (; i < 10u && feature_status.negotiated; i++)
    {
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
        CHECK(librdp_session_get_feature_status(session,
                                                LIBRDP_FEATURE_WEBAUTHN,
                                                &feature_status) == LIBRDP_STATUS_OK);
    }
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(counter.channel_close == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates that recognized but non-rendered GDI alternate
 * secondary orders fail the runtime path instead of being silently accepted.
 * This catches capability/runtime drift where parser-only GDI+ or window
 * composition packets would otherwise look successfully rendered.
 */
static int test_gdi_unsupported_altsec_order(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_full(&test_port,
                                      &server_pid,
                                      0,
                                      0,
                                      0,
                                      0,
                                      1,
                                      DVC_SCENARIO_NORMAL,
                                      GDI_SCENARIO_UNSUPPORTED_ALTSEC,
                                      0,
                                      CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 6u && status == LIBRDP_STATUS_OK; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_UNSUPPORTED);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates that terminal licensing PDUs can appear before Demand
 * Active without being misclassified as malformed slow-path share traffic. It
 * catches licensing/lifecycle ordering regressions while keeping the fixture
 * deterministic and credential-free.
 */
static int test_licensing_new_before_activation(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t i = 0;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_NORMAL,
                                       1,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);
    for (i = 0; i < 6u; i++)
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

int test_common(void)
{
    if (test_trace() != 0)
        return 1;
    if (test_buffer_stream() != 0)
        return 1;
    if (test_charset() != 0)
        return 1;
    if (test_pointer_decode() != 0)
        return 1;
    return 0;
}

int test_client_core(void)
{
    if (test_smartcard_backend_mock() != 0)
        return 1;
    if (test_usb_backend_boundary() != 0)
        return 1;
    if (test_static_channels() != 0)
        return 1;
    if (test_clipboard_unmatched_responses() != 0)
        return 1;
    if (test_reconnect_policy() != 0)
        return 1;
    if (test_reconnect_success() != 0)
        return 1;
    if (test_dynamic_channel_duplicate_create() != 0)
        return 1;
    if (test_dynamic_channel_close_pending_fragment() != 0)
        return 1;
    if (test_dynamic_channel_empty_continuation() != 0)
        return 1;
    if (test_dynamic_channel_nested_data_first() != 0)
        return 1;
    if (test_dynamic_channel_empty_compressed_fragments() != 0)
        return 1;
    if (test_dynamic_channel_soft_sync_runtime_fallback() != 0)
        return 1;
    if (test_display_control_caps_reject_pending_layout() != 0)
        return 1;
    if (test_dynamic_channel_data_before_create() != 0)
        return 1;
    if (test_webauthn_feature_status_channel_lifecycle() != 0)
        return 1;
    if (test_gdi_unsupported_altsec_order() != 0)
        return 1;
    if (test_licensing_new_before_activation() != 0)
        return 1;
    return test_settings_surface_input_session();
}

#ifndef LIBRDP_TEST_NO_MAIN
int main(void)
{
    if (test_common() != 0)
        return 1;
    if (test_protocol() != 0)
        return 1;
    if (test_transport() != 0)
        return 1;
    if (test_client_core() != 0)
        return 1;
    return 0;
}
#endif
