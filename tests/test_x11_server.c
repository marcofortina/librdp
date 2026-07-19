/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: isolated Xvfb exercise for the X11 desktop-server providers,
 * including bidirectional direct and INCR clipboard transfers.
 * Coverage: damage-driven BGRA capture, cursor shape and position updates,
 * XTest keyboard/pointer injection, permission state, selection ownership,
 * UTF conversion and outbound INCR chunking.
 * Bug classes: unchecked XImage layout, stale geometry, missed damage,
 * key/button state leaks, cursor bounds, clipboard owner loops, malformed
 * correlation and unbounded selection payloads.
 * Determinism: every test owns a private Xvfb display and uses synthetic
 * windows, pixels, input events and clipboard payloads.
 */

#include "server_cli.h"
#include "server_clipboard_files.h"
#include "server_fuse.h"
#include "server_x11.h"

#include <X11/Xatom.h>
#include <X11/Xlib.h>
#include <X11/keysym.h>

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef LIBRDP_TEST_XVFB_PATH
#define LIBRDP_TEST_XVFB_PATH "Xvfb"
#endif

#define TEST_REMOTE_FORMAT_HTML 0xd101u
#define TEST_REMOTE_FORMAT_PNG 0xd102u
#define TEST_CLIPBOARD_FORMAT_LIMIT 8u

#define CHECK(condition)                                                        \
    do                                                                          \
    {                                                                           \
        if (!(condition))                                                       \
        {                                                                       \
            fprintf(stderr,                                                     \
                    "check failed %s:%d: %s\n",                                 \
                    __FILE__,                                                   \
                    __LINE__,                                                   \
                    #condition);                                                \
            return 1;                                                           \
        }                                                                       \
    } while (0)

typedef struct x11_server_test_state
{
    const server_platform_clipboard_vtable* clipboard;
    void* clipboard_context;
    uint64_t frame_count;
    uint64_t pointer_count;
    uint64_t format_count;
    uint64_t data_count;
    uint64_t request_count;
    uint64_t cancel_count;
    uint64_t permission_count;
    uint64_t clipboard_generation;
    size_t published_format_count;
    uint32_t published_format_ids[TEST_CLIPBOARD_FORMAT_LIMIT];
    uint32_t last_width;
    uint32_t last_height;
    uint8_t sample_b;
    uint8_t sample_g;
    uint8_t sample_r;
    int pointer_shape;
    int pointer_visible;
    uint8_t clipboard_data[4096];
    size_t clipboard_data_len;
    size_t clipboard_total_len;
    uint32_t clipboard_format_id;
    librdp_status clipboard_status;
    uint32_t clipboard_peer_id;
    uint32_t clipboard_peer_generation;
    int send_large_clipboard;
    int defer_clipboard_response;
    librdp_status response_status;
} x11_server_test_state;

typedef struct test_selection_source
{
    Display* display;
    Window owner;
    Atom clipboard;
    Atom targets;
    Atom incr;
    Atom formats[4];
    const uint8_t* payload;
    size_t payload_len;
    Atom payload_target;
    XSelectionRequestEvent request;
    size_t offset;
    int incremental;
    int transfer_active;
} test_selection_source;

static void test_sleep_ms(unsigned int milliseconds)
{
    struct timespec delay;

    delay.tv_sec = (time_t)(milliseconds / 1000u);
    delay.tv_nsec = (long)(milliseconds % 1000u) * 1000000l;
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR)
    {
    }
}

static int test_bytes_contains(const uint8_t* data,
                               size_t data_len,
                               const uint8_t* needle,
                               size_t needle_len)
{
    size_t index = 0u;

    if ((!data && data_len > 0u) || !needle || needle_len == 0u ||
        needle_len > data_len)
        return 0;
    for (index = 0u; index <= data_len - needle_len; index++)
    {
        if (memcmp(data + index, needle, needle_len) == 0)
            return 1;
    }
    return 0;
}

static int test_start_xvfb(char display_name[32], pid_t* child)
{
    unsigned int attempt = 0u;

    if (!display_name || !child)
        return 0;
    for (attempt = 0u; attempt < 20u; attempt++)
    {
        unsigned int number =
            180u + ((unsigned int)getpid() + attempt) % 60u;
        pid_t pid = 0;
        unsigned int wait_index = 0u;

        if (snprintf(display_name, 32u, ":%u", number) <= 0)
            return 0;
        pid = fork();
        if (pid < 0)
            return 0;
        if (pid == 0)
        {
            execl(LIBRDP_TEST_XVFB_PATH,
                  LIBRDP_TEST_XVFB_PATH,
                  display_name,
                  "-screen",
                  "0",
                  "320x240x24",
                  "-nolisten",
                  "tcp",
                  (char*)NULL);
            _exit(127);
        }
        for (wait_index = 0u; wait_index < 100u; wait_index++)
        {
            Display* probe = XOpenDisplay(display_name);
            int status = 0;

            if (probe)
            {
                XCloseDisplay(probe);
                *child = pid;
                return 1;
            }
            if (waitpid(pid, &status, WNOHANG) == pid)
                break;
            test_sleep_ms(10u);
        }
        kill(pid, SIGTERM);
        (void)waitpid(pid, NULL, 0);
    }
    return 0;
}

static void test_stop_xvfb(pid_t child)
{
    if (child <= 0)
        return;
    kill(child, SIGTERM);
    (void)waitpid(child, NULL, 0);
}

static int test_dispatch_platform(const server_platform_capture_vtable* capture,
                                  void* context,
                                  int timeout_ms)
{
    const server_platform_event_source_vtable* events =
        capture ? capture->events : NULL;
    struct pollfd descriptor;
    size_t count = 0u;
    int ready = 0;

    if (!events ||
        events->get_pollfds(context, NULL, 0u, &count) !=
            LIBRDP_STATUS_OK ||
        count != 1u ||
        events->get_pollfds(context, &descriptor, 1u, &count) !=
            LIBRDP_STATUS_OK)
        return 0;
    ready = poll(&descriptor, 1u, timeout_ms);
    if (ready < 0)
        return errno == EINTR;
    if (ready > 0 &&
        events->notify_poll(context, &descriptor, 1u) !=
            LIBRDP_STATUS_OK)
        return 0;
    return events->dispatch(context, 64u) == LIBRDP_STATUS_OK;
}

static void test_frame_callback(const server_platform_frame* frame,
                                void* user_data)
{
    x11_server_test_state* state = (x11_server_test_state*)user_data;
    size_t sample_offset = 0u;

    if (!state || !frame || !frame->pixels || frame->width <= 20u ||
        frame->height <= 20u || frame->stride < frame->width * 4u)
        return;
    sample_offset = 20u * frame->stride + 20u * 4u;
    if (sample_offset + 4u > frame->pixels_len)
        return;
    state->frame_count++;
    state->last_width = frame->width;
    state->last_height = frame->height;
    state->sample_b = frame->pixels[sample_offset];
    state->sample_g = frame->pixels[sample_offset + 1u];
    state->sample_r = frame->pixels[sample_offset + 2u];
}

static void test_capture_lost(librdp_status status, void* user_data)
{
    x11_server_test_state* state = (x11_server_test_state*)user_data;

    (void)status;
    if (state)
        state->frame_count = UINT64_MAX;
}

static void test_pointer_callback(const server_platform_pointer* pointer,
                                  void* user_data)
{
    x11_server_test_state* state = (x11_server_test_state*)user_data;

    if (!state || !pointer)
        return;
    state->pointer_count++;
    state->pointer_shape = pointer->shape_valid;
    state->pointer_visible = pointer->visible;
}

static void test_clipboard_formats(
    const server_platform_clipboard_format* formats,
    size_t format_count,
    uint64_t generation,
    void* user_data)
{
    x11_server_test_state* state = (x11_server_test_state*)user_data;

    if (!state || generation == 0u ||
        (format_count > 0u && !formats))
        return;
    state->format_count++;
    state->clipboard_generation = generation;
    state->published_format_count = format_count;
    if (format_count > 0u)
    {
        size_t index = 0u;

        for (index = 0u;
             index < format_count &&
             index < TEST_CLIPBOARD_FORMAT_LIMIT;
             index++)
            state->published_format_ids[index] = formats[index].id;
    }
}

static void test_clipboard_data(
    const server_platform_clipboard_data* data,
    void* user_data)
{
    x11_server_test_state* state = (x11_server_test_state*)user_data;

    if (!state || !data)
        return;
    state->data_count++;
    state->clipboard_total_len = data->data_len;
    state->clipboard_format_id = data->format_id;
    state->clipboard_status = data->status;
    state->clipboard_data_len =
        data->data_len < sizeof(state->clipboard_data)
            ? data->data_len
            : sizeof(state->clipboard_data);
    if (state->clipboard_data_len > 0u && data->data)
    {
        memcpy(state->clipboard_data,
               data->data,
               state->clipboard_data_len);
    }
}

static librdp_status test_clipboard_request(
    const server_platform_clipboard_request* request,
    void* user_data)
{
    static const uint8_t utf16_text[] = {
        'r', 0, 'e', 0, 'm', 0, 'o', 0, 't', 0, 'e', 0, 0, 0,
    };
    static const uint8_t html[] =
        "Version:0.9\r\n"
        "StartHTML:0000000105\r\n"
        "EndHTML:0000000187\r\n"
        "StartFragment:0000000137\r\n"
        "EndFragment:0000000155\r\n"
        "<html><body><!--StartFragment-->"
        "<b>remote html</b>"
        "<!--EndFragment--></body></html>";
    static const uint8_t png[] = {
        0x89u, 0x50u, 0x4eu, 0x47u, 0x0du, 0x0au, 0x1au, 0x0au,
        0x00u, 0x00u, 0x00u, 0x0du, 0x49u, 0x48u, 0x44u, 0x52u,
        0x00u, 0x00u, 0x00u, 0x01u, 0x00u, 0x00u, 0x00u, 0x01u,
        0x08u, 0x06u, 0x00u, 0x00u, 0x00u, 0x1fu, 0x15u, 0xc4u,
        0x89u,
    };
    x11_server_test_state* state = (x11_server_test_state*)user_data;
    server_platform_clipboard_data response;
    uint8_t* large = NULL;
    size_t large_units = 70000u;
    size_t index = 0u;

    if (!state || !request || !state->clipboard)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    state->request_count++;
    state->clipboard_peer_id = request->peer_id;
    state->clipboard_peer_generation = request->generation;
    if (state->defer_clipboard_response)
        return LIBRDP_STATUS_OK;
    memset(&response, 0, sizeof(response));
    response.peer_id = request->peer_id;
    response.generation = request->generation;
    response.ownership_generation = request->ownership_generation;
    response.request_id = request->request_id;
    response.format_id = request->format_id;
    response.status = LIBRDP_STATUS_OK;
    response.final_chunk = 1;
    if (request->format_id == TEST_REMOTE_FORMAT_HTML)
    {
        response.data = html;
        response.data_len = sizeof(html) - 1u;
        state->response_status = state->clipboard->write_data(
            state->clipboard_context, &response);
        return state->response_status;
    }
    if (request->format_id == TEST_REMOTE_FORMAT_PNG)
    {
        response.data = png;
        response.data_len = sizeof(png);
        state->response_status = state->clipboard->write_data(
            state->clipboard_context, &response);
        return state->response_status;
    }
    if (!state->send_large_clipboard)
    {
        response.data = utf16_text;
        response.data_len = sizeof(utf16_text);
        state->response_status = state->clipboard->write_data(
            state->clipboard_context, &response);
        return state->response_status;
    }
    large = (uint8_t*)malloc(large_units * 2u + 2u);
    if (!large)
        return LIBRDP_STATUS_NO_MEMORY;
    for (index = 0u; index < large_units; index++)
    {
        large[index * 2u] = 'x';
        large[index * 2u + 1u] = 0u;
    }
    large[large_units * 2u] = 0u;
    large[large_units * 2u + 1u] = 0u;
    response.data = large;
    response.data_len = large_units * 2u + 2u;
    state->response_status = state->clipboard->write_data(
        state->clipboard_context, &response);
    free(large);
    return state->response_status;
}

static librdp_status test_clipboard_file_request(
    const server_platform_clipboard_file_request* request,
    void* user_data)
{
    (void)request;
    (void)user_data;
    return LIBRDP_STATUS_UNSUPPORTED;
}

static librdp_status test_clipboard_cancel(
    uint32_t peer_id,
    uint32_t generation,
    uint64_t ownership_generation,
    uint64_t request_id,
    void* user_data)
{
    x11_server_test_state* state = (x11_server_test_state*)user_data;

    if (!state || peer_id == 0u || generation == 0u ||
        ownership_generation == 0u || request_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    state->cancel_count++;
    return LIBRDP_STATUS_OK;
}

static void test_permission_changed(
    server_platform_permission_kind kind,
    server_platform_permission_state state,
    void* user_data)
{
    x11_server_test_state* test_state =
        (x11_server_test_state*)user_data;

    if (!test_state ||
        kind < SERVER_PLATFORM_PERMISSION_CAPTURE ||
        kind > SERVER_PLATFORM_PERMISSION_DRIVE ||
        state < SERVER_PLATFORM_PERMISSION_UNKNOWN ||
        state > SERVER_PLATFORM_PERMISSION_GRANTED)
        return;
    test_state->permission_count++;
}

static int test_wait_for_event(Display* display,
                               int expected_type,
                               XEvent* output,
                               unsigned int timeout_ms)
{
    unsigned int elapsed = 0u;

    while (elapsed < timeout_ms)
    {
        if (XPending(display) > 0)
        {
            XNextEvent(display, output);
            if (output->type == expected_type)
                return 1;
        }
        test_sleep_ms(5u);
        elapsed += 5u;
    }
    return 0;
}

static void test_selection_source_notify(
    const test_selection_source* source,
    const XSelectionRequestEvent* request,
    Atom property)
{
    XEvent response;

    memset(&response, 0, sizeof(response));
    response.xselection.type = SelectionNotify;
    response.xselection.display = source->display;
    response.xselection.requestor = request->requestor;
    response.xselection.selection = request->selection;
    response.xselection.target = request->target;
    response.xselection.property = property;
    response.xselection.time = request->time;
    XSendEvent(source->display, request->requestor, False, 0, &response);
    XFlush(source->display);
}

/*
 * The synthetic owner implements the native side of ICCCM selection
 * transfers, including the property-delete handshake required by INCR.
 */
static int test_selection_source_dispatch(test_selection_source* source)
{
    if (!source || !source->display)
        return 0;
    while (XPending(source->display) > 0)
    {
        XEvent event;

        XNextEvent(source->display, &event);
        if (event.type == SelectionRequest)
        {
            const XSelectionRequestEvent* request =
                &event.xselectionrequest;
            Atom property = request->property != None
                                ? request->property
                                : request->target;

            if (request->selection != source->clipboard)
                continue;
            if (request->target == source->targets)
            {
                XChangeProperty(source->display,
                                request->requestor,
                                property,
                                XA_ATOM,
                                32,
                                PropModeReplace,
                                (const unsigned char*)source->formats,
                                4);
                test_selection_source_notify(source, request, property);
            }
            else if (request->target == source->payload_target &&
                     (source->payload || source->payload_len == 0u))
            {
                if (source->incremental)
                {
                    unsigned long total =
                        (unsigned long)source->payload_len;

                    source->request = *request;
                    source->request.property = property;
                    source->offset = 0u;
                    source->transfer_active = 1;
                    XSelectInput(source->display,
                                 request->requestor,
                                 PropertyChangeMask);
                    XChangeProperty(source->display,
                                    request->requestor,
                                    property,
                                    source->incr,
                                    32,
                                    PropModeReplace,
                                    (const unsigned char*)&total,
                                    1);
                    test_selection_source_notify(source, request, property);
                }
                else
                {
                    XChangeProperty(source->display,
                                    request->requestor,
                                    property,
                                    request->target,
                                    8,
                                    PropModeReplace,
                                    source->payload,
                                    (int)source->payload_len);
                    test_selection_source_notify(source, request, property);
                }
            }
            else
                test_selection_source_notify(source, request, None);
        }
        else if (event.type == PropertyNotify && source->transfer_active &&
                 event.xproperty.window == source->request.requestor &&
                 event.xproperty.atom == source->request.property &&
                 event.xproperty.state == PropertyDelete)
        {
            size_t remaining = source->payload_len - source->offset;
            size_t chunk = remaining < 7u ? remaining : 7u;

            XChangeProperty(source->display,
                            source->request.requestor,
                            source->request.property,
                            source->request.target,
                            8,
                            PropModeReplace,
                            chunk > 0u
                                ? source->payload + source->offset
                                : NULL,
                            (int)chunk);
            source->offset += chunk;
            if (chunk == 0u)
                source->transfer_active = 0;
            XFlush(source->display);
        }
    }
    return 1;
}

static int test_selection_pump_until(
    const server_platform_capture_vtable* capture,
    void* context,
    test_selection_source* source,
    const uint64_t* counter,
    uint64_t expected)
{
    unsigned int attempt = 0u;

    for (attempt = 0u; attempt < 200u; attempt++)
    {
        if (!test_dispatch_platform(capture, context, 20) ||
            !test_selection_source_dispatch(source))
            return 0;
        if (*counter >= expected && !source->transfer_active)
            return 1;
    }
    return 0;
}

/*
 * Selection reads cover both direct properties and the delete/notify handshake
 * required by INCR, while enforcing a fixed aggregate payload ceiling.
 */
static int test_read_selection(Display* display,
                               Window window,
                               Atom property,
                               Atom incr,
                               const server_platform_capture_vtable* capture,
                               void* context,
                               uint8_t** output,
                               size_t* output_len)
{
    XEvent event;
    Atom type = None;
    int format = 0;
    unsigned long items = 0ul;
    unsigned long after = 0ul;
    unsigned char* data = NULL;
    uint8_t* buffer = NULL;
    size_t length = 0u;
    size_t capacity = 0u;

    if (!test_wait_for_event(display, SelectionNotify, &event, 1000u) ||
        event.xselection.property == None ||
        XGetWindowProperty(display,
                           window,
                           property,
                           0,
                           16 * 1024 * 1024 / 4,
                           False,
                           AnyPropertyType,
                           &type,
                           &format,
                           &items,
                           &after,
                           &data) != Success)
        return 0;
    if (type != incr)
    {
        if (format != 8 || after != 0ul)
        {
            if (data)
                XFree(data);
            return 0;
        }
        buffer = (uint8_t*)malloc((size_t)items + 1u);
        if (!buffer)
        {
            XFree(data);
            return 0;
        }
        memcpy(buffer, data, (size_t)items);
        length = (size_t)items;
        XFree(data);
        buffer[length] = 0u;
        *output = buffer;
        *output_len = length;
        return 1;
    }
    XFree(data);
    XDeleteProperty(display, window, property);
    XFlush(display);
    for (;;)
    {
        size_t chunk_len = 0u;

        if (!test_dispatch_platform(capture, context, 1000))
            break;
        if (!test_wait_for_event(display, PropertyNotify, &event, 1000u))
            break;
        if (event.xproperty.atom != property ||
            event.xproperty.state != PropertyNewValue)
            continue;
        if (XGetWindowProperty(display,
                               window,
                               property,
                               0,
                               16 * 1024 * 1024 / 4,
                               True,
                               AnyPropertyType,
                               &type,
                               &format,
                               &items,
                               &after,
                               &data) != Success ||
            format != 8 || after != 0ul)
            break;
        chunk_len = (size_t)items;
        if (chunk_len == 0u)
        {
            if (data)
                XFree(data);
            if (!buffer)
                buffer = (uint8_t*)calloc(1u, 1u);
            else
                buffer[length] = 0u;
            *output = buffer;
            *output_len = length;
            return buffer != NULL;
        }
        if (length > 16u * 1024u * 1024u - chunk_len)
        {
            XFree(data);
            break;
        }
        if (length + chunk_len + 1u > capacity)
        {
            size_t next = length + chunk_len + 1u;
            uint8_t* resized = (uint8_t*)realloc(buffer, next);

            if (!resized)
            {
                XFree(data);
                break;
            }
            buffer = resized;
            capacity = next;
        }
        memcpy(buffer + length, data, chunk_len);
        length += chunk_len;
        XFree(data);
        data = NULL;
        XFlush(display);
    }
    if (data)
        XFree(data);
    free(buffer);
    return 0;
}

static int test_cli_policy(void)
{
    x11_server_options options;
    char* valid[] = {
        (char*)"server",
        (char*)"--tls-cert",
        (char*)"/tmp/cert.pem",
        (char*)"--tls-key",
        (char*)"/tmp/key.pem",
        (char*)"--allow-capture",
        (char*)"--source",
        (char*)"monitor:2",
        (char*)"--max-fps",
        (char*)"45",
        (char*)"--max-frame-bytes",
        (char*)"1048576",
    };
    char* unsafe[] = {
        (char*)"server",
        (char*)"--security",
        (char*)"standard",
        (char*)"--allow-capture",
    };
    char* relative_tls[] = {
        (char*)"server",
        (char*)"--tls-cert",
        (char*)"cert.pem",
        (char*)"--tls-key",
        (char*)"/tmp/key.pem",
        (char*)"--allow-capture",
    };
    char* zero_fps[] = {
        (char*)"server",
        (char*)"--max-fps",
        (char*)"0",
    };
    char* managed[] = {
        (char*)"server",
        (char*)"--mode",
        (char*)"managed",
        (char*)"--managed-action",
        (char*)"start",
        (char*)"--user",
        (char*)"test-account",
        (char*)"--allow-capture",
        (char*)"--persistent",
        (char*)"--reconnect",
    };

    CHECK(x11_server_parse_options(
              (int)(sizeof(valid) / sizeof(valid[0])),
              valid,
              &options) == 1);
    CHECK(options.source_kind == X11_SERVER_SOURCE_MONITOR);
    CHECK(options.monitor_index == 2u);
    CHECK(options.max_fps == 45u);
    CHECK(options.max_frame_bytes == 1048576u);
    CHECK(options.drive_read_only == 1);
    CHECK(x11_server_parse_options(
              (int)(sizeof(unsafe) / sizeof(unsafe[0])),
              unsafe,
              &options) == 0);
    CHECK(x11_server_parse_options(
              (int)(sizeof(relative_tls) / sizeof(relative_tls[0])),
              relative_tls,
              &options) == 0);
    CHECK(x11_server_parse_options(
              (int)(sizeof(zero_fps) / sizeof(zero_fps[0])),
              zero_fps,
              &options) == 0);
    CHECK(x11_server_parse_options(
              (int)(sizeof(managed) / sizeof(managed[0])),
              managed,
              &options) == 1);
    CHECK(options.session_mode == X11_SERVER_SESSION_MANAGED);
    CHECK(options.managed_action == X11_SERVER_MANAGED_START);
    CHECK(options.persistent_session == 1);
    CHECK(options.reconnect_session == 1);
    return 0;
}

/*
 * File-list tests verify that local URIs become descriptor metadata only after
 * a no-follow regular-file open and that remote range requests remain scoped
 * to the active clipboard generation.
 */
static int test_clipboard_files(void)
{
    static const uint8_t contents[] = "bounded clipboard file";
    server_clipboard_files* files = NULL;
    server_platform_clipboard_file_request request;
    librdp_clipboard_file_metadata metadata;
    char template_path[] = "/tmp/librdp-x11-clipboard-XXXXXX";
    char uri[256];
    char name[256];
    uint8_t* encoded = NULL;
    uint8_t* response = NULL;
    size_t encoded_len = 0u;
    size_t response_len = 0u;
    size_t name_len = 0u;
    uint32_t count = 0u;
    int descriptor = -1;
    int uri_len = 0;

    descriptor = mkstemp(template_path);
    CHECK(descriptor >= 0);
    CHECK(write(descriptor, contents, sizeof(contents) - 1u) ==
          (ssize_t)(sizeof(contents) - 1u));
    CHECK(close(descriptor) == 0);
    descriptor = -1;
    uri_len = snprintf(uri, sizeof(uri), "file://%s\r\n", template_path);
    CHECK(uri_len > 0 && (size_t)uri_len < sizeof(uri));
    files = server_clipboard_files_new();
    CHECK(files != NULL);
    CHECK(server_clipboard_files_import_uri_list(
              files,
              (const uint8_t*)uri,
              (size_t)uri_len,
              19u,
              &encoded,
              &encoded_len) == LIBRDP_STATUS_OK);
    CHECK(server_clipboard_files_count(files) == 1u);
    CHECK(librdp_clipboard_file_group_count(encoded,
                                            encoded_len,
                                            &count) ==
          LIBRDP_STATUS_OK);
    CHECK(count == 1u);
    CHECK(librdp_clipboard_file_metadata_init(&metadata) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_clipboard_file_group_get(encoded,
                                          encoded_len,
                                          0u,
                                          &metadata,
                                          name,
                                          sizeof(name),
                                          &name_len) ==
          LIBRDP_STATUS_OK);
    CHECK(metadata.file_size == sizeof(contents) - 1u);
    CHECK(name_len > 1u && strcmp(name, template_path + 5u) == 0);

    memset(&request, 0, sizeof(request));
    request.ownership_generation = 19u;
    request.file_index = 0;
    request.flags = LIBRDP_CLIPBOARD_FILECONTENTS_SIZE;
    CHECK(server_clipboard_files_read(files,
                                          &request,
                                          &response,
                                          &response_len) ==
          LIBRDP_STATUS_OK);
    CHECK(response_len == 8u &&
          response[0] == sizeof(contents) - 1u);
    free(response);
    response = NULL;

    request.flags = LIBRDP_CLIPBOARD_FILECONTENTS_RANGE;
    request.position = 8u;
    request.requested_bytes = 9u;
    CHECK(server_clipboard_files_read(files,
                                          &request,
                                          &response,
                                          &response_len) ==
          LIBRDP_STATUS_OK);
    CHECK(response_len == 9u &&
          memcmp(response, contents + 8u, 9u) == 0);
    free(response);
    response = NULL;

    request.ownership_generation = 20u;
    CHECK(server_clipboard_files_read(files,
                                          &request,
                                          &response,
                                          &response_len) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(server_clipboard_files_import_uri_list(
              files,
              (const uint8_t*)"file://remote.example/tmp/value\n",
              sizeof("file://remote.example/tmp/value\n") - 1u,
              20u,
              &response,
              &response_len) == LIBRDP_STATUS_UNSUPPORTED);
    CHECK(server_clipboard_files_count(files) == 1u);
    free(encoded);
    server_clipboard_files_free(files);
    CHECK(unlink(template_path) == 0);
    return 0;
}

/*
 * The FUSE provider model is exercised without mounting: this covers secure
 * mount-directory policy, bounded volume registration, duplicate rejection
 * and peer-scoped removal on hosts where the optional backend is built.
 */
static int test_fuse_drive_model(void)
{
    char path[] = "/tmp/librdp-x11-fuse-XXXXXX";
    server_fuse_config config;
    server_fuse* provider = NULL;
    server_platform_drive_volume volume;
    const server_platform_drive_vtable* drive = NULL;

    if (!server_fuse_available())
        return 0;
    CHECK(mkdtemp(path) != NULL);
    CHECK(chmod(path, 0700) == 0);
    CHECK(server_fuse_test_mount_path_secure(path));
    CHECK(chmod(path, 0755) == 0);
    CHECK(!server_fuse_test_mount_path_secure(path));
    CHECK(chmod(path, 0700) == 0);

    server_fuse_config_init(&config);
    config.mount_path = path;
    provider = server_fuse_new(&config);
    CHECK(provider != NULL);
    drive = server_fuse_vtable();
    CHECK(drive != NULL);

    memset(&volume, 0, sizeof(volume));
    volume.volume_id = 17u;
    volume.peer_id = 3u;
    volume.generation = 5u;
    volume.device.reconnect_generation = 5u;
    volume.device.device_id = 9u;
    volume.name = "documents";
    volume.read_only = 1;
    CHECK(server_fuse_test_present(provider, &volume) == LIBRDP_STATUS_OK);
    CHECK(server_fuse_test_volume_count(provider) == 1u);
    CHECK(server_fuse_test_present(provider, &volume) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);

    volume.volume_id = 18u;
    volume.name = "../outside";
    CHECK(server_fuse_test_present(provider, &volume) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    volume.name = "writable";
    volume.read_only = 0;
    CHECK(server_fuse_test_present(provider, &volume) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);

    drive->remove(provider, 3u, 5u, 9u);
    CHECK(server_fuse_test_volume_count(provider) == 0u);
    server_fuse_free(provider);
    CHECK(rmdir(path) == 0);
    return 0;
}

/*
 * Remote clipboard descriptors become read-only FUSE files only after the
 * complete descriptor group is valid. URI escaping and duplicate-name
 * handling prevent ambiguous native paths, while ownership revocation removes
 * every file atomically.
 */
static int test_fuse_clipboard_model(void)
{
    char path[] = "/tmp/librdp-x11-clipboard-fuse-XXXXXX";
    server_fuse_config config;
    server_fuse* provider = NULL;
    librdp_clipboard_file_metadata files[2];
    uint8_t* encoded = NULL;
    uint8_t* uri_list = NULL;
    size_t encoded_len = 0u;
    size_t uri_list_len = 0u;

    if (!server_fuse_available())
        return 0;
    CHECK(mkdtemp(path) != NULL);
    CHECK(chmod(path, 0700) == 0);
    server_fuse_config_init(&config);
    config.mount_path = path;
    provider = server_fuse_new(&config);
    CHECK(provider != NULL);
    CHECK(librdp_clipboard_file_metadata_init(&files[0]) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_clipboard_file_metadata_init(&files[1]) ==
          LIBRDP_STATUS_OK);
    files[0].name = "report file.txt";
    files[0].file_size = 41u;
    files[1].name = "report file.txt";
    files[1].file_size = 73u;
    CHECK(librdp_clipboard_file_group_encode(files,
                                             2u,
                                             NULL,
                                             0u,
                                             &encoded_len) ==
          LIBRDP_STATUS_OK);
    encoded = (uint8_t*)malloc(encoded_len);
    CHECK(encoded != NULL);
    CHECK(librdp_clipboard_file_group_encode(files,
                                             2u,
                                             encoded,
                                             encoded_len,
                                             &encoded_len) ==
          LIBRDP_STATUS_OK);
    CHECK(server_fuse_test_clipboard_publish(provider,
                                                 7u,
                                                 9u,
                                                 11u,
                                                 encoded,
                                                 encoded_len,
                                                 &uri_list,
                                                 &uri_list_len) ==
          LIBRDP_STATUS_OK);
    CHECK(uri_list != NULL && uri_list_len > 0u);
    CHECK(strstr((const char*)uri_list, "report%20file.txt") != NULL);
    CHECK(strstr((const char*)uri_list, "/file-2\r\n") != NULL);
    CHECK(server_fuse_test_clipboard_file_count(provider) == 2u);
    free(uri_list);
    uri_list = NULL;
    CHECK(server_fuse_test_clipboard_publish(provider,
                                                 7u,
                                                 9u,
                                                 12u,
                                                 encoded,
                                                 encoded_len - 1u,
                                                 &uri_list,
                                                 &uri_list_len) ==
          LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(uri_list == NULL && uri_list_len == 0u);
    CHECK(server_fuse_test_clipboard_file_count(provider) == 2u);
    server_fuse_clipboard_clear(provider, 7u, 9u, 11u);
    CHECK(server_fuse_test_clipboard_file_count(provider) == 0u);
    free(encoded);
    server_fuse_free(provider);
    CHECK(rmdir(path) == 0);
    return 0;
}

/*
 * The end-to-end provider fixture exercises all X11 vtables against one
 * isolated display so native event ordering and cross-provider teardown are
 * validated together.
 */
static int test_x11_providers(const char* display_name)
{
    Display* client = NULL;
    int screen = 0;
    Window root = None;
    Window window = None;
    Window requestor = None;
    GC graphics = None;
    XColor red;
    XColor blue;
    Colormap colormap = None;
    x11_server_config config;
    x11_server_context* context = NULL;
    server_platform platform;
    const server_platform_capture_vtable* capture = NULL;
    const server_platform_pointer_vtable* pointer = NULL;
    const server_platform_input_vtable* input = NULL;
    const server_platform_clipboard_vtable* clipboard = NULL;
    const server_platform_permission_vtable* permission = NULL;
    x11_server_test_state state;
    server_platform_capture_sink capture_sink;
    server_platform_pointer_sink pointer_sink;
    server_platform_clipboard_sink clipboard_sink;
    server_platform_permission_sink permission_sink;
    server_platform_permission_state permission_state =
        SERVER_PLATFORM_PERMISSION_UNKNOWN;
    librdp_server_input_event input_event;
    Atom property = None;
    uint8_t* selection = NULL;
    size_t selection_len = 0u;
    uint64_t request_count = 0u;
    unsigned int index = 0u;

    memset(&state, 0, sizeof(state));
    client = XOpenDisplay(display_name);
    CHECK(client != NULL);
    screen = DefaultScreen(client);
    root = RootWindow(client, screen);
    colormap = DefaultColormap(client, screen);
    memset(&red, 0, sizeof(red));
    memset(&blue, 0, sizeof(blue));
    CHECK(XParseColor(client, colormap, "#ff0000", &red));
    CHECK(XAllocColor(client, colormap, &red));
    CHECK(XParseColor(client, colormap, "#0000ff", &blue));
    CHECK(XAllocColor(client, colormap, &blue));
    window = XCreateSimpleWindow(client,
                                 root,
                                 10,
                                 10,
                                 100u,
                                 80u,
                                 0u,
                                 0u,
                                 red.pixel);
    requestor = XCreateSimpleWindow(client,
                                    root,
                                    150,
                                    10,
                                    80u,
                                    40u,
                                    0u,
                                    0u,
                                    0u);
    CHECK(window != None && requestor != None);
    XSelectInput(client,
                 window,
                 KeyPressMask | KeyReleaseMask | ButtonPressMask |
                     ButtonReleaseMask | PointerMotionMask);
    XSelectInput(client, requestor, PropertyChangeMask);
    XMapWindow(client, window);
    XMapWindow(client, requestor);
    graphics = XCreateGC(client, window, 0ul, NULL);
    XSync(client, False);

    x11_server_config_init(&config);
    config.display_name = display_name;
    config.allow_capture = 1;
    config.allow_input = 1;
    config.allow_clipboard = 1;
    context = x11_server_context_new(&config);
    CHECK(context != NULL);
    CHECK(x11_server_context_platform(context, &platform) ==
          LIBRDP_STATUS_OK);
    capture = (const server_platform_capture_vtable*)platform.capture.vtable;
    pointer = (const server_platform_pointer_vtable*)platform.pointer.vtable;
    input = (const server_platform_input_vtable*)platform.input.vtable;
    clipboard =
        (const server_platform_clipboard_vtable*)platform.clipboard.vtable;
    permission =
        (const server_platform_permission_vtable*)platform.permission.vtable;
    CHECK(capture && pointer && input && clipboard && permission);
    memset(&permission_sink, 0, sizeof(permission_sink));
    permission_sink.changed = test_permission_changed;
    permission_sink.user_data = &state;
    CHECK(permission->query(context,
                            SERVER_PLATFORM_PERMISSION_CAPTURE,
                            &permission_state) ==
          LIBRDP_STATUS_OK);
    CHECK(permission_state == SERVER_PLATFORM_PERMISSION_GRANTED);
    CHECK(permission->start(context, &permission_sink) == LIBRDP_STATUS_OK);
    CHECK(permission->revoke(
              context,
              SERVER_PLATFORM_PERMISSION_CAPTURE) == LIBRDP_STATUS_OK);
    CHECK(state.permission_count == 1u);
    CHECK(permission->query(context,
                            SERVER_PLATFORM_PERMISSION_CAPTURE,
                            &permission_state) == LIBRDP_STATUS_OK);
    CHECK(permission_state == SERVER_PLATFORM_PERMISSION_DENIED);
    CHECK(permission->request(
              context,
              SERVER_PLATFORM_PERMISSION_CAPTURE) == LIBRDP_STATUS_OK);
    CHECK(state.permission_count == 2u);
    CHECK(permission->query(context,
                            SERVER_PLATFORM_PERMISSION_CAPTURE,
                            &permission_state) == LIBRDP_STATUS_OK);
    CHECK(permission_state == SERVER_PLATFORM_PERMISSION_GRANTED);
    CHECK(x11_server_context_set_permission(
              context,
              SERVER_PLATFORM_PERMISSION_DRIVE,
              SERVER_PLATFORM_PERMISSION_GRANTED) ==
          LIBRDP_STATUS_UNSUPPORTED);

    memset(&capture_sink, 0, sizeof(capture_sink));
    capture_sink.frame = test_frame_callback;
    capture_sink.lost = test_capture_lost;
    capture_sink.user_data = &state;
    CHECK(capture->start(context, &capture_sink) == LIBRDP_STATUS_OK);
    memset(&pointer_sink, 0, sizeof(pointer_sink));
    pointer_sink.update = test_pointer_callback;
    pointer_sink.user_data = &state;
    CHECK(pointer->start(context, &pointer_sink) == LIBRDP_STATUS_OK);
    memset(&clipboard_sink, 0, sizeof(clipboard_sink));
    clipboard_sink.formats = test_clipboard_formats;
    clipboard_sink.data = test_clipboard_data;
    clipboard_sink.request = test_clipboard_request;
    clipboard_sink.file_request = test_clipboard_file_request;
    clipboard_sink.cancel = test_clipboard_cancel;
    clipboard_sink.user_data = &state;
    CHECK(clipboard->start(context, &clipboard_sink) == LIBRDP_STATUS_OK);
    state.clipboard = clipboard;
    state.clipboard_context = context;

    CHECK(capture->request_frame(context) == LIBRDP_STATUS_OK);
    CHECK(state.frame_count == 1u);
    CHECK(state.last_width == 320u && state.last_height == 240u);
    CHECK(state.sample_r > 200u && state.sample_g < 40u &&
          state.sample_b < 40u);

    XSetForeground(client, graphics, blue.pixel);
    XFillRectangle(client, window, graphics, 0, 0, 40u, 40u);
    XFlush(client);
    for (index = 0u; index < 20u && state.frame_count < 2u; index++)
        CHECK(test_dispatch_platform(capture, context, 100));
    CHECK(state.frame_count >= 2u);
    CHECK(state.sample_b > 200u && state.sample_g < 40u &&
          state.sample_r < 40u);

    XSetInputFocus(client, window, RevertToParent, CurrentTime);
    XSync(client, False);
    CHECK(librdp_server_input_event_init(&input_event) ==
          LIBRDP_STATUS_OK);
    input_event.type = LIBRDP_SERVER_INPUT_SCANCODE_KEY;
    input_event.param1 = 0x1eu;
    CHECK(input->inject(context, &input_event) == LIBRDP_STATUS_OK);
    {
        XEvent event;

        CHECK(test_wait_for_event(client, KeyPress, &event, 1000u));
    }
    input_event.flags = 0x8000u;
    CHECK(input->inject(context, &input_event) == LIBRDP_STATUS_OK);
    input_event.type = LIBRDP_SERVER_INPUT_MOUSE;
    input_event.flags = 0x0800u;
    input_event.x = 20u;
    input_event.y = 20u;
    CHECK(input->inject(context, &input_event) == LIBRDP_STATUS_OK);
    input_event.flags = 0x9000u;
    CHECK(input->inject(context, &input_event) == LIBRDP_STATUS_OK);
    {
        XEvent event;

        CHECK(test_wait_for_event(client, ButtonPress, &event, 1000u));
    }
    input_event.flags = 0x1000u;
    CHECK(input->inject(context, &input_event) == LIBRDP_STATUS_OK);
    input->release_all(context);

    XWarpPointer(client, None, root, 0, 0, 0, 0, 50, 50);
    XFlush(client);
    for (index = 0u; index < 20u && state.pointer_count < 2u; index++)
        CHECK(test_dispatch_platform(capture, context, 100));
    CHECK(state.pointer_count >= 1u);
    CHECK(state.pointer_shape);
    CHECK(state.pointer_visible);

    {
        server_platform_clipboard_format formats[4];
        server_platform_clipboard_offer offer;

        memset(formats, 0, sizeof(formats));
        formats[0].id = LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT;
        formats[0].mime_type = "text/plain;charset=utf-8";
        formats[1].id = TEST_REMOTE_FORMAT_HTML;
        formats[1].mime_type = "text/html";
        formats[2].id = TEST_REMOTE_FORMAT_PNG;
        formats[2].mime_type = "image/png";
        formats[3].id = LIBRDP_CLIPBOARD_FORMAT_HDROP;
        formats[3].mime_type = "text/uri-list";
        memset(&offer, 0, sizeof(offer));
        offer.peer_id = 23u;
        offer.generation = 5u;
        offer.ownership_generation = 7u;
        offer.formats = formats;
        offer.format_count = 4u;
        CHECK(clipboard->publish_formats(context, &offer) ==
              LIBRDP_STATUS_OK);
    }
    property = XInternAtom(client, "_LIBRDP_TEST_SELECTION", False);
    XConvertSelection(client,
                      XInternAtom(client, "CLIPBOARD", False),
                      XInternAtom(client, "UTF8_STRING", False),
                      property,
                      requestor,
                      CurrentTime);
    XFlush(client);
    CHECK(test_dispatch_platform(capture, context, 1000));
    CHECK(state.response_status == LIBRDP_STATUS_OK);
    CHECK(test_read_selection(client,
                              requestor,
                              property,
                              XInternAtom(client, "INCR", False),
                              capture,
                              context,
                              &selection,
                              &selection_len));
    CHECK(selection_len == 6u &&
          memcmp(selection, "remote", 6u) == 0);
    CHECK(state.clipboard_peer_id == 23u);
    CHECK(state.clipboard_peer_generation == 5u);
    free(selection);
    selection = NULL;

    request_count = state.request_count;
    state.response_status = LIBRDP_STATUS_STATE;
    XConvertSelection(client,
                      XInternAtom(client, "CLIPBOARD", False),
                      XInternAtom(client, "text/html", False),
                      property,
                      requestor,
                      CurrentTime);
    XFlush(client);
    CHECK(test_dispatch_platform(capture, context, 1000));
    CHECK(state.request_count == request_count + 1u);
    CHECK(state.response_status == LIBRDP_STATUS_OK);
    CHECK(test_read_selection(client,
                              requestor,
                              property,
                              XInternAtom(client, "INCR", False),
                              capture,
                              context,
                              &selection,
                              &selection_len));
    CHECK(selection_len == sizeof("<b>remote html</b>") - 1u &&
          memcmp(selection,
                 "<b>remote html</b>",
                 sizeof("<b>remote html</b>") - 1u) == 0);
    free(selection);
    selection = NULL;

    XConvertSelection(client,
                      XInternAtom(client, "CLIPBOARD", False),
                      XInternAtom(client, "image/png", False),
                      property,
                      requestor,
                      CurrentTime);
    XFlush(client);
    CHECK(test_dispatch_platform(capture, context, 1000));
    CHECK(test_read_selection(client,
                              requestor,
                              property,
                              XInternAtom(client, "INCR", False),
                              capture,
                              context,
                              &selection,
                              &selection_len));
    CHECK(selection_len == 33u &&
          memcmp(selection, "\x89PNG\r\n\x1a\n", 8u) == 0);
    free(selection);
    selection = NULL;

    XConvertSelection(client,
                      XInternAtom(client, "CLIPBOARD", False),
                      XInternAtom(client, "text/uri-list", False),
                      property,
                      requestor,
                      CurrentTime);
    XFlush(client);
    CHECK(test_dispatch_platform(capture, context, 1000));
    {
        XEvent event;

        CHECK(test_wait_for_event(client, SelectionNotify, &event, 1000u));
        CHECK(event.xselection.property == None);
    }

    state.send_large_clipboard = 1;
    XConvertSelection(client,
                      XInternAtom(client, "CLIPBOARD", False),
                      XInternAtom(client, "UTF8_STRING", False),
                      property,
                      requestor,
                      CurrentTime);
    XFlush(client);
    CHECK(test_dispatch_platform(capture, context, 1000));
    CHECK(test_read_selection(client,
                              requestor,
                              property,
                              XInternAtom(client, "INCR", False),
                              capture,
                              context,
                              &selection,
                              &selection_len));
    CHECK(selection_len == 70000u);
    for (index = 0u; index < selection_len; index++)
        CHECK(selection[index] == 'x');
    free(selection);

    state.send_large_clipboard = 0;
    state.defer_clipboard_response = 1;
    request_count = state.request_count;
    XConvertSelection(client,
                      XInternAtom(client, "CLIPBOARD", False),
                      XInternAtom(client, "UTF8_STRING", False),
                      property,
                      requestor,
                      CurrentTime);
    XFlush(client);
    for (index = 0u;
         index < 20u && state.request_count == request_count;
         index++)
        CHECK(test_dispatch_platform(capture, context, 100));
    CHECK(state.request_count == request_count + 1u);
    x11_server_context_test_expire_clipboard(context);
    {
        XEvent event;

        CHECK(test_wait_for_event(client, SelectionNotify, &event, 1000u));
        CHECK(event.xselection.property == None);
    }
    CHECK(state.cancel_count == 1u);

    {
        static const uint8_t local_text[] = "local incremental text";
        static const uint8_t local_html[] = "<i>local html</i>";
        static const uint8_t local_png[] = {
            0x89u, 0x50u, 0x4eu, 0x47u, 0x0du, 0x0au, 0x1au, 0x0au,
            0x00u, 0x00u, 0x00u, 0x0du, 0x49u, 0x48u, 0x44u, 0x52u,
            0x00u, 0x00u, 0x00u, 0x01u, 0x00u, 0x00u, 0x00u, 0x01u,
            0x08u, 0x06u, 0x00u, 0x00u, 0x00u, 0x1fu, 0x15u, 0xc4u,
            0x89u,
        };
        static const uint8_t file_contents[] = "clipboard range payload";
        test_selection_source source;
        server_platform_clipboard_file_request file_request;
        librdp_clipboard_file_metadata metadata;
        char file_path[] = "/tmp/librdp-x11-owner-file-XXXXXX";
        char file_uri[256];
        char decoded_name[256];
        size_t decoded_name_len = 0u;
        uint32_t file_count = 0u;
        uint64_t format_events = state.format_count;
        uint64_t data_events = 0u;
        int descriptor = -1;
        int uri_len = 0;

        memset(&source, 0, sizeof(source));
        source.display = client;
        source.owner = requestor;
        source.clipboard = XInternAtom(client, "CLIPBOARD", False);
        source.targets = XInternAtom(client, "TARGETS", False);
        source.incr = XInternAtom(client, "INCR", False);
        source.formats[0] = XInternAtom(client, "UTF8_STRING", False);
        source.formats[1] = XInternAtom(client, "text/html", False);
        source.formats[2] = XInternAtom(client, "image/png", False);
        source.formats[3] = XInternAtom(client, "text/uri-list", False);
        state.defer_clipboard_response = 0;
        XSetSelectionOwner(client,
                           source.clipboard,
                           source.owner,
                           CurrentTime);
        XFlush(client);
        CHECK(test_selection_pump_until(capture,
                                        context,
                                        &source,
                                        &state.format_count,
                                        format_events + 1u));
        CHECK(state.published_format_count == 4u);
        CHECK(state.published_format_ids[0] ==
              LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT);
        CHECK(state.published_format_ids[1] ==
              LIBRDP_CLIPBOARD_FORMAT_HTML);
        CHECK(state.published_format_ids[2] ==
              LIBRDP_CLIPBOARD_FORMAT_PNG);
        CHECK(state.published_format_ids[3] ==
              LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW);
        CHECK(state.clipboard_generation != 0u);

        source.payload = local_text;
        source.payload_len = sizeof(local_text) - 1u;
        source.payload_target = source.formats[0];
        source.incremental = 1;
        data_events = state.data_count;
        CHECK(clipboard->request_data(context,
                                      501u,
                                      LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT) ==
              LIBRDP_STATUS_OK);
        CHECK(test_selection_pump_until(capture,
                                        context,
                                        &source,
                                        &state.data_count,
                                        data_events + 1u));
        CHECK(state.clipboard_status == LIBRDP_STATUS_OK);
        CHECK(state.clipboard_format_id ==
              LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT);
        CHECK(state.clipboard_total_len ==
              (sizeof(local_text) - 1u) * 2u);
        CHECK(state.clipboard_data[0] == 'l' &&
              state.clipboard_data[1] == 0u &&
              state.clipboard_data[2] == 'o' &&
              state.clipboard_data[3] == 0u);

        source.payload = local_html;
        source.payload_len = sizeof(local_html) - 1u;
        source.payload_target = source.formats[1];
        source.incremental = 0;
        data_events = state.data_count;
        CHECK(clipboard->request_data(context,
                                      502u,
                                      LIBRDP_CLIPBOARD_FORMAT_HTML) ==
              LIBRDP_STATUS_OK);
        CHECK(test_selection_pump_until(capture,
                                        context,
                                        &source,
                                        &state.data_count,
                                        data_events + 1u));
        CHECK(state.clipboard_status == LIBRDP_STATUS_OK);
        CHECK(test_bytes_contains(state.clipboard_data,
                                  state.clipboard_data_len,
                                  local_html,
                                  sizeof(local_html) - 1u));
        CHECK(test_bytes_contains(
            state.clipboard_data,
            state.clipboard_data_len,
            (const uint8_t*)"StartFragment:",
            sizeof("StartFragment:") - 1u));

        source.payload = local_png;
        source.payload_len = sizeof(local_png);
        source.payload_target = source.formats[2];
        data_events = state.data_count;
        CHECK(clipboard->request_data(context,
                                      503u,
                                      LIBRDP_CLIPBOARD_FORMAT_PNG) ==
              LIBRDP_STATUS_OK);
        CHECK(test_selection_pump_until(capture,
                                        context,
                                        &source,
                                        &state.data_count,
                                        data_events + 1u));
        CHECK(state.clipboard_status == LIBRDP_STATUS_OK);
        CHECK(state.clipboard_total_len == sizeof(local_png));
        CHECK(memcmp(state.clipboard_data,
                     local_png,
                     sizeof(local_png)) == 0);

        descriptor = mkstemp(file_path);
        CHECK(descriptor >= 0);
        CHECK(write(descriptor,
                    file_contents,
                    sizeof(file_contents) - 1u) ==
              (ssize_t)(sizeof(file_contents) - 1u));
        CHECK(close(descriptor) == 0);
        descriptor = -1;
        uri_len = snprintf(file_uri,
                           sizeof(file_uri),
                           "file://%s\r\n",
                           file_path);
        CHECK(uri_len > 0 && (size_t)uri_len < sizeof(file_uri));
        source.payload = (const uint8_t*)file_uri;
        source.payload_len = (size_t)uri_len;
        source.payload_target = source.formats[3];
        data_events = state.data_count;
        CHECK(clipboard->request_data(
                  context,
                  504u,
                  LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW) ==
              LIBRDP_STATUS_OK);
        CHECK(test_selection_pump_until(capture,
                                        context,
                                        &source,
                                        &state.data_count,
                                        data_events + 1u));
        CHECK(state.clipboard_status == LIBRDP_STATUS_OK);
        CHECK(librdp_clipboard_file_group_count(state.clipboard_data,
                                                state.clipboard_total_len,
                                                &file_count) ==
              LIBRDP_STATUS_OK);
        CHECK(file_count == 1u);
        CHECK(librdp_clipboard_file_metadata_init(&metadata) ==
              LIBRDP_STATUS_OK);
        CHECK(librdp_clipboard_file_group_get(
                  state.clipboard_data,
                  state.clipboard_total_len,
                  0u,
                  &metadata,
                  decoded_name,
                  sizeof(decoded_name),
                  &decoded_name_len) == LIBRDP_STATUS_OK);
        CHECK(metadata.file_size == sizeof(file_contents) - 1u);
        memset(&file_request, 0, sizeof(file_request));
        file_request.peer_id = 31u;
        file_request.generation = 2u;
        file_request.ownership_generation =
            state.clipboard_generation;
        file_request.request_id = 505u;
        file_request.stream_id = 9u;
        file_request.file_index = 0;
        file_request.flags = LIBRDP_CLIPBOARD_FILECONTENTS_RANGE;
        file_request.position = 10u;
        file_request.requested_bytes = 5u;
        data_events = state.data_count;
        CHECK(clipboard->request_file(context, &file_request) ==
              LIBRDP_STATUS_OK);
        CHECK(state.data_count == data_events + 1u);
        CHECK(state.clipboard_status == LIBRDP_STATUS_OK);
        CHECK(state.clipboard_total_len == 5u);
        CHECK(memcmp(state.clipboard_data,
                     file_contents + 10u,
                     5u) == 0);
        CHECK(unlink(file_path) == 0);
    }

    clipboard->stop(context);
    pointer->stop(context);
    capture->stop(context);
    permission->stop(context);
    x11_server_context_free(context);
    XFreeGC(client, graphics);
    XDestroyWindow(client, requestor);
    XDestroyWindow(client, window);
    XCloseDisplay(client);
    return 0;
}

int main(void)
{
    char display_name[32];
    pid_t child = -1;
    int result = 1;

    if (test_cli_policy() != 0)
        return 1;
    if (test_clipboard_files() != 0)
        return 1;
    if (test_fuse_drive_model() != 0)
        return 1;
    if (test_fuse_clipboard_model() != 0)
        return 1;
    if (!test_start_xvfb(display_name, &child))
    {
        fprintf(stderr, "unable to start isolated Xvfb\n");
        return 1;
    }
    result = test_x11_providers(display_name);
    test_stop_xvfb(child);
    return result;
}
