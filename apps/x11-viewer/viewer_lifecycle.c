/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer lifecycle orchestration, event loop, and public
 * client API exercise path.
 * Invariants: viewer state, X11 resources, and session callbacks are kept
 * consistent with focus and resize events.
 * Ownership: the viewer state owns X11 handles and session callbacks, while
 * the core owns protocol/session lifetime.
 * Threading: called from the viewer event thread unless a backend explicitly
 * documents its own callback thread.
 * Trust boundary: command-line options, local devices, X11 events, and server
 * callbacks are separate trust domains.
 */


#include <librdp/librdp.h>

#include "audio_pipewire.h"
#include "camera_v4l2.h"
#include "device_backends.h"
#include "viewer_app.h"
#include "viewer_clipboard.h"
#include "viewer_cli.h"
#include "viewer_display.h"
#include "viewer_input.h"
#include "viewer_lifecycle.h"
#include "viewer_render.h"
#include "viewer_trace.h"
#include "viewer_window.h"

#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <X11/extensions/Xfixes.h>
#include <X11/XKBlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char* x11_strdup_text(const char* text)
{
    size_t length = 0;
    char* copy = NULL;

    if (!text)
        return NULL;
    length = strlen(text) + 1u;
    copy = (char*)malloc(length);
    if (!copy)
        return NULL;
    memcpy(copy, text, length);
    return copy;
}

static void set_window_identity(x11_app* app)
{
    XClassHint hint;

    if (!app || !app->display || !app->window)
        return;

    XStoreName(app->display, app->window, "librdp-x11-viewer");
    hint.res_name = (char*)"librdp-x11-viewer";
    hint.res_class = (char*)"LibrdpX11Viewer";
    XSetClassHint(app->display, app->window, &hint);
}

static int x11_audio_configure(x11_app* app, const librdp_settings* settings)
{
    const char* output_device = NULL;
    const char* input_device = NULL;

    if (!app || !settings)
        return 0;
    app->audio_output_requested =
        librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_AUDIO_OUTPUT) ? 1 : 0;
    app->audio_input_requested =
        librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_AUDIO_INPUT) ? 1 : 0;
    if (!app->audio_output_requested && !app->audio_input_requested)
        return 1;

    output_device = librdp_settings_audio_output_device(settings);
    input_device = librdp_settings_audio_input_device(settings);
    if (app->audio_output_requested)
    {
        app->audio_output_device = x11_strdup_text(output_device ? output_device : "pipewire");
        if (!app->audio_output_device)
            return 0;
    }
    if (app->audio_input_requested)
    {
        app->audio_input_device = x11_strdup_text(input_device ? input_device : "pipewire");
        if (!app->audio_input_device)
            return 0;
    }
    app->audio = x11_pipewire_audio_new();
    if (!app->audio)
        return 0;
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.audio.configured",
                    "output=%u input=%u backend=pipewire",
                    app->audio_output_requested ? 1u : 0u,
                    app->audio_input_requested ? 1u : 0u);
    return 1;
}

static void x11_audio_free(x11_app* app)
{
    if (!app)
        return;
    x11_pipewire_audio_free(app->audio);
    app->audio = NULL;
    free(app->audio_output_device);
    app->audio_output_device = NULL;
    free(app->audio_input_device);
    app->audio_input_device = NULL;
    app->audio_input_active = 0;
}

static int x11_runtime_features_configure(x11_app* app, const librdp_settings* settings)
{
    const char* video_path = NULL;
    const char* camera_source = NULL;

    if (!app || !settings)
        return 0;
    app->echo_requested = librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_ECHO) ? 1 : 0;
    app->telemetry_requested = librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_TELEMETRY) ? 1 : 0;
    app->video_requested = librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_VIDEO) ? 1 : 0;
    app->camera_requested = librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_CAMERA) &&
                                    librdp_settings_camera_count(settings) > 0 ?
                                1 :
                                0;
    if (app->video_requested)
    {
        video_path = librdp_settings_video_output_path(settings);
        if (video_path)
        {
            app->video_output_file = fopen(video_path, "ab");
            if (!app->video_output_file)
            {
                x11_trace_event(X11_TRACE_CLIENT,
                                "x11.video.file.failed",
                                "path=\"%s\" errno=%d",
                                video_path,
                                errno);
                return 0;
            }
            x11_trace_event(X11_TRACE_CLIENT,
                            "x11.video.file.open",
                            "path=\"%s\"",
                            video_path);
        }
    }
    if (app->camera_requested)
    {
        camera_source = librdp_settings_camera_source(settings, 0);
        app->camera_source = x11_strdup_text(camera_source);
        if (!app->camera_source)
            return 0;
        app->camera = x11_camera_capture_new();
        if (!app->camera)
            return 0;
    }
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.runtime.features",
                    "echo=%u telemetry=%u video=%u video_file=%u camera=%u",
                    app->echo_requested ? 1u : 0u,
                    app->telemetry_requested ? 1u : 0u,
                    app->video_requested ? 1u : 0u,
                    app->video_output_file ? 1u : 0u,
                    app->camera_requested ? 1u : 0u);
    return 1;
}

static void x11_runtime_features_free(x11_app* app)
{
    if (!app)
        return;
    if (app->video_output_file)
        fclose(app->video_output_file);
    app->video_output_file = NULL;
    x11_camera_capture_free(app->camera);
    app->camera = NULL;
    free(app->camera_source);
    app->camera_source = NULL;
    app->camera_requested = 0;
}

static size_t x11_audio_input_chunk_size(const librdp_audio_input_open_event* open)
{
    size_t chunk = 0;

    if (!open || open->format.block_align == 0)
        return 0;
    chunk = (size_t)open->frames_per_packet * open->format.block_align;
    if (chunk == 0)
        chunk = open->format.block_align;
    if (chunk > X11_AUDIO_INPUT_BUFFER_BYTES)
    {
        chunk = X11_AUDIO_INPUT_BUFFER_BYTES - (X11_AUDIO_INPUT_BUFFER_BYTES % open->format.block_align);
        if (chunk == 0)
            chunk = open->format.block_align;
    }
    return chunk;
}

static void x11_audio_output_store_formats(x11_app* app, const librdp_audio_output_formats_event* formats)
{
    uint32_t count = 0;

    if (!app || !formats)
        return;
    app->audio_output_format_count = 0;
    app->audio_output_current_format = UINT32_MAX;
    memset(app->audio_output_formats, 0, sizeof(app->audio_output_formats));
    if (!formats->formats || formats->count == 0)
        return;
    count = formats->count > X11_AUDIO_OUTPUT_FORMATS_MAX ? X11_AUDIO_OUTPUT_FORMATS_MAX : formats->count;
    memcpy(app->audio_output_formats, formats->formats, sizeof(app->audio_output_formats[0]) * count);
    app->audio_output_format_count = count;
}

static int x11_audio_output_select_format(x11_app* app, uint32_t format_no)
{
    int ok = 0;

    if (!app || !app->audio_output_requested || !app->audio)
        return 0;
    if (format_no >= app->audio_output_format_count)
    {
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.audio.output.format.failed",
                        "reason=index format=%u count=%u",
                        format_no,
                        app->audio_output_format_count);
        return 0;
    }
    if (app->audio_output_current_format == format_no)
        return 1;
    ok = x11_pipewire_audio_start_output(app->audio,
                                         &app->audio_output_formats[format_no],
                                         app->audio_output_device);
    if (ok)
    {
        app->audio_output_current_format = format_no;
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.audio.output.format",
                        "format=%u tag=%u channels=%u rate=%u bits=%u",
                        format_no,
                        app->audio_output_formats[format_no].format_tag,
                        app->audio_output_formats[format_no].channels,
                        app->audio_output_formats[format_no].samples_per_sec,
                        app->audio_output_formats[format_no].bits_per_sample);
    }
    return ok;
}

static void x11_audio_input_pump(x11_app* app)
{
    size_t bytes = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!app || !app->audio_input_active || !app->audio || !app->session || app->audio_input_chunk == 0)
        return;
    bytes = x11_pipewire_audio_read_input(app->audio,
                                          app->audio_input_buffer,
                                          app->audio_input_chunk);
    if (bytes == 0)
        return;
    status = librdp_session_audio_input_send_data(app->session, app->audio_input_buffer, bytes);
    if (status != LIBRDP_STATUS_OK)
    {
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.audio.input.send.failed",
                        "status=%s bytes=%u",
                        librdp_status_string(status),
                        (unsigned)bytes);
        app->audio_input_active = 0;
    }
    else
    {
        x11_trace_event_level(X11_TRACE_CLIENT,
                              X11_TRACE_LEVEL_TRACE,
                              "x11.audio.input.send",
                              "bytes=%u",
                              (unsigned)bytes);
    }
}

static int x11_channel_name_contains(const char* name, size_t name_len, const char* needle)
{
    size_t needle_len = 0;
    size_t i = 0;
    size_t j = 0;

    if (!name || !needle)
        return 0;
    needle_len = strlen(needle);
    if (needle_len == 0 || needle_len > name_len)
        return 0;
    for (i = 0; i + needle_len <= name_len; i++)
    {
        for (j = 0; j < needle_len; j++)
        {
            if (tolower((unsigned char)name[i + j]) != tolower((unsigned char)needle[j]))
                break;
        }
        if (j == needle_len)
            return 1;
    }
    return 0;
}

static int x11_channel_name_print_len(size_t name_len)
{
    return name_len > 255u ? 255 : (int)name_len;
}

static void x11_handle_channel_open(x11_app* app, librdp_session* session, const librdp_channel_open_event* event)
{
    if (!app || !session || !event)
        return;
    (void)session;
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.channel.open",
                    "id=%u name=\"%.*s\" echo=%u telemetry=%u video=%u",
                    event->channel_id,
                    x11_channel_name_print_len(event->name_len),
                    event->name ? event->name : "",
                    app->echo_requested ? 1u : 0u,
                    app->telemetry_requested ? 1u : 0u,
                    app->video_requested ? 1u : 0u);
}

static void x11_handle_channel_data(x11_app* app, librdp_session* session, const librdp_channel_data_event* event)
{
    size_t video_written = 0;

    if (!app || !session || !event)
        return;
    (void)session;
    if (app->video_output_file &&
        (x11_channel_name_contains(event->name, event->name_len, "video") ||
         x11_channel_name_contains(event->name, event->name_len, "tsmf")) &&
        event->data_len > 0)
    {
        video_written = fwrite(event->data, 1, event->data_len, app->video_output_file);
        fflush(app->video_output_file);
    }
    x11_trace_event_level(X11_TRACE_CLIENT,
                          X11_TRACE_LEVEL_DEBUG,
                          "x11.channel.data",
                          "id=%u name=\"%.*s\" bytes=%u video_written=%u",
                          event->channel_id,
                          x11_channel_name_print_len(event->name_len),
                          event->name ? event->name : "",
                          (unsigned)event->data_len,
                          (unsigned)video_written);
}

static void x11_handle_channel_close(x11_app* app, const librdp_channel_close_event* event)
{
    if (!app || !event)
        return;
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.channel.close",
                    "id=%u name=\"%.*s\"",
                    event->channel_id,
                    x11_channel_name_print_len(event->name_len),
                    event->name ? event->name : "");
}

/*
 * Handle one X11 event at the viewer boundary. The handler translates local
 * focus, pointer, keyboard, expose, and resize state into session calls while
 * keeping grabs and remote key release ordering consistent.
 */
static void app_event(librdp_session* session, const librdp_event* event, void* user_data)
{
    x11_app* app = (x11_app*)user_data;

    if (!app || !event)
        return;
    app->event_serial++;

    switch (event->type)
    {
        case LIBRDP_EVENT_SURFACE_INVALIDATED:
        {
            const int dirty_before = app->dirty;

            app->dirty = 1;
            x11_trace_event_level(X11_TRACE_CLIENT,
                                  X11_TRACE_LEVEL_TRACE,
                                  "client.active.framebuffer.blit",
                                  "x=%u y=%u width=%u height=%u dirty_before=%u event_serial=%llu",
                                  event->data.surface.x,
                                  event->data.surface.y,
                                  event->data.surface.width,
                                  event->data.surface.height,
                                  dirty_before ? 1u : 0u,
                                  (unsigned long long)app->event_serial);
            break;
        }
        case LIBRDP_EVENT_DISCONNECTED:
            app->running = 0;
            break;
        case LIBRDP_EVENT_POINTER:
            x11_input_handle_pointer_event(app, &event->data.pointer);
            break;
        case LIBRDP_EVENT_CLIPBOARD_FORMATS:
        {
            uint32_t i = 0;

            for (i = 0; i < event->data.clipboard_formats.count; i++)
            {
                if (event->data.clipboard_formats.formats[i].format_id == LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT)
                {
                    (void)librdp_session_clipboard_request_data(app->session,
                                                                LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT);
                    x11_trace_event(X11_TRACE_CLIENT,
                                    "x11.clipboard.remote_formats",
                                    "unicode_text=1 count=%u total=%u",
                                    event->data.clipboard_formats.count,
                                    event->data.clipboard_formats.total_count);
                    break;
                }
            }
            break;
        }
        case LIBRDP_EVENT_CLIPBOARD_DATA:
            if (event->data.clipboard_data.ok &&
                event->data.clipboard_data.format_id == LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT)
                x11_clipboard_set_remote_utf16le(app,
                                                 event->data.clipboard_data.data,
                                                 event->data.clipboard_data.data_len);
            break;
        case LIBRDP_EVENT_AUDIO_OUTPUT_FORMATS:
        {
            x11_audio_output_store_formats(app, &event->data.audio_output_formats);
            if (app->audio_output_format_count > 0)
                (void)x11_audio_output_select_format(app, 0);
            x11_trace_event(X11_TRACE_CLIENT,
                            "x11.audio.output.formats",
                            "count=%u stored=%u version=%u requested=%u",
                            event->data.audio_output_formats.count,
                            app->audio_output_format_count,
                            event->data.audio_output_formats.version,
                            app->audio_output_requested ? 1u : 0u);
            break;
        }
        case LIBRDP_EVENT_AUDIO_OUTPUT_DATA:
        {
            if (x11_audio_output_select_format(app, event->data.audio_output_data.format_no))
                (void)x11_pipewire_audio_write_output(app->audio,
                                                      event->data.audio_output_data.data,
                                                      event->data.audio_output_data.data_len);
            x11_trace_event_level(X11_TRACE_CLIENT,
                                  X11_TRACE_LEVEL_TRACE,
                                  "x11.audio.output.data",
                                  "bytes=%u format=%u block=%u requested=%u",
                                  (unsigned)event->data.audio_output_data.data_len,
                                  event->data.audio_output_data.format_no,
                                  event->data.audio_output_data.block_no,
                                  app->audio_output_requested ? 1u : 0u);
            break;
        }
        case LIBRDP_EVENT_AUDIO_OUTPUT_CLOSE:
            if (app->audio)
                x11_pipewire_audio_stop_output(app->audio);
            app->audio_output_current_format = UINT32_MAX;
            x11_trace_event(X11_TRACE_CLIENT,
                            "x11.audio.output.close",
                            "requested=%u",
                            app->audio_output_requested ? 1u : 0u);
            break;
        case LIBRDP_EVENT_AUDIO_INPUT_FORMATS:
            x11_trace_event(X11_TRACE_CLIENT,
                            "x11.audio.input.formats",
                            "count=%u version=%u requested=%u",
                            event->data.audio_input_formats.count,
                            event->data.audio_input_formats.version,
                            app->audio_input_requested ? 1u : 0u);
            break;
        case LIBRDP_EVENT_AUDIO_INPUT_OPEN:
        {
            int ok = 0;

            app->audio_input_active = 0;
            app->audio_input_chunk = x11_audio_input_chunk_size(&event->data.audio_input_open);
            if (app->audio_input_requested && app->audio && app->audio_input_chunk > 0)
                ok = x11_pipewire_audio_start_input(app->audio,
                                                    &event->data.audio_input_open.format,
                                                    app->audio_input_device);
            (void)librdp_session_audio_input_open_reply(session,
                                                        ok ? LIBRDP_AUDIO_INPUT_RESULT_OK :
                                                             LIBRDP_AUDIO_INPUT_RESULT_FAIL);
            app->audio_input_active = ok ? 1 : 0;
            x11_trace_event(X11_TRACE_CLIENT,
                            "x11.audio.input.open",
                            "ok=%u requested=%u frames=%u chunk=%u initial_format=%u",
                            ok ? 1u : 0u,
                            app->audio_input_requested ? 1u : 0u,
                            event->data.audio_input_open.frames_per_packet,
                            (unsigned)app->audio_input_chunk,
                            event->data.audio_input_open.initial_format);
            break;
        }
        case LIBRDP_EVENT_VIDEO_CAPTURE_OPEN:
        {
            int ok = 0;

            if (app->camera_requested && app->camera && app->camera_source)
                ok = x11_camera_capture_start(app->camera,
                                              app->camera_source,
                                              &event->data.video_capture_open.media);
            x11_trace_event(X11_TRACE_CLIENT,
                            "x11.camera.open",
                            "ok=%u requested=%u stream=%u format=%u width=%u height=%u",
                            ok ? 1u : 0u,
                            app->camera_requested ? 1u : 0u,
                            event->data.video_capture_open.stream_index,
                            event->data.video_capture_open.media.format,
                            event->data.video_capture_open.media.width,
                            event->data.video_capture_open.media.height);
            break;
        }
        case LIBRDP_EVENT_VIDEO_CAPTURE_SAMPLE_REQUEST:
        {
            uint8_t* sample = NULL;
            size_t sample_len = 0;
            int sample_result = 0;
            librdp_status status = LIBRDP_STATUS_OK;

            if (app->camera_requested && app->camera)
                sample_result = x11_camera_capture_read_sample(app->camera, &sample, &sample_len);
            if (sample_result == 1)
                status = librdp_session_video_capture_send_sample(
                    session,
                    event->data.video_capture_sample_request.stream_index,
                    sample,
                    sample_len);
            else
                status = librdp_session_video_capture_send_error(
                    session,
                    event->data.video_capture_sample_request.stream_index,
                    sample_result == 0 ? LIBRDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED :
                                         LIBRDP_VIDEO_CAPTURE_ERROR_UNEXPECTED);
            x11_trace_event_level(X11_TRACE_CLIENT,
                                  X11_TRACE_LEVEL_DEBUG,
                                  "x11.camera.sample.reply",
                                  "status=%s result=%d stream=%u bytes=%u",
                                  librdp_status_string(status),
                                  sample_result,
                                  event->data.video_capture_sample_request.stream_index,
                                  (unsigned)sample_len);
            free(sample);
            break;
        }
        case LIBRDP_EVENT_VIDEO_CAPTURE_CLOSE:
            if (app->camera)
                x11_camera_capture_stop(app->camera);
            x11_trace_event(X11_TRACE_CLIENT,
                            "x11.camera.close",
                            "stream=%u",
                            event->data.video_capture_close.stream_index);
            break;
        case LIBRDP_EVENT_CHANNEL_OPEN:
            x11_handle_channel_open(app, session, &event->data.channel_open);
            break;
        case LIBRDP_EVENT_CHANNEL_DATA:
            x11_handle_channel_data(app, session, &event->data.channel_data);
            break;
        case LIBRDP_EVENT_CHANNEL_CLOSE:
            x11_handle_channel_close(app, &event->data.channel_close);
            break;
        case LIBRDP_EVENT_ERROR:
            fprintf(stderr, "error=%s\n", librdp_status_string(event->data.error.status));
            app->running = 0;
            break;
        default:
            break;
    }
}

static int x11_handle_session_status(x11_app* app, librdp_status status)
{
    if (status == LIBRDP_STATUS_OK)
        return 1;
    fprintf(stderr, "error=%s\n", librdp_status_string(status));
    if (app)
        app->running = 0;
    return 0;
}

static int x11_dispatch_session_ready(x11_app* app, struct pollfd* session_fds, size_t session_count)
{
    librdp_status status = LIBRDP_STATUS_OK;
    unsigned int i = 0;

    if (!app || !app->session || !app->running || !session_fds || session_count == 0)
        return 1;
    status = librdp_session_notify_poll(app->session, session_fds, session_count);
    if (!x11_handle_session_status(app, status))
        return 0;
    for (i = 0; app->running && i < X11_MAX_NETWORK_PUMP; i++)
    {
        uint64_t before = app->event_serial;
        size_t count = 0;

        status = librdp_session_dispatch_pending(app->session);
        if (!x11_handle_session_status(app, status))
            return 0;
        if (!app->dirty && app->event_serial == before)
            break;
        if (librdp_session_get_pollfds(app->session,
                                       session_fds,
                                       X11_MAX_SESSION_POLL_FDS,
                                       &count) != LIBRDP_STATUS_OK ||
            count == 0)
            break;
        if (poll(session_fds, (nfds_t)count, 0) <= 0)
            break;
        session_count = count;
        status = librdp_session_notify_poll(app->session, session_fds, session_count);
        if (!x11_handle_session_status(app, status))
            return 0;
    }
    return 1;
}

static int x11_wait_for_events(x11_app* app)
{
    struct pollfd poll_fds[1u + X11_MAX_SESSION_POLL_FDS];
    struct pollfd* session_fds = &poll_fds[1];
    size_t session_count = 0;
    int timeout_ms = -1;
    int rc = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!app || !app->display || !app->session || !app->running)
        return 0;

    memset(poll_fds, 0, sizeof(poll_fds));
    poll_fds[0].fd = ConnectionNumber(app->display);
    poll_fds[0].events = POLLIN;

    status = librdp_session_get_pollfds(app->session, session_fds, X11_MAX_SESSION_POLL_FDS, &session_count);
    if (!x11_handle_session_status(app, status))
        return 0;
    status = librdp_session_get_next_timeout(app->session, &timeout_ms);
    if (!x11_handle_session_status(app, status))
        return 0;
    if (XPending(app->display) > 0)
        timeout_ms = 0;
    else if (app->audio_input_active && (timeout_ms < 0 || timeout_ms > 10))
        timeout_ms = 10;

    do
    {
        rc = poll(poll_fds, (nfds_t)(1u + session_count), timeout_ms);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0)
    {
        fprintf(stderr, "error=poll errno=%d\n", errno);
        app->running = 0;
        return 0;
    }
    if ((poll_fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
    {
        app->running = 0;
        return 0;
    }
    if (rc == 0)
        return x11_handle_session_status(app, librdp_session_dispatch_pending(app->session));
    if (session_count > 0 && x11_dispatch_session_ready(app, session_fds, session_count) == 0)
        return 0;
    return 1;
}

/*
 * Own the viewer process lifetime from argument parsing through session
 * shutdown. X11 resources, optional host backends, and the session are
 * released in reverse setup order so failed partial startup remains
 * deterministic.
 */
int x11_viewer_run(int argc, char** argv)
{
    librdp_settings* settings = NULL;
    x11_cli_options cli_options;
    x11_app app;
    XEvent event;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t width = 0;
    uint32_t height = 0;
    Bool detectable = False;

    (void)setlocale(LC_CTYPE, "");
    (void)XSetLocaleModifiers("");
    memset(&cli_options, 0, sizeof(cli_options));
    memset(&app, 0, sizeof(app));
    settings = librdp_settings_new();
    if (!settings)
        return 1;

    if (!x11_cli_configure(settings, &cli_options, argc, argv))
    {
        fprintf(stderr, x11_cli_usage(), argv[0]);
        x11_cli_options_free(&cli_options);
        x11_clipboard_free(&app);
        librdp_settings_free(settings);
        return 2;
    }
    app.clipboard_file_path = cli_options.clipboard_file_path;
    cli_options.clipboard_file_path = NULL;

    width = librdp_settings_width(settings);
    height = librdp_settings_height(settings);
    app.display = XOpenDisplay(NULL);
    if (!app.display)
    {
        fprintf(stderr, "error=x11_open_display\n");
        x11_cli_options_free(&cli_options);
        librdp_settings_free(settings);
        return 1;
    }

    XSetErrorHandler(x11_window_handle_error);
    app.screen = DefaultScreen(app.display);
    app.xkb = XkbGetKeyboard(app.display, XkbNamesMask, XkbUseCoreKbd);
    app.window = XCreateSimpleWindow(app.display,
                                     RootWindow(app.display, app.screen),
                                     0,
                                     0,
                                     width,
                                     height,
                                     0,
                                     BlackPixel(app.display, app.screen),
                                     BlackPixel(app.display, app.screen));
    app.gc = XCreateGC(app.display, app.window, 0, NULL);
    app.window_width = width;
    app.window_height = height;
    set_window_identity(&app);
    x11_input_allow_xwayland_keyboard_grab(&app);
    x11_clipboard_init(&app);
    (void)x11_render_init(&app);
    (void)x11_display_init(&app);
    app.wm_delete = XInternAtom(app.display, "WM_DELETE_WINDOW", False);
    (void)XSetWMProtocols(app.display, app.window, &app.wm_delete, 1);
    app.im = XOpenIM(app.display, NULL, NULL, NULL);
    if (app.im)
        app.ic = XCreateIC(app.im,
                           XNInputStyle,
                           XIMPreeditNothing | XIMStatusNothing,
                           XNClientWindow,
                           app.window,
                           XNFocusWindow,
                           app.window,
                           NULL);
    if (XkbSetDetectableAutoRepeat(app.display, True, &detectable))
        app.detectable_auto_repeat = detectable ? 1 : 0;
    XSelectInput(app.display,
                 app.window,
                 ExposureMask | KeyPressMask | KeyReleaseMask | ButtonPressMask | ButtonReleaseMask |
                     PointerMotionMask | StructureNotifyMask | FocusChangeMask | EnterWindowMask | LeaveWindowMask);
    XMapWindow(app.display, app.window);

    x11_cli_trace_settings(settings);
    if (!x11_audio_configure(&app, settings))
    {
        fprintf(stderr, "error=pipewire_audio_config\n");
        x11_cli_options_free(&cli_options);
        librdp_settings_free(settings);
        x11_audio_free(&app);
        if (app.xkb)
            XkbFreeKeyboard(app.xkb, 0, True);
        if (app.ic)
            XDestroyIC(app.ic);
        if (app.im)
            XCloseIM(app.im);
        x11_clipboard_free(&app);
        x11_render_shutdown(&app);
        x11_input_clear_cursor(&app);
        XFreeGC(app.display, app.gc);
        XDestroyWindow(app.display, app.window);
        XCloseDisplay(app.display);
        return 1;
    }
    if (!x11_device_backends_probe(settings))
    {
        fprintf(stderr, "error=device_backend_probe\n");
        x11_cli_options_free(&cli_options);
        librdp_settings_free(settings);
        x11_runtime_features_free(&app);
        x11_audio_free(&app);
        if (app.xkb)
            XkbFreeKeyboard(app.xkb, 0, True);
        if (app.ic)
            XDestroyIC(app.ic);
        if (app.im)
            XCloseIM(app.im);
        x11_clipboard_free(&app);
        x11_render_shutdown(&app);
        x11_input_clear_cursor(&app);
        XFreeGC(app.display, app.gc);
        XDestroyWindow(app.display, app.window);
        XCloseDisplay(app.display);
        return 1;
    }
    if (!x11_runtime_features_configure(&app, settings))
    {
        fprintf(stderr, "error=runtime_feature_config\n");
        x11_cli_options_free(&cli_options);
        librdp_settings_free(settings);
        x11_runtime_features_free(&app);
        x11_audio_free(&app);
        if (app.xkb)
            XkbFreeKeyboard(app.xkb, 0, True);
        if (app.ic)
            XDestroyIC(app.ic);
        if (app.im)
            XCloseIM(app.im);
        x11_clipboard_free(&app);
        x11_render_shutdown(&app);
        x11_input_clear_cursor(&app);
        XFreeGC(app.display, app.gc);
        XDestroyWindow(app.display, app.window);
        XCloseDisplay(app.display);
        return 1;
    }
    app.session = librdp_session_new(settings);
    librdp_settings_free(settings);
    if (!app.session)
    {
        x11_cli_options_free(&cli_options);
        x11_runtime_features_free(&app);
        x11_audio_free(&app);
        if (app.xkb)
            XkbFreeKeyboard(app.xkb, 0, True);
        if (app.ic)
            XDestroyIC(app.ic);
        if (app.im)
            XCloseIM(app.im);
        x11_clipboard_free(&app);
        x11_render_shutdown(&app);
        x11_input_clear_cursor(&app);
        XFreeGC(app.display, app.gc);
        XDestroyWindow(app.display, app.window);
        XCloseDisplay(app.display);
        return 1;
    }

    librdp_session_set_event_callback(app.session, app_event, &app);
    if (app.clipboard_file_path)
    {
        librdp_clipboard_file file;

        memset(&file, 0, sizeof(file));
        file.path = app.clipboard_file_path;
        status = librdp_session_clipboard_set_files(app.session, &file, 1);
        if (status != LIBRDP_STATUS_OK)
        {
            fprintf(stderr, "error=clipboard_file status=%s\n", librdp_status_string(status));
            librdp_session_free(app.session);
            x11_cli_options_free(&cli_options);
            x11_runtime_features_free(&app);
            x11_audio_free(&app);
            if (app.xkb)
                XkbFreeKeyboard(app.xkb, 0, True);
            if (app.ic)
                XDestroyIC(app.ic);
            if (app.im)
                XCloseIM(app.im);
            x11_clipboard_free(&app);
            x11_render_shutdown(&app);
            x11_input_clear_cursor(&app);
            XFreeGC(app.display, app.gc);
            XDestroyWindow(app.display, app.window);
            XCloseDisplay(app.display);
            return 1;
        }
        x11_trace_event(X11_TRACE_CLIENT, "x11.clipboard.local_file", "configured=1");
    }
    status = librdp_session_connect(app.session);
    if (status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr, "error=%s\n", librdp_status_string(status));
        librdp_session_free(app.session);
        x11_cli_options_free(&cli_options);
        x11_runtime_features_free(&app);
        x11_audio_free(&app);
        if (app.xkb)
            XkbFreeKeyboard(app.xkb, 0, True);
        if (app.ic)
            XDestroyIC(app.ic);
        if (app.im)
            XCloseIM(app.im);
        x11_clipboard_free(&app);
        x11_render_shutdown(&app);
        x11_input_clear_cursor(&app);
        XFreeGC(app.display, app.gc);
        XDestroyWindow(app.display, app.window);
        XCloseDisplay(app.display);
        return 1;
    }

    app.running = 1;
    app.dirty = 1;
    while (app.running)
    {
        unsigned int events_processed = 0;

        if (x11_window_is_invalid())
        {
            app.running = 0;
            break;
        }
        while (XPending(app.display) > 0 && events_processed < X11_MAX_EVENTS_PER_TICK)
        {
            XNextEvent(app.display, &event);
            events_processed++;
            if ((event.type == KeyPress || event.type == KeyRelease) && XFilterEvent(&event, app.window))
                continue;
            if (event.type == Expose)
            {
                x11_trace_event(X11_TRACE_CLIENT,
                                "x11.window.expose",
                                "x=%d y=%d width=%d height=%d count=%d dirty_before=%u",
                                event.xexpose.x,
                                event.xexpose.y,
                                event.xexpose.width,
                                event.xexpose.height,
                                event.xexpose.count,
                                app.dirty ? 1u : 0u);
                if (event.xexpose.width > 0 && event.xexpose.height > 0)
                    (void)librdp_session_refresh(app.session,
                                                 event.xexpose.x < 0 ? 0u : (uint32_t)event.xexpose.x,
                                                 event.xexpose.y < 0 ? 0u : (uint32_t)event.xexpose.y,
                                                 (uint32_t)event.xexpose.width,
                                                 (uint32_t)event.xexpose.height);
                app.dirty = 1;
            }
            else if (event.type == ClientMessage && (Atom)event.xclient.data.l[0] == app.wm_delete)
                app.running = 0;
            else if (app.xfixes_available && event.type == app.xfixes_event_base + XFixesSelectionNotify)
                x11_clipboard_handle_owner_notify(&app, &event);
            else if (x11_display_handle_event(&app, &event))
                continue;
            else if (event.type == SelectionNotify)
                x11_clipboard_handle_selection_notify(&app, &event.xselection);
            else if (event.type == SelectionRequest)
                x11_clipboard_handle_selection_request(&app, &event.xselectionrequest);
            else if (event.type == SelectionClear && event.xselectionclear.selection == app.clipboard_selection)
                x11_clipboard_handle_selection_clear(&app, &event.xselectionclear);
            else if (event.type == DestroyNotify)
            {
                x11_window_mark_invalid(&app);
            }
            else if (event.type == KeyPress)
                x11_input_handle_key_press(&app, &event.xkey);
            else if (event.type == KeyRelease)
                x11_input_handle_key_release(&app, &event.xkey);
            else if (event.type == ButtonPress)
                x11_input_handle_button(&app, &event.xbutton, LIBRDP_MOUSE_PRESSED);
            else if (event.type == ButtonRelease)
                x11_input_handle_button(&app, &event.xbutton, LIBRDP_MOUSE_RELEASED);
            else if (event.type == MotionNotify)
                x11_input_handle_motion(&app, &event.xmotion);
            else if (event.type == MappingNotify)
            {
                XRefreshKeyboardMapping(&event.xmapping);
                if (app.xkb)
                    XkbFreeKeyboard(app.xkb, 0, True);
                app.xkb = XkbGetKeyboard(app.display, XkbNamesMask, XkbUseCoreKbd);
            }
            else if (event.type == EnterNotify)
            {
                app.pointer_inside = 1;
                x11_input_restore_cursor_after_local_mouse(&app);
                x11_input_maybe_grab_keyboard(&app, event.xcrossing.time);
            }
            else if (event.type == LeaveNotify)
            {
                app.pointer_inside = 0;
                x11_input_ungrab_keyboard(&app, event.xcrossing.time, 0);
            }
            else if (event.type == FocusIn)
            {
                app.focused = 1;
                if (app.ic)
                    XSetICFocus(app.ic);
                x11_input_apply_cursor(&app);
                x11_input_restore_cursor_after_local_mouse(&app);
                x11_input_maybe_grab_keyboard(&app, CurrentTime);
            }
            else if (event.type == FocusOut)
            {
                if (event.xfocus.mode != NotifyGrab && event.xfocus.mode != NotifyUngrab)
                {
                    app.focused = 0;
                    if (app.ic)
                        XUnsetICFocus(app.ic);
                    x11_input_release_all_remote_keys(&app);
                    x11_input_ungrab_keyboard(&app, CurrentTime, 1);
                }
            }
            else if (event.type == ConfigureNotify && event.xconfigure.width > 0 && event.xconfigure.height > 0)
            {
                uint32_t configured_width = (uint32_t)event.xconfigure.width;
                uint32_t configured_height = (uint32_t)event.xconfigure.height;

                if (configured_width == app.window_width && configured_height == app.window_height)
                    continue;
                x11_trace_event(X11_TRACE_CLIENT,
                                "x11.window.configure",
                                "old_width=%u old_height=%u new_width=%u new_height=%u",
                                app.window_width,
                                app.window_height,
                                configured_width,
                                configured_height);
                app.window_width = configured_width;
                app.window_height = configured_height;
                (void)x11_display_update_or_resize(&app, "configure");
                XClearWindow(app.display, app.window);
                x11_trace_event(X11_TRACE_CLIENT,
                                "x11.window.clear",
                                "reason=configure width=%u height=%u",
                                configured_width,
                                configured_height);
                app.dirty = 1;
                x11_input_apply_cursor(&app);
            }
            if (x11_window_is_invalid())
            {
                app.running = 0;
                break;
            }
        }

        if (!app.running)
            break;
        x11_audio_input_pump(&app);
        if (app.running && app.dirty)
            x11_render_draw_surface(&app);
        if (app.running && !x11_wait_for_events(&app))
            break;
    }

    x11_input_release_all_remote_keys(&app);
    x11_input_ungrab_keyboard(&app, CurrentTime, 1);
    (void)librdp_session_disconnect(app.session);
    librdp_session_free(app.session);
    x11_cli_options_free(&cli_options);
    x11_runtime_features_free(&app);
    x11_audio_free(&app);
    if (app.xkb)
        XkbFreeKeyboard(app.xkb, 0, True);
    if (app.ic)
        XDestroyIC(app.ic);
    if (app.im)
        XCloseIM(app.im);
    x11_clipboard_free(&app);
    x11_render_shutdown(&app);
    x11_input_clear_cursor(&app);
    XFreeGC(app.display, app.gc);
    if (!x11_window_is_invalid())
        XDestroyWindow(app.display, app.window);
    XCloseDisplay(app.display);
    return 0;
}
