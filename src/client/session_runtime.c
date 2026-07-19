/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared runtime support for client sessions.
 * Invariants: owner-thread checks, event routing, lifecycle state, trace sinks,
 * wakeups, and metrics remain centralized so protocol domains cannot diverge.
 * Ownership: the session owns callback registrations, trace sink resources,
 * wakeup descriptors, and the last-error object.
 * Threading: only cancel/wakeup paths are callable across threads; mutable
 * runtime state requires the session owner thread.
 * Trust boundary: runtime events expose only validated payload extents and never
 * copy unredacted sensitive trace data into public messages.
 */

#include "client/session_internal.h"
#include "client/error_internal.h"
#include "common/trace.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int rdp_session_multitransport_runtime_supported(void)
{
    return RDP_SESSION_MULTITRANSPORT_RUNTIME_SUPPORTED != 0;
}

static librdp_status rdp_session_owner_violation(librdp_session* session, const char* phase)
{
    rdp_session_set_last_error(session,
                               LIBRDP_STATUS_STATE,
                               0,
                               LIBRDP_ERROR_COMPONENT_CLIENT,
                               phase ? phase : "client.owner_thread",
                               "session API called from non-owner thread");
    return LIBRDP_STATUS_STATE;
}

librdp_status rdp_session_bind_owner(librdp_session* session, const char* phase)
{
    pthread_t self;
    int violation = 0;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    self = pthread_self();
    (void)pthread_mutex_lock(&session->owner_mutex);
    if (!session->owner_thread_valid)
    {
        session->owner_thread = self;
        session->owner_thread_valid = 1;
    }
    else if (!pthread_equal(session->owner_thread, self))
        violation = 1;
    (void)pthread_mutex_unlock(&session->owner_mutex);

    if (violation)
        return rdp_session_owner_violation(session, phase);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_session_require_owner(librdp_session* session, const char* phase)
{
    pthread_t self;
    int violation = 0;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    self = pthread_self();
    (void)pthread_mutex_lock(&session->owner_mutex);
    if (session->owner_thread_valid && !pthread_equal(session->owner_thread, self))
        violation = 1;
    (void)pthread_mutex_unlock(&session->owner_mutex);

    if (violation)
        return rdp_session_owner_violation(session, phase);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_session_require_owner_const(const librdp_session* session, const char* phase)
{
    return rdp_session_require_owner((librdp_session*)session, phase);
}

/*
 * Event envelopes expose only the active legacy union member and its exact
 * byte extent. This table is the compatibility boundary for older consumers
 * that intentionally read less than the current payload size.
 */
static void rdp_session_event_payload(const librdp_event* event, const void** payload, size_t* payload_size)
{
    if (!payload || !payload_size)
        return;
    *payload = NULL;
    *payload_size = 0;
    if (!event)
        return;
    switch (event->type)
    {
        case LIBRDP_EVENT_STATE_CHANGED:
            *payload = &event->data.state;
            *payload_size = sizeof(event->data.state);
            break;
        case LIBRDP_EVENT_SURFACE_INVALIDATED:
            *payload = &event->data.surface;
            *payload_size = sizeof(event->data.surface);
            break;
        case LIBRDP_EVENT_KEY_SENT:
            *payload = &event->data.key;
            *payload_size = sizeof(event->data.key);
            break;
        case LIBRDP_EVENT_MOUSE_SENT:
            *payload = &event->data.mouse;
            *payload_size = sizeof(event->data.mouse);
            break;
        case LIBRDP_EVENT_ERROR:
            *payload = &event->data.error;
            *payload_size = sizeof(event->data.error);
            break;
        case LIBRDP_EVENT_POINTER:
            *payload = &event->data.pointer;
            *payload_size = sizeof(event->data.pointer);
            break;
        case LIBRDP_EVENT_CLIPBOARD_FORMATS:
            *payload = &event->data.clipboard_formats;
            *payload_size = sizeof(event->data.clipboard_formats);
            break;
        case LIBRDP_EVENT_CLIPBOARD_DATA:
            *payload = &event->data.clipboard_data;
            *payload_size = sizeof(event->data.clipboard_data);
            break;
        case LIBRDP_EVENT_CLIPBOARD_REQUEST:
            *payload = &event->data.clipboard_request;
            *payload_size = sizeof(event->data.clipboard_request);
            break;
        case LIBRDP_EVENT_CLIPBOARD_FILE_CONTENTS:
            *payload = &event->data.clipboard_file_contents;
            *payload_size = sizeof(event->data.clipboard_file_contents);
            break;
        case LIBRDP_EVENT_CHANNEL_OPEN:
            *payload = &event->data.channel_open;
            *payload_size = sizeof(event->data.channel_open);
            break;
        case LIBRDP_EVENT_CHANNEL_DATA:
            *payload = &event->data.channel_data;
            *payload_size = sizeof(event->data.channel_data);
            break;
        case LIBRDP_EVENT_CHANNEL_CLOSE:
            *payload = &event->data.channel_close;
            *payload_size = sizeof(event->data.channel_close);
            break;
        case LIBRDP_EVENT_AUDIO_OUTPUT_FORMATS:
            *payload = &event->data.audio_output_formats;
            *payload_size = sizeof(event->data.audio_output_formats);
            break;
        case LIBRDP_EVENT_AUDIO_OUTPUT_DATA:
            *payload = &event->data.audio_output_data;
            *payload_size = sizeof(event->data.audio_output_data);
            break;
        case LIBRDP_EVENT_AUDIO_INPUT_FORMATS:
            *payload = &event->data.audio_input_formats;
            *payload_size = sizeof(event->data.audio_input_formats);
            break;
        case LIBRDP_EVENT_AUDIO_INPUT_OPEN:
            *payload = &event->data.audio_input_open;
            *payload_size = sizeof(event->data.audio_input_open);
            break;
        case LIBRDP_EVENT_VIDEO_CAPTURE_OPEN:
            *payload = &event->data.video_capture_open;
            *payload_size = sizeof(event->data.video_capture_open);
            break;
        case LIBRDP_EVENT_VIDEO_CAPTURE_SAMPLE_REQUEST:
            *payload = &event->data.video_capture_sample_request;
            *payload_size = sizeof(event->data.video_capture_sample_request);
            break;
        case LIBRDP_EVENT_VIDEO_CAPTURE_CLOSE:
            *payload = &event->data.video_capture_close;
            *payload_size = sizeof(event->data.video_capture_close);
            break;
        case LIBRDP_EVENT_ECHO_RESULT:
            *payload = &event->data.echo_result;
            *payload_size = sizeof(event->data.echo_result);
            break;
        case LIBRDP_EVENT_NONE:
        case LIBRDP_EVENT_DISCONNECTED:
        default:
            break;
    }
}

static int rdp_session_has_domain_callback(const librdp_session* session)
{
    return session && (session->graphics_callback || session->pointer_callback || session->channel_callback ||
                       session->clipboard_callback || session->audio_callback || session->video_callback);
}

/*
 * Domain callbacks are a routing layer over the versioned event envelope. The
 * payload contract stays centralized in rdp_session_event_payload(), so domain
 * registration cannot drift from the aggregate callback ABI.
 */
static void rdp_session_emit_domain(librdp_session* session, const librdp_event_envelope* envelope)
{
    librdp_domain_event_callback callback = NULL;
    void* user_data = NULL;

    if (!session || !envelope)
        return;

    switch (envelope->type)
    {
        case LIBRDP_EVENT_SURFACE_INVALIDATED:
            callback = session->graphics_callback;
            user_data = session->graphics_callback_data;
            break;
        case LIBRDP_EVENT_POINTER:
            callback = session->pointer_callback;
            user_data = session->pointer_callback_data;
            break;
        case LIBRDP_EVENT_CHANNEL_OPEN:
        case LIBRDP_EVENT_CHANNEL_DATA:
        case LIBRDP_EVENT_CHANNEL_CLOSE:
        case LIBRDP_EVENT_ECHO_RESULT:
            callback = session->channel_callback;
            user_data = session->channel_callback_data;
            break;
        case LIBRDP_EVENT_CLIPBOARD_FORMATS:
        case LIBRDP_EVENT_CLIPBOARD_DATA:
        case LIBRDP_EVENT_CLIPBOARD_REQUEST:
        case LIBRDP_EVENT_CLIPBOARD_FILE_CONTENTS:
            callback = session->clipboard_callback;
            user_data = session->clipboard_callback_data;
            break;
        case LIBRDP_EVENT_AUDIO_OUTPUT_FORMATS:
        case LIBRDP_EVENT_AUDIO_OUTPUT_DATA:
        case LIBRDP_EVENT_AUDIO_OUTPUT_CLOSE:
        case LIBRDP_EVENT_AUDIO_INPUT_FORMATS:
        case LIBRDP_EVENT_AUDIO_INPUT_OPEN:
            callback = session->audio_callback;
            user_data = session->audio_callback_data;
            break;
        case LIBRDP_EVENT_VIDEO_CAPTURE_OPEN:
        case LIBRDP_EVENT_VIDEO_CAPTURE_SAMPLE_REQUEST:
        case LIBRDP_EVENT_VIDEO_CAPTURE_CLOSE:
            callback = session->video_callback;
            user_data = session->video_callback_data;
            break;
        default:
            break;
    }

    if (callback)
        callback(session, envelope, user_data);
}

void rdp_session_emit(librdp_session* session, const librdp_event* event)
{
    if (!session || !event)
        return;
    if (session->envelope_callback || rdp_session_has_domain_callback(session))
    {
        librdp_event_envelope envelope;

        (void)librdp_event_envelope_init(&envelope);
        envelope.type = event->type;
        envelope.legacy_event = event;
        rdp_session_event_payload(event, &envelope.payload, &envelope.payload_size);
        if (session->envelope_callback)
            session->envelope_callback(session, &envelope, session->envelope_callback_data);
        rdp_session_emit_domain(session, &envelope);
    }
    if (session->callback)
        session->callback(session, event, session->callback_data);
}

void rdp_session_emit_graphics_update(librdp_session* session,
                                             librdp_graphics_update_type type,
                                             uint32_t surface_id,
                                             uint32_t frame_id,
                                             const librdp_rect* rect,
                                             librdp_pixel_format format,
                                             const uint8_t* pixels,
                                             size_t stride)
{
    librdp_graphics_update update;

    if (!session || !session->graphics_update_callback)
        return;
    memset(&update, 0, sizeof(update));
    update.version = LIBRDP_GRAPHICS_UPDATE_VERSION;
    update.size = (uint32_t)sizeof(update);
    update.type = type;
    update.surface_id = surface_id;
    update.frame_id = frame_id;
    update.format = format;
    if (rect)
        update.rect = *rect;
    update.desktop_width = librdp_surface_width(session->surface);
    update.desktop_height = librdp_surface_height(session->surface);
    update.pixels = pixels;
    update.stride = stride;
    session->graphics_update_callback(session, &update, session->graphics_update_callback_data);
}

void rdp_session_emit_graphics_pixel_rect(librdp_session* session,
                                                 uint32_t x,
                                                 uint32_t y,
                                                 uint32_t width,
                                                 uint32_t height)
{
    librdp_rect rect;
    const uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;

    if (!session || width == 0 || height == 0)
        return;

    surface_width = librdp_surface_width(session->surface);
    surface_height = librdp_surface_height(session->surface);
    stride = librdp_surface_stride(session->surface);
    if (x <= surface_width && y <= surface_height && width <= surface_width - x &&
        height <= surface_height - y && stride >= (size_t)surface_width * 4u)
    {
        const uint8_t* surface_pixels = librdp_surface_pixels(session->surface);

        if (surface_pixels)
            pixels = surface_pixels + ((size_t)y * stride) + ((size_t)x * 4u);
    }

    rect.x = x;
    rect.y = y;
    rect.width = width;
    rect.height = height;
    rdp_session_emit_graphics_update(session,
                                     LIBRDP_GRAPHICS_UPDATE_PIXEL_RECT,
                                     0,
                                     session->graphics_current_frame_id,
                                     &rect,
                                     LIBRDP_PIXEL_FORMAT_BGRA32,
                                     pixels,
                                     pixels ? stride : 0u);
}

void rdp_session_emit_graphics_frame(librdp_session* session,
                                            librdp_graphics_update_type type,
                                            uint32_t frame_id)
{
    librdp_rect rect;

    if (!session)
        return;
    memset(&rect, 0, sizeof(rect));
    rect.width = librdp_surface_width(session->surface);
    rect.height = librdp_surface_height(session->surface);
    rdp_session_emit_graphics_update(session, type, 0, frame_id, &rect, LIBRDP_PIXEL_FORMAT_BGRA32, NULL, 0);
}

void rdp_session_metric_add(uint64_t* counter, uint64_t value)
{
    if (!counter)
        return;
    if (*counter > UINT64_MAX - value)
        *counter = UINT64_MAX;
    else
        *counter += value;
}

librdp_status rdp_session_limit_rejected(librdp_session* session)
{
    if (session)
        rdp_session_metric_add(&session->metrics.limits_rejected, 1);
    return LIBRDP_STATUS_LIMIT_EXCEEDED;
}

static int rdp_session_set_fd_nonblocking_close_on_exec(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    int fd_flags = 0;

    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
        return -1;
    fd_flags = fcntl(fd, F_GETFD, 0);
    if (fd_flags < 0 || fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC) != 0)
        return -1;
    return 0;
}

void rdp_session_wakeup_close(librdp_session* session)
{
    if (!session)
        return;
    if (session->wakeup_pipe[0] >= 0)
        close(session->wakeup_pipe[0]);
    if (session->wakeup_pipe[1] >= 0)
        close(session->wakeup_pipe[1]);
    session->wakeup_pipe[0] = -1;
    session->wakeup_pipe[1] = -1;
}

librdp_status rdp_session_wakeup_init(librdp_session* session)
{
    int fds[2] = {-1, -1};

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (pipe(fds) != 0)
        return LIBRDP_STATUS_IO_ERROR;
    if (rdp_session_set_fd_nonblocking_close_on_exec(fds[0]) != 0 ||
        rdp_session_set_fd_nonblocking_close_on_exec(fds[1]) != 0)
    {
        close(fds[0]);
        close(fds[1]);
        return LIBRDP_STATUS_IO_ERROR;
    }
    session->wakeup_pipe[0] = fds[0];
    session->wakeup_pipe[1] = fds[1];
    return LIBRDP_STATUS_OK;
}

void rdp_session_wakeup_drain(librdp_session* session)
{
    uint8_t buffer[64];

    if (!session || session->wakeup_pipe[0] < 0)
        return;
    for (;;)
    {
        ssize_t rc = read(session->wakeup_pipe[0], buffer, sizeof(buffer));

        if (rc > 0)
            continue;
        if (rc < 0 && errno == EINTR)
            continue;
        if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        return;
    }
}

librdp_status rdp_session_wakeup_signal(librdp_session* session)
{
    const uint8_t byte = 1;

    if (!session || session->wakeup_pipe[1] < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (;;)
    {
        ssize_t rc = write(session->wakeup_pipe[1], &byte, sizeof(byte));

        if (rc == (ssize_t)sizeof(byte))
            return LIBRDP_STATUS_OK;
        if (rc < 0 && errno == EINTR)
            continue;
        if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return LIBRDP_STATUS_OK;
        return LIBRDP_STATUS_IO_ERROR;
    }
}

/*
 * Publish, interrupt, and close the transport through one synchronization
 * boundary. Cancellation only shuts down the socket; protocol and backend
 * ownership remain with the session owner thread.
 */
void rdp_session_transport_cancel_arm(librdp_session* session)
{
    if (!session)
        return;
    (void)pthread_mutex_lock(&session->transport_cancel_mutex);
    session->transport_cancel_ready = session->transport.fd >= 0 ? 1u : 0u;
    (void)pthread_mutex_unlock(&session->transport_cancel_mutex);
}

void rdp_session_transport_cancel_interrupt(librdp_session* session)
{
    if (!session)
        return;
    (void)pthread_mutex_lock(&session->transport_cancel_mutex);
    if (session->transport_cancel_ready && session->transport.fd >= 0)
        (void)shutdown(session->transport.fd, SHUT_RDWR);
    (void)pthread_mutex_unlock(&session->transport_cancel_mutex);
}

void rdp_session_transport_close(librdp_session* session)
{
    if (!session)
        return;
    (void)pthread_mutex_lock(&session->transport_cancel_mutex);
    session->transport_cancel_ready = 0;
    rdp_transport_close(&session->transport);
    (void)pthread_mutex_unlock(&session->transport_cancel_mutex);
}

static char* rdp_session_trace_strdup(const char* text)
{
    size_t len = 0;
    char* out = NULL;

    if (!text)
        return NULL;
    len = strlen(text);
    out = (char*)malloc(len + 1u);
    if (!out)
        return NULL;
    memcpy(out, text, len + 1u);
    return out;
}

void rdp_session_trace_policy_clear(librdp_session* session)
{
    if (!session)
        return;
    if (session->trace_file)
        fclose(session->trace_file);
    session->trace_file = NULL;
    free(session->trace_file_path);
    free(session->trace_session_id);
    free(session->trace_connection_id);
    free(session->trace_id);
    session->trace_file_path = NULL;
    session->trace_session_id = NULL;
    session->trace_connection_id = NULL;
    session->trace_id = NULL;
    memset(&session->trace_policy, 0, sizeof(session->trace_policy));
    session->trace_policy_configured = 0;
    session->trace_sequence = 0;
    session->trace_first_ns = 0;
}

static rdp_trace_level rdp_session_trace_level_internal(librdp_trace_level level)
{
    switch (level)
    {
        case LIBRDP_TRACE_LEVEL_ERROR:
            return RDP_TRACE_LEVEL_ERROR;
        case LIBRDP_TRACE_LEVEL_WARN:
            return RDP_TRACE_LEVEL_WARN;
        case LIBRDP_TRACE_LEVEL_INFO:
            return RDP_TRACE_LEVEL_INFO;
        case LIBRDP_TRACE_LEVEL_DEBUG:
            return RDP_TRACE_LEVEL_DEBUG;
        case LIBRDP_TRACE_LEVEL_TRACE:
            return RDP_TRACE_LEVEL_TRACE;
        default:
            return RDP_TRACE_LEVEL_INFO;
    }
}

static int rdp_session_trace_policy_valid(const librdp_trace_policy* policy)
{
    const uint32_t known_categories = LIBRDP_TRACE_CATEGORY_ALL;

    if (!policy || policy->version != LIBRDP_TRACE_POLICY_VERSION ||
        policy->size < sizeof(librdp_trace_policy) ||
        (policy->categories & ~known_categories) != 0 ||
        policy->level > LIBRDP_TRACE_LEVEL_TRACE)
        return 0;
    if (policy->sink == LIBRDP_TRACE_SINK_DISABLED)
        return 1;
    if (policy->categories == 0)
        return 0;
    if (policy->sink == LIBRDP_TRACE_SINK_CALLBACK)
        return policy->callback != NULL;
    if (policy->sink == LIBRDP_TRACE_SINK_FILE)
        return policy->file_path && policy->file_path[0] != '\0';
    return policy->sink == LIBRDP_TRACE_SINK_STDERR;
}

void rdp_session_trace_scope_begin(librdp_session* session, rdp_trace_session_scope* scope)
{
    if (!session || !scope || !session->trace_policy_configured)
        return;
    memset(scope, 0, sizeof(*scope));
    scope->session = session;
    scope->categories = session->trace_policy.categories;
    scope->level = rdp_session_trace_level_internal(session->trace_policy.level);
    scope->hex_limit = session->trace_policy.hex_bytes;
    scope->unsafe_hexdump = session->trace_policy.unsafe_payloads != 0;
    scope->sink = session->trace_policy.sink;
    scope->file = session->trace_file;
    scope->callback = session->trace_policy.callback;
    scope->callback_user_data = session->trace_policy.callback_user_data;
    scope->session_id = session->trace_session_id;
    scope->connection_id = session->trace_connection_id;
    scope->trace_id = session->trace_id;
    scope->sequence = &session->trace_sequence;
    scope->first_ns = &session->trace_first_ns;
    rdp_trace_push_session(scope);
}

void rdp_session_trace_scope_end(const librdp_session* session)
{
    if (session && session->trace_policy_configured)
        rdp_trace_pop_session();
}

void rdp_session_set_state(librdp_session* session, librdp_session_state state)
{
    librdp_event event;
    librdp_session_state old_state = LIBRDP_SESSION_IDLE;

    if (!session || session->state == state)
        return;

    old_state = session->state;
    session->state = state;

    event.type = LIBRDP_EVENT_STATE_CHANGED;
    event.data.state.old_state = (int)old_state;
    event.data.state.new_state = (int)state;
    rdp_session_emit(session, &event);
}

void rdp_session_set_lifecycle(librdp_session* session, librdp_session_lifecycle lifecycle)
{
    if (!session || session->lifecycle == lifecycle)
        return;

    session->lifecycle = lifecycle;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.lifecycle",
                          "phase=%u",
                          (unsigned)lifecycle);
}

static librdp_error_component rdp_session_error_component_for_status(librdp_status status)
{
    switch (status)
    {
        case LIBRDP_STATUS_IO_ERROR:
        case LIBRDP_STATUS_TIMEOUT:
        case LIBRDP_STATUS_CLOSED:
        case LIBRDP_STATUS_AGAIN:
            return LIBRDP_ERROR_COMPONENT_TRANSPORT;
        case LIBRDP_STATUS_CANCELLED:
            return LIBRDP_ERROR_COMPONENT_CLIENT;
        case LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED:
        case LIBRDP_STATUS_TLS_HOSTNAME_MISMATCH:
        case LIBRDP_STATUS_TLS_HANDSHAKE_FAILED:
            return LIBRDP_ERROR_COMPONENT_TLS;
        case LIBRDP_STATUS_PROTOCOL_ERROR:
        case LIBRDP_STATUS_UNSUPPORTED:
        case LIBRDP_STATUS_SECURITY_DOWNGRADE:
            return LIBRDP_ERROR_COMPONENT_PROTOCOL;
        default:
            return LIBRDP_ERROR_COMPONENT_CLIENT;
    }
}

void rdp_session_set_last_error(librdp_session* session,
                                       librdp_status status,
                                       int os_errno,
                                       librdp_error_component component,
                                       const char* phase,
                                       const char* message)
{
    if (!session || status == LIBRDP_STATUS_OK)
        return;
    rdp_session_metric_add(&session->metrics.errors, 1);
    rdp_error_set(&session->last_error,
                  status,
                  os_errno,
                  component,
                  phase,
                  message,
                  session->trace_id);
}

static void rdp_session_set_last_error_if_empty(librdp_session* session,
                                                librdp_status status,
                                                const char* phase,
                                                const char* message)
{
    if (!session || rdp_error_has_error(&session->last_error))
        return;
    rdp_session_set_last_error(session,
                               status,
                               0,
                               rdp_session_error_component_for_status(status),
                               phase,
                               message);
}

librdp_status rdp_session_fail(librdp_session* session, librdp_status status)
{
    librdp_event event;

    rdp_session_set_last_error_if_empty(session, status, "client.dispatch", "session operation failed");
    rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_FAILED);
    rdp_session_set_state(session, LIBRDP_SESSION_FAILED);
    event.type = LIBRDP_EVENT_ERROR;
    event.data.error.status = status;
    rdp_session_emit(session, &event);
    return status;
}

librdp_status rdp_session_finish_cancel(librdp_session* session)
{
    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    atomic_store_explicit(&session->cancel_requested, 0u, memory_order_release);
    rdp_session_wakeup_drain(session);
    rdp_session_set_last_error(session,
                               LIBRDP_STATUS_CANCELLED,
                               0,
                               LIBRDP_ERROR_COMPONENT_CLIENT,
                               "client.cancel",
                               "session cancelled by application");
    rdp_trace_event(RDP_TRACE_CLIENT, "client.cancel.done", "state=%d", (int)session->state);
    (void)rdp_session_disconnect_inner(session);
    rdp_session_set_state(session, LIBRDP_SESSION_CANCELLED);
    return LIBRDP_STATUS_CANCELLED;
}



void librdp_session_set_event_callback(librdp_session* session, librdp_event_callback callback, void* user_data)
{
    if (!session)
        return;
    if (rdp_session_require_owner(session, "client.callback.event") != LIBRDP_STATUS_OK)
        return;
    session->callback = callback;
    session->callback_data = user_data;
}

librdp_status librdp_event_envelope_init(librdp_event_envelope* envelope)
{
    if (!envelope)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(envelope, 0, sizeof(*envelope));
    envelope->version = LIBRDP_EVENT_ENVELOPE_VERSION;
    envelope->size = (uint32_t)sizeof(*envelope);
    return LIBRDP_STATUS_OK;
}

void librdp_session_set_event_envelope_callback(librdp_session* session,
                                                librdp_event_envelope_callback callback,
                                                void* user_data)
{
    if (!session)
        return;
    if (rdp_session_require_owner(session, "client.callback.envelope") != LIBRDP_STATUS_OK)
        return;
    session->envelope_callback = callback;
    session->envelope_callback_data = user_data;
}

void librdp_session_set_graphics_callback(librdp_session* session,
                                          librdp_domain_event_callback callback,
                                          void* user_data)
{
    if (!session)
        return;
    if (rdp_session_require_owner(session, "client.callback.graphics") != LIBRDP_STATUS_OK)
        return;
    session->graphics_callback = callback;
    session->graphics_callback_data = user_data;
}

void librdp_session_set_pointer_callback(librdp_session* session,
                                         librdp_domain_event_callback callback,
                                         void* user_data)
{
    if (!session)
        return;
    if (rdp_session_require_owner(session, "client.callback.pointer") != LIBRDP_STATUS_OK)
        return;
    session->pointer_callback = callback;
    session->pointer_callback_data = user_data;
}

void librdp_session_set_channel_callback(librdp_session* session,
                                         librdp_domain_event_callback callback,
                                         void* user_data)
{
    if (!session)
        return;
    if (rdp_session_require_owner(session, "client.callback.channel") != LIBRDP_STATUS_OK)
        return;
    session->channel_callback = callback;
    session->channel_callback_data = user_data;
}

void librdp_session_set_clipboard_callback(librdp_session* session,
                                           librdp_domain_event_callback callback,
                                           void* user_data)
{
    if (!session)
        return;
    if (rdp_session_require_owner(session, "client.callback.clipboard") != LIBRDP_STATUS_OK)
        return;
    session->clipboard_callback = callback;
    session->clipboard_callback_data = user_data;
}

void librdp_session_set_audio_callback(librdp_session* session,
                                       librdp_domain_event_callback callback,
                                       void* user_data)
{
    if (!session)
        return;
    if (rdp_session_require_owner(session, "client.callback.audio") != LIBRDP_STATUS_OK)
        return;
    session->audio_callback = callback;
    session->audio_callback_data = user_data;
}

void librdp_session_set_video_callback(librdp_session* session,
                                       librdp_domain_event_callback callback,
                                       void* user_data)
{
    if (!session)
        return;
    if (rdp_session_require_owner(session, "client.callback.video") != LIBRDP_STATUS_OK)
        return;
    session->video_callback = callback;
    session->video_callback_data = user_data;
}

void librdp_session_set_graphics_update_callback(librdp_session* session,
                                                 librdp_graphics_update_callback callback,
                                                 void* user_data)
{
    if (!session)
        return;
    if (rdp_session_require_owner(session, "client.callback.graphics_update") != LIBRDP_STATUS_OK)
        return;
    session->graphics_update_callback = callback;
    session->graphics_update_callback_data = user_data;
}

librdp_status librdp_trace_policy_init(librdp_trace_policy* policy)
{
    if (!policy)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(policy, 0, sizeof(*policy));
    policy->version = LIBRDP_TRACE_POLICY_VERSION;
    policy->size = (uint32_t)sizeof(*policy);
    policy->categories = LIBRDP_TRACE_CATEGORY_ALL;
    policy->level = LIBRDP_TRACE_LEVEL_INFO;
    policy->sink = LIBRDP_TRACE_SINK_STDERR;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_metrics_init(librdp_metrics* metrics)
{
    if (!metrics)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(metrics, 0, sizeof(*metrics));
    metrics->version = LIBRDP_METRICS_VERSION;
    metrics->size = (uint32_t)sizeof(*metrics);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_echo_stats_init(librdp_echo_stats* stats)
{
    if (!stats)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(stats, 0, sizeof(*stats));
    stats->version = LIBRDP_ECHO_STATS_VERSION;
    stats->size = (uint32_t)sizeof(*stats);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_reconnect_policy_init(librdp_reconnect_policy* policy)
{
    if (!policy)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(policy, 0, sizeof(*policy));
    policy->version = LIBRDP_RECONNECT_POLICY_VERSION;
    policy->size = (uint32_t)sizeof(*policy);
    policy->max_attempts = 1;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_set_trace_policy(librdp_session* session, const librdp_trace_policy* policy)
{
    librdp_trace_policy copy;
    char* file_path = NULL;
    char* session_id = NULL;
    char* connection_id = NULL;
    char* trace_id = NULL;
    FILE* file = NULL;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_session_require_owner(session, "client.trace.policy") != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_STATE;
    if (!policy)
    {
        rdp_session_trace_policy_clear(session);
        return LIBRDP_STATUS_OK;
    }
    if (!rdp_session_trace_policy_valid(policy))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&copy, 0, sizeof(copy));
    copy = *policy;
    if (policy->file_path)
    {
        file_path = rdp_session_trace_strdup(policy->file_path);
        if (!file_path)
            return LIBRDP_STATUS_NO_MEMORY;
    }
    if (policy->session_id)
    {
        session_id = rdp_session_trace_strdup(policy->session_id);
        if (!session_id)
            goto no_memory;
    }
    if (policy->connection_id)
    {
        connection_id = rdp_session_trace_strdup(policy->connection_id);
        if (!connection_id)
            goto no_memory;
    }
    if (policy->trace_id)
    {
        trace_id = rdp_session_trace_strdup(policy->trace_id);
        if (!trace_id)
            goto no_memory;
    }
    if (policy->sink == LIBRDP_TRACE_SINK_FILE)
    {
        file = fopen(file_path, "a");
        if (!file)
        {
            free(file_path);
            free(session_id);
            free(connection_id);
            free(trace_id);
            return LIBRDP_STATUS_IO_ERROR;
        }
    }

    rdp_session_trace_policy_clear(session);
    copy.file_path = file_path;
    copy.session_id = session_id;
    copy.connection_id = connection_id;
    copy.trace_id = trace_id;
    session->trace_policy = copy;
    session->trace_file_path = file_path;
    session->trace_session_id = session_id;
    session->trace_connection_id = connection_id;
    session->trace_id = trace_id;
    session->trace_file = file;
    session->trace_policy_configured = 1;
    return LIBRDP_STATUS_OK;

no_memory:
    free(file_path);
    free(session_id);
    free(connection_id);
    free(trace_id);
    return LIBRDP_STATUS_NO_MEMORY;
}



librdp_status librdp_session_get_metrics(const librdp_session* session, librdp_metrics* metrics)
{
    if (!session || !metrics || metrics->version != LIBRDP_METRICS_VERSION ||
        metrics->size < sizeof(*metrics))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_session_require_owner_const(session, "client.metrics.get.owner") != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_STATE;
    *metrics = session->metrics;
    metrics->version = LIBRDP_METRICS_VERSION;
    metrics->size = (uint32_t)sizeof(*metrics);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_reset_metrics(librdp_session* session)
{
    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    {
        librdp_status status = rdp_session_require_owner(session, "client.metrics.reset.owner");
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return librdp_metrics_init(&session->metrics);
}

void librdp_session_clear_last_error(librdp_session* session)
{
    if (session && rdp_session_require_owner(session, "client.error.clear.owner") == LIBRDP_STATUS_OK)
        rdp_error_clear(&session->last_error);
}
