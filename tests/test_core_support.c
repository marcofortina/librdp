/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared client core fixtures.
 * Coverage: handshake construction, callbacks, and loopback I/O.
 * Bug classes: malformed input, invalid state, bounds, ownership, and cleanup.
 * Determinism: fixtures use synthetic data and local transports only.
 */

#include "test_core_support.h"
#include "test_core_suites.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

const uint8_t core_test_server_random[32] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};

const librdp_feature core_test_all_features[] = {
    LIBRDP_FEATURE_AUDIO_OUTPUT,
    LIBRDP_FEATURE_AUDIO_INPUT,
    LIBRDP_FEATURE_VIDEO,
    LIBRDP_FEATURE_CAMERA,
    LIBRDP_FEATURE_SMARTCARD,
    LIBRDP_FEATURE_USB,
    LIBRDP_FEATURE_PNP,
    LIBRDP_FEATURE_WEBAUTHN,
    LIBRDP_FEATURE_RAIL,
    LIBRDP_FEATURE_CR2,
    LIBRDP_FEATURE_ECHO,
    LIBRDP_FEATURE_TELEMETRY,
    LIBRDP_FEATURE_MULTITRANSPORT,
    LIBRDP_FEATURE_DESKTOP_COMPOSITION,
    LIBRDP_FEATURE_DISPLAY_CONTROL,
    LIBRDP_FEATURE_UDP_TRANSPORT,
    LIBRDP_FEATURE_UDP2_TRANSPORT,
    LIBRDP_FEATURE_GEOMETRY_TRACKING,
    LIBRDP_FEATURE_MULTIPARTY
};
const uint8_t core_test_server_certificate[] = {
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

const size_t core_test_server_certificate_len = sizeof(core_test_server_certificate);

void on_event(librdp_session* session, const librdp_event* event, void* user_data)
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
        case LIBRDP_EVENT_ECHO_RESULT:
            counter->echo_result++;
            counter->echo_ok = event->data.echo_result.ok;
            counter->echo_timed_out = event->data.echo_result.timed_out;
            counter->echo_sequence = event->data.echo_result.sequence;
            counter->echo_rtt_us = event->data.echo_result.rtt_us;
            break;
        case LIBRDP_EVENT_DISCONNECTED:
            counter->disconnected++;
            break;
        default:
            break;
    }
}

void on_event_envelope(librdp_session* session, const librdp_event_envelope* envelope, void* user_data)
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

void on_domain_event(librdp_session* session, const librdp_event_envelope* envelope, void* user_data)
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
        case LIBRDP_EVENT_ECHO_RESULT:
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

void on_graphics_update(librdp_session* session, const librdp_graphics_update* update, void* user_data)
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
void* cancel_thread_main(void* user_data)
{
    cancel_thread_capture* capture = (cancel_thread_capture*)user_data;
    struct timespec ts;

    ts.tv_sec = 0;
    ts.tv_nsec = (long)capture->delay_ms * 1000000L;
    (void)nanosleep(&ts, NULL);
    capture->status = librdp_session_cancel(capture->session);
    return NULL;
}

void* owner_thread_main(void* user_data)
{
    owner_thread_capture* capture = (owner_thread_capture*)user_data;

    if (!capture)
        return NULL;
    capture->status = librdp_session_refresh(capture->session, 0, 0, 1, 1);
    return NULL;
}

void on_trace(librdp_session* session, const librdp_trace_record* record, void* user_data)
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

void on_secure_string_cleanse(const void* data, size_t length, void* user_data)
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

void test_sleep_ms(uint32_t timeout_ms)
{
    struct timespec requested;
    struct timespec remaining;

    requested.tv_sec = (time_t)(timeout_ms / 1000u);
    requested.tv_nsec = (long)((timeout_ms % 1000u) * 1000000u);
    while (nanosleep(&requested, &remaining) != 0 && errno == EINTR)
        requested = remaining;
}

void test_core_fill_secret(char* output, size_t output_len, uint32_t seed)
{
    static const char alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

    if (!output || output_len == 0)
        return;
    for (size_t i = 0; i + 1u < output_len; i++)
        output[i] = alphabet[(seed + (uint32_t)(i * 17u)) % (sizeof(alphabet) - 1u)];
    output[output_len - 1u] = '\0';
}

librdp_status on_credentials_provider(librdp_credentials* credentials, void* user_data)
{
    credentials_provider_capture* capture = (credentials_provider_capture*)user_data;
    char local_domain[32];
    char local_password[32];
    char local_username[32];
    const char* domain = NULL;
    const char* password = NULL;
    const char* username = NULL;

    memset(local_domain, 0, sizeof(local_domain));
    memset(local_password, 0, sizeof(local_password));
    memset(local_username, 0, sizeof(local_username));
    if (capture)
    {
        capture->calls++;
        if (capture->fail)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        if (capture->password[0] == '\0')
            test_core_fill_secret(capture->password, sizeof(capture->password), 11u);
        if (capture->username[0] == '\0')
            test_core_fill_secret(capture->username, sizeof(capture->username), 31u);
        if (capture->domain[0] == '\0')
            test_core_fill_secret(capture->domain, sizeof(capture->domain), 47u);
        username = capture->username;
        password = capture->password;
        domain = capture->domain;
    }
    else
    {
        test_core_fill_secret(local_username, sizeof(local_username), 19u);
        test_core_fill_secret(local_password, sizeof(local_password), 23u);
        test_core_fill_secret(local_domain, sizeof(local_domain), 29u);
        username = local_username;
        password = local_password;
        domain = local_domain;
    }
    return librdp_credentials_set(credentials,
                                  username,
                                  password,
                                  domain);
}

librdp_tls_certificate_decision core_tls_certificate_callback(const librdp_tls_certificate_info* certificate,
                                                                    void* user_data)
{
    (void)certificate;
    (void)user_data;
    return LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT;
}

int capture_stderr(void (*fn)(void), char* out, size_t out_len)
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

int read_exact_fd(int fd, void* data, size_t length)
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
static int build_server_connect_response(rdp_buffer* out,
                                         int encrypted,
                                         int extra_static_channel,
                                         int multitransport)
{
    static const uint8_t oid[] = {5, 0, 20, 124, 0, 1};
    static const uint8_t key[] = {'M', 'c', 'D', 'n'};
    rdp_buffer core;
    rdp_buffer security;
    rdp_buffer network;
    rdp_buffer multitransport_block;
    rdp_buffer blocks;
    rdp_buffer gcc;
    rdp_buffer content;
    rdp_buffer mcs;
    size_t total = 0;
    int ok = 0;

    rdp_buffer_init(&core);
    rdp_buffer_init(&security);
    rdp_buffer_init(&network);
    rdp_buffer_init(&multitransport_block);
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
            ok = rdp_buffer_append_u32_le(&security, (uint32_t)sizeof(core_test_server_random)) == LIBRDP_STATUS_OK &&
                 rdp_buffer_append_u32_le(&security,
                                          (uint32_t)sizeof(core_test_server_certificate)) == LIBRDP_STATUS_OK &&
                 rdp_buffer_append(&security,
                                   core_test_server_random,
                                   sizeof(core_test_server_random)) == LIBRDP_STATUS_OK &&
                 rdp_buffer_append(&security,
                                   core_test_server_certificate,
                                   sizeof(core_test_server_certificate)) == LIBRDP_STATUS_OK;
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
    if (ok && multitransport)
    {
        ok = rdp_buffer_append_u32_le(&multitransport_block,
                                      RDP_GCC_MULTITRANSPORT_UDP_FECR |
                                          RDP_GCC_MULTITRANSPORT_UDP_FECL |
                                          RDP_GCC_MULTITRANSPORT_UDP_PREFERRED |
                                          RDP_GCC_MULTITRANSPORT_SOFTSYNC_TCP_TO_UDP) ==
                 LIBRDP_STATUS_OK &&
             append_gcc_block(&blocks, RDP_GCC_SC_MULTITRANSPORT, &multitransport_block);
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
    rdp_buffer_free(&multitransport_block);
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

static int validate_new_license_request(const uint8_t* input, size_t input_len)
{
    const uint8_t* payload = NULL;
    size_t payload_len = 0;
    rdp_license_client_new_license_request request;

    if (!read_security_payload(input, input_len, &payload, &payload_len))
        return 0;
    if (rdp_license_parse_client_new_license_request(payload, payload_len, &request) != LIBRDP_STATUS_OK)
        return 0;
    return request.preferred_key_exchange_alg == RDP_LICENSE_KEY_EXCHANGE_RSA &&
           request.platform_id == RDP_LICENSE_PLATFORM_ID_CLIENT &&
           request.encrypted_pre_master.length == 128u &&
           request.user_name.length > 1u &&
           request.machine_name.length > 1u;
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

    ok = rdp_buffer_append_u16_le(&caps, 1u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 0u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps,
                                  RDP_CAPABILITY_TYPE_GENERAL) ==
             LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 24u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 1u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 3u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 0x0200u) ==
             LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 0u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 0u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 0x0404u) ==
             LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 0u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 0u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 0u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&caps, 1u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&caps, 1u) == LIBRDP_STATUS_OK;
    total = 6u + 4u + 2u + 2u + sizeof(source) + caps.length + 4u;
    if (ok)
        ok = rdp_buffer_append_u16_le(&slow,
                                      (uint16_t)total) ==
                 LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(
                 &slow,
                 (uint16_t)(RDP_SLOWPATH_PDU_VERSION |
                            RDP_SLOWPATH_PDU_TYPE_DEMAND_ACTIVE)) ==
                 LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, 1002u) ==
                 LIBRDP_STATUS_OK &&
             rdp_buffer_append_u32_le(&slow, 0x10203040u) ==
                 LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow,
                                      (uint16_t)sizeof(source)) ==
                 LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow,
                                      (uint16_t)caps.length) ==
                 LIBRDP_STATUS_OK &&
             rdp_buffer_append(&slow,
                               source,
                               sizeof(source)) ==
                 LIBRDP_STATUS_OK &&
             rdp_buffer_append(&slow,
                               caps.data,
                               caps.length) ==
                 LIBRDP_STATUS_OK &&
             rdp_buffer_append_u32_le(&slow, 0u) ==
                 LIBRDP_STATUS_OK;
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

/*
 * Wrap one licensing message in the global-channel MCS and TPKT framing used
 * by the loopback handshake fixture.
 */
static int build_license_transport_packet(rdp_buffer* out, const rdp_buffer* license)
{
    rdp_buffer mcs;
    size_t total = 0;
    int ok = 0;

    if (!out || !license)
        return 0;
    rdp_buffer_init(&mcs);
    ok = rdp_buffer_append_u8(&mcs, 0x68) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_be(&mcs, 3) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_be(&mcs, (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u8(&mcs, 0x70) == LIBRDP_STATUS_OK &&
         append_per_length(&mcs, license->length) &&
         rdp_buffer_append(&mcs, license->data, license->length) == LIBRDP_STATUS_OK;
    total = mcs.length + 7u;
    if (ok)
        ok = total <= UINT16_MAX &&
             rdp_buffer_append_u8(out, 0x03) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x00) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(out, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x02) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0xf0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x80) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(out, mcs.data, mcs.length) == LIBRDP_STATUS_OK;
    rdp_buffer_free(&mcs);
    return ok;
}

static int build_license_new_packet(rdp_buffer* out)
{
    static const uint8_t license_data[] = {0x11, 0x22, 0x33, 0x44};
    static const uint8_t license_mac[16] = {0};
    rdp_buffer license;
    int ok = 0;

    rdp_buffer_init(&license);
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
        ok = build_license_transport_packet(out, &license);

    rdp_buffer_free(&license);
    return ok;
}

static int build_license_valid_client_alert_packet(rdp_buffer* out)
{
    rdp_buffer license;
    int ok = 0;

    rdp_buffer_init(&license);
    ok = rdp_license_write_error_alert(&license,
                                       RDP_LICENSE_VERSION_3,
                                       RDP_LICENSE_ERROR_STATUS_VALID_CLIENT,
                                       RDP_LICENSE_STATE_TRANSITION_NO_TRANSITION,
                                       RDP_LICENSE_BLOB_ERROR,
                                       NULL,
                                       0) == LIBRDP_STATUS_OK;
    if (ok)
        ok = build_license_transport_packet(out, &license);

    rdp_buffer_free(&license);
    return ok;
}

static int build_license_error_alert_packet(rdp_buffer* out)
{
    rdp_buffer license;
    int ok = 0;

    rdp_buffer_init(&license);
    ok = rdp_license_write_error_alert(&license,
                                       RDP_LICENSE_VERSION_3,
                                       RDP_LICENSE_ERROR_INVALID_CLIENT,
                                       RDP_LICENSE_STATE_TRANSITION_TOTAL_ABORT,
                                       RDP_LICENSE_BLOB_ERROR,
                                       NULL,
                                       0) == LIBRDP_STATUS_OK;
    if (ok)
        ok = build_license_transport_packet(out, &license);
    rdp_buffer_free(&license);
    return ok;
}

static int build_license_request_packet_ex(rdp_buffer* out,
                                           const void* certificate,
                                           size_t certificate_len)
{
    static const uint8_t company[] = {'L', 0, 'a', 0, 'b', 0, 0, 0};
    static const uint8_t product[] = {'T', 0, 'e', 0, 's', 0, 't', 0, 0, 0};
    static const uint8_t key_exchange[] = {1, 0, 0, 0};
    static const uint8_t scope[] = {'s', 'c', 'o', 'p', 'e', 0};
    rdp_buffer payload;
    rdp_buffer license;
    int ok = 0;

    if (!out || !certificate || certificate_len == 0 || certificate_len > UINT16_MAX)
        return 0;
    rdp_buffer_init(&payload);
    rdp_buffer_init(&license);
    ok = rdp_buffer_append(&payload, core_test_server_random, sizeof(core_test_server_random)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&payload, 0x00060002u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&payload, (uint32_t)sizeof(company)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&payload, company, sizeof(company)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&payload, (uint32_t)sizeof(product)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&payload, product, sizeof(product)) == LIBRDP_STATUS_OK &&
         rdp_license_write_binary_blob(&payload,
                                       RDP_LICENSE_BLOB_KEY_EXCHANGE_ALG,
                                       key_exchange,
                                       (uint16_t)sizeof(key_exchange)) == LIBRDP_STATUS_OK &&
         rdp_license_write_binary_blob(&payload,
                                       RDP_LICENSE_BLOB_CERTIFICATE,
                                       certificate,
                                       (uint16_t)certificate_len) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK &&
         rdp_license_write_binary_blob(&payload,
                                       RDP_LICENSE_BLOB_SCOPE,
                                       scope,
                                       (uint16_t)sizeof(scope)) == LIBRDP_STATUS_OK &&
         rdp_license_write_preamble(&license,
                                    RDP_LICENSE_MESSAGE_REQUEST,
                                    RDP_LICENSE_VERSION_3,
                                    (uint16_t)payload.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&license, payload.data, payload.length) == LIBRDP_STATUS_OK;
    if (ok)
        ok = build_license_transport_packet(out, &license);

    rdp_buffer_free(&license);
    rdp_buffer_free(&payload);
    return ok;
}

static int build_license_request_packet(rdp_buffer* out)
{
    return build_license_request_packet_ex(out,
                                           core_test_server_certificate,
                                           sizeof(core_test_server_certificate));
}

/*
 * Derive the server view of the transient licensing keys from the client's
 * RSA-encrypted premaster secret. This keeps the challenge fixture on the same
 * cryptographic path as an actual licensing exchange.
 */
static int initialize_license_server_crypto(const uint8_t* input,
                                            size_t input_len,
                                            EVP_PKEY* private_key,
                                            rdp_license_crypto_context* context)
{
    const uint8_t* payload = NULL;
    size_t payload_len = 0;
    rdp_license_client_new_license_request request;
    uint8_t premaster[RDP_LICENSE_PREMASTER_SECRET_LEN];
    librdp_status status = LIBRDP_STATUS_PROTOCOL_ERROR;

    if (!input || !private_key || !context)
        return 0;
    memset(&request, 0, sizeof(request));
    memset(premaster, 0, sizeof(premaster));
    if (read_security_payload(input, input_len, &payload, &payload_len) &&
        rdp_license_parse_client_new_license_request(payload, payload_len, &request) ==
            LIBRDP_STATUS_OK &&
        request.preferred_key_exchange_alg == RDP_LICENSE_KEY_EXCHANGE_RSA &&
        request.platform_id == RDP_LICENSE_PLATFORM_ID_CLIENT)
    {
        status = rdp_security_decrypt_private_secret(private_key,
                                                     request.encrypted_pre_master.data,
                                                     request.encrypted_pre_master.length,
                                                     premaster,
                                                     sizeof(premaster));
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_license_keys(premaster,
                                               request.client_random,
                                               core_test_server_random,
                                               context->mac_salt_key,
                                               context->encryption_key);
        if (status == LIBRDP_STATUS_OK)
        {
            memcpy(context->premaster_secret, premaster, sizeof(premaster));
            memcpy(context->client_random,
                   request.client_random,
                   sizeof(context->client_random));
            memcpy(context->server_random,
                   core_test_server_random,
                   sizeof(context->server_random));
            context->ready = 1;
        }
    }
    OPENSSL_cleanse(premaster, sizeof(premaster));
    if (status != LIBRDP_STATUS_OK)
        rdp_license_crypto_context_clear(context);
    return status == LIBRDP_STATUS_OK;
}

static int build_license_platform_challenge_packet(rdp_buffer* out,
                                                   const rdp_license_crypto_context* context,
                                                   const void* challenge,
                                                   size_t challenge_len)
{
    rdp_buffer encrypted;
    rdp_buffer payload;
    rdp_buffer license;
    uint8_t mac[RDP_LICENSE_MAC_LEN];
    int ok = 0;

    if (!out || !context || !context->ready || (!challenge && challenge_len > 0) ||
        challenge_len > UINT16_MAX)
        return 0;
    rdp_buffer_init(&encrypted);
    rdp_buffer_init(&payload);
    rdp_buffer_init(&license);
    memset(mac, 0, sizeof(mac));
    ok = rdp_security_license_crypt(context->encryption_key,
                                    challenge,
                                    challenge_len,
                                    &encrypted) == LIBRDP_STATUS_OK &&
         rdp_security_license_mac(context->mac_salt_key,
                                  challenge,
                                  challenge_len,
                                  mac) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK &&
         rdp_license_write_binary_blob(&payload,
                                       RDP_LICENSE_BLOB_ENCRYPTED_DATA,
                                       encrypted.data,
                                       (uint16_t)encrypted.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&payload, mac, sizeof(mac)) == LIBRDP_STATUS_OK &&
         rdp_license_write_preamble(&license,
                                    RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE,
                                    RDP_LICENSE_VERSION_3,
                                    (uint16_t)payload.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&license, payload.data, payload.length) == LIBRDP_STATUS_OK &&
         build_license_transport_packet(out, &license);
    OPENSSL_cleanse(mac, sizeof(mac));
    if (encrypted.data)
        OPENSSL_cleanse(encrypted.data, encrypted.length);
    rdp_buffer_free(&license);
    rdp_buffer_free(&payload);
    rdp_buffer_free(&encrypted);
    return ok;
}

/*
 * Validate the complete platform response, including both decrypted blobs and
 * the MAC over the response data plus the client hardware identifier.
 */
static int validate_license_platform_challenge_response(
    const uint8_t* input,
    size_t input_len,
    const rdp_license_crypto_context* context,
    const void* expected_challenge,
    size_t expected_challenge_len)
{
    const uint8_t* payload = NULL;
    size_t payload_len = 0;
    rdp_license_platform_challenge_response response;
    rdp_license_platform_challenge_response_data response_data;
    rdp_buffer plain_response;
    rdp_buffer plain_hardware;
    rdp_buffer mac_input;
    uint8_t expected_mac[RDP_LICENSE_MAC_LEN];
    int ok = 0;

    if (!input || !context || !context->ready ||
        (!expected_challenge && expected_challenge_len > 0))
        return 0;
    memset(&response, 0, sizeof(response));
    memset(&response_data, 0, sizeof(response_data));
    memset(expected_mac, 0, sizeof(expected_mac));
    rdp_buffer_init(&plain_response);
    rdp_buffer_init(&plain_hardware);
    rdp_buffer_init(&mac_input);
    ok = read_security_payload(input, input_len, &payload, &payload_len) &&
         rdp_license_parse_platform_challenge_response(payload,
                                                       payload_len,
                                                       &response) == LIBRDP_STATUS_OK &&
         rdp_security_license_crypt(context->encryption_key,
                                    response.encrypted_response.data,
                                    response.encrypted_response.length,
                                    &plain_response) == LIBRDP_STATUS_OK &&
         rdp_security_license_crypt(context->encryption_key,
                                    response.encrypted_hardware_id.data,
                                    response.encrypted_hardware_id.length,
                                    &plain_hardware) == LIBRDP_STATUS_OK &&
         plain_hardware.length == RDP_LICENSE_HARDWARE_ID_LEN &&
         rdp_license_parse_platform_challenge_response_data(
             plain_response.data,
             plain_response.length,
             &response_data) == LIBRDP_STATUS_OK &&
         response_data.challenge_len == expected_challenge_len &&
         (expected_challenge_len == 0 ||
          memcmp(response_data.challenge,
                 expected_challenge,
                 expected_challenge_len) == 0) &&
         rdp_buffer_append(&mac_input,
                           plain_response.data,
                           plain_response.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&mac_input,
                           plain_hardware.data,
                           plain_hardware.length) == LIBRDP_STATUS_OK &&
         rdp_security_license_mac(context->mac_salt_key,
                                  mac_input.data,
                                  mac_input.length,
                                  expected_mac) == LIBRDP_STATUS_OK &&
         CRYPTO_memcmp(expected_mac, response.mac, sizeof(expected_mac)) == 0;
    OPENSSL_cleanse(expected_mac, sizeof(expected_mac));
    if (mac_input.data)
        OPENSSL_cleanse(mac_input.data, mac_input.length);
    if (plain_hardware.data)
        OPENSSL_cleanse(plain_hardware.data, plain_hardware.length);
    if (plain_response.data)
        OPENSSL_cleanse(plain_response.data, plain_response.length);
    rdp_buffer_free(&mac_input);
    rdp_buffer_free(&plain_hardware);
    rdp_buffer_free(&plain_response);
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
         rdp_buffer_append_u16_le(&payload, (uint16_t)sizeof(pixels)) == LIBRDP_STATUS_OK &&
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

/*
 * Fixture: emits a mixed GDI update with a secondary bitmap cache insert,
 * immediate-mode orders, and cache-backed MEMBLT/MEM3BLT. It catches cache
 * lifetime bugs, field-mask drift, bottom-up bitmap decode regressions, and
 * missing surface invalidations in the runtime renderer.
 */
static int build_gdi_orders_update_packet(rdp_buffer* out)
{
    static const uint8_t cache_bitmap_payload[] = {
        1u, 0u, 2u, 2u, 32u, 16u, 0u, 5u, 0u,
        0x10u, 0x20u, 0x30u, 0xffu,
        0x11u, 0x21u, 0x31u, 0xffu,
        0x12u, 0x22u, 0x32u, 0xffu,
        0x13u, 0x23u, 0x33u, 0xffu
    };
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
    static const uint8_t render_memblt[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_MEMBLT,
        0xffu, 0x01u,
        0x01u, 0x00u,
        0x20u, 0x00u,
        0x08u, 0x00u,
        0x02u, 0x00u,
        0x02u, 0x00u,
        0xccu,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x05u, 0x00u
    };
    static const uint8_t render_mem3blt[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_MEM3BLT,
        0xffu, 0xffu, 0x00u,
        0x01u, 0x00u,
        0x24u, 0x00u,
        0x08u, 0x00u,
        0x02u, 0x00u,
        0x02u, 0x00u,
        0xccu,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u,
        0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x05u, 0x00u
    };
    rdp_buffer orders;
    rdp_buffer cache_bitmap;
    rdp_buffer frame_marker;
    rdp_buffer frame_marker_payload;
    rdp_gdi_frame_marker_order marker;
    int ok = 0;

    rdp_buffer_init(&orders);
    rdp_buffer_init(&cache_bitmap);
    rdp_buffer_init(&frame_marker);
    rdp_buffer_init(&frame_marker_payload);
    memset(&marker, 0, sizeof(marker));

    ok = rdp_gdi_write_frame_marker_order(
             &frame_marker_payload,
             &marker) == LIBRDP_STATUS_OK &&
         rdp_gdi_write_altsec_order(
             &frame_marker,
             RDP_GDI_ALTSEC_FRAME_MARKER,
             frame_marker_payload.data,
             frame_marker_payload.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(
             &orders,
             frame_marker.data,
             frame_marker.length) == LIBRDP_STATUS_OK &&
         rdp_gdi_write_secondary_order(&cache_bitmap,
                                       0,
                                       RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED,
                                       cache_bitmap_payload,
                                       sizeof(cache_bitmap_payload)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, cache_bitmap.data, cache_bitmap.length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, render_opaque, sizeof(render_opaque)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, render_scrblt, sizeof(render_scrblt)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, render_patblt, sizeof(render_patblt)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, render_lineto, sizeof(render_lineto)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, render_memblt, sizeof(render_memblt)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, render_mem3blt, sizeof(render_mem3blt)) == LIBRDP_STATUS_OK;
    frame_marker.length = 0u;
    frame_marker_payload.length = 0u;
    marker.action = 1u;
    if (ok)
    {
        ok = rdp_gdi_write_frame_marker_order(
                 &frame_marker_payload,
                 &marker) == LIBRDP_STATUS_OK &&
             rdp_gdi_write_altsec_order(
                 &frame_marker,
                 RDP_GDI_ALTSEC_FRAME_MARKER,
                 frame_marker_payload.data,
                 frame_marker_payload.length) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(
                 &orders,
                 frame_marker.data,
                 frame_marker.length) == LIBRDP_STATUS_OK &&
             build_gdi_update_packet_from_orders(
                 out,
                 orders.data,
                 orders.length,
                 9u);
    }

    rdp_buffer_free(&frame_marker_payload);
    rdp_buffer_free(&frame_marker);
    rdp_buffer_free(&cache_bitmap);
    rdp_buffer_free(&orders);
    return ok;
}

/*
 * Builds a compact alternate-secondary stream covering GDI+ chunk correlation,
 * GDI+ cache storage, window state, and desktop-composition lifecycle handling.
 * The fixture catches regressions where recognized order families are parsed
 * but then silently dropped by the session runtime.
 */
static int build_gdi_altsec_runtime_update_packet(rdp_buffer* out)
{
    static const uint8_t gdiplus_draw_first[] = {
        (uint8_t)((RDP_GDI_ALTSEC_DRAW_GDIPLUS_FIRST << 2u) | RDP_GDI_TS_SECONDARY),
        0x04u,
        0x00u,
        0x0cu,
        0x00u,
        0x00u,
        0x00u,
        0x0cu,
        0x00u,
        0x00u,
        0x00u,
        0x01u,
        0x40u,
        0x00u,
        0x00u
    };
    static const uint8_t gdiplus_draw_next[] = {
        (uint8_t)((RDP_GDI_ALTSEC_DRAW_GDIPLUS_NEXT << 2u) | RDP_GDI_TS_SECONDARY),
        0x04u,
        0x00u,
        0x0cu,
        0x00u,
        0x00u,
        0x00u
    };
    static const uint8_t gdiplus_draw_end[] = {
        (uint8_t)((RDP_GDI_ALTSEC_DRAW_GDIPLUS_END << 2u) | RDP_GDI_TS_SECONDARY),
        0x04u,
        0x00u,
        0x0cu,
        0x00u,
        0x00u,
        0x00u,
        0x0cu,
        0x00u,
        0x00u,
        0x00u,
        0x00u,
        0x00u,
        0x00u,
        0x00u
    };
    static const uint8_t gdiplus_cache_first[] = {
        (uint8_t)((RDP_GDI_ALTSEC_DRAW_GDIPLUS_CACHE_FIRST << 2u) | RDP_GDI_TS_SECONDARY),
        0x01u,
        0x02u,
        0x00u,
        0x04u,
        0x00u,
        0x01u,
        0x00u,
        0x04u,
        0x00u,
        0x00u,
        0x00u,
        0xf0u
    };
    static const uint8_t gdiplus_cache_next[] = {
        (uint8_t)((RDP_GDI_ALTSEC_DRAW_GDIPLUS_CACHE_NEXT << 2u) | RDP_GDI_TS_SECONDARY),
        0x01u,
        0x02u,
        0x00u,
        0x04u,
        0x00u,
        0x01u,
        0x00u,
        0xf1u
    };
    static const uint8_t gdiplus_cache_end[] = {
        (uint8_t)((RDP_GDI_ALTSEC_DRAW_GDIPLUS_CACHE_END << 2u) | RDP_GDI_TS_SECONDARY),
        0x01u,
        0x02u,
        0x00u,
        0x04u,
        0x00u,
        0x02u,
        0x00u,
        0x04u,
        0x00u,
        0x00u,
        0x00u,
        0xf2u,
        0xf3u
    };
    static const uint8_t window_altsec[] = {
        (uint8_t)((RDP_GDI_ALTSEC_WINDOW << 2u) | RDP_GDI_TS_SECONDARY),
        0x08u,
        0x00u,
        0x00u,
        0x00u,
        0x00u,
        0x04u,
        0x12u
    };
    static const uint8_t compdesk_first[] = {
        (uint8_t)((RDP_GDI_ALTSEC_COMPDESK_FIRST << 2u) | RDP_GDI_TS_SECONDARY)
    };
    rdp_buffer orders;
    int ok = 0;

    rdp_buffer_init(&orders);
    ok = rdp_buffer_append(&orders, gdiplus_draw_first, sizeof(gdiplus_draw_first)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, gdiplus_draw_next, sizeof(gdiplus_draw_next)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, gdiplus_draw_end, sizeof(gdiplus_draw_end)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, gdiplus_cache_first, sizeof(gdiplus_cache_first)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, gdiplus_cache_next, sizeof(gdiplus_cache_next)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, gdiplus_cache_end, sizeof(gdiplus_cache_end)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, window_altsec, sizeof(window_altsec)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, compdesk_first, sizeof(compdesk_first)) == LIBRDP_STATUS_OK &&
         build_gdi_update_packet_from_orders(out, orders.data, orders.length, 8);

    rdp_buffer_free(&orders);
    return ok;
}

static int build_gdi_desktop_composition_update_packet(rdp_buffer* out)
{
    static const uint8_t window_altsec[] = {
        (uint8_t)((RDP_GDI_ALTSEC_WINDOW << 2u) | RDP_GDI_TS_SECONDARY),
        0x08u,
        0x00u,
        0x00u,
        0x00u,
        0x00u,
        0x04u,
        0x12u
    };
    static const uint8_t compdesk_first[] = {
        (uint8_t)((RDP_GDI_ALTSEC_COMPDESK_FIRST << 2u) | RDP_GDI_TS_SECONDARY)
    };
    rdp_buffer orders;
    int ok = 0;

    rdp_buffer_init(&orders);
    ok = rdp_buffer_append(&orders, window_altsec, sizeof(window_altsec)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, compdesk_first, sizeof(compdesk_first)) == LIBRDP_STATUS_OK &&
         build_gdi_update_packet_from_orders(out, orders.data, orders.length, 2);
    rdp_buffer_free(&orders);
    return ok;
}

/*
 * Build a deterministic RemoteApp window lifecycle. The same window id is
 * created again after deletion so session state cannot rely on monotonic ids.
 */
static int build_gdi_rail_runtime_update_packet(rdp_buffer* out)
{
    static const uint8_t window_create[] = {
        (uint8_t)((RDP_GDI_ALTSEC_WINDOW << 2u) | RDP_GDI_TS_SECONDARY),
        0x0bu, 0x00u,
        0x00u, 0x00u, 0x00u, 0x11u,
        0x40u, 0x30u, 0x20u, 0x10u
    };
    static const uint8_t window_update[] = {
        (uint8_t)((RDP_GDI_ALTSEC_WINDOW << 2u) | RDP_GDI_TS_SECONDARY),
        0x0bu, 0x00u,
        0x00u, 0x00u, 0x00u, 0x01u,
        0x40u, 0x30u, 0x20u, 0x10u
    };
    static const uint8_t window_cached_icon[] = {
        (uint8_t)((RDP_GDI_ALTSEC_WINDOW << 2u) | RDP_GDI_TS_SECONDARY),
        0x0eu, 0x00u,
        0x00u, 0x00u, 0x00u, 0x81u,
        0x40u, 0x30u, 0x20u, 0x10u,
        0x21u, 0x00u, 0x02u
    };
    static const uint8_t window_delete[] = {
        (uint8_t)((RDP_GDI_ALTSEC_WINDOW << 2u) | RDP_GDI_TS_SECONDARY),
        0x0bu, 0x00u,
        0x00u, 0x00u, 0x00u, 0x21u,
        0x40u, 0x30u, 0x20u, 0x10u
    };
    rdp_buffer orders;
    int ok = 0;

    rdp_buffer_init(&orders);
    ok = rdp_buffer_append(&orders, window_create, sizeof(window_create)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, window_update, sizeof(window_update)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, window_cached_icon, sizeof(window_cached_icon)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, window_delete, sizeof(window_delete)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&orders, window_create, sizeof(window_create)) == LIBRDP_STATUS_OK &&
         build_gdi_update_packet_from_orders(out, orders.data, orders.length, 5u);
    rdp_buffer_free(&orders);
    return ok;
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

static int build_multiparty_static_channel_packet(rdp_buffer* out)
{
    rdp_buffer payload;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = rdp_multiparty_write_filter_state(&payload, RDP_MULTIPARTY_FILTER_ENABLED) == LIBRDP_STATUS_OK &&
         build_static_channel_packet(out, &payload, 1006);
    rdp_buffer_free(&payload);
    return ok;
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
    return build_dynamic_channel_create_named_packet(out, "APPDVC");
}

static int build_dynamic_channel_create_webauthn_packet(rdp_buffer* out)
{
    return build_dynamic_channel_create_named_packet(out, "WebAuthN_Channel");
}

static int build_dynamic_channel_create_auth_redirection_packet(rdp_buffer* out)
{
    return build_dynamic_channel_create_named_packet(out, "Microsoft::Windows::RDS::AuthRedirection");
}

static int build_dynamic_channel_create_display_control_packet(rdp_buffer* out)
{
    return build_dynamic_channel_create_named_packet(out, "Microsoft::Windows::RDS::DisplayControl");
}

static int build_dynamic_channel_create_telemetry_packet(rdp_buffer* out)
{
    return build_dynamic_channel_create_named_packet(out, RDP_TELEMETRY_DVC_CHANNEL_NAME);
}

static int build_dynamic_channel_create_video_redirection_packet(rdp_buffer* out)
{
    return build_dynamic_channel_create_named_packet(out, RDP_VIDEO_REDIRECTION_CHANNEL_NAME);
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

static int build_dynamic_channel_data_payload_packet(rdp_buffer* out, const uint8_t* data, size_t data_len)
{
    rdp_buffer payload;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = rdp_dynamic_channel_write_data(&payload, 7, 1, data, data_len) == LIBRDP_STATUS_OK &&
         build_static_channel_packet(out, &payload, 1004);
    rdp_buffer_free(&payload);
    return ok;
}

static int build_dynamic_channel_telemetry_packet(rdp_buffer* out)
{
    rdp_buffer telemetry;
    int ok = 0;

    rdp_buffer_init(&telemetry);
    ok = rdp_telemetry_write_metrics(&telemetry, 10u, 20u, 30u, 40u) == LIBRDP_STATUS_OK &&
         build_dynamic_channel_data_payload_packet(out, telemetry.data, telemetry.length);
    rdp_buffer_free(&telemetry);
    return ok;
}

static const uint8_t geometry_presentation_id[16] = {
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
    0x18u, 0x19u, 0x1au, 0x1bu, 0x1cu, 0x1du, 0x1eu, 0x1fu
};

static int build_dynamic_channel_geometry_packet(
    rdp_buffer* out,
    uint32_t message_id,
    const rdp_video_redirection_geometry_info* info,
    const rdp_video_redirection_rect* rects,
    uint32_t rect_count)
{
    rdp_buffer geometry;
    rdp_buffer visible;
    rdp_buffer update;
    int ok = 0;
    uint32_t i = 0;

    if (!out || !info || (!rects && rect_count > 0))
        return 0;
    rdp_buffer_init(&geometry);
    rdp_buffer_init(&visible);
    rdp_buffer_init(&update);
    for (i = 0; i < rect_count; i++)
    {
        if (rdp_video_redirection_write_rect(&visible,
                                             rects[i].top,
                                             rects[i].left,
                                             rects[i].bottom,
                                             rects[i].right) != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&update);
            rdp_buffer_free(&visible);
            rdp_buffer_free(&geometry);
            return 0;
        }
    }
    ok = rdp_video_redirection_write_geometry_info(&geometry, info) == LIBRDP_STATUS_OK &&
         rdp_video_redirection_write_geometry_update(&update,
                                                     message_id,
                                                     geometry_presentation_id,
                                                     geometry.data,
                                                     (uint32_t)geometry.length,
                                                     visible.data,
                                                     (uint32_t)visible.length) == LIBRDP_STATUS_OK &&
         build_dynamic_channel_data_payload_packet(out, update.data, update.length);
    rdp_buffer_free(&update);
    rdp_buffer_free(&visible);
    rdp_buffer_free(&geometry);
    return ok;
}

static int write_dynamic_channel_geometry_packet(
    int fd,
    uint32_t message_id,
    const rdp_video_redirection_geometry_info* info,
    const rdp_video_redirection_rect* rects,
    uint32_t rect_count)
{
    rdp_buffer packet;
    int ok = 0;

    rdp_buffer_init(&packet);
    ok = build_dynamic_channel_geometry_packet(&packet,
                                               message_id,
                                               info,
                                               rects,
                                               rect_count) &&
         write_exact_fd(fd, packet.data, packet.length);
    rdp_buffer_free(&packet);
    return ok;
}

/*
 * Drive geometry state through create, clipped visible-region update, delete,
 * stale update, and identifier reuse while keeping the socket open until the
 * client has inspected and disconnected the session.
 */
static int run_geometry_tracking_runtime_server_scenario(int fd)
{
    static const rdp_video_redirection_rect initial_rects[] = {
        {90u, 90u, 210u, 310u},
        {300u, 400u, 340u, 450u}
    };
    static const rdp_video_redirection_rect update_rects[] = {
        {120u, 130u, 180u, 250u}
    };
    rdp_video_redirection_geometry_info info;

    memset(&info, 0, sizeof(info));
    info.video_window_id = 0x1020304050607080u;
    info.window_state = RDP_VIDEO_REDIRECTION_WINDOW_NEW |
                        RDP_VIDEO_REDIRECTION_WINDOW_VISRGN;
    info.width = 200u;
    info.height = 100u;
    info.left = 100u;
    info.top = 100u;
    if (!write_dynamic_channel_geometry_packet(fd,
                                               1u,
                                               &info,
                                               initial_rects,
                                               2u))
        return 0;

    info.window_state = RDP_VIDEO_REDIRECTION_WINDOW_VISRGN;
    if (!write_dynamic_channel_geometry_packet(fd,
                                               2u,
                                               &info,
                                               update_rects,
                                               1u))
        return 0;

    info.window_state = RDP_VIDEO_REDIRECTION_WINDOW_DELETED;
    info.width = 0u;
    info.height = 0u;
    if (!write_dynamic_channel_geometry_packet(fd, 3u, &info, NULL, 0u))
        return 0;

    info.window_state = RDP_VIDEO_REDIRECTION_WINDOW_VISRGN;
    info.width = 200u;
    info.height = 100u;
    if (!write_dynamic_channel_geometry_packet(fd,
                                               4u,
                                               &info,
                                               update_rects,
                                               1u))
        return 0;

    info.video_window_id = 0x8877665544332211u;
    info.window_state = RDP_VIDEO_REDIRECTION_WINDOW_NEW;
    info.left = 20u;
    info.top = 30u;
    info.width = 160u;
    info.height = 90u;
    return write_dynamic_channel_geometry_packet(fd, 5u, &info, NULL, 0u);
}

static int build_dynamic_channel_webauthn_request_packet(rdp_buffer* out, const char* rp_id)
{
    static const uint8_t transaction_id[RDP_WEBAUTHN_GUID_LENGTH] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t request[] = {RDP_WEBAUTHN_CMD_GET_ASSERTION};
    rdp_buffer webauthn;
    int ok = 0;

    if (!out || !rp_id)
        return 0;
    rdp_buffer_init(&webauthn);
    ok = rdp_webauthn_write_request(&webauthn,
                                    RDP_WEBAUTHN_COMMAND_WEB_AUTHN,
                                    0,
                                    request,
                                    sizeof(request),
                                    rp_id,
                                    transaction_id) == LIBRDP_STATUS_OK &&
         build_dynamic_channel_data_payload_packet(out, webauthn.data, webauthn.length);
    rdp_buffer_free(&webauthn);
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

static int build_dynamic_channel_display_control_caps_packet_ex(rdp_buffer* out,
                                                                uint32_t max_monitors,
                                                                uint32_t area_factor_a,
                                                                uint32_t area_factor_b)
{
    rdp_buffer caps;
    rdp_buffer payload;
    int ok = 0;

    rdp_buffer_init(&caps);
    rdp_buffer_init(&payload);
    ok = rdp_buffer_append_u32_le(&caps, RDP_DISPLAY_CONTROL_PDU_CAPS) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&caps, 20u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&caps, max_monitors) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&caps, area_factor_a) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&caps, area_factor_b) == LIBRDP_STATUS_OK &&
         rdp_dynamic_channel_write_data(&payload, 7, 1, caps.data, caps.length) == LIBRDP_STATUS_OK &&
         build_static_channel_packet(out, &payload, 1004);
    rdp_buffer_free(&payload);
    rdp_buffer_free(&caps);
    return ok;
}

static int build_dynamic_channel_display_control_caps_packet(rdp_buffer* out)
{
    return build_dynamic_channel_display_control_caps_packet_ex(out, 1u, 8192u, 8192u);
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

/*
 * Read one client RAIL order through its static virtual channel. Startup
 * validation checks semantic fields rather than accepting any well-framed PDU.
 */
static int read_client_remote_programs_order_fd(int fd,
                                                uint8_t* input,
                                                size_t capacity,
                                                uint16_t expected_channel_id,
                                                uint16_t expected_order)
{
    size_t input_len = 0u;
    rdp_virtual_channel_packet packet;
    rdp_remote_programs_header header;

    if (!read_tpkt_fd(fd, input, capacity, &input_len) ||
        !parse_client_dynamic_channel_payload(input,
                                              input_len,
                                              expected_channel_id,
                                              &packet) ||
        rdp_remote_programs_parse_header(packet.payload,
                                         packet.payload_len,
                                         &header) != LIBRDP_STATUS_OK ||
        header.order_type != expected_order)
    {
        return 0;
    }
    if (expected_order == RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE)
    {
        rdp_remote_programs_u32_order order;

        return rdp_remote_programs_parse_u32_order(packet.payload,
                                                   packet.payload_len,
                                                   expected_order,
                                                   &order) == LIBRDP_STATUS_OK &&
               order.value != 0u;
    }
    if (expected_order == RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE_EX)
    {
        rdp_remote_programs_handshake_ex order;

        return rdp_remote_programs_parse_handshake_ex(packet.payload,
                                                      packet.payload_len,
                                                      &order) == LIBRDP_STATUS_OK &&
               order.build_number != 0u &&
               (order.flags & RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_HIDEF) != 0u;
    }
    if (expected_order == RDP_REMOTE_PROGRAMS_ORDER_CLIENTSTATUS)
    {
        rdp_remote_programs_u32_order order;

        return rdp_remote_programs_parse_u32_order(packet.payload,
                                                   packet.payload_len,
                                                   expected_order,
                                                   &order) == LIBRDP_STATUS_OK &&
               (order.value & RDP_REMOTE_PROGRAMS_CLIENTSTATUS_ALLOW_LOCAL_MOVE_SIZE) != 0u;
    }
    if (expected_order == RDP_REMOTE_PROGRAMS_ORDER_EXEC)
    {
        rdp_remote_programs_exec order;

        return rdp_remote_programs_parse_exec(packet.payload,
                                              packet.payload_len,
                                              &order) == LIBRDP_STATUS_OK &&
               order.exe_or_file_len >= 2u &&
               (order.exe_or_file_len & 1u) == 0u;
    }
    return 0;
}

static int write_remote_programs_order_fd(int fd, const rdp_buffer* order)
{
    rdp_buffer packet;
    int ok = 0;

    if (!order)
        return 0;
    rdp_buffer_init(&packet);
    ok = build_static_channel_packet(&packet, order, 1006u) &&
         write_exact_fd(fd, packet.data, packet.length);
    rdp_buffer_free(&packet);
    return ok;
}

/*
 * Send server-side RAIL control traffic after activation. The sequence covers
 * launch result, focus, shell controls, notification icons, movement, resize
 * bounds, and application teardown on the negotiated channel.
 */
static int run_remote_programs_runtime_server_scenario(int fd)
{
    static const uint8_t executable[] = {
        's', 0u, 'm', 0u, 'o', 0u, 'k', 0u, 'e', 0u,
        '-', 0u, 'a', 0u, 'p', 0u, 'p', 0u, '.', 0u,
        'e', 0u, 'x', 0u, 'e', 0u
    };
    rdp_remote_programs_localmovesize local_move;
    rdp_remote_programs_minmaxinfo minmax;
    rdp_buffer order;
    librdp_status status = LIBRDP_STATUS_OK;
    int ok = 1;

    memset(&local_move, 0, sizeof(local_move));
    memset(&minmax, 0, sizeof(minmax));
    rdp_buffer_init(&order);

#define WRITE_RAIL_ORDER(expression)                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        order.length = 0u;                                                                                             \
        status = (expression);                                                                                         \
        if (status != LIBRDP_STATUS_OK || !write_remote_programs_order_fd(fd, &order))                                 \
            ok = 0;                                                                                                    \
    } while (0)

    WRITE_RAIL_ORDER(rdp_remote_programs_write_handshake_ex(
        &order,
        22621u,
        RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_HIDEF |
            RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_SNAP_ARRANGE));
    WRITE_RAIL_ORDER(rdp_remote_programs_write_exec_result(
        &order,
        RDP_REMOTE_PROGRAMS_EXEC_FLAG_EXPAND_ARGUMENTS,
        RDP_REMOTE_PROGRAMS_EXEC_RESULT_OK,
        0u,
        executable,
        (uint16_t)sizeof(executable)));
    WRITE_RAIL_ORDER(rdp_remote_programs_write_activate(&order, 0x10203040u, 1u));
    WRITE_RAIL_ORDER(rdp_remote_programs_write_sysmenu(&order, 0x10203040u, 20, 30));
    WRITE_RAIL_ORDER(rdp_remote_programs_write_syscommand(&order, 0x10203040u, 0xf020u));
    WRITE_RAIL_ORDER(rdp_remote_programs_write_notify_event(&order,
                                                            0x10203040u,
                                                            0x00000021u,
                                                            0x00000201u));
    WRITE_RAIL_ORDER(rdp_remote_programs_write_windowmove(&order,
                                                          0x10203040u,
                                                          32,
                                                          48,
                                                          672,
                                                          528));

    local_move.window_id = 0x10203040u;
    local_move.is_move_size_start = 1u;
    local_move.move_size_type = 9u;
    local_move.pos_x = 32;
    local_move.pos_y = 48;
    WRITE_RAIL_ORDER(rdp_remote_programs_write_localmovesize(&order, &local_move));
    local_move.is_move_size_start = 0u;
    local_move.pos_x = 64;
    local_move.pos_y = 80;
    WRITE_RAIL_ORDER(rdp_remote_programs_write_localmovesize(&order, &local_move));

    minmax.window_id = 0x10203040u;
    minmax.max_width = 1920;
    minmax.max_height = 1080;
    minmax.max_pos_x = 0;
    minmax.max_pos_y = 0;
    minmax.min_track_width = 160;
    minmax.min_track_height = 120;
    minmax.max_track_width = 3200;
    minmax.max_track_height = 2000;
    WRITE_RAIL_ORDER(rdp_remote_programs_write_minmaxinfo(&order, &minmax));
    WRITE_RAIL_ORDER(rdp_remote_programs_write_activate(&order, 0x10203040u, 0u));

#undef WRITE_RAIL_ORDER

    rdp_buffer_free(&order);
    return ok;
}

static int read_soft_sync_response_fd(int fd,
                                      uint8_t* input,
                                      size_t capacity,
                                      uint16_t expected_channel_id,
                                      uint32_t expected_tunnel_count,
                                      uint32_t expected_tunnel_type)
{
    for (size_t attempt = 0; attempt < 8u; attempt++)
    {
        size_t input_len = 0;
        rdp_virtual_channel_packet response_packet;
        rdp_dynamic_channel_soft_sync_response soft_sync_response;
        uint32_t tunnel_type = 0;

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
        {
            if (soft_sync_response.tunnel_count != expected_tunnel_count)
                return 0;
            if (expected_tunnel_count == 0)
                return 1;
            return rdp_dynamic_channel_soft_sync_response_get_tunnel(&soft_sync_response,
                                                                     0,
                                                                     &tunnel_type) == LIBRDP_STATUS_OK &&
                   tunnel_type == expected_tunnel_type;
        }
    }
    return 0;
}

static int read_echo_response_fd(int fd,
                                 uint8_t* input,
                                 size_t capacity,
                                 uint16_t expected_static_channel_id,
                                 uint32_t expected_dynamic_channel_id,
                                 const uint8_t* expected,
                                 size_t expected_len)
{
    for (size_t attempt = 0; attempt < 8u; attempt++)
    {
        size_t input_len = 0;
        rdp_virtual_channel_packet response_packet;
        rdp_dynamic_channel_data_pdu data_pdu;
        rdp_echo_channel_pdu echo;

        if (!read_tpkt_fd(fd, input, capacity, &input_len))
            return 0;
        if (!parse_client_dynamic_channel_payload(input,
                                                  input_len,
                                                  expected_static_channel_id,
                                                  &response_packet))
            continue;
        if (rdp_dynamic_channel_parse_data(response_packet.payload,
                                           response_packet.payload_len,
                                           &data_pdu) != LIBRDP_STATUS_OK)
            continue;
        if (data_pdu.channel_id != expected_dynamic_channel_id)
            continue;
        if (rdp_echo_channel_parse_response(data_pdu.data, data_pdu.data_len, &echo) != LIBRDP_STATUS_OK)
            return 0;
        return echo.payload_len == expected_len &&
               (expected_len == 0 || memcmp(echo.payload, expected, expected_len) == 0);
    }
    return 0;
}

/*
 * Fixture: validates the WebAuthn policy-denied response without decoding the
 * whole CBOR payload. It catches RP ID allowlist bypass while avoiding sensitive
 * authenticator data inspection.
 */
static int read_webauthn_operation_denied_response_fd(int fd,
                                                      uint8_t* input,
                                                      size_t capacity,
                                                      uint16_t expected_static_channel_id,
                                                      uint32_t expected_dynamic_channel_id)
{
    static const uint8_t response_marker[] = {
        0x68, 'r', 'e', 's', 'p', 'o', 'n', 's', 'e', 0x41, 0x27
    };

    for (size_t attempt = 0; attempt < 8u; attempt++)
    {
        size_t input_len = 0;
        rdp_virtual_channel_packet response_packet;
        rdp_dynamic_channel_data_pdu data_pdu;
        rdp_webauthn_response webauthn;

        if (!read_tpkt_fd(fd, input, capacity, &input_len))
            return 0;
        if (!parse_client_dynamic_channel_payload(input,
                                                  input_len,
                                                  expected_static_channel_id,
                                                  &response_packet))
            continue;
        if (rdp_dynamic_channel_parse_data(response_packet.payload,
                                           response_packet.payload_len,
                                           &data_pdu) != LIBRDP_STATUS_OK)
            continue;
        if (data_pdu.channel_id != expected_dynamic_channel_id)
            continue;
        if (rdp_webauthn_parse_response(data_pdu.data,
                                        data_pdu.data_len,
                                        &webauthn) != LIBRDP_STATUS_OK ||
            webauthn.hresult != 0 ||
            webauthn.payload_len < sizeof(response_marker))
            return 0;
        for (size_t i = 0; i <= webauthn.payload_len - sizeof(response_marker); i++)
        {
            if (memcmp(webauthn.payload + i, response_marker, sizeof(response_marker)) == 0)
                return 1;
        }
        return 0;
    }
    return 0;
}

static int test_dvc_length_code(size_t length)
{
    if (length <= 0xffu)
        return 0;
    if (length <= 0xffffu)
        return 1;
    return 2;
}

static int test_dvc_fragment_matches_sequence(const uint8_t* data, size_t data_len, size_t offset)
{
    size_t i = 0;

    if (!data && data_len > 0)
        return 0;
    for (i = 0; i < data_len; i++)
    {
        if (data[i] != (uint8_t)((offset + i) & 0xffu))
            return 0;
    }
    return 1;
}

static int read_client_fragmented_dynamic_payload_fd(int fd,
                                                     uint8_t* input,
                                                     size_t capacity,
                                                     uint16_t expected_static_channel_id,
                                                     uint32_t expected_dynamic_channel_id,
                                                     uint8_t expected_priority,
                                                     size_t expected_len)
{
    size_t received = 0;
    int saw_first = 0;

    for (size_t attempt = 0; attempt < 12u && received < expected_len; attempt++)
    {
        size_t input_len = 0;
        rdp_virtual_channel_packet response_packet;
        rdp_dynamic_channel_header header;

        if (!read_tpkt_fd(fd, input, capacity, &input_len))
            return 0;
        if (!parse_client_dynamic_channel_payload(input,
                                                  input_len,
                                                  expected_static_channel_id,
                                                  &response_packet))
            continue;
        if (rdp_dynamic_channel_parse_header(response_packet.payload,
                                             response_packet.payload_len,
                                             &header) != LIBRDP_STATUS_OK)
            return 0;
        if (!saw_first)
        {
            rdp_dynamic_channel_data_first_pdu first;

            if (header.command != RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST ||
                header.priority != (uint8_t)test_dvc_length_code(expected_len))
                return 0;
            if (rdp_dynamic_channel_parse_data_first(response_packet.payload,
                                                     response_packet.payload_len,
                                                     &first) != LIBRDP_STATUS_OK)
                return 0;
            if (first.channel_id != expected_dynamic_channel_id ||
                first.total_length != expected_len ||
                first.data_len == 0 ||
                first.data_len > expected_len ||
                !test_dvc_fragment_matches_sequence(first.data, first.data_len, 0))
                return 0;
            received = first.data_len;
            saw_first = 1;
        }
        else
        {
            rdp_dynamic_channel_data_pdu data_pdu;

            if (header.command != RDP_DYNAMIC_CHANNEL_CMD_DATA ||
                header.priority != expected_priority)
                return 0;
            if (rdp_dynamic_channel_parse_data(response_packet.payload,
                                               response_packet.payload_len,
                                               &data_pdu) != LIBRDP_STATUS_OK)
                return 0;
            if (data_pdu.channel_id != expected_dynamic_channel_id ||
                data_pdu.data_len == 0 ||
                data_pdu.data_len > expected_len - received ||
                !test_dvc_fragment_matches_sequence(data_pdu.data, data_pdu.data_len, received))
                return 0;
            received += data_pdu.data_len;
        }
    }
    return saw_first && received == expected_len;
}

static int read_client_dynamic_close_fd(int fd,
                                        uint8_t* input,
                                        size_t capacity,
                                        uint16_t expected_static_channel_id,
                                        uint32_t expected_dynamic_channel_id)
{
    for (size_t attempt = 0; attempt < 8u; attempt++)
    {
        size_t input_len = 0;
        rdp_virtual_channel_packet response_packet;
        rdp_dynamic_channel_close_pdu close_pdu;

        if (!read_tpkt_fd(fd, input, capacity, &input_len))
            return 0;
        if (!parse_client_dynamic_channel_payload(input,
                                                  input_len,
                                                  expected_static_channel_id,
                                                  &response_packet))
            continue;
        if (rdp_dynamic_channel_parse_close(response_packet.payload,
                                            response_packet.payload_len,
                                            &close_pdu) != LIBRDP_STATUS_OK)
            return 0;
        return close_pdu.channel_id == expected_dynamic_channel_id;
    }
    return 0;
}

static int read_client_dynamic_create_response_status_fd(int fd,
                                                         uint8_t* input,
                                                         size_t capacity,
                                                         uint16_t expected_static_channel_id,
                                                         uint32_t expected_dynamic_channel_id,
                                                         uint32_t* status_code)
{
    for (size_t attempt = 0; attempt < 8u; attempt++)
    {
        size_t input_len = 0;
        rdp_virtual_channel_packet response_packet;
        rdp_dynamic_channel_create_response response;

        if (!read_tpkt_fd(fd, input, capacity, &input_len))
            return 0;
        if (!parse_client_dynamic_channel_payload(input,
                                                  input_len,
                                                  expected_static_channel_id,
                                                  &response_packet))
            continue;
        if (rdp_dynamic_channel_parse_create_response(response_packet.payload,
                                                      response_packet.payload_len,
                                                      &response) != LIBRDP_STATUS_OK)
            return 0;
        if (response.channel_id != expected_dynamic_channel_id)
            return 0;
        if (status_code)
            *status_code = response.status_code;
        return 1;
    }
    return 0;
}

static int read_client_dynamic_create_response_fd(int fd,
                                                  uint8_t* input,
                                                  size_t capacity,
                                                  uint16_t expected_static_channel_id,
                                                  uint32_t expected_dynamic_channel_id)
{
    uint32_t status_code = 0;

    return read_client_dynamic_create_response_status_fd(fd,
                                                        input,
                                                        capacity,
                                                        expected_static_channel_id,
                                                        expected_dynamic_channel_id,
                                                        &status_code) &&
           status_code == RDP_DYNAMIC_CHANNEL_STATUS_OK;
}

static int read_client_composited_notification_fd(int fd,
                                                  uint8_t* input,
                                                  size_t capacity,
                                                  uint32_t expected_control,
                                                  uint32_t expected_channel,
                                                  uint32_t expected_notification,
                                                  uint32_t expected_value,
                                                  int check_value)
{
    for (size_t attempt = 0; attempt < 8u; attempt++)
    {
        size_t input_len = 0;
        rdp_virtual_channel_packet response_packet;
        rdp_dynamic_channel_data_pdu data_pdu;
        rdp_composited_control control;
        rdp_stream payload;
        uint32_t notification = 0;
        uint32_t reserved = 0;
        uint32_t value = 0;

        if (!read_tpkt_fd(fd, input, capacity, &input_len))
            return 0;
        if (!parse_client_dynamic_channel_payload(input, input_len, 1004u, &response_packet))
            continue;
        if (rdp_dynamic_channel_parse_data(response_packet.payload,
                                           response_packet.payload_len,
                                           &data_pdu) != LIBRDP_STATUS_OK ||
            data_pdu.channel_id != 7u ||
            rdp_composited_parse_control(data_pdu.data,
                                         data_pdu.data_len,
                                         &control) != LIBRDP_STATUS_OK)
            continue;
        if (control.control_code != expected_control ||
            control.word0 != expected_channel)
            continue;
        rdp_stream_init(&payload, control.payload, control.payload_len);
        if (rdp_stream_read_u32_le(&payload, &notification) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&payload, &reserved) != LIBRDP_STATUS_OK ||
            notification != expected_notification)
            return 0;
        if (!check_value)
            return 1;
        if (rdp_stream_read_u32_le(&payload, &value) != LIBRDP_STATUS_OK)
            return 0;
        return value == expected_value;
    }
    return 0;
}

static int append_composited_roundtrip(rdp_buffer* batch, uint32_t request_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, request_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_composited_write_channel_message(batch,
                                                      RDP_COMPOSITED_CMD_ROUNDTRIP_REQUEST,
                                                      payload.data,
                                                      payload.length);
    rdp_buffer_free(&payload);
    return status == LIBRDP_STATUS_OK;
}

static int build_composited_create_batch(rdp_buffer* batch)
{
    static const uint8_t clear_color[16] = {
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u
    };
    const rdp_composited_rect_i window = {16, 24, 336, 264};
    const rdp_composited_rect_i client = {20, 48, 332, 260};
    const rdp_composited_rect_i content = {24, 52, 328, 256};
    const rdp_composited_rect_i invalid = {32, 64, 160, 192};

    return rdp_composited_write_target_create(batch,
                                               0x40u,
                                               640u,
                                               480u,
                                               clear_color) == LIBRDP_STATUS_OK &&
           rdp_composited_write_window_node_create(batch,
                                                   0x41u,
                                                   0x1112131415161718ull,
                                                   0x2122232425262728ull,
                                                   0u) == LIBRDP_STATUS_OK &&
           rdp_composited_write_window_node_bounds(batch,
                                                   0x41u,
                                                   &window,
                                                   &client,
                                                   &content) == LIBRDP_STATUS_OK &&
           rdp_composited_write_u32_target_order(batch,
                                                 RDP_COMPOSITED_CMD_TARGET_SET_ROOT,
                                                 0x40u,
                                                 0x41u) == LIBRDP_STATUS_OK &&
           rdp_composited_write_rect_order(batch,
                                           RDP_COMPOSITED_CMD_TARGET_INVALIDATE,
                                           0x40u,
                                           &invalid) == LIBRDP_STATUS_OK &&
           append_composited_roundtrip(batch, 1u);
}

static int build_composited_update_batch(rdp_buffer* batch)
{
    const rdp_composited_rect_i first_window = {48, 72, 368, 312};
    const rdp_composited_rect_i first_client = {52, 96, 364, 308};
    const rdp_composited_rect_i first_content = {56, 100, 360, 304};
    const rdp_composited_rect_i second_window = {80, 96, 400, 336};
    const rdp_composited_rect_i second_client = {84, 120, 396, 332};
    const rdp_composited_rect_i second_content = {88, 124, 392, 328};
    const rdp_composited_rect_i fallback = {700, 500, 700, 500};

    return rdp_composited_write_window_node_bounds(batch,
                                                   0x41u,
                                                   &first_window,
                                                   &first_client,
                                                   &first_content) == LIBRDP_STATUS_OK &&
           rdp_composited_write_window_node_create(batch,
                                                   0x42u,
                                                   0x3132333435363738ull,
                                                   0x4142434445464748ull,
                                                   0u) == LIBRDP_STATUS_OK &&
           rdp_composited_write_window_node_bounds(batch,
                                                   0x42u,
                                                   &second_window,
                                                   &second_client,
                                                   &second_content) == LIBRDP_STATUS_OK &&
           rdp_composited_write_u32_target_order(batch,
                                                 RDP_COMPOSITED_CMD_TARGET_SET_ROOT,
                                                 0x40u,
                                                 0x42u) == LIBRDP_STATUS_OK &&
           rdp_composited_write_rect_order(batch,
                                           RDP_COMPOSITED_CMD_TARGET_INVALIDATE,
                                           0x40u,
                                           &fallback) == LIBRDP_STATUS_OK &&
           rdp_composited_write_target_order(batch,
                                             RDP_COMPOSITED_CMD_WINDOW_NODE_DETACH,
                                             0x41u) == LIBRDP_STATUS_OK &&
           rdp_composited_write_resource_order(batch,
                                               RDP_COMPOSITED_CMD_DELETE_RESOURCE,
                                               0x41u,
                                               RDP_COMPOSITED_RESOURCE_WINDOW_NODE) == LIBRDP_STATUS_OK &&
           append_composited_roundtrip(batch, 2u);
}

static int build_composited_delete_batch(rdp_buffer* batch)
{
    return rdp_composited_write_resource_order(batch,
                                               RDP_COMPOSITED_CMD_DELETE_RESOURCE,
                                               0x42u,
                                               RDP_COMPOSITED_RESOURCE_WINDOW_NODE) == LIBRDP_STATUS_OK &&
           rdp_composited_write_resource_order(batch,
                                               RDP_COMPOSITED_CMD_DELETE_RESOURCE,
                                               0x40u,
                                               RDP_COMPOSITED_RESOURCE_HWND_TARGET) == LIBRDP_STATUS_OK &&
           append_composited_roundtrip(batch, 3u);
}

static int write_composited_dynamic_packet_fd(int fd,
                                              const rdp_buffer* control,
                                              rdp_buffer* packet)
{
    if (!control || !packet)
        return 0;
    rdp_buffer_free(packet);
    rdp_buffer_init(packet);
    return build_dynamic_channel_data_payload_packet(packet,
                                                     control->data,
                                                     control->length) &&
           write_exact_fd(fd, packet->data, packet->length);
}

/*
 * Fixture: synchronizes each CR2 lifecycle phase with a client roundtrip
 * response before sending the next batch. It catches DVC ordering, partial
 * tree mutation, invalidation fallback, stale resource, and close/reset bugs.
 */
static int run_composited_runtime_server_scenario(int fd,
                                                  uint8_t* input,
                                                  size_t input_capacity)
{
    rdp_buffer create;
    rdp_buffer control;
    rdp_buffer batch;
    rdp_buffer packet;
    rdp_buffer close;
    int ok = 0;

    rdp_buffer_init(&create);
    rdp_buffer_init(&control);
    rdp_buffer_init(&batch);
    rdp_buffer_init(&packet);
    rdp_buffer_init(&close);

    ok = build_dynamic_channel_create_named_packet(&create, RDP_COMPOSITED_CHANNEL_NAME) &&
         write_exact_fd(fd, create.data, create.length) &&
         read_client_dynamic_create_response_fd(fd, input, input_capacity, 1004u, 7u);
    if (ok)
    {
        ok = rdp_composited_write_control_fixed(&control,
                                                RDP_COMPOSITED_CONTROL_VERSION_REQUEST,
                                                0u,
                                                0u) == LIBRDP_STATUS_OK &&
             write_composited_dynamic_packet_fd(fd, &control, &packet) &&
             read_client_composited_notification_fd(
                 fd,
                 input,
                 input_capacity,
                 RDP_COMPOSITED_CONTROL_CONNECTION_NOTIFICATION,
                 0u,
                 RDP_COMPOSITED_MSG_VERSION_REPLY,
                 0u,
                 0);
    }
    rdp_buffer_free(&control);
    rdp_buffer_init(&control);
    if (ok)
    {
        ok = rdp_composited_write_control_fixed(&control,
                                                RDP_COMPOSITED_CONTROL_OPEN_CONNECTION,
                                                0x31u,
                                                0u) == LIBRDP_STATUS_OK &&
             write_composited_dynamic_packet_fd(fd, &control, &packet);
    }
    rdp_buffer_free(&control);
    rdp_buffer_init(&control);
    if (ok)
    {
        ok = rdp_composited_write_control_fixed(&control,
                                                RDP_COMPOSITED_CONTROL_OPEN_CHANNEL,
                                                0x51u,
                                                0u) == LIBRDP_STATUS_OK &&
             write_composited_dynamic_packet_fd(fd, &control, &packet);
    }
    rdp_buffer_free(&control);
    rdp_buffer_init(&control);
    if (ok)
    {
        ok = build_composited_create_batch(&batch) &&
             rdp_composited_write_data_on_channel(&control,
                                                  0x51u,
                                                  batch.data,
                                                  batch.length) == LIBRDP_STATUS_OK &&
             write_composited_dynamic_packet_fd(fd, &control, &packet) &&
             read_client_composited_notification_fd(
                 fd,
                 input,
                 input_capacity,
                 RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION,
                 0x51u,
                 RDP_COMPOSITED_MSG_ROUNDTRIP_REPLY,
                 1u,
                 1);
    }
    rdp_buffer_free(&batch);
    rdp_buffer_init(&batch);
    rdp_buffer_free(&control);
    rdp_buffer_init(&control);
    if (ok)
    {
        ok = build_composited_update_batch(&batch) &&
             rdp_composited_write_data_on_channel(&control,
                                                  0x51u,
                                                  batch.data,
                                                  batch.length) == LIBRDP_STATUS_OK &&
             write_composited_dynamic_packet_fd(fd, &control, &packet) &&
             read_client_composited_notification_fd(
                 fd,
                 input,
                 input_capacity,
                 RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION,
                 0x51u,
                 RDP_COMPOSITED_MSG_ROUNDTRIP_REPLY,
                 2u,
                 1);
    }
    rdp_buffer_free(&batch);
    rdp_buffer_init(&batch);
    rdp_buffer_free(&control);
    rdp_buffer_init(&control);
    if (ok)
    {
        ok = build_composited_delete_batch(&batch) &&
             rdp_composited_write_data_on_channel(&control,
                                                  0x51u,
                                                  batch.data,
                                                  batch.length) == LIBRDP_STATUS_OK &&
             write_composited_dynamic_packet_fd(fd, &control, &packet) &&
             read_client_composited_notification_fd(
                 fd,
                 input,
                 input_capacity,
                 RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION,
                 0x51u,
                 RDP_COMPOSITED_MSG_ROUNDTRIP_REPLY,
                 3u,
                 1);
    }
    rdp_buffer_free(&control);
    rdp_buffer_init(&control);
    if (ok)
    {
        ok = rdp_composited_write_control_fixed(&control,
                                                RDP_COMPOSITED_CONTROL_CLOSE_CHANNEL,
                                                0x51u,
                                                0u) == LIBRDP_STATUS_OK &&
             write_composited_dynamic_packet_fd(fd, &control, &packet);
    }
    rdp_buffer_free(&control);
    rdp_buffer_init(&control);
    if (ok)
    {
        ok = rdp_composited_write_control_fixed(&control,
                                                RDP_COMPOSITED_CONTROL_CLOSE_CONNECTION,
                                                0x31u,
                                                0u) == LIBRDP_STATUS_OK &&
             write_composited_dynamic_packet_fd(fd, &control, &packet) &&
             build_dynamic_channel_close_packet(&close) &&
             write_exact_fd(fd, close.data, close.length);
    }

    rdp_buffer_free(&close);
    rdp_buffer_free(&packet);
    rdp_buffer_free(&batch);
    rdp_buffer_free(&control);
    rdp_buffer_free(&create);
    return ok;
}

static int test_display_control_layout_bounds(const rdp_display_control_monitor* monitors,
                                              uint32_t monitor_count,
                                              uint32_t* width,
                                              uint32_t* height)
{
    int64_t left = 0;
    int64_t top = 0;
    int64_t right = 0;
    int64_t bottom = 0;

    if (!monitors || monitor_count == 0 || !width || !height)
        return 0;
    left = monitors[0].left;
    top = monitors[0].top;
    right = (int64_t)monitors[0].left + (int64_t)monitors[0].width;
    bottom = (int64_t)monitors[0].top + (int64_t)monitors[0].height;
    for (uint32_t i = 1; i < monitor_count; i++)
    {
        int64_t monitor_right = (int64_t)monitors[i].left + (int64_t)monitors[i].width;
        int64_t monitor_bottom = (int64_t)monitors[i].top + (int64_t)monitors[i].height;

        if ((int64_t)monitors[i].left < left)
            left = monitors[i].left;
        if ((int64_t)monitors[i].top < top)
            top = monitors[i].top;
        if (monitor_right > right)
            right = monitor_right;
        if (monitor_bottom > bottom)
            bottom = monitor_bottom;
    }
    if (right <= left || bottom <= top ||
        right - left > UINT32_MAX ||
        bottom - top > UINT32_MAX)
        return 0;
    *width = (uint32_t)(right - left);
    *height = (uint32_t)(bottom - top);
    return 1;
}

static int read_client_display_control_layout_fd(int fd,
                                                 uint8_t* input,
                                                 size_t capacity,
                                                 uint16_t expected_static_channel_id,
                                                 uint32_t expected_dynamic_channel_id,
                                                 uint32_t expected_monitor_count,
                                                 uint32_t expected_width,
                                                 uint32_t expected_height)
{
    for (size_t attempt = 0; attempt < 8u; attempt++)
    {
        size_t input_len = 0;
        rdp_virtual_channel_packet response_packet;
        rdp_dynamic_channel_data_pdu data_pdu;
        rdp_display_control_monitor monitors[LIBRDP_DISPLAY_MAX_MONITORS];
        uint32_t monitor_count = 0;
        uint32_t width = 0;
        uint32_t height = 0;

        if (!read_tpkt_fd(fd, input, capacity, &input_len))
            return 0;
        if (!parse_client_dynamic_channel_payload(input,
                                                  input_len,
                                                  expected_static_channel_id,
                                                  &response_packet))
            continue;
        if (rdp_dynamic_channel_parse_data(response_packet.payload,
                                           response_packet.payload_len,
                                           &data_pdu) != LIBRDP_STATUS_OK)
            return 0;
        if (data_pdu.channel_id != expected_dynamic_channel_id)
            return 0;
        if (rdp_display_control_parse_monitor_layout(data_pdu.data,
                                                     data_pdu.data_len,
                                                     monitors,
                                                     LIBRDP_DISPLAY_MAX_MONITORS,
                                                     &monitor_count) != LIBRDP_STATUS_OK)
            return 0;
        if (!test_display_control_layout_bounds(monitors, monitor_count, &width, &height))
            return 0;
        return monitor_count == expected_monitor_count &&
               width == expected_width &&
               height == expected_height;
    }
    return 0;
}

/*
 * Fixture: reads one client device-redirection PDU from a static virtual
 * channel and copies it out of the stack-backed TPKT buffer. It lets RDPDR
 * tests validate replies precisely while tolerating unrelated client traffic
 * that can be emitted by other negotiated channels.
 */
static int read_client_device_packet_fd(int fd,
                                        uint8_t* input,
                                        size_t capacity,
                                        uint16_t expected_static_channel_id,
                                        uint16_t expected_packet_id,
                                        rdp_buffer* payload)
{
    for (size_t attempt = 0; attempt < 16u; attempt++)
    {
        size_t input_len = 0;
        rdp_virtual_channel_packet response_packet;
        rdp_device_redirection_header header;

        if (!read_tpkt_fd(fd, input, capacity, &input_len))
            return 0;
        if (!parse_client_dynamic_channel_payload(input,
                                                  input_len,
                                                  expected_static_channel_id,
                                                  &response_packet))
            continue;
        if (rdp_device_redirection_parse_header(response_packet.payload,
                                                response_packet.payload_len,
                                                &header) != LIBRDP_STATUS_OK)
            continue;
        if (header.packet_id != expected_packet_id)
            continue;
        payload->length = 0;
        return rdp_buffer_append(payload,
                                 response_packet.payload,
                                 response_packet.payload_len) == LIBRDP_STATUS_OK;
    }
    return 0;
}

int build_device_redirection_server_capabilities(rdp_buffer* out)
{
    rdp_device_redirection_capability_config config;
    rdp_buffer general;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!out)
        return 0;
    rdp_buffer_init(&general);
    status = rdp_device_redirection_make_default_capability_config(&config);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_device_redirection_write_general_capability(&general, &config.general);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_device_redirection_write_header(out,
                                                     RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                                     RDP_DEVICE_REDIRECTION_PAKID_CORE_SERVER_CAPABILITY);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(out, 2u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(out, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(out, general.data, general.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(out, RDP_DEVICE_REDIRECTION_CAP_PRINTER);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(out, 8u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(out, RDP_DEVICE_REDIRECTION_CAP_VERSION_1);
    rdp_buffer_free(&general);
    return status == LIBRDP_STATUS_OK;
}

int write_device_static_packet_fd(int fd, const rdp_buffer* payload, uint16_t channel_id)
{
    rdp_buffer packet;
    int ok = 0;

    if (!payload)
        return 0;
    rdp_buffer_init(&packet);
    ok = build_static_channel_packet(&packet, payload, channel_id) &&
         write_exact_fd(fd, packet.data, packet.length);
    rdp_buffer_free(&packet);
    return ok;
}

int read_client_device_announce_fd(int fd, uint8_t* input, size_t capacity, uint16_t channel_id)
{
    rdp_buffer payload;
    rdp_device_redirection_announce confirm;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = read_client_device_packet_fd(fd,
                                      input,
                                      capacity,
                                      channel_id,
                                      RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENTID_CONFIRM,
                                      &payload) &&
         rdp_device_redirection_parse_client_id_confirm(payload.data,
                                                        payload.length,
                                                        &confirm) == LIBRDP_STATUS_OK &&
         confirm.version_major == RDP_DEVICE_REDIRECTION_VERSION_MAJOR &&
         confirm.version_minor == RDP_DEVICE_REDIRECTION_VERSION_MINOR_13;
    rdp_buffer_free(&payload);
    return ok;
}

int read_client_device_name_fd(int fd, uint8_t* input, size_t capacity, uint16_t channel_id)
{
    rdp_buffer payload;
    rdp_device_redirection_client_name name;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = read_client_device_packet_fd(fd,
                                      input,
                                      capacity,
                                      channel_id,
                                      RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENT_NAME,
                                      &payload) &&
         rdp_device_redirection_parse_client_name(payload.data,
                                                  payload.length,
                                                  &name) == LIBRDP_STATUS_OK &&
         name.unicode == 1u &&
         name.name_len >= 2u &&
         name.name[name.name_len - 2u] == 0 &&
         name.name[name.name_len - 1u] == 0;
    rdp_buffer_free(&payload);
    return ok;
}

int read_client_device_capabilities_fd(int fd, uint8_t* input, size_t capacity, uint16_t channel_id)
{
    rdp_buffer payload;
    rdp_device_redirection_capability_list caps;
    int saw_printer = 0;
    int ok = 0;

    rdp_buffer_init(&payload);
    if (read_client_device_packet_fd(fd,
                                     input,
                                     capacity,
                                     channel_id,
                                     RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENT_CAPABILITY,
                                     &payload) &&
        rdp_device_redirection_parse_capability_list(payload.data,
                                                     payload.length,
                                                     RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENT_CAPABILITY,
                                                     &caps) == LIBRDP_STATUS_OK)
    {
        for (uint16_t i = 0; i < caps.count; i++)
        {
            if (caps.capabilities[i].type == RDP_DEVICE_REDIRECTION_CAP_PRINTER)
                saw_printer = 1;
        }
        ok = saw_printer;
    }
    rdp_buffer_free(&payload);
    return ok;
}

int read_client_printer_device_id_fd(int fd,
                                            uint8_t* input,
                                            size_t capacity,
                                            uint16_t channel_id,
                                            uint32_t* device_id)
{
    rdp_buffer payload;
    rdp_device_redirection_device_list list;
    int ok = 0;

    if (!device_id)
        return 0;
    *device_id = 0;
    rdp_buffer_init(&payload);
    if (read_client_device_packet_fd(fd,
                                     input,
                                     capacity,
                                     channel_id,
                                     RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_ANNOUNCE,
                                     &payload) &&
        rdp_device_redirection_parse_device_list_announce(payload.data,
                                                          payload.length,
                                                          &list) == LIBRDP_STATUS_OK)
    {
        for (uint32_t i = 0; i < list.count; i++)
        {
            if (list.devices[i].device_type == RDP_DEVICE_REDIRECTION_TYPE_PRINTER)
            {
                rdp_printer_redirection_announce announce;

                if (rdp_printer_redirection_parse_announce_data(list.devices[i].data,
                                                                list.devices[i].data_len,
                                                                &announce) != LIBRDP_STATUS_OK ||
                    (announce.flags & RDP_PRINTER_REDIRECTION_ANNOUNCE_FLAG_XPS) != 0)
                {
                    ok = 0;
                    break;
                }
                *device_id = list.devices[i].device_id;
                ok = 1;
                break;
            }
        }
    }
    rdp_buffer_free(&payload);
    return ok;
}

int read_client_printer_create_response_fd(int fd,
                                                  uint8_t* input,
                                                  size_t capacity,
                                                  uint16_t channel_id,
                                                  uint32_t expected_device_id,
                                                  uint32_t expected_completion_id,
                                                  uint32_t* file_id)
{
    rdp_buffer payload;
    rdp_device_redirection_io_completion completion;
    int ok = 0;

    if (!file_id)
        return 0;
    *file_id = 0;
    rdp_buffer_init(&payload);
    ok = read_client_device_packet_fd(fd,
                                      input,
                                      capacity,
                                      channel_id,
                                      RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOCOMPLETION,
                                      &payload) &&
         rdp_printer_redirection_parse_create_response(payload.data,
                                                       payload.length,
                                                       &completion,
                                                       file_id) == LIBRDP_STATUS_OK &&
         completion.device_id == expected_device_id &&
         completion.completion_id == expected_completion_id &&
         completion.io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS &&
         *file_id != 0;
    rdp_buffer_free(&payload);
    return ok;
}

int read_client_printer_write_response_fd(int fd,
                                                 uint8_t* input,
                                                 size_t capacity,
                                                 uint16_t channel_id,
                                                 uint32_t expected_device_id,
                                                 uint32_t expected_completion_id,
                                                 uint32_t expected_written,
                                                 int expect_success)
{
    rdp_buffer payload;
    rdp_device_redirection_io_completion completion;
    uint32_t written = 0;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = read_client_device_packet_fd(fd,
                                      input,
                                      capacity,
                                      channel_id,
                                      RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOCOMPLETION,
                                      &payload) &&
         rdp_printer_redirection_parse_write_response(payload.data,
                                                      payload.length,
                                                      &completion,
                                                      &written) == LIBRDP_STATUS_OK &&
         completion.device_id == expected_device_id &&
         completion.completion_id == expected_completion_id &&
         ((expect_success &&
           completion.io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS &&
           written == expected_written) ||
          (!expect_success &&
           completion.io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS));
    rdp_buffer_free(&payload);
    return ok;
}

int read_client_printer_read_response_fd(int fd,
                                                uint8_t* input,
                                                size_t capacity,
                                                uint16_t channel_id,
                                                uint32_t expected_device_id,
                                                uint32_t expected_completion_id,
                                                const uint8_t* expected,
                                                uint32_t expected_len)
{
    rdp_buffer payload;
    rdp_device_redirection_io_completion completion;
    const uint8_t* returned = NULL;
    uint32_t returned_len = 0;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = read_client_device_packet_fd(fd,
                                      input,
                                      capacity,
                                      channel_id,
                                      RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOCOMPLETION,
                                      &payload) &&
         rdp_printer_redirection_parse_read_response(payload.data,
                                                     payload.length,
                                                     &completion,
                                                     &returned,
                                                     &returned_len) == LIBRDP_STATUS_OK &&
         completion.device_id == expected_device_id &&
         completion.completion_id == expected_completion_id &&
         completion.io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS &&
         returned_len == expected_len &&
         (expected_len == 0 || memcmp(returned, expected, expected_len) == 0);
    rdp_buffer_free(&payload);
    return ok;
}

int read_client_printer_query_response_fd(int fd,
                                                 uint8_t* input,
                                                 size_t capacity,
                                                 uint16_t channel_id,
                                                 uint32_t expected_device_id,
                                                 uint32_t expected_completion_id)
{
    rdp_buffer payload;
    rdp_device_redirection_io_completion completion;
    const uint8_t* returned = NULL;
    uint32_t returned_len = 0;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = read_client_device_packet_fd(fd,
                                      input,
                                      capacity,
                                      channel_id,
                                      RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOCOMPLETION,
                                      &payload) &&
         rdp_printer_redirection_parse_buffer_response(payload.data,
                                                       payload.length,
                                                       &completion,
                                                       &returned,
                                                       &returned_len) == LIBRDP_STATUS_OK &&
         completion.device_id == expected_device_id &&
         completion.completion_id == expected_completion_id &&
         completion.io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS &&
         returned != NULL &&
         returned_len > 0;
    rdp_buffer_free(&payload);
    return ok;
}

int read_client_device_completion_fd(int fd,
                                            uint8_t* input,
                                            size_t capacity,
                                            uint16_t channel_id,
                                            uint32_t expected_device_id,
                                            uint32_t expected_completion_id)
{
    rdp_buffer payload;
    rdp_device_redirection_io_completion completion;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = read_client_device_packet_fd(fd,
                                      input,
                                      capacity,
                                      channel_id,
                                      RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOCOMPLETION,
                                      &payload) &&
         rdp_device_redirection_parse_io_completion(payload.data,
                                                    payload.length,
                                                    &completion) == LIBRDP_STATUS_OK &&
         completion.device_id == expected_device_id &&
         completion.completion_id == expected_completion_id &&
         completion.io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    rdp_buffer_free(&payload);
    return ok;
}

int read_client_printer_close_response_fd(int fd,
                                                 uint8_t* input,
                                                 size_t capacity,
                                                 uint16_t channel_id,
                                                 uint32_t expected_device_id,
                                                 uint32_t expected_completion_id)
{
    rdp_buffer payload;
    rdp_device_redirection_io_completion completion;
    int ok = 0;

    rdp_buffer_init(&payload);
    ok = read_client_device_packet_fd(fd,
                                      input,
                                      capacity,
                                      channel_id,
                                      RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOCOMPLETION,
                                      &payload) &&
         rdp_printer_redirection_parse_close_response(payload.data,
                                                      payload.length,
                                                      &completion) == LIBRDP_STATUS_OK &&
         completion.device_id == expected_device_id &&
         completion.completion_id == expected_completion_id &&
         completion.io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    rdp_buffer_free(&payload);
    return ok;
}

int reserve_closed_loopback_port(uint16_t* port)
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
 * Fixture: accepts a loopback connection and deliberately withholds the X.224
 * response. The peer exits as soon as cancellation shuts down the socket.
 */
int start_stalling_handshake_server(uint16_t* port, pid_t* child_pid)
{
    int listener = -1;
    struct sockaddr_in addr;
    socklen_t addr_len = (socklen_t)sizeof(addr);

    if (!port || !child_pid)
        return 0;
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0)
        return 0;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        getsockname(listener, (struct sockaddr*)&addr, &addr_len) != 0 ||
        listen(listener, 1) != 0)
    {
        close(listener);
        return 0;
    }
    *port = ntohs(addr.sin_port);
    *child_pid = fork();
    if (*child_pid < 0)
    {
        close(listener);
        return 0;
    }
    if (*child_pid == 0)
    {
        uint8_t buffer[256];
        int client = -1;
        ssize_t got = 0;

        alarm(8);
        client = accept(listener, NULL, NULL);
        close(listener);
        if (client < 0)
            _exit(2);
        do
        {
            got = read(client, buffer, sizeof(buffer));
        } while (got > 0 || (got < 0 && errno == EINTR));
        close(client);
        _exit(got == 0 ? 0 : 3);
    }
    close(listener);
    return 1;
}

/*
 * Fixture: starts a local handshake peer that feeds deterministic protocol
 * bytes to the client session. It isolates connection state-machine coverage
 * from external network and credential dependencies.
 */
int start_handshake_server_full(uint16_t* port,
                                       pid_t* child_pid,
                                       int encrypted,
                                       uint32_t error_info,
                                       int extra_static_channel,
                                       int client_dynamic_channel_open_response,
                                       int connection_count,
                                       int dynamic_channel_scenario,
                                       int gdi_scenario,
                                       int license_scenario,
                                       int clipboard_scenario,
                                       int handshake_scenario)
{
    int fd = -1;
    struct sockaddr_in addr;
    socklen_t addr_len = (socklen_t)sizeof(addr);

    if (!port || !child_pid)
        return 0;
    if (connection_count <= 0 || connection_count > 4)
        return 0;
    if (gdi_scenario != GDI_SCENARIO_NORMAL &&
        gdi_scenario != GDI_SCENARIO_ALTSEC_RUNTIME &&
        gdi_scenario != GDI_SCENARIO_UPDATE_BEFORE_ACTIVATION &&
        gdi_scenario != GDI_SCENARIO_DESKTOP_COMPOSITION &&
        gdi_scenario != GDI_SCENARIO_GOLDEN_RUNTIME &&
        gdi_scenario != GDI_SCENARIO_RAIL_RUNTIME)
        return 0;
    if (license_scenario != LICENSE_SCENARIO_NONE &&
        license_scenario != LICENSE_SCENARIO_NEW &&
        license_scenario != LICENSE_SCENARIO_REQUEST &&
        license_scenario != LICENSE_SCENARIO_VALID_CLIENT_ALERT &&
        license_scenario != LICENSE_SCENARIO_CHALLENGE &&
        license_scenario != LICENSE_SCENARIO_ERROR_ALERT)
        return 0;
    if ((handshake_scenario != HANDSHAKE_SCENARIO_NORMAL &&
         handshake_scenario != HANDSHAKE_SCENARIO_STALL_ACTIVATION &&
         handshake_scenario != HANDSHAKE_SCENARIO_GRACEFUL_IDLE_EOF) ||
        (handshake_scenario == HANDSHAKE_SCENARIO_STALL_ACTIVATION &&
         encrypted))
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
            rdp_buffer license_request;
            rdp_buffer license_alert;
            rdp_buffer license_challenge;
            rdp_buffer license_certificate;
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
            rdp_buffer multiparty_static;
            rdp_buffer error_update;
            rdp_license_crypto_context license_crypto;
            EVP_PKEY* license_private_key = NULL;
            int client = accept(fd, NULL, NULL);

            rdp_buffer_init(&mcs_response);
            rdp_buffer_init(&license_new);
            rdp_buffer_init(&license_request);
            rdp_buffer_init(&license_alert);
            rdp_buffer_init(&license_challenge);
            rdp_buffer_init(&license_certificate);
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
            rdp_buffer_init(&multiparty_static);
            rdp_buffer_init(&error_update);
            memset(&license_crypto, 0, sizeof(license_crypto));
            if (client < 0)
                _exit(6);
            if (!build_server_connect_response(&mcs_response,
                                               encrypted,
                                               extra_static_channel,
                                               dynamic_channel_scenario == DVC_SCENARIO_SOFT_SYNC_TUNNEL_REQUEST))
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
            if (handshake_scenario ==
                HANDSHAKE_SCENARIO_STALL_ACTIVATION)
            {
                ssize_t got = 0;

                do
                {
                    got = read(client, input, sizeof(input));
                } while (got > 0 || (got < 0 && errno == EINTR));
                if (got < 0)
                    _exit(4);
                goto done_connection;
            }
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
                if (gdi_scenario == GDI_SCENARIO_UPDATE_BEFORE_ACTIVATION)
                {
                    if (!build_bitmap_update_packet(&bitmap_update) ||
                        !write_exact_fd(client, bitmap_update.data, bitmap_update.length))
                        _exit(4);
                    goto done_connection;
                }
                if (license_scenario == LICENSE_SCENARIO_NEW &&
                    (!build_license_new_packet(&license_new) ||
                     !write_exact_fd(client, license_new.data, license_new.length)))
                    _exit(4);
                if (license_scenario == LICENSE_SCENARIO_VALID_CLIENT_ALERT &&
                    (!build_license_valid_client_alert_packet(&license_alert) ||
                     !write_exact_fd(client, license_alert.data, license_alert.length)))
                    _exit(4);
                if (license_scenario == LICENSE_SCENARIO_REQUEST)
                {
                    if (!build_license_request_packet(&license_request) ||
                        !write_exact_fd(client, license_request.data, license_request.length))
                        _exit(4);
                    if (!read_tpkt_fd(client, input, sizeof(input), &input_len) ||
                        !validate_new_license_request(input, input_len) ||
                        !build_license_valid_client_alert_packet(&license_alert) ||
                        !write_exact_fd(client, license_alert.data, license_alert.length))
                        _exit(4);
                }
                if (license_scenario == LICENSE_SCENARIO_CHALLENGE)
                {
                    static const uint8_t challenge[] = {
                        0x43, 0x00, 0x48, 0x00, 0x41, 0x00, 0x4c, 0x00,
                        0x4c, 0x00, 0x45, 0x00, 0x4e, 0x00, 0x47, 0x00
                    };

                    if (rdp_security_generate_server_certificate(&license_private_key,
                                                                 &license_certificate) !=
                            LIBRDP_STATUS_OK ||
                        !build_license_request_packet_ex(&license_request,
                                                         license_certificate.data,
                                                         license_certificate.length) ||
                        !write_exact_fd(client,
                                        license_request.data,
                                        license_request.length) ||
                        !read_tpkt_fd(client, input, sizeof(input), &input_len) ||
                        !initialize_license_server_crypto(input,
                                                          input_len,
                                                          license_private_key,
                                                          &license_crypto) ||
                        !build_license_platform_challenge_packet(&license_challenge,
                                                                 &license_crypto,
                                                                 challenge,
                                                                 sizeof(challenge)) ||
                        !write_exact_fd(client,
                                        license_challenge.data,
                                        license_challenge.length) ||
                        !read_tpkt_fd(client, input, sizeof(input), &input_len) ||
                        !validate_license_platform_challenge_response(input,
                                                                      input_len,
                                                                      &license_crypto,
                                                                      challenge,
                                                                      sizeof(challenge)) ||
                        !build_license_new_packet(&license_new) ||
                        !write_exact_fd(client,
                                        license_new.data,
                                        license_new.length))
                    {
                        _exit(4);
                    }
                }
                if (license_scenario == LICENSE_SCENARIO_ERROR_ALERT)
                {
                    if (!build_license_error_alert_packet(&license_alert) ||
                        !write_exact_fd(client,
                                        license_alert.data,
                                        license_alert.length))
                    {
                        _exit(4);
                    }
                    goto done_connection;
                }
                if (dynamic_channel_scenario == DVC_SCENARIO_RAIL_RUNTIME &&
                    (!extra_static_channel ||
                     !read_client_remote_programs_order_fd(client,
                                                           input,
                                                           sizeof(input),
                                                           1006u,
                                                           RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE) ||
                     !read_client_remote_programs_order_fd(client,
                                                           input,
                                                           sizeof(input),
                                                           1006u,
                                                           RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE_EX) ||
                     !read_client_remote_programs_order_fd(client,
                                                           input,
                                                           sizeof(input),
                                                           1006u,
                                                           RDP_REMOTE_PROGRAMS_ORDER_CLIENTSTATUS) ||
                     !read_client_remote_programs_order_fd(client,
                                                           input,
                                                           sizeof(input),
                                                           1006u,
                                                           RDP_REMOTE_PROGRAMS_ORDER_EXEC)))
                {
                    _exit(4);
                }
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
                        !((gdi_scenario == GDI_SCENARIO_ALTSEC_RUNTIME) ?
                              build_gdi_altsec_runtime_update_packet(&gdi_orders_update) :
                              ((gdi_scenario == GDI_SCENARIO_DESKTOP_COMPOSITION) ?
                                   build_gdi_desktop_composition_update_packet(&gdi_orders_update) :
                                   ((gdi_scenario == GDI_SCENARIO_RAIL_RUNTIME) ?
                                        build_gdi_rail_runtime_update_packet(&gdi_orders_update) :
                                        build_gdi_orders_update_packet(&gdi_orders_update)))) ||
                        !write_exact_fd(client, gdi_orders_update.data, gdi_orders_update.length) ||
                        (gdi_scenario == GDI_SCENARIO_NORMAL && extra_static_channel &&
                         dynamic_channel_scenario != DVC_SCENARIO_RDPDR_PRINTER_JOB &&
                         dynamic_channel_scenario != DVC_SCENARIO_MULTIPARTY_RUNTIME &&
                         (!build_application_static_channel_first_packet(&static_first) ||
                          !write_exact_fd(client, static_first.data, static_first.length) ||
                          !build_application_static_channel_last_packet(&static_last) ||
                          !write_exact_fd(client, static_last.data, static_last.length))))
                    {
                        _exit(5);
                    }
                    if (gdi_scenario == GDI_SCENARIO_ALTSEC_RUNTIME ||
                        gdi_scenario == GDI_SCENARIO_GOLDEN_RUNTIME)
                        goto done_connection;
                    if (dynamic_channel_scenario == DVC_SCENARIO_MULTIPARTY_RUNTIME)
                    {
                        if (!extra_static_channel ||
                            !build_multiparty_static_channel_packet(&multiparty_static) ||
                            !write_exact_fd(client, multiparty_static.data, multiparty_static.length))
                        {
                            _exit(5);
                        }
                        goto done_connection;
                    }
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
                    if (dynamic_channel_scenario == DVC_SCENARIO_RDPDR_PRINTER_JOB)
                    {
                        if (!extra_static_channel ||
                            !run_printer_job_server_scenario(client, input, sizeof(input)))
                        {
                            _exit(5);
                        }
                        goto done_connection;
                    }
                    if (dynamic_channel_scenario == DVC_SCENARIO_COMPOSITED_RUNTIME)
                    {
                        if (!run_composited_runtime_server_scenario(client,
                                                                    input,
                                                                    sizeof(input)))
                        {
                            _exit(5);
                        }
                        goto done_connection;
                    }
                    if (dynamic_channel_scenario == DVC_SCENARIO_RAIL_RUNTIME)
                    {
                        if (!run_remote_programs_runtime_server_scenario(client))
                            _exit(5);
                        goto done_connection;
                    }
                    if (dynamic_channel_scenario == DVC_SCENARIO_DATA_BEFORE_CREATE)
                    {
                        if (!build_dynamic_channel_data_packet(&dvc_data) ||
                            !write_exact_fd(client, dvc_data.data, dvc_data.length))
                        {
                            _exit(5);
                        }
                        goto done_connection;
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
                        goto done_connection;
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_WEBAUTHN_CREATE_REJECT)
                    {
                        uint32_t status_code = RDP_DYNAMIC_CHANNEL_STATUS_OK;

                        if (!build_dynamic_channel_create_webauthn_packet(&dvc_create) ||
                            !write_exact_fd(client, dvc_create.data, dvc_create.length) ||
                            !read_client_dynamic_create_response_status_fd(client,
                                                                          input,
                                                                          sizeof(input),
                                                                          1004,
                                                                          7,
                                                                          &status_code) ||
                            status_code == RDP_DYNAMIC_CHANNEL_STATUS_OK)
                        {
                            _exit(5);
                        }
                        goto done_connection;
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_WEBAUTHN_RP_ID_DENIED)
                    {
                        if (!build_dynamic_channel_create_webauthn_packet(&dvc_create) ||
                            !write_exact_fd(client, dvc_create.data, dvc_create.length) ||
                            !read_client_dynamic_create_response_fd(client, input, sizeof(input), 1004, 7) ||
                            !build_dynamic_channel_webauthn_request_packet(&dvc_data, "blocked.example") ||
                            !write_exact_fd(client, dvc_data.data, dvc_data.length) ||
                            !read_webauthn_operation_denied_response_fd(client, input, sizeof(input), 1004, 7))
                        {
                            _exit(5);
                        }
                        goto done_connection;
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_AUTH_REDIRECTION_CREATE_REJECT)
                    {
                        uint32_t status_code = RDP_DYNAMIC_CHANNEL_STATUS_OK;

                        if (!build_dynamic_channel_create_auth_redirection_packet(&dvc_create) ||
                            !write_exact_fd(client, dvc_create.data, dvc_create.length) ||
                            !read_client_dynamic_create_response_status_fd(client,
                                                                          input,
                                                                          sizeof(input),
                                                                          1004,
                                                                          7,
                                                                          &status_code) ||
                            status_code == RDP_DYNAMIC_CHANNEL_STATUS_OK)
                        {
                            _exit(5);
                        }
                        goto done_connection;
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_DISPLAY_CONTROL_CREATE_REJECT)
                    {
                        uint32_t status_code = RDP_DYNAMIC_CHANNEL_STATUS_OK;

                        if (!build_dynamic_channel_create_display_control_packet(&dvc_create) ||
                            !write_exact_fd(client, dvc_create.data, dvc_create.length) ||
                            !read_client_dynamic_create_response_status_fd(client,
                                                                          input,
                                                                          sizeof(input),
                                                                          1004,
                                                                          7,
                                                                          &status_code) ||
                            status_code == RDP_DYNAMIC_CHANNEL_STATUS_OK)
                        {
                            _exit(5);
                        }
                        goto done_connection;
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_SOFT_SYNC_TUNNEL_REQUEST)
                    {
                        if (!build_dynamic_channel_soft_sync_tunnel_request_packet(&dvc_soft_sync) ||
                            !write_exact_fd(client, dvc_soft_sync.data, dvc_soft_sync.length) ||
                            !read_soft_sync_response_fd(client,
                                                        input,
                                                        sizeof(input),
                                                        1004,
                                                        1u,
                                                        RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE))
                        {
                            _exit(5);
                        }
                    }
	                    else if (dynamic_channel_scenario == DVC_SCENARIO_DISPLAY_CONTROL_CAPS_REJECT_LAYOUT ||
	                             dynamic_channel_scenario == DVC_SCENARIO_DISPLAY_CONTROL_ACCEPT_LAYOUT)
	                    {
	                        if (!build_dynamic_channel_create_display_control_packet(&dvc_create) ||
	                            !write_exact_fd(client, dvc_create.data, dvc_create.length))
	                        {
	                            _exit(5);
	                        }
	                    }
	                    else if (dynamic_channel_scenario == DVC_SCENARIO_TELEMETRY_RUNTIME)
	                    {
	                        if (!build_dynamic_channel_create_telemetry_packet(&dvc_create) ||
	                            !write_exact_fd(client, dvc_create.data, dvc_create.length))
	                        {
	                            _exit(5);
	                        }
	                    }
	                    else if (dynamic_channel_scenario == DVC_SCENARIO_GEOMETRY_TRACKING_RUNTIME)
	                    {
	                        if (!build_dynamic_channel_create_video_redirection_packet(&dvc_create) ||
	                            !write_exact_fd(client, dvc_create.data, dvc_create.length))
	                        {
	                            _exit(5);
	                        }
	                    }
	                    else if (dynamic_channel_scenario == DVC_SCENARIO_ECHO_VALIDATE ||
	                             dynamic_channel_scenario == DVC_SCENARIO_ECHO_PING ||
                             dynamic_channel_scenario == DVC_SCENARIO_ECHO_TIMEOUT ||
                             dynamic_channel_scenario == DVC_SCENARIO_ECHO_LATE_RESPONSE)
                    {
                        if (!build_dynamic_channel_create_named_packet(&dvc_create, "ECHO") ||
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
	                    if (dynamic_channel_scenario == DVC_SCENARIO_CLIENT_FRAGMENT_SEND)
	                    {
	                        if (!read_client_dynamic_create_response_fd(client, input, sizeof(input), 1004, 7) ||
	                            !read_client_fragmented_dynamic_payload_fd(client,
	                                                                       input,
                                                                       sizeof(input),
                                                                       1004,
                                                                       7,
                                                                       LIBRDP_CHANNEL_PRIORITY_HIGH,
                                                                       3600u) ||
                            !read_client_dynamic_close_fd(client, input, sizeof(input), 1004, 7))
	                        {
	                            _exit(5);
	                        }
	                    }
	                    else if (dynamic_channel_scenario == DVC_SCENARIO_TELEMETRY_RUNTIME)
	                    {
	                        if (!build_dynamic_channel_telemetry_packet(&dvc_data) ||
	                            !write_exact_fd(client, dvc_data.data, dvc_data.length))
	                        {
	                            _exit(5);
	                        }
	                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_GEOMETRY_TRACKING_RUNTIME)
                    {
                        if (!run_geometry_tracking_runtime_server_scenario(client))
                            _exit(5);
                    }
	                    else if (dynamic_channel_scenario == DVC_SCENARIO_DUPLICATE_CREATE)
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
                    else if (dynamic_channel_scenario == DVC_SCENARIO_DISPLAY_CONTROL_ACCEPT_LAYOUT)
                    {
                        if (!read_client_dynamic_create_response_fd(client, input, sizeof(input), 1004, 7) ||
                            !build_dynamic_channel_display_control_caps_packet_ex(&dvc_data, 2u, 8192u, 8192u) ||
                            !write_exact_fd(client, dvc_data.data, dvc_data.length) ||
                            !read_client_display_control_layout_fd(client, input, sizeof(input), 1004, 7, 2u, 1440u, 600u) ||
                            !read_client_display_control_layout_fd(client, input, sizeof(input), 1004, 7, 1u, 1024u, 768u))
                        {
                            _exit(5);
                        }
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_ECHO_VALIDATE)
                    {
                        static const uint8_t echo_request[] = {'e', 'f', 'g', 'h'};

                        if (!build_dynamic_channel_data_packet(&dvc_data) ||
                            !write_exact_fd(client, dvc_data.data, dvc_data.length) ||
                            !read_echo_response_fd(client,
                                                   input,
                                                   sizeof(input),
                                                   1004,
                                                   7,
                                                   echo_request,
                                                   sizeof(echo_request)) ||
                            !build_dynamic_channel_close_packet(&dvc_close) ||
                            !write_exact_fd(client, dvc_close.data, dvc_close.length))
                        {
                            _exit(5);
                        }
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_ECHO_PING)
                    {
                        static const uint8_t echo_ping[] = {'p', 'i', 'n', 'g'};

                        if (!read_echo_response_fd(client,
                                                   input,
                                                   sizeof(input),
                                                   1004,
                                                   7,
                                                   echo_ping,
                                                   sizeof(echo_ping)) ||
                            !build_dynamic_channel_data_payload_packet(&dvc_data,
                                                                       echo_ping,
                                                                       sizeof(echo_ping)) ||
                            !write_exact_fd(client, dvc_data.data, dvc_data.length) ||
                            !build_dynamic_channel_close_packet(&dvc_close) ||
                            !write_exact_fd(client, dvc_close.data, dvc_close.length))
                        {
                            _exit(5);
                        }
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_ECHO_TIMEOUT)
                    {
                        static const uint8_t echo_ping[] = {'t', 'i', 'm', 'e'};

                        if (!read_echo_response_fd(client,
                                                   input,
                                                   sizeof(input),
                                                   1004,
                                                   7,
                                                   echo_ping,
                                                   sizeof(echo_ping)))
                        {
                            _exit(5);
                        }
                    }
                    else if (dynamic_channel_scenario == DVC_SCENARIO_ECHO_LATE_RESPONSE)
                    {
                        static const uint8_t echo_ping[] = {'l', 'a', 't', 'e'};

                        if (!read_echo_response_fd(client,
                                                   input,
                                                   sizeof(input),
                                                   1004,
                                                   7,
                                                   echo_ping,
                                                   sizeof(echo_ping)))
                        {
                            _exit(5);
                        }
                        test_sleep_ms(80u);
                        if (!build_dynamic_channel_data_payload_packet(&dvc_data,
                                                                       echo_ping,
                                                                       sizeof(echo_ping)) ||
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
            if (dynamic_channel_scenario == DVC_SCENARIO_GEOMETRY_TRACKING_RUNTIME)
            {
                ssize_t got = 0;

                do
                {
                    got = read(client, input, sizeof(input));
                } while (got > 0 || (got < 0 && errno == EINTR));
                if (got < 0)
                    _exit(5);
            }
            if (handshake_scenario ==
                HANDSHAKE_SCENARIO_GRACEFUL_IDLE_EOF)
            {
                ssize_t got = 0;

                if (shutdown(client, SHUT_WR) != 0)
                    _exit(5);
                do
                {
                    got = read(client, input, sizeof(input));
                } while (got > 0 || (got < 0 && errno == EINTR));
                if (got < 0)
                    _exit(5);
            }
            else
            {
                ts.tv_sec = 1;
                ts.tv_nsec = 0;
                (void)nanosleep(&ts, NULL);
            }
            close(client);
            rdp_buffer_free(&error_update);
            rdp_buffer_free(&static_last);
            rdp_buffer_free(&static_first);
            rdp_buffer_free(&multiparty_static);
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
            EVP_PKEY_free(license_private_key);
            rdp_license_crypto_context_clear(&license_crypto);
            rdp_buffer_free(&license_certificate);
            rdp_buffer_free(&license_challenge);
            rdp_buffer_free(&license_alert);
            rdp_buffer_free(&license_new);
            rdp_buffer_free(&license_request);
            rdp_buffer_free(&mcs_response);
        }
        close(fd);
        _exit(0);
    }

    close(fd);
    return 1;
}

int start_handshake_server_multi(uint16_t* port,
                                        pid_t* child_pid,
                                        int encrypted,
                                        uint32_t error_info,
                                        int extra_static_channel,
                                        int client_dynamic_channel_open_response,
                                        int connection_count,
                                        int dynamic_channel_scenario,
                                        int license_scenario,
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
                                       license_scenario,
                                       clipboard_scenario,
                                       HANDSHAKE_SCENARIO_NORMAL);
}

int start_activation_stalling_server(uint16_t* port, pid_t* child_pid)
{
    return start_handshake_server_full(port,
                                       child_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_NORMAL,
                                       GDI_SCENARIO_NORMAL,
                                       LICENSE_SCENARIO_NONE,
                                       CLIPBOARD_SCENARIO_NONE,
                                       HANDSHAKE_SCENARIO_STALL_ACTIVATION);
}

int start_idle_eof_server(uint16_t* port, pid_t* child_pid)
{
    return start_handshake_server_full(port,
                                       child_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_NORMAL,
                                       GDI_SCENARIO_NORMAL,
                                       LICENSE_SCENARIO_NONE,
                                       CLIPBOARD_SCENARIO_NONE,
                                       HANDSHAKE_SCENARIO_GRACEFUL_IDLE_EOF);
}

int start_handshake_server_ex(uint16_t* port,
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

int start_handshake_server(uint16_t* port, pid_t* child_pid, int encrypted, uint32_t error_info)
{
    return start_handshake_server_ex(port, child_pid, encrypted, error_info, 0, 0);
}

int test_standard_security_available(void)
{
    rdp_standard_security_context security;
    uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    uint8_t server_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    librdp_status status = LIBRDP_STATUS_OK;

    memset(client_random, 0x11, sizeof(client_random));
    memset(server_random, 0x22, sizeof(server_random));
    memset(&security, 0, sizeof(security));
    status = rdp_security_standard_client_init(&security,
                                               RDP_SECURITY_METHOD_128BIT,
                                               client_random,
                                               server_random);
    rdp_security_standard_clear(&security);
    return status == LIBRDP_STATUS_OK;
}
