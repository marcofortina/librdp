/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: opt-in public API interoperability smoke harness.
 * Coverage: connects to an endpoint described by environment variables, drives
 * activation, enables only requested optional features, and emits a JSON
 * report without secrets.
 * Bug classes: public API configuration drift, activation regressions,
 * callback lifetime issues, and optional-feature negotiation failures.
 * Determinism: without endpoint credentials the CTest is skipped; when
 * configured it performs network I/O only against the supplied endpoint.
 */

#include <librdp/librdp.h>

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define INTEROP_SKIP_RETURN_CODE 77
#define INTEROP_DEFAULT_PORT 3389u
#define INTEROP_DEFAULT_WIDTH 1024u
#define INTEROP_DEFAULT_HEIGHT 768u
#define INTEROP_DEFAULT_RUN_MS 3000u

typedef struct interop_report
{
    const char* status;
    const char* target;
    const char* security;
    const char* features;
    const char* missing;
    const char* failure;
    uint16_t port;
    uint32_t width;
    uint32_t height;
    uint32_t run_ms;
    librdp_status connect_status;
    librdp_status run_status;
    librdp_session_state final_state;
    uint32_t state_events;
    uint32_t surface_events;
    uint32_t pointer_events;
    uint32_t error_events;
    uint32_t channel_open_events;
    uint32_t channel_data_events;
    uint32_t channel_close_events;
    uint32_t audio_output_events;
    uint32_t audio_input_events;
    uint32_t video_capture_events;
    uint32_t clipboard_events;
    int activated;
} interop_report;

static const char* interop_getenv_nonempty(const char* name)
{
    const char* value = getenv(name);

    return (value && value[0] != '\0') ? value : NULL;
}

static uint32_t interop_run_seconds(uint32_t run_ms)
{
    uint32_t seconds = (run_ms + 999u) / 1000u;

    return seconds ? seconds : 1u;
}

static uint32_t interop_parse_u32_env(const char* name, uint32_t fallback, uint32_t min_value, uint32_t max_value)
{
    const char* value = interop_getenv_nonempty(name);
    char* end = NULL;
    unsigned long parsed = 0;

    if (!value)
        return fallback;
    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed < min_value || parsed > max_value)
        return fallback;
    return (uint32_t)parsed;
}

static uint16_t interop_parse_port(void)
{
    return (uint16_t)interop_parse_u32_env("LIBRDP_INTEROP_PORT", INTEROP_DEFAULT_PORT, 1u, 65535u);
}

static librdp_security_mode interop_parse_security(const char* value, int* ok)
{
    if (!value || strcmp(value, "auto") == 0)
    {
        *ok = 1;
        return LIBRDP_SECURITY_AUTO;
    }
    if (strcmp(value, "standard") == 0)
    {
        *ok = 1;
        return LIBRDP_SECURITY_STANDARD;
    }
    if (strcmp(value, "tls") == 0)
    {
        *ok = 1;
        return LIBRDP_SECURITY_TLS;
    }
    if (strcmp(value, "nla") == 0)
    {
        *ok = 1;
        return LIBRDP_SECURITY_NLA;
    }

    *ok = 0;
    return LIBRDP_SECURITY_AUTO;
}

static const char* interop_security_name(const char* requested)
{
    return requested ? requested : "auto";
}

static char* interop_copy_string(const char* value)
{
    size_t length = value ? strlen(value) : 0;
    char* copy = (char*)malloc(length + 1u);

    if (!copy)
        return NULL;
    if (length > 0)
        memcpy(copy, value, length);
    copy[length] = '\0';
    return copy;
}

static char* interop_trim_token(char* token)
{
    char* end = NULL;

    while (*token && isspace((unsigned char)*token))
        token++;
    end = token + strlen(token);
    while (end > token && isspace((unsigned char)end[-1]))
        end--;
    *end = '\0';
    return token;
}

/*
 * Feature configurator: maps one requested smoke token to public settings
 * calls. Failure policy is strict so typos or missing explicit RAIL command
 * cannot silently produce a weaker smoke.
 */
static librdp_status interop_enable_feature(librdp_settings* settings, const char* feature)
{
    if (strcmp(feature, "audio-output") == 0)
    {
        const char* device = interop_getenv_nonempty("LIBRDP_INTEROP_AUDIO_OUTPUT");

        if (!device)
            device = "default";
        if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_OUTPUT, 1) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        return librdp_settings_set_audio_output_device(settings, device);
    }
    if (strcmp(feature, "audio-input") == 0)
    {
        const char* device = interop_getenv_nonempty("LIBRDP_INTEROP_AUDIO_INPUT");

        if (!device)
            device = "default";
        if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_INPUT, 1) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        return librdp_settings_set_audio_input_device(settings, device);
    }
    if (strcmp(feature, "video") == 0)
    {
        const char* path = interop_getenv_nonempty("LIBRDP_INTEROP_VIDEO_PATH");

        if (!path)
            path = "/tmp/librdp-interop-video.bin";
        if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_VIDEO, 1) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        return librdp_settings_set_video_output_path(settings, path);
    }
    if (strcmp(feature, "camera") == 0)
    {
        const char* source = interop_getenv_nonempty("LIBRDP_INTEROP_CAMERA");

        if (!source)
            source = "mock";
        if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_CAMERA, 1) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        return librdp_settings_add_camera(settings, source);
    }
    if (strcmp(feature, "smartcard") == 0)
    {
        const char* source = interop_getenv_nonempty("LIBRDP_INTEROP_SMARTCARD");

        if (!source)
            source = "mock";
        if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_SMARTCARD, 1) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        return librdp_settings_add_smartcard(settings, source);
    }
    if (strcmp(feature, "usb") == 0)
    {
        const char* selector = interop_getenv_nonempty("LIBRDP_INTEROP_USB");

        if (!selector)
            selector = "vid:0000:0000";
        if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_USB, 1) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        return librdp_settings_add_usb_device(settings, selector);
    }
    if (strcmp(feature, "pnp") == 0)
    {
        if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_PNP, 1) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        return librdp_settings_add_pnp_device(settings,
                                             "LIBRDP\\INTEROP",
                                             "LIBRDP\\INTEROP",
                                             "librdp interop device",
                                             LIBRDP_PNP_DEVICE_CAP_REMOVABLE);
    }
    if (strcmp(feature, "webauthn") == 0)
    {
        const char* provider = interop_getenv_nonempty("LIBRDP_INTEROP_WEBAUTHN");

        if (!provider)
            provider = "mock";
        if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_WEBAUTHN, 1) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        return librdp_settings_set_webauthn_provider(settings, provider);
    }
    if (strcmp(feature, "rail") == 0)
    {
        const char* app = interop_getenv_nonempty("LIBRDP_INTEROP_RAIL_APP");

        if (!app)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_RAIL, 1) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        return librdp_settings_add_rail_app(settings, app);
    }
    if (strcmp(feature, "cr2") == 0)
        return librdp_settings_enable_feature(settings, LIBRDP_FEATURE_CR2, 1);
    if (strcmp(feature, "echo") == 0)
        return librdp_settings_enable_feature(settings, LIBRDP_FEATURE_ECHO, 1);
    if (strcmp(feature, "telemetry") == 0)
        return librdp_settings_enable_feature(settings, LIBRDP_FEATURE_TELEMETRY, 1);
    if (strcmp(feature, "multitransport") == 0)
        return librdp_settings_enable_feature(settings, LIBRDP_FEATURE_MULTITRANSPORT, 1);

    return LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status interop_configure_features(librdp_settings* settings, const char* features)
{
    char* copy = NULL;
    char* token = NULL;
    char* cursor = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!features || features[0] == '\0')
        return LIBRDP_STATUS_OK;
    copy = interop_copy_string(features);
    if (!copy)
        return LIBRDP_STATUS_NO_MEMORY;
    cursor = copy;
    while (cursor)
    {
        char* comma = strchr(cursor, ',');

        if (comma)
            *comma = '\0';
        token = cursor;
        token = interop_trim_token(token);
        if (token[0] == '\0')
        {
            cursor = comma ? comma + 1 : NULL;
            continue;
        }
        status = interop_enable_feature(settings, token);
        if (status != LIBRDP_STATUS_OK)
            break;
        cursor = comma ? comma + 1 : NULL;
    }
    free(copy);
    return status;
}

/*
 * Event collector: stores only counters and state booleans. It deliberately
 * avoids copying event payloads so borrowed buffers and sensitive data cannot
 * leak into the JSON report.
 */
static void interop_event_callback(librdp_session* session, const librdp_event* event, void* user_data)
{
    interop_report* report = (interop_report*)user_data;

    (void)session;
    if (!report || !event)
        return;
    switch (event->type)
    {
        case LIBRDP_EVENT_STATE_CHANGED:
            report->state_events++;
            if (event->data.state.new_state == LIBRDP_SESSION_ACTIVE)
                report->activated = 1;
            break;
        case LIBRDP_EVENT_SURFACE_INVALIDATED:
            report->surface_events++;
            break;
        case LIBRDP_EVENT_POINTER:
            report->pointer_events++;
            break;
        case LIBRDP_EVENT_ERROR:
            report->error_events++;
            break;
        case LIBRDP_EVENT_CHANNEL_OPEN:
            report->channel_open_events++;
            break;
        case LIBRDP_EVENT_CHANNEL_DATA:
            report->channel_data_events++;
            break;
        case LIBRDP_EVENT_CHANNEL_CLOSE:
            report->channel_close_events++;
            break;
        case LIBRDP_EVENT_AUDIO_OUTPUT_FORMATS:
        case LIBRDP_EVENT_AUDIO_OUTPUT_DATA:
        case LIBRDP_EVENT_AUDIO_OUTPUT_CLOSE:
            report->audio_output_events++;
            break;
        case LIBRDP_EVENT_AUDIO_INPUT_FORMATS:
        case LIBRDP_EVENT_AUDIO_INPUT_OPEN:
            report->audio_input_events++;
            break;
        case LIBRDP_EVENT_VIDEO_CAPTURE_OPEN:
        case LIBRDP_EVENT_VIDEO_CAPTURE_SAMPLE_REQUEST:
        case LIBRDP_EVENT_VIDEO_CAPTURE_CLOSE:
            report->video_capture_events++;
            break;
        case LIBRDP_EVENT_CLIPBOARD_FORMATS:
        case LIBRDP_EVENT_CLIPBOARD_DATA:
        case LIBRDP_EVENT_CLIPBOARD_REQUEST:
        case LIBRDP_EVENT_CLIPBOARD_FILE_CONTENTS:
            report->clipboard_events++;
            break;
        default:
            break;
    }
}

static void interop_json_string(FILE* output, const char* value)
{
    const unsigned char* p = (const unsigned char*)(value ? value : "");

    fputc('"', output);
    while (*p)
    {
        if (*p == '"' || *p == '\\')
            fprintf(output, "\\%c", *p);
        else if (*p == '\n')
            fputs("\\n", output);
        else if (*p == '\r')
            fputs("\\r", output);
        else if (*p == '\t')
            fputs("\\t", output);
        else if (*p < 0x20u)
            fprintf(output, "\\u%04x", (unsigned)*p);
        else
            fputc(*p, output);
        p++;
    }
    fputc('"', output);
}

static const char* interop_state_name(librdp_session_state state)
{
    switch (state)
    {
        case LIBRDP_SESSION_IDLE:
            return "idle";
        case LIBRDP_SESSION_CONNECTING:
            return "connecting";
        case LIBRDP_SESSION_CONNECTED:
            return "connected";
        case LIBRDP_SESSION_ACTIVE:
            return "active";
        case LIBRDP_SESSION_CLOSING:
            return "closing";
        case LIBRDP_SESSION_CLOSED:
            return "closed";
        case LIBRDP_SESSION_FAILED:
            return "failed";
        default:
            return "unknown";
    }
}

static void interop_write_report(FILE* output, const interop_report* report)
{
    fprintf(output, "{\n  \"status\": ");
    interop_json_string(output, report->status);
    fprintf(output, ",\n  \"target\": ");
    interop_json_string(output, report->target);
    fprintf(output, ",\n  \"port\": %u,\n  \"security\": ", (unsigned)report->port);
    interop_json_string(output, report->security);
    fprintf(output, ",\n  \"features\": ");
    interop_json_string(output, report->features);
    fprintf(output, ",\n  \"dimensions\": {\"width\": %u, \"height\": %u},", report->width, report->height);
    fprintf(output, "\n  \"run_ms\": %u,\n  \"missing\": ", report->run_ms);
    interop_json_string(output, report->missing);
    fprintf(output, ",\n  \"failure\": ");
    interop_json_string(output, report->failure);
    fprintf(output, ",\n  \"connect_status\": ");
    interop_json_string(output, librdp_status_string(report->connect_status));
    fprintf(output, ",\n  \"run_status\": ");
    interop_json_string(output, librdp_status_string(report->run_status));
    fprintf(output, ",\n  \"final_state\": ");
    interop_json_string(output, interop_state_name(report->final_state));
    fprintf(output, ",\n  \"activated\": %s,\n  \"events\": {", report->activated ? "true" : "false");
    fprintf(output,
            "\"state\": %u, \"surface\": %u, \"pointer\": %u, \"error\": %u, "
            "\"channel_open\": %u, \"channel_data\": %u, \"channel_close\": %u, "
            "\"audio_output\": %u, \"audio_input\": %u, \"video_capture\": %u, \"clipboard\": %u",
            report->state_events,
            report->surface_events,
            report->pointer_events,
            report->error_events,
            report->channel_open_events,
            report->channel_data_events,
            report->channel_close_events,
            report->audio_output_events,
            report->audio_input_events,
            report->video_capture_events,
            report->clipboard_events);
    fprintf(output, "}\n}\n");
}

static void interop_emit_report(const interop_report* report)
{
    const char* path = interop_getenv_nonempty("LIBRDP_INTEROP_REPORT");
    FILE* output = stdout;

    if (path)
        output = fopen(path, "wb");
    if (!output)
        output = stdout;
    interop_write_report(output, report);
    if (output != stdout)
        fclose(output);
}

static int interop_skip_missing(interop_report* report)
{
    const char* target = interop_getenv_nonempty("LIBRDP_INTEROP_TARGET");
    const char* user = interop_getenv_nonempty("LIBRDP_INTEROP_USER");
    const char* password = interop_getenv_nonempty("LIBRDP_INTEROP_PASSWORD");

    if (target && user && password)
        return 0;
    report->status = "skipped";
    report->target = target ? target : "";
    report->missing = !target ? "LIBRDP_INTEROP_TARGET" :
                      (!user ? "LIBRDP_INTEROP_USER" : "LIBRDP_INTEROP_PASSWORD");
    report->failure = "missing required interop environment";
    interop_emit_report(report);
    return INTEROP_SKIP_RETURN_CODE;
}

/*
 * Session runner: connects and drives the public session loop until ACTIVE is
 * reached or the configured time budget expires. Failure policy returns a
 * non-zero process status for configured endpoints that do not complete.
 */
static int interop_run_session(interop_report* report,
                               librdp_session* session,
                               uint32_t run_ms)
{
    time_t start = 0;
    uint32_t run_seconds = interop_run_seconds(run_ms);

    report->connect_status = librdp_session_connect(session);
    if (report->connect_status != LIBRDP_STATUS_OK)
    {
        report->status = "failed";
        report->failure = "connect failed";
        report->final_state = librdp_session_get_state(session);
        return 1;
    }

    start = time(NULL);
    do
    {
        report->run_status = librdp_session_run_once(session, 50);
        report->final_state = librdp_session_get_state(session);
        if (report->run_status != LIBRDP_STATUS_OK)
            break;
        if (report->final_state == LIBRDP_SESSION_ACTIVE)
            report->activated = 1;
    } while (time(NULL) < start + (time_t)run_seconds);

    if (report->run_status != LIBRDP_STATUS_OK)
    {
        report->status = "failed";
        report->failure = "session loop failed";
        return 1;
    }
    if (!report->activated)
    {
        report->status = "failed";
        report->failure = "activation not reached";
        return 1;
    }

    report->status = "passed";
    report->failure = "";
    return 0;
}

int main(void)
{
    const char* target = interop_getenv_nonempty("LIBRDP_INTEROP_TARGET");
    const char* user = interop_getenv_nonempty("LIBRDP_INTEROP_USER");
    const char* password = interop_getenv_nonempty("LIBRDP_INTEROP_PASSWORD");
    const char* domain = interop_getenv_nonempty("LIBRDP_INTEROP_DOMAIN");
    const char* requested_security = interop_getenv_nonempty("LIBRDP_INTEROP_SECURITY");
    const char* features = interop_getenv_nonempty("LIBRDP_INTEROP_FEATURES");
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    interop_report report;
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_security_mode security = LIBRDP_SECURITY_AUTO;
    int security_ok = 0;
    int exit_code = 1;

    memset(&report, 0, sizeof(report));
    report.status = "failed";
    report.target = target ? target : "";
    report.security = interop_security_name(requested_security);
    report.features = features ? features : "";
    report.missing = "";
    report.failure = "";
    report.port = interop_parse_port();
    report.width = interop_parse_u32_env("LIBRDP_INTEROP_WIDTH", INTEROP_DEFAULT_WIDTH, 1u, 8192u);
    report.height = interop_parse_u32_env("LIBRDP_INTEROP_HEIGHT", INTEROP_DEFAULT_HEIGHT, 1u, 8192u);
    report.run_ms = interop_parse_u32_env("LIBRDP_INTEROP_RUN_MS", INTEROP_DEFAULT_RUN_MS, 1u, 60000u);
    report.connect_status = LIBRDP_STATUS_OK;
    report.run_status = LIBRDP_STATUS_OK;
    report.final_state = LIBRDP_SESSION_IDLE;

    exit_code = interop_skip_missing(&report);
    if (exit_code != 0)
        return exit_code;

    security = interop_parse_security(requested_security, &security_ok);
    if (!security_ok)
    {
        report.failure = "invalid security mode";
        interop_emit_report(&report);
        return 1;
    }

    settings = librdp_settings_new();
    if (!settings)
    {
        report.failure = "settings allocation failed";
        interop_emit_report(&report);
        return 1;
    }

    status = librdp_settings_set_target(settings, target);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_settings_set_username(settings, user);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_settings_set_password(settings, password);
    if (status == LIBRDP_STATUS_OK && domain)
        status = librdp_settings_set_domain(settings, domain);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_settings_set_port(settings, report.port);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_settings_set_security_mode(settings, security);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_settings_set_desktop_size(settings, report.width, report.height);
    if (status == LIBRDP_STATUS_OK)
        status = interop_configure_features(settings, features);
    if (status != LIBRDP_STATUS_OK)
    {
        report.failure = "settings configuration failed";
        report.run_status = status;
        librdp_settings_free(settings);
        interop_emit_report(&report);
        return 1;
    }

    session = librdp_session_new(settings);
    librdp_settings_free(settings);
    if (!session)
    {
        report.failure = "session allocation failed";
        interop_emit_report(&report);
        return 1;
    }

    librdp_session_set_event_callback(session, interop_event_callback, &report);
    exit_code = interop_run_session(&report, session, report.run_ms);
    report.final_state = librdp_session_get_state(session);
    (void)librdp_session_disconnect(session);
    librdp_session_free(session);
    interop_emit_report(&report);
    return exit_code;
}
