/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer command-line parser and settings trace.
 * Invariants: parser helpers never partially register a malformed device
 * selector, and desktop size is committed only after all arguments validate.
 * Ownership: accepted clipboard path is copied into x11_cli_options; public
 * settings copy every accepted string through the librdp API.
 * Threading: startup-only code; no shared state is mutated outside the caller.
 * Trust boundary: command-line credentials and device selectors are local user
 * input and must not be traced as secrets.
 */

#include "viewer_cli.h"
#include "viewer_trace.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum x11_tls_cert_mode
{
    X11_TLS_CERT_DEFAULT = 0,
    X11_TLS_CERT_PROMPT = 1,
    X11_TLS_CERT_ACCEPT = 2
} x11_tls_cert_mode;

static const char* tls_verify_status_name(librdp_status status)
{
    return librdp_status_name(status);
}

/*
 * Ask the local user whether to trust a TLS certificate that failed strict
 * verification. This callback is synchronous because TLS negotiation is
 * synchronous; it never stores borrowed certificate pointers after returning.
 */
static librdp_tls_certificate_decision x11_tls_certificate_callback(
    const librdp_tls_certificate_info* certificate,
    void* user_data)
{
    const x11_cli_options* options = (const x11_cli_options*)user_data;
    char answer[16];

    if (!certificate || !options)
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
    fprintf(stderr, "tls_certificate host=\"%s\"\n", certificate->host ? certificate->host : "");
    fprintf(stderr, "tls_certificate subject=\"%s\"\n", certificate->subject ? certificate->subject : "");
    fprintf(stderr, "tls_certificate issuer=\"%s\"\n", certificate->issuer ? certificate->issuer : "");
    fprintf(stderr, "tls_certificate sha256=%s\n", certificate->sha256_fingerprint);
    fprintf(stderr,
            "tls_certificate verify_status=%s native_verify_result=%ld\n",
            tls_verify_status_name(certificate->verify_status),
            certificate->native_verify_result);
    if (options->tls_accept_any_cert)
    {
        fprintf(stderr, "tls_certificate decision=accepted mode=auto\n");
        return LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT;
    }
    if (!options->tls_prompt_cert)
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
    fprintf(stderr, "Accept this TLS certificate for this connection? [y/N] ");
    fflush(stderr);
    if (!fgets(answer, sizeof(answer), stdin))
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
    if (answer[0] == 'y' || answer[0] == 'Y')
    {
        fprintf(stderr, "tls_certificate decision=accepted mode=prompt\n");
        return LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT;
    }
    fprintf(stderr, "tls_certificate decision=rejected mode=prompt\n");
    return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
}

static int configure_tls_prompt_policy(librdp_settings* settings,
                                       x11_cli_options* options,
                                       x11_tls_cert_mode mode)
{
    librdp_tls_policy policy;

    if (!settings || !options)
        return 0;
    if (mode == X11_TLS_CERT_PROMPT)
    {
        options->tls_prompt_cert = 1;
        options->tls_accept_any_cert = 0;
    }
    else if (mode == X11_TLS_CERT_ACCEPT)
    {
        options->tls_prompt_cert = 0;
        options->tls_accept_any_cert = 1;
    }
    else
        return 0;
    if (librdp_tls_policy_init(&policy) != LIBRDP_STATUS_OK)
        return 0;
    policy.mode = LIBRDP_TLS_POLICY_TOFU;
    policy.use_system_store = 1;
    policy.certificate_callback = x11_tls_certificate_callback;
    policy.certificate_callback_user_data = options;
    return librdp_settings_set_tls_policy(settings, &policy) == LIBRDP_STATUS_OK;
}

static char* x11_cli_strdup_text(const char* text)
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

static int parse_u16(const char* text, uint16_t* value)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!text || !value)
        return 0;
    parsed = strtoul(text, &end, 10);
    if (!end || *end != '\0' || parsed == 0 || parsed > 65535ul)
        return 0;
    *value = (uint16_t)parsed;
    return 1;
}

static int parse_u32(const char* text, uint32_t* value)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!text || !value)
        return 0;
    parsed = strtoul(text, &end, 10);
    if (!end || *end != '\0' || parsed == 0 || parsed > 8192ul)
        return 0;
    *value = (uint32_t)parsed;
    return 1;
}

static int parse_security(const char* text, librdp_security_mode* mode)
{
    if (!text || !mode)
        return 0;
    if (strcmp(text, "auto") == 0)
        *mode = LIBRDP_SECURITY_AUTO;
    else if (strcmp(text, "rdp") == 0)
        *mode = LIBRDP_SECURITY_STANDARD;
    else if (strcmp(text, "tls") == 0)
        *mode = LIBRDP_SECURITY_TLS;
    else if (strcmp(text, "nla") == 0)
        *mode = LIBRDP_SECURITY_NLA;
    else
        return 0;
    return 1;
}

static int add_drive_arg(librdp_settings* settings, const char* text)
{
    const char* separator = NULL;
    char name[8];
    size_t name_len = 0;

    if (!settings || !text)
        return 0;
    separator = strchr(text, '=');
    if (!separator || separator == text || separator[1] == '\0')
        return 0;
    name_len = (size_t)(separator - text);
    if (name_len >= sizeof(name))
        return 0;
    memcpy(name, text, name_len);
    name[name_len] = '\0';
    return librdp_settings_add_drive(settings, name, separator + 1) == LIBRDP_STATUS_OK;
}

static int add_port_arg(librdp_settings* settings, const char* text, int serial)
{
    const char* separator = NULL;
    char name[8];
    size_t name_len = 0;

    if (!settings || !text)
        return 0;
    separator = strchr(text, '=');
    if (!separator || separator == text || separator[1] == '\0')
        return 0;
    name_len = (size_t)(separator - text);
    if (name_len >= sizeof(name))
        return 0;
    memcpy(name, text, name_len);
    name[name_len] = '\0';
    if (serial)
        return librdp_settings_add_serial_port(settings, name, separator + 1) == LIBRDP_STATUS_OK;
    return librdp_settings_add_parallel_port(settings, name, separator + 1) == LIBRDP_STATUS_OK;
}

static int add_printer_arg(librdp_settings* settings, const char* text)
{
    const char* first = NULL;
    const char* second = NULL;
    char name[128];
    char driver[128];
    size_t name_len = 0;
    size_t driver_len = 0;

    if (!settings || !text)
        return 0;
    first = strchr(text, '=');
    if (!first || first == text || first[1] == '\0')
        return 0;
    second = strchr(first + 1, '=');
    if (!second || second == first + 1 || second[1] == '\0')
        return 0;
    name_len = (size_t)(first - text);
    driver_len = (size_t)(second - first - 1);
    if (name_len >= sizeof(name) || driver_len >= sizeof(driver))
        return 0;
    memcpy(name, text, name_len);
    name[name_len] = '\0';
    memcpy(driver, first + 1, driver_len);
    driver[driver_len] = '\0';
    return librdp_settings_add_printer(settings, name, driver, second + 1) == LIBRDP_STATUS_OK;
}

static const char* value_after_prefix(const char* text, const char* prefix)
{
    const size_t prefix_len = prefix ? strlen(prefix) : 0;

    if (!text || !prefix)
        return NULL;
    if (strncmp(text, prefix, prefix_len) != 0)
        return NULL;
    if (text[prefix_len] == '\0')
        return NULL;
    return text + prefix_len;
}

static int add_camera_arg(librdp_settings* settings, const char* text)
{
    const char* value = NULL;
    size_t i = 0;

    if (!settings || !text)
        return 0;
    value = value_after_prefix(text, "device=");
    if (!value)
        value = text;
    if (strncmp(value, "/dev/video", 10u) != 0 || value[10] == '\0')
        return 0;
    for (i = 10u; value[i] != '\0'; i++)
    {
        if (value[i] < '0' || value[i] > '9')
            return 0;
    }
    return librdp_settings_enable_feature(settings, LIBRDP_FEATURE_CAMERA, 1) == LIBRDP_STATUS_OK &&
           librdp_settings_add_camera(settings, value) == LIBRDP_STATUS_OK;
}

static int add_smartcard_arg(librdp_settings* settings, const char* text)
{
    const char* value = text && text[0] != '\0' ? text : "pcsc";

    return settings &&
           librdp_settings_enable_feature(settings, LIBRDP_FEATURE_SMARTCARD, 1) == LIBRDP_STATUS_OK &&
           librdp_settings_add_smartcard(settings, value) == LIBRDP_STATUS_OK;
}

static int add_usb_arg(librdp_settings* settings, const char* text)
{
    return settings && text && text[0] != '\0' &&
           librdp_settings_enable_feature(settings, LIBRDP_FEATURE_USB, 1) == LIBRDP_STATUS_OK &&
           librdp_settings_add_usb_device(settings, text) == LIBRDP_STATUS_OK;
}

static int add_webauthn_arg(librdp_settings* settings, const char* text)
{
    const char* value = text && text[0] != '\0' ? text : "fido2";

    return settings &&
           librdp_settings_enable_feature(settings, LIBRDP_FEATURE_WEBAUTHN, 1) == LIBRDP_STATUS_OK &&
           librdp_settings_set_webauthn_provider(settings, value) == LIBRDP_STATUS_OK;
}

static int add_webauthn_rp_id_arg(librdp_settings* settings, const char* text)
{
    return settings && text && text[0] != '\0' &&
           librdp_settings_add_webauthn_rp_id(settings, text) == LIBRDP_STATUS_OK;
}

static int add_rail_arg(librdp_settings* settings, const char* text)
{
    const char* value = NULL;

    if (!settings || !text)
        return 0;
    value = value_after_prefix(text, "app=");
    if (!value)
        value = text;
    return librdp_settings_enable_feature(settings, LIBRDP_FEATURE_RAIL, 1) == LIBRDP_STATUS_OK &&
           librdp_settings_add_rail_app(settings, value) == LIBRDP_STATUS_OK;
}

static int set_echo_arg(librdp_settings* settings, const char* text)
{
    (void)text;
    return settings &&
           librdp_settings_enable_feature(settings, LIBRDP_FEATURE_ECHO, 1) == LIBRDP_STATUS_OK;
}

static int require_value(int argc, int* index)
{
    if (*index + 1 >= argc)
        return 0;
    (*index)++;
    return 1;
}

static const char* optional_value(int argc, int* index, char** argv)
{
    if (!index || !argv || *index + 1 >= argc)
        return NULL;
    if (strncmp(argv[*index + 1], "--", 2) == 0)
        return NULL;
    (*index)++;
    return argv[*index];
}

const char* x11_cli_usage(void)
{
    return "usage: %s --target host [--port port] [--user name] [--password value] [--domain name] [--width px] [--height px] [--security auto|rdp|tls|nla] [--tls-prompt-cert] [--tls-accept-any-cert] [--drive name=path] [--serial name=path] [--parallel name=path] [--printer name=driver=path] [--clipboard-file path] [--audio-output [device=name]] [--audio-input [device=name]] [--video file=path] [--camera device=/dev/videoN] [--smartcard [pcsc|vsmartcard=path]] [--usb vid:pid|bus:dev] [--pnp] [--webauthn [fido2|fido2=/dev/hidrawN|mock|mock=path]] [--webauthn-rp-id id] [--rail app=path] [--cr2] [--echo] [--telemetry] [--multitransport]\n";
}

void x11_cli_options_free(x11_cli_options* options)
{
    if (!options)
        return;
    free(options->clipboard_file_path);
    options->clipboard_file_path = NULL;
}

/*
 * Parse startup arguments into public settings. The caller receives only the
 * local viewer options that cannot live inside settings, such as a staged local
 * clipboard file path.
 */
int x11_cli_configure(librdp_settings* settings, x11_cli_options* options, int argc, char** argv)
{
    int i = 1;
    uint32_t width = librdp_settings_width(settings);
    uint32_t height = librdp_settings_height(settings);

    if (!settings || !options)
        return 0;
    while (i < argc)
    {
        if (strcmp(argv[i], "--target") == 0)
        {
            if (!require_value(argc, &i) || librdp_settings_set_target(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--user") == 0)
        {
            if (!require_value(argc, &i) || librdp_settings_set_username(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--password") == 0)
        {
            if (!require_value(argc, &i) || librdp_settings_set_password(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--domain") == 0)
        {
            if (!require_value(argc, &i) || librdp_settings_set_domain(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--port") == 0)
        {
            uint16_t port = 0;
            if (!require_value(argc, &i) || !parse_u16(argv[i], &port) ||
                librdp_settings_set_port(settings, port) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--width") == 0)
        {
            if (!require_value(argc, &i) || !parse_u32(argv[i], &width))
                return 0;
        }
        else if (strcmp(argv[i], "--height") == 0)
        {
            if (!require_value(argc, &i) || !parse_u32(argv[i], &height))
                return 0;
        }
        else if (strcmp(argv[i], "--security") == 0)
        {
            librdp_security_mode mode = LIBRDP_SECURITY_AUTO;
            if (!require_value(argc, &i) || !parse_security(argv[i], &mode) ||
                librdp_settings_set_security_mode(settings, mode) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--tls-prompt-cert") == 0)
        {
            if (!configure_tls_prompt_policy(settings, options, X11_TLS_CERT_PROMPT))
                return 0;
        }
        else if (strcmp(argv[i], "--tls-accept-any-cert") == 0)
        {
            if (!configure_tls_prompt_policy(settings, options, X11_TLS_CERT_ACCEPT))
                return 0;
        }
        else if (strcmp(argv[i], "--drive") == 0)
        {
            if (!require_value(argc, &i) || !add_drive_arg(settings, argv[i]))
                return 0;
        }
        else if (strcmp(argv[i], "--serial") == 0)
        {
            if (!require_value(argc, &i) || !add_port_arg(settings, argv[i], 1))
                return 0;
        }
        else if (strcmp(argv[i], "--parallel") == 0)
        {
            if (!require_value(argc, &i) || !add_port_arg(settings, argv[i], 0))
                return 0;
        }
        else if (strcmp(argv[i], "--printer") == 0)
        {
            if (!require_value(argc, &i) || !add_printer_arg(settings, argv[i]))
                return 0;
        }
        else if (strcmp(argv[i], "--clipboard-file") == 0)
        {
            free(options->clipboard_file_path);
            options->clipboard_file_path = NULL;
            if (!require_value(argc, &i))
                return 0;
            options->clipboard_file_path = x11_cli_strdup_text(argv[i]);
            if (!options->clipboard_file_path)
                return 0;
        }
        else if (strcmp(argv[i], "--audio-output") == 0)
        {
            const char* value = optional_value(argc, &i, argv);
            const char* device = value_after_prefix(value, "device=");

            if (!device)
                device = value ? value : "pipewire";
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_OUTPUT, 1) != LIBRDP_STATUS_OK ||
                librdp_settings_set_audio_output_device(settings, device) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--audio-input") == 0)
        {
            const char* value = optional_value(argc, &i, argv);
            const char* device = value_after_prefix(value, "device=");

            if (!device)
                device = value ? value : "pipewire";
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_INPUT, 1) != LIBRDP_STATUS_OK ||
                librdp_settings_set_audio_input_device(settings, device) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--video") == 0)
        {
            const char* value = NULL;
            const char* path = NULL;

            if (!require_value(argc, &i))
                return 0;
            value = argv[i];
            path = value_after_prefix(value, "file=");
            if (!path)
                path = value;
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_VIDEO, 1) != LIBRDP_STATUS_OK)
                return 0;
            if (librdp_settings_set_video_output_path(settings, path) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--camera") == 0)
        {
            if (!require_value(argc, &i) || !add_camera_arg(settings, argv[i]))
                return 0;
        }
        else if (strcmp(argv[i], "--smartcard") == 0)
        {
            const char* value = optional_value(argc, &i, argv);

            if (!add_smartcard_arg(settings, value))
                return 0;
        }
        else if (strcmp(argv[i], "--usb") == 0)
        {
            if (!require_value(argc, &i) || !add_usb_arg(settings, argv[i]))
                return 0;
        }
        else if (strcmp(argv[i], "--pnp") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_PNP, 1) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--webauthn") == 0)
        {
            const char* value = optional_value(argc, &i, argv);

            if (!add_webauthn_arg(settings, value))
                return 0;
        }
        else if (strcmp(argv[i], "--webauthn-rp-id") == 0)
        {
            if (!require_value(argc, &i) || !add_webauthn_rp_id_arg(settings, argv[i]))
                return 0;
        }
        else if (strcmp(argv[i], "--rail") == 0)
        {
            if (!require_value(argc, &i) || !add_rail_arg(settings, argv[i]))
                return 0;
        }
        else if (strcmp(argv[i], "--cr2") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_CR2, 1) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--echo") == 0)
        {
            if (!set_echo_arg(settings, NULL))
                return 0;
        }
        else if (strcmp(argv[i], "--telemetry") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_TELEMETRY, 1) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--multitransport") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_MULTITRANSPORT, 1) != LIBRDP_STATUS_OK)
                return 0;
        }
        else
        {
            return 0;
        }
        i++;
    }

    return librdp_settings_enable_feature(settings, LIBRDP_FEATURE_DISPLAY_CONTROL, 1) == LIBRDP_STATUS_OK &&
           librdp_settings_set_desktop_size(settings, width, height) == LIBRDP_STATUS_OK &&
           librdp_settings_target(settings) != NULL;
}

void x11_cli_trace_settings(const librdp_settings* settings)
{
    uint32_t i = 0;

    if (!settings)
        return;

    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.viewer.features",
                    "audio_output=%u audio_input=%u video=%u camera=%u smartcard=%u usb=%u pnp=%u webauthn=%u rail=%u cr2=%u echo=%u telemetry=%u multitransport=%u display_control=%u drives=%u printers=%u pnp_devices=%u",
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_AUDIO_OUTPUT) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_AUDIO_INPUT) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_VIDEO) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_CAMERA) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_SMARTCARD) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_USB) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_PNP) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_WEBAUTHN) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_RAIL) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_CR2) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_ECHO) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_TELEMETRY) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_MULTITRANSPORT) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_DISPLAY_CONTROL) ? 1u : 0u,
                    librdp_settings_drive_count(settings),
                    librdp_settings_printer_count(settings),
                    librdp_settings_pnp_device_count(settings));
    if (librdp_settings_audio_output_device(settings))
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.audio.output.config",
                        "backend=pipewire device=\"%s\"",
                        librdp_settings_audio_output_device(settings));
    if (librdp_settings_audio_input_device(settings))
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.audio.input.config",
                        "backend=pipewire device=\"%s\"",
                        librdp_settings_audio_input_device(settings));
    if (librdp_settings_video_output_path(settings))
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.video.config",
                        "path=\"%s\"",
                        librdp_settings_video_output_path(settings));
    for (i = 0; i < librdp_settings_camera_count(settings); i++)
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.camera.config",
                        "index=%u source=\"%s\"",
                        i,
                        librdp_settings_camera_source(settings, i));
    for (i = 0; i < librdp_settings_smartcard_count(settings); i++)
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.smartcard.config",
                        "index=%u source=\"%s\"",
                        i,
                        librdp_settings_smartcard_source(settings, i));
    for (i = 0; i < librdp_settings_usb_device_count(settings); i++)
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.usb.config",
                        "index=%u selector=\"%s\"",
                        i,
                        librdp_settings_usb_device_selector(settings, i));
    if (librdp_settings_webauthn_provider(settings))
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.webauthn.config",
                        "provider=\"%s\" rp_id_count=%u",
                        librdp_settings_webauthn_provider(settings),
                        librdp_settings_webauthn_rp_id_count(settings));
    for (i = 0; i < librdp_settings_rail_app_count(settings); i++)
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.rail.config",
                        "index=%u app=\"%s\"",
                        i,
                        librdp_settings_rail_app(settings, i));
}
