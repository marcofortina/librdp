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

#include "x11_cli.h"
#include "x11_trace.h"

#include <stdio.h>
#include <string.h>

/*
 * Normalize the Linux camera selector without opening the device. Runtime
 * probing remains in the V4L2 backend, while this boundary accepts only the
 * explicit /dev/videoN form supported by the X11 viewer.
 */
static const char* x11_cli_camera_source(const char* source, void* user_data)
{
    const char* value = source;
    size_t i = 0;

    (void)user_data;
    if (!source)
        return NULL;
    if (strncmp(source, "device=", 7u) == 0)
        value = source + 7u;
    if (strncmp(value, "/dev/video", 10u) != 0 || value[10] == '\0')
        return NULL;
    for (i = 10u; value[i] != '\0'; i++)
    {
        if (value[i] < '0' || value[i] > '9')
            return NULL;
    }
    return value;
}

const char* x11_cli_usage(void)
{
    return "usage: %s --target host [--port port] [--user name] [--password value] [--domain name] [--width px] [--height px] [--security auto|rdp|tls|nla] [--tls-prompt-cert] [--tls-accept-any-cert] [--gateway url] [--gateway-mode http-connect|rdg-http] [--gateway-user name] [--gateway-password value] [--gateway-domain name] [--gateway-timeout ms] [--gateway-no-session-credentials] [--drive name=path] [--serial name=path] [--parallel name=path] [--printer name=driver=path] [--clipboard-file path] [--audio-output [device=name]] [--audio-input [device=name]] [--video file=path] [--camera device=/dev/videoN] [--smartcard [pcsc|vsmartcard=path]] [--usb vid:pid|bus:dev] [--pnp] [--webauthn [fido2|fido2=/dev/hidrawN|mock|mock=path]] [--webauthn-rp-id id] [--rail app=path] [--cr2] [--echo] [--telemetry] [--multitransport]\n";
}

void x11_cli_options_free(x11_cli_options* options)
{
    client_options_clear(options);
}

/*
 * Parse startup arguments into public settings. The caller receives only the
 * local viewer options that cannot live inside settings, such as a staged local
 * clipboard file path.
 */
int x11_cli_configure(librdp_settings* settings, x11_cli_options* options, int argc, char** argv)
{
    client_option_policy policy;

    client_option_policy_init(&policy);
    policy.default_audio_output_device = "pipewire";
    policy.default_audio_input_device = "pipewire";
    policy.normalize_camera_source = x11_cli_camera_source;
    policy.allow_help = 1;
    policy.allow_clipboard_file = 1;
    return client_options_configure(settings, options, &policy, argc, argv);
}

/*
 * Emit startup trace for viewer-visible feature policy. The trace is useful for
 * reproducing backend and gateway setup decisions, but it deliberately omits
 * passwords and raw device payloads so command-line diagnostics do not leak
 * credentials or host data.
 */
void x11_cli_trace_settings(const librdp_settings* settings)
{
    uint32_t i = 0;
    librdp_gateway_config gateway_config;

    if (!settings)
        return;
    if (librdp_settings_get_gateway_config(settings, &gateway_config) != LIBRDP_STATUS_OK)
        memset(&gateway_config, 0, sizeof(gateway_config));

    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.viewer.features",
                    "audio_output=%u audio_input=%u video=%u camera=%u smartcard=%u usb=%u pnp=%u webauthn=%u rail=%u cr2=%u echo=%u telemetry=%u multitransport=%u display_control=%u gateway=%u drives=%u printers=%u pnp_devices=%u",
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
                    gateway_config.mode != LIBRDP_GATEWAY_DISABLED ? 1u : 0u,
                    librdp_settings_drive_count(settings),
                    librdp_settings_printer_count(settings),
                    librdp_settings_pnp_device_count(settings));
    if (gateway_config.mode != LIBRDP_GATEWAY_DISABLED)
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.gateway.config",
                        "mode=%s timeout_ms=%u use_session_credentials=%u",
                        gateway_config.mode == LIBRDP_GATEWAY_RDG_HTTP ? "rdg_http" : "http_connect",
                        gateway_config.timeout_ms,
                        gateway_config.use_session_credentials ? 1u : 0u);
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
