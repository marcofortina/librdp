/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa viewer command-line policy implementation.
 * Invariants: connection and feature syntax remains identical to the X11
 * viewer except for native media defaults and the documented TLS alias.
 * Ownership: argv and streams remain caller-owned; public settings copy every
 * value needed beyond startup.
 * Threading: startup-only and serialized before AppKit session dispatch.
 * Trust boundary: malformed selectors and unsupported camera sources fail
 * before any native device is opened.
 */

#include "cocoa_cli.h"
#include "cocoa_media.h"

void cocoa_viewer_usage(FILE* stream, const char* program)
{
    if (!stream || !program)
        return;
    fprintf(stream,
            "usage: %s --target host [--port port] [--user name] [--password value] "
            "[--domain name] [--width px] [--height px] [--security auto|rdp|tls|nla] "
            "[--tls-prompt-cert] [--tls-accept-any-cert] [--accept-tls-certificate] "
            "[--gateway url] [--gateway-mode http-connect|rdg-http] "
            "[--gateway-user name] [--gateway-password value] [--gateway-domain name] "
            "[--gateway-timeout ms] [--gateway-no-session-credentials] [--drive name=path] "
            "[--serial name=path] [--parallel name=path] [--printer name=driver=path] "
            "[--audio-output [device=name]] [--audio-input [device=name]] [--video file=path] "
            "[--camera device=default|device=id|file=path] [--smartcard [pcsc|source]] "
            "[--usb vid:pid|bus:dev] [--pnp] [--webauthn [fido2|mock|provider]] "
            "[--webauthn-rp-id id] [--rail app=path] [--cr2] [--echo] [--telemetry] "
            "[--multitransport]\n",
            program);
}

static const char* cocoa_viewer_camera_normalizer(const char* source,
                                                  void* user_data)
{
    (void)user_data;
    return cocoa_camera_source_allowed(source) ? source : NULL;
}

int cocoa_viewer_configure_settings(librdp_settings* settings,
                                    cocoa_viewer_options* options,
                                    int argc,
                                    char** argv)
{
    client_option_policy policy;

    if (!settings || !options)
        return 0;
    client_option_policy_init(&policy);
    policy.default_audio_output_device = "coreaudio";
    policy.default_audio_input_device = "coreaudio";
    policy.normalize_camera_source = cocoa_viewer_camera_normalizer;
    policy.error_stream = stderr;
    policy.allow_help = 1;
    policy.allow_tls_accept_alias = 1;
    policy.rail_requires_app_prefix = 1;
    return client_options_configure(settings, options, &policy, argc, argv);
}
