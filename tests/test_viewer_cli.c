/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer CLI parser regression tests.
 * Coverage: startup-only argument validation for security-sensitive feature
 * policy, without X11 or network I/O.
 * Bug classes: malformed argument acceptance, missing WebAuthn RP allowlist
 * propagation, and accidental credential or device discovery during parsing.
 * Determinism: tests use in-memory settings only and never inspect host
 * devices, environment state, or remote endpoints.
 */

#include "viewer_cli.h"

#include <librdp/librdp.h>

#include <stdio.h>
#include <string.h>

static int check_int(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr, "test_viewer_cli:%d: check failed: %s\n", line, expression);
    return 1;
}

#define CHECK(expr)                                                                                  \
    do                                                                                               \
    {                                                                                                \
        if (check_int((expr), #expr, __LINE__) != 0)                                                 \
            return 1;                                                                                \
    } while (0)

static int test_webauthn_rp_id_cli(void)
{
    char* argv[] = {
        (char*)"viewer",
        (char*)"--target",
        (char*)"127.0.0.1",
        (char*)"--webauthn",
        (char*)"mock",
        (char*)"--webauthn-rp-id",
        (char*)"login.example.com",
        (char*)"--webauthn-rp-id",
        (char*)"admin.example.com",
    };
    librdp_settings* settings = librdp_settings_new();
    x11_cli_options options;

    memset(&options, 0, sizeof(options));
    CHECK(settings != NULL);
    CHECK(x11_cli_configure(settings, &options, (int)(sizeof(argv) / sizeof(argv[0])), argv) == 1);
    CHECK(librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_WEBAUTHN));
    CHECK(strcmp(librdp_settings_webauthn_provider(settings), "mock") == 0);
    CHECK(librdp_settings_webauthn_rp_id_count(settings) == 2);
    CHECK(strcmp(librdp_settings_webauthn_rp_id(settings, 0), "login.example.com") == 0);
    CHECK(strcmp(librdp_settings_webauthn_rp_id(settings, 1), "admin.example.com") == 0);
    x11_cli_options_free(&options);
    librdp_settings_free(settings);
    return 0;
}

static int test_webauthn_rp_id_requires_value(void)
{
    char* argv[] = {
        (char*)"viewer",
        (char*)"--target",
        (char*)"127.0.0.1",
        (char*)"--webauthn-rp-id",
    };
    librdp_settings* settings = librdp_settings_new();
    x11_cli_options options;

    memset(&options, 0, sizeof(options));
    CHECK(settings != NULL);
    CHECK(x11_cli_configure(settings, &options, (int)(sizeof(argv) / sizeof(argv[0])), argv) == 0);
    CHECK(librdp_settings_webauthn_rp_id_count(settings) == 0);
    x11_cli_options_free(&options);
    librdp_settings_free(settings);
    return 0;
}

static int test_camera_cli_accepts_device_source(void)
{
    char* argv[] = {
        (char*)"viewer",
        (char*)"--target",
        (char*)"127.0.0.1",
        (char*)"--camera",
        (char*)"device=/dev/video0",
    };
    librdp_settings* settings = librdp_settings_new();
    x11_cli_options options;

    memset(&options, 0, sizeof(options));
    CHECK(settings != NULL);
    CHECK(x11_cli_configure(settings, &options, (int)(sizeof(argv) / sizeof(argv[0])), argv) == 1);
    CHECK(librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_CAMERA));
    CHECK(librdp_settings_camera_count(settings) == 1);
    CHECK(strcmp(librdp_settings_camera_source(settings, 0), "/dev/video0") == 0);
    x11_cli_options_free(&options);
    librdp_settings_free(settings);
    return 0;
}

static int test_camera_cli_rejects_file_source(void)
{
    char* argv[] = {
        (char*)"viewer",
        (char*)"--target",
        (char*)"127.0.0.1",
        (char*)"--camera",
        (char*)"file=/tmp/frame.raw",
    };
    librdp_settings* settings = librdp_settings_new();
    x11_cli_options options;

    memset(&options, 0, sizeof(options));
    CHECK(settings != NULL);
    CHECK(x11_cli_configure(settings, &options, (int)(sizeof(argv) / sizeof(argv[0])), argv) == 0);
    CHECK(!librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_CAMERA));
    CHECK(librdp_settings_camera_count(settings) == 0);
    x11_cli_options_free(&options);
    librdp_settings_free(settings);
    return 0;
}

int main(void)
{
    if (test_webauthn_rp_id_cli() != 0)
        return 1;
    if (test_webauthn_rp_id_requires_value() != 0)
        return 1;
    if (test_camera_cli_accepts_device_source() != 0)
        return 1;
    if (test_camera_cli_rejects_file_source() != 0)
        return 1;
    return 0;
}
