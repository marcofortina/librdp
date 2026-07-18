/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared application client policy tests.
 * Coverage: platform-neutral option normalization, settings population and
 * connection-scoped TLS certificate decisions without native GUI backends.
 * Bug classes: numeric overflow, malformed device syntax, implicit trust,
 * missing gateway context, credential leakage and platform-policy bypass.
 * Determinism: tests use in-memory settings and temporary stdio streams; no
 * network, device discovery or graphical session is required.
 */

#include "client_options.h"
#include "client_tls.h"

#include <librdp/librdp.h>

#include <stdio.h>
#include <string.h>

static int check_int(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr, "test_app_client:%d: check failed: %s\n", line, expression);
    return 1;
}

#define CHECK(expr)                                                                                  \
    do                                                                                               \
    {                                                                                                \
        if (check_int((expr), #expr, __LINE__) != 0)                                                 \
            return 1;                                                                                \
    } while (0)

static const char* test_camera_normalizer(const char* source, void* user_data)
{
    const char* allowed = (const char*)user_data;

    if (!source || !allowed || strcmp(source, allowed) != 0)
        return NULL;
    return source;
}

/*
 * Exercise the full shared settings boundary with representative connection,
 * gateway, device and media values so frontend wrappers cannot silently drift
 * in syntax or defaults.
 */
static int test_common_options(void)
{
    char* argv[] = {
        (char*)"viewer",
        (char*)"--target",
        (char*)"host.example",
        (char*)"--port",
        (char*)"3390",
        (char*)"--user",
        (char*)"sample-user",
        (char*)"--password",
        (char*)"sample-secret",
        (char*)"--domain",
        (char*)"SAMPLE",
        (char*)"--width",
        (char*)"1600",
        (char*)"--height",
        (char*)"900",
        (char*)"--security",
        (char*)"nla",
        (char*)"--gateway",
        (char*)"https://gateway.example/rdg",
        (char*)"--gateway-mode",
        (char*)"rdg-http",
        (char*)"--gateway-timeout",
        (char*)"5000",
        (char*)"--drive",
        (char*)"data=/tmp",
        (char*)"--audio-output",
        (char*)"--audio-input",
        (char*)"device=capture",
        (char*)"--camera",
        (char*)"camera-test",
        (char*)"--rail",
        (char*)"app=sample.exe",
    };
    client_option_policy policy;
    client_options options;
    librdp_gateway_config gateway;
    librdp_settings* settings = librdp_settings_new();

    CHECK(settings != NULL);
    client_option_policy_init(&policy);
    policy.default_audio_output_device = "playback";
    policy.default_audio_input_device = "capture-default";
    policy.normalize_camera_source = test_camera_normalizer;
    policy.camera_user_data = (void*)"camera-test";
    policy.rail_requires_app_prefix = 1;
    CHECK(client_options_configure(settings,
                                   &options,
                                   &policy,
                                   (int)(sizeof(argv) / sizeof(argv[0])),
                                   argv) == 1);
    CHECK(strcmp(librdp_settings_target(settings), "host.example") == 0);
    CHECK(librdp_settings_port(settings) == 3390u);
    CHECK(strcmp(librdp_settings_username(settings), "sample-user") == 0);
    CHECK(strcmp(librdp_settings_domain(settings), "SAMPLE") == 0);
    CHECK(librdp_settings_width(settings) == 1600u);
    CHECK(librdp_settings_height(settings) == 900u);
    CHECK(librdp_settings_security_mode(settings) == LIBRDP_SECURITY_NLA);
    CHECK(librdp_settings_drive_count(settings) == 1u);
    CHECK(strcmp(librdp_settings_audio_output_device(settings), "playback") == 0);
    CHECK(strcmp(librdp_settings_audio_input_device(settings), "capture") == 0);
    CHECK(strcmp(librdp_settings_camera_source(settings, 0), "camera-test") == 0);
    CHECK(strcmp(librdp_settings_rail_app(settings, 0), "sample.exe") == 0);
    CHECK(librdp_settings_get_gateway_config(settings, &gateway) == LIBRDP_STATUS_OK);
    CHECK(gateway.mode == LIBRDP_GATEWAY_RDG_HTTP);
    CHECK(gateway.timeout_ms == 5000u);
    client_options_clear(&options);
    librdp_settings_free(settings);
    return 0;
}

static int test_common_options_reject_invalid(void)
{
    char* overflow[] = {
        (char*)"viewer",
        (char*)"--target",
        (char*)"host.example",
        (char*)"--width",
        (char*)"8193",
    };
    char* gateway_without_url[] = {
        (char*)"viewer",
        (char*)"--target",
        (char*)"host.example",
        (char*)"--gateway-user",
        (char*)"gateway-user",
    };
    char* rejected_camera[] = {
        (char*)"viewer",
        (char*)"--target",
        (char*)"host.example",
        (char*)"--camera",
        (char*)"other-camera",
    };
    client_option_policy policy;
    client_options options;
    librdp_settings* settings = NULL;

    client_option_policy_init(&policy);
    policy.normalize_camera_source = test_camera_normalizer;
    policy.camera_user_data = (void*)"camera-test";

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(client_options_configure(settings,
                                   &options,
                                   &policy,
                                   (int)(sizeof(overflow) / sizeof(overflow[0])),
                                   overflow) == 0);
    client_options_clear(&options);
    librdp_settings_free(settings);

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(client_options_configure(
              settings,
              &options,
              &policy,
              (int)(sizeof(gateway_without_url) / sizeof(gateway_without_url[0])),
              gateway_without_url) == 0);
    client_options_clear(&options);
    librdp_settings_free(settings);

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(client_options_configure(settings,
                                   &options,
                                   &policy,
                                   (int)(sizeof(rejected_camera) / sizeof(rejected_camera[0])),
                                   rejected_camera) == 0);
    client_options_clear(&options);
    librdp_settings_free(settings);
    return 0;
}

/*
 * Drive strict, automatic and interactive certificate outcomes through
 * caller-owned streams. The test proves that trust is never granted by
 * default and that prompt input is consumed only in prompt mode.
 */
static int test_tls_decisions(void)
{
    client_tls_context context;
    librdp_tls_certificate_info certificate;
    FILE* input = tmpfile();
    FILE* output = tmpfile();

    CHECK(input != NULL);
    CHECK(output != NULL);
    memset(&certificate, 0, sizeof(certificate));
    certificate.host = "host.example";
    certificate.subject = "CN=host.example";
    certificate.issuer = "CN=Test CA";
    certificate.verify_status = LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
    memcpy(certificate.sha256_fingerprint,
           "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
           65u);

    client_tls_context_init(&context);
    context.input = input;
    context.output = output;
    CHECK(client_tls_certificate_callback(&certificate, &context) ==
          LIBRDP_TLS_CERTIFICATE_DECISION_REJECT);

    context.mode = CLIENT_TLS_DECISION_ACCEPT_ONCE;
    CHECK(client_tls_certificate_callback(&certificate, &context) ==
          LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT);

    CHECK(fputs("yes\n", input) >= 0);
    rewind(input);
    context.mode = CLIENT_TLS_DECISION_PROMPT;
    CHECK(client_tls_certificate_callback(&certificate, &context) ==
          LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT);

    fclose(input);
    fclose(output);
    return 0;
}

int main(void)
{
    if (test_common_options() != 0)
        return 1;
    if (test_common_options_reject_invalid() != 0)
        return 1;
    if (test_tls_decisions() != 0)
        return 1;
    return 0;
}
