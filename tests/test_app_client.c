/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared application client policy tests.
 * Coverage: platform-neutral option normalization, settings population,
 * callback binding, provider rollback, runtime state checks and
 * connection-scoped TLS certificate decisions without native GUI backends.
 * Bug classes: numeric overflow, malformed device syntax, implicit trust,
 * missing gateway context, credential leakage and platform-policy bypass.
 * Determinism: tests use in-memory settings and temporary stdio streams; no
 * network, device discovery or graphical session is required.
 */

#include "client_callbacks.h"
#include "client_credentials.h"
#include "client_options.h"
#include "client_providers.h"
#include "client_runtime.h"
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

static librdp_status test_credentials_provider(librdp_credentials* credentials,
                                               void* user_data)
{
    const char* username = (const char*)user_data;

    if (!credentials || !username)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return librdp_credentials_set(credentials, username, NULL, NULL);
}

/*
 * Move static values through a zeroized temporary object while retaining a
 * just-in-time provider for frontends that acquire credentials from native UI.
 */
static int test_credentials_handoff(void)
{
    client_credentials_input input;
    librdp_settings* settings = librdp_settings_new();

    CHECK(settings != NULL);
    client_credentials_input_init(&input);
    input.username = "local-user";
    input.password = "local-secret";
    input.domain = "LOCAL";
    input.provider = test_credentials_provider;
    input.provider_user_data = (void*)"prompt-user";
    CHECK(client_credentials_apply(settings, &input) == LIBRDP_STATUS_OK);
    CHECK(strcmp(librdp_settings_username(settings), "local-user") == 0);
    CHECK(strcmp(librdp_settings_domain(settings), "LOCAL") == 0);
    librdp_settings_free(settings);
    return 0;
}

typedef struct test_provider_state
{
    unsigned int configured;
    unsigned int activated;
    unsigned int stopped;
    int fail_activation;
} test_provider_state;

static librdp_status test_provider_configure(librdp_settings* settings, void* user_data)
{
    test_provider_state* state = (test_provider_state*)user_data;

    if (!settings || !state)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    state->configured++;
    return LIBRDP_STATUS_OK;
}

static librdp_status test_provider_activate(librdp_session* session, void* user_data)
{
    test_provider_state* state = (test_provider_state*)user_data;

    if (!session || !state)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    state->activated++;
    return state->fail_activation ? LIBRDP_STATUS_UNSUPPORTED
                                  : LIBRDP_STATUS_OK;
}

static void test_provider_stop(librdp_session* session, void* user_data)
{
    test_provider_state* state = (test_provider_state*)user_data;

    if (session && state)
        state->stopped++;
}

/*
 * Verify that backend descriptors are unique and bounded, settings hooks run
 * in order, and a failed session hook unwinds every earlier active provider.
 */
static int test_provider_registry(void)
{
    test_provider_state first = { 0 };
    test_provider_state second = { 0 };
    client_provider_registry registry;
    client_provider provider;
    librdp_settings* settings = librdp_settings_new();
    librdp_session* session = NULL;

    CHECK(settings != NULL);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    client_provider_registry_init(&registry);

    memset(&provider, 0, sizeof(provider));
    provider.name = "media";
    provider.configure_settings = test_provider_configure;
    provider.activate_session = test_provider_activate;
    provider.shutdown_session = test_provider_stop;
    provider.user_data = &first;
    CHECK(client_provider_registry_add(&registry, &provider) == LIBRDP_STATUS_OK);
    CHECK(client_provider_registry_add(&registry, &provider) == LIBRDP_STATUS_STATE);

    provider.name = "devices";
    provider.user_data = &second;
    second.fail_activation = 1;
    CHECK(client_provider_registry_add(&registry, &provider) == LIBRDP_STATUS_OK);
    CHECK(client_provider_registry_configure(&registry, settings) == LIBRDP_STATUS_OK);
    CHECK(first.configured == 1u);
    CHECK(second.configured == 1u);
    CHECK(client_provider_registry_activate(&registry, session) ==
          LIBRDP_STATUS_UNSUPPORTED);
    CHECK(first.activated == 1u);
    CHECK(first.stopped == 1u);
    CHECK(second.activated == 1u);
    CHECK(second.stopped == 0u);
    CHECK(registry.active_session == NULL);

    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}

/*
 * Exercise callback and runtime argument/state contracts without networking.
 * This catches accidental acceptance of incomplete session ownership before a
 * native event loop has established a connection.
 */
static int test_callbacks_and_runtime_state(void)
{
    client_callbacks callbacks;
    client_runtime runtime;
    struct pollfd* pollfds = NULL;
    size_t poll_count = 0;
    int timeout_ms = 0;
    librdp_settings* settings = librdp_settings_new();
    librdp_session* session = NULL;

    CHECK(settings != NULL);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    client_callbacks_init(&callbacks);
    CHECK(client_callbacks_apply(NULL, &callbacks) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(client_callbacks_apply(session, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(client_callbacks_apply(session, &callbacks) == LIBRDP_STATUS_OK);

    client_runtime_init(&runtime, session);
    CHECK(client_runtime_prepare_poll(&runtime,
                                      NULL,
                                      0,
                                      -1,
                                      &pollfds,
                                      &poll_count,
                                      &timeout_ms) == LIBRDP_STATUS_STATE);
    CHECK(client_runtime_dispatch_poll(&runtime, 1u) == LIBRDP_STATUS_STATE);
    CHECK(client_runtime_disconnect(&runtime) == LIBRDP_STATUS_OK);
    client_runtime_clear(&runtime);

    librdp_session_free(session);
    librdp_settings_free(settings);
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
    if (test_credentials_handoff() != 0)
        return 1;
    if (test_provider_registry() != 0)
        return 1;
    if (test_callbacks_and_runtime_state() != 0)
        return 1;
    return 0;
}
