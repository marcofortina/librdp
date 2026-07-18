/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa desktop-server CLI policy tests.
 * Coverage: secure defaults, capture selectors, numeric bounds, explicit
 * Standard-security opt-in and rejection of unavailable managed/provider
 * modes.
 * Bug classes: option-value desynchronization, integer overflow, implicit
 * security downgrade and accidental advertisement of unavailable providers.
 * Determinism: tests operate only on fixed argv arrays and load no native
 * frameworks, files, environment credentials or network resources.
 * Failure policy: malformed or partial startup policy must fail before any
 * macOS framework is loaded.
 */

#include "cocoa_server_cli.h"

#include <stdio.h>
#include <string.h>

static int test_check(int condition,
                      const char* expression,
                      int line)
{
    if (!condition)
        fprintf(stderr,
                "check failed %s:%d: %s\n",
                __FILE__,
                line,
                expression);
    return condition;
}

#define CHECK(expression)                                      \
    do                                                         \
    {                                                          \
        if (!test_check((expression), #expression, __LINE__))  \
            return 0;                                          \
    } while (0)

static int test_secure_tls_options(void)
{
    char* argv[] = {
        (char*)"server",
        (char*)"--allow-capture",
        (char*)"--tls-cert",
        (char*)"/tmp/server.crt",
        (char*)"--tls-key",
        (char*)"/tmp/server.key",
        (char*)"--source",
        (char*)"window:42",
        (char*)"--max-peers",
        (char*)"8",
        (char*)"--max-fps",
        (char*)"45",
    };
    cocoa_server_options options;

    CHECK(cocoa_server_parse_options(
              (int)(sizeof(argv) / sizeof(argv[0])),
              argv,
              &options) == 1);
    CHECK(options.security_mode == LIBRDP_SECURITY_TLS);
    CHECK(options.source_kind == COCOA_SERVER_SOURCE_WINDOW);
    CHECK(options.source_id == 42u);
    CHECK(options.max_peers == 8u);
    CHECK(options.max_fps == 45u);
    CHECK(options.allow_capture == 1);
    return 1;
}

static int test_standard_requires_explicit_policy(void)
{
    char* rejected[] = {
        (char*)"server",
        (char*)"--allow-capture",
        (char*)"--security",
        (char*)"standard",
    };
    char* accepted[] = {
        (char*)"server",
        (char*)"--allow-capture",
        (char*)"--security",
        (char*)"standard",
        (char*)"--allow-standard-security",
    };
    cocoa_server_options options;

    CHECK(cocoa_server_parse_options(
              (int)(sizeof(rejected) / sizeof(rejected[0])),
              rejected,
              &options) == 0);
    CHECK(cocoa_server_parse_options(
              (int)(sizeof(accepted) / sizeof(accepted[0])),
              accepted,
              &options) == 1);
    return 1;
}

static int test_nla_policy(void)
{
    char* argv[] = {
        (char*)"server",
        (char*)"--allow-capture",
        (char*)"--security",
        (char*)"nla",
        (char*)"--tls-cert",
        (char*)"/tmp/server.crt",
        (char*)"--tls-key",
        (char*)"/tmp/server.key",
        (char*)"--user",
        (char*)"test-user",
        (char*)"--domain",
        (char*)"test-domain",
        (char*)"--password-env",
        (char*)"TEST_SERVER_SECRET",
    };
    cocoa_server_options options;

    CHECK(cocoa_server_parse_options(
              (int)(sizeof(argv) / sizeof(argv[0])),
              argv,
              &options) == 1);
    CHECK(options.security_mode == LIBRDP_SECURITY_NLA);
    CHECK(strcmp(options.nla_username, "test-user") == 0);
    CHECK(strcmp(options.nla_domain, "test-domain") == 0);
    CHECK(strcmp(options.password_environment,
                 "TEST_SERVER_SECRET") == 0);
    return 1;
}

static int test_rejects_unavailable_modes(void)
{
    char* managed[] = {
        (char*)"server",
        (char*)"--mode",
        (char*)"managed",
    };
    char* input[] = {
        (char*)"server",
        (char*)"--allow-capture",
        (char*)"--allow-input",
        (char*)"--tls-cert",
        (char*)"/tmp/server.crt",
        (char*)"--tls-key",
        (char*)"/tmp/server.key",
    };
    cocoa_server_options options;

    CHECK(cocoa_server_parse_options(
              (int)(sizeof(managed) / sizeof(managed[0])),
              managed,
              &options) == 0);
    CHECK(cocoa_server_parse_options(
              (int)(sizeof(input) / sizeof(input[0])),
              input,
              &options) == 0);
    return 1;
}

static int test_bounds_and_help(void)
{
    char* zero_fps[] = {
        (char*)"server",
        (char*)"--max-fps",
        (char*)"0",
    };
    char* invalid_window[] = {
        (char*)"server",
        (char*)"--source",
        (char*)"window:0",
    };
    char* help[] = {
        (char*)"server",
        (char*)"--help",
    };
    cocoa_server_options options;

    CHECK(cocoa_server_parse_options(
              (int)(sizeof(zero_fps) / sizeof(zero_fps[0])),
              zero_fps,
              &options) == 0);
    CHECK(cocoa_server_parse_options(
              (int)(sizeof(invalid_window) /
                    sizeof(invalid_window[0])),
              invalid_window,
              &options) == 0);
    CHECK(cocoa_server_parse_options(
              (int)(sizeof(help) / sizeof(help[0])),
              help,
              &options) == 2);
    CHECK(options.show_help == 1);
    return 1;
}

int main(void)
{
    int ok = 1;

    ok &= test_secure_tls_options();
    ok &= test_standard_requires_explicit_policy();
    ok &= test_nla_policy();
    ok &= test_rejects_unavailable_modes();
    ok &= test_bounds_and_help();
    return ok ? 0 : 1;
}
