/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic Cocoa server permission policy tests.
 * Coverage: independent Screen Recording, Accessibility, clipboard and drive
 * decisions in interactive and non-interactive modes.
 * Bug classes: implicit TCC bypass, cross-provider denial, missing mount
 * validation, unexpected native prompts and false provider activation.
 * Determinism: all privacy and UI calls are replaced by bounded mock callbacks.
 * Failure policy: malformed policy fails before any backend callback executes.
 */

#include "cocoa_permission.h"

#include <stdio.h>
#include <string.h>

typedef struct permission_test_state
{
    int screen_preflight;
    int screen_request;
    int accessibility_preflight;
    int accessibility_request;
    int clipboard_confirm;
    int drive_confirm;
    unsigned int screen_requests;
    unsigned int accessibility_requests;
    unsigned int confirmations;
    unsigned int denied_notices;
} permission_test_state;

static int test_check(int condition, const char* expression, int line)
{
    if (!condition)
        fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, line, expression);
    return condition;
}

#define CHECK(expression)                                                      \
    do                                                                         \
    {                                                                          \
        if (!test_check((expression), #expression, __LINE__))                  \
            return 1;                                                          \
    } while (0)

static int test_screen_preflight(void* context)
{
    return ((permission_test_state*)context)->screen_preflight;
}

static int test_screen_request(void* context)
{
    permission_test_state* state = (permission_test_state*)context;

    state->screen_requests++;
    return state->screen_request;
}

static int test_accessibility_preflight(void* context)
{
    return ((permission_test_state*)context)->accessibility_preflight;
}

static int test_accessibility_request(void* context)
{
    permission_test_state* state = (permission_test_state*)context;

    state->accessibility_requests++;
    return state->accessibility_request;
}

static int test_confirm(server_platform_permission_kind kind,
                        const char* detail, void* context)
{
    permission_test_state* state = (permission_test_state*)context;

    state->confirmations++;
    if (kind == SERVER_PLATFORM_PERMISSION_DRIVE)
    {
        if (!detail || strcmp(detail, "/tmp/client-drives") != 0)
            return 0;
        return state->drive_confirm;
    }
    if (kind == SERVER_PLATFORM_PERMISSION_CLIPBOARD)
        return state->clipboard_confirm;
    return 0;
}

static void test_show_denied(server_platform_permission_kind kind,
                             void* context)
{
    permission_test_state* state = (permission_test_state*)context;

    (void)kind;
    state->denied_notices++;
}

static cocoa_server_permission_backend test_backend(
    permission_test_state* state)
{
    cocoa_server_permission_backend backend;

    memset(&backend, 0, sizeof(backend));
    backend.screen_preflight = test_screen_preflight;
    backend.screen_request = test_screen_request;
    backend.accessibility_preflight = test_accessibility_preflight;
    backend.accessibility_request = test_accessibility_request;
    backend.confirm = test_confirm;
    backend.show_denied = test_show_denied;
    backend.context = state;
    return backend;
}

static int test_independent_decisions(void)
{
    cocoa_server_permission_policy policy;
    cocoa_server_permission_result result;
    permission_test_state state;
    cocoa_server_permission_backend backend;

    memset(&state, 0, sizeof(state));
    state.screen_preflight = 1;
    state.accessibility_preflight = 0;
    state.accessibility_request = 0;
    state.clipboard_confirm = 1;
    state.drive_confirm = 0;
    backend = test_backend(&state);
    cocoa_server_permission_policy_init(&policy);
    policy.drive_mount = "/tmp/client-drives";
    policy.request_input = 1;
    policy.request_clipboard = 1;
    policy.request_drive = 1;
    CHECK(cocoa_server_permission_resolve_with_backend(
              &policy, &backend, &result) == LIBRDP_STATUS_OK);
    CHECK(result.capture == 1);
    CHECK(result.input == 0);
    CHECK(result.clipboard == 1);
    CHECK(result.drive == 0);
    CHECK(state.screen_requests == 0u);
    CHECK(state.accessibility_requests == 1u);
    CHECK(state.confirmations == 2u);
    CHECK(state.denied_notices == 1u);
    return 0;
}

static int test_noninteractive_privacy(void)
{
    cocoa_server_permission_policy policy;
    cocoa_server_permission_result result;
    permission_test_state state;
    cocoa_server_permission_backend backend;

    memset(&state, 0, sizeof(state));
    backend = test_backend(&state);
    cocoa_server_permission_policy_init(&policy);
    policy.interactive = 0;
    policy.drive_mount = "/tmp/client-drives";
    policy.request_input = 1;
    policy.request_clipboard = 1;
    policy.request_drive = 1;
    CHECK(cocoa_server_permission_resolve_with_backend(
              &policy, &backend, &result) == LIBRDP_STATUS_OK);
    CHECK(result.capture == 0);
    CHECK(result.input == 0);
    CHECK(result.clipboard == 1);
    CHECK(result.drive == 1);
    CHECK(state.screen_requests == 0u);
    CHECK(state.accessibility_requests == 0u);
    CHECK(state.confirmations == 0u);
    CHECK(state.denied_notices == 0u);
    return 0;
}

static int test_invalid_drive_policy(void)
{
    cocoa_server_permission_policy policy;
    cocoa_server_permission_result result;
    permission_test_state state;
    cocoa_server_permission_backend backend;

    memset(&state, 0, sizeof(state));
    backend = test_backend(&state);
    cocoa_server_permission_policy_init(&policy);
    policy.request_drive = 1;
    CHECK(cocoa_server_permission_resolve_with_backend(
              &policy, &backend, &result) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(state.screen_requests == 0u);
    CHECK(state.confirmations == 0u);
    return 0;
}

int main(void)
{
    int result = 0;

    result |= test_independent_decisions();
    result |= test_noninteractive_privacy();
    result |= test_invalid_drive_policy();
    return result;
}
