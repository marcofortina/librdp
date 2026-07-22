/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic Cocoa server input translation tests.
 * Coverage: base and extended scancodes, release flags, malformed flags,
 * vertical and horizontal wheel signs, and pointer flag combinations.
 * Bug classes: host-key mismatch, unsupported extended prefixes, accidental
 * input injection during tests, signed wheel errors and flag confusion.
 * Determinism: translation helpers do not query privacy state, post events or
 * require a graphical session.
 * Failure policy: an invalid protocol combination must fail before any native
 * event object is created.
 */

#include "cocoa_input.h"

#include <librdp/server.h>

#import <Carbon/Carbon.h>

#include <stdio.h>

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
            return 1;                                          \
    } while (0)

int main(void)
{
    uint16_t keycode = 0u;

    CHECK(cocoa_server_input_test_scancode(0x1eu,
                                            0u,
                                            &keycode) == 1);
    CHECK(keycode == (uint16_t)kVK_ANSI_A);
    CHECK(cocoa_server_input_test_scancode(0x1du,
                                            0x0100u,
                                            &keycode) == 1);
    CHECK(keycode == (uint16_t)kVK_RightControl);
    CHECK(cocoa_server_input_test_scancode(0x1eu,
                                            0x8000u,
                                            &keycode) == 1);
    CHECK(cocoa_server_input_test_scancode(0u, 0u, &keycode) == 0);
    CHECK(cocoa_server_input_test_scancode(0x1eu,
                                            0x0200u,
                                            &keycode) == 0);
    CHECK(cocoa_server_input_test_scancode(0x1eu,
                                            0x0001u,
                                            &keycode) == 0);
    CHECK(cocoa_server_input_test_modifier_flag(
              (uint16_t)kVK_Shift) ==
          (uint64_t)kCGEventFlagMaskShift);
    CHECK(cocoa_server_input_test_modifier_flag(
              (uint16_t)kVK_RightOption) ==
          (uint64_t)kCGEventFlagMaskAlternate);
    CHECK(cocoa_server_input_test_modifier_flag(
              (uint16_t)kVK_Control) ==
          (uint64_t)kCGEventFlagMaskControl);
    CHECK(cocoa_server_input_test_modifier_flag(
              (uint16_t)kVK_Command) ==
          (uint64_t)kCGEventFlagMaskCommand);
    CHECK(cocoa_server_input_test_modifier_flag(
              (uint16_t)kVK_ANSI_A) == 0u);

    CHECK(cocoa_server_input_test_wheel_steps(0x0278u) == 1);
    CHECK(cocoa_server_input_test_wheel_steps(0x0388u) == -1);
    CHECK(cocoa_server_input_test_pointer_flags(
              LIBRDP_SERVER_INPUT_MOUSE, 0x0800u) == 1);
    CHECK(cocoa_server_input_test_pointer_flags(
              LIBRDP_SERVER_INPUT_MOUSE, 0x9000u) == 1);
    CHECK(cocoa_server_input_test_pointer_flags(
              LIBRDP_SERVER_INPUT_MOUSE, 0x6000u) == 0);
    CHECK(cocoa_server_input_test_pointer_flags(
              LIBRDP_SERVER_INPUT_MOUSE, 0x0600u) == 0);
    CHECK(cocoa_server_input_test_pointer_flags(
              LIBRDP_SERVER_INPUT_EXTENDED_MOUSE, 0x8001u) == 1);
    CHECK(cocoa_server_input_test_pointer_flags(
              LIBRDP_SERVER_INPUT_EXTENDED_MOUSE, 0x8003u) == 0);
    return 0;
}
