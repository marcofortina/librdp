/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa viewer input bridge regression tests.
 * Coverage: AppKit-committed UTF-16, supplementary characters, malformed
 * surrogates, physical shortcuts, command selectors, modifiers, autorepeat,
 * and focus-loss cleanup. These cases catch duplicate input, stuck keys,
 * premature IME transmission, and layout-independent scancode regressions.
 */

#include "cocoa_input.h"
#include "cocoa_keymap.h"

#import <Carbon/Carbon.h>
#import <Cocoa/Cocoa.h>

#include <stdio.h>
#include <string.h>

typedef struct cocoa_input_capture
{
    librdp_key_event events[64];
    size_t count;
} cocoa_input_capture;

static int check_int(int condition,
                     const char* expression,
                     int line)
{
    if (condition)
        return 0;
    fprintf(stderr,
            "test_cocoa_viewer_input:%d: check failed: %s\n",
            line,
            expression);
    return 1;
}

#define CHECK(expression)                                      \
    do                                                         \
    {                                                          \
        if (check_int((expression), #expression, __LINE__) != 0) \
            return 1;                                          \
    } while (0)

static librdp_status capture_key(const librdp_key_event* event,
                                 void* user_data)
{
    cocoa_input_capture* capture =
        (cocoa_input_capture*)user_data;

    if (!capture || !event ||
        capture->count >= sizeof(capture->events) /
                              sizeof(capture->events[0]))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    capture->events[capture->count++] = *event;
    return LIBRDP_STATUS_OK;
}

static NSEvent* key_event(NSEventType type,
                          uint16_t keycode,
                          NSEventModifierFlags modifiers,
                          NSString* characters,
                          NSString* characters_ignoring,
                          BOOL repeat)
{
    return [NSEvent keyEventWithType:type
                            location:NSZeroPoint
                       modifierFlags:modifiers
                           timestamp:1.0
                        windowNumber:0
                             context:nil
                          characters:characters
         charactersIgnoringModifiers:characters_ignoring
                           isARepeat:repeat
                             keyCode:keycode];
}

static int test_keymap_round_trip(void)
{
    uint16_t keycode = 0u;
    uint32_t scancode = 0u;
    uint32_t flags = 0u;

    CHECK(cocoa_keymap_native_to_rdp(
              kVK_ANSI_A, &scancode, &flags) == 1);
    CHECK(scancode == 0x1eu && flags == 0u);
    CHECK(cocoa_keymap_rdp_to_native(
              scancode, flags, &keycode) == 1);
    CHECK(keycode == kVK_ANSI_A);
    CHECK(cocoa_keymap_native_to_rdp(
              kVK_RightOption, &scancode, &flags) == 1);
    CHECK(scancode == 0x38u &&
          flags == LIBRDP_KEY_FLAG_EXTENDED);
    CHECK(cocoa_keymap_rdp_to_native(
              scancode, flags, &keycode) == 1);
    CHECK(keycode == kVK_RightOption);
    CHECK(cocoa_keymap_native_to_rdp(
              UINT16_MAX, &scancode, &flags) == 0);
    CHECK(cocoa_keymap_rdp_to_native(
              0u, 0u, &keycode) == 0);
    return 0;
}

static int test_committed_text(void)
{
    cocoa_input_capture capture;
    CocoaViewerInputBridge* bridge = nil;
    const unichar malformed_units[] = { 0xd83du };
    NSString* malformed = nil;
    NSAttributedString* attributed = nil;

    memset(&capture, 0, sizeof(capture));
    bridge = [[CocoaViewerInputBridge alloc]
        initWithSink:capture_key
           userData:&capture];
    CHECK(bridge != nil);
    CHECK([bridge sendCommittedText:@"\u00e9\U0001f600"] == YES);
    CHECK(capture.count == 6u);
    CHECK(capture.events[0].unicode == 0x00e9u);
    CHECK(capture.events[2].unicode == 0xd83du);
    CHECK(capture.events[4].unicode == 0xde00u);
    for (size_t index = 0u; index < capture.count; index++)
    {
        CHECK(capture.events[index].flags ==
              LIBRDP_KEY_FLAG_UNICODE);
        CHECK(capture.events[index].state ==
              ((index & 1u) == 0u
                   ? LIBRDP_KEY_PRESSED
                   : LIBRDP_KEY_RELEASED));
    }

    attributed = [[NSAttributedString alloc]
        initWithString:@"x"];
    CHECK([bridge sendCommittedText:attributed] == YES);
    CHECK(capture.count == 8u &&
          capture.events[6].unicode == (uint32_t)'x');
    malformed = [NSString stringWithCharacters:malformed_units
                                        length:1u];
    CHECK([bridge sendCommittedText:malformed] == NO);
    CHECK(capture.count == 8u);
    CHECK([bridge sendCommittedText:@""] == NO);
    CHECK([bridge sendCommittedText:nil] == NO);
    return 0;
}

static int test_commands_and_physical_keys(void)
{
    cocoa_input_capture capture;
    CocoaViewerInputBridge* bridge = nil;
    NSEvent* normal = nil;
    NSEvent* down = nil;
    NSEvent* repeat = nil;
    NSEvent* up = nil;

    memset(&capture, 0, sizeof(capture));
    bridge = [[CocoaViewerInputBridge alloc]
        initWithSink:capture_key
           userData:&capture];
    CHECK(bridge != nil);
    CHECK([bridge sendCommand:@selector(insertTab:)] == YES);
    CHECK(capture.count == 2u);
    CHECK(capture.events[0].scancode == 0x0fu &&
          capture.events[0].state == LIBRDP_KEY_PRESSED);
    CHECK(capture.events[1].state == LIBRDP_KEY_RELEASED);
    CHECK([bridge sendCommand:@selector(moveLeft:)] == YES);
    CHECK(capture.events[2].scancode == 0x4bu &&
          capture.events[2].flags ==
              LIBRDP_KEY_FLAG_EXTENDED);
    CHECK([bridge sendCommand:@selector(complete:)] == NO);

    normal = key_event(NSEventTypeKeyDown,
                       kVK_ANSI_A,
                       0u,
                       @"a",
                       @"a",
                       NO);
    CHECK([bridge handleKeyDown:normal] == NO);
    down = key_event(NSEventTypeKeyDown,
                     kVK_ANSI_Q,
                     NSEventModifierFlagOption,
                     @"@",
                     @"q",
                     NO);
    repeat = key_event(NSEventTypeKeyDown,
                       kVK_ANSI_Q,
                       NSEventModifierFlagOption,
                       @"@",
                       @"q",
                       YES);
    up = key_event(NSEventTypeKeyUp,
                   kVK_ANSI_Q,
                   NSEventModifierFlagOption,
                   @"@",
                   @"q",
                   NO);
    CHECK([bridge handleKeyDown:down] == YES);
    CHECK([bridge handleKeyDown:down] == YES);
    CHECK([bridge handleKeyDown:repeat] == YES);
    CHECK([bridge handleKeyUp:up] == YES);
    CHECK(capture.count == 7u);
    CHECK(capture.events[4].scancode == 0x10u &&
          capture.events[4].state == LIBRDP_KEY_PRESSED);
    CHECK(capture.events[5].state == LIBRDP_KEY_PRESSED);
    CHECK(capture.events[6].state == LIBRDP_KEY_RELEASED);
    CHECK([bridge handleKeyUp:up] == NO);
    return 0;
}

static int test_modifiers_and_release_all(void)
{
    cocoa_input_capture capture;
    CocoaViewerInputBridge* bridge = nil;
    NSEvent* option_down = nil;
    NSEvent* option_up = nil;
    NSEvent* command_down = nil;

    memset(&capture, 0, sizeof(capture));
    bridge = [[CocoaViewerInputBridge alloc]
        initWithSink:capture_key
           userData:&capture];
    CHECK(bridge != nil);
    option_down = key_event(NSEventTypeFlagsChanged,
                            kVK_RightOption,
                            NSEventModifierFlagOption,
                            @"",
                            @"",
                            NO);
    option_up = key_event(NSEventTypeFlagsChanged,
                          kVK_RightOption,
                          0u,
                          @"",
                          @"",
                          NO);
    command_down = key_event(NSEventTypeFlagsChanged,
                             kVK_Command,
                             NSEventModifierFlagCommand,
                             @"",
                             @"",
                             NO);
    CHECK([bridge handleFlagsChanged:option_down] == YES);
    CHECK([bridge handleFlagsChanged:option_up] == YES);
    CHECK(capture.count == 2u);
    CHECK(capture.events[0].scancode == 0x38u &&
          capture.events[0].flags ==
              LIBRDP_KEY_FLAG_EXTENDED);
    CHECK(capture.events[1].state == LIBRDP_KEY_RELEASED);
    CHECK([bridge handleFlagsChanged:command_down] == YES);
    [bridge releaseAll];
    CHECK(capture.count == 4u);
    CHECK(capture.events[2].state == LIBRDP_KEY_PRESSED);
    CHECK(capture.events[3].state == LIBRDP_KEY_RELEASED);
    [bridge releaseAll];
    CHECK(capture.count == 4u);
    return 0;
}

int main(void)
{
    int result = 0;

    @autoreleasepool
    {
        result |= test_keymap_round_trip();
        result |= test_committed_text();
        result |= test_commands_and_physical_keys();
        result |= test_modifiers_and_release_all();
    }
    return result;
}
