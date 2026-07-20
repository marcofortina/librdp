/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer keyboard bridge regression tests.
 * Coverage: pure keyboard translation helpers without opening a real X server.
 * Bug classes: layout-position drift, AltGr extended scancode loss, Unicode
 * fallback suppression mistakes, autorepeat false releases, and stuck key-up
 * state after focus/grab transitions.
 * Determinism: fixtures use synthetic XKB names, evdev codes, UTF-8 bytes, and
 * pressed-key tables only.
 */

#include "x11_keyboard.h"

#include <X11/X.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int check_int(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr, "test_x11_viewer_keyboard:%d: check failed: %s\n", line, expression);
    return 1;
}

#define CHECK(expr)                                                                                  \
    do                                                                                               \
    {                                                                                                \
        if (check_int((expr), #expr, __LINE__) != 0)                                                 \
            return 1;                                                                                \
    } while (0)

/*
 * XKB physical key names must be stable across host layouts. The text produced
 * by those keys comes from XIM/XKB, but the remote scancode must still describe
 * the physical key position.
 */
static int test_xkb_key_name_mapping(void)
{
    uint32_t scancode = 0;
    uint32_t flags = 0;

    CHECK(x11_keyboard_map_xkb_name("AD01", &scancode, &flags) == 1);
    CHECK(scancode == 0x10u && flags == 0);
    CHECK(x11_keyboard_map_xkb_name("AC10", &scancode, &flags) == 1);
    CHECK(scancode == 0x27u && flags == 0);
    CHECK(x11_keyboard_map_xkb_name("RALT", &scancode, &flags) == 1);
    CHECK(scancode == 0x38u && flags == LIBRDP_KEY_FLAG_EXTENDED);
    CHECK(x11_keyboard_map_xkb_name("PAUS", &scancode, &flags) == 1);
    CHECK(scancode == 0x45u && flags == LIBRDP_KEY_FLAG_EXTENDED1);
    CHECK(x11_keyboard_map_xkb_name("NOPE", &scancode, &flags) == 0);
    return 0;
}

/*
 * Evdev fallback is used only when XKB names are unavailable. Extended keys,
 * including the right Alt key used by AltGr layouts, must keep their RDP
 * extended flag.
 */
static int test_evdev_fallback_mapping(void)
{
    uint32_t scancode = 0;
    uint32_t flags = 0;

    CHECK(x11_keyboard_map_evdev(30u, &scancode, &flags) == 1);
    CHECK(scancode == 30u && flags == 0);
    CHECK(x11_keyboard_map_evdev(100u, &scancode, &flags) == 1);
    CHECK(scancode == 0x38u && flags == LIBRDP_KEY_FLAG_EXTENDED);
    CHECK(x11_keyboard_map_evdev(127u, &scancode, &flags) == 1);
    CHECK(scancode == 0x5du && flags == LIBRDP_KEY_FLAG_EXTENDED);
    CHECK(x11_keyboard_map_evdev(255u, &scancode, &flags) == 0);
    return 0;
}

/*
 * Compose/dead-key text is sent as Unicode fallback only when no physical
 * scancode was translated. Control, Alt, and Super combinations remain physical
 * shortcuts; AltGr commonly uses Mod5 and must not be blocked here.
 */
static int test_unicode_fallback_policy(void)
{
    const char text[] = "\xc3\xa8";
    const char* cursor = text;
    const char* end = text + 2;
    uint32_t codepoint = 0;

    CHECK(x11_keyboard_next_utf8_codepoint(&cursor, end, &codepoint) == 1);
    CHECK(codepoint == 0x00e8u);
    CHECK(cursor == end);
    cursor = "\xf0\x9f";
    CHECK(x11_keyboard_next_utf8_codepoint(&cursor, cursor + 2, &codepoint) == 0);
    CHECK(x11_keyboard_should_send_unicode_fallback(0u, 2u, 0) == 1);
    CHECK(x11_keyboard_should_send_unicode_fallback(Mod5Mask, 2u, 0) == 1);
    CHECK(x11_keyboard_should_send_unicode_fallback(ControlMask, 2u, 0) == 0);
    CHECK(x11_keyboard_should_send_unicode_fallback(Mod1Mask, 2u, 0) == 0);
    CHECK(x11_keyboard_should_send_unicode_fallback(Mod4Mask, 2u, 0) == 0);
    CHECK(x11_keyboard_should_send_unicode_fallback(0u, 0u, 0) == 0);
    CHECK(x11_keyboard_should_send_unicode_fallback(0u, 2u, 1) == 0);
    return 0;
}

typedef struct keyboard_event_capture
{
    librdp_key_event events[12];
    size_t count;
} keyboard_event_capture;

static void capture_keyboard_event(const librdp_key_event* event,
                                   void* user_data)
{
    keyboard_event_capture* capture =
        (keyboard_event_capture*)user_data;

    if (!capture || !event ||
        capture->count >=
            sizeof(capture->events) /
                sizeof(capture->events[0]))
        return;
    capture->events[capture->count++] = *event;
}

/*
 * XIM fallback text becomes exact UTF-16 press/release pairs. The fixture
 * includes one BMP character, one supplementary character, a filtered control
 * byte, and malformed UTF-8 to catch truncation, surrogate, and overread bugs.
 */
static int test_unicode_fallback_emission(void)
{
    static const char valid[] = "\xc3\xa9\xf0\x9f\x98\x80";
    static const char malformed[] = "\xc0\xaf";
    keyboard_event_capture capture;
    size_t index = 0u;

    memset(&capture, 0, sizeof(capture));
    CHECK(x11_keyboard_emit_utf8(valid,
                                 sizeof(valid) - 1u,
                                 capture_keyboard_event,
                                 &capture) == 3u);
    CHECK(capture.count == 6u);
    CHECK(capture.events[0].unicode == 0x00e9u);
    CHECK(capture.events[1].unicode == 0x00e9u);
    CHECK(capture.events[2].unicode == 0xd83du);
    CHECK(capture.events[3].unicode == 0xd83du);
    CHECK(capture.events[4].unicode == 0xde00u);
    CHECK(capture.events[5].unicode == 0xde00u);
    for (index = 0u; index < capture.count; index++)
    {
        CHECK(capture.events[index].flags ==
              LIBRDP_KEY_FLAG_UNICODE);
        CHECK(capture.events[index].state ==
              ((index & 1u) == 0u
                   ? LIBRDP_KEY_PRESSED
                   : LIBRDP_KEY_RELEASED));
    }

    memset(&capture, 0, sizeof(capture));
    CHECK(x11_keyboard_emit_utf8("\n",
                                 1u,
                                 capture_keyboard_event,
                                 &capture) == 0u);
    CHECK(capture.count == 0u);
    CHECK(x11_keyboard_emit_utf8(malformed,
                                 sizeof(malformed) - 1u,
                                 capture_keyboard_event,
                                 &capture) == 0u);
    CHECK(capture.count == 0u);
    CHECK(x11_keyboard_emit_utf8(NULL,
                                 0u,
                                 capture_keyboard_event,
                                 &capture) == 0u);
    CHECK(x11_keyboard_emit_utf8(valid,
                                 sizeof(valid) - 1u,
                                 NULL,
                                 &capture) == 0u);
    return 0;
}

/*
 * Non-detectable autorepeat appears as a release immediately followed by a
 * press with the same keycode and timestamp. The bridge suppresses only that
 * exact pattern so real key-up events continue to release remote modifiers.
 */
static int test_autorepeat_release_match(void)
{
    CHECK(x11_keyboard_auto_repeat_release_match(0, 1, KeyPress, 38u, 100u, 38u, 100u) == 1);
    CHECK(x11_keyboard_auto_repeat_release_match(1, 1, KeyPress, 38u, 100u, 38u, 100u) == 0);
    CHECK(x11_keyboard_auto_repeat_release_match(0, 0, KeyPress, 38u, 100u, 38u, 100u) == 0);
    CHECK(x11_keyboard_auto_repeat_release_match(0, 1, KeyRelease, 38u, 100u, 38u, 100u) == 0);
    CHECK(x11_keyboard_auto_repeat_release_match(0, 1, KeyPress, 39u, 100u, 38u, 100u) == 0);
    CHECK(x11_keyboard_auto_repeat_release_match(0, 1, KeyPress, 38u, 101u, 38u, 100u) == 0);
    return 0;
}

/*
 * Pressed-key bookkeeping is what keeps Alt+Tab inside the remote desktop:
 * duplicate presses are ignored, true key-up events reuse the original scancode,
 * and pending grabs can be released after the last tracked key is up.
 */
static int test_press_release_state(void)
{
    x11_pressed_key pressed[256];
    unsigned int count = 0;
    librdp_key_event pressed_event;
    librdp_key_event released_event;

    memset(pressed, 0, sizeof(pressed));
    memset(&pressed_event, 0, sizeof(pressed_event));
    memset(&released_event, 0, sizeof(released_event));
    pressed_event.state = LIBRDP_KEY_PRESSED;
    pressed_event.scancode = 0x0fu;
    pressed_event.flags = 0;

    CHECK(x11_keyboard_record_press(pressed, 256u, &count, 23u, &pressed_event) == 1);
    CHECK(count == 1u && pressed[23].down);
    CHECK(x11_keyboard_record_press(pressed, 256u, &count, 23u, &pressed_event) == 0);
    CHECK(count == 1u);
    CHECK(x11_keyboard_prepare_release(pressed, 256u, &count, 23u, &released_event) == 1);
    CHECK(count == 0u && !pressed[23].down);
    CHECK(released_event.state == LIBRDP_KEY_RELEASED);
    CHECK(released_event.scancode == pressed_event.scancode);
    CHECK(x11_keyboard_prepare_release(pressed, 256u, &count, 23u, &released_event) == 0);
    CHECK(x11_keyboard_record_press(pressed, 256u, &count, 300u, &pressed_event) == 1);
    CHECK(count == 0u);
    return 0;
}

int main(void)
{
    if (test_xkb_key_name_mapping() != 0)
        return 1;
    if (test_evdev_fallback_mapping() != 0)
        return 1;
    if (test_unicode_fallback_policy() != 0)
        return 1;
    if (test_unicode_fallback_emission() != 0)
        return 1;
    if (test_autorepeat_release_match() != 0)
        return 1;
    if (test_press_release_state() != 0)
        return 1;
    return 0;
}
