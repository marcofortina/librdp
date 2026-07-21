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
#include "x11_keymap.h"

#include <X11/X.h>

#include <xkbcommon/xkbcommon-compose.h>
#include <xkbcommon/xkbcommon-keysyms.h>
#include <xkbcommon/xkbcommon.h>

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
    char name[4];
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
    CHECK(x11_keymap_rdp_to_xkb_name(0x0fu, 0u, name) == 1);
    CHECK(memcmp(name, "TAB", sizeof(name)) == 0);
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

typedef struct keyboard_xkb_fixture
{
    struct xkb_context* context;
    struct xkb_keymap* keymap;
    struct xkb_state* state;
} keyboard_xkb_fixture;

static void keyboard_xkb_fixture_clear(
    keyboard_xkb_fixture* fixture)
{
    if (!fixture)
        return;
    xkb_state_unref(fixture->state);
    xkb_keymap_unref(fixture->keymap);
    xkb_context_unref(fixture->context);
    memset(fixture, 0, sizeof(*fixture));
}

static int keyboard_xkb_fixture_init(
    keyboard_xkb_fixture* fixture,
    const char* layout,
    const char* variant)
{
    struct xkb_rule_names names;

    if (!fixture || !layout)
        return 0;
    memset(fixture, 0, sizeof(*fixture));
    memset(&names, 0, sizeof(names));
    names.rules = "evdev";
    names.model = "pc105";
    names.layout = layout;
    names.variant = variant;
    fixture->context =
        xkb_context_new(XKB_CONTEXT_NO_FLAGS);
    if (fixture->context)
        fixture->keymap = xkb_keymap_new_from_names(
            fixture->context,
            &names,
            XKB_KEYMAP_COMPILE_NO_FLAGS);
    if (fixture->keymap)
        fixture->state =
            xkb_state_new(fixture->keymap);
    if (!fixture->context ||
        !fixture->keymap ||
        !fixture->state)
    {
        keyboard_xkb_fixture_clear(fixture);
        return 0;
    }
    return 1;
}

/*
 * The system XKB database owns layout semantics. German AltGr produces "@"
 * while the physical RALT and AD01 names continue to map to the same RDP
 * positions used by every other layout.
 */
static int test_xkb_layout_and_altgr(void)
{
    keyboard_xkb_fixture fixture;
    xkb_keycode_t right_alt = XKB_KEYCODE_INVALID;
    xkb_keycode_t q_key = XKB_KEYCODE_INVALID;
    uint32_t scancode = 0u;
    uint32_t flags = 0u;
    char text[8];
    int length = 0;
    int ok = 0;

    if (!keyboard_xkb_fixture_init(
            &fixture,
            "de",
            NULL))
        return check_int(0, "German XKB fixture", __LINE__);
    right_alt =
        xkb_keymap_key_by_name(fixture.keymap, "RALT");
    q_key =
        xkb_keymap_key_by_name(fixture.keymap, "AD01");
    if (right_alt != XKB_KEYCODE_INVALID &&
        q_key != XKB_KEYCODE_INVALID &&
        x11_keyboard_map_xkb_name(
            xkb_keymap_key_get_name(
                fixture.keymap,
                right_alt),
            &scancode,
            &flags) == 1 &&
        scancode == 0x38u &&
        flags == LIBRDP_KEY_FLAG_EXTENDED)
    {
        ok = x11_keyboard_map_xkb_name(
                 xkb_keymap_key_get_name(
                     fixture.keymap,
                     q_key),
                 &scancode,
                 &flags) == 1 &&
             scancode == 0x10u &&
             flags == 0u;
    }
    if (ok)
    {
        (void)xkb_state_update_key(fixture.state,
                                   right_alt,
                                   XKB_KEY_DOWN);
        memset(text, 0, sizeof(text));
        length = xkb_state_key_get_utf8(fixture.state,
                                        q_key,
                                        text,
                                        sizeof(text));
        ok = length == 1 && strcmp(text, "@") == 0;
        (void)xkb_state_update_key(fixture.state,
                                   right_alt,
                                   XKB_KEY_UP);
    }
    keyboard_xkb_fixture_clear(&fixture);
    CHECK(ok);
    return 0;
}

static int keyboard_compose_result(
    struct xkb_compose_state* compose,
    const xkb_keysym_t* sequence,
    size_t count,
    char text[16])
{
    size_t index = 0u;
    int length = 0;

    if (!compose || !sequence || !text)
        return 0;
    xkb_compose_state_reset(compose);
    for (index = 0u; index < count; index++)
    {
        if (xkb_compose_state_feed(
                compose,
                sequence[index]) !=
            XKB_COMPOSE_FEED_ACCEPTED)
            return 0;
    }
    if (xkb_compose_state_get_status(compose) !=
        XKB_COMPOSE_COMPOSED)
        return 0;
    length = xkb_compose_state_get_utf8(
        compose,
        text,
        16u);
    return length > 0 && length < 16 ? length : 0;
}

/*
 * Dead-key and explicit Compose sequences are resolved by the installed XKB
 * compose table. The resulting UTF-8 is then converted into the exact Unicode
 * key pair emitted by the viewer, without a local character mapping table.
 */
static int test_xkb_dead_key_and_compose(void)
{
    keyboard_xkb_fixture fixture;
    struct xkb_compose_table* table = NULL;
    struct xkb_compose_state* compose = NULL;
    xkb_keycode_t dead_key = XKB_KEYCODE_INVALID;
    xkb_keycode_t e_key = XKB_KEYCODE_INVALID;
    xkb_keysym_t dead_sequence[2];
    static const xkb_keysym_t compose_sequence[] = {
        XKB_KEY_Multi_key,
        XKB_KEY_apostrophe,
        XKB_KEY_e
    };
    keyboard_event_capture capture;
    char text[16];
    int length = 0;
    int ok = 0;

    if (!keyboard_xkb_fixture_init(
            &fixture,
            "us",
            "intl"))
        return check_int(0, "US international XKB fixture", __LINE__);
    table = xkb_compose_table_new_from_locale(
        fixture.context,
        "en_US.UTF-8",
        XKB_COMPOSE_COMPILE_NO_FLAGS);
    if (table)
        compose = xkb_compose_state_new(
            table,
            XKB_COMPOSE_STATE_NO_FLAGS);
    if (compose)
    {
        dead_key =
            xkb_keymap_key_by_name(
                fixture.keymap,
                "AC11");
        e_key =
            xkb_keymap_key_by_name(
                fixture.keymap,
                "AD03");
        if (dead_key != XKB_KEYCODE_INVALID &&
            e_key != XKB_KEYCODE_INVALID)
        {
            dead_sequence[0] =
                xkb_state_key_get_one_sym(
                    fixture.state,
                    dead_key);
            dead_sequence[1] =
                xkb_state_key_get_one_sym(
                    fixture.state,
                    e_key);
            ok = dead_sequence[0] ==
                     XKB_KEY_dead_acute &&
                 dead_sequence[1] == XKB_KEY_e;
        }
    }
    if (ok)
    {
        memset(text, 0, sizeof(text));
        length = keyboard_compose_result(
            compose,
            dead_sequence,
            sizeof(dead_sequence) /
                sizeof(dead_sequence[0]),
            text);
        ok = length == 2 &&
             memcmp(text, "\xc3\xa9", 2u) == 0;
    }
    if (ok)
    {
        memset(&capture, 0, sizeof(capture));
        ok = x11_keyboard_emit_utf8(
                 text,
                 (size_t)length,
                 capture_keyboard_event,
                 &capture) == 1u &&
             capture.count == 2u &&
             capture.events[0].unicode == 0x00e9u &&
             capture.events[1].unicode == 0x00e9u;
    }
    if (ok)
    {
        memset(text, 0, sizeof(text));
        length = keyboard_compose_result(
            compose,
            compose_sequence,
            sizeof(compose_sequence) /
                sizeof(compose_sequence[0]),
            text);
        ok = length == 2 &&
             memcmp(text, "\xc3\xa9", 2u) == 0;
    }
    if (compose)
        xkb_compose_state_unref(compose);
    if (table)
        xkb_compose_table_unref(table);
    keyboard_xkb_fixture_clear(&fixture);
    CHECK(ok);
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
    pressed[23].suppress_release = 1;
    CHECK(x11_keyboard_consume_suppressed_release(
              pressed,
              256u,
              23u) == 1);
    CHECK(pressed[23].suppress_release == 0);
    CHECK(x11_keyboard_consume_suppressed_release(
              pressed,
              256u,
              23u) == 0);
    pressed[23].suppress_release = 1;
    CHECK(x11_keyboard_record_press(
              pressed,
              256u,
              &count,
              23u,
              &pressed_event) == 1);
    CHECK(pressed[23].suppress_release == 0);
    CHECK(x11_keyboard_prepare_release(
              pressed,
              256u,
              &count,
              23u,
              &released_event) == 1);
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
    if (test_xkb_layout_and_altgr() != 0)
        return 1;
    if (test_xkb_dead_key_and_compose() != 0)
        return 1;
    if (test_autorepeat_release_match() != 0)
        return 1;
    if (test_press_release_state() != 0)
        return 1;
    return 0;
}
