/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa viewer keyboard and text-input bridge.
 * Invariants: text comes from AppKit's active input context, commands and
 * modifier shortcuts use physical Carbon positions, and every tracked key has
 * at most one terminal release.
 * Ownership: no AppKit object is retained beyond a synchronous call; pressed
 * key records and the borrowed event sink belong to the bridge.
 * Threading: the bridge is confined to the AppKit main thread.
 * Trust boundary: malformed UTF-16, unknown native key positions, and
 * unbounded committed strings are rejected without emitting partial input.
 */

#include "cocoa_input.h"

#include "cocoa_keymap.h"

#import <Carbon/Carbon.h>

#include <string.h>

#define COCOA_INPUT_MAX_TEXT_UNITS 4096u

static int cocoa_input_valid_utf16(NSString* string)
{
    NSUInteger length = string ? [string length] : 0u;
    NSUInteger index = 0u;

    if (!string || length == 0u ||
        length > COCOA_INPUT_MAX_TEXT_UNITS)
        return 0;
    while (index < length)
    {
        unichar unit = [string characterAtIndex:index++];

        if (unit == 0u ||
            (unit >= 0xdc00u && unit <= 0xdfffu))
            return 0;
        if (unit >= 0xd800u && unit <= 0xdbffu)
        {
            unichar low = 0u;

            if (index >= length)
                return 0;
            low = [string characterAtIndex:index++];
            if (low < 0xdc00u || low > 0xdfffu)
                return 0;
        }
    }
    return 1;
}

static NSString* cocoa_input_string(id text)
{
    if ([text isKindOfClass:[NSAttributedString class]])
        return [(NSAttributedString*)text string];
    if ([text isKindOfClass:[NSString class]])
        return (NSString*)text;
    return nil;
}

static NSEventModifierFlags cocoa_input_modifier_mask(uint16_t keycode)
{
    switch (keycode)
    {
    case kVK_Shift:
    case kVK_RightShift:
        return NSEventModifierFlagShift;
    case kVK_Control:
    case kVK_RightControl:
        return NSEventModifierFlagControl;
    case kVK_Option:
    case kVK_RightOption:
        return NSEventModifierFlagOption;
    case kVK_Command:
    case kVK_RightCommand:
        return NSEventModifierFlagCommand;
    case kVK_CapsLock:
        return NSEventModifierFlagCapsLock;
    default:
        return 0u;
    }
}

static int cocoa_input_function_character(NSString* characters)
{
    unichar value = 0u;

    if (!characters || [characters length] != 1u)
        return 0;
    value = [characters characterAtIndex:0u];
    return value >= NSUpArrowFunctionKey &&
           value <= NSModeSwitchFunctionKey;
}

static int cocoa_input_command_keycode(SEL selector,
                                       uint16_t* keycode)
{
    if (!selector || !keycode)
        return 0;
    if (selector == @selector(insertNewline:) ||
        selector == @selector(insertLineBreak:) ||
        selector == @selector(insertNewlineIgnoringFieldEditor:))
        *keycode = kVK_Return;
    else if (selector == @selector(insertTab:) ||
             selector == @selector(insertBacktab:))
        *keycode = kVK_Tab;
    else if (selector == @selector(deleteBackward:))
        *keycode = kVK_Delete;
    else if (selector == @selector(deleteForward:))
        *keycode = kVK_ForwardDelete;
    else if (selector == @selector(moveLeft:))
        *keycode = kVK_LeftArrow;
    else if (selector == @selector(moveRight:))
        *keycode = kVK_RightArrow;
    else if (selector == @selector(moveUp:))
        *keycode = kVK_UpArrow;
    else if (selector == @selector(moveDown:))
        *keycode = kVK_DownArrow;
    else if (selector == @selector(pageUp:) ||
             selector == @selector(scrollPageUp:))
        *keycode = kVK_PageUp;
    else if (selector == @selector(pageDown:) ||
             selector == @selector(scrollPageDown:))
        *keycode = kVK_PageDown;
    else if (selector == @selector(moveToBeginningOfLine:) ||
             selector == @selector(moveToBeginningOfDocument:))
        *keycode = kVK_Home;
    else if (selector == @selector(moveToEndOfLine:) ||
             selector == @selector(moveToEndOfDocument:))
        *keycode = kVK_End;
    else if (selector == @selector(cancelOperation:))
        *keycode = kVK_Escape;
    else
        return 0;
    return 1;
}

@implementation CocoaViewerInputBridge

- (id)initWithSink:(cocoa_viewer_key_sink)sink
         userData:(void*)userData
{
    self = [super init];
    if (!self || !sink)
        return nil;
    _sink = sink;
    _userData = userData;
    memset(_pressedKeys, 0, sizeof(_pressedKeys));
    memset(_keyDown, 0, sizeof(_keyDown));
    return self;
}

- (BOOL)sendNativeKey:(uint16_t)keycode
              pressed:(BOOL)pressed
                repeat:(BOOL)repeat
{
    librdp_key_event event;
    uint32_t scancode = 0u;
    uint32_t flags = 0u;

    if (keycode >= sizeof(_keyDown) /
                       sizeof(_keyDown[0]))
        return NO;
    if (!pressed && _keyDown[keycode] != 0u)
    {
        event = _pressedKeys[keycode];
        event.state = LIBRDP_KEY_RELEASED;
    }
    else
    {
        if (!cocoa_keymap_native_to_rdp(
                keycode, &scancode, &flags))
            return NO;
        memset(&event, 0, sizeof(event));
        event.scancode = scancode;
        event.flags = flags;
        event.state = pressed ? LIBRDP_KEY_PRESSED
                              : LIBRDP_KEY_RELEASED;
    }
    if (pressed && _keyDown[keycode] != 0u && !repeat)
        return YES;
    if (!pressed && _keyDown[keycode] == 0u)
        return YES;
    if (_sink(&event, _userData) != LIBRDP_STATUS_OK)
        return NO;
    if (pressed)
    {
        _pressedKeys[keycode] = event;
        _keyDown[keycode] = 1u;
    }
    else
    {
        memset(&_pressedKeys[keycode],
               0,
               sizeof(_pressedKeys[keycode]));
        _keyDown[keycode] = 0u;
    }
    return YES;
}

- (BOOL)handleKeyDown:(NSEvent*)event
{
    NSEventModifierFlags modifiers = 0u;
    NSString* characters = nil;
    uint16_t keycode = 0u;

    if (!event)
        return NO;
    keycode = (uint16_t)[event keyCode];
    modifiers = [event modifierFlags] &
                NSEventModifierFlagDeviceIndependentFlagsMask;
    characters = [event charactersIgnoringModifiers];
    if ((modifiers & (NSEventModifierFlagControl |
                      NSEventModifierFlagOption |
                      NSEventModifierFlagCommand)) == 0u &&
        !cocoa_input_function_character(characters) &&
        [characters length] != 0u)
        return NO;
    return [self sendNativeKey:keycode
                       pressed:YES
                         repeat:[event isARepeat]];
}

- (BOOL)handleKeyUp:(NSEvent*)event
{
    uint16_t keycode = 0u;

    if (!event)
        return NO;
    keycode = (uint16_t)[event keyCode];
    if (keycode >= sizeof(_keyDown) /
                       sizeof(_keyDown[0]) ||
        _keyDown[keycode] == 0u)
        return NO;
    return [self sendNativeKey:keycode
                       pressed:NO
                         repeat:NO];
}

- (BOOL)handleFlagsChanged:(NSEvent*)event
{
    NSEventModifierFlags mask = 0u;
    uint16_t keycode = 0u;

    if (!event)
        return NO;
    keycode = (uint16_t)[event keyCode];
    mask = cocoa_input_modifier_mask(keycode);
    if (mask == 0u)
        return NO;
    return [self sendNativeKey:keycode
                       pressed:([event modifierFlags] & mask) != 0u
                         repeat:NO];
}

- (BOOL)sendCommittedText:(id)text
{
    NSString* string = cocoa_input_string(text);
    NSUInteger length = 0u;
    NSUInteger index = 0u;

    if (!cocoa_input_valid_utf16(string))
        return NO;
    length = [string length];
    for (index = 0u; index < length; index++)
    {
        librdp_key_event event;

        memset(&event, 0, sizeof(event));
        event.flags = LIBRDP_KEY_FLAG_UNICODE;
        event.unicode = [string characterAtIndex:index];
        event.state = LIBRDP_KEY_PRESSED;
        if (_sink(&event, _userData) != LIBRDP_STATUS_OK)
            return NO;
        event.state = LIBRDP_KEY_RELEASED;
        if (_sink(&event, _userData) != LIBRDP_STATUS_OK)
            return NO;
    }
    return YES;
}

- (BOOL)sendCommand:(SEL)selector
{
    uint16_t keycode = 0u;

    if (!cocoa_input_command_keycode(selector, &keycode))
        return NO;
    if (![self sendNativeKey:keycode
                     pressed:YES
                       repeat:NO])
        return NO;
    return [self sendNativeKey:keycode
                       pressed:NO
                         repeat:NO];
}

- (void)releaseAll
{
    size_t keycode = 0u;

    for (keycode = 0u;
         keycode < sizeof(_keyDown) /
                       sizeof(_keyDown[0]);
         keycode++)
    {
        if (_keyDown[keycode] != 0u)
        {
            (void)[self sendNativeKey:(uint16_t)keycode
                              pressed:NO
                                repeat:NO];
        }
    }
}

@end
