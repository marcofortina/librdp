/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa viewer keyboard and text-input bridge.
 * Invariants: AppKit commits text through NSTextInputClient before Unicode is
 * sent, physical shortcuts retain balanced press/release state, and focus loss
 * releases every remote key.
 * Ownership: the bridge borrows its sink context and copies all key state;
 * NSEvent and text objects are borrowed only for each method call.
 * Threading: all methods run on the AppKit main thread.
 * Trust boundary: native key codes and committed UTF-16 are bounded and
 * validated before becoming remote input events.
 */

#ifndef LIBRDP_COCOA_VIEWER_INPUT_H
#define LIBRDP_COCOA_VIEWER_INPUT_H

#import <Cocoa/Cocoa.h>

#include <librdp/error.h>
#include <librdp/input.h>

typedef librdp_status (*cocoa_viewer_key_sink)(
    const librdp_key_event* event,
    void* user_data);

@interface CocoaViewerInputBridge : NSObject
{
    cocoa_viewer_key_sink _sink;
    void* _userData;
    librdp_key_event _pressedKeys[256];
    uint8_t _keyDown[256];
}

- (id)initWithSink:(cocoa_viewer_key_sink)sink
         userData:(void*)userData;
- (BOOL)handleKeyDown:(NSEvent*)event;
- (BOOL)handleKeyUp:(NSEvent*)event;
- (BOOL)handleFlagsChanged:(NSEvent*)event;
- (BOOL)sendCommittedText:(id)text;
- (BOOL)sendCommand:(SEL)selector;
- (void)releaseAll;

@end

#endif
