/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: native Cocoa administration tool.
 * Invariants: command-line values are copied into the public admin config,
 * AppKit only renders borrowed session views, and destructive actions require
 * explicit confirmation.
 * Ownership: librdp_admin owns copied endpoint data; AppKit owns the window
 * and text view while the summary is displayed.
 * Threading: synchronous command-line and AppKit main-thread execution.
 * Trust boundary: endpoint XML is remote input and is shown only after public
 * parsing into bounded session inventory fields.
 */

#import <Cocoa/Cocoa.h>
#include "admin_app.h"

#include <librdp/librdp.h>

#include <stdio.h>

@interface CocoaAdminWindowDelegate : NSObject <NSWindowDelegate>
@end

@implementation CocoaAdminWindowDelegate
- (void)windowWillClose:(NSNotification*)notification
{
    (void)notification;
    [NSApp terminate:nil];
}
@end

static NSString* cocoa_admin_summary(const librdp_admin* admin)
{
    NSMutableString* text = [NSMutableString string];
    size_t count = librdp_admin_session_count(admin);
    size_t i = 0;

    [text appendFormat:@"sessions count=%zu\n", count];
    for (i = 0; i < count; i++)
    {
        librdp_admin_session session;

        if (librdp_admin_session_init(&session) == LIBRDP_STATUS_OK &&
            librdp_admin_session_at(admin, i, &session) == LIBRDP_STATUS_OK)
        {
            [text appendFormat:@"%zu  id=%u  logon=%llu  user=%s\\%s  "
                               @"state=%s  client=%s\n",
                               i,
                               (unsigned)session.session_id,
                               (unsigned long long)session.logon_id,
                               session.domain ? session.domain : "",
                               session.username ? session.username : "",
                               session.state ? session.state : "",
                               session.client_name ? session.client_name : ""];
        }
    }
    return text;
}

static int cocoa_admin_present(const librdp_admin* admin, void* user_data)
{
    NSString* summary = cocoa_admin_summary(admin);
    NSWindow* window = nil;
    NSScrollView* scroll = nil;
    NSTextView* text_view = nil;
    CocoaAdminWindowDelegate* delegate = nil;
    NSRect frame = NSMakeRect(0.0, 0.0, 900.0, 520.0);

    (void)user_data;
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    window = [[NSWindow alloc] initWithContentRect:frame
                                         styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                                   NSWindowStyleMaskResizable | NSWindowStyleMaskMiniaturizable
                                           backing:NSBackingStoreBuffered
                                             defer:NO];
    delegate = [[CocoaAdminWindowDelegate alloc] init];
    [window setDelegate:delegate];
    [window setTitle:@"librdp-cocoa-admin"];
    scroll = [[NSScrollView alloc] initWithFrame:frame];
    [scroll setHasVerticalScroller:YES];
    text_view = [[NSTextView alloc] initWithFrame:frame];
    [text_view setEditable:NO];
    [text_view setString:summary ? summary : @""];
    [scroll setDocumentView:text_view];
    [window setContentView:scroll];
    [window center];
    [window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
    [NSApp run];
    return 1;
}

int main(int argc, char** argv)
{
    const admin_app_platform platform = {
        cocoa_admin_present,
        NULL
    };
    int rc = 0;

    @autoreleasepool
    {
        rc = admin_app_run(argc, argv, &platform);
    }
    return rc;
}
