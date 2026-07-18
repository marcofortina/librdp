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
#include "admin_options.h"

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

static void cocoa_admin_append_session(NSMutableString* text, size_t index, const librdp_admin_session* session)
{
    [text appendFormat:@"session index=%zu session_id=%u logon_id=%llu user=\"%s\" domain=\"%s\" "
                       @"state=\"%s\" client=\"%s\" station=\"%s\" protocol=\"%s\"\n",
                       index,
                       (unsigned)session->session_id,
                       (unsigned long long)session->logon_id,
                       session->username ? session->username : "",
                       session->domain ? session->domain : "",
                       session->state ? session->state : "",
                       session->client_name ? session->client_name : "",
                       session->station_name ? session->station_name : "",
                       session->protocol_name ? session->protocol_name : ""];
}

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
            cocoa_admin_append_session(text, i, &session);
    }
    return text;
}

static void cocoa_admin_show_window(NSString* summary)
{
    NSWindow* window = nil;
    NSScrollView* scroll = nil;
    NSTextView* text_view = nil;
    CocoaAdminWindowDelegate* delegate = nil;
    NSRect frame = NSMakeRect(0.0, 0.0, 900.0, 520.0);

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
}

int main(int argc, char** argv)
{
    admin_options options;
    librdp_admin* admin = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    NSString* summary = nil;
    int rc = 0;

    @autoreleasepool
    {
        if (!admin_options_parse(argc, argv, &options, stderr))
        {
            admin_options_usage(stderr, argv[0]);
            return 2;
        }
        if (options.show_help)
        {
            admin_options_usage(stdout, argv[0]);
            return 0;
        }
        admin = librdp_admin_new(&options.config);
        if (!admin)
        {
            fprintf(stderr, "failed to create admin handle\n");
            return 2;
        }
        if (options.execute_action)
        {
            status = librdp_admin_execute_action(admin, &options.action);
            if (status != LIBRDP_STATUS_OK)
            {
                fprintf(stderr, "admin action failed: %s\n", librdp_status_name(status));
                librdp_admin_free(admin);
                return 3;
            }
            printf("admin action done type=%u session_id=%u\n",
                   (unsigned)options.action.type,
                   (unsigned)options.action.session_id);
        }
        status = librdp_admin_query_sessions(admin);
        if (status != LIBRDP_STATUS_OK)
        {
            fprintf(stderr, "admin query failed: %s\n", librdp_status_name(status));
            librdp_admin_free(admin);
            return 3;
        }
        summary = cocoa_admin_summary(admin);
        fputs([summary UTF8String], stdout);
        if (!options.no_window)
            cocoa_admin_show_window(summary);
        librdp_admin_free(admin);
    }
    return rc;
}
