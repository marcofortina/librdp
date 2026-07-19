/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: native Cocoa workspace feed launcher.
 * Invariants: common C policy validates feed metadata and launch arguments,
 * while AppKit owns only presentation and NSTask process execution.
 * Ownership: librdp_workspace owns parsed resources; AppKit owns summary
 * objects and the launch task while each operation is active.
 * Threading: synchronous CLI and AppKit main-thread execution.
 * Trust boundary: remote feed fields cross into native objects only after the
 * common bounded parser has accepted them as explicit viewer arguments.
 */

#import <Cocoa/Cocoa.h>
#include "workspace_app.h"

#include <librdp/librdp.h>

#include <stdio.h>

@interface CocoaWorkspaceWindowDelegate : NSObject <NSWindowDelegate>
@end

@implementation CocoaWorkspaceWindowDelegate
- (void)windowWillClose:(NSNotification*)notification
{
    (void)notification;
    [NSApp terminate:nil];
}
@end

static void cocoa_workspace_append_resource(NSMutableString* text,
                                            size_t index,
                                            const librdp_workspace_resource* resource)
{
    char target[WORKSPACE_FIELD_CAPACITY];
    char remote_app[WORKSPACE_FIELD_CAPACITY];
    char gateway[WORKSPACE_FIELD_CAPACITY];

    target[0] = '\0';
    remote_app[0] = '\0';
    gateway[0] = '\0';
    (void)workspace_resource_target(resource, target, sizeof(target));
    (void)workspace_resource_remote_app(resource, remote_app, sizeof(remote_app));
    (void)workspace_resource_gateway(resource, gateway, sizeof(gateway));
    [text appendFormat:@"resource index=%zu type=%s id=\"%s\" alias=\"%s\" title=\"%s\" "
                       @"target=\"%s\" app=\"%s\" gateway=\"%s\"\n",
                       index,
                       workspace_resource_type_name(resource->type),
                       resource->id ? resource->id : "",
                       resource->alias ? resource->alias : "",
                       resource->title ? resource->title : "",
                       target,
                       remote_app,
                       gateway];
}

static NSString* cocoa_workspace_summary(const librdp_workspace* workspace)
{
    NSMutableString* text = [NSMutableString string];
    size_t count = librdp_workspace_resource_count(workspace);
    size_t index = 0;

    [text appendFormat:@"resources count=%zu\n", count];
    for (index = 0; index < count; index++)
    {
        librdp_workspace_resource resource;

        if (librdp_workspace_resource_init(&resource) == LIBRDP_STATUS_OK &&
            librdp_workspace_resource_at(workspace, index, &resource) == LIBRDP_STATUS_OK)
            cocoa_workspace_append_resource(text, index, &resource);
    }
    return text;
}

/*
 * Convert a validated common launch plan into NSTask arguments. Invalid UTF-8
 * is rejected at the native boundary rather than silently dropping a remote
 * field or producing a different command line.
 */
static int cocoa_workspace_launch(
  const workspace_options* options,
  const librdp_workspace_resource* resource,
  void* user_data)
{
    workspace_launch_plan plan;
    NSMutableArray<NSString*>* arguments = [NSMutableArray array];
    NSTask* task = [[NSTask alloc] init];
    NSString* executable = nil;
    NSError* error = nil;
    size_t index = 0;

    (void)user_data;
    if (!workspace_launch_plan_build(options, resource, &plan, stderr))
        return 0;
    executable = [NSString stringWithUTF8String:plan.executable];
    if (!executable)
        return 0;
    for (index = 1; index < plan.argument_count; index++)
    {
        NSString* argument = [NSString stringWithUTF8String:plan.arguments[index]];

        if (!argument)
            return 0;
        [arguments addObject:argument];
    }
    [task setExecutableURL:[NSURL fileURLWithPath:executable]];
    [task setArguments:arguments];
    if (![task launchAndReturnError:&error])
    {
        fprintf(stderr, "viewer launch failed: %s\n", [[error localizedDescription] UTF8String]);
        return 0;
    }
    [task waitUntilExit];
    return [task terminationStatus] == 0;
}

static int cocoa_workspace_present(
  const workspace_options* options,
  const librdp_workspace* workspace,
  size_t selected,
  workspace_app_launch_callback launch,
  void* user_data)
{
    NSString* summary = cocoa_workspace_summary(workspace);
    NSWindow* window = nil;
    NSScrollView* scroll = nil;
    NSTextView* text_view = nil;
    CocoaWorkspaceWindowDelegate* delegate = nil;
    NSRect frame = NSMakeRect(0.0, 0.0, 940.0, 560.0);

    (void)options;
    (void)selected;
    (void)launch;
    (void)user_data;
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    window = [[NSWindow alloc] initWithContentRect:frame
                                         styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                                   NSWindowStyleMaskResizable | NSWindowStyleMaskMiniaturizable
                                           backing:NSBackingStoreBuffered
                                             defer:NO];
    delegate = [[CocoaWorkspaceWindowDelegate alloc] init];
    [window setDelegate:delegate];
    [window setTitle:@"librdp-cocoa-workspace"];
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
    const workspace_app_platform platform = {
        cocoa_workspace_launch,
        cocoa_workspace_present,
        NULL
    };
    int rc = 0;

    @autoreleasepool
    {
        rc = workspace_app_run(argc,
                               argv,
                               "librdp-viewer",
                               &platform);
    }
    return rc;
}
