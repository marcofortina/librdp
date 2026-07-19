/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: native Cocoa permission prompts for the desktop server.
 * Invariants: privacy prompts occur only in interactive startup, application
 * consent is requested separately for clipboard and drive access, and denial
 * of one optional provider does not authorize or disable another.
 * Ownership: AppKit objects are autoreleased; no caller storage is retained.
 * Threading: all AppKit interaction runs synchronously on the main thread.
 * Trust boundary: mount paths are displayed as text only and are never opened
 * by the consent UI.
 */

#include "cocoa_permission.h"

#import <ApplicationServices/ApplicationServices.h>
#import <Cocoa/Cocoa.h>
#import <CoreGraphics/CoreGraphics.h>

#include <string.h>

static int cocoa_permission_screen_preflight(void* context)
{
    (void)context;
    return CGPreflightScreenCaptureAccess() ? 1 : 0;
}

static int cocoa_permission_screen_request(void* context)
{
    (void)context;
    return CGRequestScreenCaptureAccess() ? 1 : 0;
}

static int cocoa_permission_accessibility_preflight(void* context)
{
    (void)context;
    return cocoa_server_accessibility_permission(0);
}

static int cocoa_permission_accessibility_request(void* context)
{
    (void)context;
    return cocoa_server_accessibility_permission(1);
}

static void cocoa_permission_activate_application(void)
{
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    if (@available(macOS 14.0, *))
        [NSApp activate];
    else
        [NSApp activateIgnoringOtherApps:YES];
}

static NSString* cocoa_permission_name(server_platform_permission_kind kind)
{
    switch (kind)
    {
    case SERVER_PLATFORM_PERMISSION_CAPTURE:
        return @"Screen Recording";
    case SERVER_PLATFORM_PERMISSION_INPUT:
        return @"Accessibility";
    case SERVER_PLATFORM_PERMISSION_CLIPBOARD:
        return @"Clipboard Sharing";
    case SERVER_PLATFORM_PERMISSION_DRIVE:
        return @"Client Drive Access";
    default:
        return @"Permission";
    }
}

static NSURL* cocoa_permission_settings_url(
    server_platform_permission_kind kind)
{
    NSString* value = nil;

    if (kind == SERVER_PLATFORM_PERMISSION_CAPTURE)
    {
        value = @"x-apple.systempreferences:"
                @"com.apple.preference.security?Privacy_ScreenCapture";
    }
    else if (kind == SERVER_PLATFORM_PERMISSION_INPUT)
    {
        value = @"x-apple.systempreferences:"
                @"com.apple.preference.security?Privacy_Accessibility";
    }
    return value ? [NSURL URLWithString:value] : nil;
}

static int cocoa_permission_confirm(server_platform_permission_kind kind,
                                    const char* detail, void* context)
{
    NSAlert* alert = nil;
    NSString* description = nil;
    NSModalResponse response = NSModalResponseCancel;

    (void)context;
    cocoa_permission_activate_application();
    alert = [[[NSAlert alloc] init] autorelease];
    [alert setAlertStyle:NSAlertStyleWarning];
    [alert
        setMessageText:[NSString stringWithFormat:@"Allow %@?",
                                                  cocoa_permission_name(kind)]];
    if (kind == SERVER_PLATFORM_PERMISSION_CLIPBOARD)
    {
        description =
            @"Remote users will be able to read and replace supported "
             "clipboard formats while connected.";
    }
    else if (kind == SERVER_PLATFORM_PERMISSION_DRIVE)
    {
        NSString* mount = detail ? [NSString stringWithUTF8String:detail] : nil;

        description =
            [NSString stringWithFormat:
                          @"Client-announced drives will be mounted read-only "
                           "at %@ while the server is running.",
                          mount ? mount : @"the selected mount point"];
    }
    else
        description = @"The requested provider requires local consent.";
    [alert setInformativeText:description];
    [alert addButtonWithTitle:@"Allow"];
    [alert addButtonWithTitle:@"Disable"];
    response = [alert runModal];
    return response == NSAlertFirstButtonReturn ? 1 : 0;
}

static void cocoa_permission_show_denied(server_platform_permission_kind kind,
                                         void* context)
{
    NSAlert* alert = nil;
    NSURL* settings = cocoa_permission_settings_url(kind);
    NSModalResponse response = NSModalResponseCancel;

    (void)context;
    cocoa_permission_activate_application();
    alert = [[[NSAlert alloc] init] autorelease];
    [alert setAlertStyle:NSAlertStyleWarning];
    [alert
        setMessageText:[NSString stringWithFormat:@"%@ is not authorized",
                                                  cocoa_permission_name(kind)]];
    [alert setInformativeText:
               @"Grant access in System Settings, then restart the server. "
                "Other optional providers remain independently available."];
    if (settings)
        [alert addButtonWithTitle:@"Open System Settings"];
    [alert addButtonWithTitle:@"Continue"];
    response = [alert runModal];
    if (settings && response == NSAlertFirstButtonReturn)
        [[NSWorkspace sharedWorkspace] openURL:settings];
}

void cocoa_server_permission_policy_init(cocoa_server_permission_policy* policy)
{
    if (!policy)
        return;
    memset(policy, 0, sizeof(*policy));
    policy->interactive = 1;
    policy->request_capture = 1;
}

/*
 * Query the Accessibility trust database and request the standard macOS
 * consent prompt only when the caller explicitly opts in.
 */
int cocoa_server_accessibility_permission(int prompt)
{
    NSDictionary* options = nil;

    if (prompt)
    {
        options = [NSDictionary
            dictionaryWithObject:@YES
                          forKey:(NSString*)kAXTrustedCheckOptionPrompt];
    }
    return AXIsProcessTrustedWithOptions((CFDictionaryRef)options) ? 1 : 0;
}

static int cocoa_permission_boolean(int value)
{
    return value == 0 || value == 1;
}

static int cocoa_permission_backend_valid(
    const cocoa_server_permission_backend* backend)
{
    return backend && backend->screen_preflight && backend->screen_request &&
           backend->accessibility_preflight && backend->accessibility_request &&
           backend->confirm && backend->show_denied;
}

/*
 * Resolve each requested provider without sharing state between decisions.
 * System privacy checks are authoritative in every mode; only AppKit prompts
 * and application-level confirmation are skipped for non-interactive startup.
 */
static librdp_status cocoa_permission_resolve_backend(
    const cocoa_server_permission_policy* policy,
    const cocoa_server_permission_backend* backend,
    cocoa_server_permission_result* result)
{
    if (!policy || !result || !cocoa_permission_backend_valid(backend) ||
        !cocoa_permission_boolean(policy->interactive) ||
        !cocoa_permission_boolean(policy->request_capture) ||
        !cocoa_permission_boolean(policy->request_input) ||
        !cocoa_permission_boolean(policy->request_clipboard) ||
        !cocoa_permission_boolean(policy->request_drive) ||
        !policy->request_capture ||
        (policy->request_drive &&
         (!policy->drive_mount || policy->drive_mount[0] == '\0')))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));
    result->capture = backend->screen_preflight(backend->context);
    if (!result->capture && policy->interactive)
    {
        result->capture = backend->screen_request(backend->context);
        if (!result->capture)
        {
            backend->show_denied(SERVER_PLATFORM_PERMISSION_CAPTURE,
                                 backend->context);
        }
    }
    if (policy->request_input)
    {
        result->input = backend->accessibility_preflight(backend->context);
        if (!result->input && policy->interactive)
        {
            result->input = backend->accessibility_request(backend->context);
            if (!result->input)
            {
                backend->show_denied(SERVER_PLATFORM_PERMISSION_INPUT,
                                     backend->context);
            }
        }
    }
    if (policy->request_clipboard)
    {
        result->clipboard =
            !policy->interactive ||
            backend->confirm(SERVER_PLATFORM_PERMISSION_CLIPBOARD, NULL,
                             backend->context);
    }
    if (policy->request_drive)
    {
        result->drive = !policy->interactive ||
                        backend->confirm(SERVER_PLATFORM_PERMISSION_DRIVE,
                                         policy->drive_mount, backend->context);
    }
    return LIBRDP_STATUS_OK;
}

librdp_status cocoa_server_permission_resolve(
    const cocoa_server_permission_policy* policy,
    cocoa_server_permission_result* result)
{
    const cocoa_server_permission_backend backend = {
        cocoa_permission_screen_preflight,
        cocoa_permission_screen_request,
        cocoa_permission_accessibility_preflight,
        cocoa_permission_accessibility_request,
        cocoa_permission_confirm,
        cocoa_permission_show_denied,
        NULL,
    };

    return cocoa_permission_resolve_backend(policy, &backend, result);
}

#ifdef LIBRDP_COCOA_SERVER_TESTING
librdp_status cocoa_server_permission_resolve_with_backend(
    const cocoa_server_permission_policy* policy,
    const cocoa_server_permission_backend* backend,
    cocoa_server_permission_result* result)
{
    return cocoa_permission_resolve_backend(policy, backend, result);
}
#endif
