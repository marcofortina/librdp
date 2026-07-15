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
#include <librdp/librdp.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ADMIN_ACTION_QUERY ((librdp_admin_action_type)0)

typedef struct cocoa_admin_options
{
    librdp_admin_config config;
    librdp_admin_action action;
    int no_window;
    int show_help;
    int execute_action;
    int confirm_action;
} cocoa_admin_options;

@interface CocoaAdminWindowDelegate : NSObject <NSWindowDelegate>
@end

@implementation CocoaAdminWindowDelegate
- (void)windowWillClose:(NSNotification*)notification
{
    (void)notification;
    [NSApp terminate:nil];
}
@end

static void cocoa_admin_usage(FILE* stream, const char* program)
{
    fprintf(stream,
            "usage: %s --endpoint url [--user name] [--password value] [--password-env name] "
            "[--domain name] [--resource-uri uri] [--timeout ms] [--insecure-lab] "
            "[--action query|logoff|disconnect|message] [--session-id id] "
            "[--message-title text] [--message-text text] [--confirm] [--no-window]\n",
            program);
}

static int cocoa_admin_parse_u32(const char* text, uint32_t* value)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!text || !value)
        return 0;
    parsed = strtoul(text, &end, 10);
    if (!end || *end != '\0' || parsed > UINT32_MAX)
        return 0;
    *value = (uint32_t)parsed;
    return 1;
}

static int cocoa_admin_need_value(int argc, int* index, const char* option)
{
    if (*index + 1 < argc)
    {
        *index += 1;
        return 1;
    }
    fprintf(stderr, "%s requires a value\n", option);
    return 0;
}

static int cocoa_admin_parse_action_type(const char* text, librdp_admin_action_type* type)
{
    if (!text || !type)
        return 0;
    if (strcmp(text, "query") == 0)
        *type = ADMIN_ACTION_QUERY;
    else if (strcmp(text, "logoff") == 0)
        *type = LIBRDP_ADMIN_ACTION_LOGOFF;
    else if (strcmp(text, "disconnect") == 0)
        *type = LIBRDP_ADMIN_ACTION_DISCONNECT;
    else if (strcmp(text, "message") == 0)
        *type = LIBRDP_ADMIN_ACTION_MESSAGE;
    else
        return 0;
    return 1;
}

static int cocoa_admin_init(cocoa_admin_options* options)
{
    if (!options)
        return 0;
    memset(options, 0, sizeof(*options));
    return librdp_admin_config_init(&options->config) == LIBRDP_STATUS_OK &&
           librdp_admin_action_init(&options->action) == LIBRDP_STATUS_OK;
}

static int cocoa_admin_parse_args(int argc, char** argv, cocoa_admin_options* options)
{
    int i = 0;

    if (!cocoa_admin_init(options))
        return 0;
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
            options->show_help = 1;
        else if (strcmp(argv[i], "--endpoint") == 0)
        {
            if (!cocoa_admin_need_value(argc, &i, argv[i]))
                return 0;
            options->config.endpoint_url = argv[i];
        }
        else if (strcmp(argv[i], "--user") == 0)
        {
            if (!cocoa_admin_need_value(argc, &i, argv[i]))
                return 0;
            options->config.username = argv[i];
        }
        else if (strcmp(argv[i], "--password") == 0)
        {
            if (!cocoa_admin_need_value(argc, &i, argv[i]))
                return 0;
            options->config.password = argv[i];
        }
        else if (strcmp(argv[i], "--password-env") == 0)
        {
            const char* value = NULL;

            if (!cocoa_admin_need_value(argc, &i, argv[i]))
                return 0;
            value = getenv(argv[i]);
            if (!value)
            {
                fprintf(stderr, "password environment variable is not set\n");
                return 0;
            }
            options->config.password = value;
        }
        else if (strcmp(argv[i], "--domain") == 0)
        {
            if (!cocoa_admin_need_value(argc, &i, argv[i]))
                return 0;
            options->config.domain = argv[i];
        }
        else if (strcmp(argv[i], "--resource-uri") == 0)
        {
            if (!cocoa_admin_need_value(argc, &i, argv[i]))
                return 0;
            options->config.resource_uri = argv[i];
        }
        else if (strcmp(argv[i], "--timeout") == 0)
        {
            if (!cocoa_admin_need_value(argc, &i, argv[i]) ||
                !cocoa_admin_parse_u32(argv[i], &options->config.timeout_ms))
                return 0;
        }
        else if (strcmp(argv[i], "--insecure-lab") == 0)
            options->config.allow_insecure_tls = 1;
        else if (strcmp(argv[i], "--no-window") == 0)
            options->no_window = 1;
        else if (strcmp(argv[i], "--action") == 0)
        {
            librdp_admin_action_type type = ADMIN_ACTION_QUERY;

            if (!cocoa_admin_need_value(argc, &i, argv[i]) ||
                !cocoa_admin_parse_action_type(argv[i], &type))
                return 0;
            options->execute_action = type != ADMIN_ACTION_QUERY;
            if (type != ADMIN_ACTION_QUERY)
                options->action.type = type;
        }
        else if (strcmp(argv[i], "--session-id") == 0)
        {
            if (!cocoa_admin_need_value(argc, &i, argv[i]) ||
                !cocoa_admin_parse_u32(argv[i], &options->action.session_id))
                return 0;
        }
        else if (strcmp(argv[i], "--message-title") == 0)
        {
            if (!cocoa_admin_need_value(argc, &i, argv[i]))
                return 0;
            options->action.message_title = argv[i];
        }
        else if (strcmp(argv[i], "--message-text") == 0)
        {
            if (!cocoa_admin_need_value(argc, &i, argv[i]))
                return 0;
            options->action.message_text = argv[i];
        }
        else if (strcmp(argv[i], "--confirm") == 0)
            options->confirm_action = 1;
        else
        {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            return 0;
        }
    }
    if (!options->show_help && (!options->config.endpoint_url || options->config.endpoint_url[0] == '\0'))
    {
        fprintf(stderr, "--endpoint is required\n");
        return 0;
    }
    if (options->execute_action)
    {
        if (options->action.session_id == 0)
        {
            fprintf(stderr, "--session-id is required for admin actions\n");
            return 0;
        }
        if ((options->action.type == LIBRDP_ADMIN_ACTION_LOGOFF ||
             options->action.type == LIBRDP_ADMIN_ACTION_DISCONNECT) &&
            !options->confirm_action)
        {
            fprintf(stderr, "--confirm is required for logoff and disconnect actions\n");
            return 0;
        }
        if (options->action.type == LIBRDP_ADMIN_ACTION_MESSAGE && !options->action.message_text)
        {
            fprintf(stderr, "--message-text is required with --action message\n");
            return 0;
        }
    }
    return 1;
}

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
    cocoa_admin_options options;
    librdp_admin* admin = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    NSString* summary = nil;
    int rc = 0;

    @autoreleasepool
    {
        if (!cocoa_admin_parse_args(argc, argv, &options))
        {
            cocoa_admin_usage(stderr, argv[0]);
            return 2;
        }
        if (options.show_help)
        {
            cocoa_admin_usage(stdout, argv[0]);
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
