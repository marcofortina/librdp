/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: native Cocoa workspace feed launcher.
 * Invariants: feed resources are accessed through public borrowed views,
 * launch arguments are built from bounded fields, and process execution is
 * explicit through --launch.
 * Ownership: librdp_workspace owns parsed feed data; AppKit owns the summary
 * window and NSTask owns child process state during launch.
 * Threading: synchronous CLI and AppKit main-thread execution.
 * Trust boundary: workspace XML and embedded RDP files are remote input; only
 * validated target, gateway, and RemoteApp fields are forwarded to the viewer.
 */

#import <Cocoa/Cocoa.h>
#include <librdp/librdp.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WORKSPACE_FIELD_MAX 1024u
#define WORKSPACE_LINE_MAX 512u

typedef struct cocoa_workspace_options
{
    librdp_workspace_config config;
    const char* select;
    const char* viewer;
    const char* security;
    int no_window;
    int show_help;
    int launch;
} cocoa_workspace_options;

@interface CocoaWorkspaceWindowDelegate : NSObject <NSWindowDelegate>
@end

@implementation CocoaWorkspaceWindowDelegate
- (void)windowWillClose:(NSNotification*)notification
{
    (void)notification;
    [NSApp terminate:nil];
}
@end

static void cocoa_workspace_usage(FILE* stream, const char* program)
{
    fprintf(stream,
            "usage: %s --feed url [--user name] [--password value] [--password-env name] "
            "[--domain name] [--timeout ms] [--select id|index|title|alias] "
            "[--viewer path] [--security auto|rdp|tls|nla] [--launch] [--no-window]\n",
            program);
}

static int cocoa_workspace_parse_u32(const char* text, uint32_t* value)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!text || !value)
        return 0;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed > UINT32_MAX)
        return 0;
    *value = (uint32_t)parsed;
    return 1;
}

static int cocoa_workspace_need_value(int argc, int* index, const char* option)
{
    if (*index + 1 < argc)
    {
        *index += 1;
        return 1;
    }
    fprintf(stderr, "%s requires a value\n", option);
    return 0;
}

static int cocoa_workspace_valid_security(const char* value)
{
    return value && (strcmp(value, "auto") == 0 || strcmp(value, "rdp") == 0 ||
                     strcmp(value, "tls") == 0 || strcmp(value, "nla") == 0);
}

static int cocoa_workspace_init(cocoa_workspace_options* options)
{
    if (!options)
        return 0;
    memset(options, 0, sizeof(*options));
    if (librdp_workspace_config_init(&options->config) != LIBRDP_STATUS_OK)
        return 0;
    options->viewer = "librdp-cocoa-viewer";
    options->security = "auto";
    return 1;
}

/*
 * Parse workspace feed options without contacting the feed. The selected
 * resource and launch command are validated later after the public workspace
 * API exposes bounded resource fields.
 */
static int cocoa_workspace_parse_args(int argc, char** argv, cocoa_workspace_options* options)
{
    int i = 0;

    if (!cocoa_workspace_init(options))
        return 0;
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
            options->show_help = 1;
        else if (strcmp(argv[i], "--feed") == 0)
        {
            if (!cocoa_workspace_need_value(argc, &i, argv[i]))
                return 0;
            options->config.feed_url = argv[i];
        }
        else if (strcmp(argv[i], "--user") == 0)
        {
            if (!cocoa_workspace_need_value(argc, &i, argv[i]))
                return 0;
            options->config.username = argv[i];
        }
        else if (strcmp(argv[i], "--password") == 0)
        {
            if (!cocoa_workspace_need_value(argc, &i, argv[i]))
                return 0;
            options->config.password = argv[i];
        }
        else if (strcmp(argv[i], "--password-env") == 0)
        {
            const char* value = NULL;

            if (!cocoa_workspace_need_value(argc, &i, argv[i]))
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
            if (!cocoa_workspace_need_value(argc, &i, argv[i]))
                return 0;
            options->config.domain = argv[i];
        }
        else if (strcmp(argv[i], "--timeout") == 0)
        {
            if (!cocoa_workspace_need_value(argc, &i, argv[i]) ||
                !cocoa_workspace_parse_u32(argv[i], &options->config.timeout_ms))
                return 0;
        }
        else if (strcmp(argv[i], "--select") == 0)
        {
            if (!cocoa_workspace_need_value(argc, &i, argv[i]))
                return 0;
            options->select = argv[i];
        }
        else if (strcmp(argv[i], "--viewer") == 0)
        {
            if (!cocoa_workspace_need_value(argc, &i, argv[i]))
                return 0;
            options->viewer = argv[i];
        }
        else if (strcmp(argv[i], "--security") == 0)
        {
            if (!cocoa_workspace_need_value(argc, &i, argv[i]))
                return 0;
            options->security = argv[i];
            if (!cocoa_workspace_valid_security(options->security))
                return 0;
        }
        else if (strcmp(argv[i], "--launch") == 0)
            options->launch = 1;
        else if (strcmp(argv[i], "--no-window") == 0)
            options->no_window = 1;
        else
        {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            return 0;
        }
    }
    if (!options->show_help && (!options->config.feed_url || options->config.feed_url[0] == '\0'))
    {
        fprintf(stderr, "--feed is required\n");
        return 0;
    }
    return 1;
}

static const char* cocoa_workspace_type_name(librdp_workspace_resource_type type)
{
    switch (type)
    {
        case LIBRDP_WORKSPACE_RESOURCE_DESKTOP:
            return "desktop";
        case LIBRDP_WORKSPACE_RESOURCE_REMOTE_APP:
            return "remote-app";
        default:
            return "unknown";
    }
}

static int cocoa_workspace_ascii_equal_ci(const char* a, size_t a_len, const char* b)
{
    size_t i = 0;

    if (!a || !b)
        return 0;
    for (i = 0; i < a_len && b[i] != '\0'; i++)
    {
        char ac = a[i];
        char bc = b[i];

        if (ac >= 'A' && ac <= 'Z')
            ac = (char)(ac - 'A' + 'a');
        if (bc >= 'A' && bc <= 'Z')
            bc = (char)(bc - 'A' + 'a');
        if (ac != bc)
            return 0;
    }
    return i == a_len && b[i] == '\0';
}

static int cocoa_workspace_copy_value(const char* start, size_t len, char* out, size_t out_len)
{
    while (len > 0 && (start[0] == ' ' || start[0] == '\t'))
    {
        start++;
        len--;
    }
    while (len > 0 && (start[len - 1u] == ' ' || start[len - 1u] == '\t' ||
                       start[len - 1u] == '\r' || start[len - 1u] == '\n'))
        len--;
    if (!out || out_len == 0 || len >= out_len)
        return 0;
    memcpy(out, start, len);
    out[len] = '\0';
    return len > 0;
}

static int cocoa_workspace_rdp_file_get(const char* contents, const char* key, char* out, size_t out_len)
{
    const char* cursor = contents;

    if (!contents || !key || !out || out_len == 0)
        return 0;
    out[0] = '\0';
    while (*cursor != '\0')
    {
        const char* line = cursor;
        const char* end = line;
        const char* first_colon = NULL;
        const char* second_colon = NULL;

        while (*end != '\0' && *end != '\n')
            end++;
        if ((size_t)(end - line) <= WORKSPACE_LINE_MAX)
        {
            first_colon = memchr(line, ':', (size_t)(end - line));
            if (first_colon)
            {
                second_colon = memchr(first_colon + 1, ':', (size_t)(end - first_colon - 1));
                if (second_colon &&
                    cocoa_workspace_ascii_equal_ci(line, (size_t)(first_colon - line), key))
                    return cocoa_workspace_copy_value(second_colon + 1,
                                                       (size_t)(end - second_colon - 1),
                                                       out,
                                                       out_len);
            }
        }
        cursor = *end == '\n' ? end + 1 : end;
    }
    return 0;
}

static int cocoa_workspace_resource_target(const librdp_workspace_resource* resource,
                                           char* out,
                                           size_t out_len)
{
    if (resource->terminal_server &&
        cocoa_workspace_copy_value(resource->terminal_server, strlen(resource->terminal_server), out, out_len))
        return 1;
    if (cocoa_workspace_rdp_file_get(resource->rdp_file_contents, "full address", out, out_len))
        return 1;
    return cocoa_workspace_rdp_file_get(resource->rdp_file_contents, "alternate full address", out, out_len);
}

static int cocoa_workspace_resource_remote_app(const librdp_workspace_resource* resource,
                                               char* out,
                                               size_t out_len)
{
    if (resource->remote_app_program &&
        cocoa_workspace_copy_value(resource->remote_app_program, strlen(resource->remote_app_program), out, out_len))
        return 1;
    return cocoa_workspace_rdp_file_get(resource->rdp_file_contents, "remoteapplicationprogram", out, out_len);
}

static int cocoa_workspace_resource_gateway(const librdp_workspace_resource* resource,
                                            char* out,
                                            size_t out_len)
{
    char host[WORKSPACE_FIELD_MAX];
    int written = 0;

    if (!cocoa_workspace_rdp_file_get(resource->rdp_file_contents, "gatewayhostname", host, sizeof(host)))
        return 0;
    if (strstr(host, "://"))
        return cocoa_workspace_copy_value(host, strlen(host), out, out_len);
    written = snprintf(out, out_len, "https://%s/", host);
    return written > 0 && (size_t)written < out_len;
}

static void cocoa_workspace_append_resource(NSMutableString* text,
                                            size_t index,
                                            const librdp_workspace_resource* resource)
{
    char target[WORKSPACE_FIELD_MAX];
    char remote_app[WORKSPACE_FIELD_MAX];
    char gateway[WORKSPACE_FIELD_MAX];

    target[0] = '\0';
    remote_app[0] = '\0';
    gateway[0] = '\0';
    cocoa_workspace_resource_target(resource, target, sizeof(target));
    cocoa_workspace_resource_remote_app(resource, remote_app, sizeof(remote_app));
    cocoa_workspace_resource_gateway(resource, gateway, sizeof(gateway));
    [text appendFormat:@"resource index=%zu type=%s id=\"%s\" alias=\"%s\" title=\"%s\" "
                       @"target=\"%s\" app=\"%s\" gateway=\"%s\"\n",
                       index,
                       cocoa_workspace_type_name(resource->type),
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
    size_t i = 0;

    [text appendFormat:@"resources count=%zu\n", count];
    for (i = 0; i < count; i++)
    {
        librdp_workspace_resource resource;

        if (librdp_workspace_resource_init(&resource) == LIBRDP_STATUS_OK &&
            librdp_workspace_resource_at(workspace, i, &resource) == LIBRDP_STATUS_OK)
            cocoa_workspace_append_resource(text, i, &resource);
    }
    return text;
}

static int cocoa_workspace_parse_index(const char* text, size_t count, size_t* index)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!text || !index)
        return 0;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed >= count)
        return 0;
    *index = (size_t)parsed;
    return 1;
}

static int cocoa_workspace_text_match(const char* candidate, const char* select)
{
    return candidate && select && strcmp(candidate, select) == 0;
}

static int cocoa_workspace_select_resource(const librdp_workspace* workspace,
                                           const char* select,
                                           size_t* selected)
{
    size_t count = librdp_workspace_resource_count(workspace);
    size_t i = 0;

    if (!workspace || !selected || count == 0)
        return 0;
    if (!select || select[0] == '\0')
    {
        if (count == 1)
        {
            *selected = 0;
            return 1;
        }
        fprintf(stderr, "--select is required when the feed contains multiple resources\n");
        return 0;
    }
    if (cocoa_workspace_parse_index(select, count, selected))
        return 1;
    for (i = 0; i < count; i++)
    {
        librdp_workspace_resource resource;

        if (librdp_workspace_resource_init(&resource) != LIBRDP_STATUS_OK ||
            librdp_workspace_resource_at(workspace, i, &resource) != LIBRDP_STATUS_OK)
            return 0;
        if (cocoa_workspace_text_match(resource.id, select) ||
            cocoa_workspace_text_match(resource.alias, select) ||
            cocoa_workspace_text_match(resource.title, select))
        {
            *selected = i;
            return 1;
        }
    }
    fprintf(stderr, "selected resource was not found\n");
    return 0;
}

static int cocoa_workspace_launch_viewer(const cocoa_workspace_options* options,
                                         const librdp_workspace_resource* resource)
{
    char target[WORKSPACE_FIELD_MAX];
    char remote_app[WORKSPACE_FIELD_MAX];
    char gateway[WORKSPACE_FIELD_MAX];
    NSMutableArray<NSString*>* arguments = [NSMutableArray array];
    NSTask* task = [[NSTask alloc] init];
    NSError* error = nil;

    target[0] = '\0';
    remote_app[0] = '\0';
    gateway[0] = '\0';
    if (!cocoa_workspace_resource_target(resource, target, sizeof(target)))
    {
        fprintf(stderr, "selected resource does not contain a launch target\n");
        return 0;
    }
    [arguments addObject:@"--target"];
    [arguments addObject:[NSString stringWithUTF8String:target]];
    [arguments addObject:@"--security"];
    [arguments addObject:[NSString stringWithUTF8String:options->security]];
    if (options->config.username)
    {
        [arguments addObject:@"--user"];
        [arguments addObject:[NSString stringWithUTF8String:options->config.username]];
    }
    if (options->config.password)
    {
        [arguments addObject:@"--password"];
        [arguments addObject:[NSString stringWithUTF8String:options->config.password]];
    }
    if (options->config.domain)
    {
        [arguments addObject:@"--domain"];
        [arguments addObject:[NSString stringWithUTF8String:options->config.domain]];
    }
    if (cocoa_workspace_resource_remote_app(resource, remote_app, sizeof(remote_app)))
    {
        [arguments addObject:@"--rail"];
        [arguments addObject:[NSString stringWithFormat:@"app=%s", remote_app]];
    }
    if (cocoa_workspace_resource_gateway(resource, gateway, sizeof(gateway)))
    {
        [arguments addObject:@"--gateway"];
        [arguments addObject:[NSString stringWithUTF8String:gateway]];
        [arguments addObject:@"--gateway-mode"];
        [arguments addObject:@"rdg-http"];
    }
    [task setExecutableURL:[NSURL fileURLWithPath:[NSString stringWithUTF8String:options->viewer]]];
    [task setArguments:arguments];
    if (![task launchAndReturnError:&error])
    {
        fprintf(stderr, "viewer launch failed: %s\n", [[error localizedDescription] UTF8String]);
        return 0;
    }
    [task waitUntilExit];
    return [task terminationStatus] == 0;
}

static void cocoa_workspace_show_window(NSString* summary)
{
    NSWindow* window = nil;
    NSScrollView* scroll = nil;
    NSTextView* text_view = nil;
    CocoaWorkspaceWindowDelegate* delegate = nil;
    NSRect frame = NSMakeRect(0.0, 0.0, 940.0, 560.0);

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
}

int main(int argc, char** argv)
{
    cocoa_workspace_options options;
    librdp_workspace* workspace = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    NSString* summary = nil;
    int rc = 0;

    @autoreleasepool
    {
        if (!cocoa_workspace_parse_args(argc, argv, &options))
        {
            cocoa_workspace_usage(stderr, argv[0]);
            return 2;
        }
        if (options.show_help)
        {
            cocoa_workspace_usage(stdout, argv[0]);
            return 0;
        }
        workspace = librdp_workspace_new(&options.config);
        if (!workspace)
        {
            fprintf(stderr, "failed to create workspace handle\n");
            return 2;
        }
        status = librdp_workspace_fetch(workspace);
        if (status != LIBRDP_STATUS_OK)
        {
            fprintf(stderr, "workspace fetch failed: %s\n", librdp_status_name(status));
            librdp_workspace_free(workspace);
            return 3;
        }
        summary = cocoa_workspace_summary(workspace);
        fputs([summary UTF8String], stdout);
        if (options.launch)
        {
            size_t selected = 0;
            librdp_workspace_resource resource;

            if (!cocoa_workspace_select_resource(workspace, options.select, &selected) ||
                librdp_workspace_resource_init(&resource) != LIBRDP_STATUS_OK ||
                librdp_workspace_resource_at(workspace, selected, &resource) != LIBRDP_STATUS_OK ||
                !cocoa_workspace_launch_viewer(&options, &resource))
                rc = 4;
        }
        if (rc == 0 && !options.no_window)
            cocoa_workspace_show_window(summary);
        librdp_workspace_free(workspace);
    }
    return rc;
}
