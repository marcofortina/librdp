/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 workspace feed launcher.
 * Invariants: feed data is accessed only through public workspace resource
 * views, RDP file metadata is parsed as untrusted launch input, and viewer
 * execution is explicit through command-line or keyboard selection.
 * Ownership: the workspace handle owns credentials and resource strings; the
 * app owns transient selection buffers, X11 resources, and child processes.
 * Threading: single-threaded CLI and X11 event-loop program.
 * Trust boundary: workspace feeds and embedded RDP file payloads are remote
 * input; only validated target and RemoteApp fields are passed to the viewer.
 */

#include <librdp/librdp.h>

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define WORKSPACE_FIELD_MAX 1024u
#define WORKSPACE_LINE_MAX 512u

typedef struct workspace_cli_options
{
    librdp_workspace_config config;
    const char* select;
    const char* viewer;
    const char* security;
    const char* password_from_env;
    int no_window;
    int show_help;
    int launch;
} workspace_cli_options;

static void workspace_usage(FILE* stream, const char* program)
{
    fprintf(stream,
            "usage: %s --feed url [--user name] [--password value] [--password-env name] "
            "[--domain name] [--timeout ms] [--select id|index|title|alias] "
            "[--viewer path] [--security auto|rdp|tls|nla] [--launch] [--no-window]\n",
            program);
}

static int workspace_parse_u32(const char* text, uint32_t* value)
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

static int workspace_need_value(int index, int argc, const char* option)
{
    if (index + 1 < argc)
        return 1;
    fprintf(stderr, "%s requires a value\n", option);
    return 0;
}

static int workspace_valid_security(const char* value)
{
    return value && (strcmp(value, "auto") == 0 || strcmp(value, "rdp") == 0 ||
                     strcmp(value, "tls") == 0 || strcmp(value, "nla") == 0);
}

static int workspace_cli_init(workspace_cli_options* options)
{
    if (!options)
        return 0;
    memset(options, 0, sizeof(*options));
    if (librdp_workspace_config_init(&options->config) != LIBRDP_STATUS_OK)
        return 0;
    options->viewer = "librdp-x11-viewer";
    options->security = "auto";
    return 1;
}

/*
 * Parses startup-only options, validates security mode and bounded numeric
 * fields, and resolves password environment lookup before workspace creation
 * so the public API owns the copied sensitive storage.
 */
static int workspace_parse_args(int argc, char** argv, workspace_cli_options* options)
{
    int i = 0;

    if (!workspace_cli_init(options))
        return 0;
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
            options->show_help = 1;
        else if (strcmp(argv[i], "--feed") == 0)
        {
            if (!workspace_need_value(i, argc, argv[i]))
                return 0;
            options->config.feed_url = argv[++i];
        }
        else if (strcmp(argv[i], "--user") == 0)
        {
            if (!workspace_need_value(i, argc, argv[i]))
                return 0;
            options->config.username = argv[++i];
        }
        else if (strcmp(argv[i], "--password") == 0)
        {
            if (!workspace_need_value(i, argc, argv[i]))
                return 0;
            options->config.password = argv[++i];
        }
        else if (strcmp(argv[i], "--password-env") == 0)
        {
            const char* value = NULL;

            if (!workspace_need_value(i, argc, argv[i]))
                return 0;
            value = getenv(argv[++i]);
            if (!value)
            {
                fprintf(stderr, "password environment variable is not set\n");
                return 0;
            }
            options->password_from_env = value;
            options->config.password = options->password_from_env;
        }
        else if (strcmp(argv[i], "--domain") == 0)
        {
            if (!workspace_need_value(i, argc, argv[i]))
                return 0;
            options->config.domain = argv[++i];
        }
        else if (strcmp(argv[i], "--timeout") == 0)
        {
            if (!workspace_need_value(i, argc, argv[i]) ||
                !workspace_parse_u32(argv[++i], &options->config.timeout_ms))
                return 0;
        }
        else if (strcmp(argv[i], "--select") == 0)
        {
            if (!workspace_need_value(i, argc, argv[i]))
                return 0;
            options->select = argv[++i];
        }
        else if (strcmp(argv[i], "--viewer") == 0)
        {
            if (!workspace_need_value(i, argc, argv[i]))
                return 0;
            options->viewer = argv[++i];
        }
        else if (strcmp(argv[i], "--security") == 0)
        {
            if (!workspace_need_value(i, argc, argv[i]))
                return 0;
            options->security = argv[++i];
            if (!workspace_valid_security(options->security))
            {
                fprintf(stderr, "invalid security mode\n");
                return 0;
            }
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

static const char* workspace_resource_type_name(librdp_workspace_resource_type type)
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

static int workspace_ascii_equal_ci(const char* a, size_t a_len, const char* b)
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

static int workspace_copy_value(const char* start, size_t len, char* out, size_t out_len)
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

/*
 * Extracts simple key:type:value fields from an embedded .rdp payload. The
 * function accepts only bounded single-line values because feed payloads are
 * remote input and must not influence process launch outside explicit fields.
 */
static int workspace_rdp_file_get(const char* contents, const char* key, char* out, size_t out_len)
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
                second_colon = memchr(first_colon + 1,
                                      ':',
                                      (size_t)(end - first_colon - 1));
                if (second_colon &&
                    workspace_ascii_equal_ci(line, (size_t)(first_colon - line), key))
                    return workspace_copy_value(second_colon + 1,
                                                (size_t)(end - second_colon - 1),
                                                out,
                                                out_len);
            }
        }
        cursor = *end == '\n' ? end + 1 : end;
    }
    return 0;
}

static int workspace_resource_target(const librdp_workspace_resource* resource,
                                     char* out,
                                     size_t out_len)
{
    if (resource->terminal_server &&
        workspace_copy_value(resource->terminal_server, strlen(resource->terminal_server), out, out_len))
        return 1;
    if (workspace_rdp_file_get(resource->rdp_file_contents, "full address", out, out_len))
        return 1;
    return workspace_rdp_file_get(resource->rdp_file_contents, "alternate full address", out, out_len);
}

static int workspace_resource_remote_app(const librdp_workspace_resource* resource,
                                         char* out,
                                         size_t out_len)
{
    if (resource->remote_app_program &&
        workspace_copy_value(resource->remote_app_program, strlen(resource->remote_app_program), out, out_len))
        return 1;
    return workspace_rdp_file_get(resource->rdp_file_contents, "remoteapplicationprogram", out, out_len);
}

static int workspace_resource_gateway(const librdp_workspace_resource* resource,
                                      char* out,
                                      size_t out_len)
{
    char host[WORKSPACE_FIELD_MAX];
    int written = 0;

    if (!workspace_rdp_file_get(resource->rdp_file_contents, "gatewayhostname", host, sizeof(host)))
        return 0;
    if (strstr(host, "://"))
        return workspace_copy_value(host, strlen(host), out, out_len);
    written = snprintf(out, out_len, "https://%s/", host);
    return written > 0 && (size_t)written < out_len;
}

static void workspace_print_resource(size_t index, const librdp_workspace_resource* resource)
{
    char target[WORKSPACE_FIELD_MAX];
    char remote_app[WORKSPACE_FIELD_MAX];
    char gateway[WORKSPACE_FIELD_MAX];

    target[0] = '\0';
    remote_app[0] = '\0';
    gateway[0] = '\0';
    workspace_resource_target(resource, target, sizeof(target));
    workspace_resource_remote_app(resource, remote_app, sizeof(remote_app));
    workspace_resource_gateway(resource, gateway, sizeof(gateway));
    printf("resource index=%zu type=%s id=\"%s\" alias=\"%s\" title=\"%s\" target=\"%s\" app=\"%s\" gateway=\"%s\"\n",
           index,
           workspace_resource_type_name(resource->type),
           resource->id ? resource->id : "",
           resource->alias ? resource->alias : "",
           resource->title ? resource->title : "",
           target,
           remote_app,
           gateway);
}

static int workspace_print_resources(const librdp_workspace* workspace)
{
    size_t count = librdp_workspace_resource_count(workspace);
    size_t i = 0;

    printf("resources count=%zu\n", count);
    for (i = 0; i < count; i++)
    {
        librdp_workspace_resource resource;

        if (librdp_workspace_resource_init(&resource) != LIBRDP_STATUS_OK ||
            librdp_workspace_resource_at(workspace, i, &resource) != LIBRDP_STATUS_OK)
            return 0;
        workspace_print_resource(i, &resource);
    }
    return 1;
}

static int workspace_parse_index(const char* text, size_t count, size_t* index)
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

static int workspace_text_match(const char* candidate, const char* select)
{
    return candidate && select && strcmp(candidate, select) == 0;
}

static int workspace_select_resource(const librdp_workspace* workspace,
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
    if (workspace_parse_index(select, count, selected))
        return 1;
    for (i = 0; i < count; i++)
    {
        librdp_workspace_resource resource;

        if (librdp_workspace_resource_init(&resource) != LIBRDP_STATUS_OK ||
            librdp_workspace_resource_at(workspace, i, &resource) != LIBRDP_STATUS_OK)
            return 0;
        if (workspace_text_match(resource.id, select) ||
            workspace_text_match(resource.alias, select) ||
            workspace_text_match(resource.title, select))
        {
            *selected = i;
            return 1;
        }
    }
    fprintf(stderr, "selected resource was not found\n");
    return 0;
}

/*
 * Launches the standalone viewer with the selected resource metadata. The
 * child receives only explicit viewer arguments; failures are reported through
 * the child exit status and never mutate the workspace handle.
 */
static int workspace_launch_viewer(const workspace_cli_options* options,
                                   const librdp_workspace_resource* resource)
{
    char target[WORKSPACE_FIELD_MAX];
    char remote_app[WORKSPACE_FIELD_MAX];
    char gateway[WORKSPACE_FIELD_MAX];
    char rail_arg[WORKSPACE_FIELD_MAX + 5u];
    char* args[24];
    size_t argc = 0;
    pid_t pid = 0;
    int status = 0;

    target[0] = '\0';
    remote_app[0] = '\0';
    gateway[0] = '\0';
    if (!workspace_resource_target(resource, target, sizeof(target)))
    {
        fprintf(stderr, "selected resource does not contain a launch target\n");
        return 0;
    }
    args[argc++] = (char*)options->viewer;
    args[argc++] = (char*)"--target";
    args[argc++] = target;
    args[argc++] = (char*)"--security";
    args[argc++] = (char*)options->security;
    if (options->config.username)
    {
        args[argc++] = (char*)"--user";
        args[argc++] = (char*)options->config.username;
    }
    if (options->config.password)
    {
        args[argc++] = (char*)"--password";
        args[argc++] = (char*)options->config.password;
    }
    if (options->config.domain)
    {
        args[argc++] = (char*)"--domain";
        args[argc++] = (char*)options->config.domain;
    }
    if (workspace_resource_remote_app(resource, remote_app, sizeof(remote_app)))
    {
        int written = snprintf(rail_arg, sizeof(rail_arg), "app=%s", remote_app);

        if (written <= 0 || (size_t)written >= sizeof(rail_arg))
        {
            fprintf(stderr, "remote app launch field is too long\n");
            return 0;
        }
        args[argc++] = (char*)"--rail";
        args[argc++] = rail_arg;
    }
    if (workspace_resource_gateway(resource, gateway, sizeof(gateway)))
    {
        args[argc++] = (char*)"--gateway";
        args[argc++] = gateway;
        args[argc++] = (char*)"--gateway-mode";
        args[argc++] = (char*)"rdg-http";
    }
    args[argc] = NULL;

    pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return 0;
    }
    if (pid == 0)
    {
        execvp(options->viewer, args);
        perror("execvp");
        _exit(127);
    }
    if (waitpid(pid, &status, 0) < 0)
    {
        perror("waitpid");
        return 0;
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status) == 0;
    return 0;
}

static void workspace_draw_line(Display* display, Window window, GC gc, int x, int y, const char* text)
{
    size_t length = text ? strlen(text) : 0;

    if (length > 4096u)
        length = 4096u;
    XDrawString(display, window, gc, x, y, text ? text : "", (int)length);
}

static void workspace_draw_resources(Display* display,
                                     Window window,
                                     GC gc,
                                     const librdp_workspace* workspace,
                                     size_t selected)
{
    size_t count = librdp_workspace_resource_count(workspace);
    size_t i = 0;
    int y = 28;

    workspace_draw_line(display, window, gc, 16, y, "librdp workspace resources");
    y += 24;
    if (count == 0)
    {
        workspace_draw_line(display, window, gc, 16, y, "No resources reported.");
        return;
    }
    for (i = 0; i < count && i < 64u; i++)
    {
        librdp_workspace_resource resource;
        char target[WORKSPACE_FIELD_MAX];
        char line[WORKSPACE_LINE_MAX];

        target[0] = '\0';
        if (librdp_workspace_resource_init(&resource) != LIBRDP_STATUS_OK ||
            librdp_workspace_resource_at(workspace, i, &resource) != LIBRDP_STATUS_OK)
            continue;
        workspace_resource_target(&resource, target, sizeof(target));
        snprintf(line,
                 sizeof(line),
                 "%c %zu  %.16s  %.220s  %.220s",
                 i == selected ? '>' : ' ',
                 i,
                 workspace_resource_type_name(resource.type),
                 resource.title ? resource.title : "",
                 target);
        workspace_draw_line(display, window, gc, 16, y, line);
        y += 18;
    }
}

/*
 * Presents resource selection through a small X11 window. Keyboard navigation
 * changes only the local selected index; Return launches the viewer through
 * the same explicit path used by command-line selection.
 */
static int workspace_show_window(const workspace_cli_options* options,
                                 const librdp_workspace* workspace,
                                 size_t selected)
{
    Display* display = NULL;
    Window root = 0;
    Window window = 0;
    GC gc = 0;
    Atom wm_delete = 0;
    XClassHint* class_hint = NULL;
    int screen = 0;
    int running = 1;
    int rc = 1;
    size_t count = librdp_workspace_resource_count(workspace);

    display = XOpenDisplay(NULL);
    if (!display)
    {
        fprintf(stderr, "unable to open X display\n");
        return 0;
    }
    screen = DefaultScreen(display);
    root = RootWindow(display, screen);
    window = XCreateSimpleWindow(display,
                                 root,
                                 96,
                                 96,
                                 920,
                                 520,
                                 1,
                                 BlackPixel(display, screen),
                                 WhitePixel(display, screen));
    XStoreName(display, window, "librdp-x11-workspace");
    class_hint = XAllocClassHint();
    if (class_hint)
    {
        class_hint->res_name = (char*)"librdp-x11-workspace";
        class_hint->res_class = (char*)"librdp-x11-workspace";
        XSetClassHint(display, window, class_hint);
        XFree(class_hint);
    }
    wm_delete = XInternAtom(display, "WM_DELETE_WINDOW", False);
    XSetWMProtocols(display, window, &wm_delete, 1);
    XSelectInput(display, window, ExposureMask | KeyPressMask | StructureNotifyMask);
    XMapWindow(display, window);
    gc = XCreateGC(display, window, 0, NULL);
    XSetForeground(display, gc, BlackPixel(display, screen));
    while (running)
    {
        XEvent event;

        XNextEvent(display, &event);
        if (event.type == Expose && event.xexpose.count == 0)
            workspace_draw_resources(display, window, gc, workspace, selected);
        else if (event.type == KeyPress)
        {
            KeySym key = XLookupKeysym(&event.xkey, 0);

            if (key == XK_Escape || key == XK_q)
                running = 0;
            else if (key == XK_Up && selected > 0)
            {
                selected--;
                XClearWindow(display, window);
                workspace_draw_resources(display, window, gc, workspace, selected);
            }
            else if (key == XK_Down && selected + 1u < count)
            {
                selected++;
                XClearWindow(display, window);
                workspace_draw_resources(display, window, gc, workspace, selected);
            }
            else if (key == XK_Return && count > 0)
            {
                librdp_workspace_resource resource;

                if (librdp_workspace_resource_init(&resource) == LIBRDP_STATUS_OK &&
                    librdp_workspace_resource_at(workspace, selected, &resource) == LIBRDP_STATUS_OK)
                    rc = workspace_launch_viewer(options, &resource);
                else
                    rc = 0;
                running = 0;
            }
        }
        else if (event.type == ClientMessage && (Atom)event.xclient.data.l[0] == wm_delete)
            running = 0;
    }
    XFreeGC(display, gc);
    XDestroyWindow(display, window);
    XCloseDisplay(display);
    return rc;
}

int main(int argc, char** argv)
{
    workspace_cli_options options;
    librdp_workspace* workspace = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t selected = 0;
    int have_selection = 0;
    int rc = 0;

    if (!workspace_parse_args(argc, argv, &options))
    {
        workspace_usage(stderr, argv[0]);
        return 2;
    }
    if (options.show_help)
    {
        workspace_usage(stdout, argv[0]);
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
    if (!workspace_print_resources(workspace))
        rc = 3;
    else
    {
        if (options.select || librdp_workspace_resource_count(workspace) == 1u)
            have_selection = workspace_select_resource(workspace, options.select, &selected);
        else
        {
            selected = 0;
            have_selection = 0;
        }
        if (options.launch)
        {
            librdp_workspace_resource resource;

            if (!have_selection ||
                librdp_workspace_resource_init(&resource) != LIBRDP_STATUS_OK ||
                librdp_workspace_resource_at(workspace, selected, &resource) != LIBRDP_STATUS_OK ||
                !workspace_launch_viewer(&options, &resource))
                rc = 4;
        }
        else if (!options.no_window)
        {
            if (!have_selection)
                selected = 0;
            if (!workspace_show_window(&options, workspace, selected))
                rc = 4;
        }
    }
    librdp_workspace_free(workspace);
    return rc;
}
