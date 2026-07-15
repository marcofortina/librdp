/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 administration inventory tool.
 * Invariants: command-line input is copied into librdp_admin configuration,
 * session inventory is read only through public borrowed views, and X11
 * rendering never owns library memory.
 * Ownership: the admin handle owns credentials and parsed inventory; this
 * process owns only transient CLI strings and X11 resources.
 * Threading: single-threaded command-line and X11 event-loop program.
 * Trust boundary: endpoint responses are untrusted and remain redacted outside
 * the public inventory fields printed by explicit user request.
 */

#include <librdp/librdp.h>

#include <X11/Xlib.h>
#include <X11/Xutil.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct admin_cli_options
{
    librdp_admin_config config;
    librdp_admin_action action;
    int no_window;
    int show_help;
    int execute_action;
    int confirm_action;
    char* password_from_env;
} admin_cli_options;

#define ADMIN_ACTION_QUERY ((librdp_admin_action_type)0)

static void admin_usage(FILE* stream, const char* program)
{
    fprintf(stream,
            "usage: %s --endpoint url [--user name] [--password value] [--password-env name] "
            "[--domain name] [--resource-uri uri] [--timeout ms] [--insecure-lab] "
            "[--action query|logoff|disconnect|message] [--session-id id] "
            "[--message-title text] [--message-text text] [--confirm] [--no-window]\n",
            program);
}

static int admin_parse_u32(const char* text, uint32_t* value)
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

static int admin_cli_init(admin_cli_options* options)
{
    if (!options)
        return 0;
    memset(options, 0, sizeof(*options));
    return librdp_admin_config_init(&options->config) == LIBRDP_STATUS_OK &&
           librdp_admin_action_init(&options->action) == LIBRDP_STATUS_OK;
}

static int admin_cli_need_value(int index, int argc, const char* option)
{
    if (index + 1 < argc)
        return 1;
    fprintf(stderr, "%s requires a value\n", option);
    return 0;
}

static int admin_parse_action_type(const char* text, librdp_admin_action_type* type)
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

/*
 * Parses startup-only options. Password environment lookup is resolved before
 * handle creation so the public admin API still receives a normal borrowed
 * string and owns the copied sensitive storage. Destructive actions require an
 * explicit confirmation flag and a numeric session id.
 */
static int admin_parse_args(int argc, char** argv, admin_cli_options* options)
{
    int i = 0;

    if (!admin_cli_init(options))
        return 0;
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
            options->show_help = 1;
        else if (strcmp(argv[i], "--endpoint") == 0)
        {
            if (!admin_cli_need_value(i, argc, argv[i]))
                return 0;
            options->config.endpoint_url = argv[++i];
        }
        else if (strcmp(argv[i], "--user") == 0)
        {
            if (!admin_cli_need_value(i, argc, argv[i]))
                return 0;
            options->config.username = argv[++i];
        }
        else if (strcmp(argv[i], "--password") == 0)
        {
            if (!admin_cli_need_value(i, argc, argv[i]))
                return 0;
            options->config.password = argv[++i];
        }
        else if (strcmp(argv[i], "--password-env") == 0)
        {
            const char* value = NULL;

            if (!admin_cli_need_value(i, argc, argv[i]))
                return 0;
            value = getenv(argv[++i]);
            if (!value)
            {
                fprintf(stderr, "password environment variable is not set\n");
                return 0;
            }
            options->password_from_env = (char*)value;
            options->config.password = options->password_from_env;
        }
        else if (strcmp(argv[i], "--domain") == 0)
        {
            if (!admin_cli_need_value(i, argc, argv[i]))
                return 0;
            options->config.domain = argv[++i];
        }
        else if (strcmp(argv[i], "--resource-uri") == 0)
        {
            if (!admin_cli_need_value(i, argc, argv[i]))
                return 0;
            options->config.resource_uri = argv[++i];
        }
        else if (strcmp(argv[i], "--timeout") == 0)
        {
            if (!admin_cli_need_value(i, argc, argv[i]) ||
                !admin_parse_u32(argv[++i], &options->config.timeout_ms))
                return 0;
        }
        else if (strcmp(argv[i], "--insecure-lab") == 0)
            options->config.allow_insecure_tls = 1;
        else if (strcmp(argv[i], "--no-window") == 0)
            options->no_window = 1;
        else if (strcmp(argv[i], "--action") == 0)
        {
            librdp_admin_action_type type = ADMIN_ACTION_QUERY;

            if (!admin_cli_need_value(i, argc, argv[i]) || !admin_parse_action_type(argv[++i], &type))
                return 0;
            options->execute_action = type != ADMIN_ACTION_QUERY;
            if (type != ADMIN_ACTION_QUERY)
                options->action.type = type;
        }
        else if (strcmp(argv[i], "--session-id") == 0)
        {
            if (!admin_cli_need_value(i, argc, argv[i]) ||
                !admin_parse_u32(argv[++i], &options->action.session_id))
                return 0;
        }
        else if (strcmp(argv[i], "--message-title") == 0)
        {
            if (!admin_cli_need_value(i, argc, argv[i]))
                return 0;
            options->action.message_title = argv[++i];
        }
        else if (strcmp(argv[i], "--message-text") == 0)
        {
            if (!admin_cli_need_value(i, argc, argv[i]))
                return 0;
            options->action.message_text = argv[++i];
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
        if (options->action.type != LIBRDP_ADMIN_ACTION_MESSAGE &&
            (options->action.message_title || options->action.message_text))
        {
            fprintf(stderr, "message fields are valid only with --action message\n");
            return 0;
        }
        if (options->action.type == LIBRDP_ADMIN_ACTION_MESSAGE && !options->action.message_text)
        {
            fprintf(stderr, "--message-text is required with --action message\n");
            return 0;
        }
    }
    else if (options->action.session_id != 0 || options->action.message_title ||
             options->action.message_text || options->confirm_action)
    {
        fprintf(stderr, "admin action options require --action logoff|disconnect|message\n");
        return 0;
    }
    return 1;
}

static void admin_print_session(size_t index, const librdp_admin_session* session)
{
    printf("session index=%zu session_id=%u logon_id=%llu user=\"%s\" domain=\"%s\" "
           "state=\"%s\" client=\"%s\" station=\"%s\" protocol=\"%s\"\n",
           index,
           (unsigned)session->session_id,
           (unsigned long long)session->logon_id,
           session->username ? session->username : "",
           session->domain ? session->domain : "",
           session->state ? session->state : "",
           session->client_name ? session->client_name : "",
           session->station_name ? session->station_name : "",
           session->protocol_name ? session->protocol_name : "");
}

static int admin_print_sessions(const librdp_admin* admin)
{
    size_t count = librdp_admin_session_count(admin);
    size_t i = 0;

    printf("sessions count=%zu\n", count);
    for (i = 0; i < count; i++)
    {
        librdp_admin_session session;

        if (librdp_admin_session_init(&session) != LIBRDP_STATUS_OK ||
            librdp_admin_session_at(admin, i, &session) != LIBRDP_STATUS_OK)
            return 0;
        admin_print_session(i, &session);
    }
    return 1;
}

static void admin_draw_line(Display* display, Window window, GC gc, int x, int y, const char* text)
{
    size_t length = text ? strlen(text) : 0;

    if (length > 4096u)
        length = 4096u;
    XDrawString(display, window, gc, x, y, text ? text : "", (int)length);
}

static void admin_draw_sessions(Display* display, Window window, GC gc, const librdp_admin* admin)
{
    size_t count = librdp_admin_session_count(admin);
    size_t i = 0;
    int y = 28;

    admin_draw_line(display, window, gc, 16, y, "librdp admin sessions");
    y += 24;
    if (count == 0)
    {
        admin_draw_line(display, window, gc, 16, y, "No sessions reported.");
        return;
    }
    for (i = 0; i < count && i < 64u; i++)
    {
        librdp_admin_session session;
        char line[512];

        if (librdp_admin_session_init(&session) != LIBRDP_STATUS_OK ||
            librdp_admin_session_at(admin, i, &session) != LIBRDP_STATUS_OK)
            continue;
        snprintf(line,
                 sizeof(line),
                 "%zu  id=%u  logon=%llu  user=%s\\%s  state=%s  client=%s",
                 i,
                 (unsigned)session.session_id,
                 (unsigned long long)session.logon_id,
                 session.domain ? session.domain : "",
                 session.username ? session.username : "",
                 session.state ? session.state : "",
                 session.client_name ? session.client_name : "");
        admin_draw_line(display, window, gc, 16, y, line);
        y += 18;
    }
}

/*
 * Presents a read-only X11 summary window. The caller remains the owner of the
 * admin handle; the event loop only borrows session views during expose redraws.
 */
static int admin_show_window(const librdp_admin* admin)
{
    Display* display = NULL;
    Window root = 0;
    Window window = 0;
    GC gc = 0;
    Atom wm_delete = 0;
    int screen = 0;
    XClassHint* class_hint = NULL;
    int running = 1;

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
                                 80,
                                 80,
                                 840,
                                 480,
                                 1,
                                 BlackPixel(display, screen),
                                 WhitePixel(display, screen));
    XStoreName(display, window, "librdp-x11-admin");
    class_hint = XAllocClassHint();
    if (class_hint)
    {
        class_hint->res_name = (char*)"librdp-x11-admin";
        class_hint->res_class = (char*)"librdp-x11-admin";
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
            admin_draw_sessions(display, window, gc, admin);
        else if (event.type == KeyPress)
            running = 0;
        else if (event.type == ClientMessage && (Atom)event.xclient.data.l[0] == wm_delete)
            running = 0;
    }
    XFreeGC(display, gc);
    XDestroyWindow(display, window);
    XCloseDisplay(display);
    return 1;
}

int main(int argc, char** argv)
{
    admin_cli_options options;
    librdp_admin* admin = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    int rc = 0;

    if (!admin_parse_args(argc, argv, &options))
    {
        admin_usage(stderr, argv[0]);
        return 2;
    }
    if (options.show_help)
    {
        admin_usage(stdout, argv[0]);
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
        if (options.no_window)
        {
            librdp_admin_free(admin);
            return 0;
        }
    }
    status = librdp_admin_query_sessions(admin);
    if (status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr, "admin query failed: %s\n", librdp_status_name(status));
        librdp_admin_free(admin);
        return 3;
    }
    if (!admin_print_sessions(admin))
        rc = 3;
    else if (!options.no_window && !admin_show_window(admin))
        rc = 4;
    librdp_admin_free(admin);
    return rc;
}
