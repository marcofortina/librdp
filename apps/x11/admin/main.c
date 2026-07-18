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

#include "admin_options.h"

#include <librdp/librdp.h>

#include <X11/Xlib.h>
#include <X11/Xutil.h>

#include <stdio.h>
#include <string.h>

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
    admin_options options;
    librdp_admin* admin = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    int rc = 0;

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
