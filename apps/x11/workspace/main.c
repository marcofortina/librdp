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

#include "workspace_options.h"

#include <librdp/librdp.h>

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define WORKSPACE_DISPLAY_LINE_CAPACITY 512u

static void workspace_print_resource(size_t index, const librdp_workspace_resource* resource)
{
    char target[WORKSPACE_FIELD_CAPACITY];
    char remote_app[WORKSPACE_FIELD_CAPACITY];
    char gateway[WORKSPACE_FIELD_CAPACITY];

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

/*
 * Launches the standalone viewer with the selected resource metadata. The
 * child receives only explicit viewer arguments; failures are reported through
 * the child exit status and never mutate the workspace handle.
 */
static int workspace_launch_viewer(const workspace_options* options,
                                   const librdp_workspace_resource* resource)
{
    workspace_launch_plan plan;
    char* arguments[WORKSPACE_LAUNCH_ARGUMENT_CAPACITY];
    size_t index = 0;
    pid_t pid = 0;
    int status = 0;

    if (!workspace_launch_plan_build(options, resource, &plan, stderr))
        return 0;
    for (index = 0; index <= plan.argument_count; index++)
        arguments[index] = (char*)plan.arguments[index];

    pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return 0;
    }
    if (pid == 0)
    {
        execvp(plan.executable, arguments);
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
        char target[WORKSPACE_FIELD_CAPACITY];
        char line[WORKSPACE_DISPLAY_LINE_CAPACITY];

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
static int workspace_show_window(const workspace_options* options,
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
    workspace_options options;
    librdp_workspace* workspace = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t selected = 0;
    int have_selection = 0;
    int rc = 0;

    if (!workspace_options_parse(argc,
                                 argv,
                                 "librdp-viewer",
                                 &options,
                                 stderr))
    {
        workspace_options_usage(stderr, argv[0]);
        return 2;
    }
    if (options.show_help)
    {
        workspace_options_usage(stdout, argv[0]);
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
            have_selection =
              workspace_select_resource(workspace, options.select, &selected, stderr);
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
