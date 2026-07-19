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

#include "workspace_app.h"

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

/*
 * Launches the standalone viewer with the selected resource metadata. The
 * child receives only explicit viewer arguments; failures are reported through
 * the child exit status and never mutate the workspace handle.
 */
static int x11_workspace_launch(
  const workspace_options* options,
  const librdp_workspace_resource* resource,
  void* user_data)
{
    workspace_launch_plan plan;
    char* arguments[WORKSPACE_LAUNCH_ARGUMENT_CAPACITY];
    size_t index = 0;
    pid_t pid = 0;
    int status = 0;

    (void)user_data;
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
static int x11_workspace_present(
  const workspace_options* options,
  const librdp_workspace* workspace,
  size_t selected,
  workspace_app_launch_callback launch,
  void* user_data)
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
    XStoreName(display, window, "librdp-workspace");
    class_hint = XAllocClassHint();
    if (class_hint)
    {
        class_hint->res_name = (char*)"librdp-workspace";
        class_hint->res_class = (char*)"LibrdpWorkspace";
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
                    rc = launch(options, &resource, user_data);
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
    const workspace_app_platform platform = {
        x11_workspace_launch,
        x11_workspace_present,
        NULL
    };

    return workspace_app_run(argc,
                             argv,
                             "librdp-viewer",
                             &platform);
}
