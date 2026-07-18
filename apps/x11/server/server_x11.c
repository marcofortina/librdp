/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 desktop-server context and shared event source.
 * Invariants: provider event tables share one X connection and are deduplicated
 * by the common host, while all capture geometry is refreshed before events
 * are dispatched.
 * Ownership: this module creates and releases the display connection, hidden
 * selection window, capture target resources and native extension state.
 * Threading: Xlib access is serialized on the owner thread.
 * Trust boundary: extension availability and target identifiers are checked
 * before any native provider is exposed as ready.
 */

#include "server_x11_internal.h"

#include <X11/extensions/Xcomposite.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static char* x11_server_copy_string(const char* value)
{
    size_t length = value ? strlen(value) : 0u;
    char* copy = NULL;

    if (!value)
        return NULL;
    if (length == SIZE_MAX)
        return NULL;
    copy = (char*)malloc(length + 1u);
    if (!copy)
        return NULL;
    memcpy(copy, value, length + 1u);
    return copy;
}

uint64_t x11_server_now_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0u;
    return (uint64_t)now.tv_sec * 1000000000u + (uint64_t)now.tv_nsec;
}

int x11_server_checked_multiply(size_t left, size_t right, size_t* result)
{
    if (!result || (left != 0u && right > SIZE_MAX / left))
        return 0;
    *result = left * right;
    return 1;
}

void x11_server_config_init(x11_server_config* config)
{
    if (!config)
        return;
    memset(config, 0, sizeof(*config));
    config->version = X11_SERVER_CONFIG_VERSION;
    config->size = sizeof(*config);
    config->source_kind = X11_SERVER_SOURCE_ROOT;
    config->max_frame_bytes = 256u * 1024u * 1024u;
}

static int x11_server_config_valid(const x11_server_config* config)
{
    return config && config->version == X11_SERVER_CONFIG_VERSION &&
           config->size >= sizeof(*config) &&
           config->source_kind >= X11_SERVER_SOURCE_ROOT &&
           config->source_kind <= X11_SERVER_SOURCE_WINDOW &&
           config->max_frame_bytes >= 4u &&
           (config->source_kind != X11_SERVER_SOURCE_WINDOW ||
            config->window_id != 0ul) &&
           (!config->allow_drive ||
            (config->drive_mount && config->drive_mount[0] != '\0' &&
             x11_server_fuse_available()));
}

static void x11_server_shm_release(x11_server_context* context)
{
    x11_server_shm_image* shm = context ? &context->shm : NULL;

    if (!context || !shm)
        return;
#ifdef LIBRDP_HAVE_XSHM
    if (shm->attached)
    {
        XShmDetach(context->display, &shm->segment);
        XSync(context->display, False);
        shm->attached = 0;
    }
    if (shm->image)
    {
        shm->image->data = NULL;
        XDestroyImage(shm->image);
        shm->image = NULL;
    }
    if (shm->segment.shmaddr && shm->segment.shmaddr != (char*)-1)
    {
        shmdt(shm->segment.shmaddr);
        shm->segment.shmaddr = NULL;
    }
    if (shm->segment.shmid >= 0)
    {
        shmctl(shm->segment.shmid, IPC_RMID, NULL);
        shm->segment.shmid = -1;
    }
#else
    (void)shm;
#endif
}

static void x11_server_capture_resources_release(
    x11_server_context* context)
{
    if (!context || !context->display)
        return;
    x11_server_shm_release(context);
    if (context->damage != None)
    {
        XDamageDestroy(context->display, context->damage);
        context->damage = None;
    }
    if (context->composite_pixmap != None)
    {
        XFreePixmap(context->display, context->composite_pixmap);
        context->composite_pixmap = None;
    }
    if (context->config.source_kind == X11_SERVER_SOURCE_WINDOW &&
        context->target != None && !context->target_destroyed)
    {
        XCompositeUnredirectWindow(context->display,
                                   context->target,
                                   CompositeRedirectAutomatic);
    }
    context->capture_drawable = None;
}

static int x11_server_query_extensions(x11_server_context* context)
{
    int major = 0;
    int minor = 0;

    if (!XDamageQueryExtension(context->display,
                               &context->damage_event_base,
                               &context->damage_error_base) ||
        !XFixesQueryExtension(context->display,
                              &context->fixes_event_base,
                              &context->fixes_error_base) ||
        !XRRQueryExtension(context->display,
                           &context->randr_event_base,
                           &context->randr_error_base) ||
        !XCompositeQueryExtension(context->display,
                                  &context->composite_event_base,
                                  &context->composite_error_base))
        return 0;
    if (!XCompositeQueryVersion(context->display, &major, &minor))
        return 0;
#ifdef LIBRDP_HAVE_XSHM
    context->shm_available =
        XShmQueryExtension(context->display) ? 1 : 0;
#else
    context->shm_available = 0;
#endif
    return 1;
}

static int x11_server_select_visual(x11_server_context* context)
{
    XWindowAttributes attributes;
    XVisualInfo template_info;
    XVisualInfo* info = NULL;
    int count = 0;

    if (!XGetWindowAttributes(context->display,
                              context->target,
                              &attributes))
        return 0;
    memset(&template_info, 0, sizeof(template_info));
    template_info.visualid = XVisualIDFromVisual(attributes.visual);
    info = XGetVisualInfo(context->display,
                          VisualIDMask,
                          &template_info,
                          &count);
    if (!info || count <= 0)
    {
        if (info)
            XFree(info);
        return 0;
    }
    context->visual_info = info[0];
    context->depth = attributes.depth;
    XFree(info);
    return 1;
}

static int x11_server_select_target(x11_server_context* context)
{
    if (context->config.source_kind == X11_SERVER_SOURCE_WINDOW)
        context->target = (Window)context->config.window_id;
    else
        context->target = context->root;
    if (context->target == None ||
        !x11_server_select_visual(context))
        return 0;
    XSelectInput(context->display,
                 context->target,
                 StructureNotifyMask | PointerMotionMask);
    XRRSelectInput(context->display,
                   context->root,
                   RRScreenChangeNotifyMask | RRCrtcChangeNotifyMask |
                       RROutputChangeNotifyMask);
    XFixesSelectCursorInput(context->display,
                            context->root,
                            XFixesDisplayCursorNotifyMask);
    if (context->config.source_kind == X11_SERVER_SOURCE_WINDOW)
    {
        XCompositeRedirectWindow(context->display,
                                 context->target,
                                 CompositeRedirectAutomatic);
        XSync(context->display, False);
        context->composite_pixmap =
            XCompositeNameWindowPixmap(context->display, context->target);
        if (context->composite_pixmap == None)
            return 0;
        context->capture_drawable = context->composite_pixmap;
    }
    else
        context->capture_drawable = context->root;
    context->damage = XDamageCreate(context->display,
                                    context->target,
                                    XDamageReportNonEmpty);
    if (context->damage == None)
        return 0;
    return x11_server_refresh_geometry(context, 1) == LIBRDP_STATUS_OK;
}

x11_server_context* x11_server_context_new(const x11_server_config* config)
{
    x11_server_context* context = NULL;
    x11_server_fuse_config fuse_config;
    XSetWindowAttributes attributes;

    if (!x11_server_config_valid(config))
        return NULL;
    context = (x11_server_context*)calloc(1u, sizeof(*context));
    if (!context)
        return NULL;
    context->clipboard_files = x11_server_clipboard_files_new();
    if (!context->clipboard_files)
    {
        free(context);
        return NULL;
    }
    context->config = *config;
    context->shm.segment.shmid = -1;
    if (config->display_name)
    {
        context->display_name = x11_server_copy_string(config->display_name);
        if (!context->display_name)
        {
            x11_server_clipboard_files_free(context->clipboard_files);
            free(context);
            return NULL;
        }
        context->config.display_name = context->display_name;
    }
    if (config->allow_drive)
    {
        context->drive_mount = x11_server_copy_string(config->drive_mount);
        if (!context->drive_mount)
        {
            x11_server_clipboard_files_free(context->clipboard_files);
            free(context->display_name);
            free(context);
            return NULL;
        }
        context->config.drive_mount = context->drive_mount;
        x11_server_fuse_config_init(&fuse_config);
        fuse_config.mount_path = context->drive_mount;
        context->fuse = x11_server_fuse_new(&fuse_config);
        if (!context->fuse)
        {
            x11_server_clipboard_files_free(context->clipboard_files);
            free(context->drive_mount);
            free(context->display_name);
            free(context);
            return NULL;
        }
    }
    context->display = XOpenDisplay(context->config.display_name);
    if (!context->display)
    {
        x11_server_fuse_free(context->fuse);
        x11_server_clipboard_files_free(context->clipboard_files);
        free(context->drive_mount);
        free(context->display_name);
        free(context);
        return NULL;
    }
    context->screen = DefaultScreen(context->display);
    context->root = RootWindow(context->display, context->screen);
    if (!x11_server_query_extensions(context))
    {
        x11_server_context_free(context);
        return NULL;
    }
    memset(&attributes, 0, sizeof(attributes));
    attributes.event_mask = PropertyChangeMask;
    context->owner_window = XCreateWindow(
        context->display,
        context->root,
        0,
        0,
        1u,
        1u,
        0u,
        CopyFromParent,
        InputOutput,
        CopyFromParent,
        CWEventMask,
        &attributes);
    context->atom_clipboard =
        XInternAtom(context->display, "CLIPBOARD", False);
    context->atom_targets =
        XInternAtom(context->display, "TARGETS", False);
    context->atom_incr = XInternAtom(context->display, "INCR", False);
    context->atom_utf8 =
        XInternAtom(context->display, "UTF8_STRING", False);
    context->atom_text = XInternAtom(context->display, "TEXT", False);
    context->atom_html =
        XInternAtom(context->display, "text/html", False);
    context->atom_png =
        XInternAtom(context->display, "image/png", False);
    context->atom_uri_list =
        XInternAtom(context->display, "text/uri-list", False);
    context->atom_property =
        XInternAtom(context->display, "_LIBRDP_SERVER_SELECTION", False);
    if (context->owner_window == None ||
        context->atom_clipboard == None || context->atom_targets == None ||
        context->atom_incr == None || context->atom_utf8 == None ||
        context->atom_property == None ||
        !x11_server_select_target(context))
    {
        x11_server_context_free(context);
        return NULL;
    }
    context->permissions[SERVER_PLATFORM_PERMISSION_CAPTURE] =
        config->allow_capture ? SERVER_PLATFORM_PERMISSION_GRANTED
                              : SERVER_PLATFORM_PERMISSION_DENIED;
    context->permissions[SERVER_PLATFORM_PERMISSION_INPUT] =
        config->allow_input ? SERVER_PLATFORM_PERMISSION_GRANTED
                            : SERVER_PLATFORM_PERMISSION_DENIED;
    context->permissions[SERVER_PLATFORM_PERMISSION_CLIPBOARD] =
        config->allow_clipboard ? SERVER_PLATFORM_PERMISSION_GRANTED
                                : SERVER_PLATFORM_PERMISSION_DENIED;
    context->permissions[SERVER_PLATFORM_PERMISSION_DRIVE] =
        config->allow_drive ? SERVER_PLATFORM_PERMISSION_GRANTED
                            : SERVER_PLATFORM_PERMISSION_DENIED;
    XFlush(context->display);
    return context;
}

void x11_server_context_free(x11_server_context* context)
{
    if (!context)
        return;
    if (context->display)
    {
        x11_server_capture_resources_release(context);
        if (context->keyboard)
            XkbFreeKeyboard(context->keyboard, XkbAllComponentsMask, True);
        if (context->owner_window != None)
            XDestroyWindow(context->display, context->owner_window);
        XCloseDisplay(context->display);
    }
    free(context->frame_pixels);
    free(context->pointer_pixels);
    free(context->clipboard_read.data);
    free(context->clipboard_write.data);
    x11_server_fuse_free(context->fuse);
    x11_server_clipboard_files_free(context->clipboard_files);
    free(context->drive_mount);
    free(context->display_name);
    free(context);
}

librdp_status x11_server_context_platform(x11_server_context* context,
                                          server_platform* platform)
{
    if (!context || !platform)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    server_platform_init(platform);
    platform->capture.vtable = &x11_server_capture_vtable;
    platform->capture.context = context;
    platform->permission.vtable = &x11_server_permission_vtable;
    platform->permission.context = context;
    if (context->config.allow_input)
    {
        platform->input.vtable = &x11_server_input_vtable;
        platform->input.context = context;
    }
    if (context->config.allow_clipboard)
    {
        platform->clipboard.vtable = &x11_server_clipboard_vtable;
        platform->clipboard.context = context;
    }
    if (context->config.allow_drive)
    {
        platform->drive.vtable = x11_server_fuse_vtable();
        platform->drive.context = context->fuse;
    }
    platform->pointer.vtable = &x11_server_pointer_vtable;
    platform->pointer.context = context;
    return server_platform_validate(platform);
}

uint32_t x11_server_context_width(const x11_server_context* context)
{
    return context ? context->width : 0u;
}

uint32_t x11_server_context_height(const x11_server_context* context)
{
    return context ? context->height : 0u;
}

librdp_status x11_server_context_set_permission(
    x11_server_context* context,
    server_platform_permission_kind kind,
    server_platform_permission_state state)
{
    if (!context || kind < SERVER_PLATFORM_PERMISSION_CAPTURE ||
        kind > SERVER_PLATFORM_PERMISSION_DRIVE ||
        state < SERVER_PLATFORM_PERMISSION_UNKNOWN ||
        state > SERVER_PLATFORM_PERMISSION_GRANTED)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    context->permissions[kind] = state;
    if (context->permission_started && context->permission_sink.changed)
    {
        context->permission_sink.changed(kind,
                                         state,
                                         context->permission_sink.user_data);
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_server_events_get_pollfds(void* opaque,
                                                   struct pollfd* fds,
                                                   size_t capacity,
                                                   size_t* count)
{
    x11_server_context* context = (x11_server_context*)opaque;

    if (!context || !count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *count = 1u;
    if (!fds && capacity == 0u)
        return LIBRDP_STATUS_OK;
    if (!fds || capacity < 1u)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    fds[0].fd = ConnectionNumber(context->display);
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_server_events_notify_poll(
    void* opaque,
    const struct pollfd* fds,
    size_t count)
{
    x11_server_context* context = (x11_server_context*)opaque;

    if (!context || !fds || count != 1u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        context->connection_failed = 1;
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_server_events_dispatch(void* opaque,
                                                unsigned int max_events)
{
    x11_server_context* context = (x11_server_context*)opaque;
    unsigned int dispatched = 0;

    if (!context || max_events == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (context->connection_failed)
    {
        if (context->capture_sink.lost)
        {
            context->capture_sink.lost(LIBRDP_STATUS_IO_ERROR,
                                       context->capture_sink.user_data);
        }
        return LIBRDP_STATUS_IO_ERROR;
    }
    while (dispatched < max_events && XPending(context->display) > 0)
    {
        XEvent event;

        XNextEvent(context->display, &event);
        x11_server_capture_handle_event(context, &event);
        x11_server_pointer_handle_event(context, &event);
        x11_server_clipboard_handle_event(context, &event);
        dispatched++;
    }
    if (context->capture_due && context->capture_started)
        return x11_server_capture_frame(context);
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_server_events_get_next_timeout(void* opaque,
                                                        int* timeout_ms)
{
    x11_server_context* context = (x11_server_context*)opaque;

    if (!context || !timeout_ms)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *timeout_ms = context->capture_due ? 0 : -1;
    return LIBRDP_STATUS_OK;
}

const server_platform_event_source_vtable x11_server_event_source_vtable = {
    SERVER_PLATFORM_EVENT_SOURCE_VERSION,
    sizeof(server_platform_event_source_vtable),
    x11_server_events_get_pollfds,
    x11_server_events_notify_poll,
    x11_server_events_dispatch,
    x11_server_events_get_next_timeout,
};
