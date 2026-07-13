/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 clipboard bridge for local selection ownership and remote
 * clipboard publication.
 * Invariants: clipboard payloads are bounded before allocation, UTF
 * conversion, or publication to X11 clients.
 * Ownership: remote data is copied into the viewer context and released by
 * x11_clipboard_free().
 * Threading: called from the viewer event thread; no state is shared with
 * backend worker threads.
 * Trust boundary: both X11 selection properties and remote clipboard data are
 * attacker-controlled inputs and are never traced as payload bytes.
 */

#include "viewer_clipboard.h"

#include "viewer_trace.h"

#include <X11/Xatom.h>
#include <X11/extensions/Xfixes.h>

#include <errno.h>
#include <iconv.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define X11_CLIPBOARD_MAX_BYTES (16u * 1024u * 1024u)

static int x11_clipboard_store_utf8(x11_app* app, const uint8_t* data, size_t length)
{
    uint8_t* copy = NULL;

    if (!app || (!data && length > 0) || length > X11_CLIPBOARD_MAX_BYTES)
        return 0;
    copy = (uint8_t*)malloc(length + 1u);
    if (!copy)
        return 0;
    if (length > 0)
        memcpy(copy, data, length);
    copy[length] = 0;
    free(app->clipboard_remote_utf8);
    app->clipboard_remote_utf8 = copy;
    app->clipboard_remote_utf8_len = length;
    return 1;
}

/*
 * Convert bounded text between X11 UTF-8 and RDP UTF-16LE clipboard formats.
 * The conversion grows the destination buffer only on E2BIG so malformed input
 * fails without publishing partial or replacement text.
 */
static int x11_convert_text_alloc(const char* to,
                                  const char* from,
                                  const uint8_t* data,
                                  size_t length,
                                  uint8_t** out,
                                  size_t* out_len)
{
    iconv_t cd = (iconv_t)-1;
    uint8_t* output = NULL;
    char* input_cursor = NULL;
    char* output_cursor = NULL;
    size_t input_left = length;
    size_t output_left = 0;
    size_t capacity = 0;
    int ok = 0;

    if (!to || !from || (!data && length > 0) || !out || !out_len)
        return 0;
    *out = NULL;
    *out_len = 0;
    capacity = length > 0 ? (length * 4u) + 16u : 16u;
    if (capacity < length)
        return 0;
    output = (uint8_t*)calloc(1u, capacity);
    if (!output)
        return 0;
    cd = iconv_open(to, from);
    if (cd == (iconv_t)-1)
    {
        free(output);
        return 0;
    }
    input_cursor = (char*)data;
    output_cursor = (char*)output;
    output_left = capacity;
    while (1)
    {
        const size_t converted = iconv(cd, &input_cursor, &input_left, &output_cursor, &output_left);

        if (converted != (size_t)-1)
        {
            ok = 1;
            break;
        }
        if (errno != E2BIG)
            break;
        {
            const size_t used = (size_t)((uint8_t*)output_cursor - output);
            const size_t next_capacity = capacity * 2u;
            uint8_t* resized = NULL;

            if (next_capacity <= capacity)
                break;
            resized = (uint8_t*)realloc(output, next_capacity);
            if (!resized)
                break;
            output = resized;
            memset(output + capacity, 0, next_capacity - capacity);
            capacity = next_capacity;
            output_cursor = (char*)output + used;
            output_left = capacity - used;
        }
    }
    if (ok)
    {
        *out_len = (size_t)((uint8_t*)output_cursor - output);
        *out = output;
        output = NULL;
    }
    iconv_close(cd);
    free(output);
    return ok;
}

static size_t utf8_to_utf16le_bytes(const uint8_t* data, size_t length, uint8_t** out)
{
    size_t converted_len = 0;
    uint8_t* converted = NULL;
    uint8_t* resized = NULL;

    if (!out || (!data && length > 0) || length > X11_CLIPBOARD_MAX_BYTES)
        return 0;
    if (!x11_convert_text_alloc("UTF-16LE", "UTF-8", data, length, &converted, &converted_len))
        return 0;
    if (converted_len > SIZE_MAX - 2u)
    {
        free(converted);
        return 0;
    }
    resized = (uint8_t*)realloc(converted, converted_len + 2u);
    if (!resized)
    {
        free(converted);
        return 0;
    }
    converted = resized;
    converted[converted_len++] = 0;
    converted[converted_len++] = 0;
    *out = converted;
    return converted_len;
}

static size_t utf16le_to_utf8_bytes(const uint8_t* data, size_t length, uint8_t** out)
{
    size_t input_len = length;
    size_t converted_len = 0;
    uint8_t* converted = NULL;
    uint8_t* resized = NULL;
    size_t i = 0;

    if (!out || (!data && length > 0) || (length & 1u) != 0 || length > X11_CLIPBOARD_MAX_BYTES)
        return 0;
    while (i + 1u < length)
    {
        if (data[i] == 0 && data[i + 1u] == 0)
        {
            input_len = i;
            break;
        }
        i += 2u;
    }
    if (!x11_convert_text_alloc("UTF-8", "UTF-16LE", data, input_len, &converted, &converted_len))
        return 0;
    if (converted_len > SIZE_MAX - 1u)
    {
        free(converted);
        return 0;
    }
    resized = (uint8_t*)realloc(converted, converted_len + 1u);
    if (!resized)
    {
        free(converted);
        return 0;
    }
    converted = resized;
    converted[converted_len] = 0;
    *out = converted;
    return converted_len;
}

void x11_clipboard_free(x11_app* app)
{
    if (!app)
        return;
    free(app->clipboard_remote_utf8);
    app->clipboard_remote_utf8 = NULL;
    app->clipboard_remote_utf8_len = 0;
    app->clipboard_owns_selection = 0;
    app->clipboard_request_pending = 0;
    free(app->clipboard_file_path);
    app->clipboard_file_path = NULL;
}

void x11_clipboard_init(x11_app* app)
{
    if (!app || !app->display || !app->window)
        return;
    app->clipboard_selection = XInternAtom(app->display, "CLIPBOARD", False);
    app->clipboard_property = XInternAtom(app->display, "LIBRDP_CLIPBOARD_DATA", False);
    app->atom_targets = XInternAtom(app->display, "TARGETS", False);
    app->atom_utf8_string = XInternAtom(app->display, "UTF8_STRING", False);
    app->atom_text = XInternAtom(app->display, "TEXT", False);
    app->atom_incr = XInternAtom(app->display, "INCR", False);
    app->xfixes_available = XFixesQueryExtension(app->display,
                                                 &app->xfixes_event_base,
                                                 &app->xfixes_error_base);
    if (app->xfixes_available)
        XFixesSelectSelectionInput(app->display,
                                   app->window,
                                   app->clipboard_selection,
                                   XFixesSetSelectionOwnerNotifyMask);
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.clipboard.init",
                    "xfixes=%u",
                    app->xfixes_available ? 1u : 0u);
}

static void x11_clipboard_request_local(x11_app* app, Time time)
{
    Window owner = None;

    if (!app || !app->display || !app->window || app->clipboard_selection == None ||
        app->atom_utf8_string == None || app->clipboard_property == None)
        return;
    owner = XGetSelectionOwner(app->display, app->clipboard_selection);
    if (owner == None || owner == app->window)
        return;
    XConvertSelection(app->display,
                      app->clipboard_selection,
                      app->atom_utf8_string,
                      app->clipboard_property,
                      app->window,
                      time == 0 ? CurrentTime : time);
    app->clipboard_request_pending = 1;
    x11_trace_event(X11_TRACE_CLIENT, "x11.clipboard.request_local", "owner=%lu", owner);
}

void x11_clipboard_handle_owner_notify(x11_app* app, XEvent* event)
{
    XFixesSelectionNotifyEvent* notify = NULL;

    if (!app || !event || !app->xfixes_available || event->type != app->xfixes_event_base + XFixesSelectionNotify)
        return;
    notify = (XFixesSelectionNotifyEvent*)event;
    if (notify->selection != app->clipboard_selection)
        return;
    if (notify->owner == app->window)
        return;
    app->clipboard_owns_selection = 0;
    x11_clipboard_request_local(app, notify->timestamp);
}

void x11_clipboard_handle_selection_notify(x11_app* app, XSelectionEvent* selection)
{
    Atom actual_type = None;
    int actual_format = 0;
    unsigned long nitems = 0;
    unsigned long bytes_after = 0;
    unsigned char* property = NULL;
    uint8_t* utf16 = NULL;
    size_t utf16_len = 0;

    if (!app || !selection || selection->selection != app->clipboard_selection)
        return;
    app->clipboard_request_pending = 0;
    if (selection->property == None)
        return;
    if (XGetWindowProperty(app->display,
                           app->window,
                           selection->property,
                           0,
                           (long)((X11_CLIPBOARD_MAX_BYTES / 4u) + 1u),
                           True,
                           AnyPropertyType,
                           &actual_type,
                           &actual_format,
                           &nitems,
                           &bytes_after,
                           &property) != Success)
        return;
    if (actual_type == app->atom_incr || actual_format != 8 || bytes_after != 0 ||
        nitems > X11_CLIPBOARD_MAX_BYTES)
    {
        if (property)
            XFree(property);
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.clipboard.local_ignored",
                        "type=%lu format=%d nitems=%lu bytes_after=%lu",
                        actual_type,
                        actual_format,
                        nitems,
                        bytes_after);
        return;
    }
    if (actual_type == app->atom_utf8_string || actual_type == XA_STRING || actual_type == app->atom_text)
    {
        utf16_len = utf8_to_utf16le_bytes(property, (size_t)nitems, &utf16);
        if (utf16_len > 0)
        {
            (void)librdp_session_clipboard_set_data(app->session,
                                                    LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT,
                                                    utf16,
                                                    utf16_len);
            x11_trace_event(X11_TRACE_CLIENT,
                            "x11.clipboard.local_data",
                            "utf8_len=%lu utf16_len=%u",
                            nitems,
                            (unsigned)utf16_len);
        }
        free(utf16);
    }
    if (property)
        XFree(property);
}

void x11_clipboard_handle_selection_request(x11_app* app, XSelectionRequestEvent* request)
{
    XSelectionEvent response;
    Atom property = None;
    Atom type = None;

    if (!app || !request)
        return;

    memset(&response, 0, sizeof(response));
    response.type = SelectionNotify;
    response.display = request->display;
    response.requestor = request->requestor;
    response.selection = request->selection;
    response.target = request->target;
    response.time = request->time;
    response.property = None;

    if (request->selection == app->clipboard_selection)
    {
        property = request->property == None ? request->target : request->property;
        if (request->target == app->atom_targets)
        {
            Atom targets[4];

            targets[0] = app->atom_targets;
            targets[1] = app->atom_utf8_string;
            targets[2] = app->atom_text;
            targets[3] = XA_STRING;
            XChangeProperty(app->display,
                            request->requestor,
                            property,
                            XA_ATOM,
                            32,
                            PropModeReplace,
                            (const unsigned char*)targets,
                            4);
            response.property = property;
        }
        else if ((request->target == app->atom_utf8_string ||
                  request->target == XA_STRING ||
                  request->target == app->atom_text) &&
                 app->clipboard_remote_utf8)
        {
            type = request->target == app->atom_text ? app->atom_utf8_string : request->target;
            XChangeProperty(app->display,
                            request->requestor,
                            property,
                            type,
                            8,
                            PropModeReplace,
                            app->clipboard_remote_utf8,
                            (int)app->clipboard_remote_utf8_len);
            response.property = property;
        }
    }

    XSendEvent(app->display, request->requestor, False, 0, (XEvent*)&response);
    XFlush(app->display);
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.clipboard.selection_request",
                    "target=%lu served=%u data_len=%u",
                    request->target,
                    response.property == None ? 0u : 1u,
                    response.property == None ? 0u : (unsigned)app->clipboard_remote_utf8_len);
}

void x11_clipboard_handle_selection_clear(x11_app* app, const XSelectionClearEvent* event)
{
    if (!app || !event || event->selection != app->clipboard_selection)
        return;
    app->clipboard_owns_selection = 0;
    x11_trace_event(X11_TRACE_CLIENT, "x11.clipboard.selection_clear", "owner=0");
}

static void x11_clipboard_set_remote_data(x11_app* app, const uint8_t* data, size_t length)
{
    if (!app || !app->display || !app->window)
        return;
    if (!x11_clipboard_store_utf8(app, data, length))
        return;
    XSetSelectionOwner(app->display, app->clipboard_selection, app->window, CurrentTime);
    app->clipboard_owns_selection =
        XGetSelectionOwner(app->display, app->clipboard_selection) == app->window ? 1 : 0;
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.clipboard.remote_data",
                    "utf8_len=%u owner=%u",
                    (unsigned)length,
                    app->clipboard_owns_selection ? 1u : 0u);
}

void x11_clipboard_set_remote_utf16le(x11_app* app, const uint8_t* data, size_t length)
{
    uint8_t* utf8 = NULL;
    size_t utf8_len = 0;

    utf8_len = utf16le_to_utf8_bytes(data, length, &utf8);
    if (utf8_len > 0 || utf8)
        x11_clipboard_set_remote_data(app, utf8, utf8_len);
    free(utf8);
}
