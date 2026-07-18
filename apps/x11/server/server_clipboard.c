/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: bounded X11 selection adapter for the desktop server.
 * Invariants: one native read and one native write are correlated at a time,
 * INCR chunks are capped, and ownership generations suppress local/remote
 * feedback loops.
 * Ownership: pending selection buffers are context-owned; X properties and
 * callback payloads are copied or consumed during their callback.
 * Threading: all selection operations execute on the X11 host thread.
 * Trust boundary: selection owners and requestors are untrusted; types, widths,
 * lengths and cumulative allocation are checked before conversion or delivery.
 */

#include "server_x11_internal.h"

#include <X11/Xatom.h>

#include <errno.h>
#include <iconv.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define X11_SERVER_CLIPBOARD_MAX_BYTES (16u * 1024u * 1024u)
#define X11_SERVER_CLIPBOARD_CHUNK_BYTES 65536u

static void x11_server_clipboard_read_clear(x11_server_context* context)
{
    x11_server_clipboard_read* read = context ? &context->clipboard_read : NULL;

    if (!read)
        return;
    free(read->data);
    memset(read, 0, sizeof(*read));
}

static void x11_server_clipboard_write_clear(x11_server_context* context)
{
    x11_server_clipboard_write* write =
        context ? &context->clipboard_write : NULL;

    if (!write)
        return;
    free(write->data);
    memset(write, 0, sizeof(*write));
}

static int x11_server_clipboard_append(x11_server_clipboard_read* read,
                                       const uint8_t* data,
                                       size_t length)
{
    size_t required = 0u;
    size_t capacity = 0u;
    uint8_t* resized = NULL;

    if (!read || (!data && length > 0u) ||
        length > X11_SERVER_CLIPBOARD_MAX_BYTES ||
        read->length > X11_SERVER_CLIPBOARD_MAX_BYTES - length)
        return 0;
    required = read->length + length;
    if (required > read->capacity)
    {
        capacity = read->capacity == 0u ? 4096u : read->capacity;
        while (capacity < required)
        {
            if (capacity > X11_SERVER_CLIPBOARD_MAX_BYTES / 2u)
            {
                capacity = X11_SERVER_CLIPBOARD_MAX_BYTES;
                break;
            }
            capacity *= 2u;
        }
        if (capacity < required)
            return 0;
        resized = (uint8_t*)realloc(read->data, capacity);
        if (!resized)
            return 0;
        read->data = resized;
        read->capacity = capacity;
    }
    if (length > 0u)
        memcpy(read->data + read->length, data, length);
    read->length = required;
    return 1;
}

static librdp_status x11_server_iconv(const char* to_code,
                                      const char* from_code,
                                      const uint8_t* source,
                                      size_t source_len,
                                      uint8_t** output,
                                      size_t* output_len,
                                      size_t terminator_bytes)
{
    iconv_t converter = (iconv_t)-1;
    char* input_cursor = (char*)source;
    size_t input_left = source_len;
    size_t capacity = 0u;
    uint8_t* buffer = NULL;
    char* output_cursor = NULL;
    size_t output_left = 0u;

    if (!to_code || !from_code || (!source && source_len > 0u) ||
        !output || !output_len ||
        source_len > X11_SERVER_CLIPBOARD_MAX_BYTES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *output = NULL;
    *output_len = 0u;
    if (source_len > (X11_SERVER_CLIPBOARD_MAX_BYTES - terminator_bytes) / 4u)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    capacity = source_len * 4u + terminator_bytes + 4u;
    buffer = (uint8_t*)calloc(1u, capacity);
    if (!buffer)
        return LIBRDP_STATUS_NO_MEMORY;
    converter = iconv_open(to_code, from_code);
    if (converter == (iconv_t)-1)
    {
        free(buffer);
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    output_cursor = (char*)buffer;
    output_left = capacity - terminator_bytes;
    if (iconv(converter,
              source_len > 0u ? &input_cursor : NULL,
              &input_left,
              &output_cursor,
              &output_left) == (size_t)-1 ||
        input_left != 0u)
    {
        iconv_close(converter);
        free(buffer);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    iconv_close(converter);
    *output_len = capacity - terminator_bytes - output_left;
    *output = buffer;
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_server_utf8_to_utf16le(const uint8_t* source,
                                                 size_t source_len,
                                                 uint8_t** output,
                                                 size_t* output_len)
{
    return x11_server_iconv("UTF-16LE",
                            "UTF-8",
                            source,
                            source_len,
                            output,
                            output_len,
                            2u);
}

static librdp_status x11_server_utf16le_to_utf8(const uint8_t* source,
                                                 size_t source_len,
                                                 uint8_t** output,
                                                 size_t* output_len)
{
    size_t content_len = source_len;

    if ((source_len & 1u) != 0u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    while (content_len >= 2u && source[content_len - 2u] == 0u &&
           source[content_len - 1u] == 0u)
        content_len -= 2u;
    return x11_server_iconv("UTF-8",
                            "UTF-16LE",
                            source,
                            content_len,
                            output,
                            output_len,
                            1u);
}

static int x11_server_html_offset(const uint8_t* data,
                                  size_t length,
                                  const char* key,
                                  size_t* value)
{
    size_t key_len = key ? strlen(key) : 0u;
    size_t index = 0u;

    if (!data || !key || !value || key_len == 0u)
        return 0;
    for (index = 0u; index + key_len < length; index++)
    {
        size_t cursor = 0u;
        size_t parsed = 0u;
        size_t digits = 0u;

        if (memcmp(data + index, key, key_len) != 0)
            continue;
        cursor = index + key_len;
        while (cursor < length && data[cursor] >= '0' &&
               data[cursor] <= '9')
        {
            size_t digit = (size_t)(data[cursor] - '0');

            if (parsed > (SIZE_MAX - digit) / 10u)
                return 0;
            parsed = parsed * 10u + digit;
            cursor++;
            digits++;
        }
        if (digits == 0u)
            return 0;
        *value = parsed;
        return 1;
    }
    return 0;
}

static librdp_status x11_server_html_extract(const uint8_t* data,
                                              size_t length,
                                              uint8_t** output,
                                              size_t* output_len)
{
    size_t start = 0u;
    size_t end = 0u;
    uint8_t* copy = NULL;

    if (!data || !output || !output_len ||
        !x11_server_html_offset(data,
                                length,
                                "StartFragment:",
                                &start) ||
        !x11_server_html_offset(data,
                                length,
                                "EndFragment:",
                                &end) ||
        start > end || end > length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    copy = (uint8_t*)malloc(end - start + 1u);
    if (!copy)
        return LIBRDP_STATUS_NO_MEMORY;
    memcpy(copy, data + start, end - start);
    copy[end - start] = 0u;
    *output = copy;
    *output_len = end - start;
    return LIBRDP_STATUS_OK;
}

static int x11_server_write_decimal(uint8_t* destination, size_t value)
{
    char text[11];
    int written = 0;

    if (!destination || value > 9999999999u)
        return 0;
    written = snprintf(text, sizeof(text), "%010zu", value);
    if (written != 10)
        return 0;
    memcpy(destination, text, 10u);
    return 1;
}

static librdp_status x11_server_html_package(const uint8_t* data,
                                              size_t length,
                                              uint8_t** output,
                                              size_t* output_len)
{
    static const char header[] =
        "Version:0.9\r\n"
        "StartHTML:0000000000\r\n"
        "EndHTML:0000000000\r\n"
        "StartFragment:0000000000\r\n"
        "EndFragment:0000000000\r\n";
    static const char prefix[] = "<html><body><!--StartFragment-->";
    static const char suffix[] = "<!--EndFragment--></body></html>";
    const size_t header_len = sizeof(header) - 1u;
    const size_t prefix_len = sizeof(prefix) - 1u;
    const size_t suffix_len = sizeof(suffix) - 1u;
    size_t total = 0u;
    size_t start_fragment = 0u;
    size_t end_fragment = 0u;
    uint8_t* buffer = NULL;

    if ((!data && length > 0u) || !output || !output_len ||
        length > X11_SERVER_CLIPBOARD_MAX_BYTES -
                     header_len - prefix_len - suffix_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    total = header_len + prefix_len + length + suffix_len;
    buffer = (uint8_t*)malloc(total);
    if (!buffer)
        return LIBRDP_STATUS_NO_MEMORY;
    memcpy(buffer, header, header_len);
    start_fragment = header_len + prefix_len;
    end_fragment = start_fragment + length;
    if (!x11_server_write_decimal(buffer + 23u, header_len) ||
        !x11_server_write_decimal(buffer + 43u,
                                  total) ||
        !x11_server_write_decimal(buffer + 69u,
                                  start_fragment) ||
        !x11_server_write_decimal(buffer + 93u,
                                  end_fragment))
    {
        free(buffer);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    memcpy(buffer + header_len, prefix, prefix_len);
    if (length > 0u)
        memcpy(buffer + start_fragment, data, length);
    memcpy(buffer + end_fragment, suffix, suffix_len);
    *output = buffer;
    *output_len = total;
    return LIBRDP_STATUS_OK;
}

static uint32_t x11_server_format_id_for_atom(
    const x11_server_context* context,
    Atom target)
{
    if (target == context->atom_utf8 || target == context->atom_text ||
        target == XA_STRING)
        return LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT;
    if (target == context->atom_html)
        return LIBRDP_CLIPBOARD_FORMAT_HTML;
    if (target == context->atom_png)
        return LIBRDP_CLIPBOARD_FORMAT_PNG;
    if (target == context->atom_uri_list)
        return LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW;
    return 0u;
}

static Atom x11_server_atom_for_format_id(
    const x11_server_context* context,
    uint32_t format_id)
{
    if (format_id == LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT)
        return context->atom_utf8;
    if (format_id == LIBRDP_CLIPBOARD_FORMAT_HTML)
        return context->atom_html;
    if (format_id == LIBRDP_CLIPBOARD_FORMAT_PNG)
        return context->atom_png;
    if (format_id == LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW ||
        format_id == LIBRDP_CLIPBOARD_FORMAT_HDROP)
        return context->atom_uri_list;
    return None;
}

static const char* x11_server_mime_for_atom(
    const x11_server_context* context,
    Atom atom)
{
    if (atom == context->atom_utf8 || atom == context->atom_text ||
        atom == XA_STRING)
        return "text/plain;charset=utf-8";
    if (atom == context->atom_html)
        return "text/html";
    if (atom == context->atom_png)
        return "image/png";
    if (atom == context->atom_uri_list)
        return "text/uri-list";
    return NULL;
}

static librdp_status x11_server_clipboard_convert_to_wire(
    x11_server_context* context,
    uint32_t format_id,
    const uint8_t* data,
    size_t length,
    uint8_t** output,
    size_t* output_len)
{
    uint8_t* copy = NULL;

    (void)context;
    if (format_id == LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT)
        return x11_server_utf8_to_utf16le(data, length, output, output_len);
    if (format_id == LIBRDP_CLIPBOARD_FORMAT_HTML)
        return x11_server_html_package(data, length, output, output_len);
    if ((!data && length > 0u) ||
        length > X11_SERVER_CLIPBOARD_MAX_BYTES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    copy = (uint8_t*)malloc(length > 0u ? length : 1u);
    if (!copy)
        return LIBRDP_STATUS_NO_MEMORY;
    if (length > 0u)
        memcpy(copy, data, length);
    *output = copy;
    *output_len = length;
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_server_clipboard_convert_from_wire(
    x11_server_context* context,
    uint32_t format_id,
    const uint8_t* data,
    size_t length,
    uint8_t** output,
    size_t* output_len)
{
    uint8_t* copy = NULL;

    (void)context;
    if (format_id == LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT)
        return x11_server_utf16le_to_utf8(data, length, output, output_len);
    if (format_id == LIBRDP_CLIPBOARD_FORMAT_HTML)
        return x11_server_html_extract(data, length, output, output_len);
    if ((!data && length > 0u) ||
        length > X11_SERVER_CLIPBOARD_MAX_BYTES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    copy = (uint8_t*)malloc(length > 0u ? length : 1u);
    if (!copy)
        return LIBRDP_STATUS_NO_MEMORY;
    if (length > 0u)
        memcpy(copy, data, length);
    *output = copy;
    *output_len = length;
    return LIBRDP_STATUS_OK;
}

static void x11_server_clipboard_send_selection_notify(
    x11_server_context* context,
    const XSelectionRequestEvent* request,
    Atom property)
{
    XEvent response;

    memset(&response, 0, sizeof(response));
    response.xselection.type = SelectionNotify;
    response.xselection.display = request->display;
    response.xselection.requestor = request->requestor;
    response.xselection.selection = request->selection;
    response.xselection.target = request->target;
    response.xselection.property = property;
    response.xselection.time = request->time;
    XSendEvent(context->display,
               request->requestor,
               False,
               0,
               &response);
    XFlush(context->display);
}

static librdp_status x11_server_clipboard_read_property(
    x11_server_context* context,
    Window window,
    Atom property,
    int delete_property,
    Atom* type,
    int* format,
    unsigned char** data,
    size_t* length)
{
    unsigned long items = 0ul;
    unsigned long after = 0ul;
    unsigned char* property_data = NULL;
    int result = 0;

    if (!context || property == None || !type || !format || !data ||
        !length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *data = NULL;
    *length = 0u;
    result = XGetWindowProperty(context->display,
                                window,
                                property,
                                0,
                                (long)(X11_SERVER_CLIPBOARD_MAX_BYTES / 4u),
                                delete_property ? True : False,
                                AnyPropertyType,
                                type,
                                format,
                                &items,
                                &after,
                                &property_data);
    if (result != Success || after != 0ul ||
        (*format != 8 && *format != 16 && *format != 32))
    {
        if (property_data)
            XFree(property_data);
        return after != 0ul ? LIBRDP_STATUS_LIMIT_EXCEEDED
                            : LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (items > SIZE_MAX / ((size_t)*format / 8u))
    {
        if (property_data)
            XFree(property_data);
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    *length = (size_t)items *
              (*format == 32 ? sizeof(unsigned long)
                             : (size_t)*format / 8u);
    *data = property_data;
    return LIBRDP_STATUS_OK;
}

static void x11_server_clipboard_deliver_read(x11_server_context* context,
                                              librdp_status status)
{
    x11_server_clipboard_read* read = &context->clipboard_read;
    server_platform_clipboard_data response;
    uint8_t* converted = NULL;
    size_t converted_len = 0u;

    if (!read->active || read->discovering_formats)
        return;
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_server_clipboard_convert_to_wire(
            context,
            read->format_id,
            read->data,
            read->length,
            &converted,
            &converted_len);
    }
    memset(&response, 0, sizeof(response));
    response.ownership_generation = context->clipboard_local_generation;
    response.request_id = read->request_id;
    response.format_id = read->format_id;
    response.status = status;
    response.data = status == LIBRDP_STATUS_OK ? converted : NULL;
    response.data_len = status == LIBRDP_STATUS_OK ? converted_len : 0u;
    response.final_chunk = 1;
    if (context->clipboard_sink.data)
        context->clipboard_sink.data(&response,
                                     context->clipboard_sink.user_data);
    free(converted);
    x11_server_clipboard_read_clear(context);
}

static void x11_server_clipboard_publish_targets(
    x11_server_context* context,
    const Atom* atoms,
    size_t count)
{
    server_platform_clipboard_format
        formats[X11_SERVER_CLIPBOARD_MAX_FORMATS];
    size_t format_count = 0u;
    size_t index = 0u;

    memset(formats, 0, sizeof(formats));
    for (index = 0u;
         index < count &&
         format_count < X11_SERVER_CLIPBOARD_MAX_FORMATS;
         index++)
    {
        uint32_t id = x11_server_format_id_for_atom(context, atoms[index]);
        const char* mime = x11_server_mime_for_atom(context, atoms[index]);
        size_t duplicate = 0u;

        if (id == 0u || !mime)
            continue;
        for (duplicate = 0u; duplicate < format_count; duplicate++)
        {
            if (formats[duplicate].id == id)
                break;
        }
        if (duplicate != format_count)
            continue;
        formats[format_count].id = id;
        formats[format_count].mime_type = mime;
        format_count++;
    }
    context->clipboard_local_generation++;
    if (context->clipboard_local_generation == 0u)
        context->clipboard_local_generation = 1u;
    if (context->clipboard_sink.formats)
    {
        context->clipboard_sink.formats(
            formats,
            format_count,
            context->clipboard_local_generation,
            context->clipboard_sink.user_data);
    }
}

static void x11_server_clipboard_handle_selection_notify(
    x11_server_context* context,
    const XSelectionEvent* selection)
{
    x11_server_clipboard_read* read = &context->clipboard_read;
    Atom type = None;
    int format = 0;
    unsigned char* data = NULL;
    size_t length = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!read->active || selection->requestor != context->owner_window ||
        selection->selection != context->atom_clipboard)
        return;
    if (selection->property == None)
    {
        if (read->discovering_formats)
            x11_server_clipboard_read_clear(context);
        else
            x11_server_clipboard_deliver_read(context,
                                              LIBRDP_STATUS_PROTOCOL_ERROR);
        return;
    }
    status = x11_server_clipboard_read_property(context,
                                                context->owner_window,
                                                selection->property,
                                                0,
                                                &type,
                                                &format,
                                                &data,
                                                &length);
    if (status != LIBRDP_STATUS_OK)
    {
        x11_server_clipboard_deliver_read(context, status);
        return;
    }
    if (type == context->atom_incr)
    {
        read->incremental = 1;
        XDeleteProperty(context->display,
                        context->owner_window,
                        selection->property);
        XFree(data);
        return;
    }
    if (read->discovering_formats)
    {
        if (type == XA_ATOM && format == 32)
        {
            x11_server_clipboard_publish_targets(
                context,
                (const Atom*)data,
                length / sizeof(Atom));
        }
        XFree(data);
        x11_server_clipboard_read_clear(context);
        return;
    }
    if (format != 8 ||
        !x11_server_clipboard_append(read, data, length))
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    XFree(data);
    x11_server_clipboard_deliver_read(context, status);
}

static void x11_server_clipboard_handle_incr_read(
    x11_server_context* context,
    const XPropertyEvent* property)
{
    x11_server_clipboard_read* read = &context->clipboard_read;
    Atom type = None;
    int format = 0;
    unsigned char* data = NULL;
    size_t length = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!read->active || !read->incremental ||
        property->window != context->owner_window ||
        property->atom != context->atom_property ||
        property->state != PropertyNewValue)
        return;
    status = x11_server_clipboard_read_property(context,
                                                context->owner_window,
                                                context->atom_property,
                                                1,
                                                &type,
                                                &format,
                                                &data,
                                                &length);
    if (status != LIBRDP_STATUS_OK || format != 8 ||
        (length > 0u &&
         !x11_server_clipboard_append(read, data, length)))
    {
        if (data)
            XFree(data);
        x11_server_clipboard_deliver_read(
            context,
            status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_LIMIT_EXCEEDED
                                       : status);
        return;
    }
    if (data)
        XFree(data);
    if (length == 0u)
        x11_server_clipboard_deliver_read(context, LIBRDP_STATUS_OK);
}

static void x11_server_clipboard_handle_incr_write(
    x11_server_context* context,
    const XPropertyEvent* property)
{
    x11_server_clipboard_write* write = &context->clipboard_write;
    size_t chunk = 0u;

    if (!write->active || !write->incremental ||
        property->window != write->request.requestor ||
        property->atom != write->request.property ||
        property->state != PropertyDelete)
        return;
    if (write->offset >= write->length)
    {
        XChangeProperty(context->display,
                        write->request.requestor,
                        write->request.property,
                        write->target,
                        8,
                        PropModeReplace,
                        NULL,
                        0);
        XFlush(context->display);
        x11_server_clipboard_write_clear(context);
        return;
    }
    chunk = write->length - write->offset;
    if (chunk > X11_SERVER_CLIPBOARD_CHUNK_BYTES)
        chunk = X11_SERVER_CLIPBOARD_CHUNK_BYTES;
    XChangeProperty(context->display,
                    write->request.requestor,
                    write->request.property,
                    write->target,
                    8,
                    PropModeReplace,
                    write->data + write->offset,
                    (int)chunk);
    write->offset += chunk;
    XFlush(context->display);
}

static void x11_server_clipboard_begin_discovery(
    x11_server_context* context)
{
    if (context->clipboard_read.active)
        x11_server_clipboard_read_clear(context);
    context->clipboard_read.active = 1;
    context->clipboard_read.discovering_formats = 1;
    context->clipboard_read.target = context->atom_targets;
    XConvertSelection(context->display,
                      context->atom_clipboard,
                      context->atom_targets,
                      context->atom_property,
                      context->owner_window,
                      CurrentTime);
    XFlush(context->display);
}

static void x11_server_clipboard_handle_owner(
    x11_server_context* context,
    const XFixesSelectionNotifyEvent* event)
{
    if (!context->clipboard_started ||
        event->selection != context->atom_clipboard ||
        event->owner == context->owner_window)
        return;
    if (event->owner == None)
    {
        context->clipboard_local_generation++;
        if (context->clipboard_sink.formats)
        {
            context->clipboard_sink.formats(
                NULL,
                0u,
                context->clipboard_local_generation,
                context->clipboard_sink.user_data);
        }
        return;
    }
    x11_server_clipboard_begin_discovery(context);
}

static int x11_server_clipboard_remote_target(
    const x11_server_context* context,
    Atom target,
    uint32_t* format_id)
{
    size_t index = 0u;

    for (index = 0u; index < context->remote_format_count; index++)
    {
        if (context->remote_targets[index] == target)
        {
            if (format_id)
                *format_id = context->remote_format_ids[index];
            return 1;
        }
    }
    return 0;
}

static void x11_server_clipboard_handle_selection_request(
    x11_server_context* context,
    const XSelectionRequestEvent* request)
{
    uint32_t format_id = 0u;
    Atom property = request->property != None ? request->property
                                              : request->target;

    if (!context->clipboard_started ||
        request->selection != context->atom_clipboard)
        return;
    if (request->target == context->atom_targets)
    {
        Atom targets[X11_SERVER_CLIPBOARD_MAX_FORMATS + 1u];
        size_t index = 0u;

        targets[0] = context->atom_targets;
        for (index = 0u; index < context->remote_format_count; index++)
            targets[index + 1u] = context->remote_targets[index];
        XChangeProperty(context->display,
                        request->requestor,
                        property,
                        XA_ATOM,
                        32,
                        PropModeReplace,
                        (const unsigned char*)targets,
                        (int)(context->remote_format_count + 1u));
        x11_server_clipboard_send_selection_notify(context,
                                                    request,
                                                    property);
        return;
    }
    if (context->clipboard_write.active ||
        !x11_server_clipboard_remote_target(context,
                                            request->target,
                                            &format_id) ||
        !context->clipboard_sink.request)
    {
        x11_server_clipboard_send_selection_notify(context,
                                                    request,
                                                    None);
        return;
    }
    context->clipboard_next_request_id++;
    if (context->clipboard_next_request_id == 0u)
        context->clipboard_next_request_id++;
    context->clipboard_write.active = 1;
    context->clipboard_write.request = *request;
    context->clipboard_write.request.property = property;
    context->clipboard_write.request_id =
        context->clipboard_next_request_id;
    context->clipboard_write.format_id = format_id;
    context->clipboard_write.target = request->target;
    {
        server_platform_clipboard_request platform_request;

        memset(&platform_request, 0, sizeof(platform_request));
        platform_request.ownership_generation =
            context->clipboard_remote_generation;
        platform_request.request_id =
            context->clipboard_write.request_id;
        platform_request.format_id = format_id;
        context->clipboard_sink.request(
            &platform_request,
            context->clipboard_sink.user_data);
    }
}

void x11_server_clipboard_handle_event(x11_server_context* context,
                                       const XEvent* event)
{
    if (!context || !event || !context->clipboard_started)
        return;
    if (event->type == SelectionNotify)
        x11_server_clipboard_handle_selection_notify(context,
                                                     &event->xselection);
    else if (event->type == SelectionRequest)
        x11_server_clipboard_handle_selection_request(
            context,
            &event->xselectionrequest);
    else if (event->type == SelectionClear)
    {
        if (event->xselectionclear.selection == context->atom_clipboard)
            context->clipboard_remote_generation = 0u;
    }
    else if (event->type == PropertyNotify)
    {
        x11_server_clipboard_handle_incr_read(context,
                                              &event->xproperty);
        x11_server_clipboard_handle_incr_write(context,
                                               &event->xproperty);
    }
    else if (event->type ==
             context->fixes_event_base + XFixesSelectionNotify)
    {
        x11_server_clipboard_handle_owner(
            context,
            (const XFixesSelectionNotifyEvent*)event);
    }
}

static librdp_status x11_server_clipboard_start(
    void* opaque,
    const server_platform_clipboard_sink* sink)
{
    x11_server_context* context = (x11_server_context*)opaque;

    if (!context || !sink || !sink->formats || !sink->data ||
        !sink->request || !sink->file_request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (context->clipboard_started)
        return LIBRDP_STATUS_STATE;
    context->clipboard_sink = *sink;
    context->clipboard_started = 1;
    XFixesSelectSelectionInput(
        context->display,
        context->owner_window,
        context->atom_clipboard,
        XFixesSetSelectionOwnerNotifyMask |
            XFixesSelectionWindowDestroyNotifyMask |
            XFixesSelectionClientCloseNotifyMask);
    if (XGetSelectionOwner(context->display,
                           context->atom_clipboard) != None)
        x11_server_clipboard_begin_discovery(context);
    return LIBRDP_STATUS_OK;
}

static void x11_server_clipboard_stop(void* opaque)
{
    x11_server_context* context = (x11_server_context*)opaque;

    if (!context)
        return;
    if (XGetSelectionOwner(context->display,
                           context->atom_clipboard) ==
        context->owner_window)
    {
        XSetSelectionOwner(context->display,
                           context->atom_clipboard,
                           None,
                           CurrentTime);
    }
    x11_server_clipboard_read_clear(context);
    x11_server_clipboard_write_clear(context);
    memset(&context->clipboard_sink, 0, sizeof(context->clipboard_sink));
    context->clipboard_started = 0;
    context->remote_format_count = 0u;
}

static librdp_status x11_server_clipboard_publish_formats(
    void* opaque,
    const server_platform_clipboard_format* formats,
    size_t format_count,
    uint64_t generation)
{
    x11_server_context* context = (x11_server_context*)opaque;
    size_t index = 0u;

    if (!context || (format_count > 0u && !formats) ||
        format_count > X11_SERVER_CLIPBOARD_MAX_FORMATS ||
        generation == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    context->remote_format_count = 0u;
    for (index = 0u; index < format_count; index++)
    {
        Atom atom = x11_server_atom_for_format_id(context, formats[index].id);

        if (atom == None)
            continue;
        context->remote_targets[context->remote_format_count] = atom;
        context->remote_format_ids[context->remote_format_count] =
            formats[index].id;
        context->remote_format_count++;
    }
    context->clipboard_remote_generation = generation;
    x11_server_clipboard_read_clear(context);
    x11_server_clipboard_write_clear(context);
    XSetSelectionOwner(context->display,
                       context->atom_clipboard,
                       context->owner_window,
                       CurrentTime);
    XFlush(context->display);
    return XGetSelectionOwner(context->display, context->atom_clipboard) ==
                   context->owner_window
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_IO_ERROR;
}

static librdp_status x11_server_clipboard_request_data(
    void* opaque,
    uint64_t request_id,
    uint32_t format_id)
{
    x11_server_context* context = (x11_server_context*)opaque;
    Atom target = None;

    if (!context || request_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (context->clipboard_read.active)
        return LIBRDP_STATUS_AGAIN;
    target = x11_server_atom_for_format_id(context, format_id);
    if (target == None)
        return LIBRDP_STATUS_UNSUPPORTED;
    context->clipboard_read.active = 1;
    context->clipboard_read.request_id = request_id;
    context->clipboard_read.format_id = format_id;
    context->clipboard_read.target = target;
    XConvertSelection(context->display,
                      context->atom_clipboard,
                      target,
                      context->atom_property,
                      context->owner_window,
                      CurrentTime);
    XFlush(context->display);
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_server_clipboard_request_file(
    void* opaque,
    const server_platform_clipboard_file_request* request)
{
    x11_server_context* context = (x11_server_context*)opaque;
    server_platform_clipboard_data response;

    if (!context || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&response, 0, sizeof(response));
    response.peer_id = request->peer_id;
    response.generation = request->generation;
    response.ownership_generation = request->ownership_generation;
    response.request_id = request->request_id;
    response.stream_id = request->stream_id;
    response.status = LIBRDP_STATUS_UNSUPPORTED;
    response.final_chunk = 1;
    context->clipboard_sink.data(&response,
                                 context->clipboard_sink.user_data);
    return LIBRDP_STATUS_UNSUPPORTED;
}

static librdp_status x11_server_clipboard_write_data(
    void* opaque,
    const server_platform_clipboard_data* data)
{
    x11_server_context* context = (x11_server_context*)opaque;
    x11_server_clipboard_write* write = NULL;
    uint8_t* converted = NULL;
    size_t converted_len = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    write = &context->clipboard_write;
    if (!write->active || write->request_id != data->request_id ||
        write->format_id != data->format_id || !data->final_chunk)
        return LIBRDP_STATUS_STATE;
    if (data->status != LIBRDP_STATUS_OK)
    {
        x11_server_clipboard_send_selection_notify(context,
                                                    &write->request,
                                                    None);
        x11_server_clipboard_write_clear(context);
        return data->status;
    }
    status = x11_server_clipboard_convert_from_wire(context,
                                                    data->format_id,
                                                    data->data,
                                                    data->data_len,
                                                    &converted,
                                                    &converted_len);
    if (status != LIBRDP_STATUS_OK)
    {
        x11_server_clipboard_send_selection_notify(context,
                                                    &write->request,
                                                    None);
        x11_server_clipboard_write_clear(context);
        return status;
    }
    write->data = converted;
    write->length = converted_len;
    if (converted_len <= X11_SERVER_CLIPBOARD_CHUNK_BYTES)
    {
        XChangeProperty(context->display,
                        write->request.requestor,
                        write->request.property,
                        write->target,
                        8,
                        PropModeReplace,
                        write->data,
                        (int)write->length);
        x11_server_clipboard_send_selection_notify(
            context,
            &write->request,
            write->request.property);
        x11_server_clipboard_write_clear(context);
        return LIBRDP_STATUS_OK;
    }
    if (converted_len > UINT32_MAX)
    {
        x11_server_clipboard_write_clear(context);
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    {
        unsigned long total = (unsigned long)converted_len;

        XSelectInput(context->display,
                     write->request.requestor,
                     PropertyChangeMask);
        XChangeProperty(context->display,
                        write->request.requestor,
                        write->request.property,
                        context->atom_incr,
                        32,
                        PropModeReplace,
                        (const unsigned char*)&total,
                        1);
        write->incremental = 1;
        x11_server_clipboard_send_selection_notify(
            context,
            &write->request,
            write->request.property);
    }
    return LIBRDP_STATUS_OK;
}

static void x11_server_clipboard_cancel_peer(void* opaque,
                                             uint32_t peer_id,
                                             uint32_t generation)
{
    x11_server_context* context = (x11_server_context*)opaque;

    (void)peer_id;
    (void)generation;
    if (!context)
        return;
    x11_server_clipboard_write_clear(context);
}

static void x11_server_clipboard_release_ownership(void* opaque,
                                                   uint64_t generation)
{
    x11_server_context* context = (x11_server_context*)opaque;

    if (!context || generation != context->clipboard_remote_generation)
        return;
    if (XGetSelectionOwner(context->display,
                           context->atom_clipboard) ==
        context->owner_window)
    {
        XSetSelectionOwner(context->display,
                           context->atom_clipboard,
                           None,
                           CurrentTime);
    }
    context->clipboard_remote_generation = 0u;
    context->remote_format_count = 0u;
    x11_server_clipboard_write_clear(context);
}

const server_platform_clipboard_vtable x11_server_clipboard_vtable = {
    SERVER_PLATFORM_CLIPBOARD_VERSION,
    sizeof(server_platform_clipboard_vtable),
    x11_server_clipboard_start,
    x11_server_clipboard_stop,
    x11_server_clipboard_publish_formats,
    x11_server_clipboard_request_data,
    x11_server_clipboard_request_file,
    x11_server_clipboard_write_data,
    x11_server_clipboard_cancel_peer,
    x11_server_clipboard_release_ownership,
    NULL,
};
