/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: validation and lookup for desktop-server platform providers.
 * Invariants: a configured binding has a complete, current-version vtable and
 * event sources are either absent or expose the complete poll contract.
 * Ownership: validation borrows all tables and contexts without retaining them.
 * Threading: callers serialize provider registration before starting the host.
 * Trust boundary: malformed application vtables are rejected before any
 * callback or native backend method can run.
 */

#include "server_platform.h"

#include <string.h>

typedef struct server_platform_table_header
{
    uint32_t version;
    size_t size;
} server_platform_table_header;

void server_platform_init(server_platform* platform)
{
    if (platform)
        memset(platform, 0, sizeof(*platform));
}

static int server_platform_header_valid(const void* table,
                                        uint32_t version,
                                        size_t minimum_size)
{
    const server_platform_table_header* header =
        (const server_platform_table_header*)table;

    return header && header->version == version && header->size >= minimum_size;
}

static int server_platform_events_valid(
    const server_platform_event_source_vtable* events)
{
    if (!events)
        return 1;
    return server_platform_header_valid(events,
                                        SERVER_PLATFORM_EVENT_SOURCE_VERSION,
                                        sizeof(*events)) &&
           events->get_pollfds && events->notify_poll && events->dispatch &&
           events->get_next_timeout;
}

static int server_platform_binding_shape_valid(
    const server_platform_binding* binding)
{
    return binding && ((binding->vtable != NULL) || (binding->context == NULL));
}

static int server_platform_capture_valid(const server_platform_binding* binding)
{
    const server_platform_capture_vtable* table = NULL;

    if (!server_platform_binding_shape_valid(binding))
        return 0;
    if (!binding->vtable)
        return 1;
    table = (const server_platform_capture_vtable*)binding->vtable;
    return server_platform_header_valid(table,
                                        SERVER_PLATFORM_CAPTURE_VERSION,
                                        sizeof(*table)) &&
           table->start && table->stop && table->request_frame &&
           server_platform_events_valid(table->events);
}

static int server_platform_pointer_valid(const server_platform_binding* binding)
{
    const server_platform_pointer_vtable* table = NULL;

    if (!server_platform_binding_shape_valid(binding))
        return 0;
    if (!binding->vtable)
        return 1;
    table = (const server_platform_pointer_vtable*)binding->vtable;
    return server_platform_header_valid(table,
                                        SERVER_PLATFORM_POINTER_VERSION,
                                        sizeof(*table)) &&
           table->start && table->stop && server_platform_events_valid(table->events);
}

static int server_platform_input_valid(const server_platform_binding* binding)
{
    const server_platform_input_vtable* table = NULL;

    if (!server_platform_binding_shape_valid(binding))
        return 0;
    if (!binding->vtable)
        return 1;
    table = (const server_platform_input_vtable*)binding->vtable;
    return server_platform_header_valid(table,
                                        SERVER_PLATFORM_INPUT_VERSION,
                                        sizeof(*table)) &&
           table->inject && table->release_all;
}

static int server_platform_clipboard_valid(
    const server_platform_binding* binding)
{
    const server_platform_clipboard_vtable* table = NULL;

    if (!server_platform_binding_shape_valid(binding))
        return 0;
    if (!binding->vtable)
        return 1;
    table = (const server_platform_clipboard_vtable*)binding->vtable;
    return server_platform_header_valid(table,
                                        SERVER_PLATFORM_CLIPBOARD_VERSION,
                                        sizeof(*table)) &&
           table->start && table->stop && table->publish_formats &&
           table->request_data && table->write_data && table->cancel_peer &&
           table->release_ownership &&
           server_platform_events_valid(table->events);
}

static int server_platform_drive_valid(const server_platform_binding* binding)
{
    const server_platform_drive_vtable* table = NULL;

    if (!server_platform_binding_shape_valid(binding))
        return 0;
    if (!binding->vtable)
        return 1;
    table = (const server_platform_drive_vtable*)binding->vtable;
    return server_platform_header_valid(table,
                                        SERVER_PLATFORM_DRIVE_VERSION,
                                        sizeof(*table)) &&
           table->start && table->stop && table->present && table->remove &&
           table->remove_peer && server_platform_events_valid(table->events);
}

static int server_platform_permission_valid(
    const server_platform_binding* binding)
{
    const server_platform_permission_vtable* table = NULL;

    if (!server_platform_binding_shape_valid(binding))
        return 0;
    if (!binding->vtable)
        return 1;
    table = (const server_platform_permission_vtable*)binding->vtable;
    return server_platform_header_valid(table,
                                        SERVER_PLATFORM_PERMISSION_VERSION,
                                        sizeof(*table)) &&
           table->start && table->stop && table->query && table->request &&
           table->revoke && server_platform_events_valid(table->events);
}

librdp_status server_platform_validate(const server_platform* platform)
{
    if (!platform)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!server_platform_capture_valid(&platform->capture) ||
        !server_platform_pointer_valid(&platform->pointer) ||
        !server_platform_input_valid(&platform->input) ||
        !server_platform_clipboard_valid(&platform->clipboard) ||
        !server_platform_drive_valid(&platform->drive) ||
        !server_platform_permission_valid(&platform->permission))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return LIBRDP_STATUS_OK;
}

static const server_platform_binding* server_platform_binding_at(
    const server_platform* platform,
    server_platform_provider_kind kind)
{
    if (!platform)
        return NULL;
    switch (kind)
    {
        case SERVER_PLATFORM_PROVIDER_CAPTURE:
            return &platform->capture;
        case SERVER_PLATFORM_PROVIDER_POINTER:
            return &platform->pointer;
        case SERVER_PLATFORM_PROVIDER_INPUT:
            return &platform->input;
        case SERVER_PLATFORM_PROVIDER_CLIPBOARD:
            return &platform->clipboard;
        case SERVER_PLATFORM_PROVIDER_DRIVE:
            return &platform->drive;
        case SERVER_PLATFORM_PROVIDER_PERMISSION:
            return &platform->permission;
        default:
            return NULL;
    }
}

int server_platform_provider_ready(const server_platform* platform,
                                   server_platform_provider_kind kind)
{
    const server_platform_binding* binding =
        server_platform_binding_at(platform, kind);

    if (!binding || !binding->vtable)
        return 0;
    return server_platform_validate(platform) == LIBRDP_STATUS_OK;
}

const server_platform_event_source_vtable* server_platform_provider_events(
    const server_platform* platform,
    server_platform_provider_kind kind,
    void** context)
{
    const server_platform_binding* binding =
        server_platform_binding_at(platform, kind);
    const server_platform_event_source_vtable* events = NULL;

    if (context)
        *context = NULL;
    if (!binding || !binding->vtable ||
        server_platform_validate(platform) != LIBRDP_STATUS_OK)
        return NULL;
    switch (kind)
    {
        case SERVER_PLATFORM_PROVIDER_CAPTURE:
            events = ((const server_platform_capture_vtable*)binding->vtable)->events;
            break;
        case SERVER_PLATFORM_PROVIDER_POINTER:
            events = ((const server_platform_pointer_vtable*)binding->vtable)->events;
            break;
        case SERVER_PLATFORM_PROVIDER_CLIPBOARD:
            events = ((const server_platform_clipboard_vtable*)binding->vtable)->events;
            break;
        case SERVER_PLATFORM_PROVIDER_DRIVE:
            events = ((const server_platform_drive_vtable*)binding->vtable)->events;
            break;
        case SERVER_PLATFORM_PROVIDER_PERMISSION:
            events = ((const server_platform_permission_vtable*)binding->vtable)->events;
            break;
        case SERVER_PLATFORM_PROVIDER_INPUT:
        case SERVER_PLATFORM_PROVIDER_COUNT:
        default:
            break;
    }
    if (events && context)
        *context = binding->context;
    return events;
}
