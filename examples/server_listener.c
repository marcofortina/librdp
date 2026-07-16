/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: minimal public server API exercise.
 * Invariants: the example never reaches into internal server state, accepts at
 * most one peer, and reports the public status returned by each dispatch step.
 * Ownership: the server owns copied bind settings and accepted peers are freed
 * before exit.
 * Threading: single-threaded listener loop.
 * Trust boundary: remote client bytes are processed only by librdp_server APIs.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <librdp/librdp.h>

typedef struct server_listener_options
{
    const char* bind_address;
    uint16_t port;
    uint32_t width;
    uint32_t height;
    int timeout_ms;
} server_listener_options;

typedef struct server_listener_peer_context
{
    uint64_t input_events;
    uint64_t channel_events;
    uint64_t runtime_events;
    uint64_t error_events;
    int surface_presented;
} server_listener_peer_context;

static void server_listener_usage(FILE* stream, const char* program)
{
    fprintf(stream,
            "usage: %s [--bind address] [--port port] [--width px] [--height px] [--timeout ms]\n",
            program);
}

static int server_listener_need_value(int argc, char** argv, int* index)
{
    if (*index + 1 < argc)
    {
        *index += 1;
        return 1;
    }
    fprintf(stderr, "%s requires a value\n", argv[*index]);
    return 0;
}

static int server_listener_parse_u16(const char* value, uint16_t* out)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!value || !out)
        return 0;
    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed > UINT16_MAX)
        return 0;
    *out = (uint16_t)parsed;
    return 1;
}

static int server_listener_parse_timeout(const char* value, int* out)
{
    char* end = NULL;
    long parsed = 0;

    if (!value || !out)
        return 0;
    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed < 0 || parsed > 60000)
        return 0;
    *out = (int)parsed;
    return 1;
}

static int server_listener_parse_size(const char* value, uint32_t* out)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!value || !out)
        return 0;
    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed == 0 || parsed > 8192ul)
        return 0;
    *out = (uint32_t)parsed;
    return 1;
}

static int server_listener_parse_args(int argc, char** argv, server_listener_options* options)
{
    int i = 0;

    if (!options)
        return 0;
    memset(options, 0, sizeof(*options));
    options->bind_address = "127.0.0.1";
    options->width = 1024;
    options->height = 768;
    options->timeout_ms = 10000;
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            server_listener_usage(stdout, argv[0]);
            exit(0);
        }
        if (strcmp(argv[i], "--bind") == 0)
        {
            if (!server_listener_need_value(argc, argv, &i))
                return 0;
            options->bind_address = argv[i];
        }
        else if (strcmp(argv[i], "--port") == 0)
        {
            if (!server_listener_need_value(argc, argv, &i) ||
                !server_listener_parse_u16(argv[i], &options->port))
                return 0;
        }
        else if (strcmp(argv[i], "--width") == 0)
        {
            if (!server_listener_need_value(argc, argv, &i) ||
                !server_listener_parse_size(argv[i], &options->width))
                return 0;
        }
        else if (strcmp(argv[i], "--height") == 0)
        {
            if (!server_listener_need_value(argc, argv, &i) ||
                !server_listener_parse_size(argv[i], &options->height))
                return 0;
        }
        else if (strcmp(argv[i], "--timeout") == 0)
        {
            if (!server_listener_need_value(argc, argv, &i) ||
                !server_listener_parse_timeout(argv[i], &options->timeout_ms))
                return 0;
        }
        else
        {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            return 0;
        }
    }
    return 1;
}

static void server_listener_input_callback(librdp_server_peer* peer,
                                           const librdp_server_input_event* event,
                                           void* user_data)
{
    server_listener_peer_context* context = (server_listener_peer_context*)user_data;

    (void)peer;
    if (!context || !event)
        return;
    context->input_events++;
    printf("input type=%d flags=%u x=%u y=%u\n",
           (int)event->type,
           event->flags,
           event->x,
           event->y);
}

static void server_listener_channel_callback(librdp_server_peer* peer,
                                             const librdp_server_channel_event* event,
                                             void* user_data)
{
    server_listener_peer_context* context = (server_listener_peer_context*)user_data;

    (void)peer;
    if (!context || !event)
        return;
    context->channel_events++;
    printf("channel name=%s id=%u bytes=%u\n",
           event->name ? event->name : "",
           event->channel_id,
           (unsigned)event->data_len);
}

static void server_listener_event_callback(librdp_server_peer* peer,
                                           const librdp_server_event* event,
                                           void* user_data)
{
    server_listener_peer_context* context = (server_listener_peer_context*)user_data;

    (void)peer;
    if (!context || !event)
        return;
    context->runtime_events++;
    if (event->type == LIBRDP_SERVER_EVENT_STATE_CHANGED)
        printf("event state old=%d new=%d\n", (int)event->old_state, (int)event->new_state);
    else if (event->type == LIBRDP_SERVER_EVENT_ERROR)
    {
        context->error_events++;
        printf("event error status=%s phase=%s\n",
               librdp_status_name(event->status),
               event->phase ? event->phase : "");
    }
    else if (event->type == LIBRDP_SERVER_EVENT_SURFACE)
        printf("event surface x=%u y=%u width=%u height=%u\n",
               event->x,
               event->y,
               event->width,
               event->height);
    else if (event->type == LIBRDP_SERVER_EVENT_CHANNEL_JOINED)
        printf("event channel_joined id=%u\n", event->channel_id);
}

static int server_listener_build_desktop(uint8_t* pixels, uint32_t width, uint32_t height)
{
    if (!pixels || width == 0 || height == 0)
        return 0;
    for (uint32_t y = 0; y < height; y++)
    {
        for (uint32_t x = 0; x < width; x++)
        {
            uint8_t* pixel = pixels + (((size_t)y * width + x) * 4u);
            const uint8_t checker = ((x / 32u) ^ (y / 32u)) & 1u ? 0x30u : 0x70u;

            pixel[0] = (uint8_t)((x * 255u) / width);
            pixel[1] = (uint8_t)((y * 255u) / height);
            pixel[2] = checker;
            pixel[3] = 0xffu;
        }
    }
    return 1;
}

static librdp_status server_listener_present_desktop(librdp_server_peer* peer,
                                                     uint32_t width,
                                                     uint32_t height)
{
    uint8_t* pixels = NULL;
    size_t stride = 0;
    size_t total = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || width == 0 || height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    stride = (size_t)width * 4u;
    if (height > SIZE_MAX / stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    total = stride * height;
    pixels = (uint8_t*)malloc(total);
    if (!pixels)
        return LIBRDP_STATUS_NO_MEMORY;
    if (!server_listener_build_desktop(pixels, width, height))
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
    if (status == LIBRDP_STATUS_OK)
        status = librdp_server_peer_surface_blit_bgra32(peer, 0, 0, width, height, stride, pixels);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_server_peer_surface_present(peer, 0, 0, width, height);
    free(pixels);
    return status;
}

static void server_listener_print_channels(librdp_server_peer* peer)
{
    uint32_t count = librdp_server_peer_static_channel_count(peer);

    for (uint32_t i = 0; i < count; i++)
    {
        librdp_server_static_channel_info info;

        if (librdp_server_static_channel_info_init(&info) == LIBRDP_STATUS_OK &&
            librdp_server_peer_static_channel_at(peer, i, &info) == LIBRDP_STATUS_OK)
        {
            printf("static_channel index=%u name=%s id=%u joined=%d flags=%u\n",
                   i,
                   info.name,
                   info.channel_id,
                   info.joined,
                   info.flags);
        }
    }
}

static int server_listener_run_peer(librdp_server_peer* peer,
                                    const server_listener_options* options,
                                    server_listener_peer_context* context)
{
    librdp_status status = LIBRDP_STATUS_OK;

    while (librdp_server_peer_get_state(peer) != LIBRDP_SERVER_PEER_CLOSED &&
           librdp_server_peer_get_state(peer) != LIBRDP_SERVER_PEER_FAILED)
    {
        status = librdp_server_peer_run_once(peer, options ? options->timeout_ms : 10000);
        printf("peer status=%s state=%d\n",
               librdp_status_name(status),
               (int)librdp_server_peer_get_state(peer));
        if (librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_ACTIVE &&
            context && !context->surface_presented)
        {
            uint32_t width = librdp_server_peer_desktop_width(peer);
            uint32_t height = librdp_server_peer_desktop_height(peer);
            if (width == 0)
                width = options ? options->width : 1024u;
            if (height == 0)
                height = options ? options->height : 768u;
            server_listener_print_channels(peer);
            status = server_listener_present_desktop(peer, width, height);
            context->surface_presented = status == LIBRDP_STATUS_OK ? 1 : 0;
            printf("surface_present status=%s\n", librdp_status_name(status));
            if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_STATE)
                return 2;
        }
        if (status == LIBRDP_STATUS_TIMEOUT && context && context->surface_presented)
            return 0;
        if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_TIMEOUT)
        {
            librdp_server_status last_status;

            if (librdp_server_status_init(&last_status) == LIBRDP_STATUS_OK &&
                librdp_server_peer_get_last_status(peer, &last_status) == LIBRDP_STATUS_OK)
                fprintf(stderr,
                        "last_status status=%s phase=%s message=%s\n",
                        librdp_status_name(last_status.status),
                        last_status.phase,
                        last_status.message);
            return status == LIBRDP_STATUS_UNSUPPORTED ? 3 : 2;
        }
    }
    return librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CLOSED ? 0 : 2;
}

int main(int argc, char** argv)
{
    server_listener_options options;
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    server_listener_peer_context peer_context;
    librdp_status status = LIBRDP_STATUS_OK;
    int rc = 0;

    memset(&peer_context, 0, sizeof(peer_context));
    if (!server_listener_parse_args(argc, argv, &options))
    {
        server_listener_usage(stderr, argv[0]);
        return 2;
    }
    if (librdp_server_config_init(&config) != LIBRDP_STATUS_OK)
        return 2;
    config.bind_address = options.bind_address;
    config.port = options.port;
    config.width = options.width;
    config.height = options.height;
    server = librdp_server_new(&config);
    if (!server)
        return 2;
    status = librdp_server_listen(server);
    if (status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr, "listen failed: %s\n", librdp_status_name(status));
        librdp_server_free(server);
        return 2;
    }
    printf("listening address=%s port=%u\n",
           options.bind_address,
           (unsigned)librdp_server_local_port(server));
    fflush(stdout);
    status = librdp_server_accept(server, options.timeout_ms, &peer);
    if (status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr, "accept failed: %s\n", librdp_status_name(status));
        librdp_server_free(server);
        return status == LIBRDP_STATUS_TIMEOUT ? 3 : 2;
    }
    (void)librdp_server_peer_set_input_callback(peer, server_listener_input_callback, &peer_context);
    (void)librdp_server_peer_set_channel_callback(peer, server_listener_channel_callback, &peer_context);
    (void)librdp_server_peer_set_event_callback(peer, server_listener_event_callback, &peer_context);
    rc = server_listener_run_peer(peer, &options, &peer_context);
    printf("summary inputs=%llu channels=%llu runtime_events=%llu errors=%llu surface=%d\n",
           (unsigned long long)peer_context.input_events,
           (unsigned long long)peer_context.channel_events,
           (unsigned long long)peer_context.runtime_events,
           (unsigned long long)peer_context.error_events,
           peer_context.surface_presented);
    (void)librdp_server_peer_close(peer);
    librdp_server_peer_free(peer);
    librdp_server_free(server);
    return rc;
}
