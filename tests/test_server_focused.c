/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: focused server peer lifecycle, channel, and graphics tests.
 * Coverage: accepted-peer ownership, pre-activation state gates, surface
 * storage, provider state, and idempotent shutdown.
 * Bug classes: invalid state, stale channel state, framebuffer bounds, and
 * resource cleanup.
 * Determinism: every peer uses an ephemeral loopback listener.
 */

#include "test_server_support.h"
#include "test_server_suites.h"
#include "channels/filesystem_redirection.h"
#include "channels/virtual_channel.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"
#include "server/server_channels.h"

#include <string.h>
#include <unistd.h>

typedef struct test_server_peer_fixture
{
    librdp_server* server;
    librdp_server_peer* peer;
    int client_fd;
} test_server_peer_fixture;

typedef struct test_server_clipboard_context
{
    uint32_t counts[LIBRDP_SERVER_CLIPBOARD_CANCELLED + 1u];
    uint32_t format_id;
    uint32_t stream_id;
    uint32_t clip_data_id;
    uint32_t general_flags;
    uint8_t format_name[32];
    size_t format_name_len;
    uint8_t data[32];
    size_t data_len;
    int valid;
} test_server_clipboard_context;

typedef struct test_server_drive_context
{
    uint32_t counts[LIBRDP_SERVER_DRIVE_REQUEST_CANCELLED + 1u];
    librdp_server_drive_device_handle device;
    librdp_server_drive_file_handle file;
    librdp_server_drive_request_id request_id;
    librdp_server_drive_operation operation;
    uint32_t io_status;
    uint64_t transferred;
    char preferred_name[9];
    char name[32];
    uint8_t data[32];
    size_t data_len;
    int valid;
} test_server_drive_context;

static void test_server_write_u32(uint8_t* data, uint32_t value)
{
    data[0] = (uint8_t)(value & 0xffu);
    data[1] = (uint8_t)((value >> 8u) & 0xffu);
    data[2] = (uint8_t)((value >> 16u) & 0xffu);
    data[3] = (uint8_t)((value >> 24u) & 0xffu);
}

static void test_server_write_u64(uint8_t* data, uint64_t value)
{
    test_server_write_u32(data, (uint32_t)(value & UINT32_MAX));
    test_server_write_u32(data + 4u, (uint32_t)(value >> 32u));
}

static void test_server_clipboard_callback(
    librdp_server_peer* peer,
    const librdp_server_clipboard_event* event,
    void* user_data)
{
    test_server_clipboard_context* context =
        (test_server_clipboard_context*)user_data;

    if (!peer || !event || !context ||
        event->version != LIBRDP_SERVER_CLIPBOARD_EVENT_VERSION ||
        event->size < sizeof(*event) ||
        event->type < LIBRDP_SERVER_CLIPBOARD_MONITOR_READY ||
        event->type > LIBRDP_SERVER_CLIPBOARD_CANCELLED)
    {
        if (context)
            context->valid = 0;
        return;
    }
    context->counts[event->type]++;
    if (event->format_id != 0u)
        context->format_id = event->format_id;
    if (event->stream_id != 0u)
        context->stream_id = event->stream_id;
    if (event->has_clip_data_id)
        context->clip_data_id = event->clip_data_id;
    if (event->type == LIBRDP_SERVER_CLIPBOARD_CAPABILITIES)
        context->general_flags = event->general_flags;
    if (event->format_count > 0u && event->formats &&
        event->formats[0].name_len <= sizeof(context->format_name))
    {
        context->format_name_len = event->formats[0].name_len;
        memcpy(context->format_name,
               event->formats[0].name,
               context->format_name_len);
    }
    if (event->data_len > 0u && event->data &&
        event->data_len <= sizeof(context->data))
    {
        context->data_len = event->data_len;
        memcpy(context->data, event->data, event->data_len);
    }
    else if (event->data_len > 0u)
        context->valid = 0;
}

static void test_server_drive_callback(
    librdp_server_peer* peer,
    const librdp_server_drive_event* event,
    void* user_data)
{
    test_server_drive_context* context =
        (test_server_drive_context*)user_data;

    if (!peer || !event || !context ||
        event->version != LIBRDP_SERVER_DRIVE_EVENT_VERSION ||
        event->size < sizeof(*event) ||
        event->type < LIBRDP_SERVER_DRIVE_DEVICE_ADDED ||
        event->type > LIBRDP_SERVER_DRIVE_REQUEST_CANCELLED)
    {
        if (context)
            context->valid = 0;
        return;
    }
    context->counts[event->type]++;
    context->device = event->device;
    context->file = event->file;
    context->request_id = event->request_id;
    context->operation = event->operation;
    context->io_status = event->io_status;
    context->transferred = event->transferred;
    memcpy(context->preferred_name,
           event->preferred_name,
           sizeof(context->preferred_name));
    if (event->name)
    {
        size_t name_len = strlen(event->name);

        if (name_len >= sizeof(context->name))
        {
            context->valid = 0;
            return;
        }
        memcpy(context->name, event->name, name_len + 1u);
    }
    if (event->data_len > sizeof(context->data) ||
        (!event->data && event->data_len > 0u))
    {
        context->valid = 0;
        return;
    }
    context->data_len = event->data_len;
    if (event->data_len > 0u)
        memcpy(context->data, event->data, event->data_len);
}

static int test_server_complete_drive_request(
    librdp_server_peer* peer,
    rdp_buffer* packet,
    uint16_t channel_id,
    uint32_t device_id,
    librdp_server_drive_request_id request_id,
    librdp_server_drive_operation operation)
{
    static const uint8_t response_data[] = {0x31u, 0x32u};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !packet || request_id == 0u)
        return 0;
    packet->length = 0u;
    switch (operation)
    {
        case LIBRDP_SERVER_DRIVE_CLOSE:
            status = rdp_filesystem_redirection_write_close_response(
                packet,
                device_id,
                (uint32_t)request_id,
                RDP_DEVICE_REDIRECTION_STATUS_SUCCESS);
            break;
        case LIBRDP_SERVER_DRIVE_WRITE:
        case LIBRDP_SERVER_DRIVE_SET_INFORMATION:
        case LIBRDP_SERVER_DRIVE_SET_VOLUME:
        case LIBRDP_SERVER_DRIVE_SET_SECURITY:
            status = rdp_filesystem_redirection_write_length_response(
                packet,
                device_id,
                (uint32_t)request_id,
                RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                (uint32_t)sizeof(response_data));
            break;
        case LIBRDP_SERVER_DRIVE_LOCK:
            status = rdp_filesystem_redirection_write_lock_response(
                packet,
                device_id,
                (uint32_t)request_id,
                RDP_DEVICE_REDIRECTION_STATUS_SUCCESS);
            break;
        case LIBRDP_SERVER_DRIVE_FLUSH:
        case LIBRDP_SERVER_DRIVE_CLEANUP:
        case LIBRDP_SERVER_DRIVE_SHUTDOWN:
            status = rdp_device_redirection_write_io_completion(
                packet,
                device_id,
                (uint32_t)request_id,
                RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                NULL,
                0u);
            break;
        default:
            status = rdp_filesystem_redirection_write_buffer_response(
                packet,
                device_id,
                (uint32_t)request_id,
                RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                response_data,
                (uint32_t)sizeof(response_data));
            break;
    }
    if (status != LIBRDP_STATUS_OK)
        return 0;
    return rdp_server_emit_extension_event(peer,
                                           "rdpdr",
                                           5u,
                                           channel_id,
                                           0u,
                                           0u,
                                           packet->data,
                                           packet->length) ==
           LIBRDP_STATUS_OK;
}

static int test_server_peer_fixture_open(test_server_peer_fixture* fixture)
{
    librdp_server_config config;
    uint16_t port = 0;

    if (!fixture)
        return 0;
    memset(fixture, 0, sizeof(*fixture));
    fixture->client_fd = -1;
    if (librdp_server_config_init(&config) != LIBRDP_STATUS_OK)
        return 0;
    config.bind_address = "127.0.0.1";
    fixture->server = librdp_server_new(&config);
    if (!fixture->server || librdp_server_listen(fixture->server) != LIBRDP_STATUS_OK)
        return 0;
    port = librdp_server_local_port(fixture->server);
    fixture->client_fd = test_server_connect_loopback(port);
    if (fixture->client_fd < 0 ||
        librdp_server_accept(fixture->server, 1000, &fixture->peer) != LIBRDP_STATUS_OK)
        return 0;
    return 1;
}

static void test_server_peer_fixture_close(test_server_peer_fixture* fixture)
{
    if (!fixture)
        return;
    librdp_server_peer_free(fixture->peer);
    if (fixture->client_fd >= 0)
        close(fixture->client_fd);
    librdp_server_close(fixture->server);
    librdp_server_free(fixture->server);
    memset(fixture, 0, sizeof(*fixture));
    fixture->client_fd = -1;
}

static int test_server_wrap_mcs_packet(
    const rdp_buffer* mcs,
    rdp_buffer* packet)
{
    rdp_buffer x224;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!mcs || !packet)
        return 0;
    rdp_buffer_init(&x224);
    status = rdp_x224_wrap_data(
        &x224,
        mcs->data,
        mcs->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_tpkt_write(packet, x224.data, x224.length);
    rdp_buffer_free(&x224);
    return status == LIBRDP_STATUS_OK;
}

static int test_server_wrap_slowpath_packet(
    const rdp_buffer* slowpath,
    uint16_t user_id,
    rdp_buffer* packet)
{
    rdp_buffer mcs;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!slowpath || !packet)
        return 0;
    rdp_buffer_init(&mcs);
    status = rdp_security_write_send_data_request(
        &mcs,
        user_id,
        (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
        slowpath->data,
        slowpath->length);
    if (status == LIBRDP_STATUS_OK &&
        !test_server_wrap_mcs_packet(&mcs, packet))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_buffer_free(&mcs);
    return status == LIBRDP_STATUS_OK;
}

/*
 * Send one complete packet while the controlled peer is pinned to a selected
 * handshake phase. Rejection must retain the phase that owned the packet
 * rather than collapsing every parser failure into a generic dispatch error.
 */
static int test_server_expect_packet_rejection(
    librdp_server_peer_state state,
    const rdp_buffer* packet,
    const char* phase)
{
    test_server_peer_fixture fixture;
    librdp_server_status server_status;
    librdp_status status = LIBRDP_STATUS_OK;
    int valid = 0;

    if (!packet || !phase ||
        !test_server_peer_fixture_open(&fixture))
        return 0;
    fixture.peer->state = state;
    fixture.peer->selected_protocol = RDP_X224_PROTOCOL_TLS;
    if (!test_server_send_all(
            fixture.client_fd,
            packet->data,
            packet->length))
        goto complete;
    status = librdp_server_peer_run_once(fixture.peer, 1000);
    if (librdp_server_status_init(&server_status) !=
            LIBRDP_STATUS_OK ||
        librdp_server_peer_get_last_status(
            fixture.peer,
            &server_status) != LIBRDP_STATUS_OK)
        goto complete;
    valid = status == LIBRDP_STATUS_PROTOCOL_ERROR &&
            server_status.status ==
                LIBRDP_STATUS_PROTOCOL_ERROR &&
            server_status.component ==
                LIBRDP_ERROR_COMPONENT_PROTOCOL &&
            strcmp(server_status.phase, phase) == 0 &&
            librdp_server_peer_get_state(fixture.peer) ==
                LIBRDP_SERVER_PEER_FAILED;

complete:
    test_server_peer_fixture_close(&fixture);
    return valid;
}

int test_server_lifecycle_focused(void)
{
    test_server_peer_fixture fixture;
    struct pollfd pollfd;
    size_t count = 0;

    SCHECK(test_server_peer_fixture_open(&fixture));
    SCHECK(librdp_server_peer_get_state(fixture.peer) == LIBRDP_SERVER_PEER_NEW);
    SCHECK(librdp_server_peer_get_pollfds(fixture.peer, NULL, 0, &count) == LIBRDP_STATUS_OK);
    SCHECK(count == 1);
    SCHECK(librdp_server_peer_get_pollfds(fixture.peer, &pollfd, 1, &count) == LIBRDP_STATUS_OK);
    SCHECK(count == 1);
    SCHECK(pollfd.fd >= 0);
    SCHECK(librdp_server_peer_close(fixture.peer) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(fixture.peer) == LIBRDP_SERVER_PEER_CLOSED);
    SCHECK(librdp_server_peer_close(fixture.peer) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_pollfds(fixture.peer, NULL, 0, &count) == LIBRDP_STATUS_STATE);
    test_server_peer_fixture_close(&fixture);
    return 0;
}

/*
 * Exercise the server handshake state gates with complete, valid packets from
 * adjacent phases. This catches accidental parser fall-through and activation
 * before licensing or capability validation has completed.
 */
int test_server_protocol_order_focused(void)
{
    rdp_buffer packet;
    rdp_buffer mcs;
    rdp_buffer slowpath;
    static const uint8_t invalid_gcc[] = {0x00u, 0x01u, 0x02u, 0x03u};

    rdp_buffer_init(&packet);
    rdp_buffer_init(&mcs);
    rdp_buffer_init(&slowpath);

    SCHECK(rdp_mcs_write_erect_domain_request(&mcs) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_wrap_mcs_packet(&mcs, &packet));
    SCHECK(test_server_expect_packet_rejection(
        LIBRDP_SERVER_PEER_NEW,
        &packet,
        "server.x224.negotiation"));
    SCHECK(test_server_expect_packet_rejection(
        LIBRDP_SERVER_PEER_X224_CONFIRMED,
        &packet,
        "server.mcs-gcc.connect"));

    packet.length = 0u;
    mcs.length = 0u;
    SCHECK(rdp_mcs_write_connect_initial(
               &mcs,
               invalid_gcc,
               sizeof(invalid_gcc)) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_wrap_mcs_packet(&mcs, &packet));
    SCHECK(test_server_expect_packet_rejection(
        LIBRDP_SERVER_PEER_X224_CONFIRMED,
        &packet,
        "server.mcs-gcc.connect"));

    packet.length = 0u;
    mcs.length = 0u;
    SCHECK(rdp_mcs_write_attach_user_request(&mcs) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_wrap_mcs_packet(&mcs, &packet));
    SCHECK(test_server_expect_packet_rejection(
        LIBRDP_SERVER_PEER_MCS_CONNECTED,
        &packet,
        "server.mcs.erect-domain"));
    SCHECK(test_server_expect_packet_rejection(
        LIBRDP_SERVER_PEER_USER_ATTACHED,
        &packet,
        "server.mcs.channel-join"));

    packet.length = 0u;
    mcs.length = 0u;
    SCHECK(rdp_mcs_write_erect_domain_request(&mcs) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_wrap_mcs_packet(&mcs, &packet));
    SCHECK(test_server_expect_packet_rejection(
        LIBRDP_SERVER_PEER_DOMAIN_READY,
        &packet,
        "server.mcs.attach-user"));

    packet.length = 0u;
    slowpath.length = 0u;
    SCHECK(rdp_slowpath_write_confirm_active(
               &slowpath,
               0x00010001u,
               (uint16_t)RDP_MCS_BASE_CHANNEL_ID,
               800u,
               600u,
               "order-test") == LIBRDP_STATUS_OK);
    SCHECK(test_server_wrap_slowpath_packet(
        &slowpath,
        (uint16_t)RDP_MCS_BASE_CHANNEL_ID,
        &packet));
    SCHECK(test_server_expect_packet_rejection(
        LIBRDP_SERVER_PEER_LICENSING,
        &packet,
        "server.licensing.client-info"));

    packet.length = 0u;
    slowpath.length = 0u;
    SCHECK(rdp_slowpath_write_client_font_list(
               &slowpath,
               0x00010001u,
               (uint16_t)RDP_MCS_BASE_CHANNEL_ID) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_wrap_slowpath_packet(
        &slowpath,
        (uint16_t)RDP_MCS_BASE_CHANNEL_ID,
        &packet));
    SCHECK(test_server_expect_packet_rejection(
        LIBRDP_SERVER_PEER_ACTIVATING,
        &packet,
        "server.activation"));

    rdp_buffer_free(&slowpath);
    rdp_buffer_free(&mcs);
    rdp_buffer_free(&packet);
    return 0;
}

/*
 * Negotiate one client desktop geometry through the full MCS/GCC server phase.
 * Rejected dimensions must leave the peer geometry unchanged and retain the
 * MCS/GCC phase in the public server status.
 */
static int test_server_negotiate_desktop_dimensions(
    uint16_t width,
    uint16_t height,
    librdp_status expected_status)
{
    test_server_peer_fixture fixture;
    librdp_server_status server_status;
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;
    int valid = 0;

    rdp_buffer_init(&packet);
    if (test_server_build_client_mcs_connect_initial_sized(
            &packet,
            width,
            height) &&
        test_server_peer_fixture_open(&fixture))
    {
        fixture.peer->state = LIBRDP_SERVER_PEER_X224_CONFIRMED;
        if (test_server_send_all(
                fixture.client_fd,
                packet.data,
                packet.length))
        {
            status = librdp_server_peer_run_once(fixture.peer, 1000);
            if (expected_status == LIBRDP_STATUS_OK)
            {
                valid = status == LIBRDP_STATUS_OK &&
                        librdp_server_peer_get_state(fixture.peer) ==
                            LIBRDP_SERVER_PEER_MCS_CONNECTED &&
                        librdp_server_peer_desktop_width(fixture.peer) ==
                            width &&
                        librdp_server_peer_desktop_height(fixture.peer) ==
                            height;
            }
            else if (librdp_server_status_init(&server_status) ==
                         LIBRDP_STATUS_OK &&
                     librdp_server_peer_get_last_status(
                         fixture.peer,
                         &server_status) == LIBRDP_STATUS_OK)
            {
                valid = status == expected_status &&
                        server_status.status == expected_status &&
                        strcmp(
                            server_status.phase,
                            "server.mcs-gcc.connect") == 0 &&
                        librdp_server_peer_get_state(fixture.peer) ==
                            LIBRDP_SERVER_PEER_FAILED &&
                        librdp_server_peer_desktop_width(fixture.peer) ==
                            1024u &&
                        librdp_server_peer_desktop_height(fixture.peer) ==
                            768u;
            }
        }
        test_server_peer_fixture_close(&fixture);
    }
    rdp_buffer_free(&packet);
    return valid;
}

int test_server_desktop_limits_focused(void)
{
    SCHECK(test_server_negotiate_desktop_dimensions(
        LIBRDP_DESKTOP_MIN_DIMENSION,
        LIBRDP_DESKTOP_MIN_DIMENSION,
        LIBRDP_STATUS_OK));
    SCHECK(test_server_negotiate_desktop_dimensions(
        LIBRDP_DESKTOP_MAX_DIMENSION,
        LIBRDP_DESKTOP_MAX_DIMENSION,
        LIBRDP_STATUS_OK));
    SCHECK(test_server_negotiate_desktop_dimensions(
        LIBRDP_DESKTOP_MIN_DIMENSION - 1u,
        LIBRDP_DESKTOP_MIN_DIMENSION,
        LIBRDP_STATUS_PROTOCOL_ERROR));
    SCHECK(test_server_negotiate_desktop_dimensions(
        LIBRDP_DESKTOP_MIN_DIMENSION,
        LIBRDP_DESKTOP_MIN_DIMENSION - 1u,
        LIBRDP_STATUS_PROTOCOL_ERROR));
    SCHECK(test_server_negotiate_desktop_dimensions(
        LIBRDP_DESKTOP_MAX_DIMENSION + 1u,
        LIBRDP_DESKTOP_MAX_DIMENSION,
        LIBRDP_STATUS_LIMIT_EXCEEDED));
    SCHECK(test_server_negotiate_desktop_dimensions(
        LIBRDP_DESKTOP_MAX_DIMENSION,
        LIBRDP_DESKTOP_MAX_DIMENSION + 1u,
        LIBRDP_STATUS_LIMIT_EXCEEDED));
    return 0;
}

/*
 * Exercises the public drive metadata boundary with complete synthetic
 * information records, malformed lengths, unsupported classes, status
 * normalization, UTF-16 conversion, and size-query behavior.
 */
int test_server_drive_metadata_focused(void)
{
    uint8_t file_info[104];
    uint8_t directory_info[72];
    librdp_server_drive_metadata metadata;
    librdp_server_drive_metadata before;
    char name[16];
    size_t name_length = 0u;
    size_t next_offset = 0u;

    memset(file_info, 0, sizeof(file_info));
    memset(directory_info, 0, sizeof(directory_info));
    SCHECK(librdp_server_drive_metadata_init(NULL) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_drive_metadata_init(&metadata) ==
           LIBRDP_STATUS_OK);
    SCHECK(metadata.version == LIBRDP_SERVER_DRIVE_METADATA_VERSION);
    SCHECK(metadata.size == sizeof(metadata));
    SCHECK(metadata.link_count == 1u);
    SCHECK(librdp_server_drive_classify_io_status(0u) ==
           LIBRDP_SERVER_DRIVE_IO_SUCCESS);
    SCHECK(librdp_server_drive_classify_io_status(0xc000000fu) ==
           LIBRDP_SERVER_DRIVE_IO_NOT_FOUND);
    SCHECK(librdp_server_drive_classify_io_status(0xc0000022u) ==
           LIBRDP_SERVER_DRIVE_IO_ACCESS_DENIED);
    SCHECK(librdp_server_drive_classify_io_status(0xc0000035u) ==
           LIBRDP_SERVER_DRIVE_IO_ALREADY_EXISTS);
    SCHECK(librdp_server_drive_classify_io_status(0xc0000103u) ==
           LIBRDP_SERVER_DRIVE_IO_NOT_DIRECTORY);
    SCHECK(librdp_server_drive_classify_io_status(0x80000006u) ==
           LIBRDP_SERVER_DRIVE_IO_NO_MORE_FILES);
    SCHECK(librdp_server_drive_classify_io_status(0xc000000du) ==
           LIBRDP_SERVER_DRIVE_IO_INVALID);
    SCHECK(librdp_server_drive_classify_io_status(0xc00000bbu) ==
           LIBRDP_SERVER_DRIVE_IO_UNSUPPORTED);
    SCHECK(librdp_server_drive_classify_io_status(0xc0000023u) ==
           LIBRDP_SERVER_DRIVE_IO_RESOURCE_LIMIT);
    SCHECK(librdp_server_drive_classify_io_status(0xdeadbeefu) ==
           LIBRDP_SERVER_DRIVE_IO_ERROR);

    test_server_write_u64(file_info, 11u);
    test_server_write_u64(file_info + 8u, 12u);
    test_server_write_u64(file_info + 16u, 13u);
    test_server_write_u64(file_info + 24u, 14u);
    test_server_write_u32(
        file_info + 32u,
        LIBRDP_SERVER_DRIVE_FILE_ATTRIBUTE_ARCHIVE);
    test_server_write_u64(file_info + 40u, 4096u);
    test_server_write_u64(file_info + 48u, 1234u);
    test_server_write_u32(file_info + 56u, 2u);
    file_info[60u] = 1u;
    test_server_write_u64(file_info + 64u, 99u);
    test_server_write_u32(file_info + 96u, 4u);
    file_info[100u] = 'x';
    file_info[102u] = 'y';
    SCHECK(librdp_server_drive_decode_file_metadata(
               LIBRDP_SERVER_DRIVE_FILE_ALL_INFORMATION,
               file_info,
               sizeof(file_info),
               &metadata) == LIBRDP_STATUS_OK);
    SCHECK(metadata.creation_time == 11u);
    SCHECK(metadata.access_time == 12u);
    SCHECK(metadata.write_time == 13u);
    SCHECK(metadata.change_time == 14u);
    SCHECK(metadata.allocation_size == 4096u);
    SCHECK(metadata.file_size == 1234u);
    SCHECK(metadata.link_count == 2u);
    SCHECK(metadata.delete_pending == 1u);
    SCHECK(metadata.directory == 0u);
    SCHECK(metadata.file_id == 99u);
    before = metadata;
    file_info[96u]--;
    SCHECK(librdp_server_drive_decode_file_metadata(
               LIBRDP_SERVER_DRIVE_FILE_ALL_INFORMATION,
               file_info,
               sizeof(file_info),
               &metadata) == LIBRDP_STATUS_PROTOCOL_ERROR);
    SCHECK(memcmp(&metadata, &before, sizeof(metadata)) == 0);
    file_info[96u]++;
    SCHECK(librdp_server_drive_decode_file_metadata(
               LIBRDP_SERVER_DRIVE_FILE_DIRECTORY_INFORMATION,
               file_info,
               sizeof(file_info),
               &metadata) == LIBRDP_STATUS_INVALID_ARGUMENT);
    metadata.version++;
    SCHECK(librdp_server_drive_decode_file_metadata(
               LIBRDP_SERVER_DRIVE_FILE_ALL_INFORMATION,
               file_info,
               sizeof(file_info),
               &metadata) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_drive_metadata_init(&metadata) ==
           LIBRDP_STATUS_OK);

    test_server_write_u64(directory_info + 8u, 21u);
    test_server_write_u64(directory_info + 16u, 22u);
    test_server_write_u64(directory_info + 24u, 23u);
    test_server_write_u64(directory_info + 32u, 24u);
    test_server_write_u64(directory_info + 40u, 55u);
    test_server_write_u64(directory_info + 48u, 4096u);
    test_server_write_u32(
        directory_info + 56u,
        LIBRDP_SERVER_DRIVE_FILE_ATTRIBUTE_DIRECTORY);
    test_server_write_u32(directory_info + 60u, 8u);
    directory_info[64u] = 'n';
    directory_info[66u] = 'o';
    directory_info[68u] = 'd';
    directory_info[70u] = 'e';
    SCHECK(librdp_server_drive_decode_directory_entry(
               LIBRDP_SERVER_DRIVE_FILE_DIRECTORY_INFORMATION,
               directory_info,
               sizeof(directory_info),
               0u,
               &metadata,
               NULL,
               0u,
               &name_length,
               &next_offset) == LIBRDP_STATUS_OK);
    SCHECK(name_length == 5u);
    SCHECK(next_offset == 0u);
    SCHECK(metadata.directory == 1u);
    SCHECK(metadata.file_size == 55u);
    SCHECK(librdp_server_drive_decode_directory_entry(
               LIBRDP_SERVER_DRIVE_FILE_DIRECTORY_INFORMATION,
               directory_info,
               sizeof(directory_info),
               0u,
               &metadata,
               name,
               4u,
               &name_length,
               &next_offset) == LIBRDP_STATUS_LIMIT_EXCEEDED);
    SCHECK(librdp_server_drive_decode_directory_entry(
               LIBRDP_SERVER_DRIVE_FILE_DIRECTORY_INFORMATION,
               directory_info,
               sizeof(directory_info),
               0u,
               &metadata,
               name,
               sizeof(name),
               &name_length,
               &next_offset) == LIBRDP_STATUS_OK);
    SCHECK(strcmp(name, "node") == 0);
    SCHECK(librdp_server_drive_decode_directory_entry(
               LIBRDP_SERVER_DRIVE_FILE_DIRECTORY_INFORMATION,
               directory_info,
               sizeof(directory_info),
               sizeof(directory_info),
               &metadata,
               name,
               sizeof(name),
               &name_length,
               &next_offset) == LIBRDP_STATUS_PROTOCOL_ERROR);
    directory_info[60u] = 7u;
    SCHECK(librdp_server_drive_decode_directory_entry(
               LIBRDP_SERVER_DRIVE_FILE_DIRECTORY_INFORMATION,
               directory_info,
               sizeof(directory_info),
               0u,
               &metadata,
               name,
               sizeof(name),
               &name_length,
               &next_offset) == LIBRDP_STATUS_PROTOCOL_ERROR);
    return 0;
}

/*
 * Exercises bounded channel state and typed clipboard/drive lifecycles,
 * including malformed fragments, duplicate identifiers, cancellation, late
 * completions, and reconnect-scoped handle invalidation.
 */
int test_server_channels_focused(void)
{
    test_server_peer_fixture fixture;
    test_server_clipboard_context clipboard;
    test_server_drive_context drive;
    test_server_runtime_context channel;
    librdp_server_dynamic_channel_info channel_info;
    librdp_server_clipboard_event initialized_event;
    librdp_server_drive_event initialized_drive_event;
    librdp_server_drive_request drive_request;
    librdp_server_drive_request_id drive_request_id = 0u;
    librdp_server_drive_device_handle primary_drive_device;
    librdp_server_drive_file_handle stale_drive_file;
    rdp_clipboard_format_entry entry;
    rdp_device_redirection_capability_config capability_config;
    rdp_device_redirection_device_announce device_announce;
    rdp_buffer packet;
    int provider_enabled = 0;
    static const uint8_t payload[] = { 0x11, 0x22 };
    static const uint8_t format_name[] = {'T', 0, 'E', 0, 'S', 0, 'T', 0};
    static const uint8_t drive_name[] = {
        'D', 0, 'R', 0, 'I', 0, 'V', 0, 'E', 0, 0, 0
    };
    static const uint8_t utf8_drive_name[] = {
        'S', 'M', 'O', 'K', 'E', 0
    };
    static const uint8_t unterminated_drive_name[] = {
        'B', 'A', 'D'
    };
    static const uint8_t embedded_null_drive_name[] = {
        'B', 0, 'A', 0
    };
    static const uint8_t invalid_utf16_drive_name[] = {
        0, 0xd8, 0, 0
    };
    static const librdp_server_drive_operation drive_operations[] = {
        LIBRDP_SERVER_DRIVE_WRITE,
        LIBRDP_SERVER_DRIVE_QUERY_INFORMATION,
        LIBRDP_SERVER_DRIVE_SET_INFORMATION,
        LIBRDP_SERVER_DRIVE_FLUSH,
        LIBRDP_SERVER_DRIVE_QUERY_VOLUME,
        LIBRDP_SERVER_DRIVE_SET_VOLUME,
        LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY,
        LIBRDP_SERVER_DRIVE_NOTIFY_DIRECTORY,
        LIBRDP_SERVER_DRIVE_CONTROL,
        LIBRDP_SERVER_DRIVE_LOCK,
        LIBRDP_SERVER_DRIVE_QUERY_SECURITY,
        LIBRDP_SERVER_DRIVE_SET_SECURITY,
        LIBRDP_SERVER_DRIVE_CLEANUP,
        LIBRDP_SERVER_DRIVE_SHUTDOWN
    };
    uint16_t device_channel_id =
        (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 1u);

    SCHECK(!rdp_server_channel_allowed(NULL, RDP_MCS_GLOBAL_CHANNEL_ID));
    SCHECK(test_server_peer_fixture_open(&fixture));
    memset(&clipboard, 0, sizeof(clipboard));
    clipboard.valid = 1;
    memset(&drive, 0, sizeof(drive));
    drive.valid = 1;
    memset(&channel, 0, sizeof(channel));
    memset(&device_announce, 0, sizeof(device_announce));
    memset(&primary_drive_device, 0, sizeof(primary_drive_device));
    memset(&stale_drive_file, 0, sizeof(stale_drive_file));
    rdp_buffer_init(&packet);
    SCHECK(librdp_server_clipboard_event_init(NULL) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_clipboard_event_init(&initialized_event) ==
           LIBRDP_STATUS_OK);
    SCHECK(initialized_event.version ==
               LIBRDP_SERVER_CLIPBOARD_EVENT_VERSION &&
           initialized_event.size == sizeof(initialized_event));
    SCHECK(librdp_server_drive_event_init(NULL) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_drive_event_init(&initialized_drive_event) ==
           LIBRDP_STATUS_OK);
    SCHECK(initialized_drive_event.version ==
               LIBRDP_SERVER_DRIVE_EVENT_VERSION &&
           initialized_drive_event.size == sizeof(initialized_drive_event));
    SCHECK(librdp_server_drive_request_init(NULL) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_drive_request_init(&drive_request) ==
           LIBRDP_STATUS_OK);
    SCHECK(drive_request.version ==
               LIBRDP_SERVER_DRIVE_REQUEST_VERSION &&
           drive_request.size == sizeof(drive_request));
    SCHECK(librdp_server_peer_set_clipboard_callback(
               NULL,
               test_server_clipboard_callback,
               &clipboard) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_set_clipboard_callback(
               fixture.peer,
               test_server_clipboard_callback,
               &clipboard) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_set_drive_callback(
               NULL,
               test_server_drive_callback,
               &drive) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_set_drive_callback(
               fixture.peer,
               test_server_drive_callback,
               &drive) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_set_channel_callback(fixture.peer, test_server_channel_callback, &channel) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_set_dynamic_channel_accept_callback(
               fixture.peer, test_server_dynamic_channel_accept_callback, NULL) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_dynamic_channel_count(fixture.peer) == 0);
    SCHECK(librdp_server_peer_dynamic_channel_at(fixture.peer, 0, &channel_info) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_send_channel_data(fixture.peer, 1003, payload, sizeof(payload)) ==
           LIBRDP_STATUS_STATE);
    SCHECK(librdp_server_peer_open_dynamic_channel(fixture.peer, 1, 0, "test") ==
           LIBRDP_STATUS_STATE);
    SCHECK(librdp_server_peer_enable_extension_provider(
               fixture.peer, LIBRDP_SERVER_EXTENSION_CLIPBOARD, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_extension_provider_status(
               fixture.peer, LIBRDP_SERVER_EXTENSION_CLIPBOARD, &provider_enabled) == LIBRDP_STATUS_OK);
    SCHECK(provider_enabled == 1);
    SCHECK(librdp_server_peer_enable_extension_provider(
               fixture.peer, LIBRDP_SERVER_EXTENSION_CLIPBOARD, 0) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_extension_provider_status(
               fixture.peer, LIBRDP_SERVER_EXTENSION_CLIPBOARD, &provider_enabled) == LIBRDP_STATUS_OK);
    SCHECK(provider_enabled == 0);

    fixture.peer->advertised_channel_count = 1u;
    memcpy(fixture.peer->advertised_channels[0].name, "testvc", 7u);
    fixture.peer->advertised_channel_ids[0] = device_channel_id;
    fixture.peer->advertised_channel_joined[0] = 1u;
    packet.length = 0u;
    SCHECK(rdp_virtual_channel_write_fragment(
               &packet,
               "frag",
               4u,
               10u,
               RDP_VIRTUAL_CHANNEL_FLAG_FIRST) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_handle_static_channel_message(fixture.peer,
                                                    0u,
                                                    device_channel_id,
                                                    packet.data,
                                                    packet.length) ==
           LIBRDP_STATUS_OK);
    SCHECK(channel.channel_count == 0u);
    packet.length = 0u;
    SCHECK(rdp_virtual_channel_write_fragment(
               &packet,
               "mented",
               6u,
               10u,
               RDP_VIRTUAL_CHANNEL_FLAG_LAST) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_handle_static_channel_message(fixture.peer,
                                                    0u,
                                                    device_channel_id,
                                                    packet.data,
                                                    packet.length) ==
           LIBRDP_STATUS_OK);
    SCHECK(channel.channel_count == 1u &&
           channel.channel_payload_len == 10u &&
           memcmp(channel.channel_payload, "fragmented", 10u) == 0);
    packet.length = 0u;
    SCHECK(rdp_virtual_channel_write_fragment(
               &packet,
               "late",
               4u,
               8u,
               RDP_VIRTUAL_CHANNEL_FLAG_LAST) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_handle_static_channel_message(fixture.peer,
                                                    0u,
                                                    device_channel_id,
                                                    packet.data,
                                                    packet.length) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    packet.length = 0u;
    SCHECK(rdp_virtual_channel_write_fragment(
               &packet,
               "du",
               2u,
               4u,
               RDP_VIRTUAL_CHANNEL_FLAG_FIRST) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_handle_static_channel_message(fixture.peer,
                                                    0u,
                                                    device_channel_id,
                                                    packet.data,
                                                    packet.length) ==
           LIBRDP_STATUS_OK);
    SCHECK(rdp_server_handle_static_channel_message(fixture.peer,
                                                    0u,
                                                    device_channel_id,
                                                    packet.data,
                                                    packet.length) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_server_static_channels_reset(fixture.peer);
    fixture.peer->advertised_channel_count = 0u;
    fixture.peer->advertised_channel_joined[0] = 0u;
    memset(fixture.peer->advertised_channels[0].name, 0, 8u);

    device_announce.device_type =
        RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM;
    device_announce.device_id = 0x44525631u;
    memcpy(device_announce.preferred_dos_name, "DRIVE", 5u);
    device_announce.data = drive_name;
    device_announce.data_len = (uint32_t)sizeof(drive_name);
    fixture.peer->state = LIBRDP_SERVER_PEER_ACTIVE;
    fixture.peer->advertised_channel_count = 1u;
    memcpy(fixture.peer->advertised_channels[0].name, "rdpdr", 6u);
    fixture.peer->advertised_channel_ids[0] = device_channel_id;
    fixture.peer->advertised_channel_joined[0] = 1u;
    SCHECK(librdp_server_peer_enable_extension_provider(
               fixture.peer,
               LIBRDP_SERVER_EXTENSION_FILESYSTEM,
               1) == LIBRDP_STATUS_OK);
    SCHECK(fixture.peer->device_redirection_announce_sent &&
           fixture.peer->device_redirection_channel_id ==
               device_channel_id &&
           fixture.peer->device_redirection_client_id != 0u);
    packet.length = 0u;
    SCHECK(rdp_device_redirection_write_device_list_announce(
               &packet,
               &device_announce,
               1u) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "rdpdr",
                                           5u,
                                           device_channel_id,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    SCHECK(drive.counts[LIBRDP_SERVER_DRIVE_DEVICE_ADDED] == 0u);
    packet.length = 0u;
    SCHECK(rdp_device_redirection_write_client_announce(
               &packet,
               fixture.peer->device_redirection_version_minor,
               fixture.peer->device_redirection_client_id) ==
           LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "rdpdr",
                                           5u,
                                           device_channel_id,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    SCHECK(fixture.peer->device_redirection_client_confirmed &&
           !fixture.peer->device_redirection_capabilities_sent);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "rdpdr",
                                           5u,
                                           device_channel_id,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    packet.length = 0u;
    SCHECK(rdp_device_redirection_write_client_name_utf16le(
               &packet,
               drive_name,
               (uint32_t)sizeof(drive_name)) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "rdpdr",
                                           5u,
                                           device_channel_id,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    SCHECK(fixture.peer->device_redirection_client_named &&
           fixture.peer->device_redirection_capabilities_sent);
    packet.length = 0u;
    SCHECK(rdp_device_redirection_make_default_capability_config(
               &capability_config) == LIBRDP_STATUS_OK);
    capability_config.include_drive = 1u;
    SCHECK(rdp_device_redirection_write_client_capability_response(
               &packet,
               &capability_config) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "rdpdr",
                                           5u,
                                           device_channel_id,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    SCHECK(fixture.peer->device_redirection_ready &&
           fixture.peer->device_redirection_client_id_sent &&
           fixture.peer->device_redirection_logged_on_sent);
    packet.length = 0u;
    SCHECK(rdp_device_redirection_write_device_list_announce(
               &packet,
               &device_announce,
               1u) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "rdpdr",
                                           5u,
                                           device_channel_id,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    SCHECK(drive.counts[LIBRDP_SERVER_DRIVE_DEVICE_ADDED] == 1u);
    SCHECK(drive.device.reconnect_generation == 1u &&
           drive.device.device_id == device_announce.device_id);
    SCHECK(strcmp(drive.preferred_name, "DRIVE") == 0 &&
           strcmp(drive.name, "DRIVE") == 0);
    primary_drive_device = drive.device;
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "rdpdr",
                                           5u,
                                           device_channel_id,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    device_announce.device_id = 0x44525632u;
    memcpy(device_announce.preferred_dos_name, "ALT", 4u);
    device_announce.data = utf8_drive_name;
    device_announce.data_len = (uint32_t)sizeof(utf8_drive_name);
    packet.length = 0u;
    SCHECK(rdp_device_redirection_write_device_list_announce(
               &packet,
               &device_announce,
               1u) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "rdpdr",
                                           5u,
                                           device_channel_id,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    SCHECK(drive.counts[LIBRDP_SERVER_DRIVE_DEVICE_ADDED] == 2u);
    SCHECK(strcmp(drive.preferred_name, "ALT") == 0 &&
           strcmp(drive.name, "SMOKE") == 0);
    device_announce.device_id = 0x44525633u;
    device_announce.data = unterminated_drive_name;
    device_announce.data_len =
        (uint32_t)sizeof(unterminated_drive_name);
    packet.length = 0u;
    SCHECK(rdp_device_redirection_write_device_list_announce(
               &packet,
               &device_announce,
               1u) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "rdpdr",
                                           5u,
                                           device_channel_id,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    device_announce.device_id = 0x44525634u;
    device_announce.data = embedded_null_drive_name;
    device_announce.data_len =
        (uint32_t)sizeof(embedded_null_drive_name);
    packet.length = 0u;
    SCHECK(rdp_device_redirection_write_device_list_announce(
               &packet,
               &device_announce,
               1u) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "rdpdr",
                                           5u,
                                           device_channel_id,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    device_announce.device_id = 0x44525635u;
    device_announce.data = invalid_utf16_drive_name;
    device_announce.data_len =
        (uint32_t)sizeof(invalid_utf16_drive_name);
    packet.length = 0u;
    SCHECK(rdp_device_redirection_write_device_list_announce(
               &packet,
               &device_announce,
               1u) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "rdpdr",
                                           5u,
                                           device_channel_id,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    SCHECK(drive.counts[LIBRDP_SERVER_DRIVE_DEVICE_ADDED] == 2u);
    device_announce.device_id = 0x44525631u;
    memcpy(device_announce.preferred_dos_name, "DRIVE", 6u);
    device_announce.data = drive_name;
    device_announce.data_len = (uint32_t)sizeof(drive_name);
    SCHECK(librdp_server_drive_request_init(&drive_request) ==
           LIBRDP_STATUS_OK);
    drive_request.operation = LIBRDP_SERVER_DRIVE_CREATE;
    drive_request.device = primary_drive_device;
    drive_request.path = "\\folder\\file.bin";
    drive_request.desired_access = 0x0012019fu;
    drive_request.shared_access = 7u;
    drive_request.create_disposition = 3u;
    drive_request.create_options = 0x40u;
    SCHECK(librdp_server_peer_submit_drive_request(
               fixture.peer,
               &drive_request,
               &drive_request_id) == LIBRDP_STATUS_OK);
    SCHECK(drive_request_id != 0u &&
           fixture.peer->drive_pending_count == 1u);
    packet.length = 0u;
    SCHECK(rdp_filesystem_redirection_write_create_response(
               &packet,
               device_announce.device_id,
               (uint32_t)drive_request_id,
               RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
               77u,
               RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_OPENED) ==
           LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "rdpdr",
                                           5u,
                                           device_channel_id,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    SCHECK(drive.counts[LIBRDP_SERVER_DRIVE_REQUEST_COMPLETED] == 1u);
    SCHECK(drive.operation == LIBRDP_SERVER_DRIVE_CREATE &&
           drive.file.file_id == 77u &&
           drive.file.reconnect_generation == 1u);
    stale_drive_file = drive.file;
    SCHECK(fixture.peer->drive_pending_count == 0u &&
           fixture.peer->drive_file_count == 1u);
    SCHECK(librdp_server_drive_request_init(&drive_request) ==
           LIBRDP_STATUS_OK);
    drive_request.operation = LIBRDP_SERVER_DRIVE_READ;
    drive_request.file = stale_drive_file;
    drive_request.length = 3u;
    drive_request.offset = 11u;
    SCHECK(librdp_server_peer_submit_drive_request(
               fixture.peer,
               &drive_request,
               &drive_request_id) == LIBRDP_STATUS_OK);
    packet.length = 0u;
    SCHECK(rdp_filesystem_redirection_write_read_response(
               &packet,
               device_announce.device_id,
               (uint32_t)drive_request_id,
               RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
               "abc",
               3u) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "rdpdr",
                                           5u,
                                           device_channel_id,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    SCHECK(drive.counts[LIBRDP_SERVER_DRIVE_REQUEST_COMPLETED] == 2u &&
           drive.operation == LIBRDP_SERVER_DRIVE_READ &&
           drive.transferred == 3u && drive.data_len == 3u &&
           memcmp(drive.data, "abc", 3u) == 0);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "rdpdr",
                                           5u,
                                           device_channel_id,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    SCHECK(librdp_server_drive_request_init(&drive_request) ==
           LIBRDP_STATUS_OK);
    drive_request.operation = LIBRDP_SERVER_DRIVE_WRITE;
    drive_request.file = drive.file;
    drive_request.data = payload;
    drive_request.data_len = sizeof(payload);
    SCHECK(librdp_server_peer_submit_drive_request(
               fixture.peer,
               &drive_request,
               &drive_request_id) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_set_drive_callback(
               fixture.peer,
               NULL,
               NULL) == LIBRDP_STATUS_STATE);
    SCHECK(librdp_server_peer_cancel_drive_request(
               fixture.peer,
               drive_request_id) == LIBRDP_STATUS_OK);
    SCHECK(drive.counts[LIBRDP_SERVER_DRIVE_REQUEST_CANCELLED] == 1u);
    SCHECK(librdp_server_peer_cancel_drive_request(
               fixture.peer,
               drive_request_id) == LIBRDP_STATUS_STATE);
    packet.length = 0u;
    SCHECK(rdp_filesystem_redirection_write_write_response(
               &packet,
               device_announce.device_id,
               (uint32_t)drive_request_id,
               RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
               (uint32_t)sizeof(payload)) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "rdpdr",
                                           5u,
                                           device_channel_id,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    SCHECK(drive.counts[LIBRDP_SERVER_DRIVE_REQUEST_COMPLETED] == 2u &&
           fixture.peer->drive_pending_count == 0u);
    for (size_t operation_index = 0u;
         operation_index <
             sizeof(drive_operations) / sizeof(drive_operations[0]);
         operation_index++)
    {
        librdp_server_drive_lock_range lock_range;
        librdp_server_drive_operation operation =
            drive_operations[operation_index];
        uint32_t expected_completions =
            drive.counts[LIBRDP_SERVER_DRIVE_REQUEST_COMPLETED] + 1u;

        memset(&lock_range, 0, sizeof(lock_range));
        lock_range.length = 1u;
        SCHECK(librdp_server_drive_request_init(&drive_request) ==
               LIBRDP_STATUS_OK);
        drive_request.operation = operation;
        drive_request.device = drive.device;
        drive_request.file = stale_drive_file;
        drive_request.offset = 5u;
        drive_request.length = 2u;
        drive_request.information_class = 1u;
        drive_request.output_buffer_length = 16u;
        drive_request.control_code =
            RDP_FILESYSTEM_REDIRECTION_FSCTL_SET_SPARSE;
        drive_request.initial_query = 1u;
        drive_request.path = "\\*";
        drive_request.completion_filter =
            RDP_FILESYSTEM_REDIRECTION_NOTIFY_FILE_NAME;
        drive_request.lock_operation =
            LIBRDP_SERVER_DRIVE_LOCK_SHARED;
        drive_request.locks = &lock_range;
        drive_request.lock_count = 1u;
        drive_request.security_information =
            RDP_FILESYSTEM_REDIRECTION_OWNER_SECURITY_INFORMATION;
        if (operation == LIBRDP_SERVER_DRIVE_WRITE ||
            operation == LIBRDP_SERVER_DRIVE_SET_INFORMATION ||
            operation == LIBRDP_SERVER_DRIVE_SET_VOLUME ||
            operation == LIBRDP_SERVER_DRIVE_CONTROL ||
            operation == LIBRDP_SERVER_DRIVE_SET_SECURITY)
        {
            drive_request.data = payload;
            drive_request.data_len = sizeof(payload);
        }
        SCHECK(librdp_server_peer_submit_drive_request(
                   fixture.peer,
                   &drive_request,
                   &drive_request_id) == LIBRDP_STATUS_OK);
        SCHECK(test_server_complete_drive_request(
            fixture.peer,
            &packet,
            device_channel_id,
            device_announce.device_id,
            drive_request_id,
            operation));
        SCHECK(drive.counts[LIBRDP_SERVER_DRIVE_REQUEST_COMPLETED] ==
                   expected_completions &&
               drive.operation == operation &&
               fixture.peer->drive_pending_count == 0u);
    }
    SCHECK(librdp_server_drive_request_init(&drive_request) ==
           LIBRDP_STATUS_OK);
    drive_request.operation = LIBRDP_SERVER_DRIVE_CLOSE;
    drive_request.file = stale_drive_file;
    SCHECK(librdp_server_peer_submit_drive_request(
               fixture.peer,
               &drive_request,
               &drive_request_id) == LIBRDP_STATUS_OK);
    SCHECK(test_server_complete_drive_request(
        fixture.peer,
        &packet,
        device_channel_id,
        device_announce.device_id,
        drive_request_id,
        LIBRDP_SERVER_DRIVE_CLOSE));
    SCHECK(fixture.peer->drive_file_count == 0u);
    SCHECK(librdp_server_peer_submit_drive_request(
               fixture.peer,
               &drive_request,
               &drive_request_id) == LIBRDP_STATUS_STATE);
    packet.length = 0u;
    {
        uint32_t removed_device = device_announce.device_id;

        SCHECK(rdp_device_redirection_write_device_remove(
                   &packet,
                   &removed_device,
                   1u) == LIBRDP_STATUS_OK);
    }
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "rdpdr",
                                           5u,
                                           device_channel_id,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    SCHECK(drive.counts[LIBRDP_SERVER_DRIVE_DEVICE_REMOVED] == 1u &&
           fixture.peer->drive_file_count == 0u);
    SCHECK(librdp_server_drive_request_init(&drive_request) ==
           LIBRDP_STATUS_OK);
    drive_request.operation = LIBRDP_SERVER_DRIVE_READ;
    drive_request.file = stale_drive_file;
    drive_request.length = 1u;
    SCHECK(librdp_server_peer_submit_drive_request(
               fixture.peer,
               &drive_request,
               &drive_request_id) == LIBRDP_STATUS_STATE);
    SCHECK(drive.valid);
    SCHECK(librdp_server_peer_set_drive_callback(
               fixture.peer,
               NULL,
               NULL) == LIBRDP_STATUS_OK);
    fixture.peer->state = LIBRDP_SERVER_PEER_NEW;

    packet.length = 0u;
    SCHECK(rdp_clipboard_write_monitor_ready(&packet) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_capabilities(
               &packet,
               RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    memset(&entry, 0, sizeof(entry));
    entry.format_id = RDP_CLIPBOARD_FORMAT_UNICODETEXT;
    entry.name = format_name;
    entry.name_len = sizeof(format_name);
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_format_list(&packet, &entry, 1u, 1) ==
           LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    fixture.peer->clipboard_formats_sent = 1u;
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_format_list_response(&packet, 1) ==
           LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_format_data_request(
               &packet,
               RDP_CLIPBOARD_FORMAT_UNICODETEXT) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    fixture.peer->clipboard_pending_format = 1u;
    fixture.peer->clipboard_pending_format_id =
        RDP_CLIPBOARD_FORMAT_UNICODETEXT;
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_format_data_response(
               &packet,
               1,
               payload,
               sizeof(payload)) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_file_contents_request(
               &packet,
               41u,
               2,
               RDP_CLIPBOARD_FILECONTENTS_RANGE,
               7u,
               11u,
               NULL) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    fixture.peer->clipboard_pending_file = 1u;
    fixture.peer->clipboard_pending_file_stream_id = 43u;
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_file_contents_response(
               &packet,
               1,
               43u,
               payload,
               sizeof(payload)) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_lock(&packet, 47u) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    packet.length = 0u;
    SCHECK(rdp_clipboard_write_unlock(&packet, 47u) == LIBRDP_STATUS_OK);
    SCHECK(rdp_server_emit_extension_event(fixture.peer,
                                           "cliprdr",
                                           7u,
                                           1003u,
                                           0u,
                                           0u,
                                           packet.data,
                                           packet.length) ==
           LIBRDP_STATUS_OK);
    fixture.peer->clipboard_pending_format = 1u;
    fixture.peer->clipboard_pending_format_id = 53u;
    fixture.peer->clipboard_pending_file = 1u;
    fixture.peer->clipboard_pending_file_stream_id = 59u;
    SCHECK(librdp_server_peer_cancel_clipboard_requests(fixture.peer) ==
           LIBRDP_STATUS_OK);
    SCHECK(clipboard.valid);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_MONITOR_READY] == 1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_CAPABILITIES] == 1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_FORMAT_LIST] == 1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_FORMAT_LIST_RESPONSE] ==
           1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_FORMAT_DATA_REQUEST] ==
           1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_FORMAT_DATA_RESPONSE] ==
           1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_FILE_CONTENTS_REQUEST] ==
           1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_FILE_CONTENTS_RESPONSE] ==
           1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_LOCK] == 1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_UNLOCK] == 1u);
    SCHECK(clipboard.counts[LIBRDP_SERVER_CLIPBOARD_CANCELLED] == 2u);
    SCHECK(clipboard.general_flags ==
           RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES);
    SCHECK(clipboard.format_name_len == sizeof(format_name) &&
           memcmp(clipboard.format_name,
                  format_name,
                  sizeof(format_name)) == 0);
    SCHECK(clipboard.data_len == sizeof(payload) &&
           memcmp(clipboard.data, payload, sizeof(payload)) == 0);
    SCHECK(clipboard.stream_id == 59u);
    SCHECK(librdp_server_peer_set_clipboard_callback(
               fixture.peer,
               NULL,
               NULL) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&packet);
    test_server_peer_fixture_close(&fixture);
    return 0;
}

int test_server_graphics_focused(void)
{
    test_server_peer_fixture fixture;
    static const uint8_t pixels[] = {
        0x10, 0x20, 0x30, 0xff, 0x40, 0x50, 0x60, 0xff,
        0x70, 0x80, 0x90, 0xff, 0xa0, 0xb0, 0xc0, 0xff,
    };

    SCHECK(test_server_peer_fixture_open(&fixture));
    SCHECK(librdp_server_peer_desktop_width(fixture.peer) == 1024);
    SCHECK(librdp_server_peer_desktop_height(fixture.peer) == 768);
    SCHECK(librdp_server_peer_surface_resize(
               fixture.peer,
               LIBRDP_DESKTOP_MIN_DIMENSION,
               LIBRDP_DESKTOP_MIN_DIMENSION) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_desktop_width(fixture.peer) ==
           LIBRDP_DESKTOP_MIN_DIMENSION);
    SCHECK(librdp_server_peer_desktop_height(fixture.peer) ==
           LIBRDP_DESKTOP_MIN_DIMENSION);
    SCHECK(librdp_server_peer_surface_resize(
               fixture.peer,
               LIBRDP_DESKTOP_MIN_DIMENSION - 1u,
               LIBRDP_DESKTOP_MIN_DIMENSION) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_surface_blit_bgra32(
               fixture.peer, 2, 1, 2, 2, 8, pixels) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_surface_blit_bgra32(
               fixture.peer,
               LIBRDP_DESKTOP_MIN_DIMENSION - 1u,
               LIBRDP_DESKTOP_MIN_DIMENSION - 1u,
               2,
               2,
               8,
               pixels) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_surface_present(fixture.peer, 2, 1, 2, 2) ==
           LIBRDP_STATUS_STATE);
    SCHECK(librdp_server_peer_set_graphics_frame_queue_limit(fixture.peer, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_set_graphics_frame_queue_limit(fixture.peer, 4) ==
           LIBRDP_STATUS_OK);
    test_server_peer_fixture_close(&fixture);
    return 0;
}
