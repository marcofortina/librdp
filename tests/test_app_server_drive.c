/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: platform-neutral server drive runtime tests.
 * Coverage: volume policy, handle provenance, request correlation, quotas,
 * cancellation, timeouts, reconnect invalidation and browser enumeration.
 * Bug classes: traversal, stale handles, duplicate completion, integer
 * overflow, cross-volume access, leaked reservations and unbounded transfer.
 * Determinism: both protocol and platform providers are in-memory mocks.
 */

#include "server_drive.h"

#include <librdp/librdp.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DRIVE_TEST_MAX_REQUESTS 16u
#define DRIVE_TEST_DATA_CAPACITY 32u

typedef struct drive_test_protocol_request
{
    uint64_t id;
    librdp_server_drive_operation operation;
    librdp_server_drive_device_handle device;
    librdp_server_drive_file_handle file;
    int active;
} drive_test_protocol_request;

typedef struct drive_test_fixture
{
    server_drive_runtime* runtime;
    uint32_t peer_id;
    uint32_t generation;
    drive_test_protocol_request requests[DRIVE_TEST_MAX_REQUESTS];
    server_platform_drive_volume last_volume;
    server_platform_drive_completion last_completion;
    char last_volume_name[32];
    char last_path[64];
    uint8_t last_data[DRIVE_TEST_DATA_CAPACITY];
    uint64_t next_protocol_id;
    uint32_t last_device_id;
    uint32_t last_device_status;
    unsigned int submits;
    unsigned int cancels;
    unsigned int device_replies;
    unsigned int presents;
    unsigned int removes;
    unsigned int peer_removals;
    unsigned int completions;
} drive_test_fixture;

static int drive_test_check(int condition,
                            const char* expression,
                            int line)
{
    if (condition)
        return 0;
    fprintf(stderr,
            "test_app_server_drive:%d: check failed: %s\n",
            line,
            expression);
    return 1;
}

#define CHECK(expression)                                                      \
    do                                                                         \
    {                                                                          \
        if (drive_test_check((expression), #expression, __LINE__) != 0)        \
            return 1;                                                          \
    } while (0)

static drive_test_protocol_request* drive_test_find_request(
    drive_test_fixture* fixture,
    uint64_t request_id)
{
    size_t index = 0u;

    if (!fixture || request_id == 0u)
        return NULL;
    for (index = 0u; index < DRIVE_TEST_MAX_REQUESTS; index++)
    {
        if (fixture->requests[index].active &&
            fixture->requests[index].id == request_id)
            return &fixture->requests[index];
    }
    return NULL;
}

static librdp_status drive_test_protocol_submit(
    void* context,
    const librdp_server_drive_request* request,
    librdp_server_drive_request_id* request_id)
{
    drive_test_fixture* fixture = (drive_test_fixture*)context;
    size_t index = 0u;

    if (!fixture || !request || !request_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (index = 0u; index < DRIVE_TEST_MAX_REQUESTS; index++)
    {
        if (!fixture->requests[index].active)
            break;
    }
    if (index == DRIVE_TEST_MAX_REQUESTS)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    fixture->next_protocol_id++;
    if (fixture->next_protocol_id == 0u)
        fixture->next_protocol_id++;
    fixture->requests[index].id = fixture->next_protocol_id;
    fixture->requests[index].operation = request->operation;
    fixture->requests[index].device = request->device;
    fixture->requests[index].file = request->file;
    fixture->requests[index].active = 1;
    fixture->last_path[0] = '\0';
    if (request->path)
    {
        size_t length = strlen(request->path);

        if (length >= sizeof(fixture->last_path))
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
        memcpy(fixture->last_path, request->path, length + 1u);
    }
    fixture->submits++;
    *request_id = fixture->requests[index].id;
    return LIBRDP_STATUS_OK;
}

/*
 * The production server API emits cancellation synchronously. This mock keeps
 * that contract so teardown tests can prove that each accepted request reaches
 * exactly one platform completion before peer storage is released.
 */
static librdp_status drive_test_protocol_cancel(
    void* context,
    librdp_server_drive_request_id request_id)
{
    drive_test_fixture* fixture = (drive_test_fixture*)context;
    drive_test_protocol_request* request =
        drive_test_find_request(fixture, request_id);
    librdp_server_drive_event event;

    if (!fixture || !request || !fixture->runtime)
        return LIBRDP_STATUS_STATE;
    request->active = 0;
    fixture->cancels++;
    if (librdp_server_drive_event_init(&event) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_STATE;
    event.type = LIBRDP_SERVER_DRIVE_REQUEST_CANCELLED;
    event.status = LIBRDP_STATUS_CANCELLED;
    event.request_id = request_id;
    event.operation = request->operation;
    event.device = request->device;
    event.file = request->file;
    if (event.device.device_id == 0u)
    {
        event.device.reconnect_generation =
            request->file.reconnect_generation;
        event.device.device_id = request->file.device_id;
    }
    (void)server_drive_runtime_protocol_event(fixture->runtime,
                                              fixture->peer_id,
                                              fixture->generation,
                                              &event);
    return LIBRDP_STATUS_OK;
}

static librdp_status drive_test_device_reply(void* context,
                                             uint32_t device_id,
                                             uint32_t io_status)
{
    drive_test_fixture* fixture = (drive_test_fixture*)context;

    if (!fixture || device_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    fixture->device_replies++;
    fixture->last_device_id = device_id;
    fixture->last_device_status = io_status;
    return LIBRDP_STATUS_OK;
}

static librdp_status drive_test_platform_present(
    void* context,
    const server_platform_drive_volume* volume)
{
    drive_test_fixture* fixture = (drive_test_fixture*)context;
    size_t length = 0u;

    if (!fixture || !volume || !volume->name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    length = strlen(volume->name);
    if (length >= sizeof(fixture->last_volume_name))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    fixture->last_volume = *volume;
    memcpy(fixture->last_volume_name, volume->name, length + 1u);
    fixture->last_volume.name = fixture->last_volume_name;
    fixture->presents++;
    return LIBRDP_STATUS_OK;
}

static void drive_test_platform_remove(void* context,
                                       uint32_t peer_id,
                                       uint32_t generation,
                                       uint32_t device_id)
{
    drive_test_fixture* fixture = (drive_test_fixture*)context;

    if (!fixture)
        return;
    fixture->removes++;
    fixture->peer_id = peer_id;
    fixture->generation = generation;
    fixture->last_device_id = device_id;
}

static void drive_test_platform_remove_peer(void* context,
                                            uint32_t peer_id,
                                            uint32_t generation)
{
    drive_test_fixture* fixture = (drive_test_fixture*)context;

    if (!fixture)
        return;
    fixture->peer_removals++;
    fixture->peer_id = peer_id;
    fixture->generation = generation;
}

static librdp_status drive_test_platform_complete(
    void* context,
    const server_platform_drive_completion* completion)
{
    drive_test_fixture* fixture = (drive_test_fixture*)context;

    if (!fixture || !completion ||
        completion->data_len > sizeof(fixture->last_data))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    fixture->last_completion = *completion;
    if (completion->data_len > 0u)
    {
        if (!completion->data)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        memcpy(fixture->last_data,
               completion->data,
               completion->data_len);
        fixture->last_completion.data = fixture->last_data;
    }
    fixture->completions++;
    return LIBRDP_STATUS_OK;
}

static const server_drive_protocol_vtable drive_test_protocol = {
    drive_test_protocol_submit,
    drive_test_protocol_cancel,
    drive_test_device_reply,
};

static const server_platform_drive_vtable drive_test_platform = {
    .version = SERVER_PLATFORM_DRIVE_VERSION,
    .size = sizeof(server_platform_drive_vtable),
    .present = drive_test_platform_present,
    .remove = drive_test_platform_remove,
    .remove_peer = drive_test_platform_remove_peer,
    .complete = drive_test_platform_complete,
};

static int drive_test_add_volume(drive_test_fixture* fixture,
                                 uint32_t device_id,
                                 const char* name,
                                 uint32_t generation)
{
    librdp_server_drive_event event;

    if (librdp_server_drive_event_init(&event) != LIBRDP_STATUS_OK)
        return 1;
    event.type = LIBRDP_SERVER_DRIVE_DEVICE_ADDED;
    event.device.reconnect_generation = generation;
    event.device.device_id = device_id;
    event.name = name;
    return server_drive_runtime_protocol_event(fixture->runtime,
                                               fixture->peer_id,
                                               fixture->generation,
                                               &event) == LIBRDP_STATUS_OK
               ? 0
               : 1;
}

static librdp_status drive_test_complete_request(
    drive_test_fixture* fixture,
    uint64_t request_id,
    librdp_server_drive_file_handle file,
    uint64_t transferred,
    const uint8_t* data,
    size_t data_len)
{
    drive_test_protocol_request* request =
        drive_test_find_request(fixture, request_id);
    librdp_server_drive_event event;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!request ||
        librdp_server_drive_event_init(&event) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_STATE;
    event.type = LIBRDP_SERVER_DRIVE_REQUEST_COMPLETED;
    event.status = LIBRDP_STATUS_OK;
    event.request_id = request_id;
    event.operation = request->operation;
    event.device.reconnect_generation = file.reconnect_generation;
    event.device.device_id = file.device_id;
    if (event.operation == LIBRDP_SERVER_DRIVE_SHUTDOWN)
        event.device = request->device;
    event.file = file;
    event.transferred = transferred;
    event.data = data;
    event.data_len = data_len;
    request->active = 0;
    status = server_drive_runtime_protocol_event(fixture->runtime,
                                                 fixture->peer_id,
                                                 fixture->generation,
                                                 &event);
    return status;
}

static void drive_test_request_init(
    server_platform_drive_request* request,
    const drive_test_fixture* fixture,
    uint64_t request_id,
    uint64_t volume_id,
    librdp_server_drive_operation operation)
{
    memset(request, 0, sizeof(*request));
    request->request_id = request_id;
    request->volume_id = volume_id;
    request->peer_id = fixture->peer_id;
    request->generation = fixture->generation;
    (void)librdp_server_drive_request_init(&request->operation);
    request->operation.operation = operation;
}

/*
 * Exercise both directions of the manager boundary, including paths and file
 * tokens that appear plausible but were never issued by a successful create.
 */
static int test_drive_runtime(void)
{
    static const char* const allowed_names[] = {"shared", "second"};
    static const uint8_t partial_data[] = {0x31u, 0x32u};
    server_drive_config config;
    server_drive_runtime* runtime = NULL;
    server_drive_volume_info volume;
    server_platform_drive_request request;
    librdp_server_drive_file_handle first_file;
    librdp_server_drive_file_handle second_file;
    drive_test_fixture fixture;
    uint64_t first_volume = 0u;
    uint64_t second_volume = 0u;
    uint64_t protocol_id = 0u;
    unsigned int completions = 0u;

    memset(&fixture, 0, sizeof(fixture));
    fixture.peer_id = 7u;
    fixture.generation = 1u;
    fixture.next_protocol_id = 100u;
    server_drive_config_init(&config);
    config.max_peers = 2u;
    config.max_volumes_per_peer = 2u;
    config.max_pending_per_peer = 3u;
    config.max_open_files_per_peer = 2u;
    config.max_path_bytes = 32u;
    config.max_request_bytes = 8u;
    config.max_transfer_bytes_per_peer = 16u;
    config.request_timeout_ms = 5u;
    config.allowed_drive_names = allowed_names;
    config.allowed_drive_name_count = 2u;
    config.enabled = 1;
    config.read_only = 1;
    CHECK(server_drive_config_validate(&config) == LIBRDP_STATUS_OK);
    config.max_request_bytes = (size_t)UINT32_MAX + 1u;
    CHECK(server_drive_config_validate(&config) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    config.max_request_bytes = 8u;
    runtime = server_drive_runtime_new(&config,
                                       &drive_test_platform,
                                       &fixture);
    CHECK(runtime != NULL);
    fixture.runtime = runtime;
    CHECK(server_drive_runtime_add_peer(runtime,
                                        fixture.peer_id,
                                        fixture.generation,
                                        &drive_test_protocol,
                                        &fixture) == LIBRDP_STATUS_OK);
    CHECK(drive_test_add_volume(&fixture, 10u, "shared", 1u) == 0);
    CHECK(fixture.presents == 1u && fixture.device_replies == 1u);
    CHECK(fixture.last_device_status == 0u);
    server_drive_volume_info_init(&volume);
    CHECK(server_drive_runtime_volume_at(runtime, 0u, &volume) ==
          LIBRDP_STATUS_OK);
    CHECK(strcmp(volume.name, "shared") == 0 && volume.read_only);
    first_volume = volume.volume_id;
    CHECK(drive_test_add_volume(&fixture, 11u, "denied", 1u) != 0);
    CHECK(fixture.last_device_status == 0xc0000022u);
    CHECK(drive_test_add_volume(&fixture, 12u, "second", 0u) != 0);
    CHECK(server_drive_runtime_volume_count(runtime) == 1u);

    drive_test_request_init(&request,
                            &fixture,
                            1u,
                            first_volume,
                            LIBRDP_SERVER_DRIVE_CREATE);
    request.operation.device = volume.device;
    request.operation.path = "folder/file";
    request.operation.desired_access = 0x80000000u;
    request.operation.create_disposition = 1u;
    CHECK(server_drive_runtime_platform_request(runtime, &request, 100u) ==
          LIBRDP_STATUS_OK);
    CHECK(strcmp(fixture.last_path, "\\folder\\file") == 0);
    protocol_id = fixture.next_protocol_id;
    memset(&first_file, 0, sizeof(first_file));
    first_file.reconnect_generation = 1u;
    first_file.device_id = 10u;
    first_file.file_id = 50u;
    CHECK(drive_test_complete_request(&fixture,
                                      protocol_id,
                                      first_file,
                                      0u,
                                      NULL,
                                      0u) == LIBRDP_STATUS_OK);
    CHECK(fixture.last_completion.request_id == 1u);
    CHECK(fixture.last_completion.file.file_id == first_file.file_id);
    CHECK(drive_test_complete_request(&fixture,
                                      protocol_id,
                                      first_file,
                                      0u,
                                      NULL,
                                      0u) == LIBRDP_STATUS_STATE);

    drive_test_request_init(&request,
                            &fixture,
                            2u,
                            first_volume,
                            LIBRDP_SERVER_DRIVE_READ);
    request.operation.file = first_file;
    request.operation.offset = UINT64_MAX - 4u;
    request.operation.length = 4u;
    CHECK(server_drive_runtime_platform_request(runtime, &request, 200u) ==
          LIBRDP_STATUS_OK);
    protocol_id = fixture.next_protocol_id;
    CHECK(drive_test_complete_request(&fixture,
                                      protocol_id,
                                      first_file,
                                      sizeof(partial_data),
                                      partial_data,
                                      sizeof(partial_data)) ==
          LIBRDP_STATUS_OK);
    CHECK(fixture.last_completion.transferred == sizeof(partial_data));
    CHECK(fixture.last_completion.data_len == sizeof(partial_data));
    CHECK(memcmp(fixture.last_completion.data,
                 partial_data,
                 sizeof(partial_data)) == 0);

    request.request_id = 3u;
    request.operation.file.file_id = 999u;
    completions = fixture.completions;
    CHECK(server_drive_runtime_platform_request(runtime, &request, 300u) ==
          LIBRDP_STATUS_STATE);
    CHECK(fixture.completions == completions + 1u);
    CHECK(fixture.last_completion.status == LIBRDP_STATUS_STATE);
    request.operation.file = first_file;
    request.operation.offset = UINT64_MAX - 3u;
    request.operation.length = 4u;
    request.request_id = 4u;
    CHECK(server_drive_runtime_platform_request(runtime, &request, 400u) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);

    drive_test_request_init(&request,
                            &fixture,
                            5u,
                            first_volume,
                            LIBRDP_SERVER_DRIVE_WRITE);
    request.operation.file = first_file;
    request.operation.data = partial_data;
    request.operation.data_len = sizeof(partial_data);
    CHECK(server_drive_runtime_platform_request(runtime, &request, 500u) ==
          LIBRDP_STATUS_STATE);
    drive_test_request_init(&request,
                            &fixture,
                            6u,
                            first_volume,
                            LIBRDP_SERVER_DRIVE_CREATE);
    request.operation.device = volume.device;
    request.operation.path = "../escape";
    request.operation.desired_access = 0x80000000u;
    request.operation.create_disposition = 1u;
    CHECK(server_drive_runtime_platform_request(runtime, &request, 600u) ==
          LIBRDP_STATUS_STATE);

    CHECK(drive_test_add_volume(&fixture, 20u, "second", 1u) == 0);
    server_drive_volume_info_init(&volume);
    CHECK(server_drive_runtime_volume_at(runtime, 1u, &volume) ==
          LIBRDP_STATUS_OK);
    second_volume = volume.volume_id;
    drive_test_request_init(&request,
                            &fixture,
                            7u,
                            second_volume,
                            LIBRDP_SERVER_DRIVE_CREATE);
    request.operation.device = volume.device;
    request.operation.path = "remote.bin";
    request.operation.desired_access = 0x80000000u;
    request.operation.create_disposition = 1u;
    CHECK(server_drive_runtime_platform_request(runtime, &request, 700u) ==
          LIBRDP_STATUS_OK);
    protocol_id = fixture.next_protocol_id;
    memset(&second_file, 0, sizeof(second_file));
    second_file.reconnect_generation = 1u;
    second_file.device_id = 20u;
    second_file.file_id = 60u;
    CHECK(drive_test_complete_request(&fixture,
                                      protocol_id,
                                      second_file,
                                      0u,
                                      NULL,
                                      0u) == LIBRDP_STATUS_OK);
    drive_test_request_init(&request,
                            &fixture,
                            70u,
                            second_volume,
                            LIBRDP_SERVER_DRIVE_CREATE);
    request.operation.device = volume.device;
    request.operation.path = "quota.bin";
    request.operation.desired_access = 0x80000000u;
    request.operation.create_disposition = 1u;
    CHECK(server_drive_runtime_platform_request(runtime, &request, 750u) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);

    drive_test_request_init(&request,
                            &fixture,
                            8u,
                            second_volume,
                            LIBRDP_SERVER_DRIVE_QUERY_INFORMATION);
    request.operation.file = second_file;
    CHECK(server_drive_runtime_platform_request(runtime, &request, 800u) ==
          LIBRDP_STATUS_OK);
    protocol_id = fixture.next_protocol_id;
    CHECK(server_drive_runtime_next_timeout(runtime, 800u) == 5);
    CHECK(server_drive_runtime_dispatch_timeouts(runtime, 5000800u) ==
          LIBRDP_STATUS_OK);
    CHECK(fixture.last_completion.request_id == 8u);
    CHECK(fixture.last_completion.status == LIBRDP_STATUS_TIMEOUT);
    CHECK(drive_test_complete_request(&fixture,
                                      protocol_id,
                                      second_file,
                                      0u,
                                      NULL,
                                      0u) == LIBRDP_STATUS_STATE);

    drive_test_request_init(&request,
                            &fixture,
                            9u,
                            second_volume,
                            LIBRDP_SERVER_DRIVE_QUERY_VOLUME);
    request.operation.file = second_file;
    CHECK(server_drive_runtime_platform_request(runtime, &request, 900u) ==
          LIBRDP_STATUS_OK);
    CHECK(server_drive_runtime_platform_cancel(runtime,
                                               fixture.peer_id,
                                               fixture.generation,
                                               9u) ==
          LIBRDP_STATUS_OK);
    CHECK(fixture.last_completion.status == LIBRDP_STATUS_CANCELLED);
    CHECK(server_drive_runtime_platform_cancel(runtime,
                                               fixture.peer_id,
                                               fixture.generation,
                                               9u) ==
          LIBRDP_STATUS_STATE);

    drive_test_request_init(&request,
                            &fixture,
                            10u,
                            first_volume,
                            LIBRDP_SERVER_DRIVE_QUERY_INFORMATION);
    request.operation.file = first_file;
    CHECK(server_drive_runtime_platform_request(runtime, &request, 1000u) ==
          LIBRDP_STATUS_OK);
    drive_test_request_init(&request,
                            &fixture,
                            11u,
                            second_volume,
                            LIBRDP_SERVER_DRIVE_QUERY_INFORMATION);
    request.operation.file = second_file;
    CHECK(server_drive_runtime_platform_request(runtime, &request, 1000u) ==
          LIBRDP_STATUS_OK);
    protocol_id = fixture.next_protocol_id;
    {
        librdp_server_drive_event removed;

        CHECK(librdp_server_drive_event_init(&removed) == LIBRDP_STATUS_OK);
        removed.type = LIBRDP_SERVER_DRIVE_DEVICE_REMOVED;
        removed.device.reconnect_generation = 1u;
        removed.device.device_id = 10u;
        CHECK(server_drive_runtime_protocol_event(runtime,
                                                  fixture.peer_id,
                                                  fixture.generation,
                                                  &removed) ==
              LIBRDP_STATUS_OK);
    }
    CHECK(fixture.last_completion.request_id == 10u);
    CHECK(fixture.last_completion.status == LIBRDP_STATUS_CANCELLED);
    CHECK(server_drive_runtime_volume_count(runtime) == 1u);
    CHECK(drive_test_complete_request(&fixture,
                                      protocol_id,
                                      second_file,
                                      0u,
                                      NULL,
                                      0u) == LIBRDP_STATUS_OK);
    CHECK(fixture.last_completion.request_id == 11u);

    server_drive_runtime_remove_peer(runtime,
                                     fixture.peer_id,
                                     fixture.generation);
    CHECK(server_drive_runtime_volume_count(runtime) == 0u);
    CHECK(fixture.peer_removals == 1u);
    request.generation = 1u;
    CHECK(server_drive_runtime_platform_request(runtime, &request, 1000u) ==
          LIBRDP_STATUS_STATE);
    fixture.generation = 2u;
    CHECK(server_drive_runtime_add_peer(runtime,
                                        fixture.peer_id,
                                        fixture.generation,
                                        &drive_test_protocol,
                                        &fixture) == LIBRDP_STATUS_OK);
    CHECK(drive_test_add_volume(&fixture, 30u, "shared", 1u) == 0);
    CHECK(drive_test_add_volume(&fixture, 30u, "shared", 1u) != 0);
    server_drive_runtime_revoke(runtime);
    CHECK(!server_drive_runtime_is_enabled(runtime));
    CHECK(server_drive_runtime_volume_count(runtime) == 0u);
    server_drive_runtime_free(runtime);
    return 0;
}

/*
 * Submit every normalized drive operation through the same correlation path.
 * The mock intentionally supplies no filesystem semantics; this test proves
 * that manager policy does not accidentally omit a typed operation that the
 * public server API can serialize.
 */
static int test_drive_operation_matrix(void)
{
    static const librdp_server_drive_operation operations[] = {
        LIBRDP_SERVER_DRIVE_READ,
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
        LIBRDP_SERVER_DRIVE_SHUTDOWN,
    };
    static const uint8_t payload[] = {0x5au};
    server_drive_config config;
    server_drive_runtime* runtime = NULL;
    server_drive_volume_info volume;
    server_platform_drive_request request;
    librdp_server_drive_file_handle file;
    librdp_server_drive_lock_range range;
    drive_test_fixture fixture;
    size_t index = 0u;

    memset(&fixture, 0, sizeof(fixture));
    fixture.peer_id = 9u;
    fixture.generation = 3u;
    fixture.next_protocol_id = 200u;
    server_drive_config_init(&config);
    config.max_peers = 1u;
    config.max_volumes_per_peer = 1u;
    config.max_pending_per_peer = 2u;
    config.max_open_files_per_peer = 2u;
    config.max_path_bytes = 64u;
    config.max_request_bytes = 64u;
    config.max_transfer_bytes_per_peer = 1024u;
    config.enabled = 1;
    config.read_only = 0;
    runtime = server_drive_runtime_new(&config,
                                       &drive_test_platform,
                                       &fixture);
    CHECK(runtime != NULL);
    fixture.runtime = runtime;
    CHECK(server_drive_runtime_add_peer(runtime,
                                        fixture.peer_id,
                                        fixture.generation,
                                        &drive_test_protocol,
                                        &fixture) == LIBRDP_STATUS_OK);
    CHECK(drive_test_add_volume(&fixture, 40u, "matrix", 3u) == 0);
    server_drive_volume_info_init(&volume);
    CHECK(server_drive_runtime_volume_at(runtime, 0u, &volume) ==
          LIBRDP_STATUS_OK);
    drive_test_request_init(&request,
                            &fixture,
                            100u,
                            volume.volume_id,
                            LIBRDP_SERVER_DRIVE_CREATE);
    request.operation.device = volume.device;
    request.operation.path = "matrix.bin";
    request.operation.create_disposition = 1u;
    CHECK(server_drive_runtime_platform_request(runtime, &request, 0u) ==
          LIBRDP_STATUS_OK);
    memset(&file, 0, sizeof(file));
    file.reconnect_generation = fixture.generation;
    file.device_id = volume.device.device_id;
    file.file_id = 90u;
    CHECK(drive_test_complete_request(&fixture,
                                      fixture.next_protocol_id,
                                      file,
                                      0u,
                                      NULL,
                                      0u) == LIBRDP_STATUS_OK);
    range.offset = UINT64_MAX - 1u;
    range.length = 1u;
    for (index = 0u; index < sizeof(operations) / sizeof(operations[0]);
         index++)
    {
        librdp_server_drive_operation operation = operations[index];
        librdp_server_drive_file_handle completion_file = file;

        drive_test_request_init(&request,
                                &fixture,
                                101u + index,
                                volume.volume_id,
                                operation);
        if (operation == LIBRDP_SERVER_DRIVE_SHUTDOWN)
        {
            request.operation.device = volume.device;
            memset(&completion_file, 0, sizeof(completion_file));
        }
        else
            request.operation.file = file;
        if (operation == LIBRDP_SERVER_DRIVE_READ)
            request.operation.length = 1u;
        if (operation == LIBRDP_SERVER_DRIVE_WRITE ||
            operation == LIBRDP_SERVER_DRIVE_SET_INFORMATION ||
            operation == LIBRDP_SERVER_DRIVE_SET_VOLUME ||
            operation == LIBRDP_SERVER_DRIVE_SET_SECURITY)
        {
            request.operation.data = payload;
            request.operation.data_len = sizeof(payload);
        }
        if (operation == LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY)
        {
            request.operation.path = "entry";
            request.operation.initial_query = 1u;
        }
        if (operation == LIBRDP_SERVER_DRIVE_NOTIFY_DIRECTORY)
            request.operation.watch_tree = 1u;
        if (operation == LIBRDP_SERVER_DRIVE_CONTROL ||
            operation == LIBRDP_SERVER_DRIVE_QUERY_SECURITY)
            request.operation.output_buffer_length = 1u;
        if (operation == LIBRDP_SERVER_DRIVE_LOCK)
        {
            request.operation.lock_operation =
                LIBRDP_SERVER_DRIVE_LOCK_EXCLUSIVE;
            request.operation.locks = &range;
            request.operation.lock_count = 1u;
        }
        CHECK(server_drive_runtime_platform_request(
                  runtime,
                  &request,
                  (uint64_t)(index + 1u) * 100u) == LIBRDP_STATUS_OK);
        CHECK(drive_test_complete_request(&fixture,
                                          fixture.next_protocol_id,
                                          completion_file,
                                          0u,
                                          NULL,
                                          0u) == LIBRDP_STATUS_OK);
    }
    drive_test_request_init(&request,
                            &fixture,
                            200u,
                            volume.volume_id,
                            LIBRDP_SERVER_DRIVE_LOCK);
    request.operation.file = file;
    request.operation.lock_operation = LIBRDP_SERVER_DRIVE_LOCK_SHARED;
    range.length = 0u;
    request.operation.locks = &range;
    request.operation.lock_count = 1u;
    CHECK(server_drive_runtime_platform_request(runtime, &request, 5000u) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    drive_test_request_init(&request,
                            &fixture,
                            201u,
                            volume.volume_id,
                            LIBRDP_SERVER_DRIVE_CLOSE);
    request.operation.file = file;
    CHECK(server_drive_runtime_platform_request(runtime, &request, 5100u) ==
          LIBRDP_STATUS_OK);
    CHECK(drive_test_complete_request(&fixture,
                                      fixture.next_protocol_id,
                                      file,
                                      0u,
                                      NULL,
                                      0u) == LIBRDP_STATUS_OK);
    request.request_id = 202u;
    CHECK(server_drive_runtime_platform_request(runtime, &request, 5200u) ==
          LIBRDP_STATUS_STATE);
    server_drive_runtime_free(runtime);
    return 0;
}

int main(void)
{
    if (test_drive_runtime() != 0)
        return 1;
    if (test_drive_operation_matrix() != 0)
        return 1;
    puts("app server drive tests passed");
    return 0;
}
