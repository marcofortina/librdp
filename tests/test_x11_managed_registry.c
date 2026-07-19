/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic managed-session registry tests.
 * Coverage: display locking, global and per-user quotas, unique reconnect
 * tokens, attach/detach, resize, expiry and filesystem cleanup.
 * Bug classes: display collisions, cross-user token lookup, stale runtime
 * directories, arithmetic boundaries and detached-session leaks.
 * Determinism: every test uses a private temporary runtime root and the
 * effective process identity; no X server or network listener is required.
 */

#include "x11_managed_registry.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define CHECK(condition)                                                        \
    do                                                                          \
    {                                                                           \
        if (!(condition))                                                       \
        {                                                                       \
            fprintf(stderr,                                                     \
                    "check failed %s:%d: %s\n",                                 \
                    __FILE__,                                                   \
                    __LINE__,                                                   \
                    #condition);                                                \
            return 1;                                                           \
        }                                                                       \
    } while (0)

static void test_start_request(x11_managed_ipc_message* request,
                               const char* username)
{
    x11_managed_ipc_message_init(request);
    request->type = X11_MANAGED_IPC_START;
    request->request_id = 1u;
    request->width = 1280u;
    request->height = 720u;
    request->flags = X11_MANAGED_IPC_PERSISTENT;
    memcpy(request->username, username, strlen(username) + 1u);
    memcpy(request->desktop_command, "/bin/true", sizeof("/bin/true"));
    memcpy(request->xserver_command, "/bin/true", sizeof("/bin/true"));
}

/*
 * Exercise one complete slot lifecycle while a second slot proves that
 * displays and tokens stay isolated. The quota rejection occurs before any
 * filesystem resource is allocated, and release must remove only paths owned
 * by the selected slot.
 */
static int test_registry_lifecycle(void)
{
    char root[] = "/tmp/librdp-managed-registry-XXXXXX";
    x11_managed_registry_config config;
    x11_managed_registry* registry = NULL;
    x11_managed_ipc_message first_request;
    x11_managed_ipc_message second_request;
    x11_managed_session_entry* first = NULL;
    x11_managed_session_entry* second = NULL;
    x11_managed_session_entry* rejected = NULL;
    uint64_t first_id = 0u;
    char first_runtime[X11_MANAGED_IPC_PATH_BYTES];
    char first_token[X11_MANAGED_IPC_TOKEN_BYTES];
    struct stat info;

    CHECK(mkdtemp(root) != NULL);
    x11_managed_registry_config_init(&config);
    config.runtime_root = root;
    config.max_sessions = 3u;
    config.max_sessions_per_user = 2u;
    config.first_display = 620u;
    config.last_display = 622u;
    config.idle_timeout_ns = 100u;
    config.max_duration_ns = 1000u;
    registry = x11_managed_registry_new(&config);
    CHECK(registry != NULL);
    test_start_request(&first_request, "registry-user");
    CHECK(x11_managed_registry_reserve(registry,
                                      &first_request,
                                      geteuid(),
                                      getegid(),
                                      1000u,
                                      &first) == LIBRDP_STATUS_OK);
    CHECK(first != NULL);
    CHECK(first->display_number >= 620u &&
          first->display_number <= 622u);
    CHECK(first->state == X11_MANAGED_SESSION_RESERVED);
    CHECK(lstat(first->runtime_directory, &info) == 0 &&
          S_ISDIR(info.st_mode));
    first_id = first->session_id;
    memcpy(first_runtime,
           first->runtime_directory,
           strlen(first->runtime_directory) + 1u);
    memcpy(first_token,
           first->reconnect_token,
           sizeof(first_token));
    test_start_request(&second_request, "other-user");
    CHECK(x11_managed_registry_reserve(registry,
                                      &second_request,
                                      geteuid(),
                                      getegid(),
                                      1002u,
                                      &second) == LIBRDP_STATUS_OK);
    CHECK(second != NULL && second->session_id != first_id);
    CHECK(second->display_number != first->display_number);
    CHECK(!x11_managed_ipc_token_equal(second->reconnect_token,
                                       first_token));
    CHECK(x11_managed_registry_find_token(registry,
                                          first_token,
                                          geteuid()) == first);
    CHECK(x11_managed_registry_find_token(registry,
                                          first_token,
                                          (uid_t)(geteuid() + 1u)) == NULL);
    test_start_request(&second_request, "quota-user");
    CHECK(x11_managed_registry_reserve(registry,
                                      &second_request,
                                      geteuid(),
                                      getegid(),
                                      1003u,
                                      &rejected) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(rejected == NULL);
    CHECK(x11_managed_registry_mark_starting(registry,
                                             first_id,
                                             100) == LIBRDP_STATUS_OK);
    CHECK(x11_managed_registry_mark_active(registry,
                                           first_id,
                                           101,
                                           102,
                                           103,
                                           33890u,
                                           1010u) == LIBRDP_STATUS_OK);
    CHECK(x11_managed_registry_attach(registry,
                                      first_id,
                                      1020u) == LIBRDP_STATUS_OK);
    CHECK(x11_managed_registry_resize(registry,
                                      first_id,
                                      1920u,
                                      1080u,
                                      1030u) == LIBRDP_STATUS_OK);
    CHECK(first->width == 1920u && first->height == 1080u);
    CHECK(x11_managed_registry_detach(registry,
                                      first_id,
                                      1040u) == LIBRDP_STATUS_OK);
    CHECK(first->state == X11_MANAGED_SESSION_DETACHED);
    CHECK(!x11_managed_registry_expired(first, 1139u));
    CHECK(x11_managed_registry_expired(first, 1140u));
    CHECK(x11_managed_registry_release(registry,
                                       first_id) == LIBRDP_STATUS_OK);
    CHECK(lstat(first_runtime, &info) != 0);
    CHECK(x11_managed_registry_count(registry) == 1u);
    x11_managed_registry_free(registry);
    CHECK(rmdir(root) == 0);
    return 0;
}

static int test_invalid_requests(void)
{
    char root[] = "/tmp/librdp-managed-invalid-XXXXXX";
    x11_managed_registry_config config;
    x11_managed_registry* registry = NULL;
    x11_managed_ipc_message request;
    x11_managed_session_entry* entry = NULL;

    CHECK(mkdtemp(root) != NULL);
    x11_managed_registry_config_init(&config);
    config.runtime_root = root;
    config.max_sessions = 1u;
    config.max_sessions_per_user = 1u;
    config.first_display = 630u;
    config.last_display = 630u;
    registry = x11_managed_registry_new(&config);
    CHECK(registry != NULL);
    test_start_request(&request, "../escape");
    CHECK(x11_managed_registry_reserve(registry,
                                      &request,
                                      geteuid(),
                                      getegid(),
                                      1000u,
                                      &entry) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    test_start_request(&request, "valid-user");
    request.width = 0u;
    CHECK(x11_managed_registry_reserve(registry,
                                      &request,
                                      geteuid(),
                                      getegid(),
                                      1000u,
                                      &entry) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    x11_managed_registry_free(registry);
    CHECK(rmdir(root) == 0);
    return 0;
}

/*
 * Model a broker restart by constructing the filesystem objects left by a
 * live supervisor. Adoption must rebuild the in-memory entry without replacing
 * its lock, token or user-owned runtime directory, then release every object.
 */
static int test_registry_recovery(void)
{
    char root[] = "/tmp/librdp-managed-recovery-XXXXXX";
    char runtime[4096];
    char control[4096];
    char lock_path[4096];
    struct sockaddr_un address;
    struct stat info;
    x11_managed_registry_config config;
    x11_managed_registry* registry = NULL;
    x11_managed_session_entry* entry = NULL;
    x11_managed_ipc_message state;
    const uint64_t session_id = 0x1234u;
    int listener = -1;
    int lock_fd = -1;
    int length = 0;

    CHECK(mkdtemp(root) != NULL);
    length = snprintf(runtime,
                      sizeof(runtime),
                      "%s/session-%016llx",
                      root,
                      (unsigned long long)session_id);
    CHECK(length > 0 && (size_t)length < sizeof(runtime));
    CHECK(mkdir(runtime, 0700) == 0);
    length = snprintf(control,
                      sizeof(control),
                      "%s/session-%016llx.sock",
                      root,
                      (unsigned long long)session_id);
    CHECK(length > 0 && (size_t)length < sizeof(control));
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(listener >= 0 && strlen(control) < sizeof(address.sun_path));
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, control, strlen(control) + 1u);
    CHECK(bind(listener,
               (const struct sockaddr*)&address,
               sizeof(address)) == 0);
    CHECK(listen(listener, 1) == 0);
    length = snprintf(lock_path,
                      sizeof(lock_path),
                      "%s/display-640.lock",
                      root);
    CHECK(length > 0 && (size_t)length < sizeof(lock_path));
    lock_fd = open(lock_path, O_RDWR | O_CREAT | O_EXCL, 0600);
    CHECK(lock_fd >= 0);
    x11_managed_registry_config_init(&config);
    config.runtime_root = root;
    config.max_sessions = 1u;
    config.max_sessions_per_user = 1u;
    config.first_display = 640u;
    config.last_display = 640u;
    registry = x11_managed_registry_new(&config);
    CHECK(registry != NULL);
    x11_managed_ipc_message_init(&state);
    state.type = X11_MANAGED_IPC_READY;
    state.request_id = 1u;
    state.session_id = session_id;
    state.created_ns = 1000u;
    state.supervisor_pid = (uint64_t)getpid();
    state.agent_pid = (uint64_t)getpid();
    state.xserver_pid = (uint64_t)getpid();
    state.desktop_pid = (uint64_t)getpid();
    state.uid = (uint32_t)geteuid();
    state.gid = (uint32_t)getegid();
    state.width = 1280u;
    state.height = 720u;
    state.port = 33992u;
    state.session_state = X11_MANAGED_SESSION_ACTIVE;
    state.attachment_count = 1u;
    memcpy(state.username,
           "recovery-user",
           sizeof("recovery-user"));
    memcpy(state.reconnect_token,
           "abcdef0123456789abcdef0123456789"
           "abcdef0123456789abcdef0123456789",
           X11_MANAGED_IPC_TOKEN_BYTES);
    memcpy(state.display_name, ":640", sizeof(":640"));
    memcpy(state.runtime_directory,
           runtime,
           strlen(runtime) + 1u);
    memcpy(state.control_socket,
           control,
           strlen(control) + 1u);
    CHECK(x11_managed_registry_adopt(registry,
                                     &state,
                                     2000u,
                                     &entry) == LIBRDP_STATUS_OK);
    CHECK(entry != NULL &&
          entry->session_id == session_id &&
          entry->supervisor_pid == getpid());
    CHECK(x11_managed_registry_capacity(registry) == 1u);
    CHECK(x11_managed_registry_entry_at(registry, 0u) == entry);
    CHECK(x11_managed_registry_find_any(registry,
                                        session_id) == entry);
    CHECK(x11_managed_registry_release(registry,
                                       session_id) == LIBRDP_STATUS_OK);
    CHECK(lstat(control, &info) != 0 &&
          lstat(runtime, &info) != 0 &&
          lstat(lock_path, &info) != 0);
    x11_managed_registry_free(registry);
    close(lock_fd);
    close(listener);
    CHECK(rmdir(root) == 0);
    x11_managed_ipc_message_clear(&state);
    return 0;
}

int main(void)
{
    if (test_registry_lifecycle() != 0)
        return 1;
    if (test_invalid_requests() != 0)
        return 1;
    if (test_registry_recovery() != 0)
        return 1;
    return 0;
}
