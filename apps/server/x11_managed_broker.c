/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * Module: privileged managed X11 session broker.
 * Invariants: authentication runs only in a dedicated supervisor process,
 * registry operations are serialized and request concurrency is bounded.
 * Ownership: the broker owns its listener, request workers and registry view;
 * persistent supervisors own their desktop resources across broker restarts.
 * Threading: one poll loop accepts clients while detached workers perform
 * bounded IPC. A mutex protects worker slots and the registry.
 * Trust boundary: Unix peer credentials, authenticated account identity,
 * policy and reconnect tokens are checked before any session operation.
 */

#include "x11_managed_broker.h"

#include "x11_managed_ipc.h"
#include "x11_managed_registry.h"

#include <openssl/crypto.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define X11_MANAGED_BROKER_MAX_WORKERS 64u
#define X11_MANAGED_BROKER_COMMAND_TIMEOUT_MS 10000
#define X11_MANAGED_BROKER_HEALTH_INTERVAL_MS 1000
#define X11_MANAGED_BROKER_SUPERVISOR_STOP_TIMEOUT_MS 7000

extern char** environ;

typedef struct x11_managed_broker_worker
{
    struct x11_managed_broker* broker;
    pthread_t thread;
    x11_managed_ipc_identity peer;
    int client_fd;
    int operation_fd;
    int active;
} x11_managed_broker_worker;

struct x11_managed_broker
{
    x11_managed_policy policy;
    x11_managed_registry* registry;
    pthread_mutex_t mutex;
    pthread_mutex_t command_mutex;
    pthread_cond_t workers_done;
    x11_managed_broker_worker workers[X11_MANAGED_BROKER_MAX_WORKERS];
    int listener_fd;
    int wake_read_fd;
    int wake_write_fd;
    atomic_int cancelled;
    int running;
    int preserve_registry;
};

static uint64_t x11_managed_broker_now_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0u;
    return (uint64_t)now.tv_sec * 1000000000u +
           (uint64_t)now.tv_nsec;
}

static int x11_managed_broker_copy(char* output,
                                   size_t capacity,
                                   const char* input)
{
    size_t length = input ? strlen(input) : 0u;

    if (!output || capacity == 0u || !input || length >= capacity)
        return 0;
    memcpy(output, input, length + 1u);
    return 1;
}

static int x11_managed_broker_set_fd(int descriptor,
                                     int nonblocking)
{
    int descriptor_flags = fcntl(descriptor, F_GETFD);
    int status_flags = fcntl(descriptor, F_GETFL);

    if (descriptor_flags < 0 || status_flags < 0 ||
        fcntl(descriptor,
              F_SETFD,
              descriptor_flags | FD_CLOEXEC) != 0)
        return 0;
    if (nonblocking &&
        fcntl(descriptor,
              F_SETFL,
              status_flags | O_NONBLOCK) != 0)
        return 0;
    return 1;
}

static librdp_status x11_managed_broker_connect(
    const char* path,
    int* output)
{
    struct sockaddr_un address;
    int descriptor = -1;
    size_t length = path ? strlen(path) : 0u;

    if (!path || !output || path[0] != '/' || length == 0u ||
        length >= sizeof(address.sun_path))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *output = -1;
    descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0 ||
        !x11_managed_broker_set_fd(descriptor, 0))
    {
        if (descriptor >= 0)
            close(descriptor);
        return LIBRDP_STATUS_IO_ERROR;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, length + 1u);
    if (connect(descriptor,
                (const struct sockaddr*)&address,
                sizeof(address)) != 0)
    {
        close(descriptor);
        return LIBRDP_STATUS_IO_ERROR;
    }
    *output = descriptor;
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_managed_broker_parent_directory(
    const char* path)
{
    char parent[X11_MANAGED_IPC_PATH_BYTES];
    char* separator = NULL;
    struct stat info;
    size_t length = path ? strlen(path) : 0u;

    if (!path || path[0] != '/' || length == 0u ||
        length >= sizeof(parent))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memcpy(parent, path, length + 1u);
    separator = strrchr(parent, '/');
    if (!separator || separator == parent)
        return LIBRDP_STATUS_OK;
    *separator = '\0';
    if (mkdir(parent, 0750) != 0 && errno != EEXIST)
        return LIBRDP_STATUS_IO_ERROR;
    if (lstat(parent, &info) != 0 || !S_ISDIR(info.st_mode) ||
        S_ISLNK(info.st_mode) ||
        (info.st_uid != 0u && info.st_uid != geteuid()) ||
        (info.st_mode & 0002u) != 0u)
        return LIBRDP_STATUS_STATE;
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_managed_broker_create_listener(
    x11_managed_broker* broker)
{
    struct sockaddr_un address;
    struct stat info;
    int probe = -1;
    int descriptor = -1;
    size_t length = strlen(broker->policy.socket_path);
    librdp_status status = x11_managed_broker_parent_directory(
        broker->policy.socket_path);

    if (status != LIBRDP_STATUS_OK ||
        length >= sizeof(address.sun_path))
        return status != LIBRDP_STATUS_OK
                   ? status
                   : LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (lstat(broker->policy.socket_path, &info) == 0)
    {
        if (!S_ISSOCK(info.st_mode) || S_ISLNK(info.st_mode) ||
            (info.st_uid != 0u && info.st_uid != geteuid()))
            return LIBRDP_STATUS_STATE;
        if (x11_managed_broker_connect(
                broker->policy.socket_path, &probe) ==
            LIBRDP_STATUS_OK)
        {
            close(probe);
            return LIBRDP_STATUS_STATE;
        }
        if (unlink(broker->policy.socket_path) != 0)
            return LIBRDP_STATUS_IO_ERROR;
    }
    else if (errno != ENOENT)
    {
        return LIBRDP_STATUS_IO_ERROR;
    }
    descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0 ||
        !x11_managed_broker_set_fd(descriptor, 1))
    {
        if (descriptor >= 0)
            close(descriptor);
        return LIBRDP_STATUS_IO_ERROR;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path,
           broker->policy.socket_path,
           length + 1u);
    if (bind(descriptor,
             (const struct sockaddr*)&address,
             sizeof(address)) != 0 ||
        chmod(broker->policy.socket_path,
              broker->policy.socket_mode) != 0 ||
        (broker->policy.socket_group_set &&
         chown(broker->policy.socket_path,
               (uid_t)-1,
               broker->policy.socket_group) != 0) ||
        listen(descriptor, (int)X11_MANAGED_BROKER_MAX_WORKERS) != 0)
    {
        close(descriptor);
        (void)unlink(broker->policy.socket_path);
        return LIBRDP_STATUS_IO_ERROR;
    }
    broker->listener_fd = descriptor;
    return LIBRDP_STATUS_OK;
}

static void x11_managed_broker_send_error(
    int descriptor,
    uint64_t request_id,
    uint64_t session_id,
    librdp_status status)
{
    x11_managed_ipc_message response;

    if (descriptor < 0)
        return;
    x11_managed_ipc_message_init(&response);
    response.type = X11_MANAGED_IPC_ERROR;
    response.request_id = request_id != 0u ? request_id : 1u;
    response.session_id = session_id;
    response.status = status == LIBRDP_STATUS_OK
                          ? LIBRDP_STATUS_STATE
                          : status;
    (void)x11_managed_ipc_send(
        descriptor,
        &response,
        X11_MANAGED_BROKER_COMMAND_TIMEOUT_MS);
    x11_managed_ipc_message_clear(&response);
}

static void x11_managed_broker_worker_operation(
    x11_managed_broker_worker* worker,
    int descriptor)
{
    x11_managed_broker* broker = worker->broker;

    pthread_mutex_lock(&broker->mutex);
    worker->operation_fd = descriptor;
    pthread_mutex_unlock(&broker->mutex);
}

static librdp_status x11_managed_broker_spawn_supervisor(
    x11_managed_broker_worker* worker,
    int* descriptor,
    pid_t* process)
{
    x11_managed_broker* broker = worker->broker;
    posix_spawn_file_actions_t actions;
    char descriptor_text[32];
    char* arguments[8];
    int sockets[2] = {-1, -1};
    int spawn_status = 0;
    int length = 0;

    if (!descriptor || !process)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (x11_managed_ipc_connected_pair(sockets) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_IO_ERROR;
    *descriptor = -1;
    *process = -1;
    if (!x11_managed_broker_set_fd(sockets[0], 0) ||
        !x11_managed_broker_set_fd(sockets[1], 0))
    {
        close(sockets[0]);
        close(sockets[1]);
        return LIBRDP_STATUS_IO_ERROR;
    }
    length = snprintf(descriptor_text,
                      sizeof(descriptor_text),
                      "%d",
                      3);
    if (length < 0 || (size_t)length >= sizeof(descriptor_text) ||
        posix_spawn_file_actions_init(&actions) != 0)
    {
        close(sockets[0]);
        close(sockets[1]);
        return LIBRDP_STATUS_IO_ERROR;
    }
    if ((sockets[1] != 3 &&
         posix_spawn_file_actions_adddup2(
             &actions, sockets[1], 3) != 0) ||
        (sockets[0] != 3 &&
         posix_spawn_file_actions_addclose(
             &actions, sockets[0]) != 0) ||
        (sockets[1] != 3 &&
         posix_spawn_file_actions_addclose(
             &actions, sockets[1]) != 0))
    {
        posix_spawn_file_actions_destroy(&actions);
        close(sockets[0]);
        close(sockets[1]);
        return LIBRDP_STATUS_IO_ERROR;
    }
    arguments[0] = broker->policy.supervisor_path;
    arguments[1] = (char*)"--control-fd";
    arguments[2] = descriptor_text;
    arguments[3] = (char*)"--agent-path";
    arguments[4] = broker->policy.agent_path;
    arguments[5] = (char*)"--auth-service";
    arguments[6] = broker->policy.authentication_service;
    arguments[7] = NULL;
    spawn_status = posix_spawn(
        process,
        broker->policy.supervisor_path,
        &actions,
        NULL,
        arguments,
        environ);
    posix_spawn_file_actions_destroy(&actions);
    close(sockets[1]);
    if (spawn_status != 0)
    {
        close(sockets[0]);
        return LIBRDP_STATUS_IO_ERROR;
    }
    *descriptor = sockets[0];
    x11_managed_broker_worker_operation(worker, sockets[0]);
    return LIBRDP_STATUS_OK;
}

static void x11_managed_broker_stop_failed_supervisor(pid_t process)
{
    uint64_t deadline_ns = 0u;

    if (process <= 0)
        return;
    (void)kill(process, SIGTERM);
    deadline_ns = x11_managed_broker_now_ns() +
                  (uint64_t)X11_MANAGED_BROKER_SUPERVISOR_STOP_TIMEOUT_MS *
                      1000000u;
    while (x11_managed_broker_now_ns() < deadline_ns)
    {
        pid_t result = waitpid(process, NULL, WNOHANG);

        if (result == process || (result < 0 && errno == ECHILD))
            return;
        (void)poll(NULL, 0u, 20);
    }
    (void)kill(process, SIGKILL);
    (void)waitpid(process, NULL, 0);
}

/*
 * Coordinate one authenticated session start across broker, supervisor,
 * policy, and registry state. The reserved session is published only after a
 * correlated READY response; failure policy stops the supervisor, releases
 * the registry slot, and clears all credential-bearing IPC messages.
 */
static librdp_status x11_managed_broker_start(
    x11_managed_broker_worker* worker,
    x11_managed_ipc_message* initial)
{
    x11_managed_broker* broker = worker->broker;
    x11_managed_ipc_message authenticated;
    x11_managed_ipc_message filtered;
    x11_managed_ipc_message start;
    x11_managed_ipc_message ready;
    x11_managed_session_entry* entry = NULL;
    x11_managed_session_entry snapshot;
    int supervisor_fd = -1;
    pid_t supervisor_pid = -1;
    uint64_t session_id = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    x11_managed_ipc_message_init(&authenticated);
    x11_managed_ipc_message_init(&filtered);
    x11_managed_ipc_message_init(&start);
    x11_managed_ipc_message_init(&ready);
    memset(&snapshot, 0, sizeof(snapshot));
    status = x11_managed_broker_spawn_supervisor(
        worker, &supervisor_fd, &supervisor_pid);
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_ipc_send(
            supervisor_fd,
            initial,
            X11_MANAGED_BROKER_COMMAND_TIMEOUT_MS);
    }
    OPENSSL_cleanse(initial->password, sizeof(initial->password));
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_ipc_receive(
            supervisor_fd,
            &authenticated,
            X11_MANAGED_BROKER_COMMAND_TIMEOUT_MS);
    }
    if (status == LIBRDP_STATUS_OK &&
        authenticated.type == X11_MANAGED_IPC_ERROR)
    {
        status = authenticated.status != LIBRDP_STATUS_OK
                     ? authenticated.status
                     : LIBRDP_STATUS_STATE;
    }
    if (status == LIBRDP_STATUS_OK &&
        (authenticated.type != X11_MANAGED_IPC_AUTHENTICATED ||
         !x11_managed_policy_authorize(
             &broker->policy,
             worker->peer.uid,
             &authenticated)))
        status = LIBRDP_STATUS_STATE;
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_policy_filter_request(
            &broker->policy,
            initial,
            &authenticated,
            &filtered);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        pthread_mutex_lock(&broker->mutex);
        status = x11_managed_registry_reserve(
            broker->registry,
            &filtered,
            (uid_t)authenticated.uid,
            (gid_t)authenticated.gid,
            x11_managed_broker_now_ns(),
            &entry);
        if (status == LIBRDP_STATUS_OK)
        {
            session_id = entry->session_id;
            snapshot = *entry;
            status = x11_managed_registry_mark_starting(
                broker->registry,
                session_id,
                supervisor_pid);
        }
        pthread_mutex_unlock(&broker->mutex);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_policy_prepare_start(
            &broker->policy, &filtered, &snapshot, &start);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_ipc_send(
            supervisor_fd,
            &start,
            X11_MANAGED_BROKER_COMMAND_TIMEOUT_MS);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_ipc_receive(
            supervisor_fd,
            &ready,
            X11_MANAGED_BROKER_COMMAND_TIMEOUT_MS);
    }
    if (status == LIBRDP_STATUS_OK &&
        ready.type == X11_MANAGED_IPC_ERROR)
    {
        status = ready.status != LIBRDP_STATUS_OK
                     ? ready.status
                     : LIBRDP_STATUS_STATE;
    }
    if (status == LIBRDP_STATUS_OK &&
        (ready.type != X11_MANAGED_IPC_READY ||
         ready.session_id != session_id ||
         ready.request_id != initial->request_id ||
         ready.supervisor_pid != (uint64_t)supervisor_pid))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
    {
        pthread_mutex_lock(&broker->mutex);
        status = x11_managed_registry_mark_active(
            broker->registry,
            session_id,
            (pid_t)ready.agent_pid,
            (pid_t)ready.xserver_pid,
            (pid_t)ready.desktop_pid,
            ready.port,
            x11_managed_broker_now_ns());
        if (status == LIBRDP_STATUS_OK)
        {
            status = x11_managed_registry_attach(
                broker->registry,
                session_id,
                x11_managed_broker_now_ns());
        }
        pthread_mutex_unlock(&broker->mutex);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_ipc_send(
            worker->client_fd,
            &ready,
            X11_MANAGED_BROKER_COMMAND_TIMEOUT_MS);
    }
    if (status != LIBRDP_STATUS_OK)
    {
        x11_managed_broker_stop_failed_supervisor(supervisor_pid);
        if (session_id != 0u)
        {
            pthread_mutex_lock(&broker->mutex);
            (void)x11_managed_registry_release(
                broker->registry, session_id);
            pthread_mutex_unlock(&broker->mutex);
        }
        x11_managed_broker_send_error(
            worker->client_fd,
            initial->request_id,
            session_id,
            status);
    }
    x11_managed_broker_worker_operation(worker, -1);
    if (supervisor_fd >= 0)
        close(supervisor_fd);
    x11_managed_ipc_message_clear(&authenticated);
    x11_managed_ipc_message_clear(&filtered);
    x11_managed_ipc_message_clear(&start);
    x11_managed_ipc_message_clear(&ready);
    OPENSSL_cleanse(&snapshot, sizeof(snapshot));
    return status;
}

static librdp_status x11_managed_broker_find_session(
    x11_managed_broker_worker* worker,
    const x11_managed_ipc_message* request,
    x11_managed_session_entry* snapshot)
{
    x11_managed_broker* broker = worker->broker;
    x11_managed_session_entry* entry = NULL;

    if (!request || !snapshot)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (request->session_id != 0u)
    {
        entry = worker->peer.uid == 0u
                    ? x11_managed_registry_find_any(
                          broker->registry, request->session_id)
                    : x11_managed_registry_find(
                          broker->registry,
                          request->session_id,
                          worker->peer.uid);
    }
    else if (request->reconnect_token[0] != '\0')
    {
        entry = x11_managed_registry_find_token(
            broker->registry,
            request->reconnect_token,
            worker->peer.uid);
    }
    if (!entry ||
        (request->reconnect_token[0] != '\0' &&
         !x11_managed_ipc_token_equal(
             entry->reconnect_token,
             request->reconnect_token)))
        return LIBRDP_STATUS_STATE;
    *snapshot = *entry;
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_managed_broker_update_registry(
    x11_managed_broker* broker,
    const x11_managed_ipc_message* request,
    const x11_managed_ipc_message* response)
{
    uint64_t now_ns = x11_managed_broker_now_ns();

    if (response->type == X11_MANAGED_IPC_ERROR)
        return response->status != LIBRDP_STATUS_OK
                   ? response->status
                   : LIBRDP_STATUS_STATE;
    if (response->type != X11_MANAGED_IPC_READY ||
        response->request_id != request->request_id ||
        response->session_id != request->session_id)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->type == X11_MANAGED_IPC_ATTACH)
        return x11_managed_registry_attach(
            broker->registry, request->session_id, now_ns);
    if (request->type == X11_MANAGED_IPC_DETACH)
        return x11_managed_registry_detach(
            broker->registry, request->session_id, now_ns);
    if (request->type == X11_MANAGED_IPC_RESIZE)
        return x11_managed_registry_resize(
            broker->registry,
            request->session_id,
            request->width,
            request->height,
            now_ns);
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_managed_broker_command(
    x11_managed_broker_worker* worker,
    x11_managed_ipc_message* request)
{
    x11_managed_broker* broker = worker->broker;
    x11_managed_session_entry snapshot;
    x11_managed_ipc_message response;
    int supervisor_fd = -1;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(&snapshot, 0, sizeof(snapshot));
    x11_managed_ipc_message_init(&response);
    pthread_mutex_lock(&broker->command_mutex);
    pthread_mutex_lock(&broker->mutex);
    status = x11_managed_broker_find_session(
        worker, request, &snapshot);
    if (status == LIBRDP_STATUS_OK &&
        request->type == X11_MANAGED_IPC_ATTACH &&
        (snapshot.flags & X11_MANAGED_IPC_RECONNECT) == 0u)
        status = LIBRDP_STATUS_STATE;
    if (status == LIBRDP_STATUS_OK &&
        request->type == X11_MANAGED_IPC_ATTACH &&
        snapshot.attachment_count != 0u)
        status = LIBRDP_STATUS_STATE;
    if (status == LIBRDP_STATUS_OK)
    {
        request->session_id = snapshot.session_id;
        if (!x11_managed_broker_copy(
                request->reconnect_token,
                sizeof(request->reconnect_token),
                snapshot.reconnect_token))
            status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        pthread_mutex_unlock(&broker->mutex);
        status = x11_managed_broker_connect(
            snapshot.agent_socket_path, &supervisor_fd);
    }
    else
    {
        pthread_mutex_unlock(&broker->mutex);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        x11_managed_broker_worker_operation(worker, supervisor_fd);
        status = x11_managed_ipc_send(
            supervisor_fd,
            request,
            X11_MANAGED_BROKER_COMMAND_TIMEOUT_MS);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_ipc_receive(
            supervisor_fd,
            &response,
            X11_MANAGED_BROKER_COMMAND_TIMEOUT_MS);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        pthread_mutex_lock(&broker->mutex);
        status = x11_managed_broker_update_registry(
            broker, request, &response);
        pthread_mutex_unlock(&broker->mutex);
    }
    x11_managed_broker_worker_operation(worker, -1);
    if (supervisor_fd >= 0)
        close(supervisor_fd);
    pthread_mutex_unlock(&broker->command_mutex);
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_ipc_send(
            worker->client_fd,
            &response,
            X11_MANAGED_BROKER_COMMAND_TIMEOUT_MS);
    }
    if (status != LIBRDP_STATUS_OK)
    {
        x11_managed_broker_send_error(
            worker->client_fd,
            request->request_id,
            request->session_id,
            status);
    }
    x11_managed_ipc_message_clear(&response);
    OPENSSL_cleanse(&snapshot, sizeof(snapshot));
    return status;
}

static void* x11_managed_broker_worker_main(void* user_data)
{
    x11_managed_broker_worker* worker =
        (x11_managed_broker_worker*)user_data;
    x11_managed_broker* broker = worker->broker;
    x11_managed_ipc_message request;
    librdp_status status = LIBRDP_STATUS_OK;

    x11_managed_ipc_message_init(&request);
    status = x11_managed_ipc_receive(
        worker->client_fd,
        &request,
        X11_MANAGED_BROKER_COMMAND_TIMEOUT_MS);
    if (status == LIBRDP_STATUS_OK)
    {
        if (request.type == X11_MANAGED_IPC_START)
            (void)x11_managed_broker_start(worker, &request);
        else if (request.type == X11_MANAGED_IPC_ATTACH ||
                 request.type == X11_MANAGED_IPC_RESIZE ||
                 request.type == X11_MANAGED_IPC_DETACH ||
                 request.type == X11_MANAGED_IPC_TERMINATE ||
                 request.type == X11_MANAGED_IPC_QUERY ||
                 request.type == X11_MANAGED_IPC_PING ||
                 request.type == X11_MANAGED_IPC_STOP)
            (void)x11_managed_broker_command(worker, &request);
        else
            x11_managed_broker_send_error(
                worker->client_fd,
                request.request_id,
                request.session_id,
                LIBRDP_STATUS_INVALID_ARGUMENT);
    }
    else
    {
        x11_managed_broker_send_error(
            worker->client_fd,
            request.request_id,
            request.session_id,
            status);
    }
    x11_managed_ipc_message_clear(&request);
    pthread_mutex_lock(&broker->mutex);
    if (worker->client_fd >= 0)
        close(worker->client_fd);
    worker->client_fd = -1;
    worker->operation_fd = -1;
    worker->active = 0;
    pthread_cond_broadcast(&broker->workers_done);
    pthread_mutex_unlock(&broker->mutex);
    return NULL;
}

static librdp_status x11_managed_broker_accept(
    x11_managed_broker* broker)
{
    x11_managed_ipc_identity identity;
    x11_managed_broker_worker* worker = NULL;
    pthread_attr_t attributes;
    int descriptor = -1;
    size_t index = 0u;
    int create_status = 0;

    descriptor = accept(broker->listener_fd, NULL, NULL);
    if (descriptor < 0)
    {
        if (errno == EINTR || errno == EAGAIN ||
            errno == EWOULDBLOCK)
            return LIBRDP_STATUS_AGAIN;
        return LIBRDP_STATUS_IO_ERROR;
    }
    if (!x11_managed_broker_set_fd(descriptor, 0) ||
        x11_managed_ipc_peer_identity(descriptor, &identity) !=
            LIBRDP_STATUS_OK)
    {
        close(descriptor);
        return LIBRDP_STATUS_STATE;
    }
    pthread_mutex_lock(&broker->mutex);
    for (index = 0u;
         index < X11_MANAGED_BROKER_MAX_WORKERS;
         index++)
    {
        if (!broker->workers[index].active)
        {
            worker = &broker->workers[index];
            worker->active = 1;
            worker->client_fd = descriptor;
            worker->operation_fd = -1;
            worker->peer = identity;
            break;
        }
    }
    pthread_mutex_unlock(&broker->mutex);
    if (!worker)
    {
        x11_managed_broker_send_error(
            descriptor, 1u, 0u, LIBRDP_STATUS_LIMIT_EXCEEDED);
        close(descriptor);
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    if (pthread_attr_init(&attributes) != 0)
        create_status = EINVAL;
    else
    {
        (void)pthread_attr_setdetachstate(
            &attributes, PTHREAD_CREATE_DETACHED);
        create_status = pthread_create(
            &worker->thread,
            &attributes,
            x11_managed_broker_worker_main,
            worker);
        pthread_attr_destroy(&attributes);
    }
    if (create_status != 0)
    {
        pthread_mutex_lock(&broker->mutex);
        worker->active = 0;
        worker->client_fd = -1;
        pthread_mutex_unlock(&broker->mutex);
        close(descriptor);
        return LIBRDP_STATUS_IO_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static int x11_managed_broker_parse_session_socket(
    const char* name,
    uint64_t* session_id)
{
    char* end = NULL;
    unsigned long long value = 0ull;

    if (!name || !session_id ||
        strlen(name) != sizeof("session-0000000000000000.sock") - 1u ||
        strncmp(name, "session-", 8u) != 0 ||
        strcmp(name + 24u, ".sock") != 0)
        return 0;
    errno = 0;
    value = strtoull(name + 8u, &end, 16);
    if (errno != 0 || !end || strcmp(end, ".sock") != 0 ||
        value == 0ull)
        return 0;
    *session_id = (uint64_t)value;
    return 1;
}

static void x11_managed_broker_recover(x11_managed_broker* broker)
{
    DIR* directory = opendir(broker->policy.runtime_root);
    struct dirent* item = NULL;

    if (!directory)
        return;
    while ((item = readdir(directory)) != NULL)
    {
        char path[X11_MANAGED_IPC_PATH_BYTES];
        x11_managed_ipc_message query;
        x11_managed_ipc_message ready;
        x11_managed_ipc_identity identity;
        x11_managed_session_entry* entry = NULL;
        uint64_t session_id = 0u;
        int descriptor = -1;
        int length = 0;

        if (!x11_managed_broker_parse_session_socket(
                item->d_name, &session_id))
            continue;
        length = snprintf(path,
                          sizeof(path),
                          "%s/%s",
                          broker->policy.runtime_root,
                          item->d_name);
        if (length < 0 || (size_t)length >= sizeof(path) ||
            x11_managed_broker_connect(path, &descriptor) !=
                LIBRDP_STATUS_OK ||
            x11_managed_ipc_peer_identity(
                descriptor, &identity) != LIBRDP_STATUS_OK ||
            (identity.uid != 0u && identity.uid != geteuid()))
        {
            if (descriptor >= 0)
                close(descriptor);
            continue;
        }
        x11_managed_ipc_message_init(&query);
        query.type = X11_MANAGED_IPC_QUERY;
        query.request_id = session_id;
        query.session_id = session_id;
        x11_managed_ipc_message_init(&ready);
        if (x11_managed_ipc_send(
                descriptor,
                &query,
                X11_MANAGED_BROKER_COMMAND_TIMEOUT_MS) ==
                LIBRDP_STATUS_OK &&
            x11_managed_ipc_receive(
                descriptor,
                &ready,
                X11_MANAGED_BROKER_COMMAND_TIMEOUT_MS) ==
                LIBRDP_STATUS_OK &&
            ready.request_id == query.request_id &&
            ready.session_id == session_id)
        {
            pthread_mutex_lock(&broker->mutex);
            (void)x11_managed_registry_adopt(
                broker->registry,
                &ready,
                x11_managed_broker_now_ns(),
                &entry);
            pthread_mutex_unlock(&broker->mutex);
        }
        x11_managed_ipc_message_clear(&query);
        x11_managed_ipc_message_clear(&ready);
        close(descriptor);
    }
    closedir(directory);
}

static int x11_managed_broker_process_alive(pid_t process)
{
    return process > 0 &&
           (kill(process, 0) == 0 || errno == EPERM);
}

static void x11_managed_broker_health(x11_managed_broker* broker)
{
    size_t capacity = 0u;
    size_t index = 0u;

    for (;;)
    {
        pid_t child = waitpid(-1, NULL, WNOHANG);

        if (child <= 0)
            break;
    }
    pthread_mutex_lock(&broker->mutex);
    capacity = x11_managed_registry_capacity(broker->registry);
    for (index = 0u; index < capacity; index++)
    {
        const x11_managed_session_entry* entry =
            x11_managed_registry_entry_at(broker->registry, index);
        uint64_t session_id = 0u;

        if (!entry)
            continue;
        session_id = entry->session_id;
        if (!x11_managed_broker_process_alive(
                entry->supervisor_pid))
        {
            (void)x11_managed_registry_release(
                broker->registry, session_id);
        }
    }
    pthread_mutex_unlock(&broker->mutex);
}

x11_managed_broker* x11_managed_broker_new(
    const x11_managed_policy* policy,
    librdp_status* status)
{
    x11_managed_broker* broker = NULL;
    x11_managed_registry_config registry_config;
    size_t index = 0u;

    if (status)
        *status = LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!x11_managed_policy_valid(policy))
        return NULL;
    broker = (x11_managed_broker*)calloc(1u, sizeof(*broker));
    if (!broker)
    {
        if (status)
            *status = LIBRDP_STATUS_NO_MEMORY;
        return NULL;
    }
    broker->policy = *policy;
    broker->listener_fd = -1;
    broker->wake_read_fd = -1;
    broker->wake_write_fd = -1;
    for (index = 0u;
         index < X11_MANAGED_BROKER_MAX_WORKERS;
         index++)
    {
        broker->workers[index].broker = broker;
        broker->workers[index].client_fd = -1;
        broker->workers[index].operation_fd = -1;
    }
    if (pthread_mutex_init(&broker->mutex, NULL) != 0)
    {
        free(broker);
        if (status)
            *status = LIBRDP_STATUS_IO_ERROR;
        return NULL;
    }
    if (pthread_mutex_init(&broker->command_mutex, NULL) != 0)
    {
        pthread_mutex_destroy(&broker->mutex);
        free(broker);
        if (status)
            *status = LIBRDP_STATUS_IO_ERROR;
        return NULL;
    }
    if (pthread_cond_init(&broker->workers_done, NULL) != 0)
    {
        pthread_mutex_destroy(&broker->command_mutex);
        pthread_mutex_destroy(&broker->mutex);
        free(broker);
        if (status)
            *status = LIBRDP_STATUS_IO_ERROR;
        return NULL;
    }
    x11_managed_registry_config_init(&registry_config);
    registry_config.runtime_root = broker->policy.runtime_root;
    registry_config.max_sessions = broker->policy.max_sessions;
    registry_config.max_sessions_per_user =
        broker->policy.max_sessions_per_user;
    registry_config.first_display = broker->policy.first_display;
    registry_config.last_display = broker->policy.last_display;
    registry_config.idle_timeout_ns =
        broker->policy.idle_timeout_ns;
    registry_config.max_duration_ns =
        broker->policy.max_duration_ns;
    registry_config.allow_reconnect =
        broker->policy.allow_reconnect;
    if (x11_managed_broker_parent_directory(
            broker->policy.runtime_root) != LIBRDP_STATUS_OK)
    {
        pthread_cond_destroy(&broker->workers_done);
        pthread_mutex_destroy(&broker->command_mutex);
        pthread_mutex_destroy(&broker->mutex);
        free(broker);
        if (status)
            *status = LIBRDP_STATUS_IO_ERROR;
        return NULL;
    }
    broker->registry =
        x11_managed_registry_new(&registry_config);
    if (!broker->registry)
    {
        pthread_cond_destroy(&broker->workers_done);
        pthread_mutex_destroy(&broker->command_mutex);
        pthread_mutex_destroy(&broker->mutex);
        free(broker);
        if (status)
            *status = LIBRDP_STATUS_IO_ERROR;
        return NULL;
    }
    if (status)
        *status = LIBRDP_STATUS_OK;
    return broker;
}

static int x11_managed_broker_has_workers(
    const x11_managed_broker* broker)
{
    size_t index = 0u;

    for (index = 0u;
         index < X11_MANAGED_BROKER_MAX_WORKERS;
         index++)
    {
        if (broker->workers[index].active)
            return 1;
    }
    return 0;
}

void x11_managed_broker_free(x11_managed_broker* broker)
{
    if (!broker)
        return;
    (void)x11_managed_broker_cancel(broker);
    pthread_mutex_lock(&broker->mutex);
    while (x11_managed_broker_has_workers(broker))
        pthread_cond_wait(&broker->workers_done, &broker->mutex);
    pthread_mutex_unlock(&broker->mutex);
    if (broker->listener_fd >= 0)
        close(broker->listener_fd);
    if (broker->wake_read_fd >= 0)
        close(broker->wake_read_fd);
    if (broker->wake_write_fd >= 0)
        close(broker->wake_write_fd);
    if (broker->policy.socket_path[0] != '\0')
        (void)unlink(broker->policy.socket_path);
    if (broker->preserve_registry)
        x11_managed_registry_forget(broker->registry);
    else
        x11_managed_registry_free(broker->registry);
    pthread_cond_destroy(&broker->workers_done);
    pthread_mutex_destroy(&broker->command_mutex);
    pthread_mutex_destroy(&broker->mutex);
    OPENSSL_cleanse(broker, sizeof(*broker));
    free(broker);
}

librdp_status x11_managed_broker_cancel(
    x11_managed_broker* broker)
{
    unsigned char value = 1u;
    size_t index = 0u;

    if (!broker)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    pthread_mutex_lock(&broker->mutex);
    atomic_store(&broker->cancelled, 1);
    for (index = 0u;
         index < X11_MANAGED_BROKER_MAX_WORKERS;
         index++)
    {
        if (broker->workers[index].active)
        {
            if (broker->workers[index].client_fd >= 0)
                (void)shutdown(
                    broker->workers[index].client_fd, SHUT_RDWR);
            if (broker->workers[index].operation_fd >= 0)
                (void)shutdown(
                    broker->workers[index].operation_fd, SHUT_RDWR);
        }
    }
    pthread_mutex_unlock(&broker->mutex);
    if (broker->wake_write_fd >= 0)
        (void)write(broker->wake_write_fd, &value, 1u);
    return LIBRDP_STATUS_OK;
}

const char* x11_managed_broker_socket_path(
    const x11_managed_broker* broker)
{
    return broker ? broker->policy.socket_path : NULL;
}

librdp_status x11_managed_broker_run(
    x11_managed_broker* broker)
{
    int wake_descriptors[2] = {-1, -1};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!broker || broker->running)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (pipe(wake_descriptors) != 0 ||
        !x11_managed_broker_set_fd(wake_descriptors[0], 1) ||
        !x11_managed_broker_set_fd(wake_descriptors[1], 1))
    {
        if (wake_descriptors[0] >= 0)
            close(wake_descriptors[0]);
        if (wake_descriptors[1] >= 0)
            close(wake_descriptors[1]);
        return LIBRDP_STATUS_IO_ERROR;
    }
    broker->wake_read_fd = wake_descriptors[0];
    broker->wake_write_fd = wake_descriptors[1];
    status = x11_managed_broker_create_listener(broker);
    if (status != LIBRDP_STATUS_OK)
        return status;
    broker->running = 1;
    broker->preserve_registry = 1;
    x11_managed_broker_recover(broker);
    while (!atomic_load(&broker->cancelled))
    {
        struct pollfd descriptors[2];
        int ready = 0;

        memset(descriptors, 0, sizeof(descriptors));
        descriptors[0].fd = broker->listener_fd;
        descriptors[0].events = POLLIN;
        descriptors[1].fd = broker->wake_read_fd;
        descriptors[1].events = POLLIN;
        ready = poll(descriptors,
                     sizeof(descriptors) / sizeof(descriptors[0]),
                     X11_MANAGED_BROKER_HEALTH_INTERVAL_MS);
        if (ready < 0)
        {
            if (errno == EINTR)
                continue;
            status = LIBRDP_STATUS_IO_ERROR;
            break;
        }
        if ((descriptors[1].revents &
             (POLLIN | POLLERR | POLLHUP)) != 0)
            break;
        if ((descriptors[0].revents & POLLIN) != 0)
        {
            while (x11_managed_broker_accept(broker) ==
                   LIBRDP_STATUS_OK)
            {
            }
        }
        else if ((descriptors[0].revents &
                  (POLLERR | POLLHUP | POLLNVAL)) != 0)
        {
            status = LIBRDP_STATUS_IO_ERROR;
            break;
        }
        x11_managed_broker_health(broker);
    }
    broker->running = 0;
    return status;
}
