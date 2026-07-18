/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * Module: managed-session identity, display and runtime-directory registry.
 * Invariants: occupied slots own one display lock descriptor and one private
 * runtime directory; cleanup releases both before the slot can be reused.
 * Ownership: fixed-capacity entry storage belongs to the registry.
 * Threading: one broker thread serializes all operations.
 * Trust boundary: path components are generated from numeric IDs rather than
 * user text, and existing X sockets or lock files make a display unavailable.
 */

#include "server_managed_registry.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define X11_MANAGED_REGISTRY_CONFIG_VERSION 1u

typedef struct x11_managed_registry_slot
{
    x11_managed_session_entry entry;
    int display_lock_fd;
    int runtime_created;
    int occupied;
} x11_managed_registry_slot;

struct x11_managed_registry
{
    x11_managed_registry_config config;
    char runtime_root[X11_MANAGED_IPC_PATH_BYTES];
    x11_managed_registry_slot* slots;
};

static int x11_managed_registry_copy_string(char* output,
                                            size_t capacity,
                                            const char* input)
{
    size_t length = input ? strlen(input) : 0u;

    if (!output || capacity == 0u || !input || length >= capacity)
        return 0;
    memcpy(output, input, length + 1u);
    return 1;
}

static int x11_managed_registry_safe_username(const char* username)
{
    size_t index = 0u;
    size_t length = username
                        ? strnlen(username,
                                  X11_MANAGED_IPC_USERNAME_BYTES)
                        : 0u;

    if (length == 0u || length >= X11_MANAGED_IPC_USERNAME_BYTES)
        return 0;
    for (index = 0u; index < length; index++)
    {
        unsigned char value = (unsigned char)username[index];

        if (value < 0x21u || value == 0x7fu || value == '/' ||
            value == '\\')
            return 0;
    }
    return 1;
}

static int x11_managed_registry_make_directory(const char* path,
                                                mode_t mode)
{
    struct stat info;

    if (mkdir(path, mode) == 0)
        return 1;
    if (errno != EEXIST || lstat(path, &info) != 0 ||
        !S_ISDIR(info.st_mode) || S_ISLNK(info.st_mode))
        return 0;
    return 1;
}

static int x11_managed_registry_path(char* output,
                                     size_t capacity,
                                     const char* root,
                                     const char* format,
                                     unsigned long long value)
{
    int length = 0;

    if (!output || capacity == 0u || !root || !format)
        return 0;
    length = snprintf(output, capacity, format, root, value);
    return length >= 0 && (size_t)length < capacity;
}

static int x11_managed_registry_join(char* output,
                                     size_t capacity,
                                     const char* directory,
                                     const char* name)
{
    int length = 0;

    if (!output || capacity == 0u || !directory || !name ||
        name[0] == '\0' || strchr(name, '/'))
        return 0;
    length = snprintf(output, capacity, "%s/%s", directory, name);
    return length >= 0 && (size_t)length < capacity;
}

static int x11_managed_registry_display_busy(uint32_t display)
{
    char path[128];
    struct stat info;
    int length = snprintf(path,
                          sizeof(path),
                          "/tmp/.X11-unix/X%u",
                          display);

    if (length < 0 || (size_t)length >= sizeof(path))
        return 1;
    if (lstat(path, &info) == 0)
        return 1;
    length = snprintf(path, sizeof(path), "/tmp/.X%u-lock", display);
    if (length < 0 || (size_t)length >= sizeof(path))
        return 1;
    return lstat(path, &info) == 0;
}

static int x11_managed_registry_lock_display(
    x11_managed_registry* registry,
    uint32_t display,
    char* path,
    size_t path_capacity)
{
    int descriptor = -1;

    if (!x11_managed_registry_path(path,
                                   path_capacity,
                                   registry->runtime_root,
                                   "%s/display-%llu.lock",
                                   (unsigned long long)display))
        return -1;
    descriptor = open(path,
                      O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC |
                          O_NOFOLLOW,
                      0600);
    if (descriptor < 0)
        return -1;
    if (x11_managed_registry_display_busy(display))
    {
        close(descriptor);
        unlink(path);
        return -1;
    }
    return descriptor;
}

static uint64_t x11_managed_registry_random_id(
    const x11_managed_registry* registry)
{
    uint64_t value = 0u;
    size_t attempt = 0u;

    for (attempt = 0u; attempt < 64u; attempt++)
    {
        size_t index = 0u;
        int collision = 0;

        if (RAND_bytes((unsigned char*)&value, (int)sizeof(value)) != 1 ||
            value == 0u)
            continue;
        for (index = 0u; index < registry->config.max_sessions; index++)
        {
            if (registry->slots[index].occupied &&
                registry->slots[index].entry.session_id == value)
            {
                collision = 1;
                break;
            }
        }
        if (!collision)
            return value;
    }
    return 0u;
}

static uint32_t x11_managed_registry_user_count(
    const x11_managed_registry* registry,
    uid_t uid)
{
    uint32_t count = 0u;
    size_t index = 0u;

    for (index = 0u; index < registry->config.max_sessions; index++)
    {
        if (registry->slots[index].occupied &&
            registry->slots[index].entry.uid == uid)
            count++;
    }
    return count;
}

static x11_managed_registry_slot* x11_managed_registry_slot_by_id(
    x11_managed_registry* registry,
    uint64_t session_id)
{
    size_t index = 0u;

    if (!registry || session_id == 0u)
        return NULL;
    for (index = 0u; index < registry->config.max_sessions; index++)
    {
        if (registry->slots[index].occupied &&
            registry->slots[index].entry.session_id == session_id)
            return &registry->slots[index];
    }
    return NULL;
}

static void x11_managed_registry_remove_tree(
    const x11_managed_session_entry* entry)
{
    if (!entry)
        return;
    if (entry->agent_socket_path[0] != '\0')
        (void)unlink(entry->agent_socket_path);
    if (entry->authority_path[0] != '\0')
        (void)unlink(entry->authority_path);
    if (entry->runtime_directory[0] != '\0')
        (void)rmdir(entry->runtime_directory);
}

static void x11_managed_registry_clear_slot(
    x11_managed_registry* registry,
    x11_managed_registry_slot* slot)
{
    char lock_path[X11_MANAGED_IPC_PATH_BYTES];

    if (!registry || !slot || !slot->occupied)
        return;
    if (slot->runtime_created)
        x11_managed_registry_remove_tree(&slot->entry);
    if (slot->display_lock_fd >= 0)
        (void)close(slot->display_lock_fd);
    if (x11_managed_registry_path(
            lock_path,
            sizeof(lock_path),
            registry->runtime_root,
            "%s/display-%llu.lock",
            (unsigned long long)slot->entry.display_number))
        (void)unlink(lock_path);
    OPENSSL_cleanse(&slot->entry, sizeof(slot->entry));
    slot->display_lock_fd = -1;
    slot->runtime_created = 0;
    slot->occupied = 0;
}

void x11_managed_registry_config_init(
    x11_managed_registry_config* config)
{
    if (!config)
        return;
    memset(config, 0, sizeof(*config));
    config->version = X11_MANAGED_REGISTRY_CONFIG_VERSION;
    config->size = sizeof(*config);
    config->runtime_root = "/run/librdp/x11-sessions";
    config->max_sessions = 32u;
    config->max_sessions_per_user = 2u;
    config->first_display = X11_MANAGED_REGISTRY_MIN_DISPLAY;
    config->last_display = 199u;
    config->idle_timeout_ns = 30u * 60u * 1000000000u;
    config->max_duration_ns = 24u * 60u * 60u * 1000000000u;
    config->allow_reconnect = 1;
}

static int x11_managed_registry_config_valid(
    const x11_managed_registry_config* config)
{
    size_t root_length = config && config->runtime_root
                             ? strlen(config->runtime_root)
                             : 0u;

    return config &&
           config->version == X11_MANAGED_REGISTRY_CONFIG_VERSION &&
           config->size >= sizeof(*config) &&
           root_length > 0u &&
           root_length < X11_MANAGED_IPC_PATH_BYTES &&
           config->max_sessions > 0u &&
           config->max_sessions <= X11_MANAGED_REGISTRY_MAX_SESSIONS &&
           config->max_sessions_per_user > 0u &&
           config->max_sessions_per_user <=
               X11_MANAGED_REGISTRY_MAX_PER_USER &&
           config->max_sessions_per_user <= config->max_sessions &&
           config->first_display >= X11_MANAGED_REGISTRY_MIN_DISPLAY &&
           config->last_display <= X11_MANAGED_REGISTRY_MAX_DISPLAY &&
           config->first_display <= config->last_display;
}

x11_managed_registry* x11_managed_registry_new(
    const x11_managed_registry_config* config)
{
    x11_managed_registry* registry = NULL;
    size_t index = 0u;

    if (!x11_managed_registry_config_valid(config) ||
        !x11_managed_registry_make_directory(config->runtime_root, 0711))
        return NULL;
    registry = (x11_managed_registry*)calloc(1u, sizeof(*registry));
    if (!registry)
        return NULL;
    registry->slots = (x11_managed_registry_slot*)calloc(
        config->max_sessions, sizeof(*registry->slots));
    if (!registry->slots)
    {
        free(registry);
        return NULL;
    }
    registry->config = *config;
    registry->config.runtime_root = registry->runtime_root;
    if (!x11_managed_registry_copy_string(registry->runtime_root,
                                          sizeof(registry->runtime_root),
                                          config->runtime_root))
    {
        free(registry->slots);
        free(registry);
        return NULL;
    }
    for (index = 0u; index < config->max_sessions; index++)
        registry->slots[index].display_lock_fd = -1;
    return registry;
}

void x11_managed_registry_free(x11_managed_registry* registry)
{
    size_t index = 0u;

    if (!registry)
        return;
    for (index = 0u; index < registry->config.max_sessions; index++)
        x11_managed_registry_clear_slot(registry,
                                        &registry->slots[index]);
    free(registry->slots);
    OPENSSL_cleanse(registry, sizeof(*registry));
    free(registry);
}

size_t x11_managed_registry_count(
    const x11_managed_registry* registry)
{
    size_t count = 0u;
    size_t index = 0u;

    if (!registry)
        return 0u;
    for (index = 0u; index < registry->config.max_sessions; index++)
    {
        if (registry->slots[index].occupied)
            count++;
    }
    return count;
}

static librdp_status x11_managed_registry_prepare_entry(
    x11_managed_registry* registry,
    x11_managed_registry_slot* slot,
    const x11_managed_ipc_message* request,
    uid_t uid,
    gid_t gid,
    uint64_t now_ns)
{
    uint32_t display = 0u;
    char lock_path[X11_MANAGED_IPC_PATH_BYTES];
    int length = 0;

    memset(&slot->entry, 0, sizeof(slot->entry));
    slot->display_lock_fd = -1;
    slot->entry.session_id =
        x11_managed_registry_random_id(registry);
    if (slot->entry.session_id == 0u ||
        x11_managed_ipc_generate_token(
            slot->entry.reconnect_token) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_IO_ERROR;
    for (display = registry->config.first_display;
         display <= registry->config.last_display;
         display++)
    {
        slot->display_lock_fd =
            x11_managed_registry_lock_display(registry,
                                              display,
                                              lock_path,
                                              sizeof(lock_path));
        if (slot->display_lock_fd >= 0)
            break;
    }
    if (slot->display_lock_fd < 0)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    slot->entry.display_number = display;
    slot->occupied = 1;
    length = snprintf(slot->entry.display_name,
                      sizeof(slot->entry.display_name),
                      ":%u",
                      display);
    if (length < 0 ||
        (size_t)length >= sizeof(slot->entry.display_name) ||
        !x11_managed_registry_path(
            slot->entry.runtime_directory,
            sizeof(slot->entry.runtime_directory),
            registry->runtime_root,
            "%s/session-%016llx",
            (unsigned long long)slot->entry.session_id) ||
        !x11_managed_registry_join(
            slot->entry.authority_path,
            sizeof(slot->entry.authority_path),
            slot->entry.runtime_directory,
            "Xauthority") ||
        !x11_managed_registry_path(
            slot->entry.agent_socket_path,
            sizeof(slot->entry.agent_socket_path),
            registry->runtime_root,
            "%s/session-%016llx.sock",
            (unsigned long long)slot->entry.session_id) ||
        mkdir(slot->entry.runtime_directory, 0700) != 0)
        return LIBRDP_STATUS_IO_ERROR;
    slot->runtime_created = 1;
    if (chown(slot->entry.runtime_directory, uid, gid) != 0 &&
        (uid != geteuid() || gid != getegid()))
        return LIBRDP_STATUS_IO_ERROR;
    slot->entry.uid = uid;
    slot->entry.gid = gid;
    slot->entry.created_ns = now_ns;
    slot->entry.last_activity_ns = now_ns;
    slot->entry.idle_timeout_ns =
        request->idle_timeout_ns != 0u
            ? request->idle_timeout_ns
            : registry->config.idle_timeout_ns;
    slot->entry.max_duration_ns =
        request->max_duration_ns != 0u
            ? request->max_duration_ns
            : registry->config.max_duration_ns;
    slot->entry.width = request->width;
    slot->entry.height = request->height;
    slot->entry.flags = request->flags;
    slot->entry.state = X11_MANAGED_SESSION_RESERVED;
    if (!x11_managed_registry_copy_string(
            slot->entry.username,
            sizeof(slot->entry.username),
            request->username))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return LIBRDP_STATUS_OK;
}

librdp_status x11_managed_registry_reserve(
    x11_managed_registry* registry,
    const x11_managed_ipc_message* request,
    uid_t uid,
    gid_t gid,
    uint64_t now_ns,
    x11_managed_session_entry** entry)
{
    size_t index = 0u;
    x11_managed_registry_slot* slot = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!registry || !request || !entry || now_ns == 0u ||
        request->type != X11_MANAGED_IPC_START ||
        x11_managed_ipc_message_validate(request) != LIBRDP_STATUS_OK ||
        !x11_managed_registry_safe_username(request->username))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *entry = NULL;
    if (x11_managed_registry_count(registry) >=
            registry->config.max_sessions ||
        x11_managed_registry_user_count(registry, uid) >=
            registry->config.max_sessions_per_user)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    for (index = 0u; index < registry->config.max_sessions; index++)
    {
        if (!registry->slots[index].occupied)
        {
            slot = &registry->slots[index];
            break;
        }
    }
    if (!slot)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    status = x11_managed_registry_prepare_entry(registry,
                                                slot,
                                                request,
                                                uid,
                                                gid,
                                                now_ns);
    if (status != LIBRDP_STATUS_OK)
    {
        x11_managed_registry_clear_slot(registry, slot);
        return status;
    }
    *entry = &slot->entry;
    return LIBRDP_STATUS_OK;
}

x11_managed_session_entry* x11_managed_registry_find(
    x11_managed_registry* registry,
    uint64_t session_id,
    uid_t uid)
{
    x11_managed_registry_slot* slot =
        x11_managed_registry_slot_by_id(registry, session_id);

    if (!slot || slot->entry.uid != uid)
        return NULL;
    return &slot->entry;
}

x11_managed_session_entry* x11_managed_registry_find_token(
    x11_managed_registry* registry,
    const char* token,
    uid_t uid)
{
    size_t index = 0u;

    if (!registry || !token)
        return NULL;
    for (index = 0u; index < registry->config.max_sessions; index++)
    {
        x11_managed_registry_slot* slot = &registry->slots[index];

        if (slot->occupied && slot->entry.uid == uid &&
            x11_managed_ipc_token_equal(slot->entry.reconnect_token,
                                        token))
            return &slot->entry;
    }
    return NULL;
}

librdp_status x11_managed_registry_mark_starting(
    x11_managed_registry* registry,
    uint64_t session_id,
    pid_t supervisor_pid)
{
    x11_managed_registry_slot* slot =
        x11_managed_registry_slot_by_id(registry, session_id);

    if (!slot || supervisor_pid <= 0 ||
        slot->entry.state != X11_MANAGED_SESSION_RESERVED)
        return LIBRDP_STATUS_STATE;
    slot->entry.supervisor_pid = supervisor_pid;
    slot->entry.state = X11_MANAGED_SESSION_STARTING;
    return LIBRDP_STATUS_OK;
}

librdp_status x11_managed_registry_mark_active(
    x11_managed_registry* registry,
    uint64_t session_id,
    pid_t agent_pid,
    pid_t xserver_pid,
    pid_t desktop_pid,
    uint32_t port,
    uint64_t now_ns)
{
    x11_managed_registry_slot* slot =
        x11_managed_registry_slot_by_id(registry, session_id);

    if (!slot || agent_pid <= 0 || xserver_pid <= 0 ||
        desktop_pid <= 0 || port == 0u || port > UINT16_MAX ||
        now_ns < slot->entry.created_ns ||
        slot->entry.state != X11_MANAGED_SESSION_STARTING)
        return LIBRDP_STATUS_STATE;
    slot->entry.agent_pid = agent_pid;
    slot->entry.xserver_pid = xserver_pid;
    slot->entry.desktop_pid = desktop_pid;
    slot->entry.port = port;
    slot->entry.last_activity_ns = now_ns;
    slot->entry.state = X11_MANAGED_SESSION_ACTIVE;
    return LIBRDP_STATUS_OK;
}

librdp_status x11_managed_registry_attach(
    x11_managed_registry* registry,
    uint64_t session_id,
    uint64_t now_ns)
{
    x11_managed_registry_slot* slot =
        x11_managed_registry_slot_by_id(registry, session_id);

    if (!slot || now_ns < slot->entry.created_ns ||
        (slot->entry.state != X11_MANAGED_SESSION_ACTIVE &&
         slot->entry.state != X11_MANAGED_SESSION_DETACHED) ||
        slot->entry.attachment_count == UINT32_MAX)
        return LIBRDP_STATUS_STATE;
    slot->entry.attachment_count++;
    slot->entry.last_activity_ns = now_ns;
    slot->entry.state = X11_MANAGED_SESSION_ACTIVE;
    return LIBRDP_STATUS_OK;
}

librdp_status x11_managed_registry_detach(
    x11_managed_registry* registry,
    uint64_t session_id,
    uint64_t now_ns)
{
    x11_managed_registry_slot* slot =
        x11_managed_registry_slot_by_id(registry, session_id);

    if (!slot || now_ns < slot->entry.created_ns ||
        slot->entry.state != X11_MANAGED_SESSION_ACTIVE ||
        slot->entry.attachment_count == 0u)
        return LIBRDP_STATUS_STATE;
    slot->entry.attachment_count--;
    slot->entry.last_activity_ns = now_ns;
    if (slot->entry.attachment_count == 0u)
        slot->entry.state = X11_MANAGED_SESSION_DETACHED;
    return LIBRDP_STATUS_OK;
}

librdp_status x11_managed_registry_resize(
    x11_managed_registry* registry,
    uint64_t session_id,
    uint32_t width,
    uint32_t height,
    uint64_t now_ns)
{
    x11_managed_registry_slot* slot =
        x11_managed_registry_slot_by_id(registry, session_id);

    if (!slot || width == 0u || height == 0u ||
        width > 16384u || height > 16384u ||
        now_ns < slot->entry.created_ns ||
        (slot->entry.state != X11_MANAGED_SESSION_ACTIVE &&
         slot->entry.state != X11_MANAGED_SESSION_DETACHED))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    slot->entry.width = width;
    slot->entry.height = height;
    slot->entry.last_activity_ns = now_ns;
    return LIBRDP_STATUS_OK;
}

int x11_managed_registry_expired(
    const x11_managed_session_entry* entry,
    uint64_t now_ns)
{
    if (!entry || now_ns < entry->created_ns)
        return 1;
    if (entry->max_duration_ns != 0u &&
        now_ns - entry->created_ns >= entry->max_duration_ns)
        return 1;
    return entry->state == X11_MANAGED_SESSION_DETACHED &&
           entry->idle_timeout_ns != 0u &&
           now_ns >= entry->last_activity_ns &&
           now_ns - entry->last_activity_ns >=
               entry->idle_timeout_ns;
}

librdp_status x11_managed_registry_release(
    x11_managed_registry* registry,
    uint64_t session_id)
{
    x11_managed_registry_slot* slot =
        x11_managed_registry_slot_by_id(registry, session_id);

    if (!slot)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    x11_managed_registry_clear_slot(registry, slot);
    return LIBRDP_STATUS_OK;
}
