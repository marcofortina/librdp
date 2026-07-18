/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: FUSE 3 client-drive presentation for the X11 desktop server.
 * Invariants: kernel requests never block the host dispatch thread, each
 * accepted request has one correlated completion, and inode/file tokens never
 * cross peer generations.
 * Ownership: the provider owns mount state, copied paths, node and handle
 * tables, directory caches and pending FUSE requests.
 * Threading: the custom FUSE loop and all RDP completions execute on the common
 * server-host owner thread.
 * Trust boundary: remote names, metadata, byte counts and status values remain
 * untrusted until validated before a FUSE reply.
 */

#include "server_fuse.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef LIBRDP_HAVE_FUSE3

#define FUSE_USE_VERSION 35
#include <fuse3/fuse_lowlevel.h>
#include <fuse3/fuse_opt.h>

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#define X11_SERVER_FUSE_MAX_NAME_BYTES 255u
#define X11_SERVER_FUSE_MAX_PATH_BYTES 4096u
#define X11_SERVER_FUSE_MAX_CLIPBOARD_URI_BYTES (16u * 1024u * 1024u)
#define X11_SERVER_FUSE_MAX_REPLY_BYTES X11_SERVER_FUSE_DEFAULT_MAX_READ_BYTES
#define X11_SERVER_FUSE_FILE_GENERIC_READ 0x00120089u
#define X11_SERVER_FUSE_FILE_SHARE_ALL 0x00000007u
#define X11_SERVER_FUSE_FILE_OPEN 0x00000001u
#define X11_SERVER_FUSE_FILE_DIRECTORY 0x00000001u
#define X11_SERVER_FUSE_FILE_NON_DIRECTORY 0x00000040u
#define X11_SERVER_FUSE_FILE_ATTRIBUTE_NORMAL 0x00000080u
#define X11_SERVER_FUSE_UNIX_EPOCH_FILETIME 116444736000000000ull
#define X11_SERVER_FUSE_FILETIME_UNITS_PER_SECOND 10000000ull

typedef enum x11_server_fuse_node_kind
{
    X11_SERVER_FUSE_NODE_ROOT = 1,
    X11_SERVER_FUSE_NODE_PEER = 2,
    X11_SERVER_FUSE_NODE_VOLUME = 3,
    X11_SERVER_FUSE_NODE_REMOTE = 4,
    X11_SERVER_FUSE_NODE_CLIPBOARD_DIRECTORY = 5,
    X11_SERVER_FUSE_NODE_CLIPBOARD_FILE = 6
} x11_server_fuse_node_kind;

typedef enum x11_server_fuse_pending_kind
{
    X11_SERVER_FUSE_PENDING_LOOKUP = 1,
    X11_SERVER_FUSE_PENDING_OPEN = 2,
    X11_SERVER_FUSE_PENDING_OPENDIR = 3,
    X11_SERVER_FUSE_PENDING_READ = 4,
    X11_SERVER_FUSE_PENDING_RELEASE = 5,
    X11_SERVER_FUSE_PENDING_RELEASEDIR = 6,
    X11_SERVER_FUSE_PENDING_READDIR = 7,
    X11_SERVER_FUSE_PENDING_CLIPBOARD_READ = 8
} x11_server_fuse_pending_kind;

typedef enum x11_server_fuse_pending_stage
{
    X11_SERVER_FUSE_STAGE_OPEN = 1,
    X11_SERVER_FUSE_STAGE_QUERY = 2,
    X11_SERVER_FUSE_STAGE_CLOSE = 3,
    X11_SERVER_FUSE_STAGE_IO = 4
} x11_server_fuse_pending_stage;

typedef struct x11_server_fuse_node
{
    fuse_ino_t inode;
    fuse_ino_t parent;
    uint64_t volume_id;
    uint64_t lookup_count;
    uint32_t peer_id;
    uint32_t generation;
    librdp_server_drive_device_handle device;
    librdp_server_drive_metadata metadata;
    uint64_t clipboard_generation;
    int32_t clipboard_file_index;
    char* name;
    char* path;
    x11_server_fuse_node_kind kind;
    int valid;
    int metadata_valid;
} x11_server_fuse_node;

typedef struct x11_server_fuse_handle
{
    uint64_t id;
    fuse_ino_t inode;
    librdp_server_drive_file_handle remote;
    fuse_ino_t* directory_entries;
    size_t directory_count;
    uint32_t query_count;
    int directory;
    int local;
    int directory_loaded;
    int closing;
    int occupied;
} x11_server_fuse_handle;

typedef struct x11_server_fuse_pending
{
    uint64_t request_id;
    fuse_req_t request;
    fuse_ino_t inode;
    fuse_ino_t parent;
    uint64_t handle_id;
    librdp_server_drive_file_handle temporary_file;
    struct fuse_file_info file_info;
    size_t requested_size;
    off_t requested_offset;
    uint32_t stream_id;
    int terminal_error;
    char name[X11_SERVER_FUSE_MAX_NAME_BYTES + 1u];
    x11_server_fuse_pending_kind kind;
    x11_server_fuse_pending_stage stage;
    int occupied;
} x11_server_fuse_pending;

typedef struct x11_server_fuse_clipboard_entry
{
    librdp_clipboard_file_metadata metadata;
    char name[X11_SERVER_FUSE_MAX_NAME_BYTES + 1u];
} x11_server_fuse_clipboard_entry;

struct x11_server_fuse
{
    x11_server_fuse_config config;
    char* mount_path;
    struct fuse_session* session;
    server_platform_drive_sink sink;
    server_platform_clipboard_file_request_callback clipboard_request;
    server_platform_clipboard_cancel_callback clipboard_cancel;
    void* clipboard_user_data;
    x11_server_fuse_node* nodes;
    x11_server_fuse_handle* handles;
    x11_server_fuse_pending* pending;
    uint64_t next_inode;
    uint64_t next_handle_id;
    uint64_t next_request_id;
    uint32_t clipboard_peer_id;
    uint32_t clipboard_peer_generation;
    uint64_t clipboard_generation;
    int descriptor_ready;
    int descriptor_failed;
    int started;
    int mounted;
};

static char* x11_server_fuse_copy_string(const char* value)
{
    size_t length = value ? strlen(value) : 0u;
    char* copy = NULL;

    if (!value || length == SIZE_MAX)
        return NULL;
    copy = (char*)malloc(length + 1u);
    if (!copy)
        return NULL;
    memcpy(copy, value, length + 1u);
    return copy;
}

static int x11_server_fuse_name_valid(const char* name)
{
    size_t length = 0u;

    if (!name || name[0] == '\0')
        return 0;
    while (length <= X11_SERVER_FUSE_MAX_NAME_BYTES && name[length] != '\0')
    {
        if (name[length] == '/' || name[length] == '\\')
            return 0;
        length++;
    }
    return length > 0u && length <= X11_SERVER_FUSE_MAX_NAME_BYTES &&
           strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}

static int x11_server_fuse_mount_path_secure(const char* path)
{
    struct stat status;
    DIR* directory = NULL;
    struct dirent* entry = NULL;
    int empty = 1;

    if (!path || path[0] != '/' || lstat(path, &status) != 0 ||
        !S_ISDIR(status.st_mode) || status.st_uid != geteuid() ||
        (status.st_mode & 0077u) != 0u)
        return 0;
    directory = opendir(path);
    if (!directory)
        return 0;
    while ((entry = readdir(directory)) != NULL)
    {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
        {
            empty = 0;
            break;
        }
    }
    closedir(directory);
    return empty;
}

static int x11_server_fuse_config_valid(const x11_server_fuse_config* config)
{
    return config && config->version == X11_SERVER_FUSE_CONFIG_VERSION &&
           config->size >= sizeof(*config) && config->mount_path &&
           config->mount_path[0] != '\0' &&
           strlen(config->mount_path) <= X11_SERVER_FUSE_MAX_PATH_BYTES &&
           config->max_nodes >= 4u &&
           config->max_handles > 0u && config->max_pending > 0u &&
           config->max_directory_entries > 0u &&
           config->max_directory_entries <= config->max_nodes &&
           config->max_read_bytes > 0u &&
           config->max_read_bytes <= X11_SERVER_FUSE_MAX_REPLY_BYTES &&
           config->read_only == 1;
}

static x11_server_fuse_node* x11_server_fuse_find_node(
    const x11_server_fuse* provider, fuse_ino_t inode)
{
    uint32_t index = 0u;

    if (!provider || inode == 0u)
        return NULL;
    for (index = 0u; index < provider->config.max_nodes; index++)
    {
        x11_server_fuse_node* node = &provider->nodes[index];

        if (node->valid && node->inode == inode)
            return node;
    }
    return NULL;
}

static x11_server_fuse_node* x11_server_fuse_find_child(
    const x11_server_fuse* provider, fuse_ino_t parent, const char* name)
{
    uint32_t index = 0u;

    if (!provider || parent == 0u || !name)
        return NULL;
    for (index = 0u; index < provider->config.max_nodes; index++)
    {
        x11_server_fuse_node* node = &provider->nodes[index];

        if (node->valid && node->parent == parent && node->name &&
            strcmp(node->name, name) == 0)
            return node;
    }
    return NULL;
}

static x11_server_fuse_node* x11_server_fuse_find_volume(
    const x11_server_fuse* provider, uint64_t volume_id)
{
    uint32_t index = 0u;

    if (!provider || volume_id == 0u)
        return NULL;
    for (index = 0u; index < provider->config.max_nodes; index++)
    {
        x11_server_fuse_node* node = &provider->nodes[index];

        if (node->valid && node->kind == X11_SERVER_FUSE_NODE_VOLUME &&
            node->volume_id == volume_id)
            return node;
    }
    return NULL;
}

static x11_server_fuse_node* x11_server_fuse_volume_for_node(
    const x11_server_fuse* provider, const x11_server_fuse_node* node)
{
    if (!node)
        return NULL;
    if (node->kind == X11_SERVER_FUSE_NODE_VOLUME)
        return (x11_server_fuse_node*)node;
    return x11_server_fuse_find_volume(provider, node->volume_id);
}

static x11_server_fuse_handle* x11_server_fuse_find_handle(
    const x11_server_fuse* provider, uint64_t id)
{
    uint32_t index = 0u;

    if (!provider || id == 0u)
        return NULL;
    for (index = 0u; index < provider->config.max_handles; index++)
    {
        x11_server_fuse_handle* handle = &provider->handles[index];

        if (handle->occupied && handle->id == id)
            return handle;
    }
    return NULL;
}

static x11_server_fuse_pending* x11_server_fuse_find_pending(
    const x11_server_fuse* provider, uint64_t request_id)
{
    uint32_t index = 0u;

    if (!provider || request_id == 0u)
        return NULL;
    for (index = 0u; index < provider->config.max_pending; index++)
    {
        x11_server_fuse_pending* pending = &provider->pending[index];

        if (pending->occupied && pending->request_id == request_id)
            return pending;
    }
    return NULL;
}

static x11_server_fuse_pending* x11_server_fuse_allocate_pending(
    x11_server_fuse* provider, fuse_req_t request,
    x11_server_fuse_pending_kind kind)
{
    uint32_t index = 0u;

    if (!provider || !request)
        return NULL;
    for (index = 0u; index < provider->config.max_pending; index++)
    {
        x11_server_fuse_pending* pending = &provider->pending[index];

        if (pending->occupied)
            continue;
        memset(pending, 0, sizeof(*pending));
        pending->request = request;
        pending->kind = kind;
        pending->occupied = 1;
        return pending;
    }
    return NULL;
}

static void x11_server_fuse_clear_pending(x11_server_fuse_pending* pending)
{
    if (pending)
        memset(pending, 0, sizeof(*pending));
}

static x11_server_fuse_handle* x11_server_fuse_allocate_handle(
    x11_server_fuse* provider, fuse_ino_t inode, int directory, int local)
{
    uint32_t index = 0u;

    if (!provider || inode == 0u)
        return NULL;
    for (index = 0u; index < provider->config.max_handles; index++)
    {
        x11_server_fuse_handle* handle = &provider->handles[index];

        if (handle->occupied)
            continue;
        memset(handle, 0, sizeof(*handle));
        handle->id = provider->next_handle_id++;
        if (handle->id == 0u)
            handle->id = provider->next_handle_id++;
        handle->inode = inode;
        handle->directory = directory;
        handle->local = local;
        handle->occupied = 1;
        return handle;
    }
    return NULL;
}

static void x11_server_fuse_clear_handle(x11_server_fuse_handle* handle)
{
    if (!handle)
        return;
    free(handle->directory_entries);
    memset(handle, 0, sizeof(*handle));
}

static int x11_server_fuse_join_path(
    const char* parent, const char* name,
    char output[X11_SERVER_FUSE_MAX_PATH_BYTES + 1u])
{
    size_t parent_len = parent ? strlen(parent) : 0u;
    size_t name_len = name ? strlen(name) : 0u;
    size_t separator = parent_len > 0u ? 1u : 0u;

    if (!name || !x11_server_fuse_name_valid(name) ||
        parent_len > X11_SERVER_FUSE_MAX_PATH_BYTES ||
        name_len > X11_SERVER_FUSE_MAX_PATH_BYTES - parent_len - separator)
        return 0;
    if (parent_len > 0u)
        memcpy(output, parent, parent_len);
    if (separator != 0u)
        output[parent_len] = '/';
    memcpy(output + parent_len + separator, name, name_len);
    output[parent_len + separator + name_len] = '\0';
    return 1;
}

static x11_server_fuse_node* x11_server_fuse_allocate_node(
    x11_server_fuse* provider, x11_server_fuse_node_kind kind,
    fuse_ino_t parent, const char* name, const char* path)
{
    uint32_t index = 0u;
    x11_server_fuse_node* node = NULL;

    if (!provider || kind < X11_SERVER_FUSE_NODE_PEER ||
        kind > X11_SERVER_FUSE_NODE_CLIPBOARD_FILE ||
        !x11_server_fuse_name_valid(name) || !path ||
        strlen(path) > X11_SERVER_FUSE_MAX_PATH_BYTES)
        return NULL;
    for (index = 1u; index < provider->config.max_nodes; index++)
    {
        if (!provider->nodes[index].valid)
        {
            node = &provider->nodes[index];
            break;
        }
    }
    if (!node)
        return NULL;
    node->name = x11_server_fuse_copy_string(name);
    node->path = x11_server_fuse_copy_string(path);
    if (!node->name || !node->path)
    {
        free(node->name);
        free(node->path);
        memset(node, 0, sizeof(*node));
        return NULL;
    }
    node->inode = (fuse_ino_t)provider->next_inode++;
    if (node->inode <= FUSE_ROOT_ID)
        node->inode = (fuse_ino_t)provider->next_inode++;
    node->parent = parent;
    node->kind = kind;
    node->valid = 1;
    (void)librdp_server_drive_metadata_init(&node->metadata);
    return node;
}

static void x11_server_fuse_invalidate_node(x11_server_fuse* provider,
                                            x11_server_fuse_node* node)
{
    if (!provider || !node || !node->valid ||
        node->kind == X11_SERVER_FUSE_NODE_ROOT)
        return;
    if (provider->mounted)
        (void)fuse_lowlevel_notify_inval_inode(provider->session, node->inode,
                                               0, 0);
    free(node->name);
    free(node->path);
    memset(node, 0, sizeof(*node));
}

static uint64_t x11_server_fuse_filetime_seconds(uint64_t value)
{
    if (value <= X11_SERVER_FUSE_UNIX_EPOCH_FILETIME)
        return 0u;
    return (value - X11_SERVER_FUSE_UNIX_EPOCH_FILETIME) /
           X11_SERVER_FUSE_FILETIME_UNITS_PER_SECOND;
}

static void x11_server_fuse_node_stat(const x11_server_fuse_node* node,
                                      struct stat* status)
{
    uint64_t seconds = 0u;
    int directory = 1;

    memset(status, 0, sizeof(*status));
    if (!node)
        return;
    if ((node->kind == X11_SERVER_FUSE_NODE_REMOTE ||
         node->kind == X11_SERVER_FUSE_NODE_CLIPBOARD_FILE) &&
        node->metadata_valid)
        directory = node->metadata.directory != 0u;
    status->st_ino = node->inode;
    status->st_uid = geteuid();
    status->st_gid = getegid();
    status->st_mode = directory ? (S_IFDIR | 0500) : (S_IFREG | 0400);
    status->st_nlink = directory ? 2u : 1u;
    if (node->metadata_valid)
    {
        status->st_size = node->metadata.file_size > (uint64_t)INT64_MAX
                              ? INT64_MAX
                              : (off_t)node->metadata.file_size;
        status->st_blocks =
            (blkcnt_t)((node->metadata.allocation_size + 511u) / 512u);
        seconds = x11_server_fuse_filetime_seconds(node->metadata.access_time);
        status->st_atime =
            seconds > (uint64_t)INT64_MAX ? (time_t)INT64_MAX : (time_t)seconds;
        seconds = x11_server_fuse_filetime_seconds(node->metadata.write_time);
        status->st_mtime =
            seconds > (uint64_t)INT64_MAX ? (time_t)INT64_MAX : (time_t)seconds;
        seconds = x11_server_fuse_filetime_seconds(node->metadata.change_time);
        status->st_ctime =
            seconds > (uint64_t)INT64_MAX ? (time_t)INT64_MAX : (time_t)seconds;
    }
}

static int x11_server_fuse_node_is_directory(
    const x11_server_fuse_node* node)
{
    if (!node)
        return 0;
    if (node->kind == X11_SERVER_FUSE_NODE_REMOTE ||
        node->kind == X11_SERVER_FUSE_NODE_CLIPBOARD_FILE)
        return node->metadata_valid && node->metadata.directory != 0u;
    return 1;
}

static void x11_server_fuse_reply_entry(fuse_req_t request,
                                        x11_server_fuse_node* node)
{
    struct fuse_entry_param entry;

    memset(&entry, 0, sizeof(entry));
    entry.ino = node->inode;
    entry.generation = node->generation;
    entry.attr_timeout = 0.25;
    entry.entry_timeout = 0.25;
    x11_server_fuse_node_stat(node, &entry.attr);
    node->lookup_count++;
    (void)fuse_reply_entry(request, &entry);
}

static int x11_server_fuse_status_errno(librdp_status status)
{
    switch (status)
    {
    case LIBRDP_STATUS_OK:
        return 0;
    case LIBRDP_STATUS_INVALID_ARGUMENT:
        return EINVAL;
    case LIBRDP_STATUS_NO_MEMORY:
        return ENOMEM;
    case LIBRDP_STATUS_UNSUPPORTED:
        return ENOTSUP;
    case LIBRDP_STATUS_LIMIT_EXCEEDED:
        return ENOSPC;
    case LIBRDP_STATUS_TIMEOUT:
        return ETIMEDOUT;
    case LIBRDP_STATUS_AGAIN:
        return EBUSY;
    case LIBRDP_STATUS_CANCELLED:
        return ECANCELED;
    case LIBRDP_STATUS_STATE:
        return ESTALE;
    default:
        return EIO;
    }
}

static int x11_server_fuse_io_errno(uint32_t io_status)
{
    switch (librdp_server_drive_classify_io_status(io_status))
    {
    case LIBRDP_SERVER_DRIVE_IO_SUCCESS:
        return 0;
    case LIBRDP_SERVER_DRIVE_IO_NOT_FOUND:
    case LIBRDP_SERVER_DRIVE_IO_NO_MORE_FILES:
        return ENOENT;
    case LIBRDP_SERVER_DRIVE_IO_ACCESS_DENIED:
        return EACCES;
    case LIBRDP_SERVER_DRIVE_IO_ALREADY_EXISTS:
        return EEXIST;
    case LIBRDP_SERVER_DRIVE_IO_NOT_DIRECTORY:
        return ENOTDIR;
    case LIBRDP_SERVER_DRIVE_IO_INVALID:
        return EINVAL;
    case LIBRDP_SERVER_DRIVE_IO_UNSUPPORTED:
        return ENOTSUP;
    case LIBRDP_SERVER_DRIVE_IO_RESOURCE_LIMIT:
        return ENOSPC;
    case LIBRDP_SERVER_DRIVE_IO_ERROR:
    default:
        return EIO;
    }
}

static int x11_server_fuse_completion_errno(
    const server_platform_drive_completion* completion)
{
    if (!completion)
        return EIO;
    if (completion->status != LIBRDP_STATUS_OK)
        return x11_server_fuse_status_errno(completion->status);
    return x11_server_fuse_io_errno(completion->io_status);
}

static uint64_t x11_server_fuse_next_request_id(x11_server_fuse* provider)
{
    uint64_t request_id = provider->next_request_id++;

    if (request_id == 0u)
        request_id = provider->next_request_id++;
    return request_id;
}

static int x11_server_fuse_prepare_request(
    x11_server_fuse* provider, x11_server_fuse_pending* pending,
    const x11_server_fuse_node* node, server_platform_drive_request* request,
    librdp_server_drive_operation operation)
{
    x11_server_fuse_node* volume =
        x11_server_fuse_volume_for_node(provider, node);

    if (!provider || !pending || !node || !request || !volume ||
        !provider->started || !provider->sink.request)
        return 0;
    memset(request, 0, sizeof(*request));
    request->request_id = x11_server_fuse_next_request_id(provider);
    request->volume_id = volume->volume_id;
    request->peer_id = volume->peer_id;
    request->generation = volume->generation;
    if (librdp_server_drive_request_init(&request->operation) !=
        LIBRDP_STATUS_OK)
        return 0;
    request->operation.operation = operation;
    pending->request_id = request->request_id;
    return 1;
}

static int x11_server_fuse_submit_create(x11_server_fuse* provider,
                                         x11_server_fuse_pending* pending,
                                         const x11_server_fuse_node* node,
                                         const char* path, int directory)
{
    server_platform_drive_request request;
    x11_server_fuse_node* volume =
        x11_server_fuse_volume_for_node(provider, node);

    if (!path || !volume ||
        !x11_server_fuse_prepare_request(provider, pending, node, &request,
                                         LIBRDP_SERVER_DRIVE_CREATE))
        return 0;
    request.operation.device = volume->device;
    request.operation.path = path;
    request.operation.desired_access = X11_SERVER_FUSE_FILE_GENERIC_READ;
    request.operation.file_attributes = X11_SERVER_FUSE_FILE_ATTRIBUTE_NORMAL;
    request.operation.shared_access = X11_SERVER_FUSE_FILE_SHARE_ALL;
    request.operation.create_disposition = X11_SERVER_FUSE_FILE_OPEN;
    request.operation.create_options = directory
                                           ? X11_SERVER_FUSE_FILE_DIRECTORY
                                           : X11_SERVER_FUSE_FILE_NON_DIRECTORY;
    pending->stage = X11_SERVER_FUSE_STAGE_OPEN;
    provider->sink.request(&request, provider->sink.user_data);
    return 1;
}

static int x11_server_fuse_submit_query_directory(
    x11_server_fuse* provider, x11_server_fuse_pending* pending,
    const x11_server_fuse_node* node, librdp_server_drive_file_handle file,
    const char* pattern, int initial)
{
    server_platform_drive_request request;

    if (!x11_server_fuse_prepare_request(provider, pending, node, &request,
                                         LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY))
        return 0;
    request.operation.file = file;
    request.operation.information_class =
        LIBRDP_SERVER_DRIVE_FILE_DIRECTORY_INFORMATION;
    request.operation.initial_query = initial ? 1u : 0u;
    request.operation.path = pattern;
    pending->stage = X11_SERVER_FUSE_STAGE_QUERY;
    provider->sink.request(&request, provider->sink.user_data);
    return 1;
}

static int x11_server_fuse_submit_read(x11_server_fuse* provider,
                                       x11_server_fuse_pending* pending,
                                       const x11_server_fuse_node* node,
                                       librdp_server_drive_file_handle file,
                                       uint64_t offset, uint32_t length)
{
    server_platform_drive_request request;

    if (!x11_server_fuse_prepare_request(provider, pending, node, &request,
                                         LIBRDP_SERVER_DRIVE_READ))
        return 0;
    request.operation.file = file;
    request.operation.offset = offset;
    request.operation.length = length;
    pending->stage = X11_SERVER_FUSE_STAGE_IO;
    provider->sink.request(&request, provider->sink.user_data);
    return 1;
}

static int x11_server_fuse_submit_close(x11_server_fuse* provider,
                                        x11_server_fuse_pending* pending,
                                        const x11_server_fuse_node* node,
                                        librdp_server_drive_file_handle file)
{
    server_platform_drive_request request;

    if (!x11_server_fuse_prepare_request(provider, pending, node, &request,
                                         LIBRDP_SERVER_DRIVE_CLOSE))
        return 0;
    request.operation.file = file;
    pending->stage = X11_SERVER_FUSE_STAGE_CLOSE;
    provider->sink.request(&request, provider->sink.user_data);
    return 1;
}

static void x11_server_fuse_reply_pending_error(
    x11_server_fuse_pending* pending, int error)
{
    if (!pending)
        return;
    (void)fuse_reply_err(pending->request, error != 0 ? error : EIO);
    x11_server_fuse_clear_pending(pending);
}

static int x11_server_fuse_clipboard_node_matches(
    const x11_server_fuse_node* node,
    uint32_t peer_id,
    uint32_t generation,
    uint64_t ownership_generation)
{
    return node &&
           (node->kind == X11_SERVER_FUSE_NODE_CLIPBOARD_DIRECTORY ||
            node->kind == X11_SERVER_FUSE_NODE_CLIPBOARD_FILE) &&
           node->peer_id == peer_id && node->generation == generation &&
           node->clipboard_generation == ownership_generation;
}

/*
 * Revoke clipboard-backed kernel state before dropping its inodes. Each
 * outstanding range receives one terminal FUSE error and one correlated
 * protocol cancellation; handles are invalidated before inode reuse.
 */
static void x11_server_fuse_clipboard_clear_internal(
    x11_server_fuse* provider,
    uint32_t peer_id,
    uint32_t generation,
    uint64_t ownership_generation)
{
    uint32_t index = 0u;

    if (!provider || peer_id == 0u || generation == 0u ||
        ownership_generation == 0u)
        return;
    for (index = 0u; index < provider->config.max_pending; index++)
    {
        x11_server_fuse_pending* pending = &provider->pending[index];
        x11_server_fuse_node* node = NULL;

        if (!pending->occupied ||
            pending->kind != X11_SERVER_FUSE_PENDING_CLIPBOARD_READ)
            continue;
        node = x11_server_fuse_find_node(provider, pending->inode);
        if (!x11_server_fuse_clipboard_node_matches(
                node, peer_id, generation, ownership_generation))
            continue;
        if (provider->clipboard_cancel)
        {
            (void)provider->clipboard_cancel(
                peer_id,
                generation,
                ownership_generation,
                pending->request_id,
                provider->clipboard_user_data);
        }
        if (pending->occupied)
            x11_server_fuse_reply_pending_error(pending, ESTALE);
    }
    for (index = 0u; index < provider->config.max_handles; index++)
    {
        x11_server_fuse_handle* handle = &provider->handles[index];
        x11_server_fuse_node* node =
            handle->occupied
                ? x11_server_fuse_find_node(provider, handle->inode)
                : NULL;

        if (x11_server_fuse_clipboard_node_matches(
                node, peer_id, generation, ownership_generation))
            x11_server_fuse_clear_handle(handle);
    }
    for (index = 0u; index < provider->config.max_nodes; index++)
    {
        x11_server_fuse_node* node = &provider->nodes[index];

        if (node->kind == X11_SERVER_FUSE_NODE_CLIPBOARD_FILE &&
            x11_server_fuse_clipboard_node_matches(
                node, peer_id, generation, ownership_generation))
            x11_server_fuse_invalidate_node(provider, node);
    }
    for (index = 0u; index < provider->config.max_nodes; index++)
    {
        x11_server_fuse_node* node = &provider->nodes[index];

        if (node->kind == X11_SERVER_FUSE_NODE_CLIPBOARD_DIRECTORY &&
            x11_server_fuse_clipboard_node_matches(
                node, peer_id, generation, ownership_generation))
            x11_server_fuse_invalidate_node(provider, node);
    }
    if (provider->clipboard_peer_id == peer_id &&
        provider->clipboard_peer_generation == generation &&
        provider->clipboard_generation == ownership_generation)
    {
        provider->clipboard_peer_id = 0u;
        provider->clipboard_peer_generation = 0u;
        provider->clipboard_generation = 0u;
    }
    if (provider->mounted)
    {
        (void)fuse_lowlevel_notify_inval_inode(provider->session,
                                               FUSE_ROOT_ID,
                                               0,
                                               0);
    }
}

static int x11_server_fuse_uri_byte_safe(uint8_t value)
{
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9') || value == '/' || value == '-' ||
           value == '_' || value == '.' || value == '~';
}

static librdp_status x11_server_fuse_append_file_uri(
    uint8_t** output,
    size_t* length,
    const char* path)
{
    static const char prefix[] = "file://";
    static const char hex[] = "0123456789ABCDEF";
    const size_t overhead = sizeof(prefix) - 1u + 2u;
    size_t path_len = path ? strlen(path) : 0u;
    size_t encoded_len = 0u;
    size_t required = 0u;
    size_t index = 0u;
    size_t cursor = 0u;
    uint8_t* resized = NULL;

    if (!output || !length || !path || path[0] != '/')
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (index = 0u; index < path_len; index++)
    {
        size_t bytes =
            x11_server_fuse_uri_byte_safe((uint8_t)path[index]) ? 1u : 3u;

        if (encoded_len > SIZE_MAX - bytes)
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
        encoded_len += bytes;
    }
    if (*length > X11_SERVER_FUSE_MAX_CLIPBOARD_URI_BYTES ||
        overhead > X11_SERVER_FUSE_MAX_CLIPBOARD_URI_BYTES - *length ||
        encoded_len >
            X11_SERVER_FUSE_MAX_CLIPBOARD_URI_BYTES - *length - overhead)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    required = *length + sizeof(prefix) - 1u + encoded_len + 2u;
    resized = (uint8_t*)realloc(*output, required + 1u);
    if (!resized)
        return LIBRDP_STATUS_NO_MEMORY;
    *output = resized;
    cursor = *length;
    memcpy(resized + cursor, prefix, sizeof(prefix) - 1u);
    cursor += sizeof(prefix) - 1u;
    for (index = 0u; index < path_len; index++)
    {
        uint8_t value = (uint8_t)path[index];

        if (x11_server_fuse_uri_byte_safe(value))
            resized[cursor++] = value;
        else
        {
            resized[cursor++] = '%';
            resized[cursor++] = (uint8_t)hex[value >> 4u];
            resized[cursor++] = (uint8_t)hex[value & 0x0fu];
        }
    }
    resized[cursor++] = '\r';
    resized[cursor++] = '\n';
    resized[cursor] = 0u;
    *length = cursor;
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_server_fuse_clipboard_publish_internal(
    x11_server_fuse* provider,
    uint32_t peer_id,
    uint32_t generation,
    uint64_t ownership_generation,
    const void* descriptors,
    size_t descriptors_len,
    uint8_t** uri_list,
    size_t* uri_list_len,
    int require_started)
{
    x11_server_fuse_node* directory = NULL;
    x11_server_fuse_clipboard_entry* entries = NULL;
    uint8_t* output = NULL;
    size_t output_len = 0u;
    uint32_t count = 0u;
    uint32_t index = 0u;
    char directory_name[X11_SERVER_FUSE_MAX_NAME_BYTES + 1u];
    int directory_name_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!provider || peer_id == 0u || generation == 0u ||
        ownership_generation == 0u || !descriptors ||
        descriptors_len == 0u || !uri_list || !uri_list_len ||
        (require_started &&
         (!provider->started || !provider->mounted ||
          !provider->clipboard_request)))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *uri_list = NULL;
    *uri_list_len = 0u;
    status = librdp_clipboard_file_group_count(descriptors,
                                               descriptors_len,
                                               &count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (count == 0u || count > (uint32_t)INT32_MAX ||
        count > provider->config.max_directory_entries ||
        count > provider->config.max_nodes - 2u)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    entries = (x11_server_fuse_clipboard_entry*)calloc(
        count, sizeof(*entries));
    if (!entries)
        return LIBRDP_STATUS_NO_MEMORY;
    for (index = 0u; index < count; index++)
    {
        size_t name_len = 0u;

        status = librdp_clipboard_file_metadata_init(
            &entries[index].metadata);
        if (status == LIBRDP_STATUS_OK)
        {
            status = librdp_clipboard_file_group_get(
                descriptors,
                descriptors_len,
                index,
                &entries[index].metadata,
                entries[index].name,
                sizeof(entries[index].name),
                &name_len);
        }
        if (status != LIBRDP_STATUS_OK)
            break;
        if (name_len == 0u ||
            (entries[index].metadata.attributes &
             LIBRDP_CLIPBOARD_FILE_ATTRIBUTE_DIRECTORY) != 0u ||
            !x11_server_fuse_name_valid(entries[index].name))
        {
            status = LIBRDP_STATUS_UNSUPPORTED;
            break;
        }
    }
    if (status != LIBRDP_STATUS_OK)
    {
        free(entries);
        return status;
    }
    if (provider->clipboard_generation != 0u)
    {
        x11_server_fuse_clipboard_clear_internal(
            provider,
            provider->clipboard_peer_id,
            provider->clipboard_peer_generation,
            provider->clipboard_generation);
    }
    directory_name_len = snprintf(directory_name,
                                  sizeof(directory_name),
                                  "clipboard-%u-%u-%llu",
                                  peer_id,
                                  generation,
                                  (unsigned long long)ownership_generation);
    if (directory_name_len <= 0 ||
        (size_t)directory_name_len >= sizeof(directory_name))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    directory = x11_server_fuse_allocate_node(
        provider,
        X11_SERVER_FUSE_NODE_CLIPBOARD_DIRECTORY,
        FUSE_ROOT_ID,
        directory_name,
        directory_name);
    if (!directory)
    {
        free(entries);
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    directory->peer_id = peer_id;
    directory->generation = generation;
    directory->clipboard_generation = ownership_generation;
    directory->metadata.directory = 1u;
    directory->metadata.attributes =
        LIBRDP_SERVER_DRIVE_FILE_ATTRIBUTE_DIRECTORY;
    directory->metadata_valid = 1;
    provider->clipboard_peer_id = peer_id;
    provider->clipboard_peer_generation = generation;
    provider->clipboard_generation = ownership_generation;
    for (index = 0u; index < count; index++)
    {
        const x11_server_fuse_clipboard_entry* entry = &entries[index];
        x11_server_fuse_node* node = NULL;
        char visible_name[X11_SERVER_FUSE_MAX_NAME_BYTES + 1u];
        char relative_path[X11_SERVER_FUSE_MAX_PATH_BYTES + 1u];
        char absolute_path[X11_SERVER_FUSE_MAX_PATH_BYTES + 1u];
        int absolute_len = 0;

        memcpy(visible_name,
               entry->name,
               strlen(entry->name) + 1u);
        if (x11_server_fuse_find_child(provider,
                                       directory->inode,
                                       visible_name))
        {
            uint32_t suffix = index + 1u;
            int visible_len = 0;

            do
            {
                visible_len = snprintf(visible_name,
                                       sizeof(visible_name),
                                       "file-%u",
                                       suffix++);
                if (visible_len <= 0 ||
                    (size_t)visible_len >= sizeof(visible_name) ||
                    suffix == 0u)
                {
                    status = LIBRDP_STATUS_LIMIT_EXCEEDED;
                    break;
                }
            } while (x11_server_fuse_find_child(provider,
                                                directory->inode,
                                                visible_name));
            if (status != LIBRDP_STATUS_OK)
                break;
        }
        if (!x11_server_fuse_join_path(directory_name,
                                       visible_name,
                                       relative_path))
        {
            status = LIBRDP_STATUS_LIMIT_EXCEEDED;
            break;
        }
        node = x11_server_fuse_allocate_node(
            provider,
            X11_SERVER_FUSE_NODE_CLIPBOARD_FILE,
            directory->inode,
            visible_name,
            relative_path);
        if (!node)
        {
            status = LIBRDP_STATUS_LIMIT_EXCEEDED;
            break;
        }
        node->peer_id = peer_id;
        node->generation = generation;
        node->clipboard_generation = ownership_generation;
        node->clipboard_file_index = (int32_t)index;
        node->metadata.file_size = entry->metadata.file_size;
        node->metadata.allocation_size = entry->metadata.file_size;
        node->metadata.attributes =
            LIBRDP_SERVER_DRIVE_FILE_ATTRIBUTE_READONLY;
        node->metadata.directory = 0u;
        node->metadata_valid = 1;
        absolute_len = snprintf(absolute_path,
                                sizeof(absolute_path),
                                "%s/%s",
                                provider->mount_path,
                                relative_path);
        if (absolute_len <= 0 ||
            (size_t)absolute_len >= sizeof(absolute_path))
        {
            status = LIBRDP_STATUS_LIMIT_EXCEEDED;
            break;
        }
        status = x11_server_fuse_append_file_uri(&output,
                                                 &output_len,
                                                 absolute_path);
        if (status != LIBRDP_STATUS_OK)
            break;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        free(entries);
        free(output);
        x11_server_fuse_clipboard_clear_internal(provider,
                                                 peer_id,
                                                 generation,
                                                 ownership_generation);
        return status;
    }
    free(entries);
    if (provider->mounted)
    {
        (void)fuse_lowlevel_notify_inval_inode(provider->session,
                                               FUSE_ROOT_ID,
                                               0,
                                               0);
    }
    *uri_list = output;
    *uri_list_len = output_len;
    return LIBRDP_STATUS_OK;
}

static x11_server_fuse_node* x11_server_fuse_add_remote_node(
    x11_server_fuse* provider, x11_server_fuse_node* parent, const char* name,
    const librdp_server_drive_metadata* metadata)
{
    x11_server_fuse_node* node =
        x11_server_fuse_find_child(provider, parent->inode, name);
    char path[X11_SERVER_FUSE_MAX_PATH_BYTES + 1u];

    if (!provider || !parent || !metadata ||
        !x11_server_fuse_join_path(parent->path, name, path))
        return NULL;
    if (!node)
    {
        node = x11_server_fuse_allocate_node(
            provider, X11_SERVER_FUSE_NODE_REMOTE, parent->inode, name, path);
        if (!node)
            return NULL;
    }
    node->volume_id = parent->volume_id;
    node->peer_id = parent->peer_id;
    node->generation = parent->generation;
    node->device = parent->device;
    node->metadata = *metadata;
    node->metadata_valid = 1;
    return node;
}

static int x11_server_fuse_directory_name_matches(const char* expected,
                                                  const char* actual)
{
    size_t index = 0u;

    if (!expected || !actual)
        return 0;
    while (expected[index] != '\0' && actual[index] != '\0')
    {
        unsigned char left = (unsigned char)expected[index];
        unsigned char right = (unsigned char)actual[index];

        if (left >= 'A' && left <= 'Z')
            left = (unsigned char)(left - 'A' + 'a');
        if (right >= 'A' && right <= 'Z')
            right = (unsigned char)(right - 'A' + 'a');
        if (left != right)
            return 0;
        index++;
    }
    return expected[index] == '\0' && actual[index] == '\0';
}

static int x11_server_fuse_decode_lookup(
    x11_server_fuse* provider, x11_server_fuse_pending* pending,
    const server_platform_drive_completion* completion)
{
    x11_server_fuse_node* parent =
        x11_server_fuse_find_node(provider, pending->parent);
    librdp_server_drive_metadata metadata;
    char remote_name[X11_SERVER_FUSE_MAX_NAME_BYTES + 1u];
    size_t name_length = 0u;
    size_t next_offset = 0u;

    if (!parent ||
        librdp_server_drive_metadata_init(&metadata) != LIBRDP_STATUS_OK ||
        librdp_server_drive_decode_directory_entry(
            completion->information_class, completion->data,
            completion->data_len, 0u, &metadata, remote_name,
            sizeof(remote_name), &name_length,
            &next_offset) != LIBRDP_STATUS_OK ||
        name_length == 0u ||
        !x11_server_fuse_directory_name_matches(pending->name, remote_name))
        return EPROTO;
    return x11_server_fuse_add_remote_node(provider, parent, pending->name,
                                           &metadata)
               ? 0
               : ENOSPC;
}

static int x11_server_fuse_handle_add_directory_entry(
    x11_server_fuse* provider, x11_server_fuse_handle* handle, fuse_ino_t inode)
{
    fuse_ino_t* resized = NULL;

    if (!provider || !handle || inode == 0u ||
        handle->directory_count >= provider->config.max_directory_entries ||
        handle->directory_count == SIZE_MAX / sizeof(*resized))
        return 0;
    resized =
        (fuse_ino_t*)realloc(handle->directory_entries,
                             (handle->directory_count + 1u) * sizeof(*resized));
    if (!resized)
        return 0;
    handle->directory_entries = resized;
    handle->directory_entries[handle->directory_count++] = inode;
    return 1;
}

static int x11_server_fuse_decode_directory_page(
    x11_server_fuse* provider, x11_server_fuse_pending* pending,
    x11_server_fuse_handle* handle,
    const server_platform_drive_completion* completion, size_t* decoded_count)
{
    x11_server_fuse_node* parent =
        x11_server_fuse_find_node(provider, handle->inode);
    size_t offset = 0u;

    if (!provider || !pending || !handle || !parent || !completion ||
        !decoded_count)
        return EINVAL;
    *decoded_count = 0u;
    do
    {
        librdp_server_drive_metadata metadata;
        char name[X11_SERVER_FUSE_MAX_NAME_BYTES + 1u];
        size_t name_length = 0u;
        size_t next_offset = 0u;
        x11_server_fuse_node* node = NULL;
        librdp_status status = librdp_server_drive_metadata_init(&metadata);

        if (status == LIBRDP_STATUS_OK)
        {
            status = librdp_server_drive_decode_directory_entry(
                completion->information_class, completion->data,
                completion->data_len, offset, &metadata, name, sizeof(name),
                &name_length, &next_offset);
        }
        if (status != LIBRDP_STATUS_OK || name_length == 0u ||
            !x11_server_fuse_name_valid(name))
            return EPROTO;
        node =
            x11_server_fuse_add_remote_node(provider, parent, name, &metadata);
        if (!node || !x11_server_fuse_handle_add_directory_entry(
                         provider, handle, node->inode))
            return ENOSPC;
        (*decoded_count)++;
        if (next_offset == 0u)
            break;
        if (next_offset <= offset || next_offset >= completion->data_len)
            return EPROTO;
        offset = next_offset;
    } while (offset < completion->data_len);
    return 0;
}

static void x11_server_fuse_reply_directory(x11_server_fuse* provider,
                                            x11_server_fuse_pending* pending,
                                            x11_server_fuse_handle* handle)
{
    x11_server_fuse_node* directory =
        x11_server_fuse_find_node(provider, handle->inode);
    size_t capacity = pending->requested_size;
    char* buffer = NULL;
    size_t used = 0u;
    uint64_t position = pending->requested_offset > 0
                            ? (uint64_t)pending->requested_offset
                            : 0u;
    uint64_t total = handle->directory_count + 2u;

    if (!directory || pending->requested_offset < 0)
    {
        x11_server_fuse_reply_pending_error(pending, ESTALE);
        return;
    }
    if (capacity > X11_SERVER_FUSE_MAX_REPLY_BYTES)
        capacity = X11_SERVER_FUSE_MAX_REPLY_BYTES;
    buffer = capacity > 0u ? (char*)malloc(capacity) : NULL;
    if (capacity > 0u && !buffer)
    {
        x11_server_fuse_reply_pending_error(pending, ENOMEM);
        return;
    }
    while (position < total)
    {
        const char* name = NULL;
        struct stat status;
        size_t entry_size = 0u;
        x11_server_fuse_node* node = NULL;

        if (position == 0u)
        {
            name = ".";
            node = directory;
        }
        else if (position == 1u)
        {
            name = "..";
            node = x11_server_fuse_find_node(provider, directory->parent);
            if (!node)
                node = directory;
        }
        else
        {
            size_t entry_index = (size_t)(position - 2u);

            node = x11_server_fuse_find_node(
                provider, handle->directory_entries[entry_index]);
            if (!node)
            {
                position++;
                continue;
            }
            name = node->name;
        }
        x11_server_fuse_node_stat(node, &status);
        entry_size = fuse_add_direntry(pending->request, NULL, 0u, name,
                                       &status, (off_t)(position + 1u));
        if (entry_size > capacity - used)
            break;
        (void)fuse_add_direntry(pending->request, buffer + used,
                                capacity - used, name, &status,
                                (off_t)(position + 1u));
        used += entry_size;
        position++;
    }
    (void)fuse_reply_buf(pending->request, buffer, used);
    free(buffer);
    x11_server_fuse_clear_pending(pending);
}

static void x11_server_fuse_finish_close(x11_server_fuse* provider,
                                         x11_server_fuse_pending* pending,
                                         int close_error)
{
    int error =
        pending->terminal_error != 0 ? pending->terminal_error : close_error;

    if (pending->kind == X11_SERVER_FUSE_PENDING_LOOKUP)
    {
        x11_server_fuse_node* node = x11_server_fuse_find_child(
            provider, pending->parent, pending->name);

        if (error == 0 && node)
        {
            x11_server_fuse_reply_entry(pending->request, node);
            x11_server_fuse_clear_pending(pending);
        }
        else
            x11_server_fuse_reply_pending_error(pending,
                                                error != 0 ? error : ENOENT);
        return;
    }
    if (pending->kind == X11_SERVER_FUSE_PENDING_RELEASE ||
        pending->kind == X11_SERVER_FUSE_PENDING_RELEASEDIR)
    {
        x11_server_fuse_handle* handle =
            x11_server_fuse_find_handle(provider, pending->handle_id);

        if (handle)
            x11_server_fuse_clear_handle(handle);
        (void)fuse_reply_err(pending->request, error);
        x11_server_fuse_clear_pending(pending);
        return;
    }
    x11_server_fuse_reply_pending_error(pending, error != 0 ? error : EIO);
}

static void x11_server_fuse_complete_lookup(
    x11_server_fuse* provider, x11_server_fuse_pending* pending,
    const server_platform_drive_completion* completion, int error)
{
    x11_server_fuse_node* parent =
        x11_server_fuse_find_node(provider, pending->parent);

    if (!parent)
    {
        x11_server_fuse_reply_pending_error(pending, ESTALE);
        return;
    }
    if (pending->stage == X11_SERVER_FUSE_STAGE_OPEN)
    {
        if (error != 0)
        {
            x11_server_fuse_reply_pending_error(pending, error);
            return;
        }
        pending->temporary_file = completion->file;
        if (!x11_server_fuse_submit_query_directory(provider, pending, parent,
                                                    pending->temporary_file,
                                                    pending->name, 1))
            x11_server_fuse_reply_pending_error(pending, EIO);
        return;
    }
    if (pending->stage == X11_SERVER_FUSE_STAGE_QUERY)
    {
        pending->terminal_error =
            error != 0
                ? error
                : x11_server_fuse_decode_lookup(provider, pending, completion);
        if (!x11_server_fuse_submit_close(provider, pending, parent,
                                          pending->temporary_file))
            x11_server_fuse_reply_pending_error(pending,
                                                pending->terminal_error);
        return;
    }
    x11_server_fuse_finish_close(provider, pending, error);
}

static void x11_server_fuse_complete_open(
    x11_server_fuse* provider, x11_server_fuse_pending* pending,
    const server_platform_drive_completion* completion, int error)
{
    x11_server_fuse_node* node =
        x11_server_fuse_find_node(provider, pending->inode);
    x11_server_fuse_handle* handle = NULL;

    if (!node)
        error = ESTALE;
    if (pending->stage == X11_SERVER_FUSE_STAGE_CLOSE)
    {
        x11_server_fuse_finish_close(provider, pending, error);
        return;
    }
    if (error == 0)
    {
        handle = x11_server_fuse_allocate_handle(
            provider, pending->inode,
            pending->kind == X11_SERVER_FUSE_PENDING_OPENDIR, 0);
        if (!handle)
            error = EMFILE;
    }
    if (error != 0)
    {
        if (completion->file.file_id != 0u && node)
        {
            pending->temporary_file = completion->file;
            pending->terminal_error = error;
            if (x11_server_fuse_submit_close(provider, pending, node,
                                             completion->file))
                return;
        }
        x11_server_fuse_reply_pending_error(pending, error);
        return;
    }
    handle->remote = completion->file;
    pending->file_info.fh = handle->id;
    pending->file_info.keep_cache = 0u;
    pending->file_info.cache_readdir = 0u;
    (void)fuse_reply_open(pending->request, &pending->file_info);
    x11_server_fuse_clear_pending(pending);
}

static void x11_server_fuse_complete_readdir(
    x11_server_fuse* provider, x11_server_fuse_pending* pending,
    const server_platform_drive_completion* completion, int error)
{
    x11_server_fuse_handle* handle =
        x11_server_fuse_find_handle(provider, pending->handle_id);
    x11_server_fuse_node* node =
        handle ? x11_server_fuse_find_node(provider, handle->inode) : NULL;
    size_t decoded = 0u;

    if (!handle || !node || handle->closing)
    {
        x11_server_fuse_reply_pending_error(pending, ESTALE);
        return;
    }
    if (error == ENOENT)
    {
        handle->directory_loaded = 1;
        x11_server_fuse_reply_directory(provider, pending, handle);
        return;
    }
    if (error != 0)
    {
        x11_server_fuse_reply_pending_error(pending, error);
        return;
    }
    error = x11_server_fuse_decode_directory_page(provider, pending, handle,
                                                  completion, &decoded);
    if (error != 0 || decoded == 0u)
    {
        x11_server_fuse_reply_pending_error(pending,
                                            error != 0 ? error : EPROTO);
        return;
    }
    handle->query_count++;
    if (handle->query_count >= provider->config.max_directory_entries)
    {
        x11_server_fuse_reply_pending_error(pending, ENOSPC);
        return;
    }
    if (!x11_server_fuse_submit_query_directory(provider, pending, node,
                                                handle->remote, NULL, 0))
        x11_server_fuse_reply_pending_error(pending, EIO);
}

static librdp_status x11_server_fuse_complete(
    void* opaque, const server_platform_drive_completion* completion)
{
    x11_server_fuse* provider = (x11_server_fuse*)opaque;
    x11_server_fuse_pending* pending = NULL;
    int error = 0;

    if (!provider || !completion)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    pending = x11_server_fuse_find_pending(provider, completion->request_id);
    if (!pending)
        return LIBRDP_STATUS_STATE;
    error = x11_server_fuse_completion_errno(completion);
    if (pending->kind == X11_SERVER_FUSE_PENDING_LOOKUP)
        x11_server_fuse_complete_lookup(provider, pending, completion, error);
    else if (pending->kind == X11_SERVER_FUSE_PENDING_OPEN ||
             pending->kind == X11_SERVER_FUSE_PENDING_OPENDIR)
        x11_server_fuse_complete_open(provider, pending, completion, error);
    else if (pending->kind == X11_SERVER_FUSE_PENDING_READ)
    {
        if (error == 0 && completion->data_len <= pending->requested_size &&
            (completion->data || completion->data_len == 0u))
        {
            (void)fuse_reply_buf(pending->request,
                                 (const char*)completion->data,
                                 completion->data_len);
            x11_server_fuse_clear_pending(pending);
        }
        else
            x11_server_fuse_reply_pending_error(pending,
                                                error != 0 ? error : EPROTO);
    }
    else if (pending->kind == X11_SERVER_FUSE_PENDING_RELEASE ||
             pending->kind == X11_SERVER_FUSE_PENDING_RELEASEDIR)
        x11_server_fuse_finish_close(provider, pending, error);
    else if (pending->kind == X11_SERVER_FUSE_PENDING_READDIR)
        x11_server_fuse_complete_readdir(provider, pending, completion, error);
    else
        x11_server_fuse_reply_pending_error(pending, EPROTO);
    return LIBRDP_STATUS_OK;
}

static void x11_server_fuse_lookup(fuse_req_t request, fuse_ino_t parent_inode,
                                   const char* name)
{
    x11_server_fuse* provider = (x11_server_fuse*)fuse_req_userdata(request);
    x11_server_fuse_node* parent =
        x11_server_fuse_find_node(provider, parent_inode);
    x11_server_fuse_node* child =
        x11_server_fuse_find_child(provider, parent_inode, name);
    x11_server_fuse_pending* pending = NULL;

    if (!parent || !x11_server_fuse_name_valid(name))
    {
        (void)fuse_reply_err(request, parent ? EINVAL : ESTALE);
        return;
    }
    if (child)
    {
        x11_server_fuse_reply_entry(request, child);
        return;
    }
    if (parent->kind == X11_SERVER_FUSE_NODE_ROOT ||
        parent->kind == X11_SERVER_FUSE_NODE_PEER ||
        parent->kind == X11_SERVER_FUSE_NODE_CLIPBOARD_DIRECTORY ||
        !parent->metadata.directory)
    {
        (void)fuse_reply_err(request, ENOENT);
        return;
    }
    pending = x11_server_fuse_allocate_pending(provider, request,
                                               X11_SERVER_FUSE_PENDING_LOOKUP);
    if (!pending)
    {
        (void)fuse_reply_err(request, EBUSY);
        return;
    }
    pending->parent = parent_inode;
    memcpy(pending->name, name, strlen(name) + 1u);
    if (!x11_server_fuse_submit_create(provider, pending, parent, parent->path,
                                       1))
        x11_server_fuse_reply_pending_error(pending, EIO);
}

static void x11_server_fuse_forget(fuse_req_t request, fuse_ino_t inode,
                                   uint64_t lookup_count)
{
    x11_server_fuse* provider = (x11_server_fuse*)fuse_req_userdata(request);
    x11_server_fuse_node* node = x11_server_fuse_find_node(provider, inode);

    if (node)
    {
        if (node->lookup_count >= lookup_count)
            node->lookup_count -= lookup_count;
        else
            node->lookup_count = 0u;
    }
    fuse_reply_none(request);
}

static void x11_server_fuse_getattr(fuse_req_t request, fuse_ino_t inode,
                                    struct fuse_file_info* file_info)
{
    x11_server_fuse* provider = (x11_server_fuse*)fuse_req_userdata(request);
    x11_server_fuse_node* node = x11_server_fuse_find_node(provider, inode);
    struct stat status;

    (void)file_info;
    if (!node)
    {
        (void)fuse_reply_err(request, ESTALE);
        return;
    }
    x11_server_fuse_node_stat(node, &status);
    (void)fuse_reply_attr(request, &status, 0.25);
}

static void x11_server_fuse_open_common(fuse_req_t request, fuse_ino_t inode,
                                        struct fuse_file_info* file_info,
                                        int directory)
{
    x11_server_fuse* provider = (x11_server_fuse*)fuse_req_userdata(request);
    x11_server_fuse_node* node = x11_server_fuse_find_node(provider, inode);
    x11_server_fuse_handle* handle = NULL;
    x11_server_fuse_pending* pending = NULL;

    if (!node || !file_info)
    {
        (void)fuse_reply_err(request, EINVAL);
        return;
    }
    if (directory != x11_server_fuse_node_is_directory(node))
    {
        (void)fuse_reply_err(request, directory ? ENOTDIR : EISDIR);
        return;
    }
    if (!directory && (file_info->flags & O_ACCMODE) != O_RDONLY)
    {
        (void)fuse_reply_err(request, EROFS);
        return;
    }
    if (node->kind == X11_SERVER_FUSE_NODE_ROOT ||
        node->kind == X11_SERVER_FUSE_NODE_PEER ||
        node->kind == X11_SERVER_FUSE_NODE_CLIPBOARD_DIRECTORY ||
        node->kind == X11_SERVER_FUSE_NODE_CLIPBOARD_FILE)
    {
        handle = x11_server_fuse_allocate_handle(provider,
                                                 inode,
                                                 directory,
                                                 1);
        if (!handle)
        {
            (void)fuse_reply_err(request, EMFILE);
            return;
        }
        file_info->fh = handle->id;
        (void)fuse_reply_open(request, file_info);
        return;
    }
    pending = x11_server_fuse_allocate_pending(
        provider, request,
        directory ? X11_SERVER_FUSE_PENDING_OPENDIR
                  : X11_SERVER_FUSE_PENDING_OPEN);
    if (!pending)
    {
        (void)fuse_reply_err(request, EBUSY);
        return;
    }
    pending->inode = inode;
    pending->file_info = *file_info;
    if (!x11_server_fuse_submit_create(provider, pending, node, node->path,
                                       directory))
        x11_server_fuse_reply_pending_error(pending, EIO);
}

static void x11_server_fuse_open(fuse_req_t request, fuse_ino_t inode,
                                 struct fuse_file_info* file_info)
{
    x11_server_fuse_open_common(request, inode, file_info, 0);
}

static void x11_server_fuse_opendir(fuse_req_t request, fuse_ino_t inode,
                                    struct fuse_file_info* file_info)
{
    x11_server_fuse_open_common(request, inode, file_info, 1);
}

static void x11_server_fuse_read(fuse_req_t request, fuse_ino_t inode,
                                 size_t size, off_t offset,
                                 struct fuse_file_info* file_info)
{
    x11_server_fuse* provider = (x11_server_fuse*)fuse_req_userdata(request);
    x11_server_fuse_node* node = x11_server_fuse_find_node(provider, inode);
    x11_server_fuse_handle* handle =
        file_info ? x11_server_fuse_find_handle(provider, file_info->fh) : NULL;
    x11_server_fuse_pending* pending = NULL;
    uint32_t request_size = 0u;

    if (!node || !handle || handle->inode != inode || handle->directory ||
        handle->closing || offset < 0)
    {
        (void)fuse_reply_err(request, ESTALE);
        return;
    }
    if (size == 0u ||
        (node->kind == X11_SERVER_FUSE_NODE_CLIPBOARD_FILE &&
         (uint64_t)offset >= node->metadata.file_size))
    {
        (void)fuse_reply_buf(request, NULL, 0u);
        return;
    }
    if (node->kind == X11_SERVER_FUSE_NODE_CLIPBOARD_FILE)
    {
        server_platform_clipboard_file_request clipboard_request;
        librdp_status status = LIBRDP_STATUS_OK;
        uint64_t remaining = node->metadata.file_size - (uint64_t)offset;

        if (!provider->clipboard_request ||
            !x11_server_fuse_clipboard_node_matches(
                node,
                provider->clipboard_peer_id,
                provider->clipboard_peer_generation,
                provider->clipboard_generation))
        {
            (void)fuse_reply_err(request, ESTALE);
            return;
        }
        pending = x11_server_fuse_allocate_pending(
            provider, request, X11_SERVER_FUSE_PENDING_CLIPBOARD_READ);
        if (!pending)
        {
            (void)fuse_reply_err(request, EBUSY);
            return;
        }
        pending->inode = inode;
        pending->handle_id = handle->id;
        pending->requested_size = size < provider->config.max_read_bytes
                                      ? size
                                      : provider->config.max_read_bytes;
        if ((uint64_t)pending->requested_size > remaining)
            pending->requested_size = (size_t)remaining;
        pending->requested_offset = offset;
        pending->request_id = x11_server_fuse_next_request_id(provider);
        pending->stream_id = (uint32_t)pending->request_id;
        if (pending->stream_id == 0u)
            pending->stream_id = 1u;
        memset(&clipboard_request, 0, sizeof(clipboard_request));
        clipboard_request.peer_id = node->peer_id;
        clipboard_request.generation = node->generation;
        clipboard_request.ownership_generation =
            node->clipboard_generation;
        clipboard_request.request_id = pending->request_id;
        clipboard_request.stream_id = pending->stream_id;
        clipboard_request.file_index = node->clipboard_file_index;
        clipboard_request.flags = LIBRDP_CLIPBOARD_FILECONTENTS_RANGE;
        clipboard_request.position = (uint64_t)offset;
        clipboard_request.requested_bytes =
            (uint32_t)pending->requested_size;
        status = provider->clipboard_request(
            &clipboard_request, provider->clipboard_user_data);
        if (status != LIBRDP_STATUS_OK)
            x11_server_fuse_reply_pending_error(
                pending, x11_server_fuse_status_errno(status));
        return;
    }
    pending = x11_server_fuse_allocate_pending(provider, request,
                                               X11_SERVER_FUSE_PENDING_READ);
    if (!pending)
    {
        (void)fuse_reply_err(request, EBUSY);
        return;
    }
    pending->inode = inode;
    pending->handle_id = handle->id;
    pending->requested_size = size < provider->config.max_read_bytes
                                  ? size
                                  : provider->config.max_read_bytes;
    pending->requested_offset = offset;
    request_size = (uint32_t)pending->requested_size;
    if (!x11_server_fuse_submit_read(provider, pending, node, handle->remote,
                                     (uint64_t)offset, request_size))
        x11_server_fuse_reply_pending_error(pending, EIO);
}

static void x11_server_fuse_reply_local_directory(
    x11_server_fuse* provider, fuse_req_t request,
    x11_server_fuse_handle* handle, size_t size, off_t offset)
{
    x11_server_fuse_pending* pending = x11_server_fuse_allocate_pending(
        provider, request, X11_SERVER_FUSE_PENDING_READDIR);
    uint32_t index = 0u;

    if (!pending)
    {
        (void)fuse_reply_err(request, EBUSY);
        return;
    }
    free(handle->directory_entries);
    handle->directory_entries = NULL;
    handle->directory_count = 0u;
    for (index = 0u; index < provider->config.max_nodes; index++)
    {
        x11_server_fuse_node* child = &provider->nodes[index];

        if (!child->valid || child->parent != handle->inode)
            continue;
        if (!x11_server_fuse_handle_add_directory_entry(provider, handle,
                                                        child->inode))
        {
            x11_server_fuse_reply_pending_error(pending, ENOSPC);
            return;
        }
    }
    handle->directory_loaded = 1;
    pending->handle_id = handle->id;
    pending->requested_size = size;
    pending->requested_offset = offset;
    x11_server_fuse_reply_directory(provider, pending, handle);
}

static void x11_server_fuse_readdir(fuse_req_t request, fuse_ino_t inode,
                                    size_t size, off_t offset,
                                    struct fuse_file_info* file_info)
{
    x11_server_fuse* provider = (x11_server_fuse*)fuse_req_userdata(request);
    x11_server_fuse_node* node = x11_server_fuse_find_node(provider, inode);
    x11_server_fuse_handle* handle =
        file_info ? x11_server_fuse_find_handle(provider, file_info->fh) : NULL;
    x11_server_fuse_pending* pending = NULL;

    if (!node || !handle || handle->inode != inode || !handle->directory ||
        handle->closing || offset < 0)
    {
        (void)fuse_reply_err(request, ESTALE);
        return;
    }
    if (handle->local)
    {
        x11_server_fuse_reply_local_directory(provider, request, handle, size,
                                              offset);
        return;
    }
    if (handle->directory_loaded)
    {
        pending = x11_server_fuse_allocate_pending(
            provider, request, X11_SERVER_FUSE_PENDING_READDIR);
        if (!pending)
        {
            (void)fuse_reply_err(request, EBUSY);
            return;
        }
        pending->handle_id = handle->id;
        pending->requested_size = size;
        pending->requested_offset = offset;
        x11_server_fuse_reply_directory(provider, pending, handle);
        return;
    }
    pending = x11_server_fuse_allocate_pending(provider, request,
                                               X11_SERVER_FUSE_PENDING_READDIR);
    if (!pending)
    {
        (void)fuse_reply_err(request, EBUSY);
        return;
    }
    pending->inode = inode;
    pending->handle_id = handle->id;
    pending->requested_size = size;
    pending->requested_offset = offset;
    if (!x11_server_fuse_submit_query_directory(provider, pending, node,
                                                handle->remote, "*", 1))
        x11_server_fuse_reply_pending_error(pending, EIO);
}

static void x11_server_fuse_release_common(fuse_req_t request, fuse_ino_t inode,
                                           struct fuse_file_info* file_info,
                                           int directory)
{
    x11_server_fuse* provider = (x11_server_fuse*)fuse_req_userdata(request);
    x11_server_fuse_node* node = x11_server_fuse_find_node(provider, inode);
    x11_server_fuse_handle* handle =
        file_info ? x11_server_fuse_find_handle(provider, file_info->fh) : NULL;
    x11_server_fuse_pending* pending = NULL;

    if (!handle || handle->inode != inode || handle->directory != directory ||
        handle->closing)
    {
        (void)fuse_reply_err(request, ESTALE);
        return;
    }
    if (handle->local)
    {
        x11_server_fuse_clear_handle(handle);
        (void)fuse_reply_err(request, 0);
        return;
    }
    if (!node)
    {
        x11_server_fuse_clear_handle(handle);
        (void)fuse_reply_err(request, ESTALE);
        return;
    }
    pending = x11_server_fuse_allocate_pending(
        provider, request,
        directory ? X11_SERVER_FUSE_PENDING_RELEASEDIR
                  : X11_SERVER_FUSE_PENDING_RELEASE);
    if (!pending)
    {
        (void)fuse_reply_err(request, EBUSY);
        return;
    }
    pending->inode = inode;
    pending->handle_id = handle->id;
    handle->closing = 1;
    if (!x11_server_fuse_submit_close(provider, pending, node, handle->remote))
    {
        handle->closing = 0;
        x11_server_fuse_reply_pending_error(pending, EIO);
    }
}

static void x11_server_fuse_release(fuse_req_t request, fuse_ino_t inode,
                                    struct fuse_file_info* file_info)
{
    x11_server_fuse_release_common(request, inode, file_info, 0);
}

static void x11_server_fuse_releasedir(fuse_req_t request, fuse_ino_t inode,
                                       struct fuse_file_info* file_info)
{
    x11_server_fuse_release_common(request, inode, file_info, 1);
}

static void x11_server_fuse_access(fuse_req_t request, fuse_ino_t inode,
                                   int mask)
{
    x11_server_fuse* provider = (x11_server_fuse*)fuse_req_userdata(request);
    x11_server_fuse_node* node = x11_server_fuse_find_node(provider, inode);

    if (!node)
        (void)fuse_reply_err(request, ESTALE);
    else if ((mask & W_OK) != 0)
        (void)fuse_reply_err(request, EROFS);
    else
        (void)fuse_reply_err(request, 0);
}

static void x11_server_fuse_statfs(fuse_req_t request, fuse_ino_t inode)
{
    struct statvfs status;

    (void)inode;
    memset(&status, 0, sizeof(status));
    status.f_bsize = 4096u;
    status.f_frsize = 4096u;
    status.f_namemax = X11_SERVER_FUSE_MAX_NAME_BYTES;
    status.f_flag = ST_RDONLY;
    (void)fuse_reply_statfs(request, &status);
}

static const struct fuse_lowlevel_ops x11_server_fuse_operations = {
    .lookup = x11_server_fuse_lookup,
    .forget = x11_server_fuse_forget,
    .getattr = x11_server_fuse_getattr,
    .open = x11_server_fuse_open,
    .read = x11_server_fuse_read,
    .release = x11_server_fuse_release,
    .opendir = x11_server_fuse_opendir,
    .readdir = x11_server_fuse_readdir,
    .releasedir = x11_server_fuse_releasedir,
    .statfs = x11_server_fuse_statfs,
    .access = x11_server_fuse_access,
};

static librdp_status x11_server_fuse_events_get_pollfds(void* opaque,
                                                        struct pollfd* fds,
                                                        size_t capacity,
                                                        size_t* count)
{
    x11_server_fuse* provider = (x11_server_fuse*)opaque;

    if (!provider || !count || !provider->mounted)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *count = 1u;
    if (!fds && capacity == 0u)
        return LIBRDP_STATUS_OK;
    if (!fds || capacity < 1u)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    fds[0].fd = fuse_session_fd(provider->session);
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    return fds[0].fd >= 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_IO_ERROR;
}

static librdp_status x11_server_fuse_events_notify_poll(
    void* opaque, const struct pollfd* fds, size_t count)
{
    x11_server_fuse* provider = (x11_server_fuse*)opaque;

    if (!provider || !fds || count != 1u || !provider->mounted ||
        fds[0].fd != fuse_session_fd(provider->session))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        provider->descriptor_failed = 1;
    if ((fds[0].revents & POLLIN) != 0)
        provider->descriptor_ready = 1;
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_server_fuse_events_dispatch(void* opaque,
                                                     unsigned int max_events)
{
    x11_server_fuse* provider = (x11_server_fuse*)opaque;
    unsigned int dispatched = 0u;

    if (!provider || max_events == 0u || !provider->mounted)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (provider->descriptor_failed)
        return LIBRDP_STATUS_IO_ERROR;
    while (provider->descriptor_ready && dispatched < max_events)
    {
        struct fuse_buf buffer;
        int received = 0;

        memset(&buffer, 0, sizeof(buffer));
        received = fuse_session_receive_buf(provider->session, &buffer);
        if (received == -EINTR)
            continue;
        provider->descriptor_ready = 0;
        if (received == -EAGAIN)
            break;
        if (received <= 0)
        {
            if (received < 0)
                return LIBRDP_STATUS_IO_ERROR;
            break;
        }
        fuse_session_process_buf(provider->session, &buffer);
        if ((buffer.flags & FUSE_BUF_IS_FD) == 0)
            free(buffer.mem);
        dispatched++;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_server_fuse_events_get_next_timeout(void* opaque,
                                                             int* timeout_ms)
{
    x11_server_fuse* provider = (x11_server_fuse*)opaque;

    if (!provider || !timeout_ms)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *timeout_ms = provider->descriptor_ready ? 0 : -1;
    return LIBRDP_STATUS_OK;
}

static const server_platform_event_source_vtable x11_server_fuse_event_source =
    {
        SERVER_PLATFORM_EVENT_SOURCE_VERSION,
        sizeof(server_platform_event_source_vtable),
        x11_server_fuse_events_get_pollfds,
        x11_server_fuse_events_notify_poll,
        x11_server_fuse_events_dispatch,
        x11_server_fuse_events_get_next_timeout,
};

static void x11_server_fuse_abort_pending(x11_server_fuse* provider, int error)
{
    uint32_t index = 0u;

    if (!provider)
        return;
    for (index = 0u; index < provider->config.max_pending; index++)
    {
        x11_server_fuse_pending* pending = &provider->pending[index];

        if (!pending->occupied)
            continue;
        if (pending->kind == X11_SERVER_FUSE_PENDING_CLIPBOARD_READ)
        {
            x11_server_fuse_node* node =
                x11_server_fuse_find_node(provider, pending->inode);

            if (node && provider->clipboard_cancel)
            {
                (void)provider->clipboard_cancel(
                    node->peer_id,
                    node->generation,
                    node->clipboard_generation,
                    pending->request_id,
                    provider->clipboard_user_data);
            }
            if (pending->occupied)
                x11_server_fuse_reply_pending_error(pending, error);
            continue;
        }
        if (provider->started && provider->sink.cancel)
        {
            x11_server_fuse_node* node = x11_server_fuse_find_node(
                provider,
                pending->inode != 0u ? pending->inode : pending->parent);
            x11_server_fuse_node* volume =
                x11_server_fuse_volume_for_node(provider, node);

            if (volume)
            {
                provider->sink.cancel(volume->peer_id, volume->generation,
                                      pending->request_id,
                                      provider->sink.user_data);
            }
        }
        if (pending->occupied)
            x11_server_fuse_reply_pending_error(pending, error);
    }
}

static librdp_status x11_server_fuse_start(
    void* opaque, const server_platform_drive_sink* sink)
{
    x11_server_fuse* provider = (x11_server_fuse*)opaque;
    struct fuse_args arguments = FUSE_ARGS_INIT(0, NULL);
    int created = 1;

    if (!provider || !sink || !sink->request || !sink->cancel ||
        provider->started ||
        !x11_server_fuse_mount_path_secure(provider->mount_path))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (fuse_opt_add_arg(&arguments, "librdp-x11-server") != 0 ||
        fuse_opt_add_arg(&arguments, "-o") != 0 ||
        fuse_opt_add_arg(&arguments,
                         "ro,default_permissions,nosuid,nodev,noexec,"
                         "fsname=librdp-client-drives") != 0)
        created = 0;
    if (created)
    {
        provider->session =
            fuse_session_new(&arguments, &x11_server_fuse_operations,
                             sizeof(x11_server_fuse_operations), provider);
        created = provider->session != NULL;
    }
    fuse_opt_free_args(&arguments);
    if (!created)
        return LIBRDP_STATUS_NO_MEMORY;
    if (fuse_session_mount(provider->session, provider->mount_path) != 0)
    {
        fuse_session_destroy(provider->session);
        provider->session = NULL;
        return LIBRDP_STATUS_IO_ERROR;
    }
    provider->sink = *sink;
    provider->mounted = 1;
    provider->started = 1;
    provider->descriptor_ready = 0;
    provider->descriptor_failed = 0;
    return LIBRDP_STATUS_OK;
}

static void x11_server_fuse_stop(void* opaque)
{
    x11_server_fuse* provider = (x11_server_fuse*)opaque;
    uint32_t index = 0u;

    if (!provider || !provider->started)
        return;
    x11_server_fuse_abort_pending(provider, ESHUTDOWN);
    if (provider->clipboard_generation != 0u)
    {
        x11_server_fuse_clipboard_clear_internal(
            provider,
            provider->clipboard_peer_id,
            provider->clipboard_peer_generation,
            provider->clipboard_generation);
    }
    for (index = 0u; index < provider->config.max_handles; index++)
        x11_server_fuse_clear_handle(&provider->handles[index]);
    if (provider->session)
    {
        fuse_session_exit(provider->session);
        if (provider->mounted)
            fuse_session_unmount(provider->session);
        fuse_session_destroy(provider->session);
    }
    provider->session = NULL;
    provider->mounted = 0;
    provider->started = 0;
    memset(&provider->sink, 0, sizeof(provider->sink));
}

static x11_server_fuse_node* x11_server_fuse_ensure_peer(
    x11_server_fuse* provider, uint32_t peer_id, uint32_t generation)
{
    uint32_t index = 0u;
    char name[64];
    int length = 0;

    for (index = 0u; index < provider->config.max_nodes; index++)
    {
        x11_server_fuse_node* node = &provider->nodes[index];

        if (node->valid && node->kind == X11_SERVER_FUSE_NODE_PEER &&
            node->peer_id == peer_id && node->generation == generation)
            return node;
    }
    length = snprintf(name, sizeof(name), "peer-%u-%u", peer_id, generation);
    if (length <= 0 || (size_t)length >= sizeof(name))
        return NULL;
    {
        x11_server_fuse_node* node = x11_server_fuse_allocate_node(
            provider, X11_SERVER_FUSE_NODE_PEER, FUSE_ROOT_ID, name, "");

        if (node)
        {
            node->peer_id = peer_id;
            node->generation = generation;
        }
        return node;
    }
}

static librdp_status x11_server_fuse_present(
    void* opaque, const server_platform_drive_volume* volume)
{
    x11_server_fuse* provider = (x11_server_fuse*)opaque;
    x11_server_fuse_node* peer = NULL;
    x11_server_fuse_node* node = NULL;
    char visible_name[X11_SERVER_FUSE_MAX_NAME_BYTES + 1u];
    int length = 0;

    if (!provider || !volume || volume->volume_id == 0u ||
        volume->peer_id == 0u || volume->generation == 0u ||
        volume->device.device_id == 0u ||
        volume->device.reconnect_generation == 0u ||
        !x11_server_fuse_name_valid(volume->name) || !volume->read_only ||
        x11_server_fuse_find_volume(provider, volume->volume_id))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer = x11_server_fuse_ensure_peer(provider, volume->peer_id,
                                       volume->generation);
    if (!peer)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (x11_server_fuse_find_child(provider, peer->inode, volume->name))
    {
        length = snprintf(visible_name, sizeof(visible_name), "%s-%u",
                          volume->name, volume->device.device_id);
        if (length <= 0 || (size_t)length >= sizeof(visible_name))
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    else
    {
        memcpy(visible_name, volume->name, strlen(volume->name) + 1u);
    }
    node = x11_server_fuse_allocate_node(provider, X11_SERVER_FUSE_NODE_VOLUME,
                                         peer->inode, visible_name, "");
    if (!node)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    node->volume_id = volume->volume_id;
    node->peer_id = volume->peer_id;
    node->generation = volume->generation;
    node->device = volume->device;
    node->metadata.directory = 1u;
    node->metadata.attributes = LIBRDP_SERVER_DRIVE_FILE_ATTRIBUTE_DIRECTORY;
    node->metadata_valid = 1;
    if (provider->mounted)
        (void)fuse_lowlevel_notify_inval_inode(provider->session, peer->inode,
                                               0, 0);
    return LIBRDP_STATUS_OK;
}

/*
 * Device removal invalidates kernel requests before inode teardown. The
 * cancellation callback may synchronously complete a request, so occupied is
 * rechecked before sending the terminal FUSE reply.
 */
static void x11_server_fuse_abort_matching(x11_server_fuse* provider,
                                           uint32_t peer_id,
                                           uint32_t generation,
                                           uint32_t device_id, int all_peer)
{
    uint32_t index = 0u;

    if (!provider)
        return;
    for (index = 0u; index < provider->config.max_pending; index++)
    {
        x11_server_fuse_pending* pending = &provider->pending[index];
        x11_server_fuse_node* node = NULL;
        x11_server_fuse_node* volume = NULL;

        if (!pending->occupied)
            continue;
        node = x11_server_fuse_find_node(
            provider, pending->inode != 0u ? pending->inode : pending->parent);
        volume = x11_server_fuse_volume_for_node(provider, node);
        if (!volume || volume->peer_id != peer_id ||
            volume->generation != generation ||
            (!all_peer && volume->device.device_id != device_id))
            continue;
        if (provider->started && provider->sink.cancel)
        {
            provider->sink.cancel(peer_id, generation, pending->request_id,
                                  provider->sink.user_data);
        }
        if (pending->occupied)
            x11_server_fuse_reply_pending_error(pending, ESTALE);
    }
}

static void x11_server_fuse_remove_matching(x11_server_fuse* provider,
                                            uint32_t peer_id,
                                            uint32_t generation,
                                            uint32_t device_id, int all_peer)
{
    uint32_t index = 0u;

    if (!provider)
        return;
    x11_server_fuse_abort_matching(provider, peer_id, generation, device_id,
                                   all_peer);
    for (index = 0u; index < provider->config.max_handles; index++)
    {
        x11_server_fuse_handle* handle = &provider->handles[index];
        x11_server_fuse_node* node =
            handle->occupied
                ? x11_server_fuse_find_node(provider, handle->inode)
                : NULL;
        x11_server_fuse_node* volume =
            x11_server_fuse_volume_for_node(provider, node);

        if (volume && volume->peer_id == peer_id &&
            volume->generation == generation &&
            (all_peer || volume->device.device_id == device_id))
            x11_server_fuse_clear_handle(handle);
    }
    for (index = 0u; index < provider->config.max_nodes; index++)
    {
        x11_server_fuse_node* node = &provider->nodes[index];

        if (!node->valid || node->kind == X11_SERVER_FUSE_NODE_ROOT ||
            node->kind == X11_SERVER_FUSE_NODE_PEER ||
            node->peer_id != peer_id || node->generation != generation ||
            (!all_peer && node->device.device_id != device_id))
            continue;
        x11_server_fuse_invalidate_node(provider, node);
    }
    if (all_peer)
    {
        for (index = 0u; index < provider->config.max_nodes; index++)
        {
            x11_server_fuse_node* node = &provider->nodes[index];

            if (node->valid && node->kind == X11_SERVER_FUSE_NODE_PEER &&
                node->peer_id == peer_id && node->generation == generation)
                x11_server_fuse_invalidate_node(provider, node);
        }
    }
}

static void x11_server_fuse_remove(void* opaque, uint32_t peer_id,
                                   uint32_t generation, uint32_t device_id)
{
    x11_server_fuse_remove_matching((x11_server_fuse*)opaque, peer_id,
                                    generation, device_id, 0);
}

static void x11_server_fuse_remove_peer(void* opaque, uint32_t peer_id,
                                        uint32_t generation)
{
    x11_server_fuse_remove_matching((x11_server_fuse*)opaque, peer_id,
                                    generation, 0u, 1);
}

static const server_platform_drive_vtable x11_server_fuse_drive_vtable = {
    SERVER_PLATFORM_DRIVE_VERSION, sizeof(server_platform_drive_vtable),
    x11_server_fuse_start,         x11_server_fuse_stop,
    x11_server_fuse_present,       x11_server_fuse_remove,
    x11_server_fuse_remove_peer,   x11_server_fuse_complete,
    &x11_server_fuse_event_source,
};

void x11_server_fuse_config_init(x11_server_fuse_config* config)
{
    if (!config)
        return;
    memset(config, 0, sizeof(*config));
    config->version = X11_SERVER_FUSE_CONFIG_VERSION;
    config->size = sizeof(*config);
    config->max_nodes = X11_SERVER_FUSE_DEFAULT_MAX_NODES;
    config->max_handles = X11_SERVER_FUSE_DEFAULT_MAX_HANDLES;
    config->max_pending = X11_SERVER_FUSE_DEFAULT_MAX_PENDING;
    config->max_directory_entries =
        X11_SERVER_FUSE_DEFAULT_MAX_DIRECTORY_ENTRIES;
    config->max_read_bytes = X11_SERVER_FUSE_DEFAULT_MAX_READ_BYTES;
    config->read_only = 1;
}

int x11_server_fuse_available(void)
{
    return 1;
}

x11_server_fuse* x11_server_fuse_new(const x11_server_fuse_config* config)
{
    x11_server_fuse* provider = NULL;
    x11_server_fuse_node* root = NULL;

    if (!x11_server_fuse_config_valid(config) ||
        !x11_server_fuse_mount_path_secure(config->mount_path))
        return NULL;
    provider = (x11_server_fuse*)calloc(1u, sizeof(*provider));
    if (!provider)
        return NULL;
    provider->nodes = (x11_server_fuse_node*)calloc(config->max_nodes,
                                                    sizeof(*provider->nodes));
    provider->handles = (x11_server_fuse_handle*)calloc(
        config->max_handles, sizeof(*provider->handles));
    provider->pending = (x11_server_fuse_pending*)calloc(
        config->max_pending, sizeof(*provider->pending));
    provider->mount_path = x11_server_fuse_copy_string(config->mount_path);
    if (!provider->nodes || !provider->handles || !provider->pending ||
        !provider->mount_path)
    {
        x11_server_fuse_free(provider);
        return NULL;
    }
    provider->config = *config;
    provider->config.mount_path = provider->mount_path;
    provider->next_inode = FUSE_ROOT_ID + 1u;
    provider->next_handle_id = 1u;
    provider->next_request_id = 1u;
    root = &provider->nodes[0];
    root->inode = FUSE_ROOT_ID;
    root->parent = FUSE_ROOT_ID;
    root->kind = X11_SERVER_FUSE_NODE_ROOT;
    root->valid = 1;
    root->name = x11_server_fuse_copy_string("/");
    root->path = x11_server_fuse_copy_string("");
    if (!root->name || !root->path ||
        librdp_server_drive_metadata_init(&root->metadata) != LIBRDP_STATUS_OK)
    {
        x11_server_fuse_free(provider);
        return NULL;
    }
    root->metadata.directory = 1u;
    root->metadata.attributes = LIBRDP_SERVER_DRIVE_FILE_ATTRIBUTE_DIRECTORY;
    root->metadata_valid = 1;
    return provider;
}

void x11_server_fuse_free(x11_server_fuse* provider)
{
    uint32_t index = 0u;

    if (!provider)
        return;
    x11_server_fuse_stop(provider);
    if (provider->handles)
    {
        for (index = 0u; index < provider->config.max_handles; index++)
            x11_server_fuse_clear_handle(&provider->handles[index]);
    }
    if (provider->nodes)
    {
        for (index = 0u; index < provider->config.max_nodes; index++)
        {
            free(provider->nodes[index].name);
            free(provider->nodes[index].path);
        }
    }
    free(provider->nodes);
    free(provider->handles);
    free(provider->pending);
    free(provider->mount_path);
    free(provider);
}

const server_platform_drive_vtable* x11_server_fuse_vtable(void)
{
    return &x11_server_fuse_drive_vtable;
}

librdp_status x11_server_fuse_set_clipboard_sink(
    x11_server_fuse* provider,
    server_platform_clipboard_file_request_callback request,
    server_platform_clipboard_cancel_callback cancel,
    void* user_data)
{
    if (!provider || ((request == NULL) != (cancel == NULL)) ||
        (!request && user_data))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!request && provider->clipboard_generation != 0u)
    {
        x11_server_fuse_clipboard_clear_internal(
            provider,
            provider->clipboard_peer_id,
            provider->clipboard_peer_generation,
            provider->clipboard_generation);
    }
    provider->clipboard_request = request;
    provider->clipboard_cancel = cancel;
    provider->clipboard_user_data = user_data;
    return LIBRDP_STATUS_OK;
}

int x11_server_fuse_clipboard_ready(const x11_server_fuse* provider)
{
    return provider && provider->started && provider->mounted &&
           provider->clipboard_request && provider->clipboard_cancel;
}

librdp_status x11_server_fuse_clipboard_publish(
    x11_server_fuse* provider,
    uint32_t peer_id,
    uint32_t generation,
    uint64_t ownership_generation,
    const void* descriptors,
    size_t descriptors_len,
    uint8_t** uri_list,
    size_t* uri_list_len)
{
    return x11_server_fuse_clipboard_publish_internal(
        provider,
        peer_id,
        generation,
        ownership_generation,
        descriptors,
        descriptors_len,
        uri_list,
        uri_list_len,
        1);
}

librdp_status x11_server_fuse_clipboard_complete(
    x11_server_fuse* provider,
    const server_platform_clipboard_data* data)
{
    x11_server_fuse_pending* pending = NULL;
    x11_server_fuse_node* node = NULL;

    if (!provider || !data || data->request_id == 0u ||
        data->stream_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    pending = x11_server_fuse_find_pending(provider, data->request_id);
    if (!pending ||
        pending->kind != X11_SERVER_FUSE_PENDING_CLIPBOARD_READ)
        return LIBRDP_STATUS_STATE;
    node = x11_server_fuse_find_node(provider, pending->inode);
    if (!x11_server_fuse_clipboard_node_matches(
            node,
            data->peer_id,
            data->generation,
            data->ownership_generation) ||
        pending->stream_id != data->stream_id || !data->final_chunk)
        return LIBRDP_STATUS_STATE;
    if (data->status != LIBRDP_STATUS_OK)
    {
        x11_server_fuse_reply_pending_error(
            pending, x11_server_fuse_status_errno(data->status));
        return data->status;
    }
    if ((!data->data && data->data_len > 0u) ||
        data->data_len > pending->requested_size)
    {
        x11_server_fuse_reply_pending_error(pending, EPROTO);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    (void)fuse_reply_buf(pending->request,
                         (const char*)data->data,
                         data->data_len);
    x11_server_fuse_clear_pending(pending);
    return LIBRDP_STATUS_OK;
}

void x11_server_fuse_clipboard_clear(
    x11_server_fuse* provider,
    uint32_t peer_id,
    uint32_t generation,
    uint64_t ownership_generation)
{
    x11_server_fuse_clipboard_clear_internal(
        provider, peer_id, generation, ownership_generation);
}

#ifdef LIBRDP_X11_SERVER_TESTING
librdp_status x11_server_fuse_test_present(
    x11_server_fuse* provider, const server_platform_drive_volume* volume)
{
    return x11_server_fuse_present(provider, volume);
}

size_t x11_server_fuse_test_volume_count(const x11_server_fuse* provider)
{
    size_t count = 0u;
    uint32_t index = 0u;

    if (!provider)
        return 0u;
    for (index = 0u; index < provider->config.max_nodes; index++)
    {
        if (provider->nodes[index].valid &&
            provider->nodes[index].kind == X11_SERVER_FUSE_NODE_VOLUME)
            count++;
    }
    return count;
}

int x11_server_fuse_test_mount_path_secure(const char* path)
{
    return x11_server_fuse_mount_path_secure(path);
}

librdp_status x11_server_fuse_test_clipboard_publish(
    x11_server_fuse* provider,
    uint32_t peer_id,
    uint32_t generation,
    uint64_t ownership_generation,
    const void* descriptors,
    size_t descriptors_len,
    uint8_t** uri_list,
    size_t* uri_list_len)
{
    return x11_server_fuse_clipboard_publish_internal(
        provider,
        peer_id,
        generation,
        ownership_generation,
        descriptors,
        descriptors_len,
        uri_list,
        uri_list_len,
        0);
}

size_t x11_server_fuse_test_clipboard_file_count(
    const x11_server_fuse* provider)
{
    size_t count = 0u;
    uint32_t index = 0u;

    if (!provider)
        return 0u;
    for (index = 0u; index < provider->config.max_nodes; index++)
    {
        if (provider->nodes[index].valid &&
            provider->nodes[index].kind ==
                X11_SERVER_FUSE_NODE_CLIPBOARD_FILE)
            count++;
    }
    return count;
}
#endif

#else

struct x11_server_fuse
{
    int unavailable;
};

void x11_server_fuse_config_init(x11_server_fuse_config* config)
{
    if (!config)
        return;
    memset(config, 0, sizeof(*config));
    config->version = X11_SERVER_FUSE_CONFIG_VERSION;
    config->size = sizeof(*config);
    config->max_nodes = X11_SERVER_FUSE_DEFAULT_MAX_NODES;
    config->max_handles = X11_SERVER_FUSE_DEFAULT_MAX_HANDLES;
    config->max_pending = X11_SERVER_FUSE_DEFAULT_MAX_PENDING;
    config->max_directory_entries =
        X11_SERVER_FUSE_DEFAULT_MAX_DIRECTORY_ENTRIES;
    config->max_read_bytes = X11_SERVER_FUSE_DEFAULT_MAX_READ_BYTES;
    config->read_only = 1;
}

int x11_server_fuse_available(void)
{
    return 0;
}

x11_server_fuse* x11_server_fuse_new(const x11_server_fuse_config* config)
{
    (void)config;
    return NULL;
}

void x11_server_fuse_free(x11_server_fuse* provider)
{
    (void)provider;
}

const server_platform_drive_vtable* x11_server_fuse_vtable(void)
{
    return NULL;
}

librdp_status x11_server_fuse_set_clipboard_sink(
    x11_server_fuse* provider,
    server_platform_clipboard_file_request_callback request,
    server_platform_clipboard_cancel_callback cancel,
    void* user_data)
{
    (void)provider;
    (void)request;
    (void)cancel;
    (void)user_data;
    return LIBRDP_STATUS_UNSUPPORTED;
}

int x11_server_fuse_clipboard_ready(const x11_server_fuse* provider)
{
    (void)provider;
    return 0;
}

librdp_status x11_server_fuse_clipboard_publish(
    x11_server_fuse* provider,
    uint32_t peer_id,
    uint32_t generation,
    uint64_t ownership_generation,
    const void* descriptors,
    size_t descriptors_len,
    uint8_t** uri_list,
    size_t* uri_list_len)
{
    (void)provider;
    (void)peer_id;
    (void)generation;
    (void)ownership_generation;
    (void)descriptors;
    (void)descriptors_len;
    if (uri_list)
        *uri_list = NULL;
    if (uri_list_len)
        *uri_list_len = 0u;
    return LIBRDP_STATUS_UNSUPPORTED;
}

librdp_status x11_server_fuse_clipboard_complete(
    x11_server_fuse* provider,
    const server_platform_clipboard_data* data)
{
    (void)provider;
    (void)data;
    return LIBRDP_STATUS_UNSUPPORTED;
}

void x11_server_fuse_clipboard_clear(
    x11_server_fuse* provider,
    uint32_t peer_id,
    uint32_t generation,
    uint64_t ownership_generation)
{
    (void)provider;
    (void)peer_id;
    (void)generation;
    (void)ownership_generation;
}

#ifdef LIBRDP_X11_SERVER_TESTING
librdp_status x11_server_fuse_test_present(
    x11_server_fuse* provider, const server_platform_drive_volume* volume)
{
    (void)provider;
    (void)volume;
    return LIBRDP_STATUS_UNSUPPORTED;
}

size_t x11_server_fuse_test_volume_count(const x11_server_fuse* provider)
{
    (void)provider;
    return 0u;
}

int x11_server_fuse_test_mount_path_secure(const char* path)
{
    (void)path;
    return 0;
}

librdp_status x11_server_fuse_test_clipboard_publish(
    x11_server_fuse* provider,
    uint32_t peer_id,
    uint32_t generation,
    uint64_t ownership_generation,
    const void* descriptors,
    size_t descriptors_len,
    uint8_t** uri_list,
    size_t* uri_list_len)
{
    return x11_server_fuse_clipboard_publish(
        provider,
        peer_id,
        generation,
        ownership_generation,
        descriptors,
        descriptors_len,
        uri_list,
        uri_list_len);
}

size_t x11_server_fuse_test_clipboard_file_count(
    const x11_server_fuse* provider)
{
    (void)provider;
    return 0u;
}
#endif

#endif
