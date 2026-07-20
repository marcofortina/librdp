/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: filesystem device redirection for client drive mappings.
 * Invariants: every server path is normalized relative to an opened root dirfd,
 * file IDs reference session-owned redirected handles, and all byte counts are
 * checked against configured limits before I/O.
 * Ownership: opened files, directories, lock ranges, path strings, and drive
 * root descriptors are owned by the session and released by device cleanup.
 * Threading: filesystem IRPs run on the session owner thread; blocking host I/O
 * is bounded by policy and must leave the redirected handle table consistent.
 * Trust boundary: remote filenames, information classes, locks, security blobs,
 * and offsets are untrusted until validated in this module.
 */

#include "client/session_internal.h"
#include "client/settings_internal.h"
#include "common/charset.h"
#include "common/trace.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#if defined(RDP_HAVE_ATTR) && defined(__linux__)
#include <sys/xattr.h>
#endif
#include <time.h>
#include <unistd.h>

librdp_status rdp_session_utf16le_path_to_utf8(const uint8_t* data, uint32_t data_len, char** out)
{
    char* text = NULL;
    size_t text_len = 0;
    size_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !out || data_len < 2u || (data_len & 1u) != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *out = NULL;
    if (data[data_len - 2u] != 0 || data[data_len - 1u] != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i + 3u < data_len; i += 2u)
    {
        if (data[i] == 0 && data[i + 1u] == 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    status = rdp_charset_utf16le_to_utf8_alloc(data, data_len, 1, &text, &text_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < text_len; i++)
    {
        if (text[i] == '\\')
            text[i] = '/';
    }
    *out = text;
    return LIBRDP_STATUS_OK;
}

/*
 * Decode an explicitly sized path field used by rename and hard-link
 * information classes. These fields are not NUL-terminated on the wire;
 * accepting one trailing terminator is harmless for peer compatibility, while
 * embedded terminators remain invalid.
 */
static librdp_status rdp_session_counted_utf16le_path_to_utf8(const uint8_t* data,
                                                              uint32_t data_len,
                                                              char** out)
{
    char* text = NULL;
    size_t effective_len = data_len;
    size_t text_len = 0;
    size_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !out || data_len < 2u || (data_len & 1u) != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *out = NULL;
    if (data[data_len - 2u] == 0 && data[data_len - 1u] == 0)
        effective_len -= 2u;
    if (effective_len == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i + 1u < effective_len; i += 2u)
    {
        if (data[i] == 0 && data[i + 1u] == 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    status = rdp_charset_utf16le_to_utf8_alloc(data, effective_len, 0, &text, &text_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (text_len == 0)
    {
        free(text);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    for (i = 0; i < text_len; i++)
    {
        if (text[i] == '\\')
            text[i] = '/';
    }
    *out = text;
    return LIBRDP_STATUS_OK;
}

static int rdp_session_volume_label_codepoint_valid(uint32_t ch)
{
    if (ch < 0x20u)
        return 0;
    switch (ch)
    {
        case '"':
        case '*':
        case '/':
        case ':':
        case '<':
        case '>':
        case '?':
        case '\\':
        case '|':
            return 0;
        default:
            return 1;
    }
}

static librdp_status rdp_session_utf16le_volume_label_to_utf8(const uint8_t* data,
                                                              uint32_t data_len,
                                                              char* out,
                                                              size_t out_len)
{
    uint32_t units = 0;
    uint32_t position = 0;
    uint32_t chars = 0;
    char* converted = NULL;
    size_t converted_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if ((!data && data_len > 0) || !out || out_len == 0 || (data_len & 1u) != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    out[0] = '\0';
    units = data_len / 2u;
    while (position < units)
    {
        uint32_t ch = (uint32_t)data[position * 2u] | ((uint32_t)data[position * 2u + 1u] << 8u);

        position++;
        if (ch >= 0xd800u && ch <= 0xdbffu)
        {
            uint32_t low = 0;

            if (position >= units)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            low = (uint32_t)data[position * 2u] | ((uint32_t)data[position * 2u + 1u] << 8u);
            if (low < 0xdc00u || low > 0xdfffu)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            position++;
            ch = 0x10000u + (((ch - 0xd800u) << 10u) | (low - 0xdc00u));
        }
        else if (ch >= 0xdc00u && ch <= 0xdfffu)
        {
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (!rdp_session_volume_label_codepoint_valid(ch))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        chars++;
        if (chars > RDP_SESSION_VOLUME_LABEL_MAX_CHARS)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    status = rdp_charset_utf16le_to_utf8_alloc(data, data_len, 0, &converted, &converted_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (converted_len >= out_len)
    {
        free(converted);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    memcpy(out, converted, converted_len + 1u);
    free(converted);
    return LIBRDP_STATUS_OK;
}

static int rdp_session_path_has_unsafe_segment(const char* path, const librdp_drive_policy* policy)
{
    const char* p = path;

    if (!path)
        return 1;
    if (path[0] == '/' || path[0] == '\\')
        return 1;
    while (*p)
    {
        const char* start = p;
        size_t length = 0;

        while (*p && *p != '/')
            p++;
        length = (size_t)(p - start);
        if ((length == 1u && start[0] == '.') ||
            (length == 2u && start[0] == '.' && start[1] == '.'))
            return 1;
        if (policy && policy->deny_dotfiles && length > 0 && start[0] == '.')
            return 1;
        if (memchr(start, ':', length) != NULL)
            return 1;
        if (*p == '/')
            p++;
    }
    return 0;
}

static librdp_status rdp_session_make_local_drive_path(librdp_session* session,
                                                       uint32_t device_id,
                                                       const uint8_t* remote_path,
                                                       uint32_t remote_path_len,
                                                       char** local_path)
{
    uint32_t drive_index = 0;
    char* relative = NULL;
    const librdp_drive_policy* policy = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !remote_path || !local_path)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *local_path = NULL;
    drive_index = rdp_session_drive_index_from_device_id(session, device_id);
    if (drive_index == UINT32_MAX)
        return LIBRDP_STATUS_STATE;
    policy = rdp_settings_drive_policy_internal(session->settings, drive_index);
    status = rdp_session_utf16le_path_to_utf8(remote_path, remote_path_len, &relative);
    if (status != LIBRDP_STATUS_OK)
        return status;
    while (relative[0] == '/')
        memmove(relative, relative + 1, strlen(relative));
    if (rdp_session_path_has_unsafe_segment(relative, policy))
    {
        free(relative);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    *local_path = relative;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_make_counted_local_drive_path(librdp_session* session,
                                                               uint32_t device_id,
                                                               const uint8_t* remote_path,
                                                               uint32_t remote_path_len,
                                                               char** local_path)
{
    uint32_t drive_index = 0;
    char* relative = NULL;
    const librdp_drive_policy* policy = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !remote_path || !local_path)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *local_path = NULL;
    drive_index = rdp_session_drive_index_from_device_id(session, device_id);
    if (drive_index == UINT32_MAX)
        return LIBRDP_STATUS_STATE;
    policy = rdp_settings_drive_policy_internal(session->settings, drive_index);
    status = rdp_session_counted_utf16le_path_to_utf8(remote_path, remote_path_len, &relative);
    if (status != LIBRDP_STATUS_OK)
        return status;
    while (relative[0] == '/')
        memmove(relative, relative + 1, strlen(relative));
    if (relative[0] == '\0' || rdp_session_path_has_unsafe_segment(relative, policy))
    {
        free(relative);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    *local_path = relative;
    return LIBRDP_STATUS_OK;
}

char* rdp_session_strdup_range(const char* data, size_t length);

static char* rdp_session_drive_basename_dup(const char* path)
{
    const char* slash = NULL;

    if (!path || path[0] == '\0')
        return rdp_session_strdup_range(".", 1u);
    slash = strrchr(path, '/');
    return rdp_session_strdup_range(slash ? slash + 1 : path, strlen(slash ? slash + 1 : path));
}

/*
 * Open the directory containing a relative drive path. Every intermediate
 * component is opened with O_NOFOLLOW so a server-controlled path cannot escape
 * through symlinks inside the shared tree.
 */
static uint32_t rdp_session_drive_open_parent_dir(librdp_session* session,
                                                  uint32_t device_id,
                                                  const char* relative_path,
                                                  int* parent_fd,
                                                  char** basename)
{
    uint32_t drive_index = 0;
    int current_fd = -1;
    char* parent_path = NULL;
    char* cursor = NULL;
    char* next = NULL;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;

    if (!session || !relative_path || !parent_fd || !basename)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (relative_path[0] == '/')
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    *parent_fd = -1;
    *basename = NULL;
    drive_index = rdp_session_drive_index_from_device_id(session, device_id);
    if (drive_index == UINT32_MAX)
        return RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    io_status = rdp_session_drive_root_fd(session, drive_index, &current_fd);
    if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
        return io_status;
    current_fd = dup(current_fd);
    if (current_fd < 0)
        return rdp_session_errno_to_device_status(errno);
    *basename = rdp_session_drive_basename_dup(relative_path);
    if (!*basename)
    {
        (void)close(current_fd);
        return RDP_SESSION_DEVICE_NOT_SUPPORTED;
    }
    parent_path = rdp_session_strdup_range(relative_path, strlen(relative_path));
    if (!parent_path)
    {
        free(*basename);
        *basename = NULL;
        (void)close(current_fd);
        return RDP_SESSION_DEVICE_NOT_SUPPORTED;
    }
    next = strrchr(parent_path, '/');
    if (!next)
    {
        free(parent_path);
        *parent_fd = current_fd;
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    }
    *next = '\0';
    cursor = parent_path;
    while (*cursor)
    {
        int next_fd = -1;
        char* slash = strchr(cursor, '/');

        if (slash)
            *slash = '\0';
        if (cursor[0] != '\0')
        {
            next_fd = openat(current_fd, cursor, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (next_fd < 0)
            {
                io_status = rdp_session_errno_to_device_status(errno);
                free(parent_path);
                free(*basename);
                *basename = NULL;
                (void)close(current_fd);
                return io_status;
            }
            (void)close(current_fd);
            current_fd = next_fd;
        }
        if (!slash)
            break;
        cursor = slash + 1;
    }
    free(parent_path);
    *parent_fd = current_fd;
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static uint32_t rdp_session_drive_fstatat(librdp_session* session,
                                          uint32_t device_id,
                                          const char* relative_path,
                                          struct stat* st,
                                          int* exists)
{
    int parent_fd = -1;
    char* basename = NULL;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;

    if (!session || !relative_path || !st)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (exists)
        *exists = 0;
    memset(st, 0, sizeof(*st));
    if (relative_path[0] == '\0')
    {
        uint32_t drive_index = rdp_session_drive_index_from_device_id(session, device_id);
        int root_fd = -1;

        if (drive_index == UINT32_MAX)
            return RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
        io_status = rdp_session_drive_root_fd(session, drive_index, &root_fd);
        if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            return io_status;
        if (fstat(root_fd, st) != 0)
            return rdp_session_errno_to_device_status(errno);
        if (exists)
            *exists = 1;
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    }
    io_status = rdp_session_drive_open_parent_dir(session, device_id, relative_path, &parent_fd, &basename);
    if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
        return io_status;
    if (!basename)
    {
        (void)close(parent_fd);
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    }
    if (fstatat(parent_fd, basename, st, AT_SYMLINK_NOFOLLOW) != 0)
    {
        if (errno == ENOENT)
            io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
        else
            io_status = rdp_session_errno_to_device_status(errno);
    }
    else if (exists)
    {
        *exists = 1;
    }
    free(basename);
    (void)close(parent_fd);
    return io_status;
}

static uint32_t rdp_session_drive_open_path(librdp_session* session,
                                            uint32_t device_id,
                                            const char* relative_path,
                                            int flags,
                                            mode_t mode,
                                            int* fd)
{
    uint32_t drive_index = 0;
    const librdp_drive_policy* policy = NULL;
    int parent_fd = -1;
    char* basename = NULL;
    struct stat st;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;

    if (!session || !relative_path || !fd)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    *fd = -1;
    drive_index = rdp_session_drive_index_from_device_id(session, device_id);
    if (drive_index == UINT32_MAX)
        return RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    policy = rdp_settings_drive_policy_internal(session->settings, drive_index);
    if (policy && policy->read_only && ((flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) != 0))
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    if (relative_path[0] == '\0')
    {
        int root_fd = -1;

        io_status = rdp_session_drive_root_fd(session, drive_index, &root_fd);
        if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            return io_status;
        *fd = openat(root_fd,
                     ".",
                     flags | O_CLOEXEC | O_NOFOLLOW,
                     mode);
        return *fd >= 0 ? RDP_DEVICE_REDIRECTION_STATUS_SUCCESS : rdp_session_errno_to_device_status(errno);
    }
    io_status = rdp_session_drive_open_parent_dir(session, device_id, relative_path, &parent_fd, &basename);
    if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
        return io_status;
    if (!basename)
    {
        (void)close(parent_fd);
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    }
    *fd = openat(parent_fd, basename, flags | O_CLOEXEC | O_NOFOLLOW, mode);
    if (*fd < 0)
        io_status = rdp_session_errno_to_device_status(errno);
    else if (fstat(*fd, &st) != 0)
        io_status = rdp_session_errno_to_device_status(errno);
    else if (policy && policy->deny_device_files && !S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
        io_status = RDP_SESSION_DEVICE_ACCESS_DENIED;
    if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS && *fd >= 0)
    {
        (void)close(*fd);
        *fd = -1;
    }
    free(basename);
    (void)close(parent_fd);
    return io_status;
}

static uint32_t rdp_session_drive_unlinkat(librdp_session* session,
                                           uint32_t device_id,
                                           const char* relative_path,
                                           int flags)
{
    int parent_fd = -1;
    char* basename = NULL;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;

    io_status = rdp_session_drive_open_parent_dir(session, device_id, relative_path, &parent_fd, &basename);
    if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
        return io_status;
    if (!basename)
    {
        (void)close(parent_fd);
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    }
    if (unlinkat(parent_fd, basename, flags) != 0)
        io_status = rdp_session_errno_to_device_status(errno);
    free(basename);
    (void)close(parent_fd);
    return io_status;
}

static uint32_t rdp_session_drive_renameat(librdp_session* session,
                                           uint32_t device_id,
                                           const char* old_path,
                                           const char* new_path)
{
    int old_parent_fd = -1;
    int new_parent_fd = -1;
    char* old_base = NULL;
    char* new_base = NULL;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;

    io_status = rdp_session_drive_open_parent_dir(session, device_id, old_path, &old_parent_fd, &old_base);
    if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
        io_status = rdp_session_drive_open_parent_dir(session, device_id, new_path, &new_parent_fd, &new_base);
    if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS && (!old_base || !new_base))
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS &&
        renameat(old_parent_fd, old_base, new_parent_fd, new_base) != 0)
        io_status = rdp_session_errno_to_device_status(errno);
    free(old_base);
    free(new_base);
    if (old_parent_fd >= 0)
        (void)close(old_parent_fd);
    if (new_parent_fd >= 0)
        (void)close(new_parent_fd);
    return io_status;
}

static uint32_t rdp_session_drive_verify_path_matches_file(librdp_session* session,
                                                           uint32_t device_id,
                                                           const char* relative_path,
                                                           int fd)
{
    struct stat handle_st;
    struct stat path_st;
    int exists = 0;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;

    if (!session || !relative_path || fd < 0)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    memset(&handle_st, 0, sizeof(handle_st));
    memset(&path_st, 0, sizeof(path_st));
    if (fstat(fd, &handle_st) != 0)
        return rdp_session_errno_to_device_status(errno);
    io_status = rdp_session_drive_fstatat(session, device_id, relative_path, &path_st, &exists);
    if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
        return io_status;
    if (!exists || handle_st.st_dev != path_st.st_dev || handle_st.st_ino != path_st.st_ino)
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static int rdp_session_open_flags_from_create(const rdp_filesystem_redirection_create_request* request,
                                              uint8_t existed)
{
    int write_requested = 0;
    int flags = O_RDONLY;

    if (!request)
        return -1;
    write_requested = (request->desired_access & 0x40000000u) != 0 ||
                      (request->desired_access & 0x00000006u) != 0 ||
                      request->create_disposition == 0 ||
                      request->create_disposition == 2 ||
                      request->create_disposition == 4 ||
                      request->create_disposition == 5;
    if (write_requested)
        flags = O_RDWR;
    switch (request->create_disposition)
    {
        case 0:
            flags |= O_CREAT | O_TRUNC;
            break;
        case 1:
            break;
        case 2:
            flags |= O_CREAT | O_EXCL;
            break;
        case 3:
            flags |= O_CREAT;
            break;
        case 4:
            if (!existed)
                return -1;
            flags |= O_TRUNC;
            break;
        case 5:
            flags |= O_CREAT | O_TRUNC;
            break;
        default:
            return -1;
    }
    return flags;
}

static uint8_t rdp_session_create_information(const rdp_filesystem_redirection_create_request* request,
                                              uint8_t existed)
{
    if (!request)
        return RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_SUPERSEDED;
    if (request->create_disposition == 2 || (request->create_disposition == 3 && !existed) ||
        (request->create_disposition == 5 && !existed))
        return RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_CREATED;
    if (request->create_disposition == 3 && existed)
        return RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_OPENED;
    if (request->create_disposition == 4)
        return RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_OVERWRITTEN;
    if (request->create_disposition == 5 && existed)
        return RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_OVERWRITTEN;
    return RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_SUPERSEDED;
}

uint32_t rdp_session_filesystem_error_from_status(librdp_status status)
{
    switch (status)
    {
        case LIBRDP_STATUS_OK:
            return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
        case LIBRDP_STATUS_NO_MEMORY:
            return RDP_SESSION_DEVICE_NOT_SUPPORTED;
        case LIBRDP_STATUS_STATE:
            return RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
        case LIBRDP_STATUS_INVALID_ARGUMENT:
        case LIBRDP_STATUS_PROTOCOL_ERROR:
        default:
            return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    }
}

int rdp_session_seek_fd(int fd, uint64_t offset)
{
    if (sizeof(off_t) < sizeof(uint64_t) && offset > (uint64_t)LONG_MAX)
    {
        errno = EINVAL;
        return -1;
    }
    if (offset > (uint64_t)INT64_MAX)
    {
        errno = EINVAL;
        return -1;
    }
    return lseek(fd, (off_t)offset, SEEK_SET) == (off_t)-1 ? -1 : 0;
}

static librdp_status rdp_session_append_u64_le(rdp_buffer* buffer, uint64_t value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, (uint32_t)(value & 0xffffffffu));
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, (uint32_t)(value >> 32));
}

static librdp_status rdp_session_append_zero(rdp_buffer* buffer, size_t length)
{
    static const uint8_t zero[32] = {0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (length > 0)
    {
        size_t chunk = length < sizeof(zero) ? length : sizeof(zero);

        status = rdp_buffer_append(buffer, zero, chunk);
        if (status != LIBRDP_STATUS_OK)
            return status;
        length -= chunk;
    }
    return LIBRDP_STATUS_OK;
}

static uint64_t rdp_session_filetime_from_parts(int64_t seconds, long nanoseconds)
{
    const int64_t epoch_delta = 11644473600ll;
    uint64_t base = 0;

    if (seconds < -epoch_delta)
        return 0;
    base = (uint64_t)(seconds + epoch_delta) * 10000000ull;
    if (nanoseconds > 0)
        base += (uint64_t)nanoseconds / 100u;
    return base;
}

static uint64_t rdp_session_read_u64_le_raw(const uint8_t* data)
{
    if (!data)
        return 0;
    return (uint64_t)data[0] | ((uint64_t)data[1] << 8) | ((uint64_t)data[2] << 16) |
           ((uint64_t)data[3] << 24) | ((uint64_t)data[4] << 32) | ((uint64_t)data[5] << 40) |
           ((uint64_t)data[6] << 48) | ((uint64_t)data[7] << 56);
}

static uint32_t rdp_session_read_u32_le_raw(const uint8_t* data)
{
    if (!data)
        return 0;
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

#if defined(RDP_HAVE_ATTR) && defined(__linux__)
static void rdp_session_write_u32_le_raw(uint8_t* data, uint32_t value)
{
    if (!data)
        return;
    data[0] = (uint8_t)(value & 0xffu);
    data[1] = (uint8_t)((value >> 8) & 0xffu);
    data[2] = (uint8_t)((value >> 16) & 0xffu);
    data[3] = (uint8_t)((value >> 24) & 0xffu);
}
#endif

static uint16_t rdp_session_read_u16_le_raw(const uint8_t* data)
{
    if (!data)
        return 0;
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

static int rdp_session_timespec_from_filetime(uint64_t filetime, struct timespec* out)
{
    uint64_t unix_100ns = 0;

    if (!out)
        return -1;
    if (filetime == 0)
    {
        out->tv_nsec = UTIME_OMIT;
        out->tv_sec = 0;
        return 0;
    }
    if (filetime < 116444736000000000ull)
        return -1;
    unix_100ns = filetime - 116444736000000000ull;
    if (unix_100ns / 10000000ull > (uint64_t)LONG_MAX)
        return -1;
    out->tv_sec = (time_t)(unix_100ns / 10000000ull);
    out->tv_nsec = (long)((unix_100ns % 10000000ull) * 100ull);
    return 0;
}

static uint64_t rdp_session_stat_atime(const struct stat* st)
{
    if (!st)
        return 0;
#if defined(__APPLE__) || defined(__FreeBSD__)
    return rdp_session_filetime_from_parts((int64_t)st->st_atimespec.tv_sec, st->st_atimespec.tv_nsec);
#else
    return rdp_session_filetime_from_parts((int64_t)st->st_atim.tv_sec, st->st_atim.tv_nsec);
#endif
}

static uint64_t rdp_session_stat_mtime(const struct stat* st)
{
    if (!st)
        return 0;
#if defined(__APPLE__) || defined(__FreeBSD__)
    return rdp_session_filetime_from_parts((int64_t)st->st_mtimespec.tv_sec, st->st_mtimespec.tv_nsec);
#else
    return rdp_session_filetime_from_parts((int64_t)st->st_mtim.tv_sec, st->st_mtim.tv_nsec);
#endif
}

static uint64_t rdp_session_stat_ctime(const struct stat* st)
{
    if (!st)
        return 0;
#if defined(__APPLE__) || defined(__FreeBSD__)
    return rdp_session_filetime_from_parts((int64_t)st->st_ctimespec.tv_sec, st->st_ctimespec.tv_nsec);
#else
    return rdp_session_filetime_from_parts((int64_t)st->st_ctim.tv_sec, st->st_ctim.tv_nsec);
#endif
}

static uint64_t rdp_session_stat_size(const struct stat* st)
{
    if (!st || S_ISDIR(st->st_mode) || st->st_size < 0)
        return 0;
    return (uint64_t)st->st_size;
}

static uint64_t rdp_session_stat_allocation_size(const struct stat* st)
{
    if (!st || S_ISDIR(st->st_mode))
        return 0;
#if defined(st_blocks)
    if (st->st_blocks > 0)
        return (uint64_t)st->st_blocks * 512ull;
#endif
    return rdp_session_stat_size(st);
}

static uint64_t rdp_session_stat_file_id(const struct stat* st)
{
    if (!st)
        return 0;
    return (uint64_t)st->st_ino;
}

static uint64_t rdp_session_stat_volume_serial(const struct stat* st)
{
    if (!st)
        return 0;
    return (uint64_t)st->st_dev;
}

static uint32_t rdp_session_stat_attributes(const struct stat* st)
{
    uint32_t attributes = 0;

    if (!st)
        return RDP_SESSION_FILE_ATTRIBUTE_NORMAL;
    if (S_ISDIR(st->st_mode))
        attributes |= RDP_SESSION_FILE_ATTRIBUTE_DIRECTORY;
    else
        attributes |= RDP_SESSION_FILE_ATTRIBUTE_NORMAL;
    if ((st->st_mode & S_IWUSR) == 0)
        attributes |= RDP_SESSION_FILE_ATTRIBUTE_READONLY;
    return attributes;
}

librdp_status rdp_session_utf8_to_utf16le(const char* text, rdp_buffer* out, uint8_t append_null)
{
    if (!text || !out)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_charset_utf8_to_utf16le_buffer(text, append_null != 0, out);
}

/*
 * Send the RAIL startup exchange required before remote-application orders are
 * meaningful. Startup state is updated only after the packet is queued so
 * retries and failures remain observable.
 */
librdp_status rdp_session_send_remote_programs_startup(librdp_session* session)
{
    rdp_buffer packet;
    uint32_t app_count = 0;
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->remote_programs_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&packet);
    status = rdp_remote_programs_write_u32_order(&packet,
                                                 RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE,
                                                 22621u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_remote_programs_packet(session,
                                                         &packet,
                                                         "client.rail.handshake");
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_handshake_ex(&packet,
                                                        22621u,
                                                        RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_HIDEF |
                                                            RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_EXTENDED_SPI |
                                                            RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_SNAP_ARRANGE |
                                                            RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_TEXT_SCALE |
                                                            RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_CARET_BLINK);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_remote_programs_packet(session,
                                                         &packet,
                                                         "client.rail.handshake_ex");
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_u32_order(
            &packet,
            RDP_REMOTE_PROGRAMS_ORDER_CLIENTSTATUS,
            RDP_REMOTE_PROGRAMS_CLIENTSTATUS_ALLOW_LOCAL_MOVE_SIZE |
                RDP_REMOTE_PROGRAMS_CLIENTSTATUS_AUTORECONNECT |
                RDP_REMOTE_PROGRAMS_CLIENTSTATUS_ZORDER_SYNC |
                RDP_REMOTE_PROGRAMS_CLIENTSTATUS_RESIZE_MARGIN |
                RDP_REMOTE_PROGRAMS_CLIENTSTATUS_HIGH_DPI_ICONS |
                RDP_REMOTE_PROGRAMS_CLIENTSTATUS_APPBAR_REMOTING |
                RDP_REMOTE_PROGRAMS_CLIENTSTATUS_BIDIRECTIONAL_CLOAK);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_remote_programs_packet(session,
                                                         &packet,
                                                         "client.rail.client_status");
    rdp_buffer_free(&packet);

    app_count = librdp_settings_rail_app_count(session->settings);
    for (i = 0; status == LIBRDP_STATUS_OK && i < app_count; i++)
    {
        const char* app = librdp_settings_rail_app(session->settings, i);
        rdp_buffer exe;

        rdp_buffer_init(&exe);
        if (!app || app[0] == '\0')
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_utf8_to_utf16le(app, &exe, 0);
        if (status == LIBRDP_STATUS_OK && (exe.length == 0 || exe.length > UINT16_MAX))
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_buffer_init(&packet);
            status = rdp_remote_programs_write_exec(&packet,
                                                    RDP_REMOTE_PROGRAMS_EXEC_FLAG_EXPAND_WORKINGDIRECTORY |
                                                        RDP_REMOTE_PROGRAMS_EXEC_FLAG_EXPAND_ARGUMENTS,
                                                    exe.data,
                                                    (uint16_t)exe.length,
                                                    NULL,
                                                    0,
                                                    NULL,
                                                    0);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_remote_programs_packet(session, &packet, "client.rail.exec");
        rdp_buffer_free(&packet);
        rdp_buffer_free(&exe);
        if (status == LIBRDP_STATUS_OK)
        {
            session->remote_programs_exec_sent = 1;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rail.exec",
                            "index=%u app_bytes=%u",
                            i,
                            (unsigned)strlen(app));
        }
    }
    if (status == LIBRDP_STATUS_OK)
    {
        session->remote_programs_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rail.ready",
                        "apps=%u",
                        app_count);
    }
    return status;
}

/*
 * RAIL messages can arrive before the startup exchange has been completed.
 * This dispatcher lazily sends the startup PDU, then routes orders while
 * preserving the session-side app launch state used by later window lifecycle
 * handling.
 */
librdp_status rdp_session_handle_remote_programs_message(librdp_session* session,
                                                                const uint8_t* data,
                                                                size_t data_len)
{
    rdp_remote_programs_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_remote_programs_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.rail.pdu",
                          "channel_id=%u order=%u length=%u",
                          session->remote_programs_channel_id,
                          header.order_type,
                          header.order_length);
    if (!session->remote_programs_ready)
    {
        status = rdp_session_send_remote_programs_startup(session);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    switch (header.order_type)
    {
        case RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE:
        case RDP_REMOTE_PROGRAMS_ORDER_CLIENTSTATUS:
        case RDP_REMOTE_PROGRAMS_ORDER_SYSPARAM:
        case RDP_REMOTE_PROGRAMS_ORDER_LANGBARINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_GET_APPID_REQ:
        case RDP_REMOTE_PROGRAMS_ORDER_GET_APPID_RESP:
        case RDP_REMOTE_PROGRAMS_ORDER_TASKBARINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_LANGUAGEIMEINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_COMPARTMENTINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_ZORDER_SYNC:
        case RDP_REMOTE_PROGRAMS_ORDER_CLOAK:
        case RDP_REMOTE_PROGRAMS_ORDER_POWER_DISPLAY_REQUEST:
        case RDP_REMOTE_PROGRAMS_ORDER_SNAP_ARRANGE:
        case RDP_REMOTE_PROGRAMS_ORDER_GET_APPID_RESP_EX:
        case RDP_REMOTE_PROGRAMS_ORDER_TEXTSCALEINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_CARETBLINKINFO:
        {
            rdp_remote_programs_opaque opaque;

            status = rdp_remote_programs_parse_opaque(data, data_len, &opaque);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event_level(RDP_TRACE_CLIENT,
                                      RDP_TRACE_LEVEL_DEBUG,
                                      "client.rail.order",
                                      "order=%u payload_len=%u",
                                      opaque.header.order_type,
                                      (unsigned)opaque.payload_len);
            break;
        }
        case RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE_EX:
        {
            rdp_remote_programs_handshake_ex order;

            status = rdp_remote_programs_parse_handshake_ex(data, data_len, &order);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rail.handshake_ex.server",
                                "build=%u flags=%u",
                                order.build_number,
                                order.flags);
            break;
        }
        case RDP_REMOTE_PROGRAMS_ORDER_ACTIVATE:
        {
            rdp_remote_programs_activate order;

            status = rdp_remote_programs_parse_activate(data, data_len, &order);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rail.activate",
                                "window_id=%u enabled=%u",
                                order.window_id,
                                order.enabled);
            break;
        }
        case RDP_REMOTE_PROGRAMS_ORDER_SYSMENU:
        {
            rdp_remote_programs_sysmenu order;

            status = rdp_remote_programs_parse_sysmenu(data, data_len, &order);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rail.sysmenu",
                                "window_id=%u left=%d top=%d",
                                order.window_id,
                                order.left,
                                order.top);
            break;
        }
        case RDP_REMOTE_PROGRAMS_ORDER_SYSCOMMAND:
        {
            rdp_remote_programs_syscommand order;

            status = rdp_remote_programs_parse_syscommand(data, data_len, &order);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rail.syscommand",
                                "window_id=%u command=%u",
                                order.window_id,
                                order.command);
            break;
        }
        case RDP_REMOTE_PROGRAMS_ORDER_NOTIFY_EVENT:
        {
            rdp_remote_programs_notify_event order;

            status = rdp_remote_programs_parse_notify_event(data, data_len, &order);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rail.notify_event",
                                "window_id=%u notify_icon_id=%u message=%u",
                                order.window_id,
                                order.notify_icon_id,
                                order.message);
            break;
        }
        case RDP_REMOTE_PROGRAMS_ORDER_WINDOWMOVE:
        {
            rdp_remote_programs_windowmove order;

            status = rdp_remote_programs_parse_windowmove(data, data_len, &order);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rail.windowmove",
                                "window_id=%u left=%d top=%d right=%d bottom=%d",
                                order.window_id,
                                order.left,
                                order.top,
                                order.right,
                                order.bottom);
            break;
        }
        case RDP_REMOTE_PROGRAMS_ORDER_LOCALMOVESIZE:
        {
            rdp_remote_programs_localmovesize order;

            status = rdp_remote_programs_parse_localmovesize(data, data_len, &order);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rail.localmovesize",
                                "window_id=%u start=%u move_size_type=%u pos_x=%d pos_y=%d",
                                order.window_id,
                                order.is_move_size_start,
                                order.move_size_type,
                                order.pos_x,
                                order.pos_y);
            break;
        }
        case RDP_REMOTE_PROGRAMS_ORDER_MINMAXINFO:
        {
            rdp_remote_programs_minmaxinfo order;

            status = rdp_remote_programs_parse_minmaxinfo(data, data_len, &order);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rail.minmaxinfo",
                                "window_id=%u max=%dx%d max_pos=%d,%d min_track=%dx%d max_track=%dx%d",
                                order.window_id,
                                order.max_width,
                                order.max_height,
                                order.max_pos_x,
                                order.max_pos_y,
                                order.min_track_width,
                                order.min_track_height,
                                order.max_track_width,
                                order.max_track_height);
            break;
        }
        case RDP_REMOTE_PROGRAMS_ORDER_EXEC_RESULT:
        {
            rdp_remote_programs_exec_result result;

            status = rdp_remote_programs_parse_exec_result(data, data_len, &result);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rail.exec_result",
                                "flags=%u result=%u raw=%u exe_len=%u",
                                result.flags,
                                result.exec_result,
                                result.raw_result,
                                result.exe_or_file_len);
            break;
        }
        default:
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
    }
    return status;
}

static librdp_status rdp_session_write_file_basic_information(rdp_buffer* buffer,
                                                              const struct stat* st)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint64_t change_time = rdp_session_stat_ctime(st);

    status = rdp_buffer_append_u32_le(buffer, 36);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, change_time);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_atime(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_mtime(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, change_time);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, rdp_session_stat_attributes(st));
    return status;
}

static librdp_status rdp_session_write_file_standard_information(rdp_buffer* buffer,
                                                                 const struct stat* st)
{
    uint64_t size = rdp_session_stat_size(st);
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, 22);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_allocation_size(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, size);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, st && st->st_nlink > 0 ? (uint32_t)st->st_nlink : 1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, st && S_ISDIR(st->st_mode) ? 1u : 0u);
    return status;
}

static librdp_status rdp_session_write_file_attribute_tag_information(rdp_buffer* buffer,
                                                                      const struct stat* st)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, 8);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, rdp_session_stat_attributes(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    return status;
}

static librdp_status rdp_session_write_file_size_information(rdp_buffer* buffer,
                                                             uint64_t size)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, 8);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, size);
    return status;
}

static librdp_status rdp_session_write_file_internal_information(rdp_buffer* buffer,
                                                                 const struct stat* st)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, 8);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, st ? (uint64_t)st->st_ino : 0);
    return status;
}

static librdp_status rdp_session_write_file_network_open_information(rdp_buffer* buffer,
                                                                     const struct stat* st)
{
    uint64_t change_time = rdp_session_stat_ctime(st);
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, 56);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, change_time);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_atime(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_mtime(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, change_time);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_allocation_size(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_size(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, rdp_session_stat_attributes(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    return status;
}

static librdp_status rdp_session_write_file_name_information(rdp_buffer* buffer,
                                                             const char* path)
{
    const char* name = NULL;
    const char* slash = NULL;
    rdp_buffer utf16;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !path)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    slash = strrchr(path, '/');
    name = slash ? slash + 1 : path;
    rdp_buffer_init(&utf16);
    status = rdp_session_utf8_to_utf16le(name, &utf16, 0);
    if (status == LIBRDP_STATUS_OK && utf16.length > UINT32_MAX)
        status = LIBRDP_STATUS_NO_MEMORY;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 4u + (uint32_t)utf16.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, (uint32_t)utf16.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, utf16.data, utf16.length);
    rdp_buffer_free(&utf16);
    return status;
}

static librdp_status rdp_session_write_file_normalized_name_information(rdp_buffer* buffer,
                                                                        const char* path)
{
    return rdp_session_write_file_name_information(buffer, path);
}

static librdp_status rdp_session_write_file_id_information(rdp_buffer* buffer,
                                                           const struct stat* st)
{
    uint64_t file_id = rdp_session_stat_file_id(st);
    uint64_t volume_serial = rdp_session_stat_volume_serial(st);
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !st)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, 24);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, volume_serial);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, file_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, volume_serial ^ (file_id << 1u));
    return status;
}

static librdp_status rdp_session_append_file_id_128(rdp_buffer* buffer,
                                                    const struct stat* st)
{
    uint64_t file_id = rdp_session_stat_file_id(st);
    uint64_t volume_serial = rdp_session_stat_volume_serial(st);
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !st)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_append_u64_le(buffer, file_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, volume_serial ^ (file_id << 1u));
    return status;
}

static librdp_status rdp_session_write_file_alternate_name_information(rdp_buffer* buffer)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, 4);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    return status;
}

static librdp_status rdp_session_write_file_stream_information(rdp_buffer* buffer,
                                                               const struct stat* st)
{
    static const uint8_t stream_name[] = {
        ':', 0, ':', 0, '$', 0, 'D', 0, 'A', 0, 'T', 0, 'A', 0};
    uint64_t size = rdp_session_stat_size(st);
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, 24u + (uint32_t)sizeof(stream_name));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, (uint32_t)sizeof(stream_name));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, size);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_allocation_size(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, stream_name, sizeof(stream_name));
    return status;
}

static librdp_status rdp_session_write_file_compression_information(rdp_buffer* buffer,
                                                                    const struct stat* st)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, 16);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_allocation_size(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_zero(buffer, 3);
    return status;
}

static librdp_status rdp_session_write_file_position_information(rdp_buffer* buffer,
                                                                 int fd)
{
    off_t position = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || fd < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    position = lseek(fd, 0, SEEK_CUR);
    if (position == (off_t)-1)
        return LIBRDP_STATUS_STATE;
    status = rdp_buffer_append_u32_le(buffer, 8);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, (uint64_t)position);
    return status;
}

static librdp_status rdp_session_current_file_position(int fd, uint64_t* position)
{
    off_t current = 0;

    if (!position || fd < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    current = lseek(fd, 0, SEEK_CUR);
    if (current == (off_t)-1)
        return LIBRDP_STATUS_STATE;
    *position = (uint64_t)current;
    return LIBRDP_STATUS_OK;
}

/*
 * Serialize FileAllInformation for redirected filesystem and printer handles.
 * The writer derives every variable-length field from trusted host metadata
 * and fails on overflow before appending the composite response.
 */
static librdp_status rdp_session_write_file_all_information(rdp_buffer* buffer,
                                                            const struct stat* st,
                                                            const rdp_session_redirected_file* file)
{
    const char* path = file ? file->path : NULL;
    const char* name = NULL;
    const char* slash = NULL;
    rdp_buffer utf16;
    uint64_t change_time = 0;
    uint64_t position = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !st || !path || !file)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    slash = strrchr(path, '/');
    name = slash ? slash + 1 : path;
    rdp_buffer_init(&utf16);
    status = rdp_session_utf8_to_utf16le(name, &utf16, 0);
    if (status == LIBRDP_STATUS_OK && utf16.length > UINT32_MAX - 100u)
        status = LIBRDP_STATUS_NO_MEMORY;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_current_file_position(file->fd, &position);
    change_time = rdp_session_stat_ctime(st);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 100u + (uint32_t)utf16.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, change_time);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_atime(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_mtime(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, change_time);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, rdp_session_stat_attributes(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_zero(buffer, 4u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_allocation_size(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_size(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, st->st_nlink > 0 ? (uint32_t)st->st_nlink : 1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, file->delete_pending ? 1u : 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, S_ISDIR(st->st_mode) ? 1u : 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_zero(buffer, 2u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_file_id(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, file->desired_access);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, position);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, file->create_options);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, (uint32_t)utf16.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, utf16.data, utf16.length);
    rdp_buffer_free(&utf16);
    return status;
}

static librdp_status rdp_session_write_file_u32_information(rdp_buffer* buffer,
                                                            uint32_t value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, 4);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, value);
    return status;
}

#if defined(RDP_HAVE_ATTR) && defined(__linux__)
static size_t rdp_session_file_ea_entry_stride(size_t name_len, size_t value_len)
{
    size_t length = 8u + name_len + 1u + value_len;

    return (length + 3u) & ~(size_t)3u;
}
#endif

static librdp_status rdp_session_file_ea_size(int fd, uint32_t* ea_size)
{
#if defined(RDP_HAVE_ATTR) && defined(__linux__)
    ssize_t list_len = 0;
    char* names = NULL;
    size_t cursor = 0;
    size_t total = 0;

    if (!ea_size || fd < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *ea_size = 0;
    list_len = flistxattr(fd, NULL, 0);
    if (list_len < 0)
    {
        if (errno == ENOTSUP || errno == ENODATA)
            return LIBRDP_STATUS_OK;
        return LIBRDP_STATUS_STATE;
    }
    if (list_len == 0)
        return LIBRDP_STATUS_OK;
    names = (char*)malloc((size_t)list_len);
    if (!names)
        return LIBRDP_STATUS_NO_MEMORY;
    list_len = flistxattr(fd, names, (size_t)list_len);
    if (list_len < 0)
    {
        free(names);
        if (errno == ENOTSUP || errno == ENODATA)
            return LIBRDP_STATUS_OK;
        return LIBRDP_STATUS_STATE;
    }
    while (cursor < (size_t)list_len)
    {
        const char* name = names + cursor;
        size_t name_len = strnlen(name, (size_t)list_len - cursor);
        ssize_t value_len = 0;

        if (name_len == (size_t)list_len - cursor)
        {
            free(names);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (name_len <= UINT8_MAX)
        {
            value_len = fgetxattr(fd, name, NULL, 0);
            if (value_len >= 0 && value_len <= UINT16_MAX)
            {
                size_t entry = rdp_session_file_ea_entry_stride(name_len, (size_t)value_len);

                if (total > UINT32_MAX - entry)
                {
                    free(names);
                    return LIBRDP_STATUS_NO_MEMORY;
                }
                total += entry;
            }
        }
        cursor += name_len + 1u;
    }
    free(names);
    *ea_size = (uint32_t)total;
    return LIBRDP_STATUS_OK;
#else
    if (!ea_size || fd < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *ea_size = 0;
    return LIBRDP_STATUS_OK;
#endif
}

static librdp_status rdp_session_write_file_ea_information(rdp_buffer* buffer, int fd)
{
    uint32_t ea_size = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || fd < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_file_ea_size(fd, &ea_size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_session_write_file_u32_information(buffer, ea_size);
}

/*
 * Serialize extended-attribute directory information for filesystem
 * redirection. Each variable-length name/value pair is size-checked before the
 * next-entry offset is committed.
 */
static librdp_status rdp_session_write_file_full_ea_information(rdp_buffer* buffer, int fd)
{
#if defined(RDP_HAVE_ATTR) && defined(__linux__)
    ssize_t list_len = 0;
    char* names = NULL;
    size_t cursor = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || fd < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, 0u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    list_len = flistxattr(fd, NULL, 0);
    if (list_len < 0)
    {
        if (errno == ENOTSUP || errno == ENODATA)
            return LIBRDP_STATUS_OK;
        return LIBRDP_STATUS_STATE;
    }
    if (list_len == 0)
        return LIBRDP_STATUS_OK;
    names = (char*)malloc((size_t)list_len);
    if (!names)
        return LIBRDP_STATUS_NO_MEMORY;
    list_len = flistxattr(fd, names, (size_t)list_len);
    if (list_len < 0)
    {
        free(names);
        if (errno == ENOTSUP || errno == ENODATA)
            return LIBRDP_STATUS_OK;
        return LIBRDP_STATUS_STATE;
    }
    while (cursor < (size_t)list_len)
    {
        const char* name = names + cursor;
        size_t name_len = strnlen(name, (size_t)list_len - cursor);
        ssize_t value_len = 0;
        uint8_t* value = NULL;
        size_t entry_start = 0;
        size_t entry_len = 0;
        size_t stride = 0;

        if (name_len == (size_t)list_len - cursor)
        {
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
        }
        cursor += name_len + 1u;
        if (name_len > UINT8_MAX)
            continue;
        value_len = fgetxattr(fd, name, NULL, 0);
        if (value_len < 0)
            continue;
        if (value_len > UINT16_MAX)
            continue;
        if (value_len > 0)
        {
            value = (uint8_t*)malloc((size_t)value_len);
            if (!value)
            {
                status = LIBRDP_STATUS_NO_MEMORY;
                break;
            }
            value_len = fgetxattr(fd, name, value, (size_t)value_len);
            if (value_len < 0)
            {
                free(value);
                continue;
            }
        }
        entry_start = buffer->length;
        entry_len = 8u + name_len + 1u + (size_t)value_len;
        stride = rdp_session_file_ea_entry_stride(name_len, (size_t)value_len);
        status = rdp_buffer_append_u32_le(buffer, 0);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u8(buffer, 0);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u8(buffer, (uint8_t)name_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u16_le(buffer, (uint16_t)value_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append(buffer, name, name_len + 1u);
        if (status == LIBRDP_STATUS_OK && value_len > 0)
            status = rdp_buffer_append(buffer, value, (size_t)value_len);
        while (status == LIBRDP_STATUS_OK && buffer->length - entry_start < stride)
            status = rdp_buffer_append_u8(buffer, 0);
        free(value);
        if (status != LIBRDP_STATUS_OK)
            break;
        if (buffer->length > entry_start + stride)
        {
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
        }
        if (cursor < (size_t)list_len)
            rdp_session_write_u32_le_raw(buffer->data + entry_start, (uint32_t)stride);
        (void)entry_len;
    }
    free(names);
    if (status == LIBRDP_STATUS_OK)
    {
        if (buffer->length - sizeof(uint32_t) > UINT32_MAX)
            return LIBRDP_STATUS_NO_MEMORY;
        rdp_session_write_u32_le_raw(
            buffer->data,
            (uint32_t)(buffer->length - sizeof(uint32_t)));
    }
    return status;
#else
    if (!buffer || fd < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u32_le(buffer, 0u);
#endif
}

/*
 * Dispatch file-information serialization by requested information class. The
 * writer covers file query classes that can be represented on redirected POSIX
 * files and reports operation-incompatible or backend-inapplicable classes as
 * invalid parameters, so the device state machine never emits a mismatched
 * response layout.
 */
librdp_status rdp_session_write_file_information(rdp_buffer* buffer,
                                                        uint32_t information_class,
                                                        const struct stat* st,
                                                        const rdp_session_redirected_file* file)
{
    if (!buffer || !st)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (information_class)
    {
        case RDP_SESSION_FILE_BASIC_INFORMATION:
            return rdp_session_write_file_basic_information(buffer, st);
        case RDP_SESSION_FILE_STANDARD_INFORMATION:
            return rdp_session_write_file_standard_information(buffer, st);
        case RDP_SESSION_FILE_INTERNAL_INFORMATION:
            return rdp_session_write_file_internal_information(buffer, st);
        case RDP_SESSION_FILE_EA_INFORMATION:
            return rdp_session_write_file_ea_information(buffer, file ? file->fd : -1);
        case RDP_SESSION_FILE_ACCESS_INFORMATION:
            return rdp_session_write_file_u32_information(buffer, file ? file->desired_access : 0);
        case RDP_SESSION_FILE_NAME_INFORMATION:
            return rdp_session_write_file_name_information(buffer, file ? file->path : NULL);
        case RDP_SESSION_FILE_NORMALIZED_NAME_INFORMATION:
            return rdp_session_write_file_normalized_name_information(buffer, file ? file->path : NULL);
        case RDP_SESSION_FILE_FULL_EA_INFORMATION:
            return rdp_session_write_file_full_ea_information(buffer, file ? file->fd : -1);
        case RDP_SESSION_FILE_POSITION_INFORMATION:
            return rdp_session_write_file_position_information(buffer, file ? file->fd : -1);
        case RDP_SESSION_FILE_MODE_INFORMATION:
            return rdp_session_write_file_u32_information(buffer, file ? file->create_options : 0);
        case RDP_SESSION_FILE_ALIGNMENT_INFORMATION:
            return rdp_session_write_file_u32_information(buffer, 0);
        case RDP_SESSION_FILE_ALL_INFORMATION:
            return rdp_session_write_file_all_information(buffer, st, file);
        case RDP_SESSION_FILE_STREAM_INFORMATION:
            return rdp_session_write_file_stream_information(buffer, st);
        case RDP_SESSION_FILE_COMPRESSION_INFORMATION:
            return rdp_session_write_file_compression_information(buffer, st);
        case RDP_SESSION_FILE_NETWORK_OPEN_INFORMATION:
            return rdp_session_write_file_network_open_information(buffer, st);
        case RDP_SESSION_FILE_ATTRIBUTE_TAG_INFORMATION:
            return rdp_session_write_file_attribute_tag_information(buffer, st);
        case RDP_SESSION_FILE_ID_INFORMATION:
            return rdp_session_write_file_id_information(buffer, st);
        case RDP_SESSION_FILE_CASE_SENSITIVE_INFORMATION:
            return rdp_session_write_file_u32_information(buffer, 0);
        case RDP_SESSION_FILE_ALTERNATE_NAME_INFORMATION:
            return rdp_session_write_file_alternate_name_information(buffer);
        case RDP_SESSION_FILE_ALLOCATION_INFORMATION:
            return rdp_session_write_file_size_information(buffer, rdp_session_stat_allocation_size(st));
        case RDP_SESSION_FILE_END_OF_FILE_INFORMATION:
        case RDP_SESSION_FILE_VALID_DATA_LENGTH_INFORMATION:
            return rdp_session_write_file_size_information(buffer, rdp_session_stat_size(st));
        default:
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
}

/*
 * Complete query-information and query-volume requests without adding a
 * second Length field around an information buffer that is already prefixed
 * by its wire length.
 */
librdp_status rdp_session_write_information_response(
    rdp_buffer* response,
    uint32_t device_id,
    uint32_t completion_id,
    uint32_t io_status,
    const rdp_buffer* information)
{
    static const uint8_t empty_length[4] = {0, 0, 0, 0};

    if (!response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
    {
        return rdp_device_redirection_write_io_completion(
            response,
            device_id,
            completion_id,
            io_status,
            empty_length,
            sizeof(empty_length));
    }
    if (!information || !information->data ||
        information->length < sizeof(uint32_t) ||
        information->length - sizeof(uint32_t) > UINT32_MAX ||
        rdp_session_read_u32_le_unaligned(information->data) !=
            (uint32_t)(information->length - sizeof(uint32_t)))
    {
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return rdp_device_redirection_write_io_completion(
        response,
        device_id,
        completion_id,
        io_status,
        information->data,
        information->length);
}

/*
 * Serialize one redirected directory enumeration record. The writer maps host
 * stat data into the requested information class, validates next-entry
 * offsets, and keeps UTF-16 names consistent.
 */
librdp_status rdp_session_write_directory_information(rdp_buffer* buffer,
                                                      uint32_t information_class,
                                                      const struct stat* st,
                                                      const char* name)
{
    rdp_buffer utf16;
    librdp_status status = LIBRDP_STATUS_OK;
    uint64_t change_time = 0;
    uint64_t size = 0;
    uint64_t allocation_size = 0;

    if (!buffer || !st || !name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&utf16);
    status = rdp_session_utf8_to_utf16le(name, &utf16, 0);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&utf16);
        return status;
    }
    if (utf16.length > UINT32_MAX)
    {
        rdp_buffer_free(&utf16);
        return LIBRDP_STATUS_NO_MEMORY;
    }

    change_time = rdp_session_stat_ctime(st);
    size = rdp_session_stat_size(st);
    allocation_size = rdp_session_stat_allocation_size(st);
    switch (information_class)
    {
        case RDP_SESSION_FILE_DIRECTORY_INFORMATION:
        case RDP_SESSION_FILE_FULL_DIRECTORY_INFORMATION:
        case RDP_SESSION_FILE_BOTH_DIRECTORY_INFORMATION:
        case RDP_SESSION_FILE_NAMES_INFORMATION:
        case RDP_SESSION_FILE_ID_BOTH_DIRECTORY_INFORMATION:
        case RDP_SESSION_FILE_ID_FULL_DIRECTORY_INFORMATION:
        case RDP_SESSION_FILE_ID_EXTD_DIRECTORY_INFORMATION:
        case RDP_SESSION_FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION:
        case RDP_SESSION_FILE_ID_64_EXTD_DIRECTORY_INFORMATION:
        case RDP_SESSION_FILE_ID_64_EXTD_BOTH_DIRECTORY_INFORMATION:
        case RDP_SESSION_FILE_ID_ALL_EXTD_DIRECTORY_INFORMATION:
        case RDP_SESSION_FILE_ID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION:
            break;
        default:
            rdp_buffer_free(&utf16);
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }

    status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (information_class == RDP_SESSION_FILE_NAMES_INFORMATION)
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, (uint32_t)utf16.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append(buffer, utf16.data, utf16.length);
        rdp_buffer_free(&utf16);
        return status;
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, change_time);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_atime(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_mtime(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, change_time);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, size);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, allocation_size);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, rdp_session_stat_attributes(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, (uint32_t)utf16.length);
    if (information_class == RDP_SESSION_FILE_ID_EXTD_DIRECTORY_INFORMATION ||
        information_class == RDP_SESSION_FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION ||
        information_class == RDP_SESSION_FILE_ID_64_EXTD_DIRECTORY_INFORMATION ||
        information_class == RDP_SESSION_FILE_ID_64_EXTD_BOTH_DIRECTORY_INFORMATION ||
        information_class == RDP_SESSION_FILE_ID_ALL_EXTD_DIRECTORY_INFORMATION ||
        information_class == RDP_SESSION_FILE_ID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION)
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, 0);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, 0);
        if (status == LIBRDP_STATUS_OK)
        {
            if (information_class == RDP_SESSION_FILE_ID_64_EXTD_DIRECTORY_INFORMATION ||
                information_class == RDP_SESSION_FILE_ID_64_EXTD_BOTH_DIRECTORY_INFORMATION ||
                information_class == RDP_SESSION_FILE_ID_ALL_EXTD_DIRECTORY_INFORMATION ||
                information_class == RDP_SESSION_FILE_ID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION)
                status = rdp_session_append_u64_le(buffer, rdp_session_stat_file_id(st));
        }
        if (status == LIBRDP_STATUS_OK &&
            (information_class == RDP_SESSION_FILE_ID_EXTD_DIRECTORY_INFORMATION ||
             information_class == RDP_SESSION_FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION ||
             information_class == RDP_SESSION_FILE_ID_ALL_EXTD_DIRECTORY_INFORMATION ||
             information_class == RDP_SESSION_FILE_ID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION))
            status = rdp_session_append_file_id_128(buffer, st);
        if (information_class == RDP_SESSION_FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION ||
            information_class == RDP_SESSION_FILE_ID_64_EXTD_BOTH_DIRECTORY_INFORMATION ||
            information_class == RDP_SESSION_FILE_ID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION)
        {
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u8(buffer, 0);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u8(buffer, 0);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_append_zero(buffer, 24);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append(buffer, utf16.data, utf16.length);
        rdp_buffer_free(&utf16);
        return status;
    }
    if (information_class == RDP_SESSION_FILE_FULL_DIRECTORY_INFORMATION ||
        information_class == RDP_SESSION_FILE_BOTH_DIRECTORY_INFORMATION ||
        information_class == RDP_SESSION_FILE_ID_BOTH_DIRECTORY_INFORMATION ||
        information_class == RDP_SESSION_FILE_ID_FULL_DIRECTORY_INFORMATION)
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, 0);
    }
    if (information_class == RDP_SESSION_FILE_ID_FULL_DIRECTORY_INFORMATION)
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_append_u64_le(buffer, rdp_session_stat_file_id(st));
    }
    if (information_class == RDP_SESSION_FILE_BOTH_DIRECTORY_INFORMATION ||
        information_class == RDP_SESSION_FILE_ID_BOTH_DIRECTORY_INFORMATION)
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u8(buffer, 0);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u8(buffer, 0);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_append_zero(buffer, 24);
    }
    if (information_class == RDP_SESSION_FILE_ID_BOTH_DIRECTORY_INFORMATION)
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_append_u64_le(buffer, rdp_session_stat_file_id(st));
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, utf16.data, utf16.length);
    rdp_buffer_free(&utf16);
    return status;
}

static const char* rdp_session_drive_volume_label(const librdp_session* session,
                                                  uint32_t drive_index,
                                                  char* fallback,
                                                  size_t fallback_len)
{
    const char* name = NULL;
    size_t name_len = 0;

    if (!session || drive_index >= LIBRDP_SETTINGS_MAX_DRIVES || !fallback || fallback_len == 0)
        return "";
    if (session->drive_volume_label_set[drive_index])
        return session->drive_volume_labels[drive_index];
    name = librdp_settings_drive_name(session->settings, drive_index);
    if (!name || name[0] == '\0')
        name = "Drive";
    name_len = strlen(name);
    if (name_len > 1u && name[name_len - 1u] == ':')
        name_len--;
    if (name_len == 0 || name_len >= fallback_len)
        name = "Drive";
    name_len = strlen(name);
    if (name_len >= fallback_len)
        name_len = fallback_len - 1u;
    if (name_len > 1u && name[name_len - 1u] == ':')
        name_len--;
    memcpy(fallback, name, name_len);
    fallback[name_len] = '\0';
    if (fallback[0] == '\0')
        memcpy(fallback, "Drive", sizeof("Drive"));
    return fallback;
}

static librdp_status rdp_session_write_volume_information(rdp_buffer* buffer,
                                                          uint32_t information_class,
                                                          int root_fd,
                                                          const char* volume_label)
{
    struct stat st;
    struct statvfs vfs;
    uint64_t total_units = 0;
    uint64_t available_units = 0;
    uint64_t volume_serial = 0;
    uint32_t bytes_per_sector = 512;
    uint32_t sectors_per_unit = 1;

    if (!buffer || root_fd < 0 || !volume_label)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&st, 0, sizeof(st));
    memset(&vfs, 0, sizeof(vfs));
    if (fstat(root_fd, &st) != 0)
        return LIBRDP_STATUS_STATE;
    if (fstatvfs(root_fd, &vfs) == 0)
    {
        unsigned long block_size = vfs.f_frsize != 0 ? vfs.f_frsize : vfs.f_bsize;

        total_units = (uint64_t)vfs.f_blocks;
        available_units = (uint64_t)vfs.f_bavail;
        if (block_size > 0 && block_size < 512u)
            bytes_per_sector = (uint32_t)block_size;
        else if (block_size >= 512u)
            sectors_per_unit = (uint32_t)(block_size / 512u);
        if (sectors_per_unit == 0)
            sectors_per_unit = 1;
    }
    volume_serial = (uint64_t)st.st_dev ^ (uint64_t)st.st_ino;
    return rdp_filesystem_redirection_write_volume_information(buffer,
                                                              information_class,
                                                              volume_label,
                                                              "POSIX",
                                                              rdp_session_stat_ctime(&st),
                                                              (uint32_t)(volume_serial & UINT64_C(0xffffffff)),
                                                              total_units,
                                                              available_units,
                                                              sectors_per_unit,
                                                              bytes_per_sector);
}

char* rdp_session_strdup_range(const char* data, size_t length)
{
    char* out = NULL;

    if (!data && length > 0)
        return NULL;
    out = (char*)malloc(length + 1u);
    if (!out)
        return NULL;
    if (length > 0)
        memcpy(out, data, length);
    out[length] = '\0';
    return out;
}

static char* rdp_session_join_path(const char* root, const char* relative)
{
    char* out = NULL;
    size_t root_len = 0;
    size_t relative_len = 0;

    if (!root || !relative)
        return NULL;
    root_len = strlen(root);
    relative_len = strlen(relative);
    out = (char*)malloc(root_len + 1u + relative_len + 1u);
    if (!out)
        return NULL;
    if (root_len == 0)
    {
        memcpy(out, relative, relative_len + 1u);
        return out;
    }
    memcpy(out, root, root_len);
    if (root_len > 0 && root[root_len - 1u] == '/')
    {
        memcpy(out + root_len, relative, relative_len + 1u);
    }
    else
    {
        out[root_len] = '/';
        memcpy(out + root_len + 1u, relative, relative_len + 1u);
    }
    return out;
}

static librdp_status rdp_session_make_query_directory(librdp_session* session,
                                                      rdp_session_redirected_file* file,
                                                      const rdp_filesystem_redirection_query_directory_request* request,
                                                      char** directory_path,
                                                      char** pattern)
{
    char* relative = NULL;
    char* slash = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !file || !request || !directory_path || !pattern || !file->path)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *directory_path = NULL;
    *pattern = NULL;
    if (request->path_len == 0)
    {
        *directory_path = rdp_session_strdup_range(file->path, strlen(file->path));
        *pattern = rdp_session_strdup_range("*", 1);
        if (*directory_path && *pattern)
            return LIBRDP_STATUS_OK;
        free(*directory_path);
        free(*pattern);
        *directory_path = NULL;
        *pattern = NULL;
        return LIBRDP_STATUS_NO_MEMORY;
    }

    status = rdp_session_utf16le_path_to_utf8(request->path, request->path_len, &relative);
    if (status != LIBRDP_STATUS_OK)
        return status;
    while (relative[0] == '/')
        memmove(relative, relative + 1, strlen(relative));
    if (rdp_session_path_has_unsafe_segment(relative,
                                            rdp_settings_drive_policy_internal(session->settings,
                                                                              rdp_session_drive_index_from_device_id(
                                                                                  session,
                                                                                  request->io.device_id))))
    {
        free(relative);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    slash = strrchr(relative, '/');
    if (!slash)
    {
        *directory_path = rdp_session_strdup_range(file->path, strlen(file->path));
        *pattern = rdp_session_strdup_range(relative[0] ? relative : "*", strlen(relative[0] ? relative : "*"));
    }
    else
    {
        char* parent = rdp_session_strdup_range(relative, (size_t)(slash - relative));

        if (!parent)
        {
            free(relative);
            return LIBRDP_STATUS_NO_MEMORY;
        }
        *directory_path = rdp_session_join_path(file->path, parent);
        *pattern = rdp_session_strdup_range(slash[1] ? slash + 1 : "*", strlen(slash[1] ? slash + 1 : "*"));
        free(parent);
    }
    free(relative);
    if (!*directory_path || !*pattern)
    {
        free(*directory_path);
        free(*pattern);
        *directory_path = NULL;
        *pattern = NULL;
        return LIBRDP_STATUS_NO_MEMORY;
    }
    return LIBRDP_STATUS_OK;
}

uint32_t rdp_session_apply_basic_information(rdp_session_redirected_file* file,
                                                    const uint8_t* data,
                                                    uint32_t length)
{
    struct stat st;
    struct timespec times[2];
    uint64_t access_time = 0;
    uint64_t write_time = 0;
    uint32_t attributes = 0;
    mode_t mode = 0;
    mode_t write_mask = (mode_t)(S_IWUSR | S_IWGRP | S_IWOTH);

    if (!file || !file->path || !data || length != 36u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (file->drive_policy.read_only)
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    if (fstat(file->fd, &st) != 0)
        return rdp_session_errno_to_device_status(errno);
    access_time = rdp_session_read_u64_le_raw(data + 8);
    write_time = rdp_session_read_u64_le_raw(data + 16);
    attributes = (uint32_t)data[32] | ((uint32_t)data[33] << 8) | ((uint32_t)data[34] << 16) |
                 ((uint32_t)data[35] << 24);
    if (rdp_session_timespec_from_filetime(access_time, &times[0]) != 0 ||
        rdp_session_timespec_from_filetime(write_time, &times[1]) != 0)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (futimens(file->fd, times) != 0)
        return rdp_session_errno_to_device_status(errno);
    if (attributes != 0)
    {
        mode = st.st_mode;
        if ((attributes & RDP_SESSION_FILE_ATTRIBUTE_READONLY) != 0)
            mode = (mode_t)(mode & (mode_t)(~write_mask));
        else
            mode = (mode_t)(mode | S_IWUSR);
        if (fchmod(file->fd, mode) != 0)
            return rdp_session_errno_to_device_status(errno);
    }
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

uint32_t rdp_session_apply_size_information(rdp_session_redirected_file* file,
                                                   const uint8_t* data,
                                                   uint32_t length)
{
    uint64_t size = 0;

    if (!file || !data || length != 8u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (file->drive_policy.read_only)
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    size = rdp_session_read_u64_le_raw(data);
    if (size > (uint64_t)INT64_MAX)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (file->drive_policy.max_file_size > 0 && size > file->drive_policy.max_file_size)
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    if (ftruncate(file->fd, (off_t)size) != 0)
        return rdp_session_errno_to_device_status(errno);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

uint32_t rdp_session_apply_valid_data_length_information(rdp_session_redirected_file* file,
                                                                const uint8_t* data,
                                                                uint32_t length)
{
    struct stat st;
    uint64_t valid_length = 0;

    if (!file || !data || length != 8u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (file->drive_policy.read_only)
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    valid_length = rdp_session_read_u64_le_raw(data);
    if (valid_length > (uint64_t)INT64_MAX)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (file->drive_policy.max_file_size > 0 && valid_length > file->drive_policy.max_file_size)
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    memset(&st, 0, sizeof(st));
    if (fstat(file->fd, &st) != 0)
        return rdp_session_errno_to_device_status(errno);
    if (!S_ISREG(st.st_mode))
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (st.st_size >= 0 && valid_length <= (uint64_t)st.st_size)
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    if (ftruncate(file->fd, (off_t)valid_length) != 0)
        return rdp_session_errno_to_device_status(errno);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static uint32_t rdp_session_write_zero_range(int fd, uint64_t offset, uint64_t end)
{
    static const uint8_t zeroes[4096] = {0};

    if (fd < 0 || offset > end || end > (uint64_t)INT64_MAX)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    while (offset < end)
    {
        size_t chunk = (end - offset) < sizeof(zeroes) ? (size_t)(end - offset) : sizeof(zeroes);
        ssize_t count = 0;

        do
        {
            count = pwrite(fd, zeroes, chunk, (off_t)offset);
        } while (count < 0 && errno == EINTR);
        if (count <= 0)
            return count < 0 ? rdp_session_errno_to_device_status(errno) :
                               RDP_SESSION_DEVICE_UNSUCCESSFUL;
        offset += (uint64_t)count;
    }
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static uint32_t rdp_session_apply_zero_data(rdp_session_redirected_file* file,
                                            const uint8_t* data,
                                            uint32_t length)
{
    struct stat st;
    uint64_t offset = 0;
    uint64_t beyond = 0;
    uint64_t file_size = 0;

    if (!file || file->fd < 0 || !data || length != 16u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (file->drive_policy.read_only)
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    offset = rdp_session_read_u64_le_raw(data);
    beyond = rdp_session_read_u64_le_raw(data + 8);
    if (offset > beyond || beyond > (uint64_t)INT64_MAX)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    memset(&st, 0, sizeof(st));
    if (fstat(file->fd, &st) != 0)
        return rdp_session_errno_to_device_status(errno);
    if (!S_ISREG(st.st_mode))
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (st.st_size <= 0 || offset >= (uint64_t)st.st_size)
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    file_size = (uint64_t)st.st_size;
    if (beyond > file_size)
        beyond = file_size;
    return rdp_session_write_zero_range(file->fd, offset, beyond);
}

static uint32_t rdp_session_append_allocated_range(rdp_buffer* payload,
                                                   uint64_t offset,
                                                   uint64_t length,
                                                   uint32_t output_limit)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!payload || length == 0)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (payload->length > output_limit || output_limit - (uint32_t)payload->length < 16u)
        return RDP_SESSION_DEVICE_BUFFER_TOO_SMALL;
    status = rdp_session_append_u64_le(payload, offset);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(payload, length);
    return status == LIBRDP_STATUS_OK ? RDP_DEVICE_REDIRECTION_STATUS_SUCCESS :
                                        rdp_session_filesystem_error_from_status(status);
}

/*
 * Query allocated filesystem ranges and encode bounded FILE_ALLOCATED_RANGE
 * entries. The function clamps host sparse-file metadata to the requested
 * window and reports buffer overflow through the returned NTSTATUS.
 */
static uint32_t rdp_session_query_allocated_ranges(rdp_session_redirected_file* file,
                                                   const uint8_t* data,
                                                   uint32_t length,
                                                   uint32_t output_limit,
                                                   rdp_buffer* payload)
{
    struct stat st;
    uint64_t offset = 0;
    uint64_t requested = 0;
    uint64_t end = 0;
    uint64_t file_size = 0;

    if (!file || file->fd < 0 || !data || !payload || length != 16u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    offset = rdp_session_read_u64_le_raw(data);
    requested = rdp_session_read_u64_le_raw(data + 8);
    if (requested == 0)
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    if (offset > UINT64_MAX - requested)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    end = offset + requested;
    memset(&st, 0, sizeof(st));
    if (fstat(file->fd, &st) != 0)
        return rdp_session_errno_to_device_status(errno);
    if (!S_ISREG(st.st_mode))
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (st.st_size <= 0 || offset >= (uint64_t)st.st_size)
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    file_size = (uint64_t)st.st_size;
    if (end > file_size)
        end = file_size;
#if defined(SEEK_DATA) && defined(SEEK_HOLE)
    {
        off_t pos = (off_t)offset;
        off_t limit = (off_t)end;
        uint8_t used_seek_data = 0;

        while (pos < limit)
        {
            off_t data_offset = lseek(file->fd, pos, SEEK_DATA);
            off_t hole_offset = 0;
            uint64_t range_offset = 0;
            uint64_t range_end = 0;
            uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;

            if (data_offset < 0)
            {
                if (errno == ENXIO)
                    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
                if (errno == EINVAL)
                    break;
                return rdp_session_errno_to_device_status(errno);
            }
            used_seek_data = 1;
            if (data_offset >= limit)
                return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
            hole_offset = lseek(file->fd, data_offset, SEEK_HOLE);
            if (hole_offset < 0)
            {
                if (errno == EINVAL)
                    break;
                return rdp_session_errno_to_device_status(errno);
            }
            range_offset = data_offset < (off_t)offset ? offset : (uint64_t)data_offset;
            range_end = hole_offset > limit ? (uint64_t)limit : (uint64_t)hole_offset;
            if (range_end > range_offset)
            {
                io_status = rdp_session_append_allocated_range(payload,
                                                               range_offset,
                                                               range_end - range_offset,
                                                               output_limit);
                if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
                    return io_status;
            }
            if (hole_offset <= pos)
                break;
            pos = hole_offset;
        }
        if (used_seek_data)
            return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    }
#endif
    return rdp_session_append_allocated_range(payload, offset, end - offset, output_limit);
}

uint32_t rdp_session_apply_position_information(rdp_session_redirected_file* file,
                                                       const uint8_t* data,
                                                       uint32_t length)
{
    uint64_t position = 0;

    if (!file || !data || length != 8u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    position = rdp_session_read_u64_le_raw(data);
    if (rdp_session_seek_fd(file->fd, position) != 0)
        return rdp_session_errno_to_device_status(errno);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

uint32_t rdp_session_apply_mode_information(rdp_session_redirected_file* file,
                                                   const uint8_t* data,
                                                   uint32_t length)
{
    if (!file || !data || length != 4u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    file->create_options = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
                           ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

uint32_t rdp_session_apply_case_sensitive_information(const uint8_t* data,
                                                             uint32_t length)
{
    uint32_t flags = 0;

    if (!data || length != 4u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    flags = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
            ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
    return flags == 0 ? RDP_DEVICE_REDIRECTION_STATUS_SUCCESS :
                        RDP_SESSION_DEVICE_NOT_SUPPORTED;
}

static int rdp_session_directory_fd_is_empty(int fd)
{
    DIR* dir = NULL;
    struct dirent* entry = NULL;
    int dup_fd = -1;

    if (fd < 0)
        return 0;
    dup_fd = dup(fd);
    if (dup_fd < 0)
        return 0;
    dir = fdopendir(dup_fd);
    if (!dir)
    {
        (void)close(dup_fd);
        return 0;
    }
    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
        {
            (void)closedir(dir);
            return 0;
        }
    }
    (void)closedir(dir);
    return 1;
}

static uint32_t rdp_session_apply_disposition(rdp_session_redirected_file* file,
                                              uint8_t delete_pending,
                                              uint8_t ignore_readonly)
{
    struct stat st;

    if (!file || !file->path)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (delete_pending)
    {
        if (file->drive_policy.read_only)
            return RDP_SESSION_DEVICE_ACCESS_DENIED;
        if (fstat(file->fd, &st) != 0)
            return rdp_session_errno_to_device_status(errno);
        if (S_ISDIR(st.st_mode) && !rdp_session_directory_fd_is_empty(file->fd))
            return RDP_SESSION_DEVICE_ACCESS_DENIED;
        if (!ignore_readonly && (st.st_mode & S_IWUSR) == 0)
            return RDP_SESSION_DEVICE_ACCESS_DENIED;
    }
    file->delete_pending = delete_pending;
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

uint32_t rdp_session_apply_disposition_information(rdp_session_redirected_file* file,
                                                         const uint8_t* data,
                                                         uint32_t length)
{
    uint8_t delete_pending = 1;

    if (length > 1u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (length == 1u)
        delete_pending = data && data[0] ? 1u : 0u;
    return rdp_session_apply_disposition(file, delete_pending, 0);
}

uint32_t rdp_session_apply_disposition_information_ex(rdp_session_redirected_file* file,
                                                            const uint8_t* data,
                                                            uint32_t length)
{
    uint32_t flags = 0;
    uint32_t supported = 0x0000001fu;

    if (!data || length != 4u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    flags = rdp_session_read_u32_le_raw(data);
    if ((flags & ~supported) != 0)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    return rdp_session_apply_disposition(file,
                                         (flags & 0x00000001u) != 0 ? 1u : 0u,
                                         (flags & 0x00000010u) != 0 ? 1u : 0u);
}

static uint32_t rdp_session_apply_rename_information(librdp_session* session,
                                                     rdp_session_redirected_file* file,
                                                     const rdp_filesystem_redirection_information_request* request)
{
    char* new_path = NULL;
    uint8_t replace = 0;
    uint32_t name_len = 0;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t drive_index = 0;
    const librdp_drive_policy* policy = NULL;
    struct stat new_st;
    int new_exists = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !file || !file->path || !request || request->length < 6u || !request->buffer)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    drive_index = rdp_session_drive_index_from_device_id(session, request->io.device_id);
    policy = rdp_settings_drive_policy_internal(session->settings, drive_index);
    if (policy && policy->read_only)
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    replace = request->buffer[0] ? 1u : 0u;
    name_len = (uint32_t)request->buffer[2] | ((uint32_t)request->buffer[3] << 8) |
               ((uint32_t)request->buffer[4] << 16) | ((uint32_t)request->buffer[5] << 24);
    if (request->buffer[1] != 0 || name_len != request->length - 6u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    status = rdp_session_make_counted_local_drive_path(session,
                                                       request->io.device_id,
                                                       request->buffer + 6u,
                                                       name_len,
                                                       &new_path);
    if (status != LIBRDP_STATUS_OK)
        return rdp_session_filesystem_error_from_status(status);
    memset(&new_st, 0, sizeof(new_st));
    io_status = rdp_session_drive_fstatat(session, request->io.device_id, new_path, &new_st, &new_exists);
    if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
    {
        free(new_path);
        return io_status;
    }
    if (!replace && new_exists)
    {
        free(new_path);
        return RDP_SESSION_DEVICE_OBJECT_NAME_COLLISION;
    }
    io_status = rdp_session_drive_verify_path_matches_file(session,
                                                           request->io.device_id,
                                                           file->path,
                                                           file->fd);
    if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
        io_status = rdp_session_drive_renameat(session, request->io.device_id, file->path, new_path);
    if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
    {
        free(new_path);
        return io_status;
    }
    free(file->path);
    file->path = new_path;
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static uint32_t rdp_session_apply_rename_information_ex(
    librdp_session* session,
    rdp_session_redirected_file* file,
    const rdp_filesystem_redirection_information_request* request)
{
    char* new_path = NULL;
    uint32_t flags = 0;
    uint64_t root_directory = 0;
    uint32_t name_len = 0;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t drive_index = 0;
    const librdp_drive_policy* policy = NULL;
    struct stat new_st;
    int new_exists = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !file || !file->path || !request || request->length < 16u || !request->buffer)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    drive_index = rdp_session_drive_index_from_device_id(session, request->io.device_id);
    policy = rdp_settings_drive_policy_internal(session->settings, drive_index);
    if (policy && policy->read_only)
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    flags = rdp_session_read_u32_le_raw(request->buffer);
    root_directory = rdp_session_read_u64_le_raw(request->buffer + 4u);
    name_len = rdp_session_read_u32_le_raw(request->buffer + 12u);
    if (root_directory != 0 || name_len != request->length - 16u || (flags & ~0x00000003u) != 0)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    status = rdp_session_make_counted_local_drive_path(session,
                                                       request->io.device_id,
                                                       request->buffer + 16u,
                                                       name_len,
                                                       &new_path);
    if (status != LIBRDP_STATUS_OK)
        return rdp_session_filesystem_error_from_status(status);
    memset(&new_st, 0, sizeof(new_st));
    io_status = rdp_session_drive_fstatat(session, request->io.device_id, new_path, &new_st, &new_exists);
    if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
    {
        free(new_path);
        return io_status;
    }
    if ((flags & 0x00000001u) == 0 && new_exists)
    {
        free(new_path);
        return RDP_SESSION_DEVICE_OBJECT_NAME_COLLISION;
    }
    io_status = rdp_session_drive_verify_path_matches_file(session,
                                                           request->io.device_id,
                                                           file->path,
                                                           file->fd);
    if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
        io_status = rdp_session_drive_renameat(session, request->io.device_id, file->path, new_path);
    if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
    {
        free(new_path);
        return io_status;
    }
    free(file->path);
    file->path = new_path;
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

/*
 * Apply legacy hard-link requests through root-relative descriptors. Replace
 * handling and source revalidation are ordered so a concurrent path swap cannot
 * turn a server-provided relative name into an operation outside the drive.
 */
static uint32_t rdp_session_apply_link_information(librdp_session* session,
                                                   rdp_session_redirected_file* file,
                                                   const rdp_filesystem_redirection_information_request* request)
{
    struct stat st;
    char* new_path = NULL;
    uint8_t replace = 0;
    uint32_t name_len = 0;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t drive_index = 0;
    const librdp_drive_policy* policy = NULL;
    struct stat new_st;
    int new_exists = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !file || !file->path || !request || request->length < 6u || !request->buffer)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    drive_index = rdp_session_drive_index_from_device_id(session, request->io.device_id);
    policy = rdp_settings_drive_policy_internal(session->settings, drive_index);
    if (policy && policy->read_only)
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    if (fstat(file->fd, &st) != 0)
        return rdp_session_errno_to_device_status(errno);
    if (!S_ISREG(st.st_mode))
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    replace = request->buffer[0] ? 1u : 0u;
    name_len = (uint32_t)request->buffer[2] | ((uint32_t)request->buffer[3] << 8) |
               ((uint32_t)request->buffer[4] << 16) | ((uint32_t)request->buffer[5] << 24);
    if (request->buffer[1] != 0 || name_len != request->length - 6u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    status = rdp_session_make_counted_local_drive_path(session,
                                                       request->io.device_id,
                                                       request->buffer + 6u,
                                                       name_len,
                                                       &new_path);
    if (status != LIBRDP_STATUS_OK)
        return rdp_session_filesystem_error_from_status(status);
    if (strcmp(file->path, new_path) == 0)
    {
        free(new_path);
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    }
    memset(&new_st, 0, sizeof(new_st));
    io_status = rdp_session_drive_fstatat(session, request->io.device_id, new_path, &new_st, &new_exists);
    if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
    {
        free(new_path);
        return io_status;
    }
    if (new_exists)
    {
        if (!replace)
        {
            free(new_path);
            return RDP_SESSION_DEVICE_OBJECT_NAME_COLLISION;
        }
        io_status = rdp_session_drive_unlinkat(session, request->io.device_id, new_path, 0);
        if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            goto out;
    }
    {
        int old_parent_fd = -1;
        int new_parent_fd = -1;
        char* old_base = NULL;
        char* new_base = NULL;

        io_status = rdp_session_drive_verify_path_matches_file(session,
                                                               request->io.device_id,
                                                               file->path,
                                                               file->fd);
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            io_status = rdp_session_drive_open_parent_dir(session,
                                                          request->io.device_id,
                                                          file->path,
                                                          &old_parent_fd,
                                                          &old_base);
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            io_status = rdp_session_drive_open_parent_dir(session,
                                                          request->io.device_id,
                                                          new_path,
                                                          &new_parent_fd,
                                                          &new_base);
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS && (!old_base || !new_base))
            io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS &&
            linkat(old_parent_fd, old_base, new_parent_fd, new_base, 0) != 0)
            io_status = rdp_session_errno_to_device_status(errno);
        free(old_base);
        free(new_base);
        if (old_parent_fd >= 0)
            (void)close(old_parent_fd);
        if (new_parent_fd >= 0)
            (void)close(new_parent_fd);
    }
out:
    free(new_path);
    return io_status;
}

/*
 * Apply legacy hard-link requests without leaving the redirected root. The
 * open handle inode is revalidated against its relative path before linkat so
 * rename races fail closed instead of linking a substituted host object.
 */
static uint32_t rdp_session_apply_link_information_ex(
    librdp_session* session,
    rdp_session_redirected_file* file,
    const rdp_filesystem_redirection_information_request* request)
{
    struct stat st;
    char* new_path = NULL;
    uint32_t flags = 0;
    uint64_t root_directory = 0;
    uint32_t name_len = 0;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t drive_index = 0;
    const librdp_drive_policy* policy = NULL;
    struct stat new_st;
    int new_exists = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !file || !file->path || !request || request->length < 16u || !request->buffer)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    drive_index = rdp_session_drive_index_from_device_id(session, request->io.device_id);
    policy = rdp_settings_drive_policy_internal(session->settings, drive_index);
    if (policy && policy->read_only)
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    if (fstat(file->fd, &st) != 0)
        return rdp_session_errno_to_device_status(errno);
    if (!S_ISREG(st.st_mode))
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    flags = rdp_session_read_u32_le_raw(request->buffer);
    root_directory = rdp_session_read_u64_le_raw(request->buffer + 4u);
    name_len = rdp_session_read_u32_le_raw(request->buffer + 12u);
    if (root_directory != 0 || name_len != request->length - 16u || (flags & ~0x00000003u) != 0)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    status = rdp_session_make_counted_local_drive_path(session,
                                                       request->io.device_id,
                                                       request->buffer + 16u,
                                                       name_len,
                                                       &new_path);
    if (status != LIBRDP_STATUS_OK)
        return rdp_session_filesystem_error_from_status(status);
    if (strcmp(file->path, new_path) == 0)
    {
        free(new_path);
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    }
    memset(&new_st, 0, sizeof(new_st));
    io_status = rdp_session_drive_fstatat(session, request->io.device_id, new_path, &new_st, &new_exists);
    if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
    {
        free(new_path);
        return io_status;
    }
    if (new_exists)
    {
        if ((flags & 0x00000001u) == 0)
        {
            free(new_path);
            return RDP_SESSION_DEVICE_OBJECT_NAME_COLLISION;
        }
        io_status = rdp_session_drive_unlinkat(session, request->io.device_id, new_path, 0);
        if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            goto out;
    }
    {
        int old_parent_fd = -1;
        int new_parent_fd = -1;
        char* old_base = NULL;
        char* new_base = NULL;

        io_status = rdp_session_drive_verify_path_matches_file(session,
                                                               request->io.device_id,
                                                               file->path,
                                                               file->fd);
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            io_status = rdp_session_drive_open_parent_dir(session,
                                                          request->io.device_id,
                                                          file->path,
                                                          &old_parent_fd,
                                                          &old_base);
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            io_status = rdp_session_drive_open_parent_dir(session,
                                                          request->io.device_id,
                                                          new_path,
                                                          &new_parent_fd,
                                                          &new_base);
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS && (!old_base || !new_base))
            io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS &&
            linkat(old_parent_fd, old_base, new_parent_fd, new_base, 0) != 0)
            io_status = rdp_session_errno_to_device_status(errno);
        free(old_base);
        free(new_base);
        if (old_parent_fd >= 0)
            (void)close(old_parent_fd);
        if (new_parent_fd >= 0)
            (void)close(new_parent_fd);
    }
out:
    free(new_path);
    return io_status;
}

static uint32_t rdp_session_filesystem_prepare_directory(
    librdp_session* session,
    const rdp_filesystem_redirection_create_request* request,
    const char* relative_path,
    uint8_t existed)
{
    uint32_t drive_index = 0;
    const librdp_drive_policy* policy = NULL;

    if (!session || !request || !relative_path)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    drive_index = rdp_session_drive_index_from_device_id(session, request->io.device_id);
    if (drive_index == UINT32_MAX)
        return RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    policy = rdp_settings_drive_policy_internal(session->settings, drive_index);
    if (request->create_disposition == 1 && !existed)
        return RDP_SESSION_DEVICE_NO_SUCH_FILE;
    if (request->create_disposition == 2 && existed)
        return RDP_SESSION_DEVICE_OBJECT_NAME_COLLISION;
    if (request->create_disposition == 4 && !existed)
        return RDP_SESSION_DEVICE_NO_SUCH_FILE;
    if (!existed &&
        (request->create_disposition == 0 || request->create_disposition == 2 ||
         request->create_disposition == 3 || request->create_disposition == 5))
    {
        int parent_fd = -1;
        char* basename = NULL;
        uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;

        if (policy && policy->read_only)
            return RDP_SESSION_DEVICE_ACCESS_DENIED;
        io_status = rdp_session_drive_open_parent_dir(session,
                                                      request->io.device_id,
                                                      relative_path,
                                                      &parent_fd,
                                                      &basename);
        if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            return io_status;
        if (mkdirat(parent_fd, basename, 0700) != 0)
            io_status = rdp_session_errno_to_device_status(errno);
        free(basename);
        (void)close(parent_fd);
        return io_status;
    }
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static librdp_status rdp_session_send_filesystem_create_response(
    librdp_session* session,
    const rdp_filesystem_redirection_create_request* request,
    uint32_t io_status,
    uint32_t file_id,
    uint8_t information)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_create_response(&response,
                                                              request->io.device_id,
                                                              request->io.completion_id,
                                                              io_status,
                                                              file_id,
                                                              information);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.create.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.create",
                        "device_id=%u completion_id=%u file_id=%u status=%u information=%u path_len=%u",
                        request->io.device_id,
                        request->io.completion_id,
                        file_id,
                        io_status,
                        information,
                        request->path_len);
    return status;
}

/*
 * Handle a redirected filesystem create/open request. Path normalization,
 * disposition flags, host open state, and protocol status mapping are kept
 * together to avoid leaking stale file handles.
 */
static librdp_status rdp_session_handle_filesystem_create(librdp_session* session,
                                                          const uint8_t* data,
                                                          size_t data_len)
{
    rdp_filesystem_redirection_create_request request;
    rdp_session_redirected_file* file = NULL;
    char* path = NULL;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t file_id = 0;
    uint8_t existed = 0;
    uint8_t information = RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_SUPERSEDED;
    int flags = -1;
    int fd = -1;
    uint32_t drive_index = 0;
    const librdp_drive_policy* policy = NULL;
    struct stat st;
    int exists_int = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_create_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    drive_index = rdp_session_drive_index_from_device_id(session, request.io.device_id);
    if (drive_index == UINT32_MAX)
        return rdp_session_send_filesystem_create_response(session,
                                                           &request,
                                                           RDP_SESSION_DEVICE_NO_SUCH_DEVICE,
                                                           0,
                                                           information);
    policy = rdp_settings_drive_policy_internal(session->settings, drive_index);

    status = rdp_session_make_local_drive_path(session,
                                               request.io.device_id,
                                               request.path,
                                               request.path_len,
                                               &path);
    if (status != LIBRDP_STATUS_OK)
    {
        io_status = rdp_session_filesystem_error_from_status(status);
        return rdp_session_send_filesystem_create_response(session, &request, io_status, 0, information);
    }

    memset(&st, 0, sizeof(st));
    io_status = rdp_session_drive_fstatat(session, request.io.device_id, path, &st, &exists_int);
    existed = exists_int ? 1u : 0u;
    if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
    {
        free(path);
        return rdp_session_send_filesystem_create_response(session, &request, io_status, 0, information);
    }
    if (policy && policy->deny_device_files && existed && !S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
        io_status = RDP_SESSION_DEVICE_ACCESS_DENIED;
    if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS && policy && policy->max_open_handles > 0)
    {
        uint32_t open_count = 0;

        for (size_t i = 0; i < RDP_SESSION_MAX_REDIRECTED_FILES; i++)
        {
            if (session->redirected_files[i].active &&
                session->redirected_files[i].device_id == request.io.device_id)
                open_count++;
        }
        if (open_count >= policy->max_open_handles)
            io_status = RDP_SESSION_DEVICE_TOO_MANY_OPENED_FILES;
    }
    information = rdp_session_create_information(&request, existed);
    if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS &&
        path[0] == '\0' &&
        (request.create_options & RDP_SESSION_FILE_DIRECTORY_FILE) == 0)
        io_status = RDP_SESSION_DEVICE_ACCESS_DENIED;
    if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS &&
        (request.create_options & RDP_SESSION_FILE_DIRECTORY_FILE) != 0)
    {
        io_status = rdp_session_filesystem_prepare_directory(session, &request, path, existed);
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
        {
            io_status = rdp_session_drive_open_path(session,
                                                    request.io.device_id,
                                                    path,
                                                    O_RDONLY | O_DIRECTORY,
                                                    0,
                                                    &fd);
        }
    }
    else if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
    {
        flags = rdp_session_open_flags_from_create(&request, existed);
        if (flags < 0)
        {
            io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
        }
        else
        {
            io_status = rdp_session_drive_open_path(session, request.io.device_id, path, flags, 0600, &fd);
        }
    }

    if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
    {
        file = rdp_session_redirected_file_alloc(session, request.io.device_id, &file_id);
        if (!file)
        {
            io_status = RDP_SESSION_DEVICE_TOO_MANY_OPENED_FILES;
            (void)close(fd);
            fd = -1;
            file_id = 0;
        }
        else
        {
            file->fd = fd;
            file->path = path;
            file->desired_access = request.desired_access;
            file->create_options = request.create_options;
            if (policy)
                file->drive_policy = *policy;
            path = NULL;
            fd = -1;
        }
    }
    free(path);
    if (fd >= 0)
        (void)close(fd);
    return rdp_session_send_filesystem_create_response(session,
                                                       &request,
                                                       io_status,
                                                       file_id,
                                                       information);
}

static librdp_status rdp_session_handle_filesystem_close(librdp_session* session,
                                                         const uint8_t* data,
                                                         size_t data_len)
{
    rdp_device_redirection_io_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_close_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;

    file = rdp_session_redirected_file_find(session, request.device_id, request.file_id);
    if (!file)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    else
    {
        uint8_t delete_pending = file->delete_pending;
        char* delete_path = file->path ? rdp_session_strdup_range(file->path, strlen(file->path)) : NULL;
        struct stat st;
        uint8_t is_directory = 0;

        memset(&st, 0, sizeof(st));
        if (file->fd >= 0 && fstat(file->fd, &st) == 0 && S_ISDIR(st.st_mode))
            is_directory = 1;
        if (file->fd >= 0 && close(file->fd) != 0)
            io_status = rdp_session_errno_to_device_status(errno);
        file->fd = -1;
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS && delete_pending && delete_path)
        {
            const librdp_drive_policy* policy = NULL;
            uint32_t drive_index = rdp_session_drive_index_from_device_id(session, request.device_id);

            policy = rdp_settings_drive_policy_internal(session->settings, drive_index);
            if (policy && policy->read_only)
                io_status = RDP_SESSION_DEVICE_ACCESS_DENIED;
            else
                io_status = rdp_session_drive_unlinkat(session,
                                                       request.device_id,
                                                       delete_path,
                                                       is_directory ? AT_REMOVEDIR : 0);
        }
        free(delete_path);
        rdp_session_redirected_file_reset(file);
    }

    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_close_response(&response,
                                                             request.device_id,
                                                             request.completion_id,
                                                             io_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.close.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.close",
                        "device_id=%u file_id=%u completion_id=%u status=%u",
                        request.device_id,
                        request.file_id,
                        request.completion_id,
                        io_status);
    return status;
}

static librdp_status rdp_session_handle_filesystem_simple(librdp_session* session,
                                                          const uint8_t* data,
                                                          size_t data_len)
{
    rdp_device_redirection_io_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_parse_io_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (request.minor_function != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_session_drive_index_from_device_id(session, request.device_id) == UINT32_MAX)
    {
        io_status = RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    }
    else if (request.major_function == RDP_DEVICE_REDIRECTION_IRP_SHUTDOWN)
    {
        io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    }
    else
    {
        file = rdp_session_redirected_file_find(session, request.device_id, request.file_id);
        if (!file)
            io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
        else if (request.major_function == RDP_DEVICE_REDIRECTION_IRP_FLUSH_BUFFERS && file->fd >= 0 &&
                 fsync(file->fd) != 0 && errno != EINVAL)
            io_status = rdp_session_errno_to_device_status(errno);
    }

    rdp_buffer_init(&response);
    status = rdp_device_redirection_write_io_completion(&response,
                                                        request.device_id,
                                                        request.completion_id,
                                                        io_status,
                                                        NULL,
                                                        0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.simple.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.simple",
                        "device_id=%u file_id=%u completion_id=%u major=%u status=%u",
                        request.device_id,
                        request.file_id,
                        request.completion_id,
                        request.major_function,
                        io_status);
    return status;
}

/*
 * Handle redirected filesystem metadata updates. The server-provided
 * information class controls parsing, but host mutations are attempted only
 * after the full payload is validated.
 */
static librdp_status rdp_session_handle_filesystem_set_information(librdp_session* session,
                                                                   const uint8_t* data,
                                                                   size_t data_len)
{
    rdp_filesystem_redirection_information_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_set_information_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;

    file = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
    if (!file)
    {
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    }
    else
    {
        switch (request.information_class)
        {
            case RDP_SESSION_FILE_BASIC_INFORMATION:
                io_status = rdp_session_apply_basic_information(file, request.buffer, request.length);
                break;
            case RDP_SESSION_FILE_END_OF_FILE_INFORMATION:
            case RDP_SESSION_FILE_ALLOCATION_INFORMATION:
                io_status = rdp_session_apply_size_information(file, request.buffer, request.length);
                break;
            case RDP_SESSION_FILE_VALID_DATA_LENGTH_INFORMATION:
                io_status = rdp_session_apply_valid_data_length_information(file,
                                                                            request.buffer,
                                                                            request.length);
                break;
            case RDP_SESSION_FILE_POSITION_INFORMATION:
                io_status = rdp_session_apply_position_information(file, request.buffer, request.length);
                break;
            case RDP_SESSION_FILE_MODE_INFORMATION:
                io_status = rdp_session_apply_mode_information(file, request.buffer, request.length);
                break;
            case RDP_SESSION_FILE_CASE_SENSITIVE_INFORMATION:
                io_status = rdp_session_apply_case_sensitive_information(request.buffer, request.length);
                break;
            case RDP_SESSION_FILE_DISPOSITION_INFORMATION:
                io_status = rdp_session_apply_disposition_information(file, request.buffer, request.length);
                break;
            case RDP_SESSION_FILE_DISPOSITION_INFORMATION_EX:
                io_status = rdp_session_apply_disposition_information_ex(file, request.buffer, request.length);
                break;
            case RDP_SESSION_FILE_RENAME_INFORMATION:
                io_status = rdp_session_apply_rename_information(session, file, &request);
                break;
            case RDP_SESSION_FILE_RENAME_INFORMATION_EX:
                io_status = rdp_session_apply_rename_information_ex(session, file, &request);
                break;
            case RDP_SESSION_FILE_LINK_INFORMATION:
                io_status = rdp_session_apply_link_information(session, file, &request);
                break;
            case RDP_SESSION_FILE_LINK_INFORMATION_EX:
                io_status = rdp_session_apply_link_information_ex(session, file, &request);
                break;
            default:
                io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
                break;
        }
    }

    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_length_response(&response,
                                                              request.io.device_id,
                                                              request.io.completion_id,
                                                              io_status,
                                                              0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.set_information.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.set_information",
                        "device_id=%u file_id=%u completion_id=%u class=%u status=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        request.information_class,
                        io_status);
    return status;
}

/*
 * Handle a redirected filesystem read request. File offsets and lengths are
 * validated before host I/O and the reply owns any data copied from the
 * backend buffer.
 */
static librdp_status rdp_session_handle_filesystem_read(librdp_session* session,
                                                        const uint8_t* data,
                                                        size_t data_len)
{
    rdp_filesystem_redirection_read_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer response;
    uint8_t* bytes = NULL;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t read_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_read_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (request.length > session->limits.file_io_bytes)
    {
        rdp_session_metric_add(&session->metrics.limits_rejected, 1);
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    }
    else
    {
        file = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
        if (!file)
        {
            io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
        }
        else if (rdp_session_seek_fd(file->fd, request.offset) != 0)
        {
            io_status = rdp_session_errno_to_device_status(errno);
        }
        else if (request.length > 0)
        {
            ssize_t count = 0;

            bytes = (uint8_t*)malloc(request.length);
            if (!bytes)
                io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
            else
            {
                do
                {
                    count = read(file->fd, bytes, request.length);
                } while (count < 0 && errno == EINTR);
                if (count < 0)
                    io_status = rdp_session_errno_to_device_status(errno);
                else
                    read_len = (uint32_t)count;
            }
        }
    }

    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_read_response(&response,
                                                            request.io.device_id,
                                                            request.io.completion_id,
                                                            io_status,
                                                            bytes,
                                                            read_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.read.response");
    rdp_buffer_free(&response);
    free(bytes);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.read",
                        "device_id=%u file_id=%u completion_id=%u status=%u requested=%u read=%u offset=%llu",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        io_status,
                        request.length,
                        read_len,
                        (unsigned long long)request.offset);
    return status;
}

/*
 * Handle a redirected filesystem write request. The incoming payload is
 * treated as transient wire data and copied or consumed before the IRP
 * completion is emitted.
 */
static librdp_status rdp_session_handle_filesystem_write(librdp_session* session,
                                                         const uint8_t* data,
                                                         size_t data_len)
{
    rdp_filesystem_redirection_write_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t written = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_write_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (request.length > session->limits.file_io_bytes)
    {
        rdp_session_metric_add(&session->metrics.limits_rejected, 1);
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    }
    else
    {
        file = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
        if (!file)
        {
            io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
        }
        else if (file->drive_policy.read_only)
        {
            io_status = RDP_SESSION_DEVICE_ACCESS_DENIED;
        }
        else if (file->drive_policy.max_file_size > 0 &&
                 request.offset != UINT64_MAX &&
                 request.length > file->drive_policy.max_file_size - (request.offset > file->drive_policy.max_file_size ?
                                                                      file->drive_policy.max_file_size :
                                                                      request.offset))
        {
            io_status = RDP_SESSION_DEVICE_ACCESS_DENIED;
        }
        else if (request.offset == UINT64_MAX)
        {
            off_t end_offset = lseek(file->fd, 0, SEEK_END);

            if (end_offset == (off_t)-1)
                io_status = rdp_session_errno_to_device_status(errno);
            else if (file->drive_policy.max_file_size > 0 &&
                     ((uint64_t)end_offset > file->drive_policy.max_file_size ||
                      request.length > file->drive_policy.max_file_size - (uint64_t)end_offset))
                io_status = RDP_SESSION_DEVICE_ACCESS_DENIED;
        }
        else if (rdp_session_seek_fd(file->fd, request.offset) != 0)
        {
            io_status = rdp_session_errno_to_device_status(errno);
        }
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
        {
            const uint8_t* cursor = request.data;
            uint32_t remaining = request.length;

            while (remaining > 0)
            {
                ssize_t count = write(file->fd, cursor, remaining);

                if (count < 0 && errno == EINTR)
                    continue;
                if (count <= 0)
                {
                    io_status = count < 0 ? rdp_session_errno_to_device_status(errno)
                                          : RDP_SESSION_DEVICE_NOT_SUPPORTED;
                    break;
                }
                cursor += (size_t)count;
                remaining -= (uint32_t)count;
                written += (uint32_t)count;
            }
        }
    }

    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_write_response(&response,
                                                             request.io.device_id,
                                                             request.io.completion_id,
                                                             io_status,
                                                             written);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.write.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.write",
                        "device_id=%u file_id=%u completion_id=%u status=%u requested=%u written=%u offset=%llu",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        io_status,
                        request.length,
                        written,
                        (unsigned long long)request.offset);
    return status;
}

static librdp_status rdp_session_handle_filesystem_query_volume(librdp_session* session,
                                                                const uint8_t* data,
                                                                size_t data_len)
{
    rdp_filesystem_redirection_information_request request;
    rdp_buffer payload;
    rdp_buffer response;
    uint32_t drive_index = 0;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    int root_fd = -1;
    char volume_label[RDP_SESSION_VOLUME_LABEL_MAX_BYTES];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_query_volume_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    drive_index = rdp_session_drive_index_from_device_id(session, request.io.device_id);
    if (drive_index == UINT32_MAX)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    else
    {
        rdp_buffer_init(&payload);
        io_status = rdp_session_drive_root_fd(session, drive_index, &root_fd);
    }
    if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS && drive_index != UINT32_MAX)
    {
        status = rdp_session_write_volume_information(&payload,
                                                      request.information_class,
                                                      root_fd,
                                                      rdp_session_drive_volume_label(session,
                                                                                     drive_index,
                                                                                     volume_label,
                                                                                     sizeof(volume_label)));
        if (status == LIBRDP_STATUS_UNSUPPORTED)
            io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
        else if (status != LIBRDP_STATUS_OK)
            io_status = rdp_session_filesystem_error_from_status(status);
    }

    rdp_buffer_init(&response);
    status = rdp_session_write_information_response(
        &response,
        request.io.device_id,
        request.io.completion_id,
        io_status,
        &payload);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.query_volume.response");
    rdp_buffer_free(&response);
    if (drive_index != UINT32_MAX)
        rdp_buffer_free(&payload);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.query_volume",
                        "device_id=%u completion_id=%u class=%u status=%u",
                        request.io.device_id,
                        request.io.completion_id,
                        request.information_class,
                        io_status);
    return status;
}

static librdp_status rdp_session_handle_filesystem_query_information(librdp_session* session,
                                                                     const uint8_t* data,
                                                                     size_t data_len)
{
    rdp_filesystem_redirection_information_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer payload;
    rdp_buffer response;
    struct stat st;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_query_information_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(&st, 0, sizeof(st));
    rdp_buffer_init(&payload);

    file = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
    if (!file)
    {
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    }
    else if (fstat(file->fd, &st) != 0)
    {
        io_status = rdp_session_errno_to_device_status(errno);
    }
    else
    {
        status = rdp_session_write_file_information(&payload, request.information_class, &st, file);
        if (status == LIBRDP_STATUS_UNSUPPORTED)
            io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
        else if (status != LIBRDP_STATUS_OK)
            io_status = rdp_session_filesystem_error_from_status(status);
    }

    rdp_buffer_init(&response);
    status = rdp_session_write_information_response(
        &response,
        request.io.device_id,
        request.io.completion_id,
        io_status,
        &payload);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.query_information.response");
    rdp_buffer_free(&response);
    rdp_buffer_free(&payload);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.query_information",
                        "device_id=%u file_id=%u completion_id=%u class=%u status=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        request.information_class,
                        io_status);
    return status;
}

/*
 * Handle redirected directory enumeration. Enumeration cookies, search
 * patterns, and host directory handles stay correlated so repeated requests
 * advance exactly one server-visible cursor.
 */
static librdp_status rdp_session_handle_filesystem_query_directory(librdp_session* session,
                                                                   const uint8_t* data,
                                                                   size_t data_len)
{
    rdp_filesystem_redirection_query_directory_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer payload;
    rdp_buffer response;
    struct dirent* entry = NULL;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t payload_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_query_directory_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&payload);

    file = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
    if (!file || !file->path)
    {
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    }
    else
    {
        if (request.initial_query || !file->directory)
        {
            char* directory_path = NULL;
            char* pattern = NULL;

            if (file->directory)
            {
                (void)closedir(file->directory);
                file->directory = NULL;
            }
            free(file->directory_path);
            free(file->directory_pattern);
            file->directory_path = NULL;
            file->directory_pattern = NULL;
            status = rdp_session_make_query_directory(session, file, &request, &directory_path, &pattern);
            if (status == LIBRDP_STATUS_OK)
            {
                int dir_fd = -1;

                io_status = rdp_session_drive_open_path(session,
                                                        request.io.device_id,
                                                        directory_path,
                                                        O_RDONLY | O_DIRECTORY,
                                                        0,
                                                        &dir_fd);
                file->directory = io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                      fdopendir(dir_fd) :
                                      NULL;
                if (!file->directory)
                {
                    if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
                        io_status = rdp_session_errno_to_device_status(errno);
                    if (dir_fd >= 0)
                        (void)close(dir_fd);
                    free(directory_path);
                    free(pattern);
                }
                else
                {
                    file->directory_path = directory_path;
                    file->directory_pattern = pattern;
                }
            }
            else
            {
                io_status = rdp_session_filesystem_error_from_status(status);
            }
        }

        while (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS && file->directory)
        {
            struct stat st;

            errno = 0;
            entry = readdir(file->directory);
            if (!entry)
            {
                io_status = errno == 0 ? RDP_SESSION_DEVICE_NO_MORE_FILES :
                                         rdp_session_errno_to_device_status(errno);
                break;
            }
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            if (file->drive_policy.deny_dotfiles && entry->d_name[0] == '.')
                continue;
            if (fnmatch(file->directory_pattern ? file->directory_pattern : "*", entry->d_name, 0) != 0)
                continue;
            memset(&st, 0, sizeof(st));
            if (fstatat(dirfd(file->directory), entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
                continue;
            if (file->drive_policy.deny_device_files && !S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
                continue;
            status = rdp_session_write_directory_information(&payload,
                                                             request.information_class,
                                                             &st,
                                                             entry->d_name);
            if (status == LIBRDP_STATUS_UNSUPPORTED)
                io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
            else if (status != LIBRDP_STATUS_OK)
                io_status = rdp_session_filesystem_error_from_status(status);
            break;
        }
    }

    payload_len = (uint32_t)payload.length;
    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_buffer_response(&response,
                                                              request.io.device_id,
                                                              request.io.completion_id,
                                                              io_status,
                                                              io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                  payload.data :
                                                                  NULL,
                                                              io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                  (uint32_t)payload.length :
                                                                  0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.query_directory.response");
    rdp_buffer_free(&response);
    rdp_buffer_free(&payload);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.query_directory",
                        "device_id=%u file_id=%u completion_id=%u class=%u initial=%u status=%u bytes=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        request.information_class,
                        request.initial_query,
                        io_status,
                        payload_len);
    return status;
}

static int rdp_session_file_lock_value_fits_off_t(uint64_t value)
{
    off_t converted = (off_t)value;

    return converted >= 0 && (uint64_t)converted == value;
}

static uint64_t rdp_session_file_lock_end(uint64_t offset, uint64_t length)
{
    if (length == 0 || UINT64_MAX - offset < length)
        return UINT64_MAX;
    return offset + length;
}

static int rdp_session_file_locks_overlap(uint64_t offset_a,
                                          uint64_t length_a,
                                          uint64_t offset_b,
                                          uint64_t length_b)
{
    uint64_t end_a = rdp_session_file_lock_end(offset_a, length_a);
    uint64_t end_b = rdp_session_file_lock_end(offset_b, length_b);

    return offset_a < end_b && offset_b < end_a;
}

static rdp_session_file_lock_range* rdp_session_find_file_lock(rdp_session_redirected_file* file,
                                                               uint64_t offset,
                                                               uint64_t length)
{
    size_t i = 0;

    if (!file)
        return NULL;
    for (i = 0; i < RDP_SESSION_MAX_FILE_LOCKS; i++)
    {
        if (file->locks[i].active && file->locks[i].offset == offset && file->locks[i].length == length)
            return &file->locks[i];
    }
    return NULL;
}

static uint32_t rdp_session_record_file_lock(rdp_session_redirected_file* file,
                                             uint64_t offset,
                                             uint64_t length,
                                             int exclusive,
                                             uint8_t* inserted)
{
    rdp_session_file_lock_range* existing = NULL;
    size_t i = 0;

    if (!file)
        return RDP_SESSION_DEVICE_NO_SUCH_FILE;
    if (inserted)
        *inserted = 0;
    existing = rdp_session_find_file_lock(file, offset, length);
    if (existing)
    {
        if (existing->exclusive != (uint8_t)(exclusive ? 1u : 0u))
            return RDP_SESSION_DEVICE_LOCK_NOT_GRANTED;
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    }
    if (file->lock_count >= RDP_SESSION_MAX_FILE_LOCKS)
        return RDP_SESSION_DEVICE_TOO_MANY_OPENED_FILES;
    for (i = 0; i < RDP_SESSION_MAX_FILE_LOCKS; i++)
    {
        if (!file->locks[i].active)
        {
            file->locks[i].active = 1u;
            file->locks[i].exclusive = exclusive ? 1u : 0u;
            file->locks[i].offset = offset;
            file->locks[i].length = length;
            file->lock_count++;
            if (inserted)
                *inserted = 1u;
            return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
        }
    }
    return RDP_SESSION_DEVICE_TOO_MANY_OPENED_FILES;
}

static uint32_t rdp_session_forget_file_lock(rdp_session_redirected_file* file,
                                             uint64_t offset,
                                             uint64_t length)
{
    rdp_session_file_lock_range* existing = rdp_session_find_file_lock(file, offset, length);

    if (!existing)
        return RDP_SESSION_DEVICE_RANGE_NOT_LOCKED;
    memset(existing, 0, sizeof(*existing));
    if (file->lock_count > 0)
        file->lock_count--;
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static uint32_t rdp_session_apply_fd_lock(int fd, short type, uint64_t offset, uint64_t length)
{
    struct flock lock;

    if (fd < 0 || !rdp_session_file_lock_value_fits_off_t(offset) ||
        !rdp_session_file_lock_value_fits_off_t(length))
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = type;
    lock.l_whence = SEEK_SET;
    lock.l_start = (off_t)offset;
    lock.l_len = (off_t)length;
    if (fcntl(fd, F_SETLK, &lock) != 0)
    {
        if (errno == EACCES || errno == EAGAIN)
            return RDP_SESSION_DEVICE_LOCK_NOT_GRANTED;
        return rdp_session_errno_to_device_status(errno);
    }
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static uint32_t rdp_session_check_file_lock_conflict(librdp_session* session,
                                                     const rdp_session_redirected_file* owner,
                                                     uint64_t offset,
                                                     uint64_t length,
                                                     int exclusive)
{
    size_t i = 0;
    size_t j = 0;

    if (!session || !owner || !owner->path)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    for (i = 0; i < RDP_SESSION_MAX_REDIRECTED_FILES; i++)
    {
        const rdp_session_redirected_file* other = &session->redirected_files[i];

        if (!other->active || other == owner || !other->path || strcmp(other->path, owner->path) != 0)
            continue;
        for (j = 0; j < RDP_SESSION_MAX_FILE_LOCKS; j++)
        {
            const rdp_session_file_lock_range* lock = &other->locks[j];

            if (!lock->active || !rdp_session_file_locks_overlap(offset, length, lock->offset, lock->length))
                continue;
            if (exclusive || lock->exclusive)
                return RDP_SESSION_DEVICE_LOCK_NOT_GRANTED;
        }
    }
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static void rdp_session_rollback_inserted_file_locks(rdp_session_redirected_file* file,
                                                     const rdp_filesystem_redirection_lock_request* request,
                                                     const uint8_t* inserted,
                                                     uint32_t count)
{
    uint32_t i = count;

    if (!file || !request || !inserted)
        return;
    while (i > 0)
    {
        i--;
        if (!inserted[i])
            continue;
        (void)rdp_session_apply_fd_lock(file->fd,
                                        F_UNLCK,
                                        request->locks[i].offset,
                                        request->locks[i].length);
        (void)rdp_session_forget_file_lock(file,
                                           request->locks[i].offset,
                                           request->locks[i].length);
    }
}

static int rdp_session_file_lock_seen_in_request(
    const rdp_filesystem_redirection_lock_request* request,
    uint32_t index,
    uint64_t offset,
    uint64_t length)
{
    uint32_t i = 0;

    if (!request)
        return 0;
    for (i = 0; i < index; i++)
    {
        if (request->locks[i].offset == offset && request->locks[i].length == length)
            return 1;
    }
    return 0;
}

/*
 * Apply server-requested byte-range locks to redirected host files. Lock state
 * is mirrored in session-owned metadata so unlock, cleanup, and failure paths
 * cannot release ranges that were never accepted by the backend.
 */
uint32_t rdp_session_apply_file_locks(librdp_session* session,
                                             rdp_session_redirected_file* file,
                                             const rdp_filesystem_redirection_lock_request* request)
{
    uint32_t i = 0;
    uint32_t pending_new = 0;
    short type = F_UNLCK;
    uint8_t inserted[RDP_FILESYSTEM_REDIRECTION_MAX_LOCKS];
    int exclusive = 0;

    if (!file || file->fd < 0 || !request)
        return RDP_SESSION_DEVICE_NO_SUCH_FILE;
    memset(inserted, 0, sizeof(inserted));
    switch (request->operation)
    {
        case RDP_FILESYSTEM_REDIRECTION_LOWIO_SHAREDLOCK:
            type = F_RDLCK;
            exclusive = 0;
            break;
        case RDP_FILESYSTEM_REDIRECTION_LOWIO_EXCLUSIVELOCK:
            type = F_WRLCK;
            exclusive = 1;
            break;
        case RDP_FILESYSTEM_REDIRECTION_LOWIO_UNLOCK:
        case RDP_FILESYSTEM_REDIRECTION_LOWIO_UNLOCK_MULTIPLE:
            type = F_UNLCK;
            break;
        default:
            return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    }
    for (i = 0; i < request->lock_count; i++)
    {
        uint64_t offset = request->locks[i].offset;
        uint64_t length = request->locks[i].length;
        uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;

        if (!rdp_session_file_lock_value_fits_off_t(offset) ||
            !rdp_session_file_lock_value_fits_off_t(length))
            return RDP_SESSION_DEVICE_INVALID_PARAMETER;
        if (type == F_UNLCK)
        {
            if (rdp_session_file_lock_seen_in_request(request, i, offset, length))
                return RDP_SESSION_DEVICE_RANGE_NOT_LOCKED;
            if (!rdp_session_find_file_lock(file, offset, length))
                return RDP_SESSION_DEVICE_RANGE_NOT_LOCKED;
            continue;
        }
        {
            rdp_session_file_lock_range* existing = rdp_session_find_file_lock(file, offset, length);

            if (existing && existing->exclusive != (uint8_t)(exclusive ? 1u : 0u))
                return RDP_SESSION_DEVICE_LOCK_NOT_GRANTED;
            if (!existing && !rdp_session_file_lock_seen_in_request(request, i, offset, length))
            {
                if (file->lock_count + pending_new >= RDP_SESSION_MAX_FILE_LOCKS)
                    return RDP_SESSION_DEVICE_TOO_MANY_OPENED_FILES;
                pending_new++;
            }
        }
        io_status = rdp_session_check_file_lock_conflict(session, file, offset, length, exclusive);
        if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            return io_status;
    }
    for (i = 0; i < request->lock_count; i++)
    {
        uint64_t offset = request->locks[i].offset;
        uint64_t length = request->locks[i].length;
        uint32_t io_status = rdp_session_apply_fd_lock(file->fd, type, offset, length);

        if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
        {
            rdp_session_rollback_inserted_file_locks(file, request, inserted, i);
            return io_status;
        }
        if (type == F_UNLCK)
        {
            io_status = rdp_session_forget_file_lock(file, offset, length);
        }
        else
        {
            io_status = rdp_session_record_file_lock(file,
                                                     offset,
                                                     length,
                                                     exclusive,
                                                     &inserted[i]);
        }
        if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
        {
            (void)rdp_session_apply_fd_lock(file->fd, F_UNLCK, offset, length);
            rdp_session_rollback_inserted_file_locks(file, request, inserted, i);
            return io_status;
        }
    }
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static librdp_status rdp_session_handle_filesystem_lock(librdp_session* session,
                                                        const uint8_t* data,
                                                        size_t data_len)
{
    rdp_filesystem_redirection_lock_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_lock_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    file = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
    if (!file)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    else
        io_status = rdp_session_apply_file_locks(session, file, &request);

    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_lock_response(&response,
                                                            request.io.device_id,
                                                            request.io.completion_id,
                                                            io_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.lock.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.lock",
                        "device_id=%u file_id=%u completion_id=%u operation=%u locks=%u status=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        request.operation,
                        request.lock_count,
                        io_status);
    return status;
}

typedef struct rdp_session_directory_snapshot
{
    rdp_session_directory_notify_entry* entries;
    size_t count;
    size_t capacity;
} rdp_session_directory_snapshot;

static void rdp_session_directory_snapshot_clear(
    rdp_session_directory_snapshot* snapshot)
{
    size_t index = 0u;

    if (!snapshot)
        return;
    for (index = 0u; index < snapshot->count; index++)
        free(snapshot->entries[index].path);
    free(snapshot->entries);
    memset(snapshot, 0, sizeof(*snapshot));
}

void rdp_session_directory_notify_clear(
    rdp_session_redirected_file* file)
{
    size_t index = 0u;

    if (!file)
        return;
    for (index = 0u; index < file->notify.entry_count; index++)
        free(file->notify.entries[index].path);
    free(file->notify.entries);
    memset(&file->notify, 0, sizeof(file->notify));
}

static int rdp_session_directory_notify_entry_compare(
    const void* left,
    const void* right)
{
    const rdp_session_directory_notify_entry* left_entry =
        (const rdp_session_directory_notify_entry*)left;
    const rdp_session_directory_notify_entry* right_entry =
        (const rdp_session_directory_notify_entry*)right;

    return strcmp(left_entry->path, right_entry->path);
}

static librdp_status rdp_session_directory_snapshot_append(
    rdp_session_directory_snapshot* snapshot,
    const char* path,
    const struct stat* st)
{
    rdp_session_directory_notify_entry* resized = NULL;
    rdp_session_directory_notify_entry* entry = NULL;
    size_t next_capacity = 0u;

    if (!snapshot || !path || !st)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (snapshot->count >= RDP_SESSION_DIRECTORY_NOTIFY_MAX_ENTRIES)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (snapshot->count == snapshot->capacity)
    {
        next_capacity = snapshot->capacity == 0u
                            ? 32u
                            : snapshot->capacity * 2u;
        if (next_capacity >
            RDP_SESSION_DIRECTORY_NOTIFY_MAX_ENTRIES)
            next_capacity =
                RDP_SESSION_DIRECTORY_NOTIFY_MAX_ENTRIES;
        resized = (rdp_session_directory_notify_entry*)realloc(
            snapshot->entries,
            next_capacity * sizeof(*resized));
        if (!resized)
            return LIBRDP_STATUS_NO_MEMORY;
        snapshot->entries = resized;
        snapshot->capacity = next_capacity;
    }
    entry = &snapshot->entries[snapshot->count];
    memset(entry, 0, sizeof(*entry));
    entry->path = strdup(path);
    if (!entry->path)
        return LIBRDP_STATUS_NO_MEMORY;
    entry->size = rdp_session_stat_size(st);
    entry->allocation_size =
        rdp_session_stat_allocation_size(st);
    entry->access_time = rdp_session_stat_atime(st);
    entry->write_time = rdp_session_stat_mtime(st);
    entry->change_time = rdp_session_stat_ctime(st);
    entry->owner_id = (uint64_t)st->st_uid;
    entry->group_id = (uint64_t)st->st_gid;
    entry->attributes = rdp_session_stat_attributes(st);
    entry->directory = S_ISDIR(st->st_mode) ? 1u : 0u;
    snapshot->count++;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_directory_notify_join_path(
    const char* prefix,
    const char* name,
    char** path)
{
    size_t prefix_len = prefix ? strlen(prefix) : 0u;
    size_t name_len = name ? strlen(name) : 0u;
    size_t length = 0u;
    char* joined = NULL;

    if (!name || !path || name_len == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (prefix_len >
            SIZE_MAX - name_len - (prefix_len > 0u ? 2u : 1u))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    length = prefix_len + name_len +
             (prefix_len > 0u ? 1u : 0u);
    if (length > RDP_SESSION_MAX_FILE_IO_BYTES)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    joined = (char*)malloc(length + 1u);
    if (!joined)
        return LIBRDP_STATUS_NO_MEMORY;
    if (prefix_len > 0u)
    {
        memcpy(joined, prefix, prefix_len);
        joined[prefix_len] = '/';
        memcpy(joined + prefix_len + 1u,
               name,
               name_len + 1u);
    }
    else
    {
        memcpy(joined, name, name_len + 1u);
    }
    *path = joined;
    return LIBRDP_STATUS_OK;
}

/*
 * Build a bounded, sorted snapshot from a directory handle. Recursion opens
 * children relative to trusted dirfds and never follows symbolic links, so a
 * remote watch request cannot escape the redirected root.
 */
static librdp_status rdp_session_directory_snapshot_scan(
    const rdp_session_redirected_file* file,
    int source_fd,
    const char* prefix,
    uint32_t depth,
    rdp_session_directory_snapshot* snapshot)
{
    DIR* directory = NULL;
    struct dirent* directory_entry = NULL;
    int scan_fd = -1;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!file || source_fd < 0 || !snapshot)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    scan_fd = openat(source_fd,
                     ".",
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scan_fd < 0)
        return LIBRDP_STATUS_STATE;
    directory = fdopendir(scan_fd);
    if (!directory)
    {
        (void)close(scan_fd);
        return LIBRDP_STATUS_STATE;
    }
    errno = 0;
    while ((directory_entry = readdir(directory)) != NULL)
    {
        struct stat st;
        char* relative_path = NULL;

        if (strcmp(directory_entry->d_name, ".") == 0 ||
            strcmp(directory_entry->d_name, "..") == 0)
            continue;
        if (file->drive_policy.deny_dotfiles &&
            directory_entry->d_name[0] == '.')
            continue;
        memset(&st, 0, sizeof(st));
        if (fstatat(dirfd(directory),
                    directory_entry->d_name,
                    &st,
                    AT_SYMLINK_NOFOLLOW) != 0)
        {
            if (errno == ENOENT)
            {
                errno = 0;
                continue;
            }
            status = LIBRDP_STATUS_STATE;
            break;
        }
        if (file->drive_policy.deny_device_files &&
            !S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
            continue;
        status = rdp_session_directory_notify_join_path(
            prefix,
            directory_entry->d_name,
            &relative_path);
        if (status == LIBRDP_STATUS_OK)
        {
            status = rdp_session_directory_snapshot_append(
                snapshot,
                relative_path,
                &st);
        }
        if (status == LIBRDP_STATUS_OK &&
            file->notify.watch_tree && S_ISDIR(st.st_mode))
        {
            int child_fd = -1;

            if (depth >= RDP_SESSION_DIRECTORY_NOTIFY_MAX_DEPTH)
                status = LIBRDP_STATUS_LIMIT_EXCEEDED;
            else
            {
                child_fd = openat(dirfd(directory),
                                  directory_entry->d_name,
                                  O_RDONLY | O_DIRECTORY |
                                      O_CLOEXEC | O_NOFOLLOW);
                if (child_fd < 0)
                {
                    if (errno == ENOENT)
                        errno = 0;
                    else
                        status = LIBRDP_STATUS_STATE;
                }
                else
                {
                    status =
                        rdp_session_directory_snapshot_scan(
                            file,
                            child_fd,
                            relative_path,
                            depth + 1u,
                            snapshot);
                    (void)close(child_fd);
                }
            }
        }
        free(relative_path);
        if (status != LIBRDP_STATUS_OK)
            break;
        errno = 0;
    }
    if (status == LIBRDP_STATUS_OK && errno != 0)
        status = LIBRDP_STATUS_STATE;
    (void)closedir(directory);
    return status;
}

static librdp_status rdp_session_directory_snapshot_build(
    const rdp_session_redirected_file* file,
    rdp_session_directory_snapshot* snapshot)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!file || file->fd < 0 || !snapshot)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(snapshot, 0, sizeof(*snapshot));
    status = rdp_session_directory_snapshot_scan(file,
                                                 file->fd,
                                                 "",
                                                 0u,
                                                 snapshot);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_session_directory_snapshot_clear(snapshot);
        return status;
    }
    if (snapshot->count > 1u)
    {
        qsort(snapshot->entries,
              snapshot->count,
              sizeof(*snapshot->entries),
              rdp_session_directory_notify_entry_compare);
    }
    return LIBRDP_STATUS_OK;
}

static uint32_t rdp_session_directory_notify_name_filter(
    const rdp_session_directory_notify_entry* entry)
{
    return entry && entry->directory
               ? RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_DIRECTORY_NAME
               : RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_FILE_NAME;
}

static uint32_t rdp_session_directory_notify_metadata_filter(
    const rdp_session_directory_notify_entry* before,
    const rdp_session_directory_notify_entry* after)
{
    uint32_t filter = 0u;

    if (!before || !after)
        return 0u;
    if (before->attributes != after->attributes ||
        before->directory != after->directory)
        filter |=
            RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_ATTRIBUTES;
    if (before->size != after->size ||
        before->allocation_size != after->allocation_size)
        filter |= RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_SIZE;
    if (before->write_time != after->write_time)
        filter |=
            RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_LAST_WRITE;
    if (before->access_time != after->access_time)
        filter |=
            RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_LAST_ACCESS;
    if (before->change_time != after->change_time)
        filter |=
            RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_CREATION;
    if (before->owner_id != after->owner_id ||
        before->group_id != after->group_id)
        filter |= RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_SECURITY;
    return filter;
}

static int rdp_session_directory_notify_find_change(
    const rdp_session_redirected_file* file,
    const rdp_session_directory_snapshot* after,
    uint32_t* action,
    const char** path)
{
    size_t before_index = 0u;
    size_t after_index = 0u;

    if (!file || !after || !action || !path)
        return 0;
    while (before_index < file->notify.entry_count ||
           after_index < after->count)
    {
        const rdp_session_directory_notify_entry* before =
            before_index < file->notify.entry_count
                ? &file->notify.entries[before_index]
                : NULL;
        const rdp_session_directory_notify_entry* current =
            after_index < after->count
                ? &after->entries[after_index]
                : NULL;
        int comparison = 0;

        if (!before)
            comparison = 1;
        else if (!current)
            comparison = -1;
        else
            comparison = strcmp(before->path, current->path);
        if (comparison < 0)
        {
            if ((file->notify.completion_filter &
                 rdp_session_directory_notify_name_filter(before)) !=
                0u)
            {
                *action =
                    RDP_FILESYSTEM_REDIRECTION_NOTIFY_ACTION_REMOVED;
                *path = before->path;
                return 1;
            }
            before_index++;
        }
        else if (comparison > 0)
        {
            if ((file->notify.completion_filter &
                 rdp_session_directory_notify_name_filter(current)) !=
                0u)
            {
                *action =
                    RDP_FILESYSTEM_REDIRECTION_NOTIFY_ACTION_ADDED;
                *path = current->path;
                return 1;
            }
            after_index++;
        }
        else
        {
            uint32_t changed =
                rdp_session_directory_notify_metadata_filter(
                    before,
                    current);

            if ((file->notify.completion_filter & changed) != 0u)
            {
                *action =
                    RDP_FILESYSTEM_REDIRECTION_NOTIFY_ACTION_MODIFIED;
                *path = current->path;
                return 1;
            }
            before_index++;
            after_index++;
        }
    }
    return 0;
}

/*
 * Serialize one bounded FILE_NOTIFY_INFORMATION record. The path is copied,
 * converted to wire separators and encoded before the response is sent; no
 * snapshot-owned pointer survives this call. Failure commits no partial PDU.
 */
static librdp_status rdp_session_send_directory_notify_response(
    librdp_session* session,
    uint32_t device_id,
    uint32_t completion_id,
    uint32_t io_status,
    uint32_t action,
    const char* path)
{
    rdp_buffer utf16;
    rdp_buffer payload;
    rdp_buffer response;
    char* wire_path = NULL;
    size_t path_index = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&utf16);
    rdp_buffer_init(&payload);
    rdp_buffer_init(&response);
    if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
    {
        if (!path)
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        else
            wire_path = strdup(path);
        if (status == LIBRDP_STATUS_OK && !wire_path)
            status = LIBRDP_STATUS_NO_MEMORY;
        if (status == LIBRDP_STATUS_OK)
        {
            for (path_index = 0u;
                 wire_path[path_index] != '\0';
                 path_index++)
            {
                if (wire_path[path_index] == '/')
                    wire_path[path_index] = '\\';
            }
            status = rdp_session_utf8_to_utf16le(wire_path,
                                                 &utf16,
                                                 0);
        }
        if (status == LIBRDP_STATUS_OK &&
            utf16.length > UINT32_MAX)
            status = LIBRDP_STATUS_LIMIT_EXCEEDED;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(&payload, 0u);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(&payload, action);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(
                &payload,
                (uint32_t)utf16.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append(&payload,
                                       utf16.data,
                                       utf16.length);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_filesystem_redirection_write_buffer_response(
            &response,
            device_id,
            completion_id,
            io_status,
            io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS
                ? payload.data
                : NULL,
            io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS
                ? (uint32_t)payload.length
                : 0u);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_session_send_device_redirection_packet(
            session,
            &response,
            "client.rdpdr.file.notify_change.response");
    }
    rdp_buffer_free(&response);
    rdp_buffer_free(&payload);
    rdp_buffer_free(&utf16);
    free(wire_path);
    return status;
}

static int rdp_session_directory_notify_filter_supported(
    uint32_t completion_filter)
{
    const uint32_t supported =
        RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_FILE_NAME |
        RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_DIRECTORY_NAME |
        RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_ATTRIBUTES |
        RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_SIZE |
        RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_LAST_WRITE |
        RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_LAST_ACCESS |
        RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_CREATION |
        RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_SECURITY;

    return (completion_filter & ~supported) == 0u;
}

/*
 * Install one watch only after validating the directory handle and supported
 * filter set. The initial snapshot becomes request-owned state; invalid or
 * duplicate watches receive an immediate bounded error response.
 */
static librdp_status rdp_session_handle_filesystem_notify_change(librdp_session* session,
                                                                 const uint8_t* data,
                                                                 size_t data_len)
{
    rdp_filesystem_redirection_notify_change_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_session_directory_snapshot snapshot;
    struct stat st;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_notify_change_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(&snapshot, 0, sizeof(snapshot));
    memset(&st, 0, sizeof(st));
    file = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
    if (!file || file->fd < 0)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    else if (fstat(file->fd, &st) != 0)
        io_status = rdp_session_errno_to_device_status(errno);
    else if (!S_ISDIR(st.st_mode))
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    else if (file->notify.active)
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    else if (!rdp_session_directory_notify_filter_supported(
                 request.completion_filter))
        io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
    else
    {
        file->notify.watch_tree = request.watch_tree;
        status = rdp_session_directory_snapshot_build(file,
                                                      &snapshot);
        if (status != LIBRDP_STATUS_OK)
            io_status =
                rdp_session_filesystem_error_from_status(status);
    }
    if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
    {
        file->notify.active = 1u;
        file->notify.completion_id =
            request.io.completion_id;
        file->notify.completion_filter =
            request.completion_filter;
        file->notify.next_check_ns =
            rdp_session_monotonic_ns() +
            RDP_SESSION_DIRECTORY_NOTIFY_POLL_NS;
        file->notify.entries = snapshot.entries;
        file->notify.entry_count = snapshot.count;
        memset(&snapshot, 0, sizeof(snapshot));
    }
    else
    {
        status = rdp_session_send_directory_notify_response(
            session,
            request.io.device_id,
            request.io.completion_id,
            io_status,
            0u,
            NULL);
        if (file && !file->notify.active)
            rdp_session_directory_notify_clear(file);
    }
    rdp_session_directory_snapshot_clear(&snapshot);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.notify_change",
                        "device_id=%u file_id=%u completion_id=%u watch_tree=%u filter=%u pending=%u status=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        request.watch_tree,
                        request.completion_filter,
                        io_status ==
                                RDP_DEVICE_REDIRECTION_STATUS_SUCCESS
                            ? 1u
                            : 0u,
                        io_status);
    return status;
}

int rdp_session_filesystem_notify_next_timeout_ms(
    const librdp_session* session)
{
    uint64_t now_ns = 0u;
    uint64_t minimum_ns = UINT64_MAX;
    size_t index = 0u;

    if (!session)
        return -1;
    now_ns = rdp_session_monotonic_ns();
    for (index = 0u; index < session->limits.file_handles; index++)
    {
        const rdp_session_redirected_file* file =
            &session->redirected_files[index];

        if (!file->active || !file->notify.active)
            continue;
        if (file->notify.next_check_ns <= now_ns)
            return 0;
        if (file->notify.next_check_ns - now_ns < minimum_ns)
            minimum_ns = file->notify.next_check_ns - now_ns;
    }
    if (minimum_ns == UINT64_MAX)
        return -1;
    minimum_ns =
        (minimum_ns + UINT64_C(999999)) / UINT64_C(1000000);
    return minimum_ns > (uint64_t)INT_MAX
               ? INT_MAX
               : (int)minimum_ns;
}

/*
 * Poll every active watch whose monotonic deadline has expired. A changed
 * snapshot emits exactly one response and releases all retained names; an
 * unchanged snapshot atomically replaces the old baseline. Scanner or send
 * failures terminate only the affected request unless transport output fails.
 */
librdp_status rdp_session_filesystem_notify_dispatch(
    librdp_session* session)
{
    uint64_t now_ns = 0u;
    size_t index = 0u;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    now_ns = rdp_session_monotonic_ns();
    for (index = 0u; index < session->limits.file_handles; index++)
    {
        rdp_session_redirected_file* file =
            &session->redirected_files[index];
        rdp_session_directory_snapshot snapshot;
        const char* changed_path = NULL;
        uint32_t action = 0u;
        librdp_status status = LIBRDP_STATUS_OK;

        if (!file->active || !file->notify.active ||
            file->notify.next_check_ns > now_ns)
            continue;
        memset(&snapshot, 0, sizeof(snapshot));
        status = rdp_session_directory_snapshot_build(file,
                                                      &snapshot);
        if (status != LIBRDP_STATUS_OK)
        {
            uint32_t io_status =
                rdp_session_filesystem_error_from_status(status);

            status = rdp_session_send_directory_notify_response(
                session,
                file->device_id,
                file->notify.completion_id,
                io_status,
                0u,
                NULL);
            rdp_session_directory_notify_clear(file);
            rdp_session_directory_snapshot_clear(&snapshot);
            if (status != LIBRDP_STATUS_OK)
                return status;
            continue;
        }
        if (rdp_session_directory_notify_find_change(
                file,
                &snapshot,
                &action,
                &changed_path))
        {
            status = rdp_session_send_directory_notify_response(
                session,
                file->device_id,
                file->notify.completion_id,
                RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                action,
                changed_path);
            rdp_trace_event(
                RDP_TRACE_CLIENT,
                "client.rdpdr.file.notify_change.completed",
                "device_id=%u file_id=%u action=%u name_bytes=%u",
                file->device_id,
                file->file_id,
                action,
                (unsigned int)strlen(changed_path));
            rdp_session_directory_notify_clear(file);
            rdp_session_directory_snapshot_clear(&snapshot);
            if (status != LIBRDP_STATUS_OK)
                return status;
            continue;
        }
        {
            uint8_t watch_tree = file->notify.watch_tree;
            uint32_t completion_id =
                file->notify.completion_id;
            uint32_t completion_filter =
                file->notify.completion_filter;

            rdp_session_directory_notify_clear(file);
            file->notify.active = 1u;
            file->notify.watch_tree = watch_tree;
            file->notify.completion_id = completion_id;
            file->notify.completion_filter =
                completion_filter;
        }
        file->notify.next_check_ns =
            now_ns + RDP_SESSION_DIRECTORY_NOTIFY_POLL_NS;
        file->notify.entries = snapshot.entries;
        file->notify.entry_count = snapshot.count;
        memset(&snapshot, 0, sizeof(snapshot));
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Handle filesystem device-control IRPs that do not map to simple read/write
 * operations. The dispatcher validates IOCTL payload sizes before forwarding
 * to host metadata helpers.
 */
static librdp_status rdp_session_handle_filesystem_device_control(librdp_session* session,
                                                                  const uint8_t* data,
                                                                  size_t data_len)
{
    rdp_filesystem_redirection_control_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer payload;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t output_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_control_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&payload);
    file = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
    if (!file)
    {
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    }
    else if (request.output_buffer_length > RDP_SESSION_MAX_FILE_IO_BYTES ||
             request.input_buffer_length > RDP_SESSION_MAX_FILE_IO_BYTES)
    {
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    }
    else
    {
        switch (request.io_control_code)
        {
            case RDP_FILESYSTEM_REDIRECTION_FSCTL_GET_COMPRESSION:
                if (request.input_buffer_length != 0)
                    io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
                else if (request.output_buffer_length < 2u)
                    io_status = RDP_SESSION_DEVICE_BUFFER_TOO_SMALL;
                else
                    status = rdp_buffer_append_u16_le(&payload, 0);
                break;
            case RDP_FILESYSTEM_REDIRECTION_FSCTL_SET_COMPRESSION:
                if (file->drive_policy.read_only)
                    io_status = RDP_SESSION_DEVICE_ACCESS_DENIED;
                else if (request.input_buffer_length != 2u || !request.input_buffer)
                    io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
                else if (rdp_session_read_u16_le_raw(request.input_buffer) != 0)
                    io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
                break;
            case RDP_FILESYSTEM_REDIRECTION_FSCTL_SET_SPARSE:
                if (file->drive_policy.read_only)
                    io_status = RDP_SESSION_DEVICE_ACCESS_DENIED;
                else if (request.input_buffer_length > 1u)
                    io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
                break;
            case RDP_FILESYSTEM_REDIRECTION_FSCTL_SET_ZERO_DATA:
                io_status = rdp_session_apply_zero_data(file,
                                                        request.input_buffer,
                                                        request.input_buffer_length);
                break;
            case RDP_FILESYSTEM_REDIRECTION_FSCTL_QUERY_ALLOCATED_RANGES:
                io_status = rdp_session_query_allocated_ranges(file,
                                                               request.input_buffer,
                                                               request.input_buffer_length,
                                                               request.output_buffer_length,
                                                               &payload);
                break;
            default:
                io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
                break;
        }
        if (status != LIBRDP_STATUS_OK)
            io_status = rdp_session_filesystem_error_from_status(status);
    }

    output_len = io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ? (uint32_t)payload.length : 0;
    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_buffer_response(
        &response,
        request.io.device_id,
        request.io.completion_id,
        io_status,
        output_len > 0 ? payload.data : NULL,
        output_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.device_control.response");
    rdp_buffer_free(&response);
    rdp_buffer_free(&payload);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.device_control",
                        "device_id=%u file_id=%u completion_id=%u ioctl=%u status=%u input_len=%u output_limit=%u output_len=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        request.io_control_code,
                        io_status,
                        request.input_buffer_length,
                        request.output_buffer_length,
                        output_len);
    return status;
}

static uint32_t rdp_session_apply_filesystem_set_volume(librdp_session* session,
                                                        uint32_t drive_index,
                                                        const rdp_filesystem_redirection_information_request* request)
{
    uint32_t label_len = 0;
    char label[RDP_SESSION_VOLUME_LABEL_MAX_BYTES];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request || drive_index >= LIBRDP_SETTINGS_MAX_DRIVES)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (request->information_class != RDP_FILESYSTEM_REDIRECTION_FS_LABEL_INFORMATION)
        return RDP_SESSION_DEVICE_NOT_SUPPORTED;
    if (request->length < 4u || !request->buffer)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    label_len = (uint32_t)request->buffer[0] | ((uint32_t)request->buffer[1] << 8u) |
                ((uint32_t)request->buffer[2] << 16u) | ((uint32_t)request->buffer[3] << 24u);
    if (label_len != request->length - 4u || (label_len & 1u) != 0)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    status = rdp_session_utf16le_volume_label_to_utf8(request->buffer + 4u,
                                                      label_len,
                                                      label,
                                                      sizeof(label));
    if (status != LIBRDP_STATUS_OK)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    memcpy(session->drive_volume_labels[drive_index], label, strlen(label) + 1u);
    session->drive_volume_label_set[drive_index] = 1u;
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static librdp_status rdp_session_handle_filesystem_set_volume(librdp_session* session,
                                                              const uint8_t* data,
                                                              size_t data_len)
{
    rdp_filesystem_redirection_information_request request;
    rdp_buffer response;
    uint32_t drive_index = UINT32_MAX;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_set_volume_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    drive_index = rdp_session_drive_index_from_device_id(session, request.io.device_id);
    if (drive_index == UINT32_MAX)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    else
        io_status = rdp_session_apply_filesystem_set_volume(session, drive_index, &request);

    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_length_response(&response,
                                                              request.io.device_id,
                                                              request.io.completion_id,
                                                              io_status,
                                                              0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.set_volume.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.set_volume",
                        "device_id=%u completion_id=%u class=%u input_len=%u status=%u",
                        request.io.device_id,
                        request.io.completion_id,
                        request.information_class,
                        request.length,
                        io_status);
    return status;
}

static uint32_t rdp_session_apply_filesystem_security(
    rdp_session_redirected_file* file,
    const rdp_filesystem_redirection_security_request* request)
{
    rdp_filesystem_redirection_posix_security security;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!file || file->fd < 0 || !request)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (file->drive_policy.read_only)
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    status = rdp_filesystem_redirection_parse_posix_security_descriptor(request->buffer,
                                                                        request->length,
                                                                        request->security_information,
                                                                        &security);
    if (status == LIBRDP_STATUS_UNSUPPORTED)
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    if (status != LIBRDP_STATUS_OK)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;

    if (security.owner_present || security.group_present)
    {
        uid_t owner = (uid_t)-1;
        gid_t group = (gid_t)-1;

        if (security.owner_present)
        {
            owner = (uid_t)security.owner_id;
            if ((uint32_t)owner != security.owner_id)
                return RDP_SESSION_DEVICE_INVALID_PARAMETER;
        }
        if (security.group_present)
        {
            group = (gid_t)security.group_id;
            if ((uint32_t)group != security.group_id)
                return RDP_SESSION_DEVICE_INVALID_PARAMETER;
        }
        if (fchown(file->fd, owner, group) != 0)
            return rdp_session_errno_to_device_status(errno);
    }
    if (security.mode_present && fchmod(file->fd, (mode_t)(security.mode & 0777u)) != 0)
        return rdp_session_errno_to_device_status(errno);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

/*
 * Handle filesystem security query and set requests. Host ACL translation and
 * protocol status mapping are centralized here to keep privilege-sensitive
 * failures explicit.
 */
static librdp_status rdp_session_handle_filesystem_security(librdp_session* session,
                                                            const uint8_t* data,
                                                            size_t data_len,
                                                            uint32_t major_function)
{
    rdp_filesystem_redirection_security_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer payload;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t payload_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    if (major_function == RDP_DEVICE_REDIRECTION_IRP_QUERY_SECURITY)
        status = rdp_filesystem_redirection_parse_query_security_request(data, data_len, &request);
    else if (major_function == RDP_DEVICE_REDIRECTION_IRP_SET_SECURITY)
        status = rdp_filesystem_redirection_parse_set_security_request(data, data_len, &request);
    else
    {
        rdp_buffer_free(&payload);
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&payload);
        return status;
    }
    file = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
    if (!file || file->fd < 0)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    else if (major_function == RDP_DEVICE_REDIRECTION_IRP_QUERY_SECURITY)
    {
        struct stat st;

        if (fstat(file->fd, &st) != 0)
        {
            io_status = rdp_session_errno_to_device_status(errno);
        }
        else
        {
            status = rdp_filesystem_redirection_write_posix_security_descriptor(&payload,
                                                                                request.security_information,
                                                                                (uint32_t)st.st_uid,
                                                                                (uint32_t)st.st_gid,
                                                                                (uint32_t)st.st_mode);
            if (status == LIBRDP_STATUS_UNSUPPORTED)
            {
                io_status = RDP_SESSION_DEVICE_ACCESS_DENIED;
            }
            else if (status != LIBRDP_STATUS_OK)
            {
                io_status = rdp_session_filesystem_error_from_status(status);
            }
            else if (payload.length > request.length)
            {
                io_status = RDP_SESSION_DEVICE_BUFFER_TOO_SMALL;
            }
        }
    }
    else
        io_status = rdp_session_apply_filesystem_security(file, &request);

    payload_len = (uint32_t)payload.length;
    rdp_buffer_init(&response);
    if (major_function == RDP_DEVICE_REDIRECTION_IRP_QUERY_SECURITY)
    {
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            status = rdp_filesystem_redirection_write_buffer_response(&response,
                                                                      request.io.device_id,
                                                                      request.io.completion_id,
                                                                      io_status,
                                                                      payload.data,
                                                                      payload_len);
        else if (io_status == RDP_SESSION_DEVICE_BUFFER_TOO_SMALL)
            status = rdp_filesystem_redirection_write_length_response(&response,
                                                                      request.io.device_id,
                                                                      request.io.completion_id,
                                                                      io_status,
                                                                      payload_len);
        else
            status = rdp_filesystem_redirection_write_buffer_response(&response,
                                                                      request.io.device_id,
                                                                      request.io.completion_id,
                                                                      io_status,
                                                                      NULL,
                                                                      0);
    }
    else
        status = rdp_filesystem_redirection_write_length_response(&response,
                                                                  request.io.device_id,
                                                                  request.io.completion_id,
                                                                  io_status,
                                                                  0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.security.response");
    rdp_buffer_free(&response);
    rdp_buffer_free(&payload);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.security",
                        "device_id=%u file_id=%u completion_id=%u major=%u security_information=%u length=%u payload_len=%u status=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        request.io.major_function,
                        request.security_information,
                        request.length,
                        payload_len,
                        io_status);
    return status;
}

static librdp_status rdp_session_write_filesystem_not_supported_response(
    rdp_buffer* response,
    const rdp_device_redirection_io_request* request,
    uint32_t io_status)
{
    if (!response || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (request->major_function)
    {
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_VOLUME_INFORMATION:
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION:
        case RDP_DEVICE_REDIRECTION_IRP_DIRECTORY_CONTROL:
        case RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL:
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_SECURITY:
            return rdp_filesystem_redirection_write_buffer_response(response,
                                                                    request->device_id,
                                                                    request->completion_id,
                                                                    io_status,
                                                                    NULL,
                                                                    0);
        case RDP_DEVICE_REDIRECTION_IRP_SET_VOLUME_INFORMATION:
        case RDP_DEVICE_REDIRECTION_IRP_SET_INFORMATION:
        case RDP_DEVICE_REDIRECTION_IRP_SET_SECURITY:
            return rdp_filesystem_redirection_write_length_response(response,
                                                                    request->device_id,
                                                                    request->completion_id,
                                                                    io_status,
                                                                    0);
        case RDP_DEVICE_REDIRECTION_IRP_LOCK_CONTROL:
            return rdp_filesystem_redirection_write_lock_response(response,
                                                                  request->device_id,
                                                                  request->completion_id,
                                                                  io_status);
        default:
            return rdp_device_redirection_write_io_completion(response,
                                                              request->device_id,
                                                              request->completion_id,
                                                              io_status,
                                                              NULL,
                                                              0);
    }
}

static librdp_status rdp_session_validate_filesystem_not_supported_request(const uint8_t* data,
                                                                         size_t data_len,
                                                                         const rdp_device_redirection_io_request* request)
{
    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (request->major_function)
    {
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_VOLUME_INFORMATION:
        {
            rdp_filesystem_redirection_information_request typed;
            return rdp_filesystem_redirection_parse_query_volume_request(data, data_len, &typed);
        }
        case RDP_DEVICE_REDIRECTION_IRP_SET_VOLUME_INFORMATION:
        {
            rdp_filesystem_redirection_information_request typed;
            return rdp_filesystem_redirection_parse_set_volume_request(data, data_len, &typed);
        }
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION:
        {
            rdp_filesystem_redirection_information_request typed;
            return rdp_filesystem_redirection_parse_query_information_request(data, data_len, &typed);
        }
        case RDP_DEVICE_REDIRECTION_IRP_SET_INFORMATION:
        {
            rdp_filesystem_redirection_information_request typed;
            return rdp_filesystem_redirection_parse_set_information_request(data, data_len, &typed);
        }
        case RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL:
        {
            rdp_filesystem_redirection_control_request typed;
            return rdp_filesystem_redirection_parse_control_request(data, data_len, &typed);
        }
        case RDP_DEVICE_REDIRECTION_IRP_DIRECTORY_CONTROL:
            if (request->minor_function == RDP_FILESYSTEM_REDIRECTION_MINOR_QUERY_DIRECTORY)
            {
                rdp_filesystem_redirection_query_directory_request typed;
                return rdp_filesystem_redirection_parse_query_directory_request(data, data_len, &typed);
            }
            if (request->minor_function == RDP_FILESYSTEM_REDIRECTION_MINOR_NOTIFY_CHANGE_DIRECTORY)
            {
                rdp_filesystem_redirection_notify_change_request typed;
                return rdp_filesystem_redirection_parse_notify_change_request(data, data_len, &typed);
            }
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        case RDP_DEVICE_REDIRECTION_IRP_LOCK_CONTROL:
        {
            rdp_filesystem_redirection_lock_request typed;
            return rdp_filesystem_redirection_parse_lock_request(data, data_len, &typed);
        }
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_SECURITY:
        {
            rdp_filesystem_redirection_security_request typed;
            return rdp_filesystem_redirection_parse_query_security_request(data, data_len, &typed);
        }
        case RDP_DEVICE_REDIRECTION_IRP_SET_SECURITY:
        {
            rdp_filesystem_redirection_security_request typed;
            return rdp_filesystem_redirection_parse_set_security_request(data, data_len, &typed);
        }
        default:
            return LIBRDP_STATUS_OK;
    }
}

static librdp_status rdp_session_handle_filesystem_not_supported(librdp_session* session,
                                                               const uint8_t* data,
                                                               size_t data_len,
                                                               const rdp_device_redirection_io_request* request,
                                                               uint32_t io_status)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_validate_filesystem_not_supported_request(data, data_len, request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&response);
    status = rdp_session_write_filesystem_not_supported_response(&response, request, io_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.not_supported.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.not_supported",
                        "device_id=%u file_id=%u completion_id=%u major=%u minor=%u status=%u",
                        request->device_id,
                        request->file_id,
                        request->completion_id,
                        request->major_function,
                        request->minor_function,
                        io_status);
    return status;
}

librdp_status rdp_session_handle_filesystem_io_request(librdp_session* session,
                                                              const uint8_t* data,
                                                              size_t data_len)
{
    rdp_device_redirection_io_request request;
    uint32_t io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_parse_io_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_session_drive_index_from_device_id(session, request.device_id) == UINT32_MAX)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    else
        io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;

    switch (request.major_function)
    {
        case RDP_DEVICE_REDIRECTION_IRP_CREATE:
            return rdp_session_handle_filesystem_create(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_CLEANUP:
        case RDP_DEVICE_REDIRECTION_IRP_FLUSH_BUFFERS:
        case RDP_DEVICE_REDIRECTION_IRP_SHUTDOWN:
            return rdp_session_handle_filesystem_simple(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_CLOSE:
            return rdp_session_handle_filesystem_close(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_READ:
            return rdp_session_handle_filesystem_read(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_WRITE:
            return rdp_session_handle_filesystem_write(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_VOLUME_INFORMATION:
            return rdp_session_handle_filesystem_query_volume(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_SET_VOLUME_INFORMATION:
            return rdp_session_handle_filesystem_set_volume(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION:
            return rdp_session_handle_filesystem_query_information(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_SET_INFORMATION:
            return rdp_session_handle_filesystem_set_information(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_DIRECTORY_CONTROL:
            if (request.minor_function == RDP_FILESYSTEM_REDIRECTION_MINOR_QUERY_DIRECTORY)
                return rdp_session_handle_filesystem_query_directory(session, data, data_len);
            if (request.minor_function == RDP_FILESYSTEM_REDIRECTION_MINOR_NOTIFY_CHANGE_DIRECTORY)
                return rdp_session_handle_filesystem_notify_change(session, data, data_len);
            return rdp_session_handle_filesystem_not_supported(session,
                                                             data,
                                                             data_len,
                                                             &request,
                                                             io_status);
        case RDP_DEVICE_REDIRECTION_IRP_LOCK_CONTROL:
            return rdp_session_handle_filesystem_lock(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_SECURITY:
        case RDP_DEVICE_REDIRECTION_IRP_SET_SECURITY:
            return rdp_session_handle_filesystem_security(session,
                                                          data,
                                                          data_len,
                                                          request.major_function);
        case RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL:
            return rdp_session_handle_filesystem_device_control(session, data, data_len);
        default:
            return rdp_session_handle_filesystem_not_supported(session,
                                                             data,
                                                             data_len,
                                                             &request,
                                                             io_status);
    }
}
