/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: bounded URI-list decoder and descriptor-backed clipboard file
 * source for desktop-server platform adapters.
 * Invariants: imported state is committed only after every descriptor and the
 * complete wire metadata payload are valid; reads never exceed the negotiated
 * range cap or the retained regular-file size.
 * Ownership: each committed entry owns an open descriptor and UTF-8 basename;
 * temporary import state is released on every failure.
 * Threading: the source is confined to the desktop-server host thread.
 * Trust boundary: native clipboard bytes and filesystem metadata are untrusted;
 * URI authorities, escapes, file types, offsets and lengths are validated.
 */

#include "server_clipboard_files.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define SERVER_CLIPBOARD_URI_LIMIT (16u * 1024u * 1024u)

typedef struct server_clipboard_file_entry
{
    int descriptor;
    char* name;
    uint64_t size;
} server_clipboard_file_entry;

struct server_clipboard_files
{
    server_clipboard_file_entry entries[SERVER_CLIPBOARD_FILE_LIMIT];
    size_t count;
    uint64_t ownership_generation;
};

static void server_clipboard_file_entries_clear(
    server_clipboard_file_entry* entries,
    size_t count)
{
    size_t index = 0u;

    if (!entries)
        return;
    for (index = 0u; index < count; index++)
    {
        if (entries[index].descriptor >= 0)
            close(entries[index].descriptor);
        free(entries[index].name);
        entries[index].descriptor = -1;
        entries[index].name = NULL;
        entries[index].size = 0u;
    }
}

server_clipboard_files* server_clipboard_files_new(void)
{
    server_clipboard_files* files =
        (server_clipboard_files*)calloc(1u, sizeof(*files));
    size_t index = 0u;

    if (!files)
        return NULL;
    for (index = 0u; index < SERVER_CLIPBOARD_FILE_LIMIT; index++)
        files->entries[index].descriptor = -1;
    return files;
}

void server_clipboard_files_reset(server_clipboard_files* files)
{
    if (!files)
        return;
    server_clipboard_file_entries_clear(files->entries, files->count);
    files->count = 0u;
    files->ownership_generation = 0u;
}

void server_clipboard_files_free(server_clipboard_files* files)
{
    if (!files)
        return;
    server_clipboard_files_reset(files);
    free(files);
}

static int server_clipboard_hex_value(uint8_t value)
{
    if (value >= (uint8_t)'0' && value <= (uint8_t)'9')
        return (int)(value - (uint8_t)'0');
    if (value >= (uint8_t)'a' && value <= (uint8_t)'f')
        return (int)(value - (uint8_t)'a') + 10;
    if (value >= (uint8_t)'A' && value <= (uint8_t)'F')
        return (int)(value - (uint8_t)'A') + 10;
    return -1;
}

/*
 * Accept only local file URIs. A non-empty authority is rejected unless it is
 * exactly localhost, preventing a selection owner from turning file transfer
 * into implicit network access.
 */
static librdp_status server_clipboard_decode_uri(const uint8_t* line,
                                                  size_t line_len,
                                                  char** path)
{
    static const uint8_t prefix[] = "file://";
    static const uint8_t localhost[] = "localhost";
    const uint8_t* encoded = NULL;
    size_t encoded_len = 0u;
    char* decoded = NULL;
    size_t input = 0u;
    size_t output = 0u;

    if (!line || !path || line_len <= sizeof(prefix) - 1u ||
        memcmp(line, prefix, sizeof(prefix) - 1u) != 0)
        return LIBRDP_STATUS_UNSUPPORTED;
    *path = NULL;
    encoded = line + sizeof(prefix) - 1u;
    encoded_len = line_len - (sizeof(prefix) - 1u);
    if (encoded[0] != (uint8_t)'/')
    {
        const uint8_t* slash =
            (const uint8_t*)memchr(encoded, '/', encoded_len);
        size_t authority_len =
            slash ? (size_t)(slash - encoded) : encoded_len;

        if (!slash || authority_len != sizeof(localhost) - 1u ||
            memcmp(encoded, localhost, authority_len) != 0)
            return LIBRDP_STATUS_UNSUPPORTED;
        encoded = slash;
        encoded_len -= authority_len;
    }
    if (encoded_len == 0u || encoded[0] != (uint8_t)'/')
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    decoded = (char*)malloc(encoded_len + 1u);
    if (!decoded)
        return LIBRDP_STATUS_NO_MEMORY;
    while (input < encoded_len)
    {
        uint8_t value = encoded[input++];

        if (value == (uint8_t)'%')
        {
            int high = 0;
            int low = 0;

            if (input + 1u >= encoded_len)
            {
                free(decoded);
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            high = server_clipboard_hex_value(encoded[input]);
            low = server_clipboard_hex_value(encoded[input + 1u]);
            if (high < 0 || low < 0)
            {
                free(decoded);
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            value = (uint8_t)((high << 4) | low);
            input += 2u;
        }
        if (value == 0u || value == (uint8_t)'\r' ||
            value == (uint8_t)'\n')
        {
            free(decoded);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        decoded[output++] = (char)value;
    }
    decoded[output] = '\0';
    *path = decoded;
    return LIBRDP_STATUS_OK;
}

static const char* server_clipboard_basename(const char* path)
{
    const char* slash = path ? strrchr(path, '/') : NULL;

    if (!path || path[0] == '\0')
        return NULL;
    if (!slash)
        return path;
    return slash[1] != '\0' ? slash + 1u : NULL;
}

static librdp_status server_clipboard_import_file(
    const uint8_t* line,
    size_t line_len,
    server_clipboard_file_entry* entry)
{
    struct stat metadata;
    const char* basename = NULL;
    char* path = NULL;
    int descriptor = -1;
    size_t name_len = 0u;
    librdp_status status =
        server_clipboard_decode_uri(line, line_len, &path);

    if (status != LIBRDP_STATUS_OK)
        return status;
    basename = server_clipboard_basename(path);
    if (!basename)
    {
        free(path);
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    name_len = strlen(basename);
    if (name_len == 0u || name_len > 255u)
    {
        free(path);
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
    {
        free(path);
        return LIBRDP_STATUS_IO_ERROR;
    }
    if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_size < 0)
    {
        close(descriptor);
        free(path);
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    entry->name = (char*)malloc(name_len + 1u);
    if (!entry->name)
    {
        close(descriptor);
        free(path);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    memcpy(entry->name, basename, name_len + 1u);
    free(path);
    entry->descriptor = descriptor;
    entry->size = (uint64_t)metadata.st_size;
    return LIBRDP_STATUS_OK;
}

static librdp_status server_clipboard_encode_entries(
    const server_clipboard_file_entry* entries,
    size_t count,
    uint8_t** encoded,
    size_t* encoded_len)
{
    librdp_clipboard_file_metadata
        metadata[SERVER_CLIPBOARD_FILE_LIMIT];
    size_t required = 0u;
    size_t index = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!entries || count == 0u ||
        count > SERVER_CLIPBOARD_FILE_LIMIT || !encoded || !encoded_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *encoded = NULL;
    *encoded_len = 0u;
    memset(metadata, 0, sizeof(metadata));
    for (index = 0u; index < count; index++)
    {
        status = librdp_clipboard_file_metadata_init(&metadata[index]);
        if (status != LIBRDP_STATUS_OK)
            return status;
        metadata[index].name = entries[index].name;
        metadata[index].file_size = entries[index].size;
        metadata[index].attributes =
            LIBRDP_CLIPBOARD_FILE_ATTRIBUTE_NORMAL;
    }
    status = librdp_clipboard_file_group_encode(metadata,
                                                (uint32_t)count,
                                                NULL,
                                                0u,
                                                &required);
    if (status != LIBRDP_STATUS_OK)
        return status;
    *encoded = (uint8_t*)malloc(required);
    if (!*encoded)
        return LIBRDP_STATUS_NO_MEMORY;
    status = librdp_clipboard_file_group_encode(metadata,
                                                (uint32_t)count,
                                                *encoded,
                                                required,
                                                encoded_len);
    if (status != LIBRDP_STATUS_OK)
    {
        free(*encoded);
        *encoded = NULL;
        *encoded_len = 0u;
    }
    return status;
}

/*
 * Parse into temporary entries so an invalid selection cannot discard a
 * previously usable clipboard generation or leak partially opened files.
 */
librdp_status server_clipboard_files_import_uri_list(
    server_clipboard_files* files,
    const uint8_t* data,
    size_t data_len,
    uint64_t ownership_generation,
    uint8_t** encoded,
    size_t* encoded_len)
{
    server_clipboard_file_entry
        pending[SERVER_CLIPBOARD_FILE_LIMIT];
    size_t offset = 0u;
    size_t count = 0u;
    size_t index = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!files || (!data && data_len > 0u) || data_len == 0u ||
        data_len > SERVER_CLIPBOARD_URI_LIMIT ||
        ownership_generation == 0u || !encoded || !encoded_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(pending, 0, sizeof(pending));
    for (index = 0u; index < SERVER_CLIPBOARD_FILE_LIMIT; index++)
        pending[index].descriptor = -1;
    while (offset < data_len)
    {
        size_t start = offset;
        size_t end = 0u;

        while (offset < data_len && data[offset] != (uint8_t)'\n')
            offset++;
        end = offset;
        if (offset < data_len)
            offset++;
        if (end > start && data[end - 1u] == (uint8_t)'\r')
            end--;
        if (end == start || data[start] == (uint8_t)'#')
            continue;
        if (count >= SERVER_CLIPBOARD_FILE_LIMIT)
        {
            status = LIBRDP_STATUS_LIMIT_EXCEEDED;
            break;
        }
        status = server_clipboard_import_file(data + start,
                                              end - start,
                                              &pending[count]);
        if (status != LIBRDP_STATUS_OK)
            break;
        count++;
    }
    if (status == LIBRDP_STATUS_OK && count == 0u)
        status = LIBRDP_STATUS_UNSUPPORTED;
    if (status == LIBRDP_STATUS_OK)
    {
        status = server_clipboard_encode_entries(pending,
                                                 count,
                                                 encoded,
                                                 encoded_len);
    }
    if (status != LIBRDP_STATUS_OK)
    {
        server_clipboard_file_entries_clear(pending, count);
        return status;
    }
    server_clipboard_files_reset(files);
    memcpy(files->entries, pending, sizeof(pending));
    files->count = count;
    files->ownership_generation = ownership_generation;
    return LIBRDP_STATUS_OK;
}

static void server_clipboard_write_u64_le(uint8_t output[8],
                                          uint64_t value)
{
    size_t index = 0u;

    for (index = 0u; index < 8u; index++)
        output[index] = (uint8_t)(value >> (index * 8u));
}

librdp_status server_clipboard_files_read(
    server_clipboard_files* files,
    const server_platform_clipboard_file_request* request,
    uint8_t** data,
    size_t* data_len)
{
    server_clipboard_file_entry* entry = NULL;
    uint8_t* buffer = NULL;
    size_t requested = 0u;
    ssize_t received = 0;

    if (!files || !request || !data || !data_len ||
        request->ownership_generation == 0u ||
        request->ownership_generation != files->ownership_generation ||
        request->file_index < 0 ||
        (size_t)request->file_index >= files->count ||
        (request->flags != LIBRDP_CLIPBOARD_FILECONTENTS_SIZE &&
         request->flags != LIBRDP_CLIPBOARD_FILECONTENTS_RANGE))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *data = NULL;
    *data_len = 0u;
    entry = &files->entries[(size_t)request->file_index];
    if (request->flags == LIBRDP_CLIPBOARD_FILECONTENTS_SIZE)
    {
        buffer = (uint8_t*)malloc(8u);
        if (!buffer)
            return LIBRDP_STATUS_NO_MEMORY;
        server_clipboard_write_u64_le(buffer, entry->size);
        *data = buffer;
        *data_len = 8u;
        return LIBRDP_STATUS_OK;
    }
    if (request->requested_bytes > SERVER_CLIPBOARD_FILE_RANGE_LIMIT)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (request->position >= entry->size ||
        request->requested_bytes == 0u)
    {
        buffer = (uint8_t*)calloc(1u, 1u);
        if (!buffer)
            return LIBRDP_STATUS_NO_MEMORY;
        *data = buffer;
        return LIBRDP_STATUS_OK;
    }
    requested = request->requested_bytes;
    if ((uint64_t)requested > entry->size - request->position)
        requested = (size_t)(entry->size - request->position);
    if (request->position > (uint64_t)INT64_MAX)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    buffer = (uint8_t*)malloc(requested);
    if (!buffer)
        return LIBRDP_STATUS_NO_MEMORY;
    do
    {
        received = pread(entry->descriptor,
                         buffer,
                         requested,
                         (off_t)request->position);
    } while (received < 0 && errno == EINTR);
    if (received < 0)
    {
        free(buffer);
        return LIBRDP_STATUS_IO_ERROR;
    }
    *data = buffer;
    *data_len = (size_t)received;
    return LIBRDP_STATUS_OK;
}

size_t server_clipboard_files_count(
    const server_clipboard_files* files)
{
    return files ? files->count : 0u;
}
