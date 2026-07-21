/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: session clipboard publication, requests, and file-transfer responses.
 * Invariants: local advertisements are replaced atomically and pending file streams are correlated by stream ID.
 * Ownership: local clipboard buffers and file descriptors are session-owned; event payloads expose borrowed data.
 * Threading: public entry points validate the session owner thread before changing clipboard state.
 * Trust boundary: remote format and file-content requests are bounded before reading local files or emitting data.
 */

#include "client/session_internal.h"
#include "common/trace.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static librdp_status rdp_session_clipboard_format_name(const char* name, rdp_buffer* out)
{
    if (!name || !out)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_utf8_to_utf16le(name, out, 0);
}

/*
 * Parse a remote format list transactionally and retain only the configured
 * number of entries. The event view borrows names from the caller's packet,
 * while the session stores only numeric identifiers that survive dispatch.
 */
librdp_status rdp_session_clipboard_store_remote_formats(
    librdp_session* session,
    const rdp_clipboard_format_list* list,
    int long_names,
    librdp_clipboard_format* formats,
    uint32_t capacity,
    uint32_t* stored,
    uint32_t* total)
{
    uint32_t identifiers[RDP_SESSION_CLIPBOARD_MAX_FORMATS];
    uint32_t available = 0u;
    uint32_t retained = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !list || !formats || !stored || !total)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_clipboard_format_list_entry_count(list,
                                                   long_names,
                                                   &available);
    if (status != LIBRDP_STATUS_OK)
        return status;
    retained = available;
    if (retained > session->limits.clipboard_formats)
        retained = session->limits.clipboard_formats;
    if (retained > capacity || retained > RDP_SESSION_CLIPBOARD_MAX_FORMATS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(identifiers, 0, sizeof(identifiers));
    for (uint32_t index = 0u; index < retained; index++)
    {
        rdp_clipboard_format_entry item;

        status = rdp_clipboard_format_list_get_entry(list,
                                                     long_names,
                                                     index,
                                                     &item);
        if (status != LIBRDP_STATUS_OK)
            return status;
        formats[index].format_id = item.format_id;
        formats[index].name = item.name;
        formats[index].name_len = item.name_len;
        identifiers[index] = item.format_id;
    }

    memset(session->clipboard_remote_formats,
           0,
           sizeof(session->clipboard_remote_formats));
    if (retained > 0u)
    {
        memcpy(session->clipboard_remote_formats,
               identifiers,
               (size_t)retained * sizeof(identifiers[0]));
    }
    session->clipboard_remote_format_count = retained;
    if (available > retained)
        rdp_session_metric_add(&session->metrics.limits_rejected, 1u);
    *stored = retained;
    *total = available;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_clipboard_file_descriptors(const librdp_session* session,
                                                            rdp_clipboard_file_descriptor* files,
                                                            uint32_t* count)
{
    uint32_t i = 0;

    if (!session || !files || !count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!session->clipboard_local_files_available || session->clipboard_local_file_count == 0)
        return LIBRDP_STATUS_STATE;
    for (i = 0; i < session->clipboard_local_file_count; i++)
    {
        if (!session->clipboard_local_files[i].name_utf16.data ||
            session->clipboard_local_files[i].name_utf16.length == 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        files[i].name_utf16 = session->clipboard_local_files[i].name_utf16.data;
        files[i].name_utf16_len = session->clipboard_local_files[i].name_utf16.length;
        files[i].size = session->clipboard_local_files[i].size;
        files[i].attributes = RDP_CLIPBOARD_FILE_ATTRIBUTE_NORMAL;
    }
    *count = session->clipboard_local_file_count;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_clipboard_write_file_payload(librdp_session* session,
                                                              uint32_t format_id,
                                                              rdp_buffer* payload)
{
    rdp_clipboard_file_descriptor files[RDP_SESSION_CLIPBOARD_MAX_LOCAL_FILES];
    uint32_t count = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_clipboard_file_descriptors(session, files, &count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (format_id == RDP_CLIPBOARD_FORMAT_HDROP)
        return rdp_clipboard_write_hdrop(payload, files, count);
    if (format_id == RDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW)
        return rdp_clipboard_write_file_group_descriptor_w(payload, files, count);
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_session_clipboard_write_local_data_response(librdp_session* session,
                                                                     uint32_t format_id,
                                                                     rdp_buffer* response,
                                                                     uint8_t* available,
                                                                     size_t* data_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !response || !available || !data_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *available = 0;
    *data_len = 0;
    if (session->clipboard_local_available && session->clipboard_local_format_id == format_id)
    {
        *available = 1;
        *data_len = session->clipboard_local_data.length;
        return rdp_clipboard_write_format_data_response(response,
                                                        1,
                                                        session->clipboard_local_data.data,
                                                        session->clipboard_local_data.length);
    }
    if (!session->clipboard_local_files_available)
        return rdp_clipboard_write_format_data_response(response, 0, NULL, 0);
    if (format_id != RDP_CLIPBOARD_FORMAT_HDROP &&
        format_id != RDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW)
        return rdp_clipboard_write_format_data_response(response, 0, NULL, 0);

    rdp_buffer_init(&payload);
    status = rdp_session_clipboard_write_file_payload(session, format_id, &payload);
    if (status == LIBRDP_STATUS_OK)
    {
        *available = 1;
        *data_len = payload.length;
        status = rdp_clipboard_write_format_data_response(response, 1, payload.data, payload.length);
    }
    rdp_buffer_free(&payload);
    if (status != LIBRDP_STATUS_OK)
        return rdp_clipboard_write_format_data_response(response, 0, NULL, 0);
    return status;
}

static int rdp_session_clipboard_file_index(const librdp_session* session, int32_t lindex, uint32_t* index)
{
    if (!session || !index || !session->clipboard_local_files_available ||
        session->clipboard_local_file_count == 0)
        return 0;
    if (lindex >= 0 && (uint32_t)lindex < session->clipboard_local_file_count)
    {
        *index = (uint32_t)lindex;
        return 1;
    }
    if (lindex < 0 && session->clipboard_local_file_count == 1)
    {
        *index = 0;
        return 1;
    }
    return 0;
}

static librdp_status rdp_session_clipboard_read_file_range(const rdp_session_clipboard_file_entry* file,
                                                           uint64_t position,
                                                           uint32_t requested,
                                                           rdp_buffer* out)
{
    int fd = -1;
    uint64_t available = 0;
    uint64_t take = 0;
    size_t remaining = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!file || !file->path || !out)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (position > file->size)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    available = file->size - position;
    take = available > requested ? requested : available;
    if (take > RDP_SESSION_CLIPBOARD_FILE_RANGE_MAX)
        take = RDP_SESSION_CLIPBOARD_FILE_RANGE_MAX;
    remaining = (size_t)take;
    fd = open(file->path, O_RDONLY);
    if (fd < 0)
        return LIBRDP_STATUS_IO_ERROR;
    if (position > (uint64_t)INT64_MAX || lseek(fd, (off_t)position, SEEK_SET) < 0)
    {
        (void)close(fd);
        return LIBRDP_STATUS_IO_ERROR;
    }
    while (remaining > 0)
    {
        uint8_t chunk[32768];
        size_t want = remaining > sizeof(chunk) ? sizeof(chunk) : remaining;
        ssize_t got = 0;

        do
        {
            got = read(fd, chunk, want);
        } while (got < 0 && errno == EINTR);
        if (got < 0)
        {
            status = LIBRDP_STATUS_IO_ERROR;
            break;
        }
        if (got == 0)
            break;
        status = rdp_buffer_append(out, chunk, (size_t)got);
        if (status != LIBRDP_STATUS_OK)
            break;
        remaining -= (size_t)got;
    }
    (void)close(fd);
    return status;
}

librdp_status rdp_session_clipboard_write_file_contents(librdp_session* session,
                                                               const rdp_clipboard_file_contents_request* request,
                                                               rdp_buffer* response,
                                                               uint8_t* ok,
                                                               size_t* data_len)
{
    rdp_buffer payload;
    uint32_t index = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request || !response || !ok || !data_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *ok = 0;
    *data_len = 0;
    rdp_buffer_init(&payload);
    if (!rdp_session_clipboard_file_index(session, request->lindex, &index))
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
    else if (request->flags == RDP_CLIPBOARD_FILECONTENTS_SIZE)
    {
        uint64_t size = session->clipboard_local_files[index].size;

        status = rdp_buffer_append_u32_le(&payload, (uint32_t)(size & 0xffffffffu));
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(&payload, (uint32_t)(size >> 32));
    }
    else if (request->flags == RDP_CLIPBOARD_FILECONTENTS_RANGE)
    {
        status = rdp_session_clipboard_read_file_range(&session->clipboard_local_files[index],
                                                       request->position,
                                                       request->requested,
                                                       &payload);
    }
    else
    {
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        *ok = 1;
        *data_len = payload.length;
        status = rdp_clipboard_write_file_contents_response(response,
                                                            1,
                                                            request->stream_id,
                                                            payload.data,
                                                            payload.length);
    }
    else
    {
        status = rdp_clipboard_write_file_contents_response(response, 0, request->stream_id, NULL, 0);
    }
    rdp_buffer_free(&payload);
    return status;
}

static void rdp_session_clipboard_file_requests_clear(librdp_session* session)
{
    if (!session)
        return;
    memset(session->clipboard_file_requests, 0, sizeof(session->clipboard_file_requests));
}

rdp_session_clipboard_file_request* rdp_session_clipboard_file_request_find(librdp_session* session,
                                                                                  uint32_t stream_id)
{
    uint32_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_CLIPBOARD_MAX_PENDING_FILE_REQUESTS; i++)
    {
        if (session->clipboard_file_requests[i].active &&
            session->clipboard_file_requests[i].stream_id == stream_id)
            return &session->clipboard_file_requests[i];
    }
    return NULL;
}

librdp_status rdp_session_clipboard_file_request_store(librdp_session* session,
                                                              uint32_t stream_id,
                                                              int32_t file_index,
                                                              uint32_t flags,
                                                              uint64_t position,
                                                              uint32_t requested)
{
    uint32_t i = 0;
    rdp_session_clipboard_file_request* slot = NULL;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    slot = rdp_session_clipboard_file_request_find(session, stream_id);
    if (!slot)
    {
        for (i = 0; i < RDP_SESSION_CLIPBOARD_MAX_PENDING_FILE_REQUESTS; i++)
        {
            if (!session->clipboard_file_requests[i].active)
            {
                slot = &session->clipboard_file_requests[i];
                break;
            }
        }
    }
    if (!slot)
        return LIBRDP_STATUS_NO_MEMORY;
    memset(slot, 0, sizeof(*slot));
    slot->active = 1;
    slot->stream_id = stream_id;
    slot->file_index = file_index;
    slot->flags = flags;
    slot->position = position;
    slot->requested = requested;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_session_send_clipboard_format_list(librdp_session* session)
{
    rdp_buffer packet;
    rdp_buffer file_group_name;
    rdp_buffer file_contents_name;
    rdp_clipboard_format_entry entries[4];
    uint32_t count = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!session->clipboard_ready || session->clipboard_channel_id == 0)
        return LIBRDP_STATUS_OK;

    memset(entries, 0, sizeof(entries));
    rdp_buffer_init(&file_group_name);
    rdp_buffer_init(&file_contents_name);
    if (session->clipboard_local_available)
    {
        entries[count].format_id = session->clipboard_local_format_id;
        if (session->clipboard_local_has_name)
        {
            entries[count].name = session->clipboard_local_format_name.data;
            entries[count].name_len = session->clipboard_local_format_name.length;
        }
        count++;
    }
    if (session->clipboard_local_files_available)
    {
        status = rdp_session_clipboard_format_name("FileGroupDescriptorW", &file_group_name);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_clipboard_format_name("FileContents", &file_contents_name);
        if (status == LIBRDP_STATUS_OK)
        {
            entries[count].format_id = RDP_CLIPBOARD_FORMAT_HDROP;
            count++;
            entries[count].format_id = RDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW;
            entries[count].name = file_group_name.data;
            entries[count].name_len = file_group_name.length;
            count++;
            entries[count].format_id = RDP_CLIPBOARD_FORMAT_FILECONTENTS;
            entries[count].name = file_contents_name.data;
            entries[count].name_len = file_contents_name.length;
            count++;
        }
    }

    rdp_buffer_init(&packet);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_clipboard_write_format_list(&packet, count ? entries : NULL, count, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_clipboard_packet(session, &packet, "client.clipboard.format_list");
    rdp_buffer_free(&packet);
    rdp_buffer_free(&file_group_name);
    rdp_buffer_free(&file_contents_name);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.clipboard.format_list",
                        "channel_id=%u count=%u",
                        session->clipboard_channel_id,
                        count);
    return status;
}

librdp_status rdp_session_send_clipboard_handshake(librdp_session* session)
{
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;
    const uint32_t flags = RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES |
                           RDP_CLIPBOARD_CAP_STREAM_FILECLIP_ENABLED |
                           RDP_CLIPBOARD_CAP_FILECLIP_NO_FILE_PATHS |
                           RDP_CLIPBOARD_CAP_CAN_LOCK_CLIPDATA |
                           RDP_CLIPBOARD_CAP_HUGE_FILE_SUPPORT_ENABLED;

    if (!session || session->clipboard_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->clipboard_ready)
        return LIBRDP_STATUS_OK;

    rdp_buffer_init(&packet);
    status = rdp_clipboard_write_capabilities(&packet, flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_clipboard_packet(session, &packet, "client.clipboard.capabilities");
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.clipboard.capabilities",
                        "channel_id=%u flags=%u",
                        session->clipboard_channel_id,
                        flags);
        packet.length = 0;
        status = rdp_clipboard_write_monitor_ready(&packet);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_clipboard_packet(session, &packet, "client.clipboard.monitor_ready");
    rdp_buffer_free(&packet);
    if (status == LIBRDP_STATUS_OK)
    {
        session->clipboard_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.clipboard.monitor_ready",
                        "channel_id=%u",
                        session->clipboard_channel_id);
        status = rdp_session_send_clipboard_format_list(session);
    }
    return status;
}


void rdp_session_clipboard_clear(librdp_session* session)
{
    if (!session)
        return;
    rdp_buffer_free(&session->clipboard_fragment);
    session->clipboard_fragmenting = 0;
    session->clipboard_fragment_expected = 0;
    session->clipboard_ready = 0;
    session->clipboard_general_flags = 0;
    session->clipboard_pending_request_format_id = 0;
    session->clipboard_remote_format_count = 0;
    rdp_session_clipboard_file_requests_clear(session);
}

static void rdp_session_clipboard_files_clear(librdp_session* session)
{
    uint32_t i = 0;

    if (!session)
        return;
    for (i = 0; i < session->clipboard_local_file_count; i++)
    {
        free(session->clipboard_local_files[i].path);
        free(session->clipboard_local_files[i].name);
        rdp_buffer_free(&session->clipboard_local_files[i].name_utf16);
        memset(&session->clipboard_local_files[i], 0, sizeof(session->clipboard_local_files[i]));
    }
    session->clipboard_local_file_count = 0;
    session->clipboard_local_files_available = 0;
}

void rdp_session_clipboard_local_clear(librdp_session* session)
{
    if (!session)
        return;
    rdp_buffer_free(&session->clipboard_local_data);
    rdp_buffer_free(&session->clipboard_local_format_name);
    session->clipboard_local_format_id = 0;
    session->clipboard_local_has_name = 0;
    session->clipboard_local_available = 0;
    rdp_session_clipboard_files_clear(session);
}


static char* rdp_session_clipboard_strdup(const char* text)
{
    size_t length = 0;
    char* copy = NULL;

    if (!text)
        return NULL;
    length = strlen(text);
    if (length == 0 || length == SIZE_MAX)
        return NULL;
    copy = (char*)malloc(length + 1u);
    if (!copy)
        return NULL;
    memcpy(copy, text, length + 1u);
    return copy;
}

static const char* rdp_session_clipboard_basename(const char* path)
{
    const char* slash = NULL;

    if (!path)
        return NULL;
    slash = strrchr(path, '/');
    if (slash && slash[1] != '\0')
        return slash + 1;
    if (slash && slash[1] == '\0')
        return NULL;
    return path;
}

static librdp_status rdp_session_clipboard_set_file_entry(librdp_session* session,
                                                          uint32_t index,
                                                          const librdp_clipboard_file* file)
{
    struct stat st;
    const char* name = NULL;
    rdp_session_clipboard_file_entry* entry = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !file || !file->path || file->path[0] == '\0' ||
        index >= RDP_SESSION_CLIPBOARD_MAX_LOCAL_FILES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (stat(file->path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    name = file->name && file->name[0] != '\0' ? file->name : rdp_session_clipboard_basename(file->path);
    if (!name || name[0] == '\0')
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    entry = &session->clipboard_local_files[index];
    memset(entry, 0, sizeof(*entry));
    rdp_buffer_init(&entry->name_utf16);
    entry->path = rdp_session_clipboard_strdup(file->path);
    entry->name = rdp_session_clipboard_strdup(name);
    if (!entry->path || !entry->name)
        status = LIBRDP_STATUS_NO_MEMORY;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_utf8_to_utf16le(entry->name, &entry->name_utf16, 0);
    if (status == LIBRDP_STATUS_OK)
        entry->size = (uint64_t)st.st_size;
    if (status != LIBRDP_STATUS_OK)
    {
        free(entry->path);
        free(entry->name);
        rdp_buffer_free(&entry->name_utf16);
        memset(entry, 0, sizeof(*entry));
    }
    return status;
}

/*
 * Store local clipboard bytes with an optional registered-format name. The
 * helper validates ownership, payload limit, and UTF-8 format-name conversion
 * before publishing a new format list, so failed calls leave no partial local
 * advertisement behind.
 */
static librdp_status rdp_session_clipboard_set_data_internal(librdp_session* session,
                                                             uint32_t format_id,
                                                             const char* format_name,
                                                             const void* data,
                                                             size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || format_id == 0 || (format_name && format_name[0] == '\0') || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.clipboard.set_data.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (data_len > session->limits.dynamic_channel_message_bytes)
        return rdp_session_limit_rejected(session);

    rdp_session_clipboard_local_clear(session);
    if (data_len > 0)
    {
        rdp_buffer_init(&session->clipboard_local_data);
        status = rdp_buffer_append(&session->clipboard_local_data, data, data_len);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_session_clipboard_local_clear(session);
            return status;
        }
    }
    if (format_name)
    {
        rdp_buffer_init(&session->clipboard_local_format_name);
        status = rdp_session_clipboard_format_name(format_name, &session->clipboard_local_format_name);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_session_clipboard_local_clear(session);
            return status;
        }
        session->clipboard_local_has_name = 1;
    }
    session->clipboard_local_format_id = format_id;
    session->clipboard_local_available = 1;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.clipboard.local_data",
                    "format_id=%u named=%u data_len=%u",
                    format_id,
                    format_name ? 1u : 0u,
                    (unsigned)data_len);
    return rdp_session_send_clipboard_format_list(session);
}

librdp_status librdp_session_clipboard_set_data(librdp_session* session,
                                                uint32_t format_id,
                                                const void* data,
                                                size_t data_len)
{
    return rdp_session_clipboard_set_data_internal(session, format_id, NULL, data, data_len);
}

librdp_status librdp_session_clipboard_set_named_data(librdp_session* session,
                                                      uint32_t format_id,
                                                      const char* format_name,
                                                      const void* data,
                                                      size_t data_len)
{
    if (!format_name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_clipboard_set_data_internal(session, format_id, format_name, data, data_len);
}

librdp_status librdp_session_clipboard_set_files(librdp_session* session,
                                                 const librdp_clipboard_file* files,
                                                 uint32_t count)
{
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !files || count == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.clipboard.set_files.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (count > session->limits.clipboard_files)
        return rdp_session_limit_rejected(session);
    rdp_session_clipboard_local_clear(session);
    for (i = 0; i < count; i++)
    {
        status = rdp_session_clipboard_set_file_entry(session, i, &files[i]);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_session_clipboard_local_clear(session);
            return status;
        }
        session->clipboard_local_file_count++;
    }
    session->clipboard_local_files_available = 1;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.clipboard.local_files",
                    "count=%u",
                    count);
    return rdp_session_send_clipboard_format_list(session);
}

librdp_status librdp_session_clipboard_clear(librdp_session* session)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.clipboard.clear.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_session_clipboard_local_clear(session);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.clipboard.local_clear", "formats=0");
    return rdp_session_send_clipboard_format_list(session);
}

librdp_status librdp_session_clipboard_request_data(librdp_session* session, uint32_t format_id)
{
    rdp_buffer request;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || format_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.clipboard.request_data.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!session->clipboard_ready || session->clipboard_channel_id == 0)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&request);
    status = rdp_clipboard_write_format_data_request(&request, format_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_clipboard_packet(session, &request, "client.clipboard.format_data_request");
    rdp_buffer_free(&request);
    if (status == LIBRDP_STATUS_OK)
    {
        session->clipboard_pending_request_format_id = format_id;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.clipboard.request_data",
                        "format_id=%u",
                        format_id);
    }
    return status;
}

static librdp_status rdp_session_clipboard_request_file(librdp_session* session,
                                                        uint32_t stream_id,
                                                        int32_t file_index,
                                                        uint32_t flags,
                                                        uint64_t position,
                                                        uint32_t requested)
{
    rdp_buffer request;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || stream_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.clipboard.request_file.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (flags == RDP_CLIPBOARD_FILECONTENTS_RANGE &&
        requested == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (flags == RDP_CLIPBOARD_FILECONTENTS_RANGE &&
        requested > session->limits.clipboard_file_range_bytes)
        return rdp_session_limit_rejected(session);
    if (!session->clipboard_ready || session->clipboard_channel_id == 0)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&request);
    status = rdp_clipboard_write_file_contents_request(&request,
                                                       stream_id,
                                                       file_index,
                                                       flags,
                                                       position,
                                                       requested,
                                                       NULL);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_clipboard_file_request_store(session,
                                                          stream_id,
                                                          file_index,
                                                          flags,
                                                          position,
                                                          requested);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_clipboard_packet(session, &request, "client.clipboard.filecontents_request");
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_session_clipboard_file_request* pending =
            rdp_session_clipboard_file_request_find(session, stream_id);

        if (pending)
            memset(pending, 0, sizeof(*pending));
    }
    rdp_buffer_free(&request);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.clipboard.request_file",
                        "stream_id=%u index=%d flags=%u position=%llu requested=%u",
                        stream_id,
                        file_index,
                        flags,
                        (unsigned long long)position,
                        requested);
    return status;
}

librdp_status librdp_session_clipboard_request_file_size(librdp_session* session,
                                                         uint32_t stream_id,
                                                         int32_t file_index)
{
    return rdp_session_clipboard_request_file(session,
                                              stream_id,
                                              file_index,
                                              RDP_CLIPBOARD_FILECONTENTS_SIZE,
                                              0,
                                              8);
}

librdp_status librdp_session_clipboard_request_file_range(librdp_session* session,
                                                          uint32_t stream_id,
                                                          int32_t file_index,
                                                          uint64_t position,
                                                          uint32_t requested)
{
    return rdp_session_clipboard_request_file(session,
                                              stream_id,
                                              file_index,
                                              RDP_CLIPBOARD_FILECONTENTS_RANGE,
                                              position,
                                              requested);
}

