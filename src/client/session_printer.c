/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: printer device redirection and spool lifecycle.
 * Invariants: printer jobs are represented by redirected file handles, output
 * paths are validated before writes, and job byte counters are bounded by
 * configured device limits.
 * Ownership: spool paths, cache records, and printer job descriptors are owned
 * by the session until close, cancel, or disconnect cleanup.
 * Threading: printer IRPs run on the session owner thread and delegate host
 * backend operations through the configured printer backend.
 * Trust boundary: server-provided job IDs, cache metadata, and write offsets are
 * validated before touching host files or backend state.
 */

#include "client/session_internal.h"
#include "client/printer_backend.h"
#include "client/settings_internal.h"
#include "common/trace.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char rdp_session_print_path_char(char value)
{
    if ((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
        (value >= '0' && value <= '9') || value == '_' || value == '-' || value == '.')
        return value;
    return '_';
}

static librdp_status rdp_session_make_print_job_path(librdp_session* session,
                                                     uint32_t printer_index,
                                                     uint32_t file_id,
                                                     char** path)
{
    const char* output = NULL;
    const char* name = NULL;
    char safe[128];
    int needed = 0;
    size_t output_len = 0;
    size_t i = 0;

    if (!session || !path)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *path = NULL;
    output = librdp_settings_printer_output_path(session->settings, printer_index);
    name = librdp_settings_printer_name(session->settings, printer_index);
    if (!output || output[0] == '\0' || !name || name[0] == '\0')
        return LIBRDP_STATUS_STATE;
    for (i = 0; i + 1u < sizeof(safe) && name[i]; i++)
        safe[i] = rdp_session_print_path_char(name[i]);
    safe[i] = '\0';
    output_len = strlen(output);
    needed = snprintf(NULL,
                      0,
                      "%s%s%s-%08x.prn",
                      output,
                      output_len > 0 && output[output_len - 1u] == '/' ? "" : "/",
                      safe,
                      file_id);
    if (needed <= 0)
        return LIBRDP_STATUS_NO_MEMORY;
    *path = (char*)malloc((size_t)needed + 1u);
    if (!*path)
        return LIBRDP_STATUS_NO_MEMORY;
    (void)snprintf(*path,
                   (size_t)needed + 1u,
                   "%s%s%s-%08x.prn",
                   output,
                   output_len > 0 && output[output_len - 1u] == '/' ? "" : "/",
                   safe,
                   file_id);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_make_print_temp_path(librdp_session* session,
                                                      uint32_t printer_index,
                                                      uint32_t file_id,
                                                      char** path)
{
    const char* tmpdir = NULL;
    const char* name = NULL;
    char safe[128];
    int needed = 0;
    size_t tmpdir_len = 0;
    size_t i = 0;

    if (!session || !path)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *path = NULL;
    name = librdp_settings_printer_name(session->settings, printer_index);
    if (!name || name[0] == '\0')
        return LIBRDP_STATUS_STATE;
    for (i = 0; i + 1u < sizeof(safe) && name[i]; i++)
        safe[i] = rdp_session_print_path_char(name[i]);
    safe[i] = '\0';
    tmpdir = getenv("TMPDIR");
    if (!tmpdir || tmpdir[0] != '/')
        tmpdir = "/tmp";
    tmpdir_len = strlen(tmpdir);
    needed = snprintf(NULL,
                      0,
                      "%s%slibrdp-print-%s-%08x-XXXXXX",
                      tmpdir,
                      tmpdir_len > 0 && tmpdir[tmpdir_len - 1u] == '/' ? "" : "/",
                      safe,
                      file_id);
    if (needed <= 0)
        return LIBRDP_STATUS_NO_MEMORY;
    *path = (char*)malloc((size_t)needed + 1u);
    if (!*path)
        return LIBRDP_STATUS_NO_MEMORY;
    (void)snprintf(*path,
                   (size_t)needed + 1u,
                   "%s%slibrdp-print-%s-%08x-XXXXXX",
                   tmpdir,
                   tmpdir_len > 0 && tmpdir[tmpdir_len - 1u] == '/' ? "" : "/",
                   safe,
                   file_id);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_make_printer_cache_path(librdp_session* session,
                                                         uint32_t printer_index,
                                                         const char* printer_name,
                                                         char** path)
{
    const char* output = NULL;
    char safe[128];
    int needed = 0;
    size_t output_len = 0;
    size_t i = 0;

    if (!session || !path || !printer_name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *path = NULL;
    output = librdp_settings_printer_output_path(session->settings, printer_index);
    if (!output || output[0] == '\0')
        return LIBRDP_STATUS_STATE;
    for (i = 0; i + 1u < sizeof(safe) && printer_name[i]; i++)
        safe[i] = rdp_session_print_path_char(printer_name[i]);
    safe[i] = '\0';
    output_len = strlen(output);
    needed = snprintf(NULL,
                      0,
                      "%s%s%s.cache",
                      output,
                      output_len > 0 && output[output_len - 1u] == '/' ? "" : "/",
                      safe);
    if (needed <= 0)
        return LIBRDP_STATUS_NO_MEMORY;
    *path = (char*)malloc((size_t)needed + 1u);
    if (!*path)
        return LIBRDP_STATUS_NO_MEMORY;
    (void)snprintf(*path,
                   (size_t)needed + 1u,
                   "%s%s%s.cache",
                   output,
                   output_len > 0 && output[output_len - 1u] == '/' ? "" : "/",
                   safe);
    return LIBRDP_STATUS_OK;
}

static uint32_t rdp_session_validate_printer_output_path(librdp_session* session, uint32_t printer_index)
{
    const char* output = NULL;
    struct stat st;

    if (!session)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    output = librdp_settings_printer_output_path(session->settings, printer_index);
    if (!output || output[0] == '\0')
        return RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    if (rdp_printer_backend_output_is_cups(output))
        return rdp_printer_backend_validate_cups(output);
    memset(&st, 0, sizeof(st));
    if (stat(output, &st) != 0)
        return rdp_session_errno_to_device_status(errno);
    if (!S_ISDIR(st.st_mode))
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (access(output, W_OK | X_OK) != 0)
        return rdp_session_errno_to_device_status(errno);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static uint32_t rdp_session_printer_index_from_utf16_name(librdp_session* session,
                                                          const uint8_t* name,
                                                          uint32_t name_len,
                                                          uint32_t* printer_index,
                                                          char** utf8_name)
{
    char* converted = NULL;
    uint32_t count = 0;
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !printer_index || !utf8_name)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    *printer_index = UINT32_MAX;
    *utf8_name = NULL;
    status = rdp_session_utf16le_path_to_utf8(name, name_len, &converted);
    if (status != LIBRDP_STATUS_OK)
        return rdp_session_filesystem_error_from_status(status);
    count = librdp_settings_printer_count(session->settings);
    for (i = 0; i < count; i++)
    {
        const char* configured = librdp_settings_printer_name(session->settings, i);

        if (configured && strcmp(configured, converted) == 0)
        {
            *printer_index = i;
            *utf8_name = converted;
            return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
        }
    }
    free(converted);
    return RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
}

static uint32_t rdp_session_write_printer_cache_file(const char* path,
                                                     const uint8_t* data,
                                                     uint32_t data_len)
{
    int fd = -1;
    uint32_t written = 0;

    if (!path || (!data && data_len > 0))
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return rdp_session_errno_to_device_status(errno);
    while (written < data_len)
    {
        ssize_t count = write(fd, data + written, data_len - written);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
        {
            uint32_t status = count < 0 ? rdp_session_errno_to_device_status(errno) :
                                          RDP_SESSION_DEVICE_UNSUCCESSFUL;
            (void)close(fd);
            return status;
        }
        written += (uint32_t)count;
    }
    if (close(fd) != 0)
        return rdp_session_errno_to_device_status(errno);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

uint32_t rdp_session_store_printer_cache_event(librdp_session* session,
                                                      const rdp_printer_redirection_cache_event* event)
{
    char* name = NULL;
    char* old_name = NULL;
    char* new_name = NULL;
    char* path = NULL;
    char* new_path = NULL;
    uint32_t index = UINT32_MAX;
    uint32_t new_index = UINT32_MAX;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;

    if (!session || !event)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    switch (event->event_id)
    {
        case RDP_PRINTER_REDIRECTION_CACHE_ADD:
        case RDP_PRINTER_REDIRECTION_CACHE_UPDATE:
            io_status = rdp_session_printer_index_from_utf16_name(session,
                                                                  event->printer_name,
                                                                  event->printer_name_len,
                                                                  &index,
                                                                  &name);
            if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            {
                if (rdp_session_make_printer_cache_path(session, index, name, &path) != LIBRDP_STATUS_OK)
                    io_status = RDP_SESSION_DEVICE_UNSUCCESSFUL;
                else
                    io_status = rdp_session_write_printer_cache_file(path,
                                                                     event->cached_fields,
                                                                     event->cached_fields_len);
            }
            break;
        case RDP_PRINTER_REDIRECTION_CACHE_DELETE:
            io_status = rdp_session_printer_index_from_utf16_name(session,
                                                                  event->printer_name,
                                                                  event->printer_name_len,
                                                                  &index,
                                                                  &name);
            if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            {
                if (rdp_session_make_printer_cache_path(session, index, name, &path) != LIBRDP_STATUS_OK)
                    io_status = RDP_SESSION_DEVICE_UNSUCCESSFUL;
                else if (unlink(path) != 0 && errno != ENOENT)
                    io_status = rdp_session_errno_to_device_status(errno);
            }
            break;
        case RDP_PRINTER_REDIRECTION_CACHE_RENAME:
            io_status = rdp_session_printer_index_from_utf16_name(session,
                                                                  event->old_printer_name,
                                                                  event->old_printer_name_len,
                                                                  &index,
                                                                  &old_name);
            if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
                io_status = rdp_session_printer_index_from_utf16_name(session,
                                                                      event->new_printer_name,
                                                                      event->new_printer_name_len,
                                                                      &new_index,
                                                                      &new_name);
            if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            {
                if (rdp_session_make_printer_cache_path(session, index, old_name, &path) != LIBRDP_STATUS_OK ||
                    rdp_session_make_printer_cache_path(session, new_index, new_name, &new_path) !=
                        LIBRDP_STATUS_OK)
                    io_status = RDP_SESSION_DEVICE_UNSUCCESSFUL;
                else if (rename(path, new_path) != 0 && errno != ENOENT)
                    io_status = rdp_session_errno_to_device_status(errno);
            }
            break;
        default:
            io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            break;
    }
    free(name);
    free(old_name);
    free(new_name);
    free(path);
    free(new_path);
    return io_status;
}

static librdp_status rdp_session_send_printer_response(librdp_session* session,
                                                       const rdp_buffer* response,
                                                       const char* event)
{
    if (!session || !response || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_send_device_redirection_packet(session, response, event);
}

/*
 * Handle printer create/open requests from the device redirection channel. The
 * routine binds server file IDs to spool jobs only after printer identity and
 * backend availability are validated.
 */
static librdp_status rdp_session_handle_printer_create(librdp_session* session,
                                                       const rdp_device_redirection_io_request* request)
{
    rdp_session_redirected_file* job = NULL;
    rdp_buffer response;
    char* path = NULL;
    uint32_t printer_index = 0;
    uint32_t file_id = 0;
    uint8_t backend = RDP_SESSION_PRINTER_BACKEND_FILE;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    int fd = -1;
    librdp_status status = LIBRDP_STATUS_OK;
    const char* output = NULL;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    printer_index = rdp_session_printer_index_from_device_id(session, request->device_id);
    if (printer_index == UINT32_MAX)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    else
    {
        output = librdp_settings_printer_output_path(session->settings, printer_index);
        if (rdp_printer_backend_output_is_cups(output))
            backend = RDP_SESSION_PRINTER_BACKEND_CUPS;
        io_status = rdp_session_validate_printer_output_path(session, printer_index);
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            job = rdp_session_redirected_file_alloc(session, request->device_id, &file_id);
        if (!job)
        {
            if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
                io_status = RDP_SESSION_DEVICE_PRINT_QUEUE_FULL;
        }
        else
        {
            if (backend == RDP_SESSION_PRINTER_BACKEND_CUPS)
                status = rdp_session_make_print_temp_path(session, printer_index, file_id, &path);
            else
                status = rdp_session_make_print_job_path(session, printer_index, file_id, &path);
            if (status != LIBRDP_STATUS_OK)
                io_status = rdp_session_filesystem_error_from_status(status);
            else
            {
                if (backend == RDP_SESSION_PRINTER_BACKEND_CUPS)
                    fd = mkstemp(path);
                else
                    fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
                if (fd < 0)
                    io_status = rdp_session_errno_to_device_status(errno);
            }
            if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            {
                job->fd = fd;
                job->path = path;
                job->printer_backend = backend;
                job->printer_index = printer_index;
                fd = -1;
                path = NULL;
            }
            else
            {
                rdp_session_redirected_file_reset(job);
                file_id = 0;
            }
        }
    }

    free(path);
    if (fd >= 0)
        (void)close(fd);
    rdp_buffer_init(&response);
    status = rdp_printer_redirection_write_create_response(&response,
                                                           request->device_id,
                                                           request->completion_id,
                                                           io_status,
                                                           file_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_printer_response(session,
                                                   &response,
                                                   "client.rdpdr.printer.create.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.printer.create",
                        "device_id=%u completion_id=%u file_id=%u status=%u backend=%u",
                        request->device_id,
                        request->completion_id,
                        file_id,
                        io_status,
                        backend);
    return status;
}

static librdp_status rdp_session_handle_printer_close(librdp_session* session,
                                                      const rdp_device_redirection_io_request* request)
{
    rdp_session_redirected_file* job = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    job = rdp_session_redirected_file_find(session, request->device_id, request->file_id);
    if (!job)
    {
        io_status = RDP_SESSION_DEVICE_UNSUCCESSFUL;
    }
    else
    {
        uint8_t remove_spool = 0;

        if (job->fd >= 0 && fsync(job->fd) != 0 && errno != EINVAL)
            io_status = rdp_session_errno_to_device_status(errno);
        if (job->fd >= 0 && close(job->fd) != 0)
            io_status = rdp_session_errno_to_device_status(errno);
        job->fd = -1;
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS &&
            job->printer_backend == RDP_SESSION_PRINTER_BACKEND_CUPS)
        {
            io_status = rdp_printer_backend_submit_cups_async(
                job->printer_index,
                librdp_settings_printer_output_path(session->settings, job->printer_index),
                librdp_settings_printer_name(session->settings, job->printer_index),
                job->path,
                1);
            remove_spool = 0;
        }
        if (remove_spool && job->path && unlink(job->path) != 0 && io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            io_status = rdp_session_errno_to_device_status(errno);
        rdp_session_redirected_file_reset(job);
    }
    rdp_buffer_init(&response);
    status = rdp_printer_redirection_write_close_response(&response,
                                                          request->device_id,
                                                          request->completion_id,
                                                          io_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_printer_response(session,
                                                   &response,
                                                   "client.rdpdr.printer.close.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.printer.close",
                        "device_id=%u file_id=%u completion_id=%u status=%u",
                        request->device_id,
                        request->file_id,
                        request->completion_id,
                        io_status);
    return status;
}

static librdp_status rdp_session_handle_printer_simple(librdp_session* session,
                                                       const rdp_device_redirection_io_request* request)
{
    rdp_session_redirected_file* job = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (request->minor_function != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->major_function == RDP_DEVICE_REDIRECTION_IRP_SHUTDOWN)
    {
        if (rdp_session_printer_index_from_device_id(session, request->device_id) == UINT32_MAX)
            io_status = RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    }
    else
    {
        job = rdp_session_redirected_file_find(session, request->device_id, request->file_id);
        if (!job)
            io_status = RDP_SESSION_DEVICE_UNSUCCESSFUL;
        else if (request->major_function == RDP_DEVICE_REDIRECTION_IRP_FLUSH_BUFFERS && job->fd >= 0 &&
                 fsync(job->fd) != 0 && errno != EINVAL)
            io_status = rdp_session_errno_to_device_status(errno);
    }
    rdp_buffer_init(&response);
    status = rdp_device_redirection_write_io_completion(&response,
                                                        request->device_id,
                                                        request->completion_id,
                                                        io_status,
                                                        NULL,
                                                        0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_printer_response(session,
                                                   &response,
                                                   "client.rdpdr.printer.simple.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.printer.simple",
                        "device_id=%u file_id=%u completion_id=%u major=%u status=%u",
                        request->device_id,
                        request->file_id,
                        request->completion_id,
                        request->major_function,
                        io_status);
    return status;
}

static librdp_status rdp_session_handle_printer_write(librdp_session* session,
                                                      const uint8_t* data,
                                                      size_t data_len)
{
    rdp_filesystem_redirection_write_request request;
    rdp_session_redirected_file* job = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t written = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_write_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (request.length > RDP_SESSION_MAX_FILE_IO_BYTES)
    {
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    }
    else
    {
        job = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
        if (!job)
        {
            io_status = RDP_SESSION_DEVICE_UNSUCCESSFUL;
        }
        else
        {
            const uint8_t* cursor = request.data;
            uint32_t remaining = request.length;

            if (rdp_session_seek_fd(job->fd, request.offset) != 0)
                io_status = rdp_session_errno_to_device_status(errno);
            while (remaining > 0)
            {
                ssize_t count = 0;

                if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
                    break;
                count = write(job->fd, cursor, remaining);
                if (count < 0 && errno == EINTR)
                    continue;
                if (count <= 0)
                {
                    io_status = count < 0 ? rdp_session_errno_to_device_status(errno)
                                          : RDP_SESSION_DEVICE_UNSUCCESSFUL;
                    break;
                }
                cursor += (size_t)count;
                remaining -= (uint32_t)count;
                written += (uint32_t)count;
            }
        }
    }
    rdp_buffer_init(&response);
    status = rdp_printer_redirection_write_write_response(&response,
                                                          request.io.device_id,
                                                          request.io.completion_id,
                                                          io_status,
                                                          written);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_printer_response(session,
                                                   &response,
                                                   "client.rdpdr.printer.write.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.printer.write",
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

static librdp_status rdp_session_handle_printer_read(librdp_session* session,
                                                     const uint8_t* data,
                                                     size_t data_len)
{
    rdp_filesystem_redirection_read_request request;
    rdp_session_redirected_file* job = NULL;
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
    if (request.length > RDP_SESSION_MAX_FILE_IO_BYTES)
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    else
    {
        job = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
        if (!job)
            io_status = RDP_SESSION_DEVICE_UNSUCCESSFUL;
        else if (job->fd < 0)
            io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
        else if (rdp_session_seek_fd(job->fd, request.offset) != 0)
            io_status = rdp_session_errno_to_device_status(errno);
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
                    count = read(job->fd, bytes, request.length);
                } while (count < 0 && errno == EINTR);
                if (count < 0)
                    io_status = rdp_session_errno_to_device_status(errno);
                else
                    read_len = (uint32_t)count;
            }
        }
    }
    rdp_buffer_init(&response);
    status = rdp_printer_redirection_write_read_response(&response,
                                                         request.io.device_id,
                                                         request.io.completion_id,
                                                         io_status,
                                                         bytes,
                                                         read_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_printer_response(session,
                                                   &response,
                                                   "client.rdpdr.printer.read.response");
    rdp_buffer_free(&response);
    free(bytes);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.printer.read",
                        "device_id=%u file_id=%u completion_id=%u status=%u requested=%u returned=%u offset=%llu",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        io_status,
                        request.length,
                        read_len,
                        (unsigned long long)request.offset);
    return status;
}

static uint32_t rdp_session_apply_printer_set_information(rdp_session_redirected_file* job,
                                                          const rdp_filesystem_redirection_information_request* request)
{
    if (!job || !request || job->fd < 0)
        return RDP_SESSION_DEVICE_UNSUCCESSFUL;
    switch (request->information_class)
    {
        case RDP_SESSION_FILE_BASIC_INFORMATION:
            return rdp_session_apply_basic_information(job, request->buffer, request->length);
        case RDP_SESSION_FILE_POSITION_INFORMATION:
            return rdp_session_apply_position_information(job, request->buffer, request->length);
        case RDP_SESSION_FILE_MODE_INFORMATION:
            return rdp_session_apply_mode_information(job, request->buffer, request->length);
        case RDP_SESSION_FILE_CASE_SENSITIVE_INFORMATION:
            return rdp_session_apply_case_sensitive_information(request->buffer, request->length);
        case RDP_SESSION_FILE_DISPOSITION_INFORMATION:
            return rdp_session_apply_disposition_information(job, request->buffer, request->length);
        case RDP_SESSION_FILE_DISPOSITION_INFORMATION_EX:
            return rdp_session_apply_disposition_information_ex(job, request->buffer, request->length);
        case RDP_SESSION_FILE_END_OF_FILE_INFORMATION:
        case RDP_SESSION_FILE_ALLOCATION_INFORMATION:
            return rdp_session_apply_size_information(job, request->buffer, request->length);
        case RDP_SESSION_FILE_VALID_DATA_LENGTH_INFORMATION:
            return rdp_session_apply_valid_data_length_information(job, request->buffer, request->length);
        default:
            return RDP_SESSION_DEVICE_NOT_SUPPORTED;
    }
}

/*
 * Handle printer IRPs whose response depends primarily on byte counts. Status,
 * completion length, and optional spooler writes are kept synchronized with
 * the server file ID.
 */
static librdp_status rdp_session_handle_printer_length_irp(librdp_session* session,
                                                           const uint8_t* data,
                                                           size_t data_len,
                                                           uint32_t major_function)
{
    rdp_filesystem_redirection_information_request request;
    rdp_session_redirected_file* job = NULL;
    rdp_buffer payload;
    rdp_buffer response;
    struct stat st;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (major_function)
    {
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION:
            status = rdp_filesystem_redirection_parse_query_information_request(data, data_len, &request);
            break;
        case RDP_DEVICE_REDIRECTION_IRP_SET_INFORMATION:
            status = rdp_filesystem_redirection_parse_set_information_request(data, data_len, &request);
            break;
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_VOLUME_INFORMATION:
            status = rdp_filesystem_redirection_parse_query_volume_request(data, data_len, &request);
            break;
        case RDP_DEVICE_REDIRECTION_IRP_SET_VOLUME_INFORMATION:
            status = rdp_filesystem_redirection_parse_set_volume_request(data, data_len, &request);
            break;
        default:
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&payload);
    memset(&st, 0, sizeof(st));
    if (rdp_session_printer_index_from_device_id(session, request.io.device_id) == UINT32_MAX)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    else if (request.io.file_id == 0)
        io_status = RDP_SESSION_DEVICE_UNSUCCESSFUL;
    else if (!(job = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id)))
        io_status = RDP_SESSION_DEVICE_UNSUCCESSFUL;
    else if (job->fd < 0)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    else if (major_function == RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION)
    {
        if (fstat(job->fd, &st) != 0)
        {
            io_status = rdp_session_errno_to_device_status(errno);
        }
        else
        {
            status = rdp_session_write_file_information(&payload, request.information_class, &st, job);
            if (status == LIBRDP_STATUS_UNSUPPORTED)
            {
                io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
            }
            else if (status != LIBRDP_STATUS_OK)
            {
                io_status = rdp_session_filesystem_error_from_status(status);
            }
            else if (payload.length > request.length && request.length > 0)
            {
                io_status = RDP_SESSION_DEVICE_BUFFER_TOO_SMALL;
            }
        }
    }
    else if (major_function == RDP_DEVICE_REDIRECTION_IRP_SET_INFORMATION)
    {
        io_status = rdp_session_apply_printer_set_information(job, &request);
    }
    else
    {
        io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
    }
    rdp_buffer_init(&response);
    if (major_function == RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION)
    {
        status = rdp_printer_redirection_write_buffer_response(&response,
                                                               request.io.device_id,
                                                               request.io.completion_id,
                                                               io_status,
                                                               io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                   payload.data :
                                                                   NULL,
                                                               io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                   (uint32_t)payload.length :
                                                                   0);
    }
    else
    {
        status = rdp_printer_redirection_write_length_response(&response,
                                                               request.io.device_id,
                                                               request.io.completion_id,
                                                               io_status,
                                                               0);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_printer_response(session,
                                                   &response,
                                                   "client.rdpdr.printer.length.response");
    rdp_buffer_free(&response);
    rdp_buffer_free(&payload);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.printer.length",
                        "device_id=%u file_id=%u completion_id=%u major=%u class=%u status=%u payload_len=%zu",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        major_function,
                        request.information_class,
                        io_status,
                        payload.length);
    return status;
}

static librdp_status rdp_session_handle_printer_lock(librdp_session* session,
                                                     const uint8_t* data,
                                                     size_t data_len)
{
    rdp_filesystem_redirection_lock_request request;
    rdp_session_redirected_file* job = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_lock_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_session_printer_index_from_device_id(session, request.io.device_id) == UINT32_MAX)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    else
    {
        job = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
        if (!job)
            io_status = RDP_SESSION_DEVICE_UNSUCCESSFUL;
        else
            io_status = rdp_session_apply_file_locks(session, job, &request);
    }
    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_lock_response(&response,
                                                            request.io.device_id,
                                                            request.io.completion_id,
                                                            io_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_printer_response(session,
                                                   &response,
                                                   "client.rdpdr.printer.lock.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.printer.lock",
                        "device_id=%u file_id=%u completion_id=%u operation=%u locks=%u status=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        request.operation,
                        request.lock_count,
                        io_status);
    return status;
}

static librdp_status rdp_session_handle_printer_device_control(librdp_session* session,
                                                               const uint8_t* data,
                                                               size_t data_len)
{
    rdp_filesystem_redirection_control_request request;
    rdp_buffer response;
    uint32_t io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_control_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_session_printer_index_from_device_id(session, request.io.device_id) == UINT32_MAX)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    else if (request.output_buffer_length > RDP_SESSION_MAX_FILE_IO_BYTES ||
             request.input_buffer_length > RDP_SESSION_MAX_FILE_IO_BYTES)
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    else if (request.io.file_id != 0 &&
             !rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id))
        io_status = RDP_SESSION_DEVICE_UNSUCCESSFUL;
    rdp_buffer_init(&response);
    status = rdp_printer_redirection_write_device_control_response(&response,
                                                                   request.io.device_id,
                                                                   request.io.completion_id,
                                                                   io_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_printer_response(session,
                                                   &response,
                                                   "client.rdpdr.printer.device_control.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.printer.device_control",
                        "device_id=%u file_id=%u completion_id=%u ioctl=%u status=%u input_len=%u output_limit=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        request.io_control_code,
                        io_status,
                        request.input_buffer_length,
                        request.output_buffer_length);
    return status;
}

static librdp_status rdp_session_handle_printer_not_supported(librdp_session* session,
                                                            const rdp_device_redirection_io_request* request)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_device_redirection_write_io_completion(&response,
                                                        request->device_id,
                                                        request->completion_id,
                                                        RDP_SESSION_DEVICE_NOT_SUPPORTED,
                                                        NULL,
                                                        0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_printer_response(session,
                                                   &response,
                                                   "client.rdpdr.printer.not_supported.response");
    rdp_buffer_free(&response);
    return status;
}

librdp_status rdp_session_handle_printer_io_request(librdp_session* session,
                                                           const uint8_t* data,
                                                           size_t data_len)
{
    rdp_device_redirection_io_request request;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_parse_io_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    switch (request.major_function)
    {
        case RDP_DEVICE_REDIRECTION_IRP_CREATE:
            return rdp_session_handle_printer_create(session, &request);
        case RDP_DEVICE_REDIRECTION_IRP_CLOSE:
            return rdp_session_handle_printer_close(session, &request);
        case RDP_DEVICE_REDIRECTION_IRP_CLEANUP:
        case RDP_DEVICE_REDIRECTION_IRP_FLUSH_BUFFERS:
        case RDP_DEVICE_REDIRECTION_IRP_SHUTDOWN:
            return rdp_session_handle_printer_simple(session, &request);
        case RDP_DEVICE_REDIRECTION_IRP_WRITE:
            return rdp_session_handle_printer_write(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_READ:
            return rdp_session_handle_printer_read(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION:
        case RDP_DEVICE_REDIRECTION_IRP_SET_INFORMATION:
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_VOLUME_INFORMATION:
        case RDP_DEVICE_REDIRECTION_IRP_SET_VOLUME_INFORMATION:
            return rdp_session_handle_printer_length_irp(session, data, data_len, request.major_function);
        case RDP_DEVICE_REDIRECTION_IRP_LOCK_CONTROL:
            return rdp_session_handle_printer_lock(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL:
            return rdp_session_handle_printer_device_control(session, data, data_len);
        default:
            return rdp_session_handle_printer_not_supported(session, &request);
    }
}
