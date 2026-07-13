/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: CUPS/file printer backend adapter.
 * Invariants: CUPS destinations and document format options are resolved only
 * inside this module, keeping native printer APIs out of the session protocol
 * dispatcher.
 * Ownership: input strings are borrowed; native option lists are released on
 * every return path.
 * Threading: synchronous CUPS calls may block and are isolated here so they can
 * move behind a worker without changing printer protocol code.
 * Trust boundary: spool files may contain sensitive document data and are never
 * emitted through trace payloads.
 */

#include "client/printer_backend.h"

#include "channels/device_redirection.h"
#include "channels/printer_redirection.h"
#include "common/trace.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef RDP_HAVE_CUPS
#include <cups/cups.h>
#endif

#define RDP_PRINTER_BACKEND_DEVICE_NO_SUCH_DEVICE 0xc000000eu
#define RDP_PRINTER_BACKEND_DEVICE_NOT_SUPPORTED 0xc00000bbu
#define RDP_PRINTER_BACKEND_DEVICE_INVALID_PARAMETER 0xc000000du
#define RDP_PRINTER_BACKEND_DEVICE_UNSUCCESSFUL 0xc0000001u
#define RDP_PRINTER_BACKEND_DEVICE_NO_MEMORY 0xc0000017u
#define RDP_PRINTER_BACKEND_FORMAT_PROBE 512u

typedef struct rdp_printer_backend_cups_job
{
    uint32_t printer_index;
    char* output;
    char* title;
    char* path;
    int unlink_spool;
} rdp_printer_backend_cups_job;

int rdp_printer_backend_output_is_cups(const char* output)
{
    return output && (strcmp(output, "cups") == 0 ||
                      (strncmp(output, "cups:", 5u) == 0 && output[5] != '\0'));
}

static char* rdp_printer_backend_strdup(const char* value)
{
    size_t length = 0;
    char* copy = NULL;

    if (!value)
        return NULL;
    length = strlen(value);
    copy = (char*)malloc(length + 1u);
    if (!copy)
        return NULL;
    memcpy(copy, value, length + 1u);
    return copy;
}

static void rdp_printer_backend_cups_job_free(rdp_printer_backend_cups_job* job)
{
    if (!job)
        return;
    free(job->output);
    free(job->title);
    free(job->path);
    free(job);
}

#ifdef RDP_HAVE_CUPS
static const char* rdp_printer_backend_cups_destination(const char* output)
{
    if (!output)
        return NULL;
    if (strncmp(output, "cups:", 5u) == 0 && output[5] != '\0')
        return output + 5u;
    return NULL;
}

static const char* rdp_printer_backend_document_format(const char* path)
{
    uint8_t prefix[RDP_PRINTER_BACKEND_FORMAT_PROBE];
    const char* format = RDP_PRINTER_REDIRECTION_FORMAT_RAW;
    FILE* fp = NULL;
    size_t read_len = 0;

    if (!path)
        return format;
    fp = fopen(path, "rb");
    if (!fp)
        return format;
    read_len = fread(prefix, 1u, sizeof(prefix), fp);
    fclose(fp);
    if (rdp_printer_redirection_detect_document_format(prefix, read_len, &format) != LIBRDP_STATUS_OK)
        format = RDP_PRINTER_REDIRECTION_FORMAT_RAW;
    return format;
}

uint32_t rdp_printer_backend_validate_cups(const char* output)
{
    const char* destination = rdp_printer_backend_cups_destination(output);
    const char* default_destination = NULL;
    cups_dest_t* dest = NULL;

    if (!rdp_printer_backend_output_is_cups(output))
        return RDP_PRINTER_BACKEND_DEVICE_INVALID_PARAMETER;
    if (!destination)
    {
        default_destination = cupsGetDefault();
        if (!default_destination || default_destination[0] == '\0')
            return RDP_PRINTER_BACKEND_DEVICE_NO_SUCH_DEVICE;
        destination = default_destination;
    }
    dest = cupsGetNamedDest(CUPS_HTTP_DEFAULT, destination, NULL);
    if (!dest)
        return RDP_PRINTER_BACKEND_DEVICE_NO_SUCH_DEVICE;
    cupsFreeDests(1, dest);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

uint32_t rdp_printer_backend_submit_cups(uint32_t printer_index,
                                         const char* output,
                                         const char* title,
                                         const char* path)
{
    const char* destination = rdp_printer_backend_cups_destination(output);
    const char* format = NULL;
    cups_option_t* options = NULL;
    int option_count = 0;
    int cups_job_id = 0;

    if (!rdp_printer_backend_output_is_cups(output) || !path)
        return RDP_PRINTER_BACKEND_DEVICE_INVALID_PARAMETER;
    if (!destination)
        destination = cupsGetDefault();
    if (!destination || destination[0] == '\0')
        return RDP_PRINTER_BACKEND_DEVICE_NO_SUCH_DEVICE;
    format = rdp_printer_backend_document_format(path);
    option_count = cupsAddOption("document-format", format, option_count, &options);
    cups_job_id = cupsPrintFile(destination,
                                path,
                                title ? title : "RDP print job",
                                option_count,
                                options);
    cupsFreeOptions(option_count, options);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.printer.cups.submit",
                    "printer_index=%u destination=%s job_id=%d format=%s path=%s",
                    printer_index,
                    destination,
                    cups_job_id,
                    format,
                    path);
    return cups_job_id > 0 ? RDP_DEVICE_REDIRECTION_STATUS_SUCCESS :
                             RDP_PRINTER_BACKEND_DEVICE_UNSUCCESSFUL;
}
#else
uint32_t rdp_printer_backend_validate_cups(const char* output)
{
    (void)output;
    return RDP_PRINTER_BACKEND_DEVICE_NOT_SUPPORTED;
}

uint32_t rdp_printer_backend_submit_cups(uint32_t printer_index,
                                         const char* output,
                                         const char* title,
                                         const char* path)
{
    (void)printer_index;
    (void)output;
    (void)title;
    (void)path;
    return RDP_PRINTER_BACKEND_DEVICE_NOT_SUPPORTED;
}
#endif

/*
 * Run native CUPS submission outside the protocol dispatch path. The worker
 * owns copied strings and optional spool cleanup, so session teardown cannot
 * invalidate pointers after the close response has been sent.
 */
static void* rdp_printer_backend_cups_worker(void* opaque)
{
    rdp_printer_backend_cups_job* job = (rdp_printer_backend_cups_job*)opaque;
    uint32_t status = RDP_PRINTER_BACKEND_DEVICE_INVALID_PARAMETER;

    if (job)
    {
        status = rdp_printer_backend_submit_cups(job->printer_index,
                                                job->output,
                                                job->title,
                                                job->path);
        if (job->unlink_spool && job->path && status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            (void)unlink(job->path);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.printer.cups.worker",
                        "printer_index=%u status=%u cleanup=%u",
                        job->printer_index,
                        status,
                        job->unlink_spool ? 1u : 0u);
    }
    rdp_printer_backend_cups_job_free(job);
    return NULL;
}

/*
 * Queue a CUPS print job after the local spool file has been closed. Returning
 * success means the backend accepted ownership of copied metadata; it does not
 * claim that the host print system has already completed the job.
 */
uint32_t rdp_printer_backend_submit_cups_async(uint32_t printer_index,
                                               const char* output,
                                               const char* title,
                                               const char* path,
                                               int unlink_spool)
{
    rdp_printer_backend_cups_job* job = NULL;
    pthread_t thread;
    int rc = 0;

    if (!rdp_printer_backend_output_is_cups(output) || !path)
        return RDP_PRINTER_BACKEND_DEVICE_INVALID_PARAMETER;
    job = (rdp_printer_backend_cups_job*)calloc(1, sizeof(*job));
    if (!job)
        return RDP_PRINTER_BACKEND_DEVICE_NO_MEMORY;
    job->printer_index = printer_index;
    job->unlink_spool = unlink_spool ? 1 : 0;
    job->output = rdp_printer_backend_strdup(output);
    job->title = rdp_printer_backend_strdup(title ? title : "RDP print job");
    job->path = rdp_printer_backend_strdup(path);
    if (!job->output || !job->title || !job->path)
    {
        rdp_printer_backend_cups_job_free(job);
        return RDP_PRINTER_BACKEND_DEVICE_NO_MEMORY;
    }
    rc = pthread_create(&thread, NULL, rdp_printer_backend_cups_worker, job);
    if (rc != 0)
    {
        rdp_printer_backend_cups_job_free(job);
        return RDP_PRINTER_BACKEND_DEVICE_UNSUCCESSFUL;
    }
    (void)pthread_detach(thread);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.printer.cups.queued",
                    "printer_index=%u cleanup=%u",
                    printer_index,
                    unlink_spool ? 1u : 0u);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}
