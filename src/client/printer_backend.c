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

#include <stdio.h>
#include <string.h>

#ifdef RDP_HAVE_CUPS
#include <cups/cups.h>
#endif

#define RDP_PRINTER_BACKEND_DEVICE_NO_SUCH_DEVICE 0xc000000eu
#define RDP_PRINTER_BACKEND_DEVICE_NOT_SUPPORTED 0xc00000bbu
#define RDP_PRINTER_BACKEND_DEVICE_INVALID_PARAMETER 0xc000000du
#define RDP_PRINTER_BACKEND_DEVICE_UNSUCCESSFUL 0xc0000001u
#define RDP_PRINTER_BACKEND_FORMAT_PROBE 512u

int rdp_printer_backend_output_is_cups(const char* output)
{
    return output && (strcmp(output, "cups") == 0 ||
                      (strncmp(output, "cups:", 5u) == 0 && output[5] != '\0'));
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
