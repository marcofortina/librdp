/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: CUPS/file printer backend adapter.
 * Invariants: CUPS destinations and document format options are resolved only
 * inside this module, keeping native printer APIs out of the session protocol
 * dispatcher.
 * Ownership: queued jobs own copied metadata and optional spool-file cleanup;
 * native option lists are released on every provider return path.
 * Threading: joinable workers execute blocking providers while the owner thread
 * consumes completions and drains all jobs during disconnect.
 * Trust boundary: spool files may contain sensitive document data and are never
 * emitted through trace payloads.
 */

#include "client/printer_backend.h"

#include "channels/device_redirection.h"
#include "channels/printer_redirection.h"
#include "common/trace.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef RDP_HAVE_CUPS
#include <cups/cups.h>
#endif

#define RDP_PRINTER_BACKEND_DEVICE_NO_SUCH_DEVICE 0xc000000eu
#define RDP_PRINTER_BACKEND_DEVICE_NOT_SUPPORTED 0xc00000bbu
#define RDP_PRINTER_BACKEND_DEVICE_INVALID_PARAMETER 0xc000000du
#define RDP_PRINTER_BACKEND_DEVICE_UNSUCCESSFUL 0xc0000001u
#define RDP_PRINTER_BACKEND_DEVICE_NO_MEMORY 0xc0000017u
#define RDP_PRINTER_BACKEND_DEVICE_CANCELLED 0xc0000120u
#define RDP_PRINTER_BACKEND_FORMAT_PROBE 512u
#define RDP_PRINTER_BACKEND_MAX_JOBS 16u
#define RDP_PRINTER_BACKEND_CUPS_TIMEOUT_MS 5000u
#define RDP_PRINTER_BACKEND_MOCK_SLICE_MS 5u

typedef uint32_t (*rdp_printer_backend_submit_fn)(void* user_data,
                                                  uint32_t printer_index,
                                                  const char* output,
                                                  const char* title,
                                                  const char* path,
                                                  const atomic_uint* cancel_requested,
                                                  uint32_t timeout_ms);

typedef struct rdp_printer_backend_ops
{
    rdp_printer_backend_submit_fn submit;
} rdp_printer_backend_ops;

typedef struct rdp_printer_backend_cups_job
{
    rdp_printer_backend_runtime* runtime;
    struct rdp_printer_backend_cups_job* next;
    pthread_t thread;
    uint32_t printer_index;
    char* output;
    char* title;
    char* path;
    uint32_t status;
    int unlink_spool;
    int done;
    atomic_uint cancel_requested;
} rdp_printer_backend_cups_job;

struct rdp_printer_backend_runtime
{
    pthread_mutex_t mutex;
    rdp_printer_backend_cups_job* jobs;
    const rdp_printer_backend_ops* ops;
    void* user_data;
    rdp_printer_backend_notify_fn notify;
    void* notify_data;
    size_t job_count;
    uint32_t timeout_ms;
    int accepting;
};

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

static void rdp_printer_backend_sleep_ms(uint32_t timeout_ms)
{
    struct timespec requested;
    struct timespec remaining;

    requested.tv_sec = (time_t)(timeout_ms / 1000u);
    requested.tv_nsec = (long)((timeout_ms % 1000u) * 1000000u);
    while (nanosleep(&requested, &remaining) != 0 && errno == EINTR)
        requested = remaining;
}

#ifdef RDP_HAVE_CUPS
typedef struct rdp_printer_backend_cups_context
{
    const char* requested_destination;
    const atomic_uint* cancel_requested;
    cups_dest_t* destination;
    struct timespec deadline;
} rdp_printer_backend_cups_context;

static const char* rdp_printer_backend_cups_destination(const char* output)
{
    if (!output)
        return NULL;
    if (strncmp(output, "cups:", 5u) == 0 && output[5] != '\0')
        return output + 5u;
    return NULL;
}

static int rdp_printer_backend_cups_cancelled(const rdp_printer_backend_cups_context* context)
{
    struct timespec now;

    if (!context)
        return 1;
    if (context->cancel_requested &&
        atomic_load_explicit(context->cancel_requested, memory_order_acquire) != 0u)
        return 1;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 1;
    return now.tv_sec > context->deadline.tv_sec ||
           (now.tv_sec == context->deadline.tv_sec &&
            now.tv_nsec >= context->deadline.tv_nsec);
}

static int rdp_printer_backend_cups_remaining_ms(const rdp_printer_backend_cups_context* context)
{
    struct timespec now;
    int64_t remaining_ns = 0;

    if (!context || clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    remaining_ns = ((int64_t)context->deadline.tv_sec - (int64_t)now.tv_sec) *
                       1000000000LL +
                   ((int64_t)context->deadline.tv_nsec - (int64_t)now.tv_nsec);
    if (remaining_ns <= 0)
        return 0;
    if (remaining_ns / 1000000LL > INT_MAX)
        return INT_MAX;
    return (int)((remaining_ns + 999999LL) / 1000000LL);
}

static int rdp_printer_backend_cups_copy_destination(
    rdp_printer_backend_cups_context* context,
    const cups_dest_t* source)
{
    cups_dest_t* destination = NULL;

    if (!context || !source || !source->name)
        return 0;
    destination = (cups_dest_t*)calloc(1, sizeof(*destination));
    if (!destination)
        return 0;
    destination->name = rdp_printer_backend_strdup(source->name);
    destination->instance = rdp_printer_backend_strdup(source->instance);
    destination->is_default = source->is_default;
    if (!destination->name || (source->instance && !destination->instance))
    {
        cupsFreeDests(1, destination);
        return 0;
    }
    for (int i = 0; destination->name && i < source->num_options; i++)
    {
        int next_count = cupsAddOption(source->options[i].name,
                                       source->options[i].value,
                                       destination->num_options,
                                       &destination->options);

        if (next_count <= destination->num_options)
        {
            cupsFreeDests(1, destination);
            return 0;
        }
        destination->num_options = next_count;
    }
    context->destination = destination;
    return 1;
}

static int rdp_printer_backend_cups_destination_callback(void* user_data,
                                                         unsigned flags,
                                                         cups_dest_t* destination)
{
    rdp_printer_backend_cups_context* context =
        (rdp_printer_backend_cups_context*)user_data;
    int selected = 0;

    if (!context || rdp_printer_backend_cups_cancelled(context))
        return 0;
    if (!destination || (flags & (CUPS_DEST_FLAGS_REMOVED | CUPS_DEST_FLAGS_ERROR)) != 0u)
        return 1;
    selected = context->requested_destination ?
                   strcmp(destination->name, context->requested_destination) == 0 :
                   destination->is_default;
    if (!selected)
        return 1;
    (void)rdp_printer_backend_cups_copy_destination(context, destination);
    return 0;
}

static int rdp_printer_backend_cups_http_timeout(http_t* http, void* user_data)
{
    (void)http;
    return !rdp_printer_backend_cups_cancelled(
        (const rdp_printer_backend_cups_context*)user_data);
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
    if (!rdp_printer_backend_output_is_cups(output))
        return RDP_PRINTER_BACKEND_DEVICE_INVALID_PARAMETER;
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

/*
 * Submit one spool file through the cancellable CUPS destination API. Discovery,
 * connection, job creation, and streaming share one monotonic deadline; every
 * partially created native resource is released or cancelled on failure.
 */
static uint32_t rdp_printer_backend_cups_submit_provider(
    void* user_data,
    uint32_t printer_index,
    const char* output,
    const char* title,
    const char* path,
    const atomic_uint* cancel_requested,
    uint32_t timeout_ms)
{
    rdp_printer_backend_cups_context context;
    char resource[1024];
    uint8_t chunk[16384];
    const char* format = NULL;
    http_t* http = NULL;
    cups_dinfo_t* destination_info = NULL;
    cups_option_t* options = NULL;
    FILE* fp = NULL;
    ipp_status_t ipp_status = IPP_STATUS_ERROR_INTERNAL;
    http_status_t http_status = HTTP_STATUS_ERROR;
    size_t read_len = 0;
    int option_count = 0;
    int cups_job_id = 0;
    int remaining_ms = 0;
    int document_started = 0;
    uint32_t status = RDP_PRINTER_BACKEND_DEVICE_UNSUCCESSFUL;

    (void)user_data;
    if (!rdp_printer_backend_output_is_cups(output) || !path)
        return RDP_PRINTER_BACKEND_DEVICE_INVALID_PARAMETER;
    memset(&context, 0, sizeof(context));
    memset(resource, 0, sizeof(resource));
    context.requested_destination = rdp_printer_backend_cups_destination(output);
    context.cancel_requested = cancel_requested;
    if (clock_gettime(CLOCK_MONOTONIC, &context.deadline) != 0)
        return RDP_PRINTER_BACKEND_DEVICE_UNSUCCESSFUL;
    context.deadline.tv_sec +=
        (time_t)((timeout_ms ? timeout_ms : RDP_PRINTER_BACKEND_CUPS_TIMEOUT_MS) / 1000u);
    context.deadline.tv_nsec +=
        (long)(((timeout_ms ? timeout_ms : RDP_PRINTER_BACKEND_CUPS_TIMEOUT_MS) % 1000u) *
               1000000u);
    if (context.deadline.tv_nsec >= 1000000000L)
    {
        context.deadline.tv_sec++;
        context.deadline.tv_nsec -= 1000000000L;
    }
    remaining_ms = rdp_printer_backend_cups_remaining_ms(&context);
    if (remaining_ms > 0)
        (void)cupsEnumDests(CUPS_DEST_FLAGS_NONE,
                            remaining_ms,
                            NULL,
                            0,
                            0,
                            rdp_printer_backend_cups_destination_callback,
                            &context);
    if (remaining_ms <= 0 || !context.destination)
    {
        status = rdp_printer_backend_cups_cancelled(&context) ?
                     RDP_PRINTER_BACKEND_DEVICE_CANCELLED :
                     RDP_PRINTER_BACKEND_DEVICE_NO_SUCH_DEVICE;
        goto cleanup;
    }
    remaining_ms = rdp_printer_backend_cups_remaining_ms(&context);
    if (remaining_ms <= 0)
    {
        status = RDP_PRINTER_BACKEND_DEVICE_CANCELLED;
        goto cleanup;
    }
    http = cupsConnectDest(context.destination,
                           CUPS_DEST_FLAGS_NONE,
                           remaining_ms,
                           NULL,
                           resource,
                           sizeof(resource),
                           NULL,
                           NULL);
    if (!http)
        goto cleanup;
    httpSetTimeout(http, 1.0, rdp_printer_backend_cups_http_timeout, &context);
    destination_info = cupsCopyDestInfo(http, context.destination);
    if (!destination_info || rdp_printer_backend_cups_cancelled(&context))
        goto cleanup;
    format = rdp_printer_backend_document_format(path);
    option_count = cupsAddOption("document-format", format, option_count, &options);
    if (option_count <= 0)
        goto cleanup;
    ipp_status = cupsCreateDestJob(http,
                                   context.destination,
                                   destination_info,
                                   &cups_job_id,
                                   title ? title : "RDP print job",
                                   option_count,
                                   options);
    if (ipp_status > IPP_STATUS_OK_EVENTS_COMPLETE || cups_job_id <= 0)
        goto cleanup;
    http_status = cupsStartDestDocument(http,
                                        context.destination,
                                        destination_info,
                                        cups_job_id,
                                        title ? title : "RDP print job",
                                        format,
                                        0,
                                        NULL,
                                        1);
    if (http_status != HTTP_STATUS_CONTINUE)
        goto cleanup;
    document_started = 1;
    fp = fopen(path, "rb");
    if (!fp)
        goto cleanup;
    while (!rdp_printer_backend_cups_cancelled(&context) &&
           (read_len = fread(chunk, 1u, sizeof(chunk), fp)) > 0)
    {
        if (cupsWriteRequestData(http, (const char*)chunk, read_len) !=
            HTTP_STATUS_CONTINUE)
            goto cleanup;
    }
    if (ferror(fp) || rdp_printer_backend_cups_cancelled(&context))
        goto cleanup;
    ipp_status = cupsFinishDestDocument(http, context.destination, destination_info);
    document_started = 0;
    if (ipp_status > IPP_STATUS_OK_EVENTS_COMPLETE)
        goto cleanup;
    status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.printer.cups.submit",
                    "printer_index=%u destination=%s job_id=%d format=%s",
                    printer_index,
                    context.destination->name,
                    cups_job_id,
                    format);
cleanup:
    if (document_started && http && context.destination && destination_info &&
        cups_job_id > 0)
        (void)cupsCancelDestJob(http, context.destination, cups_job_id);
    if (fp)
        fclose(fp);
    cupsFreeOptions(option_count, options);
    if (destination_info)
        cupsFreeDestInfo(destination_info);
    if (http)
        httpClose(http);
    if (context.destination)
        cupsFreeDests(1, context.destination);
    return status;
}
#else
uint32_t rdp_printer_backend_validate_cups(const char* output)
{
    (void)output;
    return RDP_PRINTER_BACKEND_DEVICE_NOT_SUPPORTED;
}

static uint32_t rdp_printer_backend_cups_submit_provider(
    void* user_data,
    uint32_t printer_index,
    const char* output,
    const char* title,
    const char* path,
    const atomic_uint* cancel_requested,
    uint32_t timeout_ms)
{
    (void)user_data;
    (void)printer_index;
    (void)output;
    (void)title;
    (void)path;
    (void)cancel_requested;
    (void)timeout_ms;
    return RDP_PRINTER_BACKEND_DEVICE_NOT_SUPPORTED;
}
#endif

static uint32_t rdp_printer_backend_mock_submit_provider(
    void* user_data,
    uint32_t printer_index,
    const char* output,
    const char* title,
    const char* path,
    const atomic_uint* cancel_requested,
    uint32_t timeout_ms)
{
    rdp_printer_backend_mock* mock = (rdp_printer_backend_mock*)user_data;
    uint32_t waited_ms = 0;
    uint32_t status = RDP_PRINTER_BACKEND_DEVICE_INVALID_PARAMETER;

    (void)printer_index;
    (void)output;
    (void)title;
    (void)path;
    if (!mock)
        return status;
    atomic_fetch_add_explicit(&mock->submit_calls, 1u, memory_order_relaxed);
    atomic_fetch_add_explicit(&mock->active_calls, 1u, memory_order_acq_rel);
    status = mock->submit_status;
    while (waited_ms < mock->submit_delay_ms && waited_ms < timeout_ms)
    {
        if (cancel_requested &&
            atomic_load_explicit(cancel_requested, memory_order_acquire) != 0u)
        {
            atomic_store_explicit(&mock->cancellation_observed, 1u, memory_order_release);
            status = RDP_PRINTER_BACKEND_DEVICE_CANCELLED;
            break;
        }
        rdp_printer_backend_sleep_ms(RDP_PRINTER_BACKEND_MOCK_SLICE_MS);
        waited_ms += RDP_PRINTER_BACKEND_MOCK_SLICE_MS;
    }
    if (waited_ms >= timeout_ms && waited_ms < mock->submit_delay_ms)
        status = RDP_PRINTER_BACKEND_DEVICE_UNSUCCESSFUL;
    atomic_fetch_sub_explicit(&mock->active_calls, 1u, memory_order_acq_rel);
    return status;
}

static const rdp_printer_backend_ops rdp_printer_backend_cups_ops = {
    rdp_printer_backend_cups_submit_provider
};

static const rdp_printer_backend_ops rdp_printer_backend_mock_ops = {
    rdp_printer_backend_mock_submit_provider
};

/*
 * Finish one provider submission. Spool cleanup is unconditional after
 * ownership transfer, including provider failure and cancellation.
 */
static void* rdp_printer_backend_worker(void* opaque)
{
    rdp_printer_backend_cups_job* job = (rdp_printer_backend_cups_job*)opaque;
    rdp_printer_backend_runtime* runtime = job ? job->runtime : NULL;
    rdp_printer_backend_notify_fn notify = NULL;
    void* notify_data = NULL;

    if (!job || !runtime)
        return NULL;
    job->status = runtime->ops->submit(runtime->user_data,
                                       job->printer_index,
                                       job->output,
                                       job->title,
                                       job->path,
                                       &job->cancel_requested,
                                       runtime->timeout_ms);
    if (job->unlink_spool && job->path)
        (void)unlink(job->path);
    pthread_mutex_lock(&runtime->mutex);
    job->done = 1;
    notify = runtime->notify;
    notify_data = runtime->notify_data;
    pthread_mutex_unlock(&runtime->mutex);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.printer.backend.done",
                    "printer_index=%u status=%u cancelled=%u cleanup=%u",
                    job->printer_index,
                    job->status,
                    atomic_load_explicit(&job->cancel_requested, memory_order_acquire),
                    job->unlink_spool ? 1u : 0u);
    if (notify)
        notify(notify_data);
    return NULL;
}

static void rdp_printer_backend_initialize(rdp_printer_backend* backend,
                                           const rdp_printer_backend_ops* ops,
                                           void* user_data)
{
    rdp_printer_backend_runtime* runtime = NULL;

    if (!backend)
        return;
    memset(backend, 0, sizeof(*backend));
    runtime = (rdp_printer_backend_runtime*)calloc(1, sizeof(*runtime));
    if (!runtime)
        return;
    if (pthread_mutex_init(&runtime->mutex, NULL) != 0)
    {
        free(runtime);
        return;
    }
    runtime->ops = ops;
    runtime->user_data = user_data;
    runtime->timeout_ms = RDP_PRINTER_BACKEND_CUPS_TIMEOUT_MS;
    runtime->accepting = 1;
    backend->runtime = runtime;
}

void rdp_printer_backend_init_cups(rdp_printer_backend* backend)
{
    rdp_printer_backend_initialize(backend, &rdp_printer_backend_cups_ops, NULL);
}

void rdp_printer_backend_mock_init(rdp_printer_backend_mock* mock)
{
    if (!mock)
        return;
    memset(mock, 0, sizeof(*mock));
    mock->submit_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    atomic_init(&mock->submit_calls, 0u);
    atomic_init(&mock->active_calls, 0u);
    atomic_init(&mock->cancellation_observed, 0u);
}

void rdp_printer_backend_init_mock(rdp_printer_backend* backend,
                                   rdp_printer_backend_mock* mock)
{
    rdp_printer_backend_initialize(backend, &rdp_printer_backend_mock_ops, mock);
}

void rdp_printer_backend_set_notify(rdp_printer_backend* backend,
                                    rdp_printer_backend_notify_fn notify,
                                    void* user_data)
{
    if (!backend || !backend->runtime)
        return;
    pthread_mutex_lock(&backend->runtime->mutex);
    backend->runtime->notify = notify;
    backend->runtime->notify_data = user_data;
    pthread_mutex_unlock(&backend->runtime->mutex);
}

/*
 * Queue a print job after the local spool file has been closed. Success
 * transfers optional spool cleanup to the managed job.
 */
uint32_t rdp_printer_backend_submit_async(rdp_printer_backend* backend,
                                          uint32_t printer_index,
                                          const char* output,
                                          const char* title,
                                          const char* path,
                                          int unlink_spool)
{
    rdp_printer_backend_cups_job* job = NULL;
    rdp_printer_backend_runtime* runtime = backend ? backend->runtime : NULL;
    uint32_t status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;

    if (!runtime || !runtime->ops || !runtime->ops->submit)
        return RDP_PRINTER_BACKEND_DEVICE_NOT_SUPPORTED;
    if (!rdp_printer_backend_output_is_cups(output) || !path)
        return RDP_PRINTER_BACKEND_DEVICE_INVALID_PARAMETER;
    job = (rdp_printer_backend_cups_job*)calloc(1, sizeof(*job));
    if (!job)
        return RDP_PRINTER_BACKEND_DEVICE_NO_MEMORY;
    job->runtime = runtime;
    job->printer_index = printer_index;
    job->unlink_spool = unlink_spool ? 1 : 0;
    job->output = rdp_printer_backend_strdup(output);
    job->title = rdp_printer_backend_strdup(title ? title : "RDP print job");
    job->path = rdp_printer_backend_strdup(path);
    atomic_init(&job->cancel_requested, 0u);
    if (!job->output || !job->title || !job->path)
    {
        rdp_printer_backend_cups_job_free(job);
        return RDP_PRINTER_BACKEND_DEVICE_NO_MEMORY;
    }
    pthread_mutex_lock(&runtime->mutex);
    if (!runtime->accepting)
        status = RDP_PRINTER_BACKEND_DEVICE_CANCELLED;
    else if (runtime->job_count >= RDP_PRINTER_BACKEND_MAX_JOBS)
        status = RDP_PRINTER_BACKEND_DEVICE_NO_MEMORY;
    else
    {
        job->next = runtime->jobs;
        runtime->jobs = job;
        runtime->job_count++;
    }
    pthread_mutex_unlock(&runtime->mutex);
    if (status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
    {
        rdp_printer_backend_cups_job_free(job);
        return status;
    }
    if (pthread_create(&job->thread, NULL, rdp_printer_backend_worker, job) != 0)
    {
        pthread_mutex_lock(&runtime->mutex);
        if (runtime->jobs == job)
            runtime->jobs = job->next;
        else
        {
            rdp_printer_backend_cups_job* previous = runtime->jobs;

            while (previous && previous->next != job)
                previous = previous->next;
            if (previous)
                previous->next = job->next;
        }
        runtime->job_count--;
        pthread_mutex_unlock(&runtime->mutex);
        rdp_printer_backend_cups_job_free(job);
        return RDP_PRINTER_BACKEND_DEVICE_UNSUCCESSFUL;
    }
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.printer.backend.queued",
                    "printer_index=%u cleanup=%u",
                    printer_index,
                    unlink_spool ? 1u : 0u);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

int rdp_printer_backend_take_completion(rdp_printer_backend* backend,
                                        rdp_printer_backend_completion* completion)
{
    rdp_printer_backend_runtime* runtime = backend ? backend->runtime : NULL;
    rdp_printer_backend_cups_job** current = NULL;
    rdp_printer_backend_cups_job* job = NULL;

    if (!runtime || !completion)
        return 0;
    pthread_mutex_lock(&runtime->mutex);
    current = &runtime->jobs;
    while (*current && !(*current)->done)
        current = &(*current)->next;
    if (*current)
    {
        job = *current;
        *current = job->next;
        job->next = NULL;
        runtime->job_count--;
    }
    pthread_mutex_unlock(&runtime->mutex);
    if (!job)
        return 0;
    pthread_join(job->thread, NULL);
    completion->printer_index = job->printer_index;
    completion->status = job->status;
    completion->cancelled =
        atomic_load_explicit(&job->cancel_requested, memory_order_acquire) != 0u;
    rdp_printer_backend_cups_job_free(job);
    return 1;
}

void rdp_printer_backend_drain(rdp_printer_backend* backend)
{
    rdp_printer_backend_runtime* runtime = backend ? backend->runtime : NULL;
    rdp_printer_backend_cups_job* jobs = NULL;

    if (!runtime)
        return;
    pthread_mutex_lock(&runtime->mutex);
    jobs = runtime->jobs;
    runtime->jobs = NULL;
    runtime->job_count = 0;
    for (rdp_printer_backend_cups_job* job = jobs; job; job = job->next)
        atomic_store_explicit(&job->cancel_requested, 1u, memory_order_release);
    pthread_mutex_unlock(&runtime->mutex);
    while (jobs)
    {
        rdp_printer_backend_cups_job* next = jobs->next;

        jobs->next = NULL;
        pthread_join(jobs->thread, NULL);
        rdp_printer_backend_cups_job_free(jobs);
        jobs = next;
    }
}

void rdp_printer_backend_clear(rdp_printer_backend* backend)
{
    rdp_printer_backend_runtime* runtime = backend ? backend->runtime : NULL;

    if (!backend || !runtime)
        return;
    pthread_mutex_lock(&runtime->mutex);
    runtime->accepting = 0;
    runtime->notify = NULL;
    runtime->notify_data = NULL;
    pthread_mutex_unlock(&runtime->mutex);
    rdp_printer_backend_drain(backend);
    pthread_mutex_destroy(&runtime->mutex);
    free(runtime);
    memset(backend, 0, sizeof(*backend));
}
