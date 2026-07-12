/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: smartcard backend adapters and timeout workers.
 * Invariants: blocking connect, status-change, and transmit calls operate on
 * backend-owned copies so timed-out workers cannot access session stack data.
 * Ownership: timeout jobs own duplicated strings and buffers until the worker
 * exits; successful jobs transfer provider handles explicitly to the caller.
 * Threading: one short-lived worker is created per blocking provider call, and
 * cancellation is requested before a timed-out job is detached.
 * Trust boundary: native smartcard providers receive only bounded lengths and
 * sanitized pointers prepared by the session parser.
 */

#include "client/smartcard_backend.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef SCARD_E_UNSUPPORTED_FEATURE
#define SCARD_E_UNSUPPORTED_FEATURE ((LONG)0x8010001FL)
#endif
#ifndef SCARD_E_NO_MEMORY
#define SCARD_E_NO_MEMORY ((LONG)0x80100006L)
#endif
#ifndef SCARD_E_TIMEOUT
#define SCARD_E_TIMEOUT ((LONG)0x8010000AL)
#endif

typedef LONG (*rdp_smartcard_job_fn)(void* arg);
typedef void (*rdp_smartcard_job_cleanup_fn)(void* arg);
typedef void (*rdp_smartcard_job_cancel_fn)(void* arg);

typedef struct rdp_smartcard_job
{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    pthread_t thread;
    rdp_smartcard_job_fn fn;
    rdp_smartcard_job_cleanup_fn cleanup;
    void* arg;
    LONG result;
    int done;
    int detached;
} rdp_smartcard_job;

typedef struct rdp_smartcard_cancel_context
{
    rdp_smartcard_backend* backend;
    SCARDCONTEXT context;
} rdp_smartcard_cancel_context;

typedef struct rdp_smartcard_status_change_args
{
    rdp_smartcard_backend* backend;
    SCARDCONTEXT context;
    DWORD timeout;
    SCARD_READERSTATE* states;
    char** reader_names;
    DWORD count;
} rdp_smartcard_status_change_args;

typedef struct rdp_smartcard_connect_args
{
    rdp_smartcard_backend* backend;
    SCARDCONTEXT context;
    char* reader;
    DWORD share_mode;
    DWORD preferred_protocols;
    SCARDHANDLE handle;
    DWORD active_protocol;
    int transfer_handle;
} rdp_smartcard_connect_args;

typedef struct rdp_smartcard_transmit_args
{
    rdp_smartcard_backend* backend;
    SCARDHANDLE handle;
    SCARD_IO_REQUEST send_pci;
    SCARD_IO_REQUEST recv_pci;
    uint8_t* send_data;
    uint8_t* recv_data;
    DWORD send_len;
    DWORD recv_len;
    int recv_pci_present;
} rdp_smartcard_transmit_args;

static char* rdp_smartcard_strdup(const char* text)
{
    size_t len = 0;
    char* copy = NULL;

    if (!text)
        return NULL;
    len = strlen(text);
    copy = (char*)malloc(len + 1u);
    if (!copy)
        return NULL;
    memcpy(copy, text, len + 1u);
    return copy;
}

static void rdp_smartcard_sleep_ms(uint32_t timeout_ms)
{
    struct timespec remaining;
    struct timespec requested;

    requested.tv_sec = (time_t)(timeout_ms / 1000u);
    requested.tv_nsec = (long)((timeout_ms % 1000u) * 1000000u);
    while (nanosleep(&requested, &remaining) != 0 && errno == EINTR)
        requested = remaining;
}

static void rdp_smartcard_timespec_after_ms(struct timespec* out, uint32_t timeout_ms)
{
    long add_ns = 0;

    clock_gettime(CLOCK_REALTIME, out);
    out->tv_sec += (time_t)(timeout_ms / 1000u);
    add_ns = (long)((timeout_ms % 1000u) * 1000000u);
    out->tv_nsec += add_ns;
    if (out->tv_nsec >= 1000000000L)
    {
        out->tv_sec++;
        out->tv_nsec -= 1000000000L;
    }
}

static void rdp_smartcard_job_destroy(rdp_smartcard_job* job, int cleanup_arg)
{
    if (!job)
        return;
    if (cleanup_arg && job->cleanup)
        job->cleanup(job->arg);
    pthread_cond_destroy(&job->cond);
    pthread_mutex_destroy(&job->mutex);
    free(job);
}

static void* rdp_smartcard_job_main(void* user_data)
{
    rdp_smartcard_job* job = (rdp_smartcard_job*)user_data;
    int detached = 0;
    LONG result = job->fn(job->arg);

    pthread_mutex_lock(&job->mutex);
    job->result = result;
    job->done = 1;
    detached = job->detached;
    pthread_cond_signal(&job->cond);
    pthread_mutex_unlock(&job->mutex);
    if (detached)
        rdp_smartcard_job_destroy(job, 1);
    return NULL;
}

/*
 * Run a provider operation with a bounded wait. Completed jobs leave their
 * argument owned by the caller for result harvesting; timed-out jobs detach and
 * own cleanup after the provider finally returns.
 */
static LONG rdp_smartcard_run_with_timeout(rdp_smartcard_job_fn fn,
                                           void* arg,
                                           rdp_smartcard_job_cleanup_fn cleanup,
                                           rdp_smartcard_job_cancel_fn cancel,
                                           void* cancel_arg,
                                           uint32_t timeout_ms,
                                           int* completed)
{
    rdp_smartcard_job* job = NULL;
    struct timespec deadline;
    LONG result = SCARD_E_TIMEOUT;
    int wait_status = 0;

    if (completed)
        *completed = 0;
    if (!fn)
        return SCARD_E_UNSUPPORTED_FEATURE;
    job = (rdp_smartcard_job*)calloc(1, sizeof(*job));
    if (!job)
        return SCARD_E_NO_MEMORY;
    if (pthread_mutex_init(&job->mutex, NULL) != 0)
    {
        free(job);
        return SCARD_E_NO_MEMORY;
    }
    if (pthread_cond_init(&job->cond, NULL) != 0)
    {
        pthread_mutex_destroy(&job->mutex);
        free(job);
        return SCARD_E_NO_MEMORY;
    }
    job->fn = fn;
    job->arg = arg;
    job->cleanup = cleanup;
    if (pthread_create(&job->thread, NULL, rdp_smartcard_job_main, job) != 0)
    {
        rdp_smartcard_job_destroy(job, 0);
        return SCARD_E_NO_MEMORY;
    }

    rdp_smartcard_timespec_after_ms(&deadline, timeout_ms ? timeout_ms : RDP_SMARTCARD_BACKEND_DEFAULT_TIMEOUT_MS);
    pthread_mutex_lock(&job->mutex);
    while (!job->done)
    {
        wait_status = pthread_cond_timedwait(&job->cond, &job->mutex, &deadline);
        if (wait_status == ETIMEDOUT)
            break;
    }
    if (job->done)
    {
        result = job->result;
        pthread_mutex_unlock(&job->mutex);
        pthread_join(job->thread, NULL);
        rdp_smartcard_job_destroy(job, 0);
        if (completed)
            *completed = 1;
        return result;
    }

    job->detached = 1;
    if (cancel)
        cancel(cancel_arg);
    pthread_mutex_unlock(&job->mutex);
    pthread_detach(job->thread);
    return SCARD_E_TIMEOUT;
}

static LONG rdp_smartcard_call_unsupported(void)
{
    return SCARD_E_UNSUPPORTED_FEATURE;
}

static LONG rdp_smartcard_none_establish_context(void* user_data, DWORD scope, SCARDCONTEXT* context)
{
    (void)user_data;
    (void)scope;
    if (context)
        *context = 0;
    return rdp_smartcard_call_unsupported();
}

static LONG rdp_smartcard_none_release_context(void* user_data, SCARDCONTEXT context)
{
    (void)user_data;
    (void)context;
    return rdp_smartcard_call_unsupported();
}

static LONG rdp_smartcard_none_is_valid_context(void* user_data, SCARDCONTEXT context)
{
    (void)user_data;
    (void)context;
    return rdp_smartcard_call_unsupported();
}

static LONG rdp_smartcard_none_cancel(void* user_data, SCARDCONTEXT context)
{
    (void)user_data;
    (void)context;
    return rdp_smartcard_call_unsupported();
}

static LONG rdp_smartcard_none_list_reader_groups(void* user_data,
                                                  SCARDCONTEXT context,
                                                  char* groups,
                                                  DWORD* groups_len)
{
    (void)user_data;
    (void)context;
    (void)groups;
    if (groups_len)
        *groups_len = 0;
    return rdp_smartcard_call_unsupported();
}

static LONG rdp_smartcard_none_list_readers(void* user_data,
                                            SCARDCONTEXT context,
                                            const char* groups,
                                            char* readers,
                                            DWORD* readers_len)
{
    (void)user_data;
    (void)context;
    (void)groups;
    (void)readers;
    if (readers_len)
        *readers_len = 0;
    return rdp_smartcard_call_unsupported();
}

static LONG rdp_smartcard_none_get_status_change(void* user_data,
                                                 SCARDCONTEXT context,
                                                 DWORD timeout,
                                                 SCARD_READERSTATE* readers,
                                                 DWORD count)
{
    (void)user_data;
    (void)context;
    (void)timeout;
    (void)readers;
    (void)count;
    return rdp_smartcard_call_unsupported();
}

static LONG rdp_smartcard_none_begin_transaction(void* user_data, SCARDHANDLE handle)
{
    (void)user_data;
    (void)handle;
    return rdp_smartcard_call_unsupported();
}

static LONG rdp_smartcard_none_connect(void* user_data,
                                       SCARDCONTEXT context,
                                       const char* reader,
                                       DWORD share_mode,
                                       DWORD preferred_protocols,
                                       SCARDHANDLE* handle,
                                       DWORD* active_protocol)
{
    (void)user_data;
    (void)context;
    (void)reader;
    (void)share_mode;
    (void)preferred_protocols;
    if (handle)
        *handle = 0;
    if (active_protocol)
        *active_protocol = 0;
    return rdp_smartcard_call_unsupported();
}

static LONG rdp_smartcard_none_disconnect(void* user_data, SCARDHANDLE handle, DWORD disposition)
{
    (void)user_data;
    (void)handle;
    (void)disposition;
    return rdp_smartcard_call_unsupported();
}

static LONG rdp_smartcard_none_end_transaction(void* user_data, SCARDHANDLE handle, DWORD disposition)
{
    (void)user_data;
    (void)handle;
    (void)disposition;
    return rdp_smartcard_call_unsupported();
}

static LONG rdp_smartcard_none_reconnect(void* user_data,
                                         SCARDHANDLE handle,
                                         DWORD share_mode,
                                         DWORD preferred_protocols,
                                         DWORD initialization,
                                         DWORD* active_protocol)
{
    (void)user_data;
    (void)handle;
    (void)share_mode;
    (void)preferred_protocols;
    (void)initialization;
    if (active_protocol)
        *active_protocol = 0;
    return rdp_smartcard_call_unsupported();
}

static LONG rdp_smartcard_none_status(void* user_data,
                                      SCARDHANDLE handle,
                                      char* reader_names,
                                      DWORD* reader_names_len,
                                      DWORD* state,
                                      DWORD* protocol,
                                      uint8_t* atr,
                                      DWORD* atr_len)
{
    (void)user_data;
    (void)handle;
    (void)reader_names;
    if (reader_names_len)
        *reader_names_len = 0;
    if (state)
        *state = 0;
    if (protocol)
        *protocol = 0;
    (void)atr;
    if (atr_len)
        *atr_len = 0;
    return rdp_smartcard_call_unsupported();
}

static LONG rdp_smartcard_none_transmit(void* user_data,
                                        SCARDHANDLE handle,
                                        const SCARD_IO_REQUEST* send_pci,
                                        const uint8_t* send_data,
                                        DWORD send_len,
                                        SCARD_IO_REQUEST* recv_pci,
                                        uint8_t* recv_data,
                                        DWORD* recv_len)
{
    (void)user_data;
    (void)handle;
    (void)send_pci;
    (void)send_data;
    (void)send_len;
    (void)recv_pci;
    (void)recv_data;
    if (recv_len)
        *recv_len = 0;
    return rdp_smartcard_call_unsupported();
}

static LONG rdp_smartcard_none_control(void* user_data,
                                       SCARDHANDLE handle,
                                       DWORD control_code,
                                       const uint8_t* input,
                                       DWORD input_len,
                                       uint8_t* output,
                                       DWORD output_len,
                                       DWORD* bytes_returned)
{
    (void)user_data;
    (void)handle;
    (void)control_code;
    (void)input;
    (void)input_len;
    (void)output;
    (void)output_len;
    if (bytes_returned)
        *bytes_returned = 0;
    return rdp_smartcard_call_unsupported();
}

static LONG rdp_smartcard_none_get_attrib(void* user_data,
                                          SCARDHANDLE handle,
                                          DWORD attr_id,
                                          uint8_t* attr,
                                          DWORD* attr_len)
{
    (void)user_data;
    (void)handle;
    (void)attr_id;
    (void)attr;
    if (attr_len)
        *attr_len = 0;
    return rdp_smartcard_call_unsupported();
}

static LONG rdp_smartcard_none_set_attrib(void* user_data,
                                          SCARDHANDLE handle,
                                          DWORD attr_id,
                                          const uint8_t* attr,
                                          DWORD attr_len)
{
    (void)user_data;
    (void)handle;
    (void)attr_id;
    (void)attr;
    (void)attr_len;
    return rdp_smartcard_call_unsupported();
}

static const rdp_smartcard_backend_ops rdp_smartcard_none_ops = {
    rdp_smartcard_none_establish_context,
    rdp_smartcard_none_release_context,
    rdp_smartcard_none_is_valid_context,
    rdp_smartcard_none_cancel,
    rdp_smartcard_none_list_reader_groups,
    rdp_smartcard_none_list_readers,
    rdp_smartcard_none_get_status_change,
    rdp_smartcard_none_begin_transaction,
    rdp_smartcard_none_connect,
    rdp_smartcard_none_disconnect,
    rdp_smartcard_none_end_transaction,
    rdp_smartcard_none_reconnect,
    rdp_smartcard_none_status,
    rdp_smartcard_none_transmit,
    rdp_smartcard_none_control,
    rdp_smartcard_none_get_attrib,
    rdp_smartcard_none_set_attrib
};

#ifdef RDP_HAVE_PCSC
static LONG rdp_smartcard_pcsc_establish_context(void* user_data, DWORD scope, SCARDCONTEXT* context)
{
    (void)user_data;
    return SCardEstablishContext(scope, NULL, NULL, context);
}

static LONG rdp_smartcard_pcsc_release_context(void* user_data, SCARDCONTEXT context)
{
    (void)user_data;
    return SCardReleaseContext(context);
}

static LONG rdp_smartcard_pcsc_is_valid_context(void* user_data, SCARDCONTEXT context)
{
    (void)user_data;
    return SCardIsValidContext(context);
}

static LONG rdp_smartcard_pcsc_cancel(void* user_data, SCARDCONTEXT context)
{
    (void)user_data;
    return SCardCancel(context);
}

static LONG rdp_smartcard_pcsc_list_reader_groups(void* user_data,
                                                  SCARDCONTEXT context,
                                                  char* groups,
                                                  DWORD* groups_len)
{
    (void)user_data;
    return SCardListReaderGroups(context, groups, groups_len);
}

static LONG rdp_smartcard_pcsc_list_readers(void* user_data,
                                            SCARDCONTEXT context,
                                            const char* groups,
                                            char* readers,
                                            DWORD* readers_len)
{
    (void)user_data;
    return SCardListReaders(context, groups, readers, readers_len);
}

static LONG rdp_smartcard_pcsc_get_status_change(void* user_data,
                                                 SCARDCONTEXT context,
                                                 DWORD timeout,
                                                 SCARD_READERSTATE* readers,
                                                 DWORD count)
{
    (void)user_data;
    return SCardGetStatusChange(context, timeout, readers, count);
}

static LONG rdp_smartcard_pcsc_begin_transaction(void* user_data, SCARDHANDLE handle)
{
    (void)user_data;
    return SCardBeginTransaction(handle);
}

static LONG rdp_smartcard_pcsc_connect(void* user_data,
                                       SCARDCONTEXT context,
                                       const char* reader,
                                       DWORD share_mode,
                                       DWORD preferred_protocols,
                                       SCARDHANDLE* handle,
                                       DWORD* active_protocol)
{
    (void)user_data;
    return SCardConnect(context, reader, share_mode, preferred_protocols, handle, active_protocol);
}

static LONG rdp_smartcard_pcsc_disconnect(void* user_data, SCARDHANDLE handle, DWORD disposition)
{
    (void)user_data;
    return SCardDisconnect(handle, disposition);
}

static LONG rdp_smartcard_pcsc_end_transaction(void* user_data, SCARDHANDLE handle, DWORD disposition)
{
    (void)user_data;
    return SCardEndTransaction(handle, disposition);
}

static LONG rdp_smartcard_pcsc_reconnect(void* user_data,
                                         SCARDHANDLE handle,
                                         DWORD share_mode,
                                         DWORD preferred_protocols,
                                         DWORD initialization,
                                         DWORD* active_protocol)
{
    (void)user_data;
    return SCardReconnect(handle, share_mode, preferred_protocols, initialization, active_protocol);
}

static LONG rdp_smartcard_pcsc_status(void* user_data,
                                      SCARDHANDLE handle,
                                      char* reader_names,
                                      DWORD* reader_names_len,
                                      DWORD* state,
                                      DWORD* protocol,
                                      uint8_t* atr,
                                      DWORD* atr_len)
{
    (void)user_data;
    return SCardStatus(handle, reader_names, reader_names_len, state, protocol, atr, atr_len);
}

static LONG rdp_smartcard_pcsc_transmit(void* user_data,
                                        SCARDHANDLE handle,
                                        const SCARD_IO_REQUEST* send_pci,
                                        const uint8_t* send_data,
                                        DWORD send_len,
                                        SCARD_IO_REQUEST* recv_pci,
                                        uint8_t* recv_data,
                                        DWORD* recv_len)
{
    (void)user_data;
    return SCardTransmit(handle, send_pci, send_data, send_len, recv_pci, recv_data, recv_len);
}

static LONG rdp_smartcard_pcsc_control(void* user_data,
                                       SCARDHANDLE handle,
                                       DWORD control_code,
                                       const uint8_t* input,
                                       DWORD input_len,
                                       uint8_t* output,
                                       DWORD output_len,
                                       DWORD* bytes_returned)
{
    (void)user_data;
    return SCardControl(handle, control_code, input, input_len, output, output_len, bytes_returned);
}

static LONG rdp_smartcard_pcsc_get_attrib(void* user_data,
                                          SCARDHANDLE handle,
                                          DWORD attr_id,
                                          uint8_t* attr,
                                          DWORD* attr_len)
{
    (void)user_data;
    return SCardGetAttrib(handle, attr_id, attr, attr_len);
}

static LONG rdp_smartcard_pcsc_set_attrib(void* user_data,
                                          SCARDHANDLE handle,
                                          DWORD attr_id,
                                          const uint8_t* attr,
                                          DWORD attr_len)
{
    (void)user_data;
    return SCardSetAttrib(handle, attr_id, attr, attr_len);
}

static const rdp_smartcard_backend_ops rdp_smartcard_pcsc_ops = {
    rdp_smartcard_pcsc_establish_context,
    rdp_smartcard_pcsc_release_context,
    rdp_smartcard_pcsc_is_valid_context,
    rdp_smartcard_pcsc_cancel,
    rdp_smartcard_pcsc_list_reader_groups,
    rdp_smartcard_pcsc_list_readers,
    rdp_smartcard_pcsc_get_status_change,
    rdp_smartcard_pcsc_begin_transaction,
    rdp_smartcard_pcsc_connect,
    rdp_smartcard_pcsc_disconnect,
    rdp_smartcard_pcsc_end_transaction,
    rdp_smartcard_pcsc_reconnect,
    rdp_smartcard_pcsc_status,
    rdp_smartcard_pcsc_transmit,
    rdp_smartcard_pcsc_control,
    rdp_smartcard_pcsc_get_attrib,
    rdp_smartcard_pcsc_set_attrib
};
#endif

static rdp_smartcard_mock_backend* rdp_smartcard_mock(void* user_data)
{
    return (rdp_smartcard_mock_backend*)user_data;
}

static LONG rdp_smartcard_mock_establish_context(void* user_data, DWORD scope, SCARDCONTEXT* context)
{
    rdp_smartcard_mock_backend* mock = rdp_smartcard_mock(user_data);

    (void)scope;
    if (!mock || !context)
        return SCARD_E_INVALID_PARAMETER;
    if (mock->establish_status == SCARD_S_SUCCESS)
        *context = mock->next_context ? mock->next_context : (SCARDCONTEXT)1u;
    return mock->establish_status;
}

static LONG rdp_smartcard_mock_release_context(void* user_data, SCARDCONTEXT context)
{
    rdp_smartcard_mock_backend* mock = rdp_smartcard_mock(user_data);

    (void)context;
    return mock ? mock->release_status : SCARD_E_INVALID_PARAMETER;
}

static LONG rdp_smartcard_mock_is_valid_context(void* user_data, SCARDCONTEXT context)
{
    rdp_smartcard_mock_backend* mock = rdp_smartcard_mock(user_data);

    (void)context;
    return mock ? mock->valid_status : SCARD_E_INVALID_PARAMETER;
}

static LONG rdp_smartcard_mock_cancel(void* user_data, SCARDCONTEXT context)
{
    rdp_smartcard_mock_backend* mock = rdp_smartcard_mock(user_data);

    (void)context;
    if (!mock)
        return SCARD_E_INVALID_PARAMETER;
    atomic_fetch_add_explicit(&mock->cancel_calls, 1u, memory_order_relaxed);
    atomic_store_explicit(&mock->cancelled, 1u, memory_order_release);
    return mock->cancel_status;
}

static LONG rdp_smartcard_mock_list_reader_groups(void* user_data,
                                                  SCARDCONTEXT context,
                                                  char* groups,
                                                  DWORD* groups_len)
{
    static const char default_group[] = "SCard$DefaultReaders\0\0";
    rdp_smartcard_mock_backend* mock = rdp_smartcard_mock(user_data);
    DWORD needed = (DWORD)sizeof(default_group);

    (void)context;
    if (!mock || !groups_len)
        return SCARD_E_INVALID_PARAMETER;
    if (!groups)
    {
        *groups_len = needed;
        return SCARD_S_SUCCESS;
    }
    if (*groups_len < needed)
    {
        *groups_len = needed;
        return SCARD_E_INVALID_PARAMETER;
    }
    memcpy(groups, default_group, sizeof(default_group));
    *groups_len = needed;
    return SCARD_S_SUCCESS;
}

static LONG rdp_smartcard_mock_list_readers(void* user_data,
                                            SCARDCONTEXT context,
                                            const char* groups,
                                            char* readers,
                                            DWORD* readers_len)
{
    static const char default_reader[] = "Mock Reader 0\0\0";
    rdp_smartcard_mock_backend* mock = rdp_smartcard_mock(user_data);
    DWORD needed = (DWORD)sizeof(default_reader);

    (void)context;
    (void)groups;
    if (!mock || !readers_len)
        return SCARD_E_INVALID_PARAMETER;
    if (!readers)
    {
        *readers_len = needed;
        return SCARD_S_SUCCESS;
    }
    if (*readers_len < needed)
    {
        *readers_len = needed;
        return SCARD_E_INVALID_PARAMETER;
    }
    memcpy(readers, default_reader, sizeof(default_reader));
    *readers_len = needed;
    return SCARD_S_SUCCESS;
}

static LONG rdp_smartcard_mock_get_status_change(void* user_data,
                                                 SCARDCONTEXT context,
                                                 DWORD timeout,
                                                 SCARD_READERSTATE* readers,
                                                 DWORD count)
{
    rdp_smartcard_mock_backend* mock = rdp_smartcard_mock(user_data);
    uint32_t waited = 0;

    (void)context;
    (void)timeout;
    if (!mock)
        return SCARD_E_INVALID_PARAMETER;
    atomic_fetch_add_explicit(&mock->status_change_calls, 1u, memory_order_relaxed);
    while (mock->hang_status_change_ms > waited)
    {
        if (atomic_load_explicit(&mock->cancelled, memory_order_acquire))
            return SCARD_E_CANCELLED;
        rdp_smartcard_sleep_ms(10u);
        waited += 10u;
    }
    if (readers && count > 0)
    {
        readers[0].dwEventState = mock->next_state;
        if (mock->atr_len <= sizeof(readers[0].rgbAtr))
        {
            readers[0].cbAtr = mock->atr_len;
            memcpy(readers[0].rgbAtr, mock->atr, mock->atr_len);
        }
    }
    return mock->status_change_status;
}

static LONG rdp_smartcard_mock_begin_transaction(void* user_data, SCARDHANDLE handle)
{
    (void)handle;
    return rdp_smartcard_mock(user_data) ? SCARD_S_SUCCESS : SCARD_E_INVALID_PARAMETER;
}

static LONG rdp_smartcard_mock_connect(void* user_data,
                                       SCARDCONTEXT context,
                                       const char* reader,
                                       DWORD share_mode,
                                       DWORD preferred_protocols,
                                       SCARDHANDLE* handle,
                                       DWORD* active_protocol)
{
    rdp_smartcard_mock_backend* mock = rdp_smartcard_mock(user_data);

    (void)context;
    (void)reader;
    (void)share_mode;
    (void)preferred_protocols;
    if (!mock || !handle || !active_protocol)
        return SCARD_E_INVALID_PARAMETER;
    if (mock->connect_status == SCARD_S_SUCCESS)
    {
        *handle = mock->next_handle ? mock->next_handle : (SCARDHANDLE)2u;
        *active_protocol = mock->next_protocol;
    }
    return mock->connect_status;
}

static LONG rdp_smartcard_mock_disconnect(void* user_data, SCARDHANDLE handle, DWORD disposition)
{
    rdp_smartcard_mock_backend* mock = rdp_smartcard_mock(user_data);

    (void)handle;
    (void)disposition;
    return mock ? mock->disconnect_status : SCARD_E_INVALID_PARAMETER;
}

static LONG rdp_smartcard_mock_end_transaction(void* user_data, SCARDHANDLE handle, DWORD disposition)
{
    (void)handle;
    (void)disposition;
    return rdp_smartcard_mock(user_data) ? SCARD_S_SUCCESS : SCARD_E_INVALID_PARAMETER;
}

static LONG rdp_smartcard_mock_reconnect(void* user_data,
                                         SCARDHANDLE handle,
                                         DWORD share_mode,
                                         DWORD preferred_protocols,
                                         DWORD initialization,
                                         DWORD* active_protocol)
{
    rdp_smartcard_mock_backend* mock = rdp_smartcard_mock(user_data);

    (void)handle;
    (void)share_mode;
    (void)preferred_protocols;
    (void)initialization;
    if (!mock || !active_protocol)
        return SCARD_E_INVALID_PARAMETER;
    if (mock->reconnect_status == SCARD_S_SUCCESS)
        *active_protocol = mock->next_protocol;
    return mock->reconnect_status;
}

static LONG rdp_smartcard_mock_status(void* user_data,
                                      SCARDHANDLE handle,
                                      char* reader_names,
                                      DWORD* reader_names_len,
                                      DWORD* state,
                                      DWORD* protocol,
                                      uint8_t* atr,
                                      DWORD* atr_len)
{
    rdp_smartcard_mock_backend* mock = rdp_smartcard_mock(user_data);

    (void)handle;
    (void)reader_names;
    if (!mock)
        return SCARD_E_INVALID_PARAMETER;
    if (reader_names_len)
        *reader_names_len = 0;
    if (state)
        *state = mock->next_state;
    if (protocol)
        *protocol = mock->next_protocol;
    if (atr && atr_len && *atr_len >= mock->atr_len)
    {
        memcpy(atr, mock->atr, mock->atr_len);
        *atr_len = mock->atr_len;
    }
    return mock->status_status;
}

static LONG rdp_smartcard_mock_transmit(void* user_data,
                                        SCARDHANDLE handle,
                                        const SCARD_IO_REQUEST* send_pci,
                                        const uint8_t* send_data,
                                        DWORD send_len,
                                        SCARD_IO_REQUEST* recv_pci,
                                        uint8_t* recv_data,
                                        DWORD* recv_len)
{
    rdp_smartcard_mock_backend* mock = rdp_smartcard_mock(user_data);
    uint32_t waited = 0;
    DWORD copy_len = 0;

    (void)handle;
    (void)send_pci;
    (void)send_data;
    (void)send_len;
    if (!mock || !recv_len)
        return SCARD_E_INVALID_PARAMETER;
    atomic_fetch_add_explicit(&mock->transmit_calls, 1u, memory_order_relaxed);
    while (mock->hang_transmit_ms > waited)
    {
        if (atomic_load_explicit(&mock->cancelled, memory_order_acquire))
            return SCARD_E_CANCELLED;
        rdp_smartcard_sleep_ms(10u);
        waited += 10u;
    }
    if (mock->transmit_status == SCARD_S_SUCCESS && recv_data)
    {
        copy_len = *recv_len < mock->transmit_response_len ? *recv_len : mock->transmit_response_len;
        memcpy(recv_data, mock->transmit_response, copy_len);
        *recv_len = copy_len;
        if (recv_pci)
            recv_pci->dwProtocol = mock->next_protocol;
    }
    return mock->transmit_status;
}

static LONG rdp_smartcard_mock_control(void* user_data,
                                       SCARDHANDLE handle,
                                       DWORD control_code,
                                       const uint8_t* input,
                                       DWORD input_len,
                                       uint8_t* output,
                                       DWORD output_len,
                                       DWORD* bytes_returned)
{
    rdp_smartcard_mock_backend* mock = rdp_smartcard_mock(user_data);

    (void)handle;
    (void)control_code;
    (void)input;
    (void)input_len;
    (void)output;
    (void)output_len;
    if (bytes_returned)
        *bytes_returned = 0;
    return mock ? mock->control_status : SCARD_E_INVALID_PARAMETER;
}

static LONG rdp_smartcard_mock_get_attrib(void* user_data,
                                          SCARDHANDLE handle,
                                          DWORD attr_id,
                                          uint8_t* attr,
                                          DWORD* attr_len)
{
    rdp_smartcard_mock_backend* mock = rdp_smartcard_mock(user_data);

    (void)handle;
    (void)attr_id;
    (void)attr;
    if (attr_len)
        *attr_len = 0;
    return mock ? mock->attrib_status : SCARD_E_INVALID_PARAMETER;
}

static LONG rdp_smartcard_mock_set_attrib(void* user_data,
                                          SCARDHANDLE handle,
                                          DWORD attr_id,
                                          const uint8_t* attr,
                                          DWORD attr_len)
{
    rdp_smartcard_mock_backend* mock = rdp_smartcard_mock(user_data);

    (void)handle;
    (void)attr_id;
    (void)attr;
    (void)attr_len;
    return mock ? mock->attrib_status : SCARD_E_INVALID_PARAMETER;
}

static const rdp_smartcard_backend_ops rdp_smartcard_mock_ops = {
    rdp_smartcard_mock_establish_context,
    rdp_smartcard_mock_release_context,
    rdp_smartcard_mock_is_valid_context,
    rdp_smartcard_mock_cancel,
    rdp_smartcard_mock_list_reader_groups,
    rdp_smartcard_mock_list_readers,
    rdp_smartcard_mock_get_status_change,
    rdp_smartcard_mock_begin_transaction,
    rdp_smartcard_mock_connect,
    rdp_smartcard_mock_disconnect,
    rdp_smartcard_mock_end_transaction,
    rdp_smartcard_mock_reconnect,
    rdp_smartcard_mock_status,
    rdp_smartcard_mock_transmit,
    rdp_smartcard_mock_control,
    rdp_smartcard_mock_get_attrib,
    rdp_smartcard_mock_set_attrib
};

void rdp_smartcard_backend_init_none(rdp_smartcard_backend* backend)
{
    if (!backend)
        return;
    memset(backend, 0, sizeof(*backend));
    backend->kind = RDP_SMARTCARD_BACKEND_KIND_NONE;
    backend->ops = &rdp_smartcard_none_ops;
    backend->timeout_ms = RDP_SMARTCARD_BACKEND_DEFAULT_TIMEOUT_MS;
}

void rdp_smartcard_backend_init_pcsc(rdp_smartcard_backend* backend)
{
    rdp_smartcard_backend_init_none(backend);
    if (!backend)
        return;
#ifdef RDP_HAVE_PCSC
    backend->kind = RDP_SMARTCARD_BACKEND_KIND_PCSC;
    backend->ops = &rdp_smartcard_pcsc_ops;
#endif
}

void rdp_smartcard_mock_backend_init(rdp_smartcard_mock_backend* mock)
{
    if (!mock)
        return;
    memset(mock, 0, sizeof(*mock));
    mock->establish_status = SCARD_S_SUCCESS;
    mock->release_status = SCARD_S_SUCCESS;
    mock->valid_status = SCARD_S_SUCCESS;
    mock->cancel_status = SCARD_S_SUCCESS;
    mock->connect_status = SCARD_S_SUCCESS;
    mock->disconnect_status = SCARD_S_SUCCESS;
    mock->reconnect_status = SCARD_S_SUCCESS;
    mock->status_status = SCARD_S_SUCCESS;
    mock->status_change_status = SCARD_S_SUCCESS;
    mock->transmit_status = SCARD_S_SUCCESS;
    mock->control_status = SCARD_S_SUCCESS;
    mock->attrib_status = SCARD_S_SUCCESS;
    mock->next_context = (SCARDCONTEXT)1u;
    mock->next_handle = (SCARDHANDLE)2u;
    mock->next_protocol = 2u;
    mock->next_state = 0x20u;
    mock->transmit_response[0] = 0x90u;
    mock->transmit_response[1] = 0x00u;
    mock->transmit_response_len = 2u;
    atomic_init(&mock->cancel_calls, 0u);
    atomic_init(&mock->status_change_calls, 0u);
    atomic_init(&mock->transmit_calls, 0u);
    atomic_init(&mock->cancelled, 0u);
}

void rdp_smartcard_backend_init_mock(rdp_smartcard_backend* backend, rdp_smartcard_mock_backend* mock)
{
    if (!backend)
        return;
    memset(backend, 0, sizeof(*backend));
    backend->kind = RDP_SMARTCARD_BACKEND_KIND_MOCK;
    backend->ops = &rdp_smartcard_mock_ops;
    backend->user_data = mock;
    backend->timeout_ms = RDP_SMARTCARD_BACKEND_DEFAULT_TIMEOUT_MS;
}

void rdp_smartcard_backend_set_timeout(rdp_smartcard_backend* backend, uint32_t timeout_ms)
{
    if (!backend)
        return;
    backend->timeout_ms = timeout_ms ? timeout_ms : RDP_SMARTCARD_BACKEND_DEFAULT_TIMEOUT_MS;
}

static LONG rdp_smartcard_backend_bad_args(void)
{
    return SCARD_E_INVALID_PARAMETER;
}

LONG rdp_smartcard_backend_establish_context(rdp_smartcard_backend* backend, DWORD scope, SCARDCONTEXT* context)
{
    if (!backend || !backend->ops || !context)
        return rdp_smartcard_backend_bad_args();
    return backend->ops->establish_context(backend->user_data, scope, context);
}

LONG rdp_smartcard_backend_release_context(rdp_smartcard_backend* backend, SCARDCONTEXT context)
{
    if (!backend || !backend->ops)
        return rdp_smartcard_backend_bad_args();
    return backend->ops->release_context(backend->user_data, context);
}

LONG rdp_smartcard_backend_is_valid_context(rdp_smartcard_backend* backend, SCARDCONTEXT context)
{
    if (!backend || !backend->ops)
        return rdp_smartcard_backend_bad_args();
    return backend->ops->is_valid_context(backend->user_data, context);
}

LONG rdp_smartcard_backend_cancel(rdp_smartcard_backend* backend, SCARDCONTEXT context)
{
    if (!backend || !backend->ops)
        return rdp_smartcard_backend_bad_args();
    return backend->ops->cancel(backend->user_data, context);
}

LONG rdp_smartcard_backend_list_reader_groups(rdp_smartcard_backend* backend,
                                              SCARDCONTEXT context,
                                              char* groups,
                                              DWORD* groups_len)
{
    if (!backend || !backend->ops || !groups_len)
        return rdp_smartcard_backend_bad_args();
    return backend->ops->list_reader_groups(backend->user_data, context, groups, groups_len);
}

LONG rdp_smartcard_backend_list_readers(rdp_smartcard_backend* backend,
                                        SCARDCONTEXT context,
                                        const char* groups,
                                        char* readers,
                                        DWORD* readers_len)
{
    if (!backend || !backend->ops || !readers_len)
        return rdp_smartcard_backend_bad_args();
    return backend->ops->list_readers(backend->user_data, context, groups, readers, readers_len);
}

static LONG rdp_smartcard_status_change_job(void* arg)
{
    rdp_smartcard_status_change_args* call = (rdp_smartcard_status_change_args*)arg;

    return call->backend->ops->get_status_change(call->backend->user_data,
                                                 call->context,
                                                 call->timeout,
                                                 call->states,
                                                 call->count);
}

static void rdp_smartcard_status_change_cleanup(void* arg)
{
    rdp_smartcard_status_change_args* call = (rdp_smartcard_status_change_args*)arg;

    if (!call)
        return;
    if (call->reader_names)
    {
        for (DWORD i = 0; i < call->count; i++)
            free(call->reader_names[i]);
    }
    free(call->reader_names);
    free(call->states);
    free(call);
}

static void rdp_smartcard_cancel_context_job(void* arg)
{
    rdp_smartcard_cancel_context* cancel = (rdp_smartcard_cancel_context*)arg;

    if (cancel && cancel->backend)
        (void)rdp_smartcard_backend_cancel(cancel->backend, cancel->context);
}

static rdp_smartcard_status_change_args* rdp_smartcard_status_change_args_new(rdp_smartcard_backend* backend,
                                                                              SCARDCONTEXT context,
                                                                              DWORD timeout,
                                                                              const SCARD_READERSTATE* readers,
                                                                              DWORD count)
{
    rdp_smartcard_status_change_args* call = NULL;

    call = (rdp_smartcard_status_change_args*)calloc(1, sizeof(*call));
    if (!call)
        return NULL;
    call->states = (SCARD_READERSTATE*)calloc(count ? count : 1u, sizeof(SCARD_READERSTATE));
    call->reader_names = (char**)calloc(count ? count : 1u, sizeof(char*));
    if (!call->states || !call->reader_names)
    {
        rdp_smartcard_status_change_cleanup(call);
        return NULL;
    }
    call->backend = backend;
    call->context = context;
    call->timeout = timeout;
    call->count = count;
    for (DWORD i = 0; i < count; i++)
    {
        call->states[i] = readers[i];
        call->states[i].szReader = NULL;
        if (readers[i].szReader)
        {
            call->reader_names[i] = rdp_smartcard_strdup(readers[i].szReader);
            if (!call->reader_names[i])
            {
                rdp_smartcard_status_change_cleanup(call);
                return NULL;
            }
            call->states[i].szReader = call->reader_names[i];
        }
    }
    return call;
}

LONG rdp_smartcard_backend_get_status_change(rdp_smartcard_backend* backend,
                                             SCARDCONTEXT context,
                                             DWORD timeout,
                                             SCARD_READERSTATE* readers,
                                             DWORD count)
{
    rdp_smartcard_status_change_args* call = NULL;
    rdp_smartcard_cancel_context cancel;
    int completed = 0;
    LONG status = SCARD_S_SUCCESS;

    if (!backend || !backend->ops || (!readers && count > 0))
        return rdp_smartcard_backend_bad_args();
    call = rdp_smartcard_status_change_args_new(backend, context, timeout, readers, count);
    if (!call)
        return SCARD_E_NO_MEMORY;
    cancel.backend = backend;
    cancel.context = context;
    status = rdp_smartcard_run_with_timeout(rdp_smartcard_status_change_job,
                                            call,
                                            rdp_smartcard_status_change_cleanup,
                                            rdp_smartcard_cancel_context_job,
                                            &cancel,
                                            backend->timeout_ms,
                                            &completed);
    if (completed)
    {
        if (status == SCARD_S_SUCCESS || status == SCARD_E_TIMEOUT)
        {
            for (DWORD i = 0; i < count; i++)
            {
                const char* original_reader = readers[i].szReader;

                readers[i] = call->states[i];
                readers[i].szReader = original_reader;
            }
        }
        rdp_smartcard_status_change_cleanup(call);
    }
    return status;
}

LONG rdp_smartcard_backend_begin_transaction(rdp_smartcard_backend* backend, SCARDHANDLE handle)
{
    if (!backend || !backend->ops)
        return rdp_smartcard_backend_bad_args();
    return backend->ops->begin_transaction(backend->user_data, handle);
}

static LONG rdp_smartcard_connect_job(void* arg)
{
    rdp_smartcard_connect_args* call = (rdp_smartcard_connect_args*)arg;

    return call->backend->ops->connect(call->backend->user_data,
                                      call->context,
                                      call->reader,
                                      call->share_mode,
                                      call->preferred_protocols,
                                      &call->handle,
                                      &call->active_protocol);
}

static void rdp_smartcard_connect_cleanup(void* arg)
{
    rdp_smartcard_connect_args* call = (rdp_smartcard_connect_args*)arg;

    if (!call)
        return;
    if (!call->transfer_handle && call->handle != 0 && call->backend && call->backend->ops)
        (void)call->backend->ops->disconnect(call->backend->user_data, call->handle, 0u);
    free(call->reader);
    free(call);
}

LONG rdp_smartcard_backend_connect(rdp_smartcard_backend* backend,
                                   SCARDCONTEXT context,
                                   const char* reader,
                                   DWORD share_mode,
                                   DWORD preferred_protocols,
                                   SCARDHANDLE* handle,
                                   DWORD* active_protocol)
{
    rdp_smartcard_connect_args* call = NULL;
    rdp_smartcard_cancel_context cancel;
    int completed = 0;
    LONG status = SCARD_S_SUCCESS;

    if (!backend || !backend->ops || !reader || !handle || !active_protocol)
        return rdp_smartcard_backend_bad_args();
    *handle = 0;
    *active_protocol = 0;
    call = (rdp_smartcard_connect_args*)calloc(1, sizeof(*call));
    if (!call)
        return SCARD_E_NO_MEMORY;
    call->reader = rdp_smartcard_strdup(reader);
    if (!call->reader)
    {
        free(call);
        return SCARD_E_NO_MEMORY;
    }
    call->backend = backend;
    call->context = context;
    call->share_mode = share_mode;
    call->preferred_protocols = preferred_protocols;
    cancel.backend = backend;
    cancel.context = context;
    status = rdp_smartcard_run_with_timeout(rdp_smartcard_connect_job,
                                            call,
                                            rdp_smartcard_connect_cleanup,
                                            rdp_smartcard_cancel_context_job,
                                            &cancel,
                                            backend->timeout_ms,
                                            &completed);
    if (completed)
    {
        if (status == SCARD_S_SUCCESS)
        {
            *handle = call->handle;
            *active_protocol = call->active_protocol;
            call->transfer_handle = 1;
        }
        rdp_smartcard_connect_cleanup(call);
    }
    return status;
}

LONG rdp_smartcard_backend_disconnect(rdp_smartcard_backend* backend, SCARDHANDLE handle, DWORD disposition)
{
    if (!backend || !backend->ops)
        return rdp_smartcard_backend_bad_args();
    return backend->ops->disconnect(backend->user_data, handle, disposition);
}

LONG rdp_smartcard_backend_end_transaction(rdp_smartcard_backend* backend, SCARDHANDLE handle, DWORD disposition)
{
    if (!backend || !backend->ops)
        return rdp_smartcard_backend_bad_args();
    return backend->ops->end_transaction(backend->user_data, handle, disposition);
}

LONG rdp_smartcard_backend_reconnect(rdp_smartcard_backend* backend,
                                     SCARDHANDLE handle,
                                     DWORD share_mode,
                                     DWORD preferred_protocols,
                                     DWORD initialization,
                                     DWORD* active_protocol)
{
    if (!backend || !backend->ops || !active_protocol)
        return rdp_smartcard_backend_bad_args();
    return backend->ops->reconnect(backend->user_data,
                                   handle,
                                   share_mode,
                                   preferred_protocols,
                                   initialization,
                                   active_protocol);
}

LONG rdp_smartcard_backend_status(rdp_smartcard_backend* backend,
                                  SCARDHANDLE handle,
                                  char* reader_names,
                                  DWORD* reader_names_len,
                                  DWORD* state,
                                  DWORD* protocol,
                                  uint8_t* atr,
                                  DWORD* atr_len)
{
    if (!backend || !backend->ops || !reader_names_len || !state || !protocol || !atr_len)
        return rdp_smartcard_backend_bad_args();
    return backend->ops->status(backend->user_data,
                                handle,
                                reader_names,
                                reader_names_len,
                                state,
                                protocol,
                                atr,
                                atr_len);
}

static LONG rdp_smartcard_transmit_job(void* arg)
{
    rdp_smartcard_transmit_args* call = (rdp_smartcard_transmit_args*)arg;

    return call->backend->ops->transmit(call->backend->user_data,
                                        call->handle,
                                        &call->send_pci,
                                        call->send_data,
                                        call->send_len,
                                        call->recv_pci_present ? &call->recv_pci : NULL,
                                        call->recv_data,
                                        &call->recv_len);
}

static void rdp_smartcard_transmit_cleanup(void* arg)
{
    rdp_smartcard_transmit_args* call = (rdp_smartcard_transmit_args*)arg;

    if (!call)
        return;
    free(call->send_data);
    free(call->recv_data);
    free(call);
}

LONG rdp_smartcard_backend_transmit(rdp_smartcard_backend* backend,
                                    SCARDCONTEXT context,
                                    SCARDHANDLE handle,
                                    const SCARD_IO_REQUEST* send_pci,
                                    const uint8_t* send_data,
                                    DWORD send_len,
                                    SCARD_IO_REQUEST* recv_pci,
                                    uint8_t* recv_data,
                                    DWORD* recv_len)
{
    rdp_smartcard_transmit_args* call = NULL;
    rdp_smartcard_cancel_context cancel;
    int completed = 0;
    LONG status = SCARD_S_SUCCESS;

    if (!backend || !backend->ops || !send_pci || (!send_data && send_len > 0) || !recv_data || !recv_len)
        return rdp_smartcard_backend_bad_args();
    call = (rdp_smartcard_transmit_args*)calloc(1, sizeof(*call));
    if (!call)
        return SCARD_E_NO_MEMORY;
    call->send_data = (uint8_t*)calloc(send_len ? send_len : 1u, 1u);
    call->recv_data = (uint8_t*)calloc(*recv_len ? *recv_len : 1u, 1u);
    if (!call->send_data || !call->recv_data)
    {
        rdp_smartcard_transmit_cleanup(call);
        return SCARD_E_NO_MEMORY;
    }
    memcpy(call->send_data, send_data, send_len);
    call->backend = backend;
    call->handle = handle;
    call->send_pci = *send_pci;
    if (recv_pci)
    {
        call->recv_pci = *recv_pci;
        call->recv_pci_present = 1;
    }
    call->send_len = send_len;
    call->recv_len = *recv_len;
    cancel.backend = backend;
    cancel.context = context;
    status = rdp_smartcard_run_with_timeout(rdp_smartcard_transmit_job,
                                            call,
                                            rdp_smartcard_transmit_cleanup,
                                            rdp_smartcard_cancel_context_job,
                                            &cancel,
                                            backend->timeout_ms,
                                            &completed);
    if (completed)
    {
        if (status == SCARD_S_SUCCESS)
        {
            if (recv_pci && call->recv_pci_present)
                *recv_pci = call->recv_pci;
            if (*recv_len > call->recv_len)
                *recv_len = call->recv_len;
            memcpy(recv_data, call->recv_data, *recv_len);
        }
        rdp_smartcard_transmit_cleanup(call);
    }
    else
    {
        *recv_len = 0;
    }
    return status;
}

LONG rdp_smartcard_backend_control(rdp_smartcard_backend* backend,
                                   SCARDHANDLE handle,
                                   DWORD control_code,
                                   const uint8_t* input,
                                   DWORD input_len,
                                   uint8_t* output,
                                   DWORD output_len,
                                   DWORD* bytes_returned)
{
    if (!backend || !backend->ops || (!input && input_len > 0) || !output || !bytes_returned)
        return rdp_smartcard_backend_bad_args();
    return backend->ops->control(backend->user_data,
                                 handle,
                                 control_code,
                                 input,
                                 input_len,
                                 output,
                                 output_len,
                                 bytes_returned);
}

LONG rdp_smartcard_backend_get_attrib(rdp_smartcard_backend* backend,
                                      SCARDHANDLE handle,
                                      DWORD attr_id,
                                      uint8_t* attr,
                                      DWORD* attr_len)
{
    if (!backend || !backend->ops || !attr || !attr_len)
        return rdp_smartcard_backend_bad_args();
    return backend->ops->get_attrib(backend->user_data, handle, attr_id, attr, attr_len);
}

LONG rdp_smartcard_backend_set_attrib(rdp_smartcard_backend* backend,
                                      SCARDHANDLE handle,
                                      DWORD attr_id,
                                      const uint8_t* attr,
                                      DWORD attr_len)
{
    if (!backend || !backend->ops || (!attr && attr_len > 0))
        return rdp_smartcard_backend_bad_args();
    return backend->ops->set_attrib(backend->user_data, handle, attr_id, attr, attr_len);
}
