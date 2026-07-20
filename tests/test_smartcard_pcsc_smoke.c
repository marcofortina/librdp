/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: opt-in PC/SC smartcard backend smoke test.
 * Coverage: exercises the real PC/SC backend against an explicitly selected
 * virtual reader, including card lifecycle, bounded waits, cancellation,
 * reconnect, removal and insertion.
 * Bug classes: provider hangs, stale card handles, incorrect reader-state
 * transitions, APDU truncation and accidental sensitive trace payloads.
 * Determinism: the selected reader and virtual card process are controlled by
 * the caller; no physical token or network service is required.
 */

#include "client/smartcard_backend.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SMARTCARD_SMOKE_SKIP 77
#define SMARTCARD_SMOKE_WAIT_MS 30000u
#define SMARTCARD_SMOKE_INFINITE ((DWORD)0xffffffffu)

typedef struct smartcard_smoke_fixture
{
    rdp_smartcard_backend backend;
    SCARDCONTEXT context;
    SCARDHANDLE handle;
    DWORD active_protocol;
    char* readers;
    char* reader;
    int context_established;
    int connected;
    int transaction_active;
} smartcard_smoke_fixture;

typedef struct smartcard_cancel_call
{
    rdp_smartcard_backend* backend;
    SCARDCONTEXT context;
    SCARD_READERSTATE state;
    atomic_int started;
    LONG status;
} smartcard_cancel_call;

static int smartcard_smoke_check(int condition,
                                 const char* expression,
                                 int line)
{
    if (!condition)
    {
        fprintf(stderr,
                "test_smartcard_pcsc_smoke:%d: check failed: %s\n",
                line,
                expression);
        return 0;
    }
    return 1;
}

#define SMOKE_CHECK(fixture, expression) \
    do \
    { \
        if (!smartcard_smoke_check((expression), #expression, __LINE__)) \
        { \
            smartcard_smoke_fixture_clear((fixture)); \
            return 1; \
        } \
    } while (0)

static void smartcard_smoke_sleep_ms(uint32_t milliseconds)
{
    struct timespec requested;
    struct timespec remaining;

    requested.tv_sec = (time_t)(milliseconds / 1000u);
    requested.tv_nsec = (long)((milliseconds % 1000u) * 1000000u);
    while (nanosleep(&requested, &remaining) != 0)
        requested = remaining;
}

static void smartcard_smoke_fixture_clear(smartcard_smoke_fixture* fixture)
{
    if (!fixture)
        return;
    if (fixture->transaction_active)
    {
        (void)rdp_smartcard_backend_end_transaction(&fixture->backend,
                                                    fixture->handle,
                                                    SCARD_LEAVE_CARD);
        fixture->transaction_active = 0;
    }
    if (fixture->connected)
    {
        (void)rdp_smartcard_backend_disconnect(&fixture->backend,
                                               fixture->handle,
                                               SCARD_LEAVE_CARD);
        fixture->connected = 0;
    }
    if (fixture->context_established)
    {
        (void)rdp_smartcard_backend_release_context(&fixture->backend,
                                                    fixture->context);
        fixture->context_established = 0;
    }
    rdp_smartcard_backend_clear(&fixture->backend);
    free(fixture->readers);
    memset(fixture, 0, sizeof(*fixture));
}

static char* smartcard_smoke_find_reader(char* readers,
                                         DWORD readers_len,
                                         const char* requested)
{
    size_t offset = 0;

    if (!readers || !requested)
        return NULL;
    while (offset < (size_t)readers_len && readers[offset] != '\0')
    {
        const size_t remaining = (size_t)readers_len - offset;
        const size_t length = strnlen(readers + offset, remaining);

        if (length == remaining)
            return NULL;
        if (strcmp(readers + offset, requested) == 0)
            return readers + offset;
        offset += length + 1u;
    }
    return NULL;
}

static int smartcard_smoke_fixture_init(smartcard_smoke_fixture* fixture,
                                        const char* requested_reader)
{
    DWORD readers_len = 0;
    LONG status = SCARD_S_SUCCESS;

    memset(fixture, 0, sizeof(*fixture));
    rdp_smartcard_backend_init_pcsc(&fixture->backend);
    rdp_smartcard_backend_set_timeout(&fixture->backend,
                                      SMARTCARD_SMOKE_WAIT_MS + 2000u);
    if (!smartcard_smoke_check(
            fixture->backend.kind == RDP_SMARTCARD_BACKEND_KIND_PCSC,
            "PC/SC backend selected",
            __LINE__))
        return 0;
    status = rdp_smartcard_backend_establish_context(&fixture->backend,
                                                     SCARD_SCOPE_SYSTEM,
                                                     &fixture->context);
    if (!smartcard_smoke_check(status == SCARD_S_SUCCESS,
                               "establish PC/SC context",
                               __LINE__))
        return 0;
    fixture->context_established = 1;
    if (!smartcard_smoke_check(
            rdp_smartcard_backend_is_valid_context(&fixture->backend,
                                                   fixture->context) ==
                SCARD_S_SUCCESS,
            "validate PC/SC context",
            __LINE__))
        return 0;
    status = rdp_smartcard_backend_list_readers(&fixture->backend,
                                                fixture->context,
                                                NULL,
                                                NULL,
                                                &readers_len);
    if (!smartcard_smoke_check(status == SCARD_S_SUCCESS && readers_len > 1u,
                               "query PC/SC reader list length",
                               __LINE__))
        return 0;
    fixture->readers = (char*)calloc((size_t)readers_len, 1u);
    if (!smartcard_smoke_check(fixture->readers != NULL,
                               "allocate PC/SC reader list",
                               __LINE__))
        return 0;
    status = rdp_smartcard_backend_list_readers(&fixture->backend,
                                                fixture->context,
                                                NULL,
                                                fixture->readers,
                                                &readers_len);
    if (!smartcard_smoke_check(status == SCARD_S_SUCCESS,
                               "read PC/SC reader list",
                               __LINE__))
        return 0;
    fixture->reader = smartcard_smoke_find_reader(fixture->readers,
                                                  readers_len,
                                                  requested_reader);
    return smartcard_smoke_check(fixture->reader != NULL,
                                 "find requested PC/SC reader",
                                 __LINE__);
}

static LONG smartcard_smoke_read_state(smartcard_smoke_fixture* fixture,
                                       SCARD_READERSTATE* state,
                                       DWORD timeout)
{
    return rdp_smartcard_backend_get_status_change(&fixture->backend,
                                                   fixture->context,
                                                   timeout,
                                                   state,
                                                   1u);
}

static int smartcard_smoke_initial_state(smartcard_smoke_fixture* fixture,
                                         SCARD_READERSTATE* state)
{
    memset(state, 0, sizeof(*state));
    state->szReader = fixture->reader;
    state->dwCurrentState = SCARD_STATE_UNAWARE;
    if (!smartcard_smoke_check(
            smartcard_smoke_read_state(fixture, state, 1000u) ==
                SCARD_S_SUCCESS,
            "read initial PC/SC state",
            __LINE__))
        return 0;
    state->dwCurrentState =
        state->dwEventState & ~(DWORD)SCARD_STATE_CHANGED;
    return 1;
}

static void* smartcard_smoke_cancel_thread(void* user_data)
{
    smartcard_cancel_call* call = (smartcard_cancel_call*)user_data;

    atomic_store_explicit(&call->started, 1, memory_order_release);
    call->status = rdp_smartcard_backend_get_status_change(call->backend,
                                                           call->context,
                                                           SMARTCARD_SMOKE_INFINITE,
                                                           &call->state,
                                                           1u);
    return NULL;
}

static int smartcard_smoke_timeout_and_cancel(smartcard_smoke_fixture* fixture,
                                              SCARD_READERSTATE* state)
{
    smartcard_cancel_call call;
    pthread_t thread;
    LONG status = SCARD_S_SUCCESS;
    unsigned int attempt = 0;

    for (attempt = 0; attempt < 3u; attempt++)
    {
        status = smartcard_smoke_read_state(fixture, state, 80u);
        if (status == SCARD_E_TIMEOUT)
            break;
        if (status != SCARD_S_SUCCESS)
            return smartcard_smoke_check(0,
                                         "bounded PC/SC status wait",
                                         __LINE__);
        state->dwCurrentState =
            state->dwEventState & ~(DWORD)SCARD_STATE_CHANGED;
    }
    if (!smartcard_smoke_check(status == SCARD_E_TIMEOUT,
                               "PC/SC status wait times out",
                               __LINE__))
        return 0;

    memset(&call, 0, sizeof(call));
    call.backend = &fixture->backend;
    call.context = fixture->context;
    call.state = *state;
    atomic_init(&call.started, 0);
    if (!smartcard_smoke_check(
            pthread_create(&thread,
                           NULL,
                           smartcard_smoke_cancel_thread,
                           &call) == 0,
            "create PC/SC cancel worker",
            __LINE__))
        return 0;
    while (!atomic_load_explicit(&call.started, memory_order_acquire))
        smartcard_smoke_sleep_ms(1u);
    smartcard_smoke_sleep_ms(100u);
    status = rdp_smartcard_backend_cancel(&fixture->backend,
                                          fixture->context);
    if (!smartcard_smoke_check(status == SCARD_S_SUCCESS,
                               "cancel PC/SC wait",
                               __LINE__))
    {
        (void)pthread_join(thread, NULL);
        return 0;
    }
    if (!smartcard_smoke_check(pthread_join(thread, NULL) == 0,
                               "join PC/SC cancel worker",
                               __LINE__))
        return 0;
    return smartcard_smoke_check(call.status == SCARD_E_CANCELLED,
                                 "PC/SC wait reports cancellation",
                                 __LINE__);
}

static const SCARD_IO_REQUEST* smartcard_smoke_protocol_pci(DWORD protocol)
{
    if (protocol == SCARD_PROTOCOL_T0)
        return SCARD_PCI_T0;
    if (protocol == SCARD_PROTOCOL_T1)
        return SCARD_PCI_T1;
    return NULL;
}

static int smartcard_smoke_transmit(smartcard_smoke_fixture* fixture,
                                    const uint8_t* command,
                                    DWORD command_len,
                                    int check_status_words,
                                    uint8_t expected_sw1,
                                    uint8_t expected_sw2)
{
    const SCARD_IO_REQUEST* send_pci =
        smartcard_smoke_protocol_pci(fixture->active_protocol);
    SCARD_IO_REQUEST receive_pci;
    uint8_t response[258];
    DWORD response_len = sizeof(response);
    LONG status = SCARD_S_SUCCESS;

    if (!smartcard_smoke_check(send_pci != NULL,
                               "supported PC/SC card protocol",
                               __LINE__))
        return 0;
    memset(&receive_pci, 0, sizeof(receive_pci));
    memset(response, 0, sizeof(response));
    receive_pci.dwProtocol = fixture->active_protocol;
    receive_pci.cbPciLength = sizeof(receive_pci);
    status = rdp_smartcard_backend_transmit(&fixture->backend,
                                           fixture->context,
                                           fixture->handle,
                                           send_pci,
                                           command,
                                           command_len,
                                           &receive_pci,
                                           response,
                                           &response_len);
    if (!smartcard_smoke_check(status == SCARD_S_SUCCESS &&
                                   response_len >= 2u,
                               "transmit PC/SC APDU",
                               __LINE__))
        return 0;
    if (!check_status_words)
        return 1;
    return smartcard_smoke_check(response[response_len - 2u] == expected_sw1 &&
                                     response[response_len - 1u] == expected_sw2,
                                 "validate PC/SC APDU status words",
                                 __LINE__);
}

static int smartcard_smoke_card_lifecycle(smartcard_smoke_fixture* fixture)
{
    static const uint8_t challenge[] = {0x00u, 0x84u, 0x00u, 0x00u, 0x08u};
    static const uint8_t apdu_canary[] = {
        0x00u, 0xa4u, 0x04u, 0x00u, 0x10u,
        'S', 'C', 'A', 'R', 'D', '_', 'A', 'P', 'D', 'U', '_',
        '7', 'F', '3', 'X', '!'
    };
    static const uint8_t pin_canary[] = {
        0x00u, 0x20u, 0x00u, 0x00u, 0x10u,
        'S', 'C', 'A', 'R', 'D', '_', 'P', 'I', 'N', '_', '9',
        'B', '1', 'X', 'Z', '!'
    };
    char reader_name[256];
    uint8_t atr[64];
    DWORD reader_name_len = sizeof(reader_name);
    DWORD atr_len = sizeof(atr);
    DWORD card_state = 0;
    DWORD protocol = 0;
    LONG status = SCARD_S_SUCCESS;

    status = rdp_smartcard_backend_connect(&fixture->backend,
                                           fixture->context,
                                           fixture->reader,
                                           SCARD_SHARE_SHARED,
                                           SCARD_PROTOCOL_T0 |
                                               SCARD_PROTOCOL_T1,
                                           &fixture->handle,
                                           &fixture->active_protocol);
    if (!smartcard_smoke_check(status == SCARD_S_SUCCESS,
                               "connect virtual PC/SC card",
                               __LINE__))
        return 0;
    fixture->connected = 1;
    memset(reader_name, 0, sizeof(reader_name));
    memset(atr, 0, sizeof(atr));
    status = rdp_smartcard_backend_status(&fixture->backend,
                                          fixture->handle,
                                          reader_name,
                                          &reader_name_len,
                                          &card_state,
                                          &protocol,
                                          atr,
                                          &atr_len);
    if (!smartcard_smoke_check(status == SCARD_S_SUCCESS &&
                                   reader_name_len > 1u &&
                                   atr_len > 0u &&
                                   protocol == fixture->active_protocol,
                               "query connected PC/SC card",
                               __LINE__))
        return 0;
    status = rdp_smartcard_backend_begin_transaction(&fixture->backend,
                                                     fixture->handle);
    if (!smartcard_smoke_check(status == SCARD_S_SUCCESS,
                               "begin PC/SC transaction",
                               __LINE__))
        return 0;
    fixture->transaction_active = 1;
    if (!smartcard_smoke_transmit(fixture,
                                  challenge,
                                  (DWORD)sizeof(challenge),
                                  1,
                                  0x90u,
                                  0x00u) ||
        !smartcard_smoke_transmit(fixture,
                                  apdu_canary,
                                  (DWORD)sizeof(apdu_canary),
                                  0,
                                  0x6au,
                                  0x82u) ||
        !smartcard_smoke_transmit(fixture,
                                  pin_canary,
                                  (DWORD)sizeof(pin_canary),
                                  0,
                                  0x63u,
                                  0x00u))
        return 0;
    status = rdp_smartcard_backend_end_transaction(&fixture->backend,
                                                   fixture->handle,
                                                   SCARD_LEAVE_CARD);
    if (!smartcard_smoke_check(status == SCARD_S_SUCCESS,
                               "end PC/SC transaction",
                               __LINE__))
        return 0;
    fixture->transaction_active = 0;
    status = rdp_smartcard_backend_reconnect(&fixture->backend,
                                             fixture->handle,
                                             SCARD_SHARE_SHARED,
                                             SCARD_PROTOCOL_T0 |
                                                 SCARD_PROTOCOL_T1,
                                             SCARD_RESET_CARD,
                                             &fixture->active_protocol);
    if (!smartcard_smoke_check(status == SCARD_S_SUCCESS,
                               "reconnect virtual PC/SC card",
                               __LINE__))
        return 0;
    status = rdp_smartcard_backend_disconnect(&fixture->backend,
                                              fixture->handle,
                                              SCARD_LEAVE_CARD);
    if (!smartcard_smoke_check(status == SCARD_S_SUCCESS,
                               "disconnect virtual PC/SC card",
                               __LINE__))
        return 0;
    fixture->connected = 0;
    return 1;
}

static int smartcard_smoke_lifecycle(const char* reader)
{
    smartcard_smoke_fixture fixture;
    SCARD_READERSTATE state;

    if (!smartcard_smoke_fixture_init(&fixture, reader))
    {
        smartcard_smoke_fixture_clear(&fixture);
        return 1;
    }
    SMOKE_CHECK(&fixture, smartcard_smoke_initial_state(&fixture, &state));
    SMOKE_CHECK(&fixture,
                (state.dwEventState & SCARD_STATE_PRESENT) != 0u);
    SMOKE_CHECK(&fixture,
                smartcard_smoke_timeout_and_cancel(&fixture, &state));
    SMOKE_CHECK(&fixture, smartcard_smoke_card_lifecycle(&fixture));
    smartcard_smoke_fixture_clear(&fixture);
    return 0;
}

static int smartcard_smoke_wait_removal(const char* reader)
{
    smartcard_smoke_fixture fixture;
    SCARD_READERSTATE state;
    LONG reconnect_status = SCARD_S_SUCCESS;

    if (!smartcard_smoke_fixture_init(&fixture, reader))
    {
        smartcard_smoke_fixture_clear(&fixture);
        return 1;
    }
    SMOKE_CHECK(&fixture, smartcard_smoke_initial_state(&fixture, &state));
    SMOKE_CHECK(&fixture,
                (state.dwEventState & SCARD_STATE_PRESENT) != 0u);
    SMOKE_CHECK(&fixture, smartcard_smoke_card_lifecycle(&fixture));
    SMOKE_CHECK(&fixture,
                rdp_smartcard_backend_connect(&fixture.backend,
                                              fixture.context,
                                              fixture.reader,
                                              SCARD_SHARE_SHARED,
                                              SCARD_PROTOCOL_T0 |
                                                  SCARD_PROTOCOL_T1,
                                              &fixture.handle,
                                              &fixture.active_protocol) ==
                    SCARD_S_SUCCESS);
    fixture.connected = 1;
    SMOKE_CHECK(&fixture, smartcard_smoke_initial_state(&fixture, &state));
    state.dwCurrentState =
        state.dwEventState & ~(DWORD)SCARD_STATE_CHANGED;
    puts("smartcard-smoke ready=removal");
    fflush(stdout);
    SMOKE_CHECK(&fixture,
                smartcard_smoke_read_state(&fixture,
                                           &state,
                                           SMARTCARD_SMOKE_WAIT_MS) ==
                    SCARD_S_SUCCESS);
    SMOKE_CHECK(&fixture,
                (state.dwEventState & SCARD_STATE_PRESENT) == 0u);
    reconnect_status = rdp_smartcard_backend_reconnect(
        &fixture.backend,
        fixture.handle,
        SCARD_SHARE_SHARED,
        SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
        SCARD_RESET_CARD,
        &fixture.active_protocol);
    SMOKE_CHECK(&fixture, reconnect_status != SCARD_S_SUCCESS);
    smartcard_smoke_fixture_clear(&fixture);
    return 0;
}

static int smartcard_smoke_wait_insertion(const char* reader)
{
    smartcard_smoke_fixture fixture;
    SCARD_READERSTATE state;

    if (!smartcard_smoke_fixture_init(&fixture, reader))
    {
        smartcard_smoke_fixture_clear(&fixture);
        return 1;
    }
    SMOKE_CHECK(&fixture, smartcard_smoke_initial_state(&fixture, &state));
    SMOKE_CHECK(&fixture,
                (state.dwEventState & SCARD_STATE_PRESENT) == 0u);
    state.dwCurrentState =
        state.dwEventState & ~(DWORD)SCARD_STATE_CHANGED;
    puts("smartcard-smoke ready=insertion");
    fflush(stdout);
    SMOKE_CHECK(&fixture,
                smartcard_smoke_read_state(&fixture,
                                           &state,
                                           SMARTCARD_SMOKE_WAIT_MS) ==
                    SCARD_S_SUCCESS);
    SMOKE_CHECK(&fixture,
                (state.dwEventState & SCARD_STATE_PRESENT) != 0u);
    SMOKE_CHECK(&fixture, smartcard_smoke_card_lifecycle(&fixture));
    smartcard_smoke_fixture_clear(&fixture);
    return 0;
}

int main(int argc, char** argv)
{
    const char* reader = getenv("LIBRDP_TEST_PCSC_READER");
    const char* mode = argc > 1 ? argv[1] : "lifecycle";

    if (!reader || reader[0] == '\0')
    {
        fputs("smartcard PC/SC smoke skipped: LIBRDP_TEST_PCSC_READER is unset\n",
              stderr);
        return SMARTCARD_SMOKE_SKIP;
    }
    if (strcmp(mode, "lifecycle") == 0)
        return smartcard_smoke_lifecycle(reader);
    if (strcmp(mode, "wait-removal") == 0)
        return smartcard_smoke_wait_removal(reader);
    if (strcmp(mode, "wait-insertion") == 0)
        return smartcard_smoke_wait_insertion(reader);
    fprintf(stderr, "usage: %s [lifecycle|wait-removal|wait-insertion]\n", argv[0]);
    return 2;
}
