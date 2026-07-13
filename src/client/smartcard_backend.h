/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal smartcard provider boundary for redirected PC/SC calls.
 * Invariants: session dispatch never calls a potentially blocking provider
 * operation without a backend timeout, and provider-owned buffers never escape
 * the call that produced them.
 * Ownership: callers own all input/output buffers; backend contexts and card
 * handles remain provider values until the session stores them.
 * Threading: backend objects are owned by one session, while timeout workers
 * may call provider operations concurrently with cancellation.
 * Trust boundary: remote IOCTL payloads are validated by the session before
 * this backend sees native provider handles or buffer lengths.
 */

#ifndef RDP_CLIENT_SMARTCARD_BACKEND_H
#define RDP_CLIENT_SMARTCARD_BACKEND_H

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#ifdef RDP_HAVE_PCSC
#include <winscard.h>
#else
typedef long LONG;
typedef unsigned long DWORD;
typedef uintptr_t SCARDCONTEXT;
typedef uintptr_t SCARDHANDLE;
typedef struct
{
    DWORD dwProtocol;
    DWORD cbPciLength;
} SCARD_IO_REQUEST;
typedef struct
{
    const char* szReader;
    void* pvUserData;
    DWORD dwCurrentState;
    DWORD dwEventState;
    DWORD cbAtr;
    unsigned char rgbAtr[36];
} SCARD_READERSTATE;
#ifndef SCARD_S_SUCCESS
#define SCARD_S_SUCCESS ((LONG)0x00000000L)
#endif
#ifndef SCARD_E_CANCELLED
#define SCARD_E_CANCELLED ((LONG)0x80100002L)
#endif
#ifndef SCARD_E_INVALID_HANDLE
#define SCARD_E_INVALID_HANDLE ((LONG)0x80100003L)
#endif
#ifndef SCARD_E_INVALID_PARAMETER
#define SCARD_E_INVALID_PARAMETER ((LONG)0x80100004L)
#endif
#ifndef SCARD_E_NO_MEMORY
#define SCARD_E_NO_MEMORY ((LONG)0x80100006L)
#endif
#ifndef SCARD_E_TIMEOUT
#define SCARD_E_TIMEOUT ((LONG)0x8010000AL)
#endif
#ifndef SCARD_E_NO_SERVICE
#define SCARD_E_NO_SERVICE ((LONG)0x8010001DL)
#endif
#ifndef SCARD_E_UNSUPPORTED_FEATURE
#define SCARD_E_UNSUPPORTED_FEATURE ((LONG)0x8010001FL)
#endif
#endif

#define RDP_SMARTCARD_BACKEND_DEFAULT_TIMEOUT_MS 5000u

typedef enum rdp_smartcard_backend_kind
{
    RDP_SMARTCARD_BACKEND_KIND_NONE = 0,
    RDP_SMARTCARD_BACKEND_KIND_PCSC = 1,
    RDP_SMARTCARD_BACKEND_KIND_MOCK = 2
} rdp_smartcard_backend_kind;

typedef struct rdp_smartcard_backend rdp_smartcard_backend;

typedef struct rdp_smartcard_mock_backend
{
    LONG establish_status;
    LONG release_status;
    LONG valid_status;
    LONG cancel_status;
    LONG connect_status;
    LONG disconnect_status;
    LONG reconnect_status;
    LONG status_status;
    LONG status_change_status;
    LONG transmit_status;
    LONG control_status;
    LONG attrib_status;
    SCARDCONTEXT next_context;
    SCARDHANDLE next_handle;
    DWORD next_protocol;
    DWORD next_state;
    uint8_t atr[36];
    DWORD atr_len;
    uint8_t transmit_response[258];
    DWORD transmit_response_len;
    uint32_t hang_connect_ms;
    uint32_t hang_status_change_ms;
    uint32_t hang_transmit_ms;
    atomic_uint cancel_calls;
    atomic_uint connect_calls;
    atomic_uint disconnect_calls;
    atomic_uint status_change_calls;
    atomic_uint transmit_calls;
    atomic_uint cancelled;
} rdp_smartcard_mock_backend;

typedef struct rdp_smartcard_backend_ops
{
    LONG (*establish_context)(void* user_data, DWORD scope, SCARDCONTEXT* context);
    LONG (*release_context)(void* user_data, SCARDCONTEXT context);
    LONG (*is_valid_context)(void* user_data, SCARDCONTEXT context);
    LONG (*cancel)(void* user_data, SCARDCONTEXT context);
    LONG (*list_reader_groups)(void* user_data, SCARDCONTEXT context, char* groups, DWORD* groups_len);
    LONG (*list_readers)(void* user_data, SCARDCONTEXT context, const char* groups, char* readers, DWORD* readers_len);
    LONG (*get_status_change)(void* user_data, SCARDCONTEXT context, DWORD timeout, SCARD_READERSTATE* readers, DWORD count);
    LONG (*begin_transaction)(void* user_data, SCARDHANDLE handle);
    LONG (*connect)(void* user_data,
                    SCARDCONTEXT context,
                    const char* reader,
                    DWORD share_mode,
                    DWORD preferred_protocols,
                    SCARDHANDLE* handle,
                    DWORD* active_protocol);
    LONG (*disconnect)(void* user_data, SCARDHANDLE handle, DWORD disposition);
    LONG (*end_transaction)(void* user_data, SCARDHANDLE handle, DWORD disposition);
    LONG (*reconnect)(void* user_data,
                      SCARDHANDLE handle,
                      DWORD share_mode,
                      DWORD preferred_protocols,
                      DWORD initialization,
                      DWORD* active_protocol);
    LONG (*status)(void* user_data,
                   SCARDHANDLE handle,
                   char* reader_names,
                   DWORD* reader_names_len,
                   DWORD* state,
                   DWORD* protocol,
                   uint8_t* atr,
                   DWORD* atr_len);
    LONG (*transmit)(void* user_data,
                     SCARDHANDLE handle,
                     const SCARD_IO_REQUEST* send_pci,
                     const uint8_t* send_data,
                     DWORD send_len,
                     SCARD_IO_REQUEST* recv_pci,
                     uint8_t* recv_data,
                     DWORD* recv_len);
    LONG (*control)(void* user_data,
                    SCARDHANDLE handle,
                    DWORD control_code,
                    const uint8_t* input,
                    DWORD input_len,
                    uint8_t* output,
                    DWORD output_len,
                    DWORD* bytes_returned);
    LONG (*get_attrib)(void* user_data, SCARDHANDLE handle, DWORD attr_id, uint8_t* attr, DWORD* attr_len);
    LONG (*set_attrib)(void* user_data, SCARDHANDLE handle, DWORD attr_id, const uint8_t* attr, DWORD attr_len);
} rdp_smartcard_backend_ops;

struct rdp_smartcard_backend
{
    rdp_smartcard_backend_kind kind;
    const rdp_smartcard_backend_ops* ops;
    void* user_data;
    uint32_t timeout_ms;
};

void rdp_smartcard_backend_init_none(rdp_smartcard_backend* backend);
void rdp_smartcard_backend_init_pcsc(rdp_smartcard_backend* backend);
void rdp_smartcard_mock_backend_init(rdp_smartcard_mock_backend* mock);
void rdp_smartcard_backend_init_mock(rdp_smartcard_backend* backend, rdp_smartcard_mock_backend* mock);
void rdp_smartcard_backend_set_timeout(rdp_smartcard_backend* backend, uint32_t timeout_ms);

LONG rdp_smartcard_backend_establish_context(rdp_smartcard_backend* backend, DWORD scope, SCARDCONTEXT* context);
LONG rdp_smartcard_backend_release_context(rdp_smartcard_backend* backend, SCARDCONTEXT context);
LONG rdp_smartcard_backend_is_valid_context(rdp_smartcard_backend* backend, SCARDCONTEXT context);
LONG rdp_smartcard_backend_cancel(rdp_smartcard_backend* backend, SCARDCONTEXT context);
LONG rdp_smartcard_backend_list_reader_groups(rdp_smartcard_backend* backend,
                                              SCARDCONTEXT context,
                                              char* groups,
                                              DWORD* groups_len);
LONG rdp_smartcard_backend_list_readers(rdp_smartcard_backend* backend,
                                        SCARDCONTEXT context,
                                        const char* groups,
                                        char* readers,
                                        DWORD* readers_len);
LONG rdp_smartcard_backend_get_status_change(rdp_smartcard_backend* backend,
                                             SCARDCONTEXT context,
                                             DWORD timeout,
                                             SCARD_READERSTATE* readers,
                                             DWORD count);
LONG rdp_smartcard_backend_begin_transaction(rdp_smartcard_backend* backend, SCARDHANDLE handle);
LONG rdp_smartcard_backend_connect(rdp_smartcard_backend* backend,
                                   SCARDCONTEXT context,
                                   const char* reader,
                                   DWORD share_mode,
                                   DWORD preferred_protocols,
                                   SCARDHANDLE* handle,
                                   DWORD* active_protocol);
LONG rdp_smartcard_backend_disconnect(rdp_smartcard_backend* backend, SCARDHANDLE handle, DWORD disposition);
LONG rdp_smartcard_backend_end_transaction(rdp_smartcard_backend* backend, SCARDHANDLE handle, DWORD disposition);
LONG rdp_smartcard_backend_reconnect(rdp_smartcard_backend* backend,
                                     SCARDHANDLE handle,
                                     DWORD share_mode,
                                     DWORD preferred_protocols,
                                     DWORD initialization,
                                     DWORD* active_protocol);
LONG rdp_smartcard_backend_status(rdp_smartcard_backend* backend,
                                  SCARDHANDLE handle,
                                  char* reader_names,
                                  DWORD* reader_names_len,
                                  DWORD* state,
                                  DWORD* protocol,
                                  uint8_t* atr,
                                  DWORD* atr_len);
LONG rdp_smartcard_backend_transmit(rdp_smartcard_backend* backend,
                                    SCARDCONTEXT context,
                                    SCARDHANDLE handle,
                                    const SCARD_IO_REQUEST* send_pci,
                                    const uint8_t* send_data,
                                    DWORD send_len,
                                    SCARD_IO_REQUEST* recv_pci,
                                    uint8_t* recv_data,
                                    DWORD* recv_len);
LONG rdp_smartcard_backend_control(rdp_smartcard_backend* backend,
                                   SCARDHANDLE handle,
                                   DWORD control_code,
                                   const uint8_t* input,
                                   DWORD input_len,
                                   uint8_t* output,
                                   DWORD output_len,
                                   DWORD* bytes_returned);
LONG rdp_smartcard_backend_get_attrib(rdp_smartcard_backend* backend,
                                      SCARDHANDLE handle,
                                      DWORD attr_id,
                                      uint8_t* attr,
                                      DWORD* attr_len);
LONG rdp_smartcard_backend_set_attrib(rdp_smartcard_backend* backend,
                                      SCARDHANDLE handle,
                                      DWORD attr_id,
                                      const uint8_t* attr,
                                      DWORD attr_len);

#endif
