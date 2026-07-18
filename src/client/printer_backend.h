/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal printer backend boundary.
 * Invariants: protocol code passes validated printer settings and spool paths;
 * backend code owns native spooler calls and maps failures to RDPDR statuses.
 * Ownership: queued jobs copy all strings and own optional spool cleanup until
 * a completion is consumed or the backend is drained.
 * Threading: submission and completion dispatch run on the session owner
 * thread; managed joinable workers execute provider operations.
 * Trust boundary: remote print data reaches this layer only after being written
 * to a bounded local spool file.
 */

#ifndef RDP_CLIENT_PRINTER_BACKEND_H
#define RDP_CLIENT_PRINTER_BACKEND_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

typedef struct rdp_printer_backend_runtime rdp_printer_backend_runtime;

typedef struct rdp_printer_backend
{
    rdp_printer_backend_runtime* runtime;
} rdp_printer_backend;

typedef struct rdp_printer_backend_completion
{
    uint32_t printer_index;
    uint32_t status;
    int cancelled;
} rdp_printer_backend_completion;

typedef struct rdp_printer_backend_mock
{
    uint32_t submit_status;
    uint32_t submit_delay_ms;
    atomic_uint submit_calls;
    atomic_uint active_calls;
    atomic_uint cancellation_observed;
} rdp_printer_backend_mock;

typedef void (*rdp_printer_backend_notify_fn)(void* user_data);

int rdp_printer_backend_output_is_cups(const char* output);
uint32_t rdp_printer_backend_validate_cups(const char* output);
void rdp_printer_backend_init_cups(rdp_printer_backend* backend);
void rdp_printer_backend_mock_init(rdp_printer_backend_mock* mock);
void rdp_printer_backend_init_mock(rdp_printer_backend* backend,
                                   rdp_printer_backend_mock* mock);
void rdp_printer_backend_set_notify(rdp_printer_backend* backend,
                                    rdp_printer_backend_notify_fn notify,
                                    void* user_data);
uint32_t rdp_printer_backend_submit_async(rdp_printer_backend* backend,
                                          uint32_t printer_index,
                                          const char* output,
                                          const char* title,
                                          const char* path,
                                          int unlink_spool);
int rdp_printer_backend_take_completion(rdp_printer_backend* backend,
                                        rdp_printer_backend_completion* completion);
void rdp_printer_backend_drain(rdp_printer_backend* backend);
void rdp_printer_backend_clear(rdp_printer_backend* backend);

#endif
