/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal printer backend boundary.
 * Invariants: protocol code passes validated printer settings and spool paths;
 * backend code owns native spooler calls and maps failures to RDPDR statuses.
 * Ownership: all strings are caller-owned and borrowed only for the call.
 * Threading: functions are synchronous until the generic backend worker is
 * introduced; callers must not invoke them from concurrent session threads.
 * Trust boundary: remote print data reaches this layer only after being written
 * to a bounded local spool file.
 */

#ifndef RDP_CLIENT_PRINTER_BACKEND_H
#define RDP_CLIENT_PRINTER_BACKEND_H

#include <stdint.h>

int rdp_printer_backend_output_is_cups(const char* output);
uint32_t rdp_printer_backend_validate_cups(const char* output);
uint32_t rdp_printer_backend_submit_cups(uint32_t printer_index,
                                         const char* output,
                                         const char* title,
                                         const char* path);
uint32_t rdp_printer_backend_submit_cups_async(uint32_t printer_index,
                                               const char* output,
                                               const char* title,
                                               const char* path,
                                               int unlink_spool);

#endif
