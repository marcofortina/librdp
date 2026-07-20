/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: atomic state exchange for cooperating integration-test processes.
 * Invariant: readers observe either the previous complete record or the next
 * complete record, never a partially written port/stage pair.
 */

#ifndef LIBRDP_TEST_PROCESS_STATE_H
#define LIBRDP_TEST_PROCESS_STATE_H

#include <stdint.h>

int test_process_state_write(const char* path,
                             uint16_t port,
                             uint32_t stage);
int test_process_state_read(const char* path,
                            uint16_t* port,
                            uint32_t* stage);

#endif
