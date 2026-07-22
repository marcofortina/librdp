/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: thread-scoped SIGPIPE containment for Unix-like platforms.
 * Invariants: the caller's signal mask and pre-existing pending signal state
 * are preserved exactly across a guarded operation.
 * Ownership: guard state is caller-owned stack storage.
 * Threading: each guard affects only the calling thread.
 * Trust boundary: disconnected peers become ordinary I/O failures.
 */

#ifndef RDP_PLATFORM_SIGPIPE_H
#define RDP_PLATFORM_SIGPIPE_H

#include <signal.h>

typedef struct rdp_sigpipe_guard
{
    sigset_t signals;
    sigset_t previous_mask;
    int pending_before;
    int active;
} rdp_sigpipe_guard;

int rdp_sigpipe_guard_begin(rdp_sigpipe_guard* guard);
void rdp_sigpipe_guard_end(rdp_sigpipe_guard* guard);

#endif
