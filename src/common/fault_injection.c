/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic allocation fault-point state used by sanitizer smoke tests.
 * Invariants: only one point is armed per process and at most one caller consumes it.
 * Ownership: state contains no pointers and allocates no memory.
 * Threading: lock-free atomic transitions permit worker-boundary injection.
 * Trust boundary: only test binaries can arm a point; production checks are disabled.
 */

#include "common/fault_injection.h"

#ifdef RDP_ENABLE_TEST_FAULTS

#include <stdatomic.h>

static atomic_uint rdp_fault_active = ATOMIC_VAR_INIT(RDP_FAULT_NONE);
static atomic_uint rdp_fault_successful_hits = ATOMIC_VAR_INIT(0u);

void rdp_fault_injection_arm(rdp_fault_point point, uint32_t successful_hits)
{
    atomic_store_explicit(&rdp_fault_successful_hits,
                          successful_hits,
                          memory_order_relaxed);
    atomic_store_explicit(&rdp_fault_active,
                          (unsigned)point,
                          memory_order_release);
}

void rdp_fault_injection_reset(void)
{
    atomic_store_explicit(&rdp_fault_active,
                          (unsigned)RDP_FAULT_NONE,
                          memory_order_release);
    atomic_store_explicit(&rdp_fault_successful_hits,
                          0u,
                          memory_order_relaxed);
}

/*
 * Consume one matching point after its successful-hit countdown. The compare
 * exchange on the active point ensures concurrent callers cannot both fail.
 */
int rdp_fault_injection_hit(rdp_fault_point point)
{
    unsigned remaining = 0u;
    unsigned expected = (unsigned)point;

    if (point == RDP_FAULT_NONE ||
        atomic_load_explicit(&rdp_fault_active, memory_order_acquire) !=
            (unsigned)point)
        return 0;
    remaining = atomic_load_explicit(&rdp_fault_successful_hits,
                                     memory_order_relaxed);
    while (remaining > 0u)
    {
        if (atomic_compare_exchange_weak_explicit(
                &rdp_fault_successful_hits,
                &remaining,
                remaining - 1u,
                memory_order_relaxed,
                memory_order_relaxed))
            return 0;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &rdp_fault_active,
            &expected,
            (unsigned)RDP_FAULT_NONE,
            memory_order_acq_rel,
            memory_order_acquire))
        return 0;
    return 1;
}

#endif
