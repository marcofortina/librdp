/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic allocation fault points for in-process tests.
 * Invariants: a configured point fails once after the requested number of hits.
 * Ownership: the process-local state contains no dynamic resources.
 * Threading: arming, reset, and consumption are atomic across worker threads.
 * Trust boundary: production builds compile each check to a constant false expression.
 */

#ifndef RDP_COMMON_FAULT_INJECTION_H
#define RDP_COMMON_FAULT_INJECTION_H

#include <stdint.h>

typedef enum rdp_fault_point
{
    RDP_FAULT_NONE = 0,
    RDP_FAULT_SETTINGS_CLONE = 1,
    RDP_FAULT_CONNECT_ALLOCATION = 2,
    RDP_FAULT_CHANNEL_OPEN_ALLOCATION = 3,
    RDP_FAULT_DECODER_ALLOCATION = 4,
    RDP_FAULT_BACKEND_STARTUP = 5
} rdp_fault_point;

#ifdef RDP_ENABLE_TEST_FAULTS
void rdp_fault_injection_arm(rdp_fault_point point, uint32_t successful_hits);
void rdp_fault_injection_reset(void);
int rdp_fault_injection_hit(rdp_fault_point point);
#else
static inline int rdp_fault_injection_hit(rdp_fault_point point)
{
    (void)point;
    return 0;
}
#endif

#endif
