/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for standard security client-info and certificate parser
 * paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "security/security.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises standard security client-info and certificate parser
 * paths with one arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_client_info_summary summary;
    rdp_security_public_key public_key;

    (void)rdp_security_parse_client_info_pdu(data, size, &summary);
    (void)rdp_security_parse_server_certificate(data, size, &public_key);
    return 0;
}
