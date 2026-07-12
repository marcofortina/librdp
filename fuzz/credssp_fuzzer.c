/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for CredSSP TSRequest and NTLM challenge parser paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "nla/credssp.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises CredSSP TSRequest and NTLM challenge parser paths
 * with one arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_credssp_ts_request request;
    rdp_ntlm_challenge challenge;
    const uint8_t* ntlm = NULL;
    size_t ntlm_len = 0;

    (void)rdp_credssp_parse_ts_request(data, size, &request);
    (void)rdp_credssp_parse_ntlm_challenge(data, size, &challenge);
    if (rdp_credssp_extract_ntlm_challenge(data, size, &ntlm, &ntlm_len) == LIBRDP_STATUS_OK)
        (void)rdp_credssp_parse_ntlm_challenge(ntlm, ntlm_len, &challenge);
    return 0;
}
