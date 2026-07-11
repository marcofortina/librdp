/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "security/security.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_client_info_summary summary;
    rdp_security_public_key public_key;

    (void)rdp_security_parse_client_info_pdu(data, size, &summary);
    (void)rdp_security_parse_server_certificate(data, size, &public_key);
    return 0;
}
