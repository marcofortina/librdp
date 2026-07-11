/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "protocol/x224.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_x224_connection_confirm confirm;
    (void)rdp_x224_parse_connection_confirm(data, size, &confirm);
    return 0;
}
