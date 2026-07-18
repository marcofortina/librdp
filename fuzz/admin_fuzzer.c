/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for administration session inventory XML parsing.
 * Coverage: loads arbitrary bounded SOAP/XML into the public admin parser and
 * queries every normalized session produced by successful inputs.
 * Bug classes: malformed XML, namespace confusion, numeric overflow, session
 * count limits, allocation cleanup, and borrowed session lifetime.
 * Determinism: no WinRM request, network endpoint, credential, filesystem, or
 * clock is used by the fuzz entrypoint.
 */

#include <librdp/librdp.h>

#include <stddef.h>
#include <stdint.h>

#define LIBRDP_ADMIN_FUZZ_LIMIT 1048576u

/*
 * Fuzz target: passes one bounded response through administration inventory
 * normalization and exercises session views only when parsing succeeds.
 * Bug classes: XML parser bounds, malformed SOAP records, numeric conversion,
 * session indexing, and cleanup after partial documents.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    librdp_admin_config config;
    librdp_admin* admin = NULL;
    size_t index = 0;
    size_t count = 0;

    if (!data || size == 0 || size > LIBRDP_ADMIN_FUZZ_LIMIT)
        return 0;
    if (librdp_admin_config_init(&config) != LIBRDP_STATUS_OK)
        return 0;
    admin = librdp_admin_new(&config);
    if (!admin)
        return 0;
    if (librdp_admin_load_sessions_xml(admin, data, size) == LIBRDP_STATUS_OK)
    {
        count = librdp_admin_session_count(admin);
        for (index = 0; index < count; index++)
        {
            librdp_admin_session session;

            if (librdp_admin_session_init(&session) != LIBRDP_STATUS_OK)
                break;
            (void)librdp_admin_session_at(admin, index, &session);
        }
    }
    librdp_admin_free(admin);
    return 0;
}
