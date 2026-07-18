/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for workspace feed XML parsing.
 * Coverage: loads arbitrary bounded XML into the public workspace parser and
 * queries every normalized resource produced by successful inputs.
 * Bug classes: malformed XML, nested element depth, entity expansion limits,
 * resource count overflow, and borrowed resource lifetime.
 * Determinism: no feed request, network endpoint, credential, filesystem, or
 * clock is used by the fuzz entrypoint.
 */

#include <librdp/librdp.h>

#include <stddef.h>
#include <stdint.h>

#define LIBRDP_WORKSPACE_FUZZ_LIMIT 1048576u

/*
 * Fuzz target: passes one bounded document through workspace normalization and
 * exercises resource views only when parsing succeeds.
 * Bug classes: XML parser bounds, malformed feed records, allocation cleanup,
 * resource indexing, and invalid borrowed-view metadata.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    librdp_workspace_config config;
    librdp_workspace* workspace = NULL;
    size_t index = 0;
    size_t count = 0;

    if (!data || size == 0 || size > LIBRDP_WORKSPACE_FUZZ_LIMIT)
        return 0;
    if (librdp_workspace_config_init(&config) != LIBRDP_STATUS_OK)
        return 0;
    workspace = librdp_workspace_new(&config);
    if (!workspace)
        return 0;
    if (librdp_workspace_load_xml(workspace, data, size) == LIBRDP_STATUS_OK)
    {
        count = librdp_workspace_resource_count(workspace);
        for (index = 0; index < count; index++)
        {
            librdp_workspace_resource resource;

            if (librdp_workspace_resource_init(&resource) != LIBRDP_STATUS_OK)
                break;
            (void)librdp_workspace_resource_at(workspace, index, &resource);
        }
    }
    librdp_workspace_free(workspace);
    return 0;
}
