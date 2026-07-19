/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared workspace fetch, selection and launch orchestration.
 * Invariants: a feed generation remains stable while its borrowed resource
 * views are printed or passed to native callbacks, and ambiguous selections
 * never launch a viewer.
 * Ownership: this module creates and frees the workspace handle; callbacks do
 * not retain options, resources, or workspace-owned strings.
 * Threading: synchronous and single-threaded; native callbacks execute on the
 * thread that called workspace_app_run().
 * Trust boundary: remote metadata is emitted or launched only through bounded
 * public views and the fixed viewer argument vocabulary.
 */

#include "workspace_app.h"

#include <stdio.h>

static void workspace_app_print_resource(
  size_t index,
  const librdp_workspace_resource* resource)
{
    char target[WORKSPACE_FIELD_CAPACITY];
    char remote_app[WORKSPACE_FIELD_CAPACITY];
    char gateway[WORKSPACE_FIELD_CAPACITY];

    target[0] = '\0';
    remote_app[0] = '\0';
    gateway[0] = '\0';
    (void)workspace_resource_target(resource, target, sizeof(target));
    (void)workspace_resource_remote_app(resource,
                                        remote_app,
                                        sizeof(remote_app));
    (void)workspace_resource_gateway(resource, gateway, sizeof(gateway));
    printf("resource index=%zu type=%s id=\"%s\" alias=\"%s\" "
           "title=\"%s\" target=\"%s\" app=\"%s\" gateway=\"%s\"\n",
           index,
           workspace_resource_type_name(resource->type),
           resource->id ? resource->id : "",
           resource->alias ? resource->alias : "",
           resource->title ? resource->title : "",
           target,
           remote_app,
           gateway);
}

/*
 * Print the current feed generation while consuming each borrowed resource
 * view immediately. Any malformed view aborts the listing before native
 * presentation can observe an inconsistent inventory.
 */
static int workspace_app_print_resources(
  const librdp_workspace* workspace)
{
    size_t count = librdp_workspace_resource_count(workspace);
    size_t index = 0;

    printf("resources count=%zu\n", count);
    for (index = 0; index < count; index++)
    {
        librdp_workspace_resource resource;

        if (librdp_workspace_resource_init(&resource) != LIBRDP_STATUS_OK ||
            librdp_workspace_resource_at(workspace, index, &resource) !=
              LIBRDP_STATUS_OK)
            return 0;
        workspace_app_print_resource(index, &resource);
    }
    return 1;
}

/*
 * Execute common workspace startup and choose exactly one launch path. Native
 * adapters receive either a selected resource for direct launch or a stable
 * feed snapshot for presentation, never raw feed bytes.
 */
int workspace_app_run(int argc,
                      char** argv,
                      const char* default_viewer,
                      const workspace_app_platform* platform)
{
    workspace_options options;
    librdp_workspace* workspace = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t selected = 0;
    int have_selection = 0;
    int result = 0;

    if (!platform || !platform->launch || !platform->present)
        return 2;
    if (!workspace_options_parse(argc,
                                 argv,
                                 default_viewer,
                                 &options,
                                 stderr))
    {
        workspace_options_usage(stderr,
                                argc > 0 && argv ? argv[0] : NULL);
        return 2;
    }
    if (options.show_help)
    {
        workspace_options_usage(stdout, argv[0]);
        return 0;
    }
    workspace = librdp_workspace_new(&options.config);
    if (!workspace)
    {
        fprintf(stderr, "failed to create workspace handle\n");
        return 2;
    }
    status = librdp_workspace_fetch(workspace);
    if (status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr,
                "workspace fetch failed: %s\n",
                librdp_status_name(status));
        result = 3;
    }
    else if (!workspace_app_print_resources(workspace))
        result = 3;
    else
    {
        if (options.select ||
            librdp_workspace_resource_count(workspace) == 1u)
        {
            have_selection = workspace_select_resource(workspace,
                                                       options.select,
                                                       &selected,
                                                       stderr);
        }
        if (options.launch)
        {
            librdp_workspace_resource resource;

            if (!have_selection ||
                librdp_workspace_resource_init(&resource) !=
                  LIBRDP_STATUS_OK ||
                librdp_workspace_resource_at(workspace,
                                             selected,
                                             &resource) !=
                  LIBRDP_STATUS_OK ||
                !platform->launch(&options,
                                  &resource,
                                  platform->user_data))
                result = 4;
        }
        else if (!options.no_window &&
                 !platform->present(&options,
                                    workspace,
                                    selected,
                                    platform->launch,
                                    platform->user_data))
            result = 4;
    }
    librdp_workspace_free(workspace);
    return result;
}
