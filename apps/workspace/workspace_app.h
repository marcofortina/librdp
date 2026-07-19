/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: platform-neutral workspace application lifecycle.
 * Invariants: feed resources are queried and validated before native code sees
 * them, and process launch always consumes a shell-free launch plan.
 * Ownership: the lifecycle owns the workspace handle; callbacks borrow options
 * and resources only for their call duration.
 * Threading: startup, presentation and launch callbacks run serially on the
 * caller's native UI thread.
 * Trust boundary: feed metadata and embedded RDP fields remain untrusted until
 * workspace option helpers have bounded and normalized them.
 */

#ifndef LIBRDP_APPS_WORKSPACE_APP_H
#define LIBRDP_APPS_WORKSPACE_APP_H

#include "workspace_options.h"

typedef int (*workspace_app_launch_callback)(
  const workspace_options* options,
  const librdp_workspace_resource* resource,
  void* user_data);

typedef int (*workspace_app_present_callback)(
  const workspace_options* options,
  const librdp_workspace* workspace,
  size_t selected,
  workspace_app_launch_callback launch,
  void* user_data);

typedef struct workspace_app_platform
{
    workspace_app_launch_callback launch;
    workspace_app_present_callback present;
    void* user_data;
} workspace_app_platform;

int workspace_app_run(int argc,
                      char** argv,
                      const char* default_viewer,
                      const workspace_app_platform* platform);

#endif
