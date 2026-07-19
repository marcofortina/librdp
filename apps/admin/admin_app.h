/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: platform-neutral administration application lifecycle.
 * Invariants: command-line policy is validated before network activity and
 * native presentation receives only a live, fully queried admin handle.
 * Ownership: the lifecycle owns the admin handle; native callbacks borrow it
 * for the duration of the call and must not retain session field pointers.
 * Threading: the caller serializes startup and presentation on its UI thread.
 * Trust boundary: remote inventory is printed only after the public parser has
 * bounded and normalized every exposed field.
 */

#ifndef LIBRDP_APPS_ADMIN_APP_H
#define LIBRDP_APPS_ADMIN_APP_H

#include <librdp/librdp.h>

typedef int (*admin_app_present_callback)(const librdp_admin* admin,
                                          void* user_data);

typedef struct admin_app_platform
{
    admin_app_present_callback present;
    void* user_data;
} admin_app_platform;

int admin_app_run(int argc,
                  char** argv,
                  const admin_app_platform* platform);

#endif
