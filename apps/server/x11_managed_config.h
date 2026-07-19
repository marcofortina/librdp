/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: managed X11 broker configuration contract.
 * Invariants: configuration files and values are bounded, unknown or
 * duplicate scalar keys are rejected and no credential key is accepted.
 * Ownership: parsed values are copied into the caller-owned policy.
 * Threading: configuration is loaded during single-threaded startup.
 * Trust boundary: file ownership, mode, syntax and every policy value are
 * checked before the privileged broker allocates resources.
 */

#ifndef LIBRDP_X11_SERVER_MANAGED_CONFIG_H
#define LIBRDP_X11_SERVER_MANAGED_CONFIG_H

#include "x11_managed_policy.h"

#include <librdp/librdp.h>

#include <stddef.h>
#include <stdint.h>

#define X11_MANAGED_CONFIG_ERROR_VERSION 1u
#define X11_MANAGED_CONFIG_KEY_BYTES 64u
#define X11_MANAGED_CONFIG_DETAIL_BYTES 128u

typedef struct x11_managed_config_error
{
    uint32_t version;
    size_t size;
    uint32_t line;
    char key[X11_MANAGED_CONFIG_KEY_BYTES];
    char detail[X11_MANAGED_CONFIG_DETAIL_BYTES];
} x11_managed_config_error;

void x11_managed_config_error_init(
    x11_managed_config_error* error);
librdp_status x11_managed_config_apply(
    x11_managed_policy* policy,
    const char* key,
    const char* value,
    x11_managed_config_error* error);
librdp_status x11_managed_config_load(
    const char* path,
    x11_managed_policy* policy,
    x11_managed_config_error* error);

#endif
