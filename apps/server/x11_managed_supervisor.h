/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: per-session managed X11 supervisor contract.
 * Invariants: one supervisor owns one authentication session, X process group
 * and unprivileged RDP agent; credentials are retained only until agent startup.
 * Ownership: run() consumes no configuration storage and closes its inherited
 * broker descriptor before returning.
 * Threading: the supervisor is a single-threaded child process.
 * Trust boundary: broker policy supplies executable paths and session
 * resources, while kernel credentials authenticate every reconnecting broker.
 */

#ifndef LIBRDP_X11_SERVER_MANAGED_SUPERVISOR_H
#define LIBRDP_X11_SERVER_MANAGED_SUPERVISOR_H

#include "x11_managed_auth.h"

#include <librdp/librdp.h>

#include <stddef.h>
#include <stdint.h>

#define X11_MANAGED_SUPERVISOR_VERSION 1u

typedef struct x11_managed_supervisor_config
{
    uint32_t version;
    size_t size;
    x11_managed_auth_config authentication;
    const char* agent_path;
    int authentication_timeout_ms;
    int startup_timeout_ms;
    int command_timeout_ms;
    int shutdown_timeout_ms;
} x11_managed_supervisor_config;

void x11_managed_supervisor_config_init(
    x11_managed_supervisor_config* config);
librdp_status x11_managed_supervisor_run(
    int broker_descriptor,
    const x11_managed_supervisor_config* config);

#endif
