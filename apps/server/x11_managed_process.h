/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: process and virtual-display lifecycle for managed X11 sessions.
 * Invariants: X server and desktop share one process group, run as the
 * authenticated identity and receive only a bounded allowlisted environment.
 * Ownership: a process group owns generated Xauthority/configuration files and
 * child PIDs until x11_managed_process_stop() completes.
 * Threading: one supervisor process owns each group.
 * Trust boundary: command lines are parsed without a shell, privilege changes
 * happen before exec, and inherited descriptors are closed unless requested.
 */

#ifndef LIBRDP_X11_SERVER_MANAGED_PROCESS_H
#define LIBRDP_X11_SERVER_MANAGED_PROCESS_H

#include "x11_managed_auth.h"

#include <librdp/librdp.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define X11_MANAGED_PROCESS_VERSION 1u
#define X11_MANAGED_PROCESS_MAX_ARGUMENTS 64u
#define X11_MANAGED_PROCESS_MAX_JOINED 8u
#define X11_MANAGED_PROCESS_ENVIRONMENT_ALLOWLIST_BYTES 2048u

typedef struct x11_managed_process_config
{
    uint32_t version;
    size_t size;
    const x11_managed_auth_identity* identity;
    const char* const* login_environment;
    size_t login_environment_count;
    const char* environment_allowlist;
    const char* display_name;
    const char* authority_path;
    const char* runtime_directory;
    const char* xserver_path;
    const char* desktop_command;
    uint32_t width;
    uint32_t height;
    int use_xvfb;
    int startup_timeout_ms;
} x11_managed_process_config;

typedef struct x11_managed_process_group
{
    uint32_t version;
    size_t size;
    pid_t process_group;
    pid_t xserver_pid;
    pid_t desktop_pid;
    pid_t joined_pids[X11_MANAGED_PROCESS_MAX_JOINED];
    size_t joined_count;
    char display_name[64];
    char authority_path[4096];
    char xorg_config_path[4096];
} x11_managed_process_group;

void x11_managed_process_config_init(
    x11_managed_process_config* config);
void x11_managed_process_group_init(
    x11_managed_process_group* group);
librdp_status x11_managed_process_start(
    const x11_managed_process_config* config,
    x11_managed_process_group* group);
librdp_status x11_managed_process_resize(
    const x11_managed_process_group* group,
    uint32_t width,
    uint32_t height);
librdp_status x11_managed_process_join(
    const x11_managed_process_config* config,
    x11_managed_process_group* group,
    const char* executable,
    char* const argv[],
    int retained_descriptor,
    pid_t* child_pid);
librdp_status x11_managed_process_stop(
    x11_managed_process_group* group,
    int timeout_ms);

#endif
