/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: platform-neutral workspace selection and launch policy.
 * Invariants: embedded RDP fields are bounded, launch arguments are assembled
 * only from recognized metadata, and resource selection is deterministic.
 * Ownership: options and launch-plan pointers borrow argv, environment,
 * workspace resource, or plan-owned fixed storage.
 * Threading: parsing and plan construction are serialized startup work.
 * Trust boundary: feed resources and embedded RDP files are remote input and
 * cannot escape the explicit viewer argument vocabulary.
 */

#ifndef LIBRDP_APP_WORKSPACE_OPTIONS_H
#define LIBRDP_APP_WORKSPACE_OPTIONS_H

#include <librdp/librdp.h>

#include <stddef.h>
#include <stdio.h>

#define WORKSPACE_FIELD_CAPACITY 1024u
#define WORKSPACE_LAUNCH_ARGUMENT_CAPACITY 24u

typedef struct workspace_options
{
    librdp_workspace_config config;
    const char* select;
    const char* viewer;
    const char* security;
    int no_window;
    int show_help;
    int launch;
} workspace_options;

typedef struct workspace_launch_plan
{
    const char* executable;
    const char* arguments[WORKSPACE_LAUNCH_ARGUMENT_CAPACITY];
    size_t argument_count;
    char target[WORKSPACE_FIELD_CAPACITY];
    char port[6];
    char remote_app[WORKSPACE_FIELD_CAPACITY];
    char gateway[WORKSPACE_FIELD_CAPACITY];
    char rail_argument[WORKSPACE_FIELD_CAPACITY + 5u];
} workspace_launch_plan;

void workspace_options_usage(FILE* stream, const char* program);
int workspace_options_parse(int argc,
                            char** argv,
                            const char* default_viewer,
                            workspace_options* options,
                            FILE* error_stream);
const char* workspace_resource_type_name(librdp_workspace_resource_type type);
int workspace_resource_target(const librdp_workspace_resource* resource,
                              char* output,
                              size_t output_size);
int workspace_resource_remote_app(const librdp_workspace_resource* resource,
                                  char* output,
                                  size_t output_size);
int workspace_resource_gateway(const librdp_workspace_resource* resource,
                               char* output,
                               size_t output_size);
int workspace_select_resource(const librdp_workspace* workspace,
                              const char* selector,
                              size_t* selected_index,
                              FILE* error_stream);
int workspace_launch_plan_build(const workspace_options* options,
                                const librdp_workspace_resource* resource,
                                workspace_launch_plan* plan,
                                FILE* error_stream);

#endif
