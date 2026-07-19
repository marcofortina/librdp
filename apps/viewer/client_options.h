/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: platform-neutral viewer option and settings boundary.
 * Invariants: common RDP policy is parsed once, while platform media source
 * validation is delegated through a narrow callback with no native handles.
 * Ownership: settings copy accepted strings; clipboard_file_path is owned by
 * client_options and released by client_options_clear().
 * Threading: parsing and settings population are startup-only serialized work.
 * Trust boundary: argv values remain untrusted until syntax, size, and
 * platform source policy have accepted them.
 */

#ifndef LIBRDP_APP_CLIENT_OPTIONS_H
#define LIBRDP_APP_CLIENT_OPTIONS_H

#include "client_tls.h"

#include <librdp/librdp.h>

#include <stdint.h>
#include <stdio.h>

typedef const char* (*client_camera_source_normalizer)(const char* source, void* user_data);

typedef struct client_option_policy
{
    const char* default_audio_output_device;
    const char* default_audio_input_device;
    client_camera_source_normalizer normalize_camera_source;
    void* camera_user_data;
    FILE* error_stream;
    int allow_help;
    int allow_clipboard_file;
    int rail_requires_app_prefix;
} client_option_policy;

typedef struct client_options
{
    client_tls_context tls;
    char* clipboard_file_path;
    const char* audio_output_device;
    const char* audio_input_device;
    const char* video_output_path;
    const char* camera_source;
    uint32_t width;
    uint32_t height;
    int show_help;
    int audio_output_requested;
    int audio_input_requested;
    int video_requested;
    int camera_requested;
} client_options;

void client_option_policy_init(client_option_policy* policy);
void client_options_init(client_options* options);
void client_options_clear(client_options* options);
int client_options_configure(librdp_settings* settings,
                             client_options* options,
                             const client_option_policy* policy,
                             int argc,
                             char** argv);

#endif
