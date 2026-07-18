/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared desktop-server option validation.
 * Invariants: text is bounded before native or networking APIs receive it,
 * filesystem paths are absolute, and environment names use portable syntax.
 * Ownership: validators borrow input strings for the duration of each call.
 * Threading: functions are stateless and may be called concurrently.
 * Trust boundary: process arguments are untrusted and scanned without an
 * unbounded strlen before they become listener or provider configuration.
 */

#ifndef LIBRDP_APP_SERVER_OPTIONS_H
#define LIBRDP_APP_SERVER_OPTIONS_H

#include <stddef.h>

#define SERVER_OPTIONS_MAX_ADDRESS_BYTES 255u
#define SERVER_OPTIONS_MAX_IDENTITY_BYTES 255u
#define SERVER_OPTIONS_MAX_ENVIRONMENT_BYTES 127u
#define SERVER_OPTIONS_MAX_PATH_BYTES 4095u
#define SERVER_OPTIONS_DEFAULT_MAX_FPS 30u
#define SERVER_OPTIONS_MAX_FPS 60u
#define SERVER_OPTIONS_DEFAULT_MAX_FRAME_BYTES (256u * 1024u * 1024u)
#define SERVER_OPTIONS_MAX_FRAME_BYTES (512u * 1024u * 1024u)

int server_options_address_valid(const char* value);
int server_options_identity_valid(const char* value, int optional);
int server_options_environment_valid(const char* value);
int server_options_absolute_path_valid(const char* value);

#endif
