/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa viewer command-line adapter.
 * Invariants: platform-neutral syntax is delegated to apps/common and only
 * Cocoa media defaults and camera-source policy are supplied locally.
 * Ownership: option strings are borrowed from argv while settings own copies;
 * client_options_clear() releases the sole optional owned field.
 * Threading: parsing runs once on the AppKit main thread before session setup.
 * Trust boundary: camera selectors are accepted only by the Cocoa media
 * backend policy before they are copied into public settings.
 */

#ifndef LIBRDP_COCOA_VIEWER_CLI_H
#define LIBRDP_COCOA_VIEWER_CLI_H

#include "client_options.h"

#include <librdp/librdp.h>

#include <stdio.h>

typedef client_options cocoa_viewer_options;

void cocoa_viewer_usage(FILE* stream, const char* program);
int cocoa_viewer_configure_settings(librdp_settings* settings,
                                    cocoa_viewer_options* options,
                                    int argc,
                                    char** argv);

#endif
