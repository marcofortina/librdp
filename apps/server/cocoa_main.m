/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa desktop-server process entry point.
 * Invariants: command-line validation completes before AppKit or native
 * capture initialization.
 * Ownership: parsed options borrow argv storage.
 * Threading: startup and server dispatch run on the main thread.
 * Trust boundary: this module handles no credentials or protocol payloads.
 */

#include "cocoa_server_cli.h"
#include "cocoa_server_runtime.h"

#import <Cocoa/Cocoa.h>

int main(int argc, char** argv)
{
    cocoa_server_options options;
    int parsed = 0;

    parsed = cocoa_server_parse_options(argc, argv, &options);
    if (parsed == 2)
    {
        cocoa_server_usage(stdout, argv[0]);
        return 0;
    }
    if (parsed != 1)
    {
        cocoa_server_usage(stderr, argv[0]);
        return 2;
    }
    @autoreleasepool
    {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        return cocoa_server_run(&options);
    }
}
