/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client core test runner.
 * Coverage: dispatches public API settings, surface, input, callback, and
 * session lifecycle fixtures from the shared core test object.
 * Bug classes: ownership, callback lifetime, state transitions, and local
 * handshake regression coverage.
 * Determinism: the runner uses self-contained fixtures and local loopback
 * peers only.
 */

#include "test_core_suites.h"

int main(int argc, char** argv)
{
    if (argc == 2)
        return test_client_core_named(argv[1]);
    if (argc != 1)
        return 2;
    return test_client_core();
}
