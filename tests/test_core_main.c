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

int test_client_core(void);

int main(void)
{
    return test_client_core();
}
