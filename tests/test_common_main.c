/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: common test runner.
 * Coverage: dispatches trace, buffer, charset, and pointer decoding fixtures
 * from the shared core test object without duplicating test logic.
 * Bug classes: malformed buffers, bounds, encoding conversion, and trace
 * filtering regressions.
 * Determinism: the runner only invokes in-process fixtures with no external
 * services.
 */

int test_common(void);

int main(void)
{
    return test_common();
}
