/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal input-domain boundary for keyboard, pointer, touch, and pen
 * session APIs.
 * Invariants: input serialization validates coordinates, scancodes, Unicode
 * values, contact ids, pressure, and pen fields before writing protocol data.
 * Ownership: input event payloads are caller-owned and copied into temporary
 * session-local buffers during serialization.
 * Threading: input entry points enforce the session owner-thread contract.
 * Trust boundary: application-provided input is validated before it crosses the
 * RDP wire boundary.
 */

#ifndef RDP_CLIENT_SESSION_INPUT_H
#define RDP_CLIENT_SESSION_INPUT_H

#include <librdp/session.h>

#endif
