/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: viewer device backend factory declarations for optional redirected
 * devices.
 * Invariants: viewer backends validate host resources before attaching them to
 * public settings or callbacks.
 * Ownership: backend handles are owned by the viewer and attached to settings
 * before session construction.
 * Threading: viewer backend calls are serialized by the viewer unless the
 * backend documents an OS callback thread.
 * Trust boundary: command-line options, host devices, X11 events, and server
 * callbacks are separate trust domains.
 */


#ifndef LIBRDP_X11_DEVICE_BACKENDS_H
#define LIBRDP_X11_DEVICE_BACKENDS_H

#include <librdp/settings.h>

int x11_device_backends_probe(librdp_settings* settings);

#endif
