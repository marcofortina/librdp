/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: private settings structure shared by settings and session
 * construction.
 * Invariants: declarations preserve explicit bounds, ownership, and error
 * propagation across module boundaries.
 * Ownership: settings entries own copied strings and backend descriptors until
 * cloned or freed.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: external inputs are untrusted until validated by the
 * declaring module or caller.
 */


#ifndef RDP_CLIENT_SETTINGS_INTERNAL_H
#define RDP_CLIENT_SETTINGS_INTERNAL_H

#include <librdp/settings.h>

const char* rdp_settings_password_internal(const librdp_settings* settings);
uint32_t rdp_settings_drive_device_id_internal(const librdp_settings* settings, uint32_t index);
uint32_t rdp_settings_printer_device_id_internal(const librdp_settings* settings, uint32_t index);
uint32_t rdp_settings_smartcard_device_id_internal(const librdp_settings* settings, uint32_t index);
uint32_t rdp_settings_serial_port_device_id_internal(const librdp_settings* settings, uint32_t index);
uint32_t rdp_settings_parallel_port_device_id_internal(const librdp_settings* settings, uint32_t index);
uint32_t rdp_settings_pnp_device_id_internal(const librdp_settings* settings, uint32_t index);

#endif
