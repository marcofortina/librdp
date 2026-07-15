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
librdp_gateway_mode rdp_settings_gateway_mode_internal(const librdp_settings* settings);
const char* rdp_settings_gateway_url_internal(const librdp_settings* settings);
const char* rdp_settings_gateway_username_internal(const librdp_settings* settings);
const char* rdp_settings_gateway_password_internal(const librdp_settings* settings);
const char* rdp_settings_gateway_domain_internal(const librdp_settings* settings);
uint32_t rdp_settings_gateway_timeout_ms_internal(const librdp_settings* settings);
int rdp_settings_gateway_use_session_credentials_internal(const librdp_settings* settings);
librdp_credentials_provider rdp_settings_credentials_provider_internal(const librdp_settings* settings,
                                                                       void** user_data);
typedef void (*rdp_settings_secure_string_observer)(const void* data, size_t length, void* user_data);
void rdp_settings_secure_string_observer_for_tests(rdp_settings_secure_string_observer observer,
                                                   void* user_data);
uint32_t rdp_settings_drive_device_id_internal(const librdp_settings* settings, uint32_t index);
const librdp_drive_policy* rdp_settings_drive_policy_internal(const librdp_settings* settings, uint32_t index);
uint32_t rdp_settings_printer_device_id_internal(const librdp_settings* settings, uint32_t index);
uint32_t rdp_settings_smartcard_device_id_internal(const librdp_settings* settings, uint32_t index);
const librdp_usb_policy* rdp_settings_usb_policy_internal(const librdp_settings* settings);
const librdp_limits* rdp_settings_limits_internal(const librdp_settings* settings);
const char* rdp_settings_static_channel_name_internal(const librdp_settings* settings, uint32_t index);
uint32_t rdp_settings_static_channel_flags_internal(const librdp_settings* settings, uint32_t index);
uint32_t rdp_settings_serial_port_device_id_internal(const librdp_settings* settings, uint32_t index);
uint32_t rdp_settings_parallel_port_device_id_internal(const librdp_settings* settings, uint32_t index);
uint32_t rdp_settings_pnp_device_id_internal(const librdp_settings* settings, uint32_t index);

#endif
