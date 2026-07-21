/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: focused server test suite entry points.
 * Coverage: configuration, feature state, security, lifecycle, channels,
 * graphics, and the complete loopback runtime sequence.
 * Bug classes: failures are isolated by CTest group while aggregate coverage remains.
 * Determinism: every suite uses local fixtures and synthetic protocol messages.
 */

#ifndef LIBRDP_TEST_SERVER_SUITES_H
#define LIBRDP_TEST_SERVER_SUITES_H

#include <stdint.h>

int test_server_config_defaults(void);
int test_server_new_validates_metadata(void);
int test_server_transport_feature_gates(void);
int test_server_public_feature_backend_readiness(void);
int test_server_feature_status_reason_contract(void);
int test_server_new_copies_strings(void);
int test_server_loopback_negotiation_failure(void);
int test_server_loopback_tls_handshake(void);
int test_server_loopback_tls_mismatched_key(void);
int test_server_loopback_nla_handshake(void);
int test_server_loopback_nla_combined_public_key(void);
int test_server_loopback_nla_reject_vectors(void);
int test_server_standard_security_tamper_vectors(void);
int test_server_loopback_standard_activation_sequence(void);

int test_server_lifecycle_focused(void);
int test_server_protocol_order_focused(void);
int test_server_desktop_limits_focused(void);
int test_server_extension_lifecycle_focused(void);
int test_server_multitransport_focused(void);
int test_server_channels_focused(void);
int test_server_drive_metadata_focused(void);
int test_server_graphics_focused(void);

#endif
