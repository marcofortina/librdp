/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: focused server test runner.
 * Coverage: dispatches independent server suites and preserves the aggregate test.
 * Bug classes: group selection and aggregate coverage omissions.
 * Determinism: suite behavior is delegated to deterministic local fixtures.
 */

#include "test_server_suites.h"

#include <stdio.h>
#include <string.h>

static int run_config(void)
{
    if (test_server_config_defaults() != 0)
        return 1;
    if (test_server_new_validates_metadata() != 0)
        return 1;
    return test_server_new_copies_strings();
}

static int run_features(void)
{
    if (test_server_transport_feature_gates() != 0)
        return 1;
    if (test_server_public_feature_backend_readiness() != 0)
        return 1;
    return test_server_feature_status_reason_contract();
}

static int run_security(void)
{
    if (test_server_loopback_negotiation_failure() != 0)
        return 1;
    if (test_server_loopback_tls_handshake() != 0)
        return 1;
    if (test_server_loopback_tls_mismatched_key() != 0)
        return 1;
    if (test_server_loopback_nla_handshake() != 0)
        return 1;
    if (test_server_loopback_nla_combined_public_key() != 0)
        return 1;
    if (test_server_loopback_nla_reject_vectors() != 0)
        return 1;
    return test_server_standard_security_tamper_vectors();
}

static int run_named(const char* name)
{
    if (strcmp(name, "config") == 0)
        return run_config();
    if (strcmp(name, "features") == 0)
        return run_features();
    if (strcmp(name, "security") == 0)
        return run_security();
    if (strcmp(name, "lifecycle") == 0)
        return test_server_lifecycle_focused();
    if (strcmp(name, "protocol-order") == 0)
        return test_server_protocol_order_focused();
    if (strcmp(name, "desktop-limits") == 0)
        return test_server_desktop_limits_focused();
    if (strcmp(name, "extension-lifecycle") == 0)
        return test_server_extension_lifecycle_focused();
    if (strcmp(name, "multitransport") == 0)
        return test_server_multitransport_focused();
    if (strcmp(name, "channels") == 0)
        return test_server_channels_focused();
    if (strcmp(name, "drive-metadata") == 0)
        return test_server_drive_metadata_focused();
    if (strcmp(name, "graphics") == 0)
        return test_server_graphics_focused();
    if (strcmp(name, "runtime") == 0)
        return test_server_loopback_standard_activation_sequence();
    if (strcmp(name, "smoke-standard") == 0)
        return test_server_loopback_standard_activation_sequence();
    if (strcmp(name, "smoke-tls") == 0)
        return test_server_loopback_tls_handshake();
    if (strcmp(name, "smoke-nla") == 0)
        return test_server_loopback_nla_handshake();
    fprintf(stderr, "unknown server test group: %s\n", name);
    return 2;
}

int main(int argc, char** argv)
{
    if (argc == 2)
        return run_named(argv[1]);
    if (argc != 1)
        return 2;
    if (run_config() != 0 || run_features() != 0 || run_security() != 0)
        return 1;
    if (test_server_lifecycle_focused() != 0 ||
        test_server_protocol_order_focused() != 0 ||
        test_server_desktop_limits_focused() != 0 ||
        test_server_extension_lifecycle_focused() != 0 ||
        test_server_multitransport_focused() != 0 ||
        test_server_channels_focused() != 0 ||
        test_server_drive_metadata_focused() != 0 ||
        test_server_graphics_focused() != 0)
        return 1;
    return test_server_loopback_standard_activation_sequence();
}
