/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: viewer backend consent regression tests.
 * Coverage: PNP backend probing, explicit descriptor preservation, and
 * viewer-side discovery boundaries.
 * Bug classes: implicit host-device disclosure, unwanted settings mutation,
 * consent bypass, and PNP capability policy drift.
 * Determinism: tests avoid X11, network, and host device enumeration; only
 * in-memory settings objects are inspected.
 */

#include "device_backends.h"

#include <librdp/librdp.h>

#include <stdio.h>

static int check_int(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr, "test_viewer_backends:%d: check failed: %s\n", line, expression);
    return 1;
}

#define CHECK(expr)                                                                                  \
    do                                                                                               \
    {                                                                                                \
        if (check_int((expr), #expr, __LINE__) != 0)                                                 \
            return 1;                                                                                \
    } while (0)

/*
 * Protects the viewer consent boundary: enabling the PNP feature must not
 * inspect or auto-register local host devices. Only descriptors already added
 * through public settings may be announced later by the core session.
 */
static int test_pnp_probe_does_not_autoregister(void)
{
    librdp_settings* settings = librdp_settings_new();

    CHECK(settings != NULL);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_PNP, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_pnp_device_count(settings) == 0);
    CHECK(x11_device_backends_probe(settings) == 1);
    CHECK(librdp_settings_pnp_device_count(settings) == 0);
    librdp_settings_free(settings);
    return 0;
}

/*
 * Confirms that the backend probe treats existing PNP descriptors as explicit
 * user/application intent and does not rewrite their identity or capability
 * policy.
 */
static int test_pnp_probe_preserves_explicit_devices(void)
{
    librdp_settings* settings = librdp_settings_new();

    CHECK(settings != NULL);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_PNP, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_pnp_device(settings,
                                         "LIBRDP\\PNP\\TEST_DEVICE",
                                         "LIBRDP\\PNP\\TEST",
                                         "Controlled test device",
                                         LIBRDP_PNP_DEVICE_CAP_SURPRISE_REMOVAL_OK) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_settings_pnp_device_count(settings) == 1);
    CHECK(x11_device_backends_probe(settings) == 1);
    CHECK(librdp_settings_pnp_device_count(settings) == 1);
    CHECK(librdp_settings_pnp_device_caps(settings, 0) == LIBRDP_PNP_DEVICE_CAP_SURPRISE_REMOVAL_OK);
    librdp_settings_free(settings);
    return 0;
}

int main(void)
{
    if (test_pnp_probe_does_not_autoregister() != 0)
        return 1;
    if (test_pnp_probe_preserves_explicit_devices() != 0)
        return 1;
    return 0;
}
