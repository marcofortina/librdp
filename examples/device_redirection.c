/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>

#include <librdp/librdp.h>

int main(void)
{
    librdp_settings* settings = librdp_settings_new();
    librdp_drive_policy drive_policy;
    librdp_usb_policy usb_policy;

    if (!settings)
        return 1;

    if (librdp_drive_policy_init(&drive_policy) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return 1;
    }

    librdp_usb_policy_init(&usb_policy);
    drive_policy.read_only = 1;
    drive_policy.deny_dotfiles = 1;
    usb_policy.require_explicit_consent = 1;

    if (librdp_settings_add_drive(settings, "share", "/tmp") != LIBRDP_STATUS_OK ||
        librdp_settings_set_drive_policy(settings, 0u, &drive_policy) != LIBRDP_STATUS_OK ||
        librdp_settings_add_printer(settings, "pdf", "Generic", "/tmp/librdp-print.out") != LIBRDP_STATUS_OK ||
        librdp_settings_add_serial_port(settings, "COM1", "/dev/null") != LIBRDP_STATUS_OK ||
        librdp_settings_add_parallel_port(settings, "LPT1", "/dev/null") != LIBRDP_STATUS_OK ||
        librdp_settings_set_usb_policy(settings, &usb_policy) != LIBRDP_STATUS_OK ||
        librdp_settings_add_usb_device(settings, "vid:pid=1234:5678") != LIBRDP_STATUS_OK ||
        librdp_settings_add_pnp_device(settings,
                                       "ROOT\\LIBRDP\\0001",
                                       "ROOT\\LIBRDP",
                                       "Example redirected device",
                                       LIBRDP_PNP_DEVICE_CAP_REMOVABLE) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return 1;
    }

    printf("drives=%u printers=%u serial=%u parallel=%u usb=%u pnp=%u\n",
           librdp_settings_drive_count(settings),
           librdp_settings_printer_count(settings),
           librdp_settings_serial_port_count(settings),
           librdp_settings_parallel_port_count(settings),
           librdp_settings_usb_device_count(settings),
           librdp_settings_pnp_device_count(settings));

    librdp_settings_free(settings);
    return 0;
}
