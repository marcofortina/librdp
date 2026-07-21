/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: WebAuthn host-backend framing regression tests.
 * Coverage: Linux hidraw report-ID framing and argument bounds.
 * Bug classes: shifted CTAPHID fields, short writes, and buffer overflow.
 * Determinism: no authenticator or host device is opened.
 */

#include "client/webauthn_backend.h"

#include <stdio.h>
#include <string.h>

static int check_int(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr, "test_webauthn_backend:%d: check failed: %s\n", line, expression);
    return 1;
}

#define CHECK(expr)                                                                                  \
    do                                                                                               \
    {                                                                                                \
        if (check_int((expr), #expr, __LINE__) != 0)                                                 \
            return 1;                                                                                \
    } while (0)

static int test_hidraw_report_framing(void)
{
    uint8_t frame[RDP_WEBAUTHN_BACKEND_CTAPHID_FRAME_LENGTH];
    uint8_t report[RDP_WEBAUTHN_BACKEND_HIDRAW_REPORT_LENGTH];
    size_t report_len = 0;
    size_t index = 0;

    for (index = 0; index < sizeof(frame); index++)
        frame[index] = (uint8_t)index;
    memset(report, 0xa5, sizeof(report));

    CHECK(rdp_webauthn_backend_format_hidraw_report(
              frame, sizeof(frame), report, sizeof(report), &report_len) == LIBRDP_STATUS_OK);
    CHECK(report_len == sizeof(report));
    CHECK(report[0] == 0);
    CHECK(memcmp(report + 1u, frame, sizeof(frame)) == 0);
    return 0;
}

static int test_hidraw_report_rejects_invalid_buffers(void)
{
    uint8_t frame[RDP_WEBAUTHN_BACKEND_CTAPHID_FRAME_LENGTH] = { 0 };
    uint8_t report[RDP_WEBAUTHN_BACKEND_HIDRAW_REPORT_LENGTH] = { 0 };
    size_t report_len = 17u;

    CHECK(rdp_webauthn_backend_format_hidraw_report(
              NULL, sizeof(frame), report, sizeof(report), &report_len) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(rdp_webauthn_backend_format_hidraw_report(
              frame, sizeof(frame) - 1u, report, sizeof(report), &report_len) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(rdp_webauthn_backend_format_hidraw_report(
              frame, sizeof(frame), NULL, sizeof(report), &report_len) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(rdp_webauthn_backend_format_hidraw_report(
              frame, sizeof(frame), report, sizeof(report) - 1u, &report_len) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(rdp_webauthn_backend_format_hidraw_report(
              frame, sizeof(frame), report, sizeof(report), NULL) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(report_len == 17u);
    return 0;
}

int main(void)
{
    if (test_hidraw_report_framing() != 0)
        return 1;
    if (test_hidraw_report_rejects_invalid_buffers() != 0)
        return 1;
    return 0;
}
