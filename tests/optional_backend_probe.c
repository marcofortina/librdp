/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: optional backend build-matrix probe.
 * Coverage: validates compile-time backend macros, link viability, and
 * disabled-backend runtime status for the AVC decoder path.
 * Bug classes: stale CMake feature gates, incorrectly exported macros,
 * backend link drift, and disabled codec paths that fail before returning
 * UNSUPPORTED.
 * Determinism: uses only synthetic in-process AVC metadata and no host devices
 * or network endpoints.
 */

#include "graphics/avc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OCHECK(expr)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                   \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

static int optional_probe_have_ffmpeg(void)
{
#if defined(RDP_HAVE_FFMPEG_AVC)
    return 1;
#else
    return 0;
#endif
}

static int optional_probe_have_openh264(void)
{
#if defined(RDP_HAVE_OPENH264_AVC)
    return 1;
#else
    return 0;
#endif
}

/*
 * Match graphics capability advertisement to the decoder paths proven
 * operational by the runtime probe. The no-backend case must retain the base
 * graphics versions while explicitly disabling AVC.
 */
static int optional_probe_avc_capabilities(
    uint32_t expected_support)
{
    rdp_graphics_capset capsets[
        RDP_GRAPHICS_DEFAULT_CAPSET_LIMIT];
    uint16_t capset_count = 0u;
    uint16_t index = 0u;
    int have_avc420 = 0;
    int have_avc444 = 0;
    int have_avc444v2 = 0;
    int have_avc_disabled = 0;

    OCHECK(rdp_avc_runtime_support() == expected_support);
    OCHECK(rdp_graphics_default_capsets_for_avc(
               capsets,
               (uint16_t)(sizeof(capsets) /
                          sizeof(capsets[0])),
               &capset_count,
               expected_support) ==
           LIBRDP_STATUS_OK);
    for (index = 0u; index < capset_count; index++)
    {
        OCHECK(rdp_graphics_capset_is_supported_for_avc(
                   &capsets[index],
                   expected_support));
        if (capsets[index].version ==
                RDP_GRAPHICS_CAPVERSION_81 &&
            (capsets[index].flags &
             RDP_GRAPHICS_CAPS_FLAG_AVC420_ENABLED) != 0u)
            have_avc420 = 1;
        if (capsets[index].version ==
            RDP_GRAPHICS_CAPVERSION_106)
            have_avc444 = 1;
        if (capsets[index].version ==
            RDP_GRAPHICS_CAPVERSION_107)
            have_avc444v2 = 1;
        if ((capsets[index].flags &
             RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) != 0u)
            have_avc_disabled = 1;
    }

    OCHECK(have_avc420 ==
           ((expected_support &
             RDP_GRAPHICS_AVC_SUPPORT_AVC420) != 0u));
    OCHECK(have_avc444 ==
           ((expected_support &
             RDP_GRAPHICS_AVC_SUPPORT_AVC444) != 0u));
    OCHECK(have_avc444v2 ==
           ((expected_support &
             RDP_GRAPHICS_AVC_SUPPORT_AVC444V2) != 0u));
    OCHECK(have_avc_disabled ==
           (expected_support == 0u));
    return 0;
}

/*
 * Disabled AVC probe: metadata is valid so a no-backend build must reach the
 * backend availability decision and return UNSUPPORTED rather than a parser or
 * bounds error.
 */
static int optional_probe_avc_disabled_status(void)
{
    static const uint8_t avc420_stream[] = {
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    rdp_graphics_avc420_stream stream;
    rdp_avc_decoder* decoder = NULL;
    rdp_avc_frame frame;
    librdp_status status = LIBRDP_STATUS_OK;

    OCHECK(rdp_graphics_parse_avc420_stream(avc420_stream, sizeof(avc420_stream), &stream) == LIBRDP_STATUS_OK);
    decoder = rdp_avc_decoder_new();
    OCHECK(decoder != NULL);
    rdp_avc_frame_init(&frame);
    status = rdp_avc_decode_420(decoder, &stream, 16u, 16u, &frame);
    rdp_avc_frame_free(&frame);
    rdp_avc_decoder_free(decoder);
    OCHECK(status == LIBRDP_STATUS_UNSUPPORTED);
    return optional_probe_avc_capabilities(0u);
}

/*
 * Expectation dispatcher: lets the CMake matrix use one executable for all
 * cases while preserving compile-time macro checks inside C.
 */
static int optional_probe_expectation(void)
{
    const char* expect = getenv("LIBRDP_OPTIONAL_PROBE_EXPECT_AVC");

    if (!expect || strcmp(expect, "auto") == 0)
        return optional_probe_avc_capabilities(
            rdp_avc_runtime_support());
    if (strcmp(expect, "none") == 0)
    {
        OCHECK(!optional_probe_have_ffmpeg());
        OCHECK(!optional_probe_have_openh264());
        return optional_probe_avc_disabled_status();
    }
    if (strcmp(expect, "openh264") == 0)
    {
        OCHECK(!optional_probe_have_ffmpeg());
        OCHECK(optional_probe_have_openh264());
        return optional_probe_avc_capabilities(
            RDP_GRAPHICS_AVC_SUPPORT_ALL);
    }
    if (strcmp(expect, "ffmpeg") == 0)
    {
        OCHECK(optional_probe_have_ffmpeg());
        OCHECK(!optional_probe_have_openh264());
        return optional_probe_avc_capabilities(
            RDP_GRAPHICS_AVC_SUPPORT_ALL);
    }

    fprintf(stderr, "unknown optional backend probe expectation\n");
    return 1;
}

int main(void)
{
    return optional_probe_expectation();
}
