/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>

#include <librdp/librdp.h>

static int feature_ready(const librdp_settings* settings, librdp_feature feature)
{
    librdp_feature_status status;

    if (librdp_settings_get_feature_status(settings, feature, &status) != LIBRDP_STATUS_OK)
        return 0;
    return status.requested && status.built && status.backend_ready;
}

int main(void)
{
    librdp_settings* settings = librdp_settings_new();

    if (!settings)
        return 1;

    if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_OUTPUT, 1) != LIBRDP_STATUS_OK ||
        librdp_settings_set_audio_output_device(settings, "pipewire") != LIBRDP_STATUS_OK ||
        librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_INPUT, 1) != LIBRDP_STATUS_OK ||
        librdp_settings_set_audio_input_device(settings, "pipewire") != LIBRDP_STATUS_OK ||
        librdp_settings_enable_feature(settings, LIBRDP_FEATURE_VIDEO, 1) != LIBRDP_STATUS_OK ||
        librdp_settings_set_video_output_path(settings, "/tmp/librdp-video.raw") != LIBRDP_STATUS_OK ||
        librdp_settings_enable_feature(settings, LIBRDP_FEATURE_CAMERA, 1) != LIBRDP_STATUS_OK ||
        librdp_settings_add_camera(settings, "/dev/video0") != LIBRDP_STATUS_OK ||
        librdp_settings_enable_feature(settings, LIBRDP_FEATURE_SMARTCARD, 1) != LIBRDP_STATUS_OK ||
        librdp_settings_add_smartcard(settings, "pcsc") != LIBRDP_STATUS_OK ||
        librdp_settings_enable_feature(settings, LIBRDP_FEATURE_WEBAUTHN, 1) != LIBRDP_STATUS_OK ||
        librdp_settings_set_webauthn_provider(settings, "mock") != LIBRDP_STATUS_OK ||
        librdp_settings_add_webauthn_rp_id(settings, "example.test") != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return 1;
    }

    printf("audio_out=%d audio_in=%d video=%d camera=%d smartcard=%d webauthn=%d\n",
           feature_ready(settings, LIBRDP_FEATURE_AUDIO_OUTPUT),
           feature_ready(settings, LIBRDP_FEATURE_AUDIO_INPUT),
           feature_ready(settings, LIBRDP_FEATURE_VIDEO),
           feature_ready(settings, LIBRDP_FEATURE_CAMERA),
           feature_ready(settings, LIBRDP_FEATURE_SMARTCARD),
           feature_ready(settings, LIBRDP_FEATURE_WEBAUTHN));

    librdp_settings_free(settings);
    return 0;
}
