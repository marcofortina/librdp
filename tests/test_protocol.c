/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: focused protocol test runner.
 * Coverage: dispatches core, channel, security, graphics, device, and
 * transport conformance suites while preserving the aggregate protocol test.
 * Bug classes: group selection and aggregate coverage omissions.
 * Determinism: each suite uses synthetic vectors and local state only.
 */

#include <stdio.h>
#include <string.h>

int test_protocol_core_vectors(void);
int test_protocol_channel_vectors(void);
int test_protocol_update_vectors(void);
int test_protocol_codec_vectors(void);
int test_protocol_activation_vectors(void);
int test_protocol_security_vectors(void);
int test_protocol_interaction_vectors(void);
int test_protocol_graphics_vectors(void);
int test_protocol_graphics_pipeline_vectors(void);
int test_protocol_clipboard_vectors(void);
int test_protocol_authentication_vectors(void);
int test_protocol_devices(void);
int test_protocol_transport(void);

static int test_protocol_named(const char* name)
{
    if (strcmp(name, "core") == 0)
        return test_protocol_core_vectors();
    if (strcmp(name, "channels") == 0)
        return test_protocol_channel_vectors();
    if (strcmp(name, "updates") == 0)
        return test_protocol_update_vectors();
    if (strcmp(name, "codecs") == 0)
        return test_protocol_codec_vectors();
    if (strcmp(name, "activation") == 0)
        return test_protocol_activation_vectors();
    if (strcmp(name, "security") == 0)
        return test_protocol_security_vectors();
    if (strcmp(name, "interaction") == 0)
        return test_protocol_interaction_vectors();
    if (strcmp(name, "graphics") == 0)
        return test_protocol_graphics_vectors();
    if (strcmp(name, "graphics-pipeline") == 0)
        return test_protocol_graphics_pipeline_vectors();
    if (strcmp(name, "clipboard") == 0)
        return test_protocol_clipboard_vectors();
    if (strcmp(name, "authentication") == 0)
        return test_protocol_authentication_vectors();
    if (strcmp(name, "devices") == 0)
        return test_protocol_devices();
    if (strcmp(name, "transport") == 0)
        return test_protocol_transport();
    fprintf(stderr, "unknown protocol test group: %s\n", name);
    return 2;
}

int test_protocol(void)
{
    if (test_protocol_channel_vectors() != 0)
        return 1;
    if (test_protocol_core_vectors() != 0)
        return 1;
    if (test_protocol_update_vectors() != 0)
        return 1;
    if (test_protocol_codec_vectors() != 0)
        return 1;
    if (test_protocol_activation_vectors() != 0)
        return 1;
    if (test_protocol_security_vectors() != 0)
        return 1;
    if (test_protocol_interaction_vectors() != 0)
        return 1;
    if (test_protocol_graphics_vectors() != 0)
        return 1;
    if (test_protocol_graphics_pipeline_vectors() != 0)
        return 1;
    if (test_protocol_clipboard_vectors() != 0)
        return 1;
    if (test_protocol_authentication_vectors() != 0)
        return 1;
    if (test_protocol_devices() != 0)
        return 1;
    return test_protocol_transport();
}

#ifdef LIBRDP_TEST_PROTOCOL_MAIN
int main(int argc, char** argv)
{
    if (argc == 2)
        return test_protocol_named(argv[1]);
    if (argc != 1)
        return 2;
    return test_protocol();
}
#endif
