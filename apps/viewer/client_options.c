/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared viewer command-line normalization and settings population.
 * Invariants: desktop dimensions and gateway policy are committed only after
 * all arguments validate, and WebAuthn requires at least one RP identifier.
 * Ownership: public setters copy borrowed argv strings; only the optional
 * clipboard path is duplicated into client_options-owned storage.
 * Threading: one startup thread owns both settings and options during parsing.
 * Trust boundary: command-line credentials, paths, selectors, and gateway
 * fields are validated locally and sensitive values are never emitted.
 */

#include "client_options.h"
#include "client_credentials.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct client_gateway_options
{
    const char* url;
    const char* username;
    const char* password;
    const char* domain;
    librdp_gateway_mode mode;
    uint32_t timeout_ms;
    int has_timeout;
    int no_session_credentials;
    int mode_set;
} client_gateway_options;

static char* client_options_strdup(const char* text)
{
    size_t length = 0;
    char* copy = NULL;

    if (!text)
        return NULL;
    length = strlen(text) + 1u;
    copy = (char*)malloc(length);
    if (!copy)
        return NULL;
    memcpy(copy, text, length);
    return copy;
}

static int client_parse_unsigned(const char* text,
                                 unsigned long minimum,
                                 unsigned long maximum,
                                 unsigned long* value)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!text || !value || minimum > maximum)
        return 0;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || !end || end == text || *end != '\0' ||
        parsed < minimum || parsed > maximum)
        return 0;
    *value = parsed;
    return 1;
}

static int client_parse_u16(const char* text, uint16_t* value)
{
    unsigned long parsed = 0;

    if (!value || !client_parse_unsigned(text, 1ul, UINT16_MAX, &parsed))
        return 0;
    *value = (uint16_t)parsed;
    return 1;
}

static int client_parse_dimension(const char* text, uint32_t* value)
{
    unsigned long parsed = 0;

    if (!value || !client_parse_unsigned(text, 1ul, 8192ul, &parsed))
        return 0;
    *value = (uint32_t)parsed;
    return 1;
}

static int client_parse_u32(const char* text, uint32_t* value)
{
    unsigned long parsed = 0;

    if (!value || !client_parse_unsigned(text, 0ul, UINT32_MAX, &parsed))
        return 0;
    *value = (uint32_t)parsed;
    return 1;
}

static int client_parse_security(const char* text, librdp_security_mode* mode)
{
    if (!text || !mode)
        return 0;
    if (strcmp(text, "auto") == 0)
        *mode = LIBRDP_SECURITY_AUTO;
    else if (strcmp(text, "rdp") == 0)
        *mode = LIBRDP_SECURITY_STANDARD;
    else if (strcmp(text, "tls") == 0)
        *mode = LIBRDP_SECURITY_TLS;
    else if (strcmp(text, "nla") == 0)
        *mode = LIBRDP_SECURITY_NLA;
    else
        return 0;
    return 1;
}

static int client_parse_gateway_mode(const char* text, librdp_gateway_mode* mode)
{
    if (!text || !mode)
        return 0;
    if (strcmp(text, "http-connect") == 0)
        *mode = LIBRDP_GATEWAY_HTTP_CONNECT;
    else if (strcmp(text, "rdg-http") == 0)
        *mode = LIBRDP_GATEWAY_RDG_HTTP;
    else
        return 0;
    return 1;
}

static const char* client_value_after_prefix(const char* text, const char* prefix)
{
    size_t prefix_len = 0;

    if (!text || !prefix)
        return NULL;
    prefix_len = strlen(prefix);
    if (strncmp(text, prefix, prefix_len) != 0 || text[prefix_len] == '\0')
        return NULL;
    return text + prefix_len;
}

static int client_require_value(int argc, int* index, char** argv, FILE* error_stream)
{
    if (!index || !argv || *index + 1 >= argc)
    {
        if (error_stream && index && argv && *index >= 0 && *index < argc)
            fprintf(error_stream, "%s requires a value\n", argv[*index]);
        return 0;
    }
    (*index)++;
    return 1;
}

static const char* client_optional_value(int argc, int* index, char** argv)
{
    if (!index || !argv || *index + 1 >= argc)
        return NULL;
    if (strncmp(argv[*index + 1], "--", 2u) == 0)
        return NULL;
    (*index)++;
    return argv[*index];
}

static int client_add_drive(librdp_settings* settings, const char* text)
{
    const char* separator = NULL;
    char name[8];
    size_t name_len = 0;

    if (!settings || !text)
        return 0;
    separator = strchr(text, '=');
    if (!separator || separator == text || separator[1] == '\0')
        return 0;
    name_len = (size_t)(separator - text);
    if (name_len >= sizeof(name))
        return 0;
    memcpy(name, text, name_len);
    name[name_len] = '\0';
    return librdp_settings_add_drive(settings, name, separator + 1) == LIBRDP_STATUS_OK;
}

static int client_add_port(librdp_settings* settings, const char* text, int serial)
{
    const char* separator = NULL;
    char name[8];
    size_t name_len = 0;

    if (!settings || !text)
        return 0;
    separator = strchr(text, '=');
    if (!separator || separator == text || separator[1] == '\0')
        return 0;
    name_len = (size_t)(separator - text);
    if (name_len >= sizeof(name))
        return 0;
    memcpy(name, text, name_len);
    name[name_len] = '\0';
    if (serial)
        return librdp_settings_add_serial_port(settings, name, separator + 1) == LIBRDP_STATUS_OK;
    return librdp_settings_add_parallel_port(settings, name, separator + 1) == LIBRDP_STATUS_OK;
}

static int client_add_printer(librdp_settings* settings, const char* text)
{
    const char* first = NULL;
    const char* second = NULL;
    char name[128];
    char driver[128];
    size_t name_len = 0;
    size_t driver_len = 0;

    if (!settings || !text)
        return 0;
    first = strchr(text, '=');
    if (!first || first == text || first[1] == '\0')
        return 0;
    second = strchr(first + 1, '=');
    if (!second || second == first + 1 || second[1] == '\0')
        return 0;
    name_len = (size_t)(first - text);
    driver_len = (size_t)(second - first - 1);
    if (name_len >= sizeof(name) || driver_len >= sizeof(driver))
        return 0;
    memcpy(name, text, name_len);
    name[name_len] = '\0';
    memcpy(driver, first + 1, driver_len);
    driver[driver_len] = '\0';
    return librdp_settings_add_printer(settings, name, driver, second + 1) == LIBRDP_STATUS_OK;
}

static int client_apply_gateway(librdp_settings* settings,
                                const client_gateway_options* gateway)
{
    librdp_gateway_config config;

    if (!settings || !gateway)
        return 0;
    if (!gateway->url)
    {
        return !(gateway->username || gateway->password || gateway->domain ||
                 gateway->has_timeout || gateway->no_session_credentials ||
                 gateway->mode_set);
    }
    if (librdp_gateway_config_init(&config) != LIBRDP_STATUS_OK)
        return 0;
    config.mode = gateway->mode;
    config.url = gateway->url;
    config.username = gateway->username;
    config.password = gateway->password;
    config.domain = gateway->domain;
    config.timeout_ms = gateway->has_timeout ? gateway->timeout_ms : 0u;
    config.use_session_credentials = gateway->no_session_credentials ? 0 : 1;
    return librdp_settings_set_gateway_config(settings, &config) == LIBRDP_STATUS_OK;
}

void client_option_policy_init(client_option_policy* policy)
{
    if (!policy)
        return;
    memset(policy, 0, sizeof(*policy));
    policy->default_audio_output_device = "default";
    policy->default_audio_input_device = "default";
}

void client_options_init(client_options* options)
{
    if (!options)
        return;
    memset(options, 0, sizeof(*options));
    client_tls_context_init(&options->tls);
}

void client_options_clear(client_options* options)
{
    if (!options)
        return;
    free(options->clipboard_file_path);
    options->clipboard_file_path = NULL;
}

/*
 * Validate and apply one platform-neutral command line to public settings.
 * Public setters take ownership copies of accepted strings, while platform
 * policy is limited to media defaults and camera-source normalization so
 * native objects and event systems stay in their respective frontends.
 */
int client_options_configure(librdp_settings* settings,
                             client_options* options,
                             const client_option_policy* policy,
                             int argc,
                             char** argv)
{
    client_gateway_options gateway;
    client_credentials_input credentials;
    int i = 1;

    if (!settings || !options || !policy || argc < 1 || !argv)
        return 0;
    client_options_init(options);
    client_credentials_input_init(&credentials);
    options->width = librdp_settings_width(settings);
    options->height = librdp_settings_height(settings);
    memset(&gateway, 0, sizeof(gateway));
    gateway.mode = LIBRDP_GATEWAY_HTTP_CONNECT;

    while (i < argc)
    {
        if ((strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) &&
            policy->allow_help)
        {
            options->show_help = 1;
        }
        else if (strcmp(argv[i], "--target") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream) ||
                librdp_settings_set_target(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--user") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream))
                return 0;
            credentials.username = argv[i];
        }
        else if (strcmp(argv[i], "--password") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream))
                return 0;
            credentials.password = argv[i];
        }
        else if (strcmp(argv[i], "--domain") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream))
                return 0;
            credentials.domain = argv[i];
        }
        else if (strcmp(argv[i], "--port") == 0)
        {
            uint16_t port = 0;

            if (!client_require_value(argc, &i, argv, policy->error_stream) ||
                !client_parse_u16(argv[i], &port) ||
                librdp_settings_set_port(settings, port) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--width") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream) ||
                !client_parse_dimension(argv[i], &options->width))
                return 0;
        }
        else if (strcmp(argv[i], "--height") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream) ||
                !client_parse_dimension(argv[i], &options->height))
                return 0;
        }
        else if (strcmp(argv[i], "--security") == 0)
        {
            librdp_security_mode mode = LIBRDP_SECURITY_AUTO;

            if (!client_require_value(argc, &i, argv, policy->error_stream) ||
                !client_parse_security(argv[i], &mode) ||
                librdp_settings_set_security_mode(settings, mode) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--tls-prompt-cert") == 0)
        {
            options->tls.mode = CLIENT_TLS_DECISION_PROMPT;
        }
        else if (strcmp(argv[i], "--tls-accept-any-cert") == 0 ||
                 (policy->allow_tls_accept_alias &&
                  strcmp(argv[i], "--accept-tls-certificate") == 0))
        {
            options->tls.mode = CLIENT_TLS_DECISION_ACCEPT_ONCE;
        }
        else if (strcmp(argv[i], "--gateway") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream))
                return 0;
            gateway.url = argv[i];
        }
        else if (strcmp(argv[i], "--gateway-mode") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream) ||
                !client_parse_gateway_mode(argv[i], &gateway.mode))
                return 0;
            gateway.mode_set = 1;
        }
        else if (strcmp(argv[i], "--gateway-user") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream))
                return 0;
            gateway.username = argv[i];
        }
        else if (strcmp(argv[i], "--gateway-password") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream))
                return 0;
            gateway.password = argv[i];
        }
        else if (strcmp(argv[i], "--gateway-domain") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream))
                return 0;
            gateway.domain = argv[i];
        }
        else if (strcmp(argv[i], "--gateway-timeout") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream) ||
                !client_parse_u32(argv[i], &gateway.timeout_ms))
                return 0;
            gateway.has_timeout = 1;
        }
        else if (strcmp(argv[i], "--gateway-no-session-credentials") == 0)
        {
            gateway.no_session_credentials = 1;
        }
        else if (strcmp(argv[i], "--drive") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream) ||
                !client_add_drive(settings, argv[i]))
                return 0;
        }
        else if (strcmp(argv[i], "--serial") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream) ||
                !client_add_port(settings, argv[i], 1))
                return 0;
        }
        else if (strcmp(argv[i], "--parallel") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream) ||
                !client_add_port(settings, argv[i], 0))
                return 0;
        }
        else if (strcmp(argv[i], "--printer") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream) ||
                !client_add_printer(settings, argv[i]))
                return 0;
        }
        else if (strcmp(argv[i], "--clipboard-file") == 0 &&
                 policy->allow_clipboard_file)
        {
            char* path = NULL;

            if (!client_require_value(argc, &i, argv, policy->error_stream))
                return 0;
            path = client_options_strdup(argv[i]);
            if (!path)
                return 0;
            free(options->clipboard_file_path);
            options->clipboard_file_path = path;
        }
        else if (strcmp(argv[i], "--audio-output") == 0)
        {
            const char* value = client_optional_value(argc, &i, argv);
            const char* device = client_value_after_prefix(value, "device=");

            if (!device)
                device = value ? value : policy->default_audio_output_device;
            if (!device || device[0] == '\0' ||
                librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_OUTPUT, 1) !=
                    LIBRDP_STATUS_OK ||
                librdp_settings_set_audio_output_device(settings, device) != LIBRDP_STATUS_OK)
                return 0;
            options->audio_output_requested = 1;
            options->audio_output_device = device;
        }
        else if (strcmp(argv[i], "--audio-input") == 0)
        {
            const char* value = client_optional_value(argc, &i, argv);
            const char* device = client_value_after_prefix(value, "device=");

            if (!device)
                device = value ? value : policy->default_audio_input_device;
            if (!device || device[0] == '\0' ||
                librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_INPUT, 1) !=
                    LIBRDP_STATUS_OK ||
                librdp_settings_set_audio_input_device(settings, device) != LIBRDP_STATUS_OK)
                return 0;
            options->audio_input_requested = 1;
            options->audio_input_device = device;
        }
        else if (strcmp(argv[i], "--video") == 0)
        {
            const char* path = NULL;

            if (!client_require_value(argc, &i, argv, policy->error_stream))
                return 0;
            path = client_value_after_prefix(argv[i], "file=");
            if (!path)
                path = argv[i];
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_VIDEO, 1) !=
                    LIBRDP_STATUS_OK ||
                librdp_settings_set_video_output_path(settings, path) != LIBRDP_STATUS_OK)
                return 0;
            options->video_requested = 1;
            options->video_output_path = path;
        }
        else if (strcmp(argv[i], "--camera") == 0)
        {
            const char* source = NULL;

            if (!client_require_value(argc, &i, argv, policy->error_stream) ||
                !policy->normalize_camera_source)
                return 0;
            source = policy->normalize_camera_source(argv[i], policy->camera_user_data);
            if (!source || source[0] == '\0' ||
                librdp_settings_enable_feature(settings, LIBRDP_FEATURE_CAMERA, 1) !=
                    LIBRDP_STATUS_OK ||
                librdp_settings_add_camera(settings, source) != LIBRDP_STATUS_OK)
                return 0;
            options->camera_requested = 1;
            options->camera_source = source;
        }
        else if (strcmp(argv[i], "--smartcard") == 0)
        {
            const char* source = client_optional_value(argc, &i, argv);

            if (!source)
                source = "pcsc";
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_SMARTCARD, 1) !=
                    LIBRDP_STATUS_OK ||
                librdp_settings_add_smartcard(settings, source) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--usb") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream) ||
                librdp_settings_enable_feature(settings, LIBRDP_FEATURE_USB, 1) !=
                    LIBRDP_STATUS_OK ||
                librdp_settings_add_usb_device(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--pnp") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_PNP, 1) !=
                LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--webauthn") == 0)
        {
            const char* provider = client_optional_value(argc, &i, argv);

            if (!provider)
                provider = "fido2";
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_WEBAUTHN, 1) !=
                    LIBRDP_STATUS_OK ||
                librdp_settings_set_webauthn_provider(settings, provider) !=
                    LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--webauthn-rp-id") == 0)
        {
            if (!client_require_value(argc, &i, argv, policy->error_stream) ||
                librdp_settings_add_webauthn_rp_id(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--rail") == 0)
        {
            const char* app = NULL;

            if (!client_require_value(argc, &i, argv, policy->error_stream))
                return 0;
            app = client_value_after_prefix(argv[i], "app=");
            if (!app && !policy->rail_requires_app_prefix)
                app = argv[i];
            if (!app ||
                librdp_settings_enable_feature(settings, LIBRDP_FEATURE_RAIL, 1) !=
                    LIBRDP_STATUS_OK ||
                librdp_settings_add_rail_app(settings, app) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--cr2") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_CR2, 1) !=
                LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--echo") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_ECHO, 1) !=
                LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--telemetry") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_TELEMETRY, 1) !=
                LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--multitransport") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_MULTITRANSPORT, 1) !=
                LIBRDP_STATUS_OK)
                return 0;
        }
        else
        {
            if (policy->error_stream)
                fprintf(policy->error_stream, "unknown option: %s\n", argv[i]);
            return 0;
        }
        i++;
    }

    if (options->show_help)
        return 1;
    if (!librdp_settings_target(settings))
    {
        if (policy->error_stream)
            fputs("--target is required\n", policy->error_stream);
        return 0;
    }
    if (librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_WEBAUTHN) &&
        librdp_settings_webauthn_rp_id_count(settings) == 0)
        return 0;
    if (client_credentials_apply(settings, &credentials) != LIBRDP_STATUS_OK)
        return 0;
    if (!client_apply_gateway(settings, &gateway))
        return 0;
    if (client_tls_apply(settings, &options->tls) != LIBRDP_STATUS_OK)
        return 0;
    return librdp_settings_enable_feature(settings, LIBRDP_FEATURE_DISPLAY_CONTROL, 1) ==
               LIBRDP_STATUS_OK &&
           librdp_settings_set_desktop_size(settings, options->width, options->height) ==
               LIBRDP_STATUS_OK;
}
