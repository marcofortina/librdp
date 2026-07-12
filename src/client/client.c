/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: public client facade over settings and session objects.
 * Invariants: the facade owns exactly one settings object and one session
 * object, and delegates lifecycle operations without changing semantics.
 * Ownership: config strings are copied into settings during construction;
 * settings/session pointers returned publicly remain owned by the client.
 * Threading: not synchronized; callers serialize through the client owner.
 * Trust boundary: passwords enter only through the secure settings path and
 * are never logged by this wrapper.
 */

#include <librdp/client.h>

#include <stdlib.h>
#include <string.h>

struct librdp_client
{
    librdp_settings* settings;
    librdp_session* session;
};

static int rdp_client_config_valid(const librdp_client_config* config)
{
    return config && config->version == LIBRDP_CLIENT_CONFIG_VERSION &&
           config->size >= sizeof(librdp_client_config);
}

static librdp_status rdp_client_apply_config(librdp_settings* settings, const librdp_client_config* config)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!settings || !rdp_client_config_valid(config))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (config->target)
        status = librdp_settings_set_target(settings, config->target);
    if (status == LIBRDP_STATUS_OK && config->username)
        status = librdp_settings_set_username(settings, config->username);
    if (status == LIBRDP_STATUS_OK && config->password)
        status = librdp_settings_set_password(settings, config->password);
    if (status == LIBRDP_STATUS_OK && config->domain)
        status = librdp_settings_set_domain(settings, config->domain);
    if (status == LIBRDP_STATUS_OK && config->port != 0)
        status = librdp_settings_set_port(settings, config->port);
    if (status == LIBRDP_STATUS_OK && (config->width != 0 || config->height != 0))
    {
        if (config->width == 0 || config->height == 0)
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        else
            status = librdp_settings_set_desktop_size(settings, config->width, config->height);
    }
    if (status == LIBRDP_STATUS_OK)
        status = librdp_settings_set_security_mode(settings, config->security);
    return status;
}

librdp_status librdp_client_config_init(librdp_client_config* config)
{
    if (!config)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(config, 0, sizeof(*config));
    config->version = LIBRDP_CLIENT_CONFIG_VERSION;
    config->size = (uint32_t)sizeof(*config);
    config->port = 3389;
    config->width = 1024;
    config->height = 768;
    config->security = LIBRDP_SECURITY_AUTO;
    return LIBRDP_STATUS_OK;
}

librdp_client* librdp_client_new(const librdp_client_config* config)
{
    librdp_client* client = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_client_config_valid(config))
        return NULL;

    client = (librdp_client*)calloc(1, sizeof(*client));
    if (!client)
        return NULL;
    client->settings = librdp_settings_new();
    if (!client->settings)
        goto fail;
    status = rdp_client_apply_config(client->settings, config);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    client->session = librdp_session_new(client->settings);
    if (!client->session)
        goto fail;
    return client;

fail:
    librdp_settings_free(client->settings);
    free(client);
    return NULL;
}

void librdp_client_free(librdp_client* client)
{
    if (!client)
        return;
    librdp_session_free(client->session);
    librdp_settings_free(client->settings);
    free(client);
}

librdp_settings* librdp_client_settings(librdp_client* client)
{
    return client ? client->settings : NULL;
}

librdp_session* librdp_client_session(librdp_client* client)
{
    return client ? client->session : NULL;
}

librdp_status librdp_client_connect(librdp_client* client)
{
    return client ? librdp_session_connect(client->session) : LIBRDP_STATUS_INVALID_ARGUMENT;
}

librdp_status librdp_client_dispatch(librdp_client* client, int timeout_ms)
{
    return client ? librdp_session_run_once(client->session, timeout_ms) : LIBRDP_STATUS_INVALID_ARGUMENT;
}

librdp_status librdp_client_disconnect(librdp_client* client)
{
    return client ? librdp_session_disconnect(client->session) : LIBRDP_STATUS_INVALID_ARGUMENT;
}

librdp_session_state librdp_client_state(const librdp_client* client)
{
    return client ? librdp_session_get_state(client->session) : LIBRDP_SESSION_FAILED;
}

librdp_session_lifecycle librdp_client_lifecycle(const librdp_client* client)
{
    return client ? librdp_session_get_lifecycle(client->session) : LIBRDP_LIFECYCLE_FAILED;
}
