/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic application backend registry.
 * Invariants: names are bounded and unique, at most one session is active, and
 * partial activation is rolled back in reverse registration order.
 * Ownership: provider descriptors are copied; callbacks retain borrowed opaque
 * state whose lifetime is controlled by the frontend.
 * Threading: all registry calls except provider-owned worker activity run on
 * the serialized application/session thread.
 * Trust boundary: providers validate native devices and local permissions;
 * this layer only coordinates their public settings and session hooks.
 */

#include "client_providers.h"

#include <string.h>

void client_provider_registry_init(client_provider_registry* registry)
{
    if (!registry)
        return;
    memset(registry, 0, sizeof(*registry));
}

librdp_status client_provider_registry_add(client_provider_registry* registry,
                                           const client_provider* provider)
{
    client_provider_entry* entry = NULL;
    size_t name_len = 0;
    size_t index = 0;

    if (!registry || !provider || !provider->name || provider->name[0] == '\0' ||
        (!provider->configure_settings && !provider->activate_session) ||
        (provider->activate_session && !provider->shutdown_session))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (registry->active_session)
        return LIBRDP_STATUS_STATE;
    name_len = strlen(provider->name);
    if (name_len >= CLIENT_PROVIDER_NAME_CAPACITY)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (registry->count >= CLIENT_PROVIDER_CAPACITY)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    for (index = 0; index < registry->count; index++)
    {
        if (strcmp(registry->entries[index].name, provider->name) == 0)
            return LIBRDP_STATUS_STATE;
    }

    entry = &registry->entries[registry->count++];
    memcpy(entry->name, provider->name, name_len + 1u);
    entry->configure_settings = provider->configure_settings;
    entry->activate_session = provider->activate_session;
    entry->shutdown_session = provider->shutdown_session;
    entry->user_data = provider->user_data;
    return LIBRDP_STATUS_OK;
}

librdp_status client_provider_registry_configure(client_provider_registry* registry,
                                                 librdp_settings* settings)
{
    size_t index = 0;

    if (!registry || !settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (registry->active_session)
        return LIBRDP_STATUS_STATE;
    for (index = 0; index < registry->count; index++)
    {
        librdp_status status = LIBRDP_STATUS_OK;

        if (!registry->entries[index].configure_settings)
            continue;
        status = registry->entries[index].configure_settings(
            settings,
            registry->entries[index].user_data);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Activate providers transactionally. Hooks that completed successfully are
 * shut down in reverse order if a later hook fails, so no partially active
 * backend set can escape into the session event loop.
 */
librdp_status client_provider_registry_activate(client_provider_registry* registry,
                                                librdp_session* session)
{
    size_t index = 0;

    if (!registry || !session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (registry->active_session)
        return LIBRDP_STATUS_STATE;
    registry->active_session = session;
    for (index = 0; index < registry->count; index++)
    {
        client_provider_entry* entry = &registry->entries[index];
        librdp_status status = LIBRDP_STATUS_OK;

        if (!entry->activate_session)
            continue;
        status = entry->activate_session(session, entry->user_data);
        if (status != LIBRDP_STATUS_OK)
        {
            client_provider_registry_deactivate(registry);
            return status;
        }
        entry->active = 1;
    }
    return LIBRDP_STATUS_OK;
}

void client_provider_registry_deactivate(client_provider_registry* registry)
{
    size_t index = 0;

    if (!registry)
        return;
    index = registry->count;
    while (index > 0)
    {
        client_provider_entry* entry = &registry->entries[--index];

        if (entry->active && entry->shutdown_session)
            entry->shutdown_session(registry->active_session, entry->user_data);
        entry->active = 0;
    }
    registry->active_session = NULL;
}
