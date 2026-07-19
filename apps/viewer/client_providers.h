/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: application backend registration and lifecycle.
 * Invariants: provider names are unique, settings hooks run before session
 * creation, and activated session hooks are unwound in reverse order.
 * Ownership: descriptors are copied into fixed storage while opaque provider
 * state remains owned by the platform frontend.
 * Threading: registry mutation and activation are serialized on the frontend
 * owner thread; provider implementations define their worker synchronization.
 * Trust boundary: native backend objects cross the boundary only as opaque
 * user data and are never inspected by the common layer.
 */

#ifndef LIBRDP_APP_CLIENT_PROVIDERS_H
#define LIBRDP_APP_CLIENT_PROVIDERS_H

#include <librdp/librdp.h>

#include <stddef.h>

#define CLIENT_PROVIDER_CAPACITY 16u
#define CLIENT_PROVIDER_NAME_CAPACITY 48u

typedef librdp_status (*client_settings_provider)(librdp_settings* settings,
                                                  void* user_data);
typedef librdp_status (*client_session_provider)(librdp_session* session,
                                                 void* user_data);
typedef void (*client_provider_shutdown)(librdp_session* session,
                                         void* user_data);

typedef struct client_provider
{
    const char* name;
    client_settings_provider configure_settings;
    client_session_provider activate_session;
    client_provider_shutdown shutdown_session;
    void* user_data;
} client_provider;

typedef struct client_provider_entry
{
    char name[CLIENT_PROVIDER_NAME_CAPACITY];
    client_settings_provider configure_settings;
    client_session_provider activate_session;
    client_provider_shutdown shutdown_session;
    void* user_data;
    int active;
} client_provider_entry;

typedef struct client_provider_registry
{
    client_provider_entry entries[CLIENT_PROVIDER_CAPACITY];
    size_t count;
    librdp_session* active_session;
} client_provider_registry;

void client_provider_registry_init(client_provider_registry* registry);
librdp_status client_provider_registry_add(client_provider_registry* registry,
                                           const client_provider* provider);
librdp_status client_provider_registry_configure(client_provider_registry* registry,
                                                 librdp_settings* settings);
librdp_status client_provider_registry_activate(client_provider_registry* registry,
                                                librdp_session* session);
void client_provider_registry_deactivate(client_provider_registry* registry);

#endif
