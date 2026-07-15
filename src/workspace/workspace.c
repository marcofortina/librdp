/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: workspace feed lifecycle and resource ownership.
 * Invariants: parsed resource lists are committed atomically after successful
 * validation, and borrowed public views never outlive the owning workspace.
 * Ownership: the workspace owns configuration strings, sensitive credentials,
 * and every parsed resource field.
 * Threading: workspace objects are not internally synchronized; callers
 * serialize fetch, load, clear, and query operations.
 * Trust boundary: feed XML and fetched launch metadata are untrusted until
 * parsed and bounded by this module.
 */

#include <librdp/workspace.h>

#include <openssl/crypto.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define RDP_WORKSPACE_DEFAULT_TIMEOUT_MS 15000u
#define RDP_WORKSPACE_MAX_TIMEOUT_MS 600000u
#define RDP_WORKSPACE_MAX_TEXT_LEN 65536u

typedef struct rdp_workspace_resource_storage
{
    librdp_workspace_resource_type type;
    char* id;
    char* title;
    char* alias;
    char* rdp_file_contents;
    char* rdp_file_url;
    char* icon_url;
    char* terminal_server;
    char* remote_app_program;
} rdp_workspace_resource_storage;

struct librdp_workspace
{
    char* feed_url;
    char* username;
    char* password;
    char* domain;
    uint32_t timeout_ms;
    rdp_workspace_resource_storage* resources;
    size_t resource_count;
};

static char* rdp_workspace_strdup_bounded(const char* value)
{
    char* copy = NULL;
    size_t len = 0;

    if (!value)
        return NULL;
    len = strlen(value);
    if (len > RDP_WORKSPACE_MAX_TEXT_LEN)
        return NULL;
    copy = (char*)malloc(len + 1u);
    if (!copy)
        return NULL;
    memcpy(copy, value, len + 1u);
    return copy;
}

static void rdp_workspace_secure_free(char* value)
{
    if (!value)
        return;
    OPENSSL_cleanse(value, strlen(value));
    free(value);
}

static void rdp_workspace_resource_free(rdp_workspace_resource_storage* resource)
{
    if (!resource)
        return;
    free(resource->id);
    free(resource->title);
    free(resource->alias);
    free(resource->rdp_file_contents);
    free(resource->rdp_file_url);
    free(resource->icon_url);
    free(resource->terminal_server);
    free(resource->remote_app_program);
    memset(resource, 0, sizeof(*resource));
}

static void rdp_workspace_resources_free(rdp_workspace_resource_storage* resources, size_t count)
{
    size_t i = 0;

    if (!resources)
        return;
    for (i = 0; i < count; i++)
        rdp_workspace_resource_free(&resources[i]);
    free(resources);
}

static int rdp_workspace_config_valid(const librdp_workspace_config* config)
{
    if (!config || config->version != LIBRDP_WORKSPACE_CONFIG_VERSION ||
        config->size < offsetof(librdp_workspace_config, timeout_ms) + sizeof(config->timeout_ms))
        return 0;
    if (config->timeout_ms > RDP_WORKSPACE_MAX_TIMEOUT_MS)
        return 0;
    if ((config->feed_url && strlen(config->feed_url) > RDP_WORKSPACE_MAX_TEXT_LEN) ||
        (config->username && strlen(config->username) > RDP_WORKSPACE_MAX_TEXT_LEN) ||
        (config->password && strlen(config->password) > RDP_WORKSPACE_MAX_TEXT_LEN) ||
        (config->domain && strlen(config->domain) > RDP_WORKSPACE_MAX_TEXT_LEN))
        return 0;
    return 1;
}

static librdp_status rdp_workspace_copy_optional(const char* source, char** destination)
{
    char* copy = NULL;

    if (!destination)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *destination = NULL;
    if (!source)
        return LIBRDP_STATUS_OK;
    copy = rdp_workspace_strdup_bounded(source);
    if (!copy)
        return LIBRDP_STATUS_NO_MEMORY;
    *destination = copy;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_workspace_copy_config(librdp_workspace* workspace,
                                               const librdp_workspace_config* config)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_workspace_copy_optional(config->feed_url, &workspace->feed_url);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_workspace_copy_optional(config->username, &workspace->username);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_workspace_copy_optional(config->password, &workspace->password);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_workspace_copy_optional(config->domain, &workspace->domain);
    if (status != LIBRDP_STATUS_OK)
        return status;
    workspace->timeout_ms = config->timeout_ms ? config->timeout_ms : RDP_WORKSPACE_DEFAULT_TIMEOUT_MS;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_workspace_config_init(librdp_workspace_config* config)
{
    if (!config)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(config, 0, sizeof(*config));
    config->version = LIBRDP_WORKSPACE_CONFIG_VERSION;
    config->size = (uint32_t)sizeof(*config);
    config->timeout_ms = RDP_WORKSPACE_DEFAULT_TIMEOUT_MS;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_workspace_resource_init(librdp_workspace_resource* resource)
{
    if (!resource)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(resource, 0, sizeof(*resource));
    resource->version = LIBRDP_WORKSPACE_RESOURCE_VERSION;
    resource->size = (uint32_t)sizeof(*resource);
    return LIBRDP_STATUS_OK;
}

librdp_workspace* librdp_workspace_new(const librdp_workspace_config* config)
{
    librdp_workspace* workspace = NULL;

    if (!rdp_workspace_config_valid(config))
        return NULL;
    workspace = (librdp_workspace*)calloc(1u, sizeof(*workspace));
    if (!workspace)
        return NULL;
    if (rdp_workspace_copy_config(workspace, config) != LIBRDP_STATUS_OK)
    {
        librdp_workspace_free(workspace);
        return NULL;
    }
    return workspace;
}

void librdp_workspace_free(librdp_workspace* workspace)
{
    if (!workspace)
        return;
    free(workspace->feed_url);
    free(workspace->username);
    rdp_workspace_secure_free(workspace->password);
    free(workspace->domain);
    rdp_workspace_resources_free(workspace->resources, workspace->resource_count);
    free(workspace);
}

librdp_status librdp_workspace_clear(librdp_workspace* workspace)
{
    if (!workspace)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_workspace_resources_free(workspace->resources, workspace->resource_count);
    workspace->resources = NULL;
    workspace->resource_count = 0;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_workspace_fetch(librdp_workspace* workspace)
{
    if (!workspace || !workspace->feed_url || workspace->feed_url[0] == '\0')
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return LIBRDP_STATUS_UNSUPPORTED;
}

librdp_status librdp_workspace_load_xml(librdp_workspace* workspace, const void* xml, size_t xml_len)
{
    if (!workspace || !xml || xml_len == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return LIBRDP_STATUS_UNSUPPORTED;
}

size_t librdp_workspace_resource_count(const librdp_workspace* workspace)
{
    return workspace ? workspace->resource_count : 0;
}

librdp_status librdp_workspace_resource_at(const librdp_workspace* workspace,
                                           size_t index,
                                           librdp_workspace_resource* resource)
{
    const rdp_workspace_resource_storage* source = NULL;

    if (!workspace || !resource || resource->version != LIBRDP_WORKSPACE_RESOURCE_VERSION ||
        resource->size < offsetof(librdp_workspace_resource, type) + sizeof(resource->type) ||
        index >= workspace->resource_count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    source = &workspace->resources[index];
    if (resource->size >= offsetof(librdp_workspace_resource, type) + sizeof(resource->type))
        resource->type = source->type;
    if (resource->size >= offsetof(librdp_workspace_resource, id) + sizeof(resource->id))
        resource->id = source->id;
    if (resource->size >= offsetof(librdp_workspace_resource, title) + sizeof(resource->title))
        resource->title = source->title;
    if (resource->size >= offsetof(librdp_workspace_resource, alias) + sizeof(resource->alias))
        resource->alias = source->alias;
    if (resource->size >= offsetof(librdp_workspace_resource, rdp_file_contents) + sizeof(resource->rdp_file_contents))
        resource->rdp_file_contents = source->rdp_file_contents;
    if (resource->size >= offsetof(librdp_workspace_resource, rdp_file_url) + sizeof(resource->rdp_file_url))
        resource->rdp_file_url = source->rdp_file_url;
    if (resource->size >= offsetof(librdp_workspace_resource, icon_url) + sizeof(resource->icon_url))
        resource->icon_url = source->icon_url;
    if (resource->size >= offsetof(librdp_workspace_resource, terminal_server) + sizeof(resource->terminal_server))
        resource->terminal_server = source->terminal_server;
    if (resource->size >= offsetof(librdp_workspace_resource, remote_app_program) + sizeof(resource->remote_app_program))
        resource->remote_app_program = source->remote_app_program;
    return LIBRDP_STATUS_OK;
}
