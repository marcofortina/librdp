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

#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(RDP_HAVE_CURL) && defined(RDP_HAVE_LIBXML2)
#include <curl/curl.h>
#include <pthread.h>
#endif
#ifdef RDP_HAVE_LIBXML2
#include <libxml/parser.h>
#include <libxml/tree.h>
#endif

#include "common/trace.h"

#define RDP_WORKSPACE_DEFAULT_TIMEOUT_MS 15000u
#define RDP_WORKSPACE_MAX_TIMEOUT_MS 600000u
#define RDP_WORKSPACE_MAX_TEXT_LEN 65536u
#define RDP_WORKSPACE_MAX_XML_LEN (4u * 1024u * 1024u)
#define RDP_WORKSPACE_MAX_RESOURCES 1024u

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

#if defined(RDP_HAVE_CURL) && defined(RDP_HAVE_LIBXML2)
typedef struct rdp_workspace_fetch_buffer
{
    char* data;
    size_t length;
    size_t capacity;
    int limit_exceeded;
} rdp_workspace_fetch_buffer;

static pthread_once_t rdp_workspace_curl_once = PTHREAD_ONCE_INIT;

static void rdp_workspace_curl_init_once(void)
{
    (void)curl_global_init(CURL_GLOBAL_DEFAULT);
}

static librdp_status rdp_workspace_curl_status(CURLcode code)
{
    if (code == CURLE_OK)
        return LIBRDP_STATUS_OK;
    if (code == CURLE_OPERATION_TIMEDOUT)
        return LIBRDP_STATUS_TIMEOUT;
    if (code == CURLE_UNSUPPORTED_PROTOCOL)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (code == CURLE_PEER_FAILED_VERIFICATION || code == CURLE_SSL_CACERT_BADFILE)
        return LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
    if (code == CURLE_OUT_OF_MEMORY)
        return LIBRDP_STATUS_NO_MEMORY;
    return LIBRDP_STATUS_IO_ERROR;
}

static size_t rdp_workspace_curl_write(char* ptr, size_t size, size_t nmemb, void* user_data)
{
    rdp_workspace_fetch_buffer* buffer = (rdp_workspace_fetch_buffer*)user_data;
    size_t total = 0;
    size_t required = 0;
    size_t capacity = 0;
    char* resized = NULL;

    if (!buffer || !ptr || (size != 0 && nmemb > SIZE_MAX / size))
        return 0;
    total = size * nmemb;
    if (total == 0)
        return 0;
    if (buffer->length > RDP_WORKSPACE_MAX_XML_LEN || total > RDP_WORKSPACE_MAX_XML_LEN - buffer->length)
    {
        buffer->limit_exceeded = 1;
        return 0;
    }
    required = buffer->length + total + 1u;
    if (required > buffer->capacity)
    {
        capacity = buffer->capacity == 0 ? 4096u : buffer->capacity;
        while (capacity < required)
        {
            if (capacity > RDP_WORKSPACE_MAX_XML_LEN / 2u)
            {
                capacity = RDP_WORKSPACE_MAX_XML_LEN + 1u;
                break;
            }
            capacity *= 2u;
        }
        if (capacity > RDP_WORKSPACE_MAX_XML_LEN + 1u)
            capacity = RDP_WORKSPACE_MAX_XML_LEN + 1u;
        resized = (char*)realloc(buffer->data, capacity);
        if (!resized)
            return 0;
        buffer->data = resized;
        buffer->capacity = capacity;
    }
    memcpy(buffer->data + buffer->length, ptr, total);
    buffer->length += total;
    buffer->data[buffer->length] = '\0';
    return total;
}

static librdp_status rdp_workspace_http_user(const librdp_workspace* workspace, char** out)
{
    int written = 0;
    size_t needed = 0;
    char* value = NULL;

    if (!out)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *out = NULL;
    if (!workspace->username)
        return LIBRDP_STATUS_OK;
    if (!workspace->domain)
        return rdp_workspace_copy_optional(workspace->username, out);
    written = snprintf(NULL, 0, "%s\\%s", workspace->domain, workspace->username);
    if (written <= 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    needed = (size_t)written + 1u;
    value = (char*)malloc(needed);
    if (!value)
        return LIBRDP_STATUS_NO_MEMORY;
    written = snprintf(value, needed, "%s\\%s", workspace->domain, workspace->username);
    if (written <= 0 || (size_t)written + 1u != needed)
    {
        free(value);
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    *out = value;
    return LIBRDP_STATUS_OK;
}
#endif

#ifdef RDP_HAVE_LIBXML2
typedef struct rdp_workspace_parse_list
{
    rdp_workspace_resource_storage* items;
    size_t count;
    size_t capacity;
} rdp_workspace_parse_list;

static void rdp_workspace_commit_resources(librdp_workspace* workspace,
                                           rdp_workspace_resource_storage* resources,
                                           size_t count)
{
    rdp_workspace_resources_free(workspace->resources, workspace->resource_count);
    workspace->resources = resources;
    workspace->resource_count = count;
}

static int rdp_workspace_node_is(const xmlNode* node, const char* name)
{
    return node && node->type == XML_ELEMENT_NODE && node->name &&
           strcmp((const char*)node->name, name) == 0;
}

static int rdp_workspace_ascii_lower(int value)
{
    return value >= 'A' && value <= 'Z' ? value + ('a' - 'A') : value;
}

static int rdp_workspace_ascii_contains(const char* value, const char* needle)
{
    size_t value_len = 0;
    size_t needle_len = 0;
    size_t i = 0;

    if (!value || !needle)
        return 0;
    value_len = strlen(value);
    needle_len = strlen(needle);
    if (needle_len == 0 || needle_len > value_len)
        return 0;
    for (i = 0; i + needle_len <= value_len; i++)
    {
        size_t j = 0;

        for (j = 0; j < needle_len; j++)
        {
            if (rdp_workspace_ascii_lower((unsigned char)value[i + j]) !=
                rdp_workspace_ascii_lower((unsigned char)needle[j]))
                break;
        }
        if (j == needle_len)
            return 1;
    }
    return 0;
}

static char* rdp_workspace_trimmed_xml_string(xmlChar* value)
{
    const char* text = (const char*)value;
    const char* start = text;
    const char* end = NULL;
    size_t len = 0;
    char* copy = NULL;

    if (!value)
        return NULL;
    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n')
        start++;
    end = start + strlen(start);
    while (end > start && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'))
        end--;
    len = (size_t)(end - start);
    if (len == 0 || len > RDP_WORKSPACE_MAX_TEXT_LEN)
        return NULL;
    copy = (char*)malloc(len + 1u);
    if (!copy)
        return NULL;
    memcpy(copy, start, len);
    copy[len] = '\0';
    return copy;
}

static librdp_status rdp_workspace_xml_child_text(const xmlNode* node, const char* name, char** destination)
{
    const xmlNode* child = NULL;
    xmlChar* value = NULL;
    char* copy = NULL;

    if (!destination)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *destination = NULL;
    for (child = node ? node->children : NULL; child; child = child->next)
    {
        if (!rdp_workspace_node_is(child, name))
            continue;
        value = xmlNodeGetContent((xmlNode*)child);
        copy = rdp_workspace_trimmed_xml_string(value);
        xmlFree(value);
        if (!copy)
            return LIBRDP_STATUS_OK;
        *destination = copy;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_workspace_xml_prop_text(const xmlNode* node, const char* name, char** destination)
{
    xmlChar* value = NULL;
    char* copy = NULL;

    if (!destination)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *destination = NULL;
    value = xmlGetProp((xmlNode*)node, (const xmlChar*)name);
    if (!value)
        return LIBRDP_STATUS_OK;
    copy = rdp_workspace_trimmed_xml_string(value);
    xmlFree(value);
    if (!copy)
        return LIBRDP_STATUS_OK;
    *destination = copy;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_workspace_xml_value(const xmlNode* node,
                                             const char* const* names,
                                             size_t name_count,
                                             char** destination)
{
    size_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!destination)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *destination = NULL;
    for (i = 0; i < name_count && !*destination; i++)
    {
        status = rdp_workspace_xml_child_text(node, names[i], destination);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    for (i = 0; i < name_count && !*destination; i++)
    {
        status = rdp_workspace_xml_prop_text(node, names[i], destination);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_workspace_resource_type rdp_workspace_resource_type_from_text(const char* value,
                                                                           const xmlNode* node)
{
    if (rdp_workspace_ascii_contains(value, "remoteapp") ||
        rdp_workspace_ascii_contains(value, "remote app") ||
        rdp_workspace_ascii_contains(value, "application") ||
        rdp_workspace_node_is(node, "RemoteApp"))
        return LIBRDP_WORKSPACE_RESOURCE_REMOTE_APP;
    if (rdp_workspace_ascii_contains(value, "desktop") || rdp_workspace_node_is(node, "Desktop"))
        return LIBRDP_WORKSPACE_RESOURCE_DESKTOP;
    return LIBRDP_WORKSPACE_RESOURCE_UNKNOWN;
}

static int rdp_workspace_resource_has_content(const rdp_workspace_resource_storage* resource)
{
    return resource && (resource->id || resource->title || resource->alias || resource->rdp_file_contents ||
                        resource->rdp_file_url || resource->icon_url || resource->terminal_server ||
                        resource->remote_app_program);
}

static librdp_status rdp_workspace_parse_resource(const xmlNode* node,
                                                  rdp_workspace_resource_storage* resource)
{
    static const char* const id_names[] = {"ID", "Id", "ResourceID", "ResourceId", "id"};
    static const char* const title_names[] = {"Title", "Name", "DisplayName", "title", "name"};
    static const char* const alias_names[] = {"Alias", "AppAlias", "alias"};
    static const char* const type_names[] = {"Type", "ResourceType", "type"};
    static const char* const rdp_contents_names[] = {"RDPFileContents", "RdpFileContents", "RDPFile", "RdpFile"};
    static const char* const rdp_url_names[] = {"RDPFileURL", "RDPFileUrl", "RdpFileUrl", "RdpFileURL"};
    static const char* const icon_names[] = {"IconUrl", "IconURL", "Icon", "iconUrl"};
    static const char* const server_names[] = {"TerminalServer", "Server", "Host", "Address"};
    static const char* const app_names[] = {"RemoteAppProgram", "FilePath", "Program", "Executable"};
    char* type_text = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!node || !resource)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(resource, 0, sizeof(*resource));
    status = rdp_workspace_xml_value(node, id_names, sizeof(id_names) / sizeof(id_names[0]), &resource->id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_workspace_xml_value(node, title_names, sizeof(title_names) / sizeof(title_names[0]), &resource->title);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_workspace_xml_value(node, alias_names, sizeof(alias_names) / sizeof(alias_names[0]), &resource->alias);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_workspace_xml_value(node,
                                         rdp_contents_names,
                                         sizeof(rdp_contents_names) / sizeof(rdp_contents_names[0]),
                                         &resource->rdp_file_contents);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_workspace_xml_value(node, rdp_url_names, sizeof(rdp_url_names) / sizeof(rdp_url_names[0]),
                                         &resource->rdp_file_url);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_workspace_xml_value(node, icon_names, sizeof(icon_names) / sizeof(icon_names[0]),
                                         &resource->icon_url);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_workspace_xml_value(node, server_names, sizeof(server_names) / sizeof(server_names[0]),
                                         &resource->terminal_server);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_workspace_xml_value(node, app_names, sizeof(app_names) / sizeof(app_names[0]),
                                         &resource->remote_app_program);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_workspace_xml_value(node, type_names, sizeof(type_names) / sizeof(type_names[0]), &type_text);
    if (status != LIBRDP_STATUS_OK)
    {
        free(type_text);
        rdp_workspace_resource_free(resource);
        return status;
    }
    resource->type = rdp_workspace_resource_type_from_text(type_text, node);
    free(type_text);
    if (!rdp_workspace_resource_has_content(resource))
    {
        rdp_workspace_resource_free(resource);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_workspace_parse_list_append(rdp_workspace_parse_list* list,
                                                     const rdp_workspace_resource_storage* resource)
{
    rdp_workspace_resource_storage* resized = NULL;
    size_t new_capacity = 0;

    if (!list || !resource)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (list->count >= RDP_WORKSPACE_MAX_RESOURCES)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (list->count == list->capacity)
    {
        new_capacity = list->capacity == 0 ? 8u : list->capacity * 2u;
        if (new_capacity > RDP_WORKSPACE_MAX_RESOURCES)
            new_capacity = RDP_WORKSPACE_MAX_RESOURCES;
        resized = (rdp_workspace_resource_storage*)realloc(list->items, new_capacity * sizeof(*list->items));
        if (!resized)
            return LIBRDP_STATUS_NO_MEMORY;
        memset(resized + list->capacity, 0, (new_capacity - list->capacity) * sizeof(*resized));
        list->items = resized;
        list->capacity = new_capacity;
    }
    list->items[list->count] = *resource;
    list->count++;
    return LIBRDP_STATUS_OK;
}

static int rdp_workspace_resource_node(const xmlNode* node)
{
    return rdp_workspace_node_is(node, "Resource") || rdp_workspace_node_is(node, "RemoteResource") ||
           rdp_workspace_node_is(node, "Desktop") || rdp_workspace_node_is(node, "RemoteApp");
}

static librdp_status rdp_workspace_parse_nodes(const xmlNode* node, rdp_workspace_parse_list* list)
{
    const xmlNode* child = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    for (child = node; child; child = child->next)
    {
        if (rdp_workspace_resource_node(child))
        {
            rdp_workspace_resource_storage resource;

            status = rdp_workspace_parse_resource(child, &resource);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_workspace_parse_list_append(list, &resource);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_workspace_resource_free(&resource);
                return status;
            }
        }
        else
        {
            status = rdp_workspace_parse_nodes(child->children, list);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_workspace_parse_xml(librdp_workspace* workspace, const void* xml, size_t xml_len)
{
    xmlDocPtr doc = NULL;
    xmlNode* root = NULL;
    rdp_workspace_parse_list list;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(&list, 0, sizeof(list));
    if (xml_len > RDP_WORKSPACE_MAX_XML_LEN || xml_len > (size_t)INT_MAX)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    doc = xmlReadMemory((const char*)xml,
                        (int)xml_len,
                        "workspace.xml",
                        NULL,
                        XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING | XML_PARSE_NOBLANKS);
    if (!doc)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    root = xmlDocGetRootElement(doc);
    if (!root)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_workspace_parse_nodes(root, &list);
    xmlFreeDoc(doc);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_workspace_resources_free(list.items, list.count);
        return status;
    }
    rdp_workspace_commit_resources(workspace, list.items, list.count);
    return LIBRDP_STATUS_OK;
}
#endif

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
#if !defined(RDP_HAVE_CURL) || !defined(RDP_HAVE_LIBXML2)
    return LIBRDP_STATUS_UNSUPPORTED;
#else
    CURL* easy = NULL;
    CURLcode code = CURLE_OK;
    rdp_workspace_fetch_buffer buffer;
    librdp_status status = LIBRDP_STATUS_OK;
    char* http_user = NULL;
    long response_code = 0;

    memset(&buffer, 0, sizeof(buffer));
    status = rdp_workspace_http_user(workspace, &http_user);
    if (status != LIBRDP_STATUS_OK)
        return status;

    pthread_once(&rdp_workspace_curl_once, rdp_workspace_curl_init_once);
    easy = curl_easy_init();
    if (!easy)
    {
        free(http_user);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.workspace.fetch.start",
                    "url_set=1 has_user=%d timeout_ms=%u",
                    workspace->username ? 1 : 0,
                    (unsigned)workspace->timeout_ms);
    curl_easy_setopt(easy, CURLOPT_URL, workspace->feed_url);
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(easy, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, (long)workspace->timeout_ms);
    curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, (long)workspace->timeout_ms);
    curl_easy_setopt(easy, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(easy, CURLOPT_HTTPAUTH, (long)CURLAUTH_ANYSAFE);
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
    curl_easy_setopt(easy, CURLOPT_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
    curl_easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, rdp_workspace_curl_write);
    curl_easy_setopt(easy, CURLOPT_WRITEDATA, &buffer);
    if (http_user)
        curl_easy_setopt(easy, CURLOPT_USERNAME, http_user);
    if (workspace->password)
        curl_easy_setopt(easy, CURLOPT_PASSWORD, workspace->password);

    code = curl_easy_perform(easy);
    if (buffer.limit_exceeded)
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    else
        status = rdp_workspace_curl_status(code);
    if (status == LIBRDP_STATUS_OK)
    {
        (void)curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code < 200 || response_code >= 300)
            status = LIBRDP_STATUS_IO_ERROR;
    }
    if (status == LIBRDP_STATUS_OK)
        status = buffer.length == 0 ? LIBRDP_STATUS_PROTOCOL_ERROR :
                                      rdp_workspace_parse_xml(workspace, buffer.data, buffer.length);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.workspace.fetch.done",
                        "bytes=%zu resources=%zu",
                        buffer.length,
                        workspace->resource_count);
    else
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.workspace.fetch.failed",
                        "status=%s curl_code=%u http_status=%ld",
                        librdp_status_name(status),
                        (unsigned)code,
                        response_code);
    curl_easy_cleanup(easy);
    free(buffer.data);
    free(http_user);
    return status;
#endif
}

librdp_status librdp_workspace_load_xml(librdp_workspace* workspace, const void* xml, size_t xml_len)
{
    if (!workspace || !xml || xml_len == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
#ifndef RDP_HAVE_LIBXML2
    (void)xml_len;
    return LIBRDP_STATUS_UNSUPPORTED;
#else
    return rdp_workspace_parse_xml(workspace, xml, xml_len);
#endif
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
