/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: administration inventory lifecycle and XML parsing.
 * Invariants: parsed session lists are committed atomically after successful
 * validation, and borrowed public views never outlive the owning admin handle.
 * Ownership: the admin handle owns endpoint strings, sensitive credentials,
 * and every parsed session field.
 * Threading: admin handles are not internally synchronized; callers serialize
 * query, load, clear, and query operations.
 * Trust boundary: management XML and endpoint responses are untrusted until
 * parsed and bounded by this module.
 */

#include <librdp/admin.h>

#include <openssl/crypto.h>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef RDP_HAVE_LIBXML2
#include <libxml/parser.h>
#include <libxml/tree.h>
#endif

#define RDP_ADMIN_DEFAULT_TIMEOUT_MS 15000u
#define RDP_ADMIN_MAX_TIMEOUT_MS 600000u
#define RDP_ADMIN_MAX_TEXT_LEN 65536u
#define RDP_ADMIN_MAX_XML_LEN (4u * 1024u * 1024u)
#define RDP_ADMIN_MAX_SESSIONS 4096u

typedef struct rdp_admin_session_storage
{
    uint32_t session_id;
    uint64_t logon_id;
    char* username;
    char* domain;
    char* state;
    char* client_name;
    char* station_name;
    char* protocol_name;
} rdp_admin_session_storage;

struct librdp_admin
{
    librdp_admin_transport transport;
    char* endpoint_url;
    char* username;
    char* password;
    char* domain;
    char* resource_uri;
    uint32_t timeout_ms;
    int allow_insecure_tls;
    rdp_admin_session_storage* sessions;
    size_t session_count;
};

static char* rdp_admin_strdup_bounded(const char* value)
{
    char* copy = NULL;
    size_t len = 0;

    if (!value)
        return NULL;
    len = strlen(value);
    if (len > RDP_ADMIN_MAX_TEXT_LEN)
        return NULL;
    copy = (char*)malloc(len + 1u);
    if (!copy)
        return NULL;
    memcpy(copy, value, len + 1u);
    return copy;
}

static void rdp_admin_secure_free(char* value)
{
    if (!value)
        return;
    OPENSSL_cleanse(value, strlen(value));
    free(value);
}

static void rdp_admin_session_free(rdp_admin_session_storage* session)
{
    if (!session)
        return;
    free(session->username);
    free(session->domain);
    free(session->state);
    free(session->client_name);
    free(session->station_name);
    free(session->protocol_name);
    memset(session, 0, sizeof(*session));
}

static void rdp_admin_sessions_free(rdp_admin_session_storage* sessions, size_t count)
{
    size_t i = 0;

    if (!sessions)
        return;
    for (i = 0; i < count; i++)
        rdp_admin_session_free(&sessions[i]);
    free(sessions);
}

static int rdp_admin_config_valid(const librdp_admin_config* config)
{
    if (!config || config->version != LIBRDP_ADMIN_CONFIG_VERSION ||
        config->size < offsetof(librdp_admin_config, allow_insecure_tls) + sizeof(config->allow_insecure_tls))
        return 0;
    if (config->transport != LIBRDP_ADMIN_TRANSPORT_WINRM)
        return 0;
    if (config->timeout_ms > RDP_ADMIN_MAX_TIMEOUT_MS)
        return 0;
    if ((config->endpoint_url && strlen(config->endpoint_url) > RDP_ADMIN_MAX_TEXT_LEN) ||
        (config->username && strlen(config->username) > RDP_ADMIN_MAX_TEXT_LEN) ||
        (config->password && strlen(config->password) > RDP_ADMIN_MAX_TEXT_LEN) ||
        (config->domain && strlen(config->domain) > RDP_ADMIN_MAX_TEXT_LEN) ||
        (config->resource_uri && strlen(config->resource_uri) > RDP_ADMIN_MAX_TEXT_LEN))
        return 0;
    return 1;
}

static librdp_status rdp_admin_copy_optional(const char* source, char** destination)
{
    char* copy = NULL;

    if (!destination)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *destination = NULL;
    if (!source)
        return LIBRDP_STATUS_OK;
    copy = rdp_admin_strdup_bounded(source);
    if (!copy)
        return LIBRDP_STATUS_NO_MEMORY;
    *destination = copy;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_admin_copy_config(librdp_admin* admin, const librdp_admin_config* config)
{
    librdp_status status = LIBRDP_STATUS_OK;

    admin->transport = config->transport;
    status = rdp_admin_copy_optional(config->endpoint_url, &admin->endpoint_url);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_copy_optional(config->username, &admin->username);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_copy_optional(config->password, &admin->password);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_copy_optional(config->domain, &admin->domain);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_copy_optional(config->resource_uri, &admin->resource_uri);
    if (status != LIBRDP_STATUS_OK)
        return status;
    admin->timeout_ms = config->timeout_ms ? config->timeout_ms : RDP_ADMIN_DEFAULT_TIMEOUT_MS;
    admin->allow_insecure_tls = config->allow_insecure_tls ? 1 : 0;
    return LIBRDP_STATUS_OK;
}

#ifdef RDP_HAVE_LIBXML2
typedef struct rdp_admin_parse_list
{
    rdp_admin_session_storage* items;
    size_t count;
    size_t capacity;
} rdp_admin_parse_list;

static void rdp_admin_commit_sessions(librdp_admin* admin,
                                      rdp_admin_session_storage* sessions,
                                      size_t count)
{
    rdp_admin_sessions_free(admin->sessions, admin->session_count);
    admin->sessions = sessions;
    admin->session_count = count;
}

static int rdp_admin_node_is(const xmlNode* node, const char* name)
{
    return node && node->type == XML_ELEMENT_NODE && node->name &&
           strcmp((const char*)node->name, name) == 0;
}

static char* rdp_admin_trimmed_xml_string(xmlChar* value)
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
    if (len == 0 || len > RDP_ADMIN_MAX_TEXT_LEN)
        return NULL;
    copy = (char*)malloc(len + 1u);
    if (!copy)
        return NULL;
    memcpy(copy, start, len);
    copy[len] = '\0';
    return copy;
}

static librdp_status rdp_admin_xml_child_text(const xmlNode* node, const char* name, char** destination)
{
    const xmlNode* child = NULL;
    xmlChar* value = NULL;
    char* copy = NULL;

    if (!destination)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *destination = NULL;
    for (child = node ? node->children : NULL; child; child = child->next)
    {
        if (!rdp_admin_node_is(child, name))
            continue;
        value = xmlNodeGetContent((xmlNode*)child);
        copy = rdp_admin_trimmed_xml_string(value);
        xmlFree(value);
        if (!copy)
            return LIBRDP_STATUS_OK;
        *destination = copy;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_admin_xml_prop_text(const xmlNode* node, const char* name, char** destination)
{
    xmlChar* value = NULL;
    char* copy = NULL;

    if (!destination)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *destination = NULL;
    value = xmlGetProp((xmlNode*)node, (const xmlChar*)name);
    if (!value)
        return LIBRDP_STATUS_OK;
    copy = rdp_admin_trimmed_xml_string(value);
    xmlFree(value);
    if (!copy)
        return LIBRDP_STATUS_OK;
    *destination = copy;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_admin_xml_value(const xmlNode* node,
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
        status = rdp_admin_xml_child_text(node, names[i], destination);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    for (i = 0; i < name_count && !*destination; i++)
    {
        status = rdp_admin_xml_prop_text(node, names[i], destination);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static uint64_t rdp_admin_parse_u64(const char* text)
{
    char* end = NULL;
    unsigned long long value = 0;

    if (!text || text[0] == '\0')
        return 0;
    value = strtoull(text, &end, 10);
    if (!end || *end != '\0')
        return 0;
    return (uint64_t)value;
}

static uint32_t rdp_admin_parse_u32(const char* text)
{
    uint64_t value = rdp_admin_parse_u64(text);

    return value > UINT32_MAX ? 0 : (uint32_t)value;
}

static int rdp_admin_session_has_content(const rdp_admin_session_storage* session)
{
    return session && (session->session_id != 0 || session->logon_id != 0 || session->username ||
                       session->domain || session->state || session->client_name || session->station_name ||
                       session->protocol_name);
}

static librdp_status rdp_admin_parse_session(const xmlNode* node, rdp_admin_session_storage* session)
{
    static const char* const id_names[] = {"SessionId", "SessionID", "ID", "Id", "id"};
    static const char* const logon_names[] = {"LogonId", "LogonID", "logonId"};
    static const char* const user_names[] = {"UserName", "Username", "User", "user"};
    static const char* const domain_names[] = {"Domain", "UserDomain", "domain"};
    static const char* const state_names[] = {"State", "Status", "SessionState", "state"};
    static const char* const client_names[] = {"ClientName", "Client", "client"};
    static const char* const station_names[] = {"StationName", "WinStationName", "WindowStation", "station"};
    static const char* const protocol_names[] = {"ProtocolName", "Protocol", "protocol"};
    char* session_id = NULL;
    char* logon_id = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(session, 0, sizeof(*session));
    status = rdp_admin_xml_value(node, id_names, sizeof(id_names) / sizeof(id_names[0]), &session_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_xml_value(node, logon_names, sizeof(logon_names) / sizeof(logon_names[0]), &logon_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_xml_value(node, user_names, sizeof(user_names) / sizeof(user_names[0]), &session->username);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_xml_value(node, domain_names, sizeof(domain_names) / sizeof(domain_names[0]), &session->domain);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_xml_value(node, state_names, sizeof(state_names) / sizeof(state_names[0]), &session->state);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_xml_value(node, client_names, sizeof(client_names) / sizeof(client_names[0]),
                                     &session->client_name);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_xml_value(node, station_names, sizeof(station_names) / sizeof(station_names[0]),
                                     &session->station_name);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_xml_value(node, protocol_names, sizeof(protocol_names) / sizeof(protocol_names[0]),
                                     &session->protocol_name);
    session->session_id = rdp_admin_parse_u32(session_id);
    session->logon_id = rdp_admin_parse_u64(logon_id);
    free(session_id);
    free(logon_id);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_admin_session_free(session);
        return status;
    }
    if (!rdp_admin_session_has_content(session))
    {
        rdp_admin_session_free(session);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_admin_parse_list_append(rdp_admin_parse_list* list,
                                                 const rdp_admin_session_storage* session)
{
    rdp_admin_session_storage* resized = NULL;
    size_t new_capacity = 0;

    if (!list || !session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (list->count >= RDP_ADMIN_MAX_SESSIONS)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (list->count == list->capacity)
    {
        new_capacity = list->capacity == 0 ? 16u : list->capacity * 2u;
        if (new_capacity > RDP_ADMIN_MAX_SESSIONS)
            new_capacity = RDP_ADMIN_MAX_SESSIONS;
        resized = (rdp_admin_session_storage*)realloc(list->items, new_capacity * sizeof(*list->items));
        if (!resized)
            return LIBRDP_STATUS_NO_MEMORY;
        memset(resized + list->capacity, 0, (new_capacity - list->capacity) * sizeof(*resized));
        list->items = resized;
        list->capacity = new_capacity;
    }
    list->items[list->count] = *session;
    list->count++;
    return LIBRDP_STATUS_OK;
}

static int rdp_admin_session_node(const xmlNode* node)
{
    return rdp_admin_node_is(node, "Session") || rdp_admin_node_is(node, "RDSSession") ||
           rdp_admin_node_is(node, "Win32_LogonSession");
}

static librdp_status rdp_admin_parse_nodes(const xmlNode* node, rdp_admin_parse_list* list)
{
    const xmlNode* child = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    for (child = node; child; child = child->next)
    {
        if (rdp_admin_session_node(child))
        {
            rdp_admin_session_storage session;

            status = rdp_admin_parse_session(child, &session);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_admin_parse_list_append(list, &session);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_admin_session_free(&session);
                return status;
            }
        }
        else
        {
            status = rdp_admin_parse_nodes(child->children, list);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_admin_parse_xml(librdp_admin* admin, const void* xml, size_t xml_len)
{
    xmlDocPtr doc = NULL;
    xmlNode* root = NULL;
    rdp_admin_parse_list list;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(&list, 0, sizeof(list));
    if (xml_len > RDP_ADMIN_MAX_XML_LEN || xml_len > (size_t)INT_MAX)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    doc = xmlReadMemory((const char*)xml,
                        (int)xml_len,
                        "admin.xml",
                        NULL,
                        XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING | XML_PARSE_NOBLANKS);
    if (!doc)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    root = xmlDocGetRootElement(doc);
    if (!root)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_parse_nodes(root, &list);
    xmlFreeDoc(doc);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_admin_sessions_free(list.items, list.count);
        return status;
    }
    rdp_admin_commit_sessions(admin, list.items, list.count);
    return LIBRDP_STATUS_OK;
}
#endif

librdp_status librdp_admin_config_init(librdp_admin_config* config)
{
    if (!config)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(config, 0, sizeof(*config));
    config->version = LIBRDP_ADMIN_CONFIG_VERSION;
    config->size = (uint32_t)sizeof(*config);
    config->transport = LIBRDP_ADMIN_TRANSPORT_WINRM;
    config->timeout_ms = RDP_ADMIN_DEFAULT_TIMEOUT_MS;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_admin_session_init(librdp_admin_session* session)
{
    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(session, 0, sizeof(*session));
    session->version = LIBRDP_ADMIN_SESSION_VERSION;
    session->size = (uint32_t)sizeof(*session);
    return LIBRDP_STATUS_OK;
}

librdp_admin* librdp_admin_new(const librdp_admin_config* config)
{
    librdp_admin* admin = NULL;

    if (!rdp_admin_config_valid(config))
        return NULL;
    admin = (librdp_admin*)calloc(1u, sizeof(*admin));
    if (!admin)
        return NULL;
    if (rdp_admin_copy_config(admin, config) != LIBRDP_STATUS_OK)
    {
        librdp_admin_free(admin);
        return NULL;
    }
    return admin;
}

void librdp_admin_free(librdp_admin* admin)
{
    if (!admin)
        return;
    free(admin->endpoint_url);
    free(admin->username);
    rdp_admin_secure_free(admin->password);
    free(admin->domain);
    free(admin->resource_uri);
    rdp_admin_sessions_free(admin->sessions, admin->session_count);
    free(admin);
}

librdp_status librdp_admin_clear(librdp_admin* admin)
{
    if (!admin)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_admin_sessions_free(admin->sessions, admin->session_count);
    admin->sessions = NULL;
    admin->session_count = 0;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_admin_query_sessions(librdp_admin* admin)
{
    if (!admin || !admin->endpoint_url || admin->endpoint_url[0] == '\0')
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return LIBRDP_STATUS_UNSUPPORTED;
}

librdp_status librdp_admin_load_sessions_xml(librdp_admin* admin, const void* xml, size_t xml_len)
{
    if (!admin || !xml || xml_len == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
#ifndef RDP_HAVE_LIBXML2
    (void)xml_len;
    return LIBRDP_STATUS_UNSUPPORTED;
#else
    return rdp_admin_parse_xml(admin, xml, xml_len);
#endif
}

size_t librdp_admin_session_count(const librdp_admin* admin)
{
    return admin ? admin->session_count : 0;
}

librdp_status librdp_admin_session_at(const librdp_admin* admin,
                                      size_t index,
                                      librdp_admin_session* session)
{
    const rdp_admin_session_storage* source = NULL;

    if (!admin || !session || session->version != LIBRDP_ADMIN_SESSION_VERSION ||
        session->size < offsetof(librdp_admin_session, session_id) + sizeof(session->session_id) ||
        index >= admin->session_count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    source = &admin->sessions[index];
    if (session->size >= offsetof(librdp_admin_session, session_id) + sizeof(session->session_id))
        session->session_id = source->session_id;
    if (session->size >= offsetof(librdp_admin_session, logon_id) + sizeof(session->logon_id))
        session->logon_id = source->logon_id;
    if (session->size >= offsetof(librdp_admin_session, username) + sizeof(session->username))
        session->username = source->username;
    if (session->size >= offsetof(librdp_admin_session, domain) + sizeof(session->domain))
        session->domain = source->domain;
    if (session->size >= offsetof(librdp_admin_session, state) + sizeof(session->state))
        session->state = source->state;
    if (session->size >= offsetof(librdp_admin_session, client_name) + sizeof(session->client_name))
        session->client_name = source->client_name;
    if (session->size >= offsetof(librdp_admin_session, station_name) + sizeof(session->station_name))
        session->station_name = source->station_name;
    if (session->size >= offsetof(librdp_admin_session, protocol_name) + sizeof(session->protocol_name))
        session->protocol_name = source->protocol_name;
    return LIBRDP_STATUS_OK;
}
