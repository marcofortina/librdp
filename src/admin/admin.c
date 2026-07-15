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

#define RDP_ADMIN_DEFAULT_TIMEOUT_MS 15000u
#define RDP_ADMIN_MAX_TIMEOUT_MS 600000u
#define RDP_ADMIN_MAX_TEXT_LEN 65536u
#define RDP_ADMIN_MAX_XML_LEN (4u * 1024u * 1024u)
#define RDP_ADMIN_MAX_SESSIONS 4096u
#define RDP_ADMIN_MAX_ACTION_TEXT_LEN 512u
#define RDP_ADMIN_DEFAULT_RESOURCE_URI "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_LogonSession"
#define RDP_ADMIN_PROCESS_RESOURCE_URI "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Process"

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

static int rdp_admin_action_text_valid(const char* text, int required)
{
    size_t i = 0;
    size_t len = 0;

    if (!text)
        return required ? 0 : 1;
    len = strlen(text);
    if ((required && len == 0) || len > RDP_ADMIN_MAX_ACTION_TEXT_LEN)
        return 0;
    for (i = 0; i < len; i++)
    {
        unsigned char c = (unsigned char)text[i];

        if (c < 0x20u || c == 0x7fu)
            return 0;
        if (strchr("\"&|<>^%!`", (int)c))
            return 0;
    }
    return 1;
}

static int rdp_admin_action_valid(const librdp_admin_action* action)
{
    if (!action || action->version != LIBRDP_ADMIN_ACTION_VERSION ||
        action->size < offsetof(librdp_admin_action, timeout_ms) + sizeof(action->timeout_ms) ||
        action->session_id == 0 || action->timeout_ms > RDP_ADMIN_MAX_TIMEOUT_MS)
        return 0;
    if (action->type < LIBRDP_ADMIN_ACTION_LOGOFF || action->type > LIBRDP_ADMIN_ACTION_MESSAGE)
        return 0;
    if (!rdp_admin_action_text_valid(action->message_title, 0))
        return 0;
    if (action->type == LIBRDP_ADMIN_ACTION_MESSAGE)
        return rdp_admin_action_text_valid(action->message_text, 1);
    return action->message_text == NULL;
}

#if defined(RDP_HAVE_CURL) && defined(RDP_HAVE_LIBXML2)
/*
 * Builds a bounded Windows command for the WinRM process provider. Free-form
 * message text is accepted only after rejecting shell metacharacters so action
 * requests cannot become command-injection primitives.
 */
static librdp_status rdp_admin_build_action_command(const librdp_admin_action* action,
                                                    char** command)
{
    int written = 0;
    size_t needed = 0;
    uint32_t message_seconds = 60u;

    if (!rdp_admin_action_valid(action) || !command)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *command = NULL;
    if (action->type == LIBRDP_ADMIN_ACTION_LOGOFF)
        written = snprintf(NULL, 0, "logoff %u", (unsigned)action->session_id);
    else if (action->type == LIBRDP_ADMIN_ACTION_DISCONNECT)
        written = snprintf(NULL, 0, "tsdiscon %u", (unsigned)action->session_id);
    else
    {
        if (action->timeout_ms)
            message_seconds = action->timeout_ms / 1000u;
        if (message_seconds == 0)
            message_seconds = 1u;
        written = snprintf(NULL,
                           0,
                           "msg %u /TIME:%u \"%s%s%s\"",
                           (unsigned)action->session_id,
                           (unsigned)message_seconds,
                           action->message_title ? action->message_title : "",
                           action->message_title ? ": " : "",
                           action->message_text);
    }
    if (written <= 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    needed = (size_t)written + 1u;
    *command = (char*)malloc(needed);
    if (!*command)
        return LIBRDP_STATUS_NO_MEMORY;
    if (action->type == LIBRDP_ADMIN_ACTION_LOGOFF)
        written = snprintf(*command, needed, "logoff %u", (unsigned)action->session_id);
    else if (action->type == LIBRDP_ADMIN_ACTION_DISCONNECT)
        written = snprintf(*command, needed, "tsdiscon %u", (unsigned)action->session_id);
    else
        written = snprintf(*command,
                           needed,
                           "msg %u /TIME:%u \"%s%s%s\"",
                           (unsigned)action->session_id,
                           (unsigned)message_seconds,
                           action->message_title ? action->message_title : "",
                           action->message_title ? ": " : "",
                           action->message_text);
    if (written <= 0 || (size_t)written + 1u != needed)
    {
        free(*command);
        *command = NULL;
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    return LIBRDP_STATUS_OK;
}
#endif

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

#if defined(RDP_HAVE_CURL) && defined(RDP_HAVE_LIBXML2)
typedef struct rdp_admin_fetch_buffer
{
    char* data;
    size_t length;
    size_t capacity;
    int limit_exceeded;
} rdp_admin_fetch_buffer;

static pthread_once_t rdp_admin_curl_once = PTHREAD_ONCE_INIT;

static void rdp_admin_curl_init_once(void)
{
    (void)curl_global_init(CURL_GLOBAL_DEFAULT);
}

static librdp_status rdp_admin_curl_status(CURLcode code)
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

static size_t rdp_admin_curl_write(char* ptr, size_t size, size_t nmemb, void* user_data)
{
    rdp_admin_fetch_buffer* buffer = (rdp_admin_fetch_buffer*)user_data;
    size_t total = 0;
    size_t required = 0;
    size_t capacity = 0;
    char* resized = NULL;

    if (!buffer || !ptr || (size != 0 && nmemb > SIZE_MAX / size))
        return 0;
    total = size * nmemb;
    if (total == 0)
        return 0;
    if (buffer->length > RDP_ADMIN_MAX_XML_LEN || total > RDP_ADMIN_MAX_XML_LEN - buffer->length)
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
            if (capacity > RDP_ADMIN_MAX_XML_LEN / 2u)
            {
                capacity = RDP_ADMIN_MAX_XML_LEN + 1u;
                break;
            }
            capacity *= 2u;
        }
        if (capacity > RDP_ADMIN_MAX_XML_LEN + 1u)
            capacity = RDP_ADMIN_MAX_XML_LEN + 1u;
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

static librdp_status rdp_admin_http_user(const librdp_admin* admin, char** out)
{
    int written = 0;
    size_t needed = 0;
    char* value = NULL;

    if (!out)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *out = NULL;
    if (!admin->username)
        return LIBRDP_STATUS_OK;
    if (!admin->domain)
        return rdp_admin_copy_optional(admin->username, out);
    written = snprintf(NULL, 0, "%s\\%s", admin->domain, admin->username);
    if (written <= 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    needed = (size_t)written + 1u;
    value = (char*)malloc(needed);
    if (!value)
        return LIBRDP_STATUS_NO_MEMORY;
    written = snprintf(value, needed, "%s\\%s", admin->domain, admin->username);
    if (written <= 0 || (size_t)written + 1u != needed)
    {
        free(value);
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    *out = value;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_admin_xml_escape(const char* value, char** out)
{
    size_t i = 0;
    size_t length = 0;
    char* escaped = NULL;
    char* cursor = NULL;

    if (!out)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *out = NULL;
    if (!value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; value[i]; i++)
    {
        switch (value[i])
        {
            case '&':
                length += 5u;
                break;
            case '<':
            case '>':
                length += 4u;
                break;
            case '"':
            case '\'':
                length += 6u;
                break;
            default:
                length++;
                break;
        }
        if (length > RDP_ADMIN_MAX_TEXT_LEN * 6u)
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    escaped = (char*)malloc(length + 1u);
    if (!escaped)
        return LIBRDP_STATUS_NO_MEMORY;
    cursor = escaped;
    for (i = 0; value[i]; i++)
    {
        switch (value[i])
        {
            case '&':
                memcpy(cursor, "&amp;", 5u);
                cursor += 5u;
                break;
            case '<':
                memcpy(cursor, "&lt;", 4u);
                cursor += 4u;
                break;
            case '>':
                memcpy(cursor, "&gt;", 4u);
                cursor += 4u;
                break;
            case '"':
                memcpy(cursor, "&quot;", 6u);
                cursor += 6u;
                break;
            case '\'':
                memcpy(cursor, "&apos;", 6u);
                cursor += 6u;
                break;
            default:
                *cursor++ = value[i];
                break;
        }
    }
    *cursor = '\0';
    *out = escaped;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_admin_build_enumerate_request(const librdp_admin* admin, char** request)
{
    static const char prefix[] =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
        "xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" "
        "xmlns:n=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\">"
        "<s:Header><a:To>";
    static const char middle[] =
        "</a:To><w:ResourceURI s:mustUnderstand=\"true\">";
    static const char suffix[] =
        "</w:ResourceURI><a:ReplyTo><a:Address>"
        "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
        "</a:Address></a:ReplyTo><a:Action s:mustUnderstand=\"true\">"
        "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
        "</a:Action><a:MessageID>uuid:librdp-admin-enumerate</a:MessageID>"
        "<w:OperationTimeout>PT60S</w:OperationTimeout></s:Header>"
        "<s:Body><n:Enumerate/></s:Body></s:Envelope>";
    const char* resource_uri = NULL;
    char* endpoint = NULL;
    char* resource = NULL;
    char* body = NULL;
    size_t body_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!admin || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *request = NULL;
    resource_uri = admin->resource_uri ? admin->resource_uri : RDP_ADMIN_DEFAULT_RESOURCE_URI;
    status = rdp_admin_xml_escape(admin->endpoint_url, &endpoint);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_xml_escape(resource_uri, &resource);
    if (status != LIBRDP_STATUS_OK)
    {
        free(endpoint);
        free(resource);
        return status;
    }
    body_len = sizeof(prefix) - 1u + strlen(endpoint) + sizeof(middle) - 1u + strlen(resource) +
               sizeof(suffix) - 1u;
    body = (char*)malloc(body_len + 1u);
    if (!body)
    {
        free(endpoint);
        free(resource);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    snprintf(body, body_len + 1u, "%s%s%s%s%s", prefix, endpoint, middle, resource, suffix);
    free(endpoint);
    free(resource);
    *request = body;
    return LIBRDP_STATUS_OK;
}

/*
 * Builds the WinRM Process.Create envelope used by bounded admin actions. The
 * command string has already passed action validation; this layer only escapes
 * XML content and keeps management credentials out of the generated body.
 */
static librdp_status rdp_admin_build_process_create_request(const librdp_admin* admin,
                                                            const char* command,
                                                            char** request)
{
    static const char prefix[] =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
        "xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" "
        "xmlns:p=\"http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Process\">"
        "<s:Header><a:To>";
    static const char resource_prefix[] =
        "</a:To><w:ResourceURI s:mustUnderstand=\"true\">";
    static const char action_prefix[] =
        "</w:ResourceURI><a:ReplyTo><a:Address>"
        "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
        "</a:Address></a:ReplyTo><a:Action s:mustUnderstand=\"true\">";
    static const char body_prefix[] =
        "</a:Action><a:MessageID>uuid:librdp-admin-action</a:MessageID>"
        "<w:OperationTimeout>PT60S</w:OperationTimeout></s:Header>"
        "<s:Body><p:Create_INPUT><p:CommandLine>";
    static const char suffix[] =
        "</p:CommandLine></p:Create_INPUT></s:Body></s:Envelope>";
    static const char action_uri[] =
        "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Process/Create";
    char* endpoint = NULL;
    char* resource = NULL;
    char* action = NULL;
    char* escaped_command = NULL;
    char* body = NULL;
    size_t body_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!admin || !command || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *request = NULL;
    status = rdp_admin_xml_escape(admin->endpoint_url, &endpoint);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_xml_escape(RDP_ADMIN_PROCESS_RESOURCE_URI, &resource);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_xml_escape(action_uri, &action);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_xml_escape(command, &escaped_command);
    if (status != LIBRDP_STATUS_OK)
    {
        free(endpoint);
        free(resource);
        free(action);
        free(escaped_command);
        return status;
    }
    body_len = sizeof(prefix) - 1u + strlen(endpoint) + sizeof(resource_prefix) - 1u +
               strlen(resource) + sizeof(action_prefix) - 1u + strlen(action) +
               sizeof(body_prefix) - 1u + strlen(escaped_command) + sizeof(suffix) - 1u;
    body = (char*)malloc(body_len + 1u);
    if (!body)
    {
        free(endpoint);
        free(resource);
        free(action);
        free(escaped_command);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    snprintf(body,
             body_len + 1u,
             "%s%s%s%s%s%s%s%s%s",
             prefix,
             endpoint,
             resource_prefix,
             resource,
             action_prefix,
             action,
             body_prefix,
             escaped_command,
             suffix);
    free(endpoint);
    free(resource);
    free(action);
    free(escaped_command);
    *request = body;
    return LIBRDP_STATUS_OK;
}
#endif

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

#ifdef RDP_HAVE_CURL
static librdp_status rdp_admin_find_return_value(const xmlNode* node, int* found, uint32_t* value)
{
    const xmlNode* child = NULL;
    xmlChar* content = NULL;
    char* text = NULL;

    if (!found || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (child = node; child; child = child->next)
    {
        if (rdp_admin_node_is(child, "ReturnValue") || rdp_admin_node_is(child, "ReturnCode"))
        {
            content = xmlNodeGetContent((xmlNode*)child);
            text = rdp_admin_trimmed_xml_string(content);
            xmlFree(content);
            if (!text)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            {
                char* end = NULL;
                unsigned long parsed = strtoul(text, &end, 10);

                if (!end || *end != '\0' || parsed > UINT32_MAX)
                {
                    free(text);
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                }
                *value = (uint32_t)parsed;
            }
            free(text);
            *found = 1;
            return LIBRDP_STATUS_OK;
        }
        if (child->children)
        {
            librdp_status status = rdp_admin_find_return_value(child->children, found, value);

            if (status != LIBRDP_STATUS_OK || *found)
                return status;
        }
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_admin_parse_action_response(const void* xml, size_t xml_len)
{
    xmlDocPtr doc = NULL;
    xmlNode* root = NULL;
    int found = 0;
    uint32_t value = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!xml || xml_len == 0 || xml_len > RDP_ADMIN_MAX_XML_LEN || xml_len > (size_t)INT_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    doc = xmlReadMemory((const char*)xml,
                        (int)xml_len,
                        "admin-action.xml",
                        NULL,
                        XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING | XML_PARSE_NOBLANKS);
    if (!doc)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    root = xmlDocGetRootElement(doc);
    if (!root)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_find_return_value(root, &found, &value);
    xmlFreeDoc(doc);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!found)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return value == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_IO_ERROR;
}
#endif
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

librdp_status librdp_admin_action_init(librdp_admin_action* action)
{
    if (!action)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(action, 0, sizeof(*action));
    action->version = LIBRDP_ADMIN_ACTION_VERSION;
    action->size = (uint32_t)sizeof(*action);
    action->type = LIBRDP_ADMIN_ACTION_LOGOFF;
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

/*
 * Sends one bounded WinRM enumeration request and commits parsed sessions only
 * after curl transport, HTTP status, response size, and XML parsing all
 * succeed. The function owns every transient credential-bearing curl option
 * for the duration of the call and never writes response payloads to trace.
 */
librdp_status librdp_admin_query_sessions(librdp_admin* admin)
{
    if (!admin || !admin->endpoint_url || admin->endpoint_url[0] == '\0')
        return LIBRDP_STATUS_INVALID_ARGUMENT;
#if !defined(RDP_HAVE_CURL) || !defined(RDP_HAVE_LIBXML2)
    return LIBRDP_STATUS_UNSUPPORTED;
#else
    CURL* easy = NULL;
    CURLcode code = CURLE_OK;
    struct curl_slist* headers = NULL;
    rdp_admin_fetch_buffer buffer;
    librdp_status status = LIBRDP_STATUS_OK;
    char* http_user = NULL;
    char* request_body = NULL;
    struct curl_slist* appended = NULL;
    long response_code = 0;

    memset(&buffer, 0, sizeof(buffer));
    status = rdp_admin_http_user(admin, &http_user);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_build_enumerate_request(admin, &request_body);
    if (status != LIBRDP_STATUS_OK)
    {
        free(http_user);
        return status;
    }
    pthread_once(&rdp_admin_curl_once, rdp_admin_curl_init_once);
    easy = curl_easy_init();
    if (!easy)
    {
        free(http_user);
        free(request_body);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.admin.query.start",
                    "transport=winrm endpoint_set=1 has_user=%d timeout_ms=%u insecure_tls=%d",
                    admin->username ? 1 : 0,
                    (unsigned)admin->timeout_ms,
                    admin->allow_insecure_tls ? 1 : 0);
    if (admin->allow_insecure_tls)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.admin.tls.insecure",
                        "policy=insecure-lab verification=disabled");
    appended = curl_slist_append(headers, "Content-Type: application/soap+xml; charset=utf-8");
    if (!appended)
        status = LIBRDP_STATUS_NO_MEMORY;
    else
        headers = appended;
    if (status == LIBRDP_STATUS_OK)
    {
        appended = curl_slist_append(headers, "Accept: application/soap+xml, text/xml");
        if (!appended)
            status = LIBRDP_STATUS_NO_MEMORY;
        else
            headers = appended;
    }
    if (!headers)
        status = LIBRDP_STATUS_NO_MEMORY;
    if (status == LIBRDP_STATUS_OK)
    {
        curl_easy_setopt(easy, CURLOPT_URL, admin->endpoint_url);
        curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(easy, CURLOPT_POST, 1L);
        curl_easy_setopt(easy, CURLOPT_POSTFIELDS, request_body);
        curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE, (long)strlen(request_body));
        curl_easy_setopt(easy, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, (long)admin->timeout_ms);
        curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, (long)admin->timeout_ms);
        curl_easy_setopt(easy, CURLOPT_FAILONERROR, 1L);
        curl_easy_setopt(easy, CURLOPT_HTTPAUTH, (long)CURLAUTH_ANYSAFE);
        curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, rdp_admin_curl_write);
        curl_easy_setopt(easy, CURLOPT_WRITEDATA, &buffer);
        if (admin->allow_insecure_tls)
        {
            curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 0L);
        }
#if LIBCURL_VERSION_NUM >= 0x075500
        curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, "http,https");
        curl_easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
        curl_easy_setopt(easy, CURLOPT_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
        curl_easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
        if (http_user)
            curl_easy_setopt(easy, CURLOPT_USERNAME, http_user);
        if (admin->password)
            curl_easy_setopt(easy, CURLOPT_PASSWORD, admin->password);
        code = curl_easy_perform(easy);
        if (buffer.limit_exceeded)
            status = LIBRDP_STATUS_LIMIT_EXCEEDED;
        else
            status = rdp_admin_curl_status(code);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        (void)curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code < 200 || response_code >= 300)
            status = LIBRDP_STATUS_IO_ERROR;
    }
    if (status == LIBRDP_STATUS_OK)
        status = buffer.length == 0 ? LIBRDP_STATUS_PROTOCOL_ERROR :
                                      rdp_admin_parse_xml(admin, buffer.data, buffer.length);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.admin.query.done",
                        "bytes=%zu sessions=%zu",
                        buffer.length,
                        admin->session_count);
    else
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.admin.query.failed",
                        "status=%s curl_code=%u http_status=%ld",
                        librdp_status_name(status),
                        (unsigned)code,
                        response_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(easy);
    free(buffer.data);
    free(http_user);
    free(request_body);
    return status;
#endif
}

/*
 * Executes one bounded WinRM process action. Trace records only action type and
 * session id so message text, credentials, and generated command lines never
 * leave process memory through diagnostics.
 */
librdp_status librdp_admin_execute_action(librdp_admin* admin,
                                          const librdp_admin_action* action)
{
    if (!admin || !admin->endpoint_url || admin->endpoint_url[0] == '\0' ||
        !rdp_admin_action_valid(action))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
#if !defined(RDP_HAVE_CURL) || !defined(RDP_HAVE_LIBXML2)
    return LIBRDP_STATUS_UNSUPPORTED;
#else
    CURL* easy = NULL;
    CURLcode code = CURLE_OK;
    struct curl_slist* headers = NULL;
    struct curl_slist* appended = NULL;
    rdp_admin_fetch_buffer buffer;
    librdp_status status = LIBRDP_STATUS_OK;
    char* http_user = NULL;
    char* command = NULL;
    char* request_body = NULL;
    long response_code = 0;
    uint32_t timeout_ms = action->timeout_ms ? action->timeout_ms : admin->timeout_ms;

    memset(&buffer, 0, sizeof(buffer));
    status = rdp_admin_build_action_command(action, &command);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_http_user(admin, &http_user);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_admin_build_process_create_request(admin, command, &request_body);
    if (status != LIBRDP_STATUS_OK)
    {
        free(command);
        free(http_user);
        free(request_body);
        return status;
    }
    pthread_once(&rdp_admin_curl_once, rdp_admin_curl_init_once);
    easy = curl_easy_init();
    if (!easy)
        status = LIBRDP_STATUS_NO_MEMORY;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.admin.action.start",
                    "transport=winrm type=%u session_id=%u timeout_ms=%u insecure_tls=%d",
                    (unsigned)action->type,
                    (unsigned)action->session_id,
                    (unsigned)timeout_ms,
                    admin->allow_insecure_tls ? 1 : 0);
    if (status == LIBRDP_STATUS_OK)
    {
        appended = curl_slist_append(headers, "Content-Type: application/soap+xml; charset=utf-8");
        if (!appended)
            status = LIBRDP_STATUS_NO_MEMORY;
        else
            headers = appended;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        appended = curl_slist_append(headers, "Accept: application/soap+xml, text/xml");
        if (!appended)
            status = LIBRDP_STATUS_NO_MEMORY;
        else
            headers = appended;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        curl_easy_setopt(easy, CURLOPT_URL, admin->endpoint_url);
        curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(easy, CURLOPT_POST, 1L);
        curl_easy_setopt(easy, CURLOPT_POSTFIELDS, request_body);
        curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE, (long)strlen(request_body));
        curl_easy_setopt(easy, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, (long)timeout_ms);
        curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, (long)timeout_ms);
        curl_easy_setopt(easy, CURLOPT_FAILONERROR, 1L);
        curl_easy_setopt(easy, CURLOPT_HTTPAUTH, (long)CURLAUTH_ANYSAFE);
        curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, rdp_admin_curl_write);
        curl_easy_setopt(easy, CURLOPT_WRITEDATA, &buffer);
        if (admin->allow_insecure_tls)
        {
            curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 0L);
        }
#if LIBCURL_VERSION_NUM >= 0x075500
        curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, "http,https");
        curl_easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
        curl_easy_setopt(easy, CURLOPT_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
        curl_easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
        if (http_user)
            curl_easy_setopt(easy, CURLOPT_USERNAME, http_user);
        if (admin->password)
            curl_easy_setopt(easy, CURLOPT_PASSWORD, admin->password);
        code = curl_easy_perform(easy);
        if (buffer.limit_exceeded)
            status = LIBRDP_STATUS_LIMIT_EXCEEDED;
        else
            status = rdp_admin_curl_status(code);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        (void)curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code < 200 || response_code >= 300)
            status = LIBRDP_STATUS_IO_ERROR;
    }
    if (status == LIBRDP_STATUS_OK)
        status = buffer.length == 0 ? LIBRDP_STATUS_PROTOCOL_ERROR :
                                      rdp_admin_parse_action_response(buffer.data, buffer.length);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.admin.action.done",
                        "type=%u session_id=%u",
                        (unsigned)action->type,
                        (unsigned)action->session_id);
    else
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.admin.action.failed",
                        "type=%u session_id=%u status=%s curl_code=%u http_status=%ld",
                        (unsigned)action->type,
                        (unsigned)action->session_id,
                        librdp_status_name(status),
                        (unsigned)code,
                        response_code);
    curl_slist_free_all(headers);
    if (easy)
        curl_easy_cleanup(easy);
    free(buffer.data);
    free(http_user);
    free(command);
    free(request_body);
    return status;
#endif
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
