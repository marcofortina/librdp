/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/*
 * Module: bounded managed X11 broker configuration.
 * Invariants: the complete regular file is read through one no-follow
 * descriptor, scalar keys occur once and list keys remain bounded by policy.
 * Ownership: temporary file contents are owned and cleansed by the loader;
 * accepted fields are copied into the caller's policy.
 * Threading: startup-only and not internally synchronized.
 * Trust boundary: an administrative file controls authentication, executable
 * paths and resource policy, so unsafe ownership, modes and syntax fail closed.
 */

#include "server_managed_config.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <openssl/crypto.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define X11_MANAGED_CONFIG_MAX_BYTES 65536u
#define X11_MANAGED_CONFIG_MAX_LINE_BYTES 4096u

typedef enum x11_managed_config_key_id
{
    X11_MANAGED_CONFIG_SOCKET = 0,
    X11_MANAGED_CONFIG_RUNTIME_ROOT,
    X11_MANAGED_CONFIG_SUPERVISOR,
    X11_MANAGED_CONFIG_AGENT,
    X11_MANAGED_CONFIG_XSERVER,
    X11_MANAGED_CONFIG_AUTH_SERVICE,
    X11_MANAGED_CONFIG_DESKTOP,
    X11_MANAGED_CONFIG_BIND,
    X11_MANAGED_CONFIG_SECURITY,
    X11_MANAGED_CONFIG_TLS_CERT,
    X11_MANAGED_CONFIG_TLS_KEY,
    X11_MANAGED_CONFIG_ALLOW_USER,
    X11_MANAGED_CONFIG_ALLOW_GROUP,
    X11_MANAGED_CONFIG_ALLOW_ENV,
    X11_MANAGED_CONFIG_MAX_SESSIONS,
    X11_MANAGED_CONFIG_MAX_SESSIONS_PER_USER,
    X11_MANAGED_CONFIG_FIRST_DISPLAY,
    X11_MANAGED_CONFIG_LAST_DISPLAY,
    X11_MANAGED_CONFIG_IDLE_SECONDS,
    X11_MANAGED_CONFIG_MAX_DURATION_SECONDS,
    X11_MANAGED_CONFIG_SOCKET_MODE,
    X11_MANAGED_CONFIG_SOCKET_GROUP,
    X11_MANAGED_CONFIG_ALLOW_STANDARD_SECURITY,
    X11_MANAGED_CONFIG_ALLOW_USER_SWITCH,
    X11_MANAGED_CONFIG_ALLOW_INPUT,
    X11_MANAGED_CONFIG_ALLOW_CLIPBOARD,
    X11_MANAGED_CONFIG_ALLOW_DRIVE,
    X11_MANAGED_CONFIG_DRIVE_READ_ONLY,
    X11_MANAGED_CONFIG_ALLOW_RECONNECT,
    X11_MANAGED_CONFIG_PERSISTENT,
    X11_MANAGED_CONFIG_XVFB,
    X11_MANAGED_CONFIG_KEY_COUNT
} x11_managed_config_key_id;

typedef struct x11_managed_config_key
{
    const char* name;
    x11_managed_config_key_id id;
    int repeatable;
} x11_managed_config_key;

static const x11_managed_config_key x11_managed_config_keys[] = {
    {"socket", X11_MANAGED_CONFIG_SOCKET, 0},
    {"runtime-root", X11_MANAGED_CONFIG_RUNTIME_ROOT, 0},
    {"supervisor", X11_MANAGED_CONFIG_SUPERVISOR, 0},
    {"agent", X11_MANAGED_CONFIG_AGENT, 0},
    {"xserver", X11_MANAGED_CONFIG_XSERVER, 0},
    {"auth-service", X11_MANAGED_CONFIG_AUTH_SERVICE, 0},
    {"desktop", X11_MANAGED_CONFIG_DESKTOP, 0},
    {"bind", X11_MANAGED_CONFIG_BIND, 0},
    {"security", X11_MANAGED_CONFIG_SECURITY, 0},
    {"tls-cert", X11_MANAGED_CONFIG_TLS_CERT, 0},
    {"tls-key", X11_MANAGED_CONFIG_TLS_KEY, 0},
    {"allow-user", X11_MANAGED_CONFIG_ALLOW_USER, 1},
    {"allow-group", X11_MANAGED_CONFIG_ALLOW_GROUP, 1},
    {"allow-env", X11_MANAGED_CONFIG_ALLOW_ENV, 1},
    {"max-sessions", X11_MANAGED_CONFIG_MAX_SESSIONS, 0},
    {"max-sessions-per-user",
     X11_MANAGED_CONFIG_MAX_SESSIONS_PER_USER,
     0},
    {"first-display", X11_MANAGED_CONFIG_FIRST_DISPLAY, 0},
    {"last-display", X11_MANAGED_CONFIG_LAST_DISPLAY, 0},
    {"idle-seconds", X11_MANAGED_CONFIG_IDLE_SECONDS, 0},
    {"max-duration-seconds",
     X11_MANAGED_CONFIG_MAX_DURATION_SECONDS,
     0},
    {"socket-mode", X11_MANAGED_CONFIG_SOCKET_MODE, 0},
    {"socket-group", X11_MANAGED_CONFIG_SOCKET_GROUP, 0},
    {"allow-standard-security",
     X11_MANAGED_CONFIG_ALLOW_STANDARD_SECURITY,
     0},
    {"allow-user-switch",
     X11_MANAGED_CONFIG_ALLOW_USER_SWITCH,
     0},
    {"allow-input", X11_MANAGED_CONFIG_ALLOW_INPUT, 0},
    {"allow-clipboard", X11_MANAGED_CONFIG_ALLOW_CLIPBOARD, 0},
    {"allow-drive", X11_MANAGED_CONFIG_ALLOW_DRIVE, 0},
    {"drive-read-only", X11_MANAGED_CONFIG_DRIVE_READ_ONLY, 0},
    {"allow-reconnect", X11_MANAGED_CONFIG_ALLOW_RECONNECT, 0},
    {"persistent", X11_MANAGED_CONFIG_PERSISTENT, 0},
    {"xvfb", X11_MANAGED_CONFIG_XVFB, 0},
};

static int x11_managed_config_copy(char* output,
                                   size_t capacity,
                                   const char* input)
{
    size_t length = input ? strlen(input) : 0u;

    if (!output || !input || capacity == 0u ||
        length >= capacity)
        return 0;
    memcpy(output, input, length + 1u);
    return 1;
}

void x11_managed_config_error_init(
    x11_managed_config_error* error)
{
    if (!error)
        return;
    memset(error, 0, sizeof(*error));
    error->version = X11_MANAGED_CONFIG_ERROR_VERSION;
    error->size = sizeof(*error);
}

static void x11_managed_config_error_set(
    x11_managed_config_error* error,
    uint32_t line,
    const char* key,
    const char* detail)
{
    if (!error)
        return;
    error->line = line;
    error->key[0] = '\0';
    error->detail[0] = '\0';
    if (key)
        (void)x11_managed_config_copy(
            error->key, sizeof(error->key), key);
    if (detail)
        (void)x11_managed_config_copy(
            error->detail, sizeof(error->detail), detail);
}

static const x11_managed_config_key*
x11_managed_config_find_key(const char* name)
{
    size_t index = 0u;

    if (!name)
        return NULL;
    for (index = 0u;
         index < sizeof(x11_managed_config_keys) /
                     sizeof(x11_managed_config_keys[0]);
         index++)
    {
        if (strcmp(x11_managed_config_keys[index].name,
                   name) == 0)
            return &x11_managed_config_keys[index];
    }
    return NULL;
}

static int x11_managed_config_parse_u64(
    const char* value,
    uint64_t maximum,
    uint64_t* output)
{
    char* end = NULL;
    unsigned long long parsed = 0ull;

    if (!value || !output || value[0] == '\0' ||
        value[0] == '-')
        return 0;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' ||
        (uint64_t)parsed > maximum)
        return 0;
    *output = (uint64_t)parsed;
    return 1;
}

static int x11_managed_config_parse_bool(
    const char* value,
    int* output)
{
    if (!value || !output)
        return 0;
    if (strcmp(value, "1") == 0 ||
        strcasecmp(value, "true") == 0 ||
        strcasecmp(value, "yes") == 0 ||
        strcasecmp(value, "on") == 0)
    {
        *output = 1;
        return 1;
    }
    if (strcmp(value, "0") == 0 ||
        strcasecmp(value, "false") == 0 ||
        strcasecmp(value, "no") == 0 ||
        strcasecmp(value, "off") == 0)
    {
        *output = 0;
        return 1;
    }
    return 0;
}

static int x11_managed_config_parse_mode(
    const char* value,
    mode_t* output)
{
    char* end = NULL;
    unsigned long parsed = 0ul;

    if (!value || !output || value[0] == '\0' ||
        value[0] == '-')
        return 0;
    errno = 0;
    parsed = strtoul(value, &end, 8);
    if (errno != 0 || !end || *end != '\0' ||
        parsed > 0770u || (parsed & 0007u) != 0u ||
        (parsed & 0600u) != 0600u)
        return 0;
    *output = (mode_t)parsed;
    return 1;
}

static int x11_managed_config_parse_security(
    const char* value,
    librdp_security_mode* output)
{
    if (!value || !output)
        return 0;
    if (strcmp(value, "nla") == 0)
        *output = LIBRDP_SECURITY_NLA;
    else if (strcmp(value, "tls") == 0)
        *output = LIBRDP_SECURITY_TLS;
    else if (strcmp(value, "standard") == 0)
        *output = LIBRDP_SECURITY_STANDARD;
    else
        return 0;
    return 1;
}

static int x11_managed_config_path(
    char* output,
    size_t capacity,
    const char* value)
{
    return value && value[0] == '/' &&
           x11_managed_config_copy(output, capacity, value);
}

static librdp_status x11_managed_config_socket_group(
    x11_managed_policy* policy,
    const char* value)
{
    struct group group;
    struct group* result = NULL;
    char buffer[16384];
    int lookup = 0;

    if (!policy || !value || value[0] == '\0')
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&group, 0, sizeof(group));
    lookup = getgrnam_r(
        value, &group, buffer, sizeof(buffer), &result);
    if (lookup != 0 || !result)
        return LIBRDP_STATUS_STATE;
    policy->socket_group = group.gr_gid;
    policy->socket_group_set = 1;
    return LIBRDP_STATUS_OK;
}

/*
 * Apply one normalized key without retaining its source text. Error details
 * identify the field and rejection class but never echo its value.
 */
librdp_status x11_managed_config_apply(
    x11_managed_policy* policy,
    const char* key,
    const char* value,
    x11_managed_config_error* error)
{
    const x11_managed_config_key* entry =
        x11_managed_config_find_key(key);
    uint64_t number = 0u;
    int boolean = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!policy || !entry || !value)
    {
        x11_managed_config_error_set(
            error, error ? error->line : 0u, key, "unknown-key");
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    switch (entry->id)
    {
        case X11_MANAGED_CONFIG_SOCKET:
            if (!x11_managed_config_path(
                    policy->socket_path,
                    sizeof(policy->socket_path),
                    value))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        case X11_MANAGED_CONFIG_RUNTIME_ROOT:
            if (!x11_managed_config_path(
                    policy->runtime_root,
                    sizeof(policy->runtime_root),
                    value))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        case X11_MANAGED_CONFIG_SUPERVISOR:
            if (!x11_managed_config_path(
                    policy->supervisor_path,
                    sizeof(policy->supervisor_path),
                    value))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        case X11_MANAGED_CONFIG_AGENT:
            if (!x11_managed_config_path(
                    policy->agent_path,
                    sizeof(policy->agent_path),
                    value))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        case X11_MANAGED_CONFIG_XSERVER:
            if (!x11_managed_config_path(
                    policy->xserver_path,
                    sizeof(policy->xserver_path),
                    value))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        case X11_MANAGED_CONFIG_AUTH_SERVICE:
            if (!x11_managed_config_copy(
                    policy->authentication_service,
                    sizeof(policy->authentication_service),
                    value))
                status = LIBRDP_STATUS_LIMIT_EXCEEDED;
            break;
        case X11_MANAGED_CONFIG_DESKTOP:
            if (!x11_managed_config_path(
                    policy->desktop_command,
                    sizeof(policy->desktop_command),
                    value))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        case X11_MANAGED_CONFIG_BIND:
            if (value[0] == '\0' ||
                !x11_managed_config_copy(
                    policy->bind_address,
                    sizeof(policy->bind_address),
                    value))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        case X11_MANAGED_CONFIG_SECURITY:
            if (!x11_managed_config_parse_security(
                    value, &policy->security_mode))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        case X11_MANAGED_CONFIG_TLS_CERT:
            if (!x11_managed_config_path(
                    policy->tls_certificate,
                    sizeof(policy->tls_certificate),
                    value))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        case X11_MANAGED_CONFIG_TLS_KEY:
            if (!x11_managed_config_path(
                    policy->tls_private_key,
                    sizeof(policy->tls_private_key),
                    value))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        case X11_MANAGED_CONFIG_ALLOW_USER:
            status = x11_managed_policy_add_user(policy, value);
            break;
        case X11_MANAGED_CONFIG_ALLOW_GROUP:
            status = x11_managed_policy_add_group(policy, value);
            break;
        case X11_MANAGED_CONFIG_ALLOW_ENV:
            status =
                x11_managed_policy_add_environment(policy, value);
            break;
        case X11_MANAGED_CONFIG_MAX_SESSIONS:
            if (!x11_managed_config_parse_u64(
                    value,
                    X11_MANAGED_REGISTRY_MAX_SESSIONS,
                    &number) ||
                number == 0u)
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            else
                policy->max_sessions = (uint32_t)number;
            break;
        case X11_MANAGED_CONFIG_MAX_SESSIONS_PER_USER:
            if (!x11_managed_config_parse_u64(
                    value,
                    X11_MANAGED_REGISTRY_MAX_PER_USER,
                    &number) ||
                number == 0u)
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            else
                policy->max_sessions_per_user =
                    (uint32_t)number;
            break;
        case X11_MANAGED_CONFIG_FIRST_DISPLAY:
            if (!x11_managed_config_parse_u64(
                    value,
                    X11_MANAGED_REGISTRY_MAX_DISPLAY,
                    &number))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            else
                policy->first_display = (uint32_t)number;
            break;
        case X11_MANAGED_CONFIG_LAST_DISPLAY:
            if (!x11_managed_config_parse_u64(
                    value,
                    X11_MANAGED_REGISTRY_MAX_DISPLAY,
                    &number))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            else
                policy->last_display = (uint32_t)number;
            break;
        case X11_MANAGED_CONFIG_IDLE_SECONDS:
            if (!x11_managed_config_parse_u64(
                    value,
                    UINT64_MAX / 1000000000u,
                    &number))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            else
                policy->idle_timeout_ns =
                    number * 1000000000u;
            break;
        case X11_MANAGED_CONFIG_MAX_DURATION_SECONDS:
            if (!x11_managed_config_parse_u64(
                    value,
                    UINT64_MAX / 1000000000u,
                    &number))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            else
                policy->max_duration_ns =
                    number * 1000000000u;
            break;
        case X11_MANAGED_CONFIG_SOCKET_MODE:
            if (!x11_managed_config_parse_mode(
                    value, &policy->socket_mode))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        case X11_MANAGED_CONFIG_SOCKET_GROUP:
            status =
                x11_managed_config_socket_group(policy, value);
            break;
        case X11_MANAGED_CONFIG_ALLOW_STANDARD_SECURITY:
        case X11_MANAGED_CONFIG_ALLOW_USER_SWITCH:
        case X11_MANAGED_CONFIG_ALLOW_INPUT:
        case X11_MANAGED_CONFIG_ALLOW_CLIPBOARD:
        case X11_MANAGED_CONFIG_ALLOW_DRIVE:
        case X11_MANAGED_CONFIG_DRIVE_READ_ONLY:
        case X11_MANAGED_CONFIG_ALLOW_RECONNECT:
        case X11_MANAGED_CONFIG_PERSISTENT:
        case X11_MANAGED_CONFIG_XVFB:
            if (!x11_managed_config_parse_bool(value, &boolean))
            {
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
                break;
            }
            if (entry->id ==
                X11_MANAGED_CONFIG_ALLOW_STANDARD_SECURITY)
                policy->allow_standard_security = boolean;
            else if (entry->id ==
                     X11_MANAGED_CONFIG_ALLOW_USER_SWITCH)
                policy->allow_user_switch = boolean;
            else if (entry->id ==
                     X11_MANAGED_CONFIG_ALLOW_INPUT)
                policy->allow_input = boolean;
            else if (entry->id ==
                     X11_MANAGED_CONFIG_ALLOW_CLIPBOARD)
                policy->allow_clipboard = boolean;
            else if (entry->id ==
                     X11_MANAGED_CONFIG_ALLOW_DRIVE)
                policy->allow_drive = boolean;
            else if (entry->id ==
                     X11_MANAGED_CONFIG_DRIVE_READ_ONLY)
                policy->drive_read_only = boolean;
            else if (entry->id ==
                     X11_MANAGED_CONFIG_ALLOW_RECONNECT)
                policy->allow_reconnect = boolean;
            else if (entry->id ==
                     X11_MANAGED_CONFIG_PERSISTENT)
                policy->persistent_sessions = boolean;
            else
                policy->use_xvfb = boolean;
            break;
        case X11_MANAGED_CONFIG_KEY_COUNT:
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        x11_managed_config_error_set(
            error,
            error ? error->line : 0u,
            key,
            status == LIBRDP_STATUS_LIMIT_EXCEEDED
                ? "limit-exceeded"
                : "invalid-value");
    }
    return status;
}

static char* x11_managed_config_trim_left(char* value)
{
    while (value && *value != '\0' &&
           isspace((unsigned char)*value))
        value++;
    return value;
}

static void x11_managed_config_trim_right(char* value)
{
    size_t length = value ? strlen(value) : 0u;

    while (length > 0u &&
           isspace((unsigned char)value[length - 1u]))
        value[--length] = '\0';
}

static librdp_status x11_managed_config_parse(
    char* content,
    size_t length,
    x11_managed_policy* policy,
    x11_managed_config_error* error)
{
    uint64_t seen = 0u;
    size_t offset = 0u;
    uint32_t line_number = 0u;

    while (offset < length)
    {
        const x11_managed_config_key* entry = NULL;
        char* line = content + offset;
        char* end = memchr(line, '\n', length - offset);
        char* key = NULL;
        char* value = NULL;
        char* separator = NULL;
        size_t line_length =
            end ? (size_t)(end - line) : length - offset;
        librdp_status status = LIBRDP_STATUS_OK;

        line_number++;
        if (line_length > X11_MANAGED_CONFIG_MAX_LINE_BYTES)
        {
            x11_managed_config_error_set(
                error, line_number, NULL, "line-too-long");
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
        }
        if (end)
            *end = '\0';
        else
            content[length] = '\0';
        if (line_length > 0u &&
            line[line_length - 1u] == '\r')
            line[line_length - 1u] = '\0';
        key = x11_managed_config_trim_left(line);
        x11_managed_config_trim_right(key);
        if (key[0] == '\0' || key[0] == '#')
        {
            offset += line_length + (end ? 1u : 0u);
            continue;
        }
        separator = strchr(key, '=');
        if (!separator)
        {
            x11_managed_config_error_set(
                error, line_number, key, "missing-separator");
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        }
        *separator = '\0';
        value = x11_managed_config_trim_left(separator + 1u);
        x11_managed_config_trim_right(key);
        x11_managed_config_trim_right(value);
        if (key[0] == '\0' || value[0] == '\0')
        {
            x11_managed_config_error_set(
                error, line_number, key, "empty-key-or-value");
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        }
        entry = x11_managed_config_find_key(key);
        if (!entry)
        {
            x11_managed_config_error_set(
                error, line_number, key, "unknown-key");
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        }
        if (!entry->repeatable &&
            (seen & (UINT64_C(1) << entry->id)) != 0u)
        {
            x11_managed_config_error_set(
                error, line_number, key, "duplicate-key");
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        }
        seen |= UINT64_C(1) << entry->id;
        if (error)
            error->line = line_number;
        status = x11_managed_config_apply(
            policy, key, value, error);
        if (status != LIBRDP_STATUS_OK)
            return status;
        offset += line_length + (end ? 1u : 0u);
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Read a stable, owner-controlled regular file into a fixed upper bound before
 * parsing it. A concurrent grow or embedded NUL is rejected rather than
 * interpreting a partial administrative policy.
 */
librdp_status x11_managed_config_load(
    const char* path,
    x11_managed_policy* policy,
    x11_managed_config_error* error)
{
    struct stat info;
    unsigned char extra = 0u;
    char* content = NULL;
    size_t expected = 0u;
    size_t used = 0u;
    int descriptor = -1;
    librdp_status status = LIBRDP_STATUS_OK;

    x11_managed_config_error_init(error);
    if (!path || !policy || path[0] != '/')
    {
        x11_managed_config_error_set(
            error, 0u, NULL, "absolute-path-required");
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &info) != 0)
    {
        if (descriptor >= 0)
            close(descriptor);
        x11_managed_config_error_set(
            error, 0u, NULL, "open-failed");
        return LIBRDP_STATUS_IO_ERROR;
    }
    if (!S_ISREG(info.st_mode) ||
        (info.st_uid != 0u && info.st_uid != geteuid()) ||
        (info.st_mode & 0022u) != 0u)
    {
        close(descriptor);
        x11_managed_config_error_set(
            error, 0u, NULL, "unsafe-file-metadata");
        return LIBRDP_STATUS_STATE;
    }
    if (info.st_size < 0 ||
        (uint64_t)info.st_size > X11_MANAGED_CONFIG_MAX_BYTES)
    {
        close(descriptor);
        x11_managed_config_error_set(
            error, 0u, NULL, "file-too-large");
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    expected = (size_t)info.st_size;
    content = (char*)calloc(expected + 1u, 1u);
    if (!content)
    {
        close(descriptor);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    while (used < expected)
    {
        ssize_t received =
            read(descriptor, content + used, expected - used);

        if (received < 0 && errno == EINTR)
            continue;
        if (received <= 0)
            break;
        used += (size_t)received;
    }
    if (used != expected ||
        read(descriptor, &extra, 1u) != 0 ||
        memchr(content, '\0', used) != NULL)
    {
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
        x11_managed_config_error_set(
            error, 0u, NULL, "unstable-or-binary-file");
    }
    else
    {
        content[used] = '\0';
        status = x11_managed_config_parse(
            content, used, policy, error);
    }
    close(descriptor);
    OPENSSL_cleanse(content, expected + 1u);
    free(content);
    return status;
}
