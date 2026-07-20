/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared workspace option, resource and launch-plan policy.
 * Invariants: line and field bounds are enforced before copying remote data,
 * selectors resolve to exactly one current resource, and argv is terminated.
 * Ownership: workspace retains resource strings; launch plans own normalized
 * target, gateway and RemoteApp buffers while borrowing option strings.
 * Threading: callers serialize access to the workspace and destination plan.
 * Trust boundary: feed and command-line values are untrusted; no shell command
 * is constructed and only fixed viewer options are emitted.
 */

#include "workspace_options.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define WORKSPACE_LINE_CAPACITY 512u

void workspace_options_usage(FILE* stream, const char* program)
{
    if (!stream)
        return;
    fprintf(stream,
            "usage: %s --feed url [--user name] [--password value] [--password-env name] "
            "[--domain name] [--timeout ms] [--select id|index|title|alias] "
            "[--viewer path] [--security auto|rdp|tls|nla] [--launch] [--no-window]\n",
            program ? program : "librdp-workspace");
}

static void workspace_options_error(FILE* stream, const char* message, const char* value)
{
    if (!stream || !message)
        return;
    if (value)
        fprintf(stream, message, value);
    else
        fputs(message, stream);
}

static int workspace_options_parse_u32(const char* text, uint32_t* value)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!text || !value)
        return 0;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || !end || end == text || *end != '\0' || parsed > UINT32_MAX)
        return 0;
    *value = (uint32_t)parsed;
    return 1;
}

static int workspace_options_require_value(int argc,
                                           int* index,
                                           char** argv,
                                           FILE* error_stream)
{
    if (!index || !argv || *index < 0 || *index >= argc)
        return 0;
    if (*index + 1 >= argc)
    {
        workspace_options_error(error_stream, "%s requires a value\n", argv[*index]);
        return 0;
    }
    (*index)++;
    return 1;
}

static int workspace_options_valid_security(const char* value)
{
    return value && (strcmp(value, "auto") == 0 || strcmp(value, "rdp") == 0 ||
                     strcmp(value, "tls") == 0 || strcmp(value, "nla") == 0);
}

/*
 * Parse feed and launch policy without contacting a server. The platform
 * supplies only its default viewer executable; all other accepted syntax and
 * credential lookup behavior remains identical across frontends.
 */
int workspace_options_parse(int argc,
                            char** argv,
                            const char* default_viewer,
                            workspace_options* options,
                            FILE* error_stream)
{
    int index = 0;

    if (argc < 1 || !argv || !default_viewer || default_viewer[0] == '\0' || !options)
        return 0;
    memset(options, 0, sizeof(*options));
    if (librdp_workspace_config_init(&options->config) != LIBRDP_STATUS_OK)
        return 0;
    options->viewer = default_viewer;
    options->security = "auto";
    for (index = 1; index < argc; index++)
    {
        if (strcmp(argv[index], "--help") == 0 || strcmp(argv[index], "-h") == 0)
            options->show_help = 1;
        else if (strcmp(argv[index], "--feed") == 0)
        {
            if (!workspace_options_require_value(argc, &index, argv, error_stream))
                return 0;
            options->config.feed_url = argv[index];
        }
        else if (strcmp(argv[index], "--user") == 0)
        {
            if (!workspace_options_require_value(argc, &index, argv, error_stream))
                return 0;
            options->config.username = argv[index];
        }
        else if (strcmp(argv[index], "--password") == 0)
        {
            if (!workspace_options_require_value(argc, &index, argv, error_stream))
                return 0;
            options->config.password = argv[index];
        }
        else if (strcmp(argv[index], "--password-env") == 0)
        {
            if (!workspace_options_require_value(argc, &index, argv, error_stream))
                return 0;
            options->config.password = getenv(argv[index]);
            if (!options->config.password)
            {
                workspace_options_error(error_stream,
                                        "password environment variable is not set\n",
                                        NULL);
                return 0;
            }
        }
        else if (strcmp(argv[index], "--domain") == 0)
        {
            if (!workspace_options_require_value(argc, &index, argv, error_stream))
                return 0;
            options->config.domain = argv[index];
        }
        else if (strcmp(argv[index], "--timeout") == 0)
        {
            if (!workspace_options_require_value(argc, &index, argv, error_stream) ||
                !workspace_options_parse_u32(argv[index], &options->config.timeout_ms))
                return 0;
        }
        else if (strcmp(argv[index], "--select") == 0)
        {
            if (!workspace_options_require_value(argc, &index, argv, error_stream))
                return 0;
            options->select = argv[index];
        }
        else if (strcmp(argv[index], "--viewer") == 0)
        {
            if (!workspace_options_require_value(argc, &index, argv, error_stream))
                return 0;
            options->viewer = argv[index];
        }
        else if (strcmp(argv[index], "--security") == 0)
        {
            if (!workspace_options_require_value(argc, &index, argv, error_stream))
                return 0;
            options->security = argv[index];
            if (!workspace_options_valid_security(options->security))
            {
                workspace_options_error(error_stream, "invalid security mode\n", NULL);
                return 0;
            }
        }
        else if (strcmp(argv[index], "--launch") == 0)
            options->launch = 1;
        else if (strcmp(argv[index], "--no-window") == 0)
            options->no_window = 1;
        else
        {
            workspace_options_error(error_stream, "unknown option: %s\n", argv[index]);
            return 0;
        }
    }
    if (!options->show_help &&
        (!options->config.feed_url || options->config.feed_url[0] == '\0'))
    {
        workspace_options_error(error_stream, "--feed is required\n", NULL);
        return 0;
    }
    return 1;
}

const char* workspace_resource_type_name(librdp_workspace_resource_type type)
{
    switch (type)
    {
        case LIBRDP_WORKSPACE_RESOURCE_DESKTOP:
            return "desktop";
        case LIBRDP_WORKSPACE_RESOURCE_REMOTE_APP:
            return "remote-app";
        default:
            return "unknown";
    }
}

static int workspace_ascii_equal_ci(const char* value,
                                    size_t value_length,
                                    const char* expected)
{
    size_t index = 0;

    if (!value || !expected)
        return 0;
    for (index = 0; index < value_length && expected[index] != '\0'; index++)
    {
        char left = value[index];
        char right = expected[index];

        if (left >= 'A' && left <= 'Z')
            left = (char)(left - 'A' + 'a');
        if (right >= 'A' && right <= 'Z')
            right = (char)(right - 'A' + 'a');
        if (left != right)
            return 0;
    }
    return index == value_length && expected[index] == '\0';
}

static int workspace_copy_value(const char* value,
                                size_t value_length,
                                char* output,
                                size_t output_size)
{
    if (!value || !output || output_size == 0)
        return 0;
    while (value_length > 0 && (value[0] == ' ' || value[0] == '\t'))
    {
        value++;
        value_length--;
    }
    while (value_length > 0 &&
           (value[value_length - 1u] == ' ' || value[value_length - 1u] == '\t' ||
            value[value_length - 1u] == '\r' || value[value_length - 1u] == '\n'))
        value_length--;
    if (value_length == 0 || value_length >= output_size)
        return 0;
    memcpy(output, value, value_length);
    output[value_length] = '\0';
    return 1;
}

/*
 * Read one bounded key:type:value entry from untrusted embedded RDP text.
 * Oversized lines and empty values are ignored rather than partially copied,
 * preventing remote metadata from altering process argument boundaries.
 */
static int workspace_rdp_file_get(const char* contents,
                                  const char* key,
                                  char* output,
                                  size_t output_size)
{
    const char* cursor = contents;

    if (!contents || !key || !output || output_size == 0)
        return 0;
    output[0] = '\0';
    while (*cursor != '\0')
    {
        const char* line = cursor;
        const char* end = line;
        const char* first_colon = NULL;
        const char* second_colon = NULL;

        while (*end != '\0' && *end != '\n')
            end++;
        if ((size_t)(end - line) <= WORKSPACE_LINE_CAPACITY)
        {
            first_colon = memchr(line, ':', (size_t)(end - line));
            if (first_colon)
            {
                second_colon = memchr(first_colon + 1,
                                      ':',
                                      (size_t)(end - first_colon - 1));
                if (second_colon &&
                    workspace_ascii_equal_ci(line,
                                             (size_t)(first_colon - line),
                                             key))
                    return workspace_copy_value(second_colon + 1,
                                                (size_t)(end - second_colon - 1),
                                                output,
                                                output_size);
            }
        }
        cursor = *end == '\n' ? end + 1 : end;
    }
    return 0;
}

int workspace_resource_target(const librdp_workspace_resource* resource,
                              char* output,
                              size_t output_size)
{
    if (!resource || !output || output_size == 0)
        return 0;
    output[0] = '\0';
    if (resource->terminal_server &&
        workspace_copy_value(resource->terminal_server,
                             strlen(resource->terminal_server),
                             output,
                             output_size))
        return 1;
    if (workspace_rdp_file_get(resource->rdp_file_contents,
                               "full address",
                               output,
                               output_size))
        return 1;
    return workspace_rdp_file_get(resource->rdp_file_contents,
                                  "alternate full address",
                                  output,
                                  output_size);
}

/*
 * Read and normalize the optional server port carried by an embedded RDP
 * file. Invalid or out-of-range values are rejected instead of falling back
 * to a different endpoint than the published resource describes.
 */
static int workspace_resource_port(const librdp_workspace_resource* resource,
                                   char* output,
                                   size_t output_size)
{
    char parsed[16];
    uint32_t value = 0;
    int written = 0;

    if (!resource || !output || output_size == 0)
        return 0;
    output[0] = '\0';
    if (!workspace_rdp_file_get(resource->rdp_file_contents,
                                "server port",
                                parsed,
                                sizeof(parsed)))
        return 0;
    if (!workspace_options_parse_u32(parsed, &value) ||
        value == 0u || value > UINT16_MAX)
        return -1;
    written = snprintf(output, output_size, "%u", (unsigned int)value);
    return written > 0 && (size_t)written < output_size ? 1 : -1;
}

int workspace_resource_remote_app(const librdp_workspace_resource* resource,
                                  char* output,
                                  size_t output_size)
{
    if (!resource || !output || output_size == 0)
        return 0;
    output[0] = '\0';
    if (resource->remote_app_program &&
        workspace_copy_value(resource->remote_app_program,
                             strlen(resource->remote_app_program),
                             output,
                             output_size))
        return 1;
    return workspace_rdp_file_get(resource->rdp_file_contents,
                                  "remoteapplicationprogram",
                                  output,
                                  output_size);
}

int workspace_resource_gateway(const librdp_workspace_resource* resource,
                               char* output,
                               size_t output_size)
{
    char host[WORKSPACE_FIELD_CAPACITY];
    int written = 0;

    if (!resource || !output || output_size == 0)
        return 0;
    output[0] = '\0';
    if (!workspace_rdp_file_get(resource->rdp_file_contents,
                                "gatewayhostname",
                                host,
                                sizeof(host)))
        return 0;
    if (strstr(host, "://"))
        return workspace_copy_value(host, strlen(host), output, output_size);
    written = snprintf(output, output_size, "https://%s/", host);
    return written > 0 && (size_t)written < output_size;
}

static int workspace_parse_index(const char* text, size_t count, size_t* index)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!text || !index)
        return 0;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || !end || end == text || *end != '\0' || parsed >= count)
        return 0;
    *index = (size_t)parsed;
    return 1;
}

/*
 * Resolve an index or exact ID, alias, or title against the current workspace
 * generation. Ambiguous implicit selection is rejected unless exactly one
 * resource exists.
 */
int workspace_select_resource(const librdp_workspace* workspace,
                              const char* selector,
                              size_t* selected_index,
                              FILE* error_stream)
{
    size_t count = 0;
    size_t index = 0;
    size_t match = 0;
    int found = 0;

    if (!workspace || !selected_index)
        return 0;
    count = librdp_workspace_resource_count(workspace);
    if (count == 0)
        return 0;
    if (!selector || selector[0] == '\0')
    {
        if (count == 1)
        {
            *selected_index = 0;
            return 1;
        }
        workspace_options_error(
          error_stream,
          "--select is required when the feed contains multiple resources\n",
          NULL);
        return 0;
    }
    if (workspace_parse_index(selector, count, selected_index))
        return 1;
    for (index = 0; index < count; index++)
    {
        librdp_workspace_resource resource;

        if (librdp_workspace_resource_init(&resource) != LIBRDP_STATUS_OK ||
            librdp_workspace_resource_at(workspace, index, &resource) != LIBRDP_STATUS_OK)
            return 0;
        if ((resource.id && strcmp(resource.id, selector) == 0) ||
            (resource.alias && strcmp(resource.alias, selector) == 0) ||
            (resource.title && strcmp(resource.title, selector) == 0))
        {
            if (found)
            {
                workspace_options_error(error_stream,
                                        "selected resource is ambiguous\n",
                                        NULL);
                return 0;
            }
            match = index;
            found = 1;
        }
    }
    if (found)
    {
        *selected_index = match;
        return 1;
    }
    workspace_options_error(error_stream, "selected resource was not found\n", NULL);
    return 0;
}

static int workspace_launch_add(workspace_launch_plan* plan, const char* argument)
{
    if (!plan || !argument ||
        plan->argument_count + 1u >= WORKSPACE_LAUNCH_ARGUMENT_CAPACITY)
        return 0;
    plan->arguments[plan->argument_count++] = argument;
    plan->arguments[plan->argument_count] = NULL;
    return 1;
}

/*
 * Build an argv-style launch plan without invoking a shell or native process
 * API. Fixed buffers own normalized remote fields, while option and credential
 * pointers remain borrowed for the immediate platform launch call.
 */
int workspace_launch_plan_build(const workspace_options* options,
                                const librdp_workspace_resource* resource,
                                workspace_launch_plan* plan,
                                FILE* error_stream)
{
    int written = 0;
    int port_status = 0;

    if (!options || !resource || !plan || !options->viewer ||
        options->viewer[0] == '\0' || !workspace_options_valid_security(options->security))
        return 0;
    memset(plan, 0, sizeof(*plan));
    plan->executable = options->viewer;
    if (!workspace_resource_target(resource, plan->target, sizeof(plan->target)))
    {
        workspace_options_error(error_stream,
                                "selected resource does not contain a launch target\n",
                                NULL);
        return 0;
    }
    if (!workspace_launch_add(plan, options->viewer) ||
        !workspace_launch_add(plan, "--target") ||
        !workspace_launch_add(plan, plan->target) ||
        !workspace_launch_add(plan, "--security") ||
        !workspace_launch_add(plan, options->security))
        return 0;
    port_status = workspace_resource_port(resource,
                                          plan->port,
                                          sizeof(plan->port));
    if (port_status < 0)
    {
        workspace_options_error(error_stream,
                                "selected resource contains an invalid server port\n",
                                NULL);
        return 0;
    }
    if (port_status > 0 &&
        (!workspace_launch_add(plan, "--port") ||
         !workspace_launch_add(plan, plan->port)))
        return 0;
    if (options->config.username &&
        (!workspace_launch_add(plan, "--user") ||
         !workspace_launch_add(plan, options->config.username)))
        return 0;
    if (options->config.password &&
        (!workspace_launch_add(plan, "--password") ||
         !workspace_launch_add(plan, options->config.password)))
        return 0;
    if (options->config.domain &&
        (!workspace_launch_add(plan, "--domain") ||
         !workspace_launch_add(plan, options->config.domain)))
        return 0;
    if (workspace_resource_remote_app(resource,
                                      plan->remote_app,
                                      sizeof(plan->remote_app)))
    {
        written = snprintf(plan->rail_argument,
                           sizeof(plan->rail_argument),
                           "app=%s",
                           plan->remote_app);
        if (written <= 0 || (size_t)written >= sizeof(plan->rail_argument) ||
            !workspace_launch_add(plan, "--rail") ||
            !workspace_launch_add(plan, plan->rail_argument))
        {
            workspace_options_error(error_stream,
                                    "remote app launch field is too long\n",
                                    NULL);
            return 0;
        }
    }
    if (workspace_resource_gateway(resource, plan->gateway, sizeof(plan->gateway)) &&
        (!workspace_launch_add(plan, "--gateway") ||
         !workspace_launch_add(plan, plan->gateway) ||
         !workspace_launch_add(plan, "--gateway-mode") ||
         !workspace_launch_add(plan, "rdg-http")))
        return 0;
    return 1;
}
