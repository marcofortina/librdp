/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared administration option parser and action policy.
 * Invariants: query mode carries no action-only fields, destructive actions
 * require confirmation, and every executable action has a non-zero session.
 * Ownership: accepted strings are borrowed; public admin construction copies
 * configuration and credentials into its own storage.
 * Threading: one startup thread owns the destination structure.
 * Trust boundary: argv and environment values may contain sensitive or
 * malformed input and are never echoed by this module.
 */

#include "admin_options.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ADMIN_ACTION_QUERY ((librdp_admin_action_type)0)

void admin_options_usage(FILE* stream, const char* program)
{
    if (!stream)
        return;
    fprintf(stream,
            "usage: %s --endpoint url [--user name] [--password value] [--password-env name] "
            "[--domain name] [--resource-uri uri] [--timeout ms] [--insecure-lab] "
            "[--action query|logoff|disconnect|message] [--session-id id] "
            "[--message-title text] [--message-text text] [--confirm] [--no-window]\n",
            program ? program : "librdp-admin");
}

static void admin_options_error(FILE* stream, const char* message, const char* value)
{
    if (!stream || !message)
        return;
    if (value)
        fprintf(stream, message, value);
    else
        fputs(message, stream);
}

static int admin_options_parse_u32(const char* text, uint32_t* value)
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

static int admin_options_require_value(int argc,
                                       int* index,
                                       char** argv,
                                       FILE* error_stream)
{
    if (!index || !argv || *index < 0 || *index >= argc)
        return 0;
    if (*index + 1 >= argc)
    {
        admin_options_error(error_stream, "%s requires a value\n", argv[*index]);
        return 0;
    }
    (*index)++;
    return 1;
}

static int admin_options_parse_action(const char* text, librdp_admin_action_type* type)
{
    if (!text || !type)
        return 0;
    if (strcmp(text, "query") == 0)
        *type = ADMIN_ACTION_QUERY;
    else if (strcmp(text, "logoff") == 0)
        *type = LIBRDP_ADMIN_ACTION_LOGOFF;
    else if (strcmp(text, "disconnect") == 0)
        *type = LIBRDP_ADMIN_ACTION_DISCONNECT;
    else if (strcmp(text, "message") == 0)
        *type = LIBRDP_ADMIN_ACTION_MESSAGE;
    else
        return 0;
    return 1;
}

/*
 * Validate relationships between action fields after parsing so no frontend
 * can accidentally permit an unconfirmed destructive action or silently
 * attach message data to a different operation.
 */
static int admin_options_validate(admin_options* options, FILE* error_stream)
{
    if (!options)
        return 0;
    if (!options->show_help &&
        (!options->config.endpoint_url || options->config.endpoint_url[0] == '\0'))
    {
        admin_options_error(error_stream, "--endpoint is required\n", NULL);
        return 0;
    }
    if (options->execute_action)
    {
        if (options->action.session_id == 0)
        {
            admin_options_error(error_stream,
                                "--session-id is required for admin actions\n",
                                NULL);
            return 0;
        }
        if ((options->action.type == LIBRDP_ADMIN_ACTION_LOGOFF ||
             options->action.type == LIBRDP_ADMIN_ACTION_DISCONNECT) &&
            !options->confirm_action)
        {
            admin_options_error(error_stream,
                                "--confirm is required for logoff and disconnect actions\n",
                                NULL);
            return 0;
        }
        if (options->action.type != LIBRDP_ADMIN_ACTION_MESSAGE &&
            (options->action.message_title || options->action.message_text))
        {
            admin_options_error(error_stream,
                                "message fields are valid only with --action message\n",
                                NULL);
            return 0;
        }
        if (options->action.type == LIBRDP_ADMIN_ACTION_MESSAGE &&
            !options->action.message_text)
        {
            admin_options_error(error_stream,
                                "--message-text is required with --action message\n",
                                NULL);
            return 0;
        }
    }
    else if (options->action.session_id != 0 || options->action.message_title ||
             options->action.message_text || options->confirm_action)
    {
        admin_options_error(
          error_stream,
          "admin action options require --action logoff|disconnect|message\n",
          NULL);
        return 0;
    }
    return 1;
}

/*
 * Parse common administration CLI syntax without performing I/O. Environment
 * lookup resolves only the named password value and never reports its
 * contents; the returned pointers remain valid for immediate handle creation.
 */
int admin_options_parse(int argc,
                        char** argv,
                        admin_options* options,
                        FILE* error_stream)
{
    int index = 0;

    if (argc < 1 || !argv || !options)
        return 0;
    memset(options, 0, sizeof(*options));
    if (librdp_admin_config_init(&options->config) != LIBRDP_STATUS_OK ||
        librdp_admin_action_init(&options->action) != LIBRDP_STATUS_OK)
        return 0;
    for (index = 1; index < argc; index++)
    {
        if (strcmp(argv[index], "--help") == 0 || strcmp(argv[index], "-h") == 0)
            options->show_help = 1;
        else if (strcmp(argv[index], "--endpoint") == 0)
        {
            if (!admin_options_require_value(argc, &index, argv, error_stream))
                return 0;
            options->config.endpoint_url = argv[index];
        }
        else if (strcmp(argv[index], "--user") == 0)
        {
            if (!admin_options_require_value(argc, &index, argv, error_stream))
                return 0;
            options->config.username = argv[index];
        }
        else if (strcmp(argv[index], "--password") == 0)
        {
            if (!admin_options_require_value(argc, &index, argv, error_stream))
                return 0;
            options->config.password = argv[index];
        }
        else if (strcmp(argv[index], "--password-env") == 0)
        {
            if (!admin_options_require_value(argc, &index, argv, error_stream))
                return 0;
            options->config.password = getenv(argv[index]);
            if (!options->config.password)
            {
                admin_options_error(error_stream,
                                    "password environment variable is not set\n",
                                    NULL);
                return 0;
            }
        }
        else if (strcmp(argv[index], "--domain") == 0)
        {
            if (!admin_options_require_value(argc, &index, argv, error_stream))
                return 0;
            options->config.domain = argv[index];
        }
        else if (strcmp(argv[index], "--resource-uri") == 0)
        {
            if (!admin_options_require_value(argc, &index, argv, error_stream))
                return 0;
            options->config.resource_uri = argv[index];
        }
        else if (strcmp(argv[index], "--timeout") == 0)
        {
            if (!admin_options_require_value(argc, &index, argv, error_stream) ||
                !admin_options_parse_u32(argv[index], &options->config.timeout_ms))
                return 0;
        }
        else if (strcmp(argv[index], "--insecure-lab") == 0)
            options->config.allow_insecure_tls = 1;
        else if (strcmp(argv[index], "--no-window") == 0)
            options->no_window = 1;
        else if (strcmp(argv[index], "--action") == 0)
        {
            librdp_admin_action_type type = ADMIN_ACTION_QUERY;

            if (!admin_options_require_value(argc, &index, argv, error_stream) ||
                !admin_options_parse_action(argv[index], &type))
                return 0;
            options->execute_action = type != ADMIN_ACTION_QUERY;
            if (options->execute_action)
                options->action.type = type;
        }
        else if (strcmp(argv[index], "--session-id") == 0)
        {
            if (!admin_options_require_value(argc, &index, argv, error_stream) ||
                !admin_options_parse_u32(argv[index], &options->action.session_id))
                return 0;
        }
        else if (strcmp(argv[index], "--message-title") == 0)
        {
            if (!admin_options_require_value(argc, &index, argv, error_stream))
                return 0;
            options->action.message_title = argv[index];
        }
        else if (strcmp(argv[index], "--message-text") == 0)
        {
            if (!admin_options_require_value(argc, &index, argv, error_stream))
                return 0;
            options->action.message_text = argv[index];
        }
        else if (strcmp(argv[index], "--confirm") == 0)
            options->confirm_action = 1;
        else
        {
            admin_options_error(error_stream, "unknown option: %s\n", argv[index]);
            return 0;
        }
    }
    return admin_options_validate(options, error_stream);
}
