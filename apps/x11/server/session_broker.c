/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/*
 * Module: managed X11 session broker process.
 * Invariants: security defaults to NLA, Standard Security requires explicit
 * opt-in and file/CLI policy uses one bounded value parser.
 * Ownership: the parsed policy is copied by the broker constructor.
 * Threading: a signal-wait thread cancels the broker through its thread-safe
 * wakeup path.
 * Trust boundary: configuration never accepts credentials; authentication
 * secrets arrive only over the bounded local IPC conversation.
 */

#include "server_managed_broker.h"
#include "server_managed_config.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

typedef struct x11_session_broker_signal
{
    x11_managed_broker* broker;
    sigset_t signals;
} x11_session_broker_signal;

typedef struct x11_session_broker_option
{
    const char* option;
    const char* key;
    const char* fixed_value;
} x11_session_broker_option;

static const x11_session_broker_option
x11_session_broker_options[] = {
    {"--socket", "socket", NULL},
    {"--runtime-root", "runtime-root", NULL},
    {"--supervisor", "supervisor", NULL},
    {"--agent", "agent", NULL},
    {"--xserver", "xserver", NULL},
    {"--auth-service", "auth-service", NULL},
    {"--desktop", "desktop", NULL},
    {"--bind", "bind", NULL},
    {"--security", "security", NULL},
    {"--tls-cert", "tls-cert", NULL},
    {"--tls-key", "tls-key", NULL},
    {"--allow-user", "allow-user", NULL},
    {"--allow-group", "allow-group", NULL},
    {"--allow-env", "allow-env", NULL},
    {"--max-sessions", "max-sessions", NULL},
    {"--max-sessions-per-user",
     "max-sessions-per-user",
     NULL},
    {"--first-display", "first-display", NULL},
    {"--last-display", "last-display", NULL},
    {"--idle-seconds", "idle-seconds", NULL},
    {"--max-duration-seconds",
     "max-duration-seconds",
     NULL},
    {"--socket-mode", "socket-mode", NULL},
    {"--socket-group", "socket-group", NULL},
    {"--allow-standard-security",
     "allow-standard-security",
     "true"},
    {"--deny-standard-security",
     "allow-standard-security",
     "false"},
    {"--allow-user-switch", "allow-user-switch", "true"},
    {"--deny-user-switch", "allow-user-switch", "false"},
    {"--allow-input", "allow-input", "true"},
    {"--deny-input", "allow-input", "false"},
    {"--allow-clipboard", "allow-clipboard", "true"},
    {"--deny-clipboard", "allow-clipboard", "false"},
    {"--allow-drive", "allow-drive", "true"},
    {"--deny-drive", "allow-drive", "false"},
    {"--drive-read-only", "drive-read-only", "true"},
    {"--drive-read-write", "drive-read-only", "false"},
    {"--allow-reconnect", "allow-reconnect", "true"},
    {"--no-reconnect", "allow-reconnect", "false"},
    {"--persistent", "persistent", "true"},
    {"--non-persistent", "persistent", "false"},
    {"--xvfb", "xvfb", "true"},
    {"--xorg", "xvfb", "false"},
};

static const x11_session_broker_option*
x11_session_broker_find_option(const char* option)
{
    size_t index = 0u;

    if (!option)
        return NULL;
    for (index = 0u;
         index < sizeof(x11_session_broker_options) /
                     sizeof(x11_session_broker_options[0]);
         index++)
    {
        if (strcmp(x11_session_broker_options[index].option,
                   option) == 0)
            return &x11_session_broker_options[index];
    }
    return NULL;
}

static const char* x11_session_broker_security_name(
    librdp_security_mode mode)
{
    switch (mode)
    {
        case LIBRDP_SECURITY_STANDARD:
            return "standard";
        case LIBRDP_SECURITY_TLS:
            return "tls";
        case LIBRDP_SECURITY_NLA:
            return "nla";
        case LIBRDP_SECURITY_AUTO:
        default:
            return "unknown";
    }
}

static void x11_session_broker_usage(FILE* stream,
                                     const char* program)
{
    fprintf(
        stream,
        "usage: %s [--config path] --desktop command "
        "[--check-config] [--socket path] [--runtime-root path] "
        "[--supervisor path] [--agent path] [--xserver path] "
        "[--auth-service name] [--bind address] "
        "[--security nla|tls|standard] "
        "[--tls-cert path --tls-key path] "
        "[--allow-standard-security|--deny-standard-security] "
        "[--allow-user name] [--allow-group name] "
        "[--allow-user-switch|--deny-user-switch] "
        "[--allow-env name] [--max-sessions count] "
        "[--max-sessions-per-user count] "
        "[--first-display number] [--last-display number] "
        "[--idle-seconds value] [--max-duration-seconds value] "
        "[--socket-mode octal] [--socket-group name] "
        "[--allow-input|--deny-input] "
        "[--allow-clipboard|--deny-clipboard] "
        "[--allow-drive|--deny-drive] "
        "[--drive-read-only|--drive-read-write] "
        "[--allow-reconnect|--no-reconnect] "
        "[--persistent|--non-persistent] [--xorg|--xvfb]\n",
        program);
}

static void x11_session_broker_parse_error(
    x11_managed_config_error* error,
    const char* key,
    const char* detail)
{
    size_t length = 0u;

    if (!error)
        return;
    error->line = 0u;
    error->key[0] = '\0';
    error->detail[0] = '\0';
    length = key ? strlen(key) : 0u;
    if (length < sizeof(error->key))
        memcpy(error->key, key, length + 1u);
    length = detail ? strlen(detail) : 0u;
    if (length < sizeof(error->detail))
        memcpy(error->detail, detail, length + 1u);
}

/*
 * A configuration file, when used, must be the first argument. This removes
 * ambiguity between option values and file selection while preserving a clear
 * precedence rule: later command-line options override file values.
 */
static int x11_session_broker_parse(
    int argc,
    char** argv,
    x11_managed_policy* policy,
    x11_managed_config_error* error)
{
    int index = 1;
    int check_only = 0;

    x11_managed_policy_init(policy);
    x11_managed_config_error_init(error);
    if (index < argc &&
        strcmp(argv[index], "--config") == 0)
    {
        librdp_status status = LIBRDP_STATUS_OK;

        if (index + 1 >= argc)
        {
            x11_session_broker_parse_error(
                error, "--config", "missing-value");
            return 0;
        }
        status = x11_managed_config_load(
            argv[index + 1], policy, error);
        if (status != LIBRDP_STATUS_OK)
            return 0;
        index += 2;
    }
    for (; index < argc; index++)
    {
        const x11_session_broker_option* option = NULL;
        const char* value = NULL;
        librdp_status status = LIBRDP_STATUS_OK;

        if (strcmp(argv[index], "--help") == 0 ||
            strcmp(argv[index], "-h") == 0)
            return 2;
        if (strcmp(argv[index], "--check-config") == 0)
        {
            check_only = 1;
            continue;
        }
        option = x11_session_broker_find_option(argv[index]);
        if (!option)
        {
            x11_session_broker_parse_error(
                error, argv[index], "unknown-option");
            return 0;
        }
        value = option->fixed_value;
        if (!value)
        {
            if (index + 1 >= argc)
            {
                x11_session_broker_parse_error(
                    error, argv[index], "missing-value");
                return 0;
            }
            value = argv[++index];
        }
        status = x11_managed_config_apply(
            policy, option->key, value, error);
        if (status != LIBRDP_STATUS_OK)
            return 0;
    }
    if (!x11_managed_policy_valid(policy))
    {
        x11_session_broker_parse_error(
            error, NULL, "incomplete-or-conflicting-policy");
        return 0;
    }
    return check_only ? 3 : 1;
}

static void* x11_session_broker_wait_signal(void* user_data)
{
    x11_session_broker_signal* context =
        (x11_session_broker_signal*)user_data;
    int signal_number = 0;

    if (sigwait(&context->signals, &signal_number) == 0)
        (void)x11_managed_broker_cancel(context->broker);
    return NULL;
}

static void x11_session_broker_report_config_error(
    const x11_managed_config_error* error)
{
    fprintf(stderr,
            "librdp x11-session-broker event=config.failed "
            "line=%u key=\"%s\" reason=%s\n",
            error ? error->line : 0u,
            error ? error->key : "",
            error && error->detail[0] != '\0'
                ? error->detail
                : "invalid-configuration");
}

int main(int argc, char** argv)
{
    x11_managed_policy policy;
    x11_managed_config_error config_error;
    x11_managed_broker* broker = NULL;
    x11_session_broker_signal signal_context;
    pthread_t signal_thread;
    librdp_status status = LIBRDP_STATUS_OK;
    int parsed = x11_session_broker_parse(
        argc, argv, &policy, &config_error);

    if (parsed == 2)
    {
        x11_session_broker_usage(stdout, argv[0]);
        return 0;
    }
    if (parsed == 0)
    {
        x11_session_broker_report_config_error(&config_error);
        x11_session_broker_usage(stderr, argv[0]);
        return 2;
    }
    if (parsed == 3)
    {
        fprintf(stdout,
                "librdp x11-session-broker event=config.valid "
                "security=%s\n",
                x11_session_broker_security_name(
                    policy.security_mode));
        return 0;
    }
    broker = x11_managed_broker_new(&policy, &status);
    if (!broker)
    {
        fprintf(stderr,
                "librdp x11-session-broker "
                "event=broker.create.failed status=%s\n",
                librdp_status_name(status));
        return 1;
    }
    memset(&signal_context, 0, sizeof(signal_context));
    signal_context.broker = broker;
    sigemptyset(&signal_context.signals);
    sigaddset(&signal_context.signals, SIGINT);
    sigaddset(&signal_context.signals, SIGTERM);
    sigaddset(&signal_context.signals, SIGHUP);
    if (pthread_sigmask(
            SIG_BLOCK, &signal_context.signals, NULL) != 0 ||
        pthread_create(
            &signal_thread,
            NULL,
            x11_session_broker_wait_signal,
            &signal_context) != 0)
    {
        x11_managed_broker_free(broker);
        return 1;
    }
    fprintf(stderr,
            "librdp x11-session-broker event=broker.start "
            "socket=\"%s\" security=%s\n",
            x11_managed_broker_socket_path(broker),
            x11_session_broker_security_name(
                policy.security_mode));
    status = x11_managed_broker_run(broker);
    (void)pthread_kill(signal_thread, SIGTERM);
    (void)pthread_join(signal_thread, NULL);
    fprintf(stderr,
            "librdp x11-session-broker event=broker.stop "
            "status=%s\n",
            librdp_status_name(status));
    x11_managed_broker_free(broker);
    return status == LIBRDP_STATUS_OK ? 0 : 1;
}
