/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/*
 * Module: managed X11 session broker command line.
 * Invariants: security defaults to NLA, Standard Security requires explicit
 * opt-in and every path, count and duration is bounded before broker startup.
 * Ownership: the parsed policy is copied by the broker constructor.
 * Threading: a signal-wait thread cancels the broker through its thread-safe
 * wakeup path.
 * Trust boundary: this process accepts administrative policy only; user
 * credentials arrive over authenticated IPC and are never stored in config.
 */

#include "server_managed_broker.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct x11_session_broker_signal
{
    x11_managed_broker* broker;
    sigset_t signals;
} x11_session_broker_signal;

static int x11_session_broker_copy(char* output,
                                   size_t capacity,
                                   const char* input)
{
    size_t length = input ? strlen(input) : 0u;

    if (!output || capacity == 0u || !input || length >= capacity)
        return 0;
    memcpy(output, input, length + 1u);
    return 1;
}

static int x11_session_broker_u64(const char* value,
                                  uint64_t maximum,
                                  uint64_t* output)
{
    char* end = NULL;
    unsigned long long parsed = 0ull;

    if (!value || !output || value[0] == '\0' || value[0] == '-')
        return 0;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' ||
        (uint64_t)parsed > maximum)
        return 0;
    *output = (uint64_t)parsed;
    return 1;
}

static int x11_session_broker_duration(const char* value,
                                       uint64_t* nanoseconds)
{
    uint64_t seconds = 0u;

    if (!x11_session_broker_u64(
            value, UINT64_MAX / 1000000000u, &seconds))
        return 0;
    *nanoseconds = seconds * 1000000000u;
    return 1;
}

static int x11_session_broker_security(
    const char* value,
    librdp_security_mode* mode)
{
    if (!value || !mode)
        return 0;
    if (strcmp(value, "nla") == 0)
        *mode = LIBRDP_SECURITY_NLA;
    else if (strcmp(value, "tls") == 0)
        *mode = LIBRDP_SECURITY_TLS;
    else if (strcmp(value, "standard") == 0)
        *mode = LIBRDP_SECURITY_STANDARD;
    else
        return 0;
    return 1;
}

static void x11_session_broker_usage(FILE* stream,
                                     const char* program)
{
    fprintf(
        stream,
        "usage: %s --desktop path [--socket path] [--runtime-root path] "
        "[--supervisor path] [--agent path] [--xserver path] "
        "[--auth-service name] [--bind address] [--security nla|tls|standard] "
        "[--tls-cert path --tls-key path] [--allow-standard-security] "
        "[--allow-user name] [--allow-group name] [--allow-user-switch] "
        "[--allow-env name] [--max-sessions count] "
        "[--max-sessions-per-user count] [--first-display number] "
        "[--last-display number] [--idle-seconds value] "
        "[--max-duration-seconds value] [--allow-input] "
        "[--allow-clipboard] [--allow-drive] [--drive-read-write] "
        "[--no-reconnect] [--non-persistent] [--xvfb]\n",
        program);
}

static int x11_session_broker_value(int argc,
                                    char** argv,
                                    int* index)
{
    if (!argv || !index || *index + 1 >= argc)
        return 0;
    (*index)++;
    return 1;
}

static int x11_session_broker_path_option(
    int argc,
    char** argv,
    int* index,
    char* output,
    size_t capacity)
{
    return x11_session_broker_value(argc, argv, index) &&
           argv[*index][0] == '/' &&
           x11_session_broker_copy(
               output, capacity, argv[*index]);
}

static int x11_session_broker_parse(
    int argc,
    char** argv,
    x11_managed_policy* policy)
{
    int index = 0;

    x11_managed_policy_init(policy);
    for (index = 1; index < argc; index++)
    {
        const char* option = argv[index];
        uint64_t value = 0u;

        if (strcmp(option, "--help") == 0 ||
            strcmp(option, "-h") == 0)
            return 2;
        if (strcmp(option, "--socket") == 0)
        {
            if (!x11_session_broker_path_option(
                    argc, argv, &index, policy->socket_path,
                    sizeof(policy->socket_path)))
                return 0;
        }
        else if (strcmp(option, "--runtime-root") == 0)
        {
            if (!x11_session_broker_path_option(
                    argc, argv, &index, policy->runtime_root,
                    sizeof(policy->runtime_root)))
                return 0;
        }
        else if (strcmp(option, "--supervisor") == 0)
        {
            if (!x11_session_broker_path_option(
                    argc, argv, &index, policy->supervisor_path,
                    sizeof(policy->supervisor_path)))
                return 0;
        }
        else if (strcmp(option, "--agent") == 0)
        {
            if (!x11_session_broker_path_option(
                    argc, argv, &index, policy->agent_path,
                    sizeof(policy->agent_path)))
                return 0;
        }
        else if (strcmp(option, "--xserver") == 0)
        {
            if (!x11_session_broker_path_option(
                    argc, argv, &index, policy->xserver_path,
                    sizeof(policy->xserver_path)))
                return 0;
        }
        else if (strcmp(option, "--desktop") == 0)
        {
            if (!x11_session_broker_path_option(
                    argc, argv, &index, policy->desktop_command,
                    sizeof(policy->desktop_command)))
                return 0;
        }
        else if (strcmp(option, "--tls-cert") == 0)
        {
            if (!x11_session_broker_path_option(
                    argc, argv, &index, policy->tls_certificate,
                    sizeof(policy->tls_certificate)))
                return 0;
        }
        else if (strcmp(option, "--tls-key") == 0)
        {
            if (!x11_session_broker_path_option(
                    argc, argv, &index, policy->tls_private_key,
                    sizeof(policy->tls_private_key)))
                return 0;
        }
        else if (strcmp(option, "--auth-service") == 0)
        {
            if (!x11_session_broker_value(argc, argv, &index) ||
                !x11_session_broker_copy(
                    policy->authentication_service,
                    sizeof(policy->authentication_service),
                    argv[index]))
                return 0;
        }
        else if (strcmp(option, "--bind") == 0)
        {
            if (!x11_session_broker_value(argc, argv, &index) ||
                !x11_session_broker_copy(
                    policy->bind_address,
                    sizeof(policy->bind_address),
                    argv[index]))
                return 0;
        }
        else if (strcmp(option, "--security") == 0)
        {
            if (!x11_session_broker_value(argc, argv, &index) ||
                !x11_session_broker_security(
                    argv[index], &policy->security_mode))
                return 0;
        }
        else if (strcmp(option, "--allow-user") == 0)
        {
            if (!x11_session_broker_value(argc, argv, &index) ||
                x11_managed_policy_add_user(
                    policy, argv[index]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(option, "--allow-group") == 0)
        {
            if (!x11_session_broker_value(argc, argv, &index) ||
                x11_managed_policy_add_group(
                    policy, argv[index]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(option, "--allow-env") == 0)
        {
            if (!x11_session_broker_value(argc, argv, &index) ||
                x11_managed_policy_add_environment(
                    policy, argv[index]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(option, "--max-sessions") == 0)
        {
            if (!x11_session_broker_value(argc, argv, &index) ||
                !x11_session_broker_u64(
                    argv[index],
                    X11_MANAGED_REGISTRY_MAX_SESSIONS,
                    &value) ||
                value == 0u)
                return 0;
            policy->max_sessions = (uint32_t)value;
        }
        else if (strcmp(option, "--max-sessions-per-user") == 0)
        {
            if (!x11_session_broker_value(argc, argv, &index) ||
                !x11_session_broker_u64(
                    argv[index],
                    X11_MANAGED_REGISTRY_MAX_PER_USER,
                    &value) ||
                value == 0u)
                return 0;
            policy->max_sessions_per_user = (uint32_t)value;
        }
        else if (strcmp(option, "--first-display") == 0)
        {
            if (!x11_session_broker_value(argc, argv, &index) ||
                !x11_session_broker_u64(
                    argv[index],
                    X11_MANAGED_REGISTRY_MAX_DISPLAY,
                    &value))
                return 0;
            policy->first_display = (uint32_t)value;
        }
        else if (strcmp(option, "--last-display") == 0)
        {
            if (!x11_session_broker_value(argc, argv, &index) ||
                !x11_session_broker_u64(
                    argv[index],
                    X11_MANAGED_REGISTRY_MAX_DISPLAY,
                    &value))
                return 0;
            policy->last_display = (uint32_t)value;
        }
        else if (strcmp(option, "--idle-seconds") == 0)
        {
            if (!x11_session_broker_value(argc, argv, &index) ||
                !x11_session_broker_duration(
                    argv[index], &policy->idle_timeout_ns))
                return 0;
        }
        else if (strcmp(option, "--max-duration-seconds") == 0)
        {
            if (!x11_session_broker_value(argc, argv, &index) ||
                !x11_session_broker_duration(
                    argv[index], &policy->max_duration_ns))
                return 0;
        }
        else if (strcmp(option, "--allow-standard-security") == 0)
            policy->allow_standard_security = 1;
        else if (strcmp(option, "--allow-user-switch") == 0)
            policy->allow_user_switch = 1;
        else if (strcmp(option, "--allow-input") == 0)
            policy->allow_input = 1;
        else if (strcmp(option, "--allow-clipboard") == 0)
            policy->allow_clipboard = 1;
        else if (strcmp(option, "--allow-drive") == 0)
            policy->allow_drive = 1;
        else if (strcmp(option, "--drive-read-write") == 0)
            policy->drive_read_only = 0;
        else if (strcmp(option, "--no-reconnect") == 0)
            policy->allow_reconnect = 0;
        else if (strcmp(option, "--non-persistent") == 0)
            policy->persistent_sessions = 0;
        else if (strcmp(option, "--xvfb") == 0)
            policy->use_xvfb = 1;
        else
            return 0;
    }
    return x11_managed_policy_valid(policy) ? 1 : 0;
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

int main(int argc, char** argv)
{
    x11_managed_policy policy;
    x11_managed_broker* broker = NULL;
    x11_session_broker_signal signal_context;
    pthread_t signal_thread;
    librdp_status status = LIBRDP_STATUS_OK;
    int parsed = x11_session_broker_parse(argc, argv, &policy);
    int signal_started = 0;

    if (parsed == 2)
    {
        x11_session_broker_usage(stdout, argv[0]);
        return 0;
    }
    if (parsed != 1)
    {
        x11_session_broker_usage(stderr, argv[0]);
        return 2;
    }
    broker = x11_managed_broker_new(&policy, &status);
    if (!broker)
    {
        fprintf(stderr,
                "error=broker.create status=%s\n",
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
    signal_started = 1;
    status = x11_managed_broker_run(broker);
    if (signal_started)
    {
        (void)pthread_kill(signal_thread, SIGTERM);
        (void)pthread_join(signal_thread, NULL);
    }
    x11_managed_broker_free(broker);
    return status == LIBRDP_STATUS_OK ? 0 : 1;
}
