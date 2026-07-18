/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * Module: headless Xorg/Xvfb and desktop process supervision.
 * Invariants: generated files are private, no shell interprets desktop
 * commands and child process groups are terminated as one unit.
 * Ownership: temporary argv/environment allocations are parent-owned and
 * released after fork; generated files belong to the process group.
 * Threading: startup, resize and teardown are serialized by one supervisor.
 * Trust boundary: account metadata, environment and commands are validated
 * before they reach setgroups, execve or the X server.
 */

#include "server_managed_process.h"

#include <X11/X.h>
#include <X11/Xauth.h>
#include <X11/Xlib.h>
#include <X11/extensions/Xrandr.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define X11_MANAGED_PROCESS_ENVIRONMENT_MAX 160u
#define X11_MANAGED_PROCESS_ENVIRONMENT_BYTES 8192u

typedef struct x11_managed_argv
{
    char storage[8192];
    char* values[X11_MANAGED_PROCESS_MAX_ARGUMENTS + 1u];
    size_t count;
} x11_managed_argv;

typedef struct x11_managed_environment
{
    char* values[X11_MANAGED_PROCESS_ENVIRONMENT_MAX + 1u];
    size_t count;
} x11_managed_environment;

static uint64_t x11_managed_process_now_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0u;
    return (uint64_t)now.tv_sec * 1000u +
           (uint64_t)now.tv_nsec / 1000000u;
}

static int x11_managed_process_copy(char* output,
                                    size_t capacity,
                                    const char* input)
{
    size_t length = input ? strlen(input) : 0u;

    if (!output || capacity == 0u || !input || length >= capacity)
        return 0;
    memcpy(output, input, length + 1u);
    return 1;
}

static int x11_managed_process_path(char* output,
                                    size_t capacity,
                                    const char* directory,
                                    const char* name)
{
    int length = 0;

    if (!output || capacity == 0u || !directory || !name ||
        name[0] == '\0' || strchr(name, '/'))
        return 0;
    length = snprintf(output, capacity, "%s/%s", directory, name);
    return length >= 0 && (size_t)length < capacity;
}

void x11_managed_process_config_init(
    x11_managed_process_config* config)
{
    if (!config)
        return;
    memset(config, 0, sizeof(*config));
    config->version = X11_MANAGED_PROCESS_VERSION;
    config->size = sizeof(*config);
    config->xserver_path = "/usr/bin/Xorg";
    config->startup_timeout_ms = 10000;
}

void x11_managed_process_group_init(
    x11_managed_process_group* group)
{
    if (!group)
        return;
    memset(group, 0, sizeof(*group));
    group->version = X11_MANAGED_PROCESS_VERSION;
    group->size = sizeof(*group);
}

static int x11_managed_process_identity_valid(
    const x11_managed_auth_identity* identity)
{
    return identity &&
           identity->version == X11_MANAGED_AUTH_VERSION &&
           identity->size >= sizeof(*identity) &&
           identity->username[0] != '\0' &&
           memchr(identity->username,
                  '\0',
                  sizeof(identity->username)) != NULL &&
           identity->home[0] == '/' &&
           memchr(identity->home,
                  '\0',
                  sizeof(identity->home)) != NULL &&
           identity->shell[0] == '/' &&
           memchr(identity->shell,
                  '\0',
                  sizeof(identity->shell)) != NULL &&
           identity->group_count > 0u &&
           identity->group_count <= X11_MANAGED_AUTH_MAX_GROUPS;
}

static int x11_managed_process_config_valid(
    const x11_managed_process_config* config)
{
    size_t index = 0u;

    if (!config ||
        config->version != X11_MANAGED_PROCESS_VERSION ||
        config->size < sizeof(*config) ||
        !x11_managed_process_identity_valid(config->identity) ||
        !config->display_name || config->display_name[0] != ':' ||
        strnlen(config->display_name, 64u) >= 64u ||
        !config->authority_path ||
        config->authority_path[0] != '/' ||
        strnlen(config->authority_path, 4096u) >= 4096u ||
        !config->runtime_directory ||
        config->runtime_directory[0] != '/' ||
        strnlen(config->runtime_directory, 4096u) >= 4096u ||
        !config->xserver_path || config->xserver_path[0] != '/' ||
        strnlen(config->xserver_path, 4096u) >= 4096u ||
        !config->desktop_command ||
        config->desktop_command[0] == '\0' ||
        strnlen(config->desktop_command, 8192u) >= 8192u ||
        config->width == 0u || config->height == 0u ||
        config->width > 16384u || config->height > 16384u ||
        config->startup_timeout_ms <= 0 ||
        config->startup_timeout_ms > 120000 ||
        config->login_environment_count >
            X11_MANAGED_AUTH_MAX_ENVIRONMENT ||
        (config->login_environment_count > 0u &&
         !config->login_environment) ||
        (config->environment_allowlist &&
         strnlen(config->environment_allowlist,
                 X11_MANAGED_PROCESS_ENVIRONMENT_ALLOWLIST_BYTES) >=
             X11_MANAGED_PROCESS_ENVIRONMENT_ALLOWLIST_BYTES))
        return 0;
    for (index = 0u;
         index < config->login_environment_count;
         index++)
    {
        if (!config->login_environment[index] ||
            strnlen(config->login_environment[index],
                    X11_MANAGED_PROCESS_ENVIRONMENT_BYTES) >=
                X11_MANAGED_PROCESS_ENVIRONMENT_BYTES)
            return 0;
    }
    return 1;
}

static int x11_managed_process_environment_name_valid(
    const char* value,
    size_t name_length)
{
    size_t index = 0u;
    static const char* denied[] = {
        "BASH_ENV",
        "ENV",
        "IFS",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "PYTHONPATH",
    };

    if (!value || name_length == 0u ||
        !(isalpha((unsigned char)value[0]) || value[0] == '_'))
        return 0;
    for (index = 1u; index < name_length; index++)
    {
        if (!(isalnum((unsigned char)value[index]) ||
              value[index] == '_'))
            return 0;
    }
    if (name_length >= 5u &&
        memcmp(value, "DYLD_", 5u) == 0)
        return 0;
    for (index = 0u;
         index < sizeof(denied) / sizeof(denied[0]);
         index++)
    {
        if (strlen(denied[index]) == name_length &&
            memcmp(value, denied[index], name_length) == 0)
            return 0;
    }
    return 1;
}

static int x11_managed_process_environment_add(
    x11_managed_environment* environment,
    const char* name,
    const char* value)
{
    size_t name_length = name ? strlen(name) : 0u;
    size_t value_length = value ? strlen(value) : 0u;
    char* entry = NULL;

    if (!environment ||
        environment->count >= X11_MANAGED_PROCESS_ENVIRONMENT_MAX ||
        !x11_managed_process_environment_name_valid(name, name_length) ||
        !value ||
        name_length + value_length + 2u >
            X11_MANAGED_PROCESS_ENVIRONMENT_BYTES)
        return 0;
    entry = (char*)malloc(name_length + value_length + 2u);
    if (!entry)
        return 0;
    memcpy(entry, name, name_length);
    entry[name_length] = '=';
    memcpy(entry + name_length + 1u, value, value_length + 1u);
    environment->values[environment->count++] = entry;
    environment->values[environment->count] = NULL;
    return 1;
}

static int x11_managed_process_environment_add_entry(
    x11_managed_environment* environment,
    const char* entry)
{
    const char* separator = entry ? strchr(entry, '=') : NULL;
    size_t name_length =
        separator ? (size_t)(separator - entry) : 0u;

    if (!separator ||
        !x11_managed_process_environment_name_valid(entry, name_length))
        return 0;
    {
        size_t index = 0u;

        for (index = 0u; index < environment->count; index++)
        {
            const char* existing_separator =
                strchr(environment->values[index], '=');

            if (existing_separator &&
                (size_t)(existing_separator -
                         environment->values[index]) == name_length &&
                memcmp(environment->values[index],
                       entry,
                       name_length) == 0)
                return 1;
        }
    }
    {
        char name[256];

        if (name_length >= sizeof(name))
            return 0;
        memcpy(name, entry, name_length);
        name[name_length] = '\0';
        return x11_managed_process_environment_add(environment,
                                                    name,
                                                    separator + 1u);
    }
}

static int x11_managed_process_environment_allowed(
    const char* allowlist,
    const char* entry)
{
    const char* separator = entry ? strchr(entry, '=') : NULL;
    const char* cursor = allowlist;
    size_t name_length =
        separator ? (size_t)(separator - entry) : 0u;

    if (!allowlist || allowlist[0] == '\0' ||
        !separator || name_length == 0u)
        return 0;
    while (*cursor != '\0')
    {
        const char* end = strchr(cursor, ',');
        size_t length =
            end ? (size_t)(end - cursor) : strlen(cursor);

        if (length == name_length &&
            memcmp(cursor, entry, name_length) == 0)
            return 1;
        if (!end)
            break;
        cursor = end + 1u;
    }
    return 0;
}

static void x11_managed_process_environment_free(
    x11_managed_environment* environment)
{
    size_t index = 0u;

    if (!environment)
        return;
    for (index = 0u; index < environment->count; index++)
    {
        if (environment->values[index])
        {
            OPENSSL_cleanse(environment->values[index],
                            strlen(environment->values[index]));
            free(environment->values[index]);
        }
    }
    memset(environment, 0, sizeof(*environment));
}

static librdp_status x11_managed_process_build_environment(
    const x11_managed_process_config* config,
    x11_managed_environment* environment)
{
    const char* locale = getenv("LANG");
    size_t index = 0u;

    memset(environment, 0, sizeof(*environment));
    if (!x11_managed_process_environment_add(
            environment, "HOME", config->identity->home) ||
        !x11_managed_process_environment_add(
            environment, "USER", config->identity->username) ||
        !x11_managed_process_environment_add(
            environment, "LOGNAME", config->identity->username) ||
        !x11_managed_process_environment_add(
            environment, "SHELL", config->identity->shell) ||
        !x11_managed_process_environment_add(
            environment, "DISPLAY", config->display_name) ||
        !x11_managed_process_environment_add(
            environment, "XAUTHORITY", config->authority_path) ||
        !x11_managed_process_environment_add(
            environment,
            "XDG_RUNTIME_DIR",
            config->runtime_directory) ||
        !x11_managed_process_environment_add(
            environment,
            "PATH",
            "/usr/local/bin:/usr/X11R6/bin:/usr/bin:/bin"))
        return LIBRDP_STATUS_NO_MEMORY;
    if (locale && locale[0] != '\0' &&
        !x11_managed_process_environment_add(
            environment, "LANG", locale))
        return LIBRDP_STATUS_NO_MEMORY;
    for (index = 0u;
         index < config->login_environment_count;
         index++)
    {
        if (!x11_managed_process_environment_allowed(
                config->environment_allowlist,
                config->login_environment[index]))
            continue;
        if (!x11_managed_process_environment_add_entry(
                environment, config->login_environment[index]))
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Parse a trusted administrator command without invoking a shell. Quotes and
 * backslash escapes are accepted, but expansion and command substitution are
 * deliberately absent.
 */
static librdp_status x11_managed_process_parse_command(
    const char* command,
    x11_managed_argv* output)
{
    size_t input_index = 0u;
    size_t output_index = 0u;
    char quote = '\0';
    int escaped = 0;
    int in_argument = 0;

    if (!command || !output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(output, 0, sizeof(*output));
    while (command[input_index] != '\0')
    {
        unsigned char value = (unsigned char)command[input_index++];

        if (escaped)
        {
            escaped = 0;
        }
        else if (value == '\\')
        {
            escaped = 1;
            if (!in_argument)
            {
                if (output->count >= X11_MANAGED_PROCESS_MAX_ARGUMENTS)
                    return LIBRDP_STATUS_LIMIT_EXCEEDED;
                output->values[output->count++] =
                    &output->storage[output_index];
                in_argument = 1;
            }
            continue;
        }
        else if (quote != '\0')
        {
            if ((char)value == quote)
            {
                quote = '\0';
                continue;
            }
        }
        else if (value == '\'' || value == '"')
        {
            quote = (char)value;
            if (!in_argument)
            {
                if (output->count >= X11_MANAGED_PROCESS_MAX_ARGUMENTS)
                    return LIBRDP_STATUS_LIMIT_EXCEEDED;
                output->values[output->count++] =
                    &output->storage[output_index];
                in_argument = 1;
            }
            continue;
        }
        else if (isspace(value))
        {
            if (in_argument)
            {
                if (output_index >= sizeof(output->storage))
                    return LIBRDP_STATUS_LIMIT_EXCEEDED;
                output->storage[output_index++] = '\0';
                in_argument = 0;
            }
            continue;
        }
        else if (!in_argument)
        {
            if (output->count >= X11_MANAGED_PROCESS_MAX_ARGUMENTS)
                return LIBRDP_STATUS_LIMIT_EXCEEDED;
            output->values[output->count++] =
                &output->storage[output_index];
            in_argument = 1;
        }
        if (value == '\0' || output_index + 1u >= sizeof(output->storage))
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
        output->storage[output_index++] = (char)value;
    }
    if (escaped || quote != '\0')
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (in_argument)
        output->storage[output_index++] = '\0';
    if (output->count == 0u || output->values[0][0] != '/')
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    output->values[output->count] = NULL;
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_managed_process_write_authority(
    const x11_managed_process_config* config)
{
    unsigned char cookie[16];
    char hostname[256];
    const char* number = config->display_name + 1u;
    Xauth authorization;
    FILE* stream = NULL;
    int descriptor = -1;
    librdp_status status = LIBRDP_STATUS_IO_ERROR;

    memset(cookie, 0, sizeof(cookie));
    memset(hostname, 0, sizeof(hostname));
    memset(&authorization, 0, sizeof(authorization));
    if (RAND_bytes(cookie, (int)sizeof(cookie)) != 1 ||
        gethostname(hostname, sizeof(hostname) - 1u) != 0)
        return LIBRDP_STATUS_IO_ERROR;
    descriptor = open(config->authority_path,
                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                          O_NOFOLLOW,
                      0600);
    if (descriptor < 0)
        return LIBRDP_STATUS_IO_ERROR;
    if (fchown(descriptor,
               config->identity->uid,
               config->identity->gid) != 0 &&
        (config->identity->uid != geteuid() ||
         config->identity->gid != getegid()))
    {
        close(descriptor);
        unlink(config->authority_path);
        return LIBRDP_STATUS_IO_ERROR;
    }
    stream = fdopen(descriptor, "wb");
    if (!stream)
    {
        close(descriptor);
        unlink(config->authority_path);
        return LIBRDP_STATUS_IO_ERROR;
    }
    authorization.family = FamilyLocal;
    authorization.address_length = (unsigned short)strlen(hostname);
    authorization.address = hostname;
    authorization.number_length = (unsigned short)strlen(number);
    authorization.number = (char*)number;
    authorization.name_length =
        (unsigned short)(sizeof("MIT-MAGIC-COOKIE-1") - 1u);
    authorization.name = (char*)"MIT-MAGIC-COOKIE-1";
    authorization.data_length = (unsigned short)sizeof(cookie);
    authorization.data = (char*)cookie;
    if (XauWriteAuth(stream, &authorization) != 0 &&
        fflush(stream) == 0 && fsync(fileno(stream)) == 0)
        status = LIBRDP_STATUS_OK;
    if (fclose(stream) != 0)
        status = LIBRDP_STATUS_IO_ERROR;
    if (status != LIBRDP_STATUS_OK)
        unlink(config->authority_path);
    OPENSSL_cleanse(cookie, sizeof(cookie));
    OPENSSL_cleanse(hostname, sizeof(hostname));
    return status;
}

static librdp_status x11_managed_process_write_xorg_config(
    const x11_managed_process_config* config,
    x11_managed_process_group* group)
{
    FILE* stream = NULL;
    int descriptor = -1;
    int written = 0;

    if (!x11_managed_process_path(group->xorg_config_path,
                                  sizeof(group->xorg_config_path),
                                  config->runtime_directory,
                                  "xorg.conf"))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    descriptor = open(group->xorg_config_path,
                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                          O_NOFOLLOW,
                      0600);
    if (descriptor < 0)
        return LIBRDP_STATUS_IO_ERROR;
    if (fchown(descriptor,
               config->identity->uid,
               config->identity->gid) != 0 &&
        (config->identity->uid != geteuid() ||
         config->identity->gid != getegid()))
    {
        close(descriptor);
        unlink(group->xorg_config_path);
        return LIBRDP_STATUS_IO_ERROR;
    }
    stream = fdopen(descriptor, "w");
    if (!stream)
    {
        close(descriptor);
        unlink(group->xorg_config_path);
        return LIBRDP_STATUS_IO_ERROR;
    }
    written = fprintf(
        stream,
        "Section \"ServerLayout\"\n"
        " Identifier \"librdp-layout\"\n"
        " Screen 0 \"librdp-screen\"\n"
        "EndSection\n"
        "Section \"Device\"\n"
        " Identifier \"librdp-device\"\n"
        " Driver \"dummy\"\n"
        " VideoRam 262144\n"
        "EndSection\n"
        "Section \"Monitor\"\n"
        " Identifier \"librdp-monitor\"\n"
        " HorizSync 5.0-1000.0\n"
        " VertRefresh 5.0-200.0\n"
        "EndSection\n"
        "Section \"Screen\"\n"
        " Identifier \"librdp-screen\"\n"
        " Device \"librdp-device\"\n"
        " Monitor \"librdp-monitor\"\n"
        " DefaultDepth 24\n"
        " SubSection \"Display\"\n"
        "  Depth 24\n"
        "  Virtual %u %u\n"
        " EndSubSection\n"
        "EndSection\n"
        "Section \"ServerFlags\"\n"
        " Option \"AutoAddDevices\" \"false\"\n"
        " Option \"DontVTSwitch\" \"true\"\n"
        "EndSection\n"
        "Section \"Extensions\"\n"
        " Option \"Composite\" \"Enable\"\n"
        " Option \"DAMAGE\" \"Enable\"\n"
        " Option \"XFIXES\" \"Enable\"\n"
        " Option \"RANDR\" \"Enable\"\n"
        "EndSection\n",
        config->width,
        config->height);
    if (written < 0 || fflush(stream) != 0 ||
        fsync(fileno(stream)) != 0)
    {
        (void)fclose(stream);
        unlink(group->xorg_config_path);
        return LIBRDP_STATUS_IO_ERROR;
    }
    if (fclose(stream) != 0)
    {
        unlink(group->xorg_config_path);
        return LIBRDP_STATUS_IO_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static void x11_managed_process_close_descriptors(int retained)
{
    long maximum = sysconf(_SC_OPEN_MAX);
    int descriptor = 0;
    int limit =
        maximum > 0 && maximum < 1048576L ? (int)maximum : 1024;

    for (descriptor = 3; descriptor < limit; descriptor++)
    {
        if (descriptor != retained)
            close(descriptor);
    }
}

static void x11_managed_process_child_identity(
    const x11_managed_process_config* config)
{
    if (geteuid() == 0)
    {
        if (setgroups(config->identity->group_count,
                      config->identity->groups) != 0 ||
            setgid(config->identity->gid) != 0 ||
            setuid(config->identity->uid) != 0)
            _exit(126);
    }
    else if (geteuid() != config->identity->uid ||
             getegid() != config->identity->gid)
    {
        _exit(126);
    }
    if (chdir(config->identity->home) != 0)
        _exit(126);
    umask(077);
}

static librdp_status x11_managed_process_spawn(
    const x11_managed_process_config* config,
    const char* executable,
    char* const argv[],
    char* const environment[],
    pid_t process_group,
    int retained_descriptor,
    pid_t* child_pid)
{
    pid_t child = -1;

    if (!config || !executable || executable[0] != '/' || !argv ||
        !argv[0] || !environment || !child_pid)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    child = fork();
    if (child < 0)
        return LIBRDP_STATUS_IO_ERROR;
    if (child == 0)
    {
        if (setpgid(0, process_group > 0 ? process_group : 0) != 0)
            _exit(126);
        x11_managed_process_child_identity(config);
        if (retained_descriptor >= 0 &&
            fcntl(retained_descriptor, F_SETFD, 0) != 0)
            _exit(126);
        x11_managed_process_close_descriptors(retained_descriptor);
        execve(executable, argv, environment);
        _exit(127);
    }
    if (setpgid(child, process_group > 0 ? process_group : child) != 0 &&
        errno != EACCES)
    {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return LIBRDP_STATUS_IO_ERROR;
    }
    *child_pid = child;
    return LIBRDP_STATUS_OK;
}

static int x11_managed_process_alive(pid_t child)
{
    int status = 0;
    pid_t result = 0;

    if (child <= 0)
        return 0;
    result = waitpid(child, &status, WNOHANG);
    return result == 0;
}

static int x11_managed_process_group_alive(pid_t process_group)
{
    if (process_group <= 0)
        return 0;
    if (kill(-process_group, 0) == 0)
        return 1;
    return errno == EPERM;
}

static int x11_managed_process_display_ready(
    const x11_managed_process_config* config)
{
    char* previous = NULL;
    const char* current = getenv("XAUTHORITY");
    Display* display = NULL;
    int ready = 0;

    if (current)
    {
        previous = strdup(current);
        if (!previous)
            return 0;
    }
    if (setenv("XAUTHORITY", config->authority_path, 1) != 0)
    {
        free(previous);
        return 0;
    }
    display = XOpenDisplay(config->display_name);
    if (display)
    {
        ready = 1;
        XCloseDisplay(display);
    }
    if (previous)
    {
        (void)setenv("XAUTHORITY", previous, 1);
        OPENSSL_cleanse(previous, strlen(previous));
        free(previous);
    }
    else
    {
        (void)unsetenv("XAUTHORITY");
    }
    return ready;
}

static librdp_status x11_managed_process_wait_display(
    const x11_managed_process_config* config,
    pid_t child)
{
    uint64_t deadline =
        x11_managed_process_now_ms() +
        (uint64_t)config->startup_timeout_ms;

    while (x11_managed_process_now_ms() < deadline)
    {
        struct pollfd wait;

        if (!x11_managed_process_alive(child))
            return LIBRDP_STATUS_IO_ERROR;
        if (x11_managed_process_display_ready(config))
            return LIBRDP_STATUS_OK;
        memset(&wait, 0, sizeof(wait));
        (void)poll(&wait, 0u, 20);
    }
    return LIBRDP_STATUS_TIMEOUT;
}

static librdp_status x11_managed_process_start_xserver(
    const x11_managed_process_config* config,
    x11_managed_process_group* group,
    x11_managed_environment* environment)
{
    char geometry[64];
    char* xvfb_arguments[11];
    char* xorg_arguments[13];
    int length = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (config->use_xvfb)
    {
        length = snprintf(geometry,
                          sizeof(geometry),
                          "%ux%ux24",
                          config->width,
                          config->height);
        if (length < 0 || (size_t)length >= sizeof(geometry))
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
        xvfb_arguments[0] = (char*)config->xserver_path;
        xvfb_arguments[1] = (char*)config->display_name;
        xvfb_arguments[2] = (char*)"-screen";
        xvfb_arguments[3] = (char*)"0";
        xvfb_arguments[4] = geometry;
        xvfb_arguments[5] = (char*)"-nolisten";
        xvfb_arguments[6] = (char*)"tcp";
        xvfb_arguments[7] = (char*)"-auth";
        xvfb_arguments[8] = (char*)config->authority_path;
        xvfb_arguments[9] = (char*)"-noreset";
        xvfb_arguments[10] = NULL;
        return x11_managed_process_spawn(
            config,
            config->xserver_path,
            xvfb_arguments,
            environment->values,
            0,
            -1,
            &group->xserver_pid);
    }
    status = x11_managed_process_write_xorg_config(config, group);
    if (status != LIBRDP_STATUS_OK)
        return status;
    xorg_arguments[0] = (char*)config->xserver_path;
    xorg_arguments[1] = (char*)config->display_name;
    xorg_arguments[2] = (char*)"-config";
    xorg_arguments[3] = group->xorg_config_path;
    xorg_arguments[4] = (char*)"-nolisten";
    xorg_arguments[5] = (char*)"tcp";
    xorg_arguments[6] = (char*)"-auth";
    xorg_arguments[7] = (char*)config->authority_path;
    xorg_arguments[8] = (char*)"-noreset";
    xorg_arguments[9] = (char*)"-keeptty";
    xorg_arguments[10] = (char*)"-novtswitch";
    xorg_arguments[11] = (char*)"-sharevts";
    xorg_arguments[12] = NULL;
    return x11_managed_process_spawn(
        config,
        config->xserver_path,
        xorg_arguments,
        environment->values,
        0,
        -1,
        &group->xserver_pid);
}

static void x11_managed_process_reap(pid_t child)
{
    int status = 0;

    if (child <= 0)
        return;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR)
    {
    }
}

librdp_status x11_managed_process_start(
    const x11_managed_process_config* config,
    x11_managed_process_group* group)
{
    x11_managed_environment environment;
    x11_managed_argv desktop;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!x11_managed_process_config_valid(config) || !group)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    x11_managed_process_group_init(group);
    if (!x11_managed_process_copy(group->display_name,
                                  sizeof(group->display_name),
                                  config->display_name) ||
        !x11_managed_process_copy(group->authority_path,
                                  sizeof(group->authority_path),
                                  config->authority_path))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    status = x11_managed_process_parse_command(
        config->desktop_command, &desktop);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = x11_managed_process_build_environment(config,
                                                   &environment);
    if (status != LIBRDP_STATUS_OK)
    {
        x11_managed_process_environment_free(&environment);
        return status;
    }
    status = x11_managed_process_write_authority(config);
    if (status == LIBRDP_STATUS_OK)
        status = x11_managed_process_start_xserver(config,
                                                   group,
                                                   &environment);
    if (status == LIBRDP_STATUS_OK)
    {
        group->process_group = group->xserver_pid;
        status = x11_managed_process_wait_display(
            config, group->xserver_pid);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_process_spawn(
            config,
            desktop.values[0],
            desktop.values,
            environment.values,
            group->process_group,
            -1,
            &group->desktop_pid);
    }
    x11_managed_process_environment_free(&environment);
    OPENSSL_cleanse(&desktop, sizeof(desktop));
    if (status != LIBRDP_STATUS_OK)
        (void)x11_managed_process_stop(group, 2000);
    return status;
}

librdp_status x11_managed_process_join(
    const x11_managed_process_config* config,
    x11_managed_process_group* group,
    const char* executable,
    char* const argv[],
    int retained_descriptor,
    pid_t* child_pid)
{
    x11_managed_environment environment;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!x11_managed_process_config_valid(config) || !group ||
        group->process_group <= 0 ||
        group->joined_count >= X11_MANAGED_PROCESS_MAX_JOINED)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = x11_managed_process_build_environment(config,
                                                   &environment);
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_process_spawn(
            config,
            executable,
            argv,
            environment.values,
            group->process_group,
            retained_descriptor,
            child_pid);
    }
    x11_managed_process_environment_free(&environment);
    if (status == LIBRDP_STATUS_OK)
        group->joined_pids[group->joined_count++] = *child_pid;
    return status;
}

static int x11_managed_process_x_error = 0;

static int x11_managed_process_error_handler(Display* display,
                                             XErrorEvent* event)
{
    (void)display;
    (void)event;
    x11_managed_process_x_error = 1;
    return 0;
}

librdp_status x11_managed_process_resize(
    const x11_managed_process_group* group,
    uint32_t width,
    uint32_t height)
{
    char* previous = NULL;
    const char* current = getenv("XAUTHORITY");
    Display* display = NULL;
    Window root = 0u;
    int minimum_width = 0;
    int minimum_height = 0;
    int maximum_width = 0;
    int maximum_height = 0;
    int (*previous_handler)(Display*, XErrorEvent*) = NULL;
    librdp_status status = LIBRDP_STATUS_UNSUPPORTED;

    if (!group || group->version != X11_MANAGED_PROCESS_VERSION ||
        group->size < sizeof(*group) || group->display_name[0] != ':' ||
        group->authority_path[0] != '/' || width == 0u || height == 0u ||
        width > 16384u || height > 16384u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (current)
    {
        previous = strdup(current);
        if (!previous)
            return LIBRDP_STATUS_NO_MEMORY;
    }
    if (setenv("XAUTHORITY", group->authority_path, 1) != 0)
    {
        free(previous);
        return LIBRDP_STATUS_IO_ERROR;
    }
    display = XOpenDisplay(group->display_name);
    if (display)
    {
        root = RootWindow(display, DefaultScreen(display));
        if (XRRGetScreenSizeRange(display,
                                  root,
                                  &minimum_width,
                                  &minimum_height,
                                  &maximum_width,
                                  &maximum_height) &&
            width >= (uint32_t)minimum_width &&
            height >= (uint32_t)minimum_height &&
            width <= (uint32_t)maximum_width &&
            height <= (uint32_t)maximum_height)
        {
            int millimetres_width =
                (int)(((uint64_t)width * 254u + 480u) / 960u);
            int millimetres_height =
                (int)(((uint64_t)height * 254u + 480u) / 960u);

            x11_managed_process_x_error = 0;
            previous_handler =
                XSetErrorHandler(x11_managed_process_error_handler);
            XRRSetScreenSize(display,
                             root,
                             (int)width,
                             (int)height,
                             millimetres_width,
                             millimetres_height);
            XSync(display, False);
            (void)XSetErrorHandler(previous_handler);
            status = x11_managed_process_x_error
                         ? LIBRDP_STATUS_UNSUPPORTED
                         : LIBRDP_STATUS_OK;
        }
        XCloseDisplay(display);
    }
    if (previous)
    {
        (void)setenv("XAUTHORITY", previous, 1);
        OPENSSL_cleanse(previous, strlen(previous));
        free(previous);
    }
    else
    {
        (void)unsetenv("XAUTHORITY");
    }
    return status;
}

librdp_status x11_managed_process_stop(
    x11_managed_process_group* group,
    int timeout_ms)
{
    uint64_t deadline = 0u;
    size_t index = 0u;
    int joined_alive = 0;

    if (!group || group->version != X11_MANAGED_PROCESS_VERSION ||
        group->size < sizeof(*group) || timeout_ms < 0 ||
        timeout_ms > 120000)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (group->process_group > 0)
    {
        (void)kill(-group->process_group, SIGTERM);
        deadline =
            x11_managed_process_now_ms() + (uint64_t)timeout_ms;
        do
        {
            struct pollfd wait;

            joined_alive = 0;
            for (index = 0u; index < group->joined_count; index++)
            {
                if (x11_managed_process_alive(
                        group->joined_pids[index]))
                    joined_alive = 1;
            }
            if (!x11_managed_process_alive(group->xserver_pid) &&
                !x11_managed_process_alive(group->desktop_pid) &&
                !joined_alive &&
                !x11_managed_process_group_alive(
                    group->process_group))
                break;
            memset(&wait, 0, sizeof(wait));
            (void)poll(&wait, 0u, 20);
        }
        while (x11_managed_process_now_ms() < deadline);
        joined_alive = 0;
        for (index = 0u; index < group->joined_count; index++)
        {
            if (x11_managed_process_alive(
                    group->joined_pids[index]))
                joined_alive = 1;
        }
        if (x11_managed_process_alive(group->xserver_pid) ||
            x11_managed_process_alive(group->desktop_pid) ||
            joined_alive ||
            x11_managed_process_group_alive(group->process_group))
            (void)kill(-group->process_group, SIGKILL);
    }
    x11_managed_process_reap(group->desktop_pid);
    x11_managed_process_reap(group->xserver_pid);
    for (index = 0u; index < group->joined_count; index++)
        x11_managed_process_reap(group->joined_pids[index]);
    if (group->authority_path[0] != '\0')
        (void)unlink(group->authority_path);
    if (group->xorg_config_path[0] != '\0')
        (void)unlink(group->xorg_config_path);
    x11_managed_process_group_init(group);
    return LIBRDP_STATUS_OK;
}
