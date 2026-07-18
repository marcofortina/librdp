/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * Module: managed X11 process-group integration tests.
 * Coverage: private Xauthority creation, Xvfb readiness, desktop launch,
 * RandR resize outcome, process-group shutdown and generated-file cleanup.
 * Bug classes: privilege leakage, shell interpretation, stale displays,
 * orphaned children, world-readable cookies and teardown hangs.
 * Determinism: a reserved high display, Xvfb and /bin/sleep provide a local
 * headless session without a desktop manager or network peer.
 */

#include "server_managed_process.h"

#include <grp.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition)                                                        \
    do                                                                          \
    {                                                                           \
        if (!(condition))                                                       \
        {                                                                       \
            fprintf(stderr,                                                     \
                    "check failed %s:%d: %s\n",                                 \
                    __FILE__,                                                   \
                    __LINE__,                                                   \
                    #condition);                                                \
            return 1;                                                           \
        }                                                                       \
    } while (0)

static int test_identity(x11_managed_auth_identity* identity)
{
    struct passwd* account = getpwuid(geteuid());
    int group_count = (int)X11_MANAGED_AUTH_MAX_GROUPS;

    if (!account)
        return 0;
    x11_managed_auth_identity_init(identity);
    identity->uid = account->pw_uid;
    identity->gid = account->pw_gid;
    memcpy(identity->username,
           account->pw_name,
           strlen(account->pw_name) + 1u);
    memcpy(identity->home,
           account->pw_dir,
           strlen(account->pw_dir) + 1u);
    memcpy(identity->shell,
           account->pw_shell,
           strlen(account->pw_shell) + 1u);
    if (getgrouplist(account->pw_name,
                     account->pw_gid,
                     identity->groups,
                     &group_count) < 0 ||
        group_count <= 0)
        return 0;
    identity->group_count = (size_t)group_count;
    return 1;
}

static int test_xvfb_group(void)
{
    char root[] = "/tmp/librdp-managed-process-XXXXXX";
    char authority[4096];
    char display[64];
    x11_managed_auth_identity identity;
    x11_managed_process_config config;
    x11_managed_process_group group;
    struct stat info;
    int display_number =
        700 + (int)(getpid() % 200);
    int length = 0;
    librdp_status resize_status = LIBRDP_STATUS_OK;

    CHECK(mkdtemp(root) != NULL);
    CHECK(test_identity(&identity));
    length = snprintf(authority,
                      sizeof(authority),
                      "%s/Xauthority",
                      root);
    CHECK(length > 0 && (size_t)length < sizeof(authority));
    length = snprintf(display,
                      sizeof(display),
                      ":%d",
                      display_number);
    CHECK(length > 0 && (size_t)length < sizeof(display));
    x11_managed_process_config_init(&config);
    config.identity = &identity;
    config.display_name = display;
    config.authority_path = authority;
    config.runtime_directory = root;
    config.xserver_path = LIBRDP_TEST_XVFB_PATH;
    config.desktop_command = "/bin/sleep 30";
    config.width = 800u;
    config.height = 600u;
    config.use_xvfb = 1;
    config.startup_timeout_ms = 5000;
    x11_managed_process_group_init(&group);
    CHECK(x11_managed_process_start(&config, &group) ==
          LIBRDP_STATUS_OK);
    CHECK(group.process_group > 0 &&
          group.xserver_pid > 0 &&
          group.desktop_pid > 0);
    CHECK(lstat(authority, &info) == 0 &&
          S_ISREG(info.st_mode) &&
          (info.st_mode & 077u) == 0u);
    resize_status =
        x11_managed_process_resize(&group, 1024u, 768u);
    CHECK(resize_status == LIBRDP_STATUS_OK ||
          resize_status == LIBRDP_STATUS_UNSUPPORTED);
    CHECK(x11_managed_process_stop(&group, 2000) ==
          LIBRDP_STATUS_OK);
    CHECK(lstat(authority, &info) != 0);
    CHECK(rmdir(root) == 0);
    return 0;
}

static int test_invalid_command(void)
{
    char root[] = "/tmp/librdp-managed-command-XXXXXX";
    char authority[4096];
    x11_managed_auth_identity identity;
    x11_managed_process_config config;
    x11_managed_process_group group;
    int length = 0;

    CHECK(mkdtemp(root) != NULL);
    CHECK(test_identity(&identity));
    length = snprintf(authority,
                      sizeof(authority),
                      "%s/Xauthority",
                      root);
    CHECK(length > 0 && (size_t)length < sizeof(authority));
    x11_managed_process_config_init(&config);
    config.identity = &identity;
    config.display_name = ":699";
    config.authority_path = authority;
    config.runtime_directory = root;
    config.xserver_path = LIBRDP_TEST_XVFB_PATH;
    config.desktop_command = "relative-command";
    config.width = 800u;
    config.height = 600u;
    config.use_xvfb = 1;
    x11_managed_process_group_init(&group);
    CHECK(x11_managed_process_start(&config, &group) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(rmdir(root) == 0);
    return 0;
}

static int test_dump_environment(const char* path)
{
    const char* allowed = getenv("LC_TIME");
    const char* denied = getenv("UNSAFE_TEST_VALUE");
    char output[256];
    int descriptor = -1;
    int length = snprintf(output,
                          sizeof(output),
                          "%s\n%s\n",
                          allowed ? allowed : "missing",
                          denied ? denied : "missing");

    if (!path || length < 0 || (size_t)length >= sizeof(output))
        return 2;
    descriptor = open(path,
                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                      0600);
    if (descriptor < 0 ||
        write(descriptor, output, (size_t)length) !=
            (ssize_t)length)
    {
        if (descriptor >= 0)
            close(descriptor);
        return 1;
    }
    return close(descriptor) == 0 ? 0 : 1;
}

/*
 * Launch the test binary as the desktop with one allowed and one denied login
 * variable. The file produced after exec proves filtering happened in the
 * child environment rather than only in policy serialization.
 */
static int test_environment_allowlist(void)
{
    char root[] = "/tmp/librdp-managed-environment-XXXXXX";
    char authority[4096];
    char output_path[4096];
    char command[8192];
    char display[64];
    const char* login_environment[] = {
        "LC_TIME=allowed-value",
        "UNSAFE_TEST_VALUE=denied-value",
    };
    x11_managed_auth_identity identity;
    x11_managed_process_config config;
    x11_managed_process_group group;
    char output[256];
    int descriptor = -1;
    int display_number = 900 + (int)(getpid() % 80);
    int length = 0;
    int attempt = 0;
    ssize_t received = 0;

    CHECK(mkdtemp(root) != NULL);
    CHECK(test_identity(&identity));
    length = snprintf(authority,
                      sizeof(authority),
                      "%s/Xauthority",
                      root);
    CHECK(length > 0 && (size_t)length < sizeof(authority));
    length = snprintf(output_path,
                      sizeof(output_path),
                      "%s/environment.txt",
                      root);
    CHECK(length > 0 && (size_t)length < sizeof(output_path));
    length = snprintf(display,
                      sizeof(display),
                      ":%d",
                      display_number);
    CHECK(length > 0 && (size_t)length < sizeof(display));
    length = snprintf(command,
                      sizeof(command),
                      "%s --dump-environment %s",
                      LIBRDP_TEST_MANAGED_PROCESS_PATH,
                      output_path);
    CHECK(length > 0 && (size_t)length < sizeof(command));
    x11_managed_process_config_init(&config);
    config.identity = &identity;
    config.login_environment = login_environment;
    config.login_environment_count =
        sizeof(login_environment) / sizeof(login_environment[0]);
    config.environment_allowlist = "LC_TIME";
    config.display_name = display;
    config.authority_path = authority;
    config.runtime_directory = root;
    config.xserver_path = LIBRDP_TEST_XVFB_PATH;
    config.desktop_command = command;
    config.width = 800u;
    config.height = 600u;
    config.use_xvfb = 1;
    config.startup_timeout_ms = 5000;
    x11_managed_process_group_init(&group);
    CHECK(x11_managed_process_start(&config, &group) ==
          LIBRDP_STATUS_OK);
    for (attempt = 0; attempt < 100; attempt++)
    {
        struct pollfd wait;

        if (access(output_path, F_OK) == 0)
            break;
        memset(&wait, 0, sizeof(wait));
        (void)poll(&wait, 0u, 20);
    }
    descriptor = open(output_path, O_RDONLY | O_CLOEXEC);
    CHECK(descriptor >= 0);
    received = read(descriptor, output, sizeof(output) - 1u);
    CHECK(received > 0);
    output[(size_t)received] = '\0';
    CHECK(strcmp(output, "allowed-value\nmissing\n") == 0);
    CHECK(close(descriptor) == 0);
    CHECK(x11_managed_process_stop(&group, 2000) ==
          LIBRDP_STATUS_OK);
    CHECK(unlink(output_path) == 0);
    CHECK(rmdir(root) == 0);
    return 0;
}

int main(int argc, char** argv)
{
    if (argc == 3 &&
        strcmp(argv[1], "--dump-environment") == 0)
        return test_dump_environment(argv[2]);
    if (test_xvfb_group() != 0)
        return 1;
    if (test_invalid_command() != 0)
        return 1;
    if (test_environment_allowlist() != 0)
        return 1;
    return 0;
}
