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

int main(void)
{
    if (test_xvfb_group() != 0)
        return 1;
    if (test_invalid_command() != 0)
        return 1;
    return 0;
}
