/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: managed X11 broker policy tests.
 * Coverage: secure defaults, account authorization, provider intersection,
 * duration caps, fixed process paths and environment allowlist serialization.
 * Bug classes: local-user impersonation, client-selected commands, accidental
 * Standard Security, provider escalation and credential retention.
 * Determinism: tests use the effective local identity and synthetic requests;
 * no listener, authentication backend or X server is involved.
 */

#include "x11_managed_policy.h"

#include "x11_managed_auth.h"

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
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

static int test_configure_policy(x11_managed_policy* policy)
{
    struct passwd* account = getpwuid(geteuid());
    struct group* group = getgrgid(getegid());

    if (!account || !group)
        return 0;
    x11_managed_policy_init(policy);
    memcpy(policy->desktop_command,
           "/bin/sleep 30",
           sizeof("/bin/sleep 30"));
    policy->security_mode = LIBRDP_SECURITY_STANDARD;
    policy->allow_standard_security = 1;
    policy->allow_input = 1;
    policy->allow_clipboard = 1;
    if (x11_managed_policy_add_user(policy, account->pw_name) !=
            LIBRDP_STATUS_OK ||
        x11_managed_policy_add_group(policy, group->gr_name) !=
            LIBRDP_STATUS_OK)
        return 0;
    return 1;
}

static void test_authenticated(
    x11_managed_ipc_message* authenticated)
{
    struct passwd* account = getpwuid(geteuid());

    x11_managed_ipc_message_init(authenticated);
    authenticated->type = X11_MANAGED_IPC_AUTHENTICATED;
    authenticated->request_id = 1u;
    authenticated->uid = (uint32_t)geteuid();
    authenticated->gid = (uint32_t)getegid();
    authenticated->auth_outcome =
        X11_MANAGED_AUTH_AUTHENTICATED;
    if (account)
    {
        memcpy(authenticated->username,
               account->pw_name,
               strlen(account->pw_name) + 1u);
    }
}

static int test_defaults_and_authorization(void)
{
    x11_managed_policy policy;
    x11_managed_ipc_message authenticated;

    x11_managed_policy_init(&policy);
    CHECK(strcmp(policy.socket_path,
                 "/run/librdp/session-broker.sock") == 0);
    CHECK(strcmp(policy.runtime_root,
                 "/run/librdp/sessions") == 0);
    CHECK(strcmp(policy.supervisor_path,
                 LIBRDP_X11_SESSION_SUPERVISOR_PATH) == 0);
    CHECK(strcmp(policy.agent_path,
                 LIBRDP_X11_SESSION_AGENT_PATH) == 0);
    CHECK(strcmp(policy.authentication_service, "librdp") == 0);
    CHECK(!x11_managed_policy_valid(&policy));
    CHECK(test_configure_policy(&policy));
    CHECK(x11_managed_policy_valid(&policy));
    test_authenticated(&authenticated);
    CHECK(x11_managed_policy_authorize(
        &policy, geteuid(), &authenticated));
    if (geteuid() != 0u)
    {
        CHECK(!x11_managed_policy_authorize(
            &policy, (uid_t)(geteuid() + 1u), &authenticated));
    }
    CHECK(x11_managed_policy_add_environment(
              &policy, "INVALID-NAME") ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(x11_managed_policy_add_user(
              &policy, "../invalid") ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    x11_managed_ipc_message_clear(&authenticated);
    return 0;
}

/*
 * Request every provider and excessive duration, then prove that the filtered
 * and supervisor messages contain only policy-approved flags, capped timers,
 * fixed commands and no copied authentication secret.
 */
static int test_request_filtering(void)
{
    x11_managed_policy policy;
    x11_managed_ipc_message initial;
    x11_managed_ipc_message authenticated;
    x11_managed_ipc_message filtered;
    x11_managed_ipc_message start;
    x11_managed_session_entry entry;

    CHECK(test_configure_policy(&policy));
    policy.idle_timeout_ns = 1000u;
    policy.max_duration_ns = 2000u;
    test_authenticated(&authenticated);
    x11_managed_ipc_message_init(&initial);
    initial.type = X11_MANAGED_IPC_START;
    initial.request_id = 2u;
    initial.width = 1280u;
    initial.height = 720u;
    initial.idle_timeout_ns = 5000u;
    initial.max_duration_ns = 6000u;
    initial.flags = X11_MANAGED_IPC_ALLOW_CAPTURE |
                    X11_MANAGED_IPC_ALLOW_INPUT |
                    X11_MANAGED_IPC_ALLOW_CLIPBOARD |
                    X11_MANAGED_IPC_ALLOW_DRIVE |
                    X11_MANAGED_IPC_PERSISTENT |
                    X11_MANAGED_IPC_RECONNECT;
    memcpy(initial.username,
           "untrusted-name",
           sizeof("untrusted-name"));
    memcpy(initial.password,
           "discarded-test-secret",
           sizeof("discarded-test-secret"));
    CHECK(x11_managed_policy_filter_request(
              &policy,
              &initial,
              &authenticated,
              &filtered) == LIBRDP_STATUS_OK);
    CHECK((filtered.flags & X11_MANAGED_IPC_ALLOW_CAPTURE) != 0u);
    CHECK((filtered.flags & X11_MANAGED_IPC_ALLOW_INPUT) != 0u);
    CHECK((filtered.flags & X11_MANAGED_IPC_ALLOW_CLIPBOARD) != 0u);
    CHECK((filtered.flags & X11_MANAGED_IPC_ALLOW_DRIVE) == 0u);
    CHECK(filtered.idle_timeout_ns == 1000u);
    CHECK(filtered.max_duration_ns == 2000u);
    CHECK(filtered.password[0] == '\0');
    memset(&entry, 0, sizeof(entry));
    entry.session_id = 0x42u;
    entry.created_ns = 100u;
    entry.idle_timeout_ns = filtered.idle_timeout_ns;
    entry.max_duration_ns = filtered.max_duration_ns;
    entry.uid = (uid_t)filtered.uid;
    entry.gid = (gid_t)filtered.gid;
    entry.width = filtered.width;
    entry.height = filtered.height;
    entry.flags = filtered.flags;
    memcpy(entry.username,
           filtered.username,
           strlen(filtered.username) + 1u);
    memcpy(entry.reconnect_token,
           "0123456789abcdef0123456789abcdef"
           "0123456789abcdef0123456789abcdef",
           X11_MANAGED_IPC_TOKEN_BYTES);
    memcpy(entry.display_name, ":50", sizeof(":50"));
    memcpy(entry.runtime_directory,
           "/tmp/managed-policy-runtime",
           sizeof("/tmp/managed-policy-runtime"));
    memcpy(entry.agent_socket_path,
           "/tmp/managed-policy-control.sock",
           sizeof("/tmp/managed-policy-control.sock"));
    CHECK(x11_managed_policy_prepare_start(
              &policy,
              &filtered,
              &entry,
              &start) == LIBRDP_STATUS_OK);
    CHECK(strcmp(start.desktop_command, "/bin/sleep 30") == 0);
    CHECK(strcmp(start.xserver_command, "/usr/bin/Xorg") == 0);
    CHECK(strstr(start.environment_allowlist, "LANG") != NULL);
    CHECK(start.password[0] == '\0');
    x11_managed_ipc_message_clear(&initial);
    x11_managed_ipc_message_clear(&authenticated);
    x11_managed_ipc_message_clear(&filtered);
    x11_managed_ipc_message_clear(&start);
    return 0;
}

int main(void)
{
    if (test_defaults_and_authorization() != 0)
        return 1;
    if (test_request_filtering() != 0)
        return 1;
    return 0;
}
