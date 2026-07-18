/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: managed X11 broker configuration tests.
 * Coverage: secure file metadata, scalar/list parsing, bounds, duplicate and
 * unknown keys, binary input and redacted diagnostics.
 * Bug classes: policy shadowing, unsafe privileged configuration, oversized
 * allocation, path injection and accidental credential disclosure.
 * Determinism: files are created below one private temporary directory and no
 * authentication, X server or network endpoint is used.
 */

#include "server_managed_config.h"

#include <fcntl.h>
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

static int test_write_file(const char* path,
                           const void* data,
                           size_t length,
                           mode_t mode)
{
    const unsigned char* input =
        (const unsigned char*)data;
    size_t offset = 0u;
    int descriptor =
        open(path, O_CREAT | O_TRUNC | O_WRONLY, mode);

    if (descriptor < 0)
        return 0;
    while (offset < length)
    {
        ssize_t written =
            write(descriptor, input + offset, length - offset);

        if (written <= 0)
        {
            close(descriptor);
            return 0;
        }
        offset += (size_t)written;
    }
    return close(descriptor) == 0;
}

static int test_path(char* output,
                     size_t capacity,
                     const char* root,
                     const char* name)
{
    int length =
        snprintf(output, capacity, "%s/%s", root, name);

    return length > 0 && (size_t)length < capacity;
}

static int test_valid_config(const char* root)
{
    static const char content[] =
        "# managed broker policy\n"
        "desktop = /bin/sleep 30\n"
        "security=standard\n"
        "allow-standard-security = YES\n"
        "max-sessions=4\n"
        "max-sessions-per-user=2\n"
        "first-display=40\n"
        "last-display=50\n"
        "socket-mode=0600\n"
        "allow-user=test-account\n"
        "allow-user=second-account\n"
        "allow-input=on\n"
        "allow-clipboard=false\n"
        "allow-drive=1\n"
        "drive-read-only=true\n"
        "allow-reconnect=yes\n"
        "persistent=TRUE\n"
        "xvfb=off\n";
    char path[4096];
    x11_managed_policy policy;
    x11_managed_config_error error;

    CHECK(test_path(path, sizeof(path), root, "valid.conf"));
    CHECK(test_write_file(
        path, content, sizeof(content) - 1u, 0600));
    x11_managed_policy_init(&policy);
    CHECK(x11_managed_config_load(
              path, &policy, &error) == LIBRDP_STATUS_OK);
    CHECK(x11_managed_policy_valid(&policy));
    CHECK(policy.max_sessions == 4u);
    CHECK(policy.max_sessions_per_user == 2u);
    CHECK(policy.first_display == 40u);
    CHECK(policy.last_display == 50u);
    CHECK(policy.allowed_user_count == 2u);
    CHECK(policy.allow_input == 1);
    CHECK(policy.allow_clipboard == 0);
    CHECK(policy.allow_drive == 1);
    CHECK(policy.drive_read_only == 1);
    CHECK(error.detail[0] == '\0');
    CHECK(unlink(path) == 0);
    return 0;
}

static int test_rejected_syntax(const char* root)
{
    static const char duplicate[] =
        "desktop=/bin/true\n"
        "desktop=/bin/false\n";
    static const char unknown[] =
        "desktop=/bin/true\n"
        "password=private-config-canary\n";
    static const unsigned char binary[] = {
        'd', 'e', 's', 'k', 't', 'o', 'p', '=',
        '/', 'b', 'i', 'n', '/', 't', 'r', 'u',
        'e', '\0', '\n'};
    char path[4096];
    x11_managed_policy policy;
    x11_managed_config_error error;

    CHECK(test_path(path, sizeof(path), root, "invalid.conf"));
    CHECK(test_write_file(
        path, duplicate, sizeof(duplicate) - 1u, 0600));
    x11_managed_policy_init(&policy);
    CHECK(x11_managed_config_load(
              path, &policy, &error) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(error.line == 2u);
    CHECK(strcmp(error.key, "desktop") == 0);
    CHECK(strcmp(error.detail, "duplicate-key") == 0);

    CHECK(test_write_file(
        path, unknown, sizeof(unknown) - 1u, 0600));
    x11_managed_policy_init(&policy);
    CHECK(x11_managed_config_load(
              path, &policy, &error) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(strcmp(error.key, "password") == 0);
    CHECK(strstr(error.detail, "private-config-canary") == NULL);

    CHECK(test_write_file(
        path, binary, sizeof(binary), 0600));
    x11_managed_policy_init(&policy);
    CHECK(x11_managed_config_load(
              path, &policy, &error) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(strcmp(
              error.detail, "unstable-or-binary-file") == 0);
    CHECK(unlink(path) == 0);
    return 0;
}

static int test_file_guards(const char* root)
{
    static const char content[] =
        "desktop=/bin/true\n"
        "security=standard\n"
        "allow-standard-security=true\n";
    char path[4096];
    char* oversized = NULL;
    x11_managed_policy policy;
    x11_managed_config_error error;

    CHECK(test_path(path, sizeof(path), root, "guard.conf"));
    CHECK(test_write_file(
        path, content, sizeof(content) - 1u, 0600));
    CHECK(chmod(path, 0666) == 0);
    x11_managed_policy_init(&policy);
    CHECK(x11_managed_config_load(
              path, &policy, &error) == LIBRDP_STATUS_STATE);
    CHECK(strcmp(error.detail, "unsafe-file-metadata") == 0);
    CHECK(chmod(path, 0600) == 0);

    oversized = (char*)malloc(65537u);
    CHECK(oversized != NULL);
    memset(oversized, 'x', 65537u);
    CHECK(test_write_file(path, oversized, 65537u, 0600));
    free(oversized);
    x11_managed_policy_init(&policy);
    CHECK(x11_managed_config_load(
              path, &policy, &error) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(strcmp(error.detail, "file-too-large") == 0);
    CHECK(unlink(path) == 0);
    return 0;
}

static int test_direct_values(void)
{
    x11_managed_policy policy;
    x11_managed_config_error error;

    x11_managed_policy_init(&policy);
    x11_managed_config_error_init(&error);
    CHECK(x11_managed_config_apply(
              &policy,
              "desktop",
              "relative-command",
              &error) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(strcmp(error.key, "desktop") == 0);
    CHECK(x11_managed_config_apply(
              &policy,
              "socket-mode",
              "0607",
              &error) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(x11_managed_config_apply(
              &policy,
              "allow-input",
              "perhaps",
              &error) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(x11_managed_config_apply(
              &policy,
              "not-a-key",
              "value",
              &error) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(strcmp(error.detail, "unknown-key") == 0);
    return 0;
}

int main(void)
{
    char root[] = "/tmp/librdp-managed-config-XXXXXX";

    CHECK(mkdtemp(root) != NULL);
    if (test_valid_config(root) != 0 ||
        test_rejected_syntax(root) != 0 ||
        test_file_guards(root) != 0 ||
        test_direct_values() != 0)
    {
        (void)rmdir(root);
        return 1;
    }
    CHECK(rmdir(root) == 0);
    return 0;
}
