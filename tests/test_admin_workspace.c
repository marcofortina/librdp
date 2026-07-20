/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared administration and workspace application policy tests.
 * Coverage: common CLI validation, credential environment handoff, embedded
 * RDP metadata parsing, resource selection and bounded viewer launch plans.
 * Bug classes: unconfirmed destructive actions, malformed numeric fields,
 * ambiguous selection, oversized remote metadata and argument injection.
 * Determinism: all inputs are synthetic strings and in-memory workspace XML;
 * no network, process launch or native window system is used.
 */

#include "admin_options.h"
#include "workspace_options.h"

#include <librdp/librdp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check_int(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr, "test_admin_workspace:%d: check failed: %s\n", line, expression);
    return 1;
}

#define CHECK(expression)                                                                           \
    do                                                                                               \
    {                                                                                                \
        if (check_int((expression), #expression, __LINE__) != 0)                                    \
            return 1;                                                                                \
    } while (0)

static int launch_plan_has_pair(const workspace_launch_plan* plan,
                                const char* option,
                                const char* value)
{
    size_t index = 0;

    if (!plan || !option || !value)
        return 0;
    for (index = 0; index + 1u < plan->argument_count; index++)
    {
        if (strcmp(plan->arguments[index], option) == 0 &&
            strcmp(plan->arguments[index + 1u], value) == 0)
            return 1;
    }
    return 0;
}

/*
 * Exercise accepted administration syntax and policy failures that frontends
 * must agree on, including environment credential handoff and explicit
 * confirmation before destructive actions.
 */
static int test_admin_policy(void)
{
    char* message_args[] = {
        (char*)"admin",
        (char*)"--endpoint",
        (char*)"https://admin.example.test/wsman",
        (char*)"--user",
        (char*)"inventory-user",
        (char*)"--password-env",
        (char*)"LIBRDP_TEST_ADMIN_VALUE",
        (char*)"--action",
        (char*)"message",
        (char*)"--session-id",
        (char*)"42",
        (char*)"--message-title",
        (char*)"Notice",
        (char*)"--message-text",
        (char*)"Maintenance",
        (char*)"--timeout",
        (char*)"3000",
        (char*)"--no-window",
    };
    char* unconfirmed_args[] = {
        (char*)"admin",
        (char*)"--endpoint",
        (char*)"https://admin.example.test/wsman",
        (char*)"--action",
        (char*)"logoff",
        (char*)"--session-id",
        (char*)"7",
    };
    char* orphan_args[] = {
        (char*)"admin",
        (char*)"--endpoint",
        (char*)"https://admin.example.test/wsman",
        (char*)"--session-id",
        (char*)"7",
    };
    char* overflow_args[] = {
        (char*)"admin",
        (char*)"--endpoint",
        (char*)"https://admin.example.test/wsman",
        (char*)"--timeout",
        (char*)"4294967296",
    };
    char* missing_environment_args[] = {
        (char*)"admin",
        (char*)"--endpoint",
        (char*)"https://admin.example.test/wsman",
        (char*)"--password-env",
        (char*)"LIBRDP_TEST_ADMIN_MISSING",
    };
    admin_options options;
    FILE* errors = tmpfile();

    CHECK(errors != NULL);
    CHECK(setenv("LIBRDP_TEST_ADMIN_VALUE", "ephemeral-admin-value", 1) == 0);
    CHECK(admin_options_parse((int)(sizeof(message_args) / sizeof(message_args[0])),
                              message_args,
                              &options,
                              errors) == 1);
    CHECK(options.execute_action == 1);
    CHECK(options.action.type == LIBRDP_ADMIN_ACTION_MESSAGE);
    CHECK(options.action.session_id == 42u);
    CHECK(options.config.timeout_ms == 3000u);
    CHECK(strcmp(options.config.password, "ephemeral-admin-value") == 0);
    CHECK(options.no_window == 1);
    CHECK(admin_options_parse((int)(sizeof(unconfirmed_args) / sizeof(unconfirmed_args[0])),
                              unconfirmed_args,
                              &options,
                              errors) == 0);
    CHECK(admin_options_parse((int)(sizeof(orphan_args) / sizeof(orphan_args[0])),
                              orphan_args,
                              &options,
                              errors) == 0);
    CHECK(admin_options_parse((int)(sizeof(overflow_args) / sizeof(overflow_args[0])),
                              overflow_args,
                              &options,
                              errors) == 0);
    CHECK(unsetenv("LIBRDP_TEST_ADMIN_VALUE") == 0);
    CHECK(unsetenv("LIBRDP_TEST_ADMIN_MISSING") == 0);
    CHECK(admin_options_parse(
              (int)(sizeof(missing_environment_args) /
                    sizeof(missing_environment_args[0])),
              missing_environment_args,
              &options,
              errors) == 0);
    fclose(errors);
    return 0;
}

/*
 * Verify that remote workspace fields produce one bounded, fixed-vocabulary
 * viewer command and that malformed or absent targets cannot create a launch
 * plan.
 */
static int test_workspace_launch_policy(void)
{
    char* args[] = {
        (char*)"workspace",
        (char*)"--feed",
        (char*)"https://workspace.example.test/feed",
        (char*)"--user",
        (char*)"feed-user",
        (char*)"--password-env",
        (char*)"LIBRDP_TEST_WORKSPACE_VALUE",
        (char*)"--domain",
        (char*)"EXAMPLE",
        (char*)"--viewer",
        (char*)"/opt/librdp-viewer",
        (char*)"--security",
        (char*)"nla",
        (char*)"--select",
        (char*)"published-app",
        (char*)"--launch",
    };
    char* invalid_security[] = {
        (char*)"workspace",
        (char*)"--feed",
        (char*)"https://workspace.example.test/feed",
        (char*)"--security",
        (char*)"unknown",
    };
    workspace_options options;
    workspace_launch_plan plan;
    librdp_workspace_resource resource;
    char oversized_field[WORKSPACE_FIELD_CAPACITY + 64u];
    char parsed_field[WORKSPACE_FIELD_CAPACITY];
    FILE* errors = tmpfile();

    CHECK(errors != NULL);
    CHECK(setenv("LIBRDP_TEST_WORKSPACE_VALUE", "ephemeral-workspace-value", 1) == 0);
    CHECK(workspace_options_parse((int)(sizeof(args) / sizeof(args[0])),
                                  args,
                                  "default-viewer",
                                  &options,
                                  errors) == 1);
    CHECK(strcmp(options.viewer, "/opt/librdp-viewer") == 0);
    CHECK(strcmp(options.security, "nla") == 0);
    CHECK(strcmp(options.config.password, "ephemeral-workspace-value") == 0);
    CHECK(options.launch == 1);
    CHECK(workspace_options_parse(
              (int)(sizeof(invalid_security) / sizeof(invalid_security[0])),
              invalid_security,
              "default-viewer",
              &options,
              errors) == 0);

    CHECK(librdp_workspace_resource_init(&resource) == LIBRDP_STATUS_OK);
    resource.type = LIBRDP_WORKSPACE_RESOURCE_REMOTE_APP;
    resource.rdp_file_contents =
      "full address:s:desktop.example.test\n"
      "server port:i:3391\n"
      "remoteapplicationprogram:s:||published\n"
      "gatewayhostname:s:gateway.example.test\n";
    CHECK(workspace_options_parse((int)(sizeof(args) / sizeof(args[0])),
                                  args,
                                  "default-viewer",
                                  &options,
                                  errors) == 1);
    CHECK(workspace_launch_plan_build(&options, &resource, &plan, errors) == 1);
    CHECK(strcmp(plan.executable, "/opt/librdp-viewer") == 0);
    CHECK(plan.arguments[plan.argument_count] == NULL);
    CHECK(launch_plan_has_pair(&plan, "--target", "desktop.example.test"));
    CHECK(launch_plan_has_pair(&plan, "--port", "3391"));
    CHECK(launch_plan_has_pair(&plan, "--security", "nla"));
    CHECK(launch_plan_has_pair(&plan, "--rail", "app=||published"));
    CHECK(launch_plan_has_pair(&plan, "--gateway", "https://gateway.example.test/"));
    CHECK(launch_plan_has_pair(&plan, "--gateway-mode", "rdg-http"));

    resource.rdp_file_contents =
      "full address:s:desktop.example.test\n"
      "server port:i:70000\n";
    CHECK(workspace_launch_plan_build(&options, &resource, &plan, errors) == 0);
    resource.rdp_file_contents = "remoteapplicationprogram:s:||published\n";
    CHECK(workspace_launch_plan_build(&options, &resource, &plan, errors) == 0);
    memset(oversized_field, 'a', sizeof(oversized_field));
    memcpy(oversized_field, "full address:s:", 15u);
    oversized_field[sizeof(oversized_field) - 1u] = '\0';
    resource.rdp_file_contents = oversized_field;
    CHECK(workspace_resource_target(&resource,
                                    parsed_field,
                                    sizeof(parsed_field)) == 0);
    CHECK(parsed_field[0] == '\0');
    CHECK(unsetenv("LIBRDP_TEST_WORKSPACE_VALUE") == 0);
    fclose(errors);
    return 0;
}

/*
 * Resolve resources by index and stable feed fields while rejecting an
 * implicit choice across multiple resources or a selector absent from the
 * current workspace generation.
 */
static int test_workspace_selection(void)
{
    static const char feed[] =
      "<Workspace><Resources>"
      "<Resource><ID>desktop-one</ID><Title>Primary Desktop</Title>"
      "<Type>Desktop</Type><TerminalServer>desktop.example.test</TerminalServer>"
      "</Resource>"
      "<RemoteApp id=\"published-app\"><Title>Published Tool</Title>"
      "<Alias>tool</Alias><RemoteAppProgram>||tool</RemoteAppProgram>"
      "</RemoteApp>"
      "</Resources></Workspace>";
    static const char duplicate_feed[] =
      "<Workspace><Resources>"
      "<Resource><ID>shared-resource</ID><Title>First Desktop</Title>"
      "<Type>Desktop</Type><TerminalServer>first.example.test</TerminalServer>"
      "</Resource>"
      "<Resource><ID>shared-resource</ID><Title>Second Desktop</Title>"
      "<Type>Desktop</Type><TerminalServer>second.example.test</TerminalServer>"
      "</Resource>"
      "</Resources></Workspace>";
    librdp_workspace_config config;
    librdp_workspace* workspace = NULL;
#ifdef RDP_HAVE_LIBXML2
    size_t selected = 99u;
#endif
    FILE* errors = tmpfile();

    CHECK(errors != NULL);
    CHECK(librdp_workspace_config_init(&config) == LIBRDP_STATUS_OK);
    workspace = librdp_workspace_new(&config);
    CHECK(workspace != NULL);
#ifdef RDP_HAVE_LIBXML2
    CHECK(librdp_workspace_load_xml(workspace, feed, sizeof(feed) - 1u) ==
          LIBRDP_STATUS_OK);
    CHECK(workspace_select_resource(workspace, NULL, &selected, errors) == 0);
    CHECK(workspace_select_resource(workspace, "0", &selected, errors) == 1);
    CHECK(selected == 0u);
    CHECK(workspace_select_resource(workspace,
                                    "desktop-one",
                                    &selected,
                                    errors) == 1);
    CHECK(selected == 0u);
    CHECK(workspace_select_resource(workspace, "tool", &selected, errors) == 1);
    CHECK(selected == 1u);
    CHECK(workspace_select_resource(workspace, "Published Tool", &selected, errors) == 1);
    CHECK(selected == 1u);
    CHECK(workspace_select_resource(workspace, "missing", &selected, errors) == 0);
    CHECK(librdp_workspace_load_xml(workspace,
                                    duplicate_feed,
                                    sizeof(duplicate_feed) - 1u) ==
          LIBRDP_STATUS_OK);
    CHECK(workspace_select_resource(workspace,
                                    "shared-resource",
                                    &selected,
                                    errors) == 0);
    CHECK(workspace_select_resource(workspace, "1", &selected, errors) == 1);
    CHECK(selected == 1u);
#else
    CHECK(librdp_workspace_load_xml(workspace,
                                    feed,
                                    sizeof(feed) - 1u) ==
          LIBRDP_STATUS_UNSUPPORTED);
#endif
    librdp_workspace_free(workspace);
    fclose(errors);
    return 0;
}

int main(void)
{
    if (test_admin_policy() != 0)
        return 1;
    if (test_workspace_launch_policy() != 0)
        return 1;
    if (test_workspace_selection() != 0)
        return 1;
    return 0;
}
