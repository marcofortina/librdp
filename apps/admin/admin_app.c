/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared administration command lifecycle and textual output.
 * Invariants: actions are executed only after option-policy validation, query
 * output uses borrowed public views synchronously, and UI presentation occurs
 * only after a successful inventory query.
 * Ownership: this module creates and frees the admin handle; argv strings and
 * callback context remain caller-owned.
 * Threading: synchronous and single-threaded; the native callback runs on the
 * thread that called admin_app_run().
 * Trust boundary: endpoint responses are untrusted and are exposed only
 * through bounded public inventory fields.
 */

#include "admin_app.h"
#include "admin_options.h"

#include <stdio.h>

static void admin_app_print_session(size_t index,
                                    const librdp_admin_session* session)
{
    printf("session index=%zu session_id=%u logon_id=%llu user=\"%s\" "
           "domain=\"%s\" state=\"%s\" client=\"%s\" station=\"%s\" "
           "protocol=\"%s\"\n",
           index,
           (unsigned)session->session_id,
           (unsigned long long)session->logon_id,
           session->username ? session->username : "",
           session->domain ? session->domain : "",
           session->state ? session->state : "",
           session->client_name ? session->client_name : "",
           session->station_name ? session->station_name : "",
           session->protocol_name ? session->protocol_name : "");
}

/*
 * Walk the immutable session inventory and print one stable record per entry.
 * A view is consumed immediately because its string storage belongs to the
 * admin handle and is invalidated by the next query or final cleanup.
 */
static int admin_app_print_sessions(const librdp_admin* admin)
{
    size_t count = librdp_admin_session_count(admin);
    size_t index = 0;

    printf("sessions count=%zu\n", count);
    for (index = 0; index < count; index++)
    {
        librdp_admin_session session;

        if (librdp_admin_session_init(&session) != LIBRDP_STATUS_OK ||
            librdp_admin_session_at(admin, index, &session) !=
              LIBRDP_STATUS_OK)
            return 0;
        admin_app_print_session(index, &session);
    }
    return 1;
}

/*
 * Execute the common parse, action and query sequence. Destructive action
 * confirmation is enforced by admin_options_parse(); a headless action exits
 * after its completion rather than issuing an unrelated inventory request.
 */
int admin_app_run(int argc,
                  char** argv,
                  const admin_app_platform* platform)
{
    admin_options options;
    librdp_admin* admin = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    int result = 0;

    if (!platform || !platform->present)
        return 2;
    if (!admin_options_parse(argc, argv, &options, stderr))
    {
        admin_options_usage(stderr, argc > 0 && argv ? argv[0] : NULL);
        return 2;
    }
    if (options.show_help)
    {
        admin_options_usage(stdout, argv[0]);
        return 0;
    }
    admin = librdp_admin_new(&options.config);
    if (!admin)
    {
        fprintf(stderr, "failed to create admin handle\n");
        return 2;
    }
    if (options.execute_action)
    {
        status = librdp_admin_execute_action(admin, &options.action);
        if (status != LIBRDP_STATUS_OK)
        {
            fprintf(stderr,
                    "admin action failed: %s\n",
                    librdp_status_name(status));
            result = 3;
        }
        else
        {
            printf("admin action done type=%u session_id=%u\n",
                   (unsigned)options.action.type,
                   (unsigned)options.action.session_id);
            if (options.no_window)
                result = 0;
        }
        if (result != 0 || options.no_window)
        {
            librdp_admin_free(admin);
            return result;
        }
    }
    status = librdp_admin_query_sessions(admin);
    if (status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr,
                "admin query failed: %s\n",
                librdp_status_name(status));
        result = 3;
    }
    else if (!admin_app_print_sessions(admin))
        result = 3;
    else if (!options.no_window &&
             !platform->present(admin, platform->user_data))
        result = 4;
    librdp_admin_free(admin);
    return result;
}
