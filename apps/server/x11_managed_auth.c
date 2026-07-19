/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * Module: PAM and BSD Authentication adapters for managed X11 sessions.
 * Invariants: a session exists only after authentication, account checks and
 * local identity resolution all succeed; native conversation secrets are
 * cleansed before release.
 * Ownership: native authentication handles and copied environment entries are
 * owned by the returned session.
 * Threading: adapters are synchronous and intended for a cancellable broker
 * worker process, never the broker dispatch thread.
 * Trust boundary: provider messages, account databases and environment values
 * are bounded before crossing into process-launch configuration.
 */

#include "x11_managed_auth.h"

#include <openssl/crypto.h>

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef LIBRDP_HAVE_PAM
#include <security/pam_appl.h>
#endif

#ifdef LIBRDP_HAVE_BSDAUTH
#include <bsd_auth.h>
#endif

struct x11_managed_auth_session
{
    x11_managed_auth_identity identity;
    char* environment[X11_MANAGED_AUTH_MAX_ENVIRONMENT];
    size_t environment_count;
#ifdef LIBRDP_HAVE_PAM
    pam_handle_t* pam;
    int pam_credentials;
    int pam_opened;
#endif
};

typedef struct x11_managed_pam_conversation
{
    const char* username;
    const char* password;
    x11_managed_auth_cancel_callback cancelled;
    void* cancel_user_data;
} x11_managed_pam_conversation;

static int x11_managed_auth_cancelled(
    x11_managed_auth_cancel_callback cancelled,
    void* user_data)
{
    return cancelled && cancelled(user_data);
}

static int x11_managed_auth_copy(char* output,
                                 size_t capacity,
                                 const char* input)
{
    size_t length = input ? strlen(input) : 0u;

    if (!output || capacity == 0u || !input || length >= capacity)
        return 0;
    memcpy(output, input, length + 1u);
    return 1;
}

void x11_managed_auth_config_init(x11_managed_auth_config* config)
{
    if (!config)
        return;
    memset(config, 0, sizeof(*config));
    config->version = X11_MANAGED_AUTH_VERSION;
    config->size = sizeof(*config);
    config->service_name = "librdp-x11";
}

void x11_managed_auth_identity_init(x11_managed_auth_identity* identity)
{
    if (!identity)
        return;
    memset(identity, 0, sizeof(*identity));
    identity->version = X11_MANAGED_AUTH_VERSION;
    identity->size = sizeof(*identity);
}

/*
 * Resolve the authenticated account with reentrant libc interfaces and copy
 * every field needed after privileges are dropped.
 */
static librdp_status x11_managed_auth_resolve_identity(
    const char* username,
    x11_managed_auth_identity* identity)
{
    struct passwd account;
    struct passwd* result = NULL;
    long configured_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t buffer_size =
        configured_size > 0 && configured_size <= 1048576L
            ? (size_t)configured_size
            : 16384u;
    char* buffer = NULL;
    int group_count = (int)X11_MANAGED_AUTH_MAX_GROUPS;
    int lookup = 0;

    if (!username || !identity)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    buffer = (char*)calloc(buffer_size, 1u);
    if (!buffer)
        return LIBRDP_STATUS_NO_MEMORY;
    memset(&account, 0, sizeof(account));
    errno = 0;
    lookup = getpwnam_r(username,
                        &account,
                        buffer,
                        buffer_size,
                        &result);
    if (lookup != 0 || !result)
    {
        OPENSSL_cleanse(buffer, buffer_size);
        free(buffer);
        return lookup == ENOMEM || lookup == ERANGE
                   ? LIBRDP_STATUS_LIMIT_EXCEEDED
                   : LIBRDP_STATUS_STATE;
    }
    x11_managed_auth_identity_init(identity);
    identity->uid = account.pw_uid;
    identity->gid = account.pw_gid;
    if (!x11_managed_auth_copy(identity->username,
                               sizeof(identity->username),
                               account.pw_name) ||
        !x11_managed_auth_copy(identity->home,
                               sizeof(identity->home),
                               account.pw_dir) ||
        !x11_managed_auth_copy(identity->shell,
                               sizeof(identity->shell),
                               account.pw_shell))
    {
        OPENSSL_cleanse(buffer, buffer_size);
        free(buffer);
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    if (getgrouplist(account.pw_name,
                     account.pw_gid,
                     identity->groups,
                     &group_count) < 0 ||
        group_count < 0 ||
        (size_t)group_count > X11_MANAGED_AUTH_MAX_GROUPS)
    {
        OPENSSL_cleanse(buffer, buffer_size);
        free(buffer);
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    identity->group_count = (size_t)group_count;
    OPENSSL_cleanse(buffer, buffer_size);
    free(buffer);
    return LIBRDP_STATUS_OK;
}

static void x11_managed_auth_free_environment(
    x11_managed_auth_session* session)
{
    size_t index = 0u;

    if (!session)
        return;
    for (index = 0u; index < session->environment_count; index++)
    {
        if (session->environment[index])
        {
            OPENSSL_cleanse(session->environment[index],
                            strlen(session->environment[index]));
            free(session->environment[index]);
            session->environment[index] = NULL;
        }
    }
    session->environment_count = 0u;
}

#ifdef LIBRDP_HAVE_PAM
static void x11_managed_auth_free_responses(struct pam_response* responses,
                                            int count)
{
    int index = 0;

    if (!responses)
        return;
    for (index = 0; index < count; index++)
    {
        if (responses[index].resp)
        {
            OPENSSL_cleanse(responses[index].resp,
                            strlen(responses[index].resp));
            free(responses[index].resp);
        }
    }
    OPENSSL_cleanse(responses,
                    (size_t)count * sizeof(*responses));
    free(responses);
}

/*
 * Answer only username and secret prompts. Informational messages receive an
 * empty response, while unknown styles abort the entire conversation.
 */
static int x11_managed_auth_pam_converse(
    int count,
    const struct pam_message** messages,
    struct pam_response** output,
    void* user_data)
{
    x11_managed_pam_conversation* conversation =
        (x11_managed_pam_conversation*)user_data;
    struct pam_response* responses = NULL;
    int index = 0;

    if (count <= 0 || count > 32 || !messages || !output ||
        !conversation ||
        x11_managed_auth_cancelled(conversation->cancelled,
                                   conversation->cancel_user_data))
        return PAM_CONV_ERR;
    responses = (struct pam_response*)calloc((size_t)count,
                                              sizeof(*responses));
    if (!responses)
        return PAM_BUF_ERR;
    for (index = 0; index < count; index++)
    {
        const char* value = "";

        if (!messages[index])
        {
            x11_managed_auth_free_responses(responses, count);
            return PAM_CONV_ERR;
        }
        if (messages[index]->msg_style == PAM_PROMPT_ECHO_ON)
            value = conversation->username;
        else if (messages[index]->msg_style == PAM_PROMPT_ECHO_OFF)
            value = conversation->password;
        else if (messages[index]->msg_style != PAM_TEXT_INFO &&
                 messages[index]->msg_style != PAM_ERROR_MSG)
        {
            x11_managed_auth_free_responses(responses, count);
            return PAM_CONV_ERR;
        }
        responses[index].resp = strdup(value);
        if (!responses[index].resp)
        {
            x11_managed_auth_free_responses(responses, count);
            return PAM_BUF_ERR;
        }
    }
    *output = responses;
    return PAM_SUCCESS;
}

static x11_managed_auth_outcome x11_managed_auth_pam_outcome(int result)
{
    if (result == PAM_SUCCESS)
        return X11_MANAGED_AUTH_AUTHENTICATED;
    if (result == PAM_AUTH_ERR || result == PAM_USER_UNKNOWN ||
        result == PAM_MAXTRIES || result == PAM_CRED_INSUFFICIENT)
        return X11_MANAGED_AUTH_DENIED;
    if (result == PAM_ACCT_EXPIRED ||
        result == PAM_NEW_AUTHTOK_REQD ||
        result == PAM_PERM_DENIED)
        return X11_MANAGED_AUTH_ACCOUNT_RESTRICTED;
    return X11_MANAGED_AUTH_UNAVAILABLE;
}

static librdp_status x11_managed_auth_copy_pam_environment(
    x11_managed_auth_session* session)
{
    char** values = NULL;
    size_t index = 0u;

    values = pam_getenvlist(session->pam);
    if (!values)
        return LIBRDP_STATUS_OK;
    while (values[index])
    {
        size_t length = strlen(values[index]);

        if (session->environment_count >=
                X11_MANAGED_AUTH_MAX_ENVIRONMENT ||
            length == 0u || length >= X11_MANAGED_AUTH_PATH_BYTES)
        {
            while (values[index])
            {
                OPENSSL_cleanse(values[index],
                                strlen(values[index]));
                free(values[index]);
                index++;
            }
            free(values);
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
        }
        session->environment[session->environment_count] =
            strdup(values[index]);
        if (!session->environment[session->environment_count])
        {
            while (values[index])
            {
                OPENSSL_cleanse(values[index],
                                strlen(values[index]));
                free(values[index]);
                index++;
            }
            free(values);
            return LIBRDP_STATUS_NO_MEMORY;
        }
        session->environment_count++;
        OPENSSL_cleanse(values[index], length);
        free(values[index]);
        index++;
    }
    free(values);
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_managed_auth_open_pam(
    const x11_managed_auth_config* config,
    const char* username,
    const char* password,
    x11_managed_auth_cancel_callback cancelled,
    void* cancel_user_data,
    x11_managed_auth_outcome* outcome,
    x11_managed_auth_session* session)
{
    x11_managed_pam_conversation conversation;
    struct pam_conv pam_conversation;
    int result = PAM_SYSTEM_ERR;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(&conversation, 0, sizeof(conversation));
    conversation.username = username;
    conversation.password = password;
    conversation.cancelled = cancelled;
    conversation.cancel_user_data = cancel_user_data;
    memset(&pam_conversation, 0, sizeof(pam_conversation));
    pam_conversation.conv = x11_managed_auth_pam_converse;
    pam_conversation.appdata_ptr = &conversation;
    result = pam_start(config->service_name,
                       username,
                       &pam_conversation,
                       &session->pam);
    if (result == PAM_SUCCESS &&
        !x11_managed_auth_cancelled(cancelled, cancel_user_data))
        result = pam_authenticate(session->pam, PAM_SILENT);
    if (result == PAM_SUCCESS &&
        !x11_managed_auth_cancelled(cancelled, cancel_user_data))
        result = pam_acct_mgmt(session->pam, PAM_SILENT);
    if (x11_managed_auth_cancelled(cancelled, cancel_user_data))
    {
        *outcome = X11_MANAGED_AUTH_CANCELLED;
        return LIBRDP_STATUS_CANCELLED;
    }
    *outcome = x11_managed_auth_pam_outcome(result);
    if (result != PAM_SUCCESS)
        return LIBRDP_STATUS_OK;
    result = pam_setcred(session->pam, PAM_ESTABLISH_CRED);
    if (result != PAM_SUCCESS)
    {
        *outcome = X11_MANAGED_AUTH_UNAVAILABLE;
        return LIBRDP_STATUS_IO_ERROR;
    }
    session->pam_credentials = 1;
    result = pam_open_session(session->pam, PAM_SILENT);
    if (result != PAM_SUCCESS)
    {
        *outcome = X11_MANAGED_AUTH_UNAVAILABLE;
        return LIBRDP_STATUS_IO_ERROR;
    }
    session->pam_opened = 1;
    status = x11_managed_auth_copy_pam_environment(session);
    if (status != LIBRDP_STATUS_OK)
        *outcome = X11_MANAGED_AUTH_UNAVAILABLE;
    return status;
}
#endif

#ifdef LIBRDP_HAVE_BSDAUTH
static librdp_status x11_managed_auth_open_bsd(
    const x11_managed_auth_config* config,
    const char* username,
    const char* password,
    x11_managed_auth_cancel_callback cancelled,
    void* cancel_user_data,
    x11_managed_auth_outcome* outcome)
{
    (void)config;
    if (x11_managed_auth_cancelled(cancelled, cancel_user_data))
    {
        *outcome = X11_MANAGED_AUTH_CANCELLED;
        return LIBRDP_STATUS_CANCELLED;
    }
    *outcome = auth_userokay(username,
                             NULL,
                             "auth-librdp-x11",
                             password)
                   ? X11_MANAGED_AUTH_AUTHENTICATED
                   : X11_MANAGED_AUTH_DENIED;
    return LIBRDP_STATUS_OK;
}
#endif

static int x11_managed_auth_config_valid(
    const x11_managed_auth_config* config)
{
    size_t service_length =
        config && config->service_name
            ? strlen(config->service_name)
            : 0u;

    return config && config->version == X11_MANAGED_AUTH_VERSION &&
           config->size >= sizeof(*config) &&
           service_length > 0u &&
           service_length < X11_MANAGED_AUTH_NAME_BYTES;
}

/*
 * Authenticate one managed-session identity through the configured provider
 * or native service and resolve all process credentials before returning.
 * Ownership: output receives a session only after complete validation.
 * Failure policy: credentials and partial provider state are cleared on every
 * denied, cancelled, unavailable, or malformed outcome.
 */
librdp_status x11_managed_auth_session_open(
    const x11_managed_auth_config* config,
    const char* username,
    const char* password,
    x11_managed_auth_cancel_callback cancelled,
    void* cancel_user_data,
    x11_managed_auth_outcome* outcome,
    x11_managed_auth_session** output)
{
    x11_managed_auth_session* session = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t username_length =
        username ? strnlen(username, X11_MANAGED_AUTH_NAME_BYTES) : 0u;
    size_t password_length =
        password ? strnlen(password, 4096u) : 0u;

    if (!x11_managed_auth_config_valid(config) || !outcome || !output ||
        username_length == 0u ||
        username_length >= X11_MANAGED_AUTH_NAME_BYTES ||
        password_length == 0u || password_length >= 4096u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *outcome = X11_MANAGED_AUTH_UNAVAILABLE;
    *output = NULL;
    if (x11_managed_auth_cancelled(cancelled, cancel_user_data))
    {
        *outcome = X11_MANAGED_AUTH_CANCELLED;
        return LIBRDP_STATUS_CANCELLED;
    }
    session = (x11_managed_auth_session*)calloc(1u, sizeof(*session));
    if (!session)
        return LIBRDP_STATUS_NO_MEMORY;
    x11_managed_auth_identity_init(&session->identity);
    if (config->provider)
    {
        status = config->provider(username,
                                  password,
                                  cancelled,
                                  cancel_user_data,
                                  outcome,
                                  &session->identity,
                                  config->provider_user_data);
    }
#ifdef LIBRDP_HAVE_PAM
    else
    {
        status = x11_managed_auth_open_pam(config,
                                           username,
                                           password,
                                           cancelled,
                                           cancel_user_data,
                                           outcome,
                                           session);
    }
#elif defined(LIBRDP_HAVE_BSDAUTH)
    else
    {
        status = x11_managed_auth_open_bsd(config,
                                           username,
                                           password,
                                           cancelled,
                                           cancel_user_data,
                                           outcome);
    }
#else
    else
    {
        status = LIBRDP_STATUS_UNSUPPORTED;
        *outcome = X11_MANAGED_AUTH_UNAVAILABLE;
    }
#endif
    if (status == LIBRDP_STATUS_OK &&
        *outcome == X11_MANAGED_AUTH_AUTHENTICATED &&
        config->provider == NULL)
    {
        status = x11_managed_auth_resolve_identity(
            username, &session->identity);
        if (status != LIBRDP_STATUS_OK)
            *outcome = X11_MANAGED_AUTH_UNAVAILABLE;
    }
    if (status != LIBRDP_STATUS_OK ||
        *outcome != X11_MANAGED_AUTH_AUTHENTICATED)
    {
        x11_managed_auth_session_close(session);
        return status;
    }
    if (session->identity.version != X11_MANAGED_AUTH_VERSION ||
        session->identity.size < sizeof(session->identity) ||
        session->identity.username[0] == '\0' ||
        session->identity.home[0] == '\0' ||
        session->identity.shell[0] == '\0' ||
        session->identity.group_count >
            X11_MANAGED_AUTH_MAX_GROUPS)
    {
        *outcome = X11_MANAGED_AUTH_UNAVAILABLE;
        x11_managed_auth_session_close(session);
        return LIBRDP_STATUS_STATE;
    }
    *output = session;
    return LIBRDP_STATUS_OK;
}

void x11_managed_auth_session_close(x11_managed_auth_session* session)
{
    if (!session)
        return;
#ifdef LIBRDP_HAVE_PAM
    if (session->pam)
    {
        if (session->pam_opened)
            (void)pam_close_session(session->pam, PAM_SILENT);
        if (session->pam_credentials)
            (void)pam_setcred(session->pam, PAM_DELETE_CRED);
        (void)pam_end(session->pam, PAM_SUCCESS);
        session->pam = NULL;
    }
#endif
    x11_managed_auth_free_environment(session);
    OPENSSL_cleanse(session, sizeof(*session));
    free(session);
}

const x11_managed_auth_identity* x11_managed_auth_session_identity(
    const x11_managed_auth_session* session)
{
    return session ? &session->identity : NULL;
}

size_t x11_managed_auth_session_environment_count(
    const x11_managed_auth_session* session)
{
    return session ? session->environment_count : 0u;
}

const char* x11_managed_auth_session_environment_at(
    const x11_managed_auth_session* session,
    size_t index)
{
    if (!session || index >= session->environment_count)
        return NULL;
    return session->environment[index];
}
