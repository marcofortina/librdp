/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client server-redirection runtime.
 * Invariants: packet views are copied before transport teardown, state changes
 * are atomic, and redirects cannot recurse beyond the configured hop bound.
 * Ownership: temporary conversion buffers are local; committed state belongs
 * to the session and securely clears any redirected password.
 * Threading: all entry points except immutable accessors require the session
 * owner thread.
 * Trust boundary: target names, address lists, routing tokens, and credential
 * overrides are untrusted wire data subject to structural and size checks.
 */

#include "client/session_internal.h"

#include "common/charset.h"
#include "common/stream.h"

#include <openssl/crypto.h>

#include <stdlib.h>
#include <string.h>

#define RDP_SESSION_MAX_REDIRECTION_ADDRESSES 64u

static void rdp_session_redirection_state_init(
    rdp_session_redirection_state* state)
{
    if (!state)
        return;
    memset(state, 0, sizeof(*state));
    rdp_buffer_init(&state->routing_data);
    (void)librdp_credentials_init(&state->credentials);
}

static void rdp_session_redirection_state_clear(
    rdp_session_redirection_state* state)
{
    if (!state)
        return;
    free(state->target_host);
    rdp_buffer_free(&state->routing_data);
    librdp_credentials_clear(&state->credentials);
    memset(state, 0, sizeof(*state));
}

librdp_status rdp_session_redirection_init(librdp_session* session)
{
    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_session_redirection_state_init(&session->redirection);
    return LIBRDP_STATUS_OK;
}

void rdp_session_redirection_clear(librdp_session* session)
{
    if (!session)
        return;
    rdp_session_redirection_state_clear(&session->redirection);
    rdp_session_redirection_state_init(&session->redirection);
}

const char* rdp_session_redirection_target(const librdp_session* session)
{
    if (!session || !session->redirection.active ||
        !session->redirection.target_host)
        return session && session->settings ?
                   librdp_settings_target(session->settings) :
                   NULL;
    return session->redirection.target_host;
}

const void* rdp_session_redirection_routing_data(
    const librdp_session* session,
    size_t* length)
{
    if (length)
        *length = 0u;
    if (!session || !session->redirection.active ||
        session->redirection.routing_data.length == 0u)
        return NULL;
    if (length)
        *length = session->redirection.routing_data.length;
    return session->redirection.routing_data.data;
}

const librdp_credentials* rdp_session_redirection_credentials(
    const librdp_session* session)
{
    return session && session->redirection.active ?
               &session->redirection.credentials :
               NULL;
}

uint32_t rdp_session_redirection_session_id(const librdp_session* session)
{
    return session && session->redirection.active ?
               session->redirection.session_id :
               0u;
}

uint8_t rdp_session_redirection_active(const librdp_session* session)
{
    return session && session->redirection.active ? 1u : 0u;
}

static librdp_status rdp_session_redirection_copy_utf16(
    const rdp_server_redirection_blob* blob,
    char** text)
{
    size_t text_len = 0u;

    if (!blob || !blob->data || blob->length < 2u || !text)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_charset_utf16le_to_utf8_alloc(
        blob->data,
        blob->length,
        1,
        text,
        &text_len);
}

/*
 * Decode and validate the complete address collection even though connection
 * fallback uses the first address. This prevents malformed trailing entries
 * from being silently accepted.
 */
static librdp_status rdp_session_redirection_first_address(
    const rdp_server_redirection_blob* blob,
    char** address)
{
    rdp_stream stream;
    uint32_t count = 0u;
    char* first = NULL;

    if (!blob || !blob->data || blob->length < 4u || !address)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *address = NULL;
    rdp_stream_init(&stream, blob->data, blob->length);
    if (rdp_stream_read_u32_le(&stream, &count) != LIBRDP_STATUS_OK ||
        count == 0u || count > RDP_SESSION_MAX_REDIRECTION_ADDRESSES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (uint32_t index = 0u; index < count; index++)
    {
        const uint8_t* bytes = NULL;
        uint32_t length = 0u;
        char* converted = NULL;
        size_t converted_len = 0u;
        librdp_status status = LIBRDP_STATUS_OK;

        if (rdp_stream_read_u32_le(&stream, &length) != LIBRDP_STATUS_OK ||
            length < 2u || (length & 1u) != 0u ||
            length > rdp_stream_remaining(&stream) ||
            rdp_stream_read_bytes(&stream, &bytes, length) !=
                LIBRDP_STATUS_OK ||
            bytes[length - 2u] != 0u || bytes[length - 1u] != 0u)
        {
            free(first);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        status = rdp_charset_utf16le_to_utf8_alloc(
            bytes,
            length,
            1,
            &converted,
            &converted_len);
        if (status != LIBRDP_STATUS_OK || converted_len == 0u)
        {
            free(converted);
            free(first);
            return status == LIBRDP_STATUS_OK ?
                       LIBRDP_STATUS_PROTOCOL_ERROR :
                       status;
        }
        if (index == 0u)
            first = converted;
        else
            free(converted);
    }
    if (rdp_stream_remaining(&stream) != 0u)
    {
        free(first);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    *address = first;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_redirection_choose_target(
    const librdp_session* session,
    const rdp_server_redirection_packet* packet,
    char** target)
{
    const rdp_server_redirection_blob* selected = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !packet || !target)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *target = NULL;
    if ((packet->redirection_flags &
         RDP_SERVER_REDIRECTION_LB_TARGET_FQDN) != 0u)
        selected = &packet->target_fqdn;
    else if ((packet->redirection_flags &
              RDP_SERVER_REDIRECTION_LB_TARGET_NET_ADDRESS) != 0u)
        selected = &packet->target_net_address;
    else if ((packet->redirection_flags &
              RDP_SERVER_REDIRECTION_LB_TARGET_NETBIOS_NAME) != 0u)
        selected = &packet->target_netbios_name;
    if (selected)
        status = rdp_session_redirection_copy_utf16(selected, target);
    else if ((packet->redirection_flags &
              RDP_SERVER_REDIRECTION_LB_TARGET_NET_ADDRESSES) != 0u)
        status = rdp_session_redirection_first_address(
            &packet->target_net_addresses,
            target);
    else
    {
        const char* current = rdp_session_redirection_target(session);

        if (!current || current[0] == '\0')
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *target = strdup(current);
        status = *target ? LIBRDP_STATUS_OK : LIBRDP_STATUS_NO_MEMORY;
    }
    if (status == LIBRDP_STATUS_OK &&
        (!*target || (*target)[0] == '\0'))
    {
        free(*target);
        *target = NULL;
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return status;
}

static librdp_status rdp_session_redirection_copy_credentials(
    const librdp_session* session,
    const rdp_server_redirection_packet* packet,
    librdp_credentials* credentials)
{
    const librdp_credentials* current =
        rdp_session_redirection_credentials(session);
    char* username = NULL;
    char* password = NULL;
    char* domain = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!packet || !credentials)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((packet->redirection_flags &
         RDP_SERVER_REDIRECTION_LB_PASSWORD_IS_PK_ENCRYPTED) != 0u)
        return LIBRDP_STATUS_UNSUPPORTED;
    if ((packet->redirection_flags &
         RDP_SERVER_REDIRECTION_LB_USERNAME) != 0u)
        status = rdp_session_redirection_copy_utf16(
            &packet->username,
            &username);
    if (status == LIBRDP_STATUS_OK &&
        (packet->redirection_flags &
         RDP_SERVER_REDIRECTION_LB_PASSWORD) != 0u)
        status = rdp_session_redirection_copy_utf16(
            &packet->password,
            &password);
    if (status == LIBRDP_STATUS_OK &&
        (packet->redirection_flags &
         RDP_SERVER_REDIRECTION_LB_DOMAIN) != 0u)
        status = rdp_session_redirection_copy_utf16(
            &packet->domain,
            &domain);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_credentials_set(
            credentials,
            username ? username : (current ? current->username : NULL),
            password ? password : (current ? current->password : NULL),
            domain ? domain : (current ? current->domain : NULL));
    free(username);
    if (password)
    {
        OPENSSL_cleanse(password, strlen(password));
        free(password);
    }
    free(domain);
    return status;
}

/*
 * Build a replacement state off to the side, then swap it into the session.
 * Any conversion or allocation failure leaves the previous route intact.
 */
librdp_status rdp_session_redirection_stage(
    librdp_session* session,
    const rdp_server_redirection_packet* packet,
    int* reconnect)
{
    rdp_session_redirection_state staged;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !packet || !reconnect)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *reconnect = 0;
    if ((packet->redirection_flags &
         RDP_SERVER_REDIRECTION_LB_NO_REDIRECT) != 0u)
    {
        rdp_trace_event(
            RDP_TRACE_CLIENT,
            "client.redirection.informational",
            "flags=%u session_id=%u",
            packet->redirection_flags,
            packet->session_id);
        return LIBRDP_STATUS_OK;
    }
    if (session->redirection.hop_count >=
        RDP_SESSION_MAX_SERVER_REDIRECTS)
    {
        rdp_session_set_last_error(
            session,
            LIBRDP_STATUS_LIMIT_EXCEEDED,
            0,
            LIBRDP_ERROR_COMPONENT_PROTOCOL,
            "client.redirection.loop",
            "server redirection hop limit exceeded");
        rdp_trace_event(
            RDP_TRACE_CLIENT,
            "client.redirection.loop_rejected",
            "hop_count=%u limit=%u",
            session->redirection.hop_count,
            RDP_SESSION_MAX_SERVER_REDIRECTS);
        return rdp_session_limit_rejected(session);
    }

    rdp_session_redirection_state_init(&staged);
    status = rdp_session_redirection_choose_target(
        session,
        packet,
        &staged.target_host);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_redirection_copy_credentials(
            session,
            packet,
            &staged.credentials);
    if (status == LIBRDP_STATUS_OK &&
        (packet->redirection_flags &
         RDP_SERVER_REDIRECTION_LB_LOAD_BALANCE_INFO) != 0u &&
        (packet->redirection_flags &
         RDP_SERVER_REDIRECTION_LB_TARGET_NET_ADDRESS) == 0u)
    {
        status = rdp_buffer_append(
            &staged.routing_data,
            packet->load_balance_info.data,
            packet->load_balance_info.length);
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_session_redirection_state_clear(&staged);
        return status;
    }

    staged.session_id = packet->session_id;
    staged.flags = packet->redirection_flags;
    staged.hop_count = session->redirection.hop_count + 1u;
    staged.active = 1u;
    rdp_session_redirection_state_clear(&session->redirection);
    session->redirection = staged;
    *reconnect = 1;
    rdp_trace_event(
        RDP_TRACE_CLIENT,
        "client.redirection.received",
        "flags=%u session_id=%u hop_count=%u routing_bytes=%u credential_fields=%u",
        packet->redirection_flags,
        packet->session_id,
        session->redirection.hop_count,
        (unsigned)session->redirection.routing_data.length,
        (session->redirection.credentials.username ? 1u : 0u) +
            (session->redirection.credentials.password ? 1u : 0u) +
            (session->redirection.credentials.domain ? 1u : 0u));
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_session_redirection_follow(librdp_session* session)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !session->redirection.active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_session_metric_add(&session->metrics.reconnects, 1u);
    rdp_trace_event(
        RDP_TRACE_CLIENT,
        "client.redirection.reconnect.start",
        "hop_count=%u routing_bytes=%u",
        session->redirection.hop_count,
        (unsigned)session->redirection.routing_data.length);
    status = rdp_session_disconnect_inner(session);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_session_set_lifecycle(
            session,
            LIBRDP_LIFECYCLE_RECONNECTING);
        status = librdp_session_connect(session);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_trace_event(
            RDP_TRACE_CLIENT,
            "client.redirection.reconnect.done",
            "hop_count=%u",
            session->redirection.hop_count);
    }
    else
    {
        rdp_trace_event(
            RDP_TRACE_CLIENT,
            "client.redirection.reconnect.failed",
            "hop_count=%u status=%s",
            session->redirection.hop_count,
            librdp_status_name(status));
    }
    return status;
}
