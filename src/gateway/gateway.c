/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: libcurl-backed gateway transport provider.
 * Invariants: HTTP CONNECT setup validates all string lengths, redacts
 * credentials in trace, and commits the socket only after libcurl reports a
 * completed tunnel.
 * Ownership: after rdp_transport_attach_curl_easy() succeeds, the transport
 * owns the libcurl easy handle and active socket.
 * Threading: connection setup is synchronous and runs on the session connection
 * thread.
 * Trust boundary: gateway responses are accepted only through libcurl's
 * HTTP/TLS/proxy-auth state machine.
 */

#include "gateway/gateway.h"

#include "common/trace.h"
#include "transport/transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef RDP_HAVE_CURL
#include <curl/curl.h>
#include <pthread.h>
#endif

#define RDP_GATEWAY_URL_MAX 4096u
#define RDP_GATEWAY_TARGET_MAX 512u

static int rdp_gateway_valid_text(const char* text, size_t max_len)
{
    size_t len = 0;

    if (!text || text[0] == '\0')
        return 0;
    len = strlen(text);
    return len <= max_len;
}

static int rdp_gateway_valid_url(const char* url)
{
    return rdp_gateway_valid_text(url, RDP_GATEWAY_URL_MAX) &&
           (strncmp(url, "https://", 8u) == 0 || strncmp(url, "http://", 7u) == 0);
}

static librdp_status rdp_gateway_target_url(const char* host, uint16_t port, char** out)
{
    int written = 0;
    size_t needed = 0;
    char* url = NULL;
    const int ipv6_literal = host && strchr(host, ':') != NULL && host[0] != '[';

    if (!rdp_gateway_valid_text(host, RDP_GATEWAY_TARGET_MAX) || port == 0 || !out)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    written = snprintf(NULL, 0, "http://%s%s%s:%u/", ipv6_literal ? "[" : "", host, ipv6_literal ? "]" : "",
                       (unsigned)port);
    if (written <= 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    needed = (size_t)written + 1u;
    url = (char*)malloc(needed);
    if (!url)
        return LIBRDP_STATUS_NO_MEMORY;
    written = snprintf(url, needed, "http://%s%s%s:%u/", ipv6_literal ? "[" : "", host, ipv6_literal ? "]" : "",
                       (unsigned)port);
    if (written <= 0 || (size_t)written + 1u != needed)
    {
        free(url);
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    *out = url;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gateway_user_name(const char* domain, const char* username, char** out)
{
    int written = 0;
    size_t needed = 0;
    char* value = NULL;

    if (!out)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *out = NULL;
    if (!username)
        return LIBRDP_STATUS_OK;
    if (!rdp_gateway_valid_text(username, RDP_GATEWAY_TARGET_MAX))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (domain && !rdp_gateway_valid_text(domain, RDP_GATEWAY_TARGET_MAX))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!domain)
    {
        value = (char*)malloc(strlen(username) + 1u);
        if (!value)
            return LIBRDP_STATUS_NO_MEMORY;
        memcpy(value, username, strlen(username) + 1u);
        *out = value;
        return LIBRDP_STATUS_OK;
    }
    written = snprintf(NULL, 0, "%s\\%s", domain, username);
    if (written <= 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    needed = (size_t)written + 1u;
    value = (char*)malloc(needed);
    if (!value)
        return LIBRDP_STATUS_NO_MEMORY;
    written = snprintf(value, needed, "%s\\%s", domain, username);
    if (written <= 0 || (size_t)written + 1u != needed)
    {
        free(value);
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    *out = value;
    return LIBRDP_STATUS_OK;
}

#ifdef RDP_HAVE_CURL
static pthread_once_t rdp_gateway_curl_once = PTHREAD_ONCE_INIT;

static void rdp_gateway_curl_init_once(void)
{
    (void)curl_global_init(CURL_GLOBAL_DEFAULT);
}

static librdp_status rdp_gateway_curl_code_status(CURLcode code)
{
    if (code == CURLE_OK)
        return LIBRDP_STATUS_OK;
    if (code == CURLE_OPERATION_TIMEDOUT)
        return LIBRDP_STATUS_TIMEOUT;
    if (code == CURLE_UNSUPPORTED_PROTOCOL)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (code == CURLE_PEER_FAILED_VERIFICATION || code == CURLE_SSL_CACERT_BADFILE)
        return LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
    return LIBRDP_STATUS_IO_ERROR;
}
#endif

librdp_status rdp_gateway_connect_transport(rdp_transport* transport,
                                            const rdp_gateway_connect_config* config)
{
    char* target_url = NULL;
    char* proxy_user = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!transport || !config || !rdp_gateway_valid_url(config->gateway_url) ||
        !rdp_gateway_valid_text(config->target_host, RDP_GATEWAY_TARGET_MAX) || config->target_port == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_gateway_target_url(config->target_host, config->target_port, &target_url);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_gateway_user_name(config->domain, config->username, &proxy_user);
    if (status != LIBRDP_STATUS_OK)
    {
        free(target_url);
        return status;
    }

#ifndef RDP_HAVE_CURL
    free(target_url);
    free(proxy_user);
    return LIBRDP_STATUS_UNSUPPORTED;
#else
    CURL* easy = NULL;
    CURLcode code = CURLE_OK;
    curl_socket_t socket_fd = CURL_SOCKET_BAD;

    pthread_once(&rdp_gateway_curl_once, rdp_gateway_curl_init_once);
    easy = curl_easy_init();
    if (!easy)
    {
        free(target_url);
        free(proxy_user);
        return LIBRDP_STATUS_NO_MEMORY;
    }

    rdp_trace_event(RDP_TRACE_TRANSPORT,
                    "transport.gateway.connect.start",
                    "url=\"%s\" target=\"%s\" port=%u",
                    config->gateway_url,
                    config->target_host,
                    (unsigned)config->target_port);
    curl_easy_setopt(easy, CURLOPT_URL, target_url);
    curl_easy_setopt(easy, CURLOPT_PROXY, config->gateway_url);
    curl_easy_setopt(easy, CURLOPT_HTTPPROXYTUNNEL, 1L);
    curl_easy_setopt(easy, CURLOPT_CONNECT_ONLY, 1L);
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, (long)config->timeout_ms);
    curl_easy_setopt(easy, CURLOPT_PROXYAUTH, (long)CURLAUTH_ANYSAFE);
    if (proxy_user)
        curl_easy_setopt(easy, CURLOPT_PROXYUSERNAME, proxy_user);
    if (config->password)
        curl_easy_setopt(easy, CURLOPT_PROXYPASSWORD, config->password);
    code = curl_easy_perform(easy);
    status = rdp_gateway_curl_code_status(code);
    if (status == LIBRDP_STATUS_OK)
    {
        code = curl_easy_getinfo(easy, CURLINFO_ACTIVESOCKET, &socket_fd);
        status = rdp_gateway_curl_code_status(code);
    }
    if (status != LIBRDP_STATUS_OK || socket_fd == CURL_SOCKET_BAD)
    {
        rdp_trace_event(RDP_TRACE_TRANSPORT,
                        "transport.gateway.connect.failed",
                        "status=%s curl_code=%u",
                        librdp_status_name(status),
                        (unsigned)code);
        curl_easy_cleanup(easy);
        free(target_url);
        free(proxy_user);
        return status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_IO_ERROR : status;
    }
    rdp_transport_attach_curl_easy(transport, easy, (int)socket_fd);
    rdp_trace_event(RDP_TRACE_TRANSPORT,
                    "transport.gateway.connect.done",
                    "target=\"%s\" port=%u",
                    config->target_host,
                    (unsigned)config->target_port);
    free(target_url);
    free(proxy_user);
    return LIBRDP_STATUS_OK;
#endif
}
