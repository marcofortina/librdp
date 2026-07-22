/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: libcurl socket configuration shared by gateway and HTTP clients.
 * Invariants: platform socket policy is installed before connect and remains
 * attached to the easy handle through connection-cache teardown.
 * Ownership: no curl handle or descriptor ownership is transferred.
 * Threading: callbacks execute on the thread driving the associated handle.
 * Trust boundary: a peer closing a socket is represented as a curl error.
 */

#include "common/curl_support.h"

#include "platform/socket.h"

#ifdef RDP_HAVE_CURL
#include <curl/curl.h>

/* Apply process-safe send semantics to every socket opened by libcurl. */
static int rdp_curl_socket_option(void* user_data,
                                  curl_socket_t descriptor,
                                  curlsocktype purpose)
{
    (void)user_data;
    (void)purpose;
    return rdp_socket_set_nosigpipe((int)descriptor) == 0
               ? CURL_SOCKOPT_OK
               : CURL_SOCKOPT_ERROR;
}
#endif

int rdp_curl_apply_socket_policy(void* easy_handle)
{
#ifdef RDP_HAVE_CURL
    CURLcode code = CURLE_OK;

    if (!easy_handle)
        return 0;
    code = curl_easy_setopt((CURL*)easy_handle,
                            CURLOPT_SOCKOPTFUNCTION,
                            rdp_curl_socket_option);
    return code == CURLE_OK;
#else
    (void)easy_handle;
    return 0;
#endif
}
