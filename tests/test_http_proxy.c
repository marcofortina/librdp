/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic HTTP CONNECT proxy fixture.
 * Coverage: Digest authentication, credential separation, CONNECT routing,
 * and bidirectional forwarding for client gateway smoke tests.
 * Bug classes: credential leakage, wrong target routing, partial I/O, and
 * tunnel teardown races.
 * Determinism: the proxy listens only on loopback and forwards to one
 * loopback target selected by the test.
 */

#include "test_http_proxy.h"

#include <openssl/evp.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define TEST_HTTP_PROXY_HEADER_MAX 8192u
#define TEST_HTTP_PROXY_FIELD_MAX 1024u
#define TEST_HTTP_PROXY_REALM "librdp-gateway-smoke"
#define TEST_HTTP_PROXY_NONCE "57f3b9639c6f4dfb82bca79331e02819"

static int test_http_proxy_send_all(int fd,
                                    const uint8_t* data,
                                    size_t length)
{
    size_t offset = 0u;

    while (offset < length)
    {
        ssize_t sent = 0;

#ifdef MSG_NOSIGNAL
        sent = send(fd,
                    data + offset,
                    length - offset,
                    MSG_NOSIGNAL);
#else
        sent = send(fd, data + offset, length - offset, 0);
#endif
        if (sent < 0 && errno == EINTR)
            continue;
        if (sent <= 0)
            return 0;
        offset += (size_t)sent;
    }
    return 1;
}

static int test_http_proxy_read_headers(int fd,
                                        char* request,
                                        size_t request_len)
{
    size_t used = 0u;

    if (!request || request_len < 5u)
        return 0;
    request[0] = '\0';
    while (used + 1u < request_len)
    {
        ssize_t received = recv(fd, request + used, 1u, 0);

        if (received < 0 && errno == EINTR)
            continue;
        if (received <= 0)
            return 0;
        used += (size_t)received;
        request[used] = '\0';
        if (used >= 4u &&
            memcmp(request + used - 4u, "\r\n\r\n", 4u) == 0)
            return 1;
    }
    return 0;
}

static const char* test_http_proxy_header(const char* request,
                                          const char* name)
{
    size_t name_len = 0u;
    const char* line = NULL;

    if (!request || !name)
        return NULL;
    name_len = strlen(name);
    line = request;
    while (line && *line)
    {
        const char* next = strstr(line, "\r\n");

        if (!next)
            return NULL;
        if ((size_t)(next - line) > name_len &&
            strncasecmp(line, name, name_len) == 0 &&
            line[name_len] == ':')
        {
            line += name_len + 1u;
            while (*line == ' ' || *line == '\t')
                line++;
            return line;
        }
        line = next + 2u;
    }
    return NULL;
}

/*
 * Parse one RFC 7616 parameter emitted by libcurl. Quoted values are
 * unescaped into caller storage; token values stop at comma or whitespace.
 */
static int test_http_proxy_digest_field(const char* authorization,
                                        const char* name,
                                        char* output,
                                        size_t output_len)
{
    size_t name_len = 0u;
    const char* cursor = NULL;
    size_t used = 0u;

    if (!authorization || !name || !output || output_len == 0u)
        return 0;
    name_len = strlen(name);
    cursor = authorization;
    while ((cursor = strstr(cursor, name)) != NULL)
    {
        if ((cursor == authorization ||
             cursor[-1] == ' ' ||
             cursor[-1] == ',') &&
            cursor[name_len] == '=')
            break;
        cursor += name_len;
    }
    if (!cursor)
        return 0;
    cursor += name_len + 1u;
    if (*cursor == '"')
    {
        cursor++;
        while (*cursor && *cursor != '"')
        {
            char value = *cursor++;

            if (value == '\\' && *cursor)
                value = *cursor++;
            if (used + 1u >= output_len)
                return 0;
            output[used++] = value;
        }
        if (*cursor != '"')
            return 0;
    }
    else
    {
        while (*cursor &&
               *cursor != ',' &&
               *cursor != '\r' &&
               *cursor != '\n' &&
               !isspace((unsigned char)*cursor))
        {
            if (used + 1u >= output_len)
                return 0;
            output[used++] = *cursor++;
        }
    }
    output[used] = '\0';
    return used > 0u;
}

static int test_http_proxy_sha256_hex(const char* text,
                                      char output[65])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0u;
    size_t index = 0u;

    if (!text || !output ||
        EVP_Digest(text,
                   strlen(text),
                   digest,
                   &digest_len,
                   EVP_sha256(),
                   NULL) != 1 ||
        digest_len != 32u)
        return 0;
    for (index = 0u; index < digest_len; index++)
    {
        output[index * 2u] = hex[digest[index] >> 4u];
        output[index * 2u + 1u] = hex[digest[index] & 0x0fu];
    }
    output[64] = '\0';
    return 1;
}

static int test_http_proxy_join_user(const test_http_proxy_config* config,
                                     char* output,
                                     size_t output_len)
{
    int written = 0;

    if (!config || !config->gateway_username ||
        !output || output_len == 0u)
        return 0;
    if (config->gateway_domain && config->gateway_domain[0] != '\0')
        written = snprintf(output,
                           output_len,
                           "%s\\%s",
                           config->gateway_domain,
                           config->gateway_username);
    else
        written = snprintf(output,
                           output_len,
                           "%s",
                           config->gateway_username);
    return written > 0 && (size_t)written < output_len;
}

/*
 * Verify Digest SHA-256 rather than merely checking for an Authorization
 * header. This proves that the gateway password selected by the session was
 * actually used and was not replaced by target credentials.
 */
static int test_http_proxy_verify_digest(const test_http_proxy_config* config,
                                         const char* authorization,
                                         const char* expected_uri)
{
    char username[TEST_HTTP_PROXY_FIELD_MAX];
    char realm[TEST_HTTP_PROXY_FIELD_MAX];
    char nonce[TEST_HTTP_PROXY_FIELD_MAX];
    char uri[TEST_HTTP_PROXY_FIELD_MAX];
    char response[TEST_HTTP_PROXY_FIELD_MAX];
    char qop[TEST_HTTP_PROXY_FIELD_MAX];
    char nonce_count[TEST_HTTP_PROXY_FIELD_MAX];
    char cnonce[TEST_HTTP_PROXY_FIELD_MAX];
    char algorithm[TEST_HTTP_PROXY_FIELD_MAX];
    char expected_username[TEST_HTTP_PROXY_FIELD_MAX];
    char input[4096];
    char ha1[65];
    char ha2[65];
    char expected_response[65];
    int written = 0;

    if (!config || !authorization || !expected_uri ||
        strncasecmp(authorization, "Digest ", 7u) != 0 ||
        !test_http_proxy_digest_field(authorization,
                                      "username",
                                      username,
                                      sizeof(username)) ||
        !test_http_proxy_digest_field(authorization,
                                      "realm",
                                      realm,
                                      sizeof(realm)) ||
        !test_http_proxy_digest_field(authorization,
                                      "nonce",
                                      nonce,
                                      sizeof(nonce)) ||
        !test_http_proxy_digest_field(authorization,
                                      "uri",
                                      uri,
                                      sizeof(uri)) ||
        !test_http_proxy_digest_field(authorization,
                                      "response",
                                      response,
                                      sizeof(response)) ||
        !test_http_proxy_digest_field(authorization,
                                      "qop",
                                      qop,
                                      sizeof(qop)) ||
        !test_http_proxy_digest_field(authorization,
                                      "nc",
                                      nonce_count,
                                      sizeof(nonce_count)) ||
        !test_http_proxy_digest_field(authorization,
                                      "cnonce",
                                      cnonce,
                                      sizeof(cnonce)) ||
        !test_http_proxy_digest_field(authorization,
                                      "algorithm",
                                      algorithm,
                                      sizeof(algorithm)) ||
        !test_http_proxy_join_user(config,
                                   expected_username,
                                   sizeof(expected_username)) ||
        strcmp(username, expected_username) != 0 ||
        strcmp(realm, TEST_HTTP_PROXY_REALM) != 0 ||
        strcmp(nonce, TEST_HTTP_PROXY_NONCE) != 0 ||
        strcmp(uri, expected_uri) != 0 ||
        strcmp(qop, "auth") != 0 ||
        strcasecmp(algorithm, "SHA-256") != 0)
        return 0;
    written = snprintf(input,
                       sizeof(input),
                       "%s:%s:%s",
                       username,
                       realm,
                       config->gateway_password);
    if (written <= 0 || (size_t)written >= sizeof(input) ||
        !test_http_proxy_sha256_hex(input, ha1))
        return 0;
    written = snprintf(input,
                       sizeof(input),
                       "CONNECT:%s",
                       uri);
    if (written <= 0 || (size_t)written >= sizeof(input) ||
        !test_http_proxy_sha256_hex(input, ha2))
        return 0;
    written = snprintf(input,
                       sizeof(input),
                       "%s:%s:%s:%s:%s:%s",
                       ha1,
                       nonce,
                       nonce_count,
                       cnonce,
                       qop,
                       ha2);
    if (written <= 0 || (size_t)written >= sizeof(input) ||
        !test_http_proxy_sha256_hex(input, expected_response))
        return 0;
    return strcasecmp(response, expected_response) == 0;
}

static int test_http_proxy_contains_forbidden(
    const test_http_proxy_config* config,
    const char* request)
{
    const char* values[3];
    size_t index = 0u;

    if (!config || !request)
        return 1;
    values[0] = config->forbidden_username;
    values[1] = config->forbidden_password;
    values[2] = config->forbidden_domain;
    for (index = 0u; index < 3u; index++)
    {
        if (values[index] && values[index][0] != '\0' &&
            strstr(request, values[index]) != NULL)
            return 1;
    }
    return 0;
}

static int test_http_proxy_connect_target(
    const test_http_proxy_config* config)
{
    struct sockaddr_in address;
    int fd = -1;

    if (!config || !config->target_host ||
        strcmp(config->target_host, "127.0.0.1") != 0 ||
        config->target_port == 0u)
        return -1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(config->target_port);
    if (connect(fd,
                (const struct sockaddr*)&address,
                (socklen_t)sizeof(address)) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

static int test_http_proxy_accept(int listener_fd)
{
    for (;;)
    {
        int fd = accept(listener_fd, NULL, NULL);

        if (fd < 0 && errno == EINTR)
            continue;
        return fd;
    }
}

static int test_http_proxy_challenge(int client_fd)
{
    static const char response[] =
        "HTTP/1.1 407 Proxy Authentication Required\r\n"
        "Proxy-Authenticate: Digest realm=\"" TEST_HTTP_PROXY_REALM
        "\", nonce=\"" TEST_HTTP_PROXY_NONCE
        "\", algorithm=SHA-256, qop=\"auth\"\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "Proxy-Connection: close\r\n\r\n";

    return test_http_proxy_send_all(
        client_fd,
        (const uint8_t*)response,
        sizeof(response) - 1u);
}

static int test_http_proxy_authorize(test_http_proxy* proxy,
                                     int client_fd)
{
    char request[TEST_HTTP_PROXY_HEADER_MAX];
    char expected_request[TEST_HTTP_PROXY_FIELD_MAX];
    char expected_uri[TEST_HTTP_PROXY_FIELD_MAX];
    const char* authorization = NULL;
    int written = 0;

    if (!proxy ||
        !test_http_proxy_read_headers(client_fd,
                                      request,
                                      sizeof(request)))
        return 0;
    written = snprintf(expected_uri,
                       sizeof(expected_uri),
                       "%s:%u",
                       proxy->config.target_host,
                       (unsigned int)proxy->config.target_port);
    if (written <= 0 || (size_t)written >= sizeof(expected_uri))
        return 0;
    written = snprintf(expected_request,
                       sizeof(expected_request),
                       "CONNECT %s HTTP/",
                       expected_uri);
    if (written <= 0 || (size_t)written >= sizeof(expected_request) ||
        strstr(request, expected_request) == NULL)
        return 0;
    if (test_http_proxy_contains_forbidden(&proxy->config, request))
    {
        atomic_store_explicit(&proxy->credential_leak,
                              1u,
                              memory_order_release);
        return 0;
    }
    authorization = test_http_proxy_header(
        request,
        "Proxy-Authorization");
    if (!authorization)
        return test_http_proxy_challenge(client_fd) ? 2 : 0;
    if (!test_http_proxy_verify_digest(&proxy->config,
                                       authorization,
                                       expected_uri))
        return 0;
    atomic_store_explicit(&proxy->authenticated,
                          1u,
                          memory_order_release);
    return 1;
}

static void test_http_proxy_set_active_fd(test_http_proxy* proxy,
                                          int* slot,
                                          int fd)
{
    if (pthread_mutex_lock(&proxy->lock) != 0)
        return;
    *slot = fd;
    (void)pthread_mutex_unlock(&proxy->lock);
}

/*
 * Relay both half-streams until the RDP session closes. Polling the stop flag
 * bounds teardown even if one endpoint remains silent.
 */
static int test_http_proxy_relay(test_http_proxy* proxy,
                                 int client_fd,
                                 int target_fd)
{
    int client_open = 1;
    int target_open = 1;

    while ((client_open || target_open) &&
           atomic_load_explicit(&proxy->stop,
                                memory_order_acquire) == 0u)
    {
        struct pollfd fds[2];
        int ready = 0;
        size_t index = 0u;

        memset(fds, 0, sizeof(fds));
        fds[0].fd = client_fd;
        fds[0].events = client_open ? POLLIN : 0;
        fds[1].fd = target_fd;
        fds[1].events = target_open ? POLLIN : 0;
        do
        {
            ready = poll(fds, 2u, 50);
        } while (ready < 0 && errno == EINTR);
        if (ready < 0)
            return 0;
        if (ready == 0)
            continue;
        for (index = 0u; index < 2u; index++)
        {
            uint8_t buffer[16384];
            int source_fd = index == 0u ? client_fd : target_fd;
            int destination_fd = index == 0u ? target_fd : client_fd;
            ssize_t received = 0;

            if ((fds[index].revents &
                 (POLLIN | POLLHUP | POLLERR | POLLNVAL)) == 0)
                continue;
            received = recv(source_fd,
                            buffer,
                            sizeof(buffer),
                            0);
            if (received > 0)
            {
                if (!test_http_proxy_send_all(
                        destination_fd,
                        buffer,
                        (size_t)received))
                    return 0;
                continue;
            }
            if (received < 0 &&
                (errno == EINTR ||
                 errno == EAGAIN ||
                 errno == EWOULDBLOCK))
                continue;
            if (index == 0u && client_open)
            {
                client_open = 0;
                (void)shutdown(target_fd, SHUT_WR);
            }
            else if (index == 1u && target_open)
            {
                target_open = 0;
                (void)shutdown(client_fd, SHUT_WR);
            }
        }
    }
    return 1;
}

static void* test_http_proxy_main(void* user_data)
{
    test_http_proxy* proxy = (test_http_proxy*)user_data;
    sigset_t blocked_signals;
    int client_fd = -1;
    int target_fd = -1;
    int authorized = 0;

    if (!proxy)
        return NULL;
    proxy->status = LIBRDP_STATUS_IO_ERROR;
    if (sigemptyset(&blocked_signals) != 0 ||
        sigaddset(&blocked_signals, SIGPIPE) != 0 ||
        pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL) != 0)
        return NULL;
    while (atomic_load_explicit(&proxy->stop,
                                memory_order_acquire) == 0u &&
           !authorized)
    {
        int result = 0;

        client_fd = test_http_proxy_accept(proxy->listener_fd);
        if (client_fd < 0)
            return NULL;
        test_http_proxy_set_active_fd(proxy,
                                      &proxy->client_fd,
                                      client_fd);
        result = test_http_proxy_authorize(proxy,
                                           client_fd);
        if (result == 2)
        {
            close(client_fd);
            client_fd = -1;
            test_http_proxy_set_active_fd(proxy,
                                          &proxy->client_fd,
                                          -1);
            continue;
        }
        if (result != 1)
            goto cleanup;
        authorized = 1;
    }
    if (!authorized)
        goto cleanup;
    target_fd = test_http_proxy_connect_target(&proxy->config);
    if (target_fd < 0)
        goto cleanup;
    test_http_proxy_set_active_fd(proxy,
                                  &proxy->target_fd,
                                  target_fd);
    {
        static const char response[] =
            "HTTP/1.1 200 Connection Established\r\n"
            "Proxy-Agent: librdp-test\r\n\r\n";

        if (!test_http_proxy_send_all(
                client_fd,
                (const uint8_t*)response,
                sizeof(response) - 1u))
            goto cleanup;
    }
    atomic_store_explicit(&proxy->forwarded,
                          1u,
                          memory_order_release);
    if (!test_http_proxy_relay(proxy,
                               client_fd,
                               target_fd) &&
        atomic_load_explicit(&proxy->stop,
                             memory_order_acquire) == 0u)
        goto cleanup;
    proxy->status = LIBRDP_STATUS_OK;

cleanup:
    if (target_fd >= 0)
    {
        close(target_fd);
        target_fd = -1;
        test_http_proxy_set_active_fd(proxy,
                                      &proxy->target_fd,
                                      -1);
    }
    if (client_fd >= 0)
    {
        close(client_fd);
        client_fd = -1;
        test_http_proxy_set_active_fd(proxy,
                                      &proxy->client_fd,
                                      -1);
    }
    return NULL;
}

int test_http_proxy_start(test_http_proxy* proxy,
                          const test_http_proxy_config* config)
{
    struct sockaddr_in address;
    socklen_t address_len = (socklen_t)sizeof(address);
    int one = 1;

    if (!proxy || !config || !config->target_host ||
        !config->gateway_username || !config->gateway_password)
        return 0;
    memset(proxy, 0, sizeof(*proxy));
    proxy->config = *config;
    proxy->listener_fd = -1;
    proxy->client_fd = -1;
    proxy->target_fd = -1;
    proxy->status = LIBRDP_STATUS_AGAIN;
    atomic_init(&proxy->authenticated, 0u);
    atomic_init(&proxy->forwarded, 0u);
    atomic_init(&proxy->credential_leak, 0u);
    atomic_init(&proxy->stop, 0u);
    if (pthread_mutex_init(&proxy->lock, NULL) != 0)
        return 0;
    proxy->listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy->listener_fd < 0)
        goto fail;
    (void)setsockopt(proxy->listener_fd,
                     SOL_SOCKET,
                     SO_REUSEADDR,
                     &one,
                     (socklen_t)sizeof(one));
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(proxy->listener_fd,
             (const struct sockaddr*)&address,
             (socklen_t)sizeof(address)) != 0 ||
        getsockname(proxy->listener_fd,
                    (struct sockaddr*)&address,
                    &address_len) != 0 ||
        listen(proxy->listener_fd, 2) != 0)
        goto fail;
    proxy->port = ntohs(address.sin_port);
    if (pthread_create(&proxy->thread,
                       NULL,
                       test_http_proxy_main,
                       proxy) != 0)
        goto fail;
    proxy->thread_started = 1;
    return 1;

fail:
    test_http_proxy_clear(proxy);
    return 0;
}

void test_http_proxy_cancel(test_http_proxy* proxy)
{
    if (!proxy)
        return;
    atomic_store_explicit(&proxy->stop, 1u, memory_order_release);
    if (pthread_mutex_lock(&proxy->lock) != 0)
        return;
    if (proxy->listener_fd >= 0)
        (void)shutdown(proxy->listener_fd, SHUT_RDWR);
    if (proxy->client_fd >= 0)
        (void)shutdown(proxy->client_fd, SHUT_RDWR);
    if (proxy->target_fd >= 0)
        (void)shutdown(proxy->target_fd, SHUT_RDWR);
    (void)pthread_mutex_unlock(&proxy->lock);
}

int test_http_proxy_join(test_http_proxy* proxy)
{
    return test_http_proxy_join_status(proxy,
                                       LIBRDP_STATUS_OK);
}

int test_http_proxy_join_status(test_http_proxy* proxy,
                                librdp_status expected_status)
{
    if (!proxy || !proxy->thread_started)
        return 0;
    if (pthread_join(proxy->thread, NULL) != 0)
        return 0;
    proxy->thread_started = 0;
    return proxy->status == expected_status;
}

void test_http_proxy_clear(test_http_proxy* proxy)
{
    if (!proxy)
        return;
    test_http_proxy_cancel(proxy);
    if (proxy->thread_started)
        (void)pthread_join(proxy->thread, NULL);
    proxy->thread_started = 0;
    if (proxy->listener_fd >= 0)
        close(proxy->listener_fd);
    proxy->listener_fd = -1;
    proxy->client_fd = -1;
    proxy->target_fd = -1;
    (void)pthread_mutex_destroy(&proxy->lock);
}
