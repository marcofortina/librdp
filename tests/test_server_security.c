/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: server TLS, NLA, and Standard Security tests.
 * Coverage: downgrade, certificate, authentication, MAC, and ciphertext failures.
 * Bug classes: malformed input, invalid state, bounds, and ownership regressions.
 * Determinism: fixtures use synthetic data and loopback transports only.
 */

#include "test_server_support.h"
#include "test_server_suites.h"

int test_server_loopback_negotiation_failure(void)
{
    static const uint8_t request[] = {
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
    };
    uint8_t response[64];
    int client_fd = -1;
    int response_len = 0;
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0;

    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.bind_address = "127.0.0.1";
    config.port = 0;
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    SCHECK(librdp_server_accept(server, 0, &peer) == LIBRDP_STATUS_STATE);
    SCHECK(peer == NULL);
    SCHECK(librdp_server_listen(server) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_listen(server) == LIBRDP_STATUS_STATE);
    port = librdp_server_local_port(server);
    SCHECK(port != 0);
    SCHECK(librdp_server_accept(server, 1, &peer) == LIBRDP_STATUS_TIMEOUT);
    SCHECK(peer == NULL);
    client_fd = test_server_connect_loopback(port);
    SCHECK(client_fd >= 0);
    status = librdp_server_accept(server, 1000, &peer);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(peer != NULL);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_NEW);
    SCHECK(send(client_fd, request, sizeof(request), 0) == (ssize_t)sizeof(request));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_UNSUPPORTED);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CLOSED);
    response_len = test_server_read_response(client_fd, response, sizeof(response));
    SCHECK(response_len == 19);
    SCHECK(response[0] == 0x03 && response[1] == 0x00 && response[2] == 0x00 && response[3] == 0x13);
    SCHECK(response[4] == 0x0e && response[5] == 0xd0);
    SCHECK(response[11] == 0x03 && response[13] == 0x08 && response[15] == 0x02);
    librdp_server_peer_free(peer);
    librdp_server_close(server);
    SCHECK(librdp_server_local_port(server) == 0);
    librdp_server_free(server);
    close(client_fd);
    return 0;
}

/*
 * Fixture: drives X.224 TLS negotiation and a local OpenSSL client/server
 * handshake before sending MCS over the encrypted stream. It catches security
 * downgrade regressions, missing certificate/key setup, TLS state lifetime
 * errors, and accidental raw-socket reads after the transport switches to TLS.
 */
int test_server_loopback_tls_handshake(void)
{
    uint8_t response[65536];
    rdp_buffer request;
    rdp_buffer x224_request;
    rdp_buffer mcs_initial;
    rdp_tpkt tpkt;
    rdp_x224_connection_confirm confirm;
    SSL_CTX* client_context = NULL;
    SSL* client_tls = NULL;
    char cert_path[128];
    char key_path[128];
    int client_fd = -1;
    int response_len = 0;
    int tls_ready = 0;
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0;

    rdp_buffer_init(&request);
    rdp_buffer_init(&x224_request);
    rdp_buffer_init(&mcs_initial);
    memset(cert_path, 0, sizeof(cert_path));
    memset(key_path, 0, sizeof(key_path));
    SCHECK(test_server_make_tls_files(cert_path, sizeof(cert_path), key_path, sizeof(key_path)));
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.bind_address = "127.0.0.1";
    config.security_mode = LIBRDP_SECURITY_TLS;
    config.tls_certificate_path = cert_path;
    config.tls_private_key_path = key_path;
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    SCHECK(librdp_server_listen(server) == LIBRDP_STATUS_OK);
    port = librdp_server_local_port(server);
    SCHECK(port != 0);
    client_fd = test_server_connect_loopback(port);
    SCHECK(client_fd >= 0);
    SCHECK(test_server_set_nonblocking(client_fd));
    SCHECK(librdp_server_accept(server, 1000, &peer) == LIBRDP_STATUS_OK);
    SCHECK(peer != NULL);
    SCHECK(rdp_x224_build_connection_request(&x224_request, NULL, RDP_X224_PROTOCOL_TLS) == LIBRDP_STATUS_OK);
    SCHECK(rdp_tpkt_write(&request, x224_request.data, x224_request.length) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_all(client_fd, request.data, request.length));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_TLS_HANDSHAKING);
    response_len = test_server_read_response(client_fd, response, sizeof(response));
    SCHECK(response_len > 0);
    SCHECK(rdp_tpkt_parse(response, (size_t)response_len, &tpkt) == LIBRDP_STATUS_OK);
    SCHECK(rdp_x224_parse_connection_confirm(tpkt.payload, tpkt.payload_len, &confirm) == LIBRDP_STATUS_OK);
    SCHECK(confirm.negotiation.present);
    SCHECK(confirm.negotiation.selected_protocol == RDP_X224_PROTOCOL_TLS);
    client_context = SSL_CTX_new(TLS_client_method());
    SCHECK(client_context != NULL);
    SSL_CTX_set_verify(client_context, SSL_VERIFY_NONE, NULL);
    client_tls = SSL_new(client_context);
    SCHECK(client_tls != NULL);
    SCHECK(SSL_set_fd(client_tls, client_fd) == 1);
    for (int attempt = 0; attempt < 100 && !tls_ready; attempt++)
    {
        int rc = SSL_connect(client_tls);

        if (rc == 1)
            tls_ready = 1;
        else
        {
            int error = SSL_get_error(client_tls, rc);

            SCHECK(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
        }
        status = librdp_server_peer_run_once(peer, 10);
        SCHECK(status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_TIMEOUT);
        if (librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_X224_CONFIRMED && tls_ready)
            break;
    }
    SCHECK(tls_ready);
    SCHECK(test_server_wait_peer_state(peer, LIBRDP_SERVER_PEER_X224_CONFIRMED));
    SCHECK(test_server_build_client_mcs_connect_initial(&mcs_initial));
    SCHECK(test_server_tls_write_all(client_tls, mcs_initial.data, mcs_initial.length));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    response_len = test_server_tls_read_tpkt(client_tls, response, sizeof(response));
    SCHECK(response_len > 0);
    SCHECK(rdp_tpkt_parse(response, (size_t)response_len, &tpkt) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_MCS_CONNECTED);
    SSL_free(client_tls);
    SSL_CTX_free(client_context);
    rdp_buffer_free(&mcs_initial);
    rdp_buffer_free(&x224_request);
    rdp_buffer_free(&request);
    librdp_server_peer_free(peer);
    librdp_server_close(server);
    librdp_server_free(server);
    close(client_fd);
    unlink(cert_path);
    unlink(key_path);
    return 0;
}

/*
 * Fixture: negotiates X.224 TLS, then verifies that server-side TLS material
 * validation rejects a certificate/private-key mismatch before handshake bytes
 * are accepted. This catches collapsed TLS setup errors that would make
 * diagnostics unusable for embedders.
 */
int test_server_loopback_tls_mismatched_key(void)
{
    uint8_t response[65536];
    rdp_buffer request;
    rdp_buffer x224_request;
    rdp_tpkt tpkt;
    rdp_x224_connection_confirm confirm;
    librdp_server_status server_status;
    char cert_path_a[128];
    char key_path_a[128];
    char cert_path_b[128];
    char key_path_b[128];
    int client_fd = -1;
    int response_len = 0;
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0;

    rdp_buffer_init(&request);
    rdp_buffer_init(&x224_request);
    memset(cert_path_a, 0, sizeof(cert_path_a));
    memset(key_path_a, 0, sizeof(key_path_a));
    memset(cert_path_b, 0, sizeof(cert_path_b));
    memset(key_path_b, 0, sizeof(key_path_b));
    SCHECK(test_server_make_tls_files(cert_path_a, sizeof(cert_path_a), key_path_a, sizeof(key_path_a)));
    SCHECK(test_server_make_tls_files(cert_path_b, sizeof(cert_path_b), key_path_b, sizeof(key_path_b)));
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.bind_address = "127.0.0.1";
    config.security_mode = LIBRDP_SECURITY_TLS;
    config.tls_certificate_path = cert_path_a;
    config.tls_private_key_path = key_path_a;
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    SCHECK(test_server_copy_file(key_path_b, key_path_a));
    SCHECK(librdp_server_listen(server) == LIBRDP_STATUS_OK);
    port = librdp_server_local_port(server);
    SCHECK(port != 0);
    client_fd = test_server_connect_loopback(port);
    SCHECK(client_fd >= 0);
    SCHECK(test_server_set_nonblocking(client_fd));
    SCHECK(librdp_server_accept(server, 1000, &peer) == LIBRDP_STATUS_OK);
    SCHECK(peer != NULL);
    SCHECK(rdp_x224_build_connection_request(&x224_request, NULL, RDP_X224_PROTOCOL_TLS) == LIBRDP_STATUS_OK);
    SCHECK(rdp_tpkt_write(&request, x224_request.data, x224_request.length) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_all(client_fd, request.data, request.length));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    response_len = test_server_read_response(client_fd, response, sizeof(response));
    SCHECK(response_len > 0);
    SCHECK(rdp_tpkt_parse(response, (size_t)response_len, &tpkt) == LIBRDP_STATUS_OK);
    SCHECK(rdp_x224_parse_connection_confirm(tpkt.payload, tpkt.payload_len, &confirm) == LIBRDP_STATUS_OK);
    SCHECK(confirm.negotiation.present && confirm.negotiation.selected_protocol == RDP_X224_PROTOCOL_TLS);
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED);
    SCHECK(librdp_server_status_init(&server_status) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_last_status(peer, &server_status) == LIBRDP_STATUS_OK);
    SCHECK(server_status.status == LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED);
    SCHECK(strcmp(server_status.phase, "server.transport.tls.accept") == 0);
    SCHECK(strstr(server_status.message, "do not match") != NULL);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_FAILED);
    rdp_buffer_free(&x224_request);
    rdp_buffer_free(&request);
    librdp_server_peer_free(peer);
    librdp_server_close(server);
    librdp_server_free(server);
    close(client_fd);
    unlink(cert_path_a);
    unlink(key_path_a);
    unlink(cert_path_b);
    unlink(key_path_b);
    return 0;
}

/*
 * Fixture: performs the complete server-side NLA exchange over a loopback TLS
 * transport, then sends one MCS Connect-Initial. It catches NLA negotiation
 * downgrades, NTLMv2 verification failures, public-key binding sequence bugs,
 * and accidental attempts to parse CredSSP as TPKT.
 */
static int test_server_loopback_nla_handshake_variant(uint32_t flags)
{
    uint8_t response[65536];
    uint8_t client_nonce[32];
    uint8_t ntlm_client_challenge[8];
    uint8_t ntlm_exported_key[16];
    rdp_buffer request;
    rdp_buffer reply;
    rdp_buffer x224_request;
    rdp_buffer mcs_initial;
    rdp_buffer ntlm_negotiate;
    rdp_buffer spnego_negotiate;
    rdp_buffer ntlm_authenticate;
    rdp_buffer spnego_authenticate;
    rdp_buffer tls_public_key;
    rdp_buffer pub_key_auth;
    rdp_buffer auth_info;
    rdp_tpkt tpkt;
    rdp_x224_connection_confirm confirm;
    rdp_credssp_ts_request ts_response;
    rdp_credssp_ts_request pub_key_response;
    rdp_ntlm_challenge ntlm_challenge;
    rdp_ntlm_authenticate_result auth_result;
    rdp_ntlm_security_context ntlm_security;
    SSL_CTX* client_context = NULL;
    SSL* client_tls = NULL;
    const uint8_t* ntlm_token = NULL;
    size_t ntlm_token_len = 0;
    char cert_path[128];
    char key_path[128];
    int client_fd = -1;
    int response_len = 0;
    int tls_ready = 0;
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    test_server_nla_provider_context provider_context;
    char domain[32];
    char username[32];
    char password[32];
    char wrong_password[32];
    const char* workstation = "unit-rdp";
    const char* authenticate_password = NULL;
    uint32_t ts_request_version = 6;
    size_t final_auth_info_len = 0;
    uint16_t port = 0;

    rdp_buffer_init(&request);
    rdp_buffer_init(&reply);
    rdp_buffer_init(&x224_request);
    rdp_buffer_init(&mcs_initial);
    rdp_buffer_init(&ntlm_negotiate);
    rdp_buffer_init(&spnego_negotiate);
    rdp_buffer_init(&ntlm_authenticate);
    rdp_buffer_init(&spnego_authenticate);
    rdp_buffer_init(&tls_public_key);
    rdp_buffer_init(&pub_key_auth);
    rdp_buffer_init(&auth_info);
    memset(&auth_result, 0, sizeof(auth_result));
    memset(&ntlm_security, 0, sizeof(ntlm_security));
    test_server_fill_secret(domain, sizeof(domain), 317u);
    test_server_fill_secret(username, sizeof(username), 331u);
    test_server_fill_secret(password, sizeof(password), 337u);
    test_server_fill_secret(wrong_password, sizeof(wrong_password), 341u);
    authenticate_password = (flags & TEST_SERVER_NLA_WRONG_PASSWORD) ? wrong_password : password;
    ts_request_version = (flags & TEST_SERVER_NLA_BAD_TS_VERSION) ? 5u : 6u;
    memset(&provider_context, 0, sizeof(provider_context));
    provider_context.domain = domain;
    provider_context.username = username;
    provider_context.password = password;
    provider_context.workstation = workstation;
    provider_context.reject = (flags & TEST_SERVER_NLA_PROVIDER_REJECT) != 0;
    for (size_t i = 0; i < sizeof(client_nonce); i++)
        client_nonce[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(ntlm_client_challenge); i++)
        ntlm_client_challenge[i] = (uint8_t)(0x80u + i);
    for (size_t i = 0; i < sizeof(ntlm_exported_key); i++)
        ntlm_exported_key[i] = (uint8_t)(0x40u + i);
    memset(cert_path, 0, sizeof(cert_path));
    memset(key_path, 0, sizeof(key_path));

    SCHECK(test_server_make_tls_files(cert_path, sizeof(cert_path), key_path, sizeof(key_path)));
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.bind_address = "127.0.0.1";
    config.security_mode = LIBRDP_SECURITY_NLA;
    config.tls_certificate_path = cert_path;
    config.tls_private_key_path = key_path;
    config.server_name = "unit-server";
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    SCHECK(librdp_server_set_credentials_provider(server,
                                                  test_server_nla_provider,
                                                  &provider_context) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_listen(server) == LIBRDP_STATUS_OK);
    port = librdp_server_local_port(server);
    SCHECK(port != 0);
    client_fd = test_server_connect_loopback(port);
    SCHECK(client_fd >= 0);
    SCHECK(test_server_set_nonblocking(client_fd));
    SCHECK(librdp_server_accept(server, 1000, &peer) == LIBRDP_STATUS_OK);
    SCHECK(peer != NULL);

    SCHECK(rdp_x224_build_connection_request(&x224_request, NULL, RDP_X224_PROTOCOL_NLA) == LIBRDP_STATUS_OK);
    SCHECK(rdp_tpkt_write(&request, x224_request.data, x224_request.length) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_all(client_fd, request.data, request.length));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_TLS_HANDSHAKING);
    response_len = test_server_read_response(client_fd, response, sizeof(response));
    SCHECK(response_len > 0);
    SCHECK(rdp_tpkt_parse(response, (size_t)response_len, &tpkt) == LIBRDP_STATUS_OK);
    SCHECK(rdp_x224_parse_connection_confirm(tpkt.payload, tpkt.payload_len, &confirm) == LIBRDP_STATUS_OK);
    SCHECK(confirm.negotiation.present);
    SCHECK(confirm.negotiation.selected_protocol == RDP_X224_PROTOCOL_NLA);

    client_context = SSL_CTX_new(TLS_client_method());
    SCHECK(client_context != NULL);
    SSL_CTX_set_verify(client_context, SSL_VERIFY_NONE, NULL);
    client_tls = SSL_new(client_context);
    SCHECK(client_tls != NULL);
    SCHECK(SSL_set_fd(client_tls, client_fd) == 1);
    for (int attempt = 0; attempt < 100 && !tls_ready; attempt++)
    {
        int rc = SSL_connect(client_tls);

        if (rc == 1)
            tls_ready = 1;
        else
        {
            int error = SSL_get_error(client_tls, rc);

            SCHECK(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
        }
        status = librdp_server_peer_run_once(peer, 10);
        SCHECK(status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_TIMEOUT);
        if (librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_NLA_AUTHENTICATING && tls_ready)
            break;
    }
    SCHECK(tls_ready);
    SCHECK(test_server_wait_peer_state(peer, LIBRDP_SERVER_PEER_NLA_AUTHENTICATING));
    SCHECK(test_server_tls_public_key(client_tls, &tls_public_key));

    request.length = 0;
    SCHECK(rdp_credssp_write_ntlm_negotiate(&ntlm_negotiate, workstation, domain) ==
           LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_write_spnego_ntlm_negotiate(&spnego_negotiate,
                                                   ntlm_negotiate.data,
                                                   ntlm_negotiate.length) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_write_ts_request(&request,
                                        ts_request_version,
                                        spnego_negotiate.data,
                                        spnego_negotiate.length,
                                        NULL,
                                        0,
                                        NULL,
                                        0,
                                        client_nonce,
                                        sizeof(client_nonce)) == LIBRDP_STATUS_OK);
    SCHECK(test_server_tls_write_all(client_tls, request.data, request.length));
    status = librdp_server_peer_run_once(peer, 1000);
    if (flags & TEST_SERVER_NLA_BAD_TS_VERSION)
    {
        SCHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
        SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_FAILED);
        goto cleanup;
    }
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_tls_read_credssp(client_tls, &reply));
    SCHECK(rdp_credssp_parse_ts_request(reply.data, reply.length, &ts_response) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_extract_ntlm_challenge(ts_response.nego_token,
                                              ts_response.nego_token_len,
                                              &ntlm_token,
                                              &ntlm_token_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_parse_ntlm_challenge(ntlm_token, ntlm_token_len, &ntlm_challenge) ==
           LIBRDP_STATUS_OK);

    SCHECK(rdp_credssp_write_ntlm_authenticate(&ntlm_authenticate,
                                               &ntlm_challenge,
                                               username,
                                               authenticate_password,
                                               domain,
                                               workstation,
                                               132223104000000000ULL,
                                               ntlm_client_challenge,
                                               ntlm_exported_key,
                                               &auth_result) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_write_spnego_ntlm_authenticate(&spnego_authenticate,
                                                      ntlm_authenticate.data,
                                                      ntlm_authenticate.length) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_ntlm_security_init(&ntlm_security, &auth_result) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_encrypt_public_key_hash(&ntlm_security,
                                               client_nonce,
                                               sizeof(client_nonce),
                                               tls_public_key.data,
                                               tls_public_key.length,
                                               &pub_key_auth) == LIBRDP_STATUS_OK);
    if ((flags & TEST_SERVER_NLA_TAMPER_PUBLIC_KEY) && pub_key_auth.length > 0)
        pub_key_auth.data[pub_key_auth.length - 1u] ^= 0x40u;
    request.length = 0;
    SCHECK(rdp_credssp_write_ts_request(&request,
                                        ts_response.version,
                                        spnego_authenticate.data,
                                        spnego_authenticate.length,
                                        NULL,
                                        0,
                                        (flags & TEST_SERVER_NLA_COMBINED_PUBLIC_KEY) ? pub_key_auth.data : NULL,
                                        (flags & TEST_SERVER_NLA_COMBINED_PUBLIC_KEY) ? pub_key_auth.length : 0,
                                        client_nonce,
                                        sizeof(client_nonce)) == LIBRDP_STATUS_OK);
    SCHECK(test_server_tls_write_all(client_tls, request.data, request.length));
    reply.length = 0;
    status = librdp_server_peer_run_once(peer, 1000);
    if (flags & (TEST_SERVER_NLA_PROVIDER_REJECT | TEST_SERVER_NLA_WRONG_PASSWORD))
    {
        SCHECK(status == LIBRDP_STATUS_AUTHENTICATION_FAILED);
        SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_FAILED);
        goto cleanup;
    }
    SCHECK(status == LIBRDP_STATUS_OK);
    if ((flags & TEST_SERVER_NLA_COMBINED_PUBLIC_KEY) == 0)
    {
        request.length = 0;
        SCHECK(rdp_credssp_write_ts_request(&request,
                                            ts_response.version,
                                            NULL,
                                            0,
                                            NULL,
                                            0,
                                            pub_key_auth.data,
                                            pub_key_auth.length,
                                            client_nonce,
                                            sizeof(client_nonce)) == LIBRDP_STATUS_OK);
        SCHECK(test_server_tls_write_all(client_tls, request.data, request.length));
        reply.length = 0;
        status = librdp_server_peer_run_once(peer, 1000);
    }
    if (flags & TEST_SERVER_NLA_TAMPER_PUBLIC_KEY)
    {
        SCHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
        SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_FAILED);
        goto cleanup;
    }
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_tls_read_credssp(client_tls, &reply));
    SCHECK(rdp_credssp_parse_ts_request(reply.data, reply.length, &pub_key_response) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_verify_public_key_hash(&ntlm_security,
                                              client_nonce,
                                              sizeof(client_nonce),
                                              tls_public_key.data,
                                              tls_public_key.length,
                                              pub_key_response.pub_key_auth,
                                              pub_key_response.pub_key_auth_len) == LIBRDP_STATUS_OK);
    status = librdp_server_peer_run_once(peer, 0);
    SCHECK(status == LIBRDP_STATUS_TIMEOUT || status == LIBRDP_STATUS_AGAIN);
    SCHECK(librdp_server_peer_get_state(peer) ==
           LIBRDP_SERVER_PEER_NLA_AUTHENTICATING);

    SCHECK(rdp_credssp_encrypt_password_credentials(&ntlm_security,
                                                    domain,
                                                    username,
                                                      password,
                                                      &auth_info) == LIBRDP_STATUS_OK);
    final_auth_info_len = auth_info.length;
    if (flags & TEST_SERVER_NLA_TRUNCATED_CREDENTIALS)
    {
        SCHECK(final_auth_info_len > 0);
        final_auth_info_len--;
    }
    request.length = 0;
    SCHECK(rdp_credssp_write_ts_request(&request,
                                        pub_key_response.version,
                                        NULL,
                                        0,
                                        auth_info.data,
                                        final_auth_info_len,
                                        NULL,
                                        0,
                                        client_nonce,
                                        sizeof(client_nonce)) == LIBRDP_STATUS_OK);
    SCHECK(test_server_tls_write_all(client_tls, request.data, request.length));
    status = librdp_server_peer_run_once(peer, 1000);
    if (flags & TEST_SERVER_NLA_TRUNCATED_CREDENTIALS)
    {
        SCHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
        SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_FAILED);
        goto cleanup;
    }
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_X224_CONFIRMED);
    SCHECK(provider_context.calls == 1);
    SCHECK(provider_context.last_version == 6);
    SCHECK(provider_context.last_failed_attempts == 0);
    SCHECK(provider_context.last_public_key_bound == 0);

    SCHECK(test_server_build_client_mcs_connect_initial(&mcs_initial));
    SCHECK(test_server_tls_write_all(client_tls, mcs_initial.data, mcs_initial.length));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    response_len = test_server_tls_read_tpkt(client_tls, response, sizeof(response));
    SCHECK(response_len > 0);
    SCHECK(rdp_tpkt_parse(response, (size_t)response_len, &tpkt) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_MCS_CONNECTED);

cleanup:
    if (client_tls)
        SSL_free(client_tls);
    if (client_context)
        SSL_CTX_free(client_context);
    OPENSSL_cleanse(&ntlm_security, sizeof(ntlm_security));
    OPENSSL_cleanse(&auth_result, sizeof(auth_result));
    rdp_buffer_free(&auth_info);
    rdp_buffer_free(&pub_key_auth);
    rdp_buffer_free(&tls_public_key);
    rdp_buffer_free(&spnego_authenticate);
    rdp_buffer_free(&ntlm_authenticate);
    rdp_buffer_free(&spnego_negotiate);
    rdp_buffer_free(&ntlm_negotiate);
    rdp_buffer_free(&mcs_initial);
    rdp_buffer_free(&x224_request);
    rdp_buffer_free(&reply);
    rdp_buffer_free(&request);
    librdp_server_peer_free(peer);
    if (server)
        librdp_server_close(server);
    librdp_server_free(server);
    if (client_fd >= 0)
        close(client_fd);
    unlink(cert_path);
    unlink(key_path);
    return 0;
}

int test_server_loopback_nla_handshake(void)
{
    return test_server_loopback_nla_handshake_variant(0);
}

int test_server_loopback_nla_combined_public_key(void)
{
    return test_server_loopback_nla_handshake_variant(TEST_SERVER_NLA_COMBINED_PUBLIC_KEY);
}

int test_server_loopback_nla_reject_vectors(void)
{
    const uint32_t vectors[] = {
        TEST_SERVER_NLA_BAD_TS_VERSION,
        TEST_SERVER_NLA_PROVIDER_REJECT,
        TEST_SERVER_NLA_WRONG_PASSWORD,
        TEST_SERVER_NLA_TAMPER_PUBLIC_KEY,
        TEST_SERVER_NLA_TRUNCATED_CREDENTIALS,
    };

    for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++)
    {
        if (test_server_loopback_nla_handshake_variant(vectors[i]) != 0)
            return 1;
    }
    return 0;
}

/*
 * Fixture: validates Standard Security signing and encryption with paired
 * client/server contexts without opening a socket.
 * Bug class: detects accepted signature tampering, ciphertext tampering,
 * secure-checksum sequence drift, and missing encrypt/decrypt counter updates.
 */
int test_server_standard_security_tamper_vectors(void)
{
    uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    uint8_t server_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    static const uint8_t payload[] = {0x11, 0x22, 0x33, 0x44, 0x55};
    rdp_standard_security_context sender;
    rdp_standard_security_context receiver;
    rdp_buffer wire;
    rdp_buffer plaintext;
    uint16_t flags = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    for (size_t i = 0; i < sizeof(client_random); i++)
    {
        client_random[i] = (uint8_t)(0x10u + i);
        server_random[i] = (uint8_t)(0x80u + i);
    }

    memset(&sender, 0, sizeof(sender));
    memset(&receiver, 0, sizeof(receiver));
    rdp_buffer_init(&wire);
    rdp_buffer_init(&plaintext);
    SCHECK(rdp_security_standard_client_init(&sender,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_standard_server_init(&receiver,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_write_encrypted_pdu(&wire, &sender, 0, payload, sizeof(payload)) ==
           LIBRDP_STATUS_OK);
    status = rdp_security_unwrap_pdu(&receiver, wire.data, wire.length, &plaintext, &flags);
    SCHECK(status == LIBRDP_STATUS_OK &&
           (flags & RDP_SEC_ENCRYPT) != 0 &&
           sender.encrypt_count == 1 &&
           receiver.decrypt_count == 1 &&
           plaintext.length == sizeof(payload) &&
           memcmp(plaintext.data, payload, sizeof(payload)) == 0);
    rdp_buffer_free(&plaintext);
    rdp_buffer_free(&wire);
    rdp_security_standard_clear(&sender);
    rdp_security_standard_clear(&receiver);

    memset(&sender, 0, sizeof(sender));
    memset(&receiver, 0, sizeof(receiver));
    rdp_buffer_init(&wire);
    rdp_buffer_init(&plaintext);
    SCHECK(rdp_security_standard_client_init(&sender,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_standard_server_init(&receiver,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_write_encrypted_pdu(&wire, &sender, 0, payload, sizeof(payload)) ==
           LIBRDP_STATUS_OK);
    wire.data[4] ^= 0x40u;
    status = rdp_security_unwrap_pdu(&receiver, wire.data, wire.length, &plaintext, &flags);
    SCHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR && plaintext.length == 0);
    rdp_buffer_free(&plaintext);
    rdp_buffer_free(&wire);
    rdp_security_standard_clear(&sender);
    rdp_security_standard_clear(&receiver);

    memset(&sender, 0, sizeof(sender));
    memset(&receiver, 0, sizeof(receiver));
    rdp_buffer_init(&wire);
    rdp_buffer_init(&plaintext);
    SCHECK(rdp_security_standard_client_init(&sender,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_standard_server_init(&receiver,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_write_encrypted_pdu(&wire, &sender, 0, payload, sizeof(payload)) ==
           LIBRDP_STATUS_OK);
    wire.data[wire.length - 1u] ^= 0x01u;
    status = rdp_security_unwrap_pdu(&receiver, wire.data, wire.length, &plaintext, &flags);
    SCHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR && plaintext.length == 0);
    rdp_buffer_free(&plaintext);
    rdp_buffer_free(&wire);
    rdp_security_standard_clear(&sender);
    rdp_security_standard_clear(&receiver);

    memset(&sender, 0, sizeof(sender));
    memset(&receiver, 0, sizeof(receiver));
    rdp_buffer_init(&wire);
    rdp_buffer_init(&plaintext);
    SCHECK(rdp_security_standard_client_init(&sender,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_standard_server_init(&receiver,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    sender.encrypt_count = 1;
    SCHECK(rdp_security_write_encrypted_pdu(&wire,
                                            &sender,
                                            (uint16_t)RDP_SEC_SECURE_CHECKSUM,
                                            payload,
                                            sizeof(payload)) == LIBRDP_STATUS_OK);
    status = rdp_security_unwrap_pdu(&receiver, wire.data, wire.length, &plaintext, &flags);
    SCHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR && plaintext.length == 0);
    rdp_buffer_free(&plaintext);
    rdp_buffer_free(&wire);
    rdp_security_standard_clear(&sender);
    rdp_security_standard_clear(&receiver);
    OPENSSL_cleanse(client_random, sizeof(client_random));
    OPENSSL_cleanse(server_random, sizeof(server_random));
    return 0;
}
