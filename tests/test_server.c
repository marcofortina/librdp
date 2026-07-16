/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: public server API tests.
 * Coverage: versioned server config defaults, invalid metadata rejection, and
 * ownership of copied listener configuration.
 * Bug classes: ABI metadata drift, invalid size/version acceptance, bounds
 * mistakes, and cleanup of partially copied strings.
 * Determinism: runtime coverage binds only to loopback on an ephemeral port
 * and exchanges one synthetic connection request.
 */

#include <librdp/librdp.h>

#include "common/buffer.h"
#include "channels/dynamic_channel.h"
#include "graphics/bitmap.h"
#include "licensing/licensing.h"
#include "nla/credssp.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SCHECK(condition)                                                                                             \
    do                                                                                                                \
    {                                                                                                                 \
        if (!(condition))                                                                                             \
        {                                                                                                             \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #condition);                              \
            return 1;                                                                                                 \
        }                                                                                                             \
    } while (0)

static int test_server_config_defaults(void)
{
    librdp_server_config config;
    librdp_server_input_event input_event;
    librdp_server_static_channel_info channel_info;
    librdp_server_event server_event;
    librdp_server_status server_status;
    librdp_server_metrics metrics;

    SCHECK(librdp_server_config_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    SCHECK(config.version == LIBRDP_SERVER_CONFIG_VERSION);
    SCHECK(config.size == sizeof(config));
    SCHECK(config.bind_address == NULL);
    SCHECK(config.port == 0);
    SCHECK(config.backlog == 4);
    SCHECK(config.max_peers == 16);
    SCHECK(config.width == 1024);
    SCHECK(config.height == 768);
    SCHECK(config.server_name == NULL);
    SCHECK(config.security_mode == LIBRDP_SECURITY_STANDARD);
    SCHECK(config.tls_certificate_path == NULL);
    SCHECK(config.tls_private_key_path == NULL);
    SCHECK(config.nla_domain == NULL);
    SCHECK(config.nla_username == NULL);
    SCHECK(config.nla_password == NULL);
    SCHECK(librdp_server_input_event_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_input_event_init(&input_event) == LIBRDP_STATUS_OK);
    SCHECK(input_event.version == LIBRDP_SERVER_INPUT_EVENT_VERSION);
    SCHECK(input_event.size == sizeof(input_event));
    SCHECK(librdp_server_static_channel_info_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_static_channel_info_init(&channel_info) == LIBRDP_STATUS_OK);
    SCHECK(channel_info.version == LIBRDP_SERVER_STATIC_CHANNEL_INFO_VERSION);
    SCHECK(channel_info.size == sizeof(channel_info));
    SCHECK(librdp_server_event_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_event_init(&server_event) == LIBRDP_STATUS_OK);
    SCHECK(server_event.version == LIBRDP_SERVER_EVENT_VERSION);
    SCHECK(server_event.size == sizeof(server_event));
    SCHECK(server_event.status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_status_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_status_init(&server_status) == LIBRDP_STATUS_OK);
    SCHECK(server_status.version == LIBRDP_SERVER_STATUS_VERSION);
    SCHECK(server_status.size == sizeof(server_status));
    SCHECK(server_status.status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_metrics_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    SCHECK(metrics.version == LIBRDP_SERVER_METRICS_VERSION);
    SCHECK(metrics.size == sizeof(metrics));
    return 0;
}

static int test_server_new_validates_metadata(void)
{
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_feature_status feature_status;

    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.version = 0;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.size = 1;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.width = 1024;
    config.height = 0;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.width = 9000;
    config.height = 9000;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.backlog = 129;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.security_mode = (librdp_security_mode)99;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.security_mode = LIBRDP_SECURITY_TLS;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.security_mode = LIBRDP_SECURITY_TLS;
    config.tls_certificate_path = "server.pem";
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.security_mode = LIBRDP_SECURITY_NLA;
    config.tls_certificate_path = "server.pem";
    config.tls_private_key_path = "server.key";
    SCHECK(librdp_server_new(&config) == NULL);
    config.nla_username = "user";
    SCHECK(librdp_server_new(&config) == NULL);
    config.nla_password = "pass";
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    librdp_server_free(server);
    server = NULL;
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    SCHECK(librdp_server_get_feature_status(NULL,
                                            LIBRDP_FEATURE_ECHO,
                                            &feature_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_get_feature_status(server,
                                            (librdp_feature)(LIBRDP_FEATURE_ECHO | LIBRDP_FEATURE_VIDEO),
                                            &feature_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_ECHO,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(!feature_status.requested && !feature_status.built && !feature_status.active);
    SCHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_REQUESTED);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_ECHO, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_ECHO,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && !feature_status.built && !feature_status.negotiated &&
           !feature_status.active);
    SCHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_BUILT);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_ECHO, 0) == LIBRDP_STATUS_OK);
    librdp_server_free(server);
    librdp_server_free(NULL);
    return 0;
}

static int test_server_new_copies_strings(void)
{
    librdp_server_config config;
    char bind_address[16] = "127.0.0.1";
    char server_name[16] = "test";
    librdp_server* server = NULL;

    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.bind_address = bind_address;
    config.server_name = server_name;
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    memset(bind_address, 'x', sizeof(bind_address) - 1u);
    bind_address[sizeof(bind_address) - 1u] = '\0';
    memset(server_name, 'y', sizeof(server_name) - 1u);
    server_name[sizeof(server_name) - 1u] = '\0';
    librdp_server_free(server);
    return 0;
}

static int test_server_connect_loopback(uint16_t port)
{
    struct sockaddr_in address;
    int fd = -1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (const struct sockaddr*)&address, (socklen_t)sizeof(address)) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

static int test_server_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0)
        return 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static int test_server_write_temp_path(char* output, size_t output_len, const char* suffix)
{
    int fd = -1;

    if (!output || output_len < 32 || !suffix)
        return -1;
    if (snprintf(output, output_len, "/tmp/librdp-server-test-%ld-%s-XXXXXX", (long)getpid(), suffix) >=
        (int)output_len)
        return -1;
    fd = mkstemp(output);
    return fd;
}

static int test_server_make_tls_files(char* cert_path,
                                      size_t cert_path_len,
                                      char* key_path,
                                      size_t key_path_len)
{
    EVP_PKEY* key = NULL;
    X509* cert = NULL;
    X509_NAME* name = NULL;
    FILE* file = NULL;
    int cert_fd = -1;
    int key_fd = -1;
    int ok = 0;

    do
    {
        cert_fd = test_server_write_temp_path(cert_path, cert_path_len, "cert");
        key_fd = test_server_write_temp_path(key_path, key_path_len, "key");
        if (cert_fd < 0 || key_fd < 0)
            break;
        key = EVP_RSA_gen(2048);
        cert = X509_new();
        if (!key || !cert)
            break;
        if (ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1 ||
            X509_set_version(cert, 2) != 1 ||
            X509_set_pubkey(cert, key) != 1 ||
            !X509_gmtime_adj(X509_get_notBefore(cert), 0) ||
            !X509_gmtime_adj(X509_get_notAfter(cert), 3600))
            break;
        name = X509_get_subject_name(cert);
        if (!name ||
            X509_NAME_add_entry_by_txt(name,
                                       "CN",
                                       MBSTRING_ASC,
                                       (const unsigned char*)"librdp-server-test",
                                       -1,
                                       -1,
                                       0) != 1 ||
            X509_set_issuer_name(cert, name) != 1 ||
            X509_sign(cert, key, EVP_sha256()) <= 0)
            break;
        file = fdopen(cert_fd, "w");
        if (!file)
            break;
        cert_fd = -1;
        if (PEM_write_X509(file, cert) != 1 || fclose(file) != 0)
        {
            file = NULL;
            break;
        }
        file = NULL;
        file = fdopen(key_fd, "w");
        if (!file)
            break;
        key_fd = -1;
        if (PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) != 1 || fclose(file) != 0)
        {
            file = NULL;
            break;
        }
        file = NULL;
        ok = 1;
    } while (0);
    if (file)
        fclose(file);
    if (cert_fd >= 0)
        close(cert_fd);
    if (key_fd >= 0)
        close(key_fd);
    X509_free(cert);
    EVP_PKEY_free(key);
    if (!ok)
    {
        if (cert_path)
            unlink(cert_path);
        if (key_path)
            unlink(key_path);
        ERR_clear_error();
    }
    return ok;
}

static int test_server_read_response(int fd, uint8_t* response, size_t response_len)
{
    struct pollfd pfd;
    ssize_t count = 0;

    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1, 1000) <= 0)
        return 0;
    count = recv(fd, response, response_len, 0);
    return count > 0 ? (int)count : 0;
}

static int test_server_send_all(int fd, const uint8_t* data, size_t length)
{
    size_t offset = 0;

    while (offset < length)
    {
        ssize_t written = send(fd, data + offset, length - offset, 0);

        if (written <= 0)
            return 0;
        offset += (size_t)written;
    }
    return 1;
}

static int test_server_tls_write_all(SSL* tls, const uint8_t* data, size_t length)
{
    size_t offset = 0;

    if (!tls || (!data && length > 0))
        return 0;
    while (offset < length)
    {
        int chunk = (length - offset) > (size_t)INT32_MAX ? INT32_MAX : (int)(length - offset);
        int written = SSL_write(tls, data + offset, chunk);

        if (written <= 0)
            return 0;
        offset += (size_t)written;
    }
    return 1;
}

static int test_server_tls_read_credssp(SSL* tls, rdp_buffer* packet)
{
    uint8_t header[6];
    size_t header_len = 2u;
    size_t payload_len = 0;
    size_t total = 0;
    int read_len = 0;

    if (!tls || !packet)
        return 0;
    read_len = SSL_read(tls, header, 2);
    if (read_len != 2 || header[0] != 0x30u)
        return 0;
    if ((header[1] & 0x80u) == 0)
        payload_len = header[1];
    else
    {
        size_t length_len = header[1] & 0x7fu;

        if (length_len == 0 || length_len > 4u)
            return 0;
        read_len = SSL_read(tls, header + 2u, (int)length_len);
        if (read_len != (int)length_len)
            return 0;
        header_len += length_len;
        for (size_t i = 0; i < length_len; i++)
            payload_len = (payload_len << 8) | header[2u + i];
    }
    total = header_len + payload_len;
    if (total > 1048576u || rdp_buffer_append(packet, header, header_len) != LIBRDP_STATUS_OK)
        return 0;
    if (rdp_buffer_reserve(packet, total) != LIBRDP_STATUS_OK)
        return 0;
    while (packet->length < total)
    {
        size_t remaining = total - packet->length;
        int chunk = remaining > (size_t)INT32_MAX ? INT32_MAX : (int)remaining;

        read_len = SSL_read(tls, packet->data + packet->length, chunk);
        if (read_len <= 0)
            return 0;
        packet->length += (size_t)read_len;
    }
    return 1;
}

static int test_server_tls_public_key(SSL* tls, rdp_buffer* public_key)
{
    X509* certificate = NULL;
    EVP_PKEY* key = NULL;
    unsigned char* cursor = NULL;
    int encoded_len = 0;
    int written = 0;

    if (!tls || !public_key)
        return 0;
    certificate = SSL_get1_peer_certificate(tls);
    if (!certificate)
        return 0;
    key = X509_get_pubkey(certificate);
    X509_free(certificate);
    if (!key)
        return 0;
    encoded_len = i2d_PublicKey(key, NULL);
    if (encoded_len > 0 && rdp_buffer_reserve(public_key, (size_t)encoded_len) == LIBRDP_STATUS_OK)
    {
        cursor = public_key->data;
        written = i2d_PublicKey(key, &cursor);
        if (written == encoded_len)
            public_key->length = (size_t)written;
    }
    EVP_PKEY_free(key);
    return public_key->length > 0;
}

typedef struct test_server_runtime_context
{
    uint32_t input_count;
    uint32_t control_count;
    uint32_t font_list_count;
    uint32_t key_count;
    uint32_t channel_count;
    uint32_t dynamic_open_count;
    uint32_t dynamic_data_count;
    uint32_t dynamic_close_count;
    uint32_t state_event_count;
    uint32_t error_event_count;
    uint32_t surface_event_count;
    uint32_t channel_joined_event_count;
    librdp_server_peer_state last_old_state;
    librdp_server_peer_state last_new_state;
    librdp_status last_error_status;
    uint16_t last_channel_id;
    uint32_t last_dynamic_channel_id;
    uint8_t channel_payload[16];
    size_t channel_payload_len;
} test_server_runtime_context;

static void test_server_input_callback(librdp_server_peer* peer,
                                       const librdp_server_input_event* event,
                                       void* user_data)
{
    test_server_runtime_context* context = (test_server_runtime_context*)user_data;

    (void)peer;
    if (!context || !event)
        return;
    context->input_count++;
    if (event->type == LIBRDP_SERVER_INPUT_CONTROL)
        context->control_count++;
    else if (event->type == LIBRDP_SERVER_INPUT_FONT_LIST)
        context->font_list_count++;
    else if (event->type == LIBRDP_SERVER_INPUT_SCANCODE_KEY)
        context->key_count++;
}

static void test_server_channel_callback(librdp_server_peer* peer,
                                         const librdp_server_channel_event* event,
                                         void* user_data)
{
    test_server_runtime_context* context = (test_server_runtime_context*)user_data;
    size_t copy_len = 0;

    (void)peer;
    if (!context || !event)
        return;
    context->channel_count++;
    context->last_channel_id = event->channel_id;
    context->last_dynamic_channel_id = event->dynamic_channel_id;
    if (event->type == LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_OPEN)
        context->dynamic_open_count++;
    else if (event->type == LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_DATA)
        context->dynamic_data_count++;
    else if (event->type == LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_CLOSE)
        context->dynamic_close_count++;
    copy_len = event->data_len > sizeof(context->channel_payload) ? sizeof(context->channel_payload) : event->data_len;
    if (copy_len > 0)
        memcpy(context->channel_payload, event->data, copy_len);
    context->channel_payload_len = copy_len;
}

static void test_server_event_callback(librdp_server_peer* peer,
                                       const librdp_server_event* event,
                                       void* user_data)
{
    test_server_runtime_context* context = (test_server_runtime_context*)user_data;

    (void)peer;
    if (!context || !event)
        return;
    if (event->type == LIBRDP_SERVER_EVENT_STATE_CHANGED)
    {
        context->state_event_count++;
        context->last_old_state = event->old_state;
        context->last_new_state = event->new_state;
    }
    else if (event->type == LIBRDP_SERVER_EVENT_ERROR)
    {
        context->error_event_count++;
        context->last_error_status = event->status;
    }
    else if (event->type == LIBRDP_SERVER_EVENT_SURFACE)
    {
        context->surface_event_count++;
    }
    else if (event->type == LIBRDP_SERVER_EVENT_CHANNEL_JOINED)
    {
        context->channel_joined_event_count++;
        context->last_channel_id = event->channel_id;
    }
}

static int test_server_build_client_mcs_connect_initial(rdp_buffer* tpkt)
{
    static const rdp_gcc_channel_definition extra_channels[1] = {
        {{'t', 'e', 's', 't', 'v', 'c', 0, 0}, 0xc0800000u}
    };
    rdp_buffer gcc_blocks;
    rdp_buffer gcc_request;
    rdp_buffer mcs_initial;
    rdp_buffer x224_data;
    rdp_gcc_client_config config;
    int ok = 0;

    if (!tpkt)
        return 0;
    rdp_buffer_init(&gcc_blocks);
    rdp_buffer_init(&gcc_request);
    rdp_buffer_init(&mcs_initial);
    rdp_buffer_init(&x224_data);
    memset(&config, 0, sizeof(config));
    config.desktop_width = 800;
    config.desktop_height = 600;
    config.requested_protocols = RDP_X224_PROTOCOL_STANDARD;
    config.client_name = "server-test";
    config.enable_dynamic_channels = 1;
    config.extra_channels = extra_channels;
    config.extra_channel_count = 1;
    if (rdp_gcc_write_client_data_blocks(&gcc_blocks, &config) == LIBRDP_STATUS_OK &&
        rdp_gcc_write_conference_create_request(&gcc_request, gcc_blocks.data, gcc_blocks.length) ==
            LIBRDP_STATUS_OK &&
        rdp_mcs_write_connect_initial(&mcs_initial, gcc_request.data, gcc_request.length) ==
            LIBRDP_STATUS_OK &&
        rdp_x224_wrap_data(&x224_data, mcs_initial.data, mcs_initial.length) == LIBRDP_STATUS_OK &&
        rdp_tpkt_write(tpkt, x224_data.data, x224_data.length) == LIBRDP_STATUS_OK)
        ok = 1;
    rdp_buffer_free(&x224_data);
    rdp_buffer_free(&mcs_initial);
    rdp_buffer_free(&gcc_request);
    rdp_buffer_free(&gcc_blocks);
    return ok;
}

static int test_server_send_client_mcs_connect_initial(int fd)
{
    rdp_buffer tpkt;
    int ok = 0;

    rdp_buffer_init(&tpkt);
    if (test_server_build_client_mcs_connect_initial(&tpkt))
        ok = test_server_send_all(fd, tpkt.data, tpkt.length);
    rdp_buffer_free(&tpkt);
    return ok;
}

static int test_server_send_mcs_pdu(int fd, const rdp_buffer* mcs_pdu)
{
    rdp_buffer x224_data;
    rdp_buffer tpkt;
    int ok = 0;

    if (!mcs_pdu)
        return 0;
    rdp_buffer_init(&x224_data);
    rdp_buffer_init(&tpkt);
    if (rdp_x224_wrap_data(&x224_data, mcs_pdu->data, mcs_pdu->length) == LIBRDP_STATUS_OK &&
        rdp_tpkt_write(&tpkt, x224_data.data, x224_data.length) == LIBRDP_STATUS_OK)
        ok = test_server_send_all(fd, tpkt.data, tpkt.length);
    rdp_buffer_free(&tpkt);
    rdp_buffer_free(&x224_data);
    return ok;
}

static int test_server_send_simple_mcs(int fd, librdp_status (*writer)(rdp_buffer*))
{
    rdp_buffer pdu;
    int ok = 0;

    if (!writer)
        return 0;
    rdp_buffer_init(&pdu);
    if (writer(&pdu) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &pdu);
    rdp_buffer_free(&pdu);
    return ok;
}

static int test_server_send_channel_join(int fd, uint16_t user_id, uint16_t channel_id)
{
    rdp_buffer pdu;
    int ok = 0;

    rdp_buffer_init(&pdu);
    if (rdp_mcs_write_channel_join_request(&pdu, user_id, channel_id) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &pdu);
    rdp_buffer_free(&pdu);
    return ok;
}

static int test_server_send_confirm_active(int fd, uint32_t share_id, uint16_t user_id)
{
    rdp_buffer confirm;
    rdp_buffer security_payload;
    rdp_buffer send_data;
    int ok = 0;

    rdp_buffer_init(&confirm);
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&send_data);
    if (rdp_slowpath_write_confirm_active(&confirm, share_id, (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID, 800, 600, "test") ==
            LIBRDP_STATUS_OK &&
        rdp_security_write_header(&security_payload, 0) == LIBRDP_STATUS_OK &&
        rdp_buffer_append(&security_payload, confirm.data, confirm.length) == LIBRDP_STATUS_OK &&
        rdp_security_write_send_data_request(&send_data,
                                             user_id,
                                             (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                             security_payload.data,
                                             security_payload.length) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &send_data);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security_payload);
    rdp_buffer_free(&confirm);
    return ok;
}

static int test_server_send_slowpath(int fd, uint16_t user_id, const rdp_buffer* slowpath)
{
    rdp_buffer security_payload;
    rdp_buffer send_data;
    int ok = 0;

    if (!slowpath)
        return 0;
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&send_data);
    if (rdp_security_write_header(&security_payload, 0) == LIBRDP_STATUS_OK &&
        rdp_buffer_append(&security_payload, slowpath->data, slowpath->length) == LIBRDP_STATUS_OK &&
        rdp_security_write_send_data_request(&send_data,
                                             user_id,
                                             (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                             security_payload.data,
                                             security_payload.length) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &send_data);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security_payload);
    return ok;
}

static int test_server_send_client_synchronize(int fd, uint32_t share_id, uint16_t user_id)
{
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_client_synchronize(&slowpath,
                                              share_id,
                                              (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK)
        ok = test_server_send_slowpath(fd, user_id, &slowpath);
    rdp_buffer_free(&slowpath);
    return ok;
}

static int test_server_send_client_control(int fd, uint32_t share_id, uint16_t user_id, uint16_t action)
{
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_client_control(&slowpath,
                                          share_id,
                                          (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                          action) == LIBRDP_STATUS_OK)
        ok = test_server_send_slowpath(fd, user_id, &slowpath);
    rdp_buffer_free(&slowpath);
    return ok;
}

static int test_server_send_client_font_list(int fd, uint32_t share_id, uint16_t user_id)
{
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_client_font_list(&slowpath,
                                            share_id,
                                            (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK)
        ok = test_server_send_slowpath(fd, user_id, &slowpath);
    rdp_buffer_free(&slowpath);
    return ok;
}

static int test_server_send_keyboard_input(int fd, uint32_t share_id, uint16_t user_id)
{
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_client_keyboard_input(&slowpath,
                                                 share_id,
                                                 (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                 0,
                                                 30) == LIBRDP_STATUS_OK)
        ok = test_server_send_slowpath(fd, user_id, &slowpath);
    rdp_buffer_free(&slowpath);
    return ok;
}

static int test_server_send_static_channel_data(int fd, uint16_t user_id, uint16_t channel_id)
{
    static const uint8_t payload[] = {1, 2, 3, 4};
    rdp_buffer send_data;
    int ok = 0;

    rdp_buffer_init(&send_data);
    if (rdp_security_write_send_data_request(&send_data, user_id, channel_id, payload, sizeof(payload)) ==
        LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &send_data);
    rdp_buffer_free(&send_data);
    return ok;
}

static int test_server_send_channel_payload(int fd, uint16_t user_id, uint16_t channel_id, const rdp_buffer* payload)
{
    rdp_buffer send_data;
    int ok = 0;

    if (!payload)
        return 0;
    rdp_buffer_init(&send_data);
    if (rdp_security_write_send_data_request(&send_data,
                                             user_id,
                                             channel_id,
                                             payload->data,
                                             payload->length) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &send_data);
    rdp_buffer_free(&send_data);
    return ok;
}

static int test_server_read_tpkt_x224_data(int fd, uint8_t* buffer, size_t buffer_len, rdp_tpkt* tpkt)
{
    struct pollfd pfd;
    size_t total = 0;
    size_t offset = 0;

    if (!buffer || buffer_len < 4 || !tpkt)
        return 0;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1, 1000) <= 0)
        return 0;
    while (offset < 4u)
    {
        ssize_t count = recv(fd, buffer + offset, 4u - offset, 0);

        if (count <= 0)
            return 0;
        offset += (size_t)count;
    }
    total = ((size_t)buffer[2] << 8) | buffer[3];
    if (total < 4u || total > buffer_len)
        return 0;
    while (offset < total)
    {
        ssize_t count = recv(fd, buffer + offset, total - offset, 0);

        if (count <= 0)
            return 0;
        offset += (size_t)count;
    }
    return rdp_tpkt_parse(buffer, total, tpkt) == LIBRDP_STATUS_OK;
}

static int test_server_read_slowpath_data_pdu(int fd,
                                              uint8_t* response,
                                              size_t response_len,
                                              rdp_slowpath_data_pdu* data_pdu)
{
    rdp_tpkt tpkt;
    rdp_mcs_send_data_indication indication;
    const uint8_t* x224_data = NULL;
    size_t x224_data_len = 0;

    if (!test_server_read_tpkt_x224_data(fd, response, response_len, &tpkt))
        return 0;
    if (rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) != LIBRDP_STATUS_OK)
        return 0;
    if (rdp_mcs_parse_send_data_indication(x224_data, x224_data_len, &indication) != LIBRDP_STATUS_OK)
        return 0;
    return rdp_slowpath_parse_data_pdu(indication.payload, indication.payload_len, data_pdu) == LIBRDP_STATUS_OK;
}

static int test_server_read_static_channel_data(int fd,
                                                uint8_t* response,
                                                size_t response_len,
                                                uint16_t* channel_id,
                                                const uint8_t** data,
                                                size_t* data_len)
{
    rdp_tpkt tpkt;
    rdp_mcs_send_data_indication indication;
    const uint8_t* x224_data = NULL;
    size_t x224_data_len = 0;

    if (!channel_id || !data || !data_len)
        return 0;
    if (!test_server_read_tpkt_x224_data(fd, response, response_len, &tpkt))
        return 0;
    if (rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) != LIBRDP_STATUS_OK)
        return 0;
    if (rdp_mcs_parse_send_data_indication(x224_data, x224_data_len, &indication) != LIBRDP_STATUS_OK)
        return 0;
    *channel_id = indication.channel_id;
    *data = indication.payload;
    *data_len = indication.payload_len;
    return 1;
}

static int test_server_loopback_negotiation_failure(void)
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
static int test_server_loopback_tls_handshake(void)
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
        status = librdp_server_peer_run_once(peer, 0);
        SCHECK(status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_TIMEOUT);
        if (librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_X224_CONFIRMED && tls_ready)
            break;
    }
    SCHECK(tls_ready);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_X224_CONFIRMED);
    SCHECK(test_server_build_client_mcs_connect_initial(&mcs_initial));
    SCHECK(test_server_tls_write_all(client_tls, mcs_initial.data, mcs_initial.length));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    response_len = SSL_read(client_tls, response, sizeof(response));
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
 * Fixture: performs the complete server-side NLA exchange over a loopback TLS
 * transport, then sends one MCS Connect-Initial. It catches NLA negotiation
 * downgrades, NTLMv2 verification failures, public-key binding sequence bugs,
 * and accidental attempts to parse CredSSP as TPKT.
 */
static int test_server_loopback_nla_handshake(void)
{
    uint8_t response[65536];
    uint8_t client_nonce[32];
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
    rdp_credssp_ts_request auth_response;
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
    for (size_t i = 0; i < sizeof(client_nonce); i++)
        client_nonce[i] = (uint8_t)i;
    memset(cert_path, 0, sizeof(cert_path));
    memset(key_path, 0, sizeof(key_path));

    SCHECK(test_server_make_tls_files(cert_path, sizeof(cert_path), key_path, sizeof(key_path)));
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.bind_address = "127.0.0.1";
    config.security_mode = LIBRDP_SECURITY_NLA;
    config.tls_certificate_path = cert_path;
    config.tls_private_key_path = key_path;
    config.server_name = "unit-server";
    config.nla_domain = "DOMAIN";
    config.nla_username = "Marco";
    config.nla_password = "Welcome1";
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
        status = librdp_server_peer_run_once(peer, 0);
        SCHECK(status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_TIMEOUT);
        if (librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_NLA_AUTHENTICATING && tls_ready)
            break;
    }
    SCHECK(tls_ready);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_NLA_AUTHENTICATING);
    SCHECK(test_server_tls_public_key(client_tls, &tls_public_key));

    request.length = 0;
    SCHECK(rdp_credssp_write_ntlm_negotiate(&ntlm_negotiate, "librdp", "DOMAIN") ==
           LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_write_spnego_ntlm_negotiate(&spnego_negotiate,
                                                   ntlm_negotiate.data,
                                                   ntlm_negotiate.length) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_write_ts_request(&request,
                                        6,
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
                                               "Marco",
                                               "Welcome1",
                                               "DOMAIN",
                                               "librdp",
                                               0,
                                               NULL,
                                               NULL,
                                               &auth_result) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_write_spnego_ntlm_authenticate(&spnego_authenticate,
                                                      ntlm_authenticate.data,
                                                      ntlm_authenticate.length) == LIBRDP_STATUS_OK);
    request.length = 0;
    SCHECK(rdp_credssp_write_ts_request(&request,
                                        ts_response.version,
                                        spnego_authenticate.data,
                                        spnego_authenticate.length,
                                        NULL,
                                        0,
                                        NULL,
                                        0,
                                        client_nonce,
                                        sizeof(client_nonce)) == LIBRDP_STATUS_OK);
    SCHECK(test_server_tls_write_all(client_tls, request.data, request.length));
    reply.length = 0;
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_tls_read_credssp(client_tls, &reply));
    SCHECK(rdp_credssp_parse_ts_request(reply.data, reply.length, &auth_response) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_ntlm_security_init(&ntlm_security, &auth_result) == LIBRDP_STATUS_OK);

    SCHECK(rdp_credssp_encrypt_public_key_hash(&ntlm_security,
                                               client_nonce,
                                               sizeof(client_nonce),
                                               tls_public_key.data,
                                               tls_public_key.length,
                                               &pub_key_auth) == LIBRDP_STATUS_OK);
    request.length = 0;
    SCHECK(rdp_credssp_write_ts_request(&request,
                                        auth_response.version,
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

    SCHECK(rdp_credssp_encrypt_password_credentials(&ntlm_security,
                                                    "DOMAIN",
                                                    "Marco",
                                                    "Welcome1",
                                                    &auth_info) == LIBRDP_STATUS_OK);
    request.length = 0;
    SCHECK(rdp_credssp_write_ts_request(&request,
                                        pub_key_response.version,
                                        NULL,
                                        0,
                                        auth_info.data,
                                        auth_info.length,
                                        NULL,
                                        0,
                                        client_nonce,
                                        sizeof(client_nonce)) == LIBRDP_STATUS_OK);
    SCHECK(test_server_tls_write_all(client_tls, request.data, request.length));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_X224_CONFIRMED);

    SCHECK(test_server_build_client_mcs_connect_initial(&mcs_initial));
    SCHECK(test_server_tls_write_all(client_tls, mcs_initial.data, mcs_initial.length));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    response_len = SSL_read(client_tls, response, sizeof(response));
    SCHECK(response_len > 0);
    SCHECK(rdp_tpkt_parse(response, (size_t)response_len, &tpkt) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_MCS_CONNECTED);

    SSL_free(client_tls);
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
    librdp_server_close(server);
    librdp_server_free(server);
    close(client_fd);
    unlink(cert_path);
    unlink(key_path);
    return 0;
}

/*
 * Drives one in-process client/server pair through the server activation path.
 * The sequence catches truncated or misordered X.224/MCS/GCC wrapping,
 * channel-join accounting, Demand Active framing, and Confirm Active state
 * transition regressions without requiring a real desktop server.
 */
static int test_server_loopback_standard_activation_sequence(void)
{
    static const uint8_t request[] = {
        0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    uint8_t response[65536];
    rdp_tpkt tpkt;
    rdp_mcs_connect_response mcs_response;
    rdp_gcc_conference_response gcc_response;
    rdp_gcc_server_data server_data;
    rdp_mcs_attach_user_confirm attach_confirm;
    rdp_mcs_channel_join_confirm join_confirm;
    rdp_mcs_send_data_indication demand_indication;
    rdp_mcs_send_data_indication license_indication;
    rdp_license_error_alert license_alert;
    rdp_security_public_key server_public_key;
    rdp_standard_security_context client_security;
    rdp_dynamic_channel_capabilities dvc_caps;
    rdp_dynamic_channel_create_response dvc_create_response;
    rdp_dynamic_channel_data_pdu dvc_data_response;
    librdp_server_dynamic_channel_info dynamic_info;
    rdp_buffer license_payload;
    rdp_buffer security_payload;
    rdp_buffer security_data;
    rdp_buffer encrypted_client_random;
    rdp_buffer dvc_packet;
    rdp_slowpath_demand_active demand;
    rdp_slowpath_data_pdu data_pdu;
    rdp_bitmap_update bitmap_update;
    librdp_server_static_channel_info static_info;
    librdp_server_metrics server_metrics;
    librdp_server_status server_status;
    librdp_feature_status feature_status;
    test_server_runtime_context runtime_context;
    const uint8_t* x224_data = NULL;
    size_t x224_data_len = 0;
    const uint8_t* static_payload = NULL;
    size_t static_payload_len = 0;
    const uint8_t* dvc_payload = NULL;
    size_t dvc_payload_len = 0;
    int client_fd = -1;
    int response_len = 0;
    size_t poll_count = 0;
    struct pollfd pollfds[2];
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0;
    uint16_t dynamic_static_channel_id = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 1u);
    uint16_t static_channel_id = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 2u);
    uint16_t response_channel_id = 0;
    uint16_t security_flags = 0;
    uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    uint8_t pixels[4u * 4u * 4u];
    uint8_t large_pixels[800u * 11u * 4u];

    memset(&server_public_key, 0, sizeof(server_public_key));
    memset(&client_security, 0, sizeof(client_security));
    rdp_buffer_init(&license_payload);
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&security_data);
    rdp_buffer_init(&encrypted_client_random);
    rdp_buffer_init(&dvc_packet);
    memset(&runtime_context, 0, sizeof(runtime_context));
    memset(pixels, 0, sizeof(pixels));
    for (size_t pixel_index = 0; pixel_index < sizeof(pixels); pixel_index++)
        pixels[pixel_index] = (uint8_t)pixel_index;
    memset(large_pixels, 0x5a, sizeof(large_pixels));
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.bind_address = "127.0.0.1";
    config.server_name = "unit-server";
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_ECHO, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_ECHO,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.reason == LIBRDP_FEATURE_REASON_NOT_BUILT);
    SCHECK(librdp_server_listen(server) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_VIDEO, 1) == LIBRDP_STATUS_STATE);
    SCHECK(librdp_server_get_pollfds(server, NULL, 0, &poll_count) == LIBRDP_STATUS_OK);
    SCHECK(poll_count == 1);
    SCHECK(librdp_server_get_pollfds(server, pollfds, 1, &poll_count) == LIBRDP_STATUS_OK);
    SCHECK(poll_count == 1 && pollfds[0].fd >= 0 && (pollfds[0].events & POLLIN));
    port = librdp_server_local_port(server);
    SCHECK(port != 0);
    client_fd = test_server_connect_loopback(port);
    SCHECK(client_fd >= 0);
    SCHECK(librdp_server_accept(server, 1000, &peer) == LIBRDP_STATUS_OK);
    SCHECK(peer != NULL);
    SCHECK(librdp_server_peer_set_input_callback(peer, test_server_input_callback, &runtime_context) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_set_channel_callback(peer, test_server_channel_callback, &runtime_context) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_set_event_callback(NULL,
                                                 test_server_event_callback,
                                                 &runtime_context) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_set_event_callback(peer, test_server_event_callback, &runtime_context) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_status_init(&server_status) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_last_status(NULL, &server_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_get_last_status(peer, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    server_status.version = 0;
    SCHECK(librdp_server_peer_get_last_status(peer, &server_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_status_init(&server_status) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_last_status(peer, &server_status) == LIBRDP_STATUS_OK);
    SCHECK(server_status.status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_ECHO,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.reason == LIBRDP_FEATURE_REASON_NOT_BUILT);
    SCHECK(librdp_server_peer_get_pollfds(peer, NULL, 0, &poll_count) == LIBRDP_STATUS_OK);
    SCHECK(poll_count == 1);
    SCHECK(librdp_server_peer_get_pollfds(peer, pollfds, 1, &poll_count) == LIBRDP_STATUS_OK);
    SCHECK(poll_count == 1 && pollfds[0].fd >= 0 && (pollfds[0].events & POLLIN));
    SCHECK(test_server_send_all(client_fd, request, sizeof(request)));
    SCHECK(poll(pollfds, 1, 1000) == 1);
    SCHECK(librdp_server_peer_notify_poll(peer, pollfds, 1) == LIBRDP_STATUS_OK);
    status = librdp_server_peer_dispatch_pending(peer);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_X224_CONFIRMED);
    SCHECK(runtime_context.state_event_count >= 2);
    SCHECK(runtime_context.last_new_state == LIBRDP_SERVER_PEER_X224_CONFIRMED);
    response_len = test_server_read_response(client_fd, response, sizeof(response));
    SCHECK(response_len == 11);
    SCHECK(response[0] == 0x03 && response[1] == 0x00 && response[2] == 0x00 && response[3] == 0x0b);
    SCHECK(response[4] == 0x06 && response[5] == 0xd0);
    SCHECK(test_server_send_client_mcs_connect_initial(client_fd));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_MCS_CONNECTED);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_connect_response(x224_data, x224_data_len, &mcs_response) == LIBRDP_STATUS_OK);
    SCHECK(mcs_response.result == 0);
    SCHECK(rdp_gcc_parse_conference_create_response(mcs_response.user_data,
                                                    mcs_response.user_data_len,
                                                    &gcc_response) == LIBRDP_STATUS_OK);
    SCHECK(gcc_response.result == 0);
    SCHECK(rdp_gcc_parse_server_data_blocks(gcc_response.user_data,
                                            gcc_response.user_data_len,
                                            &server_data) == LIBRDP_STATUS_OK);
    SCHECK(server_data.has_core && server_data.has_security && server_data.has_network);
    SCHECK(server_data.encryption_method == RDP_SECURITY_METHOD_128BIT);
    SCHECK(server_data.encryption_level == 3);
    SCHECK(server_data.server_random_len == RDP_SECURITY_CLIENT_RANDOM_LEN);
    SCHECK(server_data.server_certificate_len > 64u);
    SCHECK(server_data.mcs_channel_id == RDP_MCS_GLOBAL_CHANNEL_ID);
    SCHECK(librdp_server_peer_desktop_width(peer) == 800);
    SCHECK(librdp_server_peer_desktop_height(peer) == 600);
    SCHECK(librdp_server_peer_static_channel_count(peer) == 2);
    SCHECK(librdp_server_static_channel_info_init(&static_info) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_static_channel_at(peer, 0, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.channel_id == dynamic_static_channel_id);
    SCHECK(static_info.joined == 0);
    SCHECK(strcmp(static_info.name, "drdynvc") == 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 1, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.channel_id == static_channel_id);
    SCHECK(static_info.joined == 0);
    SCHECK(strcmp(static_info.name, "testvc") == 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 2, &static_info) == LIBRDP_STATUS_INVALID_ARGUMENT);

    SCHECK(test_server_send_simple_mcs(client_fd, rdp_mcs_write_erect_domain_request));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_DOMAIN_READY);

    SCHECK(test_server_send_simple_mcs(client_fd, rdp_mcs_write_attach_user_request));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_USER_ATTACHED);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_attach_user_confirm(x224_data, x224_data_len, &attach_confirm) == LIBRDP_STATUS_OK);
    SCHECK(attach_confirm.result == 0 && attach_confirm.user_id == RDP_MCS_BASE_CHANNEL_ID);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == attach_confirm.user_id);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, RDP_MCS_GLOBAL_CHANNEL_ID));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == RDP_MCS_GLOBAL_CHANNEL_ID);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, dynamic_static_channel_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == dynamic_static_channel_id);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, static_channel_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_LICENSING);
    SCHECK(runtime_context.channel_joined_event_count == 2);
    SCHECK(runtime_context.last_channel_id == static_channel_id);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == static_channel_id);
    SCHECK(librdp_server_peer_static_channel_at(peer, 0, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.joined != 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 1, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.joined != 0);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_send_data_indication(x224_data, x224_data_len, &license_indication) == LIBRDP_STATUS_OK);
    SCHECK(license_indication.channel_id == RDP_MCS_GLOBAL_CHANNEL_ID);
    SCHECK(rdp_security_unwrap_pdu(NULL,
                                   license_indication.payload,
                                   license_indication.payload_len,
                                   &license_payload,
                                   &security_flags) == LIBRDP_STATUS_OK);
    SCHECK(security_flags == (RDP_SEC_LICENSE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC));
    SCHECK(rdp_license_parse_error_alert(license_payload.data,
                                         license_payload.length,
                                         &license_alert) == LIBRDP_STATUS_OK);
    SCHECK(rdp_license_error_alert_is_terminal_success(&license_alert));
    SCHECK(rdp_security_parse_server_certificate(server_data.server_certificate,
                                                 server_data.server_certificate_len,
                                                 &server_public_key) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_generate_client_random(client_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_encrypt_client_random(&server_public_key, client_random, &encrypted_client_random) ==
           LIBRDP_STATUS_OK);
    SCHECK(rdp_security_standard_client_init(&client_security,
                                             server_data.encryption_method,
                                             client_random,
                                             server_data.server_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_write_exchange_pdu(&security_payload,
                                           encrypted_client_random.data,
                                           encrypted_client_random.length) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_write_send_data_request(&security_data,
                                                attach_confirm.user_id,
                                                (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                security_payload.data,
                                                security_payload.length) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_mcs_pdu(client_fd, &security_data));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_LICENSING);
    security_payload.length = 0;
    security_data.length = 0;
    {
        rdp_client_info info;

        memset(&info, 0, sizeof(info));
        info.username = "test";
        info.password = "secret";
        SCHECK(rdp_security_write_encrypted_client_info_pdu(&security_payload, &client_security, &info) ==
               LIBRDP_STATUS_OK);
    }
    SCHECK(rdp_security_write_send_data_request(&security_data,
                                                attach_confirm.user_id,
                                                (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                security_payload.data,
                                                security_payload.length) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_mcs_pdu(client_fd, &security_data));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_ACTIVATING);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_send_data_indication(x224_data, x224_data_len, &demand_indication) == LIBRDP_STATUS_OK);
    SCHECK(rdp_slowpath_parse_demand_active(demand_indication.payload,
                                            demand_indication.payload_len,
                                            &demand) == LIBRDP_STATUS_OK);
    SCHECK(demand.share_id == 0x00010001u);
    SCHECK(demand.capabilities.count == 11);
    SCHECK(rdp_capabilities_find(&demand.capabilities, RDP_CAPABILITY_TYPE_BITMAP_CACHE_V2) == NULL);
    SCHECK(rdp_capabilities_find(&demand.capabilities, RDP_CAPABILITY_TYPE_BRUSH) == NULL);
    SCHECK(rdp_capabilities_find(&demand.capabilities, RDP_CAPABILITY_TYPE_SOUND) == NULL);
    SCHECK(rdp_capabilities_find(&demand.capabilities, RDP_CAPABILITY_TYPE_CONTROL) == NULL);
    SCHECK(rdp_capabilities_find(&demand.capabilities, RDP_CAPABILITY_TYPE_ACTIVATION) == NULL);

    SCHECK(test_server_send_confirm_active(client_fd, demand.share_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_ACTIVATING);
    SCHECK(test_server_read_slowpath_data_pdu(client_fd, response, sizeof(response), &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SYNCHRONIZE);
    SCHECK(test_server_read_slowpath_data_pdu(client_fd, response, sizeof(response), &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL &&
           data_pdu.payload_len == 8 &&
           data_pdu.payload[0] == 4);
    SCHECK(test_server_read_slowpath_data_pdu(client_fd, response, sizeof(response), &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL &&
           data_pdu.payload_len == 8 &&
           data_pdu.payload[0] == 2);

    SCHECK(test_server_send_client_synchronize(client_fd, demand.share_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_client_control(client_fd, demand.share_id, attach_confirm.user_id, 4));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_client_control(client_fd, demand.share_id, attach_confirm.user_id, 1));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_client_font_list(client_fd, demand.share_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_ACTIVE);
    SCHECK(runtime_context.control_count == 2);
    SCHECK(runtime_context.font_list_count == 1);
    SCHECK(test_server_read_slowpath_data_pdu(client_fd, response, sizeof(response), &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_MAP &&
           data_pdu.payload_len == 8);

    dvc_packet.length = 0;
    SCHECK(rdp_dynamic_channel_write_capabilities_response(&dvc_packet, 3) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            dynamic_static_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_static_channel_data(client_fd,
                                                response,
                                                sizeof(response),
                                                &response_channel_id,
                                                &dvc_payload,
                                                &dvc_payload_len));
    SCHECK(response_channel_id == dynamic_static_channel_id);
    SCHECK(rdp_dynamic_channel_parse_capabilities(dvc_payload, dvc_payload_len, &dvc_caps) == LIBRDP_STATUS_OK);
    SCHECK(dvc_caps.version == 3);

    dvc_packet.length = 0;
    SCHECK(rdp_dynamic_channel_write_create_request(&dvc_packet, 7, 1, 0, "APPDVC", 6) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            dynamic_static_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_static_channel_data(client_fd,
                                                response,
                                                sizeof(response),
                                                &response_channel_id,
                                                &dvc_payload,
                                                &dvc_payload_len));
    SCHECK(response_channel_id == dynamic_static_channel_id);
    SCHECK(rdp_dynamic_channel_parse_create_response(dvc_payload,
                                                     dvc_payload_len,
                                                     &dvc_create_response) == LIBRDP_STATUS_OK);
    SCHECK(dvc_create_response.channel_id == 7 &&
           dvc_create_response.status_code == RDP_DYNAMIC_CHANNEL_STATUS_OK);
    SCHECK(runtime_context.dynamic_open_count == 1);
    SCHECK(librdp_server_peer_dynamic_channel_count(peer) == 1);
    SCHECK(librdp_server_dynamic_channel_info_init(&dynamic_info) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_dynamic_channel_at(peer, 0, &dynamic_info) == LIBRDP_STATUS_OK);
    SCHECK(dynamic_info.channel_id == 7 && dynamic_info.open && strcmp(dynamic_info.name, "APPDVC") == 0);

    dvc_packet.length = 0;
    SCHECK(rdp_dynamic_channel_write_data(&dvc_packet, 7, 1, "ping", 4) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            dynamic_static_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.dynamic_data_count == 1);
    SCHECK(runtime_context.last_dynamic_channel_id == 7);
    SCHECK(runtime_context.channel_payload_len == 4 &&
           memcmp(runtime_context.channel_payload, "ping", 4) == 0);

    SCHECK(librdp_server_peer_send_dynamic_channel_data(peer, 7, "pong", 4) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_static_channel_data(client_fd,
                                                response,
                                                sizeof(response),
                                                &response_channel_id,
                                                &dvc_payload,
                                                &dvc_payload_len));
    SCHECK(response_channel_id == dynamic_static_channel_id);
    SCHECK(rdp_dynamic_channel_parse_data(dvc_payload, dvc_payload_len, &dvc_data_response) ==
           LIBRDP_STATUS_OK);
    SCHECK(dvc_data_response.channel_id == 7 &&
           dvc_data_response.data_len == 4 &&
           memcmp(dvc_data_response.data, "pong", 4) == 0);

    dvc_packet.length = 0;
    SCHECK(rdp_dynamic_channel_write_close(&dvc_packet, 7, 1) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            dynamic_static_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.dynamic_close_count == 1);
    SCHECK(librdp_server_peer_dynamic_channel_count(peer) == 0);
    SCHECK(librdp_server_peer_dynamic_channel_at(peer, 0, &dynamic_info) == LIBRDP_STATUS_INVALID_ARGUMENT);

    SCHECK(librdp_server_peer_surface_blit_bgra32(peer, 0, 0, 4, 4, 16, pixels) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_surface_present(peer, 0, 0, 4, 4) == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.surface_event_count == 1);
    SCHECK(test_server_read_slowpath_data_pdu(client_fd, response, sizeof(response), &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE);
    SCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &bitmap_update) == LIBRDP_STATUS_OK);
    SCHECK(bitmap_update.count == 1 &&
           bitmap_update.rects[0].width == 4 &&
           bitmap_update.rects[0].height == 4 &&
           bitmap_update.rects[0].bits_per_pixel == 32);
    SCHECK(librdp_server_peer_surface_blit_bgra32(peer, 0, 0, 800, 11, 800u * 4u, large_pixels) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_surface_present(peer, 0, 0, 800, 11) == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.surface_event_count == 2);
    SCHECK(test_server_read_slowpath_data_pdu(client_fd, response, sizeof(response), &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE);
    SCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &bitmap_update) == LIBRDP_STATUS_OK);
    SCHECK(bitmap_update.count == 1 &&
           bitmap_update.rects[0].width == 800 &&
           bitmap_update.rects[0].height == 10);
    SCHECK(test_server_read_slowpath_data_pdu(client_fd, response, sizeof(response), &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE);
    SCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &bitmap_update) == LIBRDP_STATUS_OK);
    SCHECK(bitmap_update.count == 1 &&
           bitmap_update.rects[0].width == 800 &&
           bitmap_update.rects[0].height == 1);

    SCHECK(test_server_send_keyboard_input(client_fd, demand.share_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.key_count == 1);

    SCHECK(test_server_send_static_channel_data(client_fd, attach_confirm.user_id, static_channel_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.channel_count == 4);
    SCHECK(runtime_context.last_channel_id == static_channel_id);
    SCHECK(runtime_context.channel_payload_len == 4 &&
           runtime_context.channel_payload[0] == 1 &&
           runtime_context.channel_payload[3] == 4);
    SCHECK(librdp_server_peer_send_channel_data(peer, static_channel_id, pixels, 4) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_static_channel_data(client_fd,
                                                response,
                                                sizeof(response),
                                                &response_channel_id,
                                                &static_payload,
                                                &static_payload_len));
    SCHECK(response_channel_id == static_channel_id &&
           static_payload_len == 4 &&
           static_payload[0] == pixels[0] &&
           static_payload[3] == pixels[3]);
    SCHECK(librdp_server_peer_surface_present(peer, 900, 0, 1, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(runtime_context.error_event_count == 1);
    SCHECK(runtime_context.last_error_status == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_status_init(&server_status) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_last_status(peer, &server_status) == LIBRDP_STATUS_OK);
    SCHECK(server_status.status == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(strcmp(server_status.phase, "server.surface.present") == 0);
    SCHECK(librdp_server_metrics_init(&server_metrics) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_metrics(peer, &server_metrics) == LIBRDP_STATUS_OK);
    SCHECK(server_metrics.bytes_read > 0 && server_metrics.bytes_written > 0);
    SCHECK(server_metrics.pdu_in > 0 && server_metrics.pdu_out > 0);
    SCHECK(server_metrics.input_events == runtime_context.input_count);
    SCHECK(server_metrics.static_channel_in == 1 && server_metrics.static_channel_out >= 1);
    SCHECK(server_metrics.static_channel_bytes_in == 4 && server_metrics.static_channel_bytes_out >= 4);
    SCHECK(server_metrics.dynamic_channel_in == 1 && server_metrics.dynamic_channel_out == 1);
    SCHECK(server_metrics.dynamic_channel_bytes_in == 4 && server_metrics.dynamic_channel_bytes_out == 4);
    SCHECK(server_metrics.surface_updates == 2);
    SCHECK(librdp_server_peer_reset_metrics(peer) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_metrics_init(&server_metrics) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_metrics(peer, &server_metrics) == LIBRDP_STATUS_OK);
    SCHECK(server_metrics.bytes_read == 0 && server_metrics.bytes_written == 0);
    SCHECK(librdp_server_peer_close(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_close(peer) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_close(peer) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CLOSED);
    memset(client_random, 0, sizeof(client_random));
    rdp_security_standard_clear(&client_security);
    rdp_security_public_key_clear(&server_public_key);
    rdp_buffer_free(&encrypted_client_random);
    rdp_buffer_free(&dvc_packet);
    rdp_buffer_free(&security_data);
    rdp_buffer_free(&security_payload);
    rdp_buffer_free(&license_payload);
    librdp_server_peer_free(peer);
    librdp_server_close(server);
    librdp_server_free(server);
    close(client_fd);
    return 0;
}

int main(void)
{
    if (test_server_config_defaults() != 0)
        return 1;
    if (test_server_new_validates_metadata() != 0)
        return 1;
    if (test_server_new_copies_strings() != 0)
        return 1;
    if (test_server_loopback_negotiation_failure() != 0)
        return 1;
    if (test_server_loopback_tls_handshake() != 0)
        return 1;
    if (test_server_loopback_nla_handshake() != 0)
        return 1;
    if (test_server_loopback_standard_activation_sequence() != 0)
        return 1;
    return 0;
}
