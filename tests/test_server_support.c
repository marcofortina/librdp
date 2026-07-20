/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: reusable support for focused server tests.
 * Coverage: loopback I/O, TLS material, CredSSP, protocol construction, and callbacks.
 * Bug classes: partial transport, fixture cleanup, and deterministic secret handling.
 * Determinism: temporary files and loopback sockets are process-local.
 */

#include "test_server_support.h"

#include "channels/virtual_channel.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

const librdp_feature server_test_all_features[SERVER_TEST_ALL_FEATURE_COUNT] = {
    LIBRDP_FEATURE_AUDIO_OUTPUT,
    LIBRDP_FEATURE_AUDIO_INPUT,
    LIBRDP_FEATURE_VIDEO,
    LIBRDP_FEATURE_CAMERA,
    LIBRDP_FEATURE_SMARTCARD,
    LIBRDP_FEATURE_USB,
    LIBRDP_FEATURE_PNP,
    LIBRDP_FEATURE_WEBAUTHN,
    LIBRDP_FEATURE_RAIL,
    LIBRDP_FEATURE_CR2,
    LIBRDP_FEATURE_ECHO,
    LIBRDP_FEATURE_TELEMETRY,
    LIBRDP_FEATURE_MULTITRANSPORT,
    LIBRDP_FEATURE_DESKTOP_COMPOSITION,
    LIBRDP_FEATURE_DISPLAY_CONTROL,
    LIBRDP_FEATURE_UDP_TRANSPORT,
    LIBRDP_FEATURE_UDP2_TRANSPORT,
    LIBRDP_FEATURE_GEOMETRY_TRACKING,
    LIBRDP_FEATURE_MULTIPARTY
};

int server_test_feature_reason_is_current(const librdp_feature_status* status)
{
    return status &&
           status->reason >= LIBRDP_FEATURE_REASON_NONE &&
           status->reason <= LIBRDP_FEATURE_REASON_NOT_ACTIVE;
}

int test_server_connect_loopback(uint16_t port)
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

int test_server_set_nonblocking(int fd)
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

int test_server_copy_file(const char* source_path, const char* target_path)
{
    uint8_t buffer[4096];
    FILE* source = NULL;
    FILE* target = NULL;
    size_t count = 0;
    int ok = 0;

    source = fopen(source_path, "rb");
    if (!source)
        return 0;
    target = fopen(target_path, "wb");
    if (!target)
    {
        fclose(source);
        return 0;
    }
    do
    {
        count = fread(buffer, 1u, sizeof(buffer), source);
        if (count > 0u && fwrite(buffer, 1u, count, target) != count)
            break;
        if (ferror(source))
            break;
    } while (count > 0u);
    ok = count == 0u && !ferror(source) && fflush(target) == 0;
    fclose(target);
    fclose(source);
    return ok;
}

static int test_server_add_certificate_extension(X509* certificate,
                                                 int nid,
                                                 const char* value)
{
    X509V3_CTX context;
    X509_EXTENSION* extension = NULL;
    int result = 0;

    if (!certificate || !value)
        return 0;
    X509V3_set_ctx(&context,
                   certificate,
                   certificate,
                   NULL,
                   NULL,
                   0);
    extension = X509V3_EXT_conf_nid(NULL,
                                   &context,
                                   nid,
                                   (char*)value);
    if (extension)
        result = X509_add_ext(certificate, extension, -1) == 1;
    X509_EXTENSION_free(extension);
    return result;
}

/*
 * Generate process-local TLS material with an optional DNS identity. Host-bound
 * fixtures are self-signed trust anchors so libcurl can validate both the
 * chain and hostname without weakening verification.
 */
static int test_server_make_tls_files_internal(char* cert_path,
                                               size_t cert_path_len,
                                               char* key_path,
                                               size_t key_path_len,
                                               unsigned int key_bits,
                                               long not_before_offset,
                                               long not_after_offset,
                                               const char* common_name,
                                               const char* dns_name)
{
    EVP_PKEY* key = NULL;
    X509* cert = NULL;
    X509_NAME* name = NULL;
    char subject_alt_name[256];
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
        key = EVP_RSA_gen(key_bits);
        cert = X509_new();
        if (!key || !cert)
            break;
        if (!common_name ||
            ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1 ||
            X509_set_version(cert, 2) != 1 ||
            X509_set_pubkey(cert, key) != 1 ||
            !X509_gmtime_adj(X509_get_notBefore(cert),
                             not_before_offset) ||
            !X509_gmtime_adj(X509_get_notAfter(cert),
                             not_after_offset))
            break;
        name = X509_get_subject_name(cert);
        if (!name ||
            X509_NAME_add_entry_by_txt(name,
                                       "CN",
                                       MBSTRING_ASC,
                                       (const unsigned char*)common_name,
                                       -1,
                                       -1,
                                       0) != 1 ||
            X509_set_issuer_name(cert, name) != 1)
            break;
        if (dns_name)
        {
            const int written = snprintf(subject_alt_name,
                                         sizeof(subject_alt_name),
                                         "DNS:%s",
                                         dns_name);

            if (written <= 0 ||
                (size_t)written >= sizeof(subject_alt_name) ||
                !test_server_add_certificate_extension(
                    cert,
                    NID_basic_constraints,
                    "critical,CA:TRUE") ||
                !test_server_add_certificate_extension(
                    cert,
                    NID_key_usage,
                    "critical,digitalSignature,keyEncipherment,keyCertSign") ||
                !test_server_add_certificate_extension(
                    cert,
                    NID_ext_key_usage,
                    "serverAuth") ||
                !test_server_add_certificate_extension(
                    cert,
                    NID_subject_alt_name,
                    subject_alt_name))
                break;
        }
        if (X509_sign(cert, key, EVP_sha256()) <= 0)
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

int test_server_make_tls_files_with_policy(char* cert_path,
                                           size_t cert_path_len,
                                           char* key_path,
                                           size_t key_path_len,
                                           unsigned int key_bits,
                                           long not_before_offset,
                                           long not_after_offset)
{
    return test_server_make_tls_files_internal(cert_path,
                                               cert_path_len,
                                               key_path,
                                               key_path_len,
                                               key_bits,
                                               not_before_offset,
                                               not_after_offset,
                                               "librdp-server-test",
                                               NULL);
}

int test_server_make_tls_files(char* cert_path,
                               size_t cert_path_len,
                               char* key_path,
                               size_t key_path_len)
{
    return test_server_make_tls_files_with_policy(cert_path,
                                                  cert_path_len,
                                                  key_path,
                                                  key_path_len,
                                                  2048u,
                                                  0,
                                                  3600);
}

int test_server_make_tls_files_for_host(char* cert_path,
                                        size_t cert_path_len,
                                        char* key_path,
                                        size_t key_path_len,
                                        const char* host)
{
    if (!host || host[0] == '\0')
        return 0;
    return test_server_make_tls_files_internal(cert_path,
                                               cert_path_len,
                                               key_path,
                                               key_path_len,
                                               2048u,
                                               0,
                                               3600,
                                               host,
                                               host);
}

int test_server_read_response(int fd, uint8_t* response, size_t response_len)
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

int test_server_send_all(int fd, const uint8_t* data, size_t length)
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

int test_server_tls_write_all(SSL* tls, const uint8_t* data, size_t length)
{
    size_t offset = 0;

    if (!tls || (!data && length > 0))
        return 0;
    while (offset < length)
    {
        int chunk = (length - offset) > (size_t)INT32_MAX ? INT32_MAX : (int)(length - offset);
        int written = SSL_write(tls, data + offset, chunk);

        if (written <= 0)
        {
            int error = SSL_get_error(tls, written);
            struct pollfd poll_fd;

            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                return 0;
            memset(&poll_fd, 0, sizeof(poll_fd));
            poll_fd.fd = SSL_get_fd(tls);
            poll_fd.events = error == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN;
            if (poll_fd.fd < 0 || poll(&poll_fd, 1, 1000) <= 0)
                return 0;
            continue;
        }
        offset += (size_t)written;
    }
    return 1;
}

static int test_server_tls_read_exact(SSL* tls, uint8_t* data, size_t length)
{
    size_t offset = 0;

    if (!tls || (!data && length > 0))
        return 0;
    while (offset < length)
    {
        size_t remaining = length - offset;
        int chunk = remaining > (size_t)INT32_MAX ? INT32_MAX : (int)remaining;
        int read_len = SSL_read(tls, data + offset, chunk);

        if (read_len <= 0)
        {
            int error = SSL_get_error(tls, read_len);
            struct pollfd poll_fd;

            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                return 0;
            memset(&poll_fd, 0, sizeof(poll_fd));
            poll_fd.fd = SSL_get_fd(tls);
            poll_fd.events = error == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN;
            if (poll_fd.fd < 0 || poll(&poll_fd, 1, 1000) <= 0)
                return 0;
            continue;
        }
        offset += (size_t)read_len;
    }
    return 1;
}

int test_server_tls_read_tpkt(SSL* tls, uint8_t* data, size_t capacity)
{
    uint16_t length = 0;

    if (!tls || !data || capacity < 4u)
        return 0;
    if (!test_server_tls_read_exact(tls, data, 4u))
        return 0;
    length = (uint16_t)(((uint32_t)data[2] << 8) | (uint32_t)data[3]);
    if (length < 4u || length > capacity)
        return 0;
    if (!test_server_tls_read_exact(tls, data + 4u, (size_t)length - 4u))
        return 0;
    return (int)length;
}

int test_server_wait_peer_state(librdp_server_peer* peer, librdp_server_peer_state state)
{
    if (!peer)
        return 0;
    for (int attempt = 0; attempt < 100; attempt++)
    {
        librdp_status status = LIBRDP_STATUS_OK;

        if (librdp_server_peer_get_state(peer) == state)
            return 1;
        status = librdp_server_peer_run_once(peer, 10);
        if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_TIMEOUT)
            return 0;
    }
    return librdp_server_peer_get_state(peer) == state;
}

int test_server_tls_read_credssp(SSL* tls, rdp_buffer* packet)
{
    uint8_t header[6];
    size_t header_len = 2u;
    size_t payload_len = 0;
    size_t total = 0;

    if (!tls || !packet)
        return 0;
    if (!test_server_tls_read_exact(tls, header, 2))
        return 0;
    if (header[0] != 0x30u)
        return 0;
    if ((header[1] & 0x80u) == 0)
        payload_len = header[1];
    else
    {
        size_t length_len = header[1] & 0x7fu;

        if (length_len == 0 || length_len > 4u)
            return 0;
        if (!test_server_tls_read_exact(tls, header + 2u, length_len))
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
    if (!test_server_tls_read_exact(tls,
                                    packet->data + packet->length,
                                    total - packet->length))
        return 0;
    packet->length = total;
    return 1;
}

int test_server_tls_public_key(SSL* tls, rdp_buffer* public_key)
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

void test_server_fill_secret(char* output, size_t output_len, uint32_t seed)
{
    static const char alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

    if (!output || output_len == 0)
        return;
    for (size_t i = 0; i + 1u < output_len; i++)
        output[i] = alphabet[(seed + (uint32_t)(i * 13u)) % (sizeof(alphabet) - 1u)];
    output[output_len - 1u] = '\0';
}

librdp_status test_server_nla_provider(librdp_server_peer* peer,
                                              const librdp_server_credentials_request* request,
                                              librdp_credentials* credentials,
                                              void* user_data)
{
    test_server_nla_provider_context* context = (test_server_nla_provider_context*)user_data;

    if (!peer || !request || !credentials || !context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    context->calls++;
    context->last_version = request->ts_request_version;
    context->last_failed_attempts = request->failed_attempts;
    context->last_public_key_bound = request->public_key_bound;
    if (request->version != LIBRDP_SERVER_CREDENTIALS_REQUEST_VERSION ||
        request->size < sizeof(*request) ||
        !request->username ||
        strcmp(request->username, context->username) != 0 ||
        !request->domain ||
        strcmp(request->domain, context->domain) != 0 ||
        !request->workstation ||
        strcmp(request->workstation, context->workstation) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (context->reject)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return librdp_credentials_set(credentials,
                                  context->username,
                                  context->password,
                                  context->domain);
}

void test_server_input_callback(librdp_server_peer* peer,
                                       const librdp_server_input_event* event,
                                       void* user_data)
{
    test_server_runtime_context* context = (test_server_runtime_context*)user_data;

    (void)peer;
    if (!context || !event)
        return;
    context->input_count++;
    if (event->type == LIBRDP_SERVER_INPUT_SYNCHRONIZE)
        context->synchronize_count++;
    else if (event->type == LIBRDP_SERVER_INPUT_CONTROL)
        context->control_count++;
    else if (event->type == LIBRDP_SERVER_INPUT_FONT_LIST)
        context->font_list_count++;
    else if (event->type == LIBRDP_SERVER_INPUT_SCANCODE_KEY)
        context->key_count++;
}

void test_server_channel_callback(librdp_server_peer* peer,
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

int test_server_dynamic_channel_accept_callback(librdp_server_peer* peer,
                                                       uint32_t dynamic_channel_id,
                                                       uint8_t priority,
                                                       const char* name,
                                                       size_t name_len,
                                                       void* user_data)
{
    test_server_runtime_context* context = (test_server_runtime_context*)user_data;
    int accepted = 1;

    (void)peer;
    (void)priority;
    if (name && name_len == 6u && memcmp(name, "DENIED", 6u) == 0)
        accepted = 0;
    if (context)
    {
        if (accepted)
        {
            context->dynamic_accept_count++;
            context->accepted_dynamic_channel_id = dynamic_channel_id;
        }
        else
        {
            context->dynamic_reject_count++;
            context->rejected_dynamic_channel_id = dynamic_channel_id;
        }
    }
    return accepted;
}

void test_server_extension_callback(librdp_server_peer* peer,
                                           const librdp_server_extension_event* event,
                                           void* user_data)
{
    test_server_runtime_context* context = (test_server_runtime_context*)user_data;

    (void)peer;
    if (!context || !event)
        return;
    context->extension_count++;
    context->last_extension_family = event->family;
    context->last_extension_feature = event->feature;
    context->last_extension_message_type = event->message_type;
    context->last_extension_flags = event->flags;
    context->last_channel_id = event->channel_id;
    context->last_dynamic_channel_id = event->dynamic_channel_id;
}

void test_server_event_callback(librdp_server_peer* peer,
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

int test_server_build_client_mcs_connect_initial(rdp_buffer* tpkt)
{
    static const rdp_gcc_channel_definition extra_channels[8] = {
        {{'t', 'e', 's', 't', 'v', 'c', 0, 0}, 0xc0800000u},
        {{'c', 'l', 'i', 'p', 'r', 'd', 'r', 0}, 0xc0a00000u},
        {{'e', 'n', 'c', 'o', 'm', 's', 'p', 0}, 0xc0a00000u},
        {{'T', 'S', 'M', 'F', 0, 0, 0, 0}, 0xc0a00000u},
        {{'r', 'd', 'p', 'd', 'r', 0, 0, 0}, 0xc0a00000u},
        {{'P', 'N', 'P', 'D', 'R', 0, 0, 0}, 0xc0a00000u},
        {{'r', 'd', 'p', 's', 'n', 'd', 0, 0}, 0xc0a00000u},
        {{'r', 'a', 'i', 'l', 0, 0, 0, 0}, 0xc0a00000u}
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
    config.enable_multitransport = 1;
    config.multitransport_flags = RDP_GCC_MULTITRANSPORT_UDP_FECR |
                                  RDP_GCC_MULTITRANSPORT_UDP_FECL |
                                  RDP_GCC_MULTITRANSPORT_UDP_PREFERRED;
    config.extra_channels = extra_channels;
    config.extra_channel_count = 8;
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

int test_server_send_client_mcs_connect_initial(int fd)
{
    rdp_buffer tpkt;
    int ok = 0;

    rdp_buffer_init(&tpkt);
    if (test_server_build_client_mcs_connect_initial(&tpkt))
        ok = test_server_send_all(fd, tpkt.data, tpkt.length);
    rdp_buffer_free(&tpkt);
    return ok;
}

int test_server_send_mcs_pdu(int fd, const rdp_buffer* mcs_pdu)
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

int test_server_append_mcs_tpkt(rdp_buffer* output, const rdp_buffer* mcs_pdu)
{
    rdp_buffer x224_data;
    rdp_buffer tpkt;
    int ok = 0;

    if (!output || !mcs_pdu)
        return 0;
    rdp_buffer_init(&x224_data);
    rdp_buffer_init(&tpkt);
    if (rdp_x224_wrap_data(&x224_data, mcs_pdu->data, mcs_pdu->length) == LIBRDP_STATUS_OK &&
        rdp_tpkt_write(&tpkt, x224_data.data, x224_data.length) == LIBRDP_STATUS_OK &&
        rdp_buffer_append(output, tpkt.data, tpkt.length) == LIBRDP_STATUS_OK)
        ok = 1;
    rdp_buffer_free(&tpkt);
    rdp_buffer_free(&x224_data);
    return ok;
}

int test_server_send_channel_join(int fd, uint16_t user_id, uint16_t channel_id)
{
    rdp_buffer pdu;
    int ok = 0;

    rdp_buffer_init(&pdu);
    if (rdp_mcs_write_channel_join_request(&pdu, user_id, channel_id) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &pdu);
    rdp_buffer_free(&pdu);
    return ok;
}

int test_server_send_confirm_active(
    int fd,
    uint32_t share_id,
    uint16_t user_id,
    rdp_standard_security_context* security)
{
    rdp_buffer confirm;
    int ok = 0;

    rdp_buffer_init(&confirm);
    if (rdp_slowpath_write_confirm_active(
            &confirm,
            share_id,
            (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
            800,
            600,
            "test") == LIBRDP_STATUS_OK)
    {
        ok = test_server_send_encrypted_slowpath(
            fd,
            user_id,
            security,
            &confirm,
            TEST_SERVER_SECURITY_TAMPER_NONE);
    }
    rdp_buffer_free(&confirm);
    return ok;
}

int test_server_send_encrypted_slowpath(int fd,
                                               uint16_t user_id,
                                               rdp_standard_security_context* security,
                                               const rdp_buffer* slowpath,
                                               test_server_security_tamper tamper)
{
    rdp_buffer security_payload;
    rdp_buffer send_data;
    int ok = 0;

    if (!security || !slowpath)
        return 0;
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&send_data);
    if (rdp_security_write_encrypted_pdu(&security_payload,
                                         security,
                                         0,
                                         slowpath->data,
                                         slowpath->length) == LIBRDP_STATUS_OK)
    {
        if (tamper == TEST_SERVER_SECURITY_TAMPER_SIGNATURE && security_payload.length > 4u)
            security_payload.data[4] ^= 0x80u;
        else if (tamper == TEST_SERVER_SECURITY_TAMPER_CIPHERTEXT && security_payload.length > 12u)
            security_payload.data[security_payload.length - 1u] ^= 0x01u;
        if (rdp_security_write_send_data_request(&send_data,
                                                 user_id,
                                                 (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                 security_payload.data,
                                                 security_payload.length) == LIBRDP_STATUS_OK)
            ok = test_server_send_mcs_pdu(fd, &send_data);
    }
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security_payload);
    return ok;
}

int test_server_send_encrypted_channel_payload(int fd,
                                                      uint16_t user_id,
                                                      uint16_t channel_id,
                                                      rdp_standard_security_context* security,
                                                      const rdp_buffer* payload)
{
    rdp_buffer channel_packet;
    rdp_buffer security_payload;
    rdp_buffer send_data;
    int ok = 0;

    if (!security || !payload)
        return 0;
    rdp_buffer_init(&channel_packet);
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&send_data);
    if (rdp_virtual_channel_write_packet(
            &channel_packet,
            payload->data,
            payload->length,
            RDP_VIRTUAL_CHANNEL_FLAG_FIRST |
                RDP_VIRTUAL_CHANNEL_FLAG_LAST) == LIBRDP_STATUS_OK &&
        rdp_security_write_encrypted_pdu(&security_payload,
                                         security,
                                         0,
                                         channel_packet.data,
                                         channel_packet.length) == LIBRDP_STATUS_OK &&
        rdp_security_write_send_data_request(&send_data,
                                             user_id,
                                             channel_id,
                                             security_payload.data,
                                             security_payload.length) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &send_data);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security_payload);
    rdp_buffer_free(&channel_packet);
    return ok;
}

int test_server_send_client_synchronize(
    int fd,
    uint32_t share_id,
    uint16_t user_id,
    rdp_standard_security_context* security)
{
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_client_synchronize(&slowpath,
                                              share_id,
                                              (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK)
    {
        ok = test_server_send_encrypted_slowpath(
            fd,
            user_id,
            security,
            &slowpath,
            TEST_SERVER_SECURITY_TAMPER_NONE);
    }
    rdp_buffer_free(&slowpath);
    return ok;
}

int test_server_send_client_control(
    int fd,
    uint32_t share_id,
    uint16_t user_id,
    uint16_t action,
    rdp_standard_security_context* security)
{
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_client_control(&slowpath,
                                          share_id,
                                          (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                          action) == LIBRDP_STATUS_OK)
    {
        ok = test_server_send_encrypted_slowpath(
            fd,
            user_id,
            security,
            &slowpath,
            TEST_SERVER_SECURITY_TAMPER_NONE);
    }
    rdp_buffer_free(&slowpath);
    return ok;
}

int test_server_send_client_font_list(
    int fd,
    uint32_t share_id,
    uint16_t user_id,
    rdp_standard_security_context* security)
{
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_client_font_list(&slowpath,
                                            share_id,
                                            (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK)
    {
        ok = test_server_send_encrypted_slowpath(
            fd,
            user_id,
            security,
            &slowpath,
            TEST_SERVER_SECURITY_TAMPER_NONE);
    }
    rdp_buffer_free(&slowpath);
    return ok;
}

int test_server_send_keyboard_input(
    int fd,
    uint32_t share_id,
    uint16_t user_id,
    rdp_standard_security_context* security)
{
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_client_keyboard_input(&slowpath,
                                                 share_id,
                                                 (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                 0,
                                                 30) == LIBRDP_STATUS_OK)
    {
        ok = test_server_send_encrypted_slowpath(
            fd,
            user_id,
            security,
            &slowpath,
            TEST_SERVER_SECURITY_TAMPER_NONE);
    }
    rdp_buffer_free(&slowpath);
    return ok;
}

int test_server_send_sync_input(
    int fd,
    uint32_t share_id,
    uint16_t user_id,
    rdp_standard_security_context* security)
{
    static const uint8_t payload[16] = {
        1, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
    };
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_data_pdu(&slowpath,
                                    share_id,
                                    (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                    RDP_SLOWPATH_DATA_PDU_INPUT,
                                    payload,
                                    sizeof(payload)) == LIBRDP_STATUS_OK)
    {
        ok = test_server_send_encrypted_slowpath(
            fd,
            user_id,
            security,
            &slowpath,
            TEST_SERVER_SECURITY_TAMPER_NONE);
    }
    rdp_buffer_free(&slowpath);
    return ok;
}

int test_server_send_static_channel_data(
    int fd,
    uint16_t user_id,
    uint16_t channel_id,
    rdp_standard_security_context* security)
{
    static const uint8_t payload[] = {1, 2, 3, 4};
    rdp_buffer data;
    int ok = 0;

    rdp_buffer_init(&data);
    if (rdp_buffer_append(&data, payload, sizeof(payload)) ==
        LIBRDP_STATUS_OK)
    {
        ok = test_server_send_encrypted_channel_payload(
            fd,
            user_id,
            channel_id,
            security,
            &data);
    }
    rdp_buffer_free(&data);
    return ok;
}

int test_server_send_channel_payload(int fd, uint16_t user_id, uint16_t channel_id, const rdp_buffer* payload)
{
    rdp_buffer channel_packet;
    rdp_buffer send_data;
    int ok = 0;

    if (!payload)
        return 0;
    rdp_buffer_init(&channel_packet);
    rdp_buffer_init(&send_data);
    if (rdp_virtual_channel_write_packet(
            &channel_packet,
            payload->data,
            payload->length,
            RDP_VIRTUAL_CHANNEL_FLAG_FIRST |
                RDP_VIRTUAL_CHANNEL_FLAG_LAST) == LIBRDP_STATUS_OK &&
        rdp_security_write_send_data_request(&send_data,
                                             user_id,
                                             channel_id,
                                             channel_packet.data,
                                             channel_packet.length) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &send_data);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&channel_packet);
    return ok;
}

int test_server_read_tpkt_x224_data(int fd, uint8_t* buffer, size_t buffer_len, rdp_tpkt* tpkt)
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

int test_server_read_encrypted_mcs_payload(int fd,
                                                  uint8_t* response,
                                                  size_t response_len,
                                                  rdp_standard_security_context* security,
                                                  rdp_buffer* plaintext)
{
    rdp_tpkt tpkt;
    rdp_mcs_send_data_indication indication;
    const uint8_t* x224_data = NULL;
    size_t x224_data_len = 0;
    uint16_t flags = 0;

    if (!security || !plaintext)
        return 0;
    if (!test_server_read_tpkt_x224_data(fd, response, response_len, &tpkt))
        return 0;
    if (rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) != LIBRDP_STATUS_OK ||
        rdp_mcs_parse_send_data_indication(x224_data, x224_data_len, &indication) != LIBRDP_STATUS_OK ||
        rdp_security_unwrap_pdu(security,
                                indication.payload,
                                indication.payload_len,
                                plaintext,
                                &flags) != LIBRDP_STATUS_OK ||
        (flags & RDP_SEC_ENCRYPT) == 0)
        return 0;
    return 1;
}

int test_server_read_encrypted_slowpath_data_pdu(int fd,
                                                        uint8_t* response,
                                                        size_t response_len,
                                                        rdp_standard_security_context* security,
                                                        rdp_buffer* plaintext,
                                                        rdp_slowpath_data_pdu* data_pdu)
{
    int ok = 0;

    if (!plaintext)
        return 0;
    plaintext->length = 0;
    if (test_server_read_encrypted_mcs_payload(fd, response, response_len, security, plaintext) &&
        rdp_slowpath_parse_data_pdu(plaintext->data, plaintext->length, data_pdu) == LIBRDP_STATUS_OK)
        ok = 1;
    return ok;
}

int test_server_read_encrypted_static_channel_data(int fd,
                                                          uint8_t* response,
                                                          size_t response_len,
                                                          rdp_standard_security_context* security,
                                                          rdp_buffer* plaintext,
                                                          uint16_t* channel_id,
                                                          const uint8_t** data,
                                                          size_t* data_len)
{
    rdp_tpkt tpkt;
    rdp_mcs_send_data_indication indication;
    rdp_virtual_channel_packet channel_packet;
    const uint8_t* x224_data = NULL;
    size_t x224_data_len = 0;
    uint16_t flags = 0;

    if (!security || !plaintext || !channel_id || !data || !data_len)
        return 0;
    plaintext->length = 0;
    if (!test_server_read_tpkt_x224_data(fd, response, response_len, &tpkt))
        return 0;
    if (rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) != LIBRDP_STATUS_OK ||
        rdp_mcs_parse_send_data_indication(x224_data, x224_data_len, &indication) != LIBRDP_STATUS_OK ||
        rdp_security_unwrap_pdu(security,
                                indication.payload,
                                indication.payload_len,
                                plaintext,
                                &flags) != LIBRDP_STATUS_OK ||
        (flags & RDP_SEC_ENCRYPT) == 0 ||
        rdp_virtual_channel_parse_packet(plaintext->data,
                                         plaintext->length,
                                         &channel_packet) != LIBRDP_STATUS_OK ||
        channel_packet.flags !=
            (RDP_VIRTUAL_CHANNEL_FLAG_FIRST |
             RDP_VIRTUAL_CHANNEL_FLAG_LAST) ||
        channel_packet.payload_len + 8u != plaintext->length)
        return 0;
    *channel_id = indication.channel_id;
    *data = channel_packet.payload;
    *data_len = channel_packet.payload_len;
    return 1;
}

int test_server_open_client_dynamic_channel(int fd,
                                                   librdp_server_peer* peer,
                                                   uint16_t user_id,
                                                   uint16_t static_channel_id,
                                                   uint32_t dynamic_channel_id,
                                                   const char* name,
                                                   uint8_t priority,
                                                   rdp_standard_security_context* security,
                                                   rdp_buffer* plaintext,
                                                   uint8_t* response,
                                                   size_t response_len)
{
    rdp_buffer dvc_packet;
    rdp_dynamic_channel_create_response create_response;
    const uint8_t* dvc_payload = NULL;
    size_t dvc_payload_len = 0;
    uint16_t response_channel_id = 0;
    int ok = 0;

    rdp_buffer_init(&dvc_packet);
    if (name &&
        rdp_dynamic_channel_write_create_request(&dvc_packet,
                                                 dynamic_channel_id,
                                                 1,
                                                 priority,
                                                 name,
                                                 strlen(name)) == LIBRDP_STATUS_OK &&
        test_server_send_encrypted_channel_payload(fd,
                                                   user_id,
                                                   static_channel_id,
                                                   security,
                                                   &dvc_packet) &&
        librdp_server_peer_run_once(peer, 1000) == LIBRDP_STATUS_OK &&
        test_server_read_encrypted_static_channel_data(fd,
                                                       response,
                                                       response_len,
                                                       security,
                                                       plaintext,
                                                       &response_channel_id,
                                                       &dvc_payload,
                                                       &dvc_payload_len) &&
        response_channel_id == static_channel_id &&
        rdp_dynamic_channel_parse_create_response(dvc_payload,
                                                  dvc_payload_len,
                                                  &create_response) == LIBRDP_STATUS_OK &&
        create_response.channel_id == dynamic_channel_id &&
        create_response.status_code == RDP_DYNAMIC_CHANNEL_STATUS_OK)
        ok = 1;
    rdp_buffer_free(&dvc_packet);
    return ok;
}

int test_server_read_encrypted_dynamic_channel_payload(int fd,
                                                              uint8_t* response,
                                                              size_t response_len,
                                                              rdp_standard_security_context* security,
                                                              rdp_buffer* plaintext,
                                                              uint16_t static_channel_id,
                                                              uint32_t dynamic_channel_id,
                                                              rdp_dynamic_channel_data_pdu* data_response)
{
    const uint8_t* dvc_payload = NULL;
    size_t dvc_payload_len = 0;
    uint16_t response_channel_id = 0;

    if (!data_response)
        return 0;
    if (!test_server_read_encrypted_static_channel_data(fd,
                                                        response,
                                                        response_len,
                                                        security,
                                                        plaintext,
                                                        &response_channel_id,
                                                        &dvc_payload,
                                                        &dvc_payload_len) ||
        response_channel_id != static_channel_id)
        return 0;
    if (rdp_dynamic_channel_parse_data(dvc_payload, dvc_payload_len, data_response) != LIBRDP_STATUS_OK)
        return 0;
    return data_response->channel_id == dynamic_channel_id;
}
