#include "common/buffer.h"
#include "protocol/tpkt.h"
#include "transport/transport.h"

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define TCHECK(expr)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

static int make_test_certificate(EVP_PKEY** key, X509** cert)
{
    X509_NAME* name = NULL;

    if (!key || !cert)
        return 0;
    *key = EVP_RSA_gen(2048);
    *cert = X509_new();
    if (!*key || !*cert)
        return 0;
    if (ASN1_INTEGER_set(X509_get_serialNumber(*cert), 1) != 1)
        return 0;
    if (!X509_gmtime_adj(X509_get_notBefore(*cert), 0) ||
        !X509_gmtime_adj(X509_get_notAfter(*cert), 3600))
        return 0;
    if (X509_set_version(*cert, 2) != 1 || X509_set_pubkey(*cert, *key) != 1)
        return 0;
    name = X509_get_subject_name(*cert);
    if (!name)
        return 0;
    if (X509_NAME_add_entry_by_txt(name,
                                   "CN",
                                   MBSTRING_ASC,
                                   (const unsigned char*)"librdp-test",
                                   -1,
                                   -1,
                                   0) != 1)
        return 0;
    if (X509_set_issuer_name(*cert, name) != 1)
        return 0;
    return X509_sign(*cert, *key, EVP_sha256()) > 0;
}

static int run_tls_server(int fd, EVP_PKEY* key, X509* cert)
{
    SSL_CTX* context = NULL;
    SSL* tls = NULL;
    char input[4];
    int ok = 0;

    context = SSL_CTX_new(TLS_server_method());
    if (!context)
        goto out;
    if (SSL_CTX_use_certificate(context, cert) != 1 || SSL_CTX_use_PrivateKey(context, key) != 1)
        goto out;
    tls = SSL_new(context);
    if (!tls)
        goto out;
    if (SSL_set_fd(tls, fd) != 1)
        goto out;
    if (SSL_accept(tls) != 1)
        goto out;
    if (SSL_read(tls, input, sizeof(input)) != (int)sizeof(input))
        goto out;
    if (memcmp(input, "ping", 4) != 0)
        goto out;
    if (SSL_write(tls, "pong", 4) != 4)
        goto out;
    ok = 1;

out:
    if (tls)
    {
        SSL_set_quiet_shutdown(tls, 1);
        (void)SSL_shutdown(tls);
        SSL_free(tls);
    }
    if (context)
        SSL_CTX_free(context);
    close(fd);
    return ok;
}

int test_transport(void)
{
    int pair[2] = {-1, -1};
    int tls_pair[2] = {-1, -1};
    int child_status = 0;
    pid_t child = -1;
    EVP_PKEY* key = NULL;
    X509* cert = NULL;
    rdp_transport transport;
    char data[8];
    size_t got = 0;
    rdp_buffer packet;
    rdp_buffer wire;
    rdp_buffer tls_public_key;
    const uint8_t payload[] = {0xaa, 0xbb, 0xcc};
    unsigned char* expected_public_key = NULL;
    unsigned char* expected_public_key_ptr = NULL;
    int expected_public_key_len = 0;

    rdp_transport_init(&transport);
    rdp_buffer_init(&packet);
    rdp_buffer_init(&wire);
    rdp_buffer_init(&tls_public_key);

    TCHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    rdp_transport_attach_fd(&transport, pair[0], 1);

    TCHECK(rdp_transport_wait(&transport, 0, POLLIN, NULL) == LIBRDP_STATUS_TIMEOUT);
    TCHECK(write(pair[1], "abc", 3) == 3);
    TCHECK(rdp_transport_wait(&transport, 1000, POLLIN, NULL) == LIBRDP_STATUS_OK);
    TCHECK(rdp_transport_peek(&transport, data, 2, &got) == LIBRDP_STATUS_OK);
    TCHECK(got == 2 && memcmp(data, "ab", 2) == 0);
    TCHECK(rdp_transport_read_exact(&transport, data, 3) == LIBRDP_STATUS_OK);
    TCHECK(memcmp(data, "abc", 3) == 0);

    TCHECK(rdp_transport_write_all(&transport, "xy", 2) == LIBRDP_STATUS_OK);
    TCHECK(read(pair[1], data, sizeof(data)) == 2);
    TCHECK(memcmp(data, "xy", 2) == 0);

    TCHECK(rdp_tpkt_write(&wire, payload, sizeof(payload)) == LIBRDP_STATUS_OK);
    TCHECK(write(pair[1], wire.data, wire.length) == (ssize_t)wire.length);
    TCHECK(rdp_transport_read_tpkt(&transport, &packet) == LIBRDP_STATUS_OK);
    TCHECK(packet.length == wire.length);
    TCHECK(memcmp(packet.data, wire.data, wire.length) == 0);

    shutdown(pair[1], SHUT_RDWR);
    close(pair[1]);
    pair[1] = -1;
    TCHECK(rdp_transport_read(&transport, data, 1, &got) == LIBRDP_STATUS_CLOSED);

    rdp_buffer_free(&wire);
    rdp_buffer_free(&packet);
    rdp_transport_close(&transport);

    rdp_transport_init(&transport);
    TCHECK(make_test_certificate(&key, &cert));
    TCHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, tls_pair) == 0);
    child = fork();
    TCHECK(child >= 0);
    if (child == 0)
    {
        close(tls_pair[0]);
        _exit(run_tls_server(tls_pair[1], key, cert) ? 0 : 1);
    }
    close(tls_pair[1]);
    tls_pair[1] = -1;
    rdp_transport_attach_fd(&transport, tls_pair[0], 1);
    tls_pair[0] = -1;
    TCHECK(rdp_transport_start_tls(&transport, "localhost") == LIBRDP_STATUS_OK);
    TCHECK(rdp_transport_get_tls_public_key(&transport, &tls_public_key) == LIBRDP_STATUS_OK);
    expected_public_key_len = i2d_PublicKey(key, NULL);
    TCHECK(expected_public_key_len > 0);
    expected_public_key = (unsigned char*)malloc((size_t)expected_public_key_len);
    TCHECK(expected_public_key != NULL);
    expected_public_key_ptr = expected_public_key;
    TCHECK(i2d_PublicKey(key, &expected_public_key_ptr) == expected_public_key_len);
    TCHECK(tls_public_key.length == (size_t)expected_public_key_len);
    TCHECK(memcmp(tls_public_key.data, expected_public_key, tls_public_key.length) == 0);
    TCHECK(rdp_transport_write_all(&transport, "ping", 4) == LIBRDP_STATUS_OK);
    TCHECK(rdp_transport_read_exact(&transport, data, 4) == LIBRDP_STATUS_OK);
    TCHECK(memcmp(data, "pong", 4) == 0);
    rdp_transport_close(&transport);
    TCHECK(waitpid(child, &child_status, 0) == child);
    TCHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);

    X509_free(cert);
    EVP_PKEY_free(key);
    free(expected_public_key);
    rdp_buffer_free(&tls_public_key);
    return 0;
}
