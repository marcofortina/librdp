/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: transport abstraction combining TCP, TLS, buffering, wait, and
 * trace-visible I/O semantics.
 * Invariants: file descriptors, TLS state, and buffered bytes are updated only
 * after successful system calls.
 * Ownership: transport reads and writes preserve record ordering and never
 * expose stale plaintext after failure.
 * Threading: not internally synchronized; callers must serialize access
 * through the owning session or transport.
 * Trust boundary: external input is treated as untrusted until validated by
 * this module or its caller.
 */


#include "transport/transport.h"

#include "common/trace.h"
#include "platform/socket.h"
#include "protocol/tpkt.h"
#include "transport/tcp.h"

#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifdef RDP_HAVE_CURL
#include <curl/curl.h>
#endif

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define RDP_TRANSPORT_TLS_DEFAULT_TIMEOUT_MS 5000

void rdp_transport_init(rdp_transport* transport)
{
    if (!transport)
        return;
    transport->fd = -1;
    transport->owns_fd = 0;
    transport->tls_context = NULL;
    transport->tls = NULL;
    transport->tls_active = 0;
    transport->curl_easy = NULL;
    transport->curl_active = 0;
    transport->curl_socket = -1;
    transport->backend_context = NULL;
    transport->backend_ops = NULL;
}

void rdp_transport_attach_fd(rdp_transport* transport, int fd, int owns_fd)
{
    if (!transport)
        return;
    rdp_transport_close(transport);
    transport->fd = fd;
    transport->owns_fd = owns_fd;
}

void rdp_transport_attach_curl_easy(rdp_transport* transport, void* curl_easy, int fd)
{
    if (!transport)
        return;
    rdp_transport_close(transport);
    transport->fd = fd;
    transport->owns_fd = 0;
    transport->curl_easy = curl_easy;
    transport->curl_active = curl_easy ? 1 : 0;
    transport->curl_socket = fd;
}

/*
 * Hand ownership of all I/O callbacks to a tunnel backend. Gateway transports
 * use this path so the protocol core can keep the same read/write/wait calls
 * without learning about HTTP streams or worker wakeups.
 */
void rdp_transport_attach_backend(rdp_transport* transport,
                                  void* context,
                                  const rdp_transport_backend_ops* ops)
{
    if (!transport)
        return;
    rdp_transport_close(transport);
    transport->backend_context = context;
    transport->backend_ops = ops;
    transport->fd =
        ops && ops->poll_fd ? ops->poll_fd(context) : -1;
    transport->owns_fd = 0;
}

librdp_status rdp_transport_connect(rdp_transport* transport, const char* host, uint16_t port, int timeout_ms)
{
    int fd = -1;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!transport)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_tcp_connect(host, port, timeout_ms, &fd);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_transport_attach_fd(transport, fd, 1);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_transport_tls_status(SSL* tls, int rc)
{
    int error = SSL_get_error(tls, rc);

    if (error == SSL_ERROR_ZERO_RETURN)
        return LIBRDP_STATUS_CLOSED;
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
        return LIBRDP_STATUS_AGAIN;
    return LIBRDP_STATUS_IO_ERROR;
}

/*
 * Adapt an arbitrary transport backend to OpenSSL without exposing the
 * backend's event pipe as a byte stream. Retry flags preserve OpenSSL's
 * non-blocking handshake semantics; the owning transport remains alive until
 * SSL has released both BIOs.
 */
static int rdp_transport_backend_bio_create(BIO* bio)
{
    if (!bio)
        return 0;
    BIO_set_data(bio, NULL);
    BIO_set_init(bio, 1);
    return 1;
}

static int rdp_transport_backend_bio_destroy(BIO* bio)
{
    if (!bio)
        return 0;
    BIO_set_data(bio, NULL);
    BIO_set_init(bio, 0);
    return 1;
}

static int rdp_transport_backend_bio_read(BIO* bio, char* data, int length)
{
    rdp_transport* transport = NULL;
    size_t read_len = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!bio || !data || length <= 0)
        return 0;
    transport = (rdp_transport*)BIO_get_data(bio);
    if (!transport || !transport->backend_ops ||
        !transport->backend_ops->read)
        return -1;
    BIO_clear_retry_flags(bio);
    status = transport->backend_ops->read(transport->backend_context,
                                          data,
                                          (size_t)length,
                                          &read_len);
    if (status == LIBRDP_STATUS_OK)
        return read_len > (size_t)INT_MAX ? -1 : (int)read_len;
    if (status == LIBRDP_STATUS_AGAIN)
    {
        BIO_set_retry_read(bio);
        return -1;
    }
    if (status == LIBRDP_STATUS_CLOSED)
        return 0;
    errno = EIO;
    return -1;
}

static int rdp_transport_backend_bio_write(BIO* bio,
                                           const char* data,
                                           int length)
{
    rdp_transport* transport = NULL;
    size_t written_len = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!bio || !data || length <= 0)
        return 0;
    transport = (rdp_transport*)BIO_get_data(bio);
    if (!transport || !transport->backend_ops ||
        !transport->backend_ops->write)
        return -1;
    BIO_clear_retry_flags(bio);
    status = transport->backend_ops->write(transport->backend_context,
                                           data,
                                           (size_t)length,
                                           &written_len);
    if (status == LIBRDP_STATUS_OK)
        return written_len > (size_t)INT_MAX ? -1 : (int)written_len;
    if (status == LIBRDP_STATUS_AGAIN)
    {
        BIO_set_retry_write(bio);
        return -1;
    }
    errno = status == LIBRDP_STATUS_CLOSED ? EPIPE : EIO;
    return -1;
}

static long rdp_transport_backend_bio_control(BIO* bio,
                                              int command,
                                              long argument,
                                              void* pointer)
{
    (void)bio;
    (void)argument;
    (void)pointer;

    if (command == BIO_CTRL_FLUSH || command == BIO_CTRL_DUP)
        return 1;
    return 0;
}

static pthread_once_t rdp_transport_backend_bio_once =
    PTHREAD_ONCE_INIT;
static BIO_METHOD* rdp_transport_backend_bio_method = NULL;

static void rdp_transport_backend_bio_method_init(void)
{
    BIO_METHOD* method = BIO_meth_new(
        BIO_TYPE_SOURCE_SINK | BIO_get_new_index(),
        "librdp transport backend");

    if (!method ||
        BIO_meth_set_create(method,
                            rdp_transport_backend_bio_create) != 1 ||
        BIO_meth_set_destroy(method,
                             rdp_transport_backend_bio_destroy) != 1 ||
        BIO_meth_set_read(method,
                          rdp_transport_backend_bio_read) != 1 ||
        BIO_meth_set_write(method,
                           rdp_transport_backend_bio_write) != 1 ||
        BIO_meth_set_ctrl(method,
                          rdp_transport_backend_bio_control) != 1)
    {
        BIO_meth_free(method);
        return;
    }
    rdp_transport_backend_bio_method = method;
}

static BIO* rdp_transport_backend_bio_new(rdp_transport* transport)
{
    BIO* bio = NULL;

    if (!transport || !transport->backend_ops)
        return NULL;
    if (pthread_once(&rdp_transport_backend_bio_once,
                     rdp_transport_backend_bio_method_init) != 0 ||
        !rdp_transport_backend_bio_method)
        return NULL;
    bio = BIO_new(rdp_transport_backend_bio_method);
    if (!bio)
        return NULL;
    BIO_set_data(bio, transport);
    BIO_set_init(bio, 1);
    return bio;
}

static uint64_t rdp_transport_now_ns(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return 0;
    return ((uint64_t)value.tv_sec * 1000000000u) + (uint64_t)value.tv_nsec;
}

librdp_status rdp_transport_deadline_create(int timeout_ms, uint64_t* deadline_ns)
{
    uint64_t now_ns = 0;
    uint64_t interval_ns = 0;

    if (timeout_ms < 0 || !deadline_ns)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    now_ns = rdp_transport_now_ns();
    if (now_ns == 0)
        return LIBRDP_STATUS_IO_ERROR;
    interval_ns = (uint64_t)timeout_ms * 1000000u;
    if (now_ns > UINT64_MAX - interval_ns)
        return LIBRDP_STATUS_IO_ERROR;
    *deadline_ns = now_ns + interval_ns;
    return LIBRDP_STATUS_OK;
}

static int rdp_transport_deadline_remaining_ms(uint64_t deadline_ns)
{
    uint64_t now_ns = rdp_transport_now_ns();
    uint64_t remaining_ns = 0;
    uint64_t remaining_ms = 0;

    if (now_ns == 0 || now_ns >= deadline_ns)
        return 0;
    remaining_ns = deadline_ns - now_ns;
    remaining_ms = (remaining_ns + 999999u) / 1000000u;
    return remaining_ms > (uint64_t)INT_MAX ? INT_MAX : (int)remaining_ms;
}

static librdp_status rdp_transport_begin_timed_io(rdp_transport* transport,
                                                   int* changed_nonblocking)
{
    int nonblocking = 0;

    if (!transport || !changed_nonblocking)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *changed_nonblocking = 0;
    if (transport->backend_ops || transport->curl_active)
        return LIBRDP_STATUS_OK;
    if (transport->fd < 0 ||
        rdp_socket_get_nonblocking(transport->fd, &nonblocking) != 0)
        return LIBRDP_STATUS_IO_ERROR;
    if (!nonblocking)
    {
        if (rdp_socket_set_nonblocking(transport->fd, 1) != 0)
            return LIBRDP_STATUS_IO_ERROR;
        *changed_nonblocking = 1;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_transport_end_timed_io(rdp_transport* transport,
                                                 int changed_nonblocking,
                                                 librdp_status status)
{
    if (changed_nonblocking &&
        rdp_socket_set_nonblocking(transport->fd, 0) != 0 &&
        status == LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_IO_ERROR;
    return status;
}

static librdp_status rdp_transport_wait_until(rdp_transport* transport,
                                              uint64_t deadline_ns,
                                              short events)
{
    for (;;)
    {
        int remaining_ms = rdp_transport_deadline_remaining_ms(deadline_ns);
        librdp_status status = LIBRDP_STATUS_OK;

        if (remaining_ms <= 0)
            return LIBRDP_STATUS_TIMEOUT;
        status = rdp_transport_wait(transport, remaining_ms, events, NULL);
        if (status != LIBRDP_STATUS_AGAIN)
            return status;
    }
}

/*
 * Map OpenSSL verification failures onto public status codes before any trace
 * line or caller-visible error collapses them into a generic handshake failure.
 */
static librdp_status rdp_transport_tls_verify_status(long verify_result)
{
    if (verify_result == X509_V_OK)
        return LIBRDP_STATUS_OK;
    if (verify_result == X509_V_ERR_HOSTNAME_MISMATCH)
        return LIBRDP_STATUS_TLS_HOSTNAME_MISMATCH;
    return LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
}

/*
 * Decide whether OpenSSL must enforce chain and hostname verification for the
 * selected policy. Insecure lab mode is the only policy that disables it.
 */
static int rdp_transport_tls_verify_peer_required(const rdp_transport_tls_config* config)
{
    if (!config)
        return 0;
    if (config->policy_mode == LIBRDP_TLS_POLICY_INSECURE_LAB)
        return 0;
    return config->policy_mode == LIBRDP_TLS_POLICY_STRICT || config->use_system_store ||
           config->trust_anchor != NULL;
}

/*
 * TOFU needs the handshake to complete so the application callback can inspect
 * the leaf certificate. Final accept/reject still happens after the handshake.
 */
static int rdp_transport_tls_allow_verify_callback(int preverify_ok, X509_STORE_CTX* store)
{
    (void)preverify_ok;
    (void)store;
    return 1;
}

static librdp_status rdp_transport_tls_configure_context(SSL_CTX* context,
                                                        const rdp_transport_tls_config* config)
{
    X509_STORE* store = NULL;
    int verify_peer = 0;

    if (!context || !config)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    verify_peer = rdp_transport_tls_verify_peer_required(config);
    SSL_CTX_set_verify(context,
                       verify_peer ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                       config->policy_mode == LIBRDP_TLS_POLICY_TOFU ? rdp_transport_tls_allow_verify_callback
                                                                     : NULL);
    if (config->use_system_store && SSL_CTX_set_default_verify_paths(context) != 1)
        return LIBRDP_STATUS_IO_ERROR;
    if (config->trust_anchor)
    {
        store = SSL_CTX_get_cert_store(context);
        if (!store || X509_STORE_add_cert(store, config->trust_anchor) != 1)
            return LIBRDP_STATUS_IO_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static void rdp_transport_tls_sha256_hex(const unsigned char* digest,
                                         char output[LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH + 1u])
{
    static const char hex[] = "0123456789abcdef";
    size_t i = 0;

    for (i = 0; i < 32u; i++)
    {
        output[i * 2u] = hex[(digest[i] >> 4) & 0x0fu];
        output[(i * 2u) + 1u] = hex[digest[i] & 0x0fu];
    }
    output[LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH] = '\0';
}

static librdp_status rdp_transport_tls_leaf_fingerprint(
    X509* cert,
    char output[LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH + 1u])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (!cert || !output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (X509_digest(cert, EVP_sha256(), digest, &digest_len) != 1 || digest_len != 32u)
        return LIBRDP_STATUS_IO_ERROR;
    rdp_transport_tls_sha256_hex(digest, output);
    return LIBRDP_STATUS_OK;
}

static librdp_tls_certificate_decision rdp_transport_tls_call_certificate_callback(
    const rdp_transport_tls_config* config,
    X509* cert,
    const char fingerprint[LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH + 1u],
    librdp_status verify_status,
    long verify_result)
{
    librdp_tls_certificate_info info;
    unsigned char* der = NULL;
    unsigned char* der_write = NULL;
    char* subject = NULL;
    char* issuer = NULL;
    int der_len = 0;
    librdp_tls_certificate_decision decision = LIBRDP_TLS_CERTIFICATE_DECISION_DEFAULT;

    if (!config || !config->certificate_callback || !cert)
        return LIBRDP_TLS_CERTIFICATE_DECISION_DEFAULT;

    der_len = i2d_X509(cert, NULL);
    if (der_len <= 0)
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
    der = (unsigned char*)OPENSSL_malloc((size_t)der_len);
    if (!der)
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
    der_write = der;
    if (i2d_X509(cert, &der_write) != der_len)
    {
        OPENSSL_free(der);
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
    }

    subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    memset(&info, 0, sizeof(info));
    info.version = LIBRDP_TLS_CERTIFICATE_INFO_VERSION;
    info.size = (uint32_t)sizeof(info);
    info.host = config->host;
    info.der = der;
    info.der_len = (size_t)der_len;
    memcpy(info.sha256_fingerprint, fingerprint, LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH + 1u);
    info.subject = subject;
    info.issuer = issuer;
    info.verify_status = verify_status;
    info.native_verify_result = verify_result;
    decision = config->certificate_callback(&info, config->certificate_callback_user_data);
    OPENSSL_free(subject);
    OPENSSL_free(issuer);
    OPENSSL_free(der);
    if (decision != LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT &&
        decision != LIBRDP_TLS_CERTIFICATE_DECISION_REJECT)
        return LIBRDP_TLS_CERTIFICATE_DECISION_DEFAULT;
    return decision;
}

/*
 * Apply the configured certificate policy after TLS has produced the peer
 * certificate. Callback ACCEPT is intentionally limited to TOFU so strict and
 * pinned policies cannot be silently weakened by application code.
 */
static librdp_status rdp_transport_tls_evaluate_certificate(SSL* tls,
                                                            const rdp_transport_tls_config* config,
                                                            long verify_result)
{
    X509* cert = NULL;
    char fingerprint[LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH + 1u];
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_status verify_status = rdp_transport_tls_verify_status(verify_result);
    librdp_tls_certificate_decision decision = LIBRDP_TLS_CERTIFICATE_DECISION_DEFAULT;

    if (!tls || !config)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    cert = SSL_get1_peer_certificate(tls);
    if (!cert)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_transport_tls_leaf_fingerprint(cert, fingerprint);
    if (status != LIBRDP_STATUS_OK)
    {
        X509_free(cert);
        return status;
    }
    decision = rdp_transport_tls_call_certificate_callback(config, cert, fingerprint, verify_status, verify_result);
    X509_free(cert);
    if (decision == LIBRDP_TLS_CERTIFICATE_DECISION_REJECT)
        return LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;

    if (config->policy_mode == LIBRDP_TLS_POLICY_INSECURE_LAB)
    {
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_WARN,
                              "transport.tls.insecure_lab.warning",
                              "host=%s verification=disabled",
                              config->host);
        return LIBRDP_STATUS_OK;
    }
    if (config->policy_mode == LIBRDP_TLS_POLICY_STRICT)
        return verify_status;
    if (config->policy_mode == LIBRDP_TLS_POLICY_PINNED_FINGERPRINT)
    {
        if (!config->pinned_sha256 ||
            strcmp(config->pinned_sha256, fingerprint) != 0)
            return LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
        if (rdp_transport_tls_verify_peer_required(config) && verify_status != LIBRDP_STATUS_OK)
            return verify_status;
        return LIBRDP_STATUS_OK;
    }
    if (config->policy_mode == LIBRDP_TLS_POLICY_TOFU)
    {
        if (rdp_transport_tls_verify_peer_required(config) && verify_status == LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_OK;
        return decision == LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT ? LIBRDP_STATUS_OK
                                                                  : LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
    }
    return LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status rdp_transport_tls_configure_hostname(SSL* tls, const char* host)
{
    X509_VERIFY_PARAM* verify_param = NULL;

    if (!tls || !host || host[0] == '\0')
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    verify_param = SSL_get0_param(tls);
    if (!verify_param)
        return LIBRDP_STATUS_IO_ERROR;
    X509_VERIFY_PARAM_set_hostflags(verify_param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (X509_VERIFY_PARAM_set1_host(verify_param, host, 0) != 1)
        return LIBRDP_STATUS_IO_ERROR;
    if (SSL_set_tlsext_host_name(tls, host) != 1)
        return LIBRDP_STATUS_IO_ERROR;
    return LIBRDP_STATUS_OK;
}

/*
 * Start TLS with strict peer verification. The handshake is not committed to
 * the transport until context setup, trust anchors, hostname verification, and
 * certificate validation all succeed; failures keep the TCP transport intact
 * and preserve distinct status codes for certificate rejection, hostname
 * mismatch, and non-certificate handshake errors.
 */
librdp_status rdp_transport_start_tls_with_config(rdp_transport* transport, const rdp_transport_tls_config* config)
{
    SSL_CTX* context = NULL;
    SSL* tls = NULL;
    BIO* read_bio = NULL;
    BIO* write_bio = NULL;
    int rc = 0;
    int changed_nonblocking = 0;
    int timeout_ms = RDP_TRANSPORT_TLS_DEFAULT_TIMEOUT_MS;
    uint64_t deadline_ns = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    long verify_result = X509_V_OK;

    if (!transport ||
        (transport->fd < 0 && !transport->backend_ops) ||
        !config || !config->host || config->host[0] == '\0' ||
        config->timeout_ms < 0 || transport->tls_active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (config->timeout_ms > 0)
        timeout_ms = config->timeout_ms;

    rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.tls.connect.start", "host=%s", config->host);
    context = SSL_CTX_new(TLS_client_method());
    if (!context)
        return LIBRDP_STATUS_IO_ERROR;
    status = rdp_transport_tls_configure_context(context, config);
    if (status != LIBRDP_STATUS_OK)
    {
        SSL_CTX_free(context);
        ERR_clear_error();
        return status;
    }
    tls = SSL_new(context);
    if (!tls)
    {
        SSL_CTX_free(context);
        return LIBRDP_STATUS_IO_ERROR;
    }
    if (transport->backend_ops)
    {
        read_bio = rdp_transport_backend_bio_new(transport);
        write_bio = rdp_transport_backend_bio_new(transport);
        if (!read_bio || !write_bio)
        {
            BIO_free(read_bio);
            BIO_free(write_bio);
            SSL_free(tls);
            SSL_CTX_free(context);
            return LIBRDP_STATUS_NO_MEMORY;
        }
        SSL_set0_rbio(tls, read_bio);
        SSL_set0_wbio(tls, write_bio);
        read_bio = NULL;
        write_bio = NULL;
    }
    else if (SSL_set_fd(tls, transport->fd) != 1)
    {
        SSL_free(tls);
        SSL_CTX_free(context);
        return LIBRDP_STATUS_IO_ERROR;
    }
    if (rdp_transport_tls_verify_peer_required(config))
    {
        status = rdp_transport_tls_configure_hostname(tls, config->host);
        if (status != LIBRDP_STATUS_OK)
        {
            SSL_free(tls);
            SSL_CTX_free(context);
            ERR_clear_error();
            return status;
        }
    }

    status = rdp_transport_begin_timed_io(transport, &changed_nonblocking);
    if (status != LIBRDP_STATUS_OK)
        goto handshake_failed;
    status = rdp_transport_deadline_create(timeout_ms, &deadline_ns);
    if (status != LIBRDP_STATUS_OK)
        goto handshake_failed;
    for (;;)
    {
        int tls_error = SSL_ERROR_NONE;

        rc = SSL_connect(tls);
        if (rc == 1)
            break;
        tls_error = SSL_get_error(tls, rc);
        if (tls_error == SSL_ERROR_WANT_READ || tls_error == SSL_ERROR_WANT_WRITE)
        {
            status = rdp_transport_wait_until(transport,
                                              deadline_ns,
                                              tls_error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT);
            if (status == LIBRDP_STATUS_OK)
                continue;
        }
        else if (tls_error == SSL_ERROR_ZERO_RETURN)
            status = LIBRDP_STATUS_CLOSED;
        else
            status = LIBRDP_STATUS_TLS_HANDSHAKE_FAILED;
        goto handshake_failed;
    }
    status = rdp_transport_end_timed_io(transport, changed_nonblocking, LIBRDP_STATUS_OK);
    changed_nonblocking = 0;
    if (status != LIBRDP_STATUS_OK)
        goto handshake_failed;
    verify_result = SSL_get_verify_result(tls);
    status = rdp_transport_tls_evaluate_certificate(tls, config, verify_result);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_TRANSPORT,
                        "transport.tls.verify.failed",
                        "status=%s verify_result=%ld",
                        librdp_status_string(status),
                        verify_result);
        SSL_free(tls);
        SSL_CTX_free(context);
        ERR_clear_error();
        return status;
    }

    transport->tls_context = context;
    transport->tls = tls;
    transport->tls_active = 1;
    rdp_trace_event(RDP_TRACE_TRANSPORT,
                    "transport.tls.connect.done",
                    "version=%s cipher=%s",
                    SSL_get_version(tls),
                    SSL_get_cipher(tls));
    return LIBRDP_STATUS_OK;

handshake_failed:
    status = rdp_transport_end_timed_io(transport, changed_nonblocking, status);
    verify_result = SSL_get_verify_result(tls);
    if (status != LIBRDP_STATUS_TIMEOUT && status != LIBRDP_STATUS_CLOSED)
    {
        librdp_status verify_status = rdp_transport_tls_verify_status(verify_result);

        if (verify_status != LIBRDP_STATUS_OK)
            status = verify_status;
        else if (status == LIBRDP_STATUS_IO_ERROR)
            status = LIBRDP_STATUS_TLS_HANDSHAKE_FAILED;
    }
    rdp_trace_event(RDP_TRACE_TRANSPORT,
                    "transport.tls.connect.failed",
                    "status=%s verify_result=%ld",
                    librdp_status_string(status),
                    verify_result);
    SSL_free(tls);
    SSL_CTX_free(context);
    ERR_clear_error();
    return status;
}

librdp_status rdp_transport_start_tls(rdp_transport* transport, const char* host)
{
    rdp_transport_tls_config config;

    memset(&config, 0, sizeof(config));
    config.host = host;
    config.timeout_ms = RDP_TRANSPORT_TLS_DEFAULT_TIMEOUT_MS;
    config.use_system_store = 1;
    config.policy_mode = LIBRDP_TLS_POLICY_STRICT;
    return rdp_transport_start_tls_with_config(transport, &config);
}

librdp_status rdp_transport_get_tls_public_key(rdp_transport* transport, rdp_buffer* public_key)
{
    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;
    unsigned char* out = NULL;
    int length = 0;
    int written = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!transport || !transport->tls_active || !transport->tls || !public_key)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    cert = SSL_get1_peer_certificate(transport->tls);
    if (!cert)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    pkey = X509_get_pubkey(cert);
    if (!pkey)
    {
        X509_free(cert);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }

    length = i2d_PublicKey(pkey, NULL);
    if (length <= 0)
    {
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto out;
    }
    status = rdp_buffer_reserve(public_key, (size_t)length);
    if (status != LIBRDP_STATUS_OK)
        goto out;
    out = public_key->data;
    written = i2d_PublicKey(pkey, &out);
    if (written != length)
    {
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto out;
    }
    public_key->length = (size_t)written;
    rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.tls.public_key", "length=%u", (unsigned)public_key->length);

out:
    EVP_PKEY_free(pkey);
    X509_free(cert);
    return status;
}

librdp_status rdp_transport_wait(rdp_transport* transport, int timeout_ms, short events, short* revents)
{
    struct pollfd pfd;
    int rc = 0;

    if (!transport || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (transport->backend_ops && transport->backend_ops->wait)
        return transport->backend_ops->wait(transport->backend_context, timeout_ms, events, revents);
    if (transport->fd < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    pfd.fd = transport->fd;
    pfd.events = events;
    pfd.revents = 0;

    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.tcp.wait.start",
                          "timeout_ms=%d events=%d",
                          timeout_ms,
                          (int)events);
    rc = poll(&pfd, 1, timeout_ms);
    if (rc == 0)
    {
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.tcp.timeout",
                              "timeout_ms=%d",
                              timeout_ms);
        return LIBRDP_STATUS_TIMEOUT;
    }
    if (rc < 0)
        return errno == EINTR ? LIBRDP_STATUS_AGAIN : LIBRDP_STATUS_IO_ERROR;

    if (revents)
        *revents = pfd.revents;
    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.tcp.wait.done",
                          "revents=%d",
                          (int)pfd.revents);
    return LIBRDP_STATUS_OK;
}

/*
 * Peek at pending transport bytes without consuming them. The curl gateway path
 * uses the active socket directly because curl's receive API has no
 * non-destructive peek; direct TCP and TLS keep their native peek semantics.
 * All paths return AGAIN for transient readiness races and never modify caller
 * buffers after protocol-level EOF.
 */
librdp_status rdp_transport_peek(rdp_transport* transport, void* data, size_t length, size_t* read_len)
{
    ssize_t rc = 0;

    if (!transport || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (transport->tls_active)
    {
        int tls_rc = 0;
        if (length > INT_MAX)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.tls.peek.start",
                              "length=%llu",
                              (unsigned long long)length);
        tls_rc = SSL_peek(transport->tls, data, (int)length);
        if (tls_rc <= 0)
            return rdp_transport_tls_status(transport->tls, tls_rc);
        if (read_len)
            *read_len = (size_t)tls_rc;
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.tls.peek.done",
                              "read=%d",
                              tls_rc);
        return LIBRDP_STATUS_OK;
    }
    if (transport->backend_ops && transport->backend_ops->peek)
        return transport->backend_ops->peek(
            transport->backend_context,
            data,
            length,
            read_len);
    if (transport->fd < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

#ifdef RDP_HAVE_CURL
    if (transport->curl_active)
    {
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.gateway.peek.start",
                              "length=%llu",
                              (unsigned long long)length);
        rc = recv(transport->fd, data, length, MSG_PEEK);
        if (rc == 0)
        {
            rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.gateway.eof", "length=0");
            return LIBRDP_STATUS_CLOSED;
        }
        if (rc < 0)
        {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                return LIBRDP_STATUS_AGAIN;
            return LIBRDP_STATUS_IO_ERROR;
        }
        if (read_len)
            *read_len = (size_t)rc;
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.gateway.peek.done",
                              "read=%llu",
                              (unsigned long long)rc);
        return LIBRDP_STATUS_OK;
    }
#endif

    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.tcp.peek.start",
                          "length=%llu",
                          (unsigned long long)length);
    rc = recv(transport->fd, data, length, MSG_PEEK);
    if (rc == 0)
    {
        rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.tcp.eof", "length=0");
        return LIBRDP_STATUS_CLOSED;
    }
    if (rc < 0)
    {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return LIBRDP_STATUS_AGAIN;
        return LIBRDP_STATUS_IO_ERROR;
    }

    if (read_len)
        *read_len = (size_t)rc;
    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.tcp.peek.done",
                          "read=%llu",
                          (unsigned long long)rc);
    return LIBRDP_STATUS_OK;
}

/*
 * Read bytes from the active transport backend. The function normalizes TCP,
 * TLS, and curl tunnel retry behavior into librdp_status values while preserving
 * ownership of the underlying handle inside rdp_transport. EOF is reported as a
 * closed transport before any caller state is committed.
 */
librdp_status rdp_transport_read(rdp_transport* transport, void* data, size_t length, size_t* read_len)
{
    ssize_t rc = 0;

    if (!transport || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (transport->tls_active)
    {
        int tls_rc = 0;
        if (length > INT_MAX)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.tls.read.start",
                              "length=%llu",
                              (unsigned long long)length);
        tls_rc = SSL_read(transport->tls, data, (int)length);
        if (tls_rc <= 0)
            return rdp_transport_tls_status(transport->tls, tls_rc);
        if (read_len)
            *read_len = (size_t)tls_rc;
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.tls.read.done",
                              "read=%d",
                              tls_rc);
        return LIBRDP_STATUS_OK;
    }
    if (transport->backend_ops && transport->backend_ops->read)
        return transport->backend_ops->read(
            transport->backend_context,
            data,
            length,
            read_len);
    if (transport->fd < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

#ifdef RDP_HAVE_CURL
    if (transport->curl_active)
    {
        CURLcode code = CURLE_OK;
        size_t curl_read = 0;

        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.gateway.read.start",
                              "length=%llu",
                              (unsigned long long)length);
        code = curl_easy_recv((CURL*)transport->curl_easy, data, length, &curl_read);
        if (code == CURLE_AGAIN)
            return LIBRDP_STATUS_AGAIN;
        if (code != CURLE_OK)
            return LIBRDP_STATUS_IO_ERROR;
        if (curl_read == 0 && length > 0)
        {
            rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.gateway.eof", "length=0");
            return LIBRDP_STATUS_CLOSED;
        }
        if (read_len)
            *read_len = curl_read;
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.gateway.read.done",
                              "read=%llu",
                              (unsigned long long)curl_read);
        return LIBRDP_STATUS_OK;
    }
#endif

    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.tcp.read.start",
                          "length=%llu",
                          (unsigned long long)length);
    rc = recv(transport->fd, data, length, 0);
    if (rc == 0)
    {
        rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.tcp.eof", "length=0");
        return LIBRDP_STATUS_CLOSED;
    }
    if (rc < 0)
    {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return LIBRDP_STATUS_AGAIN;
        return LIBRDP_STATUS_IO_ERROR;
    }

    if (read_len)
        *read_len = (size_t)rc;
    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.tcp.read.done",
                          "read=%llu",
                          (unsigned long long)rc);
    return LIBRDP_STATUS_OK;
}

/*
 * Write bytes to the active transport backend. TCP uses MSG_NOSIGNAL when
 * available, TLS delegates record handling to OpenSSL, and gateway traffic uses
 * curl's connected socket wrapper. Partial writes are reported through
 * written_len so higher layers can keep wire ordering explicit.
 */
librdp_status rdp_transport_write(rdp_transport* transport, const void* data, size_t length, size_t* written_len)
{
    ssize_t rc = 0;
    int flags = 0;

    if (!transport || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#endif
    if (transport->tls_active)
    {
        int tls_rc = 0;
        if (length > INT_MAX)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.tls.write.start",
                              "length=%llu",
                              (unsigned long long)length);
        tls_rc = SSL_write(transport->tls, data, (int)length);
        if (tls_rc <= 0)
            return rdp_transport_tls_status(transport->tls, tls_rc);
        if (written_len)
            *written_len = (size_t)tls_rc;
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.tls.write.done",
                              "written=%d",
                              tls_rc);
        return LIBRDP_STATUS_OK;
    }
    if (transport->backend_ops && transport->backend_ops->write)
        return transport->backend_ops->write(
            transport->backend_context,
            data,
            length,
            written_len);
    if (transport->fd < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

#ifdef RDP_HAVE_CURL
    if (transport->curl_active)
    {
        CURLcode code = CURLE_OK;
        size_t curl_written = 0;

        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.gateway.write.start",
                              "length=%llu",
                              (unsigned long long)length);
        code = curl_easy_send((CURL*)transport->curl_easy, data, length, &curl_written);
        if (code == CURLE_AGAIN)
            return LIBRDP_STATUS_AGAIN;
        if (code != CURLE_OK)
            return LIBRDP_STATUS_IO_ERROR;
        if (written_len)
            *written_len = curl_written;
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.gateway.write.done",
                              "written=%llu",
                              (unsigned long long)curl_written);
        return LIBRDP_STATUS_OK;
    }
#endif

    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.tcp.write.start",
                          "length=%llu",
                          (unsigned long long)length);
    rc = send(transport->fd, data, length, flags);
    if (rc < 0)
    {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return LIBRDP_STATUS_AGAIN;
        return LIBRDP_STATUS_IO_ERROR;
    }

    if (written_len)
        *written_len = (size_t)rc;
    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.tcp.write.done",
                          "written=%llu",
                          (unsigned long long)rc);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_transport_read_exact(rdp_transport* transport, void* data, size_t length)
{
    uint8_t* out = (uint8_t*)data;
    size_t offset = 0;

    while (offset < length)
    {
        size_t got = 0;
        librdp_status status = rdp_transport_read(transport, out + offset, length - offset, &got);
        if (status != LIBRDP_STATUS_OK)
            return status;
        offset += got;
    }

    return LIBRDP_STATUS_OK;
}

librdp_status rdp_transport_read_exact_until(rdp_transport* transport,
                                             void* data,
                                             size_t length,
                                             uint64_t deadline_ns)
{
    uint8_t* out = (uint8_t*)data;
    size_t offset = 0;
    int changed_nonblocking = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!transport || (!data && length > 0) || deadline_ns == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length == 0)
        return LIBRDP_STATUS_OK;
    status = rdp_transport_begin_timed_io(transport, &changed_nonblocking);
    if (status != LIBRDP_STATUS_OK)
        return status;
    while (offset < length)
    {
        size_t got = 0;

        status = rdp_transport_read(transport, out + offset, length - offset, &got);
        if (status == LIBRDP_STATUS_OK)
        {
            if (got == 0)
            {
                status = LIBRDP_STATUS_CLOSED;
                break;
            }
            offset += got;
            continue;
        }
        if (status != LIBRDP_STATUS_AGAIN)
            break;
        status = rdp_transport_wait_until(transport, deadline_ns, POLLIN);
        if (status != LIBRDP_STATUS_OK)
            break;
    }
    return rdp_transport_end_timed_io(transport, changed_nonblocking, status);
}

librdp_status rdp_transport_read_exact_timeout(rdp_transport* transport,
                                               void* data,
                                               size_t length,
                                               int timeout_ms)
{
    uint64_t deadline_ns = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!transport || (!data && length > 0) || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length == 0)
        return LIBRDP_STATUS_OK;
    status = rdp_transport_deadline_create(timeout_ms, &deadline_ns);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_transport_read_exact_until(transport, data, length, deadline_ns);
}

librdp_status rdp_transport_write_all(rdp_transport* transport, const void* data, size_t length)
{
    const uint8_t* in = (const uint8_t*)data;
    size_t offset = 0;

    while (offset < length)
    {
        size_t wrote = 0;
        librdp_status status = rdp_transport_write(transport, in + offset, length - offset, &wrote);
        if (status != LIBRDP_STATUS_OK)
            return status;
        offset += wrote;
    }

    return LIBRDP_STATUS_OK;
}

librdp_status rdp_transport_read_tpkt(rdp_transport* transport, rdp_buffer* packet)
{
    uint8_t header[4];
    uint16_t total = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!transport || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_free(packet);
    rdp_buffer_init(packet);

    status = rdp_transport_read_exact(transport, header, sizeof(header));
    if (status != LIBRDP_STATUS_OK)
        return status;

    total = (uint16_t)(((uint16_t)header[2] << 8) | header[3]);
    if (header[0] != 3 || header[1] != 0 || total < 4)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    status = rdp_buffer_append(packet, header, sizeof(header));
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_reserve(packet, total);
    if (status != LIBRDP_STATUS_OK)
        return status;
    packet->length = total;
    return rdp_transport_read_exact(transport, packet->data + 4, (size_t)total - 4u);
}

librdp_status rdp_transport_read_tpkt_timeout(rdp_transport* transport,
                                              rdp_buffer* packet,
                                              int timeout_ms)
{
    uint8_t header[4];
    uint16_t total = 0;
    uint64_t deadline_ns = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!transport || !packet || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_free(packet);
    rdp_buffer_init(packet);
    status = rdp_transport_deadline_create(timeout_ms, &deadline_ns);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_transport_read_exact_until(transport, header, sizeof(header), deadline_ns);
    if (status != LIBRDP_STATUS_OK)
        return status;
    total = (uint16_t)(((uint16_t)header[2] << 8) | header[3]);
    if (header[0] != 3 || header[1] != 0 || total < 4)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_buffer_append(packet, header, sizeof(header));
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_reserve(packet, total);
    if (status != LIBRDP_STATUS_OK)
        return status;
    packet->length = total;
    status = rdp_transport_read_exact_until(transport,
                                            packet->data + 4,
                                            (size_t)total - 4u,
                                            deadline_ns);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(packet);
        rdp_buffer_init(packet);
    }
    return status;
}

void rdp_transport_close(rdp_transport* transport)
{
    if (!transport)
        return;
    if (transport->tls)
    {
        SSL_set_quiet_shutdown(transport->tls, 1);
        (void)SSL_shutdown(transport->tls);
        SSL_free(transport->tls);
    }
    if (transport->tls_context)
        SSL_CTX_free(transport->tls_context);
    transport->tls = NULL;
    transport->tls_context = NULL;
    transport->tls_active = 0;
    if (transport->backend_ops && transport->backend_ops->close)
        transport->backend_ops->close(transport->backend_context);
    transport->backend_context = NULL;
    transport->backend_ops = NULL;
#ifdef RDP_HAVE_CURL
    if (transport->curl_easy)
        curl_easy_cleanup((CURL*)transport->curl_easy);
#endif
    transport->curl_easy = NULL;
    transport->curl_active = 0;
    transport->curl_socket = -1;
    if (transport->fd >= 0 && transport->owns_fd)
        rdp_socket_close(transport->fd);
    transport->fd = -1;
    transport->owns_fd = 0;
}
