/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: server transport I/O, TLS, Standard Security, and CredSSP/NLA.
 * Invariants: state transitions and wire behavior are preserved from the
 * server orchestrator; cross-domain calls use private module contracts.
 * Ownership: server and peer objects own retained state; input payloads are
 * borrowed for the duration of each call.
 * Threading: callers serialize access to each listener and peer.
 * Trust boundary: remote protocol data is validated before state is committed.
 */

#include "server/server_security.h"

#include "server/server_features.h"
#include "server/server_peer.h"

#include "common/buffer.h"
#include "common/charset.h"
#include "common/stream.h"
#include "common/trace.h"
#include "channels/audio_input.h"
#include "channels/audio_output.h"
#include "channels/auth_redirection.h"
#include "channels/composited_remoting.h"
#include "channels/core_input.h"
#include "channels/desktop_composition.h"
#include "channels/device_redirection.h"
#include "channels/display_control.h"
#include "channels/dynamic_channel.h"
#include "channels/echo_channel.h"
#include "channels/graphics_pipeline.h"
#include "channels/input_channel.h"
#include "channels/mouse_cursor.h"
#include "channels/multiparty.h"
#include "channels/pnp_redirection.h"
#include "channels/remote_programs.h"
#include "channels/telemetry.h"
#include "channels/usb_redirection.h"
#include "channels/video_capture.h"
#include "channels/video_optimized.h"
#include "channels/video_redirection.h"
#include "channels/webauthn_channel.h"
#include "clipboard/clipboard.h"
#include "graphics/bitmap.h"
#include "graphics/gdi_orders.h"
#include "licensing/licensing.h"
#include "nla/credssp.h"
#include "platform/socket.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"
#include "transport/udp_transport.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509err.h>
#include <ctype.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

char* rdp_server_strdup_bounded(const char* text)
{
    size_t length = 0;
    char* copy = NULL;

    if (!text)
        return NULL;
    length = strlen(text);
    if (length > RDP_SERVER_MAX_TEXT)
        return NULL;
    copy = (char*)malloc(length + 1u);
    if (!copy)
        return NULL;
    memcpy(copy, text, length + 1u);
    return copy;
}

char* rdp_server_secure_strdup_bounded(const char* text)
{
    return rdp_server_strdup_bounded(text);
}

void rdp_server_secure_free(char* text)
{
    if (!text)
        return;
    OPENSSL_cleanse(text, strlen(text));
    free(text);
}

void rdp_server_credssp_expected_clear(librdp_server_peer* peer)
{
    if (!peer)
        return;
    free(peer->credssp_expected_domain);
    free(peer->credssp_expected_username);
    rdp_server_secure_free(peer->credssp_expected_password);
    peer->credssp_expected_domain = NULL;
    peer->credssp_expected_username = NULL;
    peer->credssp_expected_password = NULL;
}

static librdp_status rdp_server_credssp_expected_set(librdp_server_peer* peer,
                                                     const char* domain,
                                                     const char* username,
                                                     const char* password)
{
    char* domain_copy = NULL;
    char* username_copy = NULL;
    char* password_copy = NULL;

    if (!peer || !username || username[0] == '\0' || !password || password[0] == '\0')
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (domain)
    {
        domain_copy = rdp_server_strdup_bounded(domain);
        if (!domain_copy)
            return LIBRDP_STATUS_NO_MEMORY;
    }
    username_copy = rdp_server_strdup_bounded(username);
    if (!username_copy)
    {
        free(domain_copy);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    password_copy = rdp_server_secure_strdup_bounded(password);
    if (!password_copy)
    {
        free(domain_copy);
        free(username_copy);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    rdp_server_credssp_expected_clear(peer);
    peer->credssp_expected_domain = domain_copy;
    peer->credssp_expected_username = username_copy;
    peer->credssp_expected_password = password_copy;
    return LIBRDP_STATUS_OK;
}

static int rdp_server_account_equal_fold(const char* left, const char* right)
{
    if (!left || !right)
        return left == right;
    while (*left && *right)
    {
        unsigned char lch = (unsigned char)*left;
        unsigned char rch = (unsigned char)*right;

        if (lch < 0x80u && rch < 0x80u)
        {
            if (toupper(lch) != toupper(rch))
                return 0;
        }
        else if (lch != rch)
            return 0;
        left++;
        right++;
    }
    return *left == '\0' && *right == '\0';
}

static int rdp_server_secret_equal(const char* left, const char* right)
{
    size_t left_len = left ? strlen(left) : 0;
    size_t right_len = right ? strlen(right) : 0;
    unsigned char diff = (unsigned char)(left_len ^ right_len);
    size_t max_len = left_len > right_len ? left_len : right_len;

    for (size_t i = 0; i < max_len; i++)
    {
        unsigned char lch = i < left_len ? (unsigned char)left[i] : 0;
        unsigned char rch = i < right_len ? (unsigned char)right[i] : 0;

        diff |= (unsigned char)(lch ^ rch);
    }
    return diff == 0;
}

static int rdp_server_tls_error_stack_has_key_mismatch(void)
{
    unsigned long error = 0;
    int mismatch = 0;

    while ((error = ERR_get_error()) != 0u)
    {
        const int reason = ERR_GET_REASON(error);

        if (reason == X509_R_KEY_VALUES_MISMATCH || reason == X509_R_KEY_TYPE_MISMATCH)
            mismatch = 1;
    }
    return mismatch;
}

librdp_status rdp_server_create_tls_context(const char* certificate_path,
                                                   const char* private_key_path,
                                                   SSL_CTX** context,
                                                   const char** failure_message)
{
    SSL_CTX* tls_context = NULL;

    if (failure_message)
        *failure_message = "server TLS handshake failed";
    if (!context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *context = NULL;
    if (!certificate_path || certificate_path[0] == '\0' ||
        !private_key_path || private_key_path[0] == '\0')
    {
        if (failure_message)
            *failure_message = "server TLS certificate or private key is not configured";
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    tls_context = SSL_CTX_new(TLS_server_method());
    if (!tls_context)
        return LIBRDP_STATUS_TLS_HANDSHAKE_FAILED;
    if (SSL_CTX_use_certificate_file(tls_context, certificate_path, SSL_FILETYPE_PEM) != 1)
    {
        SSL_CTX_free(tls_context);
        ERR_clear_error();
        if (failure_message)
            *failure_message = "server TLS certificate load failed";
        return LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
    }
    if (SSL_CTX_use_PrivateKey_file(tls_context, private_key_path, SSL_FILETYPE_PEM) != 1)
    {
        const int key_mismatch = rdp_server_tls_error_stack_has_key_mismatch();

        SSL_CTX_free(tls_context);
        if (failure_message)
        {
            *failure_message = key_mismatch ? "server TLS certificate and private key do not match"
                                            : "server TLS private key load failed";
        }
        return LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
    }
    if (SSL_CTX_check_private_key(tls_context) != 1)
    {
        SSL_CTX_free(tls_context);
        ERR_clear_error();
        if (failure_message)
            *failure_message = "server TLS certificate and private key do not match";
        return LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
    }
    *context = tls_context;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_send_all(int fd, const uint8_t* data, size_t length)
{
    size_t offset = 0;
#ifdef MSG_NOSIGNAL
    const int send_flags = MSG_NOSIGNAL;
#else
    const int send_flags = 0;
#endif

    while (offset < length)
    {
        ssize_t written = send(fd, data + offset, length - offset, send_flags);

        if (written > 0)
        {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        if (written < 0 && (errno == EPIPE || errno == ECONNRESET))
            return LIBRDP_STATUS_CLOSED;
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            struct pollfd pfd;
            int rc = 0;

            pfd.fd = fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            rc = poll(&pfd, 1, 1000);
            if (rc == 0)
                return LIBRDP_STATUS_TIMEOUT;
            if (rc < 0 && errno == EINTR)
                continue;
            if (rc < 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
                return LIBRDP_STATUS_IO_ERROR;
            continue;
        }
        return LIBRDP_STATUS_IO_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_wait_fd(int fd, short events, int timeout_ms)
{
    struct pollfd pfd;
    int rc = 0;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = events;
    do
    {
        rc = poll(&pfd, 1, timeout_ms);
    } while (rc < 0 && errno == EINTR);
    if (rc == 0)
        return LIBRDP_STATUS_TIMEOUT;
    if (rc < 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
        return LIBRDP_STATUS_IO_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_tls_status(SSL* tls, int rc, short* wait_events)
{
    int error = SSL_get_error(tls, rc);

    if (error == SSL_ERROR_ZERO_RETURN)
        return LIBRDP_STATUS_CLOSED;
    if (error == SSL_ERROR_WANT_READ)
    {
        if (wait_events)
            *wait_events = POLLIN;
        return LIBRDP_STATUS_AGAIN;
    }
    if (error == SSL_ERROR_WANT_WRITE)
    {
        if (wait_events)
            *wait_events = POLLOUT;
        return LIBRDP_STATUS_AGAIN;
    }
    return LIBRDP_STATUS_TLS_HANDSHAKE_FAILED;
}

static librdp_status rdp_server_tls_send_all(librdp_server_peer* peer, const uint8_t* data, size_t length)
{
    size_t offset = 0;

    while (offset < length)
    {
        int chunk = (length - offset) > (size_t)INT32_MAX ? INT32_MAX : (int)(length - offset);
        int written = SSL_write(peer->tls, data + offset, chunk);

        if (written > 0)
        {
            offset += (size_t)written;
            continue;
        }
        else
        {
            short wait_events = 0;
            librdp_status status = rdp_server_tls_status(peer->tls, written, &wait_events);

            if (status != LIBRDP_STATUS_AGAIN)
                return status;
            status = rdp_server_wait_fd(peer->fd, wait_events, 1000);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_peer_send_all(librdp_server_peer* peer, const uint8_t* data, size_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = peer->tls_active ? rdp_server_tls_send_all(peer, data, length)
                              : rdp_server_send_all(peer->fd, data, length);
    if (status == LIBRDP_STATUS_CLOSED)
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_CLOSED);
    if (status == LIBRDP_STATUS_OK)
        rdp_server_metric_add(&peer->metrics.bytes_written, (uint64_t)length);
    return status;
}

static librdp_status rdp_server_send_x224_data(librdp_server_peer* peer, const void* payload, size_t payload_len)
{
    rdp_buffer x224;
    rdp_buffer tpkt;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&x224);
    rdp_buffer_init(&tpkt);
    status = rdp_x224_wrap_data(&x224, payload, payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_tpkt_write(&tpkt, x224.data, x224.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_peer_send_all(peer, tpkt.data, tpkt.length);
    rdp_buffer_free(&tpkt);
    rdp_buffer_free(&x224);
    return status;
}

librdp_status rdp_server_send_mcs_pdu(librdp_server_peer* peer, const rdp_buffer* mcs_pdu)
{
    if (!peer || !mcs_pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    librdp_status status = rdp_server_send_x224_data(peer, mcs_pdu->data, mcs_pdu->length);

    if (status == LIBRDP_STATUS_OK)
        rdp_server_metric_add(&peer->metrics.pdu_out, 1u);
    return status;
}

size_t rdp_server_outbound_security_overhead(const librdp_server_peer* peer)
{
    return peer && peer->standard_security_ready ? 12u : 0u;
}

librdp_status rdp_server_prepare_outbound_security_payload(librdp_server_peer* peer,
                                                                  rdp_buffer* secured,
                                                                  const uint8_t** payload,
                                                                  size_t* payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !secured || !payload || !payload_len || (!*payload && *payload_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!peer->standard_security_ready)
        return LIBRDP_STATUS_OK;
    status = rdp_security_write_encrypted_pdu(secured,
                                              &peer->standard_security,
                                              0,
                                              *payload,
                                              *payload_len);
    if (status == LIBRDP_STATUS_OK)
    {
        *payload = secured->data;
        *payload_len = secured->length;
    }
    return status;
}

librdp_status rdp_server_send_slowpath(librdp_server_peer* peer, const rdp_buffer* slowpath_pdu)
{
    rdp_buffer secured;
    rdp_buffer mcs;
    const uint8_t* wire_payload = NULL;
    size_t wire_payload_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !slowpath_pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&secured);
    rdp_buffer_init(&mcs);
    wire_payload = slowpath_pdu->data;
    wire_payload_len = slowpath_pdu->length;
    status = rdp_server_prepare_outbound_security_payload(peer, &secured, &wire_payload, &wire_payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_send_data_indication(&mcs,
                                                    peer->user_id,
                                                    (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                    wire_payload,
                                                    wire_payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &mcs);
    rdp_buffer_free(&mcs);
    rdp_buffer_free(&secured);
    return status;
}

void rdp_server_close_peer(librdp_server_peer* peer, librdp_server_peer_state state)
{
    if (!peer)
        return;
    if (peer->tls)
    {
        SSL_set_quiet_shutdown(peer->tls, 1);
        (void)SSL_shutdown(peer->tls);
        SSL_free(peer->tls);
        peer->tls = NULL;
    }
    if (peer->tls_context)
    {
        SSL_CTX_free(peer->tls_context);
        peer->tls_context = NULL;
    }
    peer->tls_active = 0;
    if (peer->fd >= 0)
    {
        rdp_socket_close(peer->fd);
        peer->fd = -1;
    }
    rdp_server_set_state(peer, state);
}

static librdp_status rdp_server_send_x224_failure(librdp_server_peer* peer, uint32_t failure_code)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_x224_build_negotiation_failure(&response, failure_code);
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_server_peer_send_all(peer, response.data, response.length);
        if (status == LIBRDP_STATUS_OK)
            rdp_server_metric_add(&peer->metrics.pdu_out, 1u);
    }
    rdp_buffer_free(&response);
    rdp_server_close_peer(peer, status == LIBRDP_STATUS_OK ? LIBRDP_SERVER_PEER_CLOSED
                                                           : LIBRDP_SERVER_PEER_FAILED);
    return status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_UNSUPPORTED : status;
}

static int rdp_server_tls_material_available(const librdp_server_peer* peer)
{
    return peer && peer->tls_certificate_path && peer->tls_certificate_path[0] != '\0' &&
           peer->tls_private_key_path && peer->tls_private_key_path[0] != '\0';
}

static int rdp_server_nla_material_available(const librdp_server_peer* peer)
{
    if (!rdp_server_tls_material_available(peer))
        return 0;
    if (peer->credentials_provider)
        return 1;
    return peer->nla_username && peer->nla_username[0] != '\0' &&
           peer->nla_password && peer->nla_password[0] != '\0';
}

int rdp_server_uses_standard_security(const librdp_server_peer* peer)
{
    return peer && peer->selected_protocol == RDP_X224_PROTOCOL_STANDARD;
}

/*
 * Prepare per-peer Standard Security material before GCC Server Security Data
 * is serialized. The generated private key never leaves the peer, while the
 * public legacy certificate is advertised on the wire.
 */
librdp_status rdp_server_prepare_standard_security(librdp_server_peer* peer)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_server_uses_standard_security(peer) || peer->standard_private_key)
        return LIBRDP_STATUS_OK;
    status = rdp_security_generate_client_random(peer->standard_server_random);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_generate_server_certificate(&peer->standard_private_key, &peer->standard_certificate);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.standard_security.material.ready",
                        "certificate_len=%u",
                        (unsigned)peer->standard_certificate.length);
    return status;
}

static librdp_status rdp_server_select_protocol(const librdp_server_peer* peer,
                                                const rdp_x224_connection_request* request,
                                                uint32_t* selected_protocol,
                                                uint32_t* failure_code)
{
    uint32_t requested = RDP_X224_PROTOCOL_STANDARD;
    int standard_requested = 0;

    if (!peer || !request || !selected_protocol || !failure_code)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    requested = request->negotiation.present ? request->requested_protocols : RDP_X224_PROTOCOL_STANDARD;
    standard_requested = !request->negotiation.present || requested == RDP_X224_PROTOCOL_STANDARD;
    *selected_protocol = RDP_X224_PROTOCOL_STANDARD;
    *failure_code = RDP_SERVER_NEGOTIATION_FAILURE_SSL_NOT_ALLOWED;
    if (peer->security_mode == LIBRDP_SECURITY_STANDARD)
    {
        if (standard_requested)
            return LIBRDP_STATUS_OK;
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    if (peer->security_mode == LIBRDP_SECURITY_TLS)
    {
        if (!rdp_server_tls_material_available(peer))
        {
            *failure_code = RDP_SERVER_NEGOTIATION_FAILURE_SSL_CERT_NOT_ON_SERVER;
            return LIBRDP_STATUS_UNSUPPORTED;
        }
        if ((requested & RDP_X224_PROTOCOL_TLS) != 0)
        {
            *selected_protocol = RDP_X224_PROTOCOL_TLS;
            return LIBRDP_STATUS_OK;
        }
        *failure_code = RDP_SERVER_NEGOTIATION_FAILURE_SSL_REQUIRED;
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    if (peer->security_mode == LIBRDP_SECURITY_NLA)
    {
        if (!rdp_server_tls_material_available(peer))
        {
            *failure_code = RDP_SERVER_NEGOTIATION_FAILURE_SSL_CERT_NOT_ON_SERVER;
            return LIBRDP_STATUS_UNSUPPORTED;
        }
        if (!rdp_server_nla_material_available(peer))
        {
            *failure_code = RDP_SERVER_NEGOTIATION_FAILURE_HYBRID_REQUIRED;
            return LIBRDP_STATUS_UNSUPPORTED;
        }
        if ((requested & RDP_X224_PROTOCOL_NLA) != 0)
        {
            *selected_protocol = RDP_X224_PROTOCOL_NLA;
            return LIBRDP_STATUS_OK;
        }
        *failure_code = RDP_SERVER_NEGOTIATION_FAILURE_HYBRID_REQUIRED;
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    if (rdp_server_nla_material_available(peer) && (requested & RDP_X224_PROTOCOL_NLA) != 0)
    {
        *selected_protocol = RDP_X224_PROTOCOL_NLA;
        return LIBRDP_STATUS_OK;
    }
    if (rdp_server_tls_material_available(peer) && (requested & RDP_X224_PROTOCOL_TLS) != 0)
    {
        *selected_protocol = RDP_X224_PROTOCOL_TLS;
        return LIBRDP_STATUS_OK;
    }
    if (standard_requested)
        return LIBRDP_STATUS_OK;
    return LIBRDP_STATUS_UNSUPPORTED;
}

static librdp_status rdp_server_parse_buffered_tpkt(librdp_server_peer* peer,
                                                    rdp_tpkt* packet,
                                                    size_t* packet_len,
                                                    int* need_more)
{
    size_t total = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !packet || !packet_len || !need_more)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *packet_len = 0;
    *need_more = 1;
    if (peer->input.length < 4u)
        return LIBRDP_STATUS_OK;
    if (peer->input.data[0] != 3u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    total = ((size_t)peer->input.data[2] << 8) | (size_t)peer->input.data[3];
    if (total < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (total > peer->input.length)
        return LIBRDP_STATUS_OK;
    status = rdp_tpkt_parse(peer->input.data, total, packet);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_set_state(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    rdp_server_metric_add(&peer->metrics.pdu_in, 1u);
    *packet_len = total;
    *need_more = 0;
    return LIBRDP_STATUS_OK;
}

/*
 * Read exactly one complete TPKT from the peer transport, regardless of
 * whether the byte source is the initial TCP socket or the TLS layer selected
 * after X.224 negotiation. The peer input buffer owns partial data between
 * calls, so malformed lengths must fail without discarding unrelated queued
 * bytes.
 */
librdp_status rdp_server_read_tpkt(librdp_server_peer* peer,
                                          int timeout_ms,
                                          rdp_tpkt* packet,
                                          size_t* packet_len)
{
    struct pollfd pfd;
    uint8_t chunk[2048];
    ssize_t read_len = 0;
    int poll_result = 0;
    int need_more = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !packet || !packet_len || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->fd < 0)
        return LIBRDP_STATUS_STATE;
    status = rdp_server_parse_buffered_tpkt(peer, packet, packet_len, &need_more);
    if (status != LIBRDP_STATUS_OK || !need_more)
        return status;
    pfd.fd = peer->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (peer->pending_revents != 0)
    {
        pfd.revents = peer->pending_revents;
        peer->pending_revents = 0;
        poll_result = 1;
    }
    else
    {
        poll_result = poll(&pfd, 1, timeout_ms);
        if (poll_result == 0)
            return LIBRDP_STATUS_TIMEOUT;
        if (poll_result < 0)
            return errno == EINTR ? LIBRDP_STATUS_TIMEOUT : LIBRDP_STATUS_IO_ERROR;
    }
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
    {
        rdp_server_set_state(peer, LIBRDP_SERVER_PEER_FAILED);
        return LIBRDP_STATUS_IO_ERROR;
    }
    if (peer->tls_active)
    {
        int tls_read = SSL_read(peer->tls, chunk, (int)sizeof(chunk));

        if (tls_read <= 0)
        {
            short wait_events = 0;
            librdp_status tls_status = rdp_server_tls_status(peer->tls, tls_read, &wait_events);

            (void)wait_events;
            if (tls_status == LIBRDP_STATUS_AGAIN)
                return LIBRDP_STATUS_TIMEOUT;
            if (tls_status == LIBRDP_STATUS_CLOSED)
                rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_CLOSED);
            return tls_status;
        }
        read_len = tls_read;
    }
    else
    {
        read_len = recv(peer->fd, chunk, sizeof(chunk), 0);
        if (read_len == 0)
        {
            rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_CLOSED);
            return LIBRDP_STATUS_CLOSED;
        }
        if (read_len < 0)
            return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? LIBRDP_STATUS_TIMEOUT
                                                                             : LIBRDP_STATUS_IO_ERROR;
    }
    rdp_server_metric_add(&peer->metrics.bytes_read, (uint64_t)read_len);
    if (peer->input.length + (size_t)read_len > RDP_SERVER_INITIAL_READ_MAX)
    {
        rdp_server_set_state(peer, LIBRDP_SERVER_PEER_FAILED);
        rdp_server_metric_add(&peer->metrics.limits_rejected, 1u);
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    status = rdp_buffer_append(&peer->input, chunk, (size_t)read_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_server_parse_buffered_tpkt(peer, packet, packet_len, &need_more);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (need_more)
        return LIBRDP_STATUS_TIMEOUT;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_server_start_tls(librdp_server_peer* peer,
                                          int timeout_ms,
                                          const char** failure_message)
{
    librdp_status status = LIBRDP_STATUS_OK;
    int rc = 0;

    if (failure_message)
        *failure_message = "server TLS handshake failed";
    if (!peer || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->tls_active)
        return LIBRDP_STATUS_OK;
    if (!rdp_server_tls_material_available(peer))
    {
        if (failure_message)
            *failure_message = "server TLS certificate or private key is not configured";
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    if (!peer->tls_context)
    {
        status = rdp_server_create_tls_context(peer->tls_certificate_path,
                                               peer->tls_private_key_path,
                                               &peer->tls_context,
                                               failure_message);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (!peer->tls)
    {
        peer->tls = SSL_new(peer->tls_context);
        if (!peer->tls)
            return LIBRDP_STATUS_TLS_HANDSHAKE_FAILED;
        if (SSL_set_fd(peer->tls, peer->fd) != 1)
            return LIBRDP_STATUS_TLS_HANDSHAKE_FAILED;
    }
    rc = SSL_accept(peer->tls);
    if (rc != 1)
    {
        short wait_events = 0;

        status = rdp_server_tls_status(peer->tls, rc, &wait_events);
        if (status == LIBRDP_STATUS_AGAIN)
        {
            status = rdp_server_wait_fd(peer->fd, wait_events, timeout_ms);
            return status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_TIMEOUT : status;
        }
        ERR_clear_error();
        return status == LIBRDP_STATUS_CLOSED ? LIBRDP_STATUS_TLS_HANDSHAKE_FAILED : status;
    }
    peer->tls_active = 1;
    rdp_trace_event(RDP_TRACE_TRANSPORT,
                    "server.transport.tls.accept.done",
                    "version=%s cipher=%s",
                    SSL_get_version(peer->tls),
                    SSL_get_cipher(peer->tls));
    rdp_server_set_state(peer,
                         peer->selected_protocol == RDP_X224_PROTOCOL_NLA ?
                             LIBRDP_SERVER_PEER_NLA_AUTHENTICATING :
                             LIBRDP_SERVER_PEER_X224_CONFIRMED);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_append_utf16le_ascii(rdp_buffer* buffer, const char* text)
{
    if (!buffer || !text)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (const unsigned char* current = (const unsigned char*)text; *current; current++)
    {
        if (*current >= 0x80u)
            return LIBRDP_STATUS_UNSUPPORTED;
        librdp_status status = rdp_buffer_append_u16_le(buffer, (uint16_t)*current);

        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static uint64_t rdp_server_filetime_now(void)
{
    struct timespec ts;
    const uint64_t windows_epoch_seconds = 11644473600ull;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0 || ts.tv_sec < 0)
        return 0;
    return ((uint64_t)ts.tv_sec + windows_epoch_seconds) * 10000000ull +
           (uint64_t)(ts.tv_nsec / 100u);
}

static librdp_status rdp_server_append_ntlm_av_utf16(rdp_buffer* buffer, uint16_t av_id, const char* text)
{
    rdp_buffer value;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !text)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&value);
    status = rdp_server_append_utf16le_ascii(&value, text);
    if (status == LIBRDP_STATUS_OK && value.length > UINT16_MAX)
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, av_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)value.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, value.data, value.length);
    rdp_buffer_free(&value);
    return status;
}

static librdp_status rdp_server_append_ntlm_av_u64(rdp_buffer* buffer, uint16_t av_id, uint64_t value)
{
    uint8_t encoded[8];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (size_t i = 0; i < sizeof(encoded); i++)
        encoded[i] = (uint8_t)((value >> (i * 8u)) & 0xffu);
    status = rdp_buffer_append_u16_le(buffer, av_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)sizeof(encoded));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, encoded, sizeof(encoded));
    return status;
}

static librdp_status rdp_server_append_ntlm_target_info(rdp_buffer* buffer, const char* target_name)
{
    uint64_t timestamp = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !target_name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_server_append_ntlm_av_utf16(buffer, RDP_SERVER_NTLM_AV_NB_COMPUTER_NAME, target_name);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_append_ntlm_av_utf16(buffer, RDP_SERVER_NTLM_AV_NB_DOMAIN_NAME, target_name);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_append_ntlm_av_utf16(buffer, RDP_SERVER_NTLM_AV_DNS_COMPUTER_NAME, target_name);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_append_ntlm_av_utf16(buffer, RDP_SERVER_NTLM_AV_DNS_DOMAIN_NAME, target_name);
    timestamp = rdp_server_filetime_now();
    if (status == LIBRDP_STATUS_OK && timestamp != 0)
        status = rdp_server_append_ntlm_av_u64(buffer, RDP_SERVER_NTLM_AV_TIMESTAMP, timestamp);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, RDP_SERVER_NTLM_AV_EOL);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    return status;
}

static librdp_status rdp_server_credssp_packet_length(const rdp_buffer* input, size_t* total)
{
    uint8_t length_byte = 0;
    size_t header_len = 2u;
    size_t payload_len = 0;
    size_t length_len = 0;

    if (!input || !total)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (input->length < 2u)
        return LIBRDP_STATUS_TIMEOUT;
    if (input->data[0] != 0x30u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    length_byte = input->data[1];
    if ((length_byte & 0x80u) == 0)
    {
        payload_len = length_byte;
    }
    else
    {
        length_len = length_byte & 0x7fu;
        if (length_len == 0 || length_len > 4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        header_len += length_len;
        if (input->length < header_len)
            return LIBRDP_STATUS_TIMEOUT;
        for (size_t i = 0; i < length_len; i++)
        {
            if (payload_len > (SIZE_MAX >> 8))
                return LIBRDP_STATUS_LIMIT_EXCEEDED;
            payload_len = (payload_len << 8) | input->data[2u + i];
        }
    }
    if (payload_len > RDP_SERVER_CREDSSP_MESSAGE_MAX || header_len > SIZE_MAX - payload_len)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    *total = header_len + payload_len;
    if (*total > RDP_SERVER_CREDSSP_MESSAGE_MAX)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    return input->length >= *total ? LIBRDP_STATUS_OK : LIBRDP_STATUS_TIMEOUT;
}

/*
 * Read one DER TSRequest from the TLS stream. CredSSP runs directly over TLS,
 * not inside TPKT, so partial DER bytes are buffered separately from the later
 * RDP packet parser while preserving strict maximum length enforcement.
 */
static librdp_status rdp_server_read_credssp_ts_request(librdp_server_peer* peer,
                                                        int timeout_ms,
                                                        rdp_buffer* packet)
{
    uint8_t chunk[2048];
    size_t total = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !packet || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!peer->tls_active || !peer->tls)
        return LIBRDP_STATUS_STATE;
    status = rdp_server_credssp_packet_length(&peer->input, &total);
    if (status == LIBRDP_STATUS_TIMEOUT)
    {
        struct pollfd pfd;
        int rc = 0;
        int tls_read = 0;

        pfd.fd = peer->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        rc = poll(&pfd, 1, timeout_ms);
        if (rc == 0)
            return LIBRDP_STATUS_TIMEOUT;
        if (rc < 0)
            return errno == EINTR ? LIBRDP_STATUS_TIMEOUT : LIBRDP_STATUS_IO_ERROR;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
            return LIBRDP_STATUS_IO_ERROR;
        tls_read = SSL_read(peer->tls, chunk, (int)sizeof(chunk));
        if (tls_read <= 0)
        {
            short wait_events = 0;
            librdp_status tls_status = rdp_server_tls_status(peer->tls, tls_read, &wait_events);

            (void)wait_events;
            return tls_status == LIBRDP_STATUS_AGAIN ? LIBRDP_STATUS_TIMEOUT : tls_status;
        }
        rdp_server_metric_add(&peer->metrics.bytes_read, (uint64_t)tls_read);
        if (peer->input.length + (size_t)tls_read > RDP_SERVER_CREDSSP_MESSAGE_MAX)
        {
            rdp_server_metric_add(&peer->metrics.limits_rejected, 1u);
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
        }
        status = rdp_buffer_append(&peer->input, chunk, (size_t)tls_read);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_server_credssp_packet_length(&peer->input, &total);
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(packet, peer->input.data, total);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_consume(&peer->input, total);
    if (status == LIBRDP_STATUS_OK)
        rdp_server_metric_add(&peer->metrics.pdu_in, 1u);
    return status;
}

static librdp_status rdp_server_send_credssp_ts_request(librdp_server_peer* peer,
                                                        uint32_t version,
                                                        const uint8_t* nego_token,
                                                        size_t nego_token_len,
                                                        const uint8_t* auth_info,
                                                        size_t auth_info_len,
                                                        const uint8_t* pub_key_auth,
                                                        size_t pub_key_auth_len)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&response);
    status = rdp_credssp_write_ts_request(&response,
                                          version ? version : 6u,
                                          nego_token,
                                          nego_token_len,
                                          auth_info,
                                          auth_info_len,
                                          pub_key_auth,
                                          pub_key_auth_len,
                                          NULL,
                                          0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_peer_send_all(peer, response.data, response.length);
    if (status == LIBRDP_STATUS_OK)
        rdp_server_metric_add(&peer->metrics.pdu_out, 1u);
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_server_prepare_credssp_challenge(librdp_server_peer* peer,
                                                          rdp_ntlm_challenge* challenge)
{
    const char* target_name = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !challenge)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer->credssp_target_name.length = 0;
    peer->credssp_target_info.length = 0;
    target_name = peer->server_name ? peer->server_name : "librdp";
    status = rdp_server_append_utf16le_ascii(&peer->credssp_target_name, target_name);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_append_ntlm_target_info(&peer->credssp_target_info, target_name);
    if (status == LIBRDP_STATUS_OK && RAND_bytes(peer->credssp_server_challenge,
                                                 (int)sizeof(peer->credssp_server_challenge)) != 1)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(challenge, 0, sizeof(*challenge));
    challenge->flags = rdp_credssp_default_ntlm_challenge_flags();
    memcpy(challenge->server_challenge,
           peer->credssp_server_challenge,
           sizeof(peer->credssp_server_challenge));
    challenge->target_name = peer->credssp_target_name.data;
    challenge->target_name_len = peer->credssp_target_name.length;
    challenge->target_info = peer->credssp_target_info.data;
    challenge->target_info_len = peer->credssp_target_info.length;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_tls_public_key(librdp_server_peer* peer, rdp_buffer* public_key)
{
    X509* certificate = NULL;
    EVP_PKEY* key = NULL;
    unsigned char* cursor = NULL;
    int encoded_len = 0;
    int written = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !public_key || !peer->tls)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    certificate = SSL_get_certificate(peer->tls);
    if (!certificate)
        return LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
    key = X509_get_pubkey(certificate);
    if (!key)
        return LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
    encoded_len = i2d_PublicKey(key, NULL);
    if (encoded_len <= 0)
    {
        EVP_PKEY_free(key);
        return LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
    }
    status = rdp_buffer_reserve(public_key, (size_t)encoded_len);
    if (status == LIBRDP_STATUS_OK)
    {
        cursor = public_key->data;
        written = i2d_PublicKey(key, &cursor);
        if (written != encoded_len)
            status = LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
        else
            public_key->length = (size_t)written;
    }
    EVP_PKEY_free(key);
    return status;
}

static librdp_status rdp_server_credssp_accept_version(librdp_server_peer* peer, uint32_t version)
{
    if (!peer || version != 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (peer->credssp_ts_request_version == 0)
        peer->credssp_ts_request_version = (uint8_t)version;
    return peer->credssp_ts_request_version == version ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_server_credssp_utf16_field(const uint8_t* data, size_t length, char** text)
{
    size_t text_len = 0;

    if ((!data && length > 0) || (length % 2u) != 0 || !text)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *text = NULL;
    return rdp_charset_utf16le_to_utf8_alloc(data, length, 0, text, &text_len);
}

/*
 * Purpose: turn the claimed NTLM identity into provider-approved credentials
 * without persisting raw secrets in peer state longer than required.
 * Invariants: UTF-16 fields are decoded before policy callbacks, usernames
 * must be non-empty, provider output owns the password only until copied into
 * the peer's secure expected-credential storage, and failures increment server
 * error metrics without leaking credential values to trace.
 */
static librdp_status rdp_server_credssp_resolve_expected_credentials(
    librdp_server_peer* peer,
    const rdp_ntlm_authenticate* authenticate,
    uint32_t ts_request_version)
{
    char* claimed_domain = NULL;
    char* claimed_username = NULL;
    char* claimed_workstation = NULL;
    librdp_credentials provider_credentials;
    librdp_server_credentials_request request;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !authenticate)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&provider_credentials, 0, sizeof(provider_credentials));
    memset(&request, 0, sizeof(request));
    status = rdp_server_credssp_utf16_field(authenticate->domain,
                                            authenticate->domain_len,
                                            &claimed_domain);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_credssp_utf16_field(authenticate->username,
                                                authenticate->username_len,
                                                &claimed_username);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_credssp_utf16_field(authenticate->workstation,
                                                authenticate->workstation_len,
                                                &claimed_workstation);
    if (status == LIBRDP_STATUS_OK && (!claimed_username || claimed_username[0] == '\0'))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && peer->credentials_provider)
    {
        status = librdp_credentials_init(&provider_credentials);
        if (status == LIBRDP_STATUS_OK)
            status = librdp_server_credentials_request_init(&request);
        if (status == LIBRDP_STATUS_OK)
        {
            request.domain = claimed_domain;
            request.username = claimed_username;
            request.workstation = claimed_workstation;
            request.ts_request_version = ts_request_version;
            request.failed_attempts = peer->nla_failed_attempts;
            request.public_key_bound = peer->credssp_public_key_bound;
            status = peer->credentials_provider(peer,
                                                &request,
                                                &provider_credentials,
                                                peer->credentials_provider_user_data);
        }
        if (status == LIBRDP_STATUS_OK &&
            (!provider_credentials.password || provider_credentials.password[0] == '\0'))
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status == LIBRDP_STATUS_OK)
        {
            const char* expected_domain = provider_credentials.domain ? provider_credentials.domain : claimed_domain;
            const char* expected_username =
                provider_credentials.username ? provider_credentials.username : claimed_username;

            status = rdp_server_credssp_expected_set(peer,
                                                     expected_domain,
                                                     expected_username,
                                                     provider_credentials.password);
        }
        librdp_credentials_clear(&provider_credentials);
    }
    else if (status == LIBRDP_STATUS_OK)
    {
        if (!peer->nla_username || peer->nla_username[0] == '\0' ||
            !peer->nla_password || peer->nla_password[0] == '\0')
            status = LIBRDP_STATUS_UNSUPPORTED;
        else
            status = rdp_server_credssp_expected_set(peer,
                                                     peer->nla_domain ? peer->nla_domain : claimed_domain,
                                                     peer->nla_username,
                                                     peer->nla_password);
    }
    if (status != LIBRDP_STATUS_OK)
        rdp_server_metric_add(&peer->metrics.errors, 1u);
    free(claimed_workstation);
    free(claimed_username);
    free(claimed_domain);
    return status;
}

static librdp_status rdp_server_credssp_check_final_credentials(
    librdp_server_peer* peer,
    const rdp_credssp_password_credentials* credentials)
{
    if (!peer || !credentials || !credentials->username || !credentials->password ||
        !peer->credssp_expected_username || !peer->credssp_expected_password)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_server_account_equal_fold(credentials->username, peer->credssp_expected_username))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (peer->credssp_expected_domain &&
        !rdp_server_account_equal_fold(credentials->domain ? credentials->domain : "",
                                       peer->credssp_expected_domain))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_server_secret_equal(credentials->password, peer->credssp_expected_password))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_handle_credssp_negotiate(librdp_server_peer* peer, int timeout_ms)
{
    rdp_buffer packet;
    rdp_buffer ntlm_challenge;
    rdp_credssp_ts_request request;
    rdp_ntlm_negotiate negotiate;
    rdp_ntlm_challenge challenge;
    const uint8_t* ntlm = NULL;
    size_t ntlm_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&packet);
    rdp_buffer_init(&ntlm_challenge);
    status = rdp_server_read_credssp_ts_request(peer, timeout_ms, &packet);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_parse_ts_request(packet.data, packet.length, &request);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_credssp_accept_version(peer, request.version);
    if (status == LIBRDP_STATUS_OK)
        status = request.client_nonce_len == sizeof(peer->credssp_client_nonce) ? LIBRDP_STATUS_OK
                                                                                : LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
    {
        memcpy(peer->credssp_client_nonce, request.client_nonce, sizeof(peer->credssp_client_nonce));
        peer->credssp_client_nonce_ready = 1;
        status = rdp_credssp_extract_ntlm_message(request.nego_token,
                                                  request.nego_token_len,
                                                  1,
                                                  &ntlm,
                                                  &ntlm_len);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_parse_ntlm_negotiate(ntlm, ntlm_len, &negotiate);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_prepare_credssp_challenge(peer, &challenge);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_write_ntlm_challenge(&ntlm_challenge, &challenge);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_credssp_ts_request(peer,
                                                    request.version,
                                                    ntlm_challenge.data,
                                                    ntlm_challenge.length,
                                                    NULL,
                                                    0,
                                                    NULL,
                                                    0);
    if (status == LIBRDP_STATUS_OK)
    {
        peer->credssp_stage = 1;
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.credssp.negotiate.done",
                        "flags=%u target_info_len=%u",
                        negotiate.flags,
                        (unsigned)challenge.target_info_len);
    }
    rdp_buffer_free(&ntlm_challenge);
    rdp_buffer_free(&packet);
    return status;
}

/*
 * Purpose: consume the NTLM authenticate token, verify provider credentials,
 * and support both CredSSP packet layouts observed on the wire: public-key
 * auth in a following TSRequest or combined with the final negotiate token.
 * Invariants: derived NTLM session keys become usable only after password
 * proof validation, public-key binding is checked before credentials are
 * accepted, and any failure clears expected secrets and leaves the peer in a
 * protocol-error state.
 */
static librdp_status rdp_server_handle_credssp_authenticate(librdp_server_peer* peer, int timeout_ms)
{
    rdp_buffer packet;
    rdp_buffer public_key;
    rdp_buffer pub_key_auth;
    rdp_credssp_ts_request request;
    rdp_ntlm_challenge challenge;
    rdp_ntlm_authenticate authenticate;
    rdp_ntlm_authenticate_result result;
    const uint8_t* ntlm = NULL;
    size_t ntlm_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&packet);
    rdp_buffer_init(&public_key);
    rdp_buffer_init(&pub_key_auth);
    memset(&result, 0, sizeof(result));
    status = rdp_server_read_credssp_ts_request(peer, timeout_ms, &packet);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_parse_ts_request(packet.data, packet.length, &request);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_credssp_accept_version(peer, request.version);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_extract_ntlm_message(request.nego_token,
                                                  request.nego_token_len,
                                                  3,
                                                  &ntlm,
                                                  &ntlm_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_parse_ntlm_authenticate(ntlm, ntlm_len, &authenticate);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_credssp_resolve_expected_credentials(peer, &authenticate, request.version);
    if (status == LIBRDP_STATUS_OK)
    {
        memset(&challenge, 0, sizeof(challenge));
        challenge.flags = rdp_credssp_default_ntlm_challenge_flags();
        memcpy(challenge.server_challenge,
               peer->credssp_server_challenge,
               sizeof(peer->credssp_server_challenge));
        challenge.target_name = peer->credssp_target_name.data;
        challenge.target_name_len = peer->credssp_target_name.length;
        challenge.target_info = peer->credssp_target_info.data;
        challenge.target_info_len = peer->credssp_target_info.length;
        status = rdp_credssp_verify_ntlm_authenticate(ntlm,
                                                      ntlm_len,
                                                      &challenge,
                                                      peer->credssp_expected_username,
                                                      peer->credssp_expected_password,
                                                      &result);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_ntlm_server_security_init(&peer->credssp_security, &result);
    if (status == LIBRDP_STATUS_OK)
    {
        peer->credssp_security_ready = 1;
        rdp_trace_event(RDP_TRACE_PROTOCOL, "server.credssp.authenticate.done", "username=redacted");
    }
    if (status == LIBRDP_STATUS_OK && request.pub_key_auth_len > 0)
        status = rdp_server_tls_public_key(peer, &public_key);
    if (status == LIBRDP_STATUS_OK && request.pub_key_auth_len > 0)
        status = rdp_credssp_verify_client_public_key_hash(&peer->credssp_security,
                                                           peer->credssp_client_nonce,
                                                           sizeof(peer->credssp_client_nonce),
                                                           public_key.data,
                                                           public_key.length,
                                                           request.pub_key_auth,
                                                           request.pub_key_auth_len);
    if (status == LIBRDP_STATUS_OK && request.pub_key_auth_len > 0)
        status = rdp_credssp_encrypt_server_public_key_hash(&peer->credssp_security,
                                                            peer->credssp_client_nonce,
                                                            sizeof(peer->credssp_client_nonce),
                                                            public_key.data,
                                                            public_key.length,
                                                            &pub_key_auth);
    if (status == LIBRDP_STATUS_OK && request.pub_key_auth_len > 0)
        status = rdp_server_send_credssp_ts_request(peer,
                                                    request.version,
                                                    NULL,
                                                    0,
                                                    NULL,
                                                    0,
                                                    pub_key_auth.data,
                                                    pub_key_auth.length);
    if (status == LIBRDP_STATUS_OK)
    {
        if (request.pub_key_auth_len > 0)
        {
            peer->credssp_public_key_bound = 1;
            peer->credssp_stage = 3;
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "server.credssp.pubkey.done",
                            "public_key_len=%u pub_key_auth_len=%u",
                            (unsigned)public_key.length,
                            (unsigned)pub_key_auth.length);
        }
        else
        {
            peer->credssp_stage = 2;
        }
    }
    if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_TIMEOUT && status != LIBRDP_STATUS_AGAIN)
    {
        peer->nla_failed_attempts++;
        rdp_server_credssp_expected_clear(peer);
    }
    OPENSSL_cleanse(&result, sizeof(result));
    rdp_buffer_free(&pub_key_auth);
    rdp_buffer_free(&public_key);
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status rdp_server_handle_credssp_pubkey(librdp_server_peer* peer, int timeout_ms)
{
    rdp_buffer packet;
    rdp_buffer public_key;
    rdp_buffer pub_key_auth;
    rdp_credssp_ts_request request;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&packet);
    rdp_buffer_init(&public_key);
    rdp_buffer_init(&pub_key_auth);
    status = rdp_server_read_credssp_ts_request(peer, timeout_ms, &packet);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_parse_ts_request(packet.data, packet.length, &request);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_credssp_accept_version(peer, request.version);
    if (status == LIBRDP_STATUS_OK && !peer->credssp_security_ready)
        status = LIBRDP_STATUS_STATE;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_tls_public_key(peer, &public_key);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_verify_client_public_key_hash(&peer->credssp_security,
                                                           peer->credssp_client_nonce,
                                                           sizeof(peer->credssp_client_nonce),
                                                           public_key.data,
                                                           public_key.length,
                                                           request.pub_key_auth,
                                                           request.pub_key_auth_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_encrypt_server_public_key_hash(&peer->credssp_security,
                                                            peer->credssp_client_nonce,
                                                            sizeof(peer->credssp_client_nonce),
                                                            public_key.data,
                                                            public_key.length,
                                                            &pub_key_auth);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_credssp_ts_request(peer,
                                                    request.version,
                                                    NULL,
                                                    0,
                                                    NULL,
                                                    0,
                                                    pub_key_auth.data,
                                                    pub_key_auth.length);
    if (status == LIBRDP_STATUS_OK)
    {
        peer->credssp_public_key_bound = 1;
        peer->credssp_stage = 3;
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.credssp.pubkey.done",
                        "public_key_len=%u pub_key_auth_len=%u",
                        (unsigned)public_key.length,
                        (unsigned)pub_key_auth.length);
    }
    if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_TIMEOUT && status != LIBRDP_STATUS_AGAIN)
    {
        peer->nla_failed_attempts++;
        rdp_server_credssp_expected_clear(peer);
    }
    rdp_buffer_free(&pub_key_auth);
    rdp_buffer_free(&public_key);
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status rdp_server_handle_credssp_credentials(librdp_server_peer* peer, int timeout_ms)
{
    rdp_buffer packet;
    rdp_credssp_ts_request request;
    rdp_credssp_password_credentials credentials;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&packet);
    memset(&credentials, 0, sizeof(credentials));
    status = rdp_server_read_credssp_ts_request(peer, timeout_ms, &packet);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_parse_ts_request(packet.data, packet.length, &request);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_credssp_accept_version(peer, request.version);
    if (status == LIBRDP_STATUS_OK && !peer->credssp_security_ready)
        status = LIBRDP_STATUS_STATE;
    if (status == LIBRDP_STATUS_OK && !peer->credssp_public_key_bound)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_decrypt_password_credentials_ex(&peer->credssp_security,
                                                             request.auth_info,
                                                             request.auth_info_len,
                                                             &credentials);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_credssp_check_final_credentials(peer, &credentials);
    if (status == LIBRDP_STATUS_OK)
    {
        peer->nla_authenticated = 1;
        peer->credssp_stage = 4;
        rdp_server_set_state(peer, LIBRDP_SERVER_PEER_X224_CONFIRMED);
        rdp_trace_event(RDP_TRACE_PROTOCOL, "server.credssp.done", "credentials=redacted");
        rdp_server_credssp_expected_clear(peer);
    }
    if (status != LIBRDP_STATUS_OK)
    {
        peer->nla_failed_attempts++;
        rdp_server_credssp_expected_clear(peer);
    }
    rdp_credssp_password_credentials_clear(&credentials);
    rdp_buffer_free(&packet);
    return status;
}

librdp_status rdp_server_handle_credssp(librdp_server_peer* peer, int timeout_ms)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_server_nla_material_available(peer))
        return LIBRDP_STATUS_UNSUPPORTED;
    if (peer->credssp_stage == 0)
        return rdp_server_handle_credssp_negotiate(peer, timeout_ms);
    if (peer->credssp_stage == 1)
        return rdp_server_handle_credssp_authenticate(peer, timeout_ms);
    if (peer->credssp_stage == 2)
        return rdp_server_handle_credssp_pubkey(peer, timeout_ms);
    if (peer->credssp_stage == 3)
        return rdp_server_handle_credssp_credentials(peer, timeout_ms);
    return LIBRDP_STATUS_STATE;
}

librdp_status rdp_server_handle_x224(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    rdp_x224_connection_request request;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t selected_protocol = RDP_X224_PROTOCOL_STANDARD;
    uint32_t failure_code = RDP_SERVER_NEGOTIATION_FAILURE_SSL_NOT_ALLOWED;

    status = rdp_x224_parse_connection_request(packet->payload, packet->payload_len, &request);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_set_state(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    status = rdp_server_select_protocol(peer, &request, &selected_protocol, &failure_code);
    if (status != LIBRDP_STATUS_OK)
        return rdp_server_send_x224_failure(peer, failure_code);

    rdp_buffer_init(&response);
    status = rdp_x224_build_connection_confirm_ex(&response,
                                                  selected_protocol,
                                                  request.negotiation.present);
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_server_peer_send_all(peer, response.data, response.length);
        if (status == LIBRDP_STATUS_OK)
            rdp_server_metric_add(&peer->metrics.pdu_out, 1u);
    }
    rdp_buffer_free(&response);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    peer->selected_protocol = selected_protocol;
    rdp_server_set_state(peer,
                         (selected_protocol == RDP_X224_PROTOCOL_TLS ||
                          selected_protocol == RDP_X224_PROTOCOL_NLA) ?
                             LIBRDP_SERVER_PEER_TLS_HANDSHAKING :
                             LIBRDP_SERVER_PEER_X224_CONFIRMED);
    return LIBRDP_STATUS_OK;
}

int rdp_server_security_payload_has_flag(const uint8_t* input, size_t input_len, uint16_t required)
{
    uint16_t flags = 0;
    uint16_t flags_hi = 0;

    if (!input || input_len < 4u)
        return 0;
    flags = (uint16_t)((uint16_t)input[0] | ((uint16_t)input[1] << 8));
    flags_hi = (uint16_t)((uint16_t)input[2] | ((uint16_t)input[3] << 8));
    return flags_hi == 0 && (flags & required) == required;
}

/*
 * Consume the client Security Exchange PDU and arm Standard Security for all
 * following client-to-server encrypted PDUs. The encrypted random is decrypted
 * in the certificate helper, and the plaintext is cleansed immediately after
 * key derivation.
 */
librdp_status rdp_server_handle_security_exchange(librdp_server_peer* peer,
                                                         const uint8_t* input,
                                                         size_t input_len)
{
    rdp_buffer body;
    rdp_stream stream;
    const uint8_t* encrypted_random = NULL;
    uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    uint32_t encrypted_random_padded_len = 0;
    uint16_t flags = 0;
    size_t encrypted_random_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !input)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_server_uses_standard_security(peer) || !peer->standard_private_key)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_buffer_init(&body);
    memset(client_random, 0, sizeof(client_random));
    status = rdp_security_unwrap_pdu(NULL, input, input_len, &body, &flags);
    if (status == LIBRDP_STATUS_OK &&
        (flags & (uint16_t)(RDP_SEC_EXCHANGE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC)) !=
            (uint16_t)(RDP_SEC_EXCHANGE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_stream_init(&stream, body.data, body.length);
        if (rdp_stream_read_u32_le(&stream, &encrypted_random_padded_len) != LIBRDP_STATUS_OK ||
            encrypted_random_padded_len < 8u ||
            rdp_stream_remaining(&stream) < encrypted_random_padded_len)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        encrypted_random_len = (size_t)encrypted_random_padded_len - 8u;
        if (rdp_stream_read_bytes(&stream, &encrypted_random, encrypted_random_len) != LIBRDP_STATUS_OK ||
            rdp_stream_skip(&stream, 8u) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_decrypt_private_secret(peer->standard_private_key,
                                                     encrypted_random,
                                                     encrypted_random_len,
                                                     client_random,
                                                     sizeof(client_random));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_standard_server_init(&peer->standard_security,
                                                   RDP_SECURITY_METHOD_128BIT,
                                                   client_random,
                                                   peer->standard_server_random);
    if (status == LIBRDP_STATUS_OK)
    {
        peer->standard_security_ready = 1;
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.standard_security.exchange.done",
                        "encrypted_random_len=%u",
                        (unsigned)encrypted_random_len);
    }
    OPENSSL_cleanse(client_random, sizeof(client_random));
    rdp_buffer_free(&body);
    return status;
}

librdp_status rdp_server_parse_client_info_security_payload(librdp_server_peer* peer,
                                                                   const uint8_t* input,
                                                                   size_t input_len,
                                                                   rdp_client_info_summary* summary)
{
    rdp_buffer body;
    rdp_buffer framed;
    uint16_t flags = 0;
    rdp_standard_security_context* security = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !input || !summary)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&body);
    rdp_buffer_init(&framed);
    if (peer->standard_security_ready)
        security = &peer->standard_security;
    status = rdp_security_unwrap_pdu(security, input, input_len, &body, &flags);
    if (status == LIBRDP_STATUS_OK && (flags & RDP_SEC_INFO_PKT) == 0)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_header(&framed, RDP_SEC_INFO_PKT);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&framed, body.data, body.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_parse_client_info_pdu(framed.data, framed.length, summary);
    rdp_buffer_free(&framed);
    rdp_buffer_free(&body);
    return status;
}

librdp_status rdp_server_unwrap_optional_security_header(librdp_server_peer* peer,
                                                                const uint8_t* input,
                                                                size_t input_len,
                                                                rdp_buffer* storage,
                                                                const uint8_t** output,
                                                                size_t* output_len)
{
    uint16_t flags = 0;
    uint16_t flags_hi = 0;
    uint16_t allowed = (uint16_t)(RDP_SEC_EXCHANGE_PKT | RDP_SEC_ENCRYPT | RDP_SEC_INFO_PKT |
                                  RDP_SEC_LICENSE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC |
                                  RDP_SEC_SECURE_CHECKSUM);

    if ((!input && input_len > 0) || !storage || !output || !output_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *output = input;
    *output_len = input_len;
    if (input_len < 4u)
        return LIBRDP_STATUS_OK;
    flags = (uint16_t)((uint16_t)input[0] | ((uint16_t)input[1] << 8));
    flags_hi = (uint16_t)((uint16_t)input[2] | ((uint16_t)input[3] << 8));
    if (flags_hi != 0 || (flags & (uint16_t)~allowed) != 0)
        return LIBRDP_STATUS_OK;
    if ((flags & RDP_SEC_ENCRYPT) != 0 && (!peer || !peer->standard_security_ready))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    storage->length = 0;
    if (rdp_security_unwrap_pdu((flags & RDP_SEC_ENCRYPT) != 0 ? &peer->standard_security : NULL,
                                input,
                                input_len,
                                storage,
                                NULL) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *output = storage->data;
    *output_len = storage->length;
    return LIBRDP_STATUS_OK;
}
