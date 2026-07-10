#include "common/buffer.h"
#include "protocol/tpkt.h"
#include "transport/multitransport.h"
#include "transport/transport.h"
#include "transport/udp_transport.h"

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

static int test_udp_transport_protocols(void)
{
    const uint8_t payload[] = {0xaa, 0xbb, 0xcc, 0xdd};
    const uint8_t wire_example[] = {0x73, 0x30, 0x35, 0x56, 0x78, 0xa2, 0x36, 0x10, 0xee, 0x68, 0xf2};
    const uint8_t layout_example[] = {0x30, 0x35, 0x56, 0x78, 0xa2, 0x36, 0x73, 0xee, 0x68, 0xf2};
    rdp_buffer buffer;
    rdp_buffer wire;
    rdp_buffer unwrapped;
    rdp_udp_fec_header fec_header;
    rdp_udp_fec_payload_header fec_payload;
    rdp_udp_payload_prefix payload_prefix;
    rdp_udp_source_payload_header source_header;
    rdp_udp_syn_data syn;
    rdp_udp_ack_of_ack_vector ack_of_ack;
    rdp_udp_ack_vector ack_vector;
    rdp_udp_ack_vector_entry ack_entry;
    rdp_udp_correlation_id correlation;
    rdp_udp_syn_data_ex syn_ex;
    rdp_udp2_header udp2_header;
    rdp_udp2_packet udp2_packet;
    rdp_udp2_prefix udp2_prefix;
    rdp_udp2_packet_kind udp2_kind;
    rdp_udp2_ack_vector_entry udp2_ack_entry;
    uint8_t cookie_hash[32];
    uint8_t correlation_id[16];
    uint8_t ack_vec_bytes[16];
    uint32_t received_count = 0;
    uint32_t pending_count = 0;
    uint32_t lost_count = 0;
    size_t i = 0;

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&wire);
    rdp_buffer_init(&unwrapped);
    memset(cookie_hash, 0x5a, sizeof(cookie_hash));
    memset(ack_vec_bytes, 0, sizeof(ack_vec_bytes));
    for (i = 0; i < sizeof(correlation_id); i++)
        correlation_id[i] = (uint8_t)(i + 1u);

    fec_header.source_ack = 0x11223344u;
    fec_header.receive_window_size = 64;
    fec_header.flags = RDP_UDP_FLAG_SYN | RDP_UDP_FLAG_ACK | RDP_UDP_FLAG_SYNEX;
    TCHECK(rdp_udp_write_fec_header(&buffer, &fec_header) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_fec_header(buffer.data, buffer.length, &fec_header) == LIBRDP_STATUS_OK);
    TCHECK(fec_header.source_ack == 0x11223344u);
    buffer.data[7] = 0x80u;
    TCHECK(rdp_udp_parse_fec_header(buffer.data, buffer.length, &fec_header) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    fec_payload.coded_sequence = 1;
    fec_payload.source_start = 2;
    fec_payload.range = 3;
    fec_payload.fec_index = 4;
    fec_payload.padding = 0;
    TCHECK(rdp_udp_write_fec_payload_header(&buffer, &fec_payload) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_fec_payload_header(buffer.data, buffer.length, &fec_payload) ==
           LIBRDP_STATUS_OK);
    TCHECK(fec_payload.coded_sequence == 1 && fec_payload.source_start == 2);
    buffer.data[10] = 1;
    TCHECK(rdp_udp_parse_fec_payload_header(buffer.data, buffer.length, &fec_payload) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[10] = 0;
    fec_payload.padding = 1;
    TCHECK(rdp_udp_write_fec_payload_header(&buffer, &fec_payload) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    TCHECK(rdp_udp_write_payload_prefix(&buffer, sizeof(payload)) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_payload_prefix(buffer.data, buffer.length, &payload_prefix) == LIBRDP_STATUS_OK);
    TCHECK(payload_prefix.payload_size == sizeof(payload));
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    source_header.coded_sequence = 5;
    source_header.source_start = 6;
    TCHECK(rdp_udp_write_source_payload_header(&buffer, &source_header) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_source_payload_header(buffer.data, buffer.length, &source_header) ==
           LIBRDP_STATUS_OK);
    TCHECK(source_header.coded_sequence == 5 && source_header.source_start == 6);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    syn.initial_sequence_number = 7;
    syn.upstream_mtu = RDP_UDP_MIN_MTU;
    syn.downstream_mtu = RDP_UDP_MAX_MTU;
    TCHECK(rdp_udp_write_syn_data(&buffer, &syn) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_syn_data(buffer.data, buffer.length, &syn) == LIBRDP_STATUS_OK);
    TCHECK(syn.upstream_mtu == RDP_UDP_MIN_MTU && syn.downstream_mtu == RDP_UDP_MAX_MTU);
    buffer.data[4] = 1;
    buffer.data[5] = 0;
    TCHECK(rdp_udp_parse_syn_data(buffer.data, buffer.length, &syn) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    ack_of_ack.reset_sequence_number = 99;
    TCHECK(rdp_udp_write_ack_of_ack_vector(&buffer, &ack_of_ack) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_ack_of_ack_vector(buffer.data, buffer.length, &ack_of_ack) ==
           LIBRDP_STATUS_OK);
    TCHECK(ack_of_ack.reset_sequence_number == 99);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    TCHECK(rdp_udp_write_ack_vector(&buffer, payload, 3) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_ack_vector(buffer.data, buffer.length, &ack_vector) == LIBRDP_STATUS_OK);
    TCHECK(ack_vector.size == 3 && ack_vector.padding_len == 3);
    TCHECK(rdp_udp_ack_vector_decode_entry(0x00u, &ack_entry) == LIBRDP_STATUS_OK);
    TCHECK(ack_entry.state == RDP_UDP_ACK_VECTOR_STATE_RECEIVED && ack_entry.run_length == 0);
    TCHECK(rdp_udp_ack_vector_decode_entry(0xc2u, &ack_entry) == LIBRDP_STATUS_OK);
    TCHECK(ack_entry.state == RDP_UDP_ACK_VECTOR_STATE_PENDING && ack_entry.run_length == 2);
    TCHECK(rdp_udp_ack_vector_decode_entry(0x40u, &ack_entry) == LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[0] = 0x01;
    buffer.data[1] = 0x08;
    TCHECK(rdp_udp_parse_ack_vector(buffer.data, buffer.length, &ack_vector) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    TCHECK(rdp_udp_write_correlation_id(&buffer, correlation_id) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_correlation_id(buffer.data, buffer.length, &correlation) == LIBRDP_STATUS_OK);
    TCHECK(correlation.correlation_id[0] == 1);
    buffer.data[31] = 1;
    TCHECK(rdp_udp_parse_correlation_id(buffer.data, buffer.length, &correlation) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    syn_ex.flags = RDP_UDP_SYNEX_VERSION_INFO_VALID;
    syn_ex.udp_version = RDP_UDP_PROTOCOL_VERSION_3;
    syn_ex.has_cookie_hash = 1;
    memcpy(syn_ex.cookie_hash, cookie_hash, sizeof(cookie_hash));
    TCHECK(rdp_udp_write_syn_data_ex(&buffer, &syn_ex) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_syn_data_ex(buffer.data, buffer.length, &syn_ex) == LIBRDP_STATUS_OK);
    TCHECK(syn_ex.has_cookie_hash && memcmp(syn_ex.cookie_hash, cookie_hash, sizeof(cookie_hash)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    udp2_header.flags = RDP_UDP2_FLAG_DATA;
    udp2_header.log_window_size = 4;
    TCHECK(rdp_udp2_write_header(&buffer, &udp2_header) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_parse_header(buffer.data, buffer.length, &udp2_header) == LIBRDP_STATUS_OK);
    TCHECK(udp2_header.flags == RDP_UDP2_FLAG_DATA && udp2_header.log_window_size == 4);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    TCHECK(rdp_udp2_write_data_packet(&buffer, 4, 0x1234u, payload, sizeof(payload)) ==
           LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_validate_packet(&udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(udp2_packet.has_data && udp2_packet.data_sequence_number == 0x1234u);
    TCHECK(udp2_packet.data_body_len == sizeof(payload));
    TCHECK(rdp_udp2_classify_packet(&udp2_packet, &udp2_kind) == LIBRDP_STATUS_OK);
    TCHECK(udp2_kind == RDP_UDP2_PACKET_KIND_DATA);
    TCHECK(rdp_udp2_wrap_packet(&wire,
                                buffer.data,
                                buffer.length,
                                RDP_UDP2_PACKET_TYPE_DATA) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_unwrap_packet(&unwrapped, wire.data, wire.length, &udp2_prefix) == LIBRDP_STATUS_OK);
    TCHECK(udp2_prefix.packet_type == RDP_UDP2_PACKET_TYPE_DATA);
    TCHECK(unwrapped.length == buffer.length && memcmp(unwrapped.data, buffer.data, buffer.length) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&wire);
    rdp_buffer_free(&unwrapped);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&wire);
    rdp_buffer_init(&unwrapped);

    TCHECK(rdp_udp2_write_ack_packet(&buffer, 5, 0x1010u, 0x00aabbccu, 12, payload, 2, 1) ==
           LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_validate_packet(&udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(udp2_packet.has_ack && udp2_packet.ack.sequence_number == 0x1010u);
    TCHECK(udp2_packet.ack.delayed_ack_count == 2 && udp2_packet.ack.delayed_ack_time_scale == 1);
    TCHECK(rdp_udp2_classify_packet(&udp2_packet, &udp2_kind) == LIBRDP_STATUS_OK);
    TCHECK(udp2_kind == RDP_UDP2_PACKET_KIND_ACK);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    memset(&udp2_packet, 0, sizeof(udp2_packet));
    udp2_packet.header.flags = RDP_UDP2_FLAG_ACK | RDP_UDP2_FLAG_OVERHEADSIZE |
                               RDP_UDP2_FLAG_DELAYACKINFO | RDP_UDP2_FLAG_AOA |
                               RDP_UDP2_FLAG_DATA;
    udp2_packet.header.log_window_size = 3;
    udp2_packet.has_ack = 1;
    udp2_packet.ack.sequence_number = 0x1111u;
    udp2_packet.ack.received_timestamp = 0x00010203u;
    udp2_packet.ack.send_ack_time_gap_ms = 7;
    udp2_packet.has_overhead_size = 1;
    udp2_packet.overhead_size = 9;
    udp2_packet.has_delay_ack_info = 1;
    udp2_packet.max_delayed_acks = 4;
    udp2_packet.delayed_ack_timeout_ms = 50;
    udp2_packet.has_ack_of_acks = 1;
    udp2_packet.ack_of_acks_sequence_number = 0x2222u;
    udp2_packet.has_data = 1;
    udp2_packet.data_sequence_number = 0x3333u;
    udp2_packet.data_body = payload;
    udp2_packet.data_body_len = sizeof(payload);
    TCHECK(rdp_udp2_write_packet(&buffer, &udp2_packet) == LIBRDP_STATUS_OK);
    udp2_packet.has_data = 0;
    TCHECK(rdp_udp2_validate_packet(&udp2_packet) == LIBRDP_STATUS_PROTOCOL_ERROR);
    TCHECK(rdp_udp2_write_packet(&wire, &udp2_packet) == LIBRDP_STATUS_INVALID_ARGUMENT);
    TCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_validate_packet(&udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(udp2_packet.has_ack && udp2_packet.has_overhead_size &&
           udp2_packet.has_delay_ack_info && udp2_packet.has_ack_of_acks && udp2_packet.has_data);
    TCHECK(udp2_packet.data_body_len == sizeof(payload) &&
           memcmp(udp2_packet.data_body, payload, sizeof(payload)) == 0);
    TCHECK(rdp_udp2_classify_packet(&udp2_packet, &udp2_kind) == LIBRDP_STATUS_OK);
    TCHECK(udp2_kind == RDP_UDP2_PACKET_KIND_DATA_WITH_ACK);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&wire);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&wire);

    ack_vec_bytes[0] = 0x02u;
    ack_vec_bytes[1] = 0xc2u;
    ack_vector.size = 2;
    ack_vector.vector = ack_vec_bytes;
    TCHECK(rdp_udp_ack_vector_count(&ack_vector, &received_count, &pending_count) == LIBRDP_STATUS_OK);
    TCHECK(received_count == 3 && pending_count == 3);

    TCHECK(rdp_udp2_write_ack_vector_packet(&buffer, 4, 0x2020u, 1, 0x00030201u, 4, payload, 2) ==
           LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_validate_packet(&udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(udp2_packet.has_ack_vector && udp2_packet.ack_vector.timestamp_present);
    TCHECK(udp2_packet.ack_vector.coded_ack_vector_size == 2);
    TCHECK(rdp_udp2_classify_packet(&udp2_packet, &udp2_kind) == LIBRDP_STATUS_OK);
    TCHECK(udp2_kind == RDP_UDP2_PACKET_KIND_ACK_VECTOR);
    TCHECK(rdp_udp2_ack_vector_decode_entry(0x55u, &udp2_ack_entry) == LIBRDP_STATUS_OK);
    TCHECK(udp2_ack_entry.mode == RDP_UDP2_ACK_VECTOR_MODE_BITMAP && udp2_ack_entry.bitmap == 0x55u);
    TCHECK(rdp_udp2_ack_vector_decode_entry(0xc2u, &udp2_ack_entry) == LIBRDP_STATUS_OK);
    TCHECK(udp2_ack_entry.mode == RDP_UDP2_ACK_VECTOR_MODE_RLE &&
           udp2_ack_entry.state == RDP_UDP2_ACK_VECTOR_STATE_RECEIVED &&
           udp2_ack_entry.run_length == 2);
    ack_vec_bytes[0] = 0x7fu;
    ack_vec_bytes[1] = 0xc2u;
    ack_vec_bytes[2] = 0x80u;
    ack_vec_bytes[3] = 0xffu;
    udp2_packet.ack_vector.coded_ack_vector = ack_vec_bytes;
    udp2_packet.ack_vector.coded_ack_vector_size = 4;
    TCHECK(rdp_udp2_ack_vector_count(&udp2_packet.ack_vector, &received_count, &lost_count) ==
           LIBRDP_STATUS_OK);
    TCHECK(received_count == 74 && lost_count == 1);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    TCHECK(rdp_udp2_write_ack_of_acks_packet(&buffer, 4, 0x3030u) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_validate_packet(&udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(udp2_packet.has_ack_of_acks && udp2_packet.ack_of_acks_sequence_number == 0x3030u);
    TCHECK(!udp2_packet.has_ack && !udp2_packet.has_data && !udp2_packet.has_ack_vector);
    TCHECK(rdp_udp2_classify_packet(&udp2_packet, &udp2_kind) == LIBRDP_STATUS_OK);
    TCHECK(udp2_kind == RDP_UDP2_PACKET_KIND_ACK_OF_ACKS);
    TCHECK(rdp_udp2_write_ack_of_acks_packet(NULL, 4, 0x3030u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    TCHECK(rdp_udp2_unwrap_packet(&unwrapped,
                                  wire_example,
                                  sizeof(wire_example),
                                  &udp2_prefix) == LIBRDP_STATUS_OK);
    TCHECK(udp2_prefix.packet_type == RDP_UDP2_PACKET_TYPE_DUMMY);
    TCHECK(unwrapped.length == sizeof(layout_example));
    TCHECK(memcmp(unwrapped.data, layout_example, sizeof(layout_example)) == 0);

    rdp_buffer_free(&unwrapped);
    rdp_buffer_free(&wire);
    rdp_buffer_free(&buffer);
    return 0;
}

static int test_multitransport_protocol(void)
{
    uint8_t cookie[RDP_MULTITRANSPORT_COOKIE_LENGTH];
    const uint8_t autodetect[] = {0xaa, 0xbb};
    const uint8_t payload[] = {1, 2, 3, 4, 5};
    const uint8_t bad_subheader[] = {0x01u, RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_REQUEST};
    rdp_buffer buffer;
    rdp_buffer subheader;
    rdp_multitransport_header header;
    rdp_multitransport_subheader parsed_subheader;
    rdp_multitransport_create_request request;
    rdp_multitransport_create_response response;
    rdp_multitransport_data tunnel_data;
    uint16_t subheader_count = 0;
    size_t i = 0;

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&subheader);
    for (i = 0; i < sizeof(cookie); i++)
        cookie[i] = (uint8_t)i;

    TCHECK(rdp_multitransport_write_create_request(&buffer, 7, cookie) == LIBRDP_STATUS_OK);
    TCHECK(rdp_multitransport_parse_header(buffer.data, buffer.length, &header) == LIBRDP_STATUS_OK);
    TCHECK(header.action == RDP_MULTITRANSPORT_ACTION_CREATE_REQUEST);
    TCHECK(rdp_multitransport_parse_create_request(buffer.data, buffer.length, &request) ==
           LIBRDP_STATUS_OK);
    TCHECK(request.request_id == 7 && memcmp(request.security_cookie, cookie, sizeof(cookie)) == 0);
    buffer.data[8] = 1;
    TCHECK(rdp_multitransport_parse_create_request(buffer.data, buffer.length, &request) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    TCHECK(rdp_multitransport_write_create_response(&buffer, 0) == LIBRDP_STATUS_OK);
    TCHECK(rdp_multitransport_parse_create_response(buffer.data, buffer.length, &response) ==
           LIBRDP_STATUS_OK);
    TCHECK(response.hresult == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    TCHECK(rdp_multitransport_write_subheader(&subheader,
                                              RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_REQUEST,
                                              autodetect,
                                              sizeof(autodetect)) == LIBRDP_STATUS_OK);
    TCHECK(rdp_multitransport_write_subheader(&subheader,
                                              RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_RESPONSE,
                                              autodetect,
                                              sizeof(autodetect)) == LIBRDP_STATUS_OK);
    TCHECK(rdp_multitransport_parse_subheader(subheader.data, subheader.length, &parsed_subheader) ==
           LIBRDP_STATUS_OK);
    TCHECK(parsed_subheader.length == sizeof(autodetect) + 2u);
    TCHECK(parsed_subheader.data_len == 2);
    TCHECK(memcmp(parsed_subheader.data, autodetect, sizeof(autodetect)) == 0);
    TCHECK(rdp_multitransport_count_subheaders(subheader.data,
                                               subheader.length,
                                               &subheader_count) == LIBRDP_STATUS_OK);
    TCHECK(subheader_count == 2u);
    TCHECK(rdp_multitransport_write_subheader(&buffer, 0xffu, autodetect, sizeof(autodetect)) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    TCHECK(rdp_multitransport_write_data(&buffer,
                                         bad_subheader,
                                         sizeof(bad_subheader),
                                         payload,
                                         sizeof(payload)) == LIBRDP_STATUS_INVALID_ARGUMENT);

    TCHECK(rdp_multitransport_write_data(&buffer,
                                         subheader.data,
                                         subheader.length,
                                         payload,
                                         sizeof(payload)) == LIBRDP_STATUS_OK);
    TCHECK(rdp_multitransport_parse_data(buffer.data, buffer.length, &tunnel_data) == LIBRDP_STATUS_OK);
    TCHECK(tunnel_data.header.header_length == RDP_MULTITRANSPORT_HEADER_LENGTH + subheader.length);
    TCHECK(tunnel_data.data_len == sizeof(payload));
    TCHECK(memcmp(tunnel_data.data, payload, sizeof(payload)) == 0);
    buffer.data[0] = 0xf2u;
    TCHECK(rdp_multitransport_parse_data(buffer.data, buffer.length, &tunnel_data) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[0] = RDP_MULTITRANSPORT_ACTION_DATA;
    buffer.data[RDP_MULTITRANSPORT_HEADER_LENGTH + parsed_subheader.length + 1u] = 0xffu;
    TCHECK(rdp_multitransport_parse_data(buffer.data, buffer.length, &tunnel_data) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&buffer);
    rdp_buffer_free(&subheader);
    return 0;
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

    TCHECK(test_udp_transport_protocols() == 0);
    TCHECK(test_multitransport_protocol() == 0);

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
