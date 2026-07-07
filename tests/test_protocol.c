#include "channels/virtual_channel.h"
#include "clipboard/clipboard.h"
#include "common/buffer.h"
#include "common/stream.h"
#include "graphics/bitmap.h"
#include "licensing/licensing.h"
#include "nla/credssp.h"
#include "protocol/capabilities.h"
#include "protocol/fastpath.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"

#include <openssl/evp.h>

#include <stdio.h>
#include <string.h>

#define PCHECK(expr)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

static uint16_t test_read_u16_le(const uint8_t* data)
{
    return (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
}

static uint32_t test_read_u32_le(const uint8_t* data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static int test_sha256_three(const uint8_t* a,
                             size_t a_len,
                             const uint8_t* b,
                             size_t b_len,
                             const uint8_t* c,
                             size_t c_len,
                             uint8_t out[32])
{
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    unsigned int got = 0;
    int ok = 0;

    if (!context)
        return 0;
    if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1)
        goto out;
    if (EVP_DigestUpdate(context, a, a_len) != 1)
        goto out;
    if (EVP_DigestUpdate(context, b, b_len) != 1)
        goto out;
    if (EVP_DigestUpdate(context, c, c_len) != 1)
        goto out;
    if (EVP_DigestFinal_ex(context, out, &got) != 1 || got != 32u)
        goto out;
    ok = 1;

out:
    EVP_MD_CTX_free(context);
    return ok;
}

static int test_tpkt_x224(void)
{
    rdp_buffer x224;
    rdp_buffer x224_data;
    rdp_buffer packet;
    rdp_tpkt parsed;
    rdp_x224_connection_confirm confirm;
    const uint8_t* mcs_payload = NULL;
    size_t mcs_payload_len = 0;
    const uint8_t cc_payload[] = {
        0x0e, 0xd0, 0x12, 0x34, 0x56, 0x78, 0x00,
        0x02, 0x00, 0x08, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    const uint8_t bad_tpkt[] = {0x03, 0x00, 0x00, 0x03};

    rdp_buffer_init(&x224);
    rdp_buffer_init(&x224_data);
    rdp_buffer_init(&packet);

    PCHECK(rdp_x224_build_connection_request(&x224, "user", RDP_X224_PROTOCOL_TLS | RDP_X224_PROTOCOL_NLA) ==
           LIBRDP_STATUS_OK);
    PCHECK(x224.length > 8);
    PCHECK(x224.data[1] == 0xe0);
    PCHECK(rdp_tpkt_write(&packet, x224.data, x224.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_tpkt_parse(packet.data, packet.length, &parsed) == LIBRDP_STATUS_OK);
    PCHECK(parsed.payload_len == x224.length);
    PCHECK(memcmp(parsed.payload, x224.data, x224.length) == 0);
    PCHECK(rdp_tpkt_parse(bad_tpkt, sizeof(bad_tpkt), &parsed) == LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_x224_parse_connection_confirm(cc_payload, sizeof(cc_payload), &confirm) == LIBRDP_STATUS_OK);
    PCHECK(confirm.destination_ref == 0x1234);
    PCHECK(confirm.source_ref == 0x5678);
    PCHECK(confirm.negotiation.present);
    PCHECK(!confirm.negotiation.failure);
    PCHECK(confirm.negotiation.selected_protocol == 0);
    PCHECK(rdp_x224_parse_connection_confirm(cc_payload, 4, &confirm) == LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_x224_wrap_data(&x224_data, cc_payload, sizeof(cc_payload)) == LIBRDP_STATUS_OK);
    PCHECK(x224_data.length == sizeof(cc_payload) + 3u);
    PCHECK(x224_data.data[0] == 0x02 && x224_data.data[1] == 0xf0 && x224_data.data[2] == 0x80);
    PCHECK(rdp_x224_parse_data(x224_data.data, x224_data.length, &mcs_payload, &mcs_payload_len) == LIBRDP_STATUS_OK);
    PCHECK(mcs_payload_len == sizeof(cc_payload));
    PCHECK(memcmp(mcs_payload, cc_payload, sizeof(cc_payload)) == 0);
    PCHECK(rdp_x224_parse_data(cc_payload, sizeof(cc_payload), &mcs_payload, &mcs_payload_len) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&packet);
    rdp_buffer_free(&x224_data);
    rdp_buffer_free(&x224);
    return 0;
}

static int test_mcs_gcc_capabilities(void)
{
    const uint8_t ber_short[] = {0x7f};
    const uint8_t ber_long[] = {0x82, 0x01, 0x23};
    const uint8_t ber_bad[] = {0x80};
    const uint8_t mcs_resp[] = {0x0a, 0x01, 0x00};
    const uint8_t mcs_wrapped_resp[] = {0x7f, 0x66, 0x03, 0x0a, 0x01, 0x00};
    const uint8_t mcs_resp_user_data[] = {0x7f, 0x66, 0x08, 0x0a, 0x01, 0x00, 0x04, 0x03, 7, 8, 9};
    const uint8_t gcc_block[] = {0xc1, 0x00, 0x08, 0x00, 1, 2, 3, 4};
    const uint8_t gcc_server_blocks[] = {
        0x01, 0x0c, 0x10, 0x00, 0x04, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x02, 0x0c, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x0c, 0x0a, 0x00, 0xeb, 0x03, 0x01, 0x00, 0xec, 0x03
    };
    const uint8_t gcc_response[] = {
        0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, 0x34, 0x14, 0x00, 0x03, 0x01, 0x2a, 0x00, 0x01,
        0xc0, 0x00, 'M',  'c',  'D',  'n',  0x26,
        0x01, 0x0c, 0x10, 0x00, 0x04, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x02, 0x0c, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x0c, 0x0a, 0x00, 0xeb, 0x03, 0x01, 0x00, 0xec, 0x03
    };
    const uint8_t caps[] = {
        0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x08, 0x00, 0xaa, 0xbb, 0xcc, 0xdd,
        0x02, 0x00, 0x04, 0x00
    };
    rdp_stream stream;
    size_t length = 0;
    rdp_mcs_connect_response response;
    rdp_gcc_user_data_block block;
    rdp_capability_list list;
    rdp_buffer ber;
    rdp_buffer client_blocks;
    rdp_buffer gcc_request;
    rdp_buffer mcs_initial;
    rdp_buffer mcs_domain;
    rdp_gcc_client_config config;
    rdp_gcc_client_data_summary summary;
    rdp_gcc_conference_response conference_response;
    rdp_gcc_server_data server_data;
    rdp_mcs_attach_user_confirm attach;
    rdp_mcs_channel_join_confirm join;
    const uint8_t attach_confirm[] = {0x2e, 0x00, 0x00, 0x03};
    const uint8_t join_confirm[] = {0x3e, 0x00, 0x00, 0x03, 0x03, 0xec, 0x03, 0xec};

    rdp_buffer_init(&ber);
    rdp_buffer_init(&client_blocks);
    rdp_buffer_init(&gcc_request);
    rdp_buffer_init(&mcs_initial);
    rdp_buffer_init(&mcs_domain);

    rdp_stream_init(&stream, ber_short, sizeof(ber_short));
    PCHECK(rdp_mcs_read_ber_length(&stream, &length) == LIBRDP_STATUS_OK && length == 0x7f);
    rdp_stream_init(&stream, ber_long, sizeof(ber_long));
    PCHECK(rdp_mcs_read_ber_length(&stream, &length) == LIBRDP_STATUS_OK && length == 0x123);
    rdp_stream_init(&stream, ber_bad, sizeof(ber_bad));
    PCHECK(rdp_mcs_read_ber_length(&stream, &length) == LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_mcs_parse_connect_response(mcs_resp, sizeof(mcs_resp), &response) == LIBRDP_STATUS_OK);
    PCHECK(response.has_result && response.result == 0);
    PCHECK(rdp_mcs_parse_connect_response(mcs_wrapped_resp, sizeof(mcs_wrapped_resp), &response) == LIBRDP_STATUS_OK);
    PCHECK(response.has_result && response.result == 0);
    PCHECK(rdp_mcs_parse_connect_response(mcs_resp_user_data, sizeof(mcs_resp_user_data), &response) ==
           LIBRDP_STATUS_OK);
    PCHECK(response.has_result && response.result == 0);
    PCHECK(response.user_data_len == 3 && response.user_data[0] == 7 && response.user_data[2] == 9);

    PCHECK(rdp_mcs_write_ber_length(&ber, 0x7f) == LIBRDP_STATUS_OK);
    PCHECK(rdp_mcs_write_ber_length(&ber, 0x123) == LIBRDP_STATUS_OK);
    PCHECK(ber.length == 4);
    PCHECK(ber.data[0] == 0x7f && ber.data[1] == 0x82 && ber.data[2] == 0x01 && ber.data[3] == 0x23);
    rdp_buffer_free(&ber);
    rdp_buffer_init(&ber);
    PCHECK(rdp_mcs_write_ber_integer(&ber, 0x80) == LIBRDP_STATUS_OK);
    PCHECK(ber.length == 4 && ber.data[0] == 0x02 && ber.data[1] == 0x02 && ber.data[2] == 0x00 &&
           ber.data[3] == 0x80);

    rdp_stream_init(&stream, gcc_block, sizeof(gcc_block));
    PCHECK(rdp_gcc_read_user_data_block(&stream, &block) == LIBRDP_STATUS_OK);
    PCHECK(block.type == 0x00c1);
    PCHECK(block.payload_len == 4 && block.payload[3] == 4);
    PCHECK(rdp_gcc_parse_server_data_blocks(gcc_server_blocks, sizeof(gcc_server_blocks), &server_data) ==
           LIBRDP_STATUS_OK);
    PCHECK(server_data.has_core && server_data.has_security && server_data.has_network);
    PCHECK(server_data.version == 0x00080004u && server_data.requested_protocols == 2);
    PCHECK(server_data.early_capability_flags == 0x40);
    PCHECK(server_data.encryption_method == 0 && server_data.encryption_level == 0);
    PCHECK(server_data.mcs_channel_id == 1003 && server_data.channel_count == 1 && server_data.channel_ids[0] == 1004);
    PCHECK(rdp_gcc_parse_server_data_blocks(gcc_server_blocks, sizeof(gcc_server_blocks) - 1u, &server_data) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_gcc_parse_conference_create_response(gcc_response, sizeof(gcc_response), &conference_response) ==
           LIBRDP_STATUS_OK);
    PCHECK(conference_response.node_id == 1004 && conference_response.tag == 42 && conference_response.result == 0);
    PCHECK(conference_response.user_data_len == sizeof(gcc_server_blocks));
    PCHECK(memcmp(conference_response.user_data, gcc_server_blocks, sizeof(gcc_server_blocks)) == 0);
    PCHECK(rdp_gcc_parse_server_data_blocks(conference_response.user_data,
                                            conference_response.user_data_len,
                                            &server_data) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gcc_parse_conference_create_response(gcc_response, sizeof(gcc_response) - 1u, &conference_response) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_capabilities_parse(caps, sizeof(caps), &list) == LIBRDP_STATUS_OK);
    PCHECK(list.count == 2);
    PCHECK(list.sets[0].type == 1 && list.sets[0].data_len == 4);
    PCHECK(list.sets[1].type == 2 && list.sets[1].data_len == 0);
    PCHECK(rdp_capabilities_parse(caps, 5, &list) == LIBRDP_STATUS_PROTOCOL_ERROR);

    config.desktop_width = 1024;
    config.desktop_height = 768;
    config.requested_protocols = 0;
    config.client_name = "librdp";
    PCHECK(rdp_gcc_write_client_data_blocks(&client_blocks, &config) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gcc_parse_client_data_blocks(client_blocks.data, client_blocks.length, &summary) == LIBRDP_STATUS_OK);
    PCHECK(summary.has_core && summary.has_security && summary.has_network);
    PCHECK(summary.desktop_width == 1024 && summary.desktop_height == 768);
    PCHECK(summary.version == 0x00080004u);
    PCHECK(summary.channel_count == 0);
    PCHECK(rdp_gcc_write_conference_create_request(&gcc_request, client_blocks.data, client_blocks.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(gcc_request.length > client_blocks.length);
    PCHECK(gcc_request.data[0] == 0 && gcc_request.data[1] == 5);
    PCHECK(rdp_mcs_write_connect_initial(&mcs_initial, gcc_request.data, gcc_request.length) == LIBRDP_STATUS_OK);
    PCHECK(mcs_initial.length > gcc_request.length);
    PCHECK(mcs_initial.data[0] == 0x7f && mcs_initial.data[1] == 0x65);

    PCHECK(rdp_mcs_write_erect_domain_request(&mcs_domain) == LIBRDP_STATUS_OK);
    PCHECK(mcs_domain.length == 5);
    PCHECK(mcs_domain.data[0] == 0x04 && mcs_domain.data[1] == 0x01 && mcs_domain.data[2] == 0x00 &&
           mcs_domain.data[3] == 0x01 && mcs_domain.data[4] == 0x00);
    rdp_buffer_free(&mcs_domain);
    rdp_buffer_init(&mcs_domain);
    PCHECK(rdp_mcs_write_attach_user_request(&mcs_domain) == LIBRDP_STATUS_OK);
    PCHECK(mcs_domain.length == 1 && mcs_domain.data[0] == 0x28);
    PCHECK(rdp_mcs_parse_attach_user_confirm(attach_confirm, sizeof(attach_confirm), &attach) == LIBRDP_STATUS_OK);
    PCHECK(attach.result == 0 && attach.user_id == 1004);
    PCHECK(rdp_mcs_parse_attach_user_confirm(join_confirm, sizeof(join_confirm), &attach) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&mcs_domain);
    rdp_buffer_init(&mcs_domain);
    PCHECK(rdp_mcs_write_channel_join_request(&mcs_domain, 1004, 1004) == LIBRDP_STATUS_OK);
    PCHECK(mcs_domain.length == 5);
    PCHECK(mcs_domain.data[0] == 0x38 && mcs_domain.data[1] == 0x00 && mcs_domain.data[2] == 0x03 &&
           mcs_domain.data[3] == 0x03 && mcs_domain.data[4] == 0xec);
    PCHECK(rdp_mcs_parse_channel_join_confirm(join_confirm, sizeof(join_confirm), &join) == LIBRDP_STATUS_OK);
    PCHECK(join.result == 0 && join.initiator == 1004 && join.requested_channel_id == 1004 &&
           join.channel_id == 1004);
    PCHECK(rdp_mcs_write_channel_join_request(&mcs_domain, 1000, 1004) == LIBRDP_STATUS_INVALID_ARGUMENT);

    rdp_buffer_free(&mcs_domain);
    rdp_buffer_free(&mcs_initial);
    rdp_buffer_free(&gcc_request);
    rdp_buffer_free(&client_blocks);
    rdp_buffer_free(&ber);
    return 0;
}

static int test_path_security_license_channels(void)
{
    const uint8_t fast_short[] = {0x00, 0x06, 1, 2, 3, 4};
    const uint8_t fast_long[] = {0x40, 0x80, 0x08, 1, 2, 3, 4, 5};
    const uint8_t slow[] = {0x06, 0x00, 0x13, 0x00, 0xea, 0x03};
    const uint8_t demand_active[] = {
        0x1d, 0x00, 0x11, 0x00, 0xea, 0x03, 0x78, 0x56, 0x34, 0x12,
        0x03, 0x00, 0x0c, 0x00, 's',  'r',  'v',  0x01, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x08, 0x00, 0xaa, 0xbb, 0xcc, 0xdd
    };
    const uint8_t bitmap_data_pdu[] = {
        0x3a, 0x00, 0x17, 0x00, 0xec, 0x03, 0x78, 0x56, 0x34, 0x12,
        0x00, 0x01, 0x28, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        1,    2,    3,    4,    5,    6,    7,    8,
        9,    10,   11,   12,   13,   14,   15,   16
    };
    const uint8_t bitmap_24_data[] = {
        1, 2, 3, 4, 5, 6,
        7, 8, 9, 10, 11, 12
    };
    const uint8_t bitmap_16_data[] = {0x00, 0xf8, 0xe0, 0x07};
    const uint8_t fast_bitmap_update[] = {
        0x00, 0x2b, 0x01, 0x26, 0x00,
        0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        1,    2,    3,    4,    5,    6,    7,    8,
        9,    10,   11,   12,   13,   14,   15,   16
    };
    const uint8_t license[] = {
        0xff, 0x03, 0x12, 0x00,
        1, 0, 0, 0,
        2, 0, 0, 0,
        3, 0, 2, 0,
        9, 8
    };
    const uint8_t channel[] = {3, 0, 0, 0, 0x10, 0, 0, 0, 1, 2, 3};
    const uint8_t clip[] = {1, 0, 2, 0, 3, 0, 0, 0, 4, 5, 6};
    const uint8_t indication_pdu[] = {0x68, 0x00, 0x03, 0x03, 0xeb, 0x70, 0x04, 1, 2, 3, 4};
    const uint8_t encrypted_random[] = {1, 2, 3, 4, 5};
    const uint8_t ntlm_challenge_token[] = {
        'N',  'T',  'L',  'M',  'S',  'S',  'P',  0,
        2,    0,    0,    0,
        4,    0,    4,    0,    56,   0,    0,    0,
        1,    2,    3,    4,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0,    0,    0,    0,    0,    0,    0,    0,
        8,    0,    8,    0,    60,   0,    0,    0,
        0,    0,    0,    0,    0,    0,    0,    0,
        'S',  0,    'R',  0,
        1,    0,    4,    0,    'A',  0,    0,    0
    };
    const uint8_t wrapped_ntlm_challenge[] = {
        0xa1, 0x4c, 0x30, 0x4a, 0xa2, 0x48, 0x04, 0x46,
        'N',  'T',  'L',  'M',  'S',  'S',  'P',  0,
        2,    0,    0,    0,
        4,    0,    4,    0,    56,   0,    0,    0,
        1,    2,    3,    4,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0,    0,    0,    0,    0,    0,    0,    0,
        8,    0,    8,    0,    60,   0,    0,    0,
        0,    0,    0,    0,    0,    0,    0,    0,
        'S',  0,    'R',  0,
        1,    0,    4,    0,    'A',  0,    0,    0
    };
    const uint8_t ntlm_v2_target_name[] = {'D', 0, 'O', 0, 'M', 0, 'A', 0, 'I', 0, 'N', 0};
    const uint8_t ntlm_v2_target_info[] = {
        0x02, 0x00, 0x0c, 0x00, 'D', 0, 'O', 0, 'M', 0, 'A', 0, 'I', 0, 'N', 0,
        0x01, 0x00, 0x0c, 0x00, 'S', 0, 'E', 0, 'R', 0, 'V', 0, 'E', 0, 'R', 0,
        0x04, 0x00, 0x14, 0x00, 'd', 0, 'o', 0, 'm', 0, 'a', 0, 'i', 0, 'n', 0,
        '.', 0,    'c', 0,    'o', 0,    'm', 0,
        0x03, 0x00, 0x22, 0x00, 's', 0, 'e', 0, 'r', 0, 'v', 0, 'e', 0, 'r', 0,
        '.', 0,    'd', 0,    'o', 0,    'm', 0, 'a', 0, 'i', 0, 'n', 0, '.', 0,
        'c', 0,    'o', 0,    'm', 0,
        0x00, 0x00, 0x00, 0x00
    };
    const uint8_t ntlm_v2_server_challenge[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    const uint8_t ntlm_v2_client_challenge[] = {0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44};
    const uint8_t ntlm_v2_session_key[] = {
        0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xfe, 0xdc,
        0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x99, 0x88
    };
    const uint8_t credssp_client_nonce[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const uint8_t credssp_public_key[] = {
        0x30, 0x13, 0x02, 0x0f, 0x00, 0xb8, 0x2d, 0xf1,
        0xa8, 0x88, 0x3d, 0xa8, 0xfb, 0xa6, 0x99, 0xf8,
        0x74, 0x2e, 0xc3, 0x02, 0x03, 0x01, 0x00, 0x01
    };
    const uint8_t ntlm_v2_expected_lm[] = {
        0xd6, 0xe6, 0x15, 0x2e, 0xa2, 0x5d, 0x03, 0xb7,
        0xc6, 0xba, 0x66, 0x29, 0xc2, 0xd6, 0xaa, 0xf0,
        0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44
    };
    const uint8_t ntlm_v2_expected_proof[] = {
        0x29, 0x15, 0x7f, 0x79, 0xa3, 0x08, 0x93, 0x53,
        0x78, 0x3e, 0x24, 0x4f, 0xad, 0x52, 0x8a, 0x5c
    };
    const uint8_t server_certificate[] = {
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x9c, 0x00, 0x52, 0x53, 0x41, 0x31, 0x88, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0xeb, 0x63, 0x25, 0x72, 0xe3, 0xeb, 0x4e, 0x15, 0x13, 0x3c, 0x7b, 0x9c,
        0x5c, 0x66, 0x61, 0x89, 0x0f, 0x7f, 0x79, 0x1a, 0x93, 0x75, 0x9c, 0xe2,
        0x98, 0xeb, 0xa5, 0xa6, 0x73, 0xd2, 0xc7, 0x14, 0x2c, 0x5a, 0x57, 0x10,
        0x48, 0x3b, 0x04, 0x69, 0xaf, 0x52, 0x86, 0x58, 0xe3, 0xf7, 0x05, 0xcf,
        0x22, 0x0f, 0x6e, 0x25, 0x41, 0xe0, 0x3a, 0x26, 0x62, 0x2f, 0x31, 0xcf,
        0xd5, 0x97, 0xd3, 0xa0, 0x93, 0x73, 0x4c, 0x9b, 0xc1, 0x9c, 0x2a, 0x30,
        0x66, 0x7f, 0x61, 0x25, 0x67, 0xab, 0xd3, 0xe7, 0xe2, 0x7f, 0x5e, 0x57,
        0x2a, 0x3a, 0x2b, 0x9c, 0x4f, 0x4e, 0x2c, 0xba, 0x8e, 0xf0, 0x93, 0x29,
        0x3f, 0xf7, 0xca, 0x9e, 0x46, 0xd4, 0x1e, 0x11, 0x96, 0x84, 0xef, 0x2d,
        0xa9, 0x57, 0x3d, 0x8b, 0x9b, 0x27, 0x90, 0x5b, 0x98, 0x9d, 0x5b, 0x80,
        0x64, 0x24, 0x76, 0xc0, 0xba, 0x8d, 0xe4, 0xb2, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    const uint8_t x509_der[] = {
        0x30, 0x82, 0x02, 0x08, 0x30, 0x82, 0x01, 0x71, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x2b, 0x77, 0x94, 0x65, 0x7e, 0xcb, 0xa0, 0x19, 0xd9,
        0xec, 0x74, 0x9b, 0x9a, 0xd1, 0xd1, 0x83, 0x77, 0x7f, 0x9e, 0x5a, 0x30,
        0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        0x05, 0x00, 0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x0b, 0x6c, 0x69, 0x62, 0x72, 0x64, 0x70, 0x2d, 0x74, 0x65,
        0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x37, 0x30, 0x37,
        0x31, 0x38, 0x30, 0x35, 0x34, 0x35, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x30,
        0x37, 0x30, 0x38, 0x31, 0x38, 0x30, 0x35, 0x34, 0x35, 0x5a, 0x30, 0x16,
        0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x6c,
        0x69, 0x62, 0x72, 0x64, 0x70, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x30, 0x81,
        0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02,
        0x81, 0x81, 0x00, 0xb8, 0x2d, 0xf1, 0xa8, 0x88, 0x3d, 0xa8, 0xfb, 0xa6,
        0x99, 0xf8, 0x74, 0x2e, 0xc3, 0x89, 0xab, 0x17, 0x5c, 0xb6, 0xd2, 0x7f,
        0xbd, 0x88, 0x48, 0x3f, 0x16, 0x3f, 0x94, 0x9d, 0x6a, 0xd1, 0x38, 0x5b,
        0xe8, 0x53, 0xb4, 0x1c, 0x61, 0x80, 0xef, 0xa9, 0x8c, 0xf7, 0xeb, 0x01,
        0xad, 0x87, 0xc8, 0x70, 0x55, 0x98, 0x64, 0xce, 0x24, 0x07, 0x09, 0x59,
        0x4e, 0xdf, 0x44, 0x2c, 0x4c, 0xe4, 0x44, 0xb4, 0xb1, 0x10, 0x75, 0x0e,
        0x1e, 0x38, 0xda, 0x26, 0xf4, 0x9e, 0xef, 0xec, 0x15, 0xaa, 0x2f, 0x26,
        0x35, 0xb0, 0x17, 0x9d, 0x34, 0x7e, 0x58, 0xa0, 0xeb, 0x22, 0xb3, 0xf0,
        0xff, 0x1c, 0x87, 0x7f, 0xb0, 0xf4, 0xd4, 0x3c, 0x3d, 0x59, 0xe0, 0x10,
        0x77, 0x46, 0x94, 0xa5, 0x90, 0xcf, 0x1d, 0x2c, 0xf0, 0xd7, 0x44, 0x8f,
        0x9e, 0xaa, 0x60, 0x0b, 0x16, 0x6d, 0x79, 0x5c, 0xe4, 0xdd, 0xcd, 0x02,
        0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03,
        0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x7d, 0x2f, 0xcf, 0xa9, 0x1f,
        0xc0, 0x07, 0x93, 0x49, 0xc2, 0x4d, 0xfa, 0x0f, 0x8c, 0xe4, 0x25, 0xcd,
        0x00, 0xc8, 0x15, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
        0x30, 0x16, 0x80, 0x14, 0x7d, 0x2f, 0xcf, 0xa9, 0x1f, 0xc0, 0x07, 0x93,
        0x49, 0xc2, 0x4d, 0xfa, 0x0f, 0x8c, 0xe4, 0x25, 0xcd, 0x00, 0xc8, 0x15,
        0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05,
        0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00,
        0x70, 0x99, 0xde, 0x9e, 0x51, 0xf6, 0x5a, 0x1d, 0x33, 0xab, 0xf4, 0x7b,
        0x4a, 0xa5, 0x9f, 0xf2, 0xda, 0x3a, 0xe3, 0x4d, 0x66, 0xb6, 0xfe, 0x68,
        0x44, 0x29, 0xb3, 0xe4, 0x8d, 0x8e, 0xef, 0xb4, 0x0e, 0xfc, 0xae, 0x74,
        0xb3, 0x2a, 0xf9, 0x90, 0x0c, 0x0c, 0xd6, 0xb1, 0x12, 0x6c, 0x7e, 0x6a,
        0x34, 0xb5, 0xe7, 0xc8, 0xb0, 0xee, 0x56, 0xb8, 0x02, 0xab, 0xf3, 0xe2,
        0x5e, 0xd6, 0xca, 0x4f, 0xa6, 0x3d, 0x10, 0xb1, 0x49, 0x32, 0x75, 0x07,
        0x00, 0x54, 0xa7, 0x9e, 0x65, 0xd0, 0xc4, 0x2b, 0xc4, 0xad, 0xc7, 0x3a,
        0xb9, 0xe5, 0x44, 0xdf, 0xed, 0xb8, 0x91, 0xea, 0xcc, 0x23, 0x16, 0xd3,
        0xa6, 0x23, 0x83, 0x62, 0x2d, 0x4e, 0xe4, 0x1c, 0xb8, 0x6c, 0x75, 0x61,
        0xde, 0xe6, 0x0e, 0xc8, 0xd5, 0x25, 0xc7, 0x69, 0x5a, 0xba, 0x06, 0xa3,
        0x30, 0xdb, 0xdf, 0xd2, 0xd8, 0xdc, 0xa0, 0x3f
    };
    uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    uint8_t server_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    rdp_fastpath_header fast;
    rdp_fastpath_update_list fast_updates;
    rdp_slowpath_share_control_header slow_header;
    rdp_slowpath_demand_active demand;
    rdp_slowpath_data_pdu data_pdu;
    rdp_slowpath_font_map font_map;
    rdp_slowpath_save_session_info save_info;
    rdp_bitmap_update bitmap_update;
    rdp_bitmap_update_header bitmap_header;
    rdp_bitmap_rect bitmap_rect;
    rdp_license_error_alert alert;
    rdp_virtual_channel_packet vc;
    rdp_clipboard_packet cb;
    rdp_mcs_send_data_indication indication;
    rdp_credssp_state cred_state;
    rdp_security_public_key public_key;
    rdp_standard_security_context secure_a;
    rdp_standard_security_context secure_b;
    rdp_buffer security;
    rdp_buffer send_data;
    rdp_buffer encrypted;
    rdp_buffer encrypted_info;
    rdp_buffer plain_info_body;
    rdp_buffer expected_cipher;
    rdp_buffer confirm_active;
    rdp_buffer client_sync;
    rdp_buffer client_control;
    rdp_buffer client_persistent_keys;
    rdp_buffer client_font_list;
    rdp_buffer client_keyboard_input;
    rdp_buffer client_mouse_input;
    rdp_buffer client_refresh_rect;
    rdp_buffer client_suppress_output;
    rdp_buffer decoded_bitmap;
    rdp_buffer x509_chain;
    rdp_buffer ntlm_negotiate;
    rdp_buffer ntlm_authenticate;
    rdp_buffer spnego_negotiate;
    rdp_buffer spnego_authenticate;
    rdp_buffer ntlm_wrapped;
    rdp_buffer ntlm_unwrapped;
    rdp_buffer pub_key_auth;
    rdp_buffer server_pub_key_auth;
    rdp_buffer ts_credentials;
    rdp_buffer auth_info;
    rdp_buffer ts_request;
    rdp_buffer nla_request;
    rdp_client_info info;
    rdp_client_info_summary info_summary;
    rdp_capability_list confirm_caps;
    rdp_credssp_ts_request parsed_ts;
    rdp_ntlm_challenge ntlm_challenge;
    rdp_ntlm_challenge ntlm_v2_challenge;
    rdp_ntlm_authenticate_result ntlm_auth_result;
    rdp_ntlm_security_context ntlm_security;
    rdp_ntlm_security_context server_security;
    const uint8_t* extracted_ntlm = NULL;
    size_t extracted_ntlm_len = 0;
    uint8_t server_hash[32];
    uint16_t lm_len = 0;
    uint16_t nt_len = 0;
    uint16_t key_len = 0;
    uint32_t lm_offset = 0;
    uint32_t nt_offset = 0;
    uint32_t key_offset = 0;
    uint32_t error_info = 0;
    uint8_t signature[8];
    size_t decoded_stride = 0;
    size_t i = 0;
    uint16_t confirm_source_len = 0;
    uint16_t confirm_caps_len = 0;
    const uint16_t expected_confirm_types[] = {
        RDP_CAPABILITY_TYPE_GENERAL,
        RDP_CAPABILITY_TYPE_BITMAP,
        RDP_CAPABILITY_TYPE_ORDER,
        RDP_CAPABILITY_TYPE_BITMAP_CACHE_V2,
        RDP_CAPABILITY_TYPE_POINTER,
        RDP_CAPABILITY_TYPE_INPUT,
        RDP_CAPABILITY_TYPE_BRUSH,
        RDP_CAPABILITY_TYPE_GLYPH_CACHE,
        RDP_CAPABILITY_TYPE_VIRTUAL_CHANNEL,
        RDP_CAPABILITY_TYPE_SOUND,
        RDP_CAPABILITY_TYPE_SHARE,
        RDP_CAPABILITY_TYPE_FONT,
        RDP_CAPABILITY_TYPE_CONTROL,
        RDP_CAPABILITY_TYPE_COLOR_CACHE,
        RDP_CAPABILITY_TYPE_ACTIVATION
    };
    const uint16_t expected_confirm_lengths[] = {
        24, 28, 88, 40, 10, 88, 8, 52, 12, 8, 8, 8, 12, 8, 12
    };
    const uint8_t font_map_payload[] = {1, 0, 2, 0, 3, 0, 4, 0};
    const uint8_t set_error_info_payload[] = {0x34, 0x12, 0, 0};
    const uint8_t save_session_info_payload[] = {1, 0, 0, 0, 0xaa, 0x55};
    const uint8_t orders_update_payload[] = {0, 0, 0, 0};

    rdp_buffer_init(&security);
    rdp_buffer_init(&send_data);
    rdp_buffer_init(&encrypted);
    rdp_buffer_init(&encrypted_info);
    rdp_buffer_init(&plain_info_body);
    rdp_buffer_init(&expected_cipher);
    rdp_buffer_init(&confirm_active);
    rdp_buffer_init(&client_sync);
    rdp_buffer_init(&client_control);
    rdp_buffer_init(&client_persistent_keys);
    rdp_buffer_init(&client_font_list);
    rdp_buffer_init(&client_keyboard_input);
    rdp_buffer_init(&client_mouse_input);
    rdp_buffer_init(&client_refresh_rect);
    rdp_buffer_init(&client_suppress_output);
    rdp_buffer_init(&decoded_bitmap);
    rdp_buffer_init(&x509_chain);
    rdp_buffer_init(&ntlm_negotiate);
    rdp_buffer_init(&ntlm_authenticate);
    rdp_buffer_init(&spnego_negotiate);
    rdp_buffer_init(&spnego_authenticate);
    rdp_buffer_init(&ntlm_wrapped);
    rdp_buffer_init(&ntlm_unwrapped);
    rdp_buffer_init(&pub_key_auth);
    rdp_buffer_init(&server_pub_key_auth);
    rdp_buffer_init(&ts_credentials);
    rdp_buffer_init(&auth_info);
    rdp_buffer_init(&ts_request);
    rdp_buffer_init(&nla_request);

    PCHECK(rdp_fastpath_parse_header(fast_short, sizeof(fast_short), &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 6 && fast.header_length == 2 && !fast.long_length);
    PCHECK(rdp_fastpath_parse_header(fast_long, sizeof(fast_long), &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 8 && fast.header_length == 3 && fast.long_length);
    PCHECK(rdp_fastpath_parse_header(fast_long, 2, &fast) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_fastpath_parse_updates(fast_bitmap_update, sizeof(fast_bitmap_update), &fast_updates) ==
           LIBRDP_STATUS_OK);
    PCHECK(fast_updates.count == 1 && fast_updates.updates[0].update_code == RDP_FASTPATH_UPDATE_BITMAP &&
           fast_updates.updates[0].fragmentation == RDP_FASTPATH_FRAGMENT_SINGLE &&
           fast_updates.updates[0].compression == 0 && fast_updates.updates[0].data_len == 38);
    PCHECK(rdp_bitmap_parse_fastpath_update(fast_updates.updates[0].data,
                                            fast_updates.updates[0].data_len,
                                            &bitmap_update) == LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1 && bitmap_update.rects[0].data_len == 16);
    PCHECK(rdp_fastpath_parse_updates(fast_bitmap_update, sizeof(fast_bitmap_update) - 1u, &fast_updates) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_fastpath_parse_updates(fast_long, sizeof(fast_long), &fast_updates) == LIBRDP_STATUS_UNSUPPORTED);

    PCHECK(rdp_slowpath_parse_share_control_header(slow, sizeof(slow), &slow_header) == LIBRDP_STATUS_OK);
    PCHECK(slow_header.total_length == 6 && slow_header.pdu_type == 0x13);
    PCHECK(rdp_slowpath_parse_demand_active(demand_active, sizeof(demand_active), &demand) == LIBRDP_STATUS_OK);
    PCHECK(demand.share_id == 0x12345678u);
    PCHECK(demand.source_descriptor_len == 3 && memcmp(demand.source_descriptor, "srv", 3) == 0);
    PCHECK(demand.capabilities.count == 1 && demand.capabilities.sets[0].type == 1);
    PCHECK(rdp_slowpath_parse_demand_active(demand_active, sizeof(demand_active) - 1u, &demand) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_slowpath_parse_data_pdu(bitmap_data_pdu, sizeof(bitmap_data_pdu), &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.share_id == 0x12345678u && data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE);
    PCHECK(data_pdu.payload_len == 40);
    PCHECK(rdp_bitmap_parse_update_header(data_pdu.payload, data_pdu.payload_len, &bitmap_header) ==
           LIBRDP_STATUS_OK);
    PCHECK(bitmap_header.update_type == RDP_UPDATE_TYPE_BITMAP && bitmap_header.count == 1);
    PCHECK(rdp_bitmap_parse_update_header(data_pdu.payload, 3, &bitmap_header) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &bitmap_update) == LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1);
    PCHECK(bitmap_update.rects[0].width == 2 && bitmap_update.rects[0].height == 2);
    PCHECK(bitmap_update.rects[0].bits_per_pixel == 32 && bitmap_update.rects[0].data_len == 16);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_update.rects[0], &decoded_bitmap, &decoded_stride) ==
           LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.length == 16 && decoded_bitmap.data[0] == 9 &&
           decoded_bitmap.data[1] == 10 && decoded_bitmap.data[2] == 11 && decoded_bitmap.data[3] == 12);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 2;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 1;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 24;
    bitmap_rect.data = bitmap_24_data;
    bitmap_rect.data_len = sizeof(bitmap_24_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.length == 16 && decoded_bitmap.data[0] == 7 &&
           decoded_bitmap.data[1] == 8 && decoded_bitmap.data[2] == 9 && decoded_bitmap.data[3] == 0xff);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 2;
    bitmap_rect.height = 1;
    bitmap_rect.dest_right = 1;
    bitmap_rect.bits_per_pixel = 16;
    bitmap_rect.data = bitmap_16_data;
    bitmap_rect.data_len = sizeof(bitmap_16_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.data[0] == 0 && decoded_bitmap.data[1] == 0 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[4] == 0 && decoded_bitmap.data[5] == 255 &&
           decoded_bitmap.data[6] == 0);
    bitmap_rect.flags = 1;
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_UNSUPPORTED);
    PCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len - 1u, &bitmap_update) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_bitmap_parse_update(orders_update_payload, sizeof(orders_update_payload), &bitmap_update) ==
           LIBRDP_STATUS_UNSUPPORTED);
    PCHECK(rdp_slowpath_write_confirm_active(&confirm_active, 0x12345678u, 1004, 800, 600, "librdp") ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_share_control_header(confirm_active.data, confirm_active.length, &slow_header) ==
           LIBRDP_STATUS_OK);
    PCHECK(slow_header.total_length == confirm_active.length);
    PCHECK((slow_header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE);
    PCHECK(slow_header.channel_id == 1004);
    PCHECK(confirm_active.data[6] == 0x78 && confirm_active.data[10] == 0xea);
    confirm_source_len = (uint16_t)(confirm_active.data[12] | ((uint16_t)confirm_active.data[13] << 8));
    confirm_caps_len = (uint16_t)(confirm_active.data[14] | ((uint16_t)confirm_active.data[15] << 8));
    PCHECK(confirm_source_len == 6);
    PCHECK(rdp_capabilities_parse(confirm_active.data + 16u + confirm_source_len,
                                  confirm_caps_len,
                                  &confirm_caps) == LIBRDP_STATUS_OK);
    PCHECK(confirm_caps.count == sizeof(expected_confirm_types) / sizeof(expected_confirm_types[0]));
    PCHECK(confirm_caps_len == 410);
    for (i = 0; i < sizeof(expected_confirm_types) / sizeof(expected_confirm_types[0]); i++)
    {
        PCHECK(confirm_caps.sets[i].type == expected_confirm_types[i]);
        PCHECK(confirm_caps.sets[i].length == expected_confirm_lengths[i]);
    }
    PCHECK(confirm_caps.sets[0].data[0] == 1 && confirm_caps.sets[0].data[2] == 3 &&
           confirm_caps.sets[0].data[4] == 0x00 && confirm_caps.sets[0].data[5] == 0x02);
    PCHECK(confirm_caps.sets[1].data[0] == 32 && confirm_caps.sets[1].data[8] == 0x20 &&
           confirm_caps.sets[1].data[9] == 0x03 && confirm_caps.sets[1].data[10] == 0x58 &&
           confirm_caps.sets[1].data[11] == 0x02);
    PCHECK(confirm_caps.sets[2].data[30] == 0x2a && confirm_caps.sets[2].data[31] == 0x00);
    PCHECK(confirm_caps.sets[5].data[0] == 1 && confirm_caps.sets[5].data[4] == 0x09 &&
           confirm_caps.sets[5].data[5] == 0x04);
    PCHECK(rdp_slowpath_write_client_synchronize(&client_sync, 0x12345678u, 1004) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_sync.data, client_sync.length, &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.share_id == 0x12345678u &&
           data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SYNCHRONIZE &&
           data_pdu.payload_len == 4);
    PCHECK(test_read_u16_le(data_pdu.payload) == 1 && test_read_u16_le(data_pdu.payload + 2) == 1004);
    PCHECK(rdp_slowpath_write_client_control(&client_control, 0x12345678u, 1004, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_control.data, client_control.length, &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL &&
           data_pdu.payload_len == 8 &&
           test_read_u16_le(data_pdu.payload) == 4 &&
           test_read_u16_le(data_pdu.payload + 2) == 0 &&
           test_read_u32_le(data_pdu.payload + 4) == 0);
    client_control.length = 0;
    PCHECK(rdp_slowpath_write_client_control(&client_control, 0x12345678u, 1004, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_control.data, client_control.length, &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL &&
           test_read_u16_le(data_pdu.payload) == 1);
    PCHECK(rdp_slowpath_write_client_control(&client_control, 0x12345678u, 1004, 2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_write_client_persistent_key_list(&client_persistent_keys, 0x12345678u, 1004) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_persistent_keys.data,
                                       client_persistent_keys.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_BITMAP_CACHE_PERSISTENT_LIST &&
           data_pdu.payload_len == 24 &&
           data_pdu.payload[20] == 3);
    for (i = 0; i < 20; i++)
        PCHECK(data_pdu.payload[i] == 0);
    PCHECK(data_pdu.payload[21] == 0 && data_pdu.payload[22] == 0 && data_pdu.payload[23] == 0);
    PCHECK(rdp_slowpath_write_client_font_list(&client_font_list, 0x12345678u, 1004) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_font_list.data, client_font_list.length, &data_pdu) ==
           LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_LIST &&
           data_pdu.payload_len == 8 &&
           test_read_u16_le(data_pdu.payload + 4) == 3 &&
           test_read_u16_le(data_pdu.payload + 6) == 50);
    PCHECK(rdp_slowpath_write_client_keyboard_input(&client_keyboard_input,
                                                    0x12345678u,
                                                    1004,
                                                    0x8000u,
                                                    30) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_keyboard_input.data,
                                       client_keyboard_input.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_INPUT &&
           data_pdu.payload_len == 16 &&
           test_read_u16_le(data_pdu.payload) == 1 &&
           test_read_u16_le(data_pdu.payload + 8) == 4 &&
           test_read_u16_le(data_pdu.payload + 10) == 0x8000u &&
           test_read_u16_le(data_pdu.payload + 12) == 30);
    PCHECK(rdp_slowpath_write_client_keyboard_input(&client_keyboard_input,
                                                    0x12345678u,
                                                    1004,
                                                    0,
                                                    256) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_write_client_mouse_input(&client_mouse_input,
                                                 0x12345678u,
                                                 1004,
                                                 0x9000u,
                                                 10,
                                                 11) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_mouse_input.data,
                                       client_mouse_input.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_INPUT &&
           data_pdu.payload_len == 16 &&
           test_read_u16_le(data_pdu.payload + 8) == 0x8001u &&
           test_read_u16_le(data_pdu.payload + 10) == 0x9000u &&
           test_read_u16_le(data_pdu.payload + 12) == 10 &&
           test_read_u16_le(data_pdu.payload + 14) == 11);
    PCHECK(rdp_slowpath_write_client_refresh_rect(&client_refresh_rect,
                                                  0x12345678u,
                                                  1004,
                                                  2,
                                                  3,
                                                  800,
                                                  600) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_refresh_rect.data,
                                       client_refresh_rect.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_REFRESH_RECT &&
           data_pdu.payload_len == 12 &&
           data_pdu.payload[0] == 1 &&
           test_read_u16_le(data_pdu.payload + 4) == 2 &&
           test_read_u16_le(data_pdu.payload + 6) == 3 &&
           test_read_u16_le(data_pdu.payload + 8) == 801 &&
           test_read_u16_le(data_pdu.payload + 10) == 602);
    PCHECK(rdp_slowpath_write_client_refresh_rect(&client_refresh_rect,
                                                  0x12345678u,
                                                  1004,
                                                  0xffffu,
                                                  0,
                                                  2,
                                                  1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_write_client_suppress_output(&client_suppress_output,
                                                     0x12345678u,
                                                     1004,
                                                     1,
                                                     2,
                                                     3,
                                                     800,
                                                     600) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_suppress_output.data,
                                       client_suppress_output.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SUPPRESS_OUTPUT &&
           data_pdu.payload_len == 12 &&
           data_pdu.payload[0] == 1 &&
           test_read_u16_le(data_pdu.payload + 4) == 2 &&
           test_read_u16_le(data_pdu.payload + 6) == 3 &&
           test_read_u16_le(data_pdu.payload + 8) == 801 &&
           test_read_u16_le(data_pdu.payload + 10) == 602);
    client_suppress_output.length = 0;
    PCHECK(rdp_slowpath_write_client_suppress_output(&client_suppress_output,
                                                     0x12345678u,
                                                     1004,
                                                     0,
                                                     0,
                                                     0,
                                                     0,
                                                     0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_suppress_output.data,
                                       client_suppress_output.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SUPPRESS_OUTPUT &&
           data_pdu.payload_len == 4 &&
           data_pdu.payload[0] == 0);
    PCHECK(rdp_slowpath_write_client_suppress_output(&client_suppress_output,
                                                     0x12345678u,
                                                     1004,
                                                     1,
                                                     0xffffu,
                                                     0,
                                                     2,
                                                     1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_parse_font_map(font_map_payload, sizeof(font_map_payload), &font_map) == LIBRDP_STATUS_OK);
    PCHECK(font_map.number_entries == 1 && font_map.total_entries == 2 && font_map.map_flags == 3 &&
           font_map.entry_size == 4);
    PCHECK(rdp_slowpath_parse_font_map(font_map_payload, sizeof(font_map_payload) - 1u, &font_map) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_slowpath_parse_set_error_info(set_error_info_payload,
                                             sizeof(set_error_info_payload),
                                             &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 0x1234u);
    PCHECK(rdp_slowpath_parse_set_error_info(set_error_info_payload,
                                             sizeof(set_error_info_payload) - 1u,
                                             &error_info) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_slowpath_parse_save_session_info(save_session_info_payload,
                                                sizeof(save_session_info_payload),
                                                &save_info) == LIBRDP_STATUS_OK);
    PCHECK(save_info.info_type == 1 && save_info.data_len == 2 && save_info.data[0] == 0xaa &&
           save_info.data[1] == 0x55);
    PCHECK(rdp_slowpath_parse_save_session_info(save_session_info_payload, 3, &save_info) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_security_protocol_mask(LIBRDP_SECURITY_STANDARD) == RDP_X224_PROTOCOL_STANDARD);
    PCHECK(rdp_security_protocol_mask(LIBRDP_SECURITY_TLS) == RDP_X224_PROTOCOL_TLS);
    PCHECK(rdp_security_protocol_supported(RDP_X224_PROTOCOL_TLS));
    PCHECK(rdp_security_protocol_supported(RDP_X224_PROTOCOL_NLA));
    PCHECK(rdp_security_protocol_supported(RDP_X224_PROTOCOL_STANDARD));

    memset(&info, 0, sizeof(info));
    info.domain = "D";
    info.username = "user";
    info.password = "secret";
    PCHECK(rdp_security_write_client_info_pdu(&security, &info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_parse_client_info_pdu(security.data, security.length, &info_summary) == LIBRDP_STATUS_OK);
    PCHECK(info_summary.domain_bytes == 2);
    PCHECK(info_summary.username_bytes == 8);
    PCHECK(info_summary.password_bytes == 12);
    PCHECK((info_summary.flags & 0x00000010u) != 0);
    for (i = 0; i < sizeof(client_random); i++)
    {
        client_random[i] = (uint8_t)(i + 1u);
        server_random[i] = (uint8_t)(0xa0u + i);
    }
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(secure_a.key_len == 16);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_client_info_body(&plain_info_body, &info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_mac_signature(&secure_b, plain_info_body.data, plain_info_body.length, signature) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_encrypted_client_info_pdu(&encrypted_info, &secure_a, &info) == LIBRDP_STATUS_OK);
    PCHECK(encrypted_info.length == plain_info_body.length + 12u);
    PCHECK(encrypted_info.data[0] == (uint8_t)(RDP_SEC_INFO_PKT | RDP_SEC_ENCRYPT));
    PCHECK(memcmp(encrypted_info.data + 4, signature, sizeof(signature)) == 0);
    PCHECK(memcmp(encrypted_info.data + 12, plain_info_body.data, plain_info_body.length) != 0);
    PCHECK(rdp_buffer_append(&expected_cipher, plain_info_body.data, plain_info_body.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_encrypt_payload(&secure_b, expected_cipher.data, expected_cipher.length) == LIBRDP_STATUS_OK);
    PCHECK(memcmp(encrypted_info.data + 12, expected_cipher.data, expected_cipher.length) == 0);
    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_40BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(secure_a.key_len == 8 && secure_a.sign_key[0] == 0xd1 && secure_a.sign_key[2] == 0x9e);
    rdp_security_standard_clear(&secure_a);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_56BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(secure_a.key_len == 8 && secure_a.sign_key[0] == 0xd1);
    rdp_security_standard_clear(&secure_a);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_FIPS,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_UNSUPPORTED);
    PCHECK(rdp_security_write_send_data_request(&send_data, 1004, RDP_MCS_GLOBAL_CHANNEL_ID, security.data,
                                                security.length) == LIBRDP_STATUS_OK);
    PCHECK(send_data.length > security.length);
    PCHECK(send_data.data[0] == 0x64);
    PCHECK(send_data.data[1] == 0x00 && send_data.data[2] == 0x03);
    PCHECK(send_data.data[3] == 0x03 && send_data.data[4] == 0xeb);
    rdp_buffer_free(&security);
    rdp_buffer_init(&security);
    PCHECK(rdp_security_write_exchange_pdu(&security, encrypted_random, sizeof(encrypted_random)) ==
           LIBRDP_STATUS_OK);
    PCHECK(security.length == sizeof(encrypted_random) + 16u);
    PCHECK(security.data[0] == 0x01 && security.data[1] == 0x00);
    PCHECK(security.data[4] == (uint8_t)(sizeof(encrypted_random) + 8u));
    memset(client_random, 0x4a, sizeof(client_random));
    PCHECK(rdp_security_parse_server_certificate(server_certificate, sizeof(server_certificate), &public_key) ==
           LIBRDP_STATUS_OK);
    PCHECK(public_key.exponent == 65537u && public_key.bit_len == 1024u && public_key.modulus_len == 128u);
    PCHECK(public_key.modulus_le[0] == 0xeb && public_key.modulus_le[127] == 0xb2);
    PCHECK(rdp_security_encrypt_client_random(&public_key, client_random, &encrypted) == LIBRDP_STATUS_OK);
    PCHECK(encrypted.length == public_key.modulus_len);
    PCHECK(memcmp(encrypted.data, client_random, sizeof(client_random)) != 0);
    rdp_security_public_key_clear(&public_key);
    rdp_buffer_free(&encrypted);
    rdp_buffer_init(&encrypted);
    PCHECK(rdp_buffer_append_u32_le(&x509_chain, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&x509_chain, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&x509_chain, (uint32_t)sizeof(x509_der)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&x509_chain, x509_der, sizeof(x509_der)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_parse_server_certificate(x509_chain.data, x509_chain.length, &public_key) ==
           LIBRDP_STATUS_OK);
    PCHECK(public_key.exponent == 65537u && public_key.bit_len == 1024u && public_key.modulus_len == 128u);
    PCHECK(rdp_security_encrypt_client_random(&public_key, client_random, &encrypted) == LIBRDP_STATUS_OK);
    PCHECK(encrypted.length == public_key.modulus_len);
    rdp_security_public_key_clear(&public_key);
    PCHECK(rdp_security_parse_server_certificate(x509_chain.data, x509_chain.length - 1u, &public_key) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_security_generate_client_random(client_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_parse_server_certificate(server_certificate, sizeof(server_certificate) - 1u, &public_key) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_license_parse_error_alert(license, sizeof(license), &alert) == LIBRDP_STATUS_OK);
    PCHECK(alert.error_code == 1 && alert.state_transition == 2 && alert.blob_length == 2 && alert.blob[1] == 8);
    PCHECK(rdp_license_parse_error_alert(license, 15, &alert) == LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_virtual_channel_parse_packet(channel, sizeof(channel), &vc) == LIBRDP_STATUS_OK);
    PCHECK(vc.length == 3 && vc.flags == 0x10 && vc.payload[2] == 3);
    PCHECK(rdp_clipboard_parse_packet(clip, sizeof(clip), &cb) == LIBRDP_STATUS_OK);
    PCHECK(cb.type == 1 && cb.flags == 2 && cb.payload_len == 3 && cb.payload[0] == 4);
    PCHECK(rdp_mcs_parse_send_data_indication(indication_pdu, sizeof(indication_pdu), &indication) ==
           LIBRDP_STATUS_OK);
    PCHECK(indication.initiator == 1004 && indication.channel_id == RDP_MCS_GLOBAL_CHANNEL_ID);
    PCHECK(indication.payload_len == 4 && indication.payload[0] == 1 && indication.payload[3] == 4);
    PCHECK(rdp_mcs_parse_send_data_indication(indication_pdu, sizeof(indication_pdu) - 1u, &indication) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_credssp_begin(false, &cred_state) == LIBRDP_STATUS_OK && cred_state == RDP_CREDSSP_DISABLED);
    PCHECK(rdp_credssp_begin(true, &cred_state) == LIBRDP_STATUS_OK && cred_state == RDP_CREDSSP_NEGOTIATING);
    PCHECK(rdp_credssp_write_ntlm_negotiate(&ntlm_negotiate, "host", "dom") == LIBRDP_STATUS_OK);
    PCHECK(ntlm_negotiate.length == 47);
    PCHECK(memcmp(ntlm_negotiate.data, "NTLMSSP", 7) == 0);
    PCHECK(ntlm_negotiate.data[8] == 1 && ntlm_negotiate.data[16] == 3 && ntlm_negotiate.data[24] == 4);
    PCHECK(memcmp(ntlm_negotiate.data + 40, "DOMHOST", 7) == 0);
    PCHECK(rdp_credssp_write_spnego_ntlm_negotiate(&spnego_negotiate,
                                                   ntlm_negotiate.data,
                                                   ntlm_negotiate.length) == LIBRDP_STATUS_OK);
    PCHECK(spnego_negotiate.length > ntlm_negotiate.length && spnego_negotiate.data[0] == 0x60);
    PCHECK(rdp_credssp_write_ts_request(&ts_request,
                                        6,
                                        spnego_negotiate.data,
                                        spnego_negotiate.length,
                                        NULL,
                                        0,
                                        NULL,
                                        0,
                                        credssp_client_nonce,
                                        sizeof(credssp_client_nonce)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_parse_ts_request(ts_request.data, ts_request.length, &parsed_ts) == LIBRDP_STATUS_OK);
    PCHECK(parsed_ts.version == 6 && parsed_ts.nego_token_len == spnego_negotiate.length);
    PCHECK(memcmp(parsed_ts.nego_token, spnego_negotiate.data, spnego_negotiate.length) == 0);
    PCHECK(parsed_ts.client_nonce_len == sizeof(credssp_client_nonce));
    PCHECK(memcmp(parsed_ts.client_nonce, credssp_client_nonce, sizeof(credssp_client_nonce)) == 0);
    PCHECK(rdp_credssp_parse_ts_request(ts_request.data, ts_request.length - 1u, &parsed_ts) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_credssp_write_negotiate_request(&nla_request, "host", "dom") == LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_parse_ts_request(nla_request.data, nla_request.length, &parsed_ts) == LIBRDP_STATUS_OK);
    PCHECK(parsed_ts.version == 6 && parsed_ts.nego_token_len > 0);
    PCHECK(rdp_credssp_parse_ntlm_challenge(ntlm_challenge_token,
                                            sizeof(ntlm_challenge_token),
                                            &ntlm_challenge) == LIBRDP_STATUS_OK);
    PCHECK(ntlm_challenge.flags == 0x04030201u);
    PCHECK(ntlm_challenge.server_challenge[0] == 0x10 && ntlm_challenge.server_challenge[7] == 0x17);
    PCHECK(ntlm_challenge.target_name_len == 4 && ntlm_challenge.target_info_len == 8);
    PCHECK(rdp_credssp_extract_ntlm_challenge(wrapped_ntlm_challenge,
                                              sizeof(wrapped_ntlm_challenge),
                                              &extracted_ntlm,
                                              &extracted_ntlm_len) == LIBRDP_STATUS_OK);
    PCHECK(extracted_ntlm_len == sizeof(ntlm_challenge_token));
    PCHECK(rdp_credssp_parse_ntlm_challenge(extracted_ntlm, extracted_ntlm_len, &ntlm_challenge) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_parse_ntlm_challenge(ntlm_challenge_token,
                                            sizeof(ntlm_challenge_token) - 1u,
                                            &ntlm_challenge) == LIBRDP_STATUS_PROTOCOL_ERROR);
    memset(&ntlm_v2_challenge, 0, sizeof(ntlm_v2_challenge));
    ntlm_v2_challenge.flags = 0xe2888235u;
    memcpy(ntlm_v2_challenge.server_challenge, ntlm_v2_server_challenge, sizeof(ntlm_v2_server_challenge));
    ntlm_v2_challenge.target_name = ntlm_v2_target_name;
    ntlm_v2_challenge.target_name_len = sizeof(ntlm_v2_target_name);
    ntlm_v2_challenge.target_info = ntlm_v2_target_info;
    ntlm_v2_challenge.target_info_len = sizeof(ntlm_v2_target_info);
    PCHECK(rdp_credssp_write_ntlm_authenticate(&ntlm_authenticate,
                                               &ntlm_v2_challenge,
                                               "user",
                                               "SecREt01",
                                               "DOMAIN",
                                               "COMPUTER",
                                               0x01c334b736d39000ull,
                                               ntlm_v2_client_challenge,
                                               ntlm_v2_session_key,
                                               &ntlm_auth_result) == LIBRDP_STATUS_OK);
    PCHECK(ntlm_authenticate.length > 88);
    PCHECK(memcmp(ntlm_authenticate.data, "NTLMSSP", 7) == 0);
    PCHECK(test_read_u32_le(ntlm_authenticate.data + 8) == 3);
    lm_len = test_read_u16_le(ntlm_authenticate.data + 12);
    lm_offset = test_read_u32_le(ntlm_authenticate.data + 16);
    nt_len = test_read_u16_le(ntlm_authenticate.data + 20);
    nt_offset = test_read_u32_le(ntlm_authenticate.data + 24);
    key_len = test_read_u16_le(ntlm_authenticate.data + 52);
    key_offset = test_read_u32_le(ntlm_authenticate.data + 56);
    PCHECK(test_read_u32_le(ntlm_authenticate.data + 60) == ntlm_auth_result.flags);
    PCHECK(lm_len == sizeof(ntlm_v2_expected_lm));
    PCHECK(nt_len > sizeof(ntlm_v2_expected_proof));
    PCHECK(key_len == sizeof(ntlm_v2_session_key));
    PCHECK((size_t)lm_offset + lm_len <= ntlm_authenticate.length);
    PCHECK((size_t)nt_offset + nt_len <= ntlm_authenticate.length);
    PCHECK((size_t)key_offset + key_len <= ntlm_authenticate.length);
    PCHECK(memcmp(ntlm_authenticate.data + lm_offset, ntlm_v2_expected_lm, sizeof(ntlm_v2_expected_lm)) == 0);
    PCHECK(memcmp(ntlm_authenticate.data + nt_offset,
                  ntlm_v2_expected_proof,
                  sizeof(ntlm_v2_expected_proof)) == 0);
    PCHECK(memcmp(ntlm_auth_result.session_key, ntlm_v2_session_key, sizeof(ntlm_v2_session_key)) == 0);
    PCHECK(memcmp(ntlm_authenticate.data + key_offset, ntlm_v2_session_key, sizeof(ntlm_v2_session_key)) != 0);
    PCHECK(rdp_credssp_write_spnego_ntlm_authenticate(&spnego_authenticate,
                                                      ntlm_authenticate.data,
                                                      ntlm_authenticate.length) == LIBRDP_STATUS_OK);
    PCHECK(spnego_authenticate.length > ntlm_authenticate.length && spnego_authenticate.data[0] == 0xa1);
    PCHECK(rdp_credssp_ntlm_security_init(&ntlm_security, &ntlm_auth_result) == LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_ntlm_wrap(&ntlm_security, "data", 4, &ntlm_wrapped) == LIBRDP_STATUS_OK);
    PCHECK(ntlm_wrapped.length == 20);
    PCHECK(test_read_u32_le(ntlm_wrapped.data) == 1);
    PCHECK(test_read_u32_le(ntlm_wrapped.data + 12) == 0);
    PCHECK(memcmp(ntlm_wrapped.data + 16, "data", 4) != 0);
    PCHECK(ntlm_security.send_seq == 1);
    PCHECK(rdp_credssp_encrypt_public_key_hash(&ntlm_security,
                                               credssp_client_nonce,
                                               sizeof(credssp_client_nonce),
                                               credssp_public_key,
                                               sizeof(credssp_public_key),
                                               &pub_key_auth) == LIBRDP_STATUS_OK);
    PCHECK(pub_key_auth.length == 48 && ntlm_security.send_seq == 2);
    server_security = ntlm_security;
    memcpy(server_security.client_signing_key, ntlm_security.server_signing_key, sizeof(server_security.client_signing_key));
    server_security.send_rc4 = ntlm_security.recv_rc4;
    server_security.send_seq = 0;
    PCHECK(test_sha256_three((const uint8_t*)"CredSSP Server-To-Client Binding Hash",
                             sizeof("CredSSP Server-To-Client Binding Hash"),
                             credssp_client_nonce,
                             sizeof(credssp_client_nonce),
                             credssp_public_key,
                             sizeof(credssp_public_key),
                             server_hash));
    PCHECK(rdp_credssp_ntlm_wrap(&server_security,
                                 server_hash,
                                 sizeof(server_hash),
                                 &server_pub_key_auth) == LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_verify_public_key_hash(&ntlm_security,
                                              credssp_client_nonce,
                                              sizeof(credssp_client_nonce),
                                              credssp_public_key,
                                              sizeof(credssp_public_key),
                                              server_pub_key_auth.data,
                                              server_pub_key_auth.length) == LIBRDP_STATUS_OK);
    server_security = ntlm_security;
    memcpy(server_security.client_signing_key, ntlm_security.server_signing_key, sizeof(server_security.client_signing_key));
    server_security.send_rc4 = ntlm_security.recv_rc4;
    server_security.send_seq = ntlm_security.recv_seq;
    PCHECK(rdp_credssp_ntlm_wrap(&server_security, "peer", 4, &ntlm_wrapped) == LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_ntlm_unwrap(&ntlm_security,
                                   ntlm_wrapped.data + 20,
                                   ntlm_wrapped.length - 20,
                                   &ntlm_unwrapped) == LIBRDP_STATUS_OK);
    PCHECK(ntlm_unwrapped.length == 4 && memcmp(ntlm_unwrapped.data, "peer", 4) == 0);
    PCHECK(rdp_credssp_write_password_credentials(&ts_credentials,
                                                  "DOMAIN",
                                                  "user",
                                                  "SecREt01") == LIBRDP_STATUS_OK);
    PCHECK(ts_credentials.length > 32 && ts_credentials.data[0] == 0x30);
    PCHECK(rdp_credssp_encrypt_password_credentials(&ntlm_security,
                                                    "DOMAIN",
                                                    "user",
                                                    "SecREt01",
                                                    &auth_info) == LIBRDP_STATUS_OK);
    PCHECK(auth_info.length == ts_credentials.length + 16u);
    PCHECK(test_read_u32_le(auth_info.data) == 1);
    PCHECK(test_read_u32_le(auth_info.data + 12) == 2);
    PCHECK(memcmp(auth_info.data + 16, ts_credentials.data, ts_credentials.length < 8u ? ts_credentials.length : 8u) !=
           0);
    rdp_buffer_free(&nla_request);
    rdp_buffer_free(&ts_request);
    rdp_buffer_free(&auth_info);
    rdp_buffer_free(&ts_credentials);
    rdp_buffer_free(&server_pub_key_auth);
    rdp_buffer_free(&pub_key_auth);
    rdp_buffer_free(&ntlm_unwrapped);
    rdp_buffer_free(&ntlm_wrapped);
    rdp_buffer_free(&spnego_authenticate);
    rdp_buffer_free(&spnego_negotiate);
    rdp_buffer_free(&ntlm_authenticate);
    rdp_buffer_free(&ntlm_negotiate);
    rdp_buffer_free(&x509_chain);
    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_free(&client_suppress_output);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_free(&client_mouse_input);
    rdp_buffer_free(&client_keyboard_input);
    rdp_buffer_free(&client_font_list);
    rdp_buffer_free(&client_persistent_keys);
    rdp_buffer_free(&client_control);
    rdp_buffer_free(&client_sync);
    rdp_buffer_free(&expected_cipher);
    rdp_buffer_free(&plain_info_body);
    rdp_buffer_free(&encrypted_info);
    rdp_buffer_free(&confirm_active);
    rdp_buffer_free(&encrypted);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security);
    return 0;
}

int test_protocol(void)
{
    if (test_tpkt_x224() != 0)
        return 1;
    if (test_mcs_gcc_capabilities() != 0)
        return 1;
    if (test_path_security_license_channels() != 0)
        return 1;
    return 0;
}
