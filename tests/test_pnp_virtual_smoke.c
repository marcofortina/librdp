/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic PNP redirection lifecycle smoke.
 * Coverage: explicit device consent, stable identifiers, channel negotiation,
 * device announcement, create/read/write/control, rejection, surprise removal,
 * and session cleanup.
 * Bug classes: unauthorized device exposure, protocol/runtime drift, stale
 * handles, incomplete removal, and response framing errors.
 * Determinism: the device is synthetic and transport output is captured in
 * memory without accessing host hardware.
 */

#include <librdp/librdp.h>

#include "channels/device_redirection.h"
#include "channels/pnp_redirection.h"
#include "channels/virtual_channel.h"
#include "client/session_device.h"
#include "client/session_internal.h"
#include "client/settings_internal.h"
#include "common/buffer.h"
#include "protocol/mcs.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "transport/transport.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expr)                                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

#define TEST_PNP_CHANNEL_ID 1007u
#define TEST_PNP_USER_ID 1005u
#define TEST_PNP_UNKNOWN_DEVICE_ID 0x00ff1234u

typedef struct test_pnp_capture
{
    rdp_buffer bytes;
    uint32_t writes;
} test_pnp_capture;

static librdp_status test_pnp_capture_write(void* context,
                                            const void* data,
                                            size_t length,
                                            size_t* written_len)
{
    test_pnp_capture* capture = (test_pnp_capture*)context;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!capture || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append(&capture->bytes, data, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    capture->writes++;
    if (written_len)
        *written_len = length;
    return LIBRDP_STATUS_OK;
}

static const rdp_transport_backend_ops TEST_PNP_TRANSPORT_OPS = {
    NULL,
    NULL,
    NULL,
    NULL,
    test_pnp_capture_write,
    NULL,
};

static void test_pnp_capture_reset(test_pnp_capture* capture)
{
    if (!capture)
        return;
    capture->bytes.length = 0u;
    capture->writes = 0u;
}

/*
 * Unwrap one complete client static-channel response from the captured
 * TPKT/X.224/MCS layers. Exact channel and fragment checks ensure the smoke
 * cannot pass on unrelated transport output.
 */
static int test_pnp_capture_payload(const test_pnp_capture* capture,
                                    rdp_virtual_channel_packet* packet)
{
    rdp_tpkt tpkt;
    rdp_mcs_send_data_indication request;
    const uint8_t* x224_payload = NULL;
    size_t x224_payload_len = 0u;

    if (!capture || !packet || capture->bytes.length == 0u)
        return 0;
    if (rdp_tpkt_parse(capture->bytes.data,
                       capture->bytes.length,
                       &tpkt) != LIBRDP_STATUS_OK ||
        tpkt.total_len != capture->bytes.length ||
        rdp_x224_parse_data(tpkt.payload,
                            tpkt.payload_len,
                            &x224_payload,
                            &x224_payload_len) != LIBRDP_STATUS_OK ||
        rdp_mcs_parse_send_data_request(x224_payload,
                                        x224_payload_len,
                                        &request) != LIBRDP_STATUS_OK ||
        request.channel_id != TEST_PNP_CHANNEL_ID ||
        rdp_virtual_channel_parse_packet(request.payload,
                                         request.payload_len,
                                         packet) != LIBRDP_STATUS_OK)
        return 0;
    return packet->length == packet->payload_len &&
           (packet->flags & (RDP_VIRTUAL_CHANNEL_FLAG_FIRST |
                             RDP_VIRTUAL_CHANNEL_FLAG_LAST)) ==
               (RDP_VIRTUAL_CHANNEL_FLAG_FIRST |
                RDP_VIRTUAL_CHANNEL_FLAG_LAST);
}

static int test_pnp_handle_request(librdp_session* session,
                                   test_pnp_capture* capture,
                                   const rdp_buffer* request,
                                   rdp_virtual_channel_packet* response)
{
    if (!session || !capture || !request || !response)
        return 0;
    test_pnp_capture_reset(capture);
    if (rdp_session_handle_pnp_redirection_message(session,
                                                   request->data,
                                                   request->length) !=
        LIBRDP_STATUS_OK)
        return 0;
    return test_pnp_capture_payload(capture, response);
}

/*
 * Exercise the configured PNP device through its complete session-side
 * lifecycle. The unknown-ID request proves that explicit configuration is the
 * authorization boundary; removal checks that all mutable device state is
 * discarded before subsequent I/O.
 */
static int test_pnp_virtual_lifecycle(void)
{
    static const uint8_t update_data[] = {
        0x51u, 0x52u, 0x53u, 0x54u, 0x55u
    };
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    test_pnp_capture capture;
    rdp_buffer request;
    rdp_virtual_channel_packet response;
    rdp_pnp_redirection_device_addition addition;
    rdp_pnp_redirection_status_reply status_reply;
    rdp_pnp_redirection_write_reply write_reply;
    rdp_pnp_redirection_read_reply read_reply;
    rdp_pnp_redirection_control_reply control_reply;
    librdp_metrics metrics;
    uint32_t device_id = 0u;

    memset(&capture, 0, sizeof(capture));
    memset(&response, 0, sizeof(response));
    memset(&addition, 0, sizeof(addition));
    memset(&status_reply, 0, sizeof(status_reply));
    memset(&write_reply, 0, sizeof(write_reply));
    memset(&read_reply, 0, sizeof(read_reply));
    memset(&control_reply, 0, sizeof(control_reply));
    rdp_buffer_init(&capture.bytes);
    rdp_buffer_init(&request);

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_enable_feature(settings,
                                         LIBRDP_FEATURE_PNP,
                                         1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_pnp_device(
              settings,
              "LIBRDP\\PNP\\SMOKE_DEVICE",
              "LIBRDP\\PNP\\SMOKE",
              "Synthetic PNP smoke device",
              LIBRDP_PNP_DEVICE_CAP_REMOVABLE |
                  LIBRDP_PNP_DEVICE_CAP_SURPRISE_REMOVAL_OK) ==
          LIBRDP_STATUS_OK);
    device_id = rdp_settings_pnp_device_id_internal(settings, 0u);
    CHECK(device_id != 0u);

    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(rdp_settings_pnp_device_id_internal(session->settings, 0u) ==
          device_id);
    session->mcs_user_id = TEST_PNP_USER_ID;
    session->pnp_redirection_channel_id = TEST_PNP_CHANNEL_ID;
    rdp_transport_attach_backend(&session->transport,
                                 &capture,
                                 &TEST_PNP_TRANSPORT_OPS);

    CHECK(rdp_pnp_redirection_write_version(
              &request,
              1u,
              0u,
              RDP_PNP_REDIRECTION_CAP_DYNAMIC_DEVICES) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_pnp_redirection_message(
              session, request.data, request.length) == LIBRDP_STATUS_OK);
    CHECK(capture.bytes.length == 0u);

    request.length = 0u;
    CHECK(rdp_pnp_redirection_write_authenticated(&request) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_pnp_redirection_message(
              session, request.data, request.length) == LIBRDP_STATUS_OK);
    CHECK(test_pnp_capture_payload(&capture, &response));
    CHECK(rdp_pnp_redirection_parse_device_addition(
              response.payload,
              response.payload_len,
              &addition) == LIBRDP_STATUS_OK);
    CHECK(addition.device_count == 1u);
    CHECK(addition.devices[0].client_device_id == device_id);
    CHECK(addition.devices[0].has_container_id);
    CHECK(addition.devices[0].container_id_len == 16u);
    CHECK(addition.devices[0].has_device_caps);
    CHECK(addition.devices[0].device_caps ==
          (LIBRDP_PNP_DEVICE_CAP_REMOVABLE |
           LIBRDP_PNP_DEVICE_CAP_SURPRISE_REMOVAL_OK));
    CHECK(session->pnp_redirection_ready);
    CHECK(session->pnp_redirection_devices_sent);

    test_pnp_capture_reset(&capture);
    CHECK(rdp_session_pnp_send_devices(session) == LIBRDP_STATUS_OK);
    CHECK(capture.bytes.length == 0u);

    request.length = 0u;
    CHECK(rdp_pnp_redirection_write_create_request(
              &request,
              1u,
              0u,
              TEST_PNP_UNKNOWN_DEVICE_ID,
              0u,
              0u,
              0u,
              0u) == LIBRDP_STATUS_OK);
    CHECK(test_pnp_handle_request(session, &capture, &request, &response));
    CHECK(rdp_pnp_redirection_parse_status_reply(
              response.payload,
              response.payload_len,
              &status_reply) == LIBRDP_STATUS_OK);
    CHECK(status_reply.result != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS);
    CHECK(!session->pnp_redirection_open_device_active);

    request.length = 0u;
    CHECK(rdp_pnp_redirection_write_create_request(
              &request,
              2u,
              0u,
              device_id,
              0x80000000u,
              1u,
              1u,
              0u) == LIBRDP_STATUS_OK);
    CHECK(test_pnp_handle_request(session, &capture, &request, &response));
    CHECK(rdp_pnp_redirection_parse_status_reply(
              response.payload,
              response.payload_len,
              &status_reply) == LIBRDP_STATUS_OK);
    CHECK(status_reply.result == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS);
    CHECK(session->pnp_redirection_open_device_active);
    CHECK(session->pnp_redirection_open_device_id == device_id);

    request.length = 0u;
    CHECK(rdp_pnp_redirection_write_write_request(
              &request,
              3u,
              0u,
              0u,
              4u,
              update_data,
              (uint32_t)sizeof(update_data)) == LIBRDP_STATUS_OK);
    CHECK(test_pnp_handle_request(session, &capture, &request, &response));
    CHECK(rdp_pnp_redirection_parse_write_reply(
              response.payload,
              response.payload_len,
              &write_reply) == LIBRDP_STATUS_OK);
    CHECK(write_reply.result == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS);
    CHECK(write_reply.bytes_written == sizeof(update_data));

    request.length = 0u;
    CHECK(rdp_pnp_redirection_write_read_request(
              &request,
              4u,
              0u,
              (uint32_t)sizeof(update_data),
              0u,
              4u) == LIBRDP_STATUS_OK);
    CHECK(test_pnp_handle_request(session, &capture, &request, &response));
    CHECK(rdp_pnp_redirection_parse_read_reply(
              response.payload,
              response.payload_len,
              &read_reply) == LIBRDP_STATUS_OK);
    CHECK(read_reply.result == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS);
    CHECK(read_reply.data_len == sizeof(update_data));
    CHECK(memcmp(read_reply.data,
                 update_data,
                 sizeof(update_data)) == 0);

    request.length = 0u;
    CHECK(rdp_pnp_redirection_write_control_request(
              &request,
              5u,
              0u,
              0x1020u,
              update_data,
              (uint32_t)sizeof(update_data),
              (uint32_t)sizeof(update_data),
              NULL,
              0u) == LIBRDP_STATUS_OK);
    CHECK(test_pnp_handle_request(session, &capture, &request, &response));
    CHECK(rdp_pnp_redirection_parse_control_reply(
              response.payload,
              response.payload_len,
              &control_reply) == LIBRDP_STATUS_OK);
    CHECK(control_reply.result == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS);
    CHECK(control_reply.data_len == sizeof(update_data));
    CHECK(memcmp(control_reply.data,
                 update_data,
                 sizeof(update_data)) == 0);

    request.length = 0u;
    CHECK(rdp_pnp_redirection_write_device_removal(&request, device_id) ==
          LIBRDP_STATUS_OK);
    test_pnp_capture_reset(&capture);
    CHECK(rdp_session_handle_pnp_redirection_message(
              session, request.data, request.length) == LIBRDP_STATUS_OK);
    CHECK(capture.bytes.length == 0u);
    CHECK(!session->pnp_redirection_open_device_active);
    CHECK(session->pnp_redirection_open_device_id == 0u);
    CHECK(!session->pnp_redirection_storage_active);
    CHECK(session->pnp_redirection_storage.length == 0u);

    request.length = 0u;
    CHECK(rdp_pnp_redirection_write_read_request(
              &request,
              6u,
              0u,
              1u,
              0u,
              0u) == LIBRDP_STATUS_OK);
    CHECK(test_pnp_handle_request(session, &capture, &request, &response));
    CHECK(rdp_pnp_redirection_parse_read_reply(
              response.payload,
              response.payload_len,
              &read_reply) == LIBRDP_STATUS_OK);
    CHECK(read_reply.result != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS);
    CHECK(read_reply.data_len == 0u);

    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(metrics.channel_out >= 6u);
    CHECK(metrics.channel_bytes_out > 0u);

    rdp_buffer_free(&request);
    librdp_session_free(session);
    rdp_buffer_free(&capture.bytes);
    librdp_settings_free(settings);
    return 0;
}

int main(void)
{
    return test_pnp_virtual_lifecycle();
}
