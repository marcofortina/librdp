/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: device and media extension serializers and provider-facing operations.
 * Invariants: state transitions and wire behavior are preserved from the
 * server orchestrator; cross-domain calls use private module contracts.
 * Ownership: server and peer objects own retained state; input payloads are
 * borrowed for the duration of each call.
 * Threading: callers serialize access to each listener and peer.
 * Trust boundary: remote protocol data is validated before state is committed.
 */

#include "server/server_extensions.h"

#include "server/server_channels.h"
#include "server/server_features.h"
#include "server/server_listener.h"
#include "server/server_peer.h"
#include "server/server_protocol.h"
#include "server/server_security.h"

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

static int rdp_server_device_family_typed(librdp_server_extension_family family)
{
    return family == LIBRDP_SERVER_EXTENSION_FILESYSTEM ||
           family == LIBRDP_SERVER_EXTENSION_PRINTER ||
           family == LIBRDP_SERVER_EXTENSION_SMARTCARD ||
           family == LIBRDP_SERVER_EXTENSION_SERIAL_PORT ||
           family == LIBRDP_SERVER_EXTENSION_PARALLEL_PORT;
}

static librdp_status rdp_server_validate_device_family(const librdp_server_peer* peer,
                                                       librdp_server_extension_family family,
                                                       uint32_t device_id)
{
    const rdp_server_redirected_device* device = NULL;
    librdp_feature feature = (librdp_feature)0;
    librdp_server_extension_family actual = LIBRDP_SERVER_EXTENSION_UNKNOWN;

    if (!peer || !rdp_server_device_family_typed(family))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    device = rdp_server_find_redirected_device_const(peer, device_id);
    if (!device)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    actual = rdp_server_redirected_device_family(device->device_type, &feature);
    return actual == family ? LIBRDP_STATUS_OK : LIBRDP_STATUS_INVALID_ARGUMENT;
}

librdp_status rdp_server_send_dynamic_named_buffer(librdp_server_peer* peer,
                                                         uint32_t dynamic_channel_id,
                                                         const char* expected_name,
                                                         const rdp_buffer* buffer)
{
    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_server_dynamic_channel_open_named(peer, dynamic_channel_id, expected_name))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return librdp_server_peer_send_dynamic_channel_data(peer, dynamic_channel_id, buffer->data, buffer->length);
}

static int rdp_server_extension_family_compatible(librdp_server_extension_family actual,
                                                  librdp_server_extension_family expected)
{
    if (expected == LIBRDP_SERVER_EXTENSION_UNKNOWN)
        return 0;
    if (actual == expected)
        return 1;
    return actual == LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION &&
           (expected == LIBRDP_SERVER_EXTENSION_SMARTCARD ||
            expected == LIBRDP_SERVER_EXTENSION_PNP ||
            rdp_server_device_family_typed(expected));
}

static librdp_status rdp_server_validate_outgoing_extension(librdp_server_extension_family family,
                                                            const char* name,
                                                            size_t name_len,
                                                            const void* payload,
                                                            size_t payload_len)
{
    librdp_server_extension_event event;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!name || (!payload && payload_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = librdp_server_extension_event_init(&event);
    if (status != LIBRDP_STATUS_OK)
        return status;
    event.family = family;
    event.name = name;
    event.name_len = name_len;
    event.payload = payload;
    event.payload_len = payload_len;
    return rdp_server_extension_validate(&event);
}

librdp_status librdp_server_peer_send_static_extension_data(librdp_server_peer* peer,
                                                            librdp_server_extension_family family,
                                                            uint16_t channel_id,
                                                            const void* payload,
                                                            size_t payload_len)
{
    char name[LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY];
    librdp_server_extension_family actual_family = LIBRDP_SERVER_EXTENSION_UNKNOWN;
    librdp_feature feature = (librdp_feature)0;
    uint16_t index = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || (!payload && payload_len > 0) || family == LIBRDP_SERVER_EXTENSION_UNKNOWN)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (!rdp_server_static_channel_index(peer, channel_id, &index) ||
        !peer->advertised_channel_joined[index])
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_server_copy_channel_name(name, peer->advertised_channels[index].name);
    rdp_server_extension_classify_name(name, strlen(name), &actual_family, &feature);
    if (!rdp_server_extension_family_compatible(actual_family, family))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_server_validate_outgoing_extension(actual_family, name, strlen(name), payload, payload_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return librdp_server_peer_send_channel_data(peer, channel_id, payload, payload_len);
}

librdp_status librdp_server_peer_send_dynamic_extension_data(librdp_server_peer* peer,
                                                             librdp_server_extension_family family,
                                                             uint32_t dynamic_channel_id,
                                                             const void* payload,
                                                             size_t payload_len)
{
    rdp_server_dynamic_channel* channel = NULL;
    librdp_server_extension_family actual_family = LIBRDP_SERVER_EXTENSION_UNKNOWN;
    librdp_feature feature = (librdp_feature)0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || (!payload && payload_len > 0) || family == LIBRDP_SERVER_EXTENSION_UNKNOWN)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    channel = rdp_server_find_dynamic_channel(peer, dynamic_channel_id);
    if (!channel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_server_extension_classify_name(channel->name, strlen(channel->name), &actual_family, &feature);
    if (!rdp_server_extension_family_compatible(actual_family, family))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_server_validate_outgoing_extension(actual_family,
                                                    channel->name,
                                                    strlen(channel->name),
                                                    payload,
                                                    payload_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return librdp_server_peer_send_dynamic_channel_data(peer, dynamic_channel_id, payload, payload_len);
}

librdp_status librdp_server_peer_get_extension_state(const librdp_server_peer* peer,
                                                     librdp_server_extension_family family,
                                                     librdp_server_extension_state* state)
{
    if (!peer || !state || !rdp_server_extension_family_valid(family) ||
        !rdp_server_extension_state_valid(state))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *state = peer->extension_states[(size_t)family];
    state->provider_ready =
        rdp_server_extension_provider_ready(peer->backend_extension_families, family) ||
        (state->feature != 0 &&
         rdp_server_feature_extension_provider_ready(peer->backend_extension_families, state->feature)) ||
        (state->feature != 0 && (peer->backend_features & (uint32_t)state->feature) != 0);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_cancel_extension(librdp_server_peer* peer,
                                                  librdp_server_extension_family family)
{
    librdp_server_extension_state* state = rdp_server_extension_state_mut(peer, family);

    if (!peer || !state)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    state->pending_open = 0;
    state->closing = 0;
    state->pending_requests = 0;
    state->cancelled = 1u;
    state->last_status = LIBRDP_STATUS_OK;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_record_extension_timeout(librdp_server_peer* peer,
                                                          librdp_server_extension_family family)
{
    librdp_server_extension_state* state = rdp_server_extension_state_mut(peer, family);

    if (!peer || !state)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    if (state->timeout_count != UINT32_MAX)
        state->timeout_count++;
    state->last_status = LIBRDP_STATUS_TIMEOUT;
    rdp_server_record_status(peer,
                             LIBRDP_STATUS_TIMEOUT,
                             LIBRDP_ERROR_COMPONENT_CHANNEL,
                             "server.extension.timeout",
                             "extension provider timeout");
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_send_device_reply(librdp_server_peer* peer,
                                                   uint16_t channel_id,
                                                   librdp_server_extension_family family,
                                                   uint32_t device_id,
                                                   uint32_t result_code)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_server_validate_device_family(peer, family, device_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&payload);
    status = rdp_device_redirection_write_device_reply(&payload, device_id, result_code);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_server_peer_send_static_extension_data(peer,
                                                               family,
                                                               channel_id,
                                                               payload.data,
                                                               payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_device_io_completion(librdp_server_peer* peer,
                                                           uint16_t channel_id,
                                                           librdp_server_extension_family family,
                                                           uint32_t device_id,
                                                           uint32_t completion_id,
                                                           uint32_t io_status,
                                                           const void* payload_data,
                                                           size_t payload_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || (!payload_data && payload_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_server_validate_device_family(peer, family, device_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&payload);
    status = rdp_device_redirection_write_io_completion(&payload,
                                                        device_id,
                                                        completion_id,
                                                        io_status,
                                                        payload_data,
                                                        payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_server_peer_send_static_extension_data(peer,
                                                               family,
                                                               channel_id,
                                                               payload.data,
                                                               payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_usb_device_capabilities_init(
    librdp_server_usb_device_capabilities* capabilities)
{
    if (!capabilities)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(capabilities, 0, sizeof(*capabilities));
    capabilities->version = LIBRDP_SERVER_USB_DEVICE_CAPABILITIES_VERSION;
    capabilities->size = sizeof(*capabilities);
    capabilities->usb_bus_interface_version = 1u;
    capabilities->usbdi_version = 0x00000600u;
    capabilities->supported_usb_version = 0x00000200u;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_usb_device_capabilities_to_wire(
    const librdp_server_usb_device_capabilities* capabilities,
    rdp_usb_redirection_device_capabilities* wire)
{
    const size_t required_size =
        offsetof(librdp_server_usb_device_capabilities,
                 no_ack_isoch_write_jitter_buffer_size_ms) +
        sizeof(capabilities->no_ack_isoch_write_jitter_buffer_size_ms);

    if (!capabilities || !wire ||
        capabilities->version != LIBRDP_SERVER_USB_DEVICE_CAPABILITIES_VERSION ||
        capabilities->size < required_size ||
        capabilities->usb_bus_interface_version == 0 ||
        capabilities->supported_usb_version == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(wire, 0, sizeof(*wire));
    wire->cb_size = RDP_USB_REDIRECTION_DEVICE_CAPABILITIES_SIZE;
    wire->usb_bus_interface_version = capabilities->usb_bus_interface_version;
    wire->usbdi_version = capabilities->usbdi_version;
    wire->supported_usb_version = capabilities->supported_usb_version;
    wire->hcd_capabilities = capabilities->hcd_capabilities;
    wire->device_is_high_speed = capabilities->device_is_high_speed ? 1u : 0u;
    wire->no_ack_isoch_write_jitter_buffer_size_ms =
        capabilities->no_ack_isoch_write_jitter_buffer_size_ms;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_send_usb_capability_response(librdp_server_peer* peer,
                                                              uint32_t dynamic_channel_id,
                                                              uint32_t message_id,
                                                              uint32_t capability_value,
                                                              uint32_t result)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_usb_redirection_write_capability_response(&payload,
                                                           message_id,
                                                           capability_value,
                                                           result);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_USB_REDIRECTION_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_usb_add_device(
    librdp_server_peer* peer,
    uint32_t dynamic_channel_id,
    uint32_t message_id,
    uint32_t usb_device,
    const void* device_instance_id,
    uint32_t device_instance_id_len,
    const void* hardware_ids,
    uint32_t hardware_ids_len,
    const void* compatibility_ids,
    uint32_t compatibility_ids_len,
    const void* container_id,
    uint32_t container_id_len,
    const librdp_server_usb_device_capabilities* capabilities)
{
    rdp_usb_redirection_device_capabilities wire_caps;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if ((!device_instance_id && device_instance_id_len > 0) ||
        (!hardware_ids && hardware_ids_len > 0) ||
        (!compatibility_ids && compatibility_ids_len > 0) ||
        (!container_id && container_id_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_server_usb_device_capabilities_to_wire(capabilities, &wire_caps);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&payload);
    status = rdp_usb_redirection_write_add_device(&payload,
                                                  message_id,
                                                  usb_device,
                                                  (const uint8_t*)device_instance_id,
                                                  device_instance_id_len,
                                                  (const uint8_t*)hardware_ids,
                                                  hardware_ids_len,
                                                  (const uint8_t*)compatibility_ids,
                                                  compatibility_ids_len,
                                                  (const uint8_t*)container_id,
                                                  container_id_len,
                                                  &wire_caps);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_USB_REDIRECTION_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_usb_retract_device(librdp_server_peer* peer,
                                                         uint32_t dynamic_channel_id,
                                                         uint32_t interface_id,
                                                         uint32_t message_id,
                                                         uint32_t reason)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_usb_redirection_write_retract_device(&payload, interface_id, message_id, reason);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_USB_REDIRECTION_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_usb_io_control_completion(
    librdp_server_peer* peer,
    uint32_t dynamic_channel_id,
    uint32_t request_completion_interface_id,
    uint32_t message_id,
    uint32_t request_id,
    uint32_t hresult,
    uint32_t information,
    const void* output_buffer,
    uint32_t output_buffer_len)
{
    rdp_usb_redirection_io_completion completion;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!output_buffer && output_buffer_len > 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&completion, 0, sizeof(completion));
    completion.request_id = request_id;
    completion.hresult = hresult;
    completion.information = information;
    completion.output_buffer = (const uint8_t*)output_buffer;
    completion.output_buffer_len = output_buffer_len;
    rdp_buffer_init(&payload);
    status = rdp_usb_redirection_write_io_control_completion(&payload,
                                                             request_completion_interface_id,
                                                             message_id,
                                                             &completion);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_USB_REDIRECTION_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_usb_urb_completion(
    librdp_server_peer* peer,
    uint32_t dynamic_channel_id,
    uint32_t request_completion_interface_id,
    uint32_t message_id,
    uint32_t request_id,
    const void* ts_urb_result,
    uint32_t ts_urb_result_len,
    uint32_t hresult,
    const void* output_buffer,
    uint32_t output_buffer_len)
{
    rdp_usb_redirection_urb_completion completion;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if ((!ts_urb_result && ts_urb_result_len > 0) ||
        (!output_buffer && output_buffer_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&completion, 0, sizeof(completion));
    completion.request_id = request_id;
    completion.ts_urb_result = (const uint8_t*)ts_urb_result;
    completion.cb_ts_urb_result = ts_urb_result_len;
    completion.hresult = hresult;
    completion.output_buffer = (const uint8_t*)output_buffer;
    completion.output_buffer_len = output_buffer_len;
    rdp_buffer_init(&payload);
    status = output_buffer_len > 0 ?
                 rdp_usb_redirection_write_urb_completion(&payload,
                                                          request_completion_interface_id,
                                                          message_id,
                                                          &completion) :
                 rdp_usb_redirection_write_urb_completion_no_data(&payload,
                                                                  request_completion_interface_id,
                                                                  message_id,
                                                                  &completion);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_USB_REDIRECTION_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_server_send_pnp_buffer(librdp_server_peer* peer,
                                                uint16_t channel_id,
                                                const rdp_buffer* payload)
{
    return rdp_server_send_static_named_buffer(peer,
                                               channel_id,
                                               RDP_PNP_REDIRECTION_CHANNEL_NAME,
                                               payload);
}

librdp_status librdp_server_peer_send_pnp_version(librdp_server_peer* peer,
                                                  uint16_t channel_id,
                                                  uint32_t major_version,
                                                  uint32_t minor_version,
                                                  uint32_t capabilities)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_pnp_redirection_write_version(&payload,
                                               major_version,
                                               minor_version,
                                               capabilities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_pnp_buffer(peer, channel_id, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_pnp_authenticated(librdp_server_peer* peer,
                                                        uint16_t channel_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_pnp_redirection_write_authenticated(&payload);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_pnp_buffer(peer, channel_id, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_pnp_capabilities_request(librdp_server_peer* peer,
                                                               uint16_t channel_id,
                                                               uint32_t request_id,
                                                               uint16_t version)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_pnp_redirection_write_capabilities_request(&payload, request_id, 0, version);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_pnp_buffer(peer, channel_id, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_pnp_create_request(librdp_server_peer* peer,
                                                         uint16_t channel_id,
                                                         uint32_t request_id,
                                                         uint32_t device_id,
                                                         uint32_t desired_access,
                                                         uint32_t share_mode,
                                                         uint32_t creation_disposition,
                                                         uint32_t flags_and_attributes)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_pnp_redirection_write_create_request(&payload,
                                                      request_id,
                                                      0,
                                                      device_id,
                                                      desired_access,
                                                      share_mode,
                                                      creation_disposition,
                                                      flags_and_attributes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_pnp_buffer(peer, channel_id, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_pnp_read_request(librdp_server_peer* peer,
                                                       uint16_t channel_id,
                                                       uint32_t request_id,
                                                       uint32_t bytes_to_read,
                                                       uint32_t offset_high,
                                                       uint32_t offset_low)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_pnp_redirection_write_read_request(&payload,
                                                    request_id,
                                                    0,
                                                    bytes_to_read,
                                                    offset_high,
                                                    offset_low);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_pnp_buffer(peer, channel_id, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_pnp_write_request(librdp_server_peer* peer,
                                                        uint16_t channel_id,
                                                        uint32_t request_id,
                                                        uint32_t offset_high,
                                                        uint32_t offset_low,
                                                        const void* data,
                                                        uint32_t data_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data && data_len > 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_pnp_redirection_write_write_request(&payload,
                                                     request_id,
                                                     0,
                                                     offset_high,
                                                     offset_low,
                                                     (const uint8_t*)data,
                                                     data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_pnp_buffer(peer, channel_id, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_pnp_control_request(librdp_server_peer* peer,
                                                          uint16_t channel_id,
                                                          uint32_t request_id,
                                                          uint32_t io_code,
                                                          const void* input,
                                                          uint32_t input_len,
                                                          uint32_t output_len,
                                                          const void* output,
                                                          uint32_t actual_output_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if ((!input && input_len > 0) || (!output && actual_output_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_pnp_redirection_write_control_request(&payload,
                                                       request_id,
                                                       0,
                                                       io_code,
                                                       (const uint8_t*)input,
                                                       input_len,
                                                       output_len,
                                                       (const uint8_t*)output,
                                                       actual_output_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_pnp_buffer(peer, channel_id, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_pnp_cancel_request(librdp_server_peer* peer,
                                                         uint16_t channel_id,
                                                         uint32_t request_id,
                                                         uint32_t id_to_cancel)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_pnp_redirection_write_cancel_request(&payload,
                                                      request_id,
                                                      0,
                                                      0,
                                                      id_to_cancel);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_pnp_buffer(peer, channel_id, &payload);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_server_audio_format_from_public(const librdp_audio_format* source,
                                                         rdp_audio_format* target)
{
    if (!source || !target || (!source->extra_data && source->extra_data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(target, 0, sizeof(*target));
    target->format_tag = source->format_tag;
    target->channels = source->channels;
    target->samples_per_sec = source->samples_per_sec;
    target->avg_bytes_per_sec = source->avg_bytes_per_sec;
    target->block_align = source->block_align;
    target->bits_per_sample = source->bits_per_sample;
    target->extra_data = source->extra_data;
    target->extra_data_len = source->extra_data_len;
    return rdp_audio_format_encoded_size(target) > 0 ? LIBRDP_STATUS_OK :
                                                       LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status rdp_server_audio_formats_from_public(const librdp_audio_format* formats,
                                                          uint32_t format_count,
                                                          rdp_audio_format* converted,
                                                          uint32_t converted_capacity)
{
    if ((!formats && format_count > 0) || !converted || format_count > converted_capacity)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (uint32_t i = 0; i < format_count; i++)
    {
        librdp_status status = rdp_server_audio_format_from_public(&formats[i], &converted[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static void rdp_server_video_capture_media_from_public(const librdp_video_capture_media* source,
                                                       rdp_video_capture_media_type* target)
{
    memset(target, 0, sizeof(*target));
    target->format = source->format;
    target->width = source->width;
    target->height = source->height;
    target->frame_rate_numerator = source->frame_rate_numerator;
    target->frame_rate_denominator = source->frame_rate_denominator;
    target->pixel_aspect_ratio_numerator = source->pixel_aspect_ratio_numerator;
    target->pixel_aspect_ratio_denominator = source->pixel_aspect_ratio_denominator;
    target->flags = source->flags;
}

static librdp_status rdp_server_video_capture_media_list_from_public(
    const librdp_video_capture_media* media,
    uint8_t media_count,
    rdp_video_capture_media_type* converted,
    uint8_t converted_capacity)
{
    if ((!media && media_count > 0) || !converted || media_count == 0 || media_count > converted_capacity)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (uint8_t i = 0; i < media_count; i++)
        rdp_server_video_capture_media_from_public(&media[i], &converted[i]);
    return LIBRDP_STATUS_OK;
}

static rdp_server_dynamic_channel* rdp_server_find_dynamic_channel_named(
    librdp_server_peer* peer,
    const char* name)
{
    if (!peer || !name)
        return NULL;
    for (uint32_t index = 0; index < RDP_SERVER_MAX_DYNAMIC_CHANNELS;
         index++)
    {
        rdp_server_dynamic_channel* channel = &peer->dynamic_channels[index];

        if (channel->open && strcmp(channel->name, name) == 0)
            return channel;
    }
    return NULL;
}

/*
 * Convert borrowed top-down BGRA32 pixels into bottom-up 32-bpp XOR and
 * one-bit AND planes. Checked row arithmetic and complete source bounds are
 * validated before either destination buffer becomes observable.
 */
static librdp_status rdp_server_pointer_convert_shape(
    const librdp_server_pointer_update* source,
    rdp_buffer* xor_mask,
    rdp_buffer* and_mask,
    rdp_pointer_update* wire)
{
    size_t source_row_bytes = 0u;
    size_t source_required = 0u;
    size_t xor_stride = 0u;
    size_t xor_bytes = 0u;
    size_t and_stride = 0u;
    size_t and_bytes = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!source || !xor_mask || !and_mask || !wire ||
        source->width == 0u || source->height == 0u ||
        source->width > RDP_POINTER_MAX_DIMENSION ||
        source->height > RDP_POINTER_MAX_DIMENSION ||
        source->hotspot_x >= source->width ||
        source->hotspot_y >= source->height || !source->pixels)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    source_row_bytes = (size_t)source->width * 4u;
    if (source->stride < source_row_bytes ||
        (size_t)(source->height - 1u) >
            (SIZE_MAX - source_row_bytes) / source->stride)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    source_required =
        (size_t)(source->height - 1u) * source->stride + source_row_bytes;
    if (source->pixels_len < source_required)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    xor_stride = source_row_bytes;
    and_stride = (((size_t)source->width + 15u) / 16u) * 2u;
    if ((size_t)source->height > SIZE_MAX / xor_stride ||
        (size_t)source->height > SIZE_MAX / and_stride)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    xor_bytes = xor_stride * source->height;
    and_bytes = and_stride * source->height;
    status = rdp_buffer_reserve(xor_mask, xor_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_reserve(and_mask, and_bytes);
    if (status != LIBRDP_STATUS_OK)
        return status;
    xor_mask->length = xor_bytes;
    and_mask->length = and_bytes;
    memset(and_mask->data, 0, and_bytes);
    for (uint16_t y = 0u; y < source->height; y++)
    {
        const uint8_t* source_row =
            source->pixels + (size_t)y * source->stride;
        size_t destination_row = (size_t)(source->height - 1u - y);
        uint8_t* xor_row =
            xor_mask->data + destination_row * xor_stride;
        uint8_t* and_row =
            and_mask->data + destination_row * and_stride;

        memcpy(xor_row, source_row, source_row_bytes);
        for (uint16_t x = 0u; x < source->width; x++)
        {
            if (source_row[(size_t)x * 4u + 3u] == 0u)
                and_row[(size_t)x / 8u] |=
                    (uint8_t)(0x80u >> (x % 8u));
        }
    }
    memset(wire, 0, sizeof(*wire));
    wire->kind = RDP_POINTER_UPDATE_KIND_SHAPE;
    wire->cache_index = source->cache_index;
    wire->hot_x = source->hotspot_x;
    wire->hot_y = source->hotspot_y;
    wire->width = source->width;
    wire->height = source->height;
    wire->xor_bpp = 32u;
    wire->xor_mask = xor_mask->data;
    wire->xor_mask_len = xor_mask->length;
    wire->and_mask = and_mask->data;
    wire->and_mask_len = and_mask->length;
    return LIBRDP_STATUS_OK;
}

/*
 * Map a normalized pointer update onto the equivalent fast-path update code.
 * The slow-path serializer supplies the shared pointer attribute layout; only
 * its two-byte message discriminator is omitted from fast-path payloads.
 */
static librdp_status rdp_server_send_fastpath_pointer(
    librdp_server_peer* peer,
    const rdp_pointer_update* wire)
{
    rdp_buffer payload;
    uint8_t update_code = 0u;
    const uint8_t* update_data = NULL;
    size_t update_len = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !wire)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (wire->kind)
    {
        case RDP_POINTER_UPDATE_KIND_NULL:
            update_code = RDP_FASTPATH_UPDATE_POINTER_NULL;
            break;
        case RDP_POINTER_UPDATE_KIND_DEFAULT:
            update_code = RDP_FASTPATH_UPDATE_POINTER_DEFAULT;
            break;
        case RDP_POINTER_UPDATE_KIND_POSITION:
            update_code = RDP_FASTPATH_UPDATE_POINTER_POSITION;
            break;
        case RDP_POINTER_UPDATE_KIND_CACHED:
            update_code = RDP_FASTPATH_UPDATE_POINTER_CACHED;
            break;
        case RDP_POINTER_UPDATE_KIND_SHAPE:
            if (wire->shape_format ==
                RDP_POINTER_SHAPE_FORMAT_COLOR)
                update_code = RDP_FASTPATH_UPDATE_POINTER_COLOR;
            else if (wire->shape_format ==
                         RDP_POINTER_SHAPE_FORMAT_LARGE ||
                     wire->xor_mask_len > UINT16_MAX ||
                     wire->and_mask_len > UINT16_MAX)
                update_code = RDP_FASTPATH_UPDATE_POINTER_LARGE;
            else
                update_code = RDP_FASTPATH_UPDATE_POINTER_NEW;
            break;
        default:
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    rdp_buffer_init(&payload);
    status = rdp_pointer_write_slowpath(&payload, wire);
    if (status == LIBRDP_STATUS_OK &&
        wire->kind != RDP_POINTER_UPDATE_KIND_NULL &&
        wire->kind != RDP_POINTER_UPDATE_KIND_DEFAULT)
    {
        if (payload.length < sizeof(uint16_t))
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
        {
            update_data = payload.data + sizeof(uint16_t);
            update_len = payload.length - sizeof(uint16_t);
        }
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_server_send_fastpath_update(peer,
                                                 update_code,
                                                 update_data,
                                                 update_len);
    }
    rdp_buffer_free(&payload);
    return status;
}

/*
 * Serialize an already normalized wire pointer through the negotiated cursor
 * DVC or the base slow-path update. This internal boundary preserves explicit
 * legacy color and large-pointer formats without exposing mask planes in the
 * public API.
 */
librdp_status rdp_server_peer_send_pointer_wire_update(
    librdp_server_peer* peer,
    const rdp_pointer_update* wire)
{
    rdp_server_dynamic_channel* mouse_channel = NULL;
    rdp_buffer update_payload;
    rdp_buffer slowpath;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !wire)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    rdp_buffer_init(&update_payload);
    rdp_buffer_init(&slowpath);
    if (rdp_server_extension_provider_ready(
            peer->backend_extension_families,
            LIBRDP_SERVER_EXTENSION_MOUSE_CURSOR))
    {
        mouse_channel = rdp_server_find_dynamic_channel_named(
            peer,
            RDP_MOUSE_CURSOR_CHANNEL_NAME);
    }
    if (mouse_channel)
    {
        status = librdp_server_peer_send_mouse_cursor_update(
            peer,
            mouse_channel->channel_id,
            (uint32_t)wire->kind,
            wire->cache_index,
            wire->x,
            wire->y,
            wire->hot_x,
            wire->hot_y,
            wire->width,
            wire->height,
            wire->xor_bpp,
            wire->xor_mask,
            wire->xor_mask_len,
            wire->and_mask,
            wire->and_mask_len);
    }
    else if (wire->kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
             (wire->shape_format ==
                  RDP_POINTER_SHAPE_FORMAT_LARGE ||
              wire->xor_mask_len > UINT16_MAX ||
              wire->and_mask_len > UINT16_MAX))
    {
        status = rdp_server_send_fastpath_pointer(peer, wire);
    }
    else
    {
        status = rdp_buffer_append_u16_le(&update_payload,
                                          RDP_UPDATE_TYPE_POINTER);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_pointer_write_slowpath(&update_payload, wire);
        if (status == LIBRDP_STATUS_OK)
        {
            status = rdp_slowpath_write_data_pdu(
                &slowpath,
                peer->share_id,
                (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                RDP_SLOWPATH_DATA_PDU_UPDATE,
                update_payload.data,
                update_payload.length);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_send_slowpath(peer, &slowpath);
    }
    rdp_buffer_free(&slowpath);
    rdp_buffer_free(&update_payload);
    return status;
}

/*
 * Convert a public BGRA pointer to protocol masks, then select the negotiated
 * cursor DVC or base slow-path update. Conversion storage remains local to the
 * call and no wire output occurs after validation or allocation failure.
 */
librdp_status librdp_server_peer_send_pointer_update(
    librdp_server_peer* peer,
    const librdp_server_pointer_update* update)
{
    rdp_pointer_update wire;
    rdp_buffer xor_mask;
    rdp_buffer and_mask;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !update ||
        update->version != LIBRDP_SERVER_POINTER_UPDATE_VERSION ||
        update->size < sizeof(*update))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    memset(&wire, 0, sizeof(wire));
    switch (update->type)
    {
        case LIBRDP_SERVER_POINTER_HIDDEN:
            wire.kind = RDP_POINTER_UPDATE_KIND_NULL;
            break;
        case LIBRDP_SERVER_POINTER_DEFAULT:
            wire.kind = RDP_POINTER_UPDATE_KIND_DEFAULT;
            break;
        case LIBRDP_SERVER_POINTER_POSITION:
            wire.kind = RDP_POINTER_UPDATE_KIND_POSITION;
            wire.x = update->x;
            wire.y = update->y;
            break;
        case LIBRDP_SERVER_POINTER_CACHED:
            if (update->cache_index >= 128u)
                return LIBRDP_STATUS_INVALID_ARGUMENT;
            wire.kind = RDP_POINTER_UPDATE_KIND_CACHED;
            wire.cache_index = update->cache_index;
            break;
        case LIBRDP_SERVER_POINTER_SHAPE:
            if (update->cache_index >= 128u)
                return LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        default:
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    rdp_buffer_init(&xor_mask);
    rdp_buffer_init(&and_mask);
    if (update->type == LIBRDP_SERVER_POINTER_SHAPE)
    {
        status = rdp_server_pointer_convert_shape(update,
                                                  &xor_mask,
                                                  &and_mask,
                                                  &wire);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_peer_send_pointer_wire_update(peer,
                                                          &wire);
    rdp_buffer_free(&and_mask);
    rdp_buffer_free(&xor_mask);
    return status;
}

librdp_status librdp_server_peer_send_mouse_cursor_update(librdp_server_peer* peer,
                                                          uint32_t dynamic_channel_id,
                                                          uint32_t kind,
                                                          uint16_t cache_index,
                                                          uint16_t x,
                                                          uint16_t y,
                                                          uint16_t hot_x,
                                                          uint16_t hot_y,
                                                          uint16_t width,
                                                          uint16_t height,
                                                          uint16_t xor_bpp,
                                                          const void* xor_mask,
                                                          size_t xor_mask_len,
                                                          const void* and_mask,
                                                          size_t and_mask_len)
{
    rdp_buffer payload;
    rdp_pointer_update update;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(&update, 0, sizeof(update));
    update.kind = (rdp_pointer_update_kind)kind;
    update.cache_index = cache_index;
    update.x = x;
    update.y = y;
    update.hot_x = hot_x;
    update.hot_y = hot_y;
    update.width = width;
    update.height = height;
    update.xor_bpp = xor_bpp;
    update.xor_mask = (const uint8_t*)xor_mask;
    update.xor_mask_len = xor_mask_len;
    update.and_mask = (const uint8_t*)and_mask;
    update.and_mask_len = and_mask_len;
    rdp_buffer_init(&payload);
    status = rdp_mouse_cursor_write_update(&payload, &update);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_MOUSE_CURSOR_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_audio_output_formats(librdp_server_peer* peer,
                                                           uint16_t channel_id,
                                                           uint32_t flags,
                                                           uint32_t volume,
                                                           uint32_t pitch,
                                                           uint16_t datagram_port,
                                                           uint8_t last_block_confirmed,
                                                           uint16_t protocol_version,
                                                           const librdp_audio_format* formats,
                                                           uint16_t format_count)
{
    rdp_audio_format converted[RDP_AUDIO_FORMAT_MAX_COUNT];
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_server_audio_formats_from_public(formats,
                                                  format_count,
                                                  converted,
                                                  RDP_AUDIO_FORMAT_MAX_COUNT);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&payload);
    status = rdp_audio_output_write_client_formats(&payload,
                                                   flags,
                                                   volume,
                                                   pitch,
                                                   datagram_port,
                                                   last_block_confirmed,
                                                   protocol_version,
                                                   converted,
                                                   format_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer,
                                                     channel_id,
                                                     RDP_AUDIO_OUTPUT_CHANNEL_NAME,
                                                     &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_audio_output_wave2(librdp_server_peer* peer,
                                                         uint16_t channel_id,
                                                         uint16_t timestamp,
                                                         uint16_t format_no,
                                                         uint8_t block_no,
                                                         uint32_t audio_timestamp,
                                                         const void* data,
                                                         uint16_t data_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_audio_output_write_wave2(&payload,
                                          timestamp,
                                          format_no,
                                          block_no,
                                          audio_timestamp,
                                          data,
                                          data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer,
                                                     channel_id,
                                                     RDP_AUDIO_OUTPUT_CHANNEL_NAME,
                                                     &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_audio_output_close(librdp_server_peer* peer,
                                                         uint16_t channel_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_audio_output_write_close(&payload);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer,
                                                     channel_id,
                                                     RDP_AUDIO_OUTPUT_CHANNEL_NAME,
                                                     &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_audio_input_version(librdp_server_peer* peer,
                                                          uint32_t dynamic_channel_id,
                                                          uint32_t protocol_version)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_audio_input_write_version(&payload, protocol_version);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_AUDIO_INPUT_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_audio_input_formats(librdp_server_peer* peer,
                                                          uint32_t dynamic_channel_id,
                                                          const librdp_audio_format* formats,
                                                          uint32_t format_count)
{
    rdp_audio_format converted[RDP_AUDIO_FORMAT_MAX_COUNT];
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_server_audio_formats_from_public(formats,
                                                  format_count,
                                                  converted,
                                                  RDP_AUDIO_FORMAT_MAX_COUNT);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&payload);
    status = rdp_audio_input_write_formats(&payload, converted, format_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_AUDIO_INPUT_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_audio_input_open(librdp_server_peer* peer,
                                                       uint32_t dynamic_channel_id,
                                                       uint32_t frames_per_packet,
                                                       uint32_t initial_format,
                                                       const librdp_audio_format* format)
{
    rdp_audio_format converted;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_server_audio_format_from_public(format, &converted);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&payload);
    status = rdp_audio_input_write_open(&payload,
                                        frames_per_packet,
                                        initial_format,
                                        &converted);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_AUDIO_INPUT_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_video_geometry_update(librdp_server_peer* peer,
                                                            uint16_t channel_id,
                                                            uint32_t message_id,
                                                            const uint8_t presentation_id[16],
                                                            const void* geometry,
                                                            uint32_t geometry_len,
                                                            const void* visible_rect,
                                                            uint32_t visible_rect_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_video_redirection_write_geometry_update(&payload,
                                                         message_id,
                                                         presentation_id,
                                                         geometry,
                                                         geometry_len,
                                                         visible_rect,
                                                         visible_rect_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer,
                                                     channel_id,
                                                     RDP_VIDEO_REDIRECTION_CHANNEL_NAME,
                                                     &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_video_capability_response(librdp_server_peer* peer,
                                                                uint16_t channel_id,
                                                                uint32_t message_id,
                                                                uint32_t result)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_video_redirection_write_exchange_capabilities_response(&payload,
                                                                        message_id,
                                                                        NULL,
                                                                        0,
                                                                        result);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer,
                                                     channel_id,
                                                     RDP_VIDEO_REDIRECTION_CHANNEL_NAME,
                                                     &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_video_sample(librdp_server_peer* peer,
                                                   uint16_t channel_id,
                                                   uint32_t message_id,
                                                   const uint8_t presentation_id[16],
                                                   uint32_t stream_id,
                                                   const void* data,
                                                   uint32_t data_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_video_redirection_write_sample_message(&payload,
                                                        message_id,
                                                        presentation_id,
                                                        stream_id,
                                                        data,
                                                        data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer,
                                                     channel_id,
                                                     RDP_VIDEO_REDIRECTION_CHANNEL_NAME,
                                                     &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_video_optimized_data(librdp_server_peer* peer,
                                                           uint32_t dynamic_channel_id,
                                                           uint8_t presentation_id,
                                                           uint8_t flags,
                                                           uint64_t timestamp,
                                                           uint64_t duration,
                                                           uint16_t current_packet_index,
                                                           uint16_t packets_in_sample,
                                                           uint32_t sample_number,
                                                           const void* sample,
                                                           uint32_t sample_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_video_optimized_write_video_data(&payload,
                                                  presentation_id,
                                                  flags,
                                                  timestamp,
                                                  duration,
                                                  current_packet_index,
                                                  packets_in_sample,
                                                  sample_number,
                                                  sample,
                                                  sample_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_VIDEO_OPTIMIZED_DATA_CHANNEL,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_camera_device_added(librdp_server_peer* peer,
                                                          uint32_t dynamic_channel_id,
                                                          uint8_t version,
                                                          const void* device_name_utf16le,
                                                          size_t device_name_len,
                                                          const char* channel_name)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_video_capture_write_device_added(&payload,
                                                  version,
                                                  device_name_utf16le,
                                                  device_name_len,
                                                  channel_name);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_camera_media_list(librdp_server_peer* peer,
                                                        uint32_t dynamic_channel_id,
                                                        uint8_t version,
                                                        uint8_t message_id,
                                                        const librdp_video_capture_media* media,
                                                        uint8_t media_count)
{
    rdp_video_capture_media_type converted[RDP_VIDEO_CAPTURE_MAX_STREAMS];
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_server_video_capture_media_list_from_public(media,
                                                             media_count,
                                                             converted,
                                                             RDP_VIDEO_CAPTURE_MAX_STREAMS);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&payload);
    status = rdp_video_capture_write_media_list(&payload,
                                                version,
                                                message_id,
                                                converted,
                                                media_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_VIDEO_CAPTURE_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_camera_sample(librdp_server_peer* peer,
                                                    uint32_t dynamic_channel_id,
                                                    uint8_t version,
                                                    uint8_t stream_index,
                                                    const void* sample,
                                                    size_t sample_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_video_capture_write_sample(&payload,
                                            version,
                                            stream_index,
                                            sample,
                                            sample_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_VIDEO_CAPTURE_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_webauthn_request(librdp_server_peer* peer,
                                                       uint32_t dynamic_channel_id,
                                                       uint32_t command,
                                                       uint32_t flags,
                                                       const void* request_data,
                                                       size_t request_len,
                                                       const char* rp_id,
                                                       const void* transaction_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_webauthn_write_request(&payload,
                                        command,
                                        flags,
                                        request_data,
                                        request_len,
                                        rp_id,
                                        transaction_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_WEBAUTHN_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_webauthn_response(librdp_server_peer* peer,
                                                        uint32_t dynamic_channel_id,
                                                        uint32_t hresult,
                                                        const void* payload_data,
                                                        size_t payload_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_webauthn_write_response(&payload, hresult, payload_data, payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_WEBAUTHN_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_rail_handshake_ex(librdp_server_peer* peer,
                                                        uint16_t channel_id,
                                                        uint32_t build_number,
                                                        uint32_t flags)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_remote_programs_write_handshake_ex(&payload, build_number, flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer,
                                                     channel_id,
                                                     RDP_REMOTE_PROGRAMS_CHANNEL_NAME,
                                                     &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_rail_exec_result(librdp_server_peer* peer,
                                                       uint16_t channel_id,
                                                       uint16_t flags,
                                                       uint16_t exec_result,
                                                       uint32_t raw_result,
                                                       const void* exe_or_file,
                                                       uint16_t exe_or_file_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_remote_programs_write_exec_result(&payload,
                                                   flags,
                                                   exec_result,
                                                   raw_result,
                                                   exe_or_file,
                                                   exe_or_file_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer,
                                                     channel_id,
                                                     RDP_REMOTE_PROGRAMS_CHANNEL_NAME,
                                                     &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_rail_windowmove(librdp_server_peer* peer,
                                                      uint16_t channel_id,
                                                      uint32_t window_id,
                                                      int16_t left,
                                                      int16_t top,
                                                      int16_t right,
                                                      int16_t bottom)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_remote_programs_write_windowmove(&payload,
                                                  window_id,
                                                  left,
                                                  top,
                                                  right,
                                                  bottom);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer,
                                                     channel_id,
                                                     RDP_REMOTE_PROGRAMS_CHANNEL_NAME,
                                                     &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_cr2_version_reply(librdp_server_peer* peer,
                                                        uint32_t dynamic_channel_id,
                                                        const uint32_t* versions,
                                                        uint32_t version_count)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_composited_write_version_reply(&payload, versions, version_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_COMPOSITED_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_cr2_window_node_create(librdp_server_peer* peer,
                                                             uint32_t dynamic_channel_id,
                                                             uint32_t target_resource,
                                                             uint64_t sprite_id,
                                                             uint64_t window_id,
                                                             uint32_t caching_mode)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_composited_write_window_node_create(&payload,
                                                     target_resource,
                                                     sprite_id,
                                                     window_id,
                                                     caching_mode);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_COMPOSITED_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_auth_redirection_response(librdp_server_peer* peer,
                                                                uint32_t dynamic_channel_id,
                                                                uint32_t call_id,
                                                                uint32_t status_code,
                                                                const void* payload_data,
                                                                size_t payload_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_auth_redirection_write_response(&payload,
                                                 call_id,
                                                 status_code,
                                                 payload_data,
                                                 payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_AUTH_REDIRECTION_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_telemetry_metrics(librdp_server_peer* peer,
                                                        uint32_t dynamic_channel_id,
                                                        uint32_t prompt_for_credentials_ms,
                                                        uint32_t authentication_ms,
                                                        uint32_t desktop_ready_ms,
                                                        uint32_t first_graphics_received_ms)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_telemetry_write_metrics(&payload,
                                         prompt_for_credentials_ms,
                                         authentication_ms,
                                         desktop_ready_ms,
                                         first_graphics_received_ms);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_TELEMETRY_DVC_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_multiparty_filter_state(librdp_server_peer* peer,
                                                              uint16_t channel_id,
                                                              uint8_t filter_state)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_multiparty_write_filter_state(&payload, filter_state);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer, channel_id, RDP_MULTIPARTY_CHANNEL_NAME, &payload);
    rdp_buffer_free(&payload);
    return status;
}
