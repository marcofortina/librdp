/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Microsoft RD Gateway HTTP transport provider.
 * Invariants: the gateway channel is attached to rdp_transport only after
 * OUT/IN HTTP streams, RDG handshake, tunnel authorization, and channel
 * creation all succeed.
 * Ownership: successful setup transfers the provider context to transport.
 * Threading: libcurl network progress runs in one worker; transport callers
 * serialize through the owning session.
 * Trust boundary: gateway HTTP bodies and protocol packets are untrusted and
 * validated before becoming RDP stream bytes.
 */

#ifndef RDP_GATEWAY_RDG_HTTP_H
#define RDP_GATEWAY_RDG_HTTP_H

#include "common/buffer.h"
#include "gateway/gateway.h"

#include <stddef.h>
#include <stdint.h>

typedef struct rdp_rdg_packet_view
{
    uint16_t type;
    const uint8_t* payload;
    size_t payload_len;
    const uint8_t* data;
    size_t data_len;
    size_t packet_len;
} rdp_rdg_packet_view;

typedef struct rdp_rdg_queue_node rdp_rdg_queue_node;

typedef struct rdp_rdg_bounded_queue
{
    rdp_rdg_queue_node* head;
    rdp_rdg_queue_node* tail;
    size_t bytes;
    size_t nodes;
    size_t max_bytes;
    size_t max_nodes;
} rdp_rdg_bounded_queue;

librdp_status rdp_rdg_parse_packet(const uint8_t* data,
                                   size_t length,
                                   rdp_rdg_packet_view* packet);

void rdp_rdg_bounded_queue_init(rdp_rdg_bounded_queue* queue,
                                size_t max_bytes,
                                size_t max_nodes);
void rdp_rdg_bounded_queue_clear(rdp_rdg_bounded_queue* queue);
librdp_status rdp_rdg_bounded_queue_push(rdp_rdg_bounded_queue* queue,
                                         uint16_t type,
                                         const void* data,
                                         size_t length);
int rdp_rdg_bounded_queue_has_bytes(const rdp_rdg_bounded_queue* queue);
int rdp_rdg_bounded_queue_can_push(const rdp_rdg_bounded_queue* queue, size_t length);
size_t rdp_rdg_bounded_queue_peek(const rdp_rdg_bounded_queue* queue,
                                  void* data,
                                  size_t length);
size_t rdp_rdg_bounded_queue_read(rdp_rdg_bounded_queue* queue,
                                  void* data,
                                  size_t length);
librdp_status rdp_rdg_bounded_queue_pop(rdp_rdg_bounded_queue* queue,
                                        uint16_t* type,
                                        rdp_buffer* payload);

librdp_status rdp_gateway_connect_rdg_http(rdp_transport* transport,
                                           const rdp_gateway_connect_config* config);

#endif
