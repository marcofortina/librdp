/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal server object contract.
 * Invariants: public config strings are copied before storage and released by
 * the server object; runtime listener state is added only through this header.
 * Ownership: librdp_server owns copied config strings and listener descriptors
 * until librdp_server_free().
 * Threading: server objects are single-owner unless a caller serializes all
 * access externally.
 * Trust boundary: server configuration is local input and must be validated
 * before it influences sockets or wire behavior.
 */

#ifndef RDP_SERVER_INTERNAL_H
#define RDP_SERVER_INTERNAL_H

#include "common/buffer.h"
#include "nla/credssp.h"
#include "protocol/gcc.h"
#include "security/security.h"

#include <librdp/server.h>

#include <openssl/types.h>

#define RDP_SERVER_MAX_DYNAMIC_CHANNELS 64u
#define RDP_SERVER_DYNAMIC_CHANNEL_NAME_CAPACITY 64u
#define RDP_SERVER_MAX_REDIRECTED_DEVICES 64u
#define RDP_SERVER_EXTENSION_FAMILY_COUNT ((size_t)LIBRDP_SERVER_EXTENSION_GEOMETRY_TRACKING + 1u)

typedef struct rdp_server_dynamic_channel
{
    uint32_t channel_id;
    uint8_t channel_id_bytes;
    uint8_t priority;
    uint8_t open;
    uint8_t pending_open;
    uint8_t closing;
    char name[RDP_SERVER_DYNAMIC_CHANNEL_NAME_CAPACITY];
    rdp_buffer fragment;
    uint32_t fragment_expected;
} rdp_server_dynamic_channel;

typedef struct rdp_server_redirected_device
{
    uint8_t present;
    uint32_t device_id;
    uint32_t device_type;
} rdp_server_redirected_device;

struct librdp_server
{
    char* bind_address;
    char* server_name;
    char* tls_certificate_path;
    char* tls_private_key_path;
    char* nla_domain;
    char* nla_username;
    char* nla_password;
    librdp_server_credentials_provider credentials_provider;
    void* credentials_provider_user_data;
    int listen_fd;
    uint16_t port;
    uint16_t local_port;
    uint32_t backlog;
    uint32_t max_peers;
    uint32_t accepted_peers;
    uint32_t width;
    uint32_t height;
    uint32_t requested_features;
    uint32_t backend_features;
    uint64_t backend_extension_families;
    librdp_security_mode security_mode;
};

struct librdp_server_peer
{
    int fd;
    librdp_server_peer_state state;
    uint32_t selected_protocol;
    uint32_t share_id;
    uint16_t user_id;
    uint16_t width;
    uint16_t height;
    char* server_name;
    char* tls_certificate_path;
    char* tls_private_key_path;
    char* nla_domain;
    char* nla_username;
    char* nla_password;
    char* credssp_expected_domain;
    char* credssp_expected_username;
    char* credssp_expected_password;
    librdp_server_credentials_provider credentials_provider;
    void* credentials_provider_user_data;
    uint32_t requested_features;
    uint32_t backend_features;
    uint64_t backend_extension_families;
    librdp_security_mode security_mode;
    SSL_CTX* tls_context;
    SSL* tls;
    EVP_PKEY* standard_private_key;
    rdp_standard_security_context standard_security;
    rdp_ntlm_security_context credssp_security;
    rdp_buffer standard_certificate;
    rdp_buffer credssp_target_name;
    rdp_buffer credssp_target_info;
    uint8_t standard_server_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    uint8_t credssp_server_challenge[8];
    uint8_t credssp_client_nonce[32];
    uint8_t tls_active;
    uint8_t standard_security_ready;
    uint8_t credssp_stage;
    uint8_t credssp_ts_request_version;
    uint8_t credssp_public_key_bound;
    uint8_t credssp_client_nonce_ready;
    uint8_t credssp_security_ready;
    uint8_t nla_authenticated;
    uint32_t nla_failed_attempts;
    short pending_revents;
    uint16_t advertised_channel_count;
    uint16_t dynamic_channel_static_index;
    uint32_t dynamic_channel_count;
    uint16_t joined_channel_count;
    rdp_gcc_channel_definition advertised_channels[RDP_GCC_MAX_SERVER_CHANNELS];
    uint16_t advertised_channel_ids[RDP_GCC_MAX_SERVER_CHANNELS];
    uint8_t advertised_channel_joined[RDP_GCC_MAX_SERVER_CHANNELS];
    uint8_t dynamic_channels_ready;
    uint8_t multitransport_negotiated;
    uint8_t multitransport_udp_active;
    uint8_t multitransport_udp2_active;
    uint8_t multitransport_udp_window_started;
    uint8_t multitransport_udp_fallback_tcp;
    uint16_t multitransport_udp_receive_window;
    uint32_t multitransport_udp_next_receive_sequence;
    uint32_t multitransport_udp_last_receive_sequence;
    uint8_t multitransport_udp2_window_started;
    uint8_t multitransport_udp2_fallback_tcp;
    uint8_t multitransport_udp2_log_window_size;
    uint16_t multitransport_udp2_next_receive_sequence;
    uint16_t multitransport_udp2_last_receive_sequence;
    uint16_t multitransport_udp2_last_peer_ack_sequence;
    uint32_t multitransport_flags;
    uint32_t graphics_next_frame_id;
    uint32_t graphics_last_sent_frame_id;
    uint32_t graphics_last_ack_frame_id;
    uint32_t graphics_total_acked_frames;
    uint32_t graphics_pending_frames;
    uint32_t graphics_frame_queue_limit;
    uint32_t graphics_open_frame_id;
    uint8_t graphics_frame_open;
    rdp_server_dynamic_channel dynamic_channels[RDP_SERVER_MAX_DYNAMIC_CHANNELS];
    uint32_t redirected_device_count;
    rdp_server_redirected_device redirected_devices[RDP_SERVER_MAX_REDIRECTED_DEVICES];
    uint8_t confirm_active_seen;
    uint8_t licensing_done;
    uint8_t client_info_seen;
    uint8_t synchronize_seen;
    uint8_t control_seen;
    uint8_t font_list_seen;
    uint8_t updates_suppressed;
    uint8_t surface_repaint_pending;
    uint8_t clipboard_monitor_ready_sent;
    uint8_t clipboard_monitor_ready_received;
    uint8_t clipboard_capabilities_sent;
    uint8_t clipboard_capabilities_received;
    uint8_t clipboard_formats_sent;
    uint8_t clipboard_formats_accepted;
    uint8_t clipboard_pending_format;
    uint8_t clipboard_pending_file;
    uint8_t clipboard_locked;
    uint32_t clipboard_format_count;
    uint32_t clipboard_pending_format_id;
    uint32_t clipboard_pending_file_stream_id;
    uint32_t clipboard_locked_clip_data_id;
    uint32_t clipboard_reconnect_generation;
    librdp_server_extension_state extension_states[RDP_SERVER_EXTENSION_FAMILY_COUNT];
    uint8_t* framebuffer;
    size_t framebuffer_len;
    size_t framebuffer_stride;
    librdp_server_input_callback input_callback;
    void* input_callback_user_data;
    librdp_server_channel_callback channel_callback;
    void* channel_callback_user_data;
    librdp_server_dynamic_channel_accept_callback dynamic_channel_accept_callback;
    void* dynamic_channel_accept_user_data;
    librdp_server_extension_callback extension_callback;
    void* extension_callback_user_data;
    librdp_server_extension_callback extension_family_callbacks[RDP_SERVER_EXTENSION_FAMILY_COUNT];
    void* extension_family_user_data[RDP_SERVER_EXTENSION_FAMILY_COUNT];
    librdp_server_event_callback event_callback;
    void* event_callback_user_data;
    librdp_server_status last_status;
    librdp_server_metrics metrics;
    rdp_buffer input;
};

#endif
