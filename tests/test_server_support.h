/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared fixtures and contracts for server tests.
 * Coverage: loopback transport, TLS/NLA helpers, protocol writers, callbacks,
 * and deterministic credential generation used by focused server suites.
 * Bug classes: fixture lifetime, partial I/O, malformed framing, and cleanup.
 * Determinism: all network traffic remains on loopback and uses ephemeral ports.
 */

#ifndef LIBRDP_TEST_SERVER_SUPPORT_H
#define LIBRDP_TEST_SERVER_SUPPORT_H

#include <librdp/librdp.h>

#include "common/buffer.h"
#include "channels/audio_input.h"
#include "channels/audio_output.h"
#include "channels/auth_redirection.h"
#include "channels/composited_remoting.h"
#include "channels/core_input.h"
#include "channels/device_redirection.h"
#include "channels/desktop_composition.h"
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
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"
#include "transport/udp_transport.h"

#include <openssl/ssl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define SCHECK(condition) \
    do \
    { \
        if (!(condition)) \
        { \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            return 1; \
        } \
    } while (0)

#define SERVER_TEST_ALL_FEATURE_COUNT 19u

extern const librdp_feature server_test_all_features[SERVER_TEST_ALL_FEATURE_COUNT];

typedef struct test_server_nla_provider_context
{
    const char* domain;
    const char* username;
    const char* password;
    const char* workstation;
    uint32_t calls;
    uint32_t last_version;
    uint32_t last_failed_attempts;
    uint8_t last_public_key_bound;
    int reject;
} test_server_nla_provider_context;

enum
{
    TEST_SERVER_NLA_BAD_TS_VERSION = 1u << 0,
    TEST_SERVER_NLA_PROVIDER_REJECT = 1u << 1,
    TEST_SERVER_NLA_WRONG_PASSWORD = 1u << 2,
    TEST_SERVER_NLA_TAMPER_PUBLIC_KEY = 1u << 3,
    TEST_SERVER_NLA_TRUNCATED_CREDENTIALS = 1u << 4,
    TEST_SERVER_NLA_COMBINED_PUBLIC_KEY = 1u << 5
};

typedef struct test_server_runtime_context
{
    uint32_t input_count;
    uint32_t synchronize_count;
    uint32_t control_count;
    uint32_t font_list_count;
    uint32_t key_count;
    uint32_t channel_count;
    uint32_t dynamic_open_count;
    uint32_t dynamic_data_count;
    uint32_t dynamic_close_count;
    uint32_t dynamic_accept_count;
    uint32_t dynamic_reject_count;
    uint32_t extension_count;
    uint32_t state_event_count;
    uint32_t error_event_count;
    uint32_t surface_event_count;
    uint32_t channel_joined_event_count;
    librdp_server_peer_state last_old_state;
    librdp_server_peer_state last_new_state;
    librdp_status last_error_status;
    librdp_server_extension_family last_extension_family;
    librdp_feature last_extension_feature;
    uint32_t last_extension_message_type;
    uint32_t last_extension_flags;
    uint16_t last_channel_id;
    uint32_t last_dynamic_channel_id;
    uint32_t accepted_dynamic_channel_id;
    uint32_t rejected_dynamic_channel_id;
    uint8_t channel_payload[16];
    size_t channel_payload_len;
} test_server_runtime_context;

typedef enum test_server_security_tamper
{
    TEST_SERVER_SECURITY_TAMPER_NONE,
    TEST_SERVER_SECURITY_TAMPER_SIGNATURE,
    TEST_SERVER_SECURITY_TAMPER_CIPHERTEXT,
} test_server_security_tamper;

int server_test_feature_reason_is_current(const librdp_feature_status* status);

int test_server_connect_loopback(uint16_t port);

int test_server_set_nonblocking(int fd);

int test_server_copy_file(const char* source_path, const char* target_path);

int test_server_make_tls_files(char* cert_path,
                               size_t cert_path_len,
                               char* key_path,
                               size_t key_path_len);

int test_server_make_tls_files_for_host(char* cert_path,
                                        size_t cert_path_len,
                                        char* key_path,
                                        size_t key_path_len,
                                        const char* host);

int test_server_make_tls_files_with_policy(char* cert_path,
                                           size_t cert_path_len,
                                           char* key_path,
                                           size_t key_path_len,
                                           unsigned int key_bits,
                                           long not_before_offset,
                                           long not_after_offset);

int test_server_read_response(int fd, uint8_t* response, size_t response_len);

int test_server_send_all(int fd, const uint8_t* data, size_t length);

int test_server_tls_write_all(SSL* tls, const uint8_t* data, size_t length);

int test_server_tls_read_tpkt(SSL* tls, uint8_t* data, size_t capacity);

int test_server_wait_peer_state(librdp_server_peer* peer, librdp_server_peer_state state);

int test_server_tls_read_credssp(SSL* tls, rdp_buffer* packet);

int test_server_tls_public_key(SSL* tls, rdp_buffer* public_key);

void test_server_fill_secret(char* output, size_t output_len, uint32_t seed);

librdp_status test_server_nla_provider(librdp_server_peer* peer,
                                              const librdp_server_credentials_request* request,
                                              librdp_credentials* credentials,
                                              void* user_data);

void test_server_input_callback(librdp_server_peer* peer,
                                       const librdp_server_input_event* event,
                                       void* user_data);

void test_server_channel_callback(librdp_server_peer* peer,
                                         const librdp_server_channel_event* event,
                                         void* user_data);

int test_server_dynamic_channel_accept_callback(librdp_server_peer* peer,
                                                       uint32_t dynamic_channel_id,
                                                       uint8_t priority,
                                                       const char* name,
                                                       size_t name_len,
                                                       void* user_data);

void test_server_extension_callback(librdp_server_peer* peer,
                                           const librdp_server_extension_event* event,
                                           void* user_data);

void test_server_event_callback(librdp_server_peer* peer,
                                       const librdp_server_event* event,
                                       void* user_data);

int test_server_build_client_mcs_connect_initial(rdp_buffer* tpkt);

int test_server_send_client_mcs_connect_initial(int fd);

int test_server_send_mcs_pdu(int fd, const rdp_buffer* mcs_pdu);

int test_server_append_mcs_tpkt(rdp_buffer* output, const rdp_buffer* mcs_pdu);

int test_server_send_channel_join(int fd, uint16_t user_id, uint16_t channel_id);

int test_server_send_confirm_active(
    int fd,
    uint32_t share_id,
    uint16_t user_id,
    rdp_standard_security_context* security);

int test_server_send_encrypted_slowpath(int fd,
                                               uint16_t user_id,
                                               rdp_standard_security_context* security,
                                               const rdp_buffer* slowpath,
                                               test_server_security_tamper tamper);

int test_server_send_encrypted_channel_payload(int fd,
                                                      uint16_t user_id,
                                                      uint16_t channel_id,
                                                      rdp_standard_security_context* security,
                                                      const rdp_buffer* payload);

int test_server_send_client_synchronize(
    int fd,
    uint32_t share_id,
    uint16_t user_id,
    rdp_standard_security_context* security);

int test_server_send_client_control(
    int fd,
    uint32_t share_id,
    uint16_t user_id,
    uint16_t action,
    rdp_standard_security_context* security);

int test_server_send_client_font_list(
    int fd,
    uint32_t share_id,
    uint16_t user_id,
    rdp_standard_security_context* security);

int test_server_send_keyboard_input(
    int fd,
    uint32_t share_id,
    uint16_t user_id,
    rdp_standard_security_context* security);

int test_server_send_sync_input(
    int fd,
    uint32_t share_id,
    uint16_t user_id,
    rdp_standard_security_context* security);

int test_server_send_static_channel_data(
    int fd,
    uint16_t user_id,
    uint16_t channel_id,
    rdp_standard_security_context* security);

int test_server_send_channel_payload(int fd, uint16_t user_id, uint16_t channel_id, const rdp_buffer* payload);

int test_server_read_tpkt_x224_data(int fd, uint8_t* buffer, size_t buffer_len, rdp_tpkt* tpkt);

int test_server_read_encrypted_mcs_payload(int fd,
                                                  uint8_t* response,
                                                  size_t response_len,
                                                  rdp_standard_security_context* security,
                                                  rdp_buffer* plaintext);

int test_server_read_encrypted_slowpath_data_pdu(int fd,
                                                        uint8_t* response,
                                                        size_t response_len,
                                                        rdp_standard_security_context* security,
                                                        rdp_buffer* plaintext,
                                                        rdp_slowpath_data_pdu* data_pdu);

int test_server_read_encrypted_static_channel_data(int fd,
                                                          uint8_t* response,
                                                          size_t response_len,
                                                          rdp_standard_security_context* security,
                                                          rdp_buffer* plaintext,
                                                          uint16_t* channel_id,
                                                          const uint8_t** data,
                                                          size_t* data_len);

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
                                                   size_t response_len);

int test_server_read_encrypted_dynamic_channel_payload(int fd,
                                                              uint8_t* response,
                                                              size_t response_len,
                                                              rdp_standard_security_context* security,
                                                              rdp_buffer* plaintext,
                                                              uint16_t static_channel_id,
                                                              uint32_t dynamic_channel_id,
                                                              rdp_dynamic_channel_data_pdu* data_response);

#endif
