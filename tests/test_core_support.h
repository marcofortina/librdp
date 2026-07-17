/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared fixtures and contracts for focused client core tests.
 * Coverage: synthetic handshake transport, callbacks, event captures, and
 * protocol writers reused across independent core suites.
 * Bug classes: fixture lifetime, partial I/O, state ordering, and cleanup.
 * Determinism: network fixtures bind loopback only and use ephemeral ports.
 */

#ifndef LIBRDP_TEST_CORE_SUPPORT_H
#define LIBRDP_TEST_CORE_SUPPORT_H

#include <librdp/librdp.h>

#include "common/buffer.h"
#include "common/charset.h"
#include "common/stream.h"
#include "common/trace.h"
#include "client/session_filesystem.h"
#include "client/session_internal.h"
#include "client/settings_internal.h"
#include "clipboard/clipboard.h"
#include "channels/device_redirection.h"
#include "channels/display_control.h"
#include "channels/dynamic_channel.h"
#include "channels/echo_channel.h"
#include "channels/filesystem_redirection.h"
#include "channels/multiparty.h"
#include "channels/printer_redirection.h"
#include "channels/telemetry.h"
#include "channels/virtual_channel.h"
#include "channels/video_redirection.h"
#include "channels/webauthn_channel.h"
#include "graphics/gdi_backend.h"
#include "graphics/gdi_orders.h"
#include "input/input.h"
#include "licensing/licensing.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/pointer.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "transport/udp_transport.h"
#include "security/security.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expr)                                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

#define DVC_SCENARIO_NORMAL 0
#define DVC_SCENARIO_DUPLICATE_CREATE 1
#define DVC_SCENARIO_CLOSE_PENDING_FRAGMENT 2
#define DVC_SCENARIO_DATA_BEFORE_CREATE 3
#define DVC_SCENARIO_EMPTY_CONTINUATION 4
#define DVC_SCENARIO_NESTED_DATA_FIRST 5
#define DVC_SCENARIO_WEBAUTHN_CREATE_CLOSE 6
#define DVC_SCENARIO_EMPTY_COMPRESSED_FIRST 7
#define DVC_SCENARIO_EMPTY_COMPRESSED_CONTINUATION 8
#define DVC_SCENARIO_SOFT_SYNC_TUNNEL_REQUEST 9
#define DVC_SCENARIO_DISPLAY_CONTROL_CAPS_REJECT_LAYOUT 10
#define DVC_SCENARIO_ECHO_VALIDATE 11
#define DVC_SCENARIO_CLIENT_FRAGMENT_SEND 12
#define DVC_SCENARIO_DISPLAY_CONTROL_ACCEPT_LAYOUT 13
#define DVC_SCENARIO_ECHO_PING 14
#define DVC_SCENARIO_RDPDR_PRINTER_JOB 15
#define DVC_SCENARIO_ECHO_TIMEOUT 16
#define DVC_SCENARIO_ECHO_LATE_RESPONSE 17
#define DVC_SCENARIO_WEBAUTHN_CREATE_REJECT 18
#define DVC_SCENARIO_AUTH_REDIRECTION_CREATE_REJECT 19
#define DVC_SCENARIO_DISPLAY_CONTROL_CREATE_REJECT 20
#define DVC_SCENARIO_WEBAUTHN_RP_ID_DENIED 21
#define DVC_SCENARIO_TELEMETRY_RUNTIME 22
#define DVC_SCENARIO_MULTIPARTY_RUNTIME 23
#define DVC_SCENARIO_GEOMETRY_TRACKING_RUNTIME 24

#define GDI_SCENARIO_NORMAL 0
#define GDI_SCENARIO_ALTSEC_RUNTIME 1
#define GDI_SCENARIO_UPDATE_BEFORE_ACTIVATION 2
#define GDI_SCENARIO_DESKTOP_COMPOSITION 3

#define LICENSE_SCENARIO_NONE 0
#define LICENSE_SCENARIO_NEW 1
#define LICENSE_SCENARIO_REQUEST 2
#define LICENSE_SCENARIO_VALID_CLIENT_ALERT 3

#define CLIPBOARD_SCENARIO_NONE 0
#define CLIPBOARD_SCENARIO_UNMATCHED_RESPONSES 1

typedef struct event_counter
{
    int states;
    int surfaces;
    int keys;
    int mouse;
    int pointer;
    int clipboard_formats;
    int clipboard_data;
    int clipboard_requests;
    int clipboard_file_contents;
    int channel_open;
    int channel_data;
    int channel_close;
    librdp_channel_id last_channel_id;
    size_t last_channel_data_len;
    char last_channel_data[32];
    int audio_output_formats;
    int audio_output_data;
    int audio_output_close;
    int audio_input_formats;
    int audio_input_open;
    int video_capture_open;
    int video_capture_sample_request;
    int video_capture_close;
    int echo_result;
    int echo_ok;
    int echo_timed_out;
    uint64_t echo_sequence;
    uint64_t echo_rtt_us;
    int disconnected;
} event_counter;

typedef struct event_envelope_capture
{
    int count;
    int state;
    int surface;
    int disconnected;
    int invalid;
} event_envelope_capture;

typedef struct domain_event_capture
{
    int graphics;
    int pointer;
    int channel;
    int clipboard;
    int audio;
    int video;
    int reentrant_metrics;
    int invalid;
} domain_event_capture;

typedef struct graphics_update_capture
{
    int pixel_rect;
    int desktop_resize;
    int surface_create;
    int surface_destroy;
    int frame_begin;
    int frame_end;
    int borrowed_pixels;
    int invalid;
} graphics_update_capture;

typedef struct trace_capture
{
    uint64_t count;
    uint64_t last_sequence;
    int saw_connect_start;
    int saw_protocol;
    int saw_ids;
    int saw_line;
} trace_capture;

typedef struct secure_string_capture
{
    uint32_t calls;
    uint32_t failed;
    size_t last_length;
} secure_string_capture;

typedef struct credentials_provider_capture
{
    uint32_t calls;
    uint32_t fail;
    char username[32];
    char password[32];
    char domain[32];
} credentials_provider_capture;

typedef struct cancel_thread_capture
{
    librdp_session* session;
    unsigned delay_ms;
    librdp_status status;
} cancel_thread_capture;

typedef struct owner_thread_capture
{
    librdp_session* session;
    librdp_status status;
} owner_thread_capture;

extern const uint8_t core_test_server_random[32];
extern const librdp_feature core_test_all_features[19];
extern const uint8_t core_test_server_certificate[];
extern const size_t core_test_server_certificate_len;

void on_event(librdp_session* session, const librdp_event* event, void* user_data);

void on_event_envelope(librdp_session* session, const librdp_event_envelope* envelope, void* user_data);

void on_domain_event(librdp_session* session, const librdp_event_envelope* envelope, void* user_data);

void on_graphics_update(librdp_session* session, const librdp_graphics_update* update, void* user_data);

void* cancel_thread_main(void* user_data);

void* owner_thread_main(void* user_data);

void on_trace(librdp_session* session, const librdp_trace_record* record, void* user_data);

void on_secure_string_cleanse(const void* data, size_t length, void* user_data);

void test_sleep_ms(uint32_t timeout_ms);

void test_core_fill_secret(char* output, size_t output_len, uint32_t seed);

librdp_status on_credentials_provider(librdp_credentials* credentials, void* user_data);

librdp_tls_certificate_decision core_tls_certificate_callback(const librdp_tls_certificate_info* certificate,
                                                                    void* user_data);

int capture_stderr(void (*fn)(void), char* out, size_t out_len);

int read_exact_fd(int fd, void* data, size_t length);

int build_device_redirection_server_capabilities(rdp_buffer* out);

int write_device_static_packet_fd(int fd, const rdp_buffer* payload, uint16_t channel_id);

int read_client_device_announce_fd(int fd, uint8_t* input, size_t capacity, uint16_t channel_id);

int read_client_device_name_fd(int fd, uint8_t* input, size_t capacity, uint16_t channel_id);

int read_client_device_capabilities_fd(int fd, uint8_t* input, size_t capacity, uint16_t channel_id);

int read_client_printer_device_id_fd(int fd,
                                            uint8_t* input,
                                            size_t capacity,
                                            uint16_t channel_id,
                                            uint32_t* device_id);

int read_client_printer_create_response_fd(int fd,
                                                  uint8_t* input,
                                                  size_t capacity,
                                                  uint16_t channel_id,
                                                  uint32_t expected_device_id,
                                                  uint32_t expected_completion_id,
                                                  uint32_t* file_id);

int read_client_printer_write_response_fd(int fd,
                                                 uint8_t* input,
                                                 size_t capacity,
                                                 uint16_t channel_id,
                                                 uint32_t expected_device_id,
                                                 uint32_t expected_completion_id,
                                                 uint32_t expected_written,
                                                 int expect_success);

int read_client_printer_read_response_fd(int fd,
                                                uint8_t* input,
                                                size_t capacity,
                                                uint16_t channel_id,
                                                uint32_t expected_device_id,
                                                uint32_t expected_completion_id,
                                                const uint8_t* expected,
                                                uint32_t expected_len);

int read_client_printer_query_response_fd(int fd,
                                                 uint8_t* input,
                                                 size_t capacity,
                                                 uint16_t channel_id,
                                                 uint32_t expected_device_id,
                                                 uint32_t expected_completion_id);

int read_client_device_completion_fd(int fd,
                                            uint8_t* input,
                                            size_t capacity,
                                            uint16_t channel_id,
                                            uint32_t expected_device_id,
                                            uint32_t expected_completion_id);

int read_client_printer_close_response_fd(int fd,
                                                 uint8_t* input,
                                                 size_t capacity,
                                                 uint16_t channel_id,
                                                 uint32_t expected_device_id,
                                                 uint32_t expected_completion_id);

int run_printer_job_server_scenario(int fd, uint8_t* input, size_t capacity);

int reserve_closed_loopback_port(uint16_t* port);

int start_handshake_server_full(uint16_t* port,
                                       pid_t* child_pid,
                                       int encrypted,
                                       uint32_t error_info,
                                       int extra_static_channel,
                                       int client_dynamic_channel_open_response,
                                       int connection_count,
                                       int dynamic_channel_scenario,
                                       int gdi_scenario,
                                       int license_scenario,
                                       int clipboard_scenario);

int start_handshake_server_multi(uint16_t* port,
                                        pid_t* child_pid,
                                        int encrypted,
                                        uint32_t error_info,
                                        int extra_static_channel,
                                        int client_dynamic_channel_open_response,
                                        int connection_count,
                                        int dynamic_channel_scenario,
                                        int license_scenario,
                                        int clipboard_scenario);

int start_handshake_server_ex(uint16_t* port,
                                     pid_t* child_pid,
                                     int encrypted,
                                     uint32_t error_info,
                                     int extra_static_channel,
                                     int client_dynamic_channel_open_response);

int start_handshake_server(uint16_t* port, pid_t* child_pid, int encrypted, uint32_t error_info);

int test_standard_security_available(void);

int test_static_channels(void);

int test_clipboard_unmatched_responses(void);

int test_trace(void);

int test_buffer_stream(void);

int test_charset(void);

int test_pointer_decode(void);

int test_settings_surface_input_session(void);

int test_reconnect_policy(void);

int test_reconnect_success(void);

int test_dynamic_channel_duplicate_create(void);

int test_dynamic_channel_close_pending_fragment(void);

int test_dynamic_channel_empty_continuation(void);

int test_dynamic_channel_nested_data_first(void);

int test_dynamic_channel_empty_compressed_fragments(void);

int test_dynamic_channel_soft_sync_runtime(void);

int test_optional_feature_runtime_paths(void);

int test_feature_runtime_gates(void);

int test_client_feature_status_reason_contract(void);

int test_echo_channel_auto_response(void);

int test_echo_channel_client_ping(void);

int test_echo_channel_client_timeout(void);

int test_echo_channel_client_late_response(void);

int test_display_control_caps_reject_pending_layout(void);

int test_display_control_dvc_rejects_unrequested_feature(void);

int test_display_control_accept_pending_and_resize(void);

int test_dynamic_channel_data_before_create(void);

int test_dynamic_channel_public_fragment_send(void);

int test_webauthn_feature_status_channel_lifecycle(void);

int test_webauthn_dvc_rejects_unrequested_feature(void);

int test_webauthn_rp_id_allowlist_denies_unmatched_request(void);

int test_auth_redirection_dvc_requires_credssp(void);

int test_printer_file_backend_job_lifecycle(void);

int test_filesystem_information_class_coverage(void);

int test_gdiplus_object_table_solid_brush_and_pen(void);

int test_gdiplus_known_record_families_render_visuals(void);

int test_gdiplus_compressed_images_render_pixels(void);

int test_gdiplus_image_failure_accounting(void);

int test_gdiplus_graphics_state_affects_rendering(void);

int test_gdiplus_complex_brushes_sample_pixels(void);

int test_gdiplus_interpolation_and_metadata_objects(void);

int test_gdiplus_antialias_affects_line_edges(void);

int test_gdiplus_clip_limits_visual_output(void);

int test_gdi_altsec_runtime_orders(void);

int test_graphics_update_before_activation(void);

int test_licensing_new_before_activation(void);

int test_licensing_valid_client_alert_before_activation(void);

int test_licensing_request_before_activation(void);

int test_workspace_lifecycle(void);

int test_workspace_xml_parse(void);

int test_workspace_fetch_http(void);

int test_admin_lifecycle(void);

int test_admin_sessions_xml_parse(void);

int test_admin_query_winrm_http(void);

int test_admin_action_winrm_http(void);

#endif
