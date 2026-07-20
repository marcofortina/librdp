/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: focused client core test suite entry points.
 * Coverage: public common, settings, feature, channel, storage, graphics,
 * licensing, and enterprise API behavior.
 * Bug classes: suite omissions and cross-domain regression isolation.
 * Determinism: suites use synthetic vectors and loopback fixtures only.
 */

#ifndef LIBRDP_TEST_CORE_SUITES_H
#define LIBRDP_TEST_CORE_SUITES_H

int test_core_devices(void);
int test_static_channels(void);
int test_clipboard_unmatched_responses(void);
int test_trace(void);
int test_buffer_stream(void);
int test_charset(void);
int test_pointer_decode(void);
int test_settings_surface_input_session(void);
int test_reconnect_policy(void);
int test_connect_cancellation(void);
int test_connect_timeout(void);
int test_resolution_failure(void);
int test_activation_timeout(void);
int test_idle_transport_eof(void);
int test_reconnect_success(void);
int test_dynamic_channel_duplicate_create(void);
int test_dynamic_channel_close_pending_fragment(void);
int test_dynamic_channel_empty_continuation(void);
int test_dynamic_channel_nested_data_first(void);
int test_dynamic_channel_empty_compressed_fragments(void);
int test_dynamic_channel_soft_sync_runtime(void);
int test_optional_feature_runtime_paths(void);
int test_video_geometry_runtime_lifecycle(void);
int test_feature_runtime_gates(void);
int test_client_feature_status_reason_contract(void);
int test_echo_channel_auto_response(void);
int test_echo_channel_client_ping(void);
int test_echo_channel_client_timeout(void);
int test_echo_channel_client_late_response(void);
int test_display_control_caps_reject_pending_layout(void);
int test_display_control_dvc_rejects_unrequested_feature(void);
int test_display_control_accept_pending_and_resize(void);
int test_display_control_resize_frame_stability(void);
int test_display_control_monitor_fields_and_unavailable(void);
int test_dynamic_channel_data_before_create(void);
int test_dynamic_channel_public_fragment_send(void);
int test_dynamic_channel_public_open_priorities(void);
int test_server_redirection_state(void);
int test_webauthn_feature_status_channel_lifecycle(void);
int test_webauthn_dvc_rejects_unrequested_feature(void);
int test_webauthn_rp_id_allowlist_denies_unmatched_request(void);
int test_auth_redirection_dvc_requires_credssp(void);
int test_printer_file_backend_job_lifecycle(void);
int test_filesystem_information_class_coverage(void);
int test_gdiplus_object_table_solid_brush_and_pen(void);
int test_gdiplus_known_record_families_render_visuals(void);
int test_gdiplus_compressed_images_render_pixels(void);
int test_gdiplus_compressed_image_pixel_contract(void);
int test_gdiplus_image_failure_accounting(void);
int test_gdiplus_graphics_state_affects_rendering(void);
int test_gdiplus_complex_brushes_sample_pixels(void);
int test_gdiplus_interpolation_and_metadata_objects(void);
int test_gdiplus_antialias_affects_line_edges(void);
int test_gdiplus_clip_limits_visual_output(void);
int test_gdiplus_native_backend(void);
int test_gdi_bitmap_cache_limits(void);
int test_gdi_bitmap_cache_eviction(void);
int test_gdi_cache_lifecycle(void);
int test_gdi_altsec_runtime_orders(void);
int test_composited_runtime_lifecycle(void);
int test_rail_runtime_lifecycle(void);
int test_gdi_orders_runtime_golden(void);
int test_graphics_update_before_activation(void);
int test_pointer_cache_lifecycle(void);
int test_activation_epoch_reset(void);
int test_licensing_new_before_activation(void);
int test_licensing_valid_client_alert_before_activation(void);
int test_licensing_request_before_activation(void);
int test_licensing_challenge_before_activation(void);
int test_licensing_reconnect(void);
int test_licensing_error_alert(void);
int test_workspace_lifecycle(void);
int test_workspace_xml_parse(void);
int test_workspace_fetch_http(void);
int test_admin_lifecycle(void);
int test_admin_sessions_xml_parse(void);
int test_admin_query_winrm_http(void);
int test_admin_action_winrm_http(void);

int test_common(void);
int test_client_core(void);
int test_client_core_named(const char* name);

#endif
