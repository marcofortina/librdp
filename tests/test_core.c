/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: focused client core test runner.
 * Coverage: preserves aggregate ordering and dispatches independently named
 * common, settings, feature, channel, storage, graphics, reactivation,
 * licensing, and enterprise suites.
 * Bug classes: group selection and aggregate coverage omissions.
 * Determinism: all delegated suites are self-contained or loopback-only.
 */

#include "test_core_suites.h"

#include <stdio.h>
#include <string.h>

static int run_settings(void)
{
    if (test_reconnect_policy() != 0 || test_connect_cancellation() != 0 ||
        test_reconnect_success() != 0)
        return 1;
    return test_settings_surface_input_session();
}

static int run_timeouts(void)
{
    return test_connect_timeout();
}

static int run_resolution(void)
{
    return test_resolution_failure();
}

static int run_activation_timeout(void)
{
    return test_activation_timeout();
}

static int run_idle_eof(void)
{
    return test_idle_transport_eof();
}

static int run_features(void)
{
    if (test_optional_feature_runtime_paths() != 0 ||
        test_video_geometry_runtime_lifecycle() != 0 ||
        test_feature_runtime_gates() != 0)
        return 1;
    return test_client_feature_status_reason_contract();
}

static int run_channels(void)
{
    if (test_static_channels() != 0 || test_clipboard_unmatched_responses() != 0)
        return 1;
    if (test_dynamic_channel_duplicate_create() != 0 ||
        test_dynamic_channel_close_pending_fragment() != 0 ||
        test_dynamic_channel_empty_continuation() != 0 ||
        test_dynamic_channel_nested_data_first() != 0 ||
        test_dynamic_channel_empty_compressed_fragments() != 0 ||
        test_dynamic_channel_soft_sync_runtime() != 0)
        return 1;
    if (test_echo_channel_auto_response() != 0 || test_echo_channel_client_ping() != 0 ||
        test_echo_channel_client_timeout() != 0 || test_echo_channel_client_late_response() != 0)
        return 1;
    if (test_display_control_caps_reject_pending_layout() != 0 ||
        test_display_control_dvc_rejects_unrequested_feature() != 0 ||
        test_display_control_accept_pending_and_resize() != 0 ||
        test_display_control_resize_frame_stability() != 0 ||
        test_display_control_monitor_fields_and_unavailable() != 0 ||
        test_dynamic_channel_data_before_create() != 0 ||
        test_dynamic_channel_public_fragment_send() != 0 ||
        test_server_redirection_state() != 0)
        return 1;
    if (test_webauthn_feature_status_channel_lifecycle() != 0 ||
        test_webauthn_dvc_rejects_unrequested_feature() != 0 ||
        test_webauthn_rp_id_allowlist_denies_unmatched_request() != 0)
        return 1;
    return test_auth_redirection_dvc_requires_credssp();
}

static int run_storage(void)
{
    if (test_core_devices() != 0 || test_filesystem_information_class_coverage() != 0)
        return 1;
    return test_printer_file_backend_job_lifecycle();
}

static int run_graphics(void)
{
    if (test_pointer_cache_lifecycle() != 0 ||
        test_gdiplus_object_table_solid_brush_and_pen() != 0 ||
        test_gdiplus_known_record_families_render_visuals() != 0 ||
        test_gdiplus_compressed_images_render_pixels() != 0 ||
        test_gdiplus_compressed_image_pixel_contract() != 0 ||
        test_gdiplus_image_failure_accounting() != 0 ||
        test_gdiplus_graphics_state_affects_rendering() != 0 ||
        test_gdiplus_complex_brushes_sample_pixels() != 0 ||
        test_gdiplus_interpolation_and_metadata_objects() != 0 ||
        test_gdiplus_antialias_affects_line_edges() != 0 ||
        test_gdiplus_clip_limits_visual_output() != 0 ||
        test_gdi_bitmap_cache_limits() != 0 ||
        test_gdi_bitmap_cache_eviction() != 0 ||
        test_gdi_cache_lifecycle() != 0 ||
        test_gdi_orders_runtime_golden() != 0 ||
        test_gdi_altsec_runtime_orders() != 0 ||
        test_composited_runtime_lifecycle() != 0 ||
        test_rail_runtime_lifecycle() != 0)
        return 1;
    return test_graphics_update_before_activation();
}

static int run_gdiplus_native(void)
{
    return test_gdiplus_native_backend();
}

static int run_licensing(void)
{
    if (test_licensing_new_before_activation() != 0 ||
        test_licensing_valid_client_alert_before_activation() != 0 ||
        test_licensing_request_before_activation() != 0 ||
        test_licensing_challenge_before_activation() != 0 ||
        test_licensing_reconnect() != 0)
        return 1;
    return test_licensing_error_alert();
}

static int run_enterprise(void)
{
    if (test_workspace_lifecycle() != 0 || test_admin_lifecycle() != 0)
        return 1;
#ifdef RDP_HAVE_LIBXML2
    if (test_workspace_xml_parse() != 0 || test_admin_sessions_xml_parse() != 0)
        return 1;
#endif
#if defined(RDP_HAVE_CURL) && defined(RDP_HAVE_LIBXML2)
    if (test_workspace_fetch_http() != 0 || test_admin_query_winrm_http() != 0 ||
        test_admin_action_winrm_http() != 0)
        return 1;
#endif
    return 0;
}

static int run_workspace_smoke(void)
{
#if defined(RDP_HAVE_CURL) && defined(RDP_HAVE_LIBXML2)
    return test_workspace_fetch_http();
#else
    return 77;
#endif
}

static int run_admin_smoke(void)
{
#if defined(RDP_HAVE_CURL) && defined(RDP_HAVE_LIBXML2)
    if (test_admin_query_winrm_http() != 0)
        return 1;
    return test_admin_action_winrm_http();
#else
    return 77;
#endif
}

int test_common(void)
{
    if (test_trace() != 0 || test_buffer_stream() != 0 || test_charset() != 0)
        return 1;
    return test_pointer_decode();
}

int test_client_core_named(const char* name)
{
    if (!name)
        return 2;
    if (strcmp(name, "settings") == 0)
        return run_settings();
    if (strcmp(name, "timeouts") == 0)
        return run_timeouts();
    if (strcmp(name, "resolution") == 0)
        return run_resolution();
    if (strcmp(name, "activation-timeout") == 0)
        return run_activation_timeout();
    if (strcmp(name, "idle-eof") == 0)
        return run_idle_eof();
    if (strcmp(name, "features") == 0)
        return run_features();
    if (strcmp(name, "video-geometry-smoke") == 0)
        return test_video_geometry_runtime_lifecycle();
    if (strcmp(name, "channels") == 0)
        return run_channels();
    if (strcmp(name, "display-resize-smoke") == 0)
        return test_display_control_resize_frame_stability();
    if (strcmp(name, "display-layout-smoke") == 0)
        return test_display_control_monitor_fields_and_unavailable();
    if (strcmp(name, "storage") == 0)
        return run_storage();
    if (strcmp(name, "graphics") == 0)
        return run_graphics();
    if (strcmp(name, "gdi-orders-smoke") == 0)
        return test_gdi_orders_runtime_golden();
    if (strcmp(name, "gdi-cache-smoke") == 0)
        return test_gdi_cache_lifecycle();
    if (strcmp(name, "gdi-cache-eviction") == 0)
        return test_gdi_bitmap_cache_eviction();
    if (strcmp(name, "pointer-cache-smoke") == 0)
        return test_pointer_cache_lifecycle();
    if (strcmp(name, "composition-cr2-smoke") == 0)
        return test_composited_runtime_lifecycle();
    if (strcmp(name, "rail-runtime-smoke") == 0)
        return test_rail_runtime_lifecycle();
    if (strcmp(name, "gdiplus-native-smoke") == 0)
        return run_gdiplus_native();
    if (strcmp(name, "reactivation") == 0)
        return test_activation_epoch_reset();
    if (strcmp(name, "licensing") == 0)
        return run_licensing();
    if (strcmp(name, "enterprise") == 0)
        return run_enterprise();
    if (strcmp(name, "smoke-workspace") == 0)
        return run_workspace_smoke();
    if (strcmp(name, "smoke-admin") == 0)
        return run_admin_smoke();
    fprintf(stderr, "unknown client core test group: %s\n", name);
    return 2;
}

int test_client_core(void)
{
    if (test_core_devices() != 0)
        return 1;
    if (test_static_channels() != 0 || test_clipboard_unmatched_responses() != 0)
        return 1;
    if (test_reconnect_policy() != 0 || test_connect_cancellation() != 0 ||
        test_reconnect_success() != 0)
        return 1;
    if (test_dynamic_channel_duplicate_create() != 0 ||
        test_dynamic_channel_close_pending_fragment() != 0 ||
        test_dynamic_channel_empty_continuation() != 0 ||
        test_dynamic_channel_nested_data_first() != 0 ||
        test_dynamic_channel_empty_compressed_fragments() != 0 ||
        test_dynamic_channel_soft_sync_runtime() != 0)
        return 1;
    if (test_optional_feature_runtime_paths() != 0 ||
        test_video_geometry_runtime_lifecycle() != 0 ||
        test_feature_runtime_gates() != 0 ||
        test_client_feature_status_reason_contract() != 0)
        return 1;
    if (test_echo_channel_auto_response() != 0 || test_echo_channel_client_ping() != 0 ||
        test_echo_channel_client_timeout() != 0 || test_echo_channel_client_late_response() != 0)
        return 1;
    if (test_display_control_caps_reject_pending_layout() != 0 ||
        test_display_control_dvc_rejects_unrequested_feature() != 0 ||
        test_display_control_accept_pending_and_resize() != 0 ||
        test_display_control_resize_frame_stability() != 0 ||
        test_display_control_monitor_fields_and_unavailable() != 0 ||
        test_dynamic_channel_data_before_create() != 0 ||
        test_dynamic_channel_public_fragment_send() != 0 ||
        test_server_redirection_state() != 0 ||
        test_webauthn_feature_status_channel_lifecycle() != 0 ||
        test_webauthn_dvc_rejects_unrequested_feature() != 0 ||
        test_webauthn_rp_id_allowlist_denies_unmatched_request() != 0 ||
        test_auth_redirection_dvc_requires_credssp() != 0)
        return 1;
    if (test_filesystem_information_class_coverage() != 0 ||
        test_printer_file_backend_job_lifecycle() != 0)
        return 1;
    if (run_graphics() != 0 || test_activation_epoch_reset() != 0 ||
        run_licensing() != 0 || run_enterprise() != 0)
        return 1;
    return test_settings_surface_input_session();
}
