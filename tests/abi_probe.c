/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: public ABI layout probe.
 * Coverage: emits machine-readable size and alignment values for public
 * value types and opaque handle pointer representations.
 * Bug classes: accidental public struct layout changes, enum size changes,
 * and callback handle ABI drift.
 * Determinism: output depends only on the local C ABI and public headers.
 */

#include <librdp/librdp.h>

#include <stdio.h>
#include <stddef.h>

#define ABI_TYPE_ENTRY(name, type, suffix)                                                                             \
    printf("    {\"name\":\"%s\",\"size\":%zu,\"align\":%zu}%s\n",                                                  \
           (name),                                                                                                     \
           sizeof(type),                                                                                               \
           (size_t)_Alignof(type),                                                                                     \
           (suffix))

int main(void)
{
    printf("{\n");
    printf("  \"abi\": {\"pointer_size\":%zu,\"long_size\":%zu,\"size_t_size\":%zu},\n",
           sizeof(void*),
           sizeof(long),
           sizeof(size_t));
    printf("  \"types\": [\n");
    ABI_TYPE_ENTRY("librdp_admin_ptr", librdp_admin*, ",");
    ABI_TYPE_ENTRY("librdp_admin_transport", librdp_admin_transport, ",");
    ABI_TYPE_ENTRY("librdp_admin_action_type", librdp_admin_action_type, ",");
    ABI_TYPE_ENTRY("librdp_admin_config", librdp_admin_config, ",");
    ABI_TYPE_ENTRY("librdp_admin_session", librdp_admin_session, ",");
    ABI_TYPE_ENTRY("librdp_admin_action", librdp_admin_action, ",");
    ABI_TYPE_ENTRY("librdp_session_ptr", librdp_session*, ",");
    ABI_TYPE_ENTRY("librdp_client_ptr", librdp_client*, ",");
    ABI_TYPE_ENTRY("librdp_client_config", librdp_client_config, ",");
    ABI_TYPE_ENTRY("librdp_server_ptr", librdp_server*, ",");
    ABI_TYPE_ENTRY("librdp_server_config", librdp_server_config, ",");
    ABI_TYPE_ENTRY("librdp_settings_ptr", librdp_settings*, ",");
    ABI_TYPE_ENTRY("librdp_surface_ptr", librdp_surface*, ",");
    ABI_TYPE_ENTRY("librdp_event_callback", librdp_event_callback, ",");
    ABI_TYPE_ENTRY("librdp_trace_level", librdp_trace_level, ",");
    ABI_TYPE_ENTRY("librdp_trace_sink", librdp_trace_sink, ",");
    ABI_TYPE_ENTRY("librdp_trace_callback", librdp_trace_callback, ",");
    ABI_TYPE_ENTRY("librdp_trace_record", librdp_trace_record, ",");
    ABI_TYPE_ENTRY("librdp_trace_policy", librdp_trace_policy, ",");
    ABI_TYPE_ENTRY("librdp_status", librdp_status, ",");
    ABI_TYPE_ENTRY("librdp_error_ptr", librdp_error*, ",");
    ABI_TYPE_ENTRY("librdp_error_component", librdp_error_component, ",");
    ABI_TYPE_ENTRY("librdp_error_info", librdp_error_info, ",");
    ABI_TYPE_ENTRY("librdp_security_mode", librdp_security_mode, ",");
    ABI_TYPE_ENTRY("librdp_tls_policy_mode", librdp_tls_policy_mode, ",");
    ABI_TYPE_ENTRY("librdp_tls_certificate_decision", librdp_tls_certificate_decision, ",");
    ABI_TYPE_ENTRY("librdp_tls_certificate_callback", librdp_tls_certificate_callback, ",");
    ABI_TYPE_ENTRY("librdp_tls_certificate_info", librdp_tls_certificate_info, ",");
    ABI_TYPE_ENTRY("librdp_tls_policy", librdp_tls_policy, ",");
    ABI_TYPE_ENTRY("librdp_credentials", librdp_credentials, ",");
    ABI_TYPE_ENTRY("librdp_credentials_provider", librdp_credentials_provider, ",");
    ABI_TYPE_ENTRY("librdp_gateway_mode", librdp_gateway_mode, ",");
    ABI_TYPE_ENTRY("librdp_gateway_config", librdp_gateway_config, ",");
    ABI_TYPE_ENTRY("librdp_workspace_ptr", librdp_workspace*, ",");
    ABI_TYPE_ENTRY("librdp_workspace_resource_type", librdp_workspace_resource_type, ",");
    ABI_TYPE_ENTRY("librdp_workspace_config", librdp_workspace_config, ",");
    ABI_TYPE_ENTRY("librdp_workspace_resource", librdp_workspace_resource, ",");
    ABI_TYPE_ENTRY("librdp_drive_policy", librdp_drive_policy, ",");
    ABI_TYPE_ENTRY("librdp_usb_selector_mode", librdp_usb_selector_mode, ",");
    ABI_TYPE_ENTRY("librdp_usb_policy", librdp_usb_policy, ",");
    ABI_TYPE_ENTRY("librdp_limits", librdp_limits, ",");
    ABI_TYPE_ENTRY("librdp_feature", librdp_feature, ",");
    ABI_TYPE_ENTRY("librdp_feature_unavailable_reason", librdp_feature_unavailable_reason, ",");
    ABI_TYPE_ENTRY("librdp_feature_status", librdp_feature_status, ",");
    ABI_TYPE_ENTRY("librdp_session_state", librdp_session_state, ",");
    ABI_TYPE_ENTRY("librdp_session_lifecycle", librdp_session_lifecycle, ",");
    ABI_TYPE_ENTRY("librdp_metrics", librdp_metrics, ",");
    ABI_TYPE_ENTRY("librdp_echo_stats", librdp_echo_stats, ",");
    ABI_TYPE_ENTRY("librdp_reconnect_policy", librdp_reconnect_policy, ",");
    ABI_TYPE_ENTRY("librdp_graphics_update_type", librdp_graphics_update_type, ",");
    ABI_TYPE_ENTRY("librdp_graphics_update", librdp_graphics_update, ",");
    ABI_TYPE_ENTRY("librdp_graphics_update_callback", librdp_graphics_update_callback, ",");
    ABI_TYPE_ENTRY("librdp_display_monitor", librdp_display_monitor, ",");
    ABI_TYPE_ENTRY("librdp_pixel_format", librdp_pixel_format, ",");
    ABI_TYPE_ENTRY("librdp_surface_access", librdp_surface_access, ",");
    ABI_TYPE_ENTRY("librdp_surface_mapping", librdp_surface_mapping, ",");
    ABI_TYPE_ENTRY("librdp_channel_id", librdp_channel_id, ",");
    ABI_TYPE_ENTRY("librdp_channel_handle", librdp_channel_handle, ",");
    ABI_TYPE_ENTRY("librdp_channel_priority", librdp_channel_priority, ",");
    ABI_TYPE_ENTRY("librdp_channel_info", librdp_channel_info, ",");
    ABI_TYPE_ENTRY("librdp_channel_send_options", librdp_channel_send_options, ",");
    ABI_TYPE_ENTRY("librdp_static_channel_info", librdp_static_channel_info, ",");
    ABI_TYPE_ENTRY("librdp_event_envelope", librdp_event_envelope, ",");
    ABI_TYPE_ENTRY("librdp_event_envelope_callback", librdp_event_envelope_callback, ",");
    ABI_TYPE_ENTRY("librdp_domain_event_callback", librdp_domain_event_callback, ",");
    ABI_TYPE_ENTRY("librdp_audio_format", librdp_audio_format, ",");
    ABI_TYPE_ENTRY("librdp_video_capture_media", librdp_video_capture_media, ",");
    ABI_TYPE_ENTRY("librdp_clipboard_format", librdp_clipboard_format, ",");
    ABI_TYPE_ENTRY("librdp_clipboard_file", librdp_clipboard_file, ",");
    ABI_TYPE_ENTRY("librdp_key_state", librdp_key_state, ",");
    ABI_TYPE_ENTRY("librdp_mouse_button", librdp_mouse_button, ",");
    ABI_TYPE_ENTRY("librdp_mouse_state", librdp_mouse_state, ",");
    ABI_TYPE_ENTRY("librdp_key_event", librdp_key_event, ",");
    ABI_TYPE_ENTRY("librdp_mouse_event", librdp_mouse_event, ",");
    ABI_TYPE_ENTRY("librdp_touch_contact", librdp_touch_contact, ",");
    ABI_TYPE_ENTRY("librdp_touch_frame", librdp_touch_frame, ",");
    ABI_TYPE_ENTRY("librdp_pen_contact", librdp_pen_contact, ",");
    ABI_TYPE_ENTRY("librdp_pen_frame", librdp_pen_frame, ",");
    ABI_TYPE_ENTRY("librdp_event_type", librdp_event_type, ",");
    ABI_TYPE_ENTRY("librdp_pointer_update_type", librdp_pointer_update_type, ",");
    ABI_TYPE_ENTRY("librdp_rect", librdp_rect, ",");
    ABI_TYPE_ENTRY("librdp_pointer_event", librdp_pointer_event, ",");
    ABI_TYPE_ENTRY("librdp_clipboard_formats_event", librdp_clipboard_formats_event, ",");
    ABI_TYPE_ENTRY("librdp_clipboard_data_event", librdp_clipboard_data_event, ",");
    ABI_TYPE_ENTRY("librdp_clipboard_request_event", librdp_clipboard_request_event, ",");
    ABI_TYPE_ENTRY("librdp_clipboard_file_contents_event", librdp_clipboard_file_contents_event, ",");
    ABI_TYPE_ENTRY("librdp_channel_open_event", librdp_channel_open_event, ",");
    ABI_TYPE_ENTRY("librdp_channel_data_event", librdp_channel_data_event, ",");
    ABI_TYPE_ENTRY("librdp_channel_close_event", librdp_channel_close_event, ",");
    ABI_TYPE_ENTRY("librdp_audio_output_formats_event", librdp_audio_output_formats_event, ",");
    ABI_TYPE_ENTRY("librdp_audio_output_data_event", librdp_audio_output_data_event, ",");
    ABI_TYPE_ENTRY("librdp_audio_input_formats_event", librdp_audio_input_formats_event, ",");
    ABI_TYPE_ENTRY("librdp_audio_input_open_event", librdp_audio_input_open_event, ",");
    ABI_TYPE_ENTRY("librdp_video_capture_open_event", librdp_video_capture_open_event, ",");
    ABI_TYPE_ENTRY("librdp_video_capture_sample_request_event", librdp_video_capture_sample_request_event, ",");
    ABI_TYPE_ENTRY("librdp_video_capture_close_event", librdp_video_capture_close_event, ",");
    ABI_TYPE_ENTRY("librdp_echo_result_event", librdp_echo_result_event, ",");
    ABI_TYPE_ENTRY("librdp_event", librdp_event, "");
    printf("  ]\n");
    printf("}\n");
    return 0;
}
