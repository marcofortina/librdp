/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client session object lifecycle and teardown.
 * Invariants: creation initializes every owned subsystem before exposure; teardown clears sensitive state, closes transports, resets channels, and emits terminal events in a stable order.
 * Ownership: this module owns allocation/free of librdp_session and coordinates release of session-owned surfaces, caches, buffers, backends, and security contexts.
 * Threading: public lifecycle APIs honor the session owner-thread contract except cancel, which may wake the owner thread from another thread.
 * Trust boundary: disconnect and free never trust partially negotiated server state; every remote-derived handle is invalidated before callback-visible state changes.
 */

#include "client/session_internal.h"
#include "common/trace.h"
#include "protocol/x224.h"

#include <openssl/crypto.h>

#include <limits.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/*
 * Start the bounded interval between Client Info completion and Demand Active.
 * The absolute monotonic deadline is shared by run_once and external poll-loop
 * timeout queries so both dispatch styles enforce the same activation policy.
 */
librdp_status rdp_session_activation_deadline_start(librdp_session* session)
{
    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_transport_deadline_create(RDP_SESSION_HANDSHAKE_TIMEOUT_MS,
                                         &session->activation_deadline_ns);
}

/*
 * Return the remaining activation interval rounded up to milliseconds. A
 * negative result means no activation deadline applies; expired distinguishes
 * a real deadline from that disabled state.
 */
int rdp_session_activation_timeout_ms(const librdp_session* session,
                                      int* expired)
{
    uint64_t now_ns = 0u;
    uint64_t remaining_ns = 0u;
    uint64_t remaining_ms = 0u;

    if (expired)
        *expired = 0;
    if (!session || session->state != LIBRDP_SESSION_CONNECTED ||
        session->activation_deadline_ns == 0u)
        return -1;
    now_ns = rdp_session_monotonic_ns();
    if (now_ns == 0u || now_ns >= session->activation_deadline_ns)
    {
        if (expired)
            *expired = 1;
        return 0;
    }
    remaining_ns = session->activation_deadline_ns - now_ns;
    remaining_ms = (remaining_ns + 999999u) / 1000000u;
    return remaining_ms > (uint64_t)INT_MAX ? INT_MAX : (int)remaining_ms;
}

void rdp_session_activation_deadline_clear(librdp_session* session)
{
    if (session)
        session->activation_deadline_ns = 0u;
}

void rdp_session_composited_reset(librdp_session* session)
{
    if (!session)
        return;
    session->composited_channel_id = 0;
    session->composited_channel_id_bytes = 0;
    session->composited_ready = 0;
    session->composited_connection_open = 0;
    session->composited_connection_id = 0;
    session->composited_open_channel_id = 0;
    rdp_composited_render_tree_reset(&session->composited_tree);
}

void rdp_session_auth_redirection_channel_reset(librdp_session* session)
{
    if (!session)
        return;
    session->auth_redirection_channel_id = 0;
    session->auth_redirection_channel_id_bytes = 0;
    session->auth_redirection_ready = 0;
}

void rdp_session_webauthn_channel_reset(librdp_session* session)
{
    if (!session)
        return;
    session->webauthn_channel_id = 0;
    session->webauthn_channel_id_bytes = 0;
    session->webauthn_ready = 0;
}

void rdp_session_credssp_security_reset(librdp_session* session)
{
    if (!session)
        return;
    OPENSSL_cleanse(&session->credssp_security, sizeof(session->credssp_security));
    session->credssp_security_ready = 0;
}

/*
 * Construct all session-owned protocol, backend, synchronization, and graphics
 * state. Initialization failures unwind in reverse ownership order before the
 * partially constructed session can become observable.
 */
librdp_session* librdp_session_new(const librdp_settings* settings)
{
    librdp_session* session = NULL;
    const librdp_limits* limits = NULL;

    if (!settings)
        return NULL;

    session = (librdp_session*)calloc(1, sizeof(*session));
    if (!session)
        return NULL;
    session->wakeup_pipe[0] = -1;
    session->wakeup_pipe[1] = -1;
    atomic_init(&session->cancel_requested, 0u);

    session->settings = librdp_settings_clone(settings);
    if (!session->settings)
    {
        free(session);
        return NULL;
    }
    limits = rdp_settings_limits_internal(session->settings);
    if (!limits || librdp_metrics_init(&session->metrics) != LIBRDP_STATUS_OK ||
        librdp_multitransport_metrics_init(
            &session->multitransport_metrics) != LIBRDP_STATUS_OK ||
        librdp_echo_stats_init(&session->echo_stats) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }
    session->limits = *limits;
    if (rdp_session_wakeup_init(session) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }
    if (librdp_settings_width(session->settings) > session->limits.surface_max_dimension ||
        librdp_settings_height(session->settings) > session->limits.surface_max_dimension)
    {
        rdp_session_wakeup_close(session);
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }

    session->surface = librdp_surface_new(librdp_settings_width(session->settings),
                                          librdp_settings_height(session->settings),
                                          LIBRDP_PIXEL_FORMAT_BGRA32);
    if (!session->surface)
    {
        rdp_session_wakeup_close(session);
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }

    session->state = LIBRDP_SESSION_IDLE;
    session->lifecycle = LIBRDP_LIFECYCLE_NEW;
    rdp_license_client_state_init(&session->license_state);
    if (pthread_mutex_init(&session->owner_mutex, NULL) != 0)
    {
        rdp_session_wakeup_close(session);
        librdp_surface_free(session->surface);
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }
    if (pthread_mutex_init(&session->transport_cancel_mutex, NULL) != 0)
    {
        pthread_mutex_destroy(&session->owner_mutex);
        rdp_session_wakeup_close(session);
        librdp_surface_free(session->surface);
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }
    if (rdp_session_redirection_init(session) != LIBRDP_STATUS_OK)
    {
        pthread_mutex_destroy(&session->transport_cancel_mutex);
        pthread_mutex_destroy(&session->owner_mutex);
        rdp_session_wakeup_close(session);
        librdp_surface_free(session->surface);
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }
    session->gdi_current_surface_id = RDP_SESSION_GDI_SCREEN_BITMAP_SURFACE;
    session->requested_desktop_width = librdp_settings_width(session->settings);
    session->requested_desktop_height = librdp_settings_height(session->settings);
    rdp_transport_init(&session->transport);
    session->audio_output_udp_fd = -1;
    rdp_buffer_init(&session->audio_output_fragment);
    rdp_buffer_init(&session->audio_output_pending_data);
    rdp_buffer_init(&session->audio_output_udp_data);
    rdp_buffer_init(&session->device_redirection_fragment);
    rdp_buffer_init(&session->remote_programs_fragment);
    rdp_buffer_init(&session->echo_pending_payload);
    rdp_buffer_init(&session->fastpath_fragment);
    rdp_buffer_init(&session->fastpath_decompressed);
    rdp_buffer_init(&session->slowpath_decompressed);
    rdp_buffer_init(&session->gdi_stream_bitmap.bitmap_data);
    rdp_gdi_render_state_init(&session->gdi_render);
    rdp_graphics_decompressor_init(&session->graphics_decompressor);
    rdp_graphics_decompressor_init(&session->bulk_rdp8_decompressor);
    rdp_bulk_decompressor_init(&session->bulk_decompressor);
    rdp_clearcodec_context_init(&session->clearcodec);
    rdp_nscodec_context_init(&session->surface_nscodec);
    rdp_composited_render_tree_init(&session->composited_tree);
    rdp_session_redirected_files_clear(session);
    rdp_session_drive_roots_clear(session);
    rdp_printer_backend_init_cups(&session->printer_backend);
    rdp_printer_backend_set_notify(&session->printer_backend,
                                   rdp_session_printer_backend_notify,
                                   session);
    session->next_dynamic_channel_id = 1;
#ifdef RDP_HAVE_PCSC
    rdp_smartcard_backend_init_pcsc(&session->smartcard_backend);
#endif
    session->avc = rdp_avc_decoder_new();
    if (!session->avc)
    {
        rdp_session_redirection_clear(session);
        rdp_printer_backend_clear(&session->printer_backend);
#ifdef RDP_HAVE_PCSC
        rdp_smartcard_backend_clear(&session->smartcard_backend);
#endif
        rdp_nscodec_context_free(&session->surface_nscodec);
        rdp_clearcodec_context_free(&session->clearcodec);
        rdp_bulk_decompressor_free(&session->bulk_decompressor);
        rdp_graphics_decompressor_free(&session->bulk_rdp8_decompressor);
        rdp_graphics_decompressor_free(&session->graphics_decompressor);
        rdp_session_transport_close(session);
        rdp_session_wakeup_close(session);
        pthread_mutex_destroy(&session->transport_cancel_mutex);
        pthread_mutex_destroy(&session->owner_mutex);
        librdp_surface_free(session->surface);
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }
    rdp_trace_event(RDP_TRACE_CLIENT, "client.session.new", "width=%u height=%u",
                    librdp_settings_width(session->settings),
                    librdp_settings_height(session->settings));
    return session;
}

librdp_settings* rdp_session_settings_mut(librdp_session* session)
{
    return session ? session->settings : NULL;
}

void librdp_session_free(librdp_session* session)
{
    if (!session)
        return;
    (void)librdp_session_disconnect(session);
    rdp_session_smartcard_reset(session);
#ifdef RDP_HAVE_PCSC
    rdp_smartcard_backend_clear(&session->smartcard_backend);
#endif
    rdp_session_printer_reset(session);
    rdp_printer_backend_clear(&session->printer_backend);
    rdp_session_usb_redirection_reset(session);
    rdp_session_composited_reset(session);
    rdp_session_video_redirection_reset(session);
    rdp_session_video_optimized_reset(session);
    rdp_session_video_capture_reset(session);
    rdp_session_auth_redirection_channel_reset(session);
    rdp_session_webauthn_channel_reset(session);
    rdp_session_multiparty_reset(session);
    rdp_session_credssp_security_reset(session);
    rdp_session_redirected_files_clear(session);
    rdp_session_drive_roots_clear(session);
    rdp_session_dynamic_channels_clear(session);
    rdp_session_static_channels_clear(session);
    rdp_session_clipboard_clear(session);
    rdp_session_clipboard_local_clear(session);
    rdp_session_audio_output_udp_close(session);
    rdp_buffer_free(&session->audio_output_fragment);
    rdp_buffer_free(&session->audio_output_pending_data);
    rdp_buffer_free(&session->audio_output_udp_data);
    rdp_buffer_free(&session->device_redirection_fragment);
    rdp_buffer_free(&session->pnp_redirection_fragment);
    rdp_buffer_free(&session->pnp_redirection_storage);
    rdp_buffer_free(&session->remote_programs_fragment);
    rdp_buffer_free(&session->echo_pending_payload);
    rdp_buffer_free(&session->fastpath_fragment);
    rdp_buffer_free(&session->fastpath_decompressed);
    rdp_buffer_free(&session->slowpath_decompressed);
    rdp_session_graphics_surfaces_clear(session);
    rdp_session_graphics_cache_clear(session);
    rdp_session_gdi_color_table_cache_clear(session);
    rdp_session_gdi_brush_cache_clear(session);
    rdp_session_gdi_ninegrid_cache_clear(session);
    rdp_session_gdi_glyph_cache_clear(session);
    rdp_session_gdi_glyph_fragment_cache_clear(session);
    rdp_session_gdi_bitmap_cache_clear(session);
    rdp_session_gdi_saved_bitmaps_clear(session);
    rdp_session_gdi_offscreen_cache_clear(session);
    rdp_session_gdi_stream_bitmap_reset(session);
    rdp_session_gdi_gdiplus_reset(session);
    rdp_session_gdi_window_state_reset(session);
    rdp_session_pointer_cache_clear(session);
    rdp_avc_decoder_free(session->avc);
    rdp_nscodec_context_free(&session->surface_nscodec);
    rdp_clearcodec_context_free(&session->clearcodec);
    rdp_bulk_decompressor_free(&session->bulk_decompressor);
    rdp_graphics_decompressor_free(&session->bulk_rdp8_decompressor);
    rdp_graphics_decompressor_free(&session->graphics_decompressor);
    rdp_security_standard_clear(&session->standard_security);
    rdp_session_redirection_clear(session);
    rdp_license_crypto_context_clear(&session->license_crypto);
    rdp_session_transport_close(session);
    rdp_session_wakeup_close(session);
    rdp_session_trace_policy_clear(session);
    librdp_surface_free(session->surface);
    librdp_settings_free(session->settings);
    pthread_mutex_destroy(&session->transport_cancel_mutex);
    pthread_mutex_destroy(&session->owner_mutex);
    free(session);
}

librdp_status librdp_session_cancel(librdp_session* session)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    atomic_store_explicit(&session->cancel_requested, 1u, memory_order_release);
    status = rdp_session_wakeup_signal(session);
    rdp_session_transport_cancel_interrupt(session);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT, "client.cancel.requested", "state=%d", (int)session->state);
    return status;
}

/*
 * Tear down an active or partially connected session. Transport, channels,
 * backends, caches, surfaces, and sensitive buffers are released in an order
 * that prevents callbacks from observing freed state.
 */
librdp_status rdp_session_disconnect_inner(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state == LIBRDP_SESSION_CLOSED || session->state == LIBRDP_SESSION_IDLE ||
        session->state == LIBRDP_SESSION_CANCELLED)
        return LIBRDP_STATUS_OK;

    atomic_store_explicit(&session->cancel_requested, 0u, memory_order_release);
    rdp_session_wakeup_drain(session);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.disconnect.start", "state=%d", (int)session->state);
    rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_DISCONNECTING);
    rdp_session_set_state(session, LIBRDP_SESSION_CLOSING);
    rdp_session_graphics_dirty_reset(session);
    session->reactivating = 0u;
    session->server_refresh_rect_supported = 0u;
    session->server_suppress_output_supported = 0u;
    session->output_suppressed = 0u;
    session->output_suppression_known = 0u;
    rdp_session_transport_close(session);
    rdp_session_audio_output_udp_close(session);
    rdp_security_standard_clear(&session->standard_security);
    session->standard_security_active = 0;
    session->selected_protocol = RDP_X224_PROTOCOL_STANDARD;
    rdp_license_crypto_context_clear(&session->license_crypto);
    session->clipboard_channel_id = 0;
    rdp_session_clipboard_clear(session);
    session->audio_output_channel_id = 0;
    session->audio_output_ready = 0;
    session->audio_output_fragmenting = 0;
    session->audio_output_pending_wave = 0;
    session->audio_output_udp_active = 0;
    session->audio_output_udp_block_no = 0;
    session->audio_output_udp_peer_valid = 0;
    session->audio_output_crypt_seed_valid = 0;
    session->audio_output_udp_fd = -1;
    session->audio_output_udp_port = 0;
    session->audio_output_fragment_expected = 0;
    session->audio_output_server_version = 0;
    session->audio_output_client_version = 0;
    session->audio_output_pending_format_no = 0;
    session->audio_output_pending_timestamp = 0;
    session->audio_output_pending_expected_len = 0;
    session->audio_output_pending_block_no = 0;
    session->audio_output_udp_next_fragment_no = 0;
    session->audio_output_udp_peer_len = 0;
    session->audio_output_selected_format_count = 0;
    memset(session->audio_output_selected_formats, 0, sizeof(session->audio_output_selected_formats));
    memset(&session->audio_output_udp_peer, 0, sizeof(session->audio_output_udp_peer));
    memset(session->audio_output_crypt_seed, 0, sizeof(session->audio_output_crypt_seed));
    rdp_buffer_free(&session->audio_output_fragment);
    rdp_buffer_init(&session->audio_output_fragment);
    rdp_buffer_free(&session->audio_output_pending_data);
    rdp_buffer_init(&session->audio_output_pending_data);
    rdp_buffer_free(&session->audio_output_udp_data);
    rdp_buffer_init(&session->audio_output_udp_data);
    session->device_redirection_channel_id = 0;
    session->device_redirection_ready = 0;
    session->device_redirection_fragmenting = 0;
    session->device_redirection_version_minor = 0;
    session->device_redirection_client_id = 0;
    session->device_redirection_fragment_expected = 0;
    rdp_buffer_free(&session->device_redirection_fragment);
    rdp_buffer_init(&session->device_redirection_fragment);
    session->pnp_redirection_channel_id = 0;
    session->pnp_redirection_ready = 0;
    session->pnp_redirection_fragmenting = 0;
    session->pnp_redirection_io_version = 0;
    session->pnp_redirection_devices_sent = 0;
    session->pnp_redirection_open_device_active = 0;
    session->pnp_redirection_open_device_id = 0;
    session->pnp_redirection_storage_active = 0;
    session->pnp_redirection_storage_device_id = 0;
    session->pnp_redirection_fragment_expected = 0;
    rdp_buffer_free(&session->pnp_redirection_fragment);
    rdp_buffer_init(&session->pnp_redirection_fragment);
    rdp_buffer_free(&session->pnp_redirection_storage);
    rdp_buffer_init(&session->pnp_redirection_storage);
    session->remote_programs_channel_id = 0;
    session->remote_programs_ready = 0;
    session->remote_programs_fragmenting = 0;
    session->remote_programs_exec_sent = 0;
    session->remote_programs_fragment_expected = 0;
    rdp_buffer_free(&session->remote_programs_fragment);
    rdp_buffer_init(&session->remote_programs_fragment);
    rdp_session_echo_clear_pending(session);
    rdp_session_multiparty_reset(session);
    session->core_input_channel_id = 0;
    session->core_input_channel_id_bytes = 0;
    session->core_input_ready = 0;
    session->input_channel_id = 0;
    session->input_channel_id_bytes = 0;
    session->input_channel_ready = 0;
    session->input_channel_suspended = 0;
    session->input_channel_protocol_version = 0;
    session->input_channel_supported_features = 0;
    session->input_channel_max_touch_contacts = 0;
    session->input_channel_supports_pen = 0;
    session->display_control_channel_id = 0;
    session->display_control_channel_id_bytes = 0;
    session->display_control_ready = 0;
    session->sent_desktop_width = 0;
    session->sent_desktop_height = 0;
    memset(&session->display_control_caps, 0, sizeof(session->display_control_caps));
    session->graphics_channel_id = 0;
    session->graphics_channel_id_bytes = 0;
    session->graphics_ready = 0;
    session->graphics_selected_version = 0;
    session->graphics_selected_flags = 0;
    session->graphics_frames_decoded = 0;
    session->mouse_cursor_channel_id = 0;
    session->mouse_cursor_channel_id_bytes = 0;
    session->mouse_cursor_ready = 0;
    session->audio_input_channel_id = 0;
    session->audio_input_channel_id_bytes = 0;
    session->audio_input_ready = 0;
    session->audio_input_open = 0;
    session->audio_input_open_reply_sent = 0;
    session->audio_input_version = 0;
    session->audio_input_selected_format_count = 0;
    memset(session->audio_input_selected_formats, 0, sizeof(session->audio_input_selected_formats));
    rdp_session_multitransport_reset(session, 0);
    rdp_session_composited_reset(session);
    rdp_session_video_redirection_reset(session);
    rdp_session_video_optimized_reset(session);
    rdp_session_video_capture_reset(session);
    rdp_session_webauthn_channel_reset(session);
    rdp_session_usb_redirection_reset(session);
    rdp_graphics_decompressor_reset(&session->graphics_decompressor);
    rdp_graphics_decompressor_reset(&session->bulk_rdp8_decompressor);
    rdp_bulk_decompressor_reset(&session->bulk_decompressor);
    session->slowpath_decompressed.length = 0;
    rdp_clearcodec_context_reset(&session->clearcodec);
    rdp_nscodec_context_reset(&session->surface_nscodec);
    rdp_session_graphics_surfaces_clear(session);
    rdp_session_graphics_cache_clear(session);
    rdp_session_gdi_color_table_cache_clear(session);
    rdp_session_gdi_brush_cache_clear(session);
    rdp_session_gdi_ninegrid_cache_clear(session);
    rdp_session_gdi_glyph_cache_clear(session);
    rdp_session_gdi_glyph_fragment_cache_clear(session);
    rdp_session_gdi_bitmap_cache_clear(session);
    rdp_session_gdi_saved_bitmaps_clear(session);
    rdp_session_gdi_offscreen_cache_clear(session);
    rdp_session_gdi_stream_bitmap_reset(session);
    rdp_session_gdi_gdiplus_reset(session);
    rdp_session_gdi_window_state_reset(session);
    rdp_session_pointer_cache_clear(session);
    rdp_session_palette_reset(session);
    rdp_session_dynamic_channels_clear(session);
    rdp_session_static_channels_clear(session);
    rdp_session_printer_reset(session);
    rdp_session_redirected_files_clear(session);
    rdp_session_drive_roots_clear(session);
    rdp_session_smartcard_reset(session);
    rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_DISCONNECTED);
    rdp_session_set_state(session, LIBRDP_SESSION_CLOSED);

    event.type = LIBRDP_EVENT_DISCONNECTED;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.disconnect.done", "status=ok");
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_disconnect(librdp_session* session)
{
    rdp_trace_session_scope trace_scope;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return rdp_session_disconnect_inner(session);
    status = rdp_session_require_owner(session, "client.disconnect.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_session_trace_scope_begin(session, &trace_scope);
    status = rdp_session_disconnect_inner(session);
    rdp_session_redirection_clear(session);
    rdp_session_trace_scope_end(session, &trace_scope);
    return status;
}

librdp_session_state librdp_session_get_state(const librdp_session* session)
{
    return session ? session->state : LIBRDP_SESSION_FAILED;
}

librdp_session_lifecycle librdp_session_get_lifecycle(const librdp_session* session)
{
    return session ? session->lifecycle : LIBRDP_LIFECYCLE_FAILED;
}
