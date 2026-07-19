/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal session runtime contracts.
 * Invariants: owner-thread checks, event dispatch, wakeups, trace scope, and
 * metrics remain centralized across all session domains.
 * Ownership: callbacks and trace resources are session-owned; emitted payloads
 * are borrowed for the duration of the callback.
 * Threading: only wakeup/cancel-adjacent helpers may be used across threads;
 * other helpers require the session owner thread.
 * Trust boundary: runtime diagnostics must stay redacted and must not expose
 * wire payloads beyond validated extents.
 */

#ifndef RDP_CLIENT_SESSION_RUNTIME_H
#define RDP_CLIENT_SESSION_RUNTIME_H

#include <librdp/session.h>

#include "common/buffer.h"
#include "common/trace.h"

#include <stdint.h>

librdp_status rdp_session_require_owner(librdp_session* session, const char* phase);
librdp_status rdp_session_require_owner_const(const librdp_session* session, const char* phase);
librdp_status rdp_session_bind_owner(librdp_session* session, const char* phase);
void rdp_session_emit(librdp_session* session, const librdp_event* event);
void rdp_session_emit_graphics_update(librdp_session* session,
                                      librdp_graphics_update_type type,
                                      uint32_t surface_id,
                                      uint32_t frame_id,
                                      const librdp_rect* rect,
                                      librdp_pixel_format format,
                                      const uint8_t* pixels,
                                      size_t stride);
void rdp_session_emit_graphics_frame(librdp_session* session, librdp_graphics_update_type type, uint32_t frame_id);
void rdp_session_emit_graphics_pixel_rect(librdp_session* session, uint32_t x, uint32_t y, uint32_t width, uint32_t height);
void rdp_session_metric_add(uint64_t* counter, uint64_t value);
librdp_status rdp_session_limit_rejected(librdp_session* session);
librdp_status rdp_session_utf8_to_utf16le(const char* text, rdp_buffer* out, uint8_t append_null);
int rdp_session_multitransport_runtime_supported(void);
void rdp_session_wakeup_close(librdp_session* session);
librdp_status rdp_session_wakeup_init(librdp_session* session);
void rdp_session_wakeup_drain(librdp_session* session);
librdp_status rdp_session_wakeup_signal(librdp_session* session);
void rdp_session_transport_cancel_arm(librdp_session* session);
void rdp_session_transport_cancel_interrupt(librdp_session* session);
void rdp_session_transport_close(librdp_session* session);
void rdp_session_trace_policy_clear(librdp_session* session);
void rdp_session_trace_scope_begin(librdp_session* session, rdp_trace_session_scope* scope);
void rdp_session_trace_scope_end(const librdp_session* session);
void rdp_session_set_state(librdp_session* session, librdp_session_state state);
void rdp_session_set_lifecycle(librdp_session* session, librdp_session_lifecycle lifecycle);
void rdp_session_set_last_error(librdp_session* session,
                                librdp_status status,
                                int system_error,
                                librdp_error_component component,
                                const char* phase,
                                const char* message);
librdp_status rdp_session_fail(librdp_session* session, librdp_status status);
librdp_status rdp_session_finish_cancel(librdp_session* session);
uint64_t rdp_session_monotonic_ns(void);
uint8_t rdp_session_feature_ready_for_negotiation(const librdp_session* session, librdp_feature feature);

#endif
