/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_SESSION_H
#define LIBRDP_SESSION_H

#include <stdint.h>

#include <librdp/error.h>
#include <librdp/event.h>
#include <librdp/settings.h>
#include <librdp/surface.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup librdp_session Session API
 * @brief Client session lifecycle, loop, display, input, and surface access functions.
 * @{
 */

/**
 * @brief Opaque client session handle.
 *
 * The handle owns connection state, negotiated protocol state, graphics
 * surfaces, caches, channels, and transient security material. It is allocated
 * with librdp_session_new() and freed with librdp_session_free().
 *
 * @since 0.1.0
 */
typedef struct librdp_session librdp_session;

#define LIBRDP_DISPLAY_MONITOR_PRIMARY 0x00000001u /**< Monitor layout flag marking the primary monitor. */
#define LIBRDP_DISPLAY_MAX_MONITORS 16u            /**< Maximum monitor count accepted by display layout APIs. */

/**
 * @brief Public client session lifecycle state.
 *
 * State-change events report old and new values from this enum. Session APIs
 * that require a connected or active session return LIBRDP_STATUS_STATE when
 * called in an incompatible state.
 *
 * @since 0.1.0
 */
typedef enum librdp_session_state
{
    LIBRDP_SESSION_IDLE = 0,       /**< Session has not started a connection. */
    LIBRDP_SESSION_CONNECTING = 1, /**< Session is executing the connection sequence. */
    LIBRDP_SESSION_CONNECTED = 2,  /**< Session transport and initial protocol setup completed. */
    LIBRDP_SESSION_ACTIVE = 3,     /**< Session is activated and processing updates/input. */
    LIBRDP_SESSION_CLOSING = 4,    /**< Session is closing transport and channel state. */
    LIBRDP_SESSION_CLOSED = 5,     /**< Session closed cleanly or was explicitly disconnected. */
    LIBRDP_SESSION_FAILED = 6      /**< Session reached a terminal failure state. */
} librdp_session_state;

/**
 * @brief Monitor layout entry supplied to librdp_session_set_display_layout().
 *
 * The array passed to the API is copied during the call. Coordinates are in the
 * remote desktop coordinate space and must form a layout accepted by the
 * display-control channel.
 *
 * @since 0.1.0
 */
typedef struct librdp_display_monitor
{
    uint32_t flags;                /**< Bitmask of LIBRDP_DISPLAY_MONITOR_* values. */
    int32_t left;                  /**< Monitor left coordinate. */
    int32_t top;                   /**< Monitor top coordinate. */
    uint32_t width;                /**< Monitor width in pixels. */
    uint32_t height;               /**< Monitor height in pixels. */
    uint32_t physical_width;       /**< Physical monitor width in millimeters, or 0 when unknown. */
    uint32_t physical_height;      /**< Physical monitor height in millimeters, or 0 when unknown. */
    uint32_t orientation;          /**< Display orientation value sent on the display-control channel. */
    uint32_t desktop_scale_factor; /**< Desktop scale factor percentage. */
    uint32_t device_scale_factor;  /**< Device scale factor percentage. */
} librdp_display_monitor;

/**
 * @brief Session event callback.
 *
 * The callback runs synchronously on the thread that drives the session API
 * producing the event. session is the emitting session and event is valid only
 * until the callback returns. user_data is the pointer previously supplied to
 * librdp_session_set_event_callback().
 *
 * @since 0.1.0
 */
typedef void (*librdp_event_callback)(librdp_session* session, const librdp_event* event, void* user_data);

/**
 * @brief Create a client session from immutable settings.
 *
 * The settings object is cloned during construction; the caller keeps
 * ownership of the input settings and may free or modify it after this call.
 * The session starts in LIBRDP_SESSION_IDLE and owns its transport, protocol
 * state, caches, and primary surface.
 *
 * @param[in] settings Settings to clone; must not be NULL.
 *
 * @return Newly allocated session owned by the caller, or NULL when settings
 * is NULL, memory allocation fails, settings cannot be cloned, or the initial
 * surface cannot be allocated.
 *
 * @note Thread-safety: sessions are not internally synchronized. Create,
 * drive, and destroy a session from one serialized context unless the
 * application provides external locking.
 * @since 0.1.0
 */
librdp_session* librdp_session_new(const librdp_settings* settings);

/**
 * @brief Disconnect and free a session.
 *
 * Passing NULL is allowed and has no effect. For a non-NULL session this may
 * close transports, clear credentials and channel state, emit a disconnect
 * event through the configured callback, and release the session surface.
 *
 * @param[in,out] session Session to free, or NULL.
 *
 * @note Thread-safety: the caller must ensure no other thread is inside a
 * session API or callback for the same session.
 * @warning Any pointers previously returned from this session, including the
 * session surface and event payload pointers, become invalid.
 * @since 0.1.0
 */
void librdp_session_free(librdp_session* session);

/**
 * @brief Install or clear the event callback for a session.
 *
 * Events are emitted synchronously from the API call or session loop that
 * produces them. The callback pointer and user data are stored as-is; ownership
 * remains with the caller. Passing NULL as callback disables event delivery.
 * Event structures and payload pointers passed to the callback are valid only
 * until the callback returns unless a specific event API documents a longer
 * lifetime.
 *
 * @param[in,out] session Session to configure; NULL is ignored.
 * @param[in] callback Callback to install, or NULL to clear it.
 * @param[in] user_data Opaque pointer passed to callback; may be NULL.
 *
 * @note Thread-safety: changing the callback is not synchronized with event
 * emission. Configure it before driving the session, or serialize externally.
 * @warning Callback code must not retain event-owned pointers without copying
 * the pointed-to data.
 * @since 0.1.0
 */
void librdp_session_set_event_callback(librdp_session* session, librdp_event_callback callback, void* user_data);

/**
 * @brief Establish the initial RDP connection and send client setup PDUs.
 *
 * The session must be idle, closed, or failed and must have a configured
 * target. On success the session enters LIBRDP_SESSION_CONNECTED, emits state
 * and initial surface/pointer events, and is ready to be driven with
 * librdp_session_run_once().
 *
 * @param[in,out] session Session to connect; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * session or missing target; LIBRDP_STATUS_STATE when the current state cannot
 * start a connection; LIBRDP_STATUS_NO_MEMORY, LIBRDP_STATUS_IO_ERROR,
 * LIBRDP_STATUS_PROTOCOL_ERROR, LIBRDP_STATUS_UNSUPPORTED, or
 * LIBRDP_STATUS_CLOSED from transport, security, or protocol setup failures.
 *
 * @note Thread-safety: call from one serialized session-driving context.
 * @warning Credentials configured in settings are sent according to the
 * selected security mode; applications should avoid tracing or storing them.
 * @since 0.1.0
 */
librdp_status librdp_session_connect(librdp_session* session);

/**
 * @brief Drive one iteration of network and protocol processing.
 *
 * The session must be connected or active. On the first successful call after
 * connect, the state advances to LIBRDP_SESSION_ACTIVE. Incoming PDUs are
 * parsed, surfaces may be updated, and callbacks are emitted synchronously on
 * the calling thread. A poll timeout is treated as a successful idle iteration.
 *
 * @param[in,out] session Session to drive; must not be NULL.
 * @param[in] timeout_ms Maximum wait time in milliseconds; must be non-negative.
 *
 * @return LIBRDP_STATUS_OK when processing succeeds or no data arrives before
 * timeout; LIBRDP_STATUS_INVALID_ARGUMENT for NULL session or negative timeout;
 * LIBRDP_STATUS_STATE when the session is not connected or active;
 * LIBRDP_STATUS_IO_ERROR, LIBRDP_STATUS_PROTOCOL_ERROR, LIBRDP_STATUS_CLOSED,
 * LIBRDP_STATUS_UNSUPPORTED, or allocation errors from transport and protocol
 * processing.
 *
 * @note Thread-safety: callbacks run on the same thread that calls this
 * function. Do not call it concurrently for the same session.
 * @since 0.1.0
 */
librdp_status librdp_session_run_once(librdp_session* session, int timeout_ms);

/**
 * @brief Close the transport and reset negotiated session state.
 *
 * The call is idempotent for idle or already closed sessions. A successful
 * disconnect moves the session to LIBRDP_SESSION_CLOSED, clears channels,
 * caches, and transient protocol state, and emits a disconnect event.
 *
 * @param[in,out] session Session to disconnect; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success or when already idle/closed;
 * LIBRDP_STATUS_INVALID_ARGUMENT when session is NULL.
 *
 * @note Thread-safety: call from one serialized session-driving context.
 * @warning Any pending remote channel, clipboard, audio, video, or surface
 * state is discarded.
 * @since 0.1.0
 */
librdp_status librdp_session_disconnect(librdp_session* session);

/**
 * @brief Request a single-monitor desktop size.
 *
 * The requested size is stored locally. If the display-control channel is
 * ready, a layout update is sent immediately; otherwise the request remains
 * pending for later negotiation. The primary surface size changes only after
 * the server accepts and sends the corresponding updates.
 *
 * @param[in,out] session Session to update; must not be NULL.
 * @param[in] width Requested desktop width in pixels; must be 1..8192.
 * @param[in] height Requested desktop height in pixels; must be 1..8192.
 *
 * @return LIBRDP_STATUS_OK when the request is stored and, when possible, sent;
 * LIBRDP_STATUS_INVALID_ARGUMENT for NULL session or invalid dimensions;
 * transport or allocation errors propagated from the display-control send path.
 *
 * @note Thread-safety: call from one serialized session-driving context.
 * @since 0.1.0
 */
librdp_status librdp_session_resize(librdp_session* session, uint32_t width, uint32_t height);

/**
 * @brief Request an explicit monitor layout.
 *
 * The monitor array is validated and copied into the session. If the
 * display-control channel is ready, the layout is sent immediately; otherwise
 * it is kept as the requested layout for later use.
 *
 * @param[in,out] session Session to update; must not be NULL.
 * @param[in] monitors Monitor layout array; must not be NULL and must contain
 * monitor_count entries.
 * @param[in] monitor_count Number of monitors; must be 1..LIBRDP_DISPLAY_MAX_MONITORS.
 *
 * @return LIBRDP_STATUS_OK when the layout is accepted locally and, when
 * possible, sent; LIBRDP_STATUS_INVALID_ARGUMENT for NULL pointers, invalid
 * count, invalid monitor geometry, or invalid serialized layout; transport or
 * allocation errors propagated from the display-control send path.
 *
 * @note Thread-safety: call from one serialized session-driving context.
 * @since 0.1.0
 */
librdp_status librdp_session_set_display_layout(librdp_session* session,
                                                const librdp_display_monitor* monitors,
                                                uint32_t monitor_count);

/**
 * @brief Ask the server to refresh a rectangle.
 *
 * The session must be connected or active and have an established share ID.
 * Coordinates and dimensions must fit in the 16-bit refresh-rect wire fields.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] x Rectangle left coordinate.
 * @param[in] y Rectangle top coordinate.
 * @param[in] width Rectangle width; must be non-zero.
 * @param[in] height Rectangle height; must be non-zero.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid rectangle arguments; LIBRDP_STATUS_STATE when the session cannot
 * send a refresh request; allocation or transport errors propagated from the
 * send path.
 *
 * @note Thread-safety: call from one serialized session-driving context.
 * @since 0.1.0
 */
librdp_status librdp_session_refresh(librdp_session* session, uint32_t x, uint32_t y, uint32_t width, uint32_t height);

/**
 * @brief Send one keyboard input event.
 *
 * The session must be connected or active and have a share ID. Events may be
 * sent through the core-input dynamic channel when negotiated, or through the
 * slow-path input PDU otherwise. Unicode events must fit in one UTF-16 code
 * unit; non-Unicode scancodes must fit in one byte.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] event Keyboard event; must not be NULL and is copied during the
 * call.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid keyboard arguments; LIBRDP_STATUS_STATE when input cannot be sent
 * in the current session state; allocation or transport errors propagated from
 * the send path.
 *
 * @note Thread-safety: call from one serialized session-driving context.
 * @warning Applications are responsible for filtering local secure shortcuts
 * and for avoiding unintended credential or secret text injection.
 * @since 0.1.0
 */
librdp_status librdp_session_send_key(librdp_session* session, const librdp_key_event* event);

/**
 * @brief Send one mouse input event.
 *
 * The session must be connected or active and have a share ID. Wheel and X
 * button events use the extended mouse path where required; ordinary pointer
 * motion and buttons use the negotiated core-input or slow-path transport.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] event Mouse event; must not be NULL and is copied during the call.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid mouse arguments; LIBRDP_STATUS_STATE when input cannot be sent in
 * the current session state; allocation or transport errors propagated from the
 * send path.
 *
 * @note Thread-safety: call from one serialized session-driving context.
 * @since 0.1.0
 */
librdp_status librdp_session_send_mouse(librdp_session* session, const librdp_mouse_event* event);

/**
 * @brief Send one or more touch frames through the input channel.
 *
 * The input channel must be negotiated and ready. Frame and contact arrays are
 * validated and copied into temporary wire buffers during the call only.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] encode_time Client encode timestamp sent with the touch event.
 * @param[in] frames Touch frame array; must not be NULL.
 * @param[in] frame_count Number of touch frames; must be non-zero.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * arguments, invalid frame/contact counts, duplicate contact IDs, or invalid
 * contact fields; LIBRDP_STATUS_STATE when the input channel is unavailable;
 * LIBRDP_STATUS_NO_MEMORY on temporary allocation failure; transport errors
 * propagated from the send path.
 *
 * @note Thread-safety: call from one serialized session-driving context.
 * @since 0.1.0
 */
librdp_status librdp_session_send_touch(librdp_session* session,
                                        uint32_t encode_time,
                                        const librdp_touch_frame* frames,
                                        uint16_t frame_count);

/**
 * @brief Send one or more pen frames through the input channel.
 *
 * The input channel must be negotiated, ready, and report pen support. Frame
 * and contact arrays are validated and copied into temporary wire buffers
 * during the call only.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] encode_time Client encode timestamp sent with the pen event.
 * @param[in] frames Pen frame array; must not be NULL.
 * @param[in] frame_count Number of pen frames; must be non-zero.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * arguments, invalid frame/contact counts, duplicate device IDs, or invalid
 * pen fields; LIBRDP_STATUS_STATE when the input channel is unavailable;
 * LIBRDP_STATUS_UNSUPPORTED when the server did not negotiate pen support;
 * LIBRDP_STATUS_NO_MEMORY on temporary allocation failure; transport errors
 * propagated from the send path.
 *
 * @note Thread-safety: call from one serialized session-driving context.
 * @since 0.1.0
 */
librdp_status librdp_session_send_pen(librdp_session* session,
                                      uint32_t encode_time,
                                      const librdp_pen_frame* frames,
                                      uint16_t frame_count);

/**
 * @brief Ask the server to dismiss a hovering touch contact.
 *
 * The input channel must be negotiated and ready. The contact identifier is
 * encoded into a dismiss-hovering message.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] contact_id Contact identifier to dismiss.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * session is NULL; LIBRDP_STATUS_STATE when the input channel is unavailable;
 * allocation or transport errors propagated from the send path.
 *
 * @note Thread-safety: call from one serialized session-driving context.
 * @since 0.1.0
 */
librdp_status librdp_session_dismiss_touch(librdp_session* session, uint8_t contact_id);

/**
 * @brief Return the current session state.
 *
 * @param[in] session Session to query, or NULL.
 *
 * @return Current state, or LIBRDP_SESSION_FAILED when session is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the session.
 * @since 0.1.0
 */
librdp_session_state librdp_session_get_state(const librdp_session* session);

/**
 * @brief Return the primary session surface.
 *
 * The returned surface is owned by the session. It remains valid until the
 * session is freed; its contents and dimensions may change while the session
 * loop processes server updates.
 *
 * @param[in] session Session to query, or NULL.
 *
 * @return Read-only session-owned surface, or NULL when session is NULL.
 *
 * @note Thread-safety: use the surface only from the serialized session-driving
 * context, or copy pixels while holding application-provided locking.
 * @since 0.1.0
 */
const librdp_surface* librdp_session_get_surface(const librdp_session* session);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
