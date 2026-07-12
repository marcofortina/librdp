/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_SESSION_H
#define LIBRDP_SESSION_H

#include <poll.h>
#include <stddef.h>
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
 * @brief Detailed public client lifecycle phase.
 *
 * This enum refines librdp_session_state for applications that need to report
 * or supervise connection progress. Existing state-change events continue to
 * use librdp_session_state; callers can query this lifecycle independently.
 * Values that need future asynchronous DNS or reconnect machinery are reserved
 * and returned only when that machinery is active.
 *
 * @since 0.1.0
 */
typedef enum librdp_session_lifecycle
{
    LIBRDP_LIFECYCLE_NEW = 0,           /**< Session exists and no connection attempt is in progress. */
    LIBRDP_LIFECYCLE_RESOLVING = 1,     /**< Reserved for asynchronous target resolution. */
    LIBRDP_LIFECYCLE_CONNECTING = 2,    /**< TCP transport connection is being established. */
    LIBRDP_LIFECYCLE_TLS_HANDSHAKE = 3, /**< TLS handshake is being established. */
    LIBRDP_LIFECYCLE_AUTHENTICATING = 4, /**< NLA or credential-dependent authentication is running. */
    LIBRDP_LIFECYCLE_NEGOTIATING = 5,   /**< X.224, MCS, GCC, security, channel, or client-info negotiation is running. */
    LIBRDP_LIFECYCLE_ACTIVATING = 6,    /**< Session is connected and awaiting/processing activation. */
    LIBRDP_LIFECYCLE_ACTIVE = 7,        /**< Session is active and processing updates/input. */
    LIBRDP_LIFECYCLE_RECONNECTING = 8,  /**< Reserved for coordinated reconnect attempts. */
    LIBRDP_LIFECYCLE_DISCONNECTING = 9, /**< Session teardown is in progress. */
    LIBRDP_LIFECYCLE_DISCONNECTED = 10, /**< Session closed cleanly or was explicitly disconnected. */
    LIBRDP_LIFECYCLE_FAILED = 11        /**< Session reached a terminal failure phase. */
} librdp_session_lifecycle;

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

#define LIBRDP_TRACE_POLICY_VERSION 1u /**< Current librdp_trace_policy version. */
#define LIBRDP_TRACE_RECORD_VERSION 1u /**< Current librdp_trace_record version. */

#define LIBRDP_TRACE_CATEGORY_CLIENT 0x00000001u    /**< Enable client lifecycle, surface, input, and channel trace. */
#define LIBRDP_TRACE_CATEGORY_TRANSPORT 0x00000002u /**< Enable TCP, TLS, wait, read, and write trace. */
#define LIBRDP_TRACE_CATEGORY_PROTOCOL 0x00000004u  /**< Enable handshake, parser, PDU, and bounded hexdump trace. */
#define LIBRDP_TRACE_CATEGORY_ALL                                                                                     \
    (LIBRDP_TRACE_CATEGORY_CLIENT | LIBRDP_TRACE_CATEGORY_TRANSPORT | LIBRDP_TRACE_CATEGORY_PROTOCOL) /**< Enable all trace categories. */

/**
 * @brief Public trace severity threshold.
 *
 * A session trace policy emits events with a level numerically less than or
 * equal to the configured threshold. TRACE includes bounded hexdumps subject
 * to the policy redaction and hex-byte limit.
 *
 * @since 0.1.0
 */
typedef enum librdp_trace_level
{
    LIBRDP_TRACE_LEVEL_ERROR = 0, /**< Error events only. */
    LIBRDP_TRACE_LEVEL_WARN = 1,  /**< Warning and error events. */
    LIBRDP_TRACE_LEVEL_INFO = 2,  /**< Informational, warning, and error events. */
    LIBRDP_TRACE_LEVEL_DEBUG = 3, /**< Debug, informational, warning, and error events. */
    LIBRDP_TRACE_LEVEL_TRACE = 4  /**< Full trace events and bounded hexdumps. */
} librdp_trace_level;

/**
 * @brief Destination for trace records emitted while a session API is running.
 *
 * The sink is evaluated synchronously on the thread that drives the session.
 * File sinks are opened by the library from a path in librdp_trace_policy; no
 * platform file handle is exposed in the ABI.
 *
 * @since 0.1.0
 */
typedef enum librdp_trace_sink
{
    LIBRDP_TRACE_SINK_DISABLED = 0, /**< Disable session-scoped trace. */
    LIBRDP_TRACE_SINK_STDERR = 1,   /**< Write formatted trace lines to stderr. */
    LIBRDP_TRACE_SINK_CALLBACK = 2, /**< Deliver trace records to a callback only. */
    LIBRDP_TRACE_SINK_FILE = 3      /**< Append formatted trace lines to a configured file path. */
} librdp_trace_sink;

/**
 * @brief Trace record delivered to a session trace callback.
 *
 * All pointer fields are borrowed and valid only until the callback returns.
 * line contains the exact formatted line that would be written to a text sink.
 * message contains the escaped key=value message for normal events, or NULL
 * for hexdump records where details are in line.
 *
 * @since 0.1.0
 */
typedef struct librdp_trace_record
{
    uint32_t version;           /**< Struct version, LIBRDP_TRACE_RECORD_VERSION. */
    uint32_t size;              /**< Size of this struct in bytes. */
    uint64_t sequence;          /**< Session-scoped monotonically increasing sequence number. */
    uint64_t timestamp_ns;      /**< Monotonic timestamp in nanoseconds. */
    uint64_t elapsed_us;        /**< Microseconds elapsed since this session trace scope first emitted a record. */
    const char* session_id;     /**< Optional borrowed session identifier from the policy, or NULL. */
    const char* connection_id;  /**< Optional borrowed connection identifier from the policy, or NULL. */
    const char* trace_id;       /**< Optional borrowed distributed trace identifier from the policy, or NULL. */
    const char* category;       /**< Borrowed category token, such as "client", "transport", or "protocol". */
    const char* event;          /**< Borrowed stable event name. */
    const char* level;          /**< Borrowed level token. */
    const char* message;        /**< Borrowed escaped key=value message for normal events, or NULL for hexdumps. */
    const char* line;           /**< Borrowed complete formatted trace line. */
} librdp_trace_record;

/**
 * @brief Session trace callback.
 *
 * The callback runs synchronously on the thread that emits the trace record.
 * record and all borrowed pointers inside it are valid only until the callback
 * returns. user_data is the pointer configured in librdp_trace_policy.
 *
 * @param[in] session Session that emitted the trace; never NULL during a
 * session-scoped callback.
 * @param[in] record Trace record; never NULL during callback.
 * @param[in,out] user_data Opaque application pointer; may be NULL.
 *
 * @note Thread-safety: callbacks are not invoked concurrently by one session
 * unless the application concurrently drives that session, which is unsupported.
 * @warning Trace records may describe sensitive operations. Payload bodies are
 * redacted by default; unsafe payload tracing must be explicitly enabled.
 * @since 0.1.0
 */
typedef void (*librdp_trace_callback)(librdp_session* session,
                                      const librdp_trace_record* record,
                                      void* user_data);

/**
 * @brief Versioned session trace policy.
 *
 * Initialize with librdp_trace_policy_init() before changing fields. category
 * flags select which trace categories are active. file_path, session_id,
 * connection_id, and trace_id are copied by librdp_session_set_trace_policy().
 * callback and callback_user_data are stored as-is and must remain valid while
 * the policy is installed.
 *
 * @since 0.1.0
 */
typedef struct librdp_trace_policy
{
    uint32_t version;       /**< Struct version, LIBRDP_TRACE_POLICY_VERSION. */
    uint32_t size;          /**< Size of this struct in bytes. */
    uint32_t categories;    /**< Bitmask of LIBRDP_TRACE_CATEGORY_* values. */
    librdp_trace_level level; /**< Maximum emitted severity level. */
    uint32_t hex_bytes;     /**< Maximum bytes dumped by hexdump records; zero disables dump bytes. */
    int unsafe_payloads;    /**< Non-zero to allow sensitive payload bodies in hexdumps. */
    librdp_trace_sink sink; /**< Trace sink destination. */
    const char* file_path;  /**< File path for FILE sink; copied on set and otherwise ignored. */
    librdp_trace_callback callback; /**< Callback for CALLBACK sink; borrowed, not copied. */
    void* callback_user_data;       /**< Opaque pointer passed to callback; may be NULL. */
    const char* session_id;         /**< Optional application session identifier; copied on set. */
    const char* connection_id;      /**< Optional application connection identifier; copied on set. */
    const char* trace_id;           /**< Optional distributed trace identifier; copied on set. */
} librdp_trace_policy;

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
 * @brief Initialize a trace policy to safe stderr defaults.
 *
 * The initialized policy enables all categories at INFO level, sets the sink to
 * STDERR, disables unsafe payload dumping, and sets hex_bytes to zero. String
 * pointers and callback fields are NULL.
 *
 * @param[out] policy Policy object to initialize; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * policy is NULL.
 *
 * @note Thread-safety: this function writes only the caller-owned policy
 * object and can be used without a session.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_trace_policy_init(librdp_trace_policy* policy);

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
LIBRDP_API librdp_session* librdp_session_new(const librdp_settings* settings);

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
LIBRDP_API void librdp_session_free(librdp_session* session);

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
LIBRDP_API void librdp_session_set_event_callback(librdp_session* session, librdp_event_callback callback, void* user_data);

/**
 * @brief Install, replace, or clear a session-scoped trace policy.
 *
 * A non-NULL policy overrides environment-driven internal trace while session
 * APIs are running for this session. Passing NULL clears the session policy and
 * restores the environment-controlled backend. The policy descriptor must have
 * version LIBRDP_TRACE_POLICY_VERSION and a size large enough for the current
 * struct. String fields are copied; callback pointers and callback_user_data
 * are borrowed.
 *
 * @param[in,out] session Session to configure; must not be NULL.
 * @param[in] policy Trace policy to install, or NULL to clear the session policy.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * session, invalid policy version, invalid category bits, invalid sink, missing
 * callback for CALLBACK sink, or missing file_path for FILE sink;
 * LIBRDP_STATUS_NO_MEMORY on allocation failure; LIBRDP_STATUS_IO_ERROR when a
 * FILE sink path cannot be opened for append.
 *
 * @note Thread-safety: configure trace before driving the session, or serialize
 * externally with all session API calls.
 * @warning Enabling unsafe_payloads can expose credentials, input, clipboard,
 * APDU, file, audio, video, and USB payload data in trace output.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_set_trace_policy(librdp_session* session,
                                                         const librdp_trace_policy* policy);

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
LIBRDP_API librdp_status librdp_session_connect(librdp_session* session);

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
LIBRDP_API librdp_status librdp_session_run_once(librdp_session* session, int timeout_ms);

/**
 * @brief Return the POSIX poll descriptors needed by the session loop.
 *
 * The descriptors are snapshots of session-owned transports. The caller does
 * not own or close them. The returned events use POSIX poll(2) bits. Call with
 * fds set to NULL and capacity set to 0 to query the required descriptor
 * count without writing descriptors.
 *
 * @param[in] session Connected or active session; must not be NULL.
 * @param[out] fds Destination array for poll descriptors; may be NULL only
 * when capacity is 0.
 * @param[in] capacity Number of entries available in fds.
 * @param[out] count Required descriptor count; must not be NULL. Written on
 * success and on insufficient-capacity failure.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * session/count or insufficient capacity; LIBRDP_STATUS_STATE when the session
 * is not connected or active.
 *
 * @note Thread-safety: call from the serialized session-driving context.
 * Descriptor validity ends when the session disconnects or reconnects.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_get_pollfds(librdp_session* session,
                                                    struct pollfd* fds,
                                                    size_t capacity,
                                                    size_t* count);

/**
 * @brief Notify the session about poll results collected by the application.
 *
 * Applications that drive their own event loop call librdp_session_get_pollfds(),
 * pass those descriptors to poll(2), copy revents back into the same array, and
 * then call this function before librdp_session_dispatch_pending().
 *
 * @param[in,out] session Connected or active session; must not be NULL.
 * @param[in] fds Descriptor array previously obtained from
 * librdp_session_get_pollfds(); must not be NULL when count is non-zero.
 * @param[in] count Number of descriptors in fds.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * inputs, unknown descriptors, or zero count; LIBRDP_STATUS_STATE when the
 * session is not connected or active.
 *
 * @note Thread-safety: call from the serialized session-driving context. The
 * function records readiness only; packet parsing happens in
 * librdp_session_dispatch_pending().
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_notify_poll(librdp_session* session,
                                                   const struct pollfd* fds,
                                                   size_t count);

/**
 * @brief Dispatch work made ready by librdp_session_notify_poll().
 *
 * If no poll readiness is pending this function returns immediately. Otherwise
 * it processes the same packet/channel paths as librdp_session_run_once()
 * without performing another blocking poll.
 *
 * @param[in,out] session Connected or active session; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success or idle pending state; status values
 * propagated by the packet/channel dispatch path on error.
 *
 * @note Thread-safety: call from the serialized session-driving context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_dispatch_pending(librdp_session* session);

/**
 * @brief Return the next timeout required by the session event loop.
 *
 * The value is suitable for poll(2). A value of -1 means the current session
 * has no internal deadline and the application may choose its own timeout. A
 * value of 0 means work has already been notified and should be dispatched
 * without blocking.
 *
 * @param[in] session Session to query; must not be NULL.
 * @param[out] timeout_ms Destination timeout in milliseconds; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * arguments; LIBRDP_STATUS_STATE when the session is not connected or active.
 *
 * @note Thread-safety: call from the serialized session-driving context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_get_next_timeout(const librdp_session* session, int* timeout_ms);

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
LIBRDP_API librdp_status librdp_session_disconnect(librdp_session* session);

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
LIBRDP_API librdp_status librdp_session_resize(librdp_session* session, uint32_t width, uint32_t height);

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
LIBRDP_API librdp_status librdp_session_set_display_layout(librdp_session* session,
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
LIBRDP_API librdp_status librdp_session_refresh(librdp_session* session, uint32_t x, uint32_t y, uint32_t width, uint32_t height);

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
LIBRDP_API librdp_status librdp_session_send_key(librdp_session* session, const librdp_key_event* event);

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
LIBRDP_API librdp_status librdp_session_send_mouse(librdp_session* session, const librdp_mouse_event* event);

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
LIBRDP_API librdp_status librdp_session_send_touch(librdp_session* session,
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
LIBRDP_API librdp_status librdp_session_send_pen(librdp_session* session,
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
LIBRDP_API librdp_status librdp_session_dismiss_touch(librdp_session* session, uint8_t contact_id);

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
LIBRDP_API librdp_session_state librdp_session_get_state(const librdp_session* session);

/**
 * @brief Return the detailed client lifecycle phase.
 *
 * The returned phase is a snapshot owned by the session. It can be more
 * specific than librdp_session_get_state(), especially while
 * librdp_session_connect() is executing a blocking connection attempt.
 *
 * @param[in] session Session to query, or NULL.
 *
 * @return Current lifecycle phase, or LIBRDP_LIFECYCLE_FAILED when session is
 * NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the session.
 * @since 0.1.0
 */
LIBRDP_API librdp_session_lifecycle librdp_session_get_lifecycle(const librdp_session* session);

/**
 * @brief Return the opaque last-error object owned by a session.
 *
 * The returned object is owned by the session and must not be freed by the
 * caller. Copy details with librdp_error_copy_info(). Passing NULL returns
 * NULL. The object remains valid until librdp_session_free().
 *
 * @param[in] session Session to query, or NULL.
 *
 * @return Session-owned error object, or NULL when session is NULL.
 *
 * @note Thread-safety: copy from the serialized session-driving context, or
 * protect the session externally while reading.
 * @warning Error messages are redacted, but applications should still avoid
 * forwarding diagnostics to untrusted destinations without review.
 * @since 0.1.0
 */
LIBRDP_API const librdp_error* librdp_session_last_error(const librdp_session* session);

/**
 * @brief Clear the recorded last error for a session.
 *
 * Passing NULL is allowed and has no effect. After clearing, the session's
 * last-error object reports LIBRDP_STATUS_OK and no component or message.
 *
 * @param[in,out] session Session whose last error should be cleared, or NULL.
 *
 * @note Thread-safety: call from the serialized session-driving context.
 * @since 0.1.0
 */
LIBRDP_API void librdp_session_clear_last_error(librdp_session* session);

/**
 * @brief Query runtime readiness for one optional feature.
 *
 * The function starts from the session's cloned settings and augments the
 * status with negotiated and active information observed during the current
 * session. Parser-only helpers and channels that are not wired to runtime
 * state are reported as not active rather than being promoted by the enabled
 * feature bit alone.
 *
 * @param[in] session Session to query; must not be NULL.
 * @param[in] feature Single known librdp_feature value to query; bitmasks with
 * multiple bits, zero, and unknown bits are rejected.
 * @param[out] status Destination status object; must not be NULL. The object is
 * written completely on success and contains no borrowed pointers.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * pointers, zero features, multiple feature bits, or unknown feature bits.
 *
 * @note Thread-safety: call from the same serialized context that drives the
 * session, or protect the session externally while querying.
 * @warning negotiated and active are runtime observations only; applications
 * must still handle channel closure or reconnect events after a successful
 * query.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_get_feature_status(const librdp_session* session,
                                                librdp_feature feature,
                                                librdp_feature_status* status);

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
LIBRDP_API const librdp_surface* librdp_session_get_surface(const librdp_session* session);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
