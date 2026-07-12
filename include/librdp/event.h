/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_EVENT_H
#define LIBRDP_EVENT_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/audio.h>
#include <librdp/channel.h>
#include <librdp/clipboard.h>
#include <librdp/error.h>
#include <librdp/input.h>
#include <librdp/video.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup librdp_event Event API
 * @brief Event discriminators and callback payload structures.
 * @{
 */

/**
 * @brief Event discriminator used by librdp_event.
 *
 * The event type selects the active member in librdp_event::data. Event
 * payloads are callback-owned views and are valid only until the callback
 * returns unless the receiving API explicitly documents otherwise.
 *
 * @since 0.1.0
 */
typedef enum librdp_event_type
{
    LIBRDP_EVENT_NONE = 0,                         /**< No event payload is active. */
    LIBRDP_EVENT_STATE_CHANGED = 1,                /**< data.state reports a session state transition. */
    LIBRDP_EVENT_SURFACE_INVALIDATED = 2,          /**< data.surface reports a dirty surface rectangle. */
    LIBRDP_EVENT_KEY_SENT = 3,                     /**< data.key echoes a keyboard event accepted for send. */
    LIBRDP_EVENT_MOUSE_SENT = 4,                   /**< data.mouse echoes a pointer event accepted for send. */
    LIBRDP_EVENT_ERROR = 5,                        /**< data.error reports an asynchronous session error. */
    LIBRDP_EVENT_DISCONNECTED = 6,                 /**< Session transport and protocol state have been closed. */
    LIBRDP_EVENT_POINTER = 7,                      /**< data.pointer reports pointer visibility, position, or shape. */
    LIBRDP_EVENT_CLIPBOARD_FORMATS = 8,            /**< data.clipboard_formats reports remote clipboard formats. */
    LIBRDP_EVENT_CLIPBOARD_DATA = 9,               /**< data.clipboard_data reports remote clipboard payload bytes. */
    LIBRDP_EVENT_CLIPBOARD_REQUEST = 10,           /**< data.clipboard_request asks for local clipboard data. */
    LIBRDP_EVENT_CHANNEL_OPEN = 11,                /**< data.channel_open reports an application channel. */
    LIBRDP_EVENT_CHANNEL_DATA = 12,                /**< data.channel_data reports application channel payload bytes. */
    LIBRDP_EVENT_CHANNEL_CLOSE = 13,               /**< data.channel_close reports an application channel close. */
    LIBRDP_EVENT_AUDIO_OUTPUT_FORMATS = 14,        /**< data.audio_output_formats reports playback formats. */
    LIBRDP_EVENT_AUDIO_OUTPUT_DATA = 15,           /**< data.audio_output_data reports playback sample bytes. */
    LIBRDP_EVENT_AUDIO_OUTPUT_CLOSE = 16,          /**< Audio output stream has closed; no payload is active. */
    LIBRDP_EVENT_AUDIO_INPUT_FORMATS = 17,         /**< data.audio_input_formats reports capture formats. */
    LIBRDP_EVENT_AUDIO_INPUT_OPEN = 18,            /**< data.audio_input_open asks the app to open capture. */
    LIBRDP_EVENT_VIDEO_CAPTURE_OPEN = 19,          /**< data.video_capture_open asks the app to open a camera stream. */
    LIBRDP_EVENT_VIDEO_CAPTURE_SAMPLE_REQUEST = 20, /**< data.video_capture_sample_request asks for one sample. */
    LIBRDP_EVENT_VIDEO_CAPTURE_CLOSE = 21,         /**< data.video_capture_close asks the app to close a stream. */
    LIBRDP_EVENT_CLIPBOARD_FILE_CONTENTS = 22      /**< data.clipboard_file_contents reports file-transfer bytes. */
} librdp_event_type;

#define LIBRDP_EVENT_ENVELOPE_VERSION 1u /**< Current librdp_event_envelope version. */

/**
 * @brief Pointer update subtype delivered in librdp_pointer_event.
 *
 * Shape events may include pixel data; position and visibility events do not
 * require applications to read the pixel fields.
 *
 * @since 0.1.0
 */
typedef enum librdp_pointer_update_type
{
    LIBRDP_POINTER_UPDATE_DEFAULT = 0,  /**< Restore the default pointer. */
    LIBRDP_POINTER_UPDATE_HIDDEN = 1,   /**< Hide the pointer. */
    LIBRDP_POINTER_UPDATE_POSITION = 2, /**< Move the pointer to x/y. */
    LIBRDP_POINTER_UPDATE_SHAPE = 3     /**< Replace or cache a pointer shape. */
} librdp_pointer_update_type;

/**
 * @brief Unsigned rectangle in desktop pixel coordinates.
 *
 * Rectangles delivered by callbacks are value types and can be copied freely.
 *
 * @since 0.1.0
 */
typedef struct librdp_rect
{
    uint32_t x;      /**< Left coordinate in pixels. */
    uint32_t y;      /**< Top coordinate in pixels. */
    uint32_t width;  /**< Width in pixels. */
    uint32_t height; /**< Height in pixels. */
} librdp_rect;

/**
 * @brief Pointer update payload delivered by LIBRDP_EVENT_POINTER.
 *
 * pixels is a borrowed BGRA32 buffer valid only until the event callback
 * returns. Applications that cache cursor images must copy pixels_len bytes.
 *
 * @since 0.1.0
 */
typedef struct librdp_pointer_event
{
    librdp_pointer_update_type update_type; /**< Pointer update subtype. */
    uint16_t cache_index;                   /**< Server cursor cache index associated with shape updates. */
    uint16_t x;                             /**< Pointer x coordinate for position updates. */
    uint16_t y;                             /**< Pointer y coordinate for position updates. */
    uint16_t hot_x;                         /**< Cursor hotspot x coordinate. */
    uint16_t hot_y;                         /**< Cursor hotspot y coordinate. */
    uint16_t width;                         /**< Cursor image width in pixels for shape updates. */
    uint16_t height;                        /**< Cursor image height in pixels for shape updates. */
    uint32_t stride;                        /**< Cursor pixel stride in bytes. */
    const uint8_t* pixels;                  /**< Borrowed BGRA32 cursor pixels; may be NULL when pixels_len is 0. */
    size_t pixels_len;                      /**< Length in bytes of pixels. */
    int visible;                            /**< Non-zero when the pointer should be visible. */
} librdp_pointer_event;

/**
 * @brief Remote clipboard format-list event payload.
 *
 * The formats array is borrowed and valid only for the callback duration.
 *
 * @since 0.1.0
 */
typedef struct librdp_clipboard_formats_event
{
    const librdp_clipboard_format* formats; /**< Borrowed format array; may be NULL when count is 0. */
    uint32_t count;                         /**< Number of entries in formats. */
    uint32_t total_count;                   /**< Total remote formats advertised by the server. */
} librdp_clipboard_formats_event;

/**
 * @brief Remote clipboard data response payload.
 *
 * data is borrowed and valid only for the callback duration.
 *
 * @since 0.1.0
 */
typedef struct librdp_clipboard_data_event
{
    uint32_t format_id;   /**< Clipboard format identifier for this response. */
    const uint8_t* data;  /**< Borrowed clipboard bytes; may be NULL when data_len is 0. */
    size_t data_len;      /**< Length in bytes of data. */
    int ok;               /**< Non-zero when the server returned data successfully. */
} librdp_clipboard_data_event;

/**
 * @brief Request for local clipboard data.
 *
 * Applications answer with the appropriate clipboard data API from the same
 * serialized session-driving context.
 *
 * @since 0.1.0
 */
typedef struct librdp_clipboard_request_event
{
    uint32_t format_id; /**< Requested local clipboard format identifier. */
} librdp_clipboard_request_event;

/**
 * @brief Remote clipboard file-content response payload.
 *
 * data is borrowed and valid only for the callback duration. Applications must
 * copy it before returning if they need to keep the file bytes.
 *
 * @since 0.1.0
 */
typedef struct librdp_clipboard_file_contents_event
{
    uint32_t stream_id;  /**< Stream identifier supplied by the request API. */
    int32_t file_index;  /**< Remote file index associated with the response. */
    uint32_t flags;      /**< Server file-content response flags. */
    uint64_t position;   /**< Byte position covered by this response. */
    uint32_t requested;  /**< Number of bytes requested by the caller. */
    const uint8_t* data; /**< Borrowed file bytes; may be NULL when data_len is 0. */
    size_t data_len;     /**< Length in bytes of data. */
    int ok;              /**< Non-zero when the server returned the requested bytes successfully. */
} librdp_clipboard_file_contents_event;

/**
 * @brief Dynamic virtual-channel open event payload.
 *
 * name is borrowed and valid only for the callback duration.
 *
 * @since 0.1.0
 */
typedef struct librdp_channel_open_event
{
    librdp_channel_id channel_id; /**< Channel identifier valid until close. */
    const char* name;             /**< Borrowed channel name; may be NULL when name_len is 0. */
    size_t name_len;              /**< Length in bytes of name, excluding a NUL terminator. */
} librdp_channel_open_event;

/**
 * @brief Dynamic virtual-channel data event payload.
 *
 * name and data are borrowed and valid only for the callback duration.
 *
 * @since 0.1.0
 */
typedef struct librdp_channel_data_event
{
    librdp_channel_id channel_id; /**< Channel identifier that received data. */
    const char* name;             /**< Borrowed channel name; may be NULL when name_len is 0. */
    size_t name_len;              /**< Length in bytes of name. */
    const uint8_t* data;          /**< Borrowed channel payload; may be NULL when data_len is 0. */
    size_t data_len;              /**< Length in bytes of data. */
} librdp_channel_data_event;

/**
 * @brief Dynamic virtual-channel close event payload.
 *
 * name is borrowed and valid only for the callback duration.
 *
 * @since 0.1.0
 */
typedef struct librdp_channel_close_event
{
    librdp_channel_id channel_id; /**< Channel identifier that is no longer active. */
    const char* name;             /**< Borrowed channel name; may be NULL when name_len is 0. */
    size_t name_len;              /**< Length in bytes of name. */
} librdp_channel_close_event;

/**
 * @brief Audio output format-list event payload.
 *
 * The formats array is borrowed and valid only for the callback duration.
 *
 * @since 0.1.0
 */
typedef struct librdp_audio_output_formats_event
{
    const librdp_audio_format* formats; /**< Borrowed playback format array; may be NULL when count is 0. */
    uint32_t count;                     /**< Number of entries in formats. */
    uint16_t version;                   /**< Server audio-output protocol version. */
} librdp_audio_output_formats_event;

/**
 * @brief Audio output sample event payload.
 *
 * data is borrowed and valid only for the callback duration.
 *
 * @since 0.1.0
 */
typedef struct librdp_audio_output_data_event
{
    uint16_t timestamp;       /**< Server timestamp associated with the sample block. */
    uint16_t format_no;       /**< Negotiated audio output format index. */
    uint8_t block_no;         /**< Server block number used for acknowledgements. */
    uint32_t audio_timestamp; /**< Extended audio timestamp when supplied by the server. */
    const uint8_t* data;      /**< Borrowed encoded audio bytes; may be NULL when data_len is 0. */
    size_t data_len;          /**< Length in bytes of data. */
} librdp_audio_output_data_event;

/**
 * @brief Audio input format-list event payload.
 *
 * The formats array is borrowed and valid only for the callback duration.
 *
 * @since 0.1.0
 */
typedef struct librdp_audio_input_formats_event
{
    const librdp_audio_format* formats; /**< Borrowed capture format array; may be NULL when count is 0. */
    uint32_t count;                     /**< Number of entries in formats. */
    uint32_t version;                   /**< Server audio-input protocol version. */
} librdp_audio_input_formats_event;

/**
 * @brief Audio input open request event payload.
 *
 * Applications respond with librdp_session_audio_input_open_reply().
 *
 * @since 0.1.0
 */
typedef struct librdp_audio_input_open_event
{
    uint32_t frames_per_packet; /**< Requested capture frame count per packet. */
    uint32_t initial_format;    /**< Initial capture format index selected by the server. */
    librdp_audio_format format; /**< Value copy of the selected capture format. */
} librdp_audio_input_open_event;

/**
 * @brief Camera stream open event payload.
 *
 * Applications prepare the requested local stream and later answer sample
 * requests for the same stream index.
 *
 * @since 0.1.0
 */
typedef struct librdp_video_capture_open_event
{
    uint8_t stream_index;              /**< Server stream index to open. */
    librdp_video_capture_media media;  /**< Requested media format for the stream. */
} librdp_video_capture_open_event;

/**
 * @brief Camera sample request event payload.
 *
 * Applications respond with either a sample or an error for stream_index.
 *
 * @since 0.1.0
 */
typedef struct librdp_video_capture_sample_request_event
{
    uint8_t stream_index;             /**< Server stream index requesting a sample. */
    librdp_video_capture_media media; /**< Requested media format for the sample. */
} librdp_video_capture_sample_request_event;

/**
 * @brief Camera stream close event payload.
 *
 * Applications should stop local capture and release stream-specific resources.
 *
 * @since 0.1.0
 */
typedef struct librdp_video_capture_close_event
{
    uint8_t stream_index; /**< Server stream index to close. */
} librdp_video_capture_close_event;

/**
 * @brief Event object delivered through librdp_event_callback.
 *
 * The active union member is selected by type. The object and any borrowed
 * payload pointers remain valid only until the event callback returns.
 *
 * @since 0.1.0
 */
typedef struct librdp_event
{
    librdp_event_type type; /**< Event discriminator selecting the active data member. */
    union
    {
        struct
        {
            int old_state; /**< Previous librdp_session_state value. */
            int new_state; /**< New librdp_session_state value. */
        } state; /**< Payload for LIBRDP_EVENT_STATE_CHANGED. */
        librdp_rect surface; /**< Payload for LIBRDP_EVENT_SURFACE_INVALIDATED. */
        librdp_key_event key; /**< Payload for LIBRDP_EVENT_KEY_SENT. */
        librdp_mouse_event mouse; /**< Payload for LIBRDP_EVENT_MOUSE_SENT. */
        struct
        {
            librdp_status status; /**< Status associated with the asynchronous error. */
        } error; /**< Payload for LIBRDP_EVENT_ERROR. */
        librdp_pointer_event pointer; /**< Payload for LIBRDP_EVENT_POINTER. */
        librdp_clipboard_formats_event clipboard_formats; /**< Payload for LIBRDP_EVENT_CLIPBOARD_FORMATS. */
        librdp_clipboard_data_event clipboard_data; /**< Payload for LIBRDP_EVENT_CLIPBOARD_DATA. */
        librdp_clipboard_request_event clipboard_request; /**< Payload for LIBRDP_EVENT_CLIPBOARD_REQUEST. */
        librdp_clipboard_file_contents_event clipboard_file_contents; /**< Payload for file-content responses. */
        librdp_channel_open_event channel_open; /**< Payload for LIBRDP_EVENT_CHANNEL_OPEN. */
        librdp_channel_data_event channel_data; /**< Payload for LIBRDP_EVENT_CHANNEL_DATA. */
        librdp_channel_close_event channel_close; /**< Payload for LIBRDP_EVENT_CHANNEL_CLOSE. */
        librdp_audio_output_formats_event audio_output_formats; /**< Payload for playback format events. */
        librdp_audio_output_data_event audio_output_data; /**< Payload for playback sample events. */
        librdp_audio_input_formats_event audio_input_formats; /**< Payload for capture format events. */
        librdp_audio_input_open_event audio_input_open; /**< Payload for capture open requests. */
        librdp_video_capture_open_event video_capture_open; /**< Payload for camera open requests. */
        librdp_video_capture_sample_request_event video_capture_sample_request; /**< Payload for camera sample requests. */
        librdp_video_capture_close_event video_capture_close; /**< Payload for camera close requests. */
    } data; /**< Event payload union selected by type. */
} librdp_event;

/**
 * @brief Versioned event envelope for evolvable callbacks.
 *
 * The envelope separates the event type from the payload pointer and payload
 * size. payload points into the matching member of legacy_event and remains
 * valid only until the callback returns. Consumers compiled against an older
 * payload definition must read no more than payload_size bytes.
 *
 * @since 0.1.0
 */
typedef struct librdp_event_envelope
{
    uint32_t version;                 /**< Struct version, LIBRDP_EVENT_ENVELOPE_VERSION. */
    uint32_t size;                    /**< Size of this struct in bytes. */
    librdp_event_type type;           /**< Event discriminator. */
    const void* payload;              /**< Borrowed payload pointer, or NULL when payload_size is 0. */
    size_t payload_size;              /**< Bytes valid at payload. */
    const librdp_event* legacy_event; /**< Borrowed legacy event view, valid only during the callback. */
} librdp_event_envelope;

/**
 * @brief Initialize an event envelope descriptor.
 *
 * Applications normally receive envelopes from callbacks and do not need to
 * initialize them. This helper is provided for tests, adapters, and stack-owned
 * descriptors.
 *
 * @param[out] envelope Envelope to initialize; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * envelope is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_event_envelope_init(librdp_event_envelope* envelope);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
