/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: private client session state shared by extracted session domains.
 * Invariants: this header exposes only internal state used by session modules; public ABI remains in include/librdp.
 * Ownership: librdp_session owns transport, caches, channel state, backend handles, and callback registrations.
 * Threading: callers must hold the session owner-thread contract before mutating fields through these helpers.
 * Trust boundary: fields populated from wire data are validated by the domain module before becoming observable.
 */

#ifndef LIBRDP_CLIENT_SESSION_INTERNAL_H
#define LIBRDP_CLIENT_SESSION_INTERNAL_H

#include <librdp/session.h>
#include <librdp/video.h>
#include "channels/audio_format.h"
#include "channels/audio_input.h"
#include "channels/audio_output.h"
#include "channels/auth_redirection.h"
#include "channels/composited_remoting.h"
#include "channels/core_input.h"
#include "channels/device_redirection.h"
#include "channels/display_control.h"
#include "channels/dynamic_channel.h"
#include "channels/echo_channel.h"
#include "channels/filesystem_redirection.h"
#include "channels/graphics_pipeline.h"
#include "channels/input_channel.h"
#include "channels/mouse_cursor.h"
#include "channels/multiparty.h"
#include "channels/pnp_redirection.h"
#include "channels/port_redirection.h"
#include "channels/printer_redirection.h"
#include "channels/remote_programs.h"
#include "channels/smartcard_redirection.h"
#include "channels/telemetry.h"
#include "channels/usb_redirection.h"
#include "channels/video_capture.h"
#include "channels/video_optimized.h"
#include "channels/video_redirection.h"
#include "channels/virtual_channel.h"
#include "channels/webauthn_channel.h"
#include "client/error_internal.h"
#include "client/printer_backend.h"
#include "client/settings_internal.h"
#include "client/smartcard_backend.h"
#include "client/usb_backend.h"
#include "client/webauthn_backend.h"
#include "clipboard/clipboard.h"
#include "common/stream.h"
#include "common/trace.h"
#include "graphics/avc.h"
#include "graphics/bitmap.h"
#include "graphics/clearcodec.h"
#include "graphics/gdi_orders.h"
#include "graphics/gdi_render.h"
#include "graphics/nscodec.h"
#include "graphics/rfx_codec.h"
#include "graphics/surface_commands.h"
#include "licensing/licensing.h"
#include "nla/credssp.h"
#include "protocol/bulk.h"
#include "protocol/gcc.h"
#include "protocol/pointer.h"
#include "protocol/slowpath.h"
#include "security/security.h"
#include "transport/transport.h"
#include <dirent.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#ifdef RDP_HAVE_WINPR_SMARTCARD
#include <winpr/smartcard.h>
#elif defined(RDP_HAVE_PCSC)
#include <winscard.h>
#endif
#ifdef RDP_HAVE_LIBUSB
#include <libusb.h>
typedef struct rdp_session_usb_worker rdp_session_usb_worker;
#endif

#define RDP_SESSION_MAX_DYNAMIC_CHANNELS 64u
#define RDP_SESSION_HANDSHAKE_TIMEOUT_MS 5000
#define RDP_SESSION_DYNAMIC_CHANNEL_NAME_MAX 96u
#define RDP_SESSION_MAX_DYNAMIC_MESSAGE (64u * 1024u * 1024u)
#define RDP_SESSION_ECHO_MAX_TIMEOUT_MS 600000u
#define RDP_SESSION_RECONNECT_MAX_ATTEMPTS 64u
#define RDP_SESSION_MAX_FASTPATH_FRAGMENT (16u * 1024u * 1024u)
#define RDP_SESSION_MAX_GRAPHICS_SURFACES 64u
#define RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION 8192u
#define RDP_SESSION_GRAPHICS_CACHE_SLOTS 4096u
#define RDP_SESSION_GRAPHICS_CACHE_MAX_BYTES (16u * 1024u * 1024u)
#define RDP_SESSION_GDI_BITMAP_CACHE_SLOTS 4096u
#define RDP_SESSION_GDI_BITMAP_CACHE_MAX_BYTES (64u * 1024u * 1024u)
#define RDP_SESSION_GDI_COLOR_TABLE_SLOTS 256u
#define RDP_SESSION_GDI_BRUSH_CACHE_SLOTS RDP_GDI_BRUSH_CACHE_ENTRIES
#define RDP_SESSION_GDI_NINEGRID_CACHE_SLOTS 256u
#define RDP_SESSION_GDI_GLYPH_CACHE_IDS 10u
#define RDP_SESSION_GDI_GLYPH_CACHE_SLOTS 256u
#define RDP_SESSION_GDI_GLYPH_FRAGMENT_SLOTS 256u
#define RDP_SESSION_GDI_GLYPH_MAX_BYTES (4u * 1024u * 1024u)
#define RDP_SESSION_BITMAP_FLAG_COMPRESSED 0x0001u
#define RDP_SESSION_GDI_SAVE_BITMAP_SLOTS 64u
#define RDP_SESSION_GDI_SAVE_BITMAP_MAX_BYTES (8u * 1024u * 1024u)
#define RDP_SESSION_GDI_OFFSCREEN_CACHE_SLOTS 256u
#define RDP_SESSION_GDI_GDIPLUS_CACHE_SLOTS 128u
#define RDP_SESSION_GDI_GDIPLUS_MAX_BYTES (16u * 1024u * 1024u)
#define RDP_SESSION_GDI_WINDOW_MAX_BYTES (64u * 1024u)
#define RDP_SESSION_GDI_SCREEN_BITMAP_SURFACE 0xffffu
#define RDP_SESSION_PROGRESSIVE_TILE_STATES 2048u
#define RDP_SESSION_POINTER_CACHE_SLOTS 128u
#define RDP_SESSION_VOLUME_LABEL_MAX_CHARS 32u
#define RDP_SESSION_VOLUME_LABEL_MAX_BYTES 129u
#define RDP_SESSION_VIDEO_STREAMS 32u
#define RDP_SESSION_VIDEO_OPTIMIZED_PRESENTATIONS 16u
#define RDP_SESSION_VIDEO_CAPTURE_DEFAULT_WIDTH 640u
#define RDP_SESSION_VIDEO_CAPTURE_DEFAULT_HEIGHT 480u
#define RDP_SESSION_VIDEO_CAPTURE_DEFAULT_FPS 30u
#define RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_MIN 0
#define RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_MAX 100
#define RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_STEP 1
#define RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_DEFAULT 50
#define RDP_SESSION_CLIPBOARD_MAX_FORMATS 64u
#define RDP_SESSION_CLIPBOARD_MAX_LOCAL_FILES 64u
#define RDP_SESSION_CLIPBOARD_MAX_PENDING_FILE_REQUESTS 64u
#define RDP_SESSION_CLIPBOARD_FILE_RANGE_MAX (4u * 1024u * 1024u)
#define RDP_SESSION_MULTITRANSPORT_RUNTIME_SUPPORTED 1
#define RDP_SESSION_ECHO_CHANNEL_NAME RDP_ECHO_CHANNEL_NAME
#define RDP_SESSION_DISPLAY_CONTROL_NAME RDP_DISPLAY_CONTROL_CHANNEL_NAME
#define RDP_SESSION_CORE_INPUT_NAME RDP_CORE_INPUT_CHANNEL_NAME
#define RDP_SESSION_INPUT_CHANNEL_NAME RDP_INPUT_CHANNEL_NAME
#define RDP_SESSION_GRAPHICS_PIPELINE_NAME RDP_GRAPHICS_PIPELINE_CHANNEL_NAME
#define RDP_SESSION_MOUSE_CURSOR_NAME RDP_MOUSE_CURSOR_CHANNEL_NAME
#define RDP_SESSION_AUTH_REDIRECTION_NAME RDP_AUTH_REDIRECTION_CHANNEL_NAME
#define RDP_SESSION_WEBAUTHN_CHANNEL_NAME RDP_WEBAUTHN_CHANNEL_NAME
#define RDP_SESSION_USB_REDIRECTION_CHANNEL_NAME RDP_USB_REDIRECTION_CHANNEL_NAME
#define RDP_SESSION_AUDIO_OUTPUT_FORMAT_LIMIT 16u
#define RDP_SESSION_USB_DEVICE_INTERFACE_BASE 4u
#define RDP_SESSION_HRESULT_OK 0x00000000u
#define RDP_SESSION_HRESULT_FAIL 0x80004005u
#define RDP_SESSION_HRESULT_NOTIMPL 0x80004001u
#define RDP_SESSION_CTAP2_ERR_OPERATION_DENIED 0x27u
#define RDP_SESSION_DEVICE_NO_SUCH_DEVICE 0xc000000eu
#define RDP_SESSION_DEVICE_NOT_SUPPORTED 0xc00000bbu
#define RDP_SESSION_DEVICE_INVALID_PARAMETER 0xc000000du
#define RDP_SESSION_DEVICE_NO_SUCH_FILE 0xc000000fu
#define RDP_SESSION_DEVICE_ACCESS_DENIED 0xc0000022u
#define RDP_SESSION_DEVICE_OBJECT_NAME_COLLISION 0xc0000035u
#define RDP_SESSION_DEVICE_NOT_A_DIRECTORY 0xc0000103u
#define RDP_SESSION_DEVICE_LOCK_NOT_GRANTED 0xc0000054u
#define RDP_SESSION_DEVICE_RANGE_NOT_LOCKED 0xc000007eu
#define RDP_SESSION_DEVICE_NO_MORE_FILES 0x80000006u
#define RDP_SESSION_DEVICE_TOO_MANY_OPENED_FILES 0xc000011fu
#define RDP_SESSION_DEVICE_UNSUCCESSFUL 0xc0000001u
#define RDP_SESSION_DEVICE_BUFFER_TOO_SMALL 0xc0000023u
#define RDP_SESSION_DEVICE_PRINT_QUEUE_FULL 0xc00000c6u
#define RDP_SESSION_SCARD_SUCCESS 0x00000000u
#define RDP_SESSION_SCARD_E_INVALID_HANDLE 0x80100003u
#define RDP_SESSION_SCARD_E_INVALID_PARAMETER 0x80100004u
#define RDP_SESSION_SCARD_E_NO_SERVICE 0x8010001du
#define RDP_SESSION_SCARD_E_NO_MEMORY 0x80100006u
#define RDP_SESSION_SCARD_E_UNSUPPORTED_FEATURE 0x8010001fu
#define RDP_SESSION_SCARD_E_FILE_NOT_FOUND 0x80100024u
#define RDP_SESSION_SCARD_READER_TYPE_USB 0x00000020u
#define RDP_SESSION_MAX_SMARTCARD_CONTEXTS 8u
#define RDP_SESSION_MAX_SMARTCARD_HANDLES 32u
#ifndef RDP_HAVE_WINPR_SMARTCARD
#define RDP_SESSION_MAX_SMARTCARD_CACHE_ENTRIES 32u
#define RDP_SESSION_MAX_SMARTCARD_GROUPS 16u
#define RDP_SESSION_MAX_SMARTCARD_READER_GROUPS 32u
#endif
#define RDP_SESSION_SMARTCARD_BLOB_BYTES 8u
#define RDP_SESSION_SMARTCARD_MAX_IO_BYTES 65536u
#define RDP_SESSION_MAX_REDIRECTED_FILES 256u
#define RDP_SESSION_MAX_FILE_LOCKS RDP_FILESYSTEM_REDIRECTION_MAX_LOCKS
#define RDP_SESSION_MAX_FILE_IO_BYTES (4u * 1024u * 1024u)
#define RDP_SESSION_MAX_PNP_READ_BYTES 65536u
#define RDP_SESSION_FILE_DIRECTORY_FILE 0x00000001u
#define RDP_SESSION_FILE_DIRECTORY_INFORMATION 1u
#define RDP_SESSION_FILE_FULL_DIRECTORY_INFORMATION 2u
#define RDP_SESSION_FILE_BOTH_DIRECTORY_INFORMATION 3u
#define RDP_SESSION_FILE_BASIC_INFORMATION 4u
#define RDP_SESSION_FILE_STANDARD_INFORMATION 5u
#define RDP_SESSION_FILE_INTERNAL_INFORMATION 6u
#define RDP_SESSION_FILE_EA_INFORMATION 7u
#define RDP_SESSION_FILE_ACCESS_INFORMATION 8u
#define RDP_SESSION_FILE_NAME_INFORMATION 9u
#define RDP_SESSION_FILE_RENAME_INFORMATION 10u
#define RDP_SESSION_FILE_LINK_INFORMATION 11u
#define RDP_SESSION_FILE_NAMES_INFORMATION 12u
#define RDP_SESSION_FILE_DISPOSITION_INFORMATION 13u
#define RDP_SESSION_FILE_POSITION_INFORMATION 14u
#define RDP_SESSION_FILE_FULL_EA_INFORMATION 15u
#define RDP_SESSION_FILE_MODE_INFORMATION 16u
#define RDP_SESSION_FILE_ALIGNMENT_INFORMATION 17u
#define RDP_SESSION_FILE_ALL_INFORMATION 18u
#define RDP_SESSION_FILE_ALLOCATION_INFORMATION 19u
#define RDP_SESSION_FILE_END_OF_FILE_INFORMATION 20u
#define RDP_SESSION_FILE_ALTERNATE_NAME_INFORMATION 21u
#define RDP_SESSION_FILE_STREAM_INFORMATION 22u
#define RDP_SESSION_FILE_PIPE_INFORMATION 23u
#define RDP_SESSION_FILE_PIPE_LOCAL_INFORMATION 24u
#define RDP_SESSION_FILE_PIPE_REMOTE_INFORMATION 25u
#define RDP_SESSION_FILE_MAILSLOT_QUERY_INFORMATION 26u
#define RDP_SESSION_FILE_MAILSLOT_SET_INFORMATION 27u
#define RDP_SESSION_FILE_COMPRESSION_INFORMATION 28u
#define RDP_SESSION_FILE_OBJECT_ID_INFORMATION 29u
#define RDP_SESSION_FILE_MOVE_CLUSTER_INFORMATION 31u
#define RDP_SESSION_FILE_QUOTA_INFORMATION 32u
#define RDP_SESSION_FILE_REPARSE_POINT_INFORMATION 33u
#define RDP_SESSION_FILE_NETWORK_OPEN_INFORMATION 34u
#define RDP_SESSION_FILE_ATTRIBUTE_TAG_INFORMATION 35u
#define RDP_SESSION_FILE_TRACKING_INFORMATION 36u
#define RDP_SESSION_FILE_ID_BOTH_DIRECTORY_INFORMATION 37u
#define RDP_SESSION_FILE_ID_FULL_DIRECTORY_INFORMATION 38u
#define RDP_SESSION_FILE_VALID_DATA_LENGTH_INFORMATION 39u
#define RDP_SESSION_FILE_SHORT_NAME_INFORMATION 40u
#define RDP_SESSION_FILE_SFIO_RESERVE_INFORMATION 44u
#define RDP_SESSION_FILE_SFIO_VOLUME_INFORMATION 45u
#define RDP_SESSION_FILE_HARD_LINK_INFORMATION 46u
#define RDP_SESSION_FILE_NORMALIZED_NAME_INFORMATION 48u
#define RDP_SESSION_FILE_ID_GLOBAL_TX_DIRECTORY_INFORMATION 50u
#define RDP_SESSION_FILE_STANDARD_LINK_INFORMATION 54u
#define RDP_SESSION_FILE_ID_INFORMATION 59u
#define RDP_SESSION_FILE_ID_EXTD_DIRECTORY_INFORMATION 60u
#define RDP_SESSION_FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION 63u
#define RDP_SESSION_FILE_DISPOSITION_INFORMATION_EX 64u
#define RDP_SESSION_FILE_RENAME_INFORMATION_EX 65u
#define RDP_SESSION_FILE_CASE_SENSITIVE_INFORMATION 71u
#define RDP_SESSION_FILE_LINK_INFORMATION_EX 72u
#define RDP_SESSION_FILE_ID_64_EXTD_DIRECTORY_INFORMATION 78u
#define RDP_SESSION_FILE_ID_64_EXTD_BOTH_DIRECTORY_INFORMATION 79u
#define RDP_SESSION_FILE_ID_ALL_EXTD_DIRECTORY_INFORMATION 80u
#define RDP_SESSION_FILE_ID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION 81u
#define RDP_SESSION_FILE_ATTRIBUTE_READONLY 0x00000001u
#define RDP_SESSION_FILE_ATTRIBUTE_DIRECTORY 0x00000010u
#define RDP_SESSION_FILE_ATTRIBUTE_NORMAL 0x00000080u
#define RDP_SESSION_PORT_TYPE_NONE 0u
#define RDP_SESSION_PORT_TYPE_SERIAL 1u
#define RDP_SESSION_PORT_TYPE_PARALLEL 2u
#define RDP_SESSION_PRINTER_BACKEND_FILE 0u
#define RDP_SESSION_PRINTER_BACKEND_CUPS 1u
#define RDP_SESSION_GDI_PEN_SOLID 0u
#define RDP_SESSION_GDI_PEN_DASH 1u
#define RDP_SESSION_GDI_PEN_DOT 2u
#define RDP_SESSION_GDI_PEN_DASHDOT 3u
#define RDP_SESSION_GDI_PEN_DASHDOTDOT 4u
#define RDP_SESSION_GDI_PEN_NULL 5u
#define RDP_SESSION_GDI_PEN_INSIDEFRAME 6u
#define RDP_SESSION_GDI_BRUSH_SOLID 0u
#define RDP_SESSION_GDI_BRUSH_NULL 1u
#define RDP_SESSION_GDI_BRUSH_HATCHED 2u
#define RDP_SESSION_GDI_BRUSH_PATTERN 3u
#define RDP_SESSION_GDI_BRUSH_INDEXED 4u
#define RDP_SESSION_GDI_BRUSH_DIBPATTERN 5u
#define RDP_SESSION_GDI_BRUSH_DIBPATTERNPT 6u
#define RDP_SESSION_GDI_BRUSH_PATTERN8X8 7u
#define RDP_SESSION_GDI_BRUSH_DIBPATTERN8X8 8u
#define RDP_SESSION_USB_URB_HEADER_LENGTH 8u

typedef struct rdp_session_file_lock_range
{
    uint8_t active;
    uint8_t exclusive;
    uint64_t offset;
    uint64_t length;
} rdp_session_file_lock_range;

typedef struct rdp_session_redirected_file
{
    uint8_t active;
    uint32_t device_id;
    uint32_t file_id;
    int fd;
    uint8_t delete_pending;
    DIR* directory;
    char* path;
    char* directory_path;
    char* directory_pattern;
    uint32_t desired_access;
    uint32_t create_options;
    librdp_drive_policy drive_policy;
    uint32_t lock_count;
    rdp_session_file_lock_range locks[RDP_SESSION_MAX_FILE_LOCKS];
    uint8_t port_type;
    uint8_t printer_backend;
    uint32_t printer_index;
    uint32_t serial_baud_rate;
    uint32_t serial_wait_mask;
    uint32_t serial_timeouts[5];
    uint64_t serial_rx_count;
    uint64_t serial_tx_count;
    uint8_t serial_line_control[3];
    uint8_t serial_chars[6];
    uint8_t serial_handflow[16];
} rdp_session_redirected_file;

typedef struct rdp_session_drive_root
{
    uint8_t active;
    int fd;
    dev_t dev;
    ino_t ino;
} rdp_session_drive_root;

#ifdef RDP_HAVE_PCSC
typedef struct rdp_session_smartcard_context
{
    uint8_t active;
    uint32_t id;
    uint32_t generation;
    SCARDCONTEXT context;
} rdp_session_smartcard_context;

typedef struct rdp_session_smartcard_handle
{
    uint8_t active;
    uint32_t id;
    uint32_t generation;
    uint32_t context_id;
    uint32_t context_generation;
    SCARDHANDLE handle;
    DWORD active_protocol;
    uint32_t transmit_count;
} rdp_session_smartcard_handle;

#ifndef RDP_HAVE_WINPR_SMARTCARD
typedef struct rdp_session_smartcard_cache_entry
{
    uint8_t active;
    uint8_t card_identifier[RDP_SMARTCARD_REDIRECTION_CARD_IDENTIFIER_LENGTH];
    uint32_t freshness_counter;
    char* lookup_name;
    uint8_t* data;
    uint32_t data_len;
    uint64_t clock;
} rdp_session_smartcard_cache_entry;

typedef struct rdp_session_smartcard_group_entry
{
    uint8_t active;
    char* name;
} rdp_session_smartcard_group_entry;

typedef struct rdp_session_smartcard_reader_group_entry
{
    uint8_t active;
    char* reader;
    char* group;
} rdp_session_smartcard_reader_group_entry;
#endif
#endif

typedef struct rdp_session_dynamic_channel
{
    uint32_t channel_id;
    uint32_t generation;
    uint8_t channel_id_bytes;
    uint8_t priority;
    uint8_t active;
    uint8_t opening;
    uint8_t client_initiated;
    uint8_t fragmenting;
    uint32_t fragment_expected;
    rdp_buffer fragment;
    rdp_graphics_decompressor decompressor;
    char name[RDP_SESSION_DYNAMIC_CHANNEL_NAME_MAX];
} rdp_session_dynamic_channel;

typedef struct rdp_session_static_channel
{
    uint16_t channel_id;
    uint32_t flags;
    uint8_t active;
    uint8_t joined;
    uint8_t fragmenting;
    uint32_t fragment_expected;
    rdp_buffer fragment;
    char name[LIBRDP_STATIC_CHANNEL_NAME_MAX + 1u];
} rdp_session_static_channel;

typedef struct rdp_session_graphics_surface
{
    uint8_t active;
    uint8_t mapped;
    uint16_t surface_id;
    uint16_t width;
    uint16_t height;
    uint8_t pixel_format;
    uint32_t output_origin_x;
    uint32_t output_origin_y;
    uint32_t target_width;
    uint32_t target_height;
    uint8_t scaled;
    rdp_buffer pixels;
} rdp_session_graphics_surface;

typedef struct rdp_session_graphics_cache_entry
{
    uint8_t active;
    uint16_t cache_slot;
    uint16_t width;
    uint16_t height;
    uint64_t cache_key;
    rdp_buffer pixels;
} rdp_session_graphics_cache_entry;

typedef struct rdp_session_gdi_saved_bitmap
{
    uint8_t active;
    uint32_t bitmap_id;
    uint32_t width;
    uint32_t height;
    uint32_t origin_x;
    uint32_t origin_y;
    rdp_buffer pixels;
} rdp_session_gdi_saved_bitmap;

typedef struct rdp_session_gdi_offscreen_bitmap
{
    uint8_t active;
    uint32_t bitmap_id;
    librdp_surface* surface;
} rdp_session_gdi_offscreen_bitmap;

typedef struct rdp_session_gdi_stream_bitmap
{
    uint8_t active;
    uint32_t flags;
    uint32_t bits_per_pixel;
    uint32_t bitmap_type;
    uint32_t width;
    uint32_t height;
    uint32_t bitmap_size;
    rdp_buffer bitmap_data;
} rdp_session_gdi_stream_bitmap;

typedef struct rdp_session_gdi_gdiplus_stream
{
    uint8_t active;
    uint8_t cache_type;
    uint16_t cache_index;
    uint32_t total_size;
    uint32_t total_emf_size;
    rdp_buffer data;
} rdp_session_gdi_gdiplus_stream;

typedef struct rdp_session_gdi_gdiplus_cache_entry
{
    uint8_t active;
    uint8_t cache_type;
    uint16_t cache_index;
    uint32_t total_size;
    uint32_t total_emf_size;
    uint64_t last_used;
    rdp_buffer data;
} rdp_session_gdi_gdiplus_cache_entry;

typedef struct rdp_session_gdi_window_state
{
    uint8_t active;
    uint16_t order_size;
    uint32_t flags;
    uint64_t update_count;
    rdp_buffer data;
} rdp_session_gdi_window_state;

typedef struct rdp_session_gdi_bitmap_cache_entry
{
    uint8_t active;
    uint32_t cache_id;
    uint32_t cache_index;
    uint32_t width;
    uint32_t height;
    uint32_t bits_per_pixel;
    uint16_t bitmap_flags;
    size_t stride;
    uint64_t last_used;
    rdp_buffer pixels;
    rdp_buffer raw;
} rdp_session_gdi_bitmap_cache_entry;

typedef struct rdp_session_gdi_color_table_cache_entry
{
    uint8_t active;
    rdp_palette_update palette;
} rdp_session_gdi_color_table_cache_entry;

typedef struct rdp_session_gdi_brush_cache_entry
{
    uint8_t active;
    uint8_t mono;
    uint32_t cache_entry;
    uint32_t bitmap_format;
    uint8_t mono_rows[8];
    uint8_t bgra[8u * 8u * 4u];
} rdp_session_gdi_brush_cache_entry;

typedef struct rdp_session_gdi_ninegrid_cache_entry
{
    uint8_t active;
    uint32_t bitmap_id;
    uint32_t bits_per_pixel;
    rdp_gdi_ninegrid_bitmap_info info;
} rdp_session_gdi_ninegrid_cache_entry;

typedef struct rdp_session_gdi_glyph_cache_entry
{
    uint8_t active;
    uint32_t cache_id;
    uint32_t cache_index;
    int32_t x;
    int32_t y;
    uint32_t width;
    uint32_t height;
    rdp_buffer bitmap;
} rdp_session_gdi_glyph_cache_entry;

typedef struct rdp_session_gdi_glyph_fragment
{
    uint8_t active;
    rdp_buffer data;
} rdp_session_gdi_glyph_fragment;

typedef struct rdp_session_progressive_tile_cache
{
    uint8_t active;
    uint16_t surface_id;
    uint16_t x_idx;
    uint16_t y_idx;
    uint8_t has_pixels;
    uint32_t updated_frame_id;
    uint64_t last_used;
    rdp_rfx_progressive_tile_state* state;
    rdp_rfx_tile_pixels* pixels;
} rdp_session_progressive_tile_cache;

typedef struct rdp_session_pointer_cache_entry
{
    uint8_t active;
    librdp_pointer_event pointer;
    rdp_buffer pixels;
} rdp_session_pointer_cache_entry;

typedef struct rdp_session_video_stream
{
    uint8_t active;
    uint8_t presentation_id[16];
    uint32_t stream_id;
    uint64_t sample_count;
    uint64_t sample_bytes;
    uint64_t last_sample_start;
    uint64_t last_sample_end;
    uint64_t video_window_id;
    uint32_t width;
    uint32_t height;
    uint8_t paused;
    uint32_t flush_count;
    uint32_t preroll_count;
    uint32_t playback_rate_bits;
} rdp_session_video_stream;

typedef struct rdp_session_video_optimized_presentation
{
    uint8_t active;
    uint8_t presentation_id;
    uint8_t frame_rate;
    uint16_t average_bitrate_kbps;
    uint32_t source_width;
    uint32_t source_height;
    uint32_t scaled_width;
    uint32_t scaled_height;
    uint64_t timestamp_offset;
    uint64_t geometry_mapping_id;
    uint64_t sample_count;
    uint64_t sample_bytes;
    uint64_t last_timestamp;
    uint64_t last_duration;
    uint32_t last_sample_number;
    uint16_t last_packet_index;
    uint16_t last_packets_in_sample;
    uint8_t last_flags;
} rdp_session_video_optimized_presentation;

typedef struct rdp_session_clipboard_file_entry
{
    char* path;
    char* name;
    uint64_t size;
    rdp_buffer name_utf16;
} rdp_session_clipboard_file_entry;

typedef struct rdp_session_clipboard_file_request
{
    uint8_t active;
    uint32_t stream_id;
    int32_t file_index;
    uint32_t flags;
    uint64_t position;
    uint32_t requested;
} rdp_session_clipboard_file_request;

struct librdp_session
{
    librdp_settings* settings;
    librdp_limits limits;
    librdp_metrics metrics;
    librdp_surface* surface;
    rdp_transport transport;
    uint16_t mcs_user_id;
    uint16_t dynamic_channel_id;
    uint16_t clipboard_channel_id;
    uint8_t clipboard_ready;
    uint8_t clipboard_fragmenting;
    uint32_t clipboard_fragment_expected;
    uint32_t clipboard_general_flags;
    uint32_t clipboard_local_format_id;
    uint8_t clipboard_local_has_name;
    uint32_t clipboard_pending_request_format_id;
    uint8_t clipboard_local_available;
    rdp_buffer clipboard_fragment;
    rdp_buffer clipboard_local_data;
    rdp_buffer clipboard_local_format_name;
    uint8_t clipboard_local_files_available;
    uint32_t clipboard_local_file_count;
    rdp_session_clipboard_file_entry clipboard_local_files[RDP_SESSION_CLIPBOARD_MAX_LOCAL_FILES];
    rdp_session_clipboard_file_request clipboard_file_requests[RDP_SESSION_CLIPBOARD_MAX_PENDING_FILE_REQUESTS];
    uint32_t clipboard_remote_formats[RDP_SESSION_CLIPBOARD_MAX_FORMATS];
    uint32_t clipboard_remote_format_count;
    uint16_t audio_output_channel_id;
    uint8_t audio_output_ready;
    uint8_t audio_output_fragmenting;
    uint8_t audio_output_pending_wave;
    uint8_t audio_output_udp_active;
    uint8_t audio_output_udp_block_no;
    uint8_t audio_output_udp_peer_valid;
    uint8_t audio_output_crypt_seed_valid;
    int audio_output_udp_fd;
    uint16_t audio_output_udp_port;
    uint32_t audio_output_fragment_expected;
    uint16_t audio_output_server_version;
    uint16_t audio_output_client_version;
    uint16_t audio_output_pending_format_no;
    uint16_t audio_output_pending_timestamp;
    uint16_t audio_output_pending_expected_len;
    uint8_t audio_output_pending_block_no;
    uint16_t audio_output_udp_next_fragment_no;
    uint32_t audio_output_selected_format_count;
    librdp_audio_format audio_output_selected_formats[RDP_SESSION_AUDIO_OUTPUT_FORMAT_LIMIT];
    rdp_buffer audio_output_fragment;
    rdp_buffer audio_output_pending_data;
    rdp_buffer audio_output_udp_data;
    struct sockaddr_storage audio_output_udp_peer;
    socklen_t audio_output_udp_peer_len;
    uint8_t audio_output_crypt_seed[32];
    uint16_t device_redirection_channel_id;
    uint8_t device_redirection_ready;
    uint8_t device_redirection_fragmenting;
    uint16_t device_redirection_version_minor;
    uint32_t device_redirection_client_id;
    uint32_t device_redirection_fragment_expected;
    rdp_buffer device_redirection_fragment;
    uint16_t pnp_redirection_channel_id;
    uint8_t pnp_redirection_ready;
    uint8_t pnp_redirection_fragmenting;
    uint16_t pnp_redirection_io_version;
    uint8_t pnp_redirection_devices_sent;
    uint8_t pnp_redirection_open_device_active;
    uint32_t pnp_redirection_open_device_id;
    uint8_t pnp_redirection_storage_active;
    uint32_t pnp_redirection_storage_device_id;
    uint32_t pnp_redirection_fragment_expected;
    rdp_buffer pnp_redirection_fragment;
    rdp_buffer pnp_redirection_storage;
    uint16_t remote_programs_channel_id;
    uint8_t remote_programs_ready;
    uint8_t remote_programs_fragmenting;
    uint8_t remote_programs_exec_sent;
    uint32_t remote_programs_fragment_expected;
    rdp_buffer remote_programs_fragment;
    uint8_t fastpath_fragmenting;
    uint8_t fastpath_fragment_update_code;
    rdp_buffer fastpath_fragment;
    rdp_buffer fastpath_decompressed;
    rdp_buffer slowpath_decompressed;
    rdp_gdi_render_state gdi_render;
    uint8_t palette_valid;
    rdp_palette_update palette;
    uint32_t core_input_channel_id;
    uint8_t core_input_channel_id_bytes;
    uint8_t core_input_ready;
    uint32_t input_channel_id;
    uint8_t input_channel_id_bytes;
    uint8_t input_channel_ready;
    uint8_t input_channel_suspended;
    uint32_t input_channel_protocol_version;
    uint32_t input_channel_supported_features;
    uint16_t input_channel_max_touch_contacts;
    uint8_t input_channel_supports_pen;
    uint32_t display_control_channel_id;
    uint8_t display_control_channel_id_bytes;
    uint8_t display_control_ready;
    rdp_display_control_caps display_control_caps;
    uint32_t requested_desktop_width;
    uint32_t requested_desktop_height;
    uint8_t requested_monitor_layout_valid;
    uint32_t requested_monitor_count;
    rdp_display_control_monitor requested_monitors[LIBRDP_DISPLAY_MAX_MONITORS];
    uint32_t sent_desktop_width;
    uint32_t sent_desktop_height;
    uint32_t graphics_channel_id;
    uint8_t graphics_channel_id_bytes;
    uint8_t graphics_ready;
    uint32_t graphics_selected_version;
    uint32_t graphics_selected_flags;
    uint32_t graphics_frames_decoded;
    uint32_t graphics_frame_active;
    uint8_t graphics_dirty_pending;
    uint32_t graphics_dirty_left;
    uint32_t graphics_dirty_top;
    uint32_t graphics_dirty_right;
    uint32_t graphics_dirty_bottom;
    uint32_t mouse_cursor_channel_id;
    uint8_t mouse_cursor_channel_id_bytes;
    uint8_t mouse_cursor_ready;
    uint32_t audio_input_channel_id;
    uint8_t audio_input_channel_id_bytes;
    uint8_t audio_input_ready;
    uint8_t audio_input_open;
    uint8_t audio_input_open_reply_sent;
    uint32_t audio_input_version;
    uint32_t audio_input_selected_format_count;
    librdp_audio_format audio_input_selected_formats[RDP_SESSION_AUDIO_OUTPUT_FORMAT_LIMIT];
    uint32_t auth_redirection_channel_id;
    uint8_t auth_redirection_channel_id_bytes;
    uint8_t auth_redirection_ready;
    uint32_t webauthn_channel_id;
    uint8_t webauthn_channel_id_bytes;
    uint8_t webauthn_ready;
    uint8_t credssp_security_ready;
    rdp_ntlm_security_context credssp_security;
    uint32_t composited_channel_id;
    uint8_t composited_channel_id_bytes;
    uint8_t composited_ready;
    uint8_t composited_connection_open;
    uint32_t composited_connection_id;
    uint32_t composited_open_channel_id;
    uint32_t video_redirection_channel_id;
    uint8_t video_redirection_channel_id_bytes;
    uint8_t video_redirection_ready;
    uint8_t video_redirection_capabilities_sent;
    uint8_t video_redirection_rim_sent;
    uint32_t video_optimized_control_channel_id;
    uint8_t video_optimized_control_channel_id_bytes;
    uint8_t video_optimized_control_ready;
    uint32_t video_optimized_data_channel_id;
    uint8_t video_optimized_data_channel_id_bytes;
    uint32_t video_capture_control_channel_id;
    uint8_t video_capture_control_channel_id_bytes;
    uint32_t video_capture_channel_id;
    uint8_t video_capture_channel_id_bytes;
    uint8_t video_capture_version;
    uint8_t video_capture_active;
    uint8_t video_capture_streaming;
    uint8_t video_capture_selected_stream;
    uint8_t video_capture_sample_reply_pending;
    rdp_video_capture_media_type video_capture_media;
    uint8_t video_capture_brightness_mode;
    int32_t video_capture_brightness;
    uint32_t usb_redirection_channel_id;
    uint8_t usb_redirection_channel_id_bytes;
    uint8_t usb_redirection_ready;
    uint8_t usb_request_completion_ready;
    uint32_t usb_message_id;
    uint32_t usb_request_completion_interface_id;
    uint32_t usb_device_count_sent;
    uint32_t telemetry_channel_id;
    uint8_t telemetry_channel_id_bytes;
    uint8_t telemetry_ready;
    uint16_t multiparty_channel_id;
    uint8_t multiparty_joined;
    uint8_t desktop_composition_active;
    uint32_t video_geometry_update_count;
    rdp_license_client_state license_state;
    rdp_license_crypto_context license_crypto;
    uint8_t multitransport_negotiated;
    uint32_t multitransport_flags;
    uint8_t multitransport_udp_active;
    uint8_t multitransport_udp2_active;
    uint32_t multitransport_soft_sync_count;
    rdp_graphics_decompressor graphics_decompressor;
    rdp_graphics_decompressor bulk_rdp8_decompressor;
    rdp_bulk_decompressor bulk_decompressor;
    rdp_clearcodec_context clearcodec;
    rdp_nscodec_context surface_nscodec;
    rdp_avc_decoder* avc;
    rdp_session_graphics_surface graphics_surfaces[RDP_SESSION_MAX_GRAPHICS_SURFACES];
    rdp_session_graphics_cache_entry graphics_cache[RDP_SESSION_GRAPHICS_CACHE_SLOTS];
    rdp_session_gdi_bitmap_cache_entry gdi_bitmap_cache[RDP_SESSION_GDI_BITMAP_CACHE_SLOTS];
    rdp_session_gdi_color_table_cache_entry gdi_color_table_cache[RDP_SESSION_GDI_COLOR_TABLE_SLOTS];
    rdp_session_gdi_brush_cache_entry gdi_brush_cache[RDP_SESSION_GDI_BRUSH_CACHE_SLOTS];
    rdp_session_gdi_ninegrid_cache_entry gdi_ninegrid_cache[RDP_SESSION_GDI_NINEGRID_CACHE_SLOTS];
    rdp_session_gdi_glyph_cache_entry gdi_glyph_cache[RDP_SESSION_GDI_GLYPH_CACHE_IDS][RDP_SESSION_GDI_GLYPH_CACHE_SLOTS];
    rdp_session_gdi_glyph_fragment gdi_glyph_fragments[RDP_SESSION_GDI_GLYPH_FRAGMENT_SLOTS];
    rdp_session_gdi_saved_bitmap gdi_saved_bitmaps[RDP_SESSION_GDI_SAVE_BITMAP_SLOTS];
    rdp_session_gdi_offscreen_bitmap gdi_offscreen_cache[RDP_SESSION_GDI_OFFSCREEN_CACHE_SLOTS];
    rdp_session_gdi_gdiplus_cache_entry gdi_gdiplus_cache[RDP_SESSION_GDI_GDIPLUS_CACHE_SLOTS];
    rdp_session_progressive_tile_cache progressive_tiles[RDP_SESSION_PROGRESSIVE_TILE_STATES];
    rdp_session_pointer_cache_entry pointer_cache[RDP_SESSION_POINTER_CACHE_SLOTS];
    rdp_composited_render_tree composited_tree;
    rdp_session_video_stream video_streams[RDP_SESSION_VIDEO_STREAMS];
    rdp_session_video_optimized_presentation video_optimized_presentations[RDP_SESSION_VIDEO_OPTIMIZED_PRESENTATIONS];
    rdp_session_redirected_file redirected_files[RDP_SESSION_MAX_REDIRECTED_FILES];
    rdp_printer_backend printer_backend;
    rdp_session_drive_root drive_roots[LIBRDP_SETTINGS_MAX_DRIVES];
    char drive_volume_labels[LIBRDP_SETTINGS_MAX_DRIVES][RDP_SESSION_VOLUME_LABEL_MAX_BYTES];
    uint8_t drive_volume_label_set[LIBRDP_SETTINGS_MAX_DRIVES];
#ifdef RDP_HAVE_PCSC
    rdp_session_smartcard_context smartcard_contexts[RDP_SESSION_MAX_SMARTCARD_CONTEXTS];
    rdp_session_smartcard_handle smartcard_handles[RDP_SESSION_MAX_SMARTCARD_HANDLES];
    rdp_smartcard_backend smartcard_backend;
#ifndef RDP_HAVE_WINPR_SMARTCARD
    rdp_session_smartcard_cache_entry smartcard_cache[RDP_SESSION_MAX_SMARTCARD_CACHE_ENTRIES];
    rdp_session_smartcard_group_entry smartcard_groups[RDP_SESSION_MAX_SMARTCARD_GROUPS];
    rdp_session_smartcard_reader_group_entry smartcard_reader_groups[RDP_SESSION_MAX_SMARTCARD_READER_GROUPS];
#endif
#endif
#ifdef RDP_HAVE_LIBUSB
    libusb_context* usb_libusb;
    rdp_usb_backend_device usb_devices[LIBRDP_SETTINGS_MAX_USB_DEVICES];
    rdp_session_usb_worker* usb_worker;
#endif
    uint32_t next_redirected_file_id;
#ifdef RDP_HAVE_PCSC
    uint32_t next_smartcard_context_id;
    uint32_t next_smartcard_handle_id;
#ifndef RDP_HAVE_WINPR_SMARTCARD
    uint64_t smartcard_cache_clock;
#endif
#endif
    uint64_t progressive_tile_clock;
    size_t graphics_cache_bytes;
    uint64_t gdi_bitmap_cache_clock;
    size_t gdi_bitmap_cache_bytes;
    size_t gdi_glyph_cache_bytes;
    size_t gdi_saved_bitmap_bytes;
    uint32_t gdi_current_surface_id;
    uint8_t gdi_drawing_to_offscreen;
    rdp_session_gdi_stream_bitmap gdi_stream_bitmap;
    rdp_session_gdi_gdiplus_stream gdi_gdiplus_stream;
    rdp_session_gdi_window_state gdi_window_state;
    uint64_t gdi_gdiplus_cache_clock;
    size_t gdi_gdiplus_cache_bytes;
    uint64_t gdi_gdiplus_draw_count;
    uint32_t graphics_current_frame_id;
    rdp_session_dynamic_channel dynamic_channels[RDP_SESSION_MAX_DYNAMIC_CHANNELS];
    librdp_echo_stats echo_stats;
    rdp_buffer echo_pending_payload;
    uint64_t echo_next_sequence;
    uint64_t echo_pending_sequence;
    uint64_t echo_pending_sent_ns;
    uint32_t echo_pending_timeout_ms;
    uint8_t echo_pending;
    uint32_t next_dynamic_channel_id;
    uint32_t static_channel_count;
    rdp_session_static_channel static_channels[LIBRDP_SETTINGS_MAX_STATIC_CHANNELS];
    rdp_standard_security_context standard_security;
    uint32_t share_id;
    librdp_session_state state;
    librdp_session_lifecycle lifecycle;
    uint64_t activation_deadline_ns;
    librdp_error last_error;
    pthread_mutex_t owner_mutex;
    pthread_mutex_t transport_cancel_mutex;
    pthread_t owner_thread;
    uint8_t owner_thread_valid;
    uint8_t transport_cancel_ready;
    short pending_tcp_revents;
    short pending_wakeup_revents;
    short pending_udp_revents;
    uint8_t pending_poll;
    int wakeup_pipe[2];
    atomic_uint cancel_requested;
    uint8_t standard_security_active;
    librdp_event_callback callback;
    void* callback_data;
    librdp_event_envelope_callback envelope_callback;
    void* envelope_callback_data;
    librdp_domain_event_callback graphics_callback;
    void* graphics_callback_data;
    librdp_domain_event_callback pointer_callback;
    void* pointer_callback_data;
    librdp_domain_event_callback channel_callback;
    void* channel_callback_data;
    librdp_domain_event_callback clipboard_callback;
    void* clipboard_callback_data;
    librdp_domain_event_callback audio_callback;
    void* audio_callback_data;
    librdp_domain_event_callback video_callback;
    void* video_callback_data;
    librdp_graphics_update_callback graphics_update_callback;
    void* graphics_update_callback_data;
    uint8_t trace_policy_configured;
    librdp_trace_policy trace_policy;
    char* trace_file_path;
    char* trace_session_id;
    char* trace_connection_id;
    char* trace_id;
    FILE* trace_file;
    uint64_t trace_sequence;
    uint64_t trace_first_ns;
};


#include "client/session_runtime.h"
#include "client/session_lifecycle.h"
#include "client/session_device.h"
#include "client/session_filesystem.h"
#include "client/session_ports.h"
#include "client/session_printer.h"
#include "client/session_smartcard.h"
#include "client/session_usb.h"
#include "client/session_audio.h"
#include "client/session_video.h"
#include "client/session_camera.h"
#include "client/session_protocol_io.h"
#include "client/session_activation.h"
#include "client/session_channels.h"
#include "client/session_graphics.h"
#include "client/session_graphics_pipeline.h"
#include "client/session_gdi.h"
#include "client/session_input.h"
#include "client/session_clipboard.h"

#endif
