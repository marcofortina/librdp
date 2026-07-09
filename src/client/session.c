#include <librdp/session.h>
#include <librdp/video.h>

#include "channels/audio_format.h"
#include "channels/audio_input.h"
#include "channels/audio_output.h"
#include "channels/composited_remoting.h"
#include "channels/core_input.h"
#include "channels/device_redirection.h"
#include "channels/display_control.h"
#include "channels/dynamic_channel.h"
#include "channels/filesystem_redirection.h"
#include "channels/graphics_pipeline.h"
#include "channels/input_channel.h"
#include "channels/mouse_cursor.h"
#include "channels/pnp_redirection.h"
#include "channels/port_redirection.h"
#include "channels/printer_redirection.h"
#include "channels/remote_programs.h"
#include "channels/smartcard_redirection.h"
#include "channels/usb_redirection.h"
#include "channels/video_capture.h"
#include "channels/video_redirection.h"
#include "channels/virtual_channel.h"
#include "channels/webauthn_channel.h"
#include "client/settings_internal.h"
#include "clipboard/clipboard.h"
#include "common/stream.h"
#include "common/trace.h"
#include "graphics/avc.h"
#include "graphics/bitmap.h"
#include "graphics/clearcodec.h"
#include "graphics/planar.h"
#include "graphics/rfx_codec.h"
#include "licensing/licensing.h"
#include "nla/credssp.h"
#include "protocol/fastpath.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/pointer.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"
#include "transport/transport.h"
#include "input/input.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#ifdef RDP_HAVE_PCSC
#include <winscard.h>
#endif
#ifdef RDP_HAVE_LIBUSB
#include <libusb-1.0/libusb.h>
#endif

#define RDP_SESSION_MAX_DYNAMIC_CHANNELS 64u
#define RDP_SESSION_DYNAMIC_CHANNEL_NAME_MAX 96u
#define RDP_SESSION_MAX_DYNAMIC_MESSAGE (64u * 1024u * 1024u)
#define RDP_SESSION_MAX_FASTPATH_FRAGMENT (16u * 1024u * 1024u)
#define RDP_SESSION_MAX_GRAPHICS_SURFACES 64u
#define RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION 8192u
#define RDP_SESSION_GRAPHICS_CACHE_SLOTS 4096u
#define RDP_SESSION_GRAPHICS_CACHE_MAX_BYTES (16u * 1024u * 1024u)
#define RDP_SESSION_PROGRESSIVE_TILE_STATES 2048u
#define RDP_SESSION_POINTER_CACHE_SLOTS 128u
#define RDP_SESSION_VIDEO_STREAMS 32u
#define RDP_SESSION_VIDEO_CAPTURE_DEFAULT_WIDTH 640u
#define RDP_SESSION_VIDEO_CAPTURE_DEFAULT_HEIGHT 480u
#define RDP_SESSION_VIDEO_CAPTURE_DEFAULT_FPS 30u
#define RDP_SESSION_CLIPBOARD_MAX_FORMATS 64u
#define RDP_SESSION_DISPLAY_CONTROL_NAME "Microsoft::Windows::RDS::DisplayControl"
#define RDP_SESSION_CORE_INPUT_NAME "Microsoft::Windows::RDS::CoreInput"
#define RDP_SESSION_INPUT_CHANNEL_NAME "Microsoft::Windows::RDS::Input"
#define RDP_SESSION_GRAPHICS_PIPELINE_NAME "Microsoft::Windows::RDS::Graphics"
#define RDP_SESSION_MOUSE_CURSOR_NAME "Microsoft::Windows::RDS::MouseCursor"
#define RDP_SESSION_WEBAUTHN_CHANNEL_NAME "WebAuthN_Channel"
#define RDP_SESSION_USB_REDIRECTION_CHANNEL_NAME "urbdrc"
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
#define RDP_SESSION_DEVICE_LOCK_NOT_GRANTED 0xc0000054u
#define RDP_SESSION_DEVICE_NO_MORE_FILES 0x80000006u
#define RDP_SESSION_DEVICE_TOO_MANY_OPENED_FILES 0xc000011fu
#define RDP_SESSION_DEVICE_UNSUCCESSFUL 0xc0000001u
#define RDP_SESSION_DEVICE_PRINT_QUEUE_FULL 0xc00000c6u
#define RDP_SESSION_SCARD_SUCCESS 0x00000000u
#define RDP_SESSION_SCARD_E_INVALID_HANDLE 0x80100003u
#define RDP_SESSION_SCARD_E_INVALID_PARAMETER 0x80100004u
#define RDP_SESSION_SCARD_E_NO_SERVICE 0x8010001du
#define RDP_SESSION_SCARD_E_NO_MEMORY 0x80100006u
#define RDP_SESSION_SCARD_E_UNSUPPORTED_FEATURE 0x8010001fu
#define RDP_SESSION_MAX_SMARTCARD_CONTEXTS 8u
#define RDP_SESSION_MAX_SMARTCARD_HANDLES 32u
#define RDP_SESSION_SMARTCARD_BLOB_BYTES 8u
#define RDP_SESSION_SMARTCARD_MAX_IO_BYTES 65536u
#define RDP_SESSION_MAX_REDIRECTED_FILES 256u
#define RDP_SESSION_MAX_FILE_IO_BYTES (4u * 1024u * 1024u)
#define RDP_SESSION_FILE_DIRECTORY_FILE 0x00000001u
#define RDP_SESSION_FILE_DIRECTORY_INFORMATION 1u
#define RDP_SESSION_FILE_FULL_DIRECTORY_INFORMATION 2u
#define RDP_SESSION_FILE_BOTH_DIRECTORY_INFORMATION 3u
#define RDP_SESSION_FILE_BASIC_INFORMATION 4u
#define RDP_SESSION_FILE_STANDARD_INFORMATION 5u
#define RDP_SESSION_FILE_RENAME_INFORMATION 10u
#define RDP_SESSION_FILE_NAMES_INFORMATION 12u
#define RDP_SESSION_FILE_DISPOSITION_INFORMATION 13u
#define RDP_SESSION_FILE_ALLOCATION_INFORMATION 19u
#define RDP_SESSION_FILE_END_OF_FILE_INFORMATION 20u
#define RDP_SESSION_FILE_ATTRIBUTE_TAG_INFORMATION 35u
#define RDP_SESSION_FILE_FS_VOLUME_INFORMATION 1u
#define RDP_SESSION_FILE_FS_SIZE_INFORMATION 3u
#define RDP_SESSION_FILE_FS_DEVICE_INFORMATION 4u
#define RDP_SESSION_FILE_FS_ATTRIBUTE_INFORMATION 5u
#define RDP_SESSION_FILE_FS_FULL_SIZE_INFORMATION 7u
#define RDP_SESSION_FILE_ATTRIBUTE_READONLY 0x00000001u
#define RDP_SESSION_FILE_ATTRIBUTE_DIRECTORY 0x00000010u
#define RDP_SESSION_FILE_ATTRIBUTE_NORMAL 0x00000080u
#define RDP_SESSION_FILE_CASE_SENSITIVE_SEARCH 0x00000001u
#define RDP_SESSION_FILE_CASE_PRESERVED_NAMES 0x00000002u
#define RDP_SESSION_FILE_UNICODE_ON_DISK 0x00000004u
#define RDP_SESSION_FILE_DEVICE_DISK 0x00000007u
#define RDP_SESSION_PORT_TYPE_NONE 0u
#define RDP_SESSION_PORT_TYPE_SERIAL 1u
#define RDP_SESSION_PORT_TYPE_PARALLEL 2u

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
    uint8_t port_type;
    uint32_t serial_baud_rate;
    uint32_t serial_wait_mask;
    uint32_t serial_timeouts[5];
    uint8_t serial_line_control[3];
    uint8_t serial_chars[6];
    uint8_t serial_handflow[16];
} rdp_session_redirected_file;

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
} rdp_session_smartcard_handle;
#endif

typedef struct rdp_session_dynamic_channel
{
    uint32_t channel_id;
    uint8_t channel_id_bytes;
    uint8_t active;
    uint8_t fragmenting;
    uint32_t fragment_expected;
    rdp_buffer fragment;
    rdp_graphics_decompressor decompressor;
    char name[RDP_SESSION_DYNAMIC_CHANNEL_NAME_MAX];
} rdp_session_dynamic_channel;

#ifdef RDP_HAVE_LIBUSB
typedef struct rdp_session_usb_device
{
    uint8_t active;
    uint32_t interface_id;
    libusb_device_handle* handle;
    struct libusb_device_descriptor descriptor;
    uint8_t bus_number;
    uint8_t device_address;
} rdp_session_usb_device;
#endif

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
} rdp_session_video_stream;

struct librdp_session
{
    librdp_settings* settings;
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
    uint32_t clipboard_pending_request_format_id;
    uint8_t clipboard_local_available;
    rdp_buffer clipboard_fragment;
    rdp_buffer clipboard_local_data;
    uint32_t clipboard_remote_formats[RDP_SESSION_CLIPBOARD_MAX_FORMATS];
    uint32_t clipboard_remote_format_count;
    uint16_t audio_output_channel_id;
    uint8_t audio_output_ready;
    uint8_t audio_output_fragmenting;
    uint8_t audio_output_pending_wave;
    uint32_t audio_output_fragment_expected;
    uint16_t audio_output_server_version;
    uint16_t audio_output_client_version;
    uint16_t audio_output_pending_format_no;
    uint16_t audio_output_pending_timestamp;
    uint16_t audio_output_pending_expected_len;
    uint8_t audio_output_pending_block_no;
    uint32_t audio_output_selected_format_count;
    librdp_audio_format audio_output_selected_formats[RDP_SESSION_AUDIO_OUTPUT_FORMAT_LIMIT];
    rdp_buffer audio_output_fragment;
    rdp_buffer audio_output_pending_data;
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
    uint32_t pnp_redirection_fragment_expected;
    rdp_buffer pnp_redirection_fragment;
    uint16_t remote_programs_channel_id;
    uint8_t remote_programs_ready;
    uint8_t remote_programs_fragmenting;
    uint8_t remote_programs_exec_sent;
    uint32_t remote_programs_fragment_expected;
    rdp_buffer remote_programs_fragment;
    uint8_t fastpath_fragmenting;
    uint8_t fastpath_fragment_update_code;
    rdp_buffer fastpath_fragment;
    uint32_t core_input_channel_id;
    uint8_t core_input_channel_id_bytes;
    uint8_t core_input_ready;
    uint32_t input_channel_id;
    uint8_t input_channel_id_bytes;
    uint8_t input_channel_ready;
    uint8_t input_channel_suspended;
    uint32_t input_channel_protocol_version;
    uint32_t input_channel_supported_features;
    uint32_t display_control_channel_id;
    uint8_t display_control_channel_id_bytes;
    uint8_t display_control_ready;
    rdp_display_control_caps display_control_caps;
    uint32_t requested_desktop_width;
    uint32_t requested_desktop_height;
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
    uint32_t usb_redirection_channel_id;
    uint8_t usb_redirection_channel_id_bytes;
    uint8_t usb_redirection_ready;
    uint8_t usb_request_completion_ready;
    uint32_t usb_message_id;
    uint32_t usb_request_completion_interface_id;
    uint32_t usb_device_count_sent;
    rdp_graphics_decompressor graphics_decompressor;
    rdp_clearcodec_context clearcodec;
    rdp_avc_decoder* avc;
    rdp_session_graphics_surface graphics_surfaces[RDP_SESSION_MAX_GRAPHICS_SURFACES];
    rdp_session_graphics_cache_entry graphics_cache[RDP_SESSION_GRAPHICS_CACHE_SLOTS];
    rdp_session_progressive_tile_cache progressive_tiles[RDP_SESSION_PROGRESSIVE_TILE_STATES];
    rdp_session_pointer_cache_entry pointer_cache[RDP_SESSION_POINTER_CACHE_SLOTS];
    rdp_composited_render_tree composited_tree;
    rdp_session_video_stream video_streams[RDP_SESSION_VIDEO_STREAMS];
    rdp_session_redirected_file redirected_files[RDP_SESSION_MAX_REDIRECTED_FILES];
#ifdef RDP_HAVE_PCSC
    rdp_session_smartcard_context smartcard_contexts[RDP_SESSION_MAX_SMARTCARD_CONTEXTS];
    rdp_session_smartcard_handle smartcard_handles[RDP_SESSION_MAX_SMARTCARD_HANDLES];
#endif
#ifdef RDP_HAVE_LIBUSB
    libusb_context* usb_libusb;
    rdp_session_usb_device usb_devices[LIBRDP_SETTINGS_MAX_USB_DEVICES];
#endif
    uint32_t next_redirected_file_id;
#ifdef RDP_HAVE_PCSC
    uint32_t next_smartcard_context_id;
    uint32_t next_smartcard_handle_id;
#endif
    uint64_t progressive_tile_clock;
    size_t graphics_cache_bytes;
    uint32_t graphics_current_frame_id;
    rdp_session_dynamic_channel dynamic_channels[RDP_SESSION_MAX_DYNAMIC_CHANNELS];
    rdp_standard_security_context standard_security;
    uint32_t share_id;
    librdp_session_state state;
    uint8_t standard_security_active;
    librdp_event_callback callback;
    void* callback_data;
};

static void rdp_session_emit(librdp_session* session, const librdp_event* event)
{
    if (session && session->callback && event)
        session->callback(session, event, session->callback_data);
}

static void rdp_session_set_state(librdp_session* session, librdp_session_state state)
{
    librdp_event event;
    librdp_session_state old_state = LIBRDP_SESSION_IDLE;

    if (!session || session->state == state)
        return;

    old_state = session->state;
    session->state = state;

    event.type = LIBRDP_EVENT_STATE_CHANGED;
    event.data.state.old_state = (int)old_state;
    event.data.state.new_state = (int)state;
    rdp_session_emit(session, &event);
}

static librdp_status rdp_session_fail(librdp_session* session, librdp_status status)
{
    librdp_event event;

    rdp_session_set_state(session, LIBRDP_SESSION_FAILED);
    event.type = LIBRDP_EVENT_ERROR;
    event.data.error.status = status;
    rdp_session_emit(session, &event);
    return status;
}

static void rdp_session_composited_reset(librdp_session* session)
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

static void rdp_session_video_redirection_reset(librdp_session* session)
{
    if (!session)
        return;
    session->video_redirection_channel_id = 0;
    session->video_redirection_channel_id_bytes = 0;
    session->video_redirection_ready = 0;
    session->video_redirection_capabilities_sent = 0;
    session->video_redirection_rim_sent = 0;
    memset(session->video_streams, 0, sizeof(session->video_streams));
}

static void rdp_session_video_capture_reset(librdp_session* session)
{
    if (!session)
        return;
    session->video_capture_control_channel_id = 0;
    session->video_capture_control_channel_id_bytes = 0;
    session->video_capture_channel_id = 0;
    session->video_capture_channel_id_bytes = 0;
    session->video_capture_version = 0;
    session->video_capture_active = 0;
    session->video_capture_streaming = 0;
    session->video_capture_selected_stream = 0;
    session->video_capture_sample_reply_pending = 0;
    memset(&session->video_capture_media, 0, sizeof(session->video_capture_media));
}

static rdp_session_video_stream* rdp_session_video_stream_find(librdp_session* session,
                                                               const uint8_t presentation_id[16],
                                                               uint32_t stream_id)
{
    uint32_t i = 0;

    if (!session || !presentation_id)
        return NULL;
    for (i = 0; i < RDP_SESSION_VIDEO_STREAMS; i++)
    {
        if (session->video_streams[i].active &&
            session->video_streams[i].stream_id == stream_id &&
            memcmp(session->video_streams[i].presentation_id, presentation_id, 16u) == 0)
            return &session->video_streams[i];
    }
    return NULL;
}

static rdp_session_video_stream* rdp_session_video_stream_upsert(librdp_session* session,
                                                                 const uint8_t presentation_id[16],
                                                                 uint32_t stream_id)
{
    uint32_t i = 0;
    rdp_session_video_stream* entry = rdp_session_video_stream_find(session, presentation_id, stream_id);

    if (entry)
        return entry;
    if (!session || !presentation_id)
        return NULL;
    for (i = 0; i < RDP_SESSION_VIDEO_STREAMS; i++)
    {
        if (!session->video_streams[i].active)
        {
            memset(&session->video_streams[i], 0, sizeof(session->video_streams[i]));
            session->video_streams[i].active = 1;
            session->video_streams[i].stream_id = stream_id;
            memcpy(session->video_streams[i].presentation_id, presentation_id, 16u);
            return &session->video_streams[i];
        }
    }
    return NULL;
}

static void rdp_session_video_stream_remove(librdp_session* session,
                                            const uint8_t presentation_id[16],
                                            uint32_t stream_id)
{
    rdp_session_video_stream* entry = rdp_session_video_stream_find(session, presentation_id, stream_id);

    if (entry)
        memset(entry, 0, sizeof(*entry));
}

static void rdp_session_emit_surface_invalidated(librdp_session* session,
                                                 uint32_t x,
                                                 uint32_t y,
                                                 uint32_t width,
                                                 uint32_t height)
{
    librdp_event event;

    if (!session || width == 0 || height == 0)
        return;
    event.type = LIBRDP_EVENT_SURFACE_INVALIDATED;
    event.data.surface.x = x;
    event.data.surface.y = y;
    event.data.surface.width = width;
    event.data.surface.height = height;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.surface.invalidated",
                    "x=%u y=%u width=%u height=%u output_width=%u output_height=%u frame_id=%u frame_active=%u",
                    x,
                    y,
                    width,
                    height,
                    librdp_surface_width(session->surface),
                    librdp_surface_height(session->surface),
                    session->graphics_current_frame_id,
                    session->graphics_frame_active ? 1u : 0u);
}

static void rdp_session_graphics_dirty_reset(librdp_session* session)
{
    if (!session)
        return;
    session->graphics_frame_active = 0;
    session->graphics_dirty_pending = 0;
    session->graphics_dirty_left = 0;
    session->graphics_dirty_top = 0;
    session->graphics_dirty_right = 0;
    session->graphics_dirty_bottom = 0;
    session->graphics_current_frame_id = 0;
}

static void rdp_session_graphics_dirty_add(librdp_session* session,
                                           uint32_t x,
                                           uint32_t y,
                                           uint32_t width,
                                           uint32_t height)
{
    uint32_t right = 0;
    uint32_t bottom = 0;

    if (!session || width == 0 || height == 0)
        return;
    if (!session->graphics_frame_active)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.graphics.dirty.immediate",
                              "x=%u y=%u width=%u height=%u frame_id=%u",
                              x,
                              y,
                              width,
                              height,
                              session->graphics_current_frame_id);
        rdp_session_emit_surface_invalidated(session, x, y, width, height);
        return;
    }

    right = x + width;
    bottom = y + height;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.frame.dirty.add",
                          "frame_id=%u x=%u y=%u width=%u height=%u pending=%u previous_left=%u previous_top=%u previous_right=%u previous_bottom=%u",
                          session->graphics_current_frame_id,
                          x,
                          y,
                          width,
                          height,
                          session->graphics_dirty_pending ? 1u : 0u,
                          session->graphics_dirty_left,
                          session->graphics_dirty_top,
                          session->graphics_dirty_right,
                          session->graphics_dirty_bottom);
    if (!session->graphics_dirty_pending)
    {
        session->graphics_dirty_pending = 1;
        session->graphics_dirty_left = x;
        session->graphics_dirty_top = y;
        session->graphics_dirty_right = right;
        session->graphics_dirty_bottom = bottom;
        return;
    }
    if (x < session->graphics_dirty_left)
        session->graphics_dirty_left = x;
    if (y < session->graphics_dirty_top)
        session->graphics_dirty_top = y;
    if (right > session->graphics_dirty_right)
        session->graphics_dirty_right = right;
    if (bottom > session->graphics_dirty_bottom)
        session->graphics_dirty_bottom = bottom;
}

static void rdp_session_graphics_dirty_flush(librdp_session* session)
{
    if (!session || !session->graphics_dirty_pending)
        return;
    rdp_session_emit_surface_invalidated(session,
                                         session->graphics_dirty_left,
                                         session->graphics_dirty_top,
                                         session->graphics_dirty_right - session->graphics_dirty_left,
                                         session->graphics_dirty_bottom - session->graphics_dirty_top);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.graphics.frame.flush",
                          "frame_id=%u x=%u y=%u width=%u height=%u",
                          session->graphics_current_frame_id,
                          session->graphics_dirty_left,
                          session->graphics_dirty_top,
                          session->graphics_dirty_right - session->graphics_dirty_left,
                          session->graphics_dirty_bottom - session->graphics_dirty_top);
    session->graphics_dirty_pending = 0;
}

static void rdp_session_pointer_cache_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_POINTER_CACHE_SLOTS; i++)
        rdp_buffer_free(&session->pointer_cache[i].pixels);
    memset(session->pointer_cache, 0, sizeof(session->pointer_cache));
}

static size_t rdp_session_pointer_mask_stride(uint16_t width)
{
    return (((size_t)width + 15u) / 16u) * 2u;
}

static size_t rdp_session_pointer_xor_stride(uint16_t width, uint16_t bpp)
{
    return ((((size_t)width * bpp) + 15u) / 16u) * 2u;
}

static int rdp_session_pointer_mask_bit(const uint8_t* data,
                                        size_t stride,
                                        uint16_t width,
                                        uint16_t height,
                                        uint16_t x,
                                        uint16_t y)
{
    size_t row = (size_t)(height - 1u - y);
    size_t offset = row * stride + ((size_t)x / 8u);
    uint8_t mask = (uint8_t)(0x80u >> (x % 8u));

    if (!data || x >= width || y >= height)
        return 0;
    return (data[offset] & mask) != 0;
}

static uint64_t rdp_session_pointer_hash_bytes(const uint8_t* data, size_t length)
{
    uint64_t hash = 1469598103934665603ull;
    size_t i = 0;

    if (!data)
        return 0;
    for (i = 0; i < length; i++)
    {
        hash ^= data[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

static int rdp_session_pointer_xor_pixel_nonzero(const rdp_pointer_update* update,
                                                 size_t xor_stride,
                                                 uint16_t x,
                                                 uint16_t y)
{
    const uint8_t* row = NULL;
    const uint8_t* pixel = NULL;

    if (!update || !update->xor_mask)
        return 0;
    if (update->xor_bpp == 1u)
        return rdp_session_pointer_mask_bit(update->xor_mask,
                                            xor_stride,
                                            update->width,
                                            update->height,
                                            x,
                                            y);
    row = update->xor_mask + ((size_t)(update->height - 1u - y) * xor_stride);
    if (update->xor_bpp == 24u)
    {
        pixel = row + ((size_t)x * 3u);
        return pixel[0] != 0 || pixel[1] != 0 || pixel[2] != 0;
    }
    if (update->xor_bpp == 32u)
    {
        pixel = row + ((size_t)x * 4u);
        return pixel[0] != 0 || pixel[1] != 0 || pixel[2] != 0 || pixel[3] != 0;
    }
    return 0;
}

static void rdp_session_pointer_trace_shape(const rdp_pointer_update* update,
                                            const rdp_buffer* decoded,
                                            size_t decoded_stride)
{
    uint32_t and_set = 0;
    uint32_t xor_nonzero = 0;
    uint32_t invert_like = 0;
    uint32_t decoded_opaque = 0;
    uint32_t decoded_transparent = 0;
    uint32_t decoded_rgb_nonzero = 0;
    uint32_t decoded_alpha_nonzero = 0;
    uint32_t has_alpha = 0;
    uint16_t y = 0;
    uint16_t x = 0;
    size_t and_stride = 0;
    size_t xor_stride = 0;

    if (!rdp_trace_enabled_level(RDP_TRACE_CLIENT, RDP_TRACE_LEVEL_TRACE) ||
        !update || !decoded || !decoded->data || update->kind != RDP_POINTER_UPDATE_KIND_SHAPE ||
        decoded_stride < (size_t)update->width * 4u)
        return;

    and_stride = rdp_session_pointer_mask_stride(update->width);
    xor_stride = rdp_session_pointer_xor_stride(update->width, update->xor_bpp);
    if (and_stride == 0 || xor_stride == 0)
        return;
    if (update->and_mask_len < and_stride * update->height ||
        update->xor_mask_len < xor_stride * update->height ||
        decoded->length < decoded_stride * update->height)
        return;

    if (update->xor_bpp == 32u)
    {
        size_t i = 3;

        for (i = 3; i < update->xor_mask_len; i += 4)
        {
            if (update->xor_mask[i] != 0)
            {
                has_alpha = 1;
                break;
            }
        }
    }

    for (y = 0; y < update->height; y++)
    {
        const uint8_t* row = decoded->data + ((size_t)y * decoded_stride);

        for (x = 0; x < update->width; x++)
        {
            int and_bit = rdp_session_pointer_mask_bit(update->and_mask,
                                                       and_stride,
                                                       update->width,
                                                       update->height,
                                                       x,
                                                       y);
            int xor_pixel = rdp_session_pointer_xor_pixel_nonzero(update, xor_stride, x, y);
            const uint8_t* pixel = row + ((size_t)x * 4u);

            if (and_bit)
                and_set++;
            if (xor_pixel)
                xor_nonzero++;
            if (and_bit && xor_pixel)
                invert_like++;
            if (pixel[0] != 0 || pixel[1] != 0 || pixel[2] != 0)
                decoded_rgb_nonzero++;
            if (pixel[3] != 0)
            {
                decoded_alpha_nonzero++;
                decoded_opaque++;
            }
            else
            {
                decoded_transparent++;
            }
        }
    }

    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.pointer.shape.stats",
                          "cache_index=%u width=%u height=%u hot_x=%u hot_y=%u xor_bpp=%u has_alpha=%u xor_len=%u and_len=%u and_set=%u xor_nonzero=%u invert_like=%u decoded_opaque=%u decoded_transparent=%u decoded_rgb_nonzero=%u decoded_alpha_nonzero=%u hash_xor=%016llx hash_and=%016llx hash_bgra=%016llx",
                          update->cache_index,
                          update->width,
                          update->height,
                          update->hot_x,
                          update->hot_y,
                          update->xor_bpp,
                          has_alpha,
                          (unsigned)update->xor_mask_len,
                          (unsigned)update->and_mask_len,
                          and_set,
                          xor_nonzero,
                          invert_like,
                          decoded_opaque,
                          decoded_transparent,
                          decoded_rgb_nonzero,
                          decoded_alpha_nonzero,
                          (unsigned long long)rdp_session_pointer_hash_bytes(update->xor_mask,
                                                                              update->xor_mask_len),
                          (unsigned long long)rdp_session_pointer_hash_bytes(update->and_mask,
                                                                              update->and_mask_len),
                          (unsigned long long)rdp_session_pointer_hash_bytes(decoded->data,
                                                                              decoded->length));
}

static void rdp_session_pointer_emit_default(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_POINTER;
    event.data.pointer.update_type = LIBRDP_POINTER_UPDATE_DEFAULT;
    event.data.pointer.visible = 1;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.pointer.default", "visible=1");
}

static void rdp_session_pointer_emit_hidden(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_POINTER;
    event.data.pointer.update_type = LIBRDP_POINTER_UPDATE_HIDDEN;
    event.data.pointer.visible = 0;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.pointer.hidden", "visible=0");
}

static void rdp_session_pointer_emit_position(librdp_session* session, uint16_t x, uint16_t y)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_POINTER;
    event.data.pointer.update_type = LIBRDP_POINTER_UPDATE_POSITION;
    event.data.pointer.x = x;
    event.data.pointer.y = y;
    event.data.pointer.visible = 1;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.pointer.position", "x=%u y=%u", x, y);
}

static void rdp_session_pointer_emit_shape(librdp_session* session, const rdp_session_pointer_cache_entry* entry)
{
    librdp_event event;

    if (!session || !entry || !entry->active)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_POINTER;
    event.data.pointer = entry->pointer;
    event.data.pointer.pixels = entry->pixels.data;
    event.data.pointer.pixels_len = entry->pixels.length;
    event.data.pointer.visible = 1;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.pointer.shape",
                    "cache_index=%u width=%u height=%u hot_x=%u hot_y=%u pixels=%u",
                    event.data.pointer.cache_index,
                    event.data.pointer.width,
                    event.data.pointer.height,
                    event.data.pointer.hot_x,
                    event.data.pointer.hot_y,
                    (unsigned)event.data.pointer.pixels_len);
}

static librdp_status rdp_session_pointer_store_shape(librdp_session* session, const rdp_pointer_update* update)
{
    rdp_session_pointer_cache_entry* entry = NULL;
    rdp_buffer decoded;
    size_t stride = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !update || update->kind != RDP_POINTER_UPDATE_KIND_SHAPE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (update->cache_index >= RDP_SESSION_POINTER_CACHE_SLOTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_buffer_init(&decoded);
    status = rdp_pointer_decode_bgra32(update, &decoded, &stride);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&decoded);
        return status;
    }

    entry = &session->pointer_cache[update->cache_index];
    rdp_buffer_free(&entry->pixels);
    entry->pixels = decoded;
    memset(&entry->pointer, 0, sizeof(entry->pointer));
    entry->pointer.update_type = LIBRDP_POINTER_UPDATE_SHAPE;
    entry->pointer.cache_index = update->cache_index;
    entry->pointer.hot_x = update->hot_x;
    entry->pointer.hot_y = update->hot_y;
    entry->pointer.width = update->width;
    entry->pointer.height = update->height;
    entry->pointer.stride = (uint32_t)stride;
    entry->pointer.pixels = entry->pixels.data;
    entry->pointer.pixels_len = entry->pixels.length;
    entry->pointer.visible = 1;
    entry->active = 1;
    rdp_session_pointer_trace_shape(update, &entry->pixels, stride);
    rdp_session_pointer_emit_shape(session, entry);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_pointer_apply_update(librdp_session* session, const rdp_pointer_update* update)
{
    if (!session || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    switch (update->kind)
    {
        case RDP_POINTER_UPDATE_KIND_NULL:
            rdp_session_pointer_emit_hidden(session);
            return LIBRDP_STATUS_OK;
        case RDP_POINTER_UPDATE_KIND_DEFAULT:
            rdp_session_pointer_emit_default(session);
            return LIBRDP_STATUS_OK;
        case RDP_POINTER_UPDATE_KIND_POSITION:
            rdp_session_pointer_emit_position(session, update->x, update->y);
            return LIBRDP_STATUS_OK;
        case RDP_POINTER_UPDATE_KIND_CACHED:
            if (update->cache_index >= RDP_SESSION_POINTER_CACHE_SLOTS ||
                !session->pointer_cache[update->cache_index].active)
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.pointer.cached.missing",
                                "cache_index=%u",
                                update->cache_index);
                return LIBRDP_STATUS_OK;
            }
            rdp_session_pointer_emit_shape(session, &session->pointer_cache[update->cache_index]);
            return LIBRDP_STATUS_OK;
        case RDP_POINTER_UPDATE_KIND_SHAPE:
            return rdp_session_pointer_store_shape(session, update);
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

static librdp_status rdp_session_write_mcs_pdu(librdp_session* session,
                                               const rdp_buffer* pdu,
                                               const char* event,
                                               int allow_hexdump)
{
    rdp_buffer x224_data;
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !pdu || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&x224_data);
    rdp_buffer_init(&packet);

    status = rdp_x224_wrap_data(&x224_data, pdu->data, pdu->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_tpkt_write(&packet, x224_data.data, x224_data.length);
    if (status == LIBRDP_STATUS_OK)
    {
        if (allow_hexdump)
            rdp_trace_hexdump(event, packet.data, packet.length);
        status = rdp_transport_write_all(&session->transport, packet.data, packet.length);
    }

    rdp_buffer_free(&packet);
    rdp_buffer_free(&x224_data);
    return status;
}

static librdp_status rdp_session_write_slowpath_pdu(librdp_session* session,
                                                    const rdp_buffer* slowpath,
                                                    const char* event)
{
    rdp_buffer security_payload;
    rdp_buffer send_data;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !slowpath || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&send_data);
    if (session->standard_security_active)
        status = rdp_security_write_encrypted_pdu(&security_payload,
                                                  &session->standard_security,
                                                  0,
                                                  slowpath->data,
                                                  slowpath->length);
    else
        status = rdp_buffer_append(&security_payload, slowpath->data, slowpath->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_send_data_request(&send_data,
                                                      session->mcs_user_id,
                                                      (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                      security_payload.data,
                                                      security_payload.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_mcs_pdu(session, &send_data, event, 1);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security_payload);
    return status;
}

static librdp_status rdp_session_write_channel_pdu(librdp_session* session,
                                                   uint16_t channel_id,
                                                   const rdp_buffer* payload,
                                                   const char* event)
{
    rdp_buffer channel_packet;
    rdp_buffer security_payload;
    rdp_buffer send_data;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !payload || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&channel_packet);
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&send_data);
    status = rdp_virtual_channel_write_packet(&channel_packet, payload->data, payload->length, 3);
    if (status == LIBRDP_STATUS_OK)
    {
        if (session->standard_security_active)
            status = rdp_security_write_encrypted_pdu(&security_payload,
                                                      &session->standard_security,
                                                      0,
                                                      channel_packet.data,
                                                      channel_packet.length);
        else
            status = rdp_buffer_append(&security_payload, channel_packet.data, channel_packet.length);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_send_data_request(&send_data,
                                                      session->mcs_user_id,
                                                      channel_id,
                                                      security_payload.data,
                                                      security_payload.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_mcs_pdu(session, &send_data, event, 1);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security_payload);
    rdp_buffer_free(&channel_packet);
    return status;
}

static size_t rdp_session_dynamic_channel_header_size(uint8_t channel_id_bytes)
{
    return 1u + channel_id_bytes;
}

static uint8_t rdp_session_dynamic_length_bytes(size_t length)
{
    if (length <= 0xffu)
        return 1;
    if (length <= 0xffffu)
        return 2;
    return 4;
}

static uint32_t rdp_session_pixels_to_mm(uint16_t pixels)
{
    uint32_t mm = ((uint32_t)pixels * 254u + 480u) / 960u;

    if (mm < 10u)
        return 10u;
    if (mm > 10000u)
        return 10000u;
    return mm;
}

static librdp_status rdp_session_send_dynamic_channel_data(librdp_session* session,
                                                           uint32_t channel_id,
                                                           uint8_t channel_id_bytes,
                                                           const void* data,
                                                           size_t data_len,
                                                           const char* event)
{
    rdp_buffer response;
    size_t offset = 0;
    size_t header_size = 0;
    size_t chunk_max = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0) || !event || session->dynamic_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (data_len > UINT32_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&response);
    header_size = rdp_session_dynamic_channel_header_size(channel_id_bytes);
    if (header_size >= RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE)
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
    else if (status == LIBRDP_STATUS_OK && data_len <= RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE - header_size)
    {
        status = rdp_dynamic_channel_write_data(&response, channel_id, channel_id_bytes, data, data_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_write_channel_pdu(session, session->dynamic_channel_id, &response, event);
    }
    else if (status == LIBRDP_STATUS_OK)
    {
        uint8_t length_bytes = rdp_session_dynamic_length_bytes(data_len);

        chunk_max = RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE - header_size - length_bytes;
        if (chunk_max == 0)
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        if (status == LIBRDP_STATUS_OK)
        {
            size_t chunk = data_len < chunk_max ? data_len : chunk_max;

            status = rdp_dynamic_channel_write_data_first(&response,
                                                          channel_id,
                                                          channel_id_bytes,
                                                          (uint32_t)data_len,
                                                          data,
                                                          chunk);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_write_channel_pdu(session, session->dynamic_channel_id, &response, event);
            offset = chunk;
        }
        while (status == LIBRDP_STATUS_OK && offset < data_len)
        {
            size_t remaining = data_len - offset;
            size_t chunk = remaining < RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE - header_size ?
                               remaining :
                               RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE - header_size;

            response.length = 0;
            status = rdp_dynamic_channel_write_data(&response,
                                                    channel_id,
                                                    channel_id_bytes,
                                                    ((const uint8_t*)data) + offset,
                                                    chunk);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_write_channel_pdu(session, session->dynamic_channel_id, &response, event);
            offset += chunk;
        }
    }
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_send_clipboard_packet(librdp_session* session,
                                                       const rdp_buffer* payload,
                                                       const char* event)
{
    if (!session || !payload || !event || session->clipboard_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_write_channel_pdu(session, session->clipboard_channel_id, payload, event);
}

static librdp_status rdp_session_send_device_redirection_packet(librdp_session* session,
                                                                const rdp_buffer* payload,
                                                                const char* event)
{
    if (!session || !payload || !event || session->device_redirection_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_write_channel_pdu(session, session->device_redirection_channel_id, payload, event);
}

static librdp_status rdp_session_send_pnp_redirection_packet(librdp_session* session,
                                                             const rdp_buffer* payload,
                                                             const char* event)
{
    if (!session || !payload || !event || session->pnp_redirection_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_write_channel_pdu(session, session->pnp_redirection_channel_id, payload, event);
}

static librdp_status rdp_session_send_remote_programs_packet(librdp_session* session,
                                                             const rdp_buffer* payload,
                                                             const char* event)
{
    if (!session || !payload || !event || session->remote_programs_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_write_channel_pdu(session, session->remote_programs_channel_id, payload, event);
}

static uint32_t rdp_session_errno_to_device_status(int error)
{
    switch (error)
    {
        case 0:
            return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
        case ENOENT:
        case ENOTDIR:
            return RDP_SESSION_DEVICE_NO_SUCH_FILE;
        case EEXIST:
            return RDP_SESSION_DEVICE_OBJECT_NAME_COLLISION;
        case EACCES:
        case EPERM:
        case EISDIR:
            return RDP_SESSION_DEVICE_ACCESS_DENIED;
        case EINVAL:
            return RDP_SESSION_DEVICE_INVALID_PARAMETER;
        case EMFILE:
        case ENFILE:
            return RDP_SESSION_DEVICE_TOO_MANY_OPENED_FILES;
        default:
            return RDP_SESSION_DEVICE_NOT_SUPPORTED;
    }
}

static librdp_status rdp_session_pnp_send_version(librdp_session* session)
{
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&packet);
    status = rdp_pnp_redirection_write_version(&packet,
                                               1,
                                               0,
                                               RDP_PNP_REDIRECTION_CAP_DYNAMIC_DEVICES);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_pnp_redirection_packet(session, &packet, "client.pnp.version");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.pnp.version",
                        "channel_id=%u capabilities=%u",
                        session->pnp_redirection_channel_id,
                        RDP_PNP_REDIRECTION_CAP_DYNAMIC_DEVICES);
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status rdp_session_pnp_send_authenticated(librdp_session* session)
{
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&packet);
    status = rdp_pnp_redirection_write_authenticated(&packet);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_pnp_redirection_packet(session, &packet, "client.pnp.authenticated");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.pnp.authenticated",
                        "channel_id=%u",
                        session->pnp_redirection_channel_id);
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status rdp_session_pnp_send_status(librdp_session* session,
                                                 uint32_t request_id,
                                                 uint32_t io_status,
                                                 const char* event)
{
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&packet);
    status = rdp_pnp_redirection_write_status_reply(&packet, request_id, io_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_pnp_redirection_packet(session, &packet, event);
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status rdp_session_handle_pnp_redirection_message(librdp_session* session,
                                                                const uint8_t* data,
                                                                size_t data_len)
{
    rdp_pnp_redirection_info_header info;
    rdp_pnp_redirection_server_io_header server_header;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&info, 0, sizeof(info));
    if (rdp_pnp_redirection_parse_info_header(data, data_len, &info) == LIBRDP_STATUS_OK)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.pnp.info",
                              "packet_id=%u payload_len=%u",
                              info.packet_id,
                              (unsigned)info.payload_len);
        switch (info.packet_id)
        {
            case RDP_PNP_REDIRECTION_INFO_VERSION:
            {
                rdp_pnp_redirection_version version;
                status = rdp_pnp_redirection_parse_version(data, data_len, &version);
                if (status == LIBRDP_STATUS_OK)
                {
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.pnp.server_version",
                                    "major=%u minor=%u capabilities=%u",
                                    version.major_version,
                                    version.minor_version,
                                    version.capabilities);
                }
                break;
            }
            case RDP_PNP_REDIRECTION_INFO_SERVER_LOGON:
                status = rdp_pnp_redirection_parse_authenticated(data, data_len, &info);
                if (status == LIBRDP_STATUS_OK)
                {
                    session->pnp_redirection_ready = 1;
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.pnp.server_logon",
                                    "channel_id=%u",
                                    session->pnp_redirection_channel_id);
                }
                break;
            case RDP_PNP_REDIRECTION_INFO_REDIRECT_DEVICES:
            {
                rdp_pnp_redirection_device_addition addition;
                status = rdp_pnp_redirection_parse_device_addition(data, data_len, &addition);
                if (status == LIBRDP_STATUS_OK)
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.pnp.device_addition",
                                    "device_count=%u",
                                    addition.device_count);
                break;
            }
            case RDP_PNP_REDIRECTION_INFO_UNREDIRECT_DEVICE:
            {
                rdp_pnp_redirection_device_removal removal;
                status = rdp_pnp_redirection_parse_device_removal(data, data_len, &removal);
                if (status == LIBRDP_STATUS_OK)
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.pnp.device_removal",
                                    "device_id=%u",
                                    removal.client_device_id);
                break;
            }
            default:
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
        }
        return status;
    }

    memset(&server_header, 0, sizeof(server_header));
    status = rdp_pnp_redirection_parse_server_io_header(data, data_len, &server_header);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.pnp.io_request",
                    "request_id=%u function=%u payload_len=%u",
                    server_header.request_id,
                    server_header.function_id,
                    (unsigned)server_header.payload_len);
    rdp_buffer_init(&response);
    switch (server_header.function_id)
    {
        case RDP_PNP_REDIRECTION_IO_CAPABILITIES_REQUEST:
        {
            rdp_pnp_redirection_io_version request;
            uint16_t version = RDP_PNP_REDIRECTION_IO_VERSION_6;

            status = rdp_pnp_redirection_parse_capabilities_request(data, data_len, &request);
            if (status == LIBRDP_STATUS_OK)
            {
                version = request.version == RDP_PNP_REDIRECTION_IO_VERSION_4 ?
                              RDP_PNP_REDIRECTION_IO_VERSION_4 :
                              RDP_PNP_REDIRECTION_IO_VERSION_6;
                session->pnp_redirection_io_version = version;
                status = rdp_pnp_redirection_write_capabilities_reply(&response,
                                                                      request.header.request_id,
                                                                      version);
            }
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_send_pnp_redirection_packet(session,
                                                                 &response,
                                                                 "client.pnp.capabilities_reply");
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.pnp.capabilities_reply",
                                "request_id=%u version=%u",
                                server_header.request_id,
                                version);
            break;
        }
        case RDP_PNP_REDIRECTION_IO_CREATE_FILE_REQUEST:
        {
            rdp_pnp_redirection_create_request request;
            status = rdp_pnp_redirection_parse_create_request(data, data_len, &request);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_pnp_send_status(session,
                                                     request.header.request_id,
                                                     RDP_SESSION_DEVICE_NO_SUCH_DEVICE,
                                                     "client.pnp.create_reply");
            break;
        }
        case RDP_PNP_REDIRECTION_IO_READ_REQUEST:
        {
            rdp_pnp_redirection_read_request request;
            status = rdp_pnp_redirection_parse_read_request(data, data_len, &request);
            if (status == LIBRDP_STATUS_OK)
            {
                status = rdp_pnp_redirection_write_read_reply(&response,
                                                              request.header.request_id,
                                                              RDP_SESSION_DEVICE_NO_SUCH_DEVICE,
                                                              NULL,
                                                              0);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_send_pnp_redirection_packet(session,
                                                                     &response,
                                                                     "client.pnp.read_reply");
            }
            break;
        }
        case RDP_PNP_REDIRECTION_IO_WRITE_REQUEST:
        {
            rdp_pnp_redirection_write_request request;
            status = rdp_pnp_redirection_parse_write_request(data, data_len, &request);
            if (status == LIBRDP_STATUS_OK)
            {
                status = rdp_pnp_redirection_write_write_reply(&response,
                                                               request.header.request_id,
                                                               RDP_SESSION_DEVICE_NO_SUCH_DEVICE,
                                                               0);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_send_pnp_redirection_packet(session,
                                                                     &response,
                                                                     "client.pnp.write_reply");
            }
            break;
        }
        case RDP_PNP_REDIRECTION_IO_CONTROL_REQUEST:
        {
            rdp_pnp_redirection_control_request request;
            status = rdp_pnp_redirection_parse_control_request(data, data_len, &request);
            if (status == LIBRDP_STATUS_OK)
            {
                status = rdp_pnp_redirection_write_control_reply(&response,
                                                                 request.header.request_id,
                                                                 RDP_SESSION_DEVICE_NOT_SUPPORTED,
                                                                 NULL,
                                                                 0);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_send_pnp_redirection_packet(session,
                                                                     &response,
                                                                     "client.pnp.control_reply");
            }
            break;
        }
        case RDP_PNP_REDIRECTION_IO_SPECIFIC_CANCEL_REQUEST:
        {
            rdp_pnp_redirection_cancel_request request;
            status = rdp_pnp_redirection_parse_cancel_request(data, data_len, &request);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_pnp_send_status(session,
                                                     request.header.request_id,
                                                     RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                     "client.pnp.cancel_reply");
            break;
        }
        default:
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
    }
    rdp_buffer_free(&response);
    return status;
}

static void rdp_session_redirected_file_reset(rdp_session_redirected_file* file)
{
    if (!file)
        return;
    if (!file->active)
    {
        memset(file, 0, sizeof(*file));
        file->fd = -1;
        return;
    }
    if (file->directory)
        (void)closedir(file->directory);
    if (file->fd >= 0)
        (void)close(file->fd);
    free(file->path);
    free(file->directory_path);
    free(file->directory_pattern);
    memset(file, 0, sizeof(*file));
    file->fd = -1;
}

static void rdp_session_redirected_files_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_MAX_REDIRECTED_FILES; i++)
        rdp_session_redirected_file_reset(&session->redirected_files[i]);
    memset(session->redirected_files, 0, sizeof(session->redirected_files));
    session->next_redirected_file_id = 1;
}

static rdp_session_redirected_file* rdp_session_redirected_file_find(librdp_session* session,
                                                                     uint32_t device_id,
                                                                     uint32_t file_id)
{
    size_t i = 0;

    if (!session || file_id == 0)
        return NULL;
    for (i = 0; i < RDP_SESSION_MAX_REDIRECTED_FILES; i++)
    {
        if (session->redirected_files[i].active &&
            session->redirected_files[i].device_id == device_id &&
            session->redirected_files[i].file_id == file_id)
            return &session->redirected_files[i];
    }
    return NULL;
}

static rdp_session_redirected_file* rdp_session_redirected_file_alloc(librdp_session* session,
                                                                      uint32_t device_id,
                                                                      uint32_t* file_id)
{
    size_t i = 0;
    uint32_t candidate = 0;

    if (!session || !file_id)
        return NULL;
    for (i = 0; i < RDP_SESSION_MAX_REDIRECTED_FILES; i++)
    {
        if (!session->redirected_files[i].active)
        {
            candidate = session->next_redirected_file_id++;
            if (candidate == 0)
                candidate = session->next_redirected_file_id++;
            session->redirected_files[i].active = 1;
            session->redirected_files[i].device_id = device_id;
            session->redirected_files[i].file_id = candidate;
            session->redirected_files[i].fd = -1;
            session->redirected_files[i].directory = NULL;
            *file_id = candidate;
            return &session->redirected_files[i];
        }
    }
    return NULL;
}

static uint32_t rdp_session_drive_index_from_device_id(const librdp_session* session, uint32_t device_id)
{
    uint32_t count = 0;
    uint32_t i = 0;

    if (!session)
        return UINT32_MAX;
    count = librdp_settings_drive_count(session->settings);
    for (i = 0; i < count; i++)
    {
        if (rdp_settings_drive_device_id_internal(session->settings, i) == device_id)
            return i;
    }
    return UINT32_MAX;
}

static uint32_t rdp_session_printer_index_from_device_id(const librdp_session* session, uint32_t device_id)
{
    uint32_t count = 0;
    uint32_t i = 0;

    if (!session)
        return UINT32_MAX;
    count = librdp_settings_printer_count(session->settings);
    for (i = 0; i < count; i++)
    {
        if (rdp_settings_printer_device_id_internal(session->settings, i) == device_id)
            return i;
    }
    return UINT32_MAX;
}

static uint32_t rdp_session_smartcard_index_from_device_id(const librdp_session* session, uint32_t device_id)
{
    uint32_t count = 0;
    uint32_t i = 0;

    if (!session)
        return UINT32_MAX;
    count = librdp_settings_smartcard_count(session->settings);
    for (i = 0; i < count; i++)
    {
        if (rdp_settings_smartcard_device_id_internal(session->settings, i) == device_id)
            return i;
    }
    return UINT32_MAX;
}

static uint32_t rdp_session_serial_port_index_from_device_id(const librdp_session* session, uint32_t device_id)
{
    uint32_t count = 0;
    uint32_t i = 0;

    if (!session)
        return UINT32_MAX;
    count = librdp_settings_serial_port_count(session->settings);
    for (i = 0; i < count; i++)
    {
        if (rdp_settings_serial_port_device_id_internal(session->settings, i) == device_id)
            return i;
    }
    return UINT32_MAX;
}

static uint32_t rdp_session_parallel_port_index_from_device_id(const librdp_session* session, uint32_t device_id)
{
    uint32_t count = 0;
    uint32_t i = 0;

    if (!session)
        return UINT32_MAX;
    count = librdp_settings_parallel_port_count(session->settings);
    for (i = 0; i < count; i++)
    {
        if (rdp_settings_parallel_port_device_id_internal(session->settings, i) == device_id)
            return i;
    }
    return UINT32_MAX;
}

static librdp_status rdp_session_utf16le_path_to_utf8(const uint8_t* data, uint32_t data_len, char** out)
{
    char* text = NULL;
    size_t chars = 0;
    size_t position = 0;
    size_t written = 0;

    if (!data || !out || data_len < 2u || (data_len & 1u) != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *out = NULL;
    chars = data_len / 2u;
    if (data[data_len - 2u] != 0 || data[data_len - 1u] != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    text = (char*)malloc(chars * 3u + 1u);
    if (!text)
        return LIBRDP_STATUS_NO_MEMORY;
    while (position + 1u < chars)
    {
        uint32_t ch = (uint32_t)data[position * 2u] | ((uint32_t)data[position * 2u + 1u] << 8);

        if (ch == 0)
        {
            free(text);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (ch == '\\')
            ch = '/';
        if (ch < 0x80u)
        {
            text[written++] = (char)ch;
        }
        else if (ch < 0x800u)
        {
            text[written++] = (char)(0xc0u | (ch >> 6));
            text[written++] = (char)(0x80u | (ch & 0x3fu));
        }
        else
        {
            text[written++] = (char)(0xe0u | (ch >> 12));
            text[written++] = (char)(0x80u | ((ch >> 6) & 0x3fu));
            text[written++] = (char)(0x80u | (ch & 0x3fu));
        }
        position++;
    }
    text[written] = '\0';
    *out = text;
    return LIBRDP_STATUS_OK;
}

static int rdp_session_path_has_unsafe_segment(const char* path)
{
    const char* p = path;

    if (!path)
        return 1;
    if (path[0] == '/' || path[0] == '\\')
        return 1;
    while (*p)
    {
        const char* start = p;
        size_t length = 0;

        while (*p && *p != '/')
            p++;
        length = (size_t)(p - start);
        if ((length == 1u && start[0] == '.') ||
            (length == 2u && start[0] == '.' && start[1] == '.'))
            return 1;
        if (memchr(start, ':', length) != NULL)
            return 1;
        if (*p == '/')
            p++;
    }
    return 0;
}

static librdp_status rdp_session_make_local_drive_path(librdp_session* session,
                                                       uint32_t device_id,
                                                       const uint8_t* remote_path,
                                                       uint32_t remote_path_len,
                                                       char** local_path)
{
    uint32_t drive_index = 0;
    const char* root = NULL;
    char* relative = NULL;
    size_t root_len = 0;
    size_t relative_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !remote_path || !local_path)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *local_path = NULL;
    drive_index = rdp_session_drive_index_from_device_id(session, device_id);
    if (drive_index == UINT32_MAX)
        return LIBRDP_STATUS_STATE;
    root = librdp_settings_drive_path(session->settings, drive_index);
    if (!root || root[0] == '\0')
        return LIBRDP_STATUS_STATE;
    status = rdp_session_utf16le_path_to_utf8(remote_path, remote_path_len, &relative);
    if (status != LIBRDP_STATUS_OK)
        return status;
    while (relative[0] == '/')
        memmove(relative, relative + 1, strlen(relative));
    if (rdp_session_path_has_unsafe_segment(relative))
    {
        free(relative);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    root_len = strlen(root);
    relative_len = strlen(relative);
    *local_path = (char*)malloc(root_len + 1u + relative_len + 1u);
    if (!*local_path)
    {
        free(relative);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    memcpy(*local_path, root, root_len);
    if (root_len > 0 && root[root_len - 1u] == '/')
    {
        memcpy(*local_path + root_len, relative, relative_len + 1u);
    }
    else
    {
        (*local_path)[root_len] = '/';
        memcpy(*local_path + root_len + 1u, relative, relative_len + 1u);
    }
    free(relative);
    return LIBRDP_STATUS_OK;
}

static int rdp_session_open_flags_from_create(const rdp_filesystem_redirection_create_request* request,
                                              uint8_t existed)
{
    int write_requested = 0;
    int flags = O_RDONLY;

    if (!request)
        return -1;
    write_requested = (request->desired_access & 0x40000000u) != 0 ||
                      (request->desired_access & 0x00000006u) != 0 ||
                      request->create_disposition == 0 ||
                      request->create_disposition == 2 ||
                      request->create_disposition == 4 ||
                      request->create_disposition == 5;
    if (write_requested)
        flags = O_RDWR;
    switch (request->create_disposition)
    {
        case 0:
            flags |= O_CREAT | O_TRUNC;
            break;
        case 1:
            break;
        case 2:
            flags |= O_CREAT | O_EXCL;
            break;
        case 3:
            flags |= O_CREAT;
            break;
        case 4:
            if (!existed)
                return -1;
            flags |= O_TRUNC;
            break;
        case 5:
            flags |= O_CREAT | O_TRUNC;
            break;
        default:
            return -1;
    }
    return flags;
}

static uint8_t rdp_session_create_information(const rdp_filesystem_redirection_create_request* request,
                                              uint8_t existed)
{
    if (!request)
        return RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_SUPERSEDED;
    if (request->create_disposition == 2 || (request->create_disposition == 3 && !existed) ||
        (request->create_disposition == 5 && !existed))
        return RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_CREATED;
    if (request->create_disposition == 3 && existed)
        return RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_OPENED;
    if (request->create_disposition == 4)
        return RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_OVERWRITTEN;
    if (request->create_disposition == 5 && existed)
        return RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_OVERWRITTEN;
    return RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_SUPERSEDED;
}

static uint32_t rdp_session_filesystem_error_from_status(librdp_status status)
{
    switch (status)
    {
        case LIBRDP_STATUS_OK:
            return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
        case LIBRDP_STATUS_NO_MEMORY:
            return RDP_SESSION_DEVICE_NOT_SUPPORTED;
        case LIBRDP_STATUS_STATE:
            return RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
        case LIBRDP_STATUS_INVALID_ARGUMENT:
        case LIBRDP_STATUS_PROTOCOL_ERROR:
        default:
            return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    }
}

static int rdp_session_seek_fd(int fd, uint64_t offset)
{
    if (sizeof(off_t) < sizeof(uint64_t) && offset > (uint64_t)LONG_MAX)
    {
        errno = EINVAL;
        return -1;
    }
    if (offset > (uint64_t)INT64_MAX)
    {
        errno = EINVAL;
        return -1;
    }
    return lseek(fd, (off_t)offset, SEEK_SET) == (off_t)-1 ? -1 : 0;
}

static librdp_status rdp_session_append_u64_le(rdp_buffer* buffer, uint64_t value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, (uint32_t)(value & 0xffffffffu));
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, (uint32_t)(value >> 32));
}

static librdp_status rdp_session_append_zero(rdp_buffer* buffer, size_t length)
{
    static const uint8_t zero[32] = {0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (length > 0)
    {
        size_t chunk = length < sizeof(zero) ? length : sizeof(zero);

        status = rdp_buffer_append(buffer, zero, chunk);
        if (status != LIBRDP_STATUS_OK)
            return status;
        length -= chunk;
    }
    return LIBRDP_STATUS_OK;
}

static uint64_t rdp_session_filetime_from_parts(int64_t seconds, long nanoseconds)
{
    const int64_t epoch_delta = 11644473600ll;
    uint64_t base = 0;

    if (seconds < -epoch_delta)
        return 0;
    base = (uint64_t)(seconds + epoch_delta) * 10000000ull;
    if (nanoseconds > 0)
        base += (uint64_t)nanoseconds / 100u;
    return base;
}

static uint64_t rdp_session_read_u64_le_raw(const uint8_t* data)
{
    if (!data)
        return 0;
    return (uint64_t)data[0] | ((uint64_t)data[1] << 8) | ((uint64_t)data[2] << 16) |
           ((uint64_t)data[3] << 24) | ((uint64_t)data[4] << 32) | ((uint64_t)data[5] << 40) |
           ((uint64_t)data[6] << 48) | ((uint64_t)data[7] << 56);
}

static int rdp_session_timespec_from_filetime(uint64_t filetime, struct timespec* out)
{
    uint64_t unix_100ns = 0;

    if (!out)
        return -1;
    if (filetime == 0)
    {
        out->tv_nsec = UTIME_OMIT;
        out->tv_sec = 0;
        return 0;
    }
    if (filetime < 116444736000000000ull)
        return -1;
    unix_100ns = filetime - 116444736000000000ull;
    if (unix_100ns / 10000000ull > (uint64_t)LONG_MAX)
        return -1;
    out->tv_sec = (time_t)(unix_100ns / 10000000ull);
    out->tv_nsec = (long)((unix_100ns % 10000000ull) * 100ull);
    return 0;
}

static uint64_t rdp_session_stat_atime(const struct stat* st)
{
    if (!st)
        return 0;
#if defined(__APPLE__) || defined(__FreeBSD__)
    return rdp_session_filetime_from_parts((int64_t)st->st_atimespec.tv_sec, st->st_atimespec.tv_nsec);
#else
    return rdp_session_filetime_from_parts((int64_t)st->st_atim.tv_sec, st->st_atim.tv_nsec);
#endif
}

static uint64_t rdp_session_stat_mtime(const struct stat* st)
{
    if (!st)
        return 0;
#if defined(__APPLE__) || defined(__FreeBSD__)
    return rdp_session_filetime_from_parts((int64_t)st->st_mtimespec.tv_sec, st->st_mtimespec.tv_nsec);
#else
    return rdp_session_filetime_from_parts((int64_t)st->st_mtim.tv_sec, st->st_mtim.tv_nsec);
#endif
}

static uint64_t rdp_session_stat_ctime(const struct stat* st)
{
    if (!st)
        return 0;
#if defined(__APPLE__) || defined(__FreeBSD__)
    return rdp_session_filetime_from_parts((int64_t)st->st_ctimespec.tv_sec, st->st_ctimespec.tv_nsec);
#else
    return rdp_session_filetime_from_parts((int64_t)st->st_ctim.tv_sec, st->st_ctim.tv_nsec);
#endif
}

static uint64_t rdp_session_stat_size(const struct stat* st)
{
    if (!st || S_ISDIR(st->st_mode) || st->st_size < 0)
        return 0;
    return (uint64_t)st->st_size;
}

static uint64_t rdp_session_stat_allocation_size(const struct stat* st)
{
    if (!st || S_ISDIR(st->st_mode))
        return 0;
#if defined(st_blocks)
    if (st->st_blocks > 0)
        return (uint64_t)st->st_blocks * 512ull;
#endif
    return rdp_session_stat_size(st);
}

static uint32_t rdp_session_stat_attributes(const struct stat* st)
{
    uint32_t attributes = 0;

    if (!st)
        return RDP_SESSION_FILE_ATTRIBUTE_NORMAL;
    if (S_ISDIR(st->st_mode))
        attributes |= RDP_SESSION_FILE_ATTRIBUTE_DIRECTORY;
    else
        attributes |= RDP_SESSION_FILE_ATTRIBUTE_NORMAL;
    if ((st->st_mode & S_IWUSR) == 0)
        attributes |= RDP_SESSION_FILE_ATTRIBUTE_READONLY;
    return attributes;
}

static librdp_status rdp_session_utf8_to_utf16le(const char* text, rdp_buffer* out, uint8_t append_null)
{
    const unsigned char* p = (const unsigned char*)text;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!text || !out)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (*p)
    {
        uint32_t cp = 0;

        if (*p < 0x80u)
        {
            cp = *p++;
        }
        else if ((*p & 0xe0u) == 0xc0u && (p[1] & 0xc0u) == 0x80u)
        {
            cp = ((uint32_t)(p[0] & 0x1fu) << 6) | (uint32_t)(p[1] & 0x3fu);
            p += 2;
        }
        else if ((*p & 0xf0u) == 0xe0u && (p[1] & 0xc0u) == 0x80u && (p[2] & 0xc0u) == 0x80u)
        {
            cp = ((uint32_t)(p[0] & 0x0fu) << 12) | ((uint32_t)(p[1] & 0x3fu) << 6) |
                 (uint32_t)(p[2] & 0x3fu);
            p += 3;
        }
        else if ((*p & 0xf8u) == 0xf0u && (p[1] & 0xc0u) == 0x80u &&
                 (p[2] & 0xc0u) == 0x80u && (p[3] & 0xc0u) == 0x80u)
        {
            cp = ((uint32_t)(p[0] & 0x07u) << 18) | ((uint32_t)(p[1] & 0x3fu) << 12) |
                 ((uint32_t)(p[2] & 0x3fu) << 6) | (uint32_t)(p[3] & 0x3fu);
            p += 4;
        }
        else
        {
            cp = '?';
            p++;
        }

        if (cp > 0x10ffffu)
            cp = '?';
        if (cp <= 0xffffu)
        {
            status = rdp_buffer_append_u16_le(out, (uint16_t)cp);
        }
        else
        {
            uint32_t value = cp - 0x10000u;
            uint16_t high = (uint16_t)(0xd800u | (value >> 10));
            uint16_t low = (uint16_t)(0xdc00u | (value & 0x3ffu));

            status = rdp_buffer_append_u16_le(out, high);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(out, low);
        }
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (append_null)
        return rdp_buffer_append_u16_le(out, 0);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_send_remote_programs_startup(librdp_session* session)
{
    rdp_buffer packet;
    uint32_t app_count = 0;
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->remote_programs_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&packet);
    status = rdp_remote_programs_write_u32_order(&packet,
                                                 RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE,
                                                 22621u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_remote_programs_packet(session,
                                                         &packet,
                                                         "client.rail.handshake");
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_handshake_ex(&packet,
                                                        22621u,
                                                        RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_HIDEF |
                                                            RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_EXTENDED_SPI |
                                                            RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_SNAP_ARRANGE |
                                                            RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_TEXT_SCALE |
                                                            RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_CARET_BLINK);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_remote_programs_packet(session,
                                                         &packet,
                                                         "client.rail.handshake_ex");
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_u32_order(
            &packet,
            RDP_REMOTE_PROGRAMS_ORDER_CLIENTSTATUS,
            RDP_REMOTE_PROGRAMS_CLIENTSTATUS_ALLOW_LOCAL_MOVE_SIZE |
                RDP_REMOTE_PROGRAMS_CLIENTSTATUS_AUTORECONNECT |
                RDP_REMOTE_PROGRAMS_CLIENTSTATUS_ZORDER_SYNC |
                RDP_REMOTE_PROGRAMS_CLIENTSTATUS_RESIZE_MARGIN |
                RDP_REMOTE_PROGRAMS_CLIENTSTATUS_HIGH_DPI_ICONS |
                RDP_REMOTE_PROGRAMS_CLIENTSTATUS_APPBAR_REMOTING |
                RDP_REMOTE_PROGRAMS_CLIENTSTATUS_BIDIRECTIONAL_CLOAK);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_remote_programs_packet(session,
                                                         &packet,
                                                         "client.rail.client_status");
    rdp_buffer_free(&packet);

    app_count = librdp_settings_rail_app_count(session->settings);
    for (i = 0; status == LIBRDP_STATUS_OK && i < app_count; i++)
    {
        const char* app = librdp_settings_rail_app(session->settings, i);
        rdp_buffer exe;

        rdp_buffer_init(&exe);
        if (!app || app[0] == '\0')
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_utf8_to_utf16le(app, &exe, 0);
        if (status == LIBRDP_STATUS_OK && (exe.length == 0 || exe.length > UINT16_MAX))
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_buffer_init(&packet);
            status = rdp_remote_programs_write_exec(&packet,
                                                    RDP_REMOTE_PROGRAMS_EXEC_FLAG_EXPAND_WORKINGDIRECTORY |
                                                        RDP_REMOTE_PROGRAMS_EXEC_FLAG_EXPAND_ARGUMENTS,
                                                    exe.data,
                                                    (uint16_t)exe.length,
                                                    NULL,
                                                    0,
                                                    NULL,
                                                    0);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_remote_programs_packet(session, &packet, "client.rail.exec");
        rdp_buffer_free(&packet);
        rdp_buffer_free(&exe);
        if (status == LIBRDP_STATUS_OK)
        {
            session->remote_programs_exec_sent = 1;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rail.exec",
                            "index=%u app_bytes=%u",
                            i,
                            (unsigned)strlen(app));
        }
    }
    if (status == LIBRDP_STATUS_OK)
    {
        session->remote_programs_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rail.ready",
                        "apps=%u",
                        app_count);
    }
    return status;
}

static librdp_status rdp_session_handle_remote_programs_message(librdp_session* session,
                                                                const uint8_t* data,
                                                                size_t data_len)
{
    rdp_remote_programs_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_remote_programs_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.rail.pdu",
                          "channel_id=%u order=%u length=%u",
                          session->remote_programs_channel_id,
                          header.order_type,
                          header.order_length);
    if (!session->remote_programs_ready)
    {
        status = rdp_session_send_remote_programs_startup(session);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    switch (header.order_type)
    {
        case RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE:
        case RDP_REMOTE_PROGRAMS_ORDER_CLIENTSTATUS:
        case RDP_REMOTE_PROGRAMS_ORDER_SYSPARAM:
        case RDP_REMOTE_PROGRAMS_ORDER_SYSCOMMAND:
        case RDP_REMOTE_PROGRAMS_ORDER_NOTIFY_EVENT:
        case RDP_REMOTE_PROGRAMS_ORDER_WINDOWMOVE:
        case RDP_REMOTE_PROGRAMS_ORDER_LOCALMOVESIZE:
        case RDP_REMOTE_PROGRAMS_ORDER_MINMAXINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_SYSMENU:
        case RDP_REMOTE_PROGRAMS_ORDER_LANGBARINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_GET_APPID_REQ:
        case RDP_REMOTE_PROGRAMS_ORDER_GET_APPID_RESP:
        case RDP_REMOTE_PROGRAMS_ORDER_TASKBARINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_LANGUAGEIMEINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_COMPARTMENTINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_ZORDER_SYNC:
        case RDP_REMOTE_PROGRAMS_ORDER_CLOAK:
        case RDP_REMOTE_PROGRAMS_ORDER_POWER_DISPLAY_REQUEST:
        case RDP_REMOTE_PROGRAMS_ORDER_SNAP_ARRANGE:
        case RDP_REMOTE_PROGRAMS_ORDER_GET_APPID_RESP_EX:
        case RDP_REMOTE_PROGRAMS_ORDER_TEXTSCALEINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_CARETBLINKINFO:
        {
            rdp_remote_programs_opaque opaque;

            status = rdp_remote_programs_parse_opaque(data, data_len, &opaque);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event_level(RDP_TRACE_CLIENT,
                                      RDP_TRACE_LEVEL_DEBUG,
                                      "client.rail.order",
                                      "order=%u payload_len=%u",
                                      opaque.header.order_type,
                                      (unsigned)opaque.payload_len);
            break;
        }
        case RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE_EX:
        {
            rdp_remote_programs_handshake_ex order;

            status = rdp_remote_programs_parse_handshake_ex(data, data_len, &order);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rail.handshake_ex.server",
                                "build=%u flags=%u",
                                order.build_number,
                                order.flags);
            break;
        }
        case RDP_REMOTE_PROGRAMS_ORDER_ACTIVATE:
        {
            rdp_remote_programs_activate order;

            status = rdp_remote_programs_parse_activate(data, data_len, &order);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rail.activate",
                                "window_id=%u enabled=%u",
                                order.window_id,
                                order.enabled);
            break;
        }
        case RDP_REMOTE_PROGRAMS_ORDER_EXEC_RESULT:
        {
            rdp_remote_programs_exec_result result;

            status = rdp_remote_programs_parse_exec_result(data, data_len, &result);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rail.exec_result",
                                "flags=%u result=%u raw=%u exe_len=%u",
                                result.flags,
                                result.exec_result,
                                result.raw_result,
                                result.exe_or_file_len);
            break;
        }
        default:
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
    }
    return status;
}

static librdp_status rdp_session_write_file_basic_information(rdp_buffer* buffer,
                                                              const struct stat* st)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint64_t change_time = rdp_session_stat_ctime(st);

    status = rdp_buffer_append_u32_le(buffer, 36);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, change_time);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_atime(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_mtime(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, change_time);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, rdp_session_stat_attributes(st));
    return status;
}

static librdp_status rdp_session_write_file_standard_information(rdp_buffer* buffer,
                                                                 const struct stat* st)
{
    uint64_t size = rdp_session_stat_size(st);
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, 22);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_allocation_size(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, size);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, st && st->st_nlink > 0 ? (uint32_t)st->st_nlink : 1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, st && S_ISDIR(st->st_mode) ? 1u : 0u);
    return status;
}

static librdp_status rdp_session_write_file_attribute_tag_information(rdp_buffer* buffer,
                                                                      const struct stat* st)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, 8);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, rdp_session_stat_attributes(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    return status;
}

static librdp_status rdp_session_write_file_information(rdp_buffer* buffer,
                                                        uint32_t information_class,
                                                        const struct stat* st)
{
    if (!buffer || !st)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (information_class)
    {
        case RDP_SESSION_FILE_BASIC_INFORMATION:
            return rdp_session_write_file_basic_information(buffer, st);
        case RDP_SESSION_FILE_STANDARD_INFORMATION:
            return rdp_session_write_file_standard_information(buffer, st);
        case RDP_SESSION_FILE_ATTRIBUTE_TAG_INFORMATION:
            return rdp_session_write_file_attribute_tag_information(buffer, st);
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

static librdp_status rdp_session_write_directory_information(rdp_buffer* buffer,
                                                             uint32_t information_class,
                                                             const struct stat* st,
                                                             const char* name)
{
    rdp_buffer utf16;
    librdp_status status = LIBRDP_STATUS_OK;
    uint64_t change_time = 0;
    uint64_t size = 0;
    uint64_t allocation_size = 0;
    uint32_t record_len = 0;

    if (!buffer || !st || !name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&utf16);
    status = rdp_session_utf8_to_utf16le(name, &utf16, 0);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&utf16);
        return status;
    }
    if (utf16.length > UINT32_MAX)
    {
        rdp_buffer_free(&utf16);
        return LIBRDP_STATUS_NO_MEMORY;
    }

    change_time = rdp_session_stat_ctime(st);
    size = rdp_session_stat_size(st);
    allocation_size = rdp_session_stat_allocation_size(st);
    switch (information_class)
    {
        case RDP_SESSION_FILE_DIRECTORY_INFORMATION:
            record_len = (uint32_t)(64u + utf16.length);
            break;
        case RDP_SESSION_FILE_FULL_DIRECTORY_INFORMATION:
            record_len = (uint32_t)(68u + utf16.length);
            break;
        case RDP_SESSION_FILE_BOTH_DIRECTORY_INFORMATION:
            record_len = (uint32_t)(93u + utf16.length);
            break;
        case RDP_SESSION_FILE_NAMES_INFORMATION:
            record_len = (uint32_t)(12u + utf16.length);
            break;
        default:
            rdp_buffer_free(&utf16);
            return LIBRDP_STATUS_UNSUPPORTED;
    }

    status = rdp_buffer_append_u32_le(buffer, record_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (information_class == RDP_SESSION_FILE_NAMES_INFORMATION)
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, (uint32_t)utf16.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append(buffer, utf16.data, utf16.length);
        rdp_buffer_free(&utf16);
        return status;
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, change_time);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_atime(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, rdp_session_stat_mtime(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, change_time);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, size);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_u64_le(buffer, allocation_size);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, rdp_session_stat_attributes(st));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, (uint32_t)utf16.length);
    if (information_class == RDP_SESSION_FILE_FULL_DIRECTORY_INFORMATION ||
        information_class == RDP_SESSION_FILE_BOTH_DIRECTORY_INFORMATION)
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, 0);
    }
    if (information_class == RDP_SESSION_FILE_BOTH_DIRECTORY_INFORMATION)
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u8(buffer, 0);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_append_zero(buffer, 24);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, utf16.data, utf16.length);
    rdp_buffer_free(&utf16);
    return status;
}

static librdp_status rdp_session_write_volume_label(rdp_buffer* buffer, const char* label, uint32_t* bytes)
{
    size_t start = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !label || !bytes)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_session_utf8_to_utf16le(label, buffer, 1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (buffer->length - start > UINT32_MAX)
        return LIBRDP_STATUS_NO_MEMORY;
    *bytes = (uint32_t)(buffer->length - start);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_write_volume_information(rdp_buffer* buffer,
                                                          uint32_t information_class,
                                                          const char* root)
{
    struct stat st;
    struct statvfs vfs;
    rdp_buffer text;
    uint64_t total_units = 0;
    uint64_t available_units = 0;
    uint32_t bytes_per_sector = 512;
    uint32_t sectors_per_unit = 1;
    uint32_t text_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !root)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&st, 0, sizeof(st));
    memset(&vfs, 0, sizeof(vfs));
    if (stat(root, &st) != 0)
        return LIBRDP_STATUS_STATE;
    if (statvfs(root, &vfs) == 0)
    {
        total_units = (uint64_t)vfs.f_blocks;
        available_units = (uint64_t)vfs.f_bavail;
        if (vfs.f_frsize >= 512u)
            sectors_per_unit = (uint32_t)(vfs.f_frsize / 512u);
    }

    rdp_buffer_init(&text);
    switch (information_class)
    {
        case RDP_SESSION_FILE_FS_VOLUME_INFORMATION:
            status = rdp_session_write_volume_label(&text, "librdp", &text_len);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(buffer, 17u + text_len);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_append_u64_le(buffer, rdp_session_stat_ctime(&st));
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(buffer, (uint32_t)((st.st_dev ^ st.st_ino) & 0xffffffffu));
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(buffer, text_len);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u8(buffer, 0);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append(buffer, text.data, text.length);
            break;
        case RDP_SESSION_FILE_FS_SIZE_INFORMATION:
            status = rdp_buffer_append_u32_le(buffer, 24);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_append_u64_le(buffer, total_units);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_append_u64_le(buffer, available_units);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(buffer, sectors_per_unit);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(buffer, bytes_per_sector);
            break;
        case RDP_SESSION_FILE_FS_DEVICE_INFORMATION:
            status = rdp_buffer_append_u32_le(buffer, 8);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(buffer, RDP_SESSION_FILE_DEVICE_DISK);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(buffer, 0);
            break;
        case RDP_SESSION_FILE_FS_ATTRIBUTE_INFORMATION:
            status = rdp_session_write_volume_label(&text, "POSIX", &text_len);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(buffer, 12u + text_len);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(buffer,
                                                  RDP_SESSION_FILE_CASE_SENSITIVE_SEARCH |
                                                      RDP_SESSION_FILE_CASE_PRESERVED_NAMES |
                                                      RDP_SESSION_FILE_UNICODE_ON_DISK);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(buffer, 255);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(buffer, text_len);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append(buffer, text.data, text.length);
            break;
        case RDP_SESSION_FILE_FS_FULL_SIZE_INFORMATION:
            status = rdp_buffer_append_u32_le(buffer, 32);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_append_u64_le(buffer, total_units);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_append_u64_le(buffer, available_units);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_append_u64_le(buffer, available_units);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(buffer, sectors_per_unit);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u32_le(buffer, bytes_per_sector);
            break;
        default:
            status = LIBRDP_STATUS_UNSUPPORTED;
            break;
    }
    rdp_buffer_free(&text);
    return status;
}

static char* rdp_session_strdup_range(const char* data, size_t length)
{
    char* out = NULL;

    if (!data && length > 0)
        return NULL;
    out = (char*)malloc(length + 1u);
    if (!out)
        return NULL;
    if (length > 0)
        memcpy(out, data, length);
    out[length] = '\0';
    return out;
}

static char* rdp_session_join_path(const char* root, const char* relative)
{
    char* out = NULL;
    size_t root_len = 0;
    size_t relative_len = 0;

    if (!root || !relative)
        return NULL;
    root_len = strlen(root);
    relative_len = strlen(relative);
    out = (char*)malloc(root_len + 1u + relative_len + 1u);
    if (!out)
        return NULL;
    memcpy(out, root, root_len);
    if (root_len > 0 && root[root_len - 1u] == '/')
    {
        memcpy(out + root_len, relative, relative_len + 1u);
    }
    else
    {
        out[root_len] = '/';
        memcpy(out + root_len + 1u, relative, relative_len + 1u);
    }
    return out;
}

static librdp_status rdp_session_make_query_directory(librdp_session* session,
                                                      rdp_session_redirected_file* file,
                                                      const rdp_filesystem_redirection_query_directory_request* request,
                                                      char** directory_path,
                                                      char** pattern)
{
    char* relative = NULL;
    char* slash = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !file || !request || !directory_path || !pattern || !file->path)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *directory_path = NULL;
    *pattern = NULL;
    if (request->path_len == 0)
    {
        *directory_path = rdp_session_strdup_range(file->path, strlen(file->path));
        *pattern = rdp_session_strdup_range("*", 1);
        return *directory_path && *pattern ? LIBRDP_STATUS_OK : LIBRDP_STATUS_NO_MEMORY;
    }

    status = rdp_session_utf16le_path_to_utf8(request->path, request->path_len, &relative);
    if (status != LIBRDP_STATUS_OK)
        return status;
    while (relative[0] == '/')
        memmove(relative, relative + 1, strlen(relative));
    if (rdp_session_path_has_unsafe_segment(relative))
    {
        free(relative);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    slash = strrchr(relative, '/');
    if (!slash)
    {
        *directory_path = rdp_session_strdup_range(file->path, strlen(file->path));
        *pattern = rdp_session_strdup_range(relative[0] ? relative : "*", strlen(relative[0] ? relative : "*"));
    }
    else
    {
        char* parent = rdp_session_strdup_range(relative, (size_t)(slash - relative));

        if (!parent)
        {
            free(relative);
            return LIBRDP_STATUS_NO_MEMORY;
        }
        *directory_path = rdp_session_join_path(file->path, parent);
        *pattern = rdp_session_strdup_range(slash[1] ? slash + 1 : "*", strlen(slash[1] ? slash + 1 : "*"));
        free(parent);
    }
    free(relative);
    if (!*directory_path || !*pattern)
    {
        free(*directory_path);
        free(*pattern);
        *directory_path = NULL;
        *pattern = NULL;
        return LIBRDP_STATUS_NO_MEMORY;
    }
    return LIBRDP_STATUS_OK;
}

static uint32_t rdp_session_apply_basic_information(rdp_session_redirected_file* file,
                                                    const uint8_t* data,
                                                    uint32_t length)
{
    struct stat st;
    struct timespec times[2];
    uint64_t access_time = 0;
    uint64_t write_time = 0;
    uint32_t attributes = 0;
    mode_t mode = 0;
    mode_t write_mask = (mode_t)(S_IWUSR | S_IWGRP | S_IWOTH);

    if (!file || !file->path || !data || length != 36u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (fstat(file->fd, &st) != 0)
        return rdp_session_errno_to_device_status(errno);
    access_time = rdp_session_read_u64_le_raw(data + 8);
    write_time = rdp_session_read_u64_le_raw(data + 16);
    attributes = (uint32_t)data[32] | ((uint32_t)data[33] << 8) | ((uint32_t)data[34] << 16) |
                 ((uint32_t)data[35] << 24);
    if (rdp_session_timespec_from_filetime(access_time, &times[0]) != 0 ||
        rdp_session_timespec_from_filetime(write_time, &times[1]) != 0)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (futimens(file->fd, times) != 0)
        return rdp_session_errno_to_device_status(errno);
    if (attributes != 0)
    {
        mode = st.st_mode;
        if ((attributes & RDP_SESSION_FILE_ATTRIBUTE_READONLY) != 0)
            mode = (mode_t)(mode & (mode_t)(~write_mask));
        else
            mode = (mode_t)(mode | S_IWUSR);
        if (chmod(file->path, mode) != 0)
            return rdp_session_errno_to_device_status(errno);
    }
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static uint32_t rdp_session_apply_size_information(rdp_session_redirected_file* file,
                                                   const uint8_t* data,
                                                   uint32_t length)
{
    uint64_t size = 0;

    if (!file || !data || length != 8u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    size = rdp_session_read_u64_le_raw(data);
    if (size > (uint64_t)INT64_MAX)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (ftruncate(file->fd, (off_t)size) != 0)
        return rdp_session_errno_to_device_status(errno);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static int rdp_session_directory_is_empty(const char* path)
{
    DIR* dir = NULL;
    struct dirent* entry = NULL;

    if (!path)
        return 0;
    dir = opendir(path);
    if (!dir)
        return 0;
    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
        {
            (void)closedir(dir);
            return 0;
        }
    }
    (void)closedir(dir);
    return 1;
}

static uint32_t rdp_session_apply_disposition_information(rdp_session_redirected_file* file,
                                                         const uint8_t* data,
                                                         uint32_t length)
{
    struct stat st;
    uint8_t delete_pending = 1;

    if (!file || !file->path)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (length > 1u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (length == 1u)
        delete_pending = data && data[0] ? 1u : 0u;
    if (delete_pending)
    {
        if (fstat(file->fd, &st) != 0)
            return rdp_session_errno_to_device_status(errno);
        if (S_ISDIR(st.st_mode) && !rdp_session_directory_is_empty(file->path))
            return RDP_SESSION_DEVICE_ACCESS_DENIED;
        if ((st.st_mode & S_IWUSR) == 0)
            return RDP_SESSION_DEVICE_ACCESS_DENIED;
    }
    file->delete_pending = delete_pending;
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static uint32_t rdp_session_apply_rename_information(librdp_session* session,
                                                     rdp_session_redirected_file* file,
                                                     const rdp_filesystem_redirection_information_request* request)
{
    char* new_path = NULL;
    uint8_t replace = 0;
    uint32_t name_len = 0;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !file || !file->path || !request || request->length < 6u || !request->buffer)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    replace = request->buffer[0] ? 1u : 0u;
    name_len = (uint32_t)request->buffer[2] | ((uint32_t)request->buffer[3] << 8) |
               ((uint32_t)request->buffer[4] << 16) | ((uint32_t)request->buffer[5] << 24);
    if (name_len != request->length - 6u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    status = rdp_session_make_local_drive_path(session,
                                               request->io.device_id,
                                               request->buffer + 6u,
                                               name_len,
                                               &new_path);
    if (status != LIBRDP_STATUS_OK)
        return rdp_session_filesystem_error_from_status(status);
    if (!replace && access(new_path, F_OK) == 0)
    {
        free(new_path);
        return RDP_SESSION_DEVICE_OBJECT_NAME_COLLISION;
    }
    if (rename(file->path, new_path) != 0)
    {
        io_status = rdp_session_errno_to_device_status(errno);
        free(new_path);
        return io_status;
    }
    free(file->path);
    file->path = new_path;
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static uint32_t rdp_session_filesystem_prepare_directory(
    const rdp_filesystem_redirection_create_request* request,
    const char* path,
    uint8_t existed)
{
    if (!request || !path)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (request->create_disposition == 1 && !existed)
        return RDP_SESSION_DEVICE_NO_SUCH_FILE;
    if (request->create_disposition == 2 && existed)
        return RDP_SESSION_DEVICE_OBJECT_NAME_COLLISION;
    if (request->create_disposition == 4 && !existed)
        return RDP_SESSION_DEVICE_NO_SUCH_FILE;
    if (!existed &&
        (request->create_disposition == 0 || request->create_disposition == 2 ||
         request->create_disposition == 3 || request->create_disposition == 5))
    {
        if (mkdir(path, 0700) != 0)
            return rdp_session_errno_to_device_status(errno);
    }
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static librdp_status rdp_session_send_filesystem_create_response(
    librdp_session* session,
    const rdp_filesystem_redirection_create_request* request,
    uint32_t io_status,
    uint32_t file_id,
    uint8_t information)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_create_response(&response,
                                                              request->io.device_id,
                                                              request->io.completion_id,
                                                              io_status,
                                                              file_id,
                                                              information);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.create.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.create",
                        "device_id=%u completion_id=%u file_id=%u status=%u information=%u path_len=%u",
                        request->io.device_id,
                        request->io.completion_id,
                        file_id,
                        io_status,
                        information,
                        request->path_len);
    return status;
}

static librdp_status rdp_session_handle_filesystem_create(librdp_session* session,
                                                          const uint8_t* data,
                                                          size_t data_len)
{
    rdp_filesystem_redirection_create_request request;
    rdp_session_redirected_file* file = NULL;
    char* path = NULL;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t file_id = 0;
    uint8_t existed = 0;
    uint8_t information = RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_SUPERSEDED;
    int flags = -1;
    int fd = -1;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_create_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_session_drive_index_from_device_id(session, request.io.device_id) == UINT32_MAX)
        return rdp_session_send_filesystem_create_response(session,
                                                           &request,
                                                           RDP_SESSION_DEVICE_NO_SUCH_DEVICE,
                                                           0,
                                                           information);

    status = rdp_session_make_local_drive_path(session,
                                               request.io.device_id,
                                               request.path,
                                               request.path_len,
                                               &path);
    if (status != LIBRDP_STATUS_OK)
    {
        io_status = rdp_session_filesystem_error_from_status(status);
        return rdp_session_send_filesystem_create_response(session, &request, io_status, 0, information);
    }

    existed = access(path, F_OK) == 0 ? 1u : 0u;
    information = rdp_session_create_information(&request, existed);
    if ((request.create_options & RDP_SESSION_FILE_DIRECTORY_FILE) != 0)
    {
        io_status = rdp_session_filesystem_prepare_directory(&request, path, existed);
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
        {
            fd = open(path, O_RDONLY);
            if (fd < 0)
                io_status = rdp_session_errno_to_device_status(errno);
        }
    }
    else
    {
        flags = rdp_session_open_flags_from_create(&request, existed);
        if (flags < 0)
        {
            io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
        }
        else
        {
            fd = open(path, flags, 0600);
            if (fd < 0)
                io_status = rdp_session_errno_to_device_status(errno);
        }
    }

    if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
    {
        file = rdp_session_redirected_file_alloc(session, request.io.device_id, &file_id);
        if (!file)
        {
            io_status = RDP_SESSION_DEVICE_TOO_MANY_OPENED_FILES;
            (void)close(fd);
            fd = -1;
            file_id = 0;
        }
        else
        {
            file->fd = fd;
            file->path = path;
            path = NULL;
            fd = -1;
        }
    }
    free(path);
    if (fd >= 0)
        (void)close(fd);
    return rdp_session_send_filesystem_create_response(session,
                                                       &request,
                                                       io_status,
                                                       file_id,
                                                       information);
}

static librdp_status rdp_session_handle_filesystem_close(librdp_session* session,
                                                         const uint8_t* data,
                                                         size_t data_len)
{
    rdp_device_redirection_io_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_close_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;

    file = rdp_session_redirected_file_find(session, request.device_id, request.file_id);
    if (!file)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    else
    {
        uint8_t delete_pending = file->delete_pending;
        char* delete_path = file->path ? rdp_session_strdup_range(file->path, strlen(file->path)) : NULL;
        struct stat st;
        uint8_t is_directory = 0;

        memset(&st, 0, sizeof(st));
        if (file->fd >= 0 && fstat(file->fd, &st) == 0 && S_ISDIR(st.st_mode))
            is_directory = 1;
        if (file->fd >= 0 && close(file->fd) != 0)
            io_status = rdp_session_errno_to_device_status(errno);
        file->fd = -1;
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS && delete_pending && delete_path)
        {
            if ((is_directory ? rmdir(delete_path) : unlink(delete_path)) != 0)
                io_status = rdp_session_errno_to_device_status(errno);
        }
        free(delete_path);
        rdp_session_redirected_file_reset(file);
    }

    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_close_response(&response,
                                                             request.device_id,
                                                             request.completion_id,
                                                             io_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.close.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.close",
                        "device_id=%u file_id=%u completion_id=%u status=%u",
                        request.device_id,
                        request.file_id,
                        request.completion_id,
                        io_status);
    return status;
}

static librdp_status rdp_session_handle_filesystem_set_information(librdp_session* session,
                                                                   const uint8_t* data,
                                                                   size_t data_len)
{
    rdp_filesystem_redirection_information_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_set_information_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;

    file = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
    if (!file)
    {
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    }
    else
    {
        switch (request.information_class)
        {
            case RDP_SESSION_FILE_BASIC_INFORMATION:
                io_status = rdp_session_apply_basic_information(file, request.buffer, request.length);
                break;
            case RDP_SESSION_FILE_END_OF_FILE_INFORMATION:
            case RDP_SESSION_FILE_ALLOCATION_INFORMATION:
                io_status = rdp_session_apply_size_information(file, request.buffer, request.length);
                break;
            case RDP_SESSION_FILE_DISPOSITION_INFORMATION:
                io_status = rdp_session_apply_disposition_information(file, request.buffer, request.length);
                break;
            case RDP_SESSION_FILE_RENAME_INFORMATION:
                io_status = rdp_session_apply_rename_information(session, file, &request);
                break;
            default:
                io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
                break;
        }
    }

    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_length_response(&response,
                                                              request.io.device_id,
                                                              request.io.completion_id,
                                                              io_status,
                                                              0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.set_information.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.set_information",
                        "device_id=%u file_id=%u completion_id=%u class=%u status=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        request.information_class,
                        io_status);
    return status;
}

static librdp_status rdp_session_handle_filesystem_read(librdp_session* session,
                                                        const uint8_t* data,
                                                        size_t data_len)
{
    rdp_filesystem_redirection_read_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer response;
    uint8_t* bytes = NULL;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t read_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_read_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (request.length > RDP_SESSION_MAX_FILE_IO_BYTES)
    {
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    }
    else
    {
        file = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
        if (!file)
        {
            io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
        }
        else if (rdp_session_seek_fd(file->fd, request.offset) != 0)
        {
            io_status = rdp_session_errno_to_device_status(errno);
        }
        else if (request.length > 0)
        {
            ssize_t count = 0;

            bytes = (uint8_t*)malloc(request.length);
            if (!bytes)
                io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
            else
            {
                do
                {
                    count = read(file->fd, bytes, request.length);
                } while (count < 0 && errno == EINTR);
                if (count < 0)
                    io_status = rdp_session_errno_to_device_status(errno);
                else
                    read_len = (uint32_t)count;
            }
        }
    }

    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_read_response(&response,
                                                            request.io.device_id,
                                                            request.io.completion_id,
                                                            io_status,
                                                            bytes,
                                                            read_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.read.response");
    rdp_buffer_free(&response);
    free(bytes);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.read",
                        "device_id=%u file_id=%u completion_id=%u status=%u requested=%u read=%u offset=%llu",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        io_status,
                        request.length,
                        read_len,
                        (unsigned long long)request.offset);
    return status;
}

static librdp_status rdp_session_handle_filesystem_write(librdp_session* session,
                                                         const uint8_t* data,
                                                         size_t data_len)
{
    rdp_filesystem_redirection_write_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t written = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_write_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (request.length > RDP_SESSION_MAX_FILE_IO_BYTES)
    {
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    }
    else
    {
        file = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
        if (!file)
        {
            io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
        }
        else if (request.offset == UINT64_MAX)
        {
            if (lseek(file->fd, 0, SEEK_END) == (off_t)-1)
                io_status = rdp_session_errno_to_device_status(errno);
        }
        else if (rdp_session_seek_fd(file->fd, request.offset) != 0)
        {
            io_status = rdp_session_errno_to_device_status(errno);
        }
        if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
        {
            const uint8_t* cursor = request.data;
            uint32_t remaining = request.length;

            while (remaining > 0)
            {
                ssize_t count = write(file->fd, cursor, remaining);

                if (count < 0 && errno == EINTR)
                    continue;
                if (count <= 0)
                {
                    io_status = count < 0 ? rdp_session_errno_to_device_status(errno)
                                          : RDP_SESSION_DEVICE_NOT_SUPPORTED;
                    break;
                }
                cursor += (size_t)count;
                remaining -= (uint32_t)count;
                written += (uint32_t)count;
            }
        }
    }

    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_write_response(&response,
                                                             request.io.device_id,
                                                             request.io.completion_id,
                                                             io_status,
                                                             written);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.write.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.write",
                        "device_id=%u file_id=%u completion_id=%u status=%u requested=%u written=%u offset=%llu",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        io_status,
                        request.length,
                        written,
                        (unsigned long long)request.offset);
    return status;
}

static librdp_status rdp_session_handle_filesystem_query_volume(librdp_session* session,
                                                                const uint8_t* data,
                                                                size_t data_len)
{
    rdp_filesystem_redirection_information_request request;
    rdp_buffer payload;
    rdp_buffer response;
    uint32_t drive_index = 0;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    const char* root = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_query_volume_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    drive_index = rdp_session_drive_index_from_device_id(session, request.io.device_id);
    if (drive_index == UINT32_MAX)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    else
    {
        rdp_buffer_init(&payload);
        root = librdp_settings_drive_path(session->settings, drive_index);
        status = rdp_session_write_volume_information(&payload, request.information_class, root);
        if (status == LIBRDP_STATUS_UNSUPPORTED)
            io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
        else if (status != LIBRDP_STATUS_OK)
            io_status = rdp_session_filesystem_error_from_status(status);
    }

    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_buffer_response(&response,
                                                              request.io.device_id,
                                                              request.io.completion_id,
                                                              io_status,
                                                              io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                  payload.data :
                                                                  NULL,
                                                              io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                  (uint32_t)payload.length :
                                                                  0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.query_volume.response");
    rdp_buffer_free(&response);
    if (drive_index != UINT32_MAX)
        rdp_buffer_free(&payload);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.query_volume",
                        "device_id=%u completion_id=%u class=%u status=%u",
                        request.io.device_id,
                        request.io.completion_id,
                        request.information_class,
                        io_status);
    return status;
}

static librdp_status rdp_session_handle_filesystem_query_information(librdp_session* session,
                                                                     const uint8_t* data,
                                                                     size_t data_len)
{
    rdp_filesystem_redirection_information_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer payload;
    rdp_buffer response;
    struct stat st;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_query_information_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(&st, 0, sizeof(st));
    rdp_buffer_init(&payload);

    file = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
    if (!file)
    {
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    }
    else if (fstat(file->fd, &st) != 0)
    {
        io_status = rdp_session_errno_to_device_status(errno);
    }
    else
    {
        status = rdp_session_write_file_information(&payload, request.information_class, &st);
        if (status == LIBRDP_STATUS_UNSUPPORTED)
            io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
        else if (status != LIBRDP_STATUS_OK)
            io_status = rdp_session_filesystem_error_from_status(status);
    }

    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_buffer_response(&response,
                                                              request.io.device_id,
                                                              request.io.completion_id,
                                                              io_status,
                                                              io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                  payload.data :
                                                                  NULL,
                                                              io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                  (uint32_t)payload.length :
                                                                  0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.query_information.response");
    rdp_buffer_free(&response);
    rdp_buffer_free(&payload);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.query_information",
                        "device_id=%u file_id=%u completion_id=%u class=%u status=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        request.information_class,
                        io_status);
    return status;
}

static librdp_status rdp_session_handle_filesystem_query_directory(librdp_session* session,
                                                                   const uint8_t* data,
                                                                   size_t data_len)
{
    rdp_filesystem_redirection_query_directory_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer payload;
    rdp_buffer response;
    struct dirent* entry = NULL;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t payload_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_query_directory_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&payload);

    file = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
    if (!file || !file->path)
    {
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    }
    else
    {
        if (request.initial_query || !file->directory)
        {
            char* directory_path = NULL;
            char* pattern = NULL;

            if (file->directory)
            {
                (void)closedir(file->directory);
                file->directory = NULL;
            }
            free(file->directory_path);
            free(file->directory_pattern);
            file->directory_path = NULL;
            file->directory_pattern = NULL;
            status = rdp_session_make_query_directory(session, file, &request, &directory_path, &pattern);
            if (status == LIBRDP_STATUS_OK)
            {
                file->directory = opendir(directory_path);
                if (!file->directory)
                {
                    io_status = rdp_session_errno_to_device_status(errno);
                    free(directory_path);
                    free(pattern);
                }
                else
                {
                    file->directory_path = directory_path;
                    file->directory_pattern = pattern;
                }
            }
            else
            {
                io_status = rdp_session_filesystem_error_from_status(status);
            }
        }

        while (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS && file->directory)
        {
            struct stat st;
            char* child_path = NULL;

            errno = 0;
            entry = readdir(file->directory);
            if (!entry)
            {
                io_status = errno == 0 ? RDP_SESSION_DEVICE_NO_MORE_FILES :
                                         rdp_session_errno_to_device_status(errno);
                break;
            }
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            if (fnmatch(file->directory_pattern ? file->directory_pattern : "*", entry->d_name, 0) != 0)
                continue;
            child_path = rdp_session_join_path(file->directory_path ? file->directory_path : file->path,
                                               entry->d_name);
            if (!child_path)
            {
                io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
                break;
            }
            memset(&st, 0, sizeof(st));
            if (stat(child_path, &st) != 0)
            {
                free(child_path);
                continue;
            }
            free(child_path);
            status = rdp_session_write_directory_information(&payload,
                                                             request.information_class,
                                                             &st,
                                                             entry->d_name);
            if (status == LIBRDP_STATUS_UNSUPPORTED)
                io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
            else if (status != LIBRDP_STATUS_OK)
                io_status = rdp_session_filesystem_error_from_status(status);
            break;
        }
    }

    payload_len = (uint32_t)payload.length;
    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_buffer_response(&response,
                                                              request.io.device_id,
                                                              request.io.completion_id,
                                                              io_status,
                                                              io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                  payload.data :
                                                                  NULL,
                                                              io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                  (uint32_t)payload.length :
                                                                  0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.query_directory.response");
    rdp_buffer_free(&response);
    rdp_buffer_free(&payload);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.query_directory",
                        "device_id=%u file_id=%u completion_id=%u class=%u initial=%u status=%u bytes=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        request.information_class,
                        request.initial_query,
                        io_status,
                        payload_len);
    return status;
}

static uint32_t rdp_session_apply_file_locks(rdp_session_redirected_file* file,
                                             const rdp_filesystem_redirection_lock_request* request)
{
    uint32_t i = 0;
    short type = F_UNLCK;

    if (!file || file->fd < 0 || !request)
        return RDP_SESSION_DEVICE_NO_SUCH_FILE;
    switch (request->operation)
    {
        case RDP_FILESYSTEM_REDIRECTION_LOWIO_SHAREDLOCK:
            type = F_RDLCK;
            break;
        case RDP_FILESYSTEM_REDIRECTION_LOWIO_EXCLUSIVELOCK:
            type = F_WRLCK;
            break;
        case RDP_FILESYSTEM_REDIRECTION_LOWIO_UNLOCK:
        case RDP_FILESYSTEM_REDIRECTION_LOWIO_UNLOCK_MULTIPLE:
            type = F_UNLCK;
            break;
        default:
            return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    }
    for (i = 0; i < request->lock_count; i++)
    {
        struct flock lock;

        if (request->locks[i].offset > (uint64_t)INT64_MAX ||
            request->locks[i].length > (uint64_t)INT64_MAX)
            return RDP_SESSION_DEVICE_INVALID_PARAMETER;
        memset(&lock, 0, sizeof(lock));
        lock.l_type = type;
        lock.l_whence = SEEK_SET;
        lock.l_start = (off_t)request->locks[i].offset;
        lock.l_len = (off_t)request->locks[i].length;
        if (fcntl(file->fd, F_SETLK, &lock) != 0)
        {
            if (errno == EACCES || errno == EAGAIN)
                return RDP_SESSION_DEVICE_LOCK_NOT_GRANTED;
            return rdp_session_errno_to_device_status(errno);
        }
    }
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static librdp_status rdp_session_handle_filesystem_lock(librdp_session* session,
                                                        const uint8_t* data,
                                                        size_t data_len)
{
    rdp_filesystem_redirection_lock_request request;
    rdp_session_redirected_file* file = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_lock_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    file = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
    if (!file)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    else
        io_status = rdp_session_apply_file_locks(file, &request);

    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_lock_response(&response,
                                                            request.io.device_id,
                                                            request.io.completion_id,
                                                            io_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.lock.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.lock",
                        "device_id=%u file_id=%u completion_id=%u operation=%u locks=%u status=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        request.operation,
                        request.lock_count,
                        io_status);
    return status;
}

static librdp_status rdp_session_handle_filesystem_notify_change(librdp_session* session,
                                                                 const uint8_t* data,
                                                                 size_t data_len)
{
    rdp_filesystem_redirection_notify_change_request request;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_notify_change_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id))
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;

    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_buffer_response(&response,
                                                              request.io.device_id,
                                                              request.io.completion_id,
                                                              io_status,
                                                              NULL,
                                                              0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.notify_change.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.notify_change",
                        "device_id=%u file_id=%u completion_id=%u watch_tree=%u filter=%u status=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        request.watch_tree,
                        request.completion_filter,
                        io_status);
    return status;
}

static librdp_status rdp_session_handle_filesystem_set_volume(librdp_session* session,
                                                              const uint8_t* data,
                                                              size_t data_len)
{
    rdp_filesystem_redirection_information_request request;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_set_volume_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_session_drive_index_from_device_id(session, request.io.device_id) == UINT32_MAX)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    else
        io_status = RDP_SESSION_DEVICE_ACCESS_DENIED;

    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_length_response(&response,
                                                              request.io.device_id,
                                                              request.io.completion_id,
                                                              io_status,
                                                              0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.set_volume.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.set_volume",
                        "device_id=%u completion_id=%u class=%u status=%u",
                        request.io.device_id,
                        request.io.completion_id,
                        request.information_class,
                        io_status);
    return status;
}

static librdp_status rdp_session_write_filesystem_unsupported_response(
    rdp_buffer* response,
    const rdp_device_redirection_io_request* request,
    uint32_t io_status)
{
    if (!response || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (request->major_function)
    {
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_VOLUME_INFORMATION:
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION:
        case RDP_DEVICE_REDIRECTION_IRP_DIRECTORY_CONTROL:
        case RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL:
            return rdp_filesystem_redirection_write_buffer_response(response,
                                                                    request->device_id,
                                                                    request->completion_id,
                                                                    io_status,
                                                                    NULL,
                                                                    0);
        case RDP_DEVICE_REDIRECTION_IRP_SET_VOLUME_INFORMATION:
        case RDP_DEVICE_REDIRECTION_IRP_SET_INFORMATION:
            return rdp_filesystem_redirection_write_length_response(response,
                                                                    request->device_id,
                                                                    request->completion_id,
                                                                    io_status,
                                                                    0);
        case RDP_DEVICE_REDIRECTION_IRP_LOCK_CONTROL:
            return rdp_filesystem_redirection_write_lock_response(response,
                                                                  request->device_id,
                                                                  request->completion_id,
                                                                  io_status);
        default:
            return rdp_device_redirection_write_io_completion(response,
                                                              request->device_id,
                                                              request->completion_id,
                                                              io_status,
                                                              NULL,
                                                              0);
    }
}

static librdp_status rdp_session_validate_filesystem_unsupported_request(const uint8_t* data,
                                                                         size_t data_len,
                                                                         const rdp_device_redirection_io_request* request)
{
    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (request->major_function)
    {
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_VOLUME_INFORMATION:
        {
            rdp_filesystem_redirection_information_request typed;
            return rdp_filesystem_redirection_parse_query_volume_request(data, data_len, &typed);
        }
        case RDP_DEVICE_REDIRECTION_IRP_SET_VOLUME_INFORMATION:
        {
            rdp_filesystem_redirection_information_request typed;
            return rdp_filesystem_redirection_parse_set_volume_request(data, data_len, &typed);
        }
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION:
        {
            rdp_filesystem_redirection_information_request typed;
            return rdp_filesystem_redirection_parse_query_information_request(data, data_len, &typed);
        }
        case RDP_DEVICE_REDIRECTION_IRP_SET_INFORMATION:
        {
            rdp_filesystem_redirection_information_request typed;
            return rdp_filesystem_redirection_parse_set_information_request(data, data_len, &typed);
        }
        case RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL:
        {
            rdp_filesystem_redirection_control_request typed;
            return rdp_filesystem_redirection_parse_control_request(data, data_len, &typed);
        }
        case RDP_DEVICE_REDIRECTION_IRP_DIRECTORY_CONTROL:
            if (request->minor_function == RDP_FILESYSTEM_REDIRECTION_MINOR_QUERY_DIRECTORY)
            {
                rdp_filesystem_redirection_query_directory_request typed;
                return rdp_filesystem_redirection_parse_query_directory_request(data, data_len, &typed);
            }
            if (request->minor_function == RDP_FILESYSTEM_REDIRECTION_MINOR_NOTIFY_CHANGE_DIRECTORY)
            {
                rdp_filesystem_redirection_notify_change_request typed;
                return rdp_filesystem_redirection_parse_notify_change_request(data, data_len, &typed);
            }
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        case RDP_DEVICE_REDIRECTION_IRP_LOCK_CONTROL:
        {
            rdp_filesystem_redirection_lock_request typed;
            return rdp_filesystem_redirection_parse_lock_request(data, data_len, &typed);
        }
        default:
            return LIBRDP_STATUS_OK;
    }
}

static librdp_status rdp_session_handle_filesystem_unsupported(librdp_session* session,
                                                               const uint8_t* data,
                                                               size_t data_len,
                                                               const rdp_device_redirection_io_request* request,
                                                               uint32_t io_status)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_validate_filesystem_unsupported_request(data, data_len, request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&response);
    status = rdp_session_write_filesystem_unsupported_response(&response, request, io_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.file.unsupported.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.file.unsupported",
                        "device_id=%u file_id=%u completion_id=%u major=%u minor=%u status=%u",
                        request->device_id,
                        request->file_id,
                        request->completion_id,
                        request->major_function,
                        request->minor_function,
                        io_status);
    return status;
}

static librdp_status rdp_session_handle_filesystem_io_request(librdp_session* session,
                                                              const uint8_t* data,
                                                              size_t data_len)
{
    rdp_device_redirection_io_request request;
    uint32_t io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_parse_io_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_session_drive_index_from_device_id(session, request.device_id) == UINT32_MAX)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    else
        io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;

    switch (request.major_function)
    {
        case RDP_DEVICE_REDIRECTION_IRP_CREATE:
            return rdp_session_handle_filesystem_create(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_CLOSE:
            return rdp_session_handle_filesystem_close(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_READ:
            return rdp_session_handle_filesystem_read(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_WRITE:
            return rdp_session_handle_filesystem_write(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_VOLUME_INFORMATION:
            return rdp_session_handle_filesystem_query_volume(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_SET_VOLUME_INFORMATION:
            return rdp_session_handle_filesystem_set_volume(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION:
            return rdp_session_handle_filesystem_query_information(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_SET_INFORMATION:
            return rdp_session_handle_filesystem_set_information(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_DIRECTORY_CONTROL:
            if (request.minor_function == RDP_FILESYSTEM_REDIRECTION_MINOR_QUERY_DIRECTORY)
                return rdp_session_handle_filesystem_query_directory(session, data, data_len);
            if (request.minor_function == RDP_FILESYSTEM_REDIRECTION_MINOR_NOTIFY_CHANGE_DIRECTORY)
                return rdp_session_handle_filesystem_notify_change(session, data, data_len);
            return rdp_session_handle_filesystem_unsupported(session,
                                                             data,
                                                             data_len,
                                                             &request,
                                                             io_status);
        case RDP_DEVICE_REDIRECTION_IRP_LOCK_CONTROL:
            return rdp_session_handle_filesystem_lock(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL:
            return rdp_session_handle_filesystem_unsupported(session,
                                                             data,
                                                             data_len,
                                                             &request,
                                                             io_status);
        default:
            return rdp_session_handle_filesystem_unsupported(session,
                                                             data,
                                                             data_len,
                                                             &request,
                                                             io_status);
    }
}

static char rdp_session_print_path_char(char value)
{
    if ((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
        (value >= '0' && value <= '9') || value == '_' || value == '-' || value == '.')
        return value;
    return '_';
}

static librdp_status rdp_session_make_print_job_path(librdp_session* session,
                                                     uint32_t printer_index,
                                                     uint32_t file_id,
                                                     char** path)
{
    const char* output = NULL;
    const char* name = NULL;
    char safe[128];
    int needed = 0;
    size_t output_len = 0;
    size_t i = 0;

    if (!session || !path)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *path = NULL;
    output = librdp_settings_printer_output_path(session->settings, printer_index);
    name = librdp_settings_printer_name(session->settings, printer_index);
    if (!output || output[0] == '\0' || !name || name[0] == '\0')
        return LIBRDP_STATUS_STATE;
    for (i = 0; i + 1u < sizeof(safe) && name[i]; i++)
        safe[i] = rdp_session_print_path_char(name[i]);
    safe[i] = '\0';
    output_len = strlen(output);
    needed = snprintf(NULL,
                      0,
                      "%s%s%s-%08x.prn",
                      output,
                      output_len > 0 && output[output_len - 1u] == '/' ? "" : "/",
                      safe,
                      file_id);
    if (needed <= 0)
        return LIBRDP_STATUS_NO_MEMORY;
    *path = (char*)malloc((size_t)needed + 1u);
    if (!*path)
        return LIBRDP_STATUS_NO_MEMORY;
    (void)snprintf(*path,
                   (size_t)needed + 1u,
                   "%s%s%s-%08x.prn",
                   output,
                   output_len > 0 && output[output_len - 1u] == '/' ? "" : "/",
                   safe,
                   file_id);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_make_printer_cache_path(librdp_session* session,
                                                         uint32_t printer_index,
                                                         const char* printer_name,
                                                         char** path)
{
    const char* output = NULL;
    char safe[128];
    int needed = 0;
    size_t output_len = 0;
    size_t i = 0;

    if (!session || !path || !printer_name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *path = NULL;
    output = librdp_settings_printer_output_path(session->settings, printer_index);
    if (!output || output[0] == '\0')
        return LIBRDP_STATUS_STATE;
    for (i = 0; i + 1u < sizeof(safe) && printer_name[i]; i++)
        safe[i] = rdp_session_print_path_char(printer_name[i]);
    safe[i] = '\0';
    output_len = strlen(output);
    needed = snprintf(NULL,
                      0,
                      "%s%s%s.cache",
                      output,
                      output_len > 0 && output[output_len - 1u] == '/' ? "" : "/",
                      safe);
    if (needed <= 0)
        return LIBRDP_STATUS_NO_MEMORY;
    *path = (char*)malloc((size_t)needed + 1u);
    if (!*path)
        return LIBRDP_STATUS_NO_MEMORY;
    (void)snprintf(*path,
                   (size_t)needed + 1u,
                   "%s%s%s.cache",
                   output,
                   output_len > 0 && output[output_len - 1u] == '/' ? "" : "/",
                   safe);
    return LIBRDP_STATUS_OK;
}

static uint32_t rdp_session_printer_index_from_utf16_name(librdp_session* session,
                                                          const uint8_t* name,
                                                          uint32_t name_len,
                                                          uint32_t* printer_index,
                                                          char** utf8_name)
{
    char* converted = NULL;
    uint32_t count = 0;
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !printer_index || !utf8_name)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    *printer_index = UINT32_MAX;
    *utf8_name = NULL;
    status = rdp_session_utf16le_path_to_utf8(name, name_len, &converted);
    if (status != LIBRDP_STATUS_OK)
        return rdp_session_filesystem_error_from_status(status);
    count = librdp_settings_printer_count(session->settings);
    for (i = 0; i < count; i++)
    {
        const char* configured = librdp_settings_printer_name(session->settings, i);

        if (configured && strcmp(configured, converted) == 0)
        {
            *printer_index = i;
            *utf8_name = converted;
            return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
        }
    }
    free(converted);
    return RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
}

static uint32_t rdp_session_write_printer_cache_file(const char* path,
                                                     const uint8_t* data,
                                                     uint32_t data_len)
{
    int fd = -1;
    uint32_t written = 0;

    if (!path || (!data && data_len > 0))
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return rdp_session_errno_to_device_status(errno);
    while (written < data_len)
    {
        ssize_t count = write(fd, data + written, data_len - written);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
        {
            uint32_t status = count < 0 ? rdp_session_errno_to_device_status(errno) :
                                          RDP_SESSION_DEVICE_UNSUCCESSFUL;
            (void)close(fd);
            return status;
        }
        written += (uint32_t)count;
    }
    if (close(fd) != 0)
        return rdp_session_errno_to_device_status(errno);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static uint32_t rdp_session_store_printer_cache_event(librdp_session* session,
                                                      const rdp_printer_redirection_cache_event* event)
{
    char* name = NULL;
    char* old_name = NULL;
    char* new_name = NULL;
    char* path = NULL;
    char* new_path = NULL;
    uint32_t index = UINT32_MAX;
    uint32_t new_index = UINT32_MAX;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;

    if (!session || !event)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    switch (event->event_id)
    {
        case RDP_PRINTER_REDIRECTION_CACHE_ADD:
        case RDP_PRINTER_REDIRECTION_CACHE_UPDATE:
            io_status = rdp_session_printer_index_from_utf16_name(session,
                                                                  event->printer_name,
                                                                  event->printer_name_len,
                                                                  &index,
                                                                  &name);
            if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            {
                if (rdp_session_make_printer_cache_path(session, index, name, &path) != LIBRDP_STATUS_OK)
                    io_status = RDP_SESSION_DEVICE_UNSUCCESSFUL;
                else
                    io_status = rdp_session_write_printer_cache_file(path,
                                                                     event->cached_fields,
                                                                     event->cached_fields_len);
            }
            break;
        case RDP_PRINTER_REDIRECTION_CACHE_DELETE:
            io_status = rdp_session_printer_index_from_utf16_name(session,
                                                                  event->printer_name,
                                                                  event->printer_name_len,
                                                                  &index,
                                                                  &name);
            if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            {
                if (rdp_session_make_printer_cache_path(session, index, name, &path) != LIBRDP_STATUS_OK)
                    io_status = RDP_SESSION_DEVICE_UNSUCCESSFUL;
                else if (unlink(path) != 0 && errno != ENOENT)
                    io_status = rdp_session_errno_to_device_status(errno);
            }
            break;
        case RDP_PRINTER_REDIRECTION_CACHE_RENAME:
            io_status = rdp_session_printer_index_from_utf16_name(session,
                                                                  event->old_printer_name,
                                                                  event->old_printer_name_len,
                                                                  &index,
                                                                  &old_name);
            if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
                io_status = rdp_session_printer_index_from_utf16_name(session,
                                                                      event->new_printer_name,
                                                                      event->new_printer_name_len,
                                                                      &new_index,
                                                                      &new_name);
            if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            {
                if (rdp_session_make_printer_cache_path(session, index, old_name, &path) != LIBRDP_STATUS_OK ||
                    rdp_session_make_printer_cache_path(session, new_index, new_name, &new_path) !=
                        LIBRDP_STATUS_OK)
                    io_status = RDP_SESSION_DEVICE_UNSUCCESSFUL;
                else if (rename(path, new_path) != 0 && errno != ENOENT)
                    io_status = rdp_session_errno_to_device_status(errno);
            }
            break;
        default:
            io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            break;
    }
    free(name);
    free(old_name);
    free(new_name);
    free(path);
    free(new_path);
    return io_status;
}

static librdp_status rdp_session_send_printer_response(librdp_session* session,
                                                       const rdp_buffer* response,
                                                       const char* event)
{
    if (!session || !response || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_send_device_redirection_packet(session, response, event);
}

static librdp_status rdp_session_handle_printer_create(librdp_session* session,
                                                       const rdp_device_redirection_io_request* request)
{
    rdp_session_redirected_file* job = NULL;
    rdp_buffer response;
    char* path = NULL;
    uint32_t printer_index = 0;
    uint32_t file_id = 0;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    int fd = -1;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    printer_index = rdp_session_printer_index_from_device_id(session, request->device_id);
    if (printer_index == UINT32_MAX)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    else
    {
        job = rdp_session_redirected_file_alloc(session, request->device_id, &file_id);
        if (!job)
        {
            io_status = RDP_SESSION_DEVICE_PRINT_QUEUE_FULL;
        }
        else
        {
            status = rdp_session_make_print_job_path(session, printer_index, file_id, &path);
            if (status != LIBRDP_STATUS_OK)
                io_status = rdp_session_filesystem_error_from_status(status);
            else
            {
                fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
                if (fd < 0)
                    io_status = rdp_session_errno_to_device_status(errno);
            }
            if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
            {
                job->fd = fd;
                job->path = path;
                fd = -1;
                path = NULL;
            }
            else
            {
                rdp_session_redirected_file_reset(job);
                file_id = 0;
            }
        }
    }

    free(path);
    if (fd >= 0)
        (void)close(fd);
    rdp_buffer_init(&response);
    status = rdp_printer_redirection_write_create_response(&response,
                                                           request->device_id,
                                                           request->completion_id,
                                                           io_status,
                                                           file_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_printer_response(session,
                                                   &response,
                                                   "client.rdpdr.printer.create.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.printer.create",
                        "device_id=%u completion_id=%u file_id=%u status=%u",
                        request->device_id,
                        request->completion_id,
                        file_id,
                        io_status);
    return status;
}

static librdp_status rdp_session_handle_printer_close(librdp_session* session,
                                                      const rdp_device_redirection_io_request* request)
{
    rdp_session_redirected_file* job = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    job = rdp_session_redirected_file_find(session, request->device_id, request->file_id);
    if (!job)
    {
        io_status = RDP_SESSION_DEVICE_UNSUCCESSFUL;
    }
    else
    {
        if (job->fd >= 0 && close(job->fd) != 0)
            io_status = rdp_session_errno_to_device_status(errno);
        job->fd = -1;
        rdp_session_redirected_file_reset(job);
    }
    rdp_buffer_init(&response);
    status = rdp_printer_redirection_write_close_response(&response,
                                                          request->device_id,
                                                          request->completion_id,
                                                          io_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_printer_response(session,
                                                   &response,
                                                   "client.rdpdr.printer.close.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.printer.close",
                        "device_id=%u file_id=%u completion_id=%u status=%u",
                        request->device_id,
                        request->file_id,
                        request->completion_id,
                        io_status);
    return status;
}

static librdp_status rdp_session_handle_printer_write(librdp_session* session,
                                                      const uint8_t* data,
                                                      size_t data_len)
{
    rdp_filesystem_redirection_write_request request;
    rdp_session_redirected_file* job = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t written = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_filesystem_redirection_parse_write_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (request.length > RDP_SESSION_MAX_FILE_IO_BYTES)
    {
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    }
    else
    {
        job = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
        if (!job)
        {
            io_status = RDP_SESSION_DEVICE_UNSUCCESSFUL;
        }
        else
        {
            const uint8_t* cursor = request.data;
            uint32_t remaining = request.length;

            while (remaining > 0)
            {
                ssize_t count = write(job->fd, cursor, remaining);

                if (count < 0 && errno == EINTR)
                    continue;
                if (count <= 0)
                {
                    io_status = count < 0 ? rdp_session_errno_to_device_status(errno)
                                          : RDP_SESSION_DEVICE_UNSUCCESSFUL;
                    break;
                }
                cursor += (size_t)count;
                remaining -= (uint32_t)count;
                written += (uint32_t)count;
            }
        }
    }
    rdp_buffer_init(&response);
    status = rdp_printer_redirection_write_write_response(&response,
                                                          request.io.device_id,
                                                          request.io.completion_id,
                                                          io_status,
                                                          written);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_printer_response(session,
                                                   &response,
                                                   "client.rdpdr.printer.write.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.printer.write",
                        "device_id=%u file_id=%u completion_id=%u status=%u requested=%u written=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        io_status,
                        request.length,
                        written);
    return status;
}

static librdp_status rdp_session_handle_printer_device_control(librdp_session* session,
                                                               const rdp_device_redirection_io_request* request)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_printer_redirection_write_device_control_response(&response,
                                                                   request->device_id,
                                                                   request->completion_id,
                                                                   RDP_DEVICE_REDIRECTION_STATUS_SUCCESS);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_printer_response(session,
                                                   &response,
                                                   "client.rdpdr.printer.device_control.response");
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_handle_printer_unsupported(librdp_session* session,
                                                            const rdp_device_redirection_io_request* request)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_device_redirection_write_io_completion(&response,
                                                        request->device_id,
                                                        request->completion_id,
                                                        RDP_SESSION_DEVICE_NOT_SUPPORTED,
                                                        NULL,
                                                        0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_printer_response(session,
                                                   &response,
                                                   "client.rdpdr.printer.unsupported.response");
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_handle_printer_io_request(librdp_session* session,
                                                           const uint8_t* data,
                                                           size_t data_len)
{
    rdp_device_redirection_io_request request;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_parse_io_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    switch (request.major_function)
    {
        case RDP_DEVICE_REDIRECTION_IRP_CREATE:
            return rdp_session_handle_printer_create(session, &request);
        case RDP_DEVICE_REDIRECTION_IRP_CLOSE:
            return rdp_session_handle_printer_close(session, &request);
        case RDP_DEVICE_REDIRECTION_IRP_WRITE:
            return rdp_session_handle_printer_write(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL:
            return rdp_session_handle_printer_device_control(session, &request);
        default:
            return rdp_session_handle_printer_unsupported(session, &request);
    }
}

static librdp_status rdp_session_send_smartcard_io_completion(librdp_session* session,
                                                              const rdp_device_redirection_io_request* request,
                                                              const rdp_buffer* payload,
                                                              const char* event)
{
    rdp_buffer wrapped;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request || !payload || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&wrapped);
    rdp_buffer_init(&response);
    status = rdp_smartcard_redirection_write_device_control_response(&wrapped,
                                                                     payload->data,
                                                                     (uint32_t)payload->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_device_redirection_write_io_completion(&response,
                                                            request->device_id,
                                                            request->completion_id,
                                                            RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                            wrapped.data,
                                                            wrapped.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session, &response, event);
    rdp_buffer_free(&response);
    rdp_buffer_free(&wrapped);
    return status;
}

static librdp_status rdp_session_send_smartcard_simple_completion(librdp_session* session,
                                                                  const rdp_device_redirection_io_request* request,
                                                                  uint32_t io_status,
                                                                  const char* event)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_device_redirection_write_io_completion(&response,
                                                        request->device_id,
                                                        request->completion_id,
                                                        io_status,
                                                        NULL,
                                                        0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session, &response, event);
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_send_smartcard_long_result(librdp_session* session,
                                                            const rdp_device_redirection_io_request* request,
                                                            uint32_t return_code,
                                                            const char* event)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_smartcard_redirection_write_long_return(&payload, return_code);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session, request, &payload, event);
    rdp_buffer_free(&payload);
    return status;
}

#ifdef RDP_HAVE_PCSC
static void rdp_session_smartcard_write_blob(uint8_t blob[RDP_SESSION_SMARTCARD_BLOB_BYTES],
                                             uint32_t id,
                                             uint32_t generation)
{
    blob[0] = (uint8_t)(id & 0xffu);
    blob[1] = (uint8_t)((id >> 8u) & 0xffu);
    blob[2] = (uint8_t)((id >> 16u) & 0xffu);
    blob[3] = (uint8_t)((id >> 24u) & 0xffu);
    blob[4] = (uint8_t)(generation & 0xffu);
    blob[5] = (uint8_t)((generation >> 8u) & 0xffu);
    blob[6] = (uint8_t)((generation >> 16u) & 0xffu);
    blob[7] = (uint8_t)((generation >> 24u) & 0xffu);
}

static int rdp_session_smartcard_read_blob(const uint8_t* data,
                                           uint32_t length,
                                           uint32_t* id,
                                           uint32_t* generation)
{
    if (!data || length != RDP_SESSION_SMARTCARD_BLOB_BYTES || !id || !generation)
        return 0;
    *id = (uint32_t)data[0] | ((uint32_t)data[1] << 8u) | ((uint32_t)data[2] << 16u) |
          ((uint32_t)data[3] << 24u);
    *generation = (uint32_t)data[4] | ((uint32_t)data[5] << 8u) | ((uint32_t)data[6] << 16u) |
                  ((uint32_t)data[7] << 24u);
    return *id != 0 && *generation != 0;
}

static rdp_session_smartcard_context* rdp_session_smartcard_context_find(librdp_session* session,
                                                                         const uint8_t* data,
                                                                         uint32_t length)
{
    uint32_t id = 0;
    uint32_t generation = 0;

    if (!session || !rdp_session_smartcard_read_blob(data, length, &id, &generation))
        return NULL;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_CONTEXTS; i++)
    {
        rdp_session_smartcard_context* context = &session->smartcard_contexts[i];

        if (context->active && context->id == id && context->generation == generation)
            return context;
    }
    return NULL;
}

static rdp_session_smartcard_handle* rdp_session_smartcard_handle_find(librdp_session* session,
                                                                       const uint8_t* data,
                                                                       uint32_t length)
{
    uint32_t id = 0;
    uint32_t generation = 0;

    if (!session || !rdp_session_smartcard_read_blob(data, length, &id, &generation))
        return NULL;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_HANDLES; i++)
    {
        rdp_session_smartcard_handle* handle = &session->smartcard_handles[i];

        if (handle->active && handle->id == id && handle->generation == generation)
            return handle;
    }
    return NULL;
}

static rdp_session_smartcard_context* rdp_session_smartcard_context_alloc(librdp_session* session,
                                                                          SCARDCONTEXT pcsc_context)
{
    if (!session)
        return NULL;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_CONTEXTS; i++)
    {
        rdp_session_smartcard_context* context = &session->smartcard_contexts[i];

        if (!context->active)
        {
            memset(context, 0, sizeof(*context));
            context->active = 1;
            context->id = ++session->next_smartcard_context_id;
            if (context->id == 0)
                context->id = ++session->next_smartcard_context_id;
            context->generation++;
            if (context->generation == 0)
                context->generation = 1;
            context->context = pcsc_context;
            return context;
        }
    }
    return NULL;
}

static rdp_session_smartcard_handle* rdp_session_smartcard_handle_alloc(
    librdp_session* session,
    const rdp_session_smartcard_context* context,
    SCARDHANDLE pcsc_handle,
    DWORD active_protocol)
{
    if (!session || !context)
        return NULL;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_HANDLES; i++)
    {
        rdp_session_smartcard_handle* handle = &session->smartcard_handles[i];

        if (!handle->active)
        {
            memset(handle, 0, sizeof(*handle));
            handle->active = 1;
            handle->id = ++session->next_smartcard_handle_id;
            if (handle->id == 0)
                handle->id = ++session->next_smartcard_handle_id;
            handle->generation++;
            if (handle->generation == 0)
                handle->generation = 1;
            handle->context_id = context->id;
            handle->context_generation = context->generation;
            handle->handle = pcsc_handle;
            handle->active_protocol = active_protocol;
            return handle;
        }
    }
    return NULL;
}

static DWORD rdp_session_smartcard_protocol_to_pcsc(uint32_t protocol)
{
    uint32_t base = protocol & ~RDP_SMARTCARD_REDIRECTION_PROTOCOL_DEFAULT;
    DWORD pcsc = 0;

    if (base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0)
        pcsc = SCARD_PROTOCOL_T0;
    else if (base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1)
        pcsc = SCARD_PROTOCOL_T1;
    else if (base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_TX || base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED)
        pcsc = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
#ifdef SCARD_PROTOCOL_RAW
    else if (base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_RAW)
        pcsc = SCARD_PROTOCOL_RAW;
#endif
    return pcsc;
}

static uint32_t rdp_session_smartcard_protocol_from_pcsc(DWORD protocol)
{
    if (protocol & SCARD_PROTOCOL_T1)
        return RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1;
    if (protocol & SCARD_PROTOCOL_T0)
        return RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0;
    return RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED;
}

static uint32_t rdp_session_smartcard_u32_from_dword(DWORD value)
{
    return value > UINT32_MAX ? UINT32_MAX : (uint32_t)value;
}

static const SCARD_IO_REQUEST* rdp_session_smartcard_pci_from_protocol(uint32_t protocol)
{
    uint32_t base = protocol & ~RDP_SMARTCARD_REDIRECTION_PROTOCOL_DEFAULT;

    if (base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0)
        return SCARD_PCI_T0;
    if (base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1)
        return SCARD_PCI_T1;
#ifdef SCARD_PCI_RAW
    if (base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_RAW)
        return SCARD_PCI_RAW;
#endif
    return NULL;
}

static DWORD rdp_session_smartcard_scope_to_pcsc(uint32_t scope)
{
    if (scope == RDP_SMARTCARD_REDIRECTION_SCOPE_USER)
        return SCARD_SCOPE_USER;
    if (scope == RDP_SMARTCARD_REDIRECTION_SCOPE_TERMINAL)
#ifdef SCARD_SCOPE_TERMINAL
        return SCARD_SCOPE_TERMINAL;
#else
        return SCARD_SCOPE_SYSTEM;
#endif
    return SCARD_SCOPE_SYSTEM;
}

static void rdp_session_smartcard_reset(librdp_session* session)
{
    if (!session)
        return;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_HANDLES; i++)
    {
        rdp_session_smartcard_handle* handle = &session->smartcard_handles[i];

        if (handle->active)
        {
            (void)SCardDisconnect(handle->handle, SCARD_LEAVE_CARD);
            memset(handle, 0, sizeof(*handle));
        }
    }
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_CONTEXTS; i++)
    {
        rdp_session_smartcard_context* context = &session->smartcard_contexts[i];

        if (context->active)
        {
            (void)SCardReleaseContext(context->context);
            memset(context, 0, sizeof(*context));
        }
    }
}

static librdp_status rdp_session_smartcard_handle_establish(librdp_session* session,
                                                            const rdp_device_redirection_io_request* request,
                                                            const rdp_smartcard_redirection_request_message* message)
{
    rdp_buffer payload;
    uint8_t context_blob[RDP_SESSION_SMARTCARD_BLOB_BYTES];
    SCARDCONTEXT pcsc_context = 0;
    rdp_session_smartcard_context* context = NULL;
    LONG pcsc_status = SCARD_S_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    memset(context_blob, 0, sizeof(context_blob));
    pcsc_status = SCardEstablishContext(rdp_session_smartcard_scope_to_pcsc(message->body.establish_context.scope),
                                        NULL,
                                        NULL,
                                        &pcsc_context);
    if (pcsc_status == SCARD_S_SUCCESS)
    {
        context = rdp_session_smartcard_context_alloc(session, pcsc_context);
        if (!context)
        {
            (void)SCardReleaseContext(pcsc_context);
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
        }
        else
        {
            rdp_session_smartcard_write_blob(context_blob, context->id, context->generation);
        }
    }
    status = rdp_smartcard_redirection_write_establish_context_return(&payload,
                                                                      (uint32_t)pcsc_status,
                                                                      context_blob,
                                                                      pcsc_status == SCARD_S_SUCCESS ?
                                                                          sizeof(context_blob) :
                                                                          0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.establish_context");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.establish_context",
                    "device_id=%u completion_id=%u status=%ld",
                    request->device_id,
                    request->completion_id,
                    pcsc_status);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_session_smartcard_handle_context(librdp_session* session,
                                                          const rdp_device_redirection_io_request* request,
                                                          const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_context* context = NULL;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;

    context = rdp_session_smartcard_context_find(session,
                                                 message->body.context.data,
                                                 message->body.context.length);
    if (context)
    {
        if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_RELEASECONTEXT)
        {
            pcsc_status = SCardReleaseContext(context->context);
            if (pcsc_status == SCARD_S_SUCCESS)
                memset(context, 0, sizeof(*context));
        }
        else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_ISVALIDCONTEXT)
        {
            pcsc_status = SCardIsValidContext(context->context);
        }
        else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_CANCEL)
        {
            pcsc_status = SCardCancel(context->context);
        }
    }
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.context",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status);
    return rdp_session_send_smartcard_long_result(session,
                                                  request,
                                                  (uint32_t)pcsc_status,
                                                  "client.rdpdr.smartcard.context.response");
}

static librdp_status rdp_session_smartcard_handle_handle_only(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_handle* handle = NULL;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    DWORD count = 0;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    handle = rdp_session_smartcard_handle_find(session,
                                               message->body.handle.data,
                                               message->body.handle.length);
    if (handle)
    {
        if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_BEGINTRANSACTION)
            pcsc_status = SCardBeginTransaction(handle->handle);
        else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_GETTRANSMITCOUNT)
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_UNSUPPORTED_FEATURE;
    }
    if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_GETTRANSMITCOUNT)
        status = rdp_smartcard_redirection_write_count_return(&payload,
                                                              (uint32_t)pcsc_status,
                                                              rdp_session_smartcard_u32_from_dword(count));
    else
        status = rdp_smartcard_redirection_write_long_return(&payload, (uint32_t)pcsc_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.handle.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.handle",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_session_smartcard_handle_connect(librdp_session* session,
                                                          const rdp_device_redirection_io_request* request,
                                                          const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_context* context = NULL;
    rdp_session_smartcard_handle* handle = NULL;
    uint8_t handle_blob[RDP_SESSION_SMARTCARD_BLOB_BYTES];
    char readers[4096];
    DWORD readers_len = sizeof(readers);
    DWORD active_protocol = 0;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(handle_blob, 0, sizeof(handle_blob));
    memset(readers, 0, sizeof(readers));
    rdp_buffer_init(&payload);
    context = rdp_session_smartcard_context_find(session,
                                                 message->body.connect.context.data,
                                                 message->body.connect.context.length);
    if (context)
    {
        pcsc_status = SCardListReaders(context->context, NULL, readers, &readers_len);
        if (pcsc_status == SCARD_S_SUCCESS && readers_len > 1u && readers[0] != '\0')
        {
            SCARDHANDLE pcsc_handle = 0;

            pcsc_status = SCardConnect(context->context,
                                       readers,
                                       message->body.connect.share_mode,
                                       rdp_session_smartcard_protocol_to_pcsc(message->body.connect.preferred_protocols),
                                       &pcsc_handle,
                                       &active_protocol);
            if (pcsc_status == SCARD_S_SUCCESS)
            {
                handle = rdp_session_smartcard_handle_alloc(session, context, pcsc_handle, active_protocol);
                if (!handle)
                {
                    (void)SCardDisconnect(pcsc_handle, SCARD_LEAVE_CARD);
                    pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
                }
                else
                {
                    rdp_session_smartcard_write_blob(handle_blob, handle->id, handle->generation);
                }
            }
        }
    }
    status = rdp_smartcard_redirection_write_connect_return(
        &payload,
        (uint32_t)pcsc_status,
        message->body.connect.context.data,
        pcsc_status == SCARD_S_SUCCESS ? message->body.connect.context.length : 0,
        handle_blob,
        pcsc_status == SCARD_S_SUCCESS ? sizeof(handle_blob) : 0,
        pcsc_status == SCARD_S_SUCCESS ?
            rdp_session_smartcard_protocol_from_pcsc(active_protocol) :
            RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.connect.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.connect",
                    "device_id=%u completion_id=%u status=%ld protocol=%u readers_len=%u",
                    request->device_id,
                    request->completion_id,
                    pcsc_status,
                    rdp_session_smartcard_protocol_from_pcsc(active_protocol),
                    (unsigned)readers_len);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_session_smartcard_handle_disposition(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_handle* handle = NULL;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;

    handle = rdp_session_smartcard_handle_find(session,
                                               message->body.handle_disposition.handle.data,
                                               message->body.handle_disposition.handle.length);
    if (handle)
    {
        if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_DISCONNECT)
        {
            pcsc_status = SCardDisconnect(handle->handle, message->body.handle_disposition.disposition);
            if (pcsc_status == SCARD_S_SUCCESS)
                memset(handle, 0, sizeof(*handle));
        }
        else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_ENDTRANSACTION)
        {
            pcsc_status = SCardEndTransaction(handle->handle, message->body.handle_disposition.disposition);
        }
    }
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.disposition",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status);
    return rdp_session_send_smartcard_long_result(session,
                                                  request,
                                                  (uint32_t)pcsc_status,
                                                  "client.rdpdr.smartcard.disposition.response");
}

static librdp_status rdp_session_smartcard_handle_reconnect(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_handle* handle = NULL;
    DWORD active_protocol = 0;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    handle = rdp_session_smartcard_handle_find(session,
                                               message->body.reconnect.handle.data,
                                               message->body.reconnect.handle.length);
    if (handle)
    {
        active_protocol = handle->active_protocol;
        pcsc_status = SCardReconnect(handle->handle,
                                     message->body.reconnect.share_mode,
                                     rdp_session_smartcard_protocol_to_pcsc(message->body.reconnect.preferred_protocols),
                                     message->body.reconnect.initialization,
                                     &active_protocol);
        if (pcsc_status == SCARD_S_SUCCESS)
            handle->active_protocol = active_protocol;
    }
    status = rdp_smartcard_redirection_write_reconnect_return(
        &payload,
        (uint32_t)pcsc_status,
        pcsc_status == SCARD_S_SUCCESS ?
            rdp_session_smartcard_protocol_from_pcsc(active_protocol) :
            RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.reconnect.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.reconnect",
                    "device_id=%u completion_id=%u status=%ld protocol=%u",
                    request->device_id,
                    request->completion_id,
                    pcsc_status,
                    rdp_session_smartcard_protocol_from_pcsc(active_protocol));
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_session_smartcard_handle_state(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_handle* handle = NULL;
    DWORD state = 0;
    DWORD protocol = 0;
    DWORD atr_len = RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH;
    DWORD reader_names_len = 0;
    uint8_t atr[RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH];
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(atr, 0, sizeof(atr));
    rdp_buffer_init(&payload);
    handle = rdp_session_smartcard_handle_find(session,
                                               message->body.state.handle.data,
                                               message->body.state.handle.length);
    if (handle)
        pcsc_status = SCardStatus(handle->handle, NULL, &reader_names_len, &state, &protocol, atr, &atr_len);
    status = rdp_smartcard_redirection_write_status_return(
        &payload,
        (uint32_t)pcsc_status,
        NULL,
        0,
        rdp_session_smartcard_u32_from_dword(state),
        pcsc_status == SCARD_S_SUCCESS ?
            rdp_session_smartcard_protocol_from_pcsc(protocol) :
            RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED,
        atr,
        pcsc_status == SCARD_S_SUCCESS ? rdp_session_smartcard_u32_from_dword(atr_len) : 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.state.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.state",
                    "device_id=%u completion_id=%u status=%ld state=%u protocol=%u atr_len=%u",
                    request->device_id,
                    request->completion_id,
                    pcsc_status,
                    (unsigned)state,
                    (unsigned)protocol,
                    (unsigned)atr_len);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_session_smartcard_handle_status(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_handle* handle = NULL;
    char reader_names[1024];
    DWORD reader_names_len = sizeof(reader_names);
    DWORD state = 0;
    DWORD protocol = 0;
    DWORD atr_len = RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH;
    uint8_t atr[RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH];
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(reader_names, 0, sizeof(reader_names));
    memset(atr, 0, sizeof(atr));
    rdp_buffer_init(&payload);
    handle = rdp_session_smartcard_handle_find(session,
                                               message->body.status.handle.data,
                                               message->body.status.handle.length);
    if (handle)
        pcsc_status = SCardStatus(handle->handle, reader_names, &reader_names_len, &state, &protocol, atr, &atr_len);
    status = rdp_smartcard_redirection_write_status_return(
        &payload,
        (uint32_t)pcsc_status,
        pcsc_status == SCARD_S_SUCCESS ? reader_names : NULL,
        pcsc_status == SCARD_S_SUCCESS ? rdp_session_smartcard_u32_from_dword(reader_names_len) : 0,
        rdp_session_smartcard_u32_from_dword(state),
        pcsc_status == SCARD_S_SUCCESS ?
            rdp_session_smartcard_protocol_from_pcsc(protocol) :
            RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED,
        atr,
        pcsc_status == SCARD_S_SUCCESS ? rdp_session_smartcard_u32_from_dword(atr_len) : 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.status.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.status",
                    "device_id=%u completion_id=%u status=%ld state=%u protocol=%u readers_len=%u atr_len=%u",
                    request->device_id,
                    request->completion_id,
                    pcsc_status,
                    (unsigned)state,
                    (unsigned)protocol,
                    (unsigned)reader_names_len,
                    (unsigned)atr_len);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_session_smartcard_handle_transmit(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_handle* handle = NULL;
    const SCARD_IO_REQUEST* send_pci = NULL;
    SCARD_IO_REQUEST recv_pci;
    uint8_t recv_buffer[RDP_SMARTCARD_REDIRECTION_TRANSMIT_MAX_LENGTH];
    DWORD recv_len = 0;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(&recv_pci, 0, sizeof(recv_pci));
    memset(recv_buffer, 0, sizeof(recv_buffer));
    recv_pci.dwProtocol = rdp_session_smartcard_protocol_to_pcsc(message->body.transmit.recv_pci.protocol);
    recv_pci.cbPciLength = sizeof(recv_pci);
    recv_len = message->body.transmit.recv_len;
    if (recv_len > sizeof(recv_buffer))
        recv_len = sizeof(recv_buffer);
    rdp_buffer_init(&payload);
    handle = rdp_session_smartcard_handle_find(session,
                                               message->body.transmit.handle.data,
                                               message->body.transmit.handle.length);
    if (handle)
    {
        send_pci = rdp_session_smartcard_pci_from_protocol(message->body.transmit.send_pci.protocol);
        if (send_pci)
        {
            pcsc_status = SCardTransmit(handle->handle,
                                        send_pci,
                                        message->body.transmit.send_data,
                                        message->body.transmit.send_len,
                                        message->body.transmit.recv_pci_present ? &recv_pci : NULL,
                                        recv_buffer,
                                        &recv_len);
        }
        else
        {
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
        }
    }
    status = rdp_smartcard_redirection_write_transmit_return(
        &payload,
        (uint32_t)pcsc_status,
        pcsc_status == SCARD_S_SUCCESS ?
            rdp_session_smartcard_protocol_from_pcsc(recv_pci.dwProtocol) :
            RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED,
        NULL,
        0,
        recv_buffer,
        pcsc_status == SCARD_S_SUCCESS ? rdp_session_smartcard_u32_from_dword(recv_len) : 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.transmit.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.transmit",
                    "device_id=%u completion_id=%u status=%ld send_len=%u recv_len=%u",
                    request->device_id,
                    request->completion_id,
                    pcsc_status,
                    message->body.transmit.send_len,
                    (unsigned)recv_len);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_session_smartcard_handle_control(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_handle* handle = NULL;
    uint8_t output[RDP_SESSION_SMARTCARD_MAX_IO_BYTES];
    DWORD output_len = 0;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(output, 0, sizeof(output));
    output_len = message->body.control.output_len;
    if (output_len > sizeof(output))
        output_len = sizeof(output);
    rdp_buffer_init(&payload);
    handle = rdp_session_smartcard_handle_find(session,
                                               message->body.control.handle.data,
                                               message->body.control.handle.length);
    if (handle)
        pcsc_status = SCardControl(handle->handle,
                                   message->body.control.control_code,
                                   message->body.control.input,
                                   message->body.control.input_len,
                                   output,
                                   output_len,
                                   &output_len);
    status = rdp_smartcard_redirection_write_buffer_return(&payload,
                                                           (uint32_t)pcsc_status,
                                                           output,
                                                           pcsc_status == SCARD_S_SUCCESS ?
                                                               rdp_session_smartcard_u32_from_dword(output_len) :
                                                               0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.control.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.control",
                    "device_id=%u completion_id=%u status=%ld input_len=%u output_len=%u",
                    request->device_id,
                    request->completion_id,
                    pcsc_status,
                    message->body.control.input_len,
                    (unsigned)output_len);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_session_smartcard_handle_attrib(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_handle* handle = NULL;
    uint8_t attr[RDP_SMARTCARD_REDIRECTION_ATTRIB_MAX_LENGTH];
    DWORD attr_len = 0;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(attr, 0, sizeof(attr));
    rdp_buffer_init(&payload);
    if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_GETATTRIB)
    {
        attr_len = message->body.attrib.attr_len;
        if (attr_len > sizeof(attr))
            attr_len = sizeof(attr);
        handle = rdp_session_smartcard_handle_find(session,
                                                   message->body.attrib.handle.data,
                                                   message->body.attrib.handle.length);
        if (handle)
            pcsc_status = SCardGetAttrib(handle->handle, message->body.attrib.attr_id, attr, &attr_len);
        status = rdp_smartcard_redirection_write_buffer_return(&payload,
                                                               (uint32_t)pcsc_status,
                                                               attr,
                                                               pcsc_status == SCARD_S_SUCCESS ?
                                                                   rdp_session_smartcard_u32_from_dword(attr_len) :
                                                                   0);
    }
    else
    {
        handle = rdp_session_smartcard_handle_find(session,
                                                   message->body.set_attrib.handle.data,
                                                   message->body.set_attrib.handle.length);
        if (handle)
            pcsc_status = SCardSetAttrib(handle->handle,
                                         message->body.set_attrib.attr_id,
                                         message->body.set_attrib.attr,
                                         message->body.set_attrib.attr_len);
        status = rdp_smartcard_redirection_write_long_return(&payload, (uint32_t)pcsc_status);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.attrib.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.attrib",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status);
    rdp_buffer_free(&payload);
    return status;
}
#else
static void rdp_session_smartcard_reset(librdp_session* session)
{
    (void)session;
}
#endif

static librdp_status rdp_session_handle_smartcard_io_request(librdp_session* session,
                                                             const uint8_t* data,
                                                             size_t data_len)
{
    rdp_device_redirection_io_request request;
    rdp_smartcard_redirection_request_message message;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_parse_io_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    switch (request.major_function)
    {
        case RDP_DEVICE_REDIRECTION_IRP_CREATE:
            return rdp_session_send_smartcard_simple_completion(session,
                                                                &request,
                                                                RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                                "client.rdpdr.smartcard.create.response");
        case RDP_DEVICE_REDIRECTION_IRP_CLOSE:
            return rdp_session_send_smartcard_simple_completion(session,
                                                                &request,
                                                                RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                                "client.rdpdr.smartcard.close.response");
        case RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL:
            break;
        default:
            return rdp_session_send_smartcard_simple_completion(session,
                                                                &request,
                                                                RDP_SESSION_DEVICE_NOT_SUPPORTED,
                                                                "client.rdpdr.smartcard.unsupported.response");
    }

    memset(&message, 0, sizeof(message));
    status = rdp_smartcard_redirection_parse_device_control_request_message(request.payload,
                                                                           request.payload_len,
                                                                           &message);
    if (status != LIBRDP_STATUS_OK)
        return rdp_session_send_smartcard_simple_completion(session,
                                                            &request,
                                                            RDP_SESSION_DEVICE_INVALID_PARAMETER,
                                                            "client.rdpdr.smartcard.invalid.response");
#ifdef RDP_HAVE_PCSC
    switch (message.kind)
    {
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_ESTABLISH_CONTEXT:
            return rdp_session_smartcard_handle_establish(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_CONTEXT:
            return rdp_session_smartcard_handle_context(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_HANDLE:
            return rdp_session_smartcard_handle_handle_only(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_CONNECT:
            return rdp_session_smartcard_handle_connect(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_HANDLE_DISPOSITION:
            return rdp_session_smartcard_handle_disposition(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_RECONNECT:
            return rdp_session_smartcard_handle_reconnect(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_STATE:
            return rdp_session_smartcard_handle_state(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_STATUS:
            return rdp_session_smartcard_handle_status(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_TRANSMIT:
            return rdp_session_smartcard_handle_transmit(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_CONTROL:
            return rdp_session_smartcard_handle_control(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_ATTRIB:
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_SET_ATTRIB:
            return rdp_session_smartcard_handle_attrib(session, &request, &message);
        default:
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpdr.smartcard.unsupported_ioctl",
                            "device_id=%u completion_id=%u ioctl=%u",
                            request.device_id,
                            request.completion_id,
                            message.request.io_control_code);
            return rdp_session_send_smartcard_long_result(session,
                                                          &request,
                                                          RDP_SESSION_SCARD_E_UNSUPPORTED_FEATURE,
                                                          "client.rdpdr.smartcard.unsupported_ioctl.response");
    }
#else
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.no_backend",
                    "device_id=%u completion_id=%u ioctl=%u",
                    request.device_id,
                    request.completion_id,
                    message.request.io_control_code);
    return rdp_session_send_smartcard_long_result(session,
                                                  &request,
                                                  RDP_SESSION_SCARD_E_NO_SERVICE,
                                                  "client.rdpdr.smartcard.no_backend.response");
#endif
}

static uint32_t rdp_session_read_u32_le_unaligned(const uint8_t* data)
{
    if (!data)
        return 0;
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8u) | ((uint32_t)data[2] << 16u) |
           ((uint32_t)data[3] << 24u);
}

static librdp_status rdp_session_append_zeroes(rdp_buffer* buffer, uint32_t count)
{
    static const uint8_t zeroes[64] = {0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (count > 0)
    {
        uint32_t chunk = count > sizeof(zeroes) ? (uint32_t)sizeof(zeroes) : count;

        status = rdp_buffer_append(buffer, zeroes, chunk);
        if (status != LIBRDP_STATUS_OK)
            return status;
        count -= chunk;
    }
    return LIBRDP_STATUS_OK;
}

static speed_t rdp_session_serial_to_speed(uint32_t baud, int* ok)
{
    if (ok)
        *ok = 1;
    switch (baud)
    {
#ifdef B110
        case 110: return B110;
#endif
#ifdef B300
        case 300: return B300;
#endif
#ifdef B600
        case 600: return B600;
#endif
#ifdef B1200
        case 1200: return B1200;
#endif
#ifdef B2400
        case 2400: return B2400;
#endif
#ifdef B4800
        case 4800: return B4800;
#endif
#ifdef B9600
        case 9600: return B9600;
#endif
#ifdef B19200
        case 19200: return B19200;
#endif
#ifdef B38400
        case 38400: return B38400;
#endif
#ifdef B57600
        case 57600: return B57600;
#endif
#ifdef B115200
        case 115200: return B115200;
#endif
#ifdef B230400
        case 230400: return B230400;
#endif
        default:
            if (ok)
                *ok = 0;
            return B9600;
    }
}

static uint32_t rdp_session_speed_to_serial(speed_t speed)
{
    switch (speed)
    {
#ifdef B110
        case B110: return 110;
#endif
#ifdef B300
        case B300: return 300;
#endif
#ifdef B600
        case B600: return 600;
#endif
#ifdef B1200
        case B1200: return 1200;
#endif
#ifdef B2400
        case B2400: return 2400;
#endif
#ifdef B4800
        case B4800: return 4800;
#endif
#ifdef B9600
        case B9600: return 9600;
#endif
#ifdef B19200
        case B19200: return 19200;
#endif
#ifdef B38400
        case B38400: return 38400;
#endif
#ifdef B57600
        case B57600: return 57600;
#endif
#ifdef B115200
        case B115200: return 115200;
#endif
#ifdef B230400
        case B230400: return 230400;
#endif
        default: return 9600;
    }
}

static void rdp_session_port_init_defaults(rdp_session_redirected_file* port, uint8_t type)
{
    if (!port)
        return;
    port->port_type = type;
    port->serial_baud_rate = 9600;
    port->serial_line_control[0] = 0;
    port->serial_line_control[1] = 0;
    port->serial_line_control[2] = 8;
}

static uint32_t rdp_session_port_apply_baud(rdp_session_redirected_file* port, uint32_t baud)
{
    struct termios tio;
    int ok = 0;
    speed_t speed = 0;

    if (!port || port->fd < 0)
        return RDP_SESSION_DEVICE_NO_SUCH_FILE;
    port->serial_baud_rate = baud;
    if (!isatty(port->fd))
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    speed = rdp_session_serial_to_speed(baud, &ok);
    if (!ok || tcgetattr(port->fd, &tio) != 0)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (cfsetispeed(&tio, speed) != 0 || cfsetospeed(&tio, speed) != 0 ||
        tcsetattr(port->fd, TCSANOW, &tio) != 0)
        return rdp_session_errno_to_device_status(errno);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static uint32_t rdp_session_port_refresh_baud(rdp_session_redirected_file* port)
{
    struct termios tio;

    if (!port || port->fd < 0 || !isatty(port->fd))
        return port ? port->serial_baud_rate : 0;
    if (tcgetattr(port->fd, &tio) == 0)
        port->serial_baud_rate = rdp_session_speed_to_serial(cfgetispeed(&tio));
    return port->serial_baud_rate;
}

static uint32_t rdp_session_port_apply_line_control(rdp_session_redirected_file* port,
                                                    const uint8_t* data,
                                                    uint32_t length)
{
    struct termios tio;
    tcflag_t bits = CS8;

    if (!port || port->fd < 0)
        return RDP_SESSION_DEVICE_NO_SUCH_FILE;
    if (!data || length < 3u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    memcpy(port->serial_line_control, data, 3u);
    if (!isatty(port->fd))
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    if (tcgetattr(port->fd, &tio) != 0)
        return rdp_session_errno_to_device_status(errno);
    tio.c_cflag &= (tcflag_t)~(tcflag_t)(CSIZE | PARENB | PARODD | CSTOPB);
    switch (data[2])
    {
        case 5: bits = CS5; break;
        case 6: bits = CS6; break;
        case 7: bits = CS7; break;
        case 8: bits = CS8; break;
        default: return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    }
    tio.c_cflag |= bits | CLOCAL | CREAD;
    if (data[0] == 2)
        tio.c_cflag |= CSTOPB;
    if (data[1] != 0)
    {
        tio.c_cflag |= PARENB;
        if (data[1] == 1)
            tio.c_cflag |= PARODD;
    }
    if (tcsetattr(port->fd, TCSANOW, &tio) != 0)
        return rdp_session_errno_to_device_status(errno);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static uint32_t rdp_session_port_set_modem_flag(rdp_session_redirected_file* port, int bit, int enabled)
{
#ifdef TIOCMGET
    int flags = 0;

    if (!port || port->fd < 0)
        return RDP_SESSION_DEVICE_NO_SUCH_FILE;
    if (!isatty(port->fd))
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    if (ioctl(port->fd, TIOCMGET, &flags) != 0)
        return rdp_session_errno_to_device_status(errno);
    if (enabled)
        flags |= bit;
    else
        flags &= ~bit;
    if (ioctl(port->fd, TIOCMSET, &flags) != 0)
        return rdp_session_errno_to_device_status(errno);
#else
    (void)port;
    (void)bit;
    (void)enabled;
#endif
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static uint32_t rdp_session_port_modem_flags(rdp_session_redirected_file* port)
{
#ifdef TIOCMGET
    int flags = 0;

    if (!port || port->fd < 0 || !isatty(port->fd))
        return 0;
    if (ioctl(port->fd, TIOCMGET, &flags) != 0)
        return 0;
    return (uint32_t)flags;
#else
    (void)port;
    return 0;
#endif
}

static librdp_status rdp_session_port_control_serial(rdp_session_redirected_file* port,
                                                     const rdp_filesystem_redirection_control_request* request,
                                                     rdp_buffer* output,
                                                     uint32_t* io_status)
{
    uint32_t code = 0;

    if (!port || !request || !output || !io_status)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    code = request->io_control_code;
    *io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    switch (code)
    {
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BAUD_RATE:
            if (request->input_buffer_length < 4u)
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            else
                *io_status = rdp_session_port_apply_baud(port,
                                                         rdp_session_read_u32_le_unaligned(request->input_buffer));
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_BAUD_RATE:
            return rdp_buffer_append_u32_le(output, rdp_session_port_refresh_baud(port));
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_LINE_CONTROL:
            *io_status = rdp_session_port_apply_line_control(port,
                                                             request->input_buffer,
                                                             request->input_buffer_length);
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_LINE_CONTROL:
            return rdp_buffer_append(output, port->serial_line_control, sizeof(port->serial_line_control));
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_TIMEOUTS:
            if (request->input_buffer_length < sizeof(port->serial_timeouts))
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            else
            {
                for (uint32_t i = 0; i < 5u; i++)
                    port->serial_timeouts[i] =
                        rdp_session_read_u32_le_unaligned(request->input_buffer + (i * 4u));
            }
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_TIMEOUTS:
            for (uint32_t i = 0; i < 5u; i++)
            {
                librdp_status status = rdp_buffer_append_u32_le(output, port->serial_timeouts[i]);
                if (status != LIBRDP_STATUS_OK)
                    return status;
            }
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_CHARS:
            if (request->input_buffer_length < sizeof(port->serial_chars))
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            else
                memcpy(port->serial_chars, request->input_buffer, sizeof(port->serial_chars));
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_CHARS:
            return rdp_buffer_append(output, port->serial_chars, sizeof(port->serial_chars));
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_HANDFLOW:
            if (request->input_buffer_length < sizeof(port->serial_handflow))
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            else
                memcpy(port->serial_handflow, request->input_buffer, sizeof(port->serial_handflow));
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_HANDFLOW:
            return rdp_buffer_append(output, port->serial_handflow, sizeof(port->serial_handflow));
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_WAIT_MASK:
            if (request->input_buffer_length < 4u)
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            else
                port->serial_wait_mask = rdp_session_read_u32_le_unaligned(request->input_buffer);
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_WAIT_MASK:
            return rdp_buffer_append_u32_le(output, port->serial_wait_mask);
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_WAIT_ON_MASK:
            return rdp_buffer_append_u32_le(output, 0);
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_DTR:
#ifdef TIOCM_DTR
            *io_status = rdp_session_port_set_modem_flag(port, TIOCM_DTR, 1);
#endif
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_CLR_DTR:
#ifdef TIOCM_DTR
            *io_status = rdp_session_port_set_modem_flag(port, TIOCM_DTR, 0);
#endif
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_RTS:
#ifdef TIOCM_RTS
            *io_status = rdp_session_port_set_modem_flag(port, TIOCM_RTS, 1);
#endif
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_CLR_RTS:
#ifdef TIOCM_RTS
            *io_status = rdp_session_port_set_modem_flag(port, TIOCM_RTS, 0);
#endif
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_MODEMSTATUS:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_DTRRTS:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_MODEM_CONTROL:
            return rdp_buffer_append_u32_le(output, rdp_session_port_modem_flags(port));
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_IMMEDIATE_CHAR:
            if (request->input_buffer_length < 1u)
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            else if (write(port->fd, request->input_buffer, 1u) < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                *io_status = rdp_session_errno_to_device_status(errno);
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BREAK_ON:
            if (isatty(port->fd) && tcsendbreak(port->fd, 0) != 0)
                *io_status = rdp_session_errno_to_device_status(errno);
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_COMMSTATUS:
            return rdp_session_append_zeroes(output, 18u);
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_PROPERTIES:
            return rdp_session_append_zeroes(output, 64u);
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_CONFIG_SIZE:
            return rdp_buffer_append_u32_le(output, 0);
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_STATS:
            return rdp_session_append_zeroes(output, 48u);
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_QUEUE_SIZE:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_XOFF:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_XON:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BREAK_OFF:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_PURGE:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_RESET_DEVICE:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_XOFF_COUNTER:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_LSRMST_INSERT:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_CLEAR_STATS:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_MODEM_CONTROL:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_FIFO_CONTROL:
            return LIBRDP_STATUS_OK;
        default:
            *io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
            return LIBRDP_STATUS_OK;
    }
}

static librdp_status rdp_session_port_control_parallel(rdp_session_redirected_file* port,
                                                       const rdp_filesystem_redirection_control_request* request,
                                                       rdp_buffer* output,
                                                       uint32_t* io_status)
{
    static const char device_id[] = "MFG:librdp;MDL:Redirected Parallel Port;CLS:PRINTER;";
    uint32_t code = 0;

    if (!port || !request || !output || !io_status)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    (void)port;
    code = request->io_control_code;
    *io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    switch (code)
    {
        case RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_DEVICE_ID_SIZE:
            return rdp_buffer_append_u32_le(output, (uint32_t)sizeof(device_id));
        case RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_DEVICE_ID:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_RAW_DEVICE_ID:
            return rdp_buffer_append(output, device_id, sizeof(device_id));
        case RDP_PORT_REDIRECTION_IOCTL_IEEE1284_GET_MODE:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_GET_DEFAULT_MODES:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_IS_PORT_FREE:
            return rdp_buffer_append_u32_le(output, 1u);
        case RDP_PORT_REDIRECTION_IOCTL_PAR_GET_DEVICE_CAPS:
            return rdp_buffer_append_u32_le(output, 0u);
        case RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_INFORMATION:
            return rdp_session_append_zeroes(output, 4u);
        case RDP_PORT_REDIRECTION_IOCTL_PAR_SET_INFORMATION:
        case RDP_PORT_REDIRECTION_IOCTL_IEEE1284_NEGOTIATE:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_SET_WRITE_ADDRESS:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_SET_READ_ADDRESS:
            return LIBRDP_STATUS_OK;
        default:
            *io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
            return LIBRDP_STATUS_OK;
    }
}

static librdp_status rdp_session_send_port_create_response(librdp_session* session,
                                                           const rdp_device_redirection_io_request* request,
                                                           uint32_t io_status,
                                                           uint32_t file_id)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_create_response(&response,
                                                              request->device_id,
                                                              request->completion_id,
                                                              io_status,
                                                              file_id,
                                                              RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_OPENED);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.port.create.response");
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_handle_port_create(librdp_session* session,
                                                    const rdp_device_redirection_io_request* request,
                                                    uint8_t port_type,
                                                    uint32_t port_index)
{
    rdp_session_redirected_file* port = NULL;
    const char* path = NULL;
    uint32_t file_id = 0;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    int fd = -1;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (port_type == RDP_SESSION_PORT_TYPE_SERIAL)
        path = librdp_settings_serial_port_path(session->settings, port_index);
    else
        path = librdp_settings_parallel_port_path(session->settings, port_index);
    if (!path)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    else
    {
        fd = open(path,
                  port_type == RDP_SESSION_PORT_TYPE_SERIAL ?
                      (O_RDWR | O_NOCTTY | O_NONBLOCK) :
                      (O_RDWR | O_NONBLOCK));
        if (fd < 0 && port_type == RDP_SESSION_PORT_TYPE_PARALLEL)
            fd = open(path, O_WRONLY | O_NONBLOCK);
        if (fd < 0)
            io_status = rdp_session_errno_to_device_status(errno);
        else
        {
            port = rdp_session_redirected_file_alloc(session, request->device_id, &file_id);
            if (!port)
                io_status = RDP_SESSION_DEVICE_TOO_MANY_OPENED_FILES;
            else
            {
                port->fd = fd;
                fd = -1;
                rdp_session_port_init_defaults(port, port_type);
            }
        }
    }
    if (fd >= 0)
        close(fd);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.port.create",
                    "device_id=%u completion_id=%u file_id=%u type=%u index=%u status=%u",
                    request->device_id,
                    request->completion_id,
                    file_id,
                    port_type,
                    port_index,
                    io_status);
    return rdp_session_send_port_create_response(session, request, io_status, file_id);
}

static librdp_status rdp_session_handle_port_close(librdp_session* session,
                                                   const rdp_device_redirection_io_request* request)
{
    rdp_session_redirected_file* port = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    port = rdp_session_redirected_file_find(session, request->device_id, request->file_id);
    if (!port)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    else
    {
        if (port->fd >= 0 && close(port->fd) != 0)
            io_status = rdp_session_errno_to_device_status(errno);
        port->fd = -1;
        rdp_session_redirected_file_reset(port);
    }
    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_close_response(&response,
                                                             request->device_id,
                                                             request->completion_id,
                                                             io_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.port.close.response");
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_handle_port_read(librdp_session* session,
                                                  const uint8_t* data,
                                                  size_t data_len)
{
    rdp_filesystem_redirection_read_request request;
    rdp_session_redirected_file* port = NULL;
    rdp_buffer response;
    uint8_t* payload = NULL;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t payload_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_port_redirection_parse_read_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (request.length > RDP_SESSION_MAX_FILE_IO_BYTES)
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    else
    {
        port = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
        if (!port)
            io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
        else if (request.length > 0)
        {
            payload = (uint8_t*)malloc(request.length);
            if (!payload)
                return LIBRDP_STATUS_NO_MEMORY;
            for (;;)
            {
                ssize_t got = read(port->fd, payload, request.length);

                if (got < 0 && errno == EINTR)
                    continue;
                if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                    got = 0;
                if (got < 0)
                    io_status = rdp_session_errno_to_device_status(errno);
                else
                    payload_len = (uint32_t)got;
                break;
            }
        }
    }
    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_read_response(&response,
                                                            request.io.device_id,
                                                            request.io.completion_id,
                                                            io_status,
                                                            io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                payload :
                                                                NULL,
                                                            io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                payload_len :
                                                                0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.port.read.response");
    rdp_buffer_free(&response);
    free(payload);
    return status;
}

static librdp_status rdp_session_handle_port_write(librdp_session* session,
                                                   const uint8_t* data,
                                                   size_t data_len)
{
    rdp_filesystem_redirection_write_request request;
    rdp_session_redirected_file* port = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t written = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_port_redirection_parse_write_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (request.length > RDP_SESSION_MAX_FILE_IO_BYTES)
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    else
    {
        port = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
        if (!port)
            io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
        else
        {
            const uint8_t* cursor = request.data;
            uint32_t remaining = request.length;

            while (remaining > 0)
            {
                ssize_t count = write(port->fd, cursor, remaining);

                if (count < 0 && errno == EINTR)
                    continue;
                if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                    break;
                if (count <= 0)
                {
                    io_status = count < 0 ? rdp_session_errno_to_device_status(errno)
                                          : RDP_SESSION_DEVICE_UNSUCCESSFUL;
                    break;
                }
                cursor += (size_t)count;
                remaining -= (uint32_t)count;
                written += (uint32_t)count;
            }
        }
    }
    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_write_response(&response,
                                                             request.io.device_id,
                                                             request.io.completion_id,
                                                             io_status,
                                                             written);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.port.write.response");
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_handle_port_control(librdp_session* session,
                                                     const uint8_t* data,
                                                     size_t data_len,
                                                     uint8_t port_type)
{
    rdp_filesystem_redirection_control_request request;
    rdp_session_redirected_file* port = NULL;
    rdp_buffer output;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_port_redirection_parse_control_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    port = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
    rdp_buffer_init(&output);
    rdp_buffer_init(&response);
    if (!port)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    else if (port_type == RDP_SESSION_PORT_TYPE_SERIAL && port->port_type == RDP_SESSION_PORT_TYPE_SERIAL)
        status = rdp_session_port_control_serial(port, &request, &output, &io_status);
    else if (port_type == RDP_SESSION_PORT_TYPE_PARALLEL && port->port_type == RDP_SESSION_PORT_TYPE_PARALLEL)
        status = rdp_session_port_control_parallel(port, &request, &output, &io_status);
    else
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_port_redirection_write_control_response(&response,
                                                             request.io.device_id,
                                                             request.io.completion_id,
                                                             io_status,
                                                             io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                 output.data :
                                                                 NULL,
                                                             io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                 (uint32_t)output.length :
                                                                 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.port.control.response");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.port.control",
                        "device_id=%u file_id=%u completion_id=%u type=%u ioctl=%u status=%u output_len=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        port_type,
                        request.io_control_code,
                        io_status,
                        (unsigned)output.length);
    rdp_buffer_free(&response);
    rdp_buffer_free(&output);
    return status;
}

static librdp_status rdp_session_handle_port_io_request(librdp_session* session,
                                                        const uint8_t* data,
                                                        size_t data_len,
                                                        uint8_t port_type,
                                                        uint32_t port_index)
{
    rdp_device_redirection_io_request request;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_parse_io_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    switch (request.major_function)
    {
        case RDP_DEVICE_REDIRECTION_IRP_CREATE:
            return rdp_session_handle_port_create(session, &request, port_type, port_index);
        case RDP_DEVICE_REDIRECTION_IRP_CLOSE:
            return rdp_session_handle_port_close(session, &request);
        case RDP_DEVICE_REDIRECTION_IRP_READ:
            return rdp_session_handle_port_read(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_WRITE:
            return rdp_session_handle_port_write(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL:
            return rdp_session_handle_port_control(session, data, data_len, port_type);
        default:
        {
            rdp_buffer response;

            rdp_buffer_init(&response);
            status = rdp_device_redirection_write_io_completion(&response,
                                                                request.device_id,
                                                                request.completion_id,
                                                                RDP_SESSION_DEVICE_NOT_SUPPORTED,
                                                                NULL,
                                                                0);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_send_device_redirection_packet(session,
                                                                    &response,
                                                                    "client.rdpdr.port.unsupported.response");
            rdp_buffer_free(&response);
            return status;
        }
    }
}

static librdp_status rdp_session_handle_device_io_request(librdp_session* session,
                                                          const uint8_t* data,
                                                          size_t data_len)
{
    rdp_device_redirection_io_request request;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_parse_io_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_session_drive_index_from_device_id(session, request.device_id) != UINT32_MAX)
        return rdp_session_handle_filesystem_io_request(session, data, data_len);
    if (rdp_session_serial_port_index_from_device_id(session, request.device_id) != UINT32_MAX)
        return rdp_session_handle_port_io_request(session,
                                                  data,
                                                  data_len,
                                                  RDP_SESSION_PORT_TYPE_SERIAL,
                                                  rdp_session_serial_port_index_from_device_id(session,
                                                                                              request.device_id));
    if (rdp_session_parallel_port_index_from_device_id(session, request.device_id) != UINT32_MAX)
        return rdp_session_handle_port_io_request(session,
                                                  data,
                                                  data_len,
                                                  RDP_SESSION_PORT_TYPE_PARALLEL,
                                                  rdp_session_parallel_port_index_from_device_id(session,
                                                                                                request.device_id));
    if (rdp_session_printer_index_from_device_id(session, request.device_id) != UINT32_MAX)
        return rdp_session_handle_printer_io_request(session, data, data_len);
    if (rdp_session_smartcard_index_from_device_id(session, request.device_id) != UINT32_MAX)
        return rdp_session_handle_smartcard_io_request(session, data, data_len);

    rdp_buffer_init(&response);
    status = rdp_device_redirection_write_io_completion(&response,
                                                        request.device_id,
                                                        request.completion_id,
                                                        RDP_SESSION_DEVICE_NO_SUCH_DEVICE,
                                                        NULL,
                                                        0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.io_completion.no_device");
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_write_device_redirection_client_name(rdp_buffer* buffer)
{
    static const char name[] = "librdp";
    uint8_t utf16[(sizeof(name)) * 2u];
    size_t i = 0;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(utf16, 0, sizeof(utf16));
    for (i = 0; i + 1u < sizeof(name); i++)
        utf16[i * 2u] = (uint8_t)name[i];
    return rdp_device_redirection_write_client_name_utf16le(buffer, utf16, (uint32_t)sizeof(utf16));
}

static void rdp_session_drive_name_to_utf16le(const char* name, uint8_t* out, size_t out_len)
{
    size_t i = 0;
    size_t length = 0;

    if (!name || !out || out_len < 2u)
        return;
    memset(out, 0, out_len);
    length = strlen(name);
    if ((length + 1u) * 2u > out_len)
        length = out_len / 2u - 1u;
    for (i = 0; i < length; i++)
        out[i * 2u] = (uint8_t)name[i];
}

static librdp_status rdp_session_send_device_redirection_device_list(librdp_session* session)
{
    rdp_device_redirection_device_announce
        devices[LIBRDP_SETTINGS_MAX_DRIVES + LIBRDP_SETTINGS_MAX_SERIAL_PORTS +
                LIBRDP_SETTINGS_MAX_PARALLEL_PORTS + LIBRDP_SETTINGS_MAX_PRINTERS +
                LIBRDP_SETTINGS_MAX_SMARTCARDS];
    uint8_t names[LIBRDP_SETTINGS_MAX_DRIVES][16];
    rdp_buffer printer_data[LIBRDP_SETTINGS_MAX_PRINTERS];
    rdp_buffer packet;
    uint32_t drive_count = 0;
    uint32_t serial_count = 0;
    uint32_t parallel_count = 0;
    uint32_t printer_count = 0;
    uint32_t smartcard_count = 0;
    uint32_t count = 0;
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(devices, 0, sizeof(devices));
    memset(names, 0, sizeof(names));
    for (i = 0; i < LIBRDP_SETTINGS_MAX_PRINTERS; i++)
        rdp_buffer_init(&printer_data[i]);
    drive_count = librdp_settings_drive_count(session->settings);
    serial_count = librdp_settings_serial_port_count(session->settings);
    parallel_count = librdp_settings_parallel_port_count(session->settings);
    printer_count = librdp_settings_printer_count(session->settings);
    smartcard_count = librdp_settings_smartcard_count(session->settings);
    if (drive_count > LIBRDP_SETTINGS_MAX_DRIVES || printer_count > LIBRDP_SETTINGS_MAX_PRINTERS ||
        smartcard_count > LIBRDP_SETTINGS_MAX_SMARTCARDS ||
        serial_count > LIBRDP_SETTINGS_MAX_SERIAL_PORTS ||
        parallel_count > LIBRDP_SETTINGS_MAX_PARALLEL_PORTS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < drive_count; i++)
    {
        const char* name = librdp_settings_drive_name(session->settings, i);
        size_t name_len = name ? strlen(name) : 0;

        if (!name || name_len == 0 || name_len > 7u)
        {
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
            goto out;
        }
        devices[count].device_type = RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM;
        devices[count].device_id = rdp_settings_drive_device_id_internal(session->settings, i);
        memcpy(devices[count].preferred_dos_name, name, name_len + 1u);
        rdp_session_drive_name_to_utf16le(name, names[i], sizeof(names[i]));
        devices[count].data = names[i];
        devices[count].data_len = (uint32_t)((name_len + 1u) * 2u);
        count++;
    }
    for (i = 0; i < serial_count; i++)
    {
        const char* name = librdp_settings_serial_port_name(session->settings, i);
        size_t name_len = name ? strlen(name) : 0;

        if (!name || name_len == 0 || name_len > 7u)
        {
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
            goto out;
        }
        devices[count].device_type = RDP_DEVICE_REDIRECTION_TYPE_SERIAL;
        devices[count].device_id = rdp_settings_serial_port_device_id_internal(session->settings, i);
        memcpy(devices[count].preferred_dos_name, name, name_len + 1u);
        devices[count].data = NULL;
        devices[count].data_len = 0;
        count++;
    }
    for (i = 0; i < parallel_count; i++)
    {
        const char* name = librdp_settings_parallel_port_name(session->settings, i);
        size_t name_len = name ? strlen(name) : 0;

        if (!name || name_len == 0 || name_len > 7u)
        {
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
            goto out;
        }
        devices[count].device_type = RDP_DEVICE_REDIRECTION_TYPE_PARALLEL;
        devices[count].device_id = rdp_settings_parallel_port_device_id_internal(session->settings, i);
        memcpy(devices[count].preferred_dos_name, name, name_len + 1u);
        devices[count].data = NULL;
        devices[count].data_len = 0;
        count++;
    }
    for (i = 0; i < printer_count; i++)
    {
        rdp_printer_redirection_announce announce;
        rdp_buffer driver;
        rdp_buffer printer;
        char port_name[8];
        const char* driver_name = librdp_settings_printer_driver(session->settings, i);
        const char* printer_name = librdp_settings_printer_name(session->settings, i);

        rdp_buffer_init(&driver);
        rdp_buffer_init(&printer);
        memset(&announce, 0, sizeof(announce));
        if (snprintf(port_name, sizeof(port_name), "PRN%u", (unsigned)i + 1u) <= 0)
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_utf8_to_utf16le(driver_name, &driver, 1);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_utf8_to_utf16le(printer_name, &printer, 1);
        if (status == LIBRDP_STATUS_OK)
        {
            announce.flags = i == 0 ? RDP_PRINTER_REDIRECTION_ANNOUNCE_FLAG_DEFAULT : 0u;
            announce.driver_name = driver.data;
            announce.driver_name_len = (uint32_t)driver.length;
            announce.printer_name = printer.data;
            announce.printer_name_len = (uint32_t)printer.length;
            status = rdp_printer_redirection_write_announce_data(&printer_data[i], &announce);
        }
        if (status == LIBRDP_STATUS_OK)
        {
            devices[count].device_type = RDP_DEVICE_REDIRECTION_TYPE_PRINTER;
            devices[count].device_id = rdp_settings_printer_device_id_internal(session->settings, i);
            memcpy(devices[count].preferred_dos_name, port_name, strlen(port_name) + 1u);
            devices[count].data = printer_data[i].data;
            devices[count].data_len = (uint32_t)printer_data[i].length;
            count++;
        }
        rdp_buffer_free(&driver);
        rdp_buffer_free(&printer);
        if (status != LIBRDP_STATUS_OK)
            goto out;
    }
    for (i = 0; i < smartcard_count; i++)
    {
        devices[count].device_type = RDP_DEVICE_REDIRECTION_TYPE_SMARTCARD;
        devices[count].device_id = rdp_settings_smartcard_device_id_internal(session->settings, i);
        memcpy(devices[count].preferred_dos_name, "SCARD", 6u);
        devices[count].data = NULL;
        devices[count].data_len = 0;
        count++;
    }
    rdp_buffer_init(&packet);
    status = rdp_device_redirection_write_device_list_announce(&packet, devices, count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &packet,
                                                            "client.rdpdr.device_list");
    rdp_buffer_free(&packet);
    if (status == LIBRDP_STATUS_OK)
    {
        session->device_redirection_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.device_list",
                        "channel_id=%u drive_count=%u serial_count=%u parallel_count=%u printer_count=%u smartcard_count=%u device_count=%u",
                        session->device_redirection_channel_id,
                        drive_count,
                        serial_count,
                        parallel_count,
                        printer_count,
                        smartcard_count,
                        count);
    }
out:
    for (i = 0; i < LIBRDP_SETTINGS_MAX_PRINTERS; i++)
        rdp_buffer_free(&printer_data[i]);
    return status;
}

static librdp_status rdp_session_handle_printer_component_message(librdp_session* session,
                                                                  const uint8_t* data,
                                                                  size_t data_len,
                                                                  uint16_t packet_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (packet_id == RDP_DEVICE_REDIRECTION_PAKID_PRINTER_CACHE_DATA)
    {
        rdp_printer_redirection_cache_event event;
        uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;

        status = rdp_printer_redirection_parse_cache_event(data, data_len, &event);
        if (status == LIBRDP_STATUS_OK)
            io_status = rdp_session_store_printer_cache_event(session, &event);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpdr.printer.cache",
                            "channel_id=%u event_id=%u printer_name_len=%u cached_len=%u status=%u",
                            session->device_redirection_channel_id,
                            event.event_id,
                            event.printer_name_len,
                            event.cached_fields_len,
                            io_status);
    }
    else if (packet_id == RDP_DEVICE_REDIRECTION_PAKID_PRINTER_USING_XPS)
    {
        rdp_printer_redirection_xps_mode mode;

        status = rdp_printer_redirection_parse_xps_mode(data, data_len, &mode);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpdr.printer.xps_mode",
                            "channel_id=%u printer_id=%u flags=%u",
                            session->device_redirection_channel_id,
                            mode.printer_id,
                            mode.flags);
    }
    else
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.rdpdr.printer.pdu.unsupported",
                              "channel_id=%u packet_id=%u payload_len=%u",
                              session->device_redirection_channel_id,
                              packet_id,
                              (unsigned)data_len);
    }
    return status;
}

static librdp_status rdp_session_handle_device_redirection_message(librdp_session* session,
                                                                   const uint8_t* data,
                                                                   size_t data_len)
{
    rdp_device_redirection_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header.component == RDP_DEVICE_REDIRECTION_COMPONENT_PRINTER)
        return rdp_session_handle_printer_component_message(session, data, data_len, header.packet_id);
    if (header.component != RDP_DEVICE_REDIRECTION_COMPONENT_CORE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_SERVER_ANNOUNCE)
    {
        rdp_device_redirection_announce announce;
        rdp_buffer client_announce;
        rdp_buffer client_name;

        rdp_buffer_init(&client_announce);
        rdp_buffer_init(&client_name);
        status = rdp_device_redirection_parse_server_announce(data, data_len, &announce);
        if (status == LIBRDP_STATUS_OK)
        {
            session->device_redirection_version_minor = announce.version_minor;
            session->device_redirection_client_id = announce.client_id;
            status = rdp_device_redirection_write_client_announce(&client_announce,
                                                                  announce.version_minor,
                                                                  announce.client_id);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_write_device_redirection_client_name(&client_name);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_device_redirection_packet(session,
                                                                &client_announce,
                                                                "client.rdpdr.client_announce");
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_device_redirection_packet(session,
                                                                &client_name,
                                                                "client.rdpdr.client_name");
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpdr.server_announce",
                            "channel_id=%u version_minor=%u client_id=%u",
                            session->device_redirection_channel_id,
                            announce.version_minor,
                            announce.client_id);
        rdp_buffer_free(&client_name);
        rdp_buffer_free(&client_announce);
    }
    else if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENTID_CONFIRM)
    {
        rdp_device_redirection_announce confirm;

        status = rdp_device_redirection_parse_client_id_confirm(data, data_len, &confirm);
        if (status == LIBRDP_STATUS_OK)
        {
            session->device_redirection_version_minor = confirm.version_minor;
            session->device_redirection_client_id = confirm.client_id;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpdr.client_id_confirm",
                            "channel_id=%u version_minor=%u client_id=%u",
                            session->device_redirection_channel_id,
                            confirm.version_minor,
                            confirm.client_id);
        }
    }
    else if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_SERVER_CAPABILITY)
    {
        rdp_device_redirection_capability_list server_caps;
        rdp_device_redirection_capability_config config;
        rdp_buffer response;

        rdp_buffer_init(&response);
        status = rdp_device_redirection_parse_capability_list(data,
                                                              data_len,
                                                              RDP_DEVICE_REDIRECTION_PAKID_CORE_SERVER_CAPABILITY,
                                                              &server_caps);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_device_redirection_make_default_capability_config(&config);
        if (status == LIBRDP_STATUS_OK && session->device_redirection_version_minor != 0)
            config.general.protocol_minor_version = session->device_redirection_version_minor;
        if (status == LIBRDP_STATUS_OK)
            config.include_drive = librdp_settings_drive_count(session->settings) > 0 ? 1u : 0u;
        if (status == LIBRDP_STATUS_OK)
            config.include_printer = librdp_settings_printer_count(session->settings) > 0 ? 1u : 0u;
        if (status == LIBRDP_STATUS_OK)
            config.include_port =
                librdp_settings_serial_port_count(session->settings) > 0 ||
                        librdp_settings_parallel_port_count(session->settings) > 0 ?
                    1u :
                    0u;
        if (status == LIBRDP_STATUS_OK)
            config.include_smartcard =
                librdp_settings_smartcard_count(session->settings) > 0 ||
                        librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_SMARTCARD) ?
                    1u :
                    0u;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_device_redirection_write_client_capability_response(&response, &config);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_device_redirection_packet(session,
                                                                &response,
                                                                "client.rdpdr.capability_response");
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpdr.capability_response",
                            "channel_id=%u server_caps=%u drive=%u printer=%u port=%u smartcard=%u",
                            session->device_redirection_channel_id,
                            server_caps.count,
                            config.include_drive,
                            config.include_printer,
                            config.include_port,
                            config.include_smartcard);
        rdp_buffer_free(&response);
    }
    else if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_USER_LOGGEDON)
    {
        status = rdp_device_redirection_parse_user_loggedon(data, data_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_device_redirection_device_list(session);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpdr.user_loggedon",
                            "channel_id=%u",
                            session->device_redirection_channel_id);
    }
    else if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_REPLY)
    {
        rdp_device_redirection_device_reply reply;

        status = rdp_device_redirection_parse_device_reply(data, data_len, &reply);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpdr.device_reply",
                            "channel_id=%u device_id=%u result=%u",
                            session->device_redirection_channel_id,
                            reply.device_id,
                            reply.result_code);
    }
    else if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOREQUEST)
    {
        status = rdp_session_handle_device_io_request(session, data, data_len);
    }
    else
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.rdpdr.pdu.unsupported",
                              "channel_id=%u packet_id=%u payload_len=%u",
                              session->device_redirection_channel_id,
                              header.packet_id,
                              (unsigned)data_len);
    }
    return status;
}

static librdp_status rdp_session_send_clipboard_format_list(librdp_session* session)
{
    rdp_buffer packet;
    rdp_clipboard_format_entry entry;
    uint32_t count = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!session->clipboard_ready || session->clipboard_channel_id == 0)
        return LIBRDP_STATUS_OK;

    memset(&entry, 0, sizeof(entry));
    if (session->clipboard_local_available)
    {
        entry.format_id = session->clipboard_local_format_id;
        count = 1;
    }

    rdp_buffer_init(&packet);
    status = rdp_clipboard_write_format_list(&packet, count ? &entry : NULL, count, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_clipboard_packet(session, &packet, "client.clipboard.format_list");
    rdp_buffer_free(&packet);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.clipboard.format_list",
                        "channel_id=%u count=%u",
                        session->clipboard_channel_id,
                        count);
    return status;
}

static librdp_status rdp_session_send_clipboard_handshake(librdp_session* session)
{
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;
    const uint32_t flags = RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES |
                           RDP_CLIPBOARD_CAP_STREAM_FILECLIP_ENABLED |
                           RDP_CLIPBOARD_CAP_FILECLIP_NO_FILE_PATHS |
                           RDP_CLIPBOARD_CAP_CAN_LOCK_CLIPDATA |
                           RDP_CLIPBOARD_CAP_HUGE_FILE_SUPPORT_ENABLED;

    if (!session || session->clipboard_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->clipboard_ready)
        return LIBRDP_STATUS_OK;

    rdp_buffer_init(&packet);
    status = rdp_clipboard_write_capabilities(&packet, flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_clipboard_packet(session, &packet, "client.clipboard.capabilities");
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.clipboard.capabilities",
                        "channel_id=%u flags=%u",
                        session->clipboard_channel_id,
                        flags);
        packet.length = 0;
        status = rdp_clipboard_write_monitor_ready(&packet);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_clipboard_packet(session, &packet, "client.clipboard.monitor_ready");
    rdp_buffer_free(&packet);
    if (status == LIBRDP_STATUS_OK)
    {
        session->clipboard_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.clipboard.monitor_ready",
                        "channel_id=%u",
                        session->clipboard_channel_id);
        status = rdp_session_send_clipboard_format_list(session);
    }
    return status;
}

static int rdp_session_audio_format_is_supported_pcm(const rdp_audio_format* format)
{
    if (!format)
        return 0;
    if (format->format_tag != RDP_AUDIO_FORMAT_PCM)
        return 0;
    if (format->channels == 0 || format->channels > 2)
        return 0;
    if (format->bits_per_sample != 8u && format->bits_per_sample != 16u && format->bits_per_sample != 24u &&
        format->bits_per_sample != 32u)
        return 0;
    if (format->samples_per_sec == 0 || format->block_align == 0 || format->avg_bytes_per_sec == 0)
        return 0;
    return 1;
}

static void rdp_session_audio_format_to_public(const rdp_audio_format* in, librdp_audio_format* out)
{
    if (!in || !out)
        return;
    memset(out, 0, sizeof(*out));
    out->format_tag = in->format_tag;
    out->channels = in->channels;
    out->samples_per_sec = in->samples_per_sec;
    out->avg_bytes_per_sec = in->avg_bytes_per_sec;
    out->block_align = in->block_align;
    out->bits_per_sample = in->bits_per_sample;
    out->extra_data = in->extra_data;
    out->extra_data_len = in->extra_data_len;
}

static void rdp_session_emit_audio_output_formats(librdp_session* session, uint16_t version)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_AUDIO_OUTPUT_FORMATS;
    event.data.audio_output_formats.formats = session->audio_output_selected_formats;
    event.data.audio_output_formats.count = session->audio_output_selected_format_count;
    event.data.audio_output_formats.version = version;
    rdp_session_emit(session, &event);
}

static void rdp_session_emit_audio_output_data(librdp_session* session,
                                               uint16_t timestamp,
                                               uint16_t format_no,
                                               uint8_t block_no,
                                               uint32_t audio_timestamp,
                                               const uint8_t* data,
                                               size_t data_len)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_AUDIO_OUTPUT_DATA;
    event.data.audio_output_data.timestamp = timestamp;
    event.data.audio_output_data.format_no = format_no;
    event.data.audio_output_data.block_no = block_no;
    event.data.audio_output_data.audio_timestamp = audio_timestamp;
    event.data.audio_output_data.data = data;
    event.data.audio_output_data.data_len = data_len;
    rdp_session_emit(session, &event);
}

static void rdp_session_emit_audio_output_close(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_AUDIO_OUTPUT_CLOSE;
    rdp_session_emit(session, &event);
}

static void rdp_session_emit_audio_input_formats(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_AUDIO_INPUT_FORMATS;
    event.data.audio_input_formats.formats = session->audio_input_selected_formats;
    event.data.audio_input_formats.count = session->audio_input_selected_format_count;
    event.data.audio_input_formats.version = session->audio_input_version;
    rdp_session_emit(session, &event);
}

static void rdp_session_emit_audio_input_open(librdp_session* session, const rdp_audio_input_open* open)
{
    librdp_event event;

    if (!session || !open)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_AUDIO_INPUT_OPEN;
    event.data.audio_input_open.frames_per_packet = open->frames_per_packet;
    event.data.audio_input_open.initial_format = open->initial_format;
    rdp_session_audio_format_to_public(&open->format, &event.data.audio_input_open.format);
    rdp_session_emit(session, &event);
}

static librdp_status rdp_session_send_audio_output_packet(librdp_session* session,
                                                          const rdp_buffer* payload,
                                                          const char* event)
{
    if (!session || !payload || !event || session->audio_output_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_write_channel_pdu(session, session->audio_output_channel_id, payload, event);
}

static librdp_status rdp_session_send_audio_input_packet(librdp_session* session,
                                                         const rdp_buffer* payload,
                                                         const char* event)
{
    if (!session || !payload || !event || session->audio_input_channel_id == 0 ||
        session->audio_input_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_send_dynamic_channel_data(session,
                                                 session->audio_input_channel_id,
                                                 session->audio_input_channel_id_bytes,
                                                 payload->data,
                                                 payload->length,
                                                 event);
}

static librdp_status rdp_session_send_audio_input_incoming(librdp_session* session)
{
    rdp_buffer incoming;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&incoming);
    status = rdp_audio_input_write_incoming_data(&incoming);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_input_packet(session, &incoming, "client.audin.data_incoming");
    rdp_buffer_free(&incoming);
    return status;
}

static librdp_status rdp_session_send_audio_input_formats(librdp_session* session,
                                                          const rdp_audio_input_formats* server_formats)
{
    rdp_audio_format selected[RDP_SESSION_AUDIO_OUTPUT_FORMAT_LIMIT];
    rdp_buffer formats_pdu;
    uint32_t selected_count = 0;
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !server_formats)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(selected, 0, sizeof(selected));
    memset(session->audio_input_selected_formats, 0, sizeof(session->audio_input_selected_formats));
    session->audio_input_selected_format_count = 0;
    for (i = 0; i < server_formats->format_count && selected_count < RDP_SESSION_AUDIO_OUTPUT_FORMAT_LIMIT; i++)
    {
        rdp_audio_format format;

        status = rdp_audio_format_get_from_list(server_formats->formats,
                                                server_formats->formats_len,
                                                server_formats->format_count,
                                                i,
                                                &format);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (rdp_session_audio_format_is_supported_pcm(&format))
        {
            selected[selected_count] = format;
            rdp_session_audio_format_to_public(&format,
                                               &session->audio_input_selected_formats[selected_count]);
            selected_count++;
        }
    }

    rdp_buffer_init(&formats_pdu);
    status = rdp_session_send_audio_input_incoming(session);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_audio_input_write_formats(&formats_pdu, selected, selected_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_input_packet(session, &formats_pdu, "client.audin.formats");
    rdp_buffer_free(&formats_pdu);
    if (status == LIBRDP_STATUS_OK)
    {
        session->audio_input_ready = selected_count > 0 ? 1u : 0u;
        session->audio_input_selected_format_count = selected_count;
        rdp_session_emit_audio_input_formats(session);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.audin.formats",
                        "dvc_channel_id=%u server_formats=%u selected_formats=%u",
                        session->audio_input_channel_id,
                        server_formats->format_count,
                        selected_count);
    }
    return status;
}

static librdp_status rdp_session_handle_audio_input_message(librdp_session* session,
                                                            uint32_t channel_id,
                                                            const uint8_t* data,
                                                            size_t data_len)
{
    rdp_audio_input_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_audio_input_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "rdp.audin.pdu",
                          "dvc_channel_id=%u message_id=%u payload_len=%u",
                          channel_id,
                          header.message_id,
                          (unsigned)data_len);
    if (header.message_id == RDP_AUDIO_INPUT_VERSION)
    {
        rdp_buffer response;
        uint32_t server_version = 0;
        uint32_t client_version = 0;

        rdp_buffer_init(&response);
        status = rdp_audio_input_parse_version(data, data_len, &server_version);
        if (status == LIBRDP_STATUS_OK)
        {
            client_version = server_version > RDP_AUDIO_INPUT_VERSION_2 ? RDP_AUDIO_INPUT_VERSION_2 : server_version;
            if (client_version == 0)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_audio_input_write_version(&response, client_version);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_audio_input_packet(session, &response, "client.audin.version");
        rdp_buffer_free(&response);
        if (status == LIBRDP_STATUS_OK)
        {
            session->audio_input_version = client_version;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.audin.version",
                            "dvc_channel_id=%u server_version=%u client_version=%u",
                            channel_id,
                            server_version,
                            client_version);
        }
    }
    else if (header.message_id == RDP_AUDIO_INPUT_FORMATS)
    {
        rdp_audio_input_formats formats;

        status = rdp_audio_input_parse_formats(data, data_len, &formats);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_audio_input_formats(session, &formats);
    }
    else if (header.message_id == RDP_AUDIO_INPUT_OPEN)
    {
        rdp_audio_input_open open;

        status = rdp_audio_input_parse_open(data, data_len, &open);
        if (status == LIBRDP_STATUS_OK)
        {
            session->audio_input_open_reply_sent = 0;
            rdp_session_emit_audio_input_open(session, &open);
            if (!session->audio_input_open_reply_sent)
                status = librdp_session_audio_input_open_reply(session, RDP_AUDIO_INPUT_RESULT_FAIL);
        }
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.audin.open",
                            "dvc_channel_id=%u frames_per_packet=%u initial_format=%u result=%u",
                            channel_id,
                            open.frames_per_packet,
                            open.initial_format,
                            session->audio_input_open ? RDP_AUDIO_INPUT_RESULT_OK : RDP_AUDIO_INPUT_RESULT_FAIL);
    }
    else if (header.message_id == RDP_AUDIO_INPUT_FORMAT_CHANGE)
    {
        rdp_buffer response;
        uint32_t new_format = 0;

        rdp_buffer_init(&response);
        status = rdp_audio_input_parse_format_change(data, data_len, &new_format);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_audio_input_write_format_change(&response, new_format);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_audio_input_packet(session, &response, "client.audin.format_change");
        rdp_buffer_free(&response);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.audin.format_change",
                            "dvc_channel_id=%u new_format=%u",
                            channel_id,
                            new_format);
    }
    else
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.audin.pdu",
                              "dvc_channel_id=%u message_id=%u payload_len=%u",
                              channel_id,
                              header.message_id,
                              (unsigned)data_len);
    }
    return status;
}

static librdp_status rdp_session_handle_audio_output_formats(librdp_session* session,
                                                             const uint8_t* data,
                                                             size_t data_len)
{
    rdp_audio_output_formats server_formats;
    rdp_audio_format selected[RDP_SESSION_AUDIO_OUTPUT_FORMAT_LIMIT];
    rdp_buffer response;
    rdp_buffer quality;
    uint16_t selected_count = 0;
    uint16_t i = 0;
    uint16_t client_version = 6;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(selected, 0, sizeof(selected));
    memset(session->audio_output_selected_formats, 0, sizeof(session->audio_output_selected_formats));
    session->audio_output_selected_format_count = 0;
    rdp_buffer_init(&response);
    rdp_buffer_init(&quality);

    status = rdp_audio_output_parse_formats(data, data_len, &server_formats);
    if (status == LIBRDP_STATUS_OK)
    {
        for (i = 0; i < server_formats.format_count && selected_count < RDP_SESSION_AUDIO_OUTPUT_FORMAT_LIMIT; i++)
        {
            rdp_audio_format format;

            status = rdp_audio_format_get_from_list(server_formats.formats,
                                                    server_formats.formats_len,
                                                    server_formats.format_count,
                                                    i,
                                                    &format);
            if (status != LIBRDP_STATUS_OK)
                break;
            if (rdp_session_audio_format_is_supported_pcm(&format))
            {
                selected[selected_count] = format;
                rdp_session_audio_format_to_public(&format,
                                                   &session->audio_output_selected_formats[selected_count]);
                selected_count++;
            }
        }
    }
    if (status == LIBRDP_STATUS_OK)
    {
        uint32_t flags = selected_count > 0 ? RDP_AUDIO_OUTPUT_CAP_ALIVE : 0;

        session->audio_output_server_version = server_formats.version;
        session->audio_output_client_version = client_version;
        status = rdp_audio_output_write_client_formats(&response,
                                                       flags,
                                                       0xffffffffu,
                                                       0x00010000u,
                                                       0,
                                                       server_formats.last_block_confirmed,
                                                       client_version,
                                                       selected,
                                                       selected_count);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_output_packet(session, &response, "client.rdpsnd.formats");
    if (status == LIBRDP_STATUS_OK && server_formats.version >= 6u && client_version >= 6u)
    {
        status = rdp_audio_output_write_quality_mode(&quality, RDP_AUDIO_OUTPUT_QUALITY_HIGH);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_audio_output_packet(session, &quality, "client.rdpsnd.quality_mode");
    }
    rdp_buffer_free(&quality);
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
    {
        session->audio_output_ready = selected_count > 0 ? 1u : 0u;
        session->audio_output_selected_format_count = selected_count;
        rdp_session_emit_audio_output_formats(session, client_version);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpsnd.formats",
                        "channel_id=%u server_version=%u client_version=%u server_formats=%u selected_formats=%u",
                        session->audio_output_channel_id,
                        server_formats.version,
                        client_version,
                        server_formats.format_count,
                        selected_count);
    }
    return status;
}

static librdp_status rdp_session_send_audio_output_wave_confirm(librdp_session* session,
                                                                uint16_t timestamp,
                                                                uint8_t block_no)
{
    rdp_buffer confirm;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&confirm);
    status = rdp_audio_output_write_wave_confirm(&confirm, timestamp, block_no);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_output_packet(session, &confirm, "client.rdpsnd.wave_confirm");
    rdp_buffer_free(&confirm);
    return status;
}

static librdp_status rdp_session_handle_audio_output_message(librdp_session* session,
                                                             const uint8_t* data,
                                                             size_t data_len)
{
    rdp_audio_output_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->audio_output_pending_wave)
    {
        rdp_audio_output_wave_data wave_data;

        status = rdp_audio_output_parse_wave_data(data, data_len, &wave_data);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (wave_data.data_len != session->audio_output_pending_expected_len)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_buffer_append(&session->audio_output_pending_data, wave_data.data, wave_data.data_len) !=
            LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_NO_MEMORY;
        rdp_session_emit_audio_output_data(session,
                                           session->audio_output_pending_timestamp,
                                           session->audio_output_pending_format_no,
                                           session->audio_output_pending_block_no,
                                           0,
                                           session->audio_output_pending_data.data,
                                           session->audio_output_pending_data.length);
        status = rdp_session_send_audio_output_wave_confirm(session,
                                                            session->audio_output_pending_timestamp,
                                                            session->audio_output_pending_block_no);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpsnd.wave",
                            "channel_id=%u format_no=%u block_no=%u data_len=%u",
                            session->audio_output_channel_id,
                            session->audio_output_pending_format_no,
                            session->audio_output_pending_block_no,
                            (unsigned)session->audio_output_pending_data.length);
        rdp_buffer_free(&session->audio_output_pending_data);
        session->audio_output_pending_wave = 0;
        session->audio_output_pending_expected_len = 0;
        return status;
    }

    status = rdp_audio_output_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "rdp.rdpsnd.pdu",
                          "channel_id=%u type=%u body_size=%u payload_len=%u",
                          session->audio_output_channel_id,
                          header.msg_type,
                          header.body_size,
                          (unsigned)data_len);
    if (header.msg_type == RDP_AUDIO_OUTPUT_FORMATS)
    {
        status = rdp_session_handle_audio_output_formats(session, data, data_len);
    }
    else if (header.msg_type == RDP_AUDIO_OUTPUT_TRAINING)
    {
        rdp_audio_output_training training;
        rdp_buffer confirm;

        rdp_buffer_init(&confirm);
        status = rdp_audio_output_parse_training(data, data_len, &training);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_audio_output_write_training_confirm(&confirm, training.timestamp, training.packet_size);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_audio_output_packet(session, &confirm, "client.rdpsnd.training_confirm");
        rdp_buffer_free(&confirm);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpsnd.training",
                            "channel_id=%u timestamp=%u packet_size=%u data_len=%u",
                            session->audio_output_channel_id,
                            training.timestamp,
                            training.packet_size,
                            (unsigned)training.data_len);
    }
    else if (header.msg_type == RDP_AUDIO_OUTPUT_WAVE)
    {
        rdp_audio_output_wave_info wave;

        status = rdp_audio_output_parse_wave_info(data, data_len, &wave);
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&session->audio_output_pending_data);
            rdp_buffer_init(&session->audio_output_pending_data);
            status = rdp_buffer_append(&session->audio_output_pending_data, wave.first_data, wave.first_data_len);
        }
        if (status == LIBRDP_STATUS_OK)
        {
            session->audio_output_pending_wave = 1;
            session->audio_output_pending_timestamp = wave.timestamp;
            session->audio_output_pending_format_no = wave.format_no;
            session->audio_output_pending_block_no = wave.block_no;
            session->audio_output_pending_expected_len = wave.expected_data_len;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpsnd.wave_info",
                            "channel_id=%u format_no=%u block_no=%u expected_tail=%u",
                            session->audio_output_channel_id,
                            wave.format_no,
                            wave.block_no,
                            wave.expected_data_len);
        }
    }
    else if (header.msg_type == RDP_AUDIO_OUTPUT_WAVE2)
    {
        rdp_audio_output_wave2 wave;

        status = rdp_audio_output_parse_wave2(data, data_len, &wave);
        if (status == LIBRDP_STATUS_OK)
            rdp_session_emit_audio_output_data(session,
                                               wave.timestamp,
                                               wave.format_no,
                                               wave.block_no,
                                               wave.audio_timestamp,
                                               wave.data,
                                               wave.data_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_audio_output_wave_confirm(session, wave.timestamp, wave.block_no);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpsnd.wave2",
                            "channel_id=%u format_no=%u block_no=%u audio_timestamp=%u data_len=%u",
                            session->audio_output_channel_id,
                            wave.format_no,
                            wave.block_no,
                            wave.audio_timestamp,
                            (unsigned)wave.data_len);
    }
    else if (header.msg_type == RDP_AUDIO_OUTPUT_CLOSE)
    {
        status = rdp_audio_output_parse_close(data, data_len);
        if (status == LIBRDP_STATUS_OK)
        {
            session->audio_output_ready = 0;
            rdp_buffer_free(&session->audio_output_pending_data);
            session->audio_output_pending_wave = 0;
            rdp_session_emit_audio_output_close(session);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpsnd.close",
                            "channel_id=%u",
                            session->audio_output_channel_id);
        }
    }
    else if (header.msg_type == RDP_AUDIO_OUTPUT_SETVOLUME || header.msg_type == RDP_AUDIO_OUTPUT_SETPITCH)
    {
        rdp_audio_output_setting setting;

        status = rdp_audio_output_parse_setting(data, data_len, header.msg_type, &setting);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            header.msg_type == RDP_AUDIO_OUTPUT_SETVOLUME ? "client.rdpsnd.volume" :
                                                                             "client.rdpsnd.pitch",
                            "channel_id=%u value=%u",
                            session->audio_output_channel_id,
                            setting.value);
    }
    else
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpsnd.unsupported",
                        "channel_id=%u type=%u body_size=%u",
                        session->audio_output_channel_id,
                        header.msg_type,
                        header.body_size);
    }
    return status;
}

static rdp_session_dynamic_channel* rdp_session_dynamic_channel_find(librdp_session* session, uint32_t channel_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_MAX_DYNAMIC_CHANNELS; i++)
    {
        if (session->dynamic_channels[i].active && session->dynamic_channels[i].channel_id == channel_id)
            return &session->dynamic_channels[i];
    }
    return NULL;
}

static void rdp_session_dynamic_channel_clear_entry(rdp_session_dynamic_channel* entry)
{
    if (!entry)
        return;
    rdp_buffer_free(&entry->fragment);
    rdp_graphics_decompressor_free(&entry->decompressor);
    memset(entry, 0, sizeof(*entry));
}

static librdp_status rdp_session_dynamic_channel_add(librdp_session* session,
                                                     const rdp_dynamic_channel_create_request* request)
{
    size_t i = 0;
    size_t name_len = 0;
    rdp_session_dynamic_channel* entry = NULL;

    if (!session || !request || !request->name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    entry = rdp_session_dynamic_channel_find(session, request->channel_id);
    if (!entry)
    {
        for (i = 0; i < RDP_SESSION_MAX_DYNAMIC_CHANNELS; i++)
        {
            if (!session->dynamic_channels[i].active)
            {
                entry = &session->dynamic_channels[i];
                break;
            }
        }
    }
    if (!entry)
        return LIBRDP_STATUS_UNSUPPORTED;

    rdp_session_dynamic_channel_clear_entry(entry);
    rdp_graphics_decompressor_init(&entry->decompressor);
    entry->channel_id = request->channel_id;
    entry->channel_id_bytes = request->channel_id_bytes;
    entry->active = 1;
    name_len = request->name_len < RDP_SESSION_DYNAMIC_CHANNEL_NAME_MAX - 1u ?
                   request->name_len :
                   RDP_SESSION_DYNAMIC_CHANNEL_NAME_MAX - 1u;
    memcpy(entry->name, request->name, name_len);
    entry->name[name_len] = '\0';
    return LIBRDP_STATUS_OK;
}

static int rdp_session_dynamic_channel_is_internal_name(const char* name)
{
    if (!name)
        return 0;
    return strcmp(name, RDP_SESSION_DISPLAY_CONTROL_NAME) == 0 ||
           strcmp(name, RDP_SESSION_CORE_INPUT_NAME) == 0 ||
           strcmp(name, RDP_SESSION_INPUT_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_SESSION_GRAPHICS_PIPELINE_NAME) == 0 ||
           strcmp(name, RDP_SESSION_MOUSE_CURSOR_NAME) == 0 ||
           strcmp(name, RDP_SESSION_WEBAUTHN_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_SESSION_USB_REDIRECTION_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_COMPOSITED_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_VIDEO_REDIRECTION_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_VIDEO_CAPTURE_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_AUDIO_INPUT_CHANNEL_NAME) == 0;
}

static int rdp_session_dynamic_channel_is_internal(const rdp_session_dynamic_channel* entry)
{
    return entry && rdp_session_dynamic_channel_is_internal_name(entry->name);
}

static void rdp_session_emit_channel_open(librdp_session* session, const rdp_session_dynamic_channel* entry)
{
    librdp_event event;

    if (!session || !entry)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_CHANNEL_OPEN;
    event.data.channel_open.channel_id = entry->channel_id;
    event.data.channel_open.name = entry->name;
    event.data.channel_open.name_len = strlen(entry->name);
    rdp_session_emit(session, &event);
}

static void rdp_session_emit_channel_data(librdp_session* session,
                                          const rdp_session_dynamic_channel* entry,
                                          const uint8_t* data,
                                          size_t data_len)
{
    librdp_event event;

    if (!session || !entry || (!data && data_len > 0))
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_CHANNEL_DATA;
    event.data.channel_data.channel_id = entry->channel_id;
    event.data.channel_data.name = entry->name;
    event.data.channel_data.name_len = strlen(entry->name);
    event.data.channel_data.data = data;
    event.data.channel_data.data_len = data_len;
    rdp_session_emit(session, &event);
}

static void rdp_session_emit_channel_close(librdp_session* session, const rdp_session_dynamic_channel* entry)
{
    librdp_event event;

    if (!session || !entry)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_CHANNEL_CLOSE;
    event.data.channel_close.channel_id = entry->channel_id;
    event.data.channel_close.name = entry->name;
    event.data.channel_close.name_len = strlen(entry->name);
    rdp_session_emit(session, &event);
}

static void rdp_session_dynamic_channels_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_MAX_DYNAMIC_CHANNELS; i++)
        rdp_session_dynamic_channel_clear_entry(&session->dynamic_channels[i]);
}

static void rdp_session_clipboard_clear(librdp_session* session)
{
    if (!session)
        return;
    rdp_buffer_free(&session->clipboard_fragment);
    session->clipboard_fragmenting = 0;
    session->clipboard_fragment_expected = 0;
    session->clipboard_ready = 0;
    session->clipboard_general_flags = 0;
    session->clipboard_pending_request_format_id = 0;
    session->clipboard_remote_format_count = 0;
}

static void rdp_session_clipboard_local_clear(librdp_session* session)
{
    if (!session)
        return;
    rdp_buffer_free(&session->clipboard_local_data);
    session->clipboard_local_format_id = 0;
    session->clipboard_local_available = 0;
}

static rdp_session_graphics_surface* rdp_session_graphics_surface_find(librdp_session* session, uint16_t surface_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_MAX_GRAPHICS_SURFACES; i++)
    {
        if (session->graphics_surfaces[i].active && session->graphics_surfaces[i].surface_id == surface_id)
            return &session->graphics_surfaces[i];
    }
    return NULL;
}

static rdp_session_graphics_surface* rdp_session_graphics_surface_find_slot(librdp_session* session,
                                                                            uint16_t surface_id)
{
    size_t i = 0;
    rdp_session_graphics_surface* free_slot = NULL;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_MAX_GRAPHICS_SURFACES; i++)
    {
        if (session->graphics_surfaces[i].active && session->graphics_surfaces[i].surface_id == surface_id)
            return &session->graphics_surfaces[i];
        if (!session->graphics_surfaces[i].active && !free_slot)
            free_slot = &session->graphics_surfaces[i];
    }
    return free_slot;
}

static void rdp_session_progressive_tiles_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        free(session->progressive_tiles[i].state);
        free(session->progressive_tiles[i].pixels);
        session->progressive_tiles[i].state = NULL;
        session->progressive_tiles[i].pixels = NULL;
    }
    memset(session->progressive_tiles, 0, sizeof(session->progressive_tiles));
    session->progressive_tile_clock = 0;
}

static void rdp_session_progressive_tiles_clear_surface(librdp_session* session, uint16_t surface_id)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        rdp_session_progressive_tile_cache* entry = &session->progressive_tiles[i];

        if (entry->active && entry->surface_id == surface_id)
        {
            free(entry->state);
            free(entry->pixels);
            memset(entry, 0, sizeof(*entry));
        }
    }
}

static rdp_session_progressive_tile_cache* rdp_session_progressive_tile_find(librdp_session* session,
                                                                             uint16_t surface_id,
                                                                             uint16_t x_idx,
                                                                             uint16_t y_idx)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        rdp_session_progressive_tile_cache* entry = &session->progressive_tiles[i];

        if (entry->active && entry->surface_id == surface_id &&
            entry->x_idx == x_idx && entry->y_idx == y_idx)
            return entry;
    }
    return NULL;
}

static rdp_session_progressive_tile_cache* rdp_session_progressive_tile_get(librdp_session* session,
                                                                            uint16_t surface_id,
                                                                            uint16_t x_idx,
                                                                            uint16_t y_idx,
                                                                            int create)
{
    size_t i = 0;
    rdp_session_progressive_tile_cache* entry = NULL;
    rdp_session_progressive_tile_cache* victim = NULL;
    size_t victim_slot = 0;
    int evicting = 0;
    uint16_t old_surface_id = 0;
    uint16_t old_x_idx = 0;
    uint16_t old_y_idx = 0;
    uint32_t old_valid = 0;
    uint32_t old_pass = 0;

    if (!session)
        return NULL;
    entry = rdp_session_progressive_tile_find(session, surface_id, x_idx, y_idx);
    if (entry)
    {
        entry->last_used = ++session->progressive_tile_clock;
        return entry;
    }
    if (!create)
        return NULL;

    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        rdp_session_progressive_tile_cache* candidate = &session->progressive_tiles[i];

        if (!candidate->active)
        {
            victim = candidate;
            break;
        }
        if (!victim || candidate->last_used < victim->last_used)
            victim = candidate;
    }
    if (!victim)
        return NULL;
    victim_slot = (size_t)(victim - session->progressive_tiles);
    evicting = victim->active != 0;
    if (evicting)
    {
        old_surface_id = victim->surface_id;
        old_x_idx = victim->x_idx;
        old_y_idx = victim->y_idx;
        old_valid = victim->state ? victim->state->valid : 0u;
        old_pass = victim->state ? victim->state->pass : 0u;
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "client.graphics.progressive.tile_state.evict",
                              "slot=%u old_surface_id=%u old_x_idx=%u old_y_idx=%u old_valid=%u old_pass=%u old_frame_id=%u new_surface_id=%u new_x_idx=%u new_y_idx=%u",
                              (unsigned)victim_slot,
                              old_surface_id,
                              old_x_idx,
                              old_y_idx,
                              old_valid,
                              old_pass,
                              victim->updated_frame_id,
                              surface_id,
                              x_idx,
                              y_idx);
    }
    if (!victim->state)
    {
        victim->state = (rdp_rfx_progressive_tile_state*)calloc(1, sizeof(*victim->state));
        if (!victim->state)
            return NULL;
    }
    if (!victim->pixels)
    {
        victim->pixels = (rdp_rfx_tile_pixels*)calloc(1, sizeof(*victim->pixels));
        if (!victim->pixels)
            return NULL;
    }
    else
    {
        memset(victim->pixels, 0, sizeof(*victim->pixels));
    }
    if (victim->state)
    {
        memset(victim->state, 0, sizeof(*victim->state));
    }
    victim->active = 1;
    victim->surface_id = surface_id;
    victim->x_idx = x_idx;
    victim->y_idx = y_idx;
    victim->has_pixels = 0;
    victim->updated_frame_id = 0;
    victim->last_used = ++session->progressive_tile_clock;
    victim->state->x_idx = x_idx;
    victim->state->y_idx = y_idx;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.progressive.tile_state.alloc",
                          "slot=%u surface_id=%u x_idx=%u y_idx=%u evicted=%u",
                          (unsigned)victim_slot,
                          surface_id,
                          x_idx,
                          y_idx,
                          (unsigned)evicting);
    return victim;
}

static void rdp_session_graphics_surfaces_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    rdp_session_progressive_tiles_clear(session);
    rdp_avc_decoder_reset(session->avc);
    for (i = 0; i < RDP_SESSION_MAX_GRAPHICS_SURFACES; i++)
        rdp_buffer_free(&session->graphics_surfaces[i].pixels);
    memset(session->graphics_surfaces, 0, sizeof(session->graphics_surfaces));
}

static librdp_status rdp_session_graphics_surface_create(librdp_session* session,
                                                         const rdp_graphics_create_surface* create)
{
    rdp_session_graphics_surface* surface = NULL;
    size_t stride = 0;
    size_t size = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !create)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (create->width == 0 || create->height == 0 ||
        create->width > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION ||
        create->height > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    stride = (size_t)create->width * 4u;
    if ((size_t)create->height > ((size_t)-1) / stride)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    size = stride * (size_t)create->height;

    surface = rdp_session_graphics_surface_find_slot(session, create->surface_id);
    if (!surface)
        return LIBRDP_STATUS_NO_MEMORY;

    if (surface->active)
        rdp_session_progressive_tiles_clear_surface(session, create->surface_id);
    rdp_buffer_free(&surface->pixels);
    memset(surface, 0, sizeof(*surface));
    status = rdp_buffer_reserve(&surface->pixels, size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(surface->pixels.data, 0, size);
    surface->pixels.length = size;
    surface->active = 1;
    surface->surface_id = create->surface_id;
    surface->width = create->width;
    surface->height = create->height;
    surface->target_width = create->width;
    surface->target_height = create->height;
    surface->pixel_format = create->pixel_format;
    return LIBRDP_STATUS_OK;
}

static void rdp_session_graphics_surface_delete(librdp_session* session, uint16_t surface_id)
{
    rdp_session_graphics_surface* surface = rdp_session_graphics_surface_find(session, surface_id);

    if (!surface)
        return;
    rdp_session_progressive_tiles_clear_surface(session, surface_id);
    rdp_avc_decoder_reset(session->avc);
    rdp_buffer_free(&surface->pixels);
    memset(surface, 0, sizeof(*surface));
}

static uint64_t rdp_session_trace_hash_bgra(const uint8_t* pixels,
                                            uint32_t width,
                                            uint32_t height,
                                            size_t stride);
static uint64_t rdp_session_trace_surface_hash(const rdp_session_graphics_surface* surface,
                                               uint32_t x,
                                               uint32_t y,
                                               uint32_t width,
                                               uint32_t height);

static librdp_status rdp_session_graphics_surface_flush_scaled(librdp_session* session,
                                                               rdp_session_graphics_surface* surface,
                                                               uint16_t left,
                                                               uint16_t top,
                                                               uint16_t right,
                                                               uint16_t bottom,
                                                               const char* source)
{
    uint32_t output_width = 0;
    uint32_t output_height = 0;
    uint64_t rel_left = 0;
    uint64_t rel_top = 0;
    uint64_t rel_right = 0;
    uint64_t rel_bottom = 0;
    uint64_t abs_left = 0;
    uint64_t abs_top = 0;
    uint64_t abs_right = 0;
    uint64_t abs_bottom = 0;
    uint32_t dst_x = 0;
    uint32_t dst_y = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    size_t stride = 0;
    size_t scaled_stride = 0;
    size_t scaled_len = 0;
    uint32_t y = 0;
    rdp_buffer scaled;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !surface->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (surface->target_width == 0 || surface->target_height == 0 ||
        surface->target_width > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION ||
        surface->target_height > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    output_width = librdp_surface_width(session->surface);
    output_height = librdp_surface_height(session->surface);
    rel_left = ((uint64_t)left * surface->target_width) / surface->width;
    rel_top = ((uint64_t)top * surface->target_height) / surface->height;
    rel_right = (((uint64_t)right * surface->target_width) + surface->width - 1u) / surface->width;
    rel_bottom = (((uint64_t)bottom * surface->target_height) + surface->height - 1u) / surface->height;
    if (rel_right <= rel_left || rel_bottom <= rel_top)
        return LIBRDP_STATUS_OK;

    abs_left = (uint64_t)surface->output_origin_x + rel_left;
    abs_top = (uint64_t)surface->output_origin_y + rel_top;
    abs_right = (uint64_t)surface->output_origin_x + rel_right;
    abs_bottom = (uint64_t)surface->output_origin_y + rel_bottom;
    if (abs_left >= output_width || abs_top >= output_height || abs_right <= abs_left || abs_bottom <= abs_top)
        return LIBRDP_STATUS_OK;
    if (abs_right > output_width)
        abs_right = output_width;
    if (abs_bottom > output_height)
        abs_bottom = output_height;
    dst_x = (uint32_t)abs_left;
    dst_y = (uint32_t)abs_top;
    width = (uint32_t)(abs_right - abs_left);
    height = (uint32_t)(abs_bottom - abs_top);
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_OK;

    scaled_stride = (size_t)width * 4u;
    if ((size_t)height > ((size_t)-1) / scaled_stride)
        return LIBRDP_STATUS_NO_MEMORY;
    scaled_len = scaled_stride * height;
    rdp_buffer_init(&scaled);
    status = rdp_buffer_reserve(&scaled, scaled_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    scaled.length = scaled_len;

    stride = (size_t)surface->width * 4u;
    for (y = 0; y < height; y++)
    {
        uint64_t rel_y = ((uint64_t)dst_y + y) - surface->output_origin_y;
        uint32_t src_y = (uint32_t)((rel_y * surface->height) / surface->target_height);
        uint8_t* dst = scaled.data + ((size_t)y * scaled_stride);
        uint32_t x = 0;

        if (src_y >= surface->height)
            src_y = surface->height - 1u;
        for (x = 0; x < width; x++)
        {
            uint64_t rel_x = ((uint64_t)dst_x + x) - surface->output_origin_x;
            uint32_t src_x = (uint32_t)((rel_x * surface->width) / surface->target_width);
            const uint8_t* src = NULL;

            if (src_x >= surface->width)
                src_x = surface->width - 1u;
            src = surface->pixels.data + ((size_t)src_y * stride) + ((size_t)src_x * 4u);
            memcpy(dst + ((size_t)x * 4u), src, 4u);
        }
    }

    status = librdp_surface_blit_bgra32(session->surface,
                                        dst_x,
                                        dst_y,
                                        width,
                                        height,
                                        scaled.data,
                                        scaled_stride);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_session_graphics_dirty_add(session, dst_x, dst_y, width, height);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "client.graphics.surface.flush_scaled",
                              "source=%s surface_id=%u src_x=%u src_y=%u src_width=%u src_height=%u dst_x=%u dst_y=%u dst_width=%u dst_height=%u surface_width=%u surface_height=%u target_width=%u target_height=%u frame_id=%u scaled_hash=%016llx",
                              source ? source : "unknown",
                              surface->surface_id,
                              left,
                              top,
                              (uint32_t)(right - left),
                              (uint32_t)(bottom - top),
                              dst_x,
                              dst_y,
                              width,
                              height,
                              surface->width,
                              surface->height,
                              surface->target_width,
                              surface->target_height,
                              session->graphics_current_frame_id,
                              (unsigned long long)rdp_session_trace_hash_bgra(scaled.data,
                                                                               width,
                                                                               height,
                                                                               scaled_stride));
    }
    rdp_buffer_free(&scaled);
    return status;
}

static librdp_status rdp_session_graphics_surface_flush(librdp_session* session,
                                                        rdp_session_graphics_surface* surface,
                                                        uint16_t left,
                                                        uint16_t top,
                                                        uint16_t right,
                                                        uint16_t bottom,
                                                        const char* source)
{
    uint64_t dst_x64 = 0;
    uint64_t dst_y64 = 0;
    uint32_t dst_x = 0;
    uint32_t dst_y = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t output_width = 0;
    uint32_t output_height = 0;
    size_t stride = 0;
    size_t output_stride = 0;
    const uint8_t* pixels = NULL;
    const uint8_t* output_pixels = NULL;
    uint64_t source_hash = 0;
    uint64_t output_hash = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !surface->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!surface->mapped || left >= right || top >= bottom)
        return LIBRDP_STATUS_OK;
    if (right > surface->width || bottom > surface->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (surface->scaled)
        return rdp_session_graphics_surface_flush_scaled(session,
                                                         surface,
                                                         left,
                                                         top,
                                                         right,
                                                         bottom,
                                                         source);

    output_width = librdp_surface_width(session->surface);
    output_height = librdp_surface_height(session->surface);
    dst_x64 = (uint64_t)surface->output_origin_x + left;
    dst_y64 = (uint64_t)surface->output_origin_y + top;
    if (dst_x64 >= output_width || dst_y64 >= output_height)
        return LIBRDP_STATUS_OK;
    dst_x = (uint32_t)dst_x64;
    dst_y = (uint32_t)dst_y64;
    width = (uint32_t)(right - left);
    height = (uint32_t)(bottom - top);
    if (width > output_width - dst_x)
        width = output_width - dst_x;
    if (height > output_height - dst_y)
        height = output_height - dst_y;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_OK;

    stride = (size_t)surface->width * 4u;
    pixels = surface->pixels.data + ((size_t)top * stride) + ((size_t)left * 4u);
    source_hash = rdp_session_trace_hash_bgra(pixels, width, height, stride);
    status = librdp_surface_blit_bgra32(session->surface, dst_x, dst_y, width, height, pixels, stride);
    if (status == LIBRDP_STATUS_OK)
    {
        output_stride = librdp_surface_stride(session->surface);
        output_pixels = librdp_surface_pixels(session->surface);
        if (output_pixels)
        {
            output_hash = rdp_session_trace_hash_bgra(output_pixels + ((size_t)dst_y * output_stride) +
                                                          ((size_t)dst_x * 4u),
                                                      width,
                                                      height,
                                                      output_stride);
        }
        rdp_session_graphics_dirty_add(session, dst_x, dst_y, width, height);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "client.graphics.surface.flush",
                              "source=%s surface_id=%u src_x=%u src_y=%u dst_x=%u dst_y=%u width=%u height=%u surface_width=%u surface_height=%u output_width=%u output_height=%u frame_id=%u frame_active=%u source_hash=%016llx output_hash=%016llx",
                              source ? source : "unknown",
                              surface->surface_id,
                              left,
                              top,
                              dst_x,
                              dst_y,
                              width,
                              height,
                              surface->width,
                              surface->height,
                              output_width,
                              output_height,
                              session->graphics_current_frame_id,
                              session->graphics_frame_active ? 1u : 0u,
                              (unsigned long long)source_hash,
                              (unsigned long long)output_hash);
    }
    return status;
}

static librdp_status rdp_session_graphics_surface_map(librdp_session* session,
                                                      const rdp_graphics_map_surface_to_output* map)
{
    rdp_session_graphics_surface* surface = NULL;

    if (!session || !map)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    surface = rdp_session_graphics_surface_find(session, map->surface_id);
    if (!surface)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    surface->mapped = 1;
    surface->output_origin_x = map->output_origin_x;
    surface->output_origin_y = map->output_origin_y;
    surface->target_width = surface->width;
    surface->target_height = surface->height;
    surface->scaled = 0;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_surface_map_scaled(
    librdp_session* session,
    const rdp_graphics_map_surface_to_scaled_output* map)
{
    rdp_session_graphics_surface* surface = NULL;

    if (!session || !map)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (map->target_width == 0 || map->target_height == 0 ||
        map->target_width > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION ||
        map->target_height > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    surface = rdp_session_graphics_surface_find(session, map->surface_id);
    if (!surface)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    surface->mapped = 1;
    surface->output_origin_x = map->output_origin_x;
    surface->output_origin_y = map->output_origin_y;
    surface->target_width = map->target_width;
    surface->target_height = map->target_height;
    surface->scaled = map->target_width != surface->width || map->target_height != surface->height;
    return rdp_session_graphics_surface_flush(session,
                                              surface,
                                              0,
                                              0,
                                              surface->width,
                                              surface->height,
                                              surface->scaled ? "map_scaled_output" : "map_output");
}

static librdp_status rdp_session_graphics_surface_fill(librdp_session* session,
                                                       rdp_session_graphics_surface* surface,
                                                       const rdp_graphics_rect16* rect,
                                                       uint32_t fill_pixel)
{
    uint8_t b = (uint8_t)(fill_pixel & 0xffu);
    uint8_t g = (uint8_t)((fill_pixel >> 8) & 0xffu);
    uint8_t r = (uint8_t)((fill_pixel >> 16) & 0xffu);
    uint8_t a = 0xffu;
    size_t stride = 0;
    uint16_t y = 0;

    if (!session || !surface || !rect || !surface->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rect->right > surface->width || rect->bottom > surface->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rect->left >= rect->right || rect->top >= rect->bottom)
        return LIBRDP_STATUS_OK;
    if (surface->pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_ARGB_8888)
        a = (uint8_t)((fill_pixel >> 24) & 0xffu);

    stride = (size_t)surface->width * 4u;
    for (y = rect->top; y < rect->bottom; y++)
    {
        uint8_t* pixel = surface->pixels.data + ((size_t)y * stride) + ((size_t)rect->left * 4u);
        uint16_t x = 0;

        for (x = rect->left; x < rect->right; x++)
        {
            pixel[0] = b;
            pixel[1] = g;
            pixel[2] = r;
            pixel[3] = a;
            pixel += 4;
        }
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.surface.fill.rect",
                          "source=solid_fill surface_id=%u x=%u y=%u width=%u height=%u surface_width=%u surface_height=%u fill_pixel=%08x frame_id=%u dest_hash=%016llx",
                          surface->surface_id,
                          rect->left,
                          rect->top,
                          (unsigned)(rect->right - rect->left),
                          (unsigned)(rect->bottom - rect->top),
                          surface->width,
                          surface->height,
                          fill_pixel,
                          session->graphics_current_frame_id,
                          (unsigned long long)rdp_session_trace_surface_hash(surface,
                                                                              rect->left,
                                                                              rect->top,
                                                                              (uint32_t)(rect->right - rect->left),
                                                                              (uint32_t)(rect->bottom - rect->top)));
    return rdp_session_graphics_surface_flush(session,
                                              surface,
                                              rect->left,
                                              rect->top,
                                              rect->right,
                                              rect->bottom,
                                              "solid_fill");
}

static librdp_status rdp_session_graphics_surface_write_bgra(librdp_session* session,
                                                             rdp_session_graphics_surface* surface,
                                                             uint16_t x,
                                                             uint16_t y,
                                                             uint16_t width,
                                                             uint16_t height,
                                                             const uint8_t* pixels,
                                                             size_t stride,
                                                             int force_opaque,
                                                             const char* source)
{
    uint16_t row = 0;
    size_t dest_stride = 0;
    uint64_t source_hash = 0;
    uint64_t dest_hash = 0;

    if (!session || !surface || !surface->active || !pixels)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_OK;
    if (x > surface->width || y > surface->height ||
        width > surface->width - x || height > surface->height - y ||
        stride < (size_t)width * 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    source_hash = rdp_session_trace_hash_bgra(pixels, width, height, stride);
    dest_stride = (size_t)surface->width * 4u;
    for (row = 0; row < height; row++)
    {
        uint8_t* dest = surface->pixels.data + ((size_t)(y + row) * dest_stride) + ((size_t)x * 4u);
        const uint8_t* source = pixels + ((size_t)row * stride);

        memcpy(dest, source, (size_t)width * 4u);
        if (force_opaque)
        {
            uint16_t column = 0;

            for (column = 0; column < width; column++)
                dest[((size_t)column * 4u) + 3u] = 0xffu;
        }
    }
    dest_hash = rdp_session_trace_surface_hash(surface, x, y, width, height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.surface.write",
                          "source=%s surface_id=%u x=%u y=%u width=%u height=%u surface_width=%u surface_height=%u stride=%u dest_stride=%u force_opaque=%u frame_id=%u source_hash=%016llx dest_hash=%016llx",
                          source ? source : "unknown",
                          surface->surface_id,
                          x,
                          y,
                          width,
                          height,
                          surface->width,
                          surface->height,
                          (unsigned)stride,
                          (unsigned)dest_stride,
                          force_opaque ? 1u : 0u,
                          session->graphics_current_frame_id,
                          (unsigned long long)source_hash,
                          (unsigned long long)dest_hash);
    return rdp_session_graphics_surface_flush(session,
                                              surface,
                                              x,
                                              y,
                                              (uint16_t)(x + width),
                                              (uint16_t)(y + height),
                                              source);
}

static librdp_status rdp_session_graphics_surface_write_avc_regions(
    librdp_session* session,
    rdp_session_graphics_surface* surface,
    const rdp_graphics_avc420_metablock* meta,
    const rdp_avc_frame* frame,
    int force_opaque,
    const char* source)
{
    uint32_t i = 0;

    if (!session || !surface || !meta || !frame || !frame->pixels.data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (frame->stride < (size_t)frame->width * 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    for (i = 0; i < meta->rect_count; i++)
    {
        rdp_graphics_rect16 rect;
        uint16_t width = 0;
        uint16_t height = 0;
        const uint8_t* pixels = NULL;
        librdp_status status = LIBRDP_STATUS_OK;

        if (meta->rects_len < ((size_t)i + 1u) * 8u ||
            rdp_graphics_parse_rect16(meta->rects + ((size_t)i * 8u), 8u, &rect) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rect.left >= rect.right || rect.top >= rect.bottom ||
            rect.right > surface->width || rect.bottom > surface->height ||
            rect.right > frame->width || rect.bottom > frame->height)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        width = (uint16_t)(rect.right - rect.left);
        height = (uint16_t)(rect.bottom - rect.top);
        pixels = frame->pixels.data + ((size_t)rect.top * frame->stride) + ((size_t)rect.left * 4u);
        status = rdp_session_graphics_surface_write_bgra(session,
                                                         surface,
                                                         rect.left,
                                                         rect.top,
                                                         width,
                                                         height,
                                                         pixels,
                                                         frame->stride,
                                                         force_opaque,
                                                         source);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_surface_write_wire(librdp_session* session,
                                                             rdp_session_graphics_surface* surface,
                                                             const rdp_graphics_wire_to_surface_1* wire)
{
    uint16_t width = 0;
    uint16_t height = 0;
    size_t expected = 0;

    if (!session || !surface || !wire)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (wire->dest_rect.right < wire->dest_rect.left || wire->dest_rect.bottom < wire->dest_rect.top)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    width = (uint16_t)(wire->dest_rect.right - wire->dest_rect.left);
    height = (uint16_t)(wire->dest_rect.bottom - wire->dest_rect.top);
    expected = (size_t)width * (size_t)height * 4u;
    if (wire->bitmap_data_length != expected)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_session_graphics_surface_write_bgra(session,
                                                   surface,
                                                   wire->dest_rect.left,
                                                   wire->dest_rect.top,
                                                   width,
                                                   height,
                                                   wire->bitmap_data,
                                                   (size_t)width * 4u,
                                                   wire->pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                                   "uncompressed");
}

static uint32_t rdp_session_min_u32(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}

static uint32_t rdp_session_max_u32(uint32_t a, uint32_t b)
{
    return a > b ? a : b;
}

static uint64_t rdp_session_trace_hash_seed(uint64_t hash, uint64_t value)
{
    unsigned int i = 0;

    for (i = 0; i < 8; i++)
    {
        hash ^= (uint8_t)((value >> (i * 8u)) & 0xffu);
        hash *= 1099511628211ull;
    }
    return hash;
}

static uint64_t rdp_session_trace_hash_bytes(uint64_t hash, const uint8_t* bytes, size_t length)
{
    size_t i = 0;

    for (i = 0; i < length; i++)
    {
        hash ^= bytes[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

static uint64_t rdp_session_trace_hash_bgra(const uint8_t* pixels,
                                            uint32_t width,
                                            uint32_t height,
                                            size_t stride)
{
    const size_t row_bytes = (size_t)width * 4u;
    const uint64_t offset = 1469598103934665603ull;
    uint64_t hash = offset;
    uint64_t pixel_count = 0;
    uint64_t samples = 0;
    uint64_t i = 0;

    if (!rdp_trace_enabled_level(RDP_TRACE_CLIENT, RDP_TRACE_LEVEL_TRACE) ||
        !pixels || width == 0 || height == 0 || stride < row_bytes)
        return 0;

    hash = rdp_session_trace_hash_seed(hash, width);
    hash = rdp_session_trace_hash_seed(hash, height);
    pixel_count = (uint64_t)width * (uint64_t)height;
    samples = pixel_count < 8192u ? pixel_count : 8192u;
    if (samples == 0)
        return hash;
    if (samples == 1)
        return rdp_session_trace_hash_bytes(hash, pixels, 4u);

    for (i = 0; i < samples; i++)
    {
        const uint64_t pixel_index = (i * (pixel_count - 1u)) / (samples - 1u);
        const uint32_t row = (uint32_t)(pixel_index / width);
        const uint32_t column = (uint32_t)(pixel_index % width);
        const uint8_t* p = pixels + ((size_t)row * stride) + ((size_t)column * 4u);

        hash = rdp_session_trace_hash_bytes(hash, p, 4u);
    }
    return hash;
}

static uint64_t rdp_session_trace_surface_hash(const rdp_session_graphics_surface* surface,
                                               uint32_t x,
                                               uint32_t y,
                                               uint32_t width,
                                               uint32_t height)
{
    size_t stride = 0;
    const uint8_t* pixels = NULL;

    if (!surface || !surface->active || !surface->pixels.data)
        return 0;
    if (width == 0 || height == 0 || x > surface->width || y > surface->height ||
        width > (uint32_t)surface->width - x || height > (uint32_t)surface->height - y)
        return 0;
    stride = (size_t)surface->width * 4u;
    pixels = surface->pixels.data + ((size_t)y * stride) + ((size_t)x * 4u);
    return rdp_session_trace_hash_bgra(pixels, width, height, stride);
}

static librdp_status rdp_session_graphics_progressive_base_quant(const rdp_graphics_progressive_region* region,
                                                                 uint8_t quant_idx,
                                                                 rdp_rfx_component_quant* quant)
{
    if (!region || !quant)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (quant_idx >= region->quant_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_rfx_parse_component_quant(region->quant_values + ((size_t)quant_idx * 5u), 5u, quant);
}

static librdp_status rdp_session_graphics_progressive_delta_quant(const rdp_graphics_progressive_region* region,
                                                                  uint8_t progressive_idx,
                                                                  uint8_t component_idx,
                                                                  rdp_rfx_component_quant* delta)
{
    rdp_rfx_progressive_quant progressive;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!region || !delta)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(delta, 0, sizeof(*delta));
    if (progressive_idx == 0xffu)
        return LIBRDP_STATUS_OK;
    if (progressive_idx >= region->progressive_quant_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_rfx_parse_progressive_quant(region->progressive_quant_values + ((size_t)progressive_idx * 16u),
                                             16u,
                                             &progressive);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (component_idx == 0)
        *delta = progressive.y;
    else if (component_idx == 1)
        *delta = progressive.cb;
    else if (component_idx == 2)
        *delta = progressive.cr;
    else
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_progressive_write_region_tile(
    librdp_session* session,
    rdp_session_graphics_surface* surface,
    const rdp_graphics_progressive_region* region,
    uint32_t x,
    uint32_t y,
    uint32_t width,
    uint32_t height,
    const rdp_rfx_tile_pixels* pixels,
    int* wrote)
{
    uint16_t i = 0;
    uint32_t tile_right = 0;
    uint32_t tile_bottom = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !region || !pixels || !wrote)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (pixels->stride < RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE * 4u)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.write_region.failed",
                        "stage=stride surface_id=%u tile_x=%u tile_y=%u tile_width=%u tile_height=%u stride=%u",
                        surface ? surface->surface_id : 0u,
                        x,
                        y,
                        width,
                        height,
                        (unsigned)pixels->stride);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }

    *wrote = 0;
    tile_right = x + width;
    tile_bottom = y + height;
    for (i = 0; i < region->rect_count; i++)
    {
        rdp_graphics_rect16 rect;
        uint32_t left = 0;
        uint32_t top = 0;
        uint32_t right = 0;
        uint32_t bottom = 0;
        const uint8_t* src = NULL;

        status = rdp_graphics_progressive_parse_region_rect(region->rects + ((size_t)i * 8u),
                                                            region->rects_len - ((size_t)i * 8u),
                                                            &rect);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.progressive.write_region.failed",
                            "stage=rect_parse surface_id=%u tile_x=%u tile_y=%u tile_width=%u tile_height=%u rect_index=%u status=%d",
                            surface->surface_id,
                            x,
                            y,
                            width,
                            height,
                            i,
                            (int)status);
            return status;
        }
        if (rect.right <= rect.left || rect.bottom <= rect.top)
            continue;

        left = rdp_session_max_u32(x, rect.left);
        top = rdp_session_max_u32(y, rect.top);
        right = rdp_session_min_u32(tile_right, rect.right);
        bottom = rdp_session_min_u32(tile_bottom, rect.bottom);
        if (right <= left || bottom <= top)
            continue;

        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "client.graphics.progressive.region.write",
                              "surface_id=%u tile_x=%u tile_y=%u tile_width=%u tile_height=%u rect_index=%u rect_left=%u rect_top=%u rect_right=%u rect_bottom=%u write_left=%u write_top=%u write_width=%u write_height=%u frame_id=%u",
                              surface->surface_id,
                              x,
                              y,
                              width,
                              height,
                              i,
                              rect.left,
                              rect.top,
                              rect.right,
                              rect.bottom,
                              left,
                              top,
                              right - left,
                              bottom - top,
                              session->graphics_current_frame_id);
        src = pixels->bgra + (((size_t)top - y) * pixels->stride) + (((size_t)left - x) * 4u);
        status = rdp_session_graphics_surface_write_bgra(session,
                                                         surface,
                                                         (uint16_t)left,
                                                         (uint16_t)top,
                                                         (uint16_t)(right - left),
                                                         (uint16_t)(bottom - top),
                                                         src,
                                                         pixels->stride,
                                                         0,
                                                         "progressive");
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.progressive.write_region.failed",
                            "stage=surface_write surface_id=%u surface_width=%u surface_height=%u tile_x=%u tile_y=%u tile_width=%u tile_height=%u rect_left=%u rect_top=%u rect_right=%u rect_bottom=%u write_left=%u write_top=%u write_width=%u write_height=%u stride=%u status=%d",
                            surface->surface_id,
                            surface->width,
                            surface->height,
                            x,
                            y,
                            width,
                            height,
                            rect.left,
                            rect.top,
                            rect.right,
                            rect.bottom,
                            left,
                            top,
                            right - left,
                            bottom - top,
                            (unsigned)pixels->stride,
                            (int)status);
            return status;
        }
        *wrote = 1;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_progressive_render_tile(librdp_session* session,
                                                                  uint32_t channel_id,
                                                                  uint32_t codec_context_id,
                                                                  rdp_session_graphics_surface* surface,
                                                                  const rdp_graphics_progressive_region* region,
                                                                  uint16_t block_type,
                                                                  uint8_t quant_idx_y,
                                                                  uint8_t quant_idx_cb,
                                                                  uint8_t quant_idx_cr,
                                                                  uint16_t x_idx,
                                                                  uint16_t y_idx,
                                                                  uint8_t tile_flags,
                                                                  uint8_t progressive_idx,
                                                                  const uint8_t* y_data,
                                                                  size_t y_len,
                                                                  const uint8_t* cb_data,
                                                                  size_t cb_len,
                                                                  const uint8_t* cr_data,
                                                                  size_t cr_len,
                                                                  uint32_t* rendered_tiles,
                                                                  uint32_t* failed_tiles,
                                                                  uint32_t* unsupported_tiles)
{
    rdp_session_progressive_tile_cache* tile_cache = NULL;
    rdp_rfx_component_quant y_quant;
    rdp_rfx_component_quant y_delta;
    rdp_rfx_component_quant cb_quant;
    rdp_rfx_component_quant cb_delta;
    rdp_rfx_component_quant cr_quant;
    rdp_rfx_component_quant cr_delta;
    rdp_rfx_tile_pixels pixels;
    uint32_t x = (uint32_t)x_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    uint32_t y = (uint32_t)y_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    uint32_t width = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    uint32_t height = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    int extrapolate = 0;
    const char* stage = "base_quant.y";
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !region || !rendered_tiles || !failed_tiles || !unsupported_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!y_data || !cb_data || !cr_data)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (x >= surface->width || y >= surface->height)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.clipped",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        block_type);
        return LIBRDP_STATUS_OK;
    }
    if (width > (uint32_t)surface->width - x)
        width = (uint32_t)surface->width - x;
    if (height > (uint32_t)surface->height - y)
        height = (uint32_t)surface->height - y;

    stage = "base_quant.y";
    status = rdp_session_graphics_progressive_base_quant(region, quant_idx_y, &y_quant);
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.y";
        status = rdp_session_graphics_progressive_delta_quant(region, progressive_idx, 0, &y_delta);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "base_quant.cb";
        status = rdp_session_graphics_progressive_base_quant(region, quant_idx_cb, &cb_quant);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.cb";
        status = rdp_session_graphics_progressive_delta_quant(region, progressive_idx, 1, &cb_delta);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "base_quant.cr";
        status = rdp_session_graphics_progressive_base_quant(region, quant_idx_cr, &cr_quant);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.cr";
        status = rdp_session_graphics_progressive_delta_quant(region, progressive_idx, 2, &cr_delta);
    }
    extrapolate = (region->flags & 0x01u) != 0;
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "state";
        tile_cache = rdp_session_progressive_tile_get(session,
                                                      surface->surface_id,
                                                      x_idx,
                                                      y_idx,
                                                      1);
        if (!tile_cache || !tile_cache->state || !tile_cache->pixels)
            status = LIBRDP_STATUS_NO_MEMORY;
    }
    if (status == LIBRDP_STATUS_OK &&
        (tile_flags & 0x01u) != 0 &&
        (!tile_cache->state->valid ||
         !tile_cache->state->y.valid ||
         !tile_cache->state->cb.valid ||
         !tile_cache->state->cr.valid))
    {
        (*unsupported_tiles)++;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.missing",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u flags=%u progressive_idx=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        block_type,
                        tile_flags,
                        progressive_idx);
        return LIBRDP_STATUS_OK;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "decode";
        status = rdp_rfx_decode_progressive_tile_state(y_data,
                                                       y_len,
                                                       cb_data,
                                                       cb_len,
                                                       cr_data,
                                                       cr_len,
                                                       &y_quant,
                                                       &y_delta,
                                                       &cb_quant,
                                                       &cb_delta,
                                                       &cr_quant,
                                                       &cr_delta,
                                                       extrapolate,
                                                       (tile_flags & 0x01u) != 0,
                                                       tile_cache->state,
                                                       &pixels);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        tile_cache->state->x_idx = x_idx;
        tile_cache->state->y_idx = y_idx;
        memcpy(tile_cache->pixels, &pixels, sizeof(*tile_cache->pixels));
        tile_cache->has_pixels = 1;
        tile_cache->updated_frame_id = session->graphics_current_frame_id;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        (*failed_tiles)++;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.failed",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u flags=%u progressive_idx=%u stage=%s status=%d y_len=%u cb_len=%u cr_len=%u extrapolate=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        block_type,
                        tile_flags,
                        progressive_idx,
                        stage,
                        (int)status,
                        (unsigned)y_len,
                        (unsigned)cb_len,
                        (unsigned)cr_len,
                        (unsigned)extrapolate);
        return LIBRDP_STATUS_OK;
    }

    (*rendered_tiles)++;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.progressive.tile",
                          "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u width=%u height=%u block_type=%u flags=%u progressive_idx=%u pass=%u extrapolate=%u frame_id=%u queued=1",
                          channel_id,
                          codec_context_id,
                          surface->surface_id,
                          x,
                          y,
                          width,
                          height,
                          block_type,
                          tile_flags,
                          progressive_idx,
                          tile_cache && tile_cache->state ? tile_cache->state->pass : 0u,
                          (unsigned)extrapolate,
                          session->graphics_current_frame_id);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_progressive_render_upgrade(
    librdp_session* session,
    uint32_t channel_id,
    uint32_t codec_context_id,
    rdp_session_graphics_surface* surface,
    const rdp_graphics_progressive_region* region,
    const rdp_graphics_progressive_tile_upgrade* tile,
    uint32_t* rendered_tiles,
    uint32_t* failed_tiles,
    uint32_t* unsupported_tiles)
{
    rdp_session_progressive_tile_cache* tile_cache = NULL;
    rdp_rfx_component_quant y_quant;
    rdp_rfx_component_quant y_delta;
    rdp_rfx_component_quant cb_quant;
    rdp_rfx_component_quant cb_delta;
    rdp_rfx_component_quant cr_quant;
    rdp_rfx_component_quant cr_delta;
    rdp_rfx_tile_pixels pixels;
    uint32_t x = 0;
    uint32_t y = 0;
    uint32_t width = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    uint32_t height = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    int extrapolate = 0;
    const char* stage = "state";
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !region || !tile || !rendered_tiles || !failed_tiles || !unsupported_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    x = (uint32_t)tile->x_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    y = (uint32_t)tile->y_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    if (x >= surface->width || y >= surface->height)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.clipped",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        tile->block_type);
        return LIBRDP_STATUS_OK;
    }
    if (width > (uint32_t)surface->width - x)
        width = (uint32_t)surface->width - x;
    if (height > (uint32_t)surface->height - y)
        height = (uint32_t)surface->height - y;

    tile_cache = rdp_session_progressive_tile_get(session,
                                                  surface->surface_id,
                                                  tile->x_idx,
                                                  tile->y_idx,
                                                  0);
    if (!tile_cache || !tile_cache->state || !tile_cache->pixels || !tile_cache->state->valid)
    {
        (*unsupported_tiles)++;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.missing",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u progressive_idx=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        tile->block_type,
                        tile->progressive_quality);
        return LIBRDP_STATUS_OK;
    }

    stage = "base_quant.y";
    status = rdp_session_graphics_progressive_base_quant(region, tile->quant_idx_y, &y_quant);
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.y";
        status = rdp_session_graphics_progressive_delta_quant(region, tile->progressive_quality, 0, &y_delta);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "base_quant.cb";
        status = rdp_session_graphics_progressive_base_quant(region, tile->quant_idx_cb, &cb_quant);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.cb";
        status = rdp_session_graphics_progressive_delta_quant(region, tile->progressive_quality, 1, &cb_delta);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "base_quant.cr";
        status = rdp_session_graphics_progressive_base_quant(region, tile->quant_idx_cr, &cr_quant);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.cr";
        status = rdp_session_graphics_progressive_delta_quant(region, tile->progressive_quality, 2, &cr_delta);
    }

    extrapolate = (region->flags & 0x01u) != 0;
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "decode";
        status = rdp_rfx_decode_progressive_upgrade_tile(tile->y_srl_data,
                                                         tile->y_srl_len,
                                                         tile->y_raw_data,
                                                         tile->y_raw_len,
                                                         tile->cb_srl_data,
                                                         tile->cb_srl_len,
                                                         tile->cb_raw_data,
                                                         tile->cb_raw_len,
                                                         tile->cr_srl_data,
                                                         tile->cr_srl_len,
                                                         tile->cr_raw_data,
                                                         tile->cr_raw_len,
                                                         &y_quant,
                                                         &y_delta,
                                                         &cb_quant,
                                                         &cb_delta,
                                                         &cr_quant,
                                                         &cr_delta,
                                                         extrapolate,
                                                         tile_cache->state,
                                                         &pixels);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        memcpy(tile_cache->pixels, &pixels, sizeof(*tile_cache->pixels));
        tile_cache->has_pixels = 1;
        tile_cache->updated_frame_id = session->graphics_current_frame_id;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        (*failed_tiles)++;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.failed",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u stage=%s status=%d y_srl_len=%u y_raw_len=%u cb_srl_len=%u cb_raw_len=%u cr_srl_len=%u cr_raw_len=%u extrapolate=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        tile->block_type,
                        stage,
                        (int)status,
                        tile->y_srl_len,
                        tile->y_raw_len,
                        tile->cb_srl_len,
                        tile->cb_raw_len,
                        tile->cr_srl_len,
                        tile->cr_raw_len,
                        (unsigned)extrapolate);
        return LIBRDP_STATUS_OK;
    }

    (*rendered_tiles)++;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.progressive.tile",
                          "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u width=%u height=%u block_type=%u progressive_idx=%u pass=%u extrapolate=%u frame_id=%u queued=1",
                          channel_id,
                          codec_context_id,
                          surface->surface_id,
                          x,
                          y,
                          width,
                          height,
                          tile->block_type,
                          tile->progressive_quality,
                          tile_cache->state->pass,
                          (unsigned)extrapolate,
                          session->graphics_current_frame_id);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_progressive_flush_region(librdp_session* session,
                                                                   uint32_t channel_id,
                                                                   uint32_t codec_context_id,
                                                                   rdp_session_graphics_surface* surface,
                                                                   const rdp_graphics_progressive_region* region,
                                                                   uint32_t* flushed_tiles,
                                                                   uint32_t* failed_tiles)
{
    size_t i = 0;
    uint32_t considered_tiles = 0;
    uint32_t clipped_tiles = 0;

    if (!session || !surface || !region || !flushed_tiles || !failed_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        rdp_session_progressive_tile_cache* tile_cache = &session->progressive_tiles[i];
        uint32_t x = 0;
        uint32_t y = 0;
        uint32_t width = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
        uint32_t height = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
        int wrote = 0;
        librdp_status status = LIBRDP_STATUS_OK;

        if (!tile_cache->active || tile_cache->surface_id != surface->surface_id ||
            tile_cache->updated_frame_id != session->graphics_current_frame_id ||
            !tile_cache->has_pixels || !tile_cache->pixels)
            continue;

        x = (uint32_t)tile_cache->x_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
        y = (uint32_t)tile_cache->y_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
        if (x >= surface->width || y >= surface->height)
        {
            clipped_tiles++;
            continue;
        }
        if (width > (uint32_t)surface->width - x)
            width = (uint32_t)surface->width - x;
        if (height > (uint32_t)surface->height - y)
            height = (uint32_t)surface->height - y;
        considered_tiles++;
        status = rdp_session_graphics_progressive_write_region_tile(session,
                                                                    surface,
                                                                    region,
                                                                    x,
                                                                    y,
                                                                    width,
                                                                    height,
                                                                    tile_cache->pixels,
                                                                    &wrote);
        if (status != LIBRDP_STATUS_OK)
        {
            (*failed_tiles)++;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.progressive.tile.flush.failed",
                            "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u width=%u height=%u frame_id=%u status=%d",
                            channel_id,
                            codec_context_id,
                            surface->surface_id,
                            x,
                            y,
                            width,
                            height,
                            session->graphics_current_frame_id,
                            (int)status);
            continue;
        }
        if (wrote)
            (*flushed_tiles)++;
        else
            clipped_tiles++;
    }

    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.progressive.region.flush",
                          "dvc_channel_id=%u context_id=%u surface_id=%u frame_id=%u considered_tiles=%u flushed_tiles=%u clipped_tiles=%u failed_tiles=%u",
                          channel_id,
                          codec_context_id,
                          surface->surface_id,
                          session->graphics_current_frame_id,
                          considered_tiles,
                          *flushed_tiles,
                          clipped_tiles,
                          *failed_tiles);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_progressive_render_region(librdp_session* session,
                                                                    uint32_t channel_id,
                                                                    uint32_t codec_context_id,
                                                                    rdp_session_graphics_surface* surface,
                                                                    const rdp_graphics_progressive_region* region,
                                                                    uint32_t* rendered_tiles,
                                                                    uint32_t* failed_tiles,
                                                                    uint32_t* unsupported_tiles)
{
    size_t offset = 0;

    if (!session || !surface || !region || !rendered_tiles || !failed_tiles || !unsupported_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    while (offset < region->tiles_len)
    {
        rdp_graphics_progressive_block block;
        librdp_status status = rdp_graphics_progressive_parse_block(region->tiles + offset,
                                                                    region->tiles_len - offset,
                                                                    &block);

        if (status != LIBRDP_STATUS_OK)
            return status;
        if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_SIMPLE)
        {
            rdp_graphics_progressive_tile_simple tile;

            status = rdp_graphics_progressive_parse_tile_simple(region->tiles + offset,
                                                                region->tiles_len - offset,
                                                                &tile);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_graphics_progressive_render_tile(session,
                                                                  channel_id,
                                                                  codec_context_id,
                                                                  surface,
                                                                  region,
                                                                  block.type,
                                                                  tile.quant_idx_y,
                                                                  tile.quant_idx_cb,
                                                                  tile.quant_idx_cr,
                                                                  tile.x_idx,
                                                                  tile.y_idx,
                                                                  tile.flags,
                                                                  0xffu,
                                                                  tile.y_data,
                                                                  tile.y_len,
                                                                  tile.cb_data,
                                                                  tile.cb_len,
                                                                  tile.cr_data,
                                                                  tile.cr_len,
                                                                  rendered_tiles,
                                                                  failed_tiles,
                                                                  unsupported_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_FIRST)
        {
            rdp_graphics_progressive_tile_first tile;

            status = rdp_graphics_progressive_parse_tile_first(region->tiles + offset,
                                                               region->tiles_len - offset,
                                                               &tile);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_graphics_progressive_render_tile(session,
                                                                  channel_id,
                                                                  codec_context_id,
                                                                  surface,
                                                                  region,
                                                                  block.type,
                                                                  tile.quant_idx_y,
                                                                  tile.quant_idx_cb,
                                                                  tile.quant_idx_cr,
                                                                  tile.x_idx,
                                                                  tile.y_idx,
                                                                  tile.flags,
                                                                  tile.progressive_quality,
                                                                  tile.y_data,
                                                                  tile.y_len,
                                                                  tile.cb_data,
                                                                  tile.cb_len,
                                                                  tile.cr_data,
                                                                  tile.cr_len,
                                                                  rendered_tiles,
                                                                  failed_tiles,
                                                                  unsupported_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_UPGRADE)
        {
            rdp_graphics_progressive_tile_upgrade tile;

            status = rdp_graphics_progressive_parse_tile_upgrade(region->tiles + offset,
                                                                 region->tiles_len - offset,
                                                                 &tile);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_graphics_progressive_render_upgrade(session,
                                                                     channel_id,
                                                                     codec_context_id,
                                                                     surface,
                                                                     region,
                                                                     &tile,
                                                                     rendered_tiles,
                                                                     failed_tiles,
                                                                     unsupported_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else
        {
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        offset += block.length;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_progressive_render_stream(librdp_session* session,
                                                                    uint32_t channel_id,
                                                                    rdp_session_graphics_surface* surface,
                                                                    const rdp_graphics_wire_to_surface_2* wire,
                                                                    uint32_t* rendered_tiles,
                                                                    uint32_t* failed_tiles,
                                                                    uint32_t* unsupported_tiles)
{
    size_t offset = 0;
    uint32_t region_index = 0;

    if (!session || !surface || !wire || !rendered_tiles || !failed_tiles || !unsupported_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    *rendered_tiles = 0;
    *failed_tiles = 0;
    *unsupported_tiles = 0;
    while (offset < wire->bitmap_data_length)
    {
        rdp_graphics_progressive_block block;
        librdp_status status = rdp_graphics_progressive_parse_block(wire->bitmap_data + offset,
                                                                    wire->bitmap_data_length - offset,
                                                                    &block);

        if (status != LIBRDP_STATUS_OK)
            return status;
        if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_REGION)
        {
            rdp_graphics_progressive_region region;
            uint32_t flushed_tiles = 0;

            status = rdp_graphics_progressive_parse_region(wire->bitmap_data + offset,
                                                           wire->bitmap_data_length - offset,
                                                           &region);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.progressive.region",
                            "dvc_channel_id=%u context_id=%u surface_id=%u region_index=%u rect_count=%u quant_count=%u progressive_quant_count=%u tile_count=%u tile_data_size=%u flags=%u tile_size=%u frame_id=%u",
                            channel_id,
                            wire->codec_context_id,
                            surface->surface_id,
                            region_index,
                            region.rect_count,
                            region.quant_count,
                            region.progressive_quant_count,
                            region.tile_count,
                            region.tile_data_size,
                            region.flags,
                            region.tile_size,
                            session->graphics_current_frame_id);
            status = rdp_session_graphics_progressive_render_region(session,
                                                                    channel_id,
                                                                    wire->codec_context_id,
                                                                    surface,
                                                                    &region,
                                                                    rendered_tiles,
                                                                    failed_tiles,
                                                                    unsupported_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_graphics_progressive_flush_region(session,
                                                                   channel_id,
                                                                   wire->codec_context_id,
                                                                   surface,
                                                                   &region,
                                                                   &flushed_tiles,
                                                                   failed_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
            region_index++;
        }
        offset += block.length;
    }
    return LIBRDP_STATUS_OK;
}

static void rdp_session_graphics_cache_evict(librdp_session* session, uint16_t cache_slot)
{
    rdp_session_graphics_cache_entry* entry = NULL;

    if (!session || cache_slot >= RDP_SESSION_GRAPHICS_CACHE_SLOTS)
        return;
    entry = &session->graphics_cache[cache_slot];
    if (entry->active)
    {
        if (session->graphics_cache_bytes >= entry->pixels.length)
            session->graphics_cache_bytes -= entry->pixels.length;
        else
            session->graphics_cache_bytes = 0;
    }
    rdp_buffer_free(&entry->pixels);
    memset(entry, 0, sizeof(*entry));
}

static void rdp_session_graphics_cache_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_GRAPHICS_CACHE_SLOTS; i++)
        rdp_buffer_free(&session->graphics_cache[i].pixels);
    memset(session->graphics_cache, 0, sizeof(session->graphics_cache));
    session->graphics_cache_bytes = 0;
}

static rdp_session_graphics_cache_entry* rdp_session_graphics_cache_find(librdp_session* session, uint16_t cache_slot)
{
    if (!session || cache_slot >= RDP_SESSION_GRAPHICS_CACHE_SLOTS || !session->graphics_cache[cache_slot].active)
        return NULL;
    return &session->graphics_cache[cache_slot];
}

static librdp_status rdp_session_graphics_cache_store(librdp_session* session,
                                                      const rdp_graphics_surface_to_cache* surface_to_cache)
{
    rdp_session_graphics_surface* surface = NULL;
    rdp_session_graphics_cache_entry* entry = NULL;
    uint16_t width = 0;
    uint16_t height = 0;
    size_t source_stride = 0;
    size_t size = 0;
    size_t old_size = 0;
    size_t current_without_old = 0;
    uint16_t row = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface_to_cache)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (surface_to_cache->cache_slot >= RDP_SESSION_GRAPHICS_CACHE_SLOTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    surface = rdp_session_graphics_surface_find(session, surface_to_cache->surface_id);
    if (!surface)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (surface_to_cache->rect_src.right > surface->width ||
        surface_to_cache->rect_src.bottom > surface->height ||
        surface_to_cache->rect_src.left >= surface_to_cache->rect_src.right ||
        surface_to_cache->rect_src.top >= surface_to_cache->rect_src.bottom)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    width = (uint16_t)(surface_to_cache->rect_src.right - surface_to_cache->rect_src.left);
    height = (uint16_t)(surface_to_cache->rect_src.bottom - surface_to_cache->rect_src.top);
    size = (size_t)width * (size_t)height * 4u;
    entry = &session->graphics_cache[surface_to_cache->cache_slot];
    old_size = entry->active ? entry->pixels.length : 0;
    current_without_old = session->graphics_cache_bytes >= old_size ? session->graphics_cache_bytes - old_size : 0;
    if (size > RDP_SESSION_GRAPHICS_CACHE_MAX_BYTES ||
        current_without_old > RDP_SESSION_GRAPHICS_CACHE_MAX_BYTES - size)
        return LIBRDP_STATUS_NO_MEMORY;

    status = rdp_buffer_reserve(&entry->pixels, size);
    if (status != LIBRDP_STATUS_OK)
        return status;

    source_stride = (size_t)surface->width * 4u;
    for (row = 0; row < height; row++)
    {
        memcpy(entry->pixels.data + ((size_t)row * (size_t)width * 4u),
               surface->pixels.data + ((size_t)(surface_to_cache->rect_src.top + row) * source_stride) +
                   ((size_t)surface_to_cache->rect_src.left * 4u),
               (size_t)width * 4u);
    }
    entry->pixels.length = size;
    entry->active = 1;
    entry->cache_slot = surface_to_cache->cache_slot;
    entry->width = width;
    entry->height = height;
    entry->cache_key = surface_to_cache->cache_key;
    session->graphics_cache_bytes = current_without_old + size;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.cache.store",
                          "surface_id=%u cache_slot=%u width=%u height=%u src_left=%u src_top=%u src_right=%u src_bottom=%u cache_key=%llu cache_bytes=%llu source_hash=%016llx cache_hash=%016llx frame_id=%u",
                          surface_to_cache->surface_id,
                          surface_to_cache->cache_slot,
                          width,
                          height,
                          surface_to_cache->rect_src.left,
                          surface_to_cache->rect_src.top,
                          surface_to_cache->rect_src.right,
                          surface_to_cache->rect_src.bottom,
                          (unsigned long long)surface_to_cache->cache_key,
                          (unsigned long long)session->graphics_cache_bytes,
                          (unsigned long long)rdp_session_trace_surface_hash(surface,
                                                                              surface_to_cache->rect_src.left,
                                                                              surface_to_cache->rect_src.top,
                                                                              width,
                                                                              height),
                          (unsigned long long)rdp_session_trace_hash_bgra(entry->pixels.data,
                                                                          width,
                                                                          height,
                                                                          (size_t)width * 4u),
                          session->graphics_current_frame_id);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_surface_copy(librdp_session* session,
                                                       rdp_session_graphics_surface* source,
                                                       rdp_session_graphics_surface* dest,
                                                       const rdp_graphics_rect16* rect,
                                                       const rdp_graphics_point16* point)
{
    rdp_buffer copy;
    uint16_t width = 0;
    uint16_t height = 0;
    size_t source_stride = 0;
    size_t row_stride = 0;
    uint16_t row = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !source || !dest || !rect || !point || !source->active || !dest->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rect->right > source->width || rect->bottom > source->height ||
        rect->left >= rect->right || rect->top >= rect->bottom)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    width = (uint16_t)(rect->right - rect->left);
    height = (uint16_t)(rect->bottom - rect->top);
    if (point->x > dest->width || point->y > dest->height ||
        width > dest->width - point->x || height > dest->height - point->y)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_buffer_init(&copy);
    row_stride = (size_t)width * 4u;
    status = rdp_buffer_reserve(&copy, row_stride * (size_t)height);
    if (status == LIBRDP_STATUS_OK)
    {
        source_stride = (size_t)source->width * 4u;
        for (row = 0; row < height; row++)
        {
            memcpy(copy.data + ((size_t)row * row_stride),
                   source->pixels.data + ((size_t)(rect->top + row) * source_stride) + ((size_t)rect->left * 4u),
                   row_stride);
        }
        copy.length = row_stride * (size_t)height;
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "client.graphics.surface.copy",
                              "source_id=%u dest_id=%u src_left=%u src_top=%u src_right=%u src_bottom=%u dst_x=%u dst_y=%u width=%u height=%u frame_id=%u copy_hash=%016llx",
                              source->surface_id,
                              dest->surface_id,
                              rect->left,
                              rect->top,
                              rect->right,
                              rect->bottom,
                              point->x,
                              point->y,
                              width,
                              height,
                              session->graphics_current_frame_id,
                              (unsigned long long)rdp_session_trace_hash_bgra(copy.data, width, height, row_stride));
        status = rdp_session_graphics_surface_write_bgra(session,
                                                         dest,
                                                         point->x,
                                                         point->y,
                                                         width,
                                                         height,
                                                         copy.data,
                                                         row_stride,
                                                         0,
                                                         "surface_to_surface");
    }
    rdp_buffer_free(&copy);
    return status;
}

static librdp_status rdp_session_graphics_cache_copy_to_surface(librdp_session* session,
                                                                rdp_session_graphics_cache_entry* cache,
                                                                rdp_session_graphics_surface* surface,
                                                                const rdp_graphics_point16* point)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !cache || !surface || !point || !cache->active || !surface->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (point->x > surface->width || point->y > surface->height ||
        cache->width > surface->width - point->x || cache->height > surface->height - point->y)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.cache.copy",
                          "cache_slot=%u surface_id=%u dst_x=%u dst_y=%u width=%u height=%u cache_key=%llu frame_id=%u cache_hash=%016llx",
                          cache->cache_slot,
                          surface->surface_id,
                          point->x,
                          point->y,
                          cache->width,
                          cache->height,
                          (unsigned long long)cache->cache_key,
                          session->graphics_current_frame_id,
                          (unsigned long long)rdp_session_trace_hash_bgra(cache->pixels.data,
                                                                          cache->width,
                                                                          cache->height,
                                                                          (size_t)cache->width * 4u));
    status = rdp_session_graphics_surface_write_bgra(session,
                                                     surface,
                                                     point->x,
                                                     point->y,
                                                     cache->width,
                                                     cache->height,
                                                     cache->pixels.data,
                                                     (size_t)cache->width * 4u,
                                                     0,
                                                     "cache_to_surface");
    return status;
}

static librdp_status rdp_session_read_mcs_pdu(librdp_session* session,
                                              rdp_buffer* packet,
                                              const uint8_t** pdu,
                                              size_t* pdu_len,
                                              const char* event);

static librdp_status rdp_session_send_display_control_layout(librdp_session* session,
                                                             uint32_t width,
                                                             uint32_t height)
{
    rdp_display_control_monitor monitor;
    rdp_buffer layout;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!session->display_control_ready || session->display_control_channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    if (session->sent_desktop_width == width && session->sent_desktop_height == height)
        return LIBRDP_STATUS_OK;

    rdp_buffer_init(&layout);
    status = rdp_display_control_make_single_monitor(&monitor, width, height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_display_control_write_monitor_layout_with_caps(&layout,
                                                                    &monitor,
                                                                    1,
                                                                    &session->display_control_caps);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->display_control_channel_id,
                                                       session->display_control_channel_id_bytes,
                                                       layout.data,
                                                       layout.length,
                                                       "client.display_control.layout_sent");
    rdp_buffer_free(&layout);
    if (status == LIBRDP_STATUS_OK)
    {
        session->sent_desktop_width = width;
        session->sent_desktop_height = height;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.display_control.layout_sent",
                        "dvc_channel_id=%u width=%u height=%u",
                        session->display_control_channel_id,
                        width,
                        height);
    }
    return status;
}

static librdp_status rdp_session_request_display_control_layout(librdp_session* session,
                                                                uint32_t width,
                                                                uint32_t height)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || width == 0 || height == 0 || width > 8192u || height > 8192u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    session->requested_desktop_width = width;
    session->requested_desktop_height = height;
    status = rdp_session_send_display_control_layout(session, width, height);
    if (status == LIBRDP_STATUS_STATE)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.display_control.layout.local",
                        "width=%u height=%u wire=not_sent",
                        width,
                        height);
        return LIBRDP_STATUS_OK;
    }
    return status;
}

static librdp_status rdp_session_send_core_input_init(librdp_session* session)
{
    rdp_buffer request;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->core_input_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&request);
    status = rdp_core_input_write_init_request(&request);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->core_input_channel_id,
                                                       session->core_input_channel_id_bytes,
                                                       request.data,
                                                       request.length,
                                                       "client.core_input.init");
    rdp_buffer_free(&request);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.core_input.init",
                        "dvc_channel_id=%u version=%u",
                        session->core_input_channel_id,
                        RDP_CORE_INPUT_PROTOCOL_VERSION_100);
    return status;
}

static librdp_status rdp_session_send_input_channel_ready(librdp_session* session,
                                                          const rdp_input_channel_sc_ready* ready)
{
    rdp_buffer response;
    uint32_t flags = 0;
    uint32_t protocol_version = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !ready || session->input_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    protocol_version = ready->protocol_version;
    if (protocol_version >= RDP_INPUT_CHANNEL_PROTOCOL_V101)
        flags |= RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION;
    if (protocol_version >= RDP_INPUT_CHANNEL_PROTOCOL_V200 &&
        (ready->supported_features & RDP_INPUT_CHANNEL_SC_READY_MULTIPEN) != 0)
        flags |= RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN;

    rdp_buffer_init(&response);
    status = rdp_input_channel_write_cs_ready(&response, flags, protocol_version, 10);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->input_channel_id,
                                                       session->input_channel_id_bytes,
                                                       response.data,
                                                       response.length,
                                                       "client.input_channel.ready");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.input_channel.ready",
                        "dvc_channel_id=%u protocol_version=%u flags=%u max_contacts=%u",
                        session->input_channel_id,
                        protocol_version,
                        flags,
                        10u);
    return status;
}

static librdp_status rdp_session_send_mouse_cursor_caps(librdp_session* session)
{
    rdp_buffer caps;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->mouse_cursor_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&caps);
    status = rdp_mouse_cursor_write_caps_advertise(&caps);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->mouse_cursor_channel_id,
                                                       session->mouse_cursor_channel_id_bytes,
                                                       caps.data,
                                                       caps.length,
                                                       "client.mouse_cursor.caps_advertise");
    rdp_buffer_free(&caps);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.mouse_cursor.caps_advertise",
                        "dvc_channel_id=%u version=%u",
                        session->mouse_cursor_channel_id,
                        RDP_MOUSE_CURSOR_CAPSET_VERSION1);
    return status;
}

static librdp_status rdp_session_send_graphics_caps(librdp_session* session)
{
    rdp_buffer caps;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->graphics_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&caps);
    status = rdp_graphics_write_default_caps_advertise(&caps);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->graphics_channel_id,
                                                       session->graphics_channel_id_bytes,
                                                       caps.data,
                                                       caps.length,
                                                       "client.graphics.caps_advertise");
    rdp_buffer_free(&caps);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.caps_advertise",
                        "dvc_channel_id=%u",
                        session->graphics_channel_id);
    return status;
}

static librdp_status rdp_session_send_graphics_frame_ack(librdp_session* session, uint32_t frame_id)
{
    rdp_buffer ack;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->graphics_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&ack);
    status = rdp_graphics_write_frame_ack(&ack,
                                          RDP_GRAPHICS_QUEUE_DEPTH_UNAVAILABLE,
                                          frame_id,
                                          session->graphics_frames_decoded);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->graphics_channel_id,
                                                       session->graphics_channel_id_bytes,
                                                       ack.data,
                                                       ack.length,
                                                       "client.graphics.frame_ack");
    rdp_buffer_free(&ack);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.frame_ack",
                        "dvc_channel_id=%u frame_id=%u total_frames_decoded=%u",
                        session->graphics_channel_id,
                        frame_id,
                        session->graphics_frames_decoded);
    return status;
}

static librdp_status rdp_session_handle_graphics_message(librdp_session* session,
                                                         uint32_t channel_id,
                                                         const uint8_t* data,
                                                         size_t data_len)
{
    rdp_buffer decoded;
    size_t offset = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&decoded);
    status = rdp_graphics_decode_segmented_data(&session->graphics_decompressor, data, data_len, &decoded);
    if (status == LIBRDP_STATUS_UNSUPPORTED)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.unsupported",
                        "dvc_channel_id=%u reason=bulk_compression payload_len=%u",
                        channel_id,
                        (unsigned)data_len);
        rdp_buffer_free(&decoded);
        return LIBRDP_STATUS_OK;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&decoded);
        return status;
    }

    while (offset < decoded.length)
    {
        rdp_graphics_header header;
        const uint8_t* pdu = decoded.data + offset;
        size_t remaining = decoded.length - offset;

        status = rdp_graphics_parse_header(pdu, remaining, &header);
        if (status != LIBRDP_STATUS_OK)
            break;
        rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                              RDP_TRACE_LEVEL_DEBUG,
                              "rdp.graphics.pdu",
                              "dvc_channel_id=%u cmd_id=%u pdu_len=%u",
                              channel_id,
                              header.cmd_id,
                              header.pdu_length);
        rdp_trace_hexdump("rdp.graphics.pdu", pdu, header.pdu_length);
        if (header.cmd_id == RDP_GRAPHICS_CMDID_CAPS_CONFIRM)
        {
            rdp_graphics_caps_confirm confirm;

            status = rdp_graphics_parse_caps_confirm(pdu, header.pdu_length, &confirm);
            if (status != LIBRDP_STATUS_OK)
                break;
            session->graphics_selected_version = confirm.selected.version;
            session->graphics_selected_flags = confirm.selected.flags;
            session->graphics_ready = 1;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.caps_confirm",
                            "dvc_channel_id=%u version=%u flags=%u",
                            channel_id,
                            confirm.selected.version,
                            confirm.selected.flags);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_WIRE_TO_SURFACE_1)
        {
            rdp_graphics_wire_to_surface_1 wire;

            status = rdp_graphics_parse_wire_to_surface_1(pdu, header.pdu_length, &wire);
            if (status != LIBRDP_STATUS_OK)
                break;
            if (wire.codec_id == RDP_GRAPHICS_CODECID_UNCOMPRESSED ||
                wire.codec_id == RDP_GRAPHICS_CODECID_CLEARCODEC ||
                wire.codec_id == RDP_GRAPHICS_CODECID_PLANAR ||
                wire.codec_id == RDP_GRAPHICS_CODECID_AVC420 ||
                wire.codec_id == RDP_GRAPHICS_CODECID_AVC444 ||
                wire.codec_id == RDP_GRAPHICS_CODECID_AVC444V2)
            {
                rdp_session_graphics_surface* surface = rdp_session_graphics_surface_find(session, wire.surface_id);
                int rendered = 0;

                if (!surface)
                {
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    break;
                }
                if (wire.codec_id == RDP_GRAPHICS_CODECID_UNCOMPRESSED)
                {
                    status = rdp_session_graphics_surface_write_wire(session, surface, &wire);
                    if (status != LIBRDP_STATUS_OK)
                        break;
                    rendered = 1;
                }
                else if (wire.codec_id == RDP_GRAPHICS_CODECID_CLEARCODEC ||
                         wire.codec_id == RDP_GRAPHICS_CODECID_PLANAR)
                {
                    rdp_buffer decoded_bitmap;
                    size_t decoded_stride = 0;
                    uint16_t width = (uint16_t)(wire.dest_rect.right - wire.dest_rect.left);
                    uint16_t height = (uint16_t)(wire.dest_rect.bottom - wire.dest_rect.top);

                    rdp_buffer_init(&decoded_bitmap);
                    if (wire.codec_id == RDP_GRAPHICS_CODECID_CLEARCODEC)
                    {
                        status = rdp_clearcodec_decode_bitmap(&session->clearcodec,
                                                              wire.bitmap_data,
                                                              wire.bitmap_data_length,
                                                              width,
                                                              height,
                                                              &decoded_bitmap,
                                                              &decoded_stride);
                    }
                    else
                    {
                        status = rdp_planar_decode_argb(wire.bitmap_data,
                                                        wire.bitmap_data_length,
                                                        width,
                                                        height,
                                                        &decoded_bitmap,
                                                        &decoded_stride);
                    }
                    if (status == LIBRDP_STATUS_OK)
                        status = rdp_session_graphics_surface_write_bgra(session,
                                                                         surface,
                                                                         wire.dest_rect.left,
                                                                         wire.dest_rect.top,
                                                                         width,
                                                                         height,
                                                                         decoded_bitmap.data,
                                                                         decoded_stride,
                                                                         wire.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                                                         wire.codec_id == RDP_GRAPHICS_CODECID_CLEARCODEC ? "clearcodec" : "planar");
                    rdp_buffer_free(&decoded_bitmap);
                    if (status == LIBRDP_STATUS_UNSUPPORTED || status == LIBRDP_STATUS_PROTOCOL_ERROR)
                    {
                        rdp_trace_event(RDP_TRACE_CLIENT,
                                        "client.graphics.codec.unsupported",
                                        "dvc_channel_id=%u surface_id=%u codec_id=%u payload_len=%u decoder_status=%d",
                                        channel_id,
                                        wire.surface_id,
                                        wire.codec_id,
                                        wire.bitmap_data_length,
                                        (int)status);
                        status = LIBRDP_STATUS_OK;
                    }
                    if (status != LIBRDP_STATUS_OK)
                        break;
                    if (decoded_stride != 0)
                        rendered = 1;
                }
                else
                {
                    rdp_avc_frame avc_frame;
                    int avc_rendered = 0;
                    const char* source = wire.codec_id == RDP_GRAPHICS_CODECID_AVC420 ? "avc420" :
                                         wire.codec_id == RDP_GRAPHICS_CODECID_AVC444 ? "avc444" :
                                                                                        "avc444v2";

                    rdp_avc_frame_init(&avc_frame);
                    if (wire.codec_id == RDP_GRAPHICS_CODECID_AVC420)
                    {
                        rdp_graphics_avc420_stream avc420;

                        status = rdp_graphics_parse_avc420_stream(wire.bitmap_data,
                                                                  wire.bitmap_data_length,
                                                                  &avc420);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_avc_decode_420(session->avc,
                                                        &avc420,
                                                        surface->width,
                                                        surface->height,
                                                        &avc_frame);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_session_graphics_surface_write_avc_regions(
                                session,
                                surface,
                                &avc420.meta,
                                &avc_frame,
                                wire.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                source);
                        if (status == LIBRDP_STATUS_OK)
                            avc_rendered = 1;
                    }
                    else
                    {
                        rdp_graphics_avc444_stream avc444;

                        status = rdp_graphics_parse_avc444_stream(wire.bitmap_data,
                                                                  wire.bitmap_data_length,
                                                                  &avc444);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_avc_decode_444(session->avc,
                                                        wire.codec_id,
                                                        &avc444,
                                                        surface->width,
                                                        surface->height,
                                                        &avc_frame);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_session_graphics_surface_write_avc_regions(
                                session,
                                surface,
                                &avc444.stream1.meta,
                                &avc_frame,
                                wire.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                source);
                        if (status == LIBRDP_STATUS_OK)
                            avc_rendered = 1;
                    }
                    if (status == LIBRDP_STATUS_UNSUPPORTED || status == LIBRDP_STATUS_PROTOCOL_ERROR)
                    {
                        rdp_trace_event(RDP_TRACE_CLIENT,
                                        "client.graphics.codec.unsupported",
                                        "dvc_channel_id=%u surface_id=%u codec_id=%u payload_len=%u decoder_status=%d",
                                        channel_id,
                                        wire.surface_id,
                                        wire.codec_id,
                                        wire.bitmap_data_length,
                                        (int)status);
                        status = LIBRDP_STATUS_OK;
                    }
                    if (status == LIBRDP_STATUS_OK && avc_rendered)
                        rendered = 1;
                    rdp_avc_frame_free(&avc_frame);
                    if (status != LIBRDP_STATUS_OK)
                        break;
                }
                if (rendered)
                    rdp_trace_event_level(RDP_TRACE_CLIENT,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "client.graphics.wire_to_surface",
                                          "dvc_channel_id=%u surface_id=%u codec_id=%u x=%u y=%u width=%u height=%u",
                                          channel_id,
                                          wire.surface_id,
                                          wire.codec_id,
                                          wire.dest_rect.left,
                                          wire.dest_rect.top,
                                          (unsigned)(wire.dest_rect.right - wire.dest_rect.left),
                                          (unsigned)(wire.dest_rect.bottom - wire.dest_rect.top));
            }
            else
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.graphics.wire_to_surface.unsupported",
                                "dvc_channel_id=%u surface_id=%u codec_id=%u payload_len=%u",
                                channel_id,
                                wire.surface_id,
                                wire.codec_id,
                                wire.bitmap_data_length);
            }
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_WIRE_TO_SURFACE_2)
        {
            rdp_graphics_wire_to_surface_2 wire;

            status = rdp_graphics_parse_wire_to_surface_2(pdu, header.pdu_length, &wire);
            if (status != LIBRDP_STATUS_OK)
                break;
            if (wire.codec_id == RDP_GRAPHICS_CODECID_CAPROGRESSIVE)
            {
                rdp_session_graphics_surface* surface = rdp_session_graphics_surface_find(session, wire.surface_id);
                rdp_graphics_progressive_stream progressive;
                uint32_t rendered_tiles = 0;
                uint32_t failed_tiles = 0;
                uint32_t unsupported_tiles = 0;

                if (!surface)
                {
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    break;
                }
                status = rdp_graphics_progressive_parse_stream(wire.bitmap_data,
                                                               wire.bitmap_data_length,
                                                               &progressive);
                if (status == LIBRDP_STATUS_OK)
                {
                    status = rdp_session_graphics_progressive_render_stream(session,
                                                                           channel_id,
                                                                           surface,
                                                                           &wire,
                                                                           &rendered_tiles,
                                                                           &failed_tiles,
                                                                           &unsupported_tiles);
                    if (status != LIBRDP_STATUS_OK)
                        break;
                    rdp_trace_event_level(RDP_TRACE_CLIENT,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "client.graphics.progressive",
                                          "dvc_channel_id=%u surface_id=%u context_id=%u blocks=%u regions=%u tiles=%u simple_tiles=%u first_tiles=%u upgrade_tiles=%u rendered_tiles=%u failed_tiles=%u unsupported_tiles=%u",
                                          channel_id,
                                          wire.surface_id,
                                          wire.codec_context_id,
                                          progressive.block_count,
                                          progressive.region_count,
                                          progressive.tile_count,
                                          progressive.simple_tile_count,
                                          progressive.first_tile_count,
                                          progressive.upgrade_tile_count,
                                          rendered_tiles,
                                          failed_tiles,
                                          unsupported_tiles);
                }
                else
                {
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.graphics.progressive.unsupported",
                                    "dvc_channel_id=%u surface_id=%u context_id=%u payload_len=%u parser_status=%d",
                                    channel_id,
                                    wire.surface_id,
                                    wire.codec_context_id,
                                    wire.bitmap_data_length,
                                    (int)status);
                    status = LIBRDP_STATUS_OK;
                }
            }
            else
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.graphics.wire_to_surface.unsupported",
                                "dvc_channel_id=%u surface_id=%u codec_id=%u context_id=%u payload_len=%u",
                                channel_id,
                                wire.surface_id,
                                wire.codec_id,
                                wire.codec_context_id,
                                wire.bitmap_data_length);
            }
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_DELETE_ENCODING_CONTEXT)
        {
            rdp_graphics_delete_encoding_context context;

            status = rdp_graphics_parse_delete_encoding_context(pdu, header.pdu_length, &context);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.encoding_context.delete",
                            "dvc_channel_id=%u surface_id=%u context_id=%u",
                            channel_id,
                            context.surface_id,
                            context.codec_context_id);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_SURFACE_TO_SURFACE)
        {
            rdp_graphics_surface_to_surface surface_to_surface;
            rdp_session_graphics_surface* source = NULL;
            rdp_session_graphics_surface* dest = NULL;
            rdp_graphics_point16 last_point;
            uint16_t i = 0;

            memset(&last_point, 0, sizeof(last_point));
            status = rdp_graphics_parse_surface_to_surface(pdu, header.pdu_length, &surface_to_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            source = rdp_session_graphics_surface_find(session, surface_to_surface.surface_id_src);
            dest = rdp_session_graphics_surface_find(session, surface_to_surface.surface_id_dest);
            if (!source || !dest)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            for (i = 0; i < surface_to_surface.dest_points_count; i++)
            {
                rdp_graphics_point16 point;

                status = rdp_graphics_parse_point16(surface_to_surface.dest_points + ((size_t)i * 4u),
                                                    surface_to_surface.dest_points_len - ((size_t)i * 4u),
                                                    &point);
                if (status == LIBRDP_STATUS_OK)
                {
                    status = rdp_session_graphics_surface_copy(session,
                                                               source,
                                                               dest,
                                                               &surface_to_surface.rect_src,
                                                               &point);
                    if (status == LIBRDP_STATUS_OK)
                        last_point = point;
                }
                if (status != LIBRDP_STATUS_OK)
                    break;
            }
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.graphics.surface_to_surface",
                                  "dvc_channel_id=%u source_id=%u dest_id=%u points=%u src_left=%u src_top=%u src_right=%u src_bottom=%u last_dst_x=%u last_dst_y=%u",
                                  channel_id,
                                  surface_to_surface.surface_id_src,
                                  surface_to_surface.surface_id_dest,
                                  surface_to_surface.dest_points_count,
                                  surface_to_surface.rect_src.left,
                                  surface_to_surface.rect_src.top,
                                  surface_to_surface.rect_src.right,
                                  surface_to_surface.rect_src.bottom,
                                  last_point.x,
                                  last_point.y);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_SURFACE_TO_CACHE)
        {
            rdp_graphics_surface_to_cache surface_to_cache;

            status = rdp_graphics_parse_surface_to_cache(pdu, header.pdu_length, &surface_to_cache);
            if (status != LIBRDP_STATUS_OK)
                break;
            status = rdp_session_graphics_cache_store(session, &surface_to_cache);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.graphics.surface_to_cache",
                                  "dvc_channel_id=%u surface_id=%u cache_slot=%u width=%u height=%u src_left=%u src_top=%u src_right=%u src_bottom=%u",
                                  channel_id,
                                  surface_to_cache.surface_id,
                                  surface_to_cache.cache_slot,
                                  (unsigned)(surface_to_cache.rect_src.right - surface_to_cache.rect_src.left),
                                  (unsigned)(surface_to_cache.rect_src.bottom - surface_to_cache.rect_src.top),
                                  surface_to_cache.rect_src.left,
                                  surface_to_cache.rect_src.top,
                                  surface_to_cache.rect_src.right,
                                  surface_to_cache.rect_src.bottom);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_CACHE_TO_SURFACE)
        {
            rdp_graphics_cache_to_surface cache_to_surface;
            rdp_session_graphics_cache_entry* cache = NULL;
            rdp_session_graphics_surface* surface = NULL;
            rdp_graphics_point16 last_point;
            uint16_t i = 0;

            memset(&last_point, 0, sizeof(last_point));
            status = rdp_graphics_parse_cache_to_surface(pdu, header.pdu_length, &cache_to_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            cache = rdp_session_graphics_cache_find(session, cache_to_surface.cache_slot);
            surface = rdp_session_graphics_surface_find(session, cache_to_surface.surface_id);
            if (!cache || !surface)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            for (i = 0; i < cache_to_surface.dest_points_count; i++)
            {
                rdp_graphics_point16 point;

                status = rdp_graphics_parse_point16(cache_to_surface.dest_points + ((size_t)i * 4u),
                                                    cache_to_surface.dest_points_len - ((size_t)i * 4u),
                                                    &point);
                if (status == LIBRDP_STATUS_OK)
                {
                    status = rdp_session_graphics_cache_copy_to_surface(session, cache, surface, &point);
                    if (status == LIBRDP_STATUS_OK)
                        last_point = point;
                }
                if (status != LIBRDP_STATUS_OK)
                    break;
            }
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.graphics.cache_to_surface",
                                  "dvc_channel_id=%u cache_slot=%u surface_id=%u points=%u cache_width=%u cache_height=%u last_dst_x=%u last_dst_y=%u",
                                  channel_id,
                                  cache_to_surface.cache_slot,
                                  cache_to_surface.surface_id,
                                  cache_to_surface.dest_points_count,
                                  cache->width,
                                  cache->height,
                                  last_point.x,
                                  last_point.y);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_EVICT_CACHE_ENTRY)
        {
            rdp_graphics_evict_cache_entry evict;

            status = rdp_graphics_parse_evict_cache_entry(pdu, header.pdu_length, &evict);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_session_graphics_cache_evict(session, evict.cache_slot);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.cache.evict",
                            "dvc_channel_id=%u cache_slot=%u",
                            channel_id,
                            evict.cache_slot);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_RESET_GRAPHICS)
        {
            rdp_graphics_reset reset;

            status = rdp_graphics_parse_reset(pdu, header.pdu_length, &reset);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_session_graphics_dirty_reset(session);
            rdp_session_graphics_surfaces_clear(session);
            if (reset.width != librdp_surface_width(session->surface) ||
                reset.height != librdp_surface_height(session->surface))
            {
                status = librdp_surface_resize(session->surface, reset.width, reset.height);
                if (status != LIBRDP_STATUS_OK)
                    break;
                rdp_session_emit_surface_invalidated(session, 0, 0, reset.width, reset.height);
            }
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.reset",
                            "dvc_channel_id=%u width=%u height=%u monitors=%u",
                            channel_id,
                            reset.width,
                            reset.height,
                            reset.monitor_count);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_CREATE_SURFACE)
        {
            rdp_graphics_create_surface create_surface;

            status = rdp_graphics_parse_create_surface(pdu, header.pdu_length, &create_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            status = rdp_session_graphics_surface_create(session, &create_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface.create",
                            "dvc_channel_id=%u surface_id=%u width=%u height=%u pixel_format=%u",
                            channel_id,
                            create_surface.surface_id,
                            create_surface.width,
                            create_surface.height,
                            create_surface.pixel_format);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_DELETE_SURFACE)
        {
            rdp_graphics_delete_surface delete_surface;

            status = rdp_graphics_parse_delete_surface(pdu, header.pdu_length, &delete_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_session_graphics_surface_delete(session, delete_surface.surface_id);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface.delete",
                            "dvc_channel_id=%u surface_id=%u",
                            channel_id,
                            delete_surface.surface_id);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_MAP_SURFACE_TO_OUTPUT)
        {
            rdp_graphics_map_surface_to_output map;

            status = rdp_graphics_parse_map_surface_to_output(pdu, header.pdu_length, &map);
            if (status != LIBRDP_STATUS_OK)
                break;
            status = rdp_session_graphics_surface_map(session, &map);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface.map_output",
                            "dvc_channel_id=%u surface_id=%u x=%u y=%u",
                            channel_id,
                            map.surface_id,
                            map.output_origin_x,
                            map.output_origin_y);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_MAP_SURFACE_TO_SCALED_OUTPUT)
        {
            rdp_graphics_map_surface_to_scaled_output map;

            status = rdp_graphics_parse_map_surface_to_scaled_output(pdu, header.pdu_length, &map);
            if (status != LIBRDP_STATUS_OK)
                break;
            status = rdp_session_graphics_surface_map_scaled(session, &map);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface.map_scaled_output",
                            "dvc_channel_id=%u surface_id=%u x=%u y=%u target_width=%u target_height=%u",
                            channel_id,
                            map.surface_id,
                            map.output_origin_x,
                            map.output_origin_y,
                            map.target_width,
                            map.target_height);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_SOLIDFILL)
        {
            rdp_graphics_solid_fill solid_fill;
            rdp_session_graphics_surface* surface = NULL;
            uint16_t i = 0;

            status = rdp_graphics_parse_solid_fill(pdu, header.pdu_length, &solid_fill);
            if (status != LIBRDP_STATUS_OK)
                break;
            surface = rdp_session_graphics_surface_find(session, solid_fill.surface_id);
            if (!surface)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            for (i = 0; i < solid_fill.rect_count; i++)
            {
                rdp_graphics_rect16 rect;

                status = rdp_graphics_parse_rect16(solid_fill.rects + ((size_t)i * 8u),
                                                   solid_fill.rects_len - ((size_t)i * 8u),
                                                   &rect);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_graphics_surface_fill(session, surface, &rect, solid_fill.fill_pixel);
                if (status != LIBRDP_STATUS_OK)
                    break;
            }
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.solid_fill",
                            "dvc_channel_id=%u surface_id=%u rects=%u",
                            channel_id,
                            solid_fill.surface_id,
                            solid_fill.rect_count);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_START_FRAME)
        {
            rdp_graphics_start_frame start_frame;

            status = rdp_graphics_parse_start_frame(pdu, header.pdu_length, &start_frame);
            if (status != LIBRDP_STATUS_OK)
                break;
            if (session->graphics_frame_active)
                rdp_session_graphics_dirty_flush(session);
            session->graphics_frame_active = 1;
            session->graphics_current_frame_id = start_frame.frame_id;
            session->graphics_dirty_pending = 0;
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.graphics.frame.start",
                                  "dvc_channel_id=%u frame_id=%u timestamp=%u",
                                  channel_id,
                                  start_frame.frame_id,
                                  start_frame.timestamp);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_END_FRAME)
        {
            rdp_graphics_end_frame end_frame;

            status = rdp_graphics_parse_end_frame(pdu, header.pdu_length, &end_frame);
            if (status != LIBRDP_STATUS_OK)
                break;
            session->graphics_frame_active = 0;
            rdp_session_graphics_dirty_flush(session);
            session->graphics_frames_decoded++;
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.graphics.frame.end",
                                  "dvc_channel_id=%u frame_id=%u total_frames_decoded=%u",
                                  channel_id,
                                  end_frame.frame_id,
                                  session->graphics_frames_decoded);
            status = rdp_session_send_graphics_frame_ack(session, end_frame.frame_id);
            if (status != LIBRDP_STATUS_OK)
                break;
        }
        offset += header.pdu_length;
    }

    rdp_buffer_free(&decoded);
    return status;
}

static librdp_status rdp_session_join_mcs_channel(librdp_session* session,
                                                  uint16_t channel_id,
                                                  const char* name,
                                                  rdp_buffer* request,
                                                  rdp_buffer* reply)
{
    const uint8_t* pdu = NULL;
    size_t pdu_len = 0;
    rdp_mcs_channel_join_confirm confirm;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request || !reply)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_free(request);
    rdp_buffer_init(request);
    status = rdp_mcs_write_channel_join_request(request, session->mcs_user_id, channel_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "mcs.channel_join.request",
                    "channel_id=%u name=%s",
                    channel_id,
                    name ? name : "");
    status = rdp_session_write_mcs_pdu(session, request, "mcs.channel_join.request", 1);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_buffer_free(reply);
    rdp_buffer_init(reply);
    status = rdp_session_read_mcs_pdu(session, reply, &pdu, &pdu_len, "mcs.channel_join.confirm");
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_mcs_parse_channel_join_confirm(pdu, pdu_len, &confirm);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (confirm.result != 0 || confirm.initiator != session->mcs_user_id || confirm.channel_id != channel_id)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "mcs.channel_join.failed",
                        "result=%u initiator=%u channel_id=%u",
                        confirm.result,
                        confirm.initiator,
                        confirm.channel_id);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "mcs.channel_join.confirm",
                    "channel_id=%u name=%s",
                    confirm.channel_id,
                    name ? name : "");
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_send_activation_finalization(librdp_session* session, uint32_t share_id)
{
    rdp_buffer sync;
    rdp_buffer cooperate;
    rdp_buffer request;
    rdp_buffer persistent_keys;
    rdp_buffer font_list;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&sync);
    rdp_buffer_init(&cooperate);
    rdp_buffer_init(&request);
    rdp_buffer_init(&persistent_keys);
    rdp_buffer_init(&font_list);

    status = rdp_slowpath_write_client_synchronize(&sync, share_id, session->mcs_user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &sync, "rdp.activation.client_synchronize");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_synchronize", "share_id=%u", share_id);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_client_control(&cooperate, share_id, session->mcs_user_id, 4);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &cooperate, "rdp.activation.client_control_cooperate");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_control_cooperate", "share_id=%u", share_id);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_client_control(&request, share_id, session->mcs_user_id, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &request, "rdp.activation.client_control_request");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_control_request", "share_id=%u", share_id);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_client_persistent_key_list(&persistent_keys, share_id, session->mcs_user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &persistent_keys, "rdp.activation.client_persistent_key_list");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_persistent_key_list", "share_id=%u entries=0", share_id);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_client_font_list(&font_list, share_id, session->mcs_user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &font_list, "rdp.activation.client_font_list");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_font_list", "share_id=%u", share_id);

    rdp_buffer_free(&font_list);
    rdp_buffer_free(&persistent_keys);
    rdp_buffer_free(&request);
    rdp_buffer_free(&cooperate);
    rdp_buffer_free(&sync);
    return status;
}

static librdp_status rdp_session_send_active_output_request(librdp_session* session)
{
    rdp_buffer suppress;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t width = 0;
    uint32_t height = 0;

    if (!session || !session->surface || session->share_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    width = librdp_surface_width(session->surface);
    height = librdp_surface_height(session->surface);
    if (width == 0 || height == 0 || width > 0xffffu || height > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&suppress);
    status = rdp_slowpath_write_client_suppress_output(&suppress,
                                                       session->share_id,
                                                       session->mcs_user_id,
                                                       1,
                                                       0,
                                                       0,
                                                       (uint16_t)width,
                                                       (uint16_t)height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &suppress, "rdp.activation.client_suppress_output");
    rdp_buffer_free(&suppress);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "rdp.activation.client_suppress_output",
                    "share_id=%u width=%u height=%u",
                    session->share_id,
                    width,
                    height);
    return librdp_session_refresh(session, 0, 0, width, height);
}

static librdp_status rdp_session_trace_slowpath_data_pdu(librdp_session* session, const rdp_slowpath_data_pdu* data_pdu)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data_pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (data_pdu->pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_MAP)
    {
        rdp_slowpath_font_map font_map;

        status = rdp_slowpath_parse_font_map(data_pdu->payload, data_pdu->payload_len, &font_map);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.activation.font_map",
                            "entries=%u total_entries=%u flags=%u entry_size=%u",
                            font_map.number_entries,
                            font_map.total_entries,
                            font_map.map_flags,
                            font_map.entry_size);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_active_output_request(session);
    }
    else if (data_pdu->pdu_type2 == RDP_SLOWPATH_DATA_PDU_SET_ERROR_INFO)
    {
        uint32_t error_info = 0;

        status = rdp_slowpath_parse_set_error_info(data_pdu->payload, data_pdu->payload_len, &error_info);
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.set_error_info", "error_info=%u", error_info);
            if (error_info != 0)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
    }
    else if (data_pdu->pdu_type2 == RDP_SLOWPATH_DATA_PDU_SAVE_SESSION_INFO)
    {
        rdp_slowpath_save_session_info info;

        status = rdp_slowpath_parse_save_session_info(data_pdu->payload, data_pdu->payload_len, &info);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.save_session_info",
                            "info_type=%u data_len=%u",
                            info.info_type,
                            (unsigned)info.data_len);
    }

    return status;
}

static librdp_status rdp_session_handle_mouse_cursor_message(librdp_session* session,
                                                             uint32_t channel_id,
                                                             const uint8_t* data,
                                                             size_t data_len)
{
    rdp_mouse_cursor_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_mouse_cursor_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (header.pdu_type == RDP_MOUSE_CURSOR_PDU_SC_CAPS_CONFIRM)
    {
        rdp_mouse_cursor_capset capset;

        status = rdp_mouse_cursor_parse_caps_confirm(data, data_len, &capset);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->mouse_cursor_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.mouse_cursor.caps_confirm",
                        "dvc_channel_id=%u version=%u size=%u",
                        channel_id,
                        capset.version,
                        capset.size);
        return LIBRDP_STATUS_OK;
    }

    if (header.pdu_type == RDP_MOUSE_CURSOR_PDU_SC_MOUSEPTR_UPDATE)
    {
        rdp_pointer_update update;

        status = rdp_mouse_cursor_parse_update(data, data_len, &update);
        if (status == LIBRDP_STATUS_UNSUPPORTED)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.mouse_cursor.update.unsupported",
                            "dvc_channel_id=%u update_type=%u payload_len=%u",
                            channel_id,
                            header.update_type,
                            (unsigned)data_len);
            return LIBRDP_STATUS_OK;
        }
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.mouse_cursor.update",
                        "dvc_channel_id=%u update_type=%u kind=%u cache_index=%u width=%u height=%u",
                        channel_id,
                        header.update_type,
                        update.kind,
                        update.cache_index,
                        update.width,
                        update.height);
        status = rdp_session_pointer_apply_update(session, &update);
        if (status == LIBRDP_STATUS_UNSUPPORTED)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.mouse_cursor.shape.unsupported",
                            "dvc_channel_id=%u update_type=%u xor_bpp=%u width=%u height=%u",
                            channel_id,
                            header.update_type,
                            update.xor_bpp,
                            update.width,
                            update.height);
            return LIBRDP_STATUS_OK;
        }
        return status;
    }

    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.mouse_cursor.pdu.unsupported",
                    "dvc_channel_id=%u pdu_type=%u update_type=%u payload_len=%u",
                    channel_id,
                    header.pdu_type,
                    header.update_type,
                    (unsigned)data_len);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_handle_clipboard_message(librdp_session* session,
                                                          const uint8_t* data,
                                                          size_t data_len)
{
    rdp_clipboard_packet packet;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_clipboard_parse_packet(data, data_len, &packet);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.clipboard.pdu",
                          "channel_id=%u type=%u flags=%u payload_len=%u",
                          session->clipboard_channel_id,
                          packet.type,
                          packet.flags,
                          (unsigned)packet.payload_len);

    rdp_buffer_init(&response);
    if (packet.type == RDP_CLIPBOARD_CB_CLIP_CAPS)
    {
        rdp_clipboard_capabilities caps;

        status = rdp_clipboard_parse_capabilities(&packet, &caps);
        if (status == LIBRDP_STATUS_OK)
        {
            session->clipboard_general_flags = caps.has_general ? caps.general.general_flags : 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.clipboard.capabilities.server",
                            "channel_id=%u has_general=%u flags=%u",
                            session->clipboard_channel_id,
                            caps.has_general ? 1u : 0u,
                            session->clipboard_general_flags);
            status = rdp_session_send_clipboard_handshake(session);
        }
    }
    else if (packet.type == RDP_CLIPBOARD_CB_MONITOR_READY)
    {
        status = rdp_session_send_clipboard_handshake(session);
    }
    else if (packet.type == RDP_CLIPBOARD_CB_FORMAT_LIST)
    {
        rdp_clipboard_format_list list;
        librdp_clipboard_format formats[RDP_SESSION_CLIPBOARD_MAX_FORMATS];
        librdp_event event;
        uint32_t count = 0;
        uint32_t stored = 0;
        uint32_t i = 0;
        int long_names = (packet.flags & RDP_CLIPBOARD_CB_ASCII_NAMES) == 0;

        memset(formats, 0, sizeof(formats));
        status = rdp_clipboard_parse_format_list(&packet, &list);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_clipboard_format_list_entry_count(&list, long_names, &count);
        if (status == LIBRDP_STATUS_OK)
        {
            session->clipboard_remote_format_count = 0;
            for (i = 0; i < count && i < RDP_SESSION_CLIPBOARD_MAX_FORMATS; i++)
            {
                rdp_clipboard_format_entry item;

                status = rdp_clipboard_format_list_get_entry(&list, long_names, i, &item);
                if (status != LIBRDP_STATUS_OK)
                    break;
                formats[i].format_id = item.format_id;
                formats[i].name = item.name;
                formats[i].name_len = item.name_len;
                session->clipboard_remote_formats[i] = item.format_id;
                stored++;
            }
        }
        if (status == LIBRDP_STATUS_OK)
        {
            session->clipboard_remote_format_count = stored;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.clipboard.format_list",
                            "channel_id=%u count=%u stored=%u long_names=%u",
                            session->clipboard_channel_id,
                            count,
                            stored,
                            long_names ? 1u : 0u);
            status = rdp_clipboard_write_format_list_response(&response, 1);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_clipboard_packet(session, &response, "client.clipboard.format_list_response");
        if (status == LIBRDP_STATUS_OK)
        {
            memset(&event, 0, sizeof(event));
            event.type = LIBRDP_EVENT_CLIPBOARD_FORMATS;
            event.data.clipboard_formats.formats = formats;
            event.data.clipboard_formats.count = stored;
            event.data.clipboard_formats.total_count = count;
            rdp_session_emit(session, &event);
        }
    }
    else if (packet.type == RDP_CLIPBOARD_CB_FORMAT_DATA_REQUEST)
    {
        rdp_clipboard_format_data_request request;
        librdp_event event;

        status = rdp_clipboard_parse_format_data_request(&packet, &request);
        if (status == LIBRDP_STATUS_OK)
        {
            memset(&event, 0, sizeof(event));
            event.type = LIBRDP_EVENT_CLIPBOARD_REQUEST;
            event.data.clipboard_request.format_id = request.format_id;
            rdp_session_emit(session, &event);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.clipboard.format_data_request",
                            "channel_id=%u format_id=%u available=%u data_len=%u",
                            session->clipboard_channel_id,
                            request.format_id,
                            session->clipboard_local_available &&
                                session->clipboard_local_format_id == request.format_id ? 1u : 0u,
                            session->clipboard_local_available &&
                                session->clipboard_local_format_id == request.format_id ?
                                (unsigned)session->clipboard_local_data.length :
                                0u);
            if (session->clipboard_local_available && session->clipboard_local_format_id == request.format_id)
                status = rdp_clipboard_write_format_data_response(&response,
                                                                  1,
                                                                  session->clipboard_local_data.data,
                                                                  session->clipboard_local_data.length);
            else
                status = rdp_clipboard_write_format_data_response(&response, 0, NULL, 0);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_clipboard_packet(session, &response, "client.clipboard.format_data_response");
    }
    else if (packet.type == RDP_CLIPBOARD_CB_FORMAT_DATA_RESPONSE)
    {
        rdp_clipboard_format_data_response data_response;
        librdp_event event;

        status = rdp_clipboard_parse_format_data_response(&packet, &data_response);
        if (status == LIBRDP_STATUS_OK)
        {
            memset(&event, 0, sizeof(event));
            event.type = LIBRDP_EVENT_CLIPBOARD_DATA;
            event.data.clipboard_data.format_id = session->clipboard_pending_request_format_id;
            event.data.clipboard_data.data = data_response.data;
            event.data.clipboard_data.data_len = data_response.data_len;
            event.data.clipboard_data.ok =
                data_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_OK ? 1 : 0;
            rdp_session_emit(session, &event);
            session->clipboard_pending_request_format_id = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.clipboard.format_data_response",
                            "channel_id=%u ok=%u format_id=%u data_len=%u",
                            session->clipboard_channel_id,
                            data_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_OK ? 1u : 0u,
                            event.data.clipboard_data.format_id,
                            (unsigned)data_response.data_len);
        }
    }
    else if (packet.type == RDP_CLIPBOARD_CB_FILECONTENTS_REQUEST)
    {
        rdp_clipboard_file_contents_request request;

        status = rdp_clipboard_parse_file_contents_request(&packet, &request);
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.clipboard.filecontents_request",
                            "channel_id=%u stream_id=%u flags=%u requested=%u status=unavailable",
                            session->clipboard_channel_id,
                            request.stream_id,
                            request.flags,
                            request.requested);
            status = rdp_clipboard_write_file_contents_response(&response, 0, request.stream_id, NULL, 0);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_clipboard_packet(session, &response, "client.clipboard.filecontents_response");
    }
    else if (packet.type == RDP_CLIPBOARD_CB_FILECONTENTS_RESPONSE)
    {
        rdp_clipboard_file_contents_response file_response;

        status = rdp_clipboard_parse_file_contents_response(&packet, &file_response);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.clipboard.filecontents_response",
                            "channel_id=%u ok=%u stream_id=%u data_len=%u",
                            session->clipboard_channel_id,
                            file_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_OK ? 1u : 0u,
                            file_response.stream_id,
                            (unsigned)file_response.data_len);
    }
    else if (packet.type == RDP_CLIPBOARD_CB_LOCK_CLIPDATA)
    {
        rdp_clipboard_lock lock;

        status = rdp_clipboard_parse_lock(&packet, &lock);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.clipboard.lock",
                            "channel_id=%u clip_data_id=%u",
                            session->clipboard_channel_id,
                            lock.clip_data_id);
    }
    else if (packet.type == RDP_CLIPBOARD_CB_UNLOCK_CLIPDATA)
    {
        rdp_clipboard_lock lock;

        status = rdp_clipboard_parse_unlock(&packet, &lock);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.clipboard.unlock",
                            "channel_id=%u clip_data_id=%u",
                            session->clipboard_channel_id,
                            lock.clip_data_id);
    }
    else
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.clipboard.pdu.unsupported",
                        "channel_id=%u type=%u payload_len=%u",
                        session->clipboard_channel_id,
                        packet.type,
                        (unsigned)packet.payload_len);
    }

    rdp_buffer_free(&response);
    return status;
}

static int rdp_session_webauthn_mock_enabled(const librdp_session* session)
{
    const char* provider = NULL;

    if (!session || !session->settings ||
        !librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_WEBAUTHN))
        return 0;
    provider = librdp_settings_webauthn_provider(session->settings);
    return !provider || strcmp(provider, "mock") == 0 || strncmp(provider, "mock=", 5u) == 0;
}

static const char* rdp_session_webauthn_mock_path(const librdp_session* session)
{
    const char* provider = NULL;

    if (!session || !session->settings)
        return NULL;
    provider = librdp_settings_webauthn_provider(session->settings);
    if (!provider || strncmp(provider, "mock=", 5u) != 0)
        return NULL;
    return provider + 5u;
}

static librdp_status rdp_session_webauthn_load_mock_response(const char* path, rdp_buffer* response)
{
    FILE* file = NULL;
    uint8_t chunk[4096];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!path || !path[0] || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    file = fopen(path, "rb");
    if (!file)
        return LIBRDP_STATUS_STATE;
    while (!feof(file))
    {
        size_t count = fread(chunk, 1u, sizeof(chunk), file);

        if (count > 0)
        {
            if (response->length > RDP_WEBAUTHN_MAX_MESSAGE - count)
            {
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
                break;
            }
            status = rdp_buffer_append(response, chunk, count);
            if (status != LIBRDP_STATUS_OK)
                break;
        }
        if (ferror(file))
        {
            status = LIBRDP_STATUS_STATE;
            break;
        }
    }
    if (fclose(file) != 0 && status == LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_STATE;
    if (status == LIBRDP_STATUS_OK && response->length == 0)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    return status;
}

static librdp_status rdp_session_handle_webauthn_message(librdp_session* session,
                                                         uint32_t channel_id,
                                                         uint8_t channel_id_bytes,
                                                         const uint8_t* data,
                                                         size_t data_len)
{
    rdp_webauthn_request request;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t hresult = RDP_SESSION_HRESULT_OK;
    int mock_enabled = 0;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&request, 0, sizeof(request));
    rdp_buffer_init(&response);
    mock_enabled = rdp_session_webauthn_mock_enabled(session);
    status = rdp_webauthn_parse_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
    {
        status = rdp_webauthn_write_response(&response, RDP_SESSION_HRESULT_FAIL, NULL, 0);
        hresult = RDP_SESSION_HRESULT_FAIL;
    }
    else if (!librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_WEBAUTHN))
    {
        status = rdp_webauthn_write_response(&response, RDP_SESSION_HRESULT_NOTIMPL, NULL, 0);
        hresult = RDP_SESSION_HRESULT_NOTIMPL;
    }
    else if (request.command == RDP_WEBAUTHN_COMMAND_API_VERSION)
    {
        status = rdp_webauthn_write_u32_response(&response, RDP_SESSION_HRESULT_OK, 4u);
    }
    else if (request.command == RDP_WEBAUTHN_COMMAND_IUVPAA)
    {
        status = rdp_webauthn_write_u32_response(&response,
                                                 RDP_SESSION_HRESULT_OK,
                                                 mock_enabled ? 1u : 0u);
    }
    else if (request.command == RDP_WEBAUTHN_COMMAND_CANCEL ||
             request.command == RDP_WEBAUTHN_COMMAND_GET_CREDENTIALS ||
             request.command == RDP_WEBAUTHN_COMMAND_GET_AUTHENTICATOR_LIST)
    {
        status = rdp_webauthn_write_response(&response, RDP_SESSION_HRESULT_OK, NULL, 0);
    }
    else if (request.command == RDP_WEBAUTHN_COMMAND_WEB_AUTHN && mock_enabled)
    {
        const char* mock_path = rdp_session_webauthn_mock_path(session);
        rdp_buffer mock_response;

        rdp_buffer_init(&mock_response);
        if (mock_path)
            status = rdp_session_webauthn_load_mock_response(mock_path, &mock_response);
        if (status == LIBRDP_STATUS_OK && mock_response.length > 0)
            status = rdp_webauthn_write_authenticator_response(&response,
                                                               RDP_SESSION_HRESULT_OK,
                                                               mock_response.data[0],
                                                               mock_response.data + 1u,
                                                               mock_response.length - 1u);
        else if (status == LIBRDP_STATUS_OK)
            status = rdp_webauthn_write_authenticator_response(&response,
                                                               RDP_SESSION_HRESULT_OK,
                                                               RDP_SESSION_CTAP2_ERR_OPERATION_DENIED,
                                                               NULL,
                                                               0);
        else
        {
            status = rdp_webauthn_write_authenticator_response(&response,
                                                               RDP_SESSION_HRESULT_OK,
                                                               RDP_SESSION_CTAP2_ERR_OPERATION_DENIED,
                                                               NULL,
                                                               0);
        }
        hresult = RDP_SESSION_HRESULT_OK;
        rdp_buffer_free(&mock_response);
    }
    else
    {
        status = rdp_webauthn_write_response(&response, RDP_SESSION_HRESULT_NOTIMPL, NULL, 0);
        hresult = RDP_SESSION_HRESULT_NOTIMPL;
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       channel_id,
                                                       channel_id_bytes,
                                                       response.data,
                                                       response.length,
                                                       "client.webauthn.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.webauthn.pdu",
                    "dvc_channel_id=%u command=%u request_len=%u response_len=%u hresult=%u mock=%u status=%s",
                    channel_id,
                    status == LIBRDP_STATUS_OK ? request.command : 0u,
                    (unsigned)data_len,
                    (unsigned)response.length,
                    hresult,
                    mock_enabled ? 1u : 0u,
                    librdp_status_string(status));
    rdp_buffer_free(&response);
    return status;
}

static void rdp_session_usb_redirection_reset(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
#ifdef RDP_HAVE_LIBUSB
    for (i = 0; i < LIBRDP_SETTINGS_MAX_USB_DEVICES; i++)
    {
        if (session->usb_devices[i].handle)
            libusb_close(session->usb_devices[i].handle);
    }
    memset(session->usb_devices, 0, sizeof(session->usb_devices));
    if (session->usb_libusb)
    {
        libusb_exit(session->usb_libusb);
        session->usb_libusb = NULL;
    }
#else
    (void)i;
#endif
    session->usb_redirection_channel_id = 0;
    session->usb_redirection_channel_id_bytes = 0;
    session->usb_redirection_ready = 0;
    session->usb_request_completion_ready = 0;
    session->usb_message_id = 0;
    session->usb_request_completion_interface_id = 0;
    session->usb_device_count_sent = 0;
}

static uint32_t rdp_session_usb_next_message_id(librdp_session* session)
{
    if (!session)
        return 0;
    session->usb_message_id++;
    if (session->usb_message_id == 0)
        session->usb_message_id++;
    return session->usb_message_id;
}

static int rdp_session_usb_parse_pair(const char* text, uint32_t* first, uint32_t* second, int* decimal_only)
{
    char* end = NULL;
    unsigned long a = 0;
    unsigned long b = 0;
    const char* separator = NULL;
    const char* p = NULL;
    int has_hex_alpha = 0;

    if (!text || !first || !second || !decimal_only)
        return 0;
    separator = strchr(text, ':');
    if (!separator || separator == text || separator[1] == '\0')
        return 0;
    for (p = text; *p; p++)
    {
        if ((*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F') || *p == 'x' || *p == 'X')
            has_hex_alpha = 1;
    }
    a = strtoul(text, &end, has_hex_alpha ? 16 : 10);
    if (end != separator)
        return 0;
    b = strtoul(separator + 1, &end, has_hex_alpha ? 16 : 10);
    if (!end || *end != '\0' || a > 0xfffful || b > 0xfffful)
        return 0;
    *first = (uint32_t)a;
    *second = (uint32_t)b;
    *decimal_only = !has_hex_alpha;
    return 1;
}

static librdp_status rdp_session_usb_checked_format(char* out, size_t out_len, const char* fmt, unsigned a, unsigned b, unsigned c)
{
    int written = 0;

    if (!out || out_len == 0 || !fmt)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    written = snprintf(out, out_len, fmt, a, b, c);
    if (written <= 0 || (size_t)written >= out_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return LIBRDP_STATUS_OK;
}

static int rdp_session_usb_pair_is_bus_mode(const char* selector,
                                            uint32_t first,
                                            uint32_t second,
                                            int decimal_only)
{
    return selector && decimal_only && first <= 255u && second <= 255u && strlen(selector) <= 7u;
}

static librdp_status rdp_session_usb_multisz2(rdp_buffer* out, const char* first, const char* second);

#ifdef RDP_HAVE_LIBUSB
static librdp_status rdp_session_usb_libusb_find(librdp_session* session,
                                                 const char* selector,
                                                 uint32_t interface_id,
                                                 rdp_session_usb_device* out)
{
    libusb_device** list = NULL;
    ssize_t count = 0;
    ssize_t i = 0;
    uint32_t first = 0;
    uint32_t second = 0;
    int decimal_only = 0;
    int bus_mode = 0;
    librdp_status status = LIBRDP_STATUS_IO_ERROR;

    if (!session || !selector || !out)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!rdp_session_usb_parse_pair(selector, &first, &second, &decimal_only))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    bus_mode = rdp_session_usb_pair_is_bus_mode(selector, first, second, decimal_only);
    if (!session->usb_libusb && libusb_init(&session->usb_libusb) != 0)
        return LIBRDP_STATUS_IO_ERROR;
    count = libusb_get_device_list(session->usb_libusb, &list);
    if (count < 0)
        return LIBRDP_STATUS_IO_ERROR;
    for (i = 0; i < count; i++)
    {
        libusb_device* device = list[i];
        struct libusb_device_descriptor descriptor;
        int matched = 0;

        if (libusb_get_device_descriptor(device, &descriptor) != 0)
            continue;
        if (bus_mode)
        {
            matched = libusb_get_bus_number(device) == first &&
                      libusb_get_device_address(device) == second;
        }
        else
        {
            matched = descriptor.idVendor == first && descriptor.idProduct == second;
        }
        if (!matched)
            continue;
        out->active = 1;
        out->interface_id = interface_id;
        out->descriptor = descriptor;
        out->bus_number = libusb_get_bus_number(device);
        out->device_address = libusb_get_device_address(device);
        if (libusb_open(device, &out->handle) != 0)
            out->handle = NULL;
        status = LIBRDP_STATUS_OK;
        break;
    }
    libusb_free_device_list(list, 1);
    return status;
}

static librdp_status rdp_session_usb_build_descriptor_device_strings(
    const struct libusb_device_descriptor* descriptor,
    uint32_t index,
    rdp_buffer* instance,
    rdp_buffer* hardware,
    rdp_buffer* compatibility,
    rdp_buffer* container)
{
    char instance_text[96];
    char hardware_first[96];
    char hardware_second[96];
    char compatibility_first[96];
    char compatibility_second[96];
    char container_text[48];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!descriptor || !instance || !hardware || !compatibility || !container)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_usb_checked_format(instance_text,
                                            sizeof(instance_text),
                                            "USB\\VID_%04X&PID_%04X\\RDP_%02u",
                                            descriptor->idVendor,
                                            descriptor->idProduct,
                                            (unsigned)index + 1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_checked_format(hardware_first,
                                                sizeof(hardware_first),
                                                "USB\\VID_%04X&PID_%04X&REV_%04X",
                                                descriptor->idVendor,
                                                descriptor->idProduct,
                                                descriptor->bcdDevice);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_checked_format(hardware_second,
                                                sizeof(hardware_second),
                                                "USB\\VID_%04X&PID_%04X",
                                                descriptor->idVendor,
                                                descriptor->idProduct,
                                                0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_checked_format(compatibility_first,
                                                sizeof(compatibility_first),
                                                "USB\\Class_%02X&SubClass_%02X&Prot_%02X",
                                                descriptor->bDeviceClass,
                                                descriptor->bDeviceSubClass,
                                                descriptor->bDeviceProtocol);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_checked_format(compatibility_second,
                                                sizeof(compatibility_second),
                                                "USB\\Class_%02X",
                                                descriptor->bDeviceClass,
                                                0,
                                                0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_checked_format(container_text,
                                                sizeof(container_text),
                                                "{00000000-0000-0000-0000-00000000%04X}",
                                                (unsigned)(index + 1u),
                                                0,
                                                0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_utf8_to_utf16le(instance_text, instance, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_multisz2(hardware, hardware_first, hardware_second);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_multisz2(compatibility, compatibility_first, compatibility_second);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_utf8_to_utf16le(container_text, container, 1);
    return status;
}
#endif

static librdp_status rdp_session_usb_multisz2(rdp_buffer* out, const char* first, const char* second)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!out || !first || !second)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_utf8_to_utf16le(first, out, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_utf8_to_utf16le(second, out, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(out, 0);
    return status;
}

static librdp_status rdp_session_usb_build_device_strings(const char* selector,
                                                          uint32_t index,
                                                          rdp_buffer* instance,
                                                          rdp_buffer* hardware,
                                                          rdp_buffer* compatibility,
                                                          rdp_buffer* container)
{
    uint32_t first = 0;
    uint32_t second = 0;
    int decimal_only = 0;
    int bus_mode = 0;
    char instance_text[96];
    char hardware_first[96];
    char hardware_second[96];
    char container_text[48];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!selector || !instance || !hardware || !compatibility || !container)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_session_usb_parse_pair(selector, &first, &second, &decimal_only))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    bus_mode = rdp_session_usb_pair_is_bus_mode(selector, first, second, decimal_only);
    if (bus_mode)
    {
        status = rdp_session_usb_checked_format(instance_text,
                                                sizeof(instance_text),
                                                "USB\\BUS_%03u&DEV_%03u\\RDP_%02u",
                                                (unsigned)first,
                                                (unsigned)second,
                                                (unsigned)index + 1u);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_usb_checked_format(hardware_first,
                                                    sizeof(hardware_first),
                                                    "USB\\BUS_%03u&DEV_%03u",
                                                    (unsigned)first,
                                                    (unsigned)second,
                                                    0);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_usb_checked_format(hardware_second,
                                                    sizeof(hardware_second),
                                                    "USB\\Class_00&SubClass_00&Prot_%02u",
                                                    0,
                                                    0,
                                                    0);
    }
    else
    {
        status = rdp_session_usb_checked_format(instance_text,
                                                sizeof(instance_text),
                                                "USB\\VID_%04X&PID_%04X\\RDP_%02u",
                                                (unsigned)first,
                                                (unsigned)second,
                                                (unsigned)index + 1u);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_usb_checked_format(hardware_first,
                                                    sizeof(hardware_first),
                                                    "USB\\VID_%04X&PID_%04X&REV_%04u",
                                                    (unsigned)first,
                                                    (unsigned)second,
                                                    0);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_usb_checked_format(hardware_second,
                                                    sizeof(hardware_second),
                                                    "USB\\VID_%04X&PID_%04X",
                                                    (unsigned)first,
                                                    (unsigned)second,
                                                    0);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_checked_format(container_text,
                                                sizeof(container_text),
                                                "{00000000-0000-0000-0000-00000000%04X}",
                                                (unsigned)(index + 1u),
                                                0,
                                                0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_utf8_to_utf16le(instance_text, instance, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_multisz2(hardware, hardware_first, hardware_second);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_multisz2(compatibility,
                                          "USB\\Class_00&SubClass_00&Prot_00",
                                          "USB\\Class_00");
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_utf8_to_utf16le(container_text, container, 1);
    return status;
}

static librdp_status rdp_session_send_usb_redirection_packet(librdp_session* session,
                                                             const rdp_buffer* packet,
                                                             const char* event)
{
    if (!session || !packet || !event || session->usb_redirection_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_send_dynamic_channel_data(session,
                                                 session->usb_redirection_channel_id,
                                                 session->usb_redirection_channel_id_bytes,
                                                 packet->data,
                                                 packet->length,
                                                 event);
}

static librdp_status rdp_session_usb_send_device_announcements(librdp_session* session)
{
    uint32_t count = 0;
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_USB))
        return LIBRDP_STATUS_OK;

    count = librdp_settings_usb_device_count(session->settings);
    for (i = 0; i < count && status == LIBRDP_STATUS_OK; i++)
    {
        rdp_buffer packet;
        rdp_buffer instance;
        rdp_buffer hardware;
        rdp_buffer compatibility;
        rdp_buffer container;
        rdp_usb_redirection_device_capabilities capabilities;
        uint32_t interface_id = RDP_SESSION_USB_DEVICE_INTERFACE_BASE + i;
        const char* selector = librdp_settings_usb_device_selector(session->settings, i);
#ifdef RDP_HAVE_LIBUSB
        rdp_session_usb_device backend_device;
        int have_backend_device = 0;
        const char* backend_name = "descriptor";
#endif

        rdp_buffer_init(&packet);
        rdp_buffer_init(&instance);
        rdp_buffer_init(&hardware);
        rdp_buffer_init(&compatibility);
        rdp_buffer_init(&container);
#ifdef RDP_HAVE_LIBUSB
        memset(&backend_device, 0, sizeof(backend_device));
        if (rdp_session_usb_libusb_find(session, selector, interface_id, &backend_device) == LIBRDP_STATUS_OK)
        {
            session->usb_devices[i] = backend_device;
            have_backend_device = 1;
        }
        else
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.urbdrc.backend.missing",
                            "selector=\"%s\" interface_id=%u",
                            selector ? selector : "",
                            interface_id);
            rdp_buffer_free(&container);
            rdp_buffer_free(&compatibility);
            rdp_buffer_free(&hardware);
            rdp_buffer_free(&instance);
            rdp_buffer_free(&packet);
            continue;
        }
#endif
        memset(&capabilities, 0, sizeof(capabilities));
        capabilities.cb_size = RDP_USB_REDIRECTION_DEVICE_CAPABILITIES_SIZE;
        capabilities.usb_bus_interface_version = 2;
        capabilities.usbdi_version = 0x00000600u;
        capabilities.supported_usb_version = 0x00000200u;
        capabilities.device_is_high_speed = 1;

#ifdef RDP_HAVE_LIBUSB
        if (have_backend_device)
            status = rdp_session_usb_build_descriptor_device_strings(&backend_device.descriptor,
                                                                     i,
                                                                     &instance,
                                                                     &hardware,
                                                                     &compatibility,
                                                                     &container);
        else
#endif
            status = rdp_session_usb_build_device_strings(selector,
                                                          i,
                                                          &instance,
                                                          &hardware,
                                                          &compatibility,
                                                          &container);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_usb_redirection_write_add_device(&packet,
                                                          rdp_session_usb_next_message_id(session),
                                                          interface_id,
                                                          instance.data,
                                                          (uint32_t)instance.length,
                                                          hardware.data,
                                                          (uint32_t)hardware.length,
                                                          compatibility.data,
                                                          (uint32_t)compatibility.length,
                                                          container.data,
                                                          (uint32_t)container.length,
                                                          &capabilities);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_usb_redirection_packet(session,
                                                             &packet,
                                                             "client.urbdrc.add_device");
        if (status == LIBRDP_STATUS_OK)
        {
            session->usb_device_count_sent++;
#ifdef RDP_HAVE_LIBUSB
            backend_name = have_backend_device && backend_device.handle ? "libusb" : "descriptor";
#endif
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.urbdrc.add_device",
                            "dvc_channel_id=%u selector=\"%s\" interface_id=%u count=%u backend=%s",
                            session->usb_redirection_channel_id,
                            selector ? selector : "",
                            interface_id,
                            session->usb_device_count_sent,
#ifdef RDP_HAVE_LIBUSB
                            backend_name
#else
                            "synthetic"
#endif
            );
        }
        rdp_buffer_free(&container);
        rdp_buffer_free(&compatibility);
        rdp_buffer_free(&hardware);
        rdp_buffer_free(&instance);
        rdp_buffer_free(&packet);
    }
    return status;
}

#ifdef RDP_HAVE_LIBUSB
static const rdp_session_usb_device* rdp_session_usb_device_by_interface(const librdp_session* session,
                                                                         uint32_t interface_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < LIBRDP_SETTINGS_MAX_USB_DEVICES; i++)
    {
        if (session->usb_devices[i].active && session->usb_devices[i].interface_id == interface_id)
            return &session->usb_devices[i];
    }
    return NULL;
}
#endif

static uint32_t rdp_session_usb_port_status(const librdp_session* session, uint32_t interface_id)
{
#ifdef RDP_HAVE_LIBUSB
    const rdp_session_usb_device* device = rdp_session_usb_device_by_interface(session, interface_id);

    if (device)
    {
        if (device->descriptor.bcdUSB < 0x0110u)
            return 0x00000303u;
        if (device->descriptor.bcdUSB < 0x0200u)
            return 0x00000103u;
    }
#else
    (void)session;
    (void)interface_id;
#endif
    return 0x00000503u;
}

static uint32_t rdp_session_usb_bus_time(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint32_t)(((uint64_t)ts.tv_sec * 1000ull) + ((uint64_t)ts.tv_nsec / 1000000ull));
}

static librdp_status rdp_session_usb_make_u32_output(uint32_t value, rdp_buffer* output)
{
    if (!output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u32_le(output, value);
}

static librdp_status rdp_session_usb_make_urb_result(uint32_t usbd_status, rdp_buffer* result)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(result, 8u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(result, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(result, usbd_status);
    return status;
}

static librdp_status rdp_session_usb_send_io_completion(librdp_session* session,
                                                        uint32_t request_id,
                                                        uint32_t hresult,
                                                        uint32_t information,
                                                        const uint8_t* output,
                                                        uint32_t output_len,
                                                        const char* event)
{
    rdp_usb_redirection_io_completion completion;
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!output && output_len > 0) || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!session->usb_request_completion_ready)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.completion.skipped",
                        "request_id=%u reason=no_callback",
                        request_id);
        return LIBRDP_STATUS_OK;
    }
    memset(&completion, 0, sizeof(completion));
    completion.request_id = request_id;
    completion.hresult = hresult;
    completion.information = information;
    completion.output_buffer = output;
    completion.output_buffer_len = output_len;
    rdp_buffer_init(&packet);
    status = rdp_usb_redirection_write_io_control_completion(&packet,
                                                             session->usb_request_completion_interface_id,
                                                             rdp_session_usb_next_message_id(session),
                                                             &completion);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_usb_redirection_packet(session, &packet, event);
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status rdp_session_usb_send_urb_completion(librdp_session* session,
                                                         const rdp_usb_redirection_transfer* transfer,
                                                         uint32_t usbd_status,
                                                         const char* event)
{
    rdp_usb_redirection_urb_completion completion;
    rdp_buffer packet;
    rdp_buffer result;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !transfer || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (transfer->urb.no_ack)
        return LIBRDP_STATUS_OK;
    if (!session->usb_request_completion_ready)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.urb_completion.skipped",
                        "request_id=%u reason=no_callback",
                        transfer->urb.request_id);
        return LIBRDP_STATUS_OK;
    }
    memset(&completion, 0, sizeof(completion));
    completion.request_id = transfer->urb.request_id;
    completion.hresult = RDP_SESSION_HRESULT_OK;
    rdp_buffer_init(&result);
    rdp_buffer_init(&packet);
    status = rdp_session_usb_make_urb_result(usbd_status, &result);
    if (status == LIBRDP_STATUS_OK)
    {
        completion.ts_urb_result = result.data;
        completion.cb_ts_urb_result = (uint32_t)result.length;
        status = rdp_usb_redirection_write_urb_completion_no_data(&packet,
                                                                  session->usb_request_completion_interface_id,
                                                                  rdp_session_usb_next_message_id(session),
                                                                  &completion);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_usb_redirection_packet(session, &packet, event);
    rdp_buffer_free(&packet);
    rdp_buffer_free(&result);
    return status;
}

static librdp_status rdp_session_handle_usb_redirection_message(librdp_session* session,
                                                                const uint8_t* data,
                                                                size_t data_len)
{
    rdp_usb_redirection_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_usb_redirection_parse_header(data, data_len, 1, &header);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.pdu.invalid",
                        "dvc_channel_id=%u payload_len=%u status=%s",
                        session->usb_redirection_channel_id,
                        (unsigned)data_len,
                        librdp_status_string(status));
        return status;
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.urbdrc.pdu",
                          "dvc_channel_id=%u interface_id=%u mask=%u message_id=%u function_id=%u payload_len=%u",
                          session->usb_redirection_channel_id,
                          header.interface_id,
                          header.mask,
                          header.message_id,
                          header.function_id,
                          (unsigned)header.payload_len);

    if (header.interface_id == RDP_USB_REDIRECTION_INTERFACE_CAPABILITIES &&
        header.mask == RDP_USB_REDIRECTION_MASK_NONE &&
        header.function_id == RDP_USB_REDIRECTION_FN_EXCHANGE_CAPABILITY)
    {
        rdp_usb_redirection_capability_exchange exchange;
        rdp_buffer response;
        rdp_buffer add_channel;

        rdp_buffer_init(&response);
        rdp_buffer_init(&add_channel);
        status = rdp_usb_redirection_parse_capability_request(data, data_len, &exchange);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_usb_redirection_write_capability_response(&response,
                                                                   exchange.header.message_id,
                                                                   exchange.capability_value,
                                                                   RDP_SESSION_HRESULT_OK);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_usb_redirection_packet(session,
                                                             &response,
                                                             "client.urbdrc.capability.response");
        if (status == LIBRDP_STATUS_OK)
            status = rdp_usb_redirection_write_add_virtual_channel(&add_channel,
                                                                   rdp_session_usb_next_message_id(session));
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_usb_redirection_packet(session,
                                                             &add_channel,
                                                             "client.urbdrc.add_virtual_channel");
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.capability",
                        "dvc_channel_id=%u capability=%u enabled=%u status=%s",
                        session->usb_redirection_channel_id,
                        status == LIBRDP_STATUS_OK ? exchange.capability_value : 0u,
                        librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_USB) ? 1u : 0u,
                        librdp_status_string(status));
        rdp_buffer_free(&add_channel);
        rdp_buffer_free(&response);
        return status;
    }
    if (header.mask == RDP_USB_REDIRECTION_MASK_PROXY &&
        header.function_id == RDP_USB_REDIRECTION_FN_CHANNEL_CREATED)
    {
        rdp_usb_redirection_channel_created created;

        status = rdp_usb_redirection_parse_channel_created(data, data_len, header.interface_id, &created);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->usb_redirection_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.channel_created",
                        "dvc_channel_id=%u interface_id=%u version=%u.%u capabilities=%u",
                        session->usb_redirection_channel_id,
                        header.interface_id,
                        created.major_version,
                        created.minor_version,
                        created.capabilities);
        return rdp_session_usb_send_device_announcements(session);
    }
    if (header.mask == RDP_USB_REDIRECTION_MASK_PROXY &&
        header.function_id == RDP_USB_REDIRECTION_FN_REGISTER_REQUEST_CALLBACK)
    {
        rdp_usb_redirection_register_callback callback;

        status = rdp_usb_redirection_parse_register_callback(data, data_len, &callback);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->usb_request_completion_ready = callback.has_request_completion ? 1u : 0u;
        session->usb_request_completion_interface_id =
            callback.has_request_completion ? callback.request_completion : 0u;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.register_callback",
                        "dvc_channel_id=%u interface_id=%u callback_ready=%u callback_interface_id=%u",
                        session->usb_redirection_channel_id,
                        callback.header.interface_id,
                        session->usb_request_completion_ready,
                        session->usb_request_completion_interface_id);
        return LIBRDP_STATUS_OK;
    }
    if (header.mask == RDP_USB_REDIRECTION_MASK_PROXY &&
        header.function_id == RDP_USB_REDIRECTION_FN_QUERY_DEVICE_TEXT)
    {
        static const char description[] = "librdp USB device";
        rdp_usb_redirection_query_device_text query;
        rdp_buffer text;
        rdp_buffer response;

        rdp_buffer_init(&text);
        rdp_buffer_init(&response);
        status = rdp_usb_redirection_parse_query_device_text(data, data_len, &query);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_utf8_to_utf16le(description, &text, 1);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_usb_redirection_write_query_device_text_response(&response,
                                                                          query.header.interface_id,
                                                                          query.header.message_id,
                                                                          text.data,
                                                                          (uint32_t)text.length,
                                                                          RDP_SESSION_HRESULT_OK);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_usb_redirection_packet(session,
                                                             &response,
                                                             "client.urbdrc.query_device_text.response");
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.query_device_text",
                        "dvc_channel_id=%u interface_id=%u text_type=%u locale_id=%u status=%s",
                        session->usb_redirection_channel_id,
                        header.interface_id,
                        status == LIBRDP_STATUS_OK ? query.text_type : 0u,
                        status == LIBRDP_STATUS_OK ? query.locale_id : 0u,
                        librdp_status_string(status));
        rdp_buffer_free(&response);
        rdp_buffer_free(&text);
        return status;
    }
    if (header.mask == RDP_USB_REDIRECTION_MASK_PROXY &&
        (header.function_id == RDP_USB_REDIRECTION_FN_IO_CONTROL ||
         header.function_id == RDP_USB_REDIRECTION_FN_INTERNAL_IO_CONTROL))
    {
        rdp_usb_redirection_io_control control;
        rdp_buffer output;
        uint32_t result = RDP_SESSION_HRESULT_NOTIMPL;

        rdp_buffer_init(&output);
        status = rdp_usb_redirection_parse_io_control(data, data_len, header.function_id, &control);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&output);
            return status;
        }
        if (control.header.function_id == RDP_USB_REDIRECTION_FN_IO_CONTROL)
        {
            if (control.io_control_code == RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_GET_PORT_STATUS)
            {
                status = rdp_session_usb_make_u32_output(
                    rdp_session_usb_port_status(session, control.header.interface_id),
                    &output);
                result = RDP_SESSION_HRESULT_OK;
            }
            else if (control.io_control_code == RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_RESET_PORT ||
                     control.io_control_code == RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_CYCLE_PORT ||
                     control.io_control_code == RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_SUBMIT_IDLE_NOTIFICATION)
            {
                result = RDP_SESSION_HRESULT_OK;
            }
            else if (control.io_control_code == RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_SUBMIT_URB)
            {
                result = RDP_USB_REDIRECTION_USBD_STATUS_NOT_SUPPORTED;
            }
        }
        else if (control.io_control_code == RDP_USB_REDIRECTION_IOCTL_QUERY_BUS_TIME)
        {
            status = rdp_session_usb_make_u32_output(rdp_session_usb_bus_time(), &output);
            result = RDP_SESSION_HRESULT_OK;
        }
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.io_control",
                        "dvc_channel_id=%u interface_id=%u function_id=%u io_control=%u request_id=%u input_len=%u output_size=%u result=%u response_len=%u",
                        session->usb_redirection_channel_id,
                        control.header.interface_id,
                        control.header.function_id,
                        control.io_control_code,
                        control.request_id,
                        control.input_buffer_len,
                        control.output_buffer_size,
                        result,
                        (unsigned)output.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_usb_send_io_completion(session,
                                                        control.request_id,
                                                        result,
                                                        (uint32_t)output.length,
                                                        output.data,
                                                        (uint32_t)output.length,
                                                        "client.urbdrc.io_control.completion");
        rdp_buffer_free(&output);
        return status;
    }
    if (header.mask == RDP_USB_REDIRECTION_MASK_PROXY &&
        (header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST ||
         header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST))
    {
        rdp_usb_redirection_transfer transfer;

        status = rdp_usb_redirection_parse_transfer(data, data_len, header.function_id, &transfer);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.transfer",
                        "dvc_channel_id=%u interface_id=%u function_id=%u urb_function=%u request_id=%u output_size=%u output_len=%u no_ack=%u",
                        session->usb_redirection_channel_id,
                        transfer.header.interface_id,
                        transfer.header.function_id,
                        transfer.urb.function,
                        transfer.urb.request_id,
                        transfer.output_buffer_size,
                        transfer.output_buffer_len,
                        transfer.urb.no_ack);
        return rdp_session_usb_send_urb_completion(session,
                                                   &transfer,
                                                   RDP_USB_REDIRECTION_USBD_STATUS_NOT_SUPPORTED,
                                                   "client.urbdrc.urb.completion");
    }
    if (header.mask == RDP_USB_REDIRECTION_MASK_PROXY &&
        header.function_id == RDP_USB_REDIRECTION_FN_CANCEL_REQUEST)
    {
        rdp_usb_redirection_cancel_request cancel;

        status = rdp_usb_redirection_parse_cancel_request(data, data_len, &cancel);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.cancel",
                        "dvc_channel_id=%u interface_id=%u request_id=%u",
                        session->usb_redirection_channel_id,
                        cancel.header.interface_id,
                        cancel.request_id);
        return LIBRDP_STATUS_OK;
    }
    if (header.mask == RDP_USB_REDIRECTION_MASK_PROXY &&
        header.function_id == RDP_USB_REDIRECTION_FN_RETRACT_DEVICE)
    {
        rdp_usb_redirection_retract_device retract;

        status = rdp_usb_redirection_parse_retract_device(data, data_len, &retract);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.retract",
                        "dvc_channel_id=%u interface_id=%u reason=%u",
                        session->usb_redirection_channel_id,
                        retract.header.interface_id,
                        retract.reason);
        return LIBRDP_STATUS_OK;
    }

    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.urbdrc.unsupported",
                    "dvc_channel_id=%u interface_id=%u mask=%u function_id=%u payload_len=%u",
                    session->usb_redirection_channel_id,
                    header.interface_id,
                    header.mask,
                    header.function_id,
                    (unsigned)header.payload_len);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_send_composited_packet(librdp_session* session,
                                                        const rdp_buffer* payload,
                                                        const char* event)
{
    if (!session || !payload || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->composited_channel_id == 0 || session->composited_channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    return rdp_session_send_dynamic_channel_data(session,
                                                 session->composited_channel_id,
                                                 session->composited_channel_id_bytes,
                                                 payload->data,
                                                 payload->length,
                                                 event);
}

static uint32_t rdp_session_composited_payload_code(const rdp_composited_control* control)
{
    const uint8_t* data = NULL;

    if (!control || control->payload_len < 4u)
        return 0;
    data = control->payload;
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static librdp_status rdp_session_handle_composited_message(librdp_session* session,
                                                           uint32_t channel_id,
                                                           const uint8_t* data,
                                                           size_t data_len)
{
    rdp_composited_control control;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_composited_parse_control(data, data_len, &control);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.cr2.pdu.invalid",
                        "dvc_channel_id=%u payload_len=%u status=%s",
                        channel_id,
                        (unsigned)data_len,
                        librdp_status_string(status));
        return status;
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.cr2.control",
                          "dvc_channel_id=%u control=%u word0=%u word1=%u payload_len=%u enabled=%u",
                          channel_id,
                          control.control_code,
                          control.word0,
                          control.word1,
                          (unsigned)control.payload_len,
                          librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_CR2) ? 1u : 0u);
    switch (control.control_code)
    {
        case RDP_COMPOSITED_CONTROL_VERSION_REQUEST:
        {
            uint32_t versions[1] = {RDP_COMPOSITED_PROTOCOL_VERSION};
            rdp_buffer response;

            rdp_buffer_init(&response);
            status = rdp_composited_write_version_reply(&response, versions, 1);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_send_composited_packet(session, &response, "client.cr2.version_reply");
            rdp_buffer_free(&response);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.cr2.version_reply",
                            "dvc_channel_id=%u version=%u",
                            channel_id,
                            RDP_COMPOSITED_PROTOCOL_VERSION);
            break;
        }
        case RDP_COMPOSITED_CONTROL_VERSION_ANNOUNCEMENT:
        {
            rdp_composited_version_reply reply;

            status = rdp_composited_parse_version_reply(control.payload, control.payload_len, &reply);
            if (status == LIBRDP_STATUS_OK)
            {
                session->composited_ready =
                    rdp_composited_version_reply_has(&reply, RDP_COMPOSITED_PROTOCOL_VERSION) ? 1u : 0u;
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.cr2.version_announcement",
                                "dvc_channel_id=%u versions=%u supported=%u",
                                channel_id,
                                reply.version_count,
                                session->composited_ready ? 1u : 0u);
            }
            else
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.cr2.version_announcement.invalid",
                                "dvc_channel_id=%u payload_len=%u status=%s",
                                channel_id,
                                (unsigned)control.payload_len,
                                librdp_status_string(status));
                return status;
            }
            break;
        }
        case RDP_COMPOSITED_CONTROL_OPEN_CONNECTION:
            session->composited_connection_open = 1;
            session->composited_connection_id = control.word0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.cr2.connection.open",
                            "dvc_channel_id=%u connection_id=%u flags=%u",
                            channel_id,
                            control.word0,
                            control.word1);
            break;
        case RDP_COMPOSITED_CONTROL_CLOSE_CONNECTION:
            session->composited_connection_open = 0;
            session->composited_connection_id = 0;
            session->composited_open_channel_id = 0;
            rdp_composited_render_tree_reset(&session->composited_tree);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.cr2.connection.close",
                            "dvc_channel_id=%u",
                            channel_id);
            break;
        case RDP_COMPOSITED_CONTROL_OPEN_CHANNEL:
            session->composited_ready = 1;
            session->composited_open_channel_id = control.word0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.cr2.channel.open",
                            "dvc_channel_id=%u channel=%u flags=%u",
                            channel_id,
                            control.word0,
                            control.word1);
            break;
        case RDP_COMPOSITED_CONTROL_CLOSE_CHANNEL:
            if (session->composited_open_channel_id == control.word0)
                session->composited_open_channel_id = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.cr2.channel.close",
                            "dvc_channel_id=%u channel=%u",
                            channel_id,
                            control.word0);
            break;
        case RDP_COMPOSITED_CONTROL_DATA_ON_CHANNEL:
        {
            uint32_t before_commands = session->composited_tree.command_count;
            uint32_t before_resources = session->composited_tree.resource_count;

            status = rdp_composited_render_tree_apply_batch(&session->composited_tree,
                                                            control.payload,
                                                            control.payload_len);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.cr2.render.batch",
                            "dvc_channel_id=%u channel=%u payload_len=%u status=%s commands=%u resources=%u resource_delta=%d invalidations=%u skipped=%u",
                            channel_id,
                            control.word0,
                            (unsigned)control.payload_len,
                            librdp_status_string(status),
                            session->composited_tree.command_count - before_commands,
                            session->composited_tree.resource_count,
                            (int)session->composited_tree.resource_count - (int)before_resources,
                            session->composited_tree.invalidation_count,
                            session->composited_tree.skipped_known_count);
            return status;
        }
        case RDP_COMPOSITED_CONTROL_CONNECTION_NOTIFICATION:
        case RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION:
        case RDP_COMPOSITED_CONTROL_CONNECTION_BROADCAST:
        case RDP_COMPOSITED_CONTROL_SURFACE_MANAGER_EVENT:
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.cr2.notification",
                                  "dvc_channel_id=%u control=%u channel=%u code=%u payload_len=%u",
                                  channel_id,
                                  control.control_code,
                                  control.word0,
                                  rdp_session_composited_payload_code(&control),
                                  (unsigned)control.payload_len);
            break;
        default:
            break;
    }
    return LIBRDP_STATUS_OK;
}

static void rdp_session_write_u32_bytes(uint32_t value, uint8_t out[4])
{
    out[0] = (uint8_t)(value & 0xffu);
    out[1] = (uint8_t)((value >> 8) & 0xffu);
    out[2] = (uint8_t)((value >> 16) & 0xffu);
    out[3] = (uint8_t)((value >> 24) & 0xffu);
}

static librdp_status rdp_session_send_video_redirection_packet(librdp_session* session,
                                                               const rdp_buffer* payload,
                                                               const char* event)
{
    if (!session || !payload || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->video_redirection_channel_id == 0 || session->video_redirection_channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    return rdp_session_send_dynamic_channel_data(session,
                                                 session->video_redirection_channel_id,
                                                 session->video_redirection_channel_id_bytes,
                                                 payload->data,
                                                 payload->length,
                                                 event);
}

static librdp_status rdp_session_send_video_capabilities(librdp_session* session, uint32_t message_id)
{
    uint8_t protocol[4];
    uint8_t platform[4];
    uint8_t audio[4];
    rdp_video_redirection_capability caps[3];
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_session_write_u32_bytes(RDP_VIDEO_REDIRECTION_PROTOCOL_VERSION_2, protocol);
    rdp_session_write_u32_bytes(RDP_VIDEO_REDIRECTION_PLATFORM_OTHER, platform);
    rdp_session_write_u32_bytes(
        librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_AUDIO_OUTPUT) ?
            RDP_VIDEO_REDIRECTION_AUDIO_SUPPORTED :
            RDP_VIDEO_REDIRECTION_AUDIO_NO_DEVICE,
        audio);
    memset(caps, 0, sizeof(caps));
    caps[0].type = RDP_VIDEO_REDIRECTION_CAPABILITY_PROTOCOL_VERSION;
    caps[0].length = sizeof(protocol);
    caps[0].data = protocol;
    caps[0].data_len = sizeof(protocol);
    caps[1].type = RDP_VIDEO_REDIRECTION_CAPABILITY_PLATFORM;
    caps[1].length = sizeof(platform);
    caps[1].data = platform;
    caps[1].data_len = sizeof(platform);
    caps[2].type = RDP_VIDEO_REDIRECTION_CAPABILITY_AUDIO_SUPPORT;
    caps[2].length = sizeof(audio);
    caps[2].data = audio;
    caps[2].data_len = sizeof(audio);
    rdp_buffer_init(&response);
    status = rdp_video_redirection_write_exchange_capabilities_response(&response,
                                                                        message_id,
                                                                        caps,
                                                                        3u,
                                                                        RDP_SESSION_HRESULT_OK);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_redirection_packet(session,
                                                           &response,
                                                           "client.tsmf.capabilities.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
    {
        session->video_redirection_capabilities_sent = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.tsmf.capabilities.response",
                        "dvc_channel_id=%u message_id=%u audio=%u",
                        session->video_redirection_channel_id,
                        message_id,
                        audio[0]);
    }
    return status;
}

static librdp_status rdp_session_send_video_rim(librdp_session* session, uint32_t message_id)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_redirection_write_rim_capability_response(
        &response,
        message_id,
        RDP_VIDEO_REDIRECTION_RIM_CAPABILITY_VERSION_01,
        RDP_SESSION_HRESULT_OK);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_redirection_packet(session,
                                                           &response,
                                                           "client.tsmf.rim.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
    {
        session->video_redirection_rim_sent = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.tsmf.rim.response",
                        "dvc_channel_id=%u message_id=%u",
                        session->video_redirection_channel_id,
                        message_id);
    }
    return status;
}

static librdp_status rdp_session_send_video_event(librdp_session* session,
                                                  uint32_t message_id,
                                                  uint32_t stream_id,
                                                  uint32_t event_id,
                                                  const char* event_name)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !event_name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_redirection_write_client_event(&response, message_id, stream_id, event_id, NULL, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_redirection_packet(session, &response, event_name);
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event_name,
                        "dvc_channel_id=%u message_id=%u stream_id=%u event_id=%u",
                        session->video_redirection_channel_id,
                        message_id,
                        stream_id,
                        event_id);
    return status;
}

static librdp_status rdp_session_send_video_sample_ack(librdp_session* session,
                                                       uint32_t message_id,
                                                       uint32_t stream_id,
                                                       uint64_t duration,
                                                       uint64_t data_len)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_redirection_write_playback_ack(&response,
                                                      message_id,
                                                      stream_id,
                                                      duration,
                                                      data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_redirection_packet(session, &response, "client.tsmf.sample.ack");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.tsmf.sample.ack",
                        "dvc_channel_id=%u message_id=%u stream_id=%u duration=%llu data_len=%llu",
                        session->video_redirection_channel_id,
                        message_id,
                        stream_id,
                        (unsigned long long)duration,
                        (unsigned long long)data_len);
    return status;
}

static librdp_status rdp_session_handle_video_redirection_message(librdp_session* session,
                                                                  uint32_t channel_id,
                                                                  const uint8_t* data,
                                                                  size_t data_len)
{
    rdp_video_redirection_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_parse_header(data, data_len, 1, &header);
    if (status != LIBRDP_STATUS_OK)
    {
        status = rdp_video_redirection_parse_header(data, data_len, 0, &header);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.pdu.invalid",
                            "dvc_channel_id=%u payload_len=%u status=%s",
                            channel_id,
                            (unsigned)data_len,
                            librdp_status_string(status));
            return status;
        }
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.tsmf.pdu",
                          "dvc_channel_id=%u interface_id=%u stream_mask=%u message_id=%u function_id=%u payload_len=%u enabled=%u",
                          channel_id,
                          header.interface_id,
                          header.stream_id_mask,
                          header.message_id,
                          header.has_function_id ? header.function_id : 0u,
                          (unsigned)header.payload_len,
                          librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_VIDEO) ? 1u : 0u);
    if (header.has_function_id &&
        header.interface_id == RDP_VIDEO_REDIRECTION_INTERFACE_RIM_CAPABILITIES &&
        header.function_id == RDP_VIDEO_REDIRECTION_FUNC_RIM_EXCHANGE_CAPABILITY_REQUEST)
    {
        rdp_video_redirection_rim_capability request;

        status = rdp_video_redirection_parse_rim_capability_request(data, data_len, &request);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_session_send_video_rim(session, request.header.message_id);
    }
    if (header.has_function_id &&
        header.interface_id == RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT &&
        header.function_id == RDP_VIDEO_REDIRECTION_FUNC_EXCHANGE_CAPABILITIES_REQ)
    {
        rdp_video_redirection_capability_message request;

        status = rdp_video_redirection_parse_exchange_capabilities_request(data, data_len, &request);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->video_redirection_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.tsmf.capabilities.request",
                        "dvc_channel_id=%u message_id=%u count=%u",
                        channel_id,
                        request.header.message_id,
                        request.capabilities.count);
        return rdp_session_send_video_capabilities(session, request.header.message_id);
    }
    if (!header.has_function_id || header.interface_id != RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT)
        return LIBRDP_STATUS_OK;

    switch (header.function_id)
    {
        case RDP_VIDEO_REDIRECTION_FUNC_SET_CHANNEL_PARAMS:
        {
            rdp_video_redirection_stream params;

            status = rdp_video_redirection_parse_set_channel_params(data, data_len, &params);
            if (status != LIBRDP_STATUS_OK)
                return status;
            (void)rdp_session_video_stream_upsert(session, params.presentation_id, params.stream_id);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.channel_params",
                            "dvc_channel_id=%u message_id=%u stream_id=%u",
                            channel_id,
                            params.header.message_id,
                            params.stream_id);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_NEW_PRESENTATION:
        {
            rdp_video_redirection_presentation presentation;

            status = rdp_video_redirection_parse_new_presentation(data, data_len, &presentation);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.presentation",
                            "dvc_channel_id=%u message_id=%u platform=%u",
                            channel_id,
                            presentation.header.message_id,
                            presentation.platform_cookie);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ADD_STREAM:
        {
            rdp_video_redirection_stream stream;
            rdp_session_video_stream* entry = NULL;

            status = rdp_video_redirection_parse_add_stream(data, data_len, &stream);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_session_video_stream_upsert(session, stream.presentation_id, stream.stream_id);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.stream.add",
                            "dvc_channel_id=%u message_id=%u stream_id=%u media_len=%u",
                            channel_id,
                            stream.header.message_id,
                            stream.stream_id,
                            stream.data_len);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_SAMPLE:
        {
            rdp_video_redirection_stream stream;
            rdp_video_redirection_data_sample sample;
            rdp_session_video_stream* entry = NULL;
            uint64_t duration = 0;

            status = rdp_video_redirection_parse_sample_message(data, data_len, &stream);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_video_redirection_parse_data_sample(stream.data, stream.data_len, &sample);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_session_video_stream_upsert(session, stream.presentation_id, stream.stream_id);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            duration = sample.sample_end_time > sample.sample_start_time ?
                           sample.sample_end_time - sample.sample_start_time :
                           0;
            entry->sample_count++;
            entry->sample_bytes += sample.data_len;
            entry->last_sample_start = sample.sample_start_time;
            entry->last_sample_end = sample.sample_end_time;
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.tsmf.sample",
                                  "dvc_channel_id=%u message_id=%u stream_id=%u sample_len=%u samples=%llu bytes=%llu flags=%u",
                                  channel_id,
                                  stream.header.message_id,
                                  stream.stream_id,
                                  sample.data_len,
                                  (unsigned long long)entry->sample_count,
                                  (unsigned long long)entry->sample_bytes,
                                  sample.sample_flags);
            return rdp_session_send_video_sample_ack(session,
                                                     stream.header.message_id,
                                                     stream.stream_id,
                                                     duration,
                                                     sample.data_len);
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_STARTED:
        {
            rdp_video_redirection_playback_started started;

            status = rdp_video_redirection_parse_playback_started(data, data_len, &started);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.playback.started",
                            "dvc_channel_id=%u message_id=%u offset=%llu seek=%u",
                            channel_id,
                            started.header.message_id,
                            (unsigned long long)started.playback_start_offset,
                            started.is_seek);
            return rdp_session_send_video_event(session,
                                                started.header.message_id,
                                                0,
                                                RDP_VIDEO_REDIRECTION_CLIENT_EVENT_START_COMPLETED,
                                                "client.tsmf.playback.start_completed");
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_STOPPED:
        case RDP_VIDEO_REDIRECTION_FUNC_ON_END_OF_STREAM:
        {
            rdp_video_redirection_stream stream;
            uint32_t event_id = header.function_id == RDP_VIDEO_REDIRECTION_FUNC_ON_END_OF_STREAM ?
                                    RDP_VIDEO_REDIRECTION_CLIENT_EVENT_ENDOFSTREAM :
                                    RDP_VIDEO_REDIRECTION_CLIENT_EVENT_STOP_COMPLETED;

            status = rdp_video_redirection_parse_stream_only(data, data_len, header.function_id, &stream);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_session_video_stream_remove(session, stream.presentation_id, stream.stream_id);
            return rdp_session_send_video_event(session,
                                                stream.header.message_id,
                                                stream.stream_id,
                                                event_id,
                                                event_id == RDP_VIDEO_REDIRECTION_CLIENT_EVENT_ENDOFSTREAM ?
                                                    "client.tsmf.playback.end_of_stream" :
                                                    "client.tsmf.playback.stop_completed");
        }
        case RDP_VIDEO_REDIRECTION_FUNC_SET_VIDEO_WINDOW:
        {
            rdp_video_redirection_window window;
            rdp_session_video_stream* entry = NULL;

            status = rdp_video_redirection_parse_set_video_window(data, data_len, &window);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_session_video_stream_find(session, window.presentation_id, 0);
            if (entry)
                entry->video_window_id = window.video_window_id;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.window",
                            "dvc_channel_id=%u message_id=%u video_window_id=%llu parent_window_id=%llu",
                            channel_id,
                            window.header.message_id,
                            (unsigned long long)window.video_window_id,
                            (unsigned long long)window.parent_window_id);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_UPDATE_GEOMETRY_INFO:
        {
            rdp_video_redirection_geometry_update update;
            rdp_video_redirection_geometry_info info;

            status = rdp_video_redirection_parse_geometry_update(data, data_len, &update);
            if (status != LIBRDP_STATUS_OK)
                return status;
            memset(&info, 0, sizeof(info));
            if (update.geometry_len > 0)
                (void)rdp_video_redirection_parse_geometry_info(update.geometry, update.geometry_len, &info);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.geometry",
                            "dvc_channel_id=%u message_id=%u geometry_len=%u visible_len=%u width=%u height=%u",
                            channel_id,
                            update.header.message_id,
                            update.geometry_len,
                            update.visible_rect_len,
                            info.width,
                            info.height);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_RATE_CHANGED:
        {
            rdp_video_redirection_playback_rate rate;

            status = rdp_video_redirection_parse_playback_rate(data, data_len, &rate);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.playback.rate",
                            "dvc_channel_id=%u message_id=%u rate_bits=%u",
                            channel_id,
                            rate.header.message_id,
                            rate.rate_bits);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_STREAM_VOLUME:
        case RDP_VIDEO_REDIRECTION_FUNC_ON_CHANNEL_VOLUME:
        {
            rdp_video_redirection_volume volume;

            status = header.function_id == RDP_VIDEO_REDIRECTION_FUNC_ON_STREAM_VOLUME ?
                         rdp_video_redirection_parse_stream_volume(data, data_len, &volume) :
                         rdp_video_redirection_parse_channel_volume(data, data_len, &volume);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.volume",
                            "dvc_channel_id=%u message_id=%u function_id=%u value=%u second=%u",
                            channel_id,
                            volume.header.message_id,
                            header.function_id,
                            volume.value,
                            volume.second_value);
            break;
        }
        default:
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.tsmf.pdu.skipped",
                                  "dvc_channel_id=%u message_id=%u function_id=%u payload_len=%u",
                                  channel_id,
                                  header.message_id,
                                  header.function_id,
                                  (unsigned)header.payload_len);
            break;
    }
    return LIBRDP_STATUS_OK;
}

static uint8_t rdp_session_video_capture_version(const librdp_session* session)
{
    if (!session || session->video_capture_version == 0)
        return RDP_VIDEO_CAPTURE_VERSION_2;
    return session->video_capture_version;
}

static const char* rdp_session_video_capture_source(const librdp_session* session)
{
    if (!session || !librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_CAMERA) ||
        librdp_settings_camera_count(session->settings) == 0)
        return NULL;
    return librdp_settings_camera_source(session->settings, 0);
}

static const char* rdp_session_video_capture_source_kind(const char* source)
{
    struct stat st;

    if (!source || source[0] == '\0')
        return "none";
    memset(&st, 0, sizeof(st));
    if (stat(source, &st) == 0 && S_ISREG(st.st_mode))
        return "file";
    return "device";
}

static int rdp_session_video_capture_source_is_file(const char* source)
{
    struct stat st;

    if (!source || source[0] == '\0')
        return 0;
    memset(&st, 0, sizeof(st));
    return stat(source, &st) == 0 && S_ISREG(st.st_mode);
}

static void rdp_session_video_capture_media_from_source(const char* source,
                                                        rdp_video_capture_media_type* media)
{
    const char* ext = source ? strrchr(source, '.') : NULL;

    memset(media, 0, sizeof(*media));
    media->format = RDP_VIDEO_CAPTURE_MEDIA_NV12;
    media->width = RDP_SESSION_VIDEO_CAPTURE_DEFAULT_WIDTH;
    media->height = RDP_SESSION_VIDEO_CAPTURE_DEFAULT_HEIGHT;
    media->frame_rate_numerator = RDP_SESSION_VIDEO_CAPTURE_DEFAULT_FPS;
    media->frame_rate_denominator = 1;
    media->pixel_aspect_ratio_numerator = 1;
    media->pixel_aspect_ratio_denominator = 1;
    media->flags = 0;
    if (source && strncmp(source, "/dev/video", 10u) == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_MJPG;
        media->flags = RDP_VIDEO_CAPTURE_MEDIA_FLAG_DECODING_REQUIRED;
    }
    if (!source || !ext)
        return;
    if (strcasecmp(ext, ".h264") == 0 || strcasecmp(ext, ".avc") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_H264;
        media->flags = RDP_VIDEO_CAPTURE_MEDIA_FLAG_DECODING_REQUIRED;
    }
    else if (strcasecmp(ext, ".jpg") == 0 || strcasecmp(ext, ".jpeg") == 0 ||
             strcasecmp(ext, ".mjpg") == 0 || strcasecmp(ext, ".mjpeg") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_MJPG;
        media->flags = RDP_VIDEO_CAPTURE_MEDIA_FLAG_DECODING_REQUIRED;
    }
    else if (strcasecmp(ext, ".yuy2") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_YUY2;
    }
    else if (strcasecmp(ext, ".i420") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_I420;
    }
    else if (strcasecmp(ext, ".rgb24") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_RGB24;
    }
    else if (strcasecmp(ext, ".rgb32") == 0 || strcasecmp(ext, ".bgra") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_RGB32;
    }
}

static void rdp_session_video_capture_update_media(librdp_session* session, const char* source)
{
    if (!session)
        return;
    rdp_session_video_capture_media_from_source(source, &session->video_capture_media);
}

static void rdp_session_video_capture_media_to_public(const rdp_video_capture_media_type* in,
                                                      librdp_video_capture_media* out)
{
    if (!in || !out)
        return;
    memset(out, 0, sizeof(*out));
    out->format = in->format;
    out->width = in->width;
    out->height = in->height;
    out->frame_rate_numerator = in->frame_rate_numerator;
    out->frame_rate_denominator = in->frame_rate_denominator;
    out->pixel_aspect_ratio_numerator = in->pixel_aspect_ratio_numerator;
    out->pixel_aspect_ratio_denominator = in->pixel_aspect_ratio_denominator;
    out->flags = in->flags;
}

static void rdp_session_emit_video_capture_open(librdp_session* session, uint8_t stream_index)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_VIDEO_CAPTURE_OPEN;
    event.data.video_capture_open.stream_index = stream_index;
    rdp_session_video_capture_media_to_public(&session->video_capture_media,
                                              &event.data.video_capture_open.media);
    rdp_session_emit(session, &event);
}

static void rdp_session_emit_video_capture_sample_request(librdp_session* session, uint8_t stream_index)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_VIDEO_CAPTURE_SAMPLE_REQUEST;
    event.data.video_capture_sample_request.stream_index = stream_index;
    rdp_session_video_capture_media_to_public(&session->video_capture_media,
                                              &event.data.video_capture_sample_request.media);
    rdp_session_emit(session, &event);
}

static void rdp_session_emit_video_capture_close(librdp_session* session, uint8_t stream_index)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_VIDEO_CAPTURE_CLOSE;
    event.data.video_capture_close.stream_index = stream_index;
    rdp_session_emit(session, &event);
}

static librdp_status rdp_session_video_capture_read_sample(const char* source,
                                                           rdp_buffer* sample,
                                                           uint32_t* error_code)
{
    struct stat st;
    int fd = -1;
    int flags = O_RDONLY;
    uint8_t chunk[8192];
    librdp_status status = LIBRDP_STATUS_OK;

    if (error_code)
        *error_code = RDP_VIDEO_CAPTURE_ERROR_UNEXPECTED;
    if (!source || !sample || !error_code)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&st, 0, sizeof(st));
    if (stat(source, &st) < 0)
    {
        *error_code = errno == EACCES ? RDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED :
                                        RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND;
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    if (!S_ISREG(st.st_mode))
    {
        *error_code = RDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED;
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    if (st.st_size < 0 || (uint64_t)st.st_size > RDP_VIDEO_CAPTURE_MAX_SAMPLE_BYTES)
    {
        *error_code = RDP_VIDEO_CAPTURE_ERROR_INVALID_MEDIA_TYPE;
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    fd = open(source, flags);
    if (fd < 0)
    {
        *error_code = errno == EACCES ? RDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED :
                                        RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND;
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    for (;;)
    {
        ssize_t count = read(fd, chunk, sizeof(chunk));

        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0)
        {
            *error_code = RDP_VIDEO_CAPTURE_ERROR_UNEXPECTED;
            status = LIBRDP_STATUS_IO_ERROR;
            break;
        }
        if (count == 0)
            break;
        if ((uint64_t)sample->length + (uint64_t)count > RDP_VIDEO_CAPTURE_MAX_SAMPLE_BYTES)
        {
            *error_code = RDP_VIDEO_CAPTURE_ERROR_INVALID_MEDIA_TYPE;
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        }
        status = rdp_buffer_append(sample, chunk, (size_t)count);
        if (status != LIBRDP_STATUS_OK)
        {
            *error_code = status == LIBRDP_STATUS_NO_MEMORY ?
                              RDP_VIDEO_CAPTURE_ERROR_OUT_OF_MEMORY :
                              RDP_VIDEO_CAPTURE_ERROR_UNEXPECTED;
            break;
        }
    }
    close(fd);
    return status;
}

static librdp_status rdp_session_send_video_capture_packet(librdp_session* session,
                                                           uint32_t channel_id,
                                                           uint8_t channel_id_bytes,
                                                           const rdp_buffer* payload,
                                                           const char* event)
{
    if (!session || !payload || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (channel_id == 0 || channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    return rdp_session_send_dynamic_channel_data(session,
                                                 channel_id,
                                                 channel_id_bytes,
                                                 payload->data,
                                                 payload->length,
                                                 event);
}

static librdp_status rdp_session_send_video_capture_control(librdp_session* session,
                                                            const rdp_buffer* payload,
                                                            const char* event)
{
    return rdp_session_send_video_capture_packet(session,
                                                 session ? session->video_capture_control_channel_id : 0,
                                                 session ? session->video_capture_control_channel_id_bytes : 0,
                                                 payload,
                                                 event);
}

static librdp_status rdp_session_send_video_capture_data(librdp_session* session,
                                                         const rdp_buffer* payload,
                                                         const char* event)
{
    return rdp_session_send_video_capture_packet(session,
                                                 session ? session->video_capture_channel_id : 0,
                                                 session ? session->video_capture_channel_id_bytes : 0,
                                                 payload,
                                                 event);
}

static librdp_status rdp_session_send_video_capture_error(librdp_session* session,
                                                          int control_channel,
                                                          uint32_t error_code,
                                                          const char* event)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t version = rdp_session_video_capture_version(session);

    if (!session || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_error(&response, version, error_code);
    if (status == LIBRDP_STATUS_OK)
    {
        status = control_channel ?
                     rdp_session_send_video_capture_control(session, &response, event) :
                     rdp_session_send_video_capture_data(session, &response, event);
    }
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event,
                        "channel=%s error=%u",
                        control_channel ? "control" : "data",
                        error_code);
    return status;
}

static librdp_status rdp_session_send_video_capture_success(librdp_session* session, const char* event)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t version = rdp_session_video_capture_version(session);

    if (!session || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_empty(&response,
                                           version,
                                           RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session, &response, event);
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event,
                        "dvc_channel_id=%u version=%u",
                        session->video_capture_channel_id,
                        version);
    return status;
}

static librdp_status rdp_session_send_video_capture_device_added(librdp_session* session)
{
    const char* source = rdp_session_video_capture_source(session);
    rdp_buffer device_name;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t version = rdp_session_video_capture_version(session);

    if (!session || !source)
        return LIBRDP_STATUS_OK;
    rdp_buffer_init(&device_name);
    rdp_buffer_init(&response);
    status = rdp_session_utf8_to_utf16le("Camera", &device_name, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_video_capture_write_device_added(&response,
                                                      version,
                                                      device_name.data,
                                                      device_name.length,
                                                      RDP_VIDEO_CAPTURE_CHANNEL_NAME);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_control(session,
                                                        &response,
                                                        "client.rdpecam.device.added");
    rdp_buffer_free(&response);
    rdp_buffer_free(&device_name);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.device.added",
                        "control_channel_id=%u capture_channel=%s source_kind=%s version=%u",
                        session->video_capture_control_channel_id,
                        RDP_VIDEO_CAPTURE_CHANNEL_NAME,
                        rdp_session_video_capture_source_kind(source),
                        version);
    return status;
}

static librdp_status rdp_session_send_video_capture_stream_list(librdp_session* session)
{
    const char* source = rdp_session_video_capture_source(session);
    rdp_video_capture_stream_description stream;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!source)
        return rdp_session_send_video_capture_error(session,
                                                    0,
                                                    RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND,
                                                    "client.rdpecam.stream_list.error");
    memset(&stream, 0, sizeof(stream));
    stream.frame_source_types = RDP_VIDEO_CAPTURE_STREAM_SOURCE_COLOR;
    stream.stream_category = RDP_VIDEO_CAPTURE_STREAM_CATEGORY_CAPTURE;
    stream.selected = 1;
    stream.can_be_shared = 1;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_stream_list(&response,
                                                 rdp_session_video_capture_version(session),
                                                 &stream,
                                                 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session,
                                                     &response,
                                                     "client.rdpecam.stream_list.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.stream_list.response",
                        "dvc_channel_id=%u count=1 source_kind=%s",
                        session->video_capture_channel_id,
                        rdp_session_video_capture_source_kind(source));
    return status;
}

static librdp_status rdp_session_send_video_capture_media_list(librdp_session* session,
                                                               uint8_t message_id,
                                                               const char* event)
{
    const char* source = rdp_session_video_capture_source(session);
    rdp_video_capture_media_type media;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!source)
        return rdp_session_send_video_capture_error(session,
                                                    0,
                                                    RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND,
                                                    "client.rdpecam.media.error");
    rdp_session_video_capture_update_media(session, source);
    media = session->video_capture_media;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_media_list(&response,
                                                rdp_session_video_capture_version(session),
                                                message_id,
                                                &media,
                                                1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session, &response, event);
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event,
                        "dvc_channel_id=%u format=%u width=%u height=%u fps_num=%u fps_den=%u flags=%u",
                        session->video_capture_channel_id,
                        media.format,
                        media.width,
                        media.height,
                        media.frame_rate_numerator,
                        media.frame_rate_denominator,
                        media.flags);
    return status;
}

static librdp_status rdp_session_send_video_capture_sample_error(librdp_session* session,
                                                                 uint8_t stream_index,
                                                                 uint32_t error_code)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_sample_error(&response,
                                                  rdp_session_video_capture_version(session),
                                                  stream_index,
                                                  error_code);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session,
                                                     &response,
                                                     "client.rdpecam.sample.error");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
    {
        session->video_capture_sample_reply_pending = 0;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.sample.error",
                        "dvc_channel_id=%u stream=%u error=%u",
                        session->video_capture_channel_id,
                        stream_index,
                        error_code);
    }
    return status;
}

static librdp_status rdp_session_send_video_capture_sample_payload(librdp_session* session,
                                                                   uint8_t stream_index,
                                                                   const void* data,
                                                                   size_t data_len,
                                                                   const char* event)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0) || !event ||
        data_len > RDP_VIDEO_CAPTURE_MAX_SAMPLE_BYTES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_sample(&response,
                                            rdp_session_video_capture_version(session),
                                            stream_index,
                                            data,
                                            data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session, &response, event);
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
    {
        session->video_capture_sample_reply_pending = 0;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event,
                        "dvc_channel_id=%u stream=%u data_len=%u",
                        session->video_capture_channel_id,
                        stream_index,
                        (unsigned)data_len);
    }
    return status;
}

static librdp_status rdp_session_send_video_capture_sample(librdp_session* session, uint8_t stream_index)
{
    const char* source = rdp_session_video_capture_source(session);
    rdp_buffer sample;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t error_code = RDP_VIDEO_CAPTURE_ERROR_UNEXPECTED;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!source)
        return rdp_session_send_video_capture_sample_error(session,
                                                          stream_index,
                                                          RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND);
    rdp_buffer_init(&sample);
    status = rdp_session_video_capture_read_sample(source, &sample, &error_code);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_sample_payload(session,
                                                               stream_index,
                                                               sample.data,
                                                               sample.length,
                                                               "client.rdpecam.sample.response");
    rdp_buffer_free(&sample);
    if (status == LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_OK;
    return rdp_session_send_video_capture_sample_error(session, stream_index, error_code);
}

static librdp_status rdp_session_handle_video_capture_control_message(librdp_session* session,
                                                                      uint32_t channel_id,
                                                                      const uint8_t* data,
                                                                      size_t data_len)
{
    rdp_video_capture_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_capture_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.control.invalid",
                        "dvc_channel_id=%u payload_len=%u status=%s",
                        channel_id,
                        (unsigned)data_len,
                        librdp_status_string(status));
        return status;
    }
    session->video_capture_version = header.version == RDP_VIDEO_CAPTURE_VERSION_1 ?
                                         RDP_VIDEO_CAPTURE_VERSION_1 :
                                         RDP_VIDEO_CAPTURE_VERSION_2;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.rdpecam.control.pdu",
                          "dvc_channel_id=%u version=%u message_id=%u payload_len=%u enabled=%u cameras=%u",
                          channel_id,
                          header.version,
                          header.message_id,
                          (unsigned)data_len,
                          librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_CAMERA) ? 1u : 0u,
                          librdp_settings_camera_count(session->settings));
    switch (header.message_id)
    {
        case RDP_VIDEO_CAPTURE_MESSAGE_SELECT_VERSION_REQUEST:
        {
            rdp_buffer response;
            rdp_video_capture_header request;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_SELECT_VERSION_REQUEST,
                                                   &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_buffer_init(&response);
            status = rdp_video_capture_write_empty(&response,
                                                   session->video_capture_version,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_SELECT_VERSION_RESPONSE);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_send_video_capture_control(session,
                                                                &response,
                                                                "client.rdpecam.version.response");
            rdp_buffer_free(&response);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.version.response",
                            "dvc_channel_id=%u version=%u",
                            channel_id,
                            session->video_capture_version);
            return rdp_session_send_video_capture_device_added(session);
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE:
        {
            rdp_video_capture_header response;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE,
                                                   &response);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.control.success",
                            "dvc_channel_id=%u version=%u",
                            channel_id,
                            response.version);
            break;
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_ERROR_RESPONSE:
        {
            rdp_video_capture_error error;

            status = rdp_video_capture_parse_error(data, data_len, &error);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.control.error",
                            "dvc_channel_id=%u error=%u",
                            channel_id,
                            error.error_code);
            break;
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_DEVICE_REMOVED:
        {
            rdp_video_capture_device_notification removed;

            status = rdp_video_capture_parse_device_removed(data, data_len, &removed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.device.removed",
                            "dvc_channel_id=%u channel_name_len=%u",
                            channel_id,
                            (unsigned)removed.channel_name_len);
            break;
        }
        default:
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.rdpecam.control.skipped",
                                  "dvc_channel_id=%u message_id=%u payload_len=%u",
                                  channel_id,
                                  header.message_id,
                                  (unsigned)data_len);
            break;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_handle_video_capture_data_message(librdp_session* session,
                                                                   uint32_t channel_id,
                                                                   const uint8_t* data,
                                                                   size_t data_len)
{
    rdp_video_capture_header header;
    librdp_status status = LIBRDP_STATUS_OK;
    const char* source = NULL;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_capture_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.data.invalid",
                        "dvc_channel_id=%u payload_len=%u status=%s",
                        channel_id,
                        (unsigned)data_len,
                        librdp_status_string(status));
        return status;
    }
    session->video_capture_version = header.version;
    source = rdp_session_video_capture_source(session);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.rdpecam.data.pdu",
                          "dvc_channel_id=%u version=%u message_id=%u payload_len=%u active=%u streaming=%u source_kind=%s",
                          channel_id,
                          header.version,
                          header.message_id,
                          (unsigned)data_len,
                          session->video_capture_active,
                          session->video_capture_streaming,
                          rdp_session_video_capture_source_kind(source));
    switch (header.message_id)
    {
        case RDP_VIDEO_CAPTURE_MESSAGE_ACTIVATE_DEVICE_REQUEST:
        {
            rdp_video_capture_header request;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_ACTIVATE_DEVICE_REQUEST,
                                                   &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (!source)
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND,
                                                            "client.rdpecam.activate.error");
            session->video_capture_active = 1;
            return rdp_session_send_video_capture_success(session, "client.rdpecam.activate.success");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_DEACTIVATE_DEVICE_REQUEST:
        {
            rdp_video_capture_header request;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_DEACTIVATE_DEVICE_REQUEST,
                                                   &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (session->video_capture_streaming)
                rdp_session_emit_video_capture_close(session, session->video_capture_selected_stream);
            session->video_capture_active = 0;
            session->video_capture_streaming = 0;
            return rdp_session_send_video_capture_success(session, "client.rdpecam.deactivate.success");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_STREAM_LIST_REQUEST:
        {
            rdp_video_capture_header request;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_STREAM_LIST_REQUEST,
                                                   &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            return rdp_session_send_video_capture_stream_list(session);
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_REQUEST:
        case RDP_VIDEO_CAPTURE_MESSAGE_CURRENT_MEDIA_TYPE_REQUEST:
        {
            rdp_video_capture_stream_index request;
            uint8_t response_id = header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_REQUEST ?
                                      RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_RESPONSE :
                                      RDP_VIDEO_CAPTURE_MESSAGE_CURRENT_MEDIA_TYPE_RESPONSE;

            status = rdp_video_capture_parse_stream_index(data, data_len, header.message_id, &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (request.stream_index != 0)
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_INVALID_STREAM_NUMBER,
                                                            "client.rdpecam.media.error");
            return rdp_session_send_video_capture_media_list(
                session,
                response_id,
                response_id == RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_RESPONSE ?
                    "client.rdpecam.media_list.response" :
                    "client.rdpecam.current_media.response");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_START_STREAMS_REQUEST:
        case RDP_VIDEO_CAPTURE_MESSAGE_STOP_STREAMS_REQUEST:
        {
            rdp_video_capture_stream_index request;

            status = rdp_video_capture_parse_stream_index(data, data_len, header.message_id, &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (request.stream_index != 0)
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_INVALID_STREAM_NUMBER,
                                                            "client.rdpecam.stream.error");
            if (!source)
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND,
                                                            "client.rdpecam.stream.error");
            rdp_session_video_capture_update_media(session, source);
            session->video_capture_selected_stream = request.stream_index;
            session->video_capture_active = header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_START_STREAMS_REQUEST ?
                                                1u :
                                                session->video_capture_active;
            session->video_capture_streaming =
                header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_START_STREAMS_REQUEST ? 1u : 0u;
            if (header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_START_STREAMS_REQUEST &&
                !rdp_session_video_capture_source_is_file(source))
                rdp_session_emit_video_capture_open(session, request.stream_index);
            if (header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_STOP_STREAMS_REQUEST)
                rdp_session_emit_video_capture_close(session, request.stream_index);
            return rdp_session_send_video_capture_success(
                session,
                header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_START_STREAMS_REQUEST ?
                    "client.rdpecam.stream.start.success" :
                    "client.rdpecam.stream.stop.success");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_REQUEST:
        {
            rdp_video_capture_stream_index request;

            status = rdp_video_capture_parse_stream_index(data,
                                                          data_len,
                                                          RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_REQUEST,
                                                          &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (request.stream_index != session->video_capture_selected_stream)
                return rdp_session_send_video_capture_sample_error(
                    session,
                    request.stream_index,
                    RDP_VIDEO_CAPTURE_ERROR_INVALID_STREAM_NUMBER);
            if (!session->video_capture_active || !session->video_capture_streaming)
                return rdp_session_send_video_capture_sample_error(
                    session,
                    request.stream_index,
                    RDP_VIDEO_CAPTURE_ERROR_NOT_INITIALIZED);
            if (!rdp_session_video_capture_source_is_file(source))
            {
                session->video_capture_sample_reply_pending = 1;
                rdp_session_emit_video_capture_sample_request(session, request.stream_index);
                if (session->video_capture_sample_reply_pending)
                {
                    session->video_capture_sample_reply_pending = 0;
                    return rdp_session_send_video_capture_sample_error(
                        session,
                        request.stream_index,
                        RDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED);
                }
                return LIBRDP_STATUS_OK;
            }
            return rdp_session_send_video_capture_sample(session, request.stream_index);
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_LIST_REQUEST:
        {
            rdp_video_capture_opaque request;
            rdp_buffer response;

            status = rdp_video_capture_parse_opaque(data,
                                                    data_len,
                                                    RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_LIST_REQUEST,
                                                    &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_buffer_init(&response);
            status = rdp_video_capture_write_opaque(&response,
                                                    rdp_session_video_capture_version(session),
                                                    RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_LIST_RESPONSE,
                                                    NULL,
                                                    0);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_send_video_capture_data(
                    session,
                    &response,
                    "client.rdpecam.property_list.response");
            rdp_buffer_free(&response);
            return status;
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_REQUEST:
        case RDP_VIDEO_CAPTURE_MESSAGE_SET_PROPERTY_VALUE_REQUEST:
        {
            rdp_video_capture_opaque request;

            status = rdp_video_capture_parse_opaque(data, data_len, header.message_id, &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            return rdp_session_send_video_capture_error(session,
                                                        0,
                                                        RDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED,
                                                        "client.rdpecam.property.error");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE:
        {
            rdp_video_capture_header response;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE,
                                                   &response);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.data.success",
                            "dvc_channel_id=%u version=%u",
                            channel_id,
                            response.version);
            break;
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_ERROR_RESPONSE:
        {
            rdp_video_capture_error error;

            status = rdp_video_capture_parse_error(data, data_len, &error);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.data.error",
                            "dvc_channel_id=%u error=%u",
                            channel_id,
                            error.error_code);
            break;
        }
        default:
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.rdpecam.data.skipped",
                                  "dvc_channel_id=%u message_id=%u payload_len=%u",
                                  channel_id,
                                  header.message_id,
                                  (unsigned)data_len);
            break;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_handle_dynamic_channel_message(librdp_session* session,
                                                                rdp_session_dynamic_channel* entry,
                                                                uint32_t channel_id,
                                                                uint8_t channel_id_bytes,
                                                                const uint8_t* data,
                                                                size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !entry || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    (void)channel_id_bytes;

    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.drdynvc.data",
                          "dvc_channel_id=%u name=%s payload_len=%u",
                          channel_id,
                          entry->name,
                          (unsigned)data_len);
    if (strcmp(entry->name, RDP_SESSION_DISPLAY_CONTROL_NAME) == 0)
    {
        rdp_display_control_caps caps;

        status = rdp_display_control_parse_caps(data, data_len, &caps);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->display_control_caps = caps;
        session->display_control_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.display_control.caps",
                        "dvc_channel_id=%u max_monitors=%u area_a=%u area_b=%u",
                        channel_id,
                        caps.max_num_monitors,
                        caps.max_monitor_area_factor_a,
                        caps.max_monitor_area_factor_b);
        status = rdp_session_request_display_control_layout(
            session,
            session->requested_desktop_width != 0 ? session->requested_desktop_width :
                                                    librdp_surface_width(session->surface),
            session->requested_desktop_height != 0 ? session->requested_desktop_height :
                                                     librdp_surface_height(session->surface));
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    else if (strcmp(entry->name, RDP_SESSION_CORE_INPUT_NAME) == 0)
    {
        rdp_core_input_init_response response;

        status = rdp_core_input_parse_init_response(data, data_len, &response);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->core_input_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.core_input.ready",
                        "dvc_channel_id=%u selected_version=%u max_version=%u",
                        channel_id,
                        response.selected_protocol_version,
                        response.protocol_version_max);
    }
    else if (strcmp(entry->name, RDP_SESSION_INPUT_CHANNEL_NAME) == 0)
    {
        rdp_input_channel_header header;

        status = rdp_input_channel_parse_header(data, data_len, &header);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                              RDP_TRACE_LEVEL_DEBUG,
                              "rdp.input_channel.pdu",
                              "dvc_channel_id=%u event_id=%u pdu_len=%u",
                              channel_id,
                              header.event_id,
                              header.pdu_length);
        if (header.event_id == RDP_INPUT_CHANNEL_EVENT_SC_READY)
        {
            rdp_input_channel_sc_ready ready;

            status = rdp_input_channel_parse_sc_ready(data, data_len, &ready);
            if (status != LIBRDP_STATUS_OK)
                return status;
            session->input_channel_protocol_version = ready.protocol_version;
            session->input_channel_supported_features = ready.supported_features;
            session->input_channel_suspended = 0;
            status = rdp_session_send_input_channel_ready(session, &ready);
            if (status != LIBRDP_STATUS_OK)
                return status;
            session->input_channel_ready = 1;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.input_channel.sc_ready",
                            "dvc_channel_id=%u protocol_version=%u features=%u",
                            channel_id,
                            ready.protocol_version,
                            ready.supported_features);
        }
        else if (header.event_id == RDP_INPUT_CHANNEL_EVENT_SUSPEND_INPUT)
        {
            status = rdp_input_channel_parse_empty(data, data_len, RDP_INPUT_CHANNEL_EVENT_SUSPEND_INPUT);
            if (status != LIBRDP_STATUS_OK)
                return status;
            session->input_channel_suspended = 1;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.input_channel.suspend",
                            "dvc_channel_id=%u",
                            channel_id);
        }
        else if (header.event_id == RDP_INPUT_CHANNEL_EVENT_RESUME_INPUT)
        {
            status = rdp_input_channel_parse_empty(data, data_len, RDP_INPUT_CHANNEL_EVENT_RESUME_INPUT);
            if (status != LIBRDP_STATUS_OK)
                return status;
            session->input_channel_suspended = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.input_channel.resume",
                            "dvc_channel_id=%u",
                            channel_id);
        }
        else if (header.event_id == RDP_INPUT_CHANNEL_EVENT_DISMISS_HOVERING_TOUCH_CONTACT)
        {
            uint8_t contact_id = 0;

            status = rdp_input_channel_parse_dismiss_hovering(data, data_len, &contact_id);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.input_channel.dismiss_hovering",
                            "dvc_channel_id=%u contact_id=%u",
                            channel_id,
                            contact_id);
        }
        else
        {
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.input_channel.server_event",
                                  "dvc_channel_id=%u event_id=%u payload_len=%u",
                                  channel_id,
                                  header.event_id,
                                  (unsigned)data_len);
        }
    }
    else if (strcmp(entry->name, RDP_SESSION_MOUSE_CURSOR_NAME) == 0)
    {
        status = rdp_session_handle_mouse_cursor_message(session, channel_id, data, data_len);
    }
    else if (strcmp(entry->name, RDP_SESSION_GRAPHICS_PIPELINE_NAME) == 0)
    {
        status = rdp_session_handle_graphics_message(session, channel_id, data, data_len);
    }
    else if (strcmp(entry->name, RDP_AUDIO_INPUT_CHANNEL_NAME) == 0)
    {
        status = rdp_session_handle_audio_input_message(session, channel_id, data, data_len);
    }
    else if (strcmp(entry->name, RDP_SESSION_WEBAUTHN_CHANNEL_NAME) == 0)
    {
        status = rdp_session_handle_webauthn_message(session, channel_id, channel_id_bytes, data, data_len);
    }
    else if (strcmp(entry->name, RDP_SESSION_USB_REDIRECTION_CHANNEL_NAME) == 0)
    {
        status = rdp_session_handle_usb_redirection_message(session, data, data_len);
    }
    else if (strcmp(entry->name, RDP_COMPOSITED_CHANNEL_NAME) == 0)
    {
        status = rdp_session_handle_composited_message(session, channel_id, data, data_len);
    }
    else if (strcmp(entry->name, RDP_VIDEO_REDIRECTION_CHANNEL_NAME) == 0)
    {
        status = rdp_session_handle_video_redirection_message(session, channel_id, data, data_len);
    }
    else if (strcmp(entry->name, RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME) == 0)
    {
        status = rdp_session_handle_video_capture_control_message(session, channel_id, data, data_len);
    }
    else if (strcmp(entry->name, RDP_VIDEO_CAPTURE_CHANNEL_NAME) == 0)
    {
        status = rdp_session_handle_video_capture_data_message(session, channel_id, data, data_len);
    }
    else
    {
        rdp_session_emit_channel_data(session, entry, data, data_len);
    }
    return status;
}

static librdp_status rdp_session_handle_dynamic_channel(librdp_session* session,
                                                        const rdp_virtual_channel_packet* channel_packet)
{
    rdp_dynamic_channel_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !channel_packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_dynamic_channel_parse_header(channel_packet->payload, channel_packet->payload_len, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (header.command == RDP_DYNAMIC_CHANNEL_CMD_CAPABILITIES)
    {
        rdp_dynamic_channel_capabilities capabilities;
        rdp_buffer response;
        uint16_t client_version = 0;

        rdp_buffer_init(&response);
        status = rdp_dynamic_channel_parse_capabilities(channel_packet->payload,
                                                        channel_packet->payload_len,
                                                        &capabilities);
        if (status == LIBRDP_STATUS_OK)
        {
            client_version = rdp_dynamic_channel_select_version(capabilities.version);
            if (client_version == 0)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_dynamic_channel_write_capabilities_response(&response, client_version);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_write_channel_pdu(session,
                                                   session->dynamic_channel_id,
                                                   &response,
                                                   "client.drdynvc.capabilities");
        rdp_buffer_free(&response);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.capabilities",
                        "server_version=%u client_version=%u",
                        capabilities.version,
                        client_version);
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_CREATE)
    {
        rdp_dynamic_channel_create_request request;
        rdp_buffer response;
        size_t trace_name_len = 0;
        int name_len = 0;
        rdp_session_dynamic_channel* entry = NULL;

        rdp_buffer_init(&response);
        status = rdp_dynamic_channel_parse_create_request(channel_packet->payload,
                                                          channel_packet->payload_len,
                                                          &request);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_dynamic_channel_write_create_response(&response,
                                                               request.channel_id,
                                                               request.channel_id_bytes,
                                                               RDP_DYNAMIC_CHANNEL_STATUS_OK);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_dynamic_channel_add(session, &request);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_write_channel_pdu(session,
                                                   session->dynamic_channel_id,
                                                   &response,
                                                   "client.drdynvc.create");
        if (status == LIBRDP_STATUS_OK)
            entry = rdp_session_dynamic_channel_find(session, request.channel_id);
        rdp_buffer_free(&response);
        if (status != LIBRDP_STATUS_OK)
            return status;
        trace_name_len = request.name_len > 120u ? 120u : request.name_len;
        name_len = (int)trace_name_len;
        if (request.name_len == sizeof(RDP_SESSION_DISPLAY_CONTROL_NAME) - 1u &&
            memcmp(request.name, RDP_SESSION_DISPLAY_CONTROL_NAME, request.name_len) == 0)
        {
            session->display_control_channel_id = request.channel_id;
            session->display_control_channel_id_bytes = request.channel_id_bytes;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.display_control.channel",
                            "dvc_channel_id=%u",
                            request.channel_id);
        }
        else if (request.name_len == sizeof(RDP_SESSION_CORE_INPUT_NAME) - 1u &&
                 memcmp(request.name, RDP_SESSION_CORE_INPUT_NAME, request.name_len) == 0)
        {
            session->core_input_channel_id = request.channel_id;
            session->core_input_channel_id_bytes = request.channel_id_bytes;
            session->core_input_ready = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.core_input.channel",
                            "dvc_channel_id=%u",
                            request.channel_id);
            status = rdp_session_send_core_input_init(session);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (request.name_len == sizeof(RDP_SESSION_INPUT_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_SESSION_INPUT_CHANNEL_NAME, request.name_len) == 0)
        {
            session->input_channel_id = request.channel_id;
            session->input_channel_id_bytes = request.channel_id_bytes;
            session->input_channel_ready = 0;
            session->input_channel_suspended = 0;
            session->input_channel_protocol_version = 0;
            session->input_channel_supported_features = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.input_channel.channel",
                            "dvc_channel_id=%u",
                            request.channel_id);
        }
        else if (request.name_len == sizeof(RDP_AUDIO_INPUT_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_AUDIO_INPUT_CHANNEL_NAME, request.name_len) == 0)
        {
            session->audio_input_channel_id = request.channel_id;
            session->audio_input_channel_id_bytes = request.channel_id_bytes;
            session->audio_input_ready = 0;
            session->audio_input_open = 0;
            session->audio_input_open_reply_sent = 0;
            session->audio_input_version = 0;
            session->audio_input_selected_format_count = 0;
            memset(session->audio_input_selected_formats, 0, sizeof(session->audio_input_selected_formats));
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.audin.channel",
                            "dvc_channel_id=%u",
                            request.channel_id);
        }
        else if (request.name_len == sizeof(RDP_SESSION_WEBAUTHN_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_SESSION_WEBAUTHN_CHANNEL_NAME, request.name_len) == 0)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.webauthn.channel",
                            "dvc_channel_id=%u enabled=%u",
                            request.channel_id,
                            librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_WEBAUTHN) ? 1u : 0u);
        }
        else if (request.name_len == sizeof(RDP_SESSION_USB_REDIRECTION_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_SESSION_USB_REDIRECTION_CHANNEL_NAME, request.name_len) == 0)
        {
            session->usb_redirection_channel_id = request.channel_id;
            session->usb_redirection_channel_id_bytes = request.channel_id_bytes;
            session->usb_redirection_ready = 0;
            session->usb_request_completion_ready = 0;
            session->usb_message_id = 0;
            session->usb_request_completion_interface_id = 0;
            session->usb_device_count_sent = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.urbdrc.channel",
                            "dvc_channel_id=%u enabled=%u configured_devices=%u",
                            request.channel_id,
                            librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_USB) ? 1u : 0u,
                            librdp_settings_usb_device_count(session->settings));
        }
        else if (request.name_len == sizeof(RDP_COMPOSITED_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_COMPOSITED_CHANNEL_NAME, request.name_len) == 0)
        {
            session->composited_channel_id = request.channel_id;
            session->composited_channel_id_bytes = request.channel_id_bytes;
            session->composited_ready = 0;
            session->composited_connection_open = 0;
            session->composited_connection_id = 0;
            session->composited_open_channel_id = 0;
            rdp_composited_render_tree_reset(&session->composited_tree);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.cr2.channel",
                            "dvc_channel_id=%u enabled=%u",
                            request.channel_id,
                            librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_CR2) ? 1u : 0u);
        }
        else if (request.name_len == sizeof(RDP_VIDEO_REDIRECTION_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_VIDEO_REDIRECTION_CHANNEL_NAME, request.name_len) == 0)
        {
            session->video_redirection_channel_id = request.channel_id;
            session->video_redirection_channel_id_bytes = request.channel_id_bytes;
            session->video_redirection_ready = 0;
            session->video_redirection_capabilities_sent = 0;
            session->video_redirection_rim_sent = 0;
            memset(session->video_streams, 0, sizeof(session->video_streams));
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.channel",
                            "dvc_channel_id=%u enabled=%u",
                            request.channel_id,
                            librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_VIDEO) ? 1u : 0u);
        }
        else if (request.name_len == sizeof(RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME, request.name_len) == 0)
        {
            rdp_session_video_capture_reset(session);
            session->video_capture_control_channel_id = request.channel_id;
            session->video_capture_control_channel_id_bytes = request.channel_id_bytes;
            session->video_capture_version = RDP_VIDEO_CAPTURE_VERSION_2;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.control.channel",
                            "dvc_channel_id=%u enabled=%u cameras=%u",
                            request.channel_id,
                            librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_CAMERA) ? 1u : 0u,
                            librdp_settings_camera_count(session->settings));
        }
        else if (request.name_len == sizeof(RDP_VIDEO_CAPTURE_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_VIDEO_CAPTURE_CHANNEL_NAME, request.name_len) == 0)
        {
            session->video_capture_channel_id = request.channel_id;
            session->video_capture_channel_id_bytes = request.channel_id_bytes;
            session->video_capture_active = 0;
            session->video_capture_streaming = 0;
            session->video_capture_selected_stream = 0;
            if (session->video_capture_version == 0)
                session->video_capture_version = RDP_VIDEO_CAPTURE_VERSION_2;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.data.channel",
                            "dvc_channel_id=%u enabled=%u cameras=%u",
                            request.channel_id,
                            librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_CAMERA) ? 1u : 0u,
                            librdp_settings_camera_count(session->settings));
        }
        else if (request.name_len == sizeof(RDP_SESSION_MOUSE_CURSOR_NAME) - 1u &&
                 memcmp(request.name, RDP_SESSION_MOUSE_CURSOR_NAME, request.name_len) == 0)
        {
            session->mouse_cursor_channel_id = request.channel_id;
            session->mouse_cursor_channel_id_bytes = request.channel_id_bytes;
            session->mouse_cursor_ready = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.mouse_cursor.channel",
                            "dvc_channel_id=%u",
                            request.channel_id);
            status = rdp_session_send_mouse_cursor_caps(session);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (request.name_len == sizeof(RDP_SESSION_GRAPHICS_PIPELINE_NAME) - 1u &&
                 memcmp(request.name, RDP_SESSION_GRAPHICS_PIPELINE_NAME, request.name_len) == 0)
        {
            session->graphics_channel_id = request.channel_id;
            session->graphics_channel_id_bytes = request.channel_id_bytes;
            session->graphics_ready = 0;
            session->graphics_selected_version = 0;
            session->graphics_selected_flags = 0;
            session->graphics_frames_decoded = 0;
            rdp_graphics_decompressor_reset(&session->graphics_decompressor);
            rdp_clearcodec_context_reset(&session->clearcodec);
            rdp_session_graphics_surfaces_clear(session);
            rdp_session_graphics_cache_clear(session);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.channel",
                            "dvc_channel_id=%u",
                            request.channel_id);
            status = rdp_session_send_graphics_caps(session);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (entry)
        {
            rdp_session_emit_channel_open(session, entry);
        }
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.create",
                        "channel_id=%u name=%.*s status=0",
                        request.channel_id,
                        name_len,
                        request.name);
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST)
    {
        rdp_dynamic_channel_data_first_pdu first_pdu;
        rdp_session_dynamic_channel* entry = NULL;

        status = rdp_dynamic_channel_parse_data_first(channel_packet->payload,
                                                      channel_packet->payload_len,
                                                      &first_pdu);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (first_pdu.total_length == 0 || first_pdu.total_length > RDP_SESSION_MAX_DYNAMIC_MESSAGE)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        entry = rdp_session_dynamic_channel_find(session, first_pdu.channel_id);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.drdynvc.fragment.start",
                              "dvc_channel_id=%u name=%s total_len=%u payload_len=%u",
                              first_pdu.channel_id,
                              entry ? entry->name : "",
                              first_pdu.total_length,
                              (unsigned)first_pdu.data_len);
        if (!entry)
            return LIBRDP_STATUS_OK;
        rdp_buffer_free(&entry->fragment);
        rdp_buffer_init(&entry->fragment);
        status = rdp_buffer_reserve(&entry->fragment, first_pdu.total_length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append(&entry->fragment, first_pdu.data, first_pdu.data_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        entry->fragment_expected = first_pdu.total_length;
        entry->fragmenting = entry->fragment.length < entry->fragment_expected;
        if (!entry->fragmenting)
        {
            status = rdp_session_handle_dynamic_channel_message(session,
                                                                entry,
                                                                first_pdu.channel_id,
                                                                first_pdu.channel_id_bytes,
                                                                entry->fragment.data,
                                                                entry->fragment.length);
            rdp_buffer_free(&entry->fragment);
            entry->fragment_expected = 0;
        }
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA)
    {
        rdp_dynamic_channel_data_pdu data_pdu;
        rdp_session_dynamic_channel* entry = NULL;

        status = rdp_dynamic_channel_parse_data(channel_packet->payload, channel_packet->payload_len, &data_pdu);
        if (status != LIBRDP_STATUS_OK)
            return status;

        entry = rdp_session_dynamic_channel_find(session, data_pdu.channel_id);
        if (!entry)
        {
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.drdynvc.data",
                                  "dvc_channel_id=%u name= payload_len=%u",
                                  data_pdu.channel_id,
                                  (unsigned)data_pdu.data_len);
            return LIBRDP_STATUS_OK;
        }
        if (entry->fragmenting)
        {
            if (data_pdu.data_len > (size_t)entry->fragment_expected - entry->fragment.length)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_buffer_append(&entry->fragment, data_pdu.data, data_pdu.data_len);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.drdynvc.fragment.data",
                                  "dvc_channel_id=%u name=%s total_len=%u received=%u payload_len=%u",
                                  data_pdu.channel_id,
                                  entry->name,
                                  entry->fragment_expected,
                                  (unsigned)entry->fragment.length,
                                  (unsigned)data_pdu.data_len);
            if (entry->fragment.length < entry->fragment_expected)
                return LIBRDP_STATUS_OK;
            entry->fragmenting = 0;
            status = rdp_session_handle_dynamic_channel_message(session,
                                                                entry,
                                                                data_pdu.channel_id,
                                                                data_pdu.channel_id_bytes,
                                                                entry->fragment.data,
                                                                entry->fragment.length);
            rdp_buffer_free(&entry->fragment);
            entry->fragment_expected = 0;
            return status;
        }
        status = rdp_session_handle_dynamic_channel_message(session,
                                                            entry,
                                                            data_pdu.channel_id,
                                                            data_pdu.channel_id_bytes,
                                                            data_pdu.data,
                                                            data_pdu.data_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST_COMPRESSED)
    {
        rdp_dynamic_channel_compressed_data_first_pdu first_pdu;
        rdp_session_dynamic_channel* entry = NULL;
        rdp_buffer decoded;

        rdp_buffer_init(&decoded);
        status = rdp_dynamic_channel_parse_compressed_data_first(channel_packet->payload,
                                                                 channel_packet->payload_len,
                                                                 &first_pdu);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (first_pdu.total_length == 0 || first_pdu.total_length > RDP_SESSION_MAX_DYNAMIC_MESSAGE)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        entry = rdp_session_dynamic_channel_find(session, first_pdu.channel_id);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.drdynvc.compressed.fragment.start",
                              "dvc_channel_id=%u name=%s total_len=%u compressed_len=%u",
                              first_pdu.channel_id,
                              entry ? entry->name : "",
                              first_pdu.total_length,
                              (unsigned)first_pdu.data_len);
        if (!entry)
            return LIBRDP_STATUS_OK;
        status = rdp_graphics_decode_segmented_data(&entry->decompressor,
                                                    first_pdu.data,
                                                    first_pdu.data_len,
                                                    &decoded);
        if (status == LIBRDP_STATUS_OK && decoded.length > first_pdu.total_length)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&entry->fragment);
            rdp_buffer_init(&entry->fragment);
            status = rdp_buffer_reserve(&entry->fragment, first_pdu.total_length);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append(&entry->fragment, decoded.data, decoded.length);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.drdynvc.compressed.fragment.data",
                              "dvc_channel_id=%u name=%s total_len=%u received=%u compressed_len=%u decoded_len=%u",
                              first_pdu.channel_id,
                              entry->name,
                              first_pdu.total_length,
                              (unsigned)entry->fragment.length,
                              (unsigned)first_pdu.data_len,
                              (unsigned)decoded.length);
        if (status == LIBRDP_STATUS_OK)
        {
            entry->fragment_expected = first_pdu.total_length;
            entry->fragmenting = entry->fragment.length < entry->fragment_expected;
            if (!entry->fragmenting)
            {
                status = rdp_session_handle_dynamic_channel_message(session,
                                                                    entry,
                                                                    first_pdu.channel_id,
                                                                    first_pdu.channel_id_bytes,
                                                                    entry->fragment.data,
                                                                    entry->fragment.length);
                rdp_buffer_free(&entry->fragment);
                entry->fragment_expected = 0;
            }
        }
        rdp_buffer_free(&decoded);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA_COMPRESSED)
    {
        rdp_dynamic_channel_compressed_data_pdu data_pdu;
        rdp_session_dynamic_channel* entry = NULL;
        rdp_buffer decoded;

        rdp_buffer_init(&decoded);
        status = rdp_dynamic_channel_parse_compressed_data(channel_packet->payload,
                                                           channel_packet->payload_len,
                                                           &data_pdu);
        if (status != LIBRDP_STATUS_OK)
            return status;
        entry = rdp_session_dynamic_channel_find(session, data_pdu.channel_id);
        if (!entry)
        {
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.drdynvc.compressed.data",
                                  "dvc_channel_id=%u name= compressed_len=%u",
                                  data_pdu.channel_id,
                                  (unsigned)data_pdu.data_len);
            return LIBRDP_STATUS_OK;
        }
        status = rdp_graphics_decode_segmented_data(&entry->decompressor,
                                                    data_pdu.data,
                                                    data_pdu.data_len,
                                                    &decoded);
        if (status == LIBRDP_STATUS_OK && entry->fragmenting)
        {
            if (entry->fragment.length > entry->fragment_expected ||
                decoded.length > (size_t)entry->fragment_expected - entry->fragment.length)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            else
            {
                status = rdp_buffer_append(&entry->fragment, decoded.data, decoded.length);
            }
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.drdynvc.compressed.fragment.data",
                                  "dvc_channel_id=%u name=%s total_len=%u received=%u compressed_len=%u decoded_len=%u",
                                  data_pdu.channel_id,
                                  entry->name,
                                  entry->fragment_expected,
                                  (unsigned)entry->fragment.length,
                                  (unsigned)data_pdu.data_len,
                                  (unsigned)decoded.length);
            if (status == LIBRDP_STATUS_OK && entry->fragment.length >= entry->fragment_expected)
            {
                entry->fragmenting = 0;
                status = rdp_session_handle_dynamic_channel_message(session,
                                                                    entry,
                                                                    data_pdu.channel_id,
                                                                    data_pdu.channel_id_bytes,
                                                                    entry->fragment.data,
                                                                    entry->fragment.length);
                rdp_buffer_free(&entry->fragment);
                entry->fragment_expected = 0;
            }
        }
        else if (status == LIBRDP_STATUS_OK)
        {
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.drdynvc.compressed.data",
                                  "dvc_channel_id=%u name=%s compressed_len=%u decoded_len=%u",
                                  data_pdu.channel_id,
                                  entry->name,
                                  (unsigned)data_pdu.data_len,
                                  (unsigned)decoded.length);
            status = rdp_session_handle_dynamic_channel_message(session,
                                                                entry,
                                                                data_pdu.channel_id,
                                                                data_pdu.channel_id_bytes,
                                                                decoded.data,
                                                                decoded.length);
        }
        rdp_buffer_free(&decoded);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_CLOSE)
    {
        rdp_dynamic_channel_close_pdu close_pdu;
        rdp_session_dynamic_channel* entry = NULL;

        status = rdp_dynamic_channel_parse_close(channel_packet->payload, channel_packet->payload_len, &close_pdu);
        if (status != LIBRDP_STATUS_OK)
            return status;
        entry = rdp_session_dynamic_channel_find(session, close_pdu.channel_id);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.close",
                        "dvc_channel_id=%u name=%s",
                        close_pdu.channel_id,
                        entry ? entry->name : "");
        if (entry)
        {
            if (!rdp_session_dynamic_channel_is_internal(entry))
                rdp_session_emit_channel_close(session, entry);
            if (entry->channel_id == session->display_control_channel_id)
            {
                session->display_control_channel_id = 0;
                session->display_control_channel_id_bytes = 0;
                session->display_control_ready = 0;
                session->sent_desktop_width = 0;
                session->sent_desktop_height = 0;
                memset(&session->display_control_caps, 0, sizeof(session->display_control_caps));
            }
            if (entry->channel_id == session->core_input_channel_id)
            {
                session->core_input_channel_id = 0;
                session->core_input_channel_id_bytes = 0;
                session->core_input_ready = 0;
            }
            if (entry->channel_id == session->input_channel_id)
            {
                session->input_channel_id = 0;
                session->input_channel_id_bytes = 0;
                session->input_channel_ready = 0;
                session->input_channel_suspended = 0;
                session->input_channel_protocol_version = 0;
                session->input_channel_supported_features = 0;
            }
            if (entry->channel_id == session->audio_input_channel_id)
            {
                session->audio_input_channel_id = 0;
                session->audio_input_channel_id_bytes = 0;
                session->audio_input_ready = 0;
                session->audio_input_open = 0;
                session->audio_input_open_reply_sent = 0;
                session->audio_input_version = 0;
                session->audio_input_selected_format_count = 0;
                memset(session->audio_input_selected_formats, 0, sizeof(session->audio_input_selected_formats));
            }
            if (entry->channel_id == session->mouse_cursor_channel_id)
            {
                session->mouse_cursor_channel_id = 0;
                session->mouse_cursor_channel_id_bytes = 0;
                session->mouse_cursor_ready = 0;
                rdp_session_pointer_emit_default(session);
            }
            if (entry->channel_id == session->graphics_channel_id)
            {
                session->graphics_channel_id = 0;
                session->graphics_channel_id_bytes = 0;
                session->graphics_ready = 0;
                session->graphics_selected_version = 0;
                session->graphics_selected_flags = 0;
                session->graphics_frames_decoded = 0;
                rdp_graphics_decompressor_reset(&session->graphics_decompressor);
                rdp_clearcodec_context_reset(&session->clearcodec);
                rdp_session_graphics_surfaces_clear(session);
                rdp_session_graphics_cache_clear(session);
            }
            if (entry->channel_id == session->usb_redirection_channel_id)
                rdp_session_usb_redirection_reset(session);
            if (entry->channel_id == session->composited_channel_id)
                rdp_session_composited_reset(session);
            if (entry->channel_id == session->video_redirection_channel_id)
                rdp_session_video_redirection_reset(session);
            if (entry->channel_id == session->video_capture_control_channel_id ||
                entry->channel_id == session->video_capture_channel_id)
                rdp_session_video_capture_reset(session);
            rdp_session_dynamic_channel_clear_entry(entry);
        }
    }
    else
    {
        if (header.command == RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_REQUEST)
        {
            rdp_dynamic_channel_soft_sync_request request;
            rdp_buffer response;

            rdp_buffer_init(&response);
            status = rdp_dynamic_channel_parse_soft_sync_request(channel_packet->payload,
                                                                 channel_packet->payload_len,
                                                                 &request);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_dynamic_channel_write_soft_sync_response(&response, NULL, 0);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_write_channel_pdu(session,
                                                       session->dynamic_channel_id,
                                                       &response,
                                                       "client.drdynvc.soft_sync");
            rdp_buffer_free(&response);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.drdynvc.soft_sync",
                            "flags=%u tunnel_count=%u",
                            request.flags,
                            request.tunnel_count);
        }
        else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_RESPONSE)
        {
            rdp_dynamic_channel_soft_sync_response response;

            status = rdp_dynamic_channel_parse_soft_sync_response(channel_packet->payload,
                                                                  channel_packet->payload_len,
                                                                  &response);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.drdynvc.soft_sync_response",
                            "tunnel_count=%u",
                            response.tunnel_count);
        }
        else
        {
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.drdynvc.data",
                                  "command=%u payload_len=%u",
                                  header.command,
                                  (unsigned)channel_packet->payload_len);
        }
    }

    return status;
}

static librdp_status rdp_session_read_mcs_pdu(librdp_session* session,
                                              rdp_buffer* packet,
                                              const uint8_t** pdu,
                                              size_t* pdu_len,
                                              const char* event)
{
    rdp_tpkt parsed;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !packet || !pdu || !pdu_len || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_transport_read_tpkt(&session->transport, packet);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_trace_hexdump(event, packet->data, packet->length);
    status = rdp_tpkt_parse(packet->data, packet->length, &parsed);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_x224_parse_data(parsed.payload, parsed.payload_len, pdu, pdu_len);
}

static librdp_status rdp_session_read_fastpath_packet(librdp_session* session, rdp_buffer* packet)
{
    uint8_t header[3];
    uint16_t total = 0;
    size_t header_len = 2;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_free(packet);
    rdp_buffer_init(packet);

    status = rdp_transport_read_exact(&session->transport, header, 2);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if ((header[1] & 0x80u) != 0)
    {
        status = rdp_transport_read_exact(&session->transport, header + 2, 1);
        if (status != LIBRDP_STATUS_OK)
            return status;
        total = (uint16_t)(((uint16_t)(header[1] & 0x7fu) << 8) | header[2]);
        header_len = 3;
    }
    else
    {
        total = header[1];
    }
    if (total < header_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    status = rdp_buffer_append(packet, header, header_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_reserve(packet, total);
    if (status != LIBRDP_STATUS_OK)
        return status;
    packet->length = total;
    status = rdp_transport_read_exact(&session->transport, packet->data + header_len, (size_t)total - header_len);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_hexdump("rdp.fastpath.pdu", packet->data, packet->length);
    return status;
}

static librdp_status rdp_session_write_fastpath_header(rdp_buffer* buffer,
                                                       uint8_t first,
                                                       uint16_t length,
                                                       size_t header_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (header_len != 2u && header_len != 3u) || length < header_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u8(buffer, (uint8_t)(first & 0x3fu));
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header_len == 2u)
    {
        if (length > 0x7fu)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        return rdp_buffer_append_u8(buffer, (uint8_t)length);
    }

    status = rdp_buffer_append_u8(buffer, (uint8_t)(0x80u | ((length >> 8) & 0x7fu)));
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, (uint8_t)(length & 0xffu));
}

static librdp_status rdp_session_unwrap_fastpath_packet(librdp_session* session,
                                                        const rdp_buffer* packet,
                                                        rdp_buffer* decoded,
                                                        int* used_decoded)
{
    rdp_fastpath_header header;
    const uint8_t* signature = NULL;
    uint8_t* encrypted = NULL;
    uint16_t decoded_len = 0;
    size_t encrypted_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !packet || !decoded || !used_decoded)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    *used_decoded = 0;
    status = rdp_fastpath_parse_header(packet->data, packet->length, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if ((header.security_flags & RDP_FASTPATH_OUTPUT_ENCRYPTED) == 0)
    {
        if (header.security_flags != 0)
            return LIBRDP_STATUS_UNSUPPORTED;
        return LIBRDP_STATUS_OK;
    }
    if (!session->standard_security_active || header.length < header.header_length + 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    decoded_len = (uint16_t)(header.length - 8u);
    signature = packet->data + header.header_length;
    encrypted = packet->data + header.header_length + 8u;
    encrypted_len = header.length - header.header_length - 8u;

    status = rdp_session_write_fastpath_header(decoded, packet->data[0], decoded_len, header.header_length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(decoded, encrypted, encrypted_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_decrypt_payload(&session->standard_security,
                                              decoded->data + header.header_length,
                                              encrypted_len);
    if (status == LIBRDP_STATUS_OK &&
        (header.security_flags & RDP_FASTPATH_OUTPUT_SECURE_CHECKSUM) == 0)
    {
        uint8_t expected[8];
        status = rdp_security_mac_signature(&session->standard_security,
                                            decoded->data + header.header_length,
                                            encrypted_len,
                                            expected);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (memcmp(signature, expected, sizeof(expected)) != 0)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.fastpath.signature.mismatch",
                            "payload_len=%u",
                            (unsigned)encrypted_len);
    }
    if (status == LIBRDP_STATUS_OK)
        *used_decoded = 1;
    return status;
}

static librdp_status rdp_session_read_credssp_ts_request(librdp_session* session, rdp_buffer* packet, int timeout_ms)
{
    uint8_t header[6];
    uint8_t first_len = 0;
    size_t header_len = 0;
    size_t content_len = 0;
    size_t i = 0;
    short revents = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !packet || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_free(packet);
    rdp_buffer_init(packet);

    status = rdp_transport_wait(&session->transport, timeout_ms, POLLIN, &revents);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if ((revents & POLLIN) == 0)
        return LIBRDP_STATUS_TIMEOUT;

    status = rdp_transport_read_exact(&session->transport, header, 2);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header[0] != 0x30)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    first_len = header[1];
    header_len = 2;
    if ((first_len & 0x80u) == 0)
    {
        content_len = first_len;
    }
    else
    {
        uint8_t count = (uint8_t)(first_len & 0x7fu);
        if (count == 0 || count > 4)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        status = rdp_transport_read_exact(&session->transport, header + 2, count);
        if (status != LIBRDP_STATUS_OK)
            return status;
        header_len += count;
        for (i = 0; i < count; i++)
            content_len = (content_len << 8) | header[2u + i];
    }
    if (content_len == 0 || content_len > 1024u * 1024u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_buffer_append(packet, header, header_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_reserve(packet, header_len + content_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    packet->length = header_len + content_len;
    return rdp_transport_read_exact(&session->transport, packet->data + header_len, content_len);
}

static librdp_status rdp_session_apply_bitmap_update(librdp_session* session, const rdp_bitmap_update* update)
{
    uint16_t i = 0;

    if (!session || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    for (i = 0; i < update->count; i++)
    {
        const rdp_bitmap_rect* rect = &update->rects[i];
        size_t stride = 0;
        rdp_buffer pixels;
        librdp_status status = LIBRDP_STATUS_OK;

        rdp_buffer_init(&pixels);
        status = rdp_bitmap_decode_rect_bgra32(rect, &pixels, &stride);
        if (status == LIBRDP_STATUS_OK)
            status = librdp_surface_blit_bgra32(session->surface,
                                                rect->dest_left,
                                                rect->dest_top,
                                                rect->width,
                                                rect->height,
                                                pixels.data,
                                                stride);
        rdp_buffer_free(&pixels);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_session_emit_surface_invalidated(session, rect->dest_left, rect->dest_top, rect->width, rect->height);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.active.framebuffer.blit",
                        "x=%u y=%u width=%u height=%u",
                        rect->dest_left,
                        rect->dest_top,
                        rect->width,
                        rect->height);
    }
    return LIBRDP_STATUS_OK;
}

static void rdp_session_fastpath_fragment_reset(librdp_session* session)
{
    if (!session)
        return;
    session->fastpath_fragmenting = 0;
    session->fastpath_fragment_update_code = 0;
    rdp_buffer_free(&session->fastpath_fragment);
    rdp_buffer_init(&session->fastpath_fragment);
}

static librdp_status rdp_session_fastpath_payload(librdp_session* session,
                                                  const rdp_fastpath_update* update,
                                                  const uint8_t** data,
                                                  size_t* data_len,
                                                  int* complete,
                                                  int* from_fragment)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !update || !data || !data_len || !complete || !from_fragment)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *data = NULL;
    *data_len = 0;
    *complete = 0;
    *from_fragment = 0;
    if (update->compression != 0)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (update->fragmentation == RDP_FASTPATH_FRAGMENT_SINGLE)
    {
        if (session->fastpath_fragmenting)
            rdp_session_fastpath_fragment_reset(session);
        *data = update->data;
        *data_len = update->data_len;
        *complete = 1;
        return LIBRDP_STATUS_OK;
    }
    if (update->data_len > RDP_SESSION_MAX_FASTPATH_FRAGMENT ||
        session->fastpath_fragment.length > RDP_SESSION_MAX_FASTPATH_FRAGMENT - update->data_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (update->fragmentation == RDP_FASTPATH_FRAGMENT_FIRST)
    {
        rdp_session_fastpath_fragment_reset(session);
        status = rdp_buffer_append(&session->fastpath_fragment, update->data, update->data_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->fastpath_fragmenting = 1;
        session->fastpath_fragment_update_code = update->update_code;
        rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                              RDP_TRACE_LEVEL_DEBUG,
                              "rdp.fastpath.fragment.start",
                              "code=%u received=%u",
                              update->update_code,
                              (unsigned)session->fastpath_fragment.length);
        return LIBRDP_STATUS_OK;
    }
    if (update->fragmentation != RDP_FASTPATH_FRAGMENT_NEXT &&
        update->fragmentation != RDP_FASTPATH_FRAGMENT_LAST)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!session->fastpath_fragmenting || session->fastpath_fragment_update_code != update->update_code)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_buffer_append(&session->fastpath_fragment, update->data, update->data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "rdp.fastpath.fragment.data",
                          "code=%u fragmentation=%u received=%u",
                          update->update_code,
                          update->fragmentation,
                          (unsigned)session->fastpath_fragment.length);
    if (update->fragmentation == RDP_FASTPATH_FRAGMENT_NEXT)
        return LIBRDP_STATUS_OK;
    *data = session->fastpath_fragment.data;
    *data_len = session->fastpath_fragment.length;
    *complete = 1;
    *from_fragment = 1;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_process_fastpath_packet(librdp_session* session, const rdp_buffer* packet)
{
    rdp_buffer decoded;
    const rdp_buffer* parse_packet = packet;
    rdp_fastpath_update_list updates;
    uint16_t i = 0;
    int used_decoded = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&decoded);
    status = rdp_session_unwrap_fastpath_packet(session, packet, &decoded, &used_decoded);
    if (status == LIBRDP_STATUS_OK && used_decoded)
        parse_packet = &decoded;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_fastpath_parse_updates(parse_packet->data, parse_packet->length, &updates);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&decoded);
        return status;
    }

    for (i = 0; i < updates.count; i++)
    {
        const rdp_fastpath_update* update = &updates.updates[i];

        rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                              RDP_TRACE_LEVEL_DEBUG,
                              "rdp.fastpath.update",
                              "code=%u fragmentation=%u compression=%u payload_len=%u",
                              update->update_code,
                              update->fragmentation,
                              update->compression,
                              (unsigned)update->data_len);
        if (update->update_code == RDP_FASTPATH_UPDATE_BITMAP)
        {
            rdp_bitmap_update bitmap;
            const uint8_t* update_data = NULL;
            size_t update_len = 0;
            int complete = 0;
            int from_fragment = 0;

            status = rdp_session_fastpath_payload(session, update, &update_data, &update_len, &complete, &from_fragment);
            if (status == LIBRDP_STATUS_UNSUPPORTED)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.fastpath.update.unsupported",
                                "code=%u fragmentation=%u compression=%u payload_len=%u",
                                update->update_code,
                                update->fragmentation,
                                update->compression,
                                (unsigned)update->data_len);
            }
            else if (status != LIBRDP_STATUS_OK)
            {
                goto out;
            }
            else if (complete)
            {
                status = rdp_bitmap_parse_fastpath_update(update_data, update_len, &bitmap);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_apply_bitmap_update(session, &bitmap);
                if (from_fragment)
                    rdp_session_fastpath_fragment_reset(session);
                if (status != LIBRDP_STATUS_OK)
                    goto out;
                rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.fastpath.bitmap_update", "rectangles=%u", bitmap.count);
            }
        }
        else if (update->update_code == RDP_FASTPATH_UPDATE_POINTER_NULL ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_DEFAULT ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_POSITION ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_COLOR ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_CACHED ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_NEW ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_LARGE)
        {
            rdp_pointer_update pointer;
            const uint8_t* update_data = NULL;
            size_t update_len = 0;
            int complete = 0;
            int from_fragment = 0;

            status = rdp_session_fastpath_payload(session, update, &update_data, &update_len, &complete, &from_fragment);
            if (status == LIBRDP_STATUS_UNSUPPORTED)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.fastpath.pointer.unsupported",
                                "code=%u fragmentation=%u compression=%u payload_len=%u",
                                update->update_code,
                                update->fragmentation,
                                update->compression,
                                (unsigned)update->data_len);
            }
            else if (status != LIBRDP_STATUS_OK)
            {
                goto out;
            }
            else if (complete)
            {
                status = rdp_pointer_parse_fastpath(update->update_code, update_data, update_len, &pointer);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_pointer_apply_update(session, &pointer);
                if (from_fragment)
                    rdp_session_fastpath_fragment_reset(session);
                if (status != LIBRDP_STATUS_OK)
                    goto out;
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.fastpath.pointer",
                                "code=%u kind=%u cache_index=%u width=%u height=%u",
                                update->update_code,
                                pointer.kind,
                                pointer.cache_index,
                                pointer.width,
                                pointer.height);
            }
        }
    }

out:
    rdp_buffer_free(&decoded);
    return status;
}

librdp_session* librdp_session_new(const librdp_settings* settings)
{
    librdp_session* session = NULL;

    if (!settings)
        return NULL;

    session = (librdp_session*)calloc(1, sizeof(*session));
    if (!session)
        return NULL;

    session->settings = librdp_settings_clone(settings);
    if (!session->settings)
    {
        free(session);
        return NULL;
    }

    session->surface = librdp_surface_new(librdp_settings_width(session->settings),
                                          librdp_settings_height(session->settings),
                                          LIBRDP_PIXEL_FORMAT_BGRA32);
    if (!session->surface)
    {
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }

    session->state = LIBRDP_SESSION_IDLE;
    session->requested_desktop_width = librdp_settings_width(session->settings);
    session->requested_desktop_height = librdp_settings_height(session->settings);
    rdp_transport_init(&session->transport);
    rdp_buffer_init(&session->audio_output_fragment);
    rdp_buffer_init(&session->audio_output_pending_data);
    rdp_buffer_init(&session->device_redirection_fragment);
    rdp_buffer_init(&session->remote_programs_fragment);
    rdp_buffer_init(&session->fastpath_fragment);
    rdp_graphics_decompressor_init(&session->graphics_decompressor);
    rdp_clearcodec_context_init(&session->clearcodec);
    rdp_composited_render_tree_init(&session->composited_tree);
    rdp_session_redirected_files_clear(session);
    session->avc = rdp_avc_decoder_new();
    if (!session->avc)
    {
        rdp_clearcodec_context_free(&session->clearcodec);
        rdp_graphics_decompressor_free(&session->graphics_decompressor);
        rdp_transport_close(&session->transport);
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

void librdp_session_free(librdp_session* session)
{
    if (!session)
        return;
    (void)librdp_session_disconnect(session);
    rdp_session_smartcard_reset(session);
    rdp_session_usb_redirection_reset(session);
    rdp_session_composited_reset(session);
    rdp_session_video_redirection_reset(session);
    rdp_session_video_capture_reset(session);
    rdp_session_redirected_files_clear(session);
    rdp_session_dynamic_channels_clear(session);
    rdp_session_clipboard_clear(session);
    rdp_session_clipboard_local_clear(session);
    rdp_buffer_free(&session->audio_output_fragment);
    rdp_buffer_free(&session->audio_output_pending_data);
    rdp_buffer_free(&session->device_redirection_fragment);
    rdp_buffer_free(&session->pnp_redirection_fragment);
    rdp_buffer_free(&session->remote_programs_fragment);
    rdp_buffer_free(&session->fastpath_fragment);
    rdp_session_graphics_surfaces_clear(session);
    rdp_session_graphics_cache_clear(session);
    rdp_session_pointer_cache_clear(session);
    rdp_avc_decoder_free(session->avc);
    rdp_clearcodec_context_free(&session->clearcodec);
    rdp_graphics_decompressor_free(&session->graphics_decompressor);
    rdp_security_standard_clear(&session->standard_security);
    rdp_transport_close(&session->transport);
    librdp_surface_free(session->surface);
    librdp_settings_free(session->settings);
    free(session);
}

void librdp_session_set_event_callback(librdp_session* session, librdp_event_callback callback, void* user_data)
{
    if (!session)
        return;
    session->callback = callback;
    session->callback_data = user_data;
}

librdp_status librdp_session_connect(librdp_session* session)
{
    rdp_buffer x224;
    rdp_buffer gcc_blocks;
    rdp_buffer gcc_request;
    rdp_buffer mcs;
    rdp_buffer security_payload;
    rdp_buffer security_data;
    rdp_buffer server_random;
    rdp_buffer server_certificate;
    rdp_buffer request;
    rdp_buffer reply;
    rdp_tpkt packet;
    rdp_x224_connection_confirm confirm;
    rdp_mcs_connect_response mcs_response;
    rdp_gcc_conference_response gcc_response;
    rdp_gcc_server_data server_data;
    rdp_mcs_attach_user_confirm attach_confirm;
    rdp_credssp_state credssp_state = RDP_CREDSSP_DISABLED;
    const uint8_t* mcs_pdu = NULL;
    size_t mcs_pdu_len = 0;
    uint32_t protocols = 0;
    uint32_t selected_protocol = 0;
    uint32_t server_encryption_method = 0;
    uint32_t server_encryption_level = 0;
    int standard_security_ready = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_IDLE && session->state != LIBRDP_SESSION_CLOSED &&
        session->state != LIBRDP_SESSION_FAILED)
        return LIBRDP_STATUS_STATE;
    if (!librdp_settings_target(session->settings))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_trace_event(RDP_TRACE_CLIENT, "client.connect.start", "target=%s port=%u width=%u height=%u",
                    librdp_settings_target(session->settings),
                    (unsigned)librdp_settings_port(session->settings),
                    librdp_settings_width(session->settings),
                    librdp_settings_height(session->settings));

    rdp_buffer_init(&x224);
    rdp_buffer_init(&gcc_blocks);
    rdp_buffer_init(&gcc_request);
    rdp_buffer_init(&mcs);
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&security_data);
    rdp_buffer_init(&server_random);
    rdp_buffer_init(&server_certificate);
    rdp_buffer_init(&request);
    rdp_buffer_init(&reply);

    rdp_session_set_state(session, LIBRDP_SESSION_CONNECTING);
    rdp_security_standard_clear(&session->standard_security);
    session->standard_security_active = 0;
    session->share_id = 0;
    session->dynamic_channel_id = 0;
    session->clipboard_channel_id = 0;
    rdp_session_clipboard_clear(session);
    session->audio_output_channel_id = 0;
    session->audio_output_ready = 0;
    session->audio_output_fragmenting = 0;
    session->audio_output_pending_wave = 0;
    session->audio_output_fragment_expected = 0;
    session->audio_output_server_version = 0;
    session->audio_output_client_version = 0;
    session->audio_output_pending_format_no = 0;
    session->audio_output_pending_timestamp = 0;
    session->audio_output_pending_expected_len = 0;
    session->audio_output_pending_block_no = 0;
    session->audio_output_selected_format_count = 0;
    memset(session->audio_output_selected_formats, 0, sizeof(session->audio_output_selected_formats));
    rdp_buffer_free(&session->audio_output_fragment);
    rdp_buffer_init(&session->audio_output_fragment);
    rdp_buffer_free(&session->audio_output_pending_data);
    rdp_buffer_init(&session->audio_output_pending_data);
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
    session->pnp_redirection_fragment_expected = 0;
    rdp_buffer_free(&session->pnp_redirection_fragment);
    rdp_buffer_init(&session->pnp_redirection_fragment);
    session->remote_programs_channel_id = 0;
    session->remote_programs_ready = 0;
    session->remote_programs_fragmenting = 0;
    session->remote_programs_exec_sent = 0;
    session->remote_programs_fragment_expected = 0;
    rdp_buffer_free(&session->remote_programs_fragment);
    rdp_buffer_init(&session->remote_programs_fragment);
    session->fastpath_fragmenting = 0;
    session->fastpath_fragment_update_code = 0;
    rdp_buffer_free(&session->fastpath_fragment);
    rdp_buffer_init(&session->fastpath_fragment);
    session->core_input_channel_id = 0;
    session->core_input_channel_id_bytes = 0;
    session->core_input_ready = 0;
    session->input_channel_id = 0;
    session->input_channel_id_bytes = 0;
    session->input_channel_ready = 0;
    session->input_channel_suspended = 0;
    session->input_channel_protocol_version = 0;
    session->input_channel_supported_features = 0;
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
    rdp_session_composited_reset(session);
    rdp_session_video_redirection_reset(session);
    rdp_session_video_capture_reset(session);
    rdp_session_usb_redirection_reset(session);
    rdp_graphics_decompressor_reset(&session->graphics_decompressor);
    rdp_clearcodec_context_reset(&session->clearcodec);
    rdp_session_graphics_surfaces_clear(session);
    rdp_session_graphics_cache_clear(session);
    rdp_session_pointer_cache_clear(session);
    rdp_session_dynamic_channels_clear(session);
    rdp_session_redirected_files_clear(session);

    status = rdp_transport_connect(&session->transport,
                                   librdp_settings_target(session->settings),
                                   librdp_settings_port(session->settings),
                                   5000);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    protocols = rdp_security_protocol_mask(librdp_settings_security_mode(session->settings));
    rdp_trace_event(RDP_TRACE_PROTOCOL, "x224.negotiation.start", "protocols=%u", protocols);
    status = rdp_x224_build_connection_request(&x224, librdp_settings_username(session->settings), protocols);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    status = rdp_tpkt_write(&request, x224.data, x224.length);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_hexdump("x224.negotiation.request", request.data, request.length);
    status = rdp_transport_write_all(&session->transport, request.data, request.length);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    status = rdp_transport_read_tpkt(&session->transport, &reply);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_hexdump("x224.negotiation.response", reply.data, reply.length);
    status = rdp_tpkt_parse(reply.data, reply.length, &packet);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    status = rdp_x224_parse_connection_confirm(packet.payload, packet.payload_len, &confirm);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    if (confirm.negotiation.present && confirm.negotiation.failure)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL, "x224.negotiation.failed", "code=%u", confirm.negotiation.failure_code);
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto fail;
    }
    if (confirm.negotiation.present && !rdp_security_protocol_supported(confirm.negotiation.selected_protocol))
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL, "x224.negotiation.unsupported", "selected_protocol=%u",
                        confirm.negotiation.selected_protocol);
        status = LIBRDP_STATUS_UNSUPPORTED;
        goto fail;
    }

    rdp_trace_event(RDP_TRACE_PROTOCOL, "x224.negotiation.done", "selected_protocol=%u",
                    confirm.negotiation.present ? confirm.negotiation.selected_protocol : 0);
    selected_protocol = confirm.negotiation.present ? confirm.negotiation.selected_protocol : 0;
    if (selected_protocol == RDP_X224_PROTOCOL_TLS || selected_protocol == RDP_X224_PROTOCOL_NLA)
    {
        status = rdp_transport_start_tls(&session->transport, librdp_settings_target(session->settings));
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        rdp_trace_event(RDP_TRACE_PROTOCOL, "transport.tls.ready", "selected_protocol=%u", selected_protocol);
    }
    if (selected_protocol == RDP_X224_PROTOCOL_NLA)
    {
        rdp_buffer credssp_request;
        rdp_buffer credssp_reply;
        rdp_buffer ntlm_negotiate;
        rdp_buffer spnego_negotiate;
        rdp_buffer ntlm_authenticate;
        rdp_buffer spnego_authenticate;
        rdp_buffer tls_public_key;
        rdp_buffer pub_key_auth;
        rdp_buffer auth_info;
        rdp_credssp_ts_request ts_response;
        rdp_credssp_ts_request auth_response;
        rdp_credssp_ts_request pub_key_response;
        rdp_ntlm_authenticate_result ntlm_auth_result;
        rdp_ntlm_security_context ntlm_security;
        uint8_t client_nonce[32];

        rdp_buffer_init(&credssp_request);
        rdp_buffer_init(&credssp_reply);
        rdp_buffer_init(&ntlm_negotiate);
        rdp_buffer_init(&spnego_negotiate);
        rdp_buffer_init(&ntlm_authenticate);
        rdp_buffer_init(&spnego_authenticate);
        rdp_buffer_init(&tls_public_key);
        rdp_buffer_init(&pub_key_auth);
        rdp_buffer_init(&auth_info);
        memset(&ntlm_auth_result, 0, sizeof(ntlm_auth_result));
        memset(&ntlm_security, 0, sizeof(ntlm_security));
        memset(client_nonce, 0, sizeof(client_nonce));
        rdp_trace_event(RDP_TRACE_PROTOCOL, "credssp.nla.start", "state=begin");
        status = rdp_credssp_begin(true, &credssp_state);
        if (status == LIBRDP_STATUS_OK)
            status = RAND_bytes(client_nonce, (int)sizeof(client_nonce)) == 1 ? LIBRDP_STATUS_OK
                                                                              : LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_transport_get_tls_public_key(&session->transport, &tls_public_key);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_credssp_write_ntlm_negotiate(&ntlm_negotiate,
                                                      "librdp",
                                                      librdp_settings_domain(session->settings));
        if (status == LIBRDP_STATUS_OK)
            status = rdp_credssp_write_spnego_ntlm_negotiate(&spnego_negotiate,
                                                             ntlm_negotiate.data,
                                                             ntlm_negotiate.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_credssp_write_ts_request(&credssp_request,
                                                  6,
                                                  spnego_negotiate.data,
                                                  spnego_negotiate.length,
                                                  NULL,
                                                  0,
                                                  NULL,
                                                  0,
                                                  client_nonce,
                                                  sizeof(client_nonce));
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "credssp.nla.negotiate",
                            "token_len=%u client_nonce_len=%u public_key_len=%u",
                            (unsigned)credssp_request.length,
                            (unsigned)sizeof(client_nonce),
                            (unsigned)tls_public_key.length);
            status = rdp_transport_write_all(&session->transport, credssp_request.data, credssp_request.length);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_read_credssp_ts_request(session, &credssp_reply, 5000);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_credssp_parse_ts_request(credssp_reply.data, credssp_reply.length, &ts_response);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "credssp.nla.challenge",
                            "version=%u token_len=%u error=%u",
                            ts_response.version,
                            (unsigned)ts_response.nego_token_len,
                            ts_response.has_error_code ? ts_response.error_code : 0);
        if (status == LIBRDP_STATUS_OK && ts_response.nego_token_len > 0)
        {
            const uint8_t* ntlm_token = NULL;
            size_t ntlm_token_len = 0;
            rdp_ntlm_challenge ntlm_challenge;

            status = rdp_credssp_extract_ntlm_challenge(ts_response.nego_token,
                                                        ts_response.nego_token_len,
                                                        &ntlm_token,
                                                        &ntlm_token_len);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_parse_ntlm_challenge(ntlm_token, ntlm_token_len, &ntlm_challenge);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.ntlm.challenge",
                                "flags=%u target_name_len=%u target_info_len=%u",
                                ntlm_challenge.flags,
                                (unsigned)ntlm_challenge.target_name_len,
                                (unsigned)ntlm_challenge.target_info_len);
            if (status == LIBRDP_STATUS_OK &&
                (!librdp_settings_username(session->settings) || !rdp_settings_password_internal(session->settings)))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_write_ntlm_authenticate(&ntlm_authenticate,
                                                             &ntlm_challenge,
                                                             librdp_settings_username(session->settings),
                                                             rdp_settings_password_internal(session->settings),
                                                             librdp_settings_domain(session->settings),
                                                             "librdp",
                                                             0,
                                                             NULL,
                                                             NULL,
                                                             &ntlm_auth_result);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_write_spnego_ntlm_authenticate(&spnego_authenticate,
                                                                    ntlm_authenticate.data,
                                                                    ntlm_authenticate.length);
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&credssp_request);
                rdp_buffer_init(&credssp_request);
                status = rdp_credssp_write_ts_request(&credssp_request,
                                                      ts_response.version ? ts_response.version : 6,
                                                      spnego_authenticate.data,
                                                      spnego_authenticate.length,
                                                      NULL,
                                                      0,
                                                      NULL,
                                                      0,
                                                      client_nonce,
                                                      sizeof(client_nonce));
            }
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.authenticate",
                                "token_len=%u flags=%u",
                                (unsigned)credssp_request.length,
                                ntlm_auth_result.flags);
                status = rdp_transport_write_all(&session->transport, credssp_request.data, credssp_request.length);
            }
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_read_credssp_ts_request(session, &credssp_reply, 5000);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_parse_ts_request(credssp_reply.data, credssp_reply.length, &auth_response);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.authenticate_response",
                                "version=%u token_len=%u auth_info_len=%u pub_key_auth_len=%u error=%u",
                                auth_response.version,
                                (unsigned)auth_response.nego_token_len,
                                (unsigned)auth_response.auth_info_len,
                                (unsigned)auth_response.pub_key_auth_len,
                                auth_response.has_error_code ? auth_response.error_code : 0);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_ntlm_security_init(&ntlm_security, &ntlm_auth_result);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_encrypt_public_key_hash(&ntlm_security,
                                                             client_nonce,
                                                             sizeof(client_nonce),
                                                             tls_public_key.data,
                                                             tls_public_key.length,
                                                             &pub_key_auth);
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&credssp_request);
                rdp_buffer_init(&credssp_request);
                status = rdp_credssp_write_ts_request(&credssp_request,
                                                      auth_response.version ? auth_response.version : 6,
                                                      NULL,
                                                      0,
                                                      NULL,
                                                      0,
                                                      pub_key_auth.data,
                                                      pub_key_auth.length,
                                                      client_nonce,
                                                      sizeof(client_nonce));
            }
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.pubkey",
                                "token_len=%u pub_key_auth_len=%u",
                                (unsigned)credssp_request.length,
                                (unsigned)pub_key_auth.length);
                status = rdp_transport_write_all(&session->transport, credssp_request.data, credssp_request.length);
            }
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_read_credssp_ts_request(session, &credssp_reply, 5000);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_parse_ts_request(credssp_reply.data, credssp_reply.length, &pub_key_response);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.pubkey_response",
                                "version=%u token_len=%u auth_info_len=%u pub_key_auth_len=%u error=%u",
                                pub_key_response.version,
                                (unsigned)pub_key_response.nego_token_len,
                                (unsigned)pub_key_response.auth_info_len,
                                (unsigned)pub_key_response.pub_key_auth_len,
                                pub_key_response.has_error_code ? pub_key_response.error_code : 0);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_verify_public_key_hash(&ntlm_security,
                                                            client_nonce,
                                                            sizeof(client_nonce),
                                                            tls_public_key.data,
                                                            tls_public_key.length,
                                                            pub_key_response.pub_key_auth,
                                                            pub_key_response.pub_key_auth_len);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL, "credssp.nla.pubkey.verified", "pub_key_auth_len=%u",
                                (unsigned)pub_key_response.pub_key_auth_len);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_encrypt_password_credentials(&ntlm_security,
                                                                  librdp_settings_domain(session->settings),
                                                                  librdp_settings_username(session->settings),
                                                                  rdp_settings_password_internal(session->settings),
                                                                  &auth_info);
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&credssp_request);
                rdp_buffer_init(&credssp_request);
                status = rdp_credssp_write_ts_request(&credssp_request,
                                                      pub_key_response.version ? pub_key_response.version : 6,
                                                      NULL,
                                                      0,
                                                      auth_info.data,
                                                      auth_info.length,
                                                      NULL,
                                                      0,
                                                      client_nonce,
                                                      sizeof(client_nonce));
            }
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.credentials",
                                "token_len=%u auth_info_len=%u",
                                (unsigned)credssp_request.length,
                                (unsigned)auth_info.length);
                status = rdp_transport_write_all(&session->transport, credssp_request.data, credssp_request.length);
            }
        }
        rdp_buffer_free(&auth_info);
        rdp_buffer_free(&pub_key_auth);
        rdp_buffer_free(&tls_public_key);
        rdp_buffer_free(&spnego_authenticate);
        rdp_buffer_free(&ntlm_authenticate);
        rdp_buffer_free(&spnego_negotiate);
        rdp_buffer_free(&ntlm_negotiate);
        rdp_buffer_free(&credssp_reply);
        rdp_buffer_free(&credssp_request);
        OPENSSL_cleanse(&ntlm_security, sizeof(ntlm_security));
        OPENSSL_cleanse(client_nonce, sizeof(client_nonce));
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL, "credssp.nla.failed", "status=%d", (int)status);
            goto fail;
        }
        credssp_state = RDP_CREDSSP_COMPLETE;
        rdp_trace_event(RDP_TRACE_PROTOCOL, "credssp.nla.done", "state=%u", (unsigned)credssp_state);
    }

    {
        rdp_gcc_client_config config;
        memset(&config, 0, sizeof(config));
        config.desktop_width = (uint16_t)librdp_settings_width(session->settings);
        config.desktop_height = (uint16_t)librdp_settings_height(session->settings);
        config.requested_protocols = selected_protocol;
        config.client_version = RDP_GCC_CLIENT_VERSION_10_12;
        config.early_capability_flags = RDP_GCC_EARLY_SUPPORT_ERRINFO | RDP_GCC_EARLY_WANT_32BPP |
                                        RDP_GCC_EARLY_SUPPORT_STATUSINFO |
                                        RDP_GCC_EARLY_SUPPORT_MONITOR_LAYOUT |
                                        RDP_GCC_EARLY_SUPPORT_NETCHAR_AUTODETECT |
                                        RDP_GCC_EARLY_SUPPORT_DYNVC_GFX;
        config.supported_color_depths = RDP_GCC_SUPPORTED_COLOR_DEPTHS_32BPP;
        config.connection_type = RDP_GCC_CONNECTION_TYPE_LAN;
        config.desktop_physical_width = rdp_session_pixels_to_mm(config.desktop_width);
        config.desktop_physical_height = rdp_session_pixels_to_mm(config.desktop_height);
        config.desktop_scale_factor = 100;
        config.device_scale_factor = 100;
        config.client_name = "librdp";
        config.enable_dynamic_channels = 1;
        config.enable_clipboard = 1;
        config.enable_audio_output =
            librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_AUDIO_OUTPUT) ? 1u : 0u;
        config.enable_device_redirection =
            (librdp_settings_drive_count(session->settings) > 0 ||
             librdp_settings_printer_count(session->settings) > 0 ||
             librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_SMARTCARD) ||
             librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_USB)) ?
                1u :
                0u;
        config.enable_pnp_redirection =
            librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_PNP) ? 1u : 0u;
        config.enable_remote_programs =
            librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_RAIL) ? 1u : 0u;

        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "mcs.connect.initial",
                        "width=%u height=%u selected_protocol=%u dynamic_channels=%u audio_output=%u device_redirection=%u pnp=%u remote_programs=%u early_capability_flags=%u",
                        (unsigned)config.desktop_width,
                        (unsigned)config.desktop_height,
                        config.requested_protocols,
                        (unsigned)config.enable_dynamic_channels,
                        (unsigned)config.enable_audio_output,
                        (unsigned)config.enable_device_redirection,
                        (unsigned)config.enable_pnp_redirection,
                        (unsigned)config.enable_remote_programs,
                        (unsigned)config.early_capability_flags);
        status = rdp_gcc_write_client_data_blocks(&gcc_blocks, &config);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        status = rdp_gcc_write_conference_create_request(&gcc_request, gcc_blocks.data, gcc_blocks.length);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        status = rdp_mcs_write_connect_initial(&mcs, gcc_request.data, gcc_request.length);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }

    rdp_buffer_free(&request);
    rdp_buffer_init(&request);
    status = rdp_session_write_mcs_pdu(session, &mcs, "mcs.connect.initial", 1);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    rdp_buffer_free(&reply);
    rdp_buffer_init(&reply);
    status = rdp_session_read_mcs_pdu(session, &reply, &mcs_pdu, &mcs_pdu_len, "mcs.connect.response");
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    status = rdp_mcs_parse_connect_response(mcs_pdu, mcs_pdu_len, &mcs_response);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    if (!mcs_response.has_result || mcs_response.result != 0)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.connect.response.failed", "result=%u", mcs_response.result);
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto fail;
    }
    rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.connect.response", "result=%u", mcs_response.result);
    if (mcs_response.user_data_len > 0)
    {
        status = rdp_gcc_parse_conference_create_response(mcs_response.user_data,
                                                          mcs_response.user_data_len,
                                                          &gcc_response);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        if (gcc_response.result != 0)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL, "gcc.conference.response.failed", "result=%u", gcc_response.result);
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            goto fail;
        }
        status = rdp_gcc_parse_server_data_blocks(gcc_response.user_data, gcc_response.user_data_len, &server_data);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        server_encryption_method = server_data.encryption_method;
        server_encryption_level = server_data.encryption_level;
        if (server_data.server_random_len > 0)
        {
            status = rdp_buffer_append(&server_random, server_data.server_random, server_data.server_random_len);
            if (status != LIBRDP_STATUS_OK)
                goto fail;
        }
        if (server_data.server_certificate_len > 0)
        {
            status = rdp_buffer_append(&server_certificate,
                                       server_data.server_certificate,
                                       server_data.server_certificate_len);
            if (status != LIBRDP_STATUS_OK)
                goto fail;
        }
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "gcc.conference.response",
                        "node_id=%u tag=%u user_data_len=%u",
                        gcc_response.node_id,
                        gcc_response.tag,
                        (unsigned)gcc_response.user_data_len);
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "gcc.server.core",
                        "version=%u requested_protocols=%u early_capability_flags=%u",
                        server_data.version,
                        server_data.requested_protocols,
                        server_data.early_capability_flags);
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "gcc.server.security",
                        "encryption_method=%u encryption_level=%u random_len=%u certificate_len=%u",
                        server_data.encryption_method,
                        server_data.encryption_level,
                        server_data.server_random_len,
                        server_data.server_certificate_len);
        if (server_data.has_network)
        {
            uint16_t channel_index = 0;
            uint8_t audio_output_enabled =
                librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_AUDIO_OUTPUT) ? 1u : 0u;
            uint8_t device_redirection_enabled =
                (librdp_settings_drive_count(session->settings) > 0 ||
                 librdp_settings_printer_count(session->settings) > 0 ||
                 librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_SMARTCARD) ||
                 librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_USB)) ?
                    1u :
                    0u;
            uint8_t pnp_redirection_enabled =
                librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_PNP) ? 1u : 0u;
            uint8_t remote_programs_enabled =
                librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_RAIL) ? 1u : 0u;

            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "gcc.server.network",
                            "mcs_channel_id=%u channel_count=%u",
                            server_data.mcs_channel_id,
                            server_data.channel_count);
            if (server_data.channel_count > channel_index)
            {
                session->dynamic_channel_id = server_data.channel_ids[channel_index++];
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.drdynvc.channel",
                                "channel_id=%u",
                                session->dynamic_channel_id);
            }
            if (server_data.channel_count > channel_index)
            {
                session->clipboard_channel_id = server_data.channel_ids[channel_index++];
                rdp_session_clipboard_clear(session);
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.clipboard.channel",
                                "channel_id=%u",
                                session->clipboard_channel_id);
            }
            if (audio_output_enabled && server_data.channel_count > channel_index)
            {
                session->audio_output_channel_id = server_data.channel_ids[channel_index++];
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rdpsnd.channel",
                                "channel_id=%u",
                                session->audio_output_channel_id);
            }
            if (device_redirection_enabled && server_data.channel_count > channel_index)
            {
                session->device_redirection_channel_id = server_data.channel_ids[channel_index++];
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rdpdr.channel",
                                "channel_id=%u",
                                session->device_redirection_channel_id);
            }
            if (pnp_redirection_enabled && server_data.channel_count > channel_index)
            {
                session->pnp_redirection_channel_id = server_data.channel_ids[channel_index++];
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.pnp.channel",
                                "channel_id=%u",
                                session->pnp_redirection_channel_id);
            }
            if (remote_programs_enabled && server_data.channel_count > channel_index)
            {
                session->remote_programs_channel_id = server_data.channel_ids[channel_index++];
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rail.channel",
                                "channel_id=%u apps=%u",
                                session->remote_programs_channel_id,
                                librdp_settings_rail_app_count(session->settings));
            }
        }
    }

    rdp_buffer_free(&mcs);
    rdp_buffer_init(&mcs);
    status = rdp_mcs_write_erect_domain_request(&mcs);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.erect_domain.request", "sub_height=0 sub_interval=0");
    status = rdp_session_write_mcs_pdu(session, &mcs, "mcs.erect_domain.request", 1);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    rdp_buffer_free(&mcs);
    rdp_buffer_init(&mcs);
    status = rdp_mcs_write_attach_user_request(&mcs);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.attach_user.request", "message=sent");
    status = rdp_session_write_mcs_pdu(session, &mcs, "mcs.attach_user.request", 1);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    rdp_buffer_free(&reply);
    rdp_buffer_init(&reply);
    status = rdp_session_read_mcs_pdu(session, &reply, &mcs_pdu, &mcs_pdu_len, "mcs.attach_user.confirm");
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    status = rdp_mcs_parse_attach_user_confirm(mcs_pdu, mcs_pdu_len, &attach_confirm);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    if (attach_confirm.result != 0)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.attach_user.failed", "result=%u", attach_confirm.result);
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto fail;
    }
    session->mcs_user_id = attach_confirm.user_id;
    rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.attach_user.confirm", "result=0 user_id=%u", session->mcs_user_id);

    status = rdp_session_join_mcs_channel(session, session->mcs_user_id, "user", &mcs, &reply);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    status = rdp_session_join_mcs_channel(session, (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID, "global", &mcs, &reply);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    if (session->dynamic_channel_id != 0 && session->dynamic_channel_id != session->mcs_user_id &&
        session->dynamic_channel_id != RDP_MCS_GLOBAL_CHANNEL_ID)
    {
        status = rdp_session_join_mcs_channel(session, session->dynamic_channel_id, "drdynvc", &mcs, &reply);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
    if (session->clipboard_channel_id != 0 && session->clipboard_channel_id != session->mcs_user_id &&
        session->clipboard_channel_id != RDP_MCS_GLOBAL_CHANNEL_ID)
    {
        status = rdp_session_join_mcs_channel(session, session->clipboard_channel_id, "cliprdr", &mcs, &reply);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
    if (session->audio_output_channel_id != 0 && session->audio_output_channel_id != session->mcs_user_id &&
        session->audio_output_channel_id != RDP_MCS_GLOBAL_CHANNEL_ID)
    {
        status = rdp_session_join_mcs_channel(session, session->audio_output_channel_id, "rdpsnd", &mcs, &reply);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
    if (session->device_redirection_channel_id != 0 &&
        session->device_redirection_channel_id != session->mcs_user_id &&
        session->device_redirection_channel_id != RDP_MCS_GLOBAL_CHANNEL_ID)
    {
        status = rdp_session_join_mcs_channel(session,
                                              session->device_redirection_channel_id,
                                              "rdpdr",
                                              &mcs,
                                              &reply);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
    if (session->pnp_redirection_channel_id != 0 &&
        session->pnp_redirection_channel_id != session->mcs_user_id &&
        session->pnp_redirection_channel_id != RDP_MCS_GLOBAL_CHANNEL_ID)
    {
        status = rdp_session_join_mcs_channel(session,
                                              session->pnp_redirection_channel_id,
                                              "PNPDR",
                                              &mcs,
                                              &reply);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
    if (session->remote_programs_channel_id != 0 &&
        session->remote_programs_channel_id != session->mcs_user_id &&
        session->remote_programs_channel_id != RDP_MCS_GLOBAL_CHANNEL_ID)
    {
        status = rdp_session_join_mcs_channel(session,
                                              session->remote_programs_channel_id,
                                              "rail",
                                              &mcs,
                                              &reply);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }

    if (selected_protocol == RDP_X224_PROTOCOL_STANDARD &&
        (server_encryption_method != 0 || server_encryption_level != 0))
    {
        uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
        rdp_security_public_key public_key;
        rdp_buffer encrypted_client_random;

        memset(&public_key, 0, sizeof(public_key));
        rdp_buffer_init(&encrypted_client_random);
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "rdp.security_exchange.start",
                        "encryption_method=%u encryption_level=%u random_len=%u certificate_len=%u",
                        server_encryption_method,
                        server_encryption_level,
                        (unsigned)server_random.length,
                        (unsigned)server_certificate.length);
        if (server_random.length != RDP_SECURITY_CLIENT_RANDOM_LEN || server_certificate.length == 0)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            status = rdp_security_parse_server_certificate(server_certificate.data, server_certificate.length, &public_key);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_generate_client_random(client_random);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_encrypt_client_random(&public_key, client_random, &encrypted_client_random);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_standard_client_init(&session->standard_security,
                                                       server_encryption_method,
                                                       client_random,
                                                       server_random.data);
        memset(client_random, 0, sizeof(client_random));
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_write_exchange_pdu(&security_payload,
                                                     encrypted_client_random.data,
                                                     encrypted_client_random.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_write_send_data_request(&security_data,
                                                          session->mcs_user_id,
                                                          (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                          security_payload.data,
                                                          security_payload.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_write_mcs_pdu(session, &security_data, "rdp.security_exchange.pdu", 0);
        if (status == LIBRDP_STATUS_OK)
        {
            standard_security_ready = 1;
            session->standard_security_active = 1;
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.security_exchange.done",
                            "encrypted_random_len=%u",
                            (unsigned)encrypted_client_random.length);
        }
        rdp_security_public_key_clear(&public_key);
        rdp_buffer_free(&encrypted_client_random);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        rdp_buffer_free(&security_payload);
        rdp_buffer_free(&security_data);
        rdp_buffer_init(&security_payload);
        rdp_buffer_init(&security_data);
    }

    {
        rdp_client_info info;
        memset(&info, 0, sizeof(info));
        info.domain = librdp_settings_domain(session->settings);
        info.username = librdp_settings_username(session->settings);
        info.password = rdp_settings_password_internal(session->settings);
        info.alternate_shell = NULL;
        info.working_dir = NULL;
        if (standard_security_ready)
            status = rdp_security_write_encrypted_client_info_pdu(&security_payload,
                                                                  &session->standard_security,
                                                                  &info);
        else
            status = rdp_security_write_client_info_pdu(&security_payload, &info);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
    status = rdp_security_write_send_data_request(&security_data,
                                                  session->mcs_user_id,
                                                  (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                  security_payload.data,
                                                  security_payload.length);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "rdp.client_info.start",
                    "domain_present=%u username_present=%u password=masked encrypted=%u",
                    librdp_settings_domain(session->settings) ? 1u : 0u,
                    librdp_settings_username(session->settings) ? 1u : 0u,
                    standard_security_ready ? 1u : 0u);
    status = rdp_session_write_mcs_pdu(session, &security_data, "rdp.client_info.pdu", 0);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.client_info.done", "status=sent");
    if (session->remote_programs_channel_id != 0)
    {
        status = rdp_session_send_remote_programs_startup(session);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
    if (session->pnp_redirection_channel_id != 0)
    {
        status = rdp_session_pnp_send_version(session);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        status = rdp_session_pnp_send_authenticated(session);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }

    rdp_session_set_state(session, LIBRDP_SESSION_CONNECTED);

    rdp_session_emit_surface_invalidated(session,
                                         0,
                                         0,
                                         librdp_surface_width(session->surface),
                                         librdp_surface_height(session->surface));
    rdp_session_pointer_emit_default(session);

    rdp_trace_event(RDP_TRACE_CLIENT, "client.connect.done", "transport=tcp");
    rdp_buffer_free(&reply);
    rdp_buffer_free(&request);
    rdp_buffer_free(&server_certificate);
    rdp_buffer_free(&server_random);
    rdp_buffer_free(&security_data);
    rdp_buffer_free(&security_payload);
    rdp_buffer_free(&mcs);
    rdp_buffer_free(&gcc_request);
    rdp_buffer_free(&gcc_blocks);
    rdp_buffer_free(&x224);
    return LIBRDP_STATUS_OK;

fail:
    rdp_transport_close(&session->transport);
    rdp_security_standard_clear(&session->standard_security);
    session->standard_security_active = 0;
    session->clipboard_channel_id = 0;
    rdp_session_clipboard_clear(session);
    session->audio_output_channel_id = 0;
    session->audio_output_ready = 0;
    session->audio_output_fragmenting = 0;
    session->audio_output_pending_wave = 0;
    session->audio_output_fragment_expected = 0;
    session->audio_output_server_version = 0;
    session->audio_output_client_version = 0;
    session->audio_output_pending_format_no = 0;
    session->audio_output_pending_timestamp = 0;
    session->audio_output_pending_expected_len = 0;
    session->audio_output_pending_block_no = 0;
    session->audio_output_selected_format_count = 0;
    memset(session->audio_output_selected_formats, 0, sizeof(session->audio_output_selected_formats));
    session->audio_input_channel_id = 0;
    session->audio_input_channel_id_bytes = 0;
    session->audio_input_ready = 0;
    session->audio_input_open = 0;
    session->audio_input_open_reply_sent = 0;
    session->audio_input_version = 0;
    session->audio_input_selected_format_count = 0;
    memset(session->audio_input_selected_formats, 0, sizeof(session->audio_input_selected_formats));
    rdp_session_composited_reset(session);
    rdp_session_video_redirection_reset(session);
    rdp_session_video_capture_reset(session);
    rdp_buffer_free(&session->audio_output_fragment);
    rdp_buffer_init(&session->audio_output_fragment);
    rdp_buffer_free(&session->audio_output_pending_data);
    rdp_buffer_init(&session->audio_output_pending_data);
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
    session->pnp_redirection_fragment_expected = 0;
    rdp_buffer_free(&session->pnp_redirection_fragment);
    rdp_buffer_init(&session->pnp_redirection_fragment);
    session->remote_programs_channel_id = 0;
    session->remote_programs_ready = 0;
    session->remote_programs_fragmenting = 0;
    session->remote_programs_exec_sent = 0;
    session->remote_programs_fragment_expected = 0;
    rdp_buffer_free(&session->remote_programs_fragment);
    rdp_buffer_init(&session->remote_programs_fragment);
    rdp_session_redirected_files_clear(session);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.connect.failed", "status=%d", (int)status);
    rdp_buffer_free(&reply);
    rdp_buffer_free(&request);
    rdp_buffer_free(&server_certificate);
    rdp_buffer_free(&server_random);
    rdp_buffer_free(&security_data);
    rdp_buffer_free(&security_payload);
    rdp_buffer_free(&mcs);
    rdp_buffer_free(&gcc_request);
    rdp_buffer_free(&gcc_blocks);
    rdp_buffer_free(&x224);
    return rdp_session_fail(session, status);
}

librdp_status librdp_session_run_once(librdp_session* session, int timeout_ms)
{
    short revents = 0;
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&packet);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.active.loop.start",
                          "timeout_ms=%d",
                          timeout_ms);
    if (session->state == LIBRDP_SESSION_CONNECTED)
        rdp_session_set_state(session, LIBRDP_SESSION_ACTIVE);

    status = rdp_transport_wait(&session->transport, timeout_ms, POLLIN, &revents);
    if (status == LIBRDP_STATUS_TIMEOUT)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.active.loop.done",
                              "status=timeout");
        return LIBRDP_STATUS_OK;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&packet);
        return status;
    }
    if ((revents & POLLIN) != 0)
    {
        uint8_t first_byte = 0;
        size_t peeked = 0;

        status = rdp_transport_peek(&session->transport, &first_byte, 1, &peeked);
        if (status == LIBRDP_STATUS_CLOSED)
        {
            rdp_buffer_free(&packet);
            return librdp_session_disconnect(session);
        }
        if (status != LIBRDP_STATUS_OK || peeked != 1)
        {
            rdp_buffer_free(&packet);
            return rdp_session_fail(session, status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_IO_ERROR : status);
        }
        if (first_byte != 3)
        {
            status = rdp_session_read_fastpath_packet(session, &packet);
            if (status == LIBRDP_STATUS_CLOSED)
            {
                rdp_buffer_free(&packet);
                return librdp_session_disconnect(session);
            }
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_process_fastpath_packet(session, &packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            goto done;
        }
        const uint8_t* pdu = NULL;
        size_t pdu_len = 0;
        rdp_mcs_send_data_indication indication;
        rdp_slowpath_share_control_header slow_header;
        rdp_buffer security_payload;
        const uint8_t* indication_payload = NULL;
        size_t indication_payload_len = 0;
        uint16_t security_flags = 0;
        int have_slow_header = 0;

        rdp_buffer_init(&security_payload);
        status = rdp_session_read_mcs_pdu(session, &packet, &pdu, &pdu_len, "rdp.slowpath.pdu");
        if (status == LIBRDP_STATUS_CLOSED)
        {
            rdp_buffer_free(&security_payload);
            rdp_buffer_free(&packet);
            return librdp_session_disconnect(session);
        }
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&security_payload);
            rdp_buffer_free(&packet);
            return rdp_session_fail(session, status);
        }
        status = rdp_mcs_parse_send_data_indication(pdu, pdu_len, &indication);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&security_payload);
            rdp_buffer_free(&packet);
            return rdp_session_fail(session, status);
        }
        indication_payload = indication.payload;
        indication_payload_len = indication.payload_len;
        if (session->standard_security_active)
        {
            status = rdp_security_unwrap_pdu(&session->standard_security,
                                             indication.payload,
                                             indication.payload_len,
                                             &security_payload,
                                             &security_flags);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            indication_payload = security_payload.data;
            indication_payload_len = security_payload.length;
        }
        rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                              RDP_TRACE_LEVEL_DEBUG,
                              "mcs.send_data.indication",
                              "initiator=%u channel_id=%u payload_len=%u security_flags=%u",
                              indication.initiator,
                              indication.channel_id,
                              (unsigned)indication_payload_len,
                              security_flags);
        if (session->dynamic_channel_id != 0 && indication.channel_id == session->dynamic_channel_id)
        {
            rdp_virtual_channel_packet channel_packet;

            status = rdp_virtual_channel_parse_packet(indication_payload, indication_payload_len, &channel_packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.drdynvc.data",
                                  "channel_id=%u flags=%u payload_len=%u",
                                  indication.channel_id,
                                  channel_packet.flags,
                                  (unsigned)channel_packet.payload_len);
            status = rdp_session_handle_dynamic_channel(session, &channel_packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_buffer_free(&security_payload);
            goto done;
        }
        if (session->clipboard_channel_id != 0 && indication.channel_id == session->clipboard_channel_id)
        {
            rdp_virtual_channel_packet channel_packet;
            uint32_t fragment_flags = 0;

            status = rdp_virtual_channel_parse_packet(indication_payload, indication_payload_len, &channel_packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            fragment_flags = channel_packet.flags & (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST);
            if (fragment_flags == (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST))
            {
                status = rdp_session_handle_clipboard_message(session,
                                                              channel_packet.payload,
                                                              channel_packet.payload_len);
            }
            else if (fragment_flags == RDP_VIRTUAL_CHANNEL_FLAG_FIRST)
            {
                rdp_buffer_free(&session->clipboard_fragment);
                rdp_buffer_init(&session->clipboard_fragment);
                if (channel_packet.length == 0 || channel_packet.length > RDP_SESSION_MAX_DYNAMIC_MESSAGE)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                else
                    status = rdp_buffer_reserve(&session->clipboard_fragment, channel_packet.length);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->clipboard_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                if (status == LIBRDP_STATUS_OK)
                {
                    session->clipboard_fragmenting = 1;
                    session->clipboard_fragment_expected = channel_packet.length;
                    rdp_trace_event_level(RDP_TRACE_CLIENT,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "client.clipboard.fragment.start",
                                          "channel_id=%u total_len=%u payload_len=%u",
                                          indication.channel_id,
                                          channel_packet.length,
                                          (unsigned)channel_packet.payload_len);
                }
            }
            else if (session->clipboard_fragmenting)
            {
                if (session->clipboard_fragment.length > session->clipboard_fragment_expected ||
                    channel_packet.payload_len >
                    (size_t)session->clipboard_fragment_expected - session->clipboard_fragment.length)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->clipboard_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                rdp_trace_event_level(RDP_TRACE_CLIENT,
                                      RDP_TRACE_LEVEL_DEBUG,
                                      "client.clipboard.fragment.data",
                                      "channel_id=%u total_len=%u received=%u payload_len=%u flags=%u",
                                      indication.channel_id,
                                      session->clipboard_fragment_expected,
                                      (unsigned)session->clipboard_fragment.length,
                                      (unsigned)channel_packet.payload_len,
                                      channel_packet.flags);
                if (status == LIBRDP_STATUS_OK && (channel_packet.flags & RDP_VIRTUAL_CHANNEL_FLAG_LAST) != 0)
                {
                    if (session->clipboard_fragment.length != session->clipboard_fragment_expected)
                        status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    if (status == LIBRDP_STATUS_OK)
                        status = rdp_session_handle_clipboard_message(session,
                                                                      session->clipboard_fragment.data,
                                                                      session->clipboard_fragment.length);
                    rdp_buffer_free(&session->clipboard_fragment);
                    session->clipboard_fragmenting = 0;
                    session->clipboard_fragment_expected = 0;
                }
            }
            else
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_buffer_free(&security_payload);
            goto done;
        }
        if (session->audio_output_channel_id != 0 && indication.channel_id == session->audio_output_channel_id)
        {
            rdp_virtual_channel_packet channel_packet;
            uint32_t fragment_flags = 0;

            status = rdp_virtual_channel_parse_packet(indication_payload, indication_payload_len, &channel_packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            fragment_flags = channel_packet.flags & (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST);
            if (fragment_flags == (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST))
            {
                status = rdp_session_handle_audio_output_message(session,
                                                                 channel_packet.payload,
                                                                 channel_packet.payload_len);
            }
            else if (fragment_flags == RDP_VIRTUAL_CHANNEL_FLAG_FIRST)
            {
                rdp_buffer_free(&session->audio_output_fragment);
                rdp_buffer_init(&session->audio_output_fragment);
                if (channel_packet.length == 0 || channel_packet.length > RDP_SESSION_MAX_DYNAMIC_MESSAGE)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                else
                    status = rdp_buffer_reserve(&session->audio_output_fragment, channel_packet.length);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->audio_output_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                if (status == LIBRDP_STATUS_OK)
                {
                    session->audio_output_fragmenting = 1;
                    session->audio_output_fragment_expected = channel_packet.length;
                    rdp_trace_event_level(RDP_TRACE_CLIENT,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "client.rdpsnd.fragment.start",
                                          "channel_id=%u total_len=%u payload_len=%u",
                                          indication.channel_id,
                                          channel_packet.length,
                                          (unsigned)channel_packet.payload_len);
                }
            }
            else if (session->audio_output_fragmenting)
            {
                if (session->audio_output_fragment.length > session->audio_output_fragment_expected ||
                    channel_packet.payload_len >
                    (size_t)session->audio_output_fragment_expected - session->audio_output_fragment.length)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->audio_output_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                rdp_trace_event_level(RDP_TRACE_CLIENT,
                                      RDP_TRACE_LEVEL_DEBUG,
                                      "client.rdpsnd.fragment.data",
                                      "channel_id=%u total_len=%u received=%u payload_len=%u flags=%u",
                                      indication.channel_id,
                                      session->audio_output_fragment_expected,
                                      (unsigned)session->audio_output_fragment.length,
                                      (unsigned)channel_packet.payload_len,
                                      channel_packet.flags);
                if (status == LIBRDP_STATUS_OK && (channel_packet.flags & RDP_VIRTUAL_CHANNEL_FLAG_LAST) != 0)
                {
                    if (session->audio_output_fragment.length != session->audio_output_fragment_expected)
                        status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    if (status == LIBRDP_STATUS_OK)
                        status = rdp_session_handle_audio_output_message(session,
                                                                         session->audio_output_fragment.data,
                                                                         session->audio_output_fragment.length);
                    rdp_buffer_free(&session->audio_output_fragment);
                    session->audio_output_fragmenting = 0;
                    session->audio_output_fragment_expected = 0;
                }
            }
            else
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_buffer_free(&security_payload);
            goto done;
        }
        if (session->device_redirection_channel_id != 0 &&
            indication.channel_id == session->device_redirection_channel_id)
        {
            rdp_virtual_channel_packet channel_packet;
            uint32_t fragment_flags = 0;

            status = rdp_virtual_channel_parse_packet(indication_payload, indication_payload_len, &channel_packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            fragment_flags = channel_packet.flags & (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST);
            if (fragment_flags == (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST))
            {
                status = rdp_session_handle_device_redirection_message(session,
                                                                       channel_packet.payload,
                                                                       channel_packet.payload_len);
            }
            else if (fragment_flags == RDP_VIRTUAL_CHANNEL_FLAG_FIRST)
            {
                rdp_buffer_free(&session->device_redirection_fragment);
                rdp_buffer_init(&session->device_redirection_fragment);
                if (channel_packet.length == 0 || channel_packet.length > RDP_SESSION_MAX_DYNAMIC_MESSAGE)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                else
                    status = rdp_buffer_reserve(&session->device_redirection_fragment, channel_packet.length);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->device_redirection_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                if (status == LIBRDP_STATUS_OK)
                {
                    session->device_redirection_fragmenting = 1;
                    session->device_redirection_fragment_expected = channel_packet.length;
                    rdp_trace_event_level(RDP_TRACE_CLIENT,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "client.rdpdr.fragment.start",
                                          "channel_id=%u total_len=%u payload_len=%u",
                                          indication.channel_id,
                                          channel_packet.length,
                                          (unsigned)channel_packet.payload_len);
                }
            }
            else if (session->device_redirection_fragmenting)
            {
                if (session->device_redirection_fragment.length > session->device_redirection_fragment_expected ||
                    channel_packet.payload_len >
                    (size_t)session->device_redirection_fragment_expected -
                    session->device_redirection_fragment.length)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->device_redirection_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                rdp_trace_event_level(RDP_TRACE_CLIENT,
                                      RDP_TRACE_LEVEL_DEBUG,
                                      "client.rdpdr.fragment.data",
                                      "channel_id=%u total_len=%u received=%u payload_len=%u flags=%u",
                                      indication.channel_id,
                                      session->device_redirection_fragment_expected,
                                      (unsigned)session->device_redirection_fragment.length,
                                      (unsigned)channel_packet.payload_len,
                                      channel_packet.flags);
                if (status == LIBRDP_STATUS_OK && (channel_packet.flags & RDP_VIRTUAL_CHANNEL_FLAG_LAST) != 0)
                {
                    if (session->device_redirection_fragment.length !=
                        session->device_redirection_fragment_expected)
                        status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    if (status == LIBRDP_STATUS_OK)
                        status = rdp_session_handle_device_redirection_message(
                            session,
                            session->device_redirection_fragment.data,
                            session->device_redirection_fragment.length);
                    rdp_buffer_free(&session->device_redirection_fragment);
                    session->device_redirection_fragmenting = 0;
                    session->device_redirection_fragment_expected = 0;
                }
            }
            else
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_buffer_free(&security_payload);
            goto done;
        }
        if (session->pnp_redirection_channel_id != 0 &&
            indication.channel_id == session->pnp_redirection_channel_id)
        {
            rdp_virtual_channel_packet channel_packet;
            uint32_t fragment_flags = 0;

            status = rdp_virtual_channel_parse_packet(indication_payload, indication_payload_len, &channel_packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            fragment_flags = channel_packet.flags & (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST);
            if (fragment_flags == (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST))
            {
                status = rdp_session_handle_pnp_redirection_message(session,
                                                                    channel_packet.payload,
                                                                    channel_packet.payload_len);
            }
            else if (fragment_flags == RDP_VIRTUAL_CHANNEL_FLAG_FIRST)
            {
                rdp_buffer_free(&session->pnp_redirection_fragment);
                rdp_buffer_init(&session->pnp_redirection_fragment);
                if (channel_packet.length == 0 || channel_packet.length > RDP_SESSION_MAX_DYNAMIC_MESSAGE)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                else
                    status = rdp_buffer_reserve(&session->pnp_redirection_fragment, channel_packet.length);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->pnp_redirection_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                if (status == LIBRDP_STATUS_OK)
                {
                    session->pnp_redirection_fragmenting = 1;
                    session->pnp_redirection_fragment_expected = channel_packet.length;
                    rdp_trace_event_level(RDP_TRACE_CLIENT,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "client.pnp.fragment.start",
                                          "channel_id=%u total_len=%u payload_len=%u",
                                          indication.channel_id,
                                          channel_packet.length,
                                          (unsigned)channel_packet.payload_len);
                }
            }
            else if (session->pnp_redirection_fragmenting)
            {
                if (session->pnp_redirection_fragment.length > session->pnp_redirection_fragment_expected ||
                    channel_packet.payload_len >
                    (size_t)session->pnp_redirection_fragment_expected -
                    session->pnp_redirection_fragment.length)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->pnp_redirection_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                rdp_trace_event_level(RDP_TRACE_CLIENT,
                                      RDP_TRACE_LEVEL_DEBUG,
                                      "client.pnp.fragment.data",
                                      "channel_id=%u total_len=%u received=%u payload_len=%u flags=%u",
                                      indication.channel_id,
                                      session->pnp_redirection_fragment_expected,
                                      (unsigned)session->pnp_redirection_fragment.length,
                                      (unsigned)channel_packet.payload_len,
                                      channel_packet.flags);
                if (status == LIBRDP_STATUS_OK && (channel_packet.flags & RDP_VIRTUAL_CHANNEL_FLAG_LAST) != 0)
                {
                    if (session->pnp_redirection_fragment.length != session->pnp_redirection_fragment_expected)
                        status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    if (status == LIBRDP_STATUS_OK)
                        status = rdp_session_handle_pnp_redirection_message(
                            session,
                            session->pnp_redirection_fragment.data,
                            session->pnp_redirection_fragment.length);
                    rdp_buffer_free(&session->pnp_redirection_fragment);
                    session->pnp_redirection_fragmenting = 0;
                    session->pnp_redirection_fragment_expected = 0;
                }
            }
            else
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_buffer_free(&security_payload);
            goto done;
        }
        if (session->remote_programs_channel_id != 0 &&
            indication.channel_id == session->remote_programs_channel_id)
        {
            rdp_virtual_channel_packet channel_packet;
            uint32_t fragment_flags = 0;

            status = rdp_virtual_channel_parse_packet(indication_payload, indication_payload_len, &channel_packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            fragment_flags = channel_packet.flags & (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST);
            if (fragment_flags == (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST))
            {
                status = rdp_session_handle_remote_programs_message(session,
                                                                    channel_packet.payload,
                                                                    channel_packet.payload_len);
            }
            else if (fragment_flags == RDP_VIRTUAL_CHANNEL_FLAG_FIRST)
            {
                rdp_buffer_free(&session->remote_programs_fragment);
                rdp_buffer_init(&session->remote_programs_fragment);
                if (channel_packet.length == 0 || channel_packet.length > RDP_SESSION_MAX_DYNAMIC_MESSAGE)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                else
                    status = rdp_buffer_reserve(&session->remote_programs_fragment, channel_packet.length);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->remote_programs_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                if (status == LIBRDP_STATUS_OK)
                {
                    session->remote_programs_fragmenting = 1;
                    session->remote_programs_fragment_expected = channel_packet.length;
                    rdp_trace_event_level(RDP_TRACE_CLIENT,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "client.rail.fragment.start",
                                          "channel_id=%u total_len=%u payload_len=%u",
                                          indication.channel_id,
                                          channel_packet.length,
                                          (unsigned)channel_packet.payload_len);
                }
            }
            else if (session->remote_programs_fragmenting)
            {
                if (session->remote_programs_fragment.length > session->remote_programs_fragment_expected ||
                    channel_packet.payload_len >
                    (size_t)session->remote_programs_fragment_expected -
                    session->remote_programs_fragment.length)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->remote_programs_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                rdp_trace_event_level(RDP_TRACE_CLIENT,
                                      RDP_TRACE_LEVEL_DEBUG,
                                      "client.rail.fragment.data",
                                      "channel_id=%u total_len=%u received=%u payload_len=%u flags=%u",
                                      indication.channel_id,
                                      session->remote_programs_fragment_expected,
                                      (unsigned)session->remote_programs_fragment.length,
                                      (unsigned)channel_packet.payload_len,
                                      channel_packet.flags);
                if (status == LIBRDP_STATUS_OK && (channel_packet.flags & RDP_VIRTUAL_CHANNEL_FLAG_LAST) != 0)
                {
                    if (session->remote_programs_fragment.length !=
                        session->remote_programs_fragment_expected)
                        status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    if (status == LIBRDP_STATUS_OK)
                        status = rdp_session_handle_remote_programs_message(
                            session,
                            session->remote_programs_fragment.data,
                            session->remote_programs_fragment.length);
                    rdp_buffer_free(&session->remote_programs_fragment);
                    session->remote_programs_fragmenting = 0;
                    session->remote_programs_fragment_expected = 0;
                }
            }
            else
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_buffer_free(&security_payload);
            goto done;
        }
        status = rdp_slowpath_parse_share_control_header(indication_payload, indication_payload_len, &slow_header);
        if (status == LIBRDP_STATUS_OK)
            have_slow_header = 1;
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_license_error_alert alert;
            librdp_status license_status = rdp_license_parse_error_alert(indication_payload,
                                                                         indication_payload_len,
                                                                         &alert);
            if (license_status == LIBRDP_STATUS_OK)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.licensing.error_alert",
                                "type=%u flags=%u error=%u state=%u blob_type=%u blob_len=%u",
                                alert.message_type,
                                alert.flags,
                                alert.error_code,
                                alert.state_transition,
                                alert.blob_type,
                                alert.blob_length);
                status = LIBRDP_STATUS_OK;
            }
        }
        if (have_slow_header && status == LIBRDP_STATUS_OK &&
            (slow_header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_DEMAND_ACTIVE)
        {
            rdp_slowpath_demand_active demand;
            rdp_buffer confirm;

            rdp_buffer_init(&confirm);
            status = rdp_slowpath_parse_demand_active(indication_payload, indication_payload_len, &demand);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.activation.demand_active",
                                "share_id=%u capabilities=%u",
                                demand.share_id,
                                demand.capabilities.count);
            if (status == LIBRDP_STATUS_OK)
                session->share_id = demand.share_id;
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_session_pointer_cache_clear(session);
                rdp_session_pointer_emit_default(session);
            }
            if (status == LIBRDP_STATUS_OK)
                status = rdp_slowpath_write_confirm_active(&confirm,
                                                           demand.share_id,
                                                           session->mcs_user_id,
                                                           (uint16_t)librdp_surface_width(session->surface),
                                                           (uint16_t)librdp_surface_height(session->surface),
                                                           "librdp");
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_write_slowpath_pdu(session, &confirm, "rdp.activation.confirm_active");
            rdp_buffer_free(&confirm);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.confirm_active", "share_id=%u", demand.share_id);
            status = rdp_session_send_activation_finalization(session, demand.share_id);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            if (session->clipboard_channel_id != 0)
            {
                status = rdp_session_send_clipboard_handshake(session);
                if (status != LIBRDP_STATUS_OK)
                {
                    rdp_buffer_free(&security_payload);
                    rdp_buffer_free(&packet);
                    return rdp_session_fail(session, status);
                }
            }
        }
        else if (have_slow_header && status == LIBRDP_STATUS_OK &&
                 (slow_header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_DATA)
        {
            rdp_slowpath_data_pdu data_pdu;

            status = rdp_slowpath_parse_data_pdu(indication_payload, indication_payload_len, &data_pdu);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "rdp.slowpath.data",
                                  "type=%u compressed_type=%u payload_len=%u",
                                  data_pdu.pdu_type2,
                                  data_pdu.compressed_type,
                                  (unsigned)data_pdu.payload_len);
            status = rdp_session_trace_slowpath_data_pdu(session, &data_pdu);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            if (data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE)
            {
                if (data_pdu.compressed_type != 0)
                {
                    rdp_trace_event(RDP_TRACE_PROTOCOL,
                                    "rdp.slowpath.update.unsupported",
                                    "compressed_type=%u payload_len=%u",
                                    data_pdu.compressed_type,
                                    (unsigned)data_pdu.payload_len);
                }
                else
                {
                    rdp_stream update_stream;
                    uint16_t update_type = 0;

                    rdp_stream_init(&update_stream, data_pdu.payload, data_pdu.payload_len);
                    if (rdp_stream_read_u16_le(&update_stream, &update_type) != LIBRDP_STATUS_OK)
                    {
                        rdp_buffer_free(&security_payload);
                        rdp_buffer_free(&packet);
                        return rdp_session_fail(session, LIBRDP_STATUS_PROTOCOL_ERROR);
                    }
                    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "rdp.slowpath.update",
                                          "update_type=%u payload_len=%u",
                                          update_type,
                                          (unsigned)data_pdu.payload_len);
                    if (update_type == RDP_UPDATE_TYPE_BITMAP)
                    {
                        rdp_bitmap_update update;

                        status = rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &update);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_session_apply_bitmap_update(session, &update);
                        if (status != LIBRDP_STATUS_OK)
                        {
                            rdp_buffer_free(&security_payload);
                            rdp_buffer_free(&packet);
                            return rdp_session_fail(session, status);
                        }
                        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.slowpath.bitmap_update", "rectangles=%u", update.count);
                    }
                    else if (update_type == RDP_UPDATE_TYPE_POINTER)
                    {
                        rdp_pointer_update pointer;

                        status = rdp_pointer_parse_slowpath(data_pdu.payload + 2u, data_pdu.payload_len - 2u, &pointer);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_session_pointer_apply_update(session, &pointer);
                        if (status != LIBRDP_STATUS_OK)
                        {
                            rdp_buffer_free(&security_payload);
                            rdp_buffer_free(&packet);
                            return rdp_session_fail(session, status);
                        }
                        rdp_trace_event(RDP_TRACE_PROTOCOL,
                                        "rdp.slowpath.pointer",
                                        "kind=%u cache_index=%u width=%u height=%u",
                                        pointer.kind,
                                        pointer.cache_index,
                                        pointer.width,
                                        pointer.height);
                    }
                    else
                    {
                        rdp_trace_event(RDP_TRACE_PROTOCOL,
                                        "rdp.slowpath.update.unsupported",
                                        "update_type=%u payload_len=%u",
                                        update_type,
                                        (unsigned)data_pdu.payload_len);
                    }
                }
            }
        }
        rdp_buffer_free(&security_payload);
    }

done:
    rdp_buffer_free(&packet);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.active.loop.done",
                          "status=idle");
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_disconnect(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state == LIBRDP_SESSION_CLOSED || session->state == LIBRDP_SESSION_IDLE)
        return LIBRDP_STATUS_OK;

    rdp_trace_event(RDP_TRACE_CLIENT, "client.disconnect.start", "state=%d", (int)session->state);
    rdp_session_set_state(session, LIBRDP_SESSION_CLOSING);
    rdp_session_graphics_dirty_reset(session);
    rdp_transport_close(&session->transport);
    rdp_security_standard_clear(&session->standard_security);
    session->standard_security_active = 0;
    session->clipboard_channel_id = 0;
    rdp_session_clipboard_clear(session);
    session->audio_output_channel_id = 0;
    session->audio_output_ready = 0;
    session->audio_output_fragmenting = 0;
    session->audio_output_pending_wave = 0;
    session->audio_output_fragment_expected = 0;
    session->audio_output_server_version = 0;
    session->audio_output_client_version = 0;
    session->audio_output_pending_format_no = 0;
    session->audio_output_pending_timestamp = 0;
    session->audio_output_pending_expected_len = 0;
    session->audio_output_pending_block_no = 0;
    session->audio_output_selected_format_count = 0;
    memset(session->audio_output_selected_formats, 0, sizeof(session->audio_output_selected_formats));
    rdp_buffer_free(&session->audio_output_fragment);
    rdp_buffer_init(&session->audio_output_fragment);
    rdp_buffer_free(&session->audio_output_pending_data);
    rdp_buffer_init(&session->audio_output_pending_data);
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
    session->pnp_redirection_fragment_expected = 0;
    rdp_buffer_free(&session->pnp_redirection_fragment);
    rdp_buffer_init(&session->pnp_redirection_fragment);
    session->remote_programs_channel_id = 0;
    session->remote_programs_ready = 0;
    session->remote_programs_fragmenting = 0;
    session->remote_programs_exec_sent = 0;
    session->remote_programs_fragment_expected = 0;
    rdp_buffer_free(&session->remote_programs_fragment);
    rdp_buffer_init(&session->remote_programs_fragment);
    session->core_input_channel_id = 0;
    session->core_input_channel_id_bytes = 0;
    session->core_input_ready = 0;
    session->input_channel_id = 0;
    session->input_channel_id_bytes = 0;
    session->input_channel_ready = 0;
    session->input_channel_suspended = 0;
    session->input_channel_protocol_version = 0;
    session->input_channel_supported_features = 0;
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
    rdp_session_composited_reset(session);
    rdp_session_video_redirection_reset(session);
    rdp_session_video_capture_reset(session);
    rdp_session_usb_redirection_reset(session);
    rdp_graphics_decompressor_reset(&session->graphics_decompressor);
    rdp_clearcodec_context_reset(&session->clearcodec);
    rdp_session_graphics_surfaces_clear(session);
    rdp_session_graphics_cache_clear(session);
    rdp_session_pointer_cache_clear(session);
    rdp_session_dynamic_channels_clear(session);
    rdp_session_redirected_files_clear(session);
    rdp_session_smartcard_reset(session);
    rdp_session_set_state(session, LIBRDP_SESSION_CLOSED);

    event.type = LIBRDP_EVENT_DISCONNECTED;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.disconnect.done", "status=ok");
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_resize(librdp_session* session, uint32_t width, uint32_t height)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_session_request_display_control_layout(session, width, height);
    return status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_OK : status;
}

librdp_status librdp_session_refresh(librdp_session* session, uint32_t x, uint32_t y, uint32_t width, uint32_t height)
{
    rdp_buffer refresh;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || width == 0 || height == 0 || x > 0xffffu || y > 0xffffu ||
        width > 0xffffu || height > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (x + width - 1u > 0xffffu || y + height - 1u > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->share_id == 0)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&refresh);
    status = rdp_slowpath_write_client_refresh_rect(&refresh,
                                                    session->share_id,
                                                    session->mcs_user_id,
                                                    (uint16_t)x,
                                                    (uint16_t)y,
                                                    (uint16_t)width,
                                                    (uint16_t)height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &refresh, "rdp.refresh_rect");
    rdp_buffer_free(&refresh);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.active.refresh_rect",
                        "x=%u y=%u width=%u height=%u",
                        x,
                        y,
                        width,
                        height);
    return status;
}

librdp_status librdp_session_clipboard_set_data(librdp_session* session,
                                                uint32_t format_id,
                                                const void* data,
                                                size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || format_id == 0 || (!data && data_len > 0) || data_len > RDP_SESSION_MAX_DYNAMIC_MESSAGE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_free(&session->clipboard_local_data);
    if (data_len > 0)
    {
        rdp_buffer_init(&session->clipboard_local_data);
        status = rdp_buffer_append(&session->clipboard_local_data, data, data_len);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_session_clipboard_local_clear(session);
            return status;
        }
    }
    session->clipboard_local_format_id = format_id;
    session->clipboard_local_available = 1;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.clipboard.local_data",
                    "format_id=%u data_len=%u",
                    format_id,
                    (unsigned)data_len);
    return rdp_session_send_clipboard_format_list(session);
}

librdp_status librdp_session_clipboard_clear(librdp_session* session)
{
    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_session_clipboard_local_clear(session);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.clipboard.local_clear", "formats=0");
    return rdp_session_send_clipboard_format_list(session);
}

librdp_status librdp_session_clipboard_request_data(librdp_session* session, uint32_t format_id)
{
    rdp_buffer request;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || format_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!session->clipboard_ready || session->clipboard_channel_id == 0)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&request);
    status = rdp_clipboard_write_format_data_request(&request, format_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_clipboard_packet(session, &request, "client.clipboard.format_data_request");
    rdp_buffer_free(&request);
    if (status == LIBRDP_STATUS_OK)
    {
        session->clipboard_pending_request_format_id = format_id;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.clipboard.request_data",
                        "format_id=%u",
                        format_id);
    }
    return status;
}

static librdp_status rdp_session_require_input_channel(const librdp_session* session)
{
    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (!session->input_channel_ready || session->input_channel_suspended ||
        session->input_channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_require_audio_input_channel(const librdp_session* session)
{
    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->audio_input_channel_id == 0 || session->audio_input_channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_require_user_channel(librdp_session* session,
                                                      librdp_channel_id channel_id,
                                                      rdp_session_dynamic_channel** entry)
{
    rdp_session_dynamic_channel* found = NULL;

    if (!session || channel_id == 0 || !entry)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->dynamic_channel_id == 0)
        return LIBRDP_STATUS_STATE;
    found = rdp_session_dynamic_channel_find(session, channel_id);
    if (!found || !found->active)
        return LIBRDP_STATUS_STATE;
    if (rdp_session_dynamic_channel_is_internal(found))
        return LIBRDP_STATUS_UNSUPPORTED;
    *entry = found;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_channel_send(librdp_session* session,
                                          librdp_channel_id channel_id,
                                          const void* data,
                                          size_t data_len)
{
    rdp_session_dynamic_channel* entry = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if ((!data && data_len > 0) || data_len > RDP_SESSION_MAX_DYNAMIC_MESSAGE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_user_channel(session, channel_id, &entry);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_session_send_dynamic_channel_data(session,
                                                   entry->channel_id,
                                                   entry->channel_id_bytes,
                                                   data,
                                                   data_len,
                                                   "client.drdynvc.channel_send");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.channel_send",
                        "dvc_channel_id=%u name=%s payload_len=%u",
                        entry->channel_id,
                        entry->name,
                        (unsigned)data_len);
    return status;
}

librdp_status librdp_session_channel_close(librdp_session* session, librdp_channel_id channel_id)
{
    rdp_session_dynamic_channel* entry = NULL;
    rdp_buffer close_pdu;
    librdp_status status = rdp_session_require_user_channel(session, channel_id, &entry);

    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&close_pdu);
    status = rdp_dynamic_channel_write_close(&close_pdu, entry->channel_id, entry->channel_id_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_channel_pdu(session,
                                               session->dynamic_channel_id,
                                               &close_pdu,
                                               "client.drdynvc.channel_close");
    rdp_buffer_free(&close_pdu);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.channel_close",
                        "dvc_channel_id=%u name=%s",
                        entry->channel_id,
                        entry->name);
        rdp_session_dynamic_channel_clear_entry(entry);
    }
    return status;
}

librdp_status librdp_session_audio_input_open_reply(librdp_session* session, uint32_t result)
{
    rdp_buffer reply;
    librdp_status status = rdp_session_require_audio_input_channel(session);

    rdp_buffer_init(&reply);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_input_incoming(session);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_audio_input_write_open_reply(&reply, result);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_input_packet(session, &reply, "client.audin.open_reply");
    rdp_buffer_free(&reply);
    if (status == LIBRDP_STATUS_OK)
    {
        session->audio_input_open_reply_sent = 1;
        session->audio_input_open = result == RDP_AUDIO_INPUT_RESULT_OK ? 1u : 0u;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.audin.open_reply",
                        "dvc_channel_id=%u result=%u",
                        session->audio_input_channel_id,
                        result);
    }
    return status;
}

librdp_status librdp_session_audio_input_send_data(librdp_session* session, const void* data, size_t data_len)
{
    rdp_buffer pdu;
    librdp_status status = LIBRDP_STATUS_OK;

    if ((!data && data_len > 0) || data_len > RDP_SESSION_MAX_DYNAMIC_MESSAGE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_audio_input_channel(session);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!session->audio_input_ready || !session->audio_input_open)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&pdu);
    status = rdp_session_send_audio_input_incoming(session);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_audio_input_write_data(&pdu, data, data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_input_packet(session, &pdu, "client.audin.data");
    rdp_buffer_free(&pdu);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.audin.data",
                        "dvc_channel_id=%u data_len=%u",
                        session->audio_input_channel_id,
                        (unsigned)data_len);
    return status;
}

librdp_status librdp_session_audio_input_send_format_change(librdp_session* session, uint32_t new_format)
{
    rdp_buffer pdu;
    librdp_status status = rdp_session_require_audio_input_channel(session);

    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!session->audio_input_ready)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&pdu);
    status = rdp_audio_input_write_format_change(&pdu, new_format);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_input_packet(session, &pdu, "client.audin.format_change");
    rdp_buffer_free(&pdu);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.audin.format_change_send",
                        "dvc_channel_id=%u new_format=%u",
                        session->audio_input_channel_id,
                        new_format);
    return status;
}

librdp_status librdp_session_video_capture_send_sample(librdp_session* session,
                                                       uint8_t stream_index,
                                                       const void* data,
                                                       size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0) || data_len > RDP_VIDEO_CAPTURE_MAX_SAMPLE_BYTES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->video_capture_channel_id == 0 || session->video_capture_channel_id_bytes == 0 ||
        !session->video_capture_active || !session->video_capture_streaming ||
        !session->video_capture_sample_reply_pending ||
        stream_index != session->video_capture_selected_stream)
        return LIBRDP_STATUS_STATE;
    status = rdp_session_send_video_capture_sample_payload(session,
                                                           stream_index,
                                                           data,
                                                           data_len,
                                                           "client.rdpecam.sample.response");
    return status;
}

librdp_status librdp_session_video_capture_send_error(librdp_session* session,
                                                      uint8_t stream_index,
                                                      uint32_t error_code)
{
    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->video_capture_channel_id == 0 || session->video_capture_channel_id_bytes == 0 ||
        !session->video_capture_active || !session->video_capture_streaming ||
        !session->video_capture_sample_reply_pending ||
        stream_index != session->video_capture_selected_stream)
        return LIBRDP_STATUS_STATE;
    return rdp_session_send_video_capture_sample_error(session, stream_index, error_code);
}

static void rdp_session_free_buffers(rdp_buffer* buffers, uint16_t count)
{
    uint16_t i = 0;

    if (!buffers)
        return;
    for (i = 0; i < count; i++)
        rdp_buffer_free(&buffers[i]);
    free(buffers);
}

static void rdp_session_copy_touch_contact(const librdp_touch_contact* in,
                                           rdp_input_channel_touch_contact* out)
{
    memset(out, 0, sizeof(*out));
    out->contact_id = in->contact_id;
    out->fields_present = in->fields_present;
    out->x = in->x;
    out->y = in->y;
    out->contact_flags = in->contact_flags;
    out->contact_rect_left = in->contact_rect_left;
    out->contact_rect_top = in->contact_rect_top;
    out->contact_rect_right = in->contact_rect_right;
    out->contact_rect_bottom = in->contact_rect_bottom;
    out->orientation = in->orientation;
    out->pressure = in->pressure;
}

static void rdp_session_copy_pen_contact(const librdp_pen_contact* in,
                                         rdp_input_channel_pen_contact* out)
{
    memset(out, 0, sizeof(*out));
    out->device_id = in->device_id;
    out->fields_present = in->fields_present;
    out->x = in->x;
    out->y = in->y;
    out->contact_flags = in->contact_flags;
    out->pen_flags = in->pen_flags;
    out->pressure = in->pressure;
    out->rotation = in->rotation;
    out->tilt_x = in->tilt_x;
    out->tilt_y = in->tilt_y;
}

librdp_status librdp_session_send_key(librdp_session* session, const librdp_key_event* key)
{
    uint16_t flags = 0;
    rdp_buffer input;
    librdp_event event;
    librdp_status status = LIBRDP_STATUS_OK;
    const int use_unicode = key && ((key->flags & LIBRDP_KEY_FLAG_UNICODE) != 0);
    const int use_core_input = key && session && session->core_input_ready;

    if (!session || !key)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->share_id == 0)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&input);
    if (use_core_input)
    {
        if (use_unicode)
        {
            if (key->unicode > 0xffffu)
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            else
                status = rdp_core_input_write_unicode_event(&input,
                                                            (uint16_t)key->unicode,
                                                            key->state == LIBRDP_KEY_RELEASED ? 1u : 0u);
        }
        else if (key->scancode > 0xffu)
        {
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        }
        else
        {
            uint8_t core_flags = key->state == LIBRDP_KEY_RELEASED ? RDP_CORE_INPUT_KBDFLAGS_RELEASE : 0;

            if ((key->flags & LIBRDP_KEY_FLAG_EXTENDED) != 0)
                core_flags = (uint8_t)(core_flags | RDP_CORE_INPUT_KBDFLAGS_EXTENDED);
            if ((key->flags & LIBRDP_KEY_FLAG_EXTENDED1) != 0)
                core_flags = (uint8_t)(core_flags | RDP_CORE_INPUT_KBDFLAGS_EXTENDED1);
            status = rdp_core_input_write_keyboard_event_ex(&input, (uint8_t)key->scancode, core_flags);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_dynamic_channel_data(session,
                                                           session->core_input_channel_id,
                                                           session->core_input_channel_id_bytes,
                                                           input.data,
                                                           input.length,
                                                           "client.core_input.keyboard");
    }
    else
    {
        status = rdp_input_make_keyboard_flags(key, &flags);
        if (status == LIBRDP_STATUS_OK && use_unicode)
            status = rdp_slowpath_write_client_unicode_keyboard_input(&input,
                                                                      session->share_id,
                                                                      session->mcs_user_id,
                                                                      flags,
                                                                      (uint16_t)key->unicode);
        else if (status == LIBRDP_STATUS_OK)
            status = rdp_slowpath_write_client_keyboard_input(&input,
                                                              session->share_id,
                                                              session->mcs_user_id,
                                                              flags,
                                                              (uint16_t)key->scancode);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_write_slowpath_pdu(session, &input, "rdp.input.keyboard");
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&input);
        return status;
    }

    event.type = LIBRDP_EVENT_KEY_SENT;
    event.data.key = *key;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.input.send",
                    "kind=keyboard scancode=%u unicode_present=%u transport=%s flags=%u",
                    key->scancode,
                    use_unicode ? 1u : 0u,
                    use_core_input ? "core_input" : "slowpath",
                    use_core_input ? (key->state == LIBRDP_KEY_RELEASED ? 1u : 0u) : flags);
    rdp_buffer_free(&input);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_send_mouse(librdp_session* session, const librdp_mouse_event* mouse)
{
    uint16_t flags = 0;
    rdp_buffer input;
    librdp_event event;
    librdp_status status = LIBRDP_STATUS_OK;
    int use_extended = 0;
    int use_core_input = 0;

    if (!session || !mouse)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->share_id == 0)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&input);
    use_extended = rdp_input_mouse_uses_extended(mouse);
    use_core_input = session->core_input_ready;
    status = rdp_input_make_pointer_flags(mouse, &flags);
    if (status == LIBRDP_STATUS_OK)
    {
        if (use_core_input)
        {
            if (use_extended)
                status = rdp_core_input_write_extended_mouse_event(&input,
                                                                   flags,
                                                                   mouse->x,
                                                                   mouse->y);
            else
                status = rdp_core_input_write_mouse_event(&input, flags, mouse->x, mouse->y);
        }
        else if (use_extended)
            status = rdp_slowpath_write_client_extended_mouse_input(&input,
                                                                    session->share_id,
                                                                    session->mcs_user_id,
                                                                    flags,
                                                                    mouse->x,
                                                                    mouse->y);
        else
            status = rdp_slowpath_write_client_mouse_input(&input,
                                                           session->share_id,
                                                           session->mcs_user_id,
                                                           flags,
                                                           mouse->x,
                                                           mouse->y);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        if (use_core_input)
            status = rdp_session_send_dynamic_channel_data(session,
                                                           session->core_input_channel_id,
                                                           session->core_input_channel_id_bytes,
                                                           input.data,
                                                           input.length,
                                                           use_extended ? "client.core_input.mousex" :
                                                                          "client.core_input.mouse");
        else if (use_extended)
            status = rdp_session_write_slowpath_pdu(session, &input, "rdp.input.mousex");
        else
            status = rdp_session_write_slowpath_pdu(session, &input, "rdp.input.mouse");
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&input);
        return status;
    }

    event.type = LIBRDP_EVENT_MOUSE_SENT;
    event.data.mouse = *mouse;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.input.send",
                    "kind=mouse x=%u y=%u transport=%s flags=%u",
                    mouse->x,
                    mouse->y,
                    use_core_input ? (use_extended ? "core_input_mousex" : "core_input") :
                                     (use_extended ? "slowpath_mousex" : "slowpath"),
                    flags);
    rdp_buffer_free(&input);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_send_touch(librdp_session* session,
                                        uint32_t encode_time,
                                        const librdp_touch_frame* frames,
                                        uint16_t frame_count)
{
    rdp_input_channel_touch_frame* internal_frames = NULL;
    rdp_buffer* contact_buffers = NULL;
    rdp_buffer input;
    uint16_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !frames || frame_count == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    internal_frames = (rdp_input_channel_touch_frame*)calloc(frame_count, sizeof(*internal_frames));
    contact_buffers = (rdp_buffer*)calloc(frame_count, sizeof(*contact_buffers));
    if (!internal_frames || !contact_buffers)
    {
        free(internal_frames);
        free(contact_buffers);
        return LIBRDP_STATUS_NO_MEMORY;
    }

    for (i = 0; status == LIBRDP_STATUS_OK && i < frame_count; i++)
    {
        uint16_t j = 0;

        rdp_buffer_init(&contact_buffers[i]);
        if (!frames[i].contacts || frames[i].contact_count == 0)
        {
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        }
        for (j = 0; status == LIBRDP_STATUS_OK && j < frames[i].contact_count; j++)
        {
            rdp_input_channel_touch_contact contact;

            rdp_session_copy_touch_contact(&frames[i].contacts[j], &contact);
            status = rdp_input_channel_write_touch_contact(&contact_buffers[i], &contact);
        }
        internal_frames[i].contact_count = frames[i].contact_count;
        internal_frames[i].frame_offset = frames[i].frame_offset;
        internal_frames[i].contacts = contact_buffers[i].data;
        internal_frames[i].contacts_len = contact_buffers[i].length;
    }

    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_require_input_channel(session);
    rdp_buffer_init(&input);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_input_channel_write_touch_event(&input, encode_time, internal_frames, frame_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->input_channel_id,
                                                       session->input_channel_id_bytes,
                                                       input.data,
                                                       input.length,
                                                       "client.input_channel.touch");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.input_channel.touch_send",
                        "frames=%u encode_time=%u",
                        frame_count,
                        encode_time);
    rdp_buffer_free(&input);
    rdp_session_free_buffers(contact_buffers, frame_count);
    free(internal_frames);
    return status;
}

librdp_status librdp_session_send_pen(librdp_session* session,
                                      uint32_t encode_time,
                                      const librdp_pen_frame* frames,
                                      uint16_t frame_count)
{
    rdp_input_channel_pen_frame* internal_frames = NULL;
    rdp_buffer* contact_buffers = NULL;
    rdp_buffer input;
    uint16_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !frames || frame_count == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    internal_frames = (rdp_input_channel_pen_frame*)calloc(frame_count, sizeof(*internal_frames));
    contact_buffers = (rdp_buffer*)calloc(frame_count, sizeof(*contact_buffers));
    if (!internal_frames || !contact_buffers)
    {
        free(internal_frames);
        free(contact_buffers);
        return LIBRDP_STATUS_NO_MEMORY;
    }

    for (i = 0; status == LIBRDP_STATUS_OK && i < frame_count; i++)
    {
        uint16_t j = 0;

        rdp_buffer_init(&contact_buffers[i]);
        if (!frames[i].contacts || frames[i].contact_count == 0)
        {
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        }
        for (j = 0; status == LIBRDP_STATUS_OK && j < frames[i].contact_count; j++)
        {
            rdp_input_channel_pen_contact contact;

            rdp_session_copy_pen_contact(&frames[i].contacts[j], &contact);
            status = rdp_input_channel_write_pen_contact(&contact_buffers[i], &contact);
        }
        internal_frames[i].contact_count = frames[i].contact_count;
        internal_frames[i].frame_offset = frames[i].frame_offset;
        internal_frames[i].contacts = contact_buffers[i].data;
        internal_frames[i].contacts_len = contact_buffers[i].length;
    }

    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_require_input_channel(session);
    if (status == LIBRDP_STATUS_OK &&
        session->input_channel_protocol_version < RDP_INPUT_CHANNEL_PROTOCOL_V300)
        status = LIBRDP_STATUS_UNSUPPORTED;
    rdp_buffer_init(&input);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_input_channel_write_pen_event(&input, encode_time, internal_frames, frame_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->input_channel_id,
                                                       session->input_channel_id_bytes,
                                                       input.data,
                                                       input.length,
                                                       "client.input_channel.pen");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.input_channel.pen_send",
                        "frames=%u encode_time=%u",
                        frame_count,
                        encode_time);
    rdp_buffer_free(&input);
    rdp_session_free_buffers(contact_buffers, frame_count);
    free(internal_frames);
    return status;
}

librdp_status librdp_session_dismiss_touch(librdp_session* session, uint8_t contact_id)
{
    rdp_buffer input;
    librdp_status status = rdp_session_require_input_channel(session);

    rdp_buffer_init(&input);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_input_channel_write_dismiss_hovering(&input, contact_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->input_channel_id,
                                                       session->input_channel_id_bytes,
                                                       input.data,
                                                       input.length,
                                                       "client.input_channel.dismiss_hovering");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.input_channel.dismiss_hovering_send",
                        "contact_id=%u",
                        contact_id);
    rdp_buffer_free(&input);
    return status;
}

librdp_session_state librdp_session_get_state(const librdp_session* session)
{
    return session ? session->state : LIBRDP_SESSION_FAILED;
}

const librdp_surface* librdp_session_get_surface(const librdp_session* session)
{
    return session ? session->surface : NULL;
}
