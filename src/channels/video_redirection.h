#ifndef RDP_CHANNELS_VIDEO_REDIRECTION_H
#define RDP_CHANNELS_VIDEO_REDIRECTION_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_VIDEO_REDIRECTION_CHANNEL_NAME "TSMF"

#define RDP_VIDEO_REDIRECTION_INTERFACE_VALUE_MASK 0x3fffffffu
#define RDP_VIDEO_REDIRECTION_STREAM_ID_NONE 0x00000000u
#define RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY 0x40000000u
#define RDP_VIDEO_REDIRECTION_STREAM_ID_STUB 0x80000000u

#define RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT 0x00000000u
#define RDP_VIDEO_REDIRECTION_INTERFACE_CLIENT_NOTIFICATIONS 0x00000001u
#define RDP_VIDEO_REDIRECTION_INTERFACE_RIM_CAPABILITIES 0x00000002u

#define RDP_VIDEO_REDIRECTION_FUNC_RELEASE 0x00000001u
#define RDP_VIDEO_REDIRECTION_FUNC_QUERY_INTERFACE 0x00000002u
#define RDP_VIDEO_REDIRECTION_FUNC_RIM_EXCHANGE_CAPABILITY_REQUEST 0x00000100u
#define RDP_VIDEO_REDIRECTION_FUNC_PLAYBACK_ACK 0x00000100u
#define RDP_VIDEO_REDIRECTION_FUNC_CLIENT_EVENT_NOTIFICATION 0x00000101u
#define RDP_VIDEO_REDIRECTION_FUNC_EXCHANGE_CAPABILITIES_REQ 0x00000100u
#define RDP_VIDEO_REDIRECTION_FUNC_SET_CHANNEL_PARAMS 0x00000101u
#define RDP_VIDEO_REDIRECTION_FUNC_ADD_STREAM 0x00000102u
#define RDP_VIDEO_REDIRECTION_FUNC_ON_SAMPLE 0x00000103u
#define RDP_VIDEO_REDIRECTION_FUNC_SET_VIDEO_WINDOW 0x00000104u
#define RDP_VIDEO_REDIRECTION_FUNC_ON_NEW_PRESENTATION 0x00000105u
#define RDP_VIDEO_REDIRECTION_FUNC_SHUTDOWN_PRESENTATION_REQ 0x00000106u
#define RDP_VIDEO_REDIRECTION_FUNC_SET_TOPOLOGY_REQ 0x00000107u
#define RDP_VIDEO_REDIRECTION_FUNC_CHECK_FORMAT_SUPPORT_REQ 0x00000108u
#define RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_STARTED 0x00000109u
#define RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_PAUSED 0x0000010au
#define RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_STOPPED 0x0000010bu
#define RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_RESTARTED 0x0000010cu
#define RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_RATE_CHANGED 0x0000010du
#define RDP_VIDEO_REDIRECTION_FUNC_ON_FLUSH 0x0000010eu
#define RDP_VIDEO_REDIRECTION_FUNC_ON_STREAM_VOLUME 0x0000010fu
#define RDP_VIDEO_REDIRECTION_FUNC_ON_CHANNEL_VOLUME 0x00000110u
#define RDP_VIDEO_REDIRECTION_FUNC_ON_END_OF_STREAM 0x00000111u
#define RDP_VIDEO_REDIRECTION_FUNC_SET_ALLOCATOR 0x00000112u
#define RDP_VIDEO_REDIRECTION_FUNC_NOTIFY_PREROLL 0x00000113u
#define RDP_VIDEO_REDIRECTION_FUNC_UPDATE_GEOMETRY_INFO 0x00000114u
#define RDP_VIDEO_REDIRECTION_FUNC_REMOVE_STREAM 0x00000115u
#define RDP_VIDEO_REDIRECTION_FUNC_SET_SOURCE_VIDEO_RECT 0x00000116u

#define RDP_VIDEO_REDIRECTION_RIM_CAPABILITY_VERSION_01 0x00000001u
#define RDP_VIDEO_REDIRECTION_CAPABILITY_PROTOCOL_VERSION 0x00000001u
#define RDP_VIDEO_REDIRECTION_CAPABILITY_PLATFORM 0x00000002u
#define RDP_VIDEO_REDIRECTION_CAPABILITY_AUDIO_SUPPORT 0x00000003u
#define RDP_VIDEO_REDIRECTION_CAPABILITY_LATENCY 0x00000004u
#define RDP_VIDEO_REDIRECTION_PROTOCOL_VERSION_2 0x00000002u
#define RDP_VIDEO_REDIRECTION_PLATFORM_MF 0x00000001u
#define RDP_VIDEO_REDIRECTION_PLATFORM_DSHOW 0x00000002u
#define RDP_VIDEO_REDIRECTION_PLATFORM_OTHER 0x00000004u
#define RDP_VIDEO_REDIRECTION_PLATFORM_COOKIE_UNDEFINED 0x00000000u
#define RDP_VIDEO_REDIRECTION_PLATFORM_COOKIE_MF 0x00000001u
#define RDP_VIDEO_REDIRECTION_PLATFORM_COOKIE_DSHOW 0x00000002u
#define RDP_VIDEO_REDIRECTION_AUDIO_SUPPORTED 0x00000001u
#define RDP_VIDEO_REDIRECTION_AUDIO_NO_DEVICE 0x00000002u

#define RDP_VIDEO_REDIRECTION_CLIENT_EVENT_ENDOFSTREAM 0x00000064u
#define RDP_VIDEO_REDIRECTION_CLIENT_EVENT_STOP_COMPLETED 0x000000c8u
#define RDP_VIDEO_REDIRECTION_CLIENT_EVENT_START_COMPLETED 0x000000c9u
#define RDP_VIDEO_REDIRECTION_CLIENT_EVENT_MONITOR_CHANGED 0x0000012cu

#define RDP_VIDEO_REDIRECTION_WINDOW_NEW 0x00000001u
#define RDP_VIDEO_REDIRECTION_WINDOW_DELETED 0x00000002u
#define RDP_VIDEO_REDIRECTION_WINDOW_VISRGN 0x00001000u

#define RDP_VIDEO_REDIRECTION_MAX_CAPABILITIES 16u

typedef struct rdp_video_redirection_header
{
    uint32_t raw_interface_id;
    uint32_t interface_id;
    uint32_t stream_id_mask;
    uint32_t message_id;
    uint8_t has_function_id;
    uint32_t function_id;
    const uint8_t* payload;
    size_t payload_len;
} rdp_video_redirection_header;

typedef struct rdp_video_redirection_capability
{
    uint32_t type;
    uint32_t length;
    const uint8_t* data;
    size_t data_len;
} rdp_video_redirection_capability;

typedef struct rdp_video_redirection_capability_list
{
    uint32_t count;
    rdp_video_redirection_capability capabilities[RDP_VIDEO_REDIRECTION_MAX_CAPABILITIES];
} rdp_video_redirection_capability_list;

typedef struct rdp_video_redirection_capability_message
{
    rdp_video_redirection_header header;
    rdp_video_redirection_capability_list capabilities;
    uint8_t has_result;
    uint32_t result;
} rdp_video_redirection_capability_message;

typedef struct rdp_video_redirection_rim_capability
{
    rdp_video_redirection_header header;
    uint32_t capability;
    uint8_t has_result;
    uint32_t result;
} rdp_video_redirection_rim_capability;

typedef struct rdp_video_redirection_media_type
{
    uint8_t major_type[16];
    uint8_t sub_type[16];
    uint32_t fixed_size_samples;
    uint32_t temporal_compression;
    uint32_t sample_size;
    uint8_t format_type[16];
    uint32_t format_len;
    const uint8_t* format;
} rdp_video_redirection_media_type;

typedef struct rdp_video_redirection_data_sample
{
    uint64_t sample_start_time;
    uint64_t sample_end_time;
    uint64_t throttle_duration;
    uint32_t sample_flags;
    uint32_t sample_extensions;
    uint32_t data_len;
    const uint8_t* data;
} rdp_video_redirection_data_sample;

typedef struct rdp_video_redirection_playback_ack
{
    rdp_video_redirection_header header;
    uint32_t stream_id;
    uint64_t data_duration;
    uint64_t data_len;
} rdp_video_redirection_playback_ack;

typedef struct rdp_video_redirection_client_event
{
    rdp_video_redirection_header header;
    uint32_t stream_id;
    uint32_t event_id;
    uint32_t data_len;
    const uint8_t* data;
} rdp_video_redirection_client_event;

typedef struct rdp_video_redirection_presentation
{
    rdp_video_redirection_header header;
    uint8_t presentation_id[16];
    uint32_t platform_cookie;
} rdp_video_redirection_presentation;

typedef struct rdp_video_redirection_stream
{
    rdp_video_redirection_header header;
    uint8_t presentation_id[16];
    uint32_t stream_id;
    uint32_t data_len;
    const uint8_t* data;
} rdp_video_redirection_stream;

typedef struct rdp_video_redirection_playback_started
{
    rdp_video_redirection_header header;
    uint8_t presentation_id[16];
    uint64_t playback_start_offset;
    uint32_t is_seek;
} rdp_video_redirection_playback_started;

typedef struct rdp_video_redirection_playback_rate
{
    rdp_video_redirection_header header;
    uint8_t presentation_id[16];
    uint32_t rate_bits;
} rdp_video_redirection_playback_rate;

typedef struct rdp_video_redirection_window
{
    rdp_video_redirection_header header;
    uint8_t presentation_id[16];
    uint64_t video_window_id;
    uint64_t parent_window_id;
} rdp_video_redirection_window;

typedef struct rdp_video_redirection_geometry_info
{
    uint64_t video_window_id;
    uint32_t window_state;
    uint32_t width;
    uint32_t height;
    uint32_t left;
    uint32_t top;
    uint64_t reserved;
    uint32_t client_left;
    uint32_t client_top;
    uint8_t has_padding;
    uint32_t padding;
} rdp_video_redirection_geometry_info;

typedef struct rdp_video_redirection_geometry_update
{
    rdp_video_redirection_header header;
    uint8_t presentation_id[16];
    uint32_t geometry_len;
    const uint8_t* geometry;
    uint32_t visible_rect_len;
    const uint8_t* visible_rect;
} rdp_video_redirection_geometry_update;

typedef struct rdp_video_redirection_rect
{
    uint32_t top;
    uint32_t left;
    uint32_t bottom;
    uint32_t right;
} rdp_video_redirection_rect;

typedef struct rdp_video_redirection_volume
{
    rdp_video_redirection_header header;
    uint8_t presentation_id[16];
    uint32_t value;
    uint32_t second_value;
} rdp_video_redirection_volume;

librdp_status rdp_video_redirection_parse_header(
    const void* data,
    size_t length,
    uint8_t has_function_id,
    rdp_video_redirection_header* header);
librdp_status rdp_video_redirection_write_header(
    rdp_buffer* buffer,
    uint32_t interface_id,
    uint32_t stream_id_mask,
    uint32_t message_id,
    uint8_t has_function_id,
    uint32_t function_id);
librdp_status rdp_video_redirection_parse_rim_capability_request(
    const void* data,
    size_t length,
    rdp_video_redirection_rim_capability* request);
librdp_status rdp_video_redirection_write_rim_capability_response(
    rdp_buffer* buffer,
    uint32_t message_id,
    uint32_t capability,
    uint32_t result);
librdp_status rdp_video_redirection_parse_rim_capability_response(
    const void* data,
    size_t length,
    rdp_video_redirection_rim_capability* response);
librdp_status rdp_video_redirection_parse_exchange_capabilities_request(
    const void* data,
    size_t length,
    rdp_video_redirection_capability_message* request);
librdp_status rdp_video_redirection_write_exchange_capabilities_response(
    rdp_buffer* buffer,
    uint32_t message_id,
    const rdp_video_redirection_capability* capabilities,
    uint32_t count,
    uint32_t result);
librdp_status rdp_video_redirection_parse_exchange_capabilities_response(
    const void* data,
    size_t length,
    rdp_video_redirection_capability_message* response);
librdp_status rdp_video_redirection_write_u32_capability(
    rdp_buffer* buffer,
    uint32_t capability_type,
    uint32_t value);
librdp_status rdp_video_redirection_parse_media_type(
    const void* data,
    size_t length,
    rdp_video_redirection_media_type* media_type);
librdp_status rdp_video_redirection_parse_data_sample(
    const void* data,
    size_t length,
    rdp_video_redirection_data_sample* sample);
librdp_status rdp_video_redirection_write_playback_ack(
    rdp_buffer* buffer,
    uint32_t message_id,
    uint32_t stream_id,
    uint64_t data_duration,
    uint64_t data_len);
librdp_status rdp_video_redirection_parse_playback_ack(
    const void* data,
    size_t length,
    rdp_video_redirection_playback_ack* ack);
librdp_status rdp_video_redirection_write_client_event(
    rdp_buffer* buffer,
    uint32_t message_id,
    uint32_t stream_id,
    uint32_t event_id,
    const void* data,
    uint32_t data_len);
librdp_status rdp_video_redirection_parse_client_event(
    const void* data,
    size_t length,
    rdp_video_redirection_client_event* event);
librdp_status rdp_video_redirection_parse_set_channel_params(
    const void* data,
    size_t length,
    rdp_video_redirection_stream* params);
librdp_status rdp_video_redirection_parse_new_presentation(
    const void* data,
    size_t length,
    rdp_video_redirection_presentation* presentation);
librdp_status rdp_video_redirection_parse_add_stream(
    const void* data,
    size_t length,
    rdp_video_redirection_stream* stream);
librdp_status rdp_video_redirection_parse_presentation_only(
    const void* data,
    size_t length,
    uint32_t function_id,
    rdp_video_redirection_presentation* presentation);
librdp_status rdp_video_redirection_parse_stream_only(
    const void* data,
    size_t length,
    uint32_t function_id,
    rdp_video_redirection_stream* stream);
librdp_status rdp_video_redirection_parse_playback_started(
    const void* data,
    size_t length,
    rdp_video_redirection_playback_started* started);
librdp_status rdp_video_redirection_parse_playback_rate(
    const void* data,
    size_t length,
    rdp_video_redirection_playback_rate* rate);
librdp_status rdp_video_redirection_parse_sample_message(
    const void* data,
    size_t length,
    rdp_video_redirection_stream* sample);
librdp_status rdp_video_redirection_parse_set_video_window(
    const void* data,
    size_t length,
    rdp_video_redirection_window* window);
librdp_status rdp_video_redirection_parse_geometry_update(
    const void* data,
    size_t length,
    rdp_video_redirection_geometry_update* update);
librdp_status rdp_video_redirection_parse_geometry_info(
    const void* data,
    size_t length,
    rdp_video_redirection_geometry_info* info);
librdp_status rdp_video_redirection_parse_rect(
    const void* data,
    size_t length,
    rdp_video_redirection_rect* rect);
librdp_status rdp_video_redirection_parse_stream_volume(
    const void* data,
    size_t length,
    rdp_video_redirection_volume* volume);
librdp_status rdp_video_redirection_parse_channel_volume(
    const void* data,
    size_t length,
    rdp_video_redirection_volume* volume);

#endif
