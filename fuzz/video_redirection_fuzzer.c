#include "channels/video_redirection.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_video_redirection_header header;
    rdp_video_redirection_rim_capability rim;
    rdp_video_redirection_capability_message caps;
    rdp_video_redirection_media_type media_type;
    rdp_video_redirection_data_sample data_sample;
    rdp_video_redirection_playback_ack ack;
    rdp_video_redirection_client_event event;
    rdp_video_redirection_presentation presentation;
    rdp_video_redirection_stream stream;
    rdp_video_redirection_playback_started started;
    rdp_video_redirection_playback_rate rate;
    rdp_video_redirection_window window;
    rdp_video_redirection_geometry_update geometry_update;
    rdp_video_redirection_geometry_info geometry_info;
    rdp_video_redirection_rect rect;
    rdp_video_redirection_volume volume;
    rdp_buffer buffer;

    (void)rdp_video_redirection_parse_header(data, size, 0, &header);
    (void)rdp_video_redirection_parse_header(data, size, 1, &header);
    (void)rdp_video_redirection_parse_rim_capability_request(data, size, &rim);
    (void)rdp_video_redirection_parse_rim_capability_response(data, size, &rim);
    (void)rdp_video_redirection_parse_exchange_capabilities_request(data, size, &caps);
    (void)rdp_video_redirection_parse_exchange_capabilities_response(data, size, &caps);
    (void)rdp_video_redirection_parse_media_type(data, size, &media_type);
    (void)rdp_video_redirection_parse_data_sample(data, size, &data_sample);
    (void)rdp_video_redirection_parse_playback_ack(data, size, &ack);
    (void)rdp_video_redirection_parse_client_event(data, size, &event);
    (void)rdp_video_redirection_parse_set_channel_params(data, size, &stream);
    (void)rdp_video_redirection_parse_new_presentation(data, size, &presentation);
    (void)rdp_video_redirection_parse_add_stream(data, size, &stream);
    (void)rdp_video_redirection_parse_presentation_only(data,
                                                        size,
                                                        RDP_VIDEO_REDIRECTION_FUNC_SET_TOPOLOGY_REQ,
                                                        &presentation);
    (void)rdp_video_redirection_parse_stream_only(data,
                                                  size,
                                                  RDP_VIDEO_REDIRECTION_FUNC_ON_FLUSH,
                                                  &stream);
    (void)rdp_video_redirection_parse_playback_started(data, size, &started);
    (void)rdp_video_redirection_parse_playback_rate(data, size, &rate);
    (void)rdp_video_redirection_parse_sample_message(data, size, &stream);
    (void)rdp_video_redirection_parse_set_video_window(data, size, &window);
    (void)rdp_video_redirection_parse_geometry_update(data, size, &geometry_update);
    (void)rdp_video_redirection_parse_geometry_info(data, size, &geometry_info);
    (void)rdp_video_redirection_parse_rect(data, size, &rect);
    (void)rdp_video_redirection_parse_stream_volume(data, size, &volume);
    (void)rdp_video_redirection_parse_channel_volume(data, size, &volume);

    rdp_buffer_init(&buffer);
    (void)rdp_video_redirection_write_playback_ack(&buffer, 1, 2, 3, 4);
    buffer.length = 0;
    (void)rdp_video_redirection_write_client_event(&buffer,
                                                   1,
                                                   0,
                                                   RDP_VIDEO_REDIRECTION_CLIENT_EVENT_START_COMPLETED,
                                                   data,
                                                   size > UINT32_MAX ? UINT32_MAX : (uint32_t)size);
    buffer.length = 0;
    (void)rdp_video_redirection_write_rim_capability_response(
        &buffer,
        1,
        RDP_VIDEO_REDIRECTION_RIM_CAPABILITY_VERSION_01,
        0);
    rdp_buffer_free(&buffer);
    return 0;
}
