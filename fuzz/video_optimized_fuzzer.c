#include "channels/video_optimized.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_video_optimized_header header;
    rdp_video_optimized_presentation_request request;
    rdp_video_optimized_presentation_response response;
    rdp_video_optimized_client_notification notification;
    rdp_video_optimized_framerate_override framerate;
    rdp_video_optimized_video_data video;
    rdp_buffer buffer;
    const uint8_t* h264 = rdp_video_optimized_h264_subtype_guid();
    uint32_t bounded_extra = size > 256u ? 256u : (uint32_t)size;
    uint32_t bounded_sample = size > 4096u ? 4096u : (uint32_t)size;

    (void)rdp_video_optimized_parse_header(data, size, &header);
    (void)rdp_video_optimized_parse_presentation_request(data, size, &request);
    (void)rdp_video_optimized_parse_presentation_response(data, size, &response);
    (void)rdp_video_optimized_parse_client_notification(data, size, &notification);
    (void)rdp_video_optimized_parse_framerate_override(data, size, &framerate);
    (void)rdp_video_optimized_parse_video_data(data, size, &video);

    rdp_buffer_init(&buffer);
    (void)rdp_video_optimized_write_presentation_start_request(
        &buffer,
        1,
        24,
        3000,
        640,
        480,
        640,
        480,
        0,
        0,
        h264,
        data,
        bounded_extra);
    buffer.length = 0;
    (void)rdp_video_optimized_write_presentation_stop_request(&buffer, 1);
    buffer.length = 0;
    (void)rdp_video_optimized_write_presentation_response(&buffer, 1);
    buffer.length = 0;
    (void)rdp_video_optimized_write_framerate_override(&buffer,
                                                       RDP_VIDEO_OPTIMIZED_FRAMERATE_OVERRIDE,
                                                       15);
    buffer.length = 0;
    (void)rdp_video_optimized_write_client_notification(
        &buffer,
        1,
        RDP_VIDEO_OPTIMIZED_NOTIFICATION_NETWORK_ERROR,
        NULL,
        0);
    buffer.length = 0;
    (void)rdp_video_optimized_write_video_data(&buffer,
                                               1,
                                               RDP_VIDEO_OPTIMIZED_DATA_FLAG_KEYFRAME,
                                               0,
                                               0,
                                               1,
                                               1,
                                               1,
                                               data,
                                               bounded_sample);
    rdp_buffer_free(&buffer);
    return 0;
}
