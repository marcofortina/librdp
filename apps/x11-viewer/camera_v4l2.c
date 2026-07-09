#include "camera_v4l2.h"

#include "common/trace.h"

#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <errno.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

#define X11_CAMERA_BUFFER_COUNT 4u

typedef struct x11_camera_buffer
{
    void* data;
    size_t length;
} x11_camera_buffer;

struct x11_camera_capture
{
#ifdef __linux__
    int fd;
    int streaming;
    x11_camera_buffer buffers[X11_CAMERA_BUFFER_COUNT];
    uint32_t buffer_count;
    uint32_t width;
    uint32_t height;
    uint32_t fourcc;
#else
    int unused;
#endif
};

#ifdef __linux__
static uint32_t x11_camera_fourcc(uint8_t format)
{
    switch (format)
    {
        case LIBRDP_VIDEO_CAPTURE_MEDIA_H264:
            return V4L2_PIX_FMT_H264;
        case LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG:
            return V4L2_PIX_FMT_MJPEG;
        case LIBRDP_VIDEO_CAPTURE_MEDIA_YUY2:
            return V4L2_PIX_FMT_YUYV;
        case LIBRDP_VIDEO_CAPTURE_MEDIA_NV12:
            return V4L2_PIX_FMT_NV12;
        case LIBRDP_VIDEO_CAPTURE_MEDIA_I420:
            return V4L2_PIX_FMT_YUV420;
        case LIBRDP_VIDEO_CAPTURE_MEDIA_RGB24:
            return V4L2_PIX_FMT_RGB24;
        case LIBRDP_VIDEO_CAPTURE_MEDIA_RGB32:
            return V4L2_PIX_FMT_RGB32;
        default:
            return 0;
    }
}

static int x11_camera_ioctl(int fd, unsigned long request, void* arg)
{
    int rc = 0;

    do
    {
        rc = ioctl(fd, request, arg);
    } while (rc < 0 && errno == EINTR);
    return rc;
}

static int x11_camera_open_source(const char* source)
{
    int flags = O_RDWR | O_NONBLOCK;

    if (!source || strncmp(source, "/dev/video", 10u) != 0)
        return -1;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    return open(source, flags);
}

static void x11_camera_clear_buffers(x11_camera_capture* capture)
{
    uint32_t i = 0;

    if (!capture)
        return;
    for (i = 0; i < capture->buffer_count; i++)
    {
        if (capture->buffers[i].data && capture->buffers[i].length > 0)
            munmap(capture->buffers[i].data, capture->buffers[i].length);
        capture->buffers[i].data = NULL;
        capture->buffers[i].length = 0;
    }
    capture->buffer_count = 0;
}

static int x11_camera_queue_all(x11_camera_capture* capture)
{
    uint32_t i = 0;

    if (!capture || capture->fd < 0)
        return 0;
    for (i = 0; i < capture->buffer_count; i++)
    {
        struct v4l2_buffer buffer;

        memset(&buffer, 0, sizeof(buffer));
        buffer.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buffer.memory = V4L2_MEMORY_MMAP;
        buffer.index = i;
        if (x11_camera_ioctl(capture->fd, VIDIOC_QBUF, &buffer) < 0)
            return 0;
    }
    return 1;
}

static int x11_camera_prepare_buffers(x11_camera_capture* capture)
{
    struct v4l2_requestbuffers request;
    uint32_t i = 0;

    if (!capture || capture->fd < 0)
        return 0;
    memset(&request, 0, sizeof(request));
    request.count = X11_CAMERA_BUFFER_COUNT;
    request.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    request.memory = V4L2_MEMORY_MMAP;
    if (x11_camera_ioctl(capture->fd, VIDIOC_REQBUFS, &request) < 0 || request.count < 2)
        return 0;
    if (request.count > X11_CAMERA_BUFFER_COUNT)
        request.count = X11_CAMERA_BUFFER_COUNT;
    capture->buffer_count = request.count;
    for (i = 0; i < capture->buffer_count; i++)
    {
        struct v4l2_buffer buffer;

        memset(&buffer, 0, sizeof(buffer));
        buffer.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buffer.memory = V4L2_MEMORY_MMAP;
        buffer.index = i;
        if (x11_camera_ioctl(capture->fd, VIDIOC_QUERYBUF, &buffer) < 0)
            return 0;
        capture->buffers[i].length = buffer.length;
        capture->buffers[i].data = mmap(NULL,
                                        buffer.length,
                                        PROT_READ | PROT_WRITE,
                                        MAP_SHARED,
                                        capture->fd,
                                        buffer.m.offset);
        if (capture->buffers[i].data == MAP_FAILED)
        {
            capture->buffers[i].data = NULL;
            capture->buffers[i].length = 0;
            return 0;
        }
    }
    return x11_camera_queue_all(capture);
}

static int x11_camera_apply_format(x11_camera_capture* capture, const librdp_video_capture_media* media)
{
    struct v4l2_format format;
    struct v4l2_streamparm params;
    uint32_t fourcc = 0;

    if (!capture || capture->fd < 0 || !media)
        return 0;
    fourcc = x11_camera_fourcc(media->format);
    if (fourcc == 0 || media->width == 0 || media->height == 0)
        return 0;
    memset(&format, 0, sizeof(format));
    format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    format.fmt.pix.width = media->width;
    format.fmt.pix.height = media->height;
    format.fmt.pix.pixelformat = fourcc;
    format.fmt.pix.field = V4L2_FIELD_NONE;
    if (x11_camera_ioctl(capture->fd, VIDIOC_S_FMT, &format) < 0)
        return 0;
    if (format.fmt.pix.pixelformat != fourcc)
        return 0;
    memset(&params, 0, sizeof(params));
    params.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    params.parm.capture.timeperframe.numerator =
        media->frame_rate_denominator ? media->frame_rate_denominator : 1;
    params.parm.capture.timeperframe.denominator =
        media->frame_rate_numerator ? media->frame_rate_numerator : 30;
    (void)x11_camera_ioctl(capture->fd, VIDIOC_S_PARM, &params);
    capture->width = format.fmt.pix.width;
    capture->height = format.fmt.pix.height;
    capture->fourcc = format.fmt.pix.pixelformat;
    return 1;
}
#endif

x11_camera_capture* x11_camera_capture_new(void)
{
    x11_camera_capture* capture = (x11_camera_capture*)calloc(1, sizeof(*capture));

#ifdef __linux__
    if (capture)
        capture->fd = -1;
#endif
    return capture;
}

void x11_camera_capture_stop(x11_camera_capture* capture)
{
#ifdef __linux__
    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

    if (!capture)
        return;
    if (capture->fd >= 0 && capture->streaming)
        (void)x11_camera_ioctl(capture->fd, VIDIOC_STREAMOFF, &type);
    capture->streaming = 0;
    x11_camera_clear_buffers(capture);
    if (capture->fd >= 0)
        close(capture->fd);
    capture->fd = -1;
    capture->width = 0;
    capture->height = 0;
    capture->fourcc = 0;
    rdp_trace_event(RDP_TRACE_CLIENT, "x11.camera.stop", "backend=v4l2");
#else
    (void)capture;
#endif
}

void x11_camera_capture_free(x11_camera_capture* capture)
{
    if (!capture)
        return;
    x11_camera_capture_stop(capture);
    free(capture);
}

int x11_camera_capture_start(x11_camera_capture* capture,
                             const char* source,
                             const librdp_video_capture_media* media)
{
#ifdef __linux__
    struct v4l2_capability capability;
    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

    if (!capture || !source || !media)
        return 0;
    x11_camera_capture_stop(capture);
    capture->fd = x11_camera_open_source(source);
    if (capture->fd < 0)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.camera.start.failed",
                        "backend=v4l2 reason=open errno=%d",
                        errno);
        return 0;
    }
    memset(&capability, 0, sizeof(capability));
    if (x11_camera_ioctl(capture->fd, VIDIOC_QUERYCAP, &capability) < 0 ||
        (capability.capabilities & V4L2_CAP_VIDEO_CAPTURE) == 0 ||
        (capability.capabilities & V4L2_CAP_STREAMING) == 0)
    {
        rdp_trace_event(RDP_TRACE_CLIENT, "x11.camera.start.failed", "backend=v4l2 reason=capability");
        x11_camera_capture_stop(capture);
        return 0;
    }
    if (!x11_camera_apply_format(capture, media) || !x11_camera_prepare_buffers(capture) ||
        x11_camera_ioctl(capture->fd, VIDIOC_STREAMON, &type) < 0)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.camera.start.failed",
                        "backend=v4l2 reason=stream format=%u width=%u height=%u",
                        media->format,
                        media->width,
                        media->height);
        x11_camera_capture_stop(capture);
        return 0;
    }
    capture->streaming = 1;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "x11.camera.start",
                    "backend=v4l2 width=%u height=%u fourcc=%u buffers=%u",
                    capture->width,
                    capture->height,
                    capture->fourcc,
                    capture->buffer_count);
    return 1;
#else
    (void)capture;
    (void)source;
    (void)media;
    rdp_trace_event(RDP_TRACE_CLIENT, "x11.camera.start.failed", "backend=v4l2 reason=unavailable");
    return 0;
#endif
}

int x11_camera_capture_read_sample(x11_camera_capture* capture, uint8_t** data, size_t* data_len)
{
#ifdef __linux__
    struct pollfd pfd;
    struct v4l2_buffer buffer;
    uint8_t* copy = NULL;
    int rc = 0;

    if (!capture || !data || !data_len || capture->fd < 0 || !capture->streaming)
        return -1;
    *data = NULL;
    *data_len = 0;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = capture->fd;
    pfd.events = POLLIN;
    rc = poll(&pfd, 1, 50);
    if (rc == 0)
        return 0;
    if (rc < 0)
        return errno == EINTR ? 0 : -1;
    memset(&buffer, 0, sizeof(buffer));
    buffer.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buffer.memory = V4L2_MEMORY_MMAP;
    if (x11_camera_ioctl(capture->fd, VIDIOC_DQBUF, &buffer) < 0)
        return errno == EAGAIN ? 0 : -1;
    if (buffer.index >= capture->buffer_count || !capture->buffers[buffer.index].data ||
        buffer.bytesused > capture->buffers[buffer.index].length)
    {
        (void)x11_camera_ioctl(capture->fd, VIDIOC_QBUF, &buffer);
        return -1;
    }
    copy = (uint8_t*)malloc(buffer.bytesused ? buffer.bytesused : 1u);
    if (!copy)
    {
        (void)x11_camera_ioctl(capture->fd, VIDIOC_QBUF, &buffer);
        return -1;
    }
    if (buffer.bytesused > 0)
        memcpy(copy, capture->buffers[buffer.index].data, buffer.bytesused);
    *data = copy;
    *data_len = buffer.bytesused;
    if (x11_camera_ioctl(capture->fd, VIDIOC_QBUF, &buffer) < 0)
    {
        free(copy);
        *data = NULL;
        *data_len = 0;
        return -1;
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "x11.camera.sample",
                          "backend=v4l2 bytes=%u",
                          (unsigned)*data_len);
    return 1;
#else
    (void)capture;
    (void)data;
    (void)data_len;
    return -1;
#endif
}
