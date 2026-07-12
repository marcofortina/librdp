/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: V4L2 camera backend used by the viewer to feed redirected camera
 * samples.
 * Invariants: viewer state, X11 resources, and session callbacks are kept
 * consistent with focus and resize events.
 * Ownership: captured buffers are copied or released before the next device
 * dequeue boundary.
 * Threading: called from the viewer event thread unless a backend explicitly
 * documents its own callback thread.
 * Trust boundary: command-line options, local devices, X11 events, and server
 * callbacks are separate trust domains.
 */


#include "camera_v4l2.h"

#include "common/trace.h"

#include <limits.h>
#include <stdio.h>
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

#if defined(__linux__) && defined(LIBRDP_HAVE_JPEG)
#include <jpeglib.h>
#include <setjmp.h>
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
    uint8_t output_format;
#else
    int unused;
#endif
};

#ifdef __linux__
#ifdef LIBRDP_HAVE_JPEG
typedef struct x11_camera_jpeg_error
{
    struct jpeg_error_mgr base;
    jmp_buf jump;
} x11_camera_jpeg_error;

static void x11_camera_jpeg_error_exit(j_common_ptr cinfo)
{
    x11_camera_jpeg_error* error = (x11_camera_jpeg_error*)cinfo->err;

    longjmp(error->jump, 1);
}
#endif

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

static const char* x11_camera_source_path(const char* source)
{
    if (!source)
        return NULL;
    if (strncmp(source, "device=", 7u) == 0 && source[7] != '\0')
        return source + 7u;
    if (strncmp(source, "file=", 5u) == 0 && source[5] != '\0')
        return source + 5u;
    return source;
}

static int x11_camera_open_source(const char* source)
{
    const char* path = x11_camera_source_path(source);
    int flags = O_RDWR | O_NONBLOCK;

    if (!path || strncmp(path, "/dev/video", 10u) != 0)
        return -1;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    return open(path, flags);
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

static int x11_camera_set_format(x11_camera_capture* capture,
                                 const librdp_video_capture_media* media,
                                 uint32_t fourcc)
{
    struct v4l2_format format;
    struct v4l2_streamparm params;

    if (!capture || capture->fd < 0 || !media || fourcc == 0 || media->width == 0 ||
        media->height == 0)
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

static int x11_camera_apply_format(x11_camera_capture* capture, const librdp_video_capture_media* media)
{
    uint32_t fourcc = 0;

    if (!capture || capture->fd < 0 || !media)
        return 0;
    fourcc = x11_camera_fourcc(media->format);
    capture->output_format = media->format;
    if (x11_camera_set_format(capture, media, fourcc))
        return 1;
#ifdef LIBRDP_HAVE_JPEG
    if (media->format == LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG &&
        x11_camera_set_format(capture, media, V4L2_PIX_FMT_YUYV))
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.camera.format.fallback",
                        "backend=v4l2 requested=%u capture_fourcc=%u output=%u",
                        fourcc,
                        capture->fourcc,
                        media->format);
        return 1;
    }
#endif
    return 0;
}

#ifdef LIBRDP_HAVE_JPEG
static uint8_t x11_camera_clip_rgb(int value)
{
    if (value < 0)
        return 0;
    if (value > 255)
        return 255;
    return (uint8_t)value;
}

static void x11_camera_yuyv_pair_to_rgb(const uint8_t* in, uint8_t* out0, uint8_t* out1)
{
    const int y0 = in[0];
    const int cb = (int)in[1] - 128;
    const int y1 = in[2];
    const int cr = (int)in[3] - 128;
    const int r_add = (91881 * cr) >> 16;
    const int g_sub = ((22554 * cb) + (46802 * cr)) >> 16;
    const int b_add = (116130 * cb) >> 16;

    out0[0] = x11_camera_clip_rgb(y0 + r_add);
    out0[1] = x11_camera_clip_rgb(y0 - g_sub);
    out0[2] = x11_camera_clip_rgb(y0 + b_add);
    out1[0] = x11_camera_clip_rgb(y1 + r_add);
    out1[1] = x11_camera_clip_rgb(y1 - g_sub);
    out1[2] = x11_camera_clip_rgb(y1 + b_add);
}

static int x11_camera_encode_yuyv_jpeg(const uint8_t* input,
                                       size_t input_len,
                                       uint32_t width,
                                       uint32_t height,
                                       uint8_t** data,
                                       size_t* data_len)
{
    struct jpeg_compress_struct cinfo;
    x11_camera_jpeg_error jerr;
    uint8_t* row = NULL;
    unsigned char* jpeg = NULL;
    unsigned long jpeg_len = 0;
    size_t required = 0;

    if (!input || !data || !data_len || width == 0 || height == 0 ||
        width > SIZE_MAX / height / 2u)
        return 0;
    required = (size_t)width * (size_t)height * 2u;
    if (input_len < required || width > UINT_MAX || height > UINT_MAX)
        return 0;
    row = (uint8_t*)malloc((size_t)width * 3u);
    if (!row)
        return 0;
    memset(&cinfo, 0, sizeof(cinfo));
    memset(&jerr, 0, sizeof(jerr));
    cinfo.err = jpeg_std_error(&jerr.base);
    jerr.base.error_exit = x11_camera_jpeg_error_exit;
    if (setjmp(jerr.jump))
    {
        jpeg_destroy_compress(&cinfo);
        free(row);
        free(jpeg);
        return 0;
    }
    jpeg_create_compress(&cinfo);
    jpeg_mem_dest(&cinfo, &jpeg, &jpeg_len);
    cinfo.image_width = width;
    cinfo.image_height = height;
    cinfo.input_components = 3;
    cinfo.in_color_space = JCS_RGB;
    jpeg_set_defaults(&cinfo);
    jpeg_set_quality(&cinfo, 85, TRUE);
    jpeg_start_compress(&cinfo, TRUE);
    while (cinfo.next_scanline < cinfo.image_height)
    {
        const uint8_t* source = input + ((size_t)cinfo.next_scanline * (size_t)width * 2u);
        uint32_t x = 0;
        JSAMPROW row_ptr = row;

        for (x = 0; x < width; x += 2u)
        {
            uint8_t* out0 = row + ((size_t)x * 3u);
            uint8_t* out1 = out0 + 3u;

            if (x + 1u < width)
                x11_camera_yuyv_pair_to_rgb(source + ((size_t)x * 2u), out0, out1);
            else
                x11_camera_yuyv_pair_to_rgb(source + ((size_t)x * 2u), out0, out0);
        }
        jpeg_write_scanlines(&cinfo, &row_ptr, 1);
    }
    jpeg_finish_compress(&cinfo);
    jpeg_destroy_compress(&cinfo);
    free(row);
    if (!jpeg || jpeg_len == 0 || jpeg_len > SIZE_MAX)
    {
        free(jpeg);
        return 0;
    }
    *data = (uint8_t*)jpeg;
    *data_len = (size_t)jpeg_len;
    return 1;
}
#endif
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
    capture->output_format = 0;
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
                    "backend=v4l2 width=%u height=%u fourcc=%u output_format=%u buffers=%u",
                    capture->width,
                    capture->height,
                    capture->fourcc,
                    capture->output_format,
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

/*
 * Read one V4L2 camera sample for the redirected camera backend. Device
 * buffers are copied into caller-owned storage before they are requeued so the
 * protocol layer never retains driver-owned memory.
 */
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
#ifdef LIBRDP_HAVE_JPEG
    if (capture->fourcc == V4L2_PIX_FMT_YUYV &&
        capture->output_format == LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG)
    {
        if (!x11_camera_encode_yuyv_jpeg((const uint8_t*)capture->buffers[buffer.index].data,
                                         buffer.bytesused,
                                         capture->width,
                                         capture->height,
                                         &copy,
                                         data_len))
        {
            (void)x11_camera_ioctl(capture->fd, VIDIOC_QBUF, &buffer);
            return -1;
        }
    }
    else
#endif
    {
        copy = (uint8_t*)malloc(buffer.bytesused ? buffer.bytesused : 1u);
        if (!copy)
        {
            (void)x11_camera_ioctl(capture->fd, VIDIOC_QBUF, &buffer);
            return -1;
        }
        if (buffer.bytesused > 0)
            memcpy(copy, capture->buffers[buffer.index].data, buffer.bytesused);
        *data_len = buffer.bytesused;
    }
    *data = copy;
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
                          "backend=v4l2 fourcc=%u output_format=%u bytes=%u",
                          capture->fourcc,
                          capture->output_format,
                          (unsigned)*data_len);
    return 1;
#else
    (void)capture;
    (void)data;
    (void)data_len;
    return -1;
#endif
}
