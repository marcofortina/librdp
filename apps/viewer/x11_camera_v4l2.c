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


#include "x11_camera_v4l2.h"

#include "x11_trace.h"

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
    uint64_t frames;
    uint64_t bytes;
    uint64_t errors;
    uint64_t oversize_frames;
#else
    int unused;
#endif
};

static const char* x11_camera_source_path(const char* source)
{
    if (!source)
        return NULL;
    if (strncmp(source, "device=", 7u) == 0 && source[7] != '\0')
        return source + 7u;
    return source;
}

int x11_camera_source_allowed(const char* source)
{
    const char* path = x11_camera_source_path(source);
    size_t i = 0;

    if (!path || strncmp(path, "/dev/video", 10u) != 0 || path[10] == '\0')
        return 0;
    for (i = 10u; path[i] != '\0'; i++)
    {
        if (path[i] < '0' || path[i] > '9')
            return 0;
    }
    return 1;
}

static int x11_camera_format_sample_cap(uint8_t format,
                                        uint32_t width,
                                        uint32_t height,
                                        size_t* max_sample_bytes)
{
    size_t pixels = 0;
    size_t bytes = 0;

    if (width == 0 || height == 0 || width > SIZE_MAX / height)
        return 0;
    pixels = (size_t)width * (size_t)height;
    switch (format)
    {
        case LIBRDP_VIDEO_CAPTURE_MEDIA_H264:
        case LIBRDP_VIDEO_CAPTURE_MEDIA_MJPG:
            bytes = X11_CAMERA_MAX_SAMPLE_BYTES;
            break;
        case LIBRDP_VIDEO_CAPTURE_MEDIA_YUY2:
        case LIBRDP_VIDEO_CAPTURE_MEDIA_NV12:
        case LIBRDP_VIDEO_CAPTURE_MEDIA_I420:
            if (pixels > SIZE_MAX / 2u)
                return 0;
            bytes = pixels * 2u;
            break;
        case LIBRDP_VIDEO_CAPTURE_MEDIA_RGB24:
            if (pixels > SIZE_MAX / 3u)
                return 0;
            bytes = pixels * 3u;
            break;
        case LIBRDP_VIDEO_CAPTURE_MEDIA_RGB32:
            if (pixels > SIZE_MAX / 4u)
                return 0;
            bytes = pixels * 4u;
            break;
        default:
            return 0;
    }
    if (bytes == 0 || bytes > X11_CAMERA_MAX_SAMPLE_BYTES)
        return 0;
    if (max_sample_bytes)
        *max_sample_bytes = bytes;
    return 1;
}

int x11_camera_media_supported(const librdp_video_capture_media* media, size_t* max_sample_bytes)
{
    uint64_t fps = 0;

    if (max_sample_bytes)
        *max_sample_bytes = 0;
    if (!media || media->width == 0 || media->height == 0 ||
        media->width > X11_CAMERA_MAX_WIDTH || media->height > X11_CAMERA_MAX_HEIGHT ||
        (media->flags & ~(LIBRDP_VIDEO_CAPTURE_MEDIA_FLAG_DECODING_REQUIRED |
                          LIBRDP_VIDEO_CAPTURE_MEDIA_FLAG_BOTTOM_UP)) != 0)
        return 0;
    if (media->frame_rate_numerator != 0)
    {
        const uint32_t denominator = media->frame_rate_denominator ? media->frame_rate_denominator : 1u;

        fps = ((uint64_t)media->frame_rate_numerator + denominator - 1u) / denominator;
        if (fps > X11_CAMERA_MAX_FPS)
            return 0;
    }
    return x11_camera_format_sample_cap(media->format, media->width, media->height, max_sample_bytes);
}

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

static int x11_camera_open_source(const char* source)
{
    const char* path = x11_camera_source_path(source);
    int flags = O_RDWR | O_NONBLOCK;

    if (!x11_camera_source_allowed(source))
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
        x11_trace_event(X11_TRACE_CLIENT,
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
    x11_trace_event(X11_TRACE_CLIENT, "x11.camera.stop", "backend=v4l2");
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
    size_t max_sample_bytes = 0;

    if (!capture || !source || !media)
        return 0;
    x11_camera_capture_stop(capture);
    capture->frames = 0;
    capture->bytes = 0;
    capture->errors = 0;
    capture->oversize_frames = 0;
    if (!x11_camera_source_allowed(source))
    {
        capture->errors++;
        x11_trace_event(X11_TRACE_CLIENT, "x11.camera.start.failed", "backend=v4l2 reason=source_policy");
        return 0;
    }
    if (!x11_camera_media_supported(media, &max_sample_bytes))
    {
        capture->errors++;
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.camera.start.failed",
                        "backend=v4l2 reason=media_policy format=%u width=%u height=%u",
                        media->format,
                        media->width,
                        media->height);
        return 0;
    }
    capture->fd = x11_camera_open_source(source);
    if (capture->fd < 0)
    {
        capture->errors++;
        x11_trace_event(X11_TRACE_CLIENT,
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
        capture->errors++;
        x11_trace_event(X11_TRACE_CLIENT, "x11.camera.start.failed", "backend=v4l2 reason=capability");
        x11_camera_capture_stop(capture);
        return 0;
    }
    if (!x11_camera_apply_format(capture, media) || !x11_camera_prepare_buffers(capture) ||
        x11_camera_ioctl(capture->fd, VIDIOC_STREAMON, &type) < 0)
    {
        capture->errors++;
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.camera.start.failed",
                        "backend=v4l2 reason=stream format=%u width=%u height=%u",
                        media->format,
                        media->width,
                        media->height);
        x11_camera_capture_stop(capture);
        return 0;
    }
    capture->streaming = 1;
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.camera.start",
                    "backend=v4l2 width=%u height=%u fourcc=%u output_format=%u buffers=%u max_sample=%u",
                    capture->width,
                    capture->height,
                    capture->fourcc,
                    capture->output_format,
                    capture->buffer_count,
                    (unsigned)max_sample_bytes);
    return 1;
#else
    (void)capture;
    (void)source;
    (void)media;
    x11_trace_event(X11_TRACE_CLIENT, "x11.camera.start.failed", "backend=v4l2 reason=unavailable");
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
    size_t max_sample_bytes = 0;

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
    {
        if (errno == EINTR)
            return 0;
        capture->errors++;
        return -1;
    }
    memset(&buffer, 0, sizeof(buffer));
    buffer.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buffer.memory = V4L2_MEMORY_MMAP;
    if (x11_camera_ioctl(capture->fd, VIDIOC_DQBUF, &buffer) < 0)
    {
        if (errno == EAGAIN)
            return 0;
        capture->errors++;
        return -1;
    }
    if (buffer.index >= capture->buffer_count || !capture->buffers[buffer.index].data ||
        buffer.bytesused > capture->buffers[buffer.index].length)
    {
        (void)x11_camera_ioctl(capture->fd, VIDIOC_QBUF, &buffer);
        capture->errors++;
        return -1;
    }
    if (!x11_camera_format_sample_cap(capture->output_format,
                                      capture->width,
                                      capture->height,
                                      &max_sample_bytes) ||
        buffer.bytesused > max_sample_bytes)
    {
        (void)x11_camera_ioctl(capture->fd, VIDIOC_QBUF, &buffer);
        capture->errors++;
        capture->oversize_frames++;
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
            capture->errors++;
            return -1;
        }
        if (*data_len > max_sample_bytes)
        {
            free(copy);
            copy = NULL;
            *data_len = 0;
            (void)x11_camera_ioctl(capture->fd, VIDIOC_QBUF, &buffer);
            capture->errors++;
            capture->oversize_frames++;
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
            capture->errors++;
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
        capture->errors++;
        return -1;
    }
    capture->frames++;
    capture->bytes += *data_len;
    x11_trace_event_level(X11_TRACE_CLIENT,
                          X11_TRACE_LEVEL_TRACE,
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

void x11_camera_capture_get_stats(const x11_camera_capture* capture, x11_camera_capture_stats* stats)
{
    if (!stats)
        return;
    memset(stats, 0, sizeof(*stats));
    if (!capture)
        return;
#ifdef __linux__
    stats->frames = capture->frames;
    stats->bytes = capture->bytes;
    stats->errors = capture->errors;
    stats->oversize_frames = capture->oversize_frames;
    stats->streaming = capture->streaming ? 1 : 0;
#else
    (void)capture;
#endif
}

#ifdef LIBRDP_X11_CAMERA_TESTING
struct x11_camera_mock
{
    int permission_denied;
    int unplugged;
    int started;
    size_t frame_len;
    librdp_video_capture_media media;
    x11_camera_capture_stats stats;
};

x11_camera_mock* x11_camera_mock_new(int permission_denied, int unplugged, size_t frame_len)
{
    x11_camera_mock* mock = (x11_camera_mock*)calloc(1, sizeof(*mock));

    if (!mock)
        return NULL;
    mock->permission_denied = permission_denied ? 1 : 0;
    mock->unplugged = unplugged ? 1 : 0;
    mock->frame_len = frame_len;
    return mock;
}

void x11_camera_mock_free(x11_camera_mock* mock)
{
    free(mock);
}

int x11_camera_mock_start(x11_camera_mock* mock, const librdp_video_capture_media* media)
{
    size_t max_sample_bytes = 0;

    if (!mock || !media)
        return 0;
    mock->started = 0;
    memset(&mock->stats, 0, sizeof(mock->stats));
    if (mock->permission_denied)
    {
        mock->stats.errors++;
        return 0;
    }
    if (!x11_camera_media_supported(media, &max_sample_bytes))
    {
        mock->stats.errors++;
        return 0;
    }
    (void)max_sample_bytes;
    mock->media = *media;
    mock->started = 1;
    mock->stats.streaming = 1;
    return 1;
}

/*
 * Purpose: emulate one camera sample request with the same failure policy as
 * the V4L2 path. Invariant: returned data is caller-owned and oversized frames
 * are rejected before allocation. Failure policy: unplug and oversize update
 * metrics and return -1 without producing a payload.
 */
int x11_camera_mock_read_sample(x11_camera_mock* mock, uint8_t** data, size_t* data_len)
{
    size_t max_sample_bytes = 0;
    uint8_t* sample = NULL;

    if (!mock || !data || !data_len || !mock->started)
        return -1;
    *data = NULL;
    *data_len = 0;
    if (mock->unplugged)
    {
        mock->started = 0;
        mock->stats.streaming = 0;
        mock->stats.errors++;
        return -1;
    }
    if (!x11_camera_media_supported(&mock->media, &max_sample_bytes) ||
        mock->frame_len > max_sample_bytes)
    {
        mock->stats.errors++;
        mock->stats.oversize_frames++;
        return -1;
    }
    sample = (uint8_t*)malloc(mock->frame_len ? mock->frame_len : 1u);
    if (!sample)
    {
        mock->stats.errors++;
        return -1;
    }
    if (mock->frame_len > 0)
        memset(sample, 0x5a, mock->frame_len);
    *data = sample;
    *data_len = mock->frame_len;
    mock->stats.frames++;
    mock->stats.bytes += mock->frame_len;
    return 1;
}

void x11_camera_mock_get_stats(const x11_camera_mock* mock, x11_camera_capture_stats* stats)
{
    if (!stats)
        return;
    memset(stats, 0, sizeof(*stats));
    if (mock)
        *stats = mock->stats;
}
#endif
