/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: AVC420/AVC444 graphics codec reconstruction support.
 * Invariants: rectangles, strides, cache keys, and pixel formats are validated
 * before any surface mutation.
 * Ownership: decoded pixels and cache entries are owned by the caller or
 * session surface selected by the API.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: codec payloads, rectangles, and cache references are
 * untrusted server data.
 */


#include "graphics/avc.h"

#include "common/trace.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if defined(RDP_HAVE_FFMPEG_AVC)
#include <libavcodec/avcodec.h>
#include <libavutil/error.h>
#include <libavutil/frame.h>
#include <libavutil/pixfmt.h>
#include <libswscale/swscale.h>
#endif
#if defined(RDP_HAVE_OPENH264_AVC)
#include <wels/codec_api.h>
#endif

#if defined(RDP_HAVE_FFMPEG_AVC) || defined(RDP_HAVE_OPENH264_AVC)
#define RDP_HAVE_ANY_AVC 1
#endif

typedef struct rdp_avc_yuv420
{
    rdp_buffer planes[3];
    uint32_t width;
    uint32_t height;
    size_t stride[3];
} rdp_avc_yuv420;

typedef struct rdp_avc_yuv444_snapshot
{
    rdp_buffer planes[3];
    size_t stride[3];
    uint32_t width;
    uint32_t height;
    uint8_t luma_valid;
    uint8_t chroma_valid;
    uint8_t active;
} rdp_avc_yuv444_snapshot;

#if defined(RDP_HAVE_FFMPEG_AVC)
typedef struct rdp_avc_h264
{
    AVCodecContext* context;
    AVPacket* packet;
    AVFrame* frame;
    struct SwsContext* to_bgra;
    struct SwsContext* to_yuv420;
} rdp_avc_h264;
#endif

#if defined(RDP_HAVE_OPENH264_AVC)
typedef struct rdp_avc_openh264
{
    ISVCDecoder* decoder;
} rdp_avc_openh264;
#endif

struct rdp_avc_decoder
{
#if defined(RDP_HAVE_FFMPEG_AVC)
    rdp_avc_h264 main_stream;
    rdp_avc_h264 aux_stream;
#endif
#if defined(RDP_HAVE_OPENH264_AVC)
    rdp_avc_openh264 openh264_main_stream;
    rdp_avc_openh264 openh264_aux_stream;
#endif
#if defined(RDP_HAVE_ANY_AVC)
    rdp_avc_yuv420 main_yuv;
    rdp_avc_yuv420 aux_yuv;
    rdp_buffer yuv444[3];
    size_t yuv444_stride[3];
    uint32_t yuv444_width;
    uint32_t yuv444_height;
    uint8_t yuv444_luma_valid;
    uint8_t yuv444_chroma_valid;
#endif
#if defined(RDP_HAVE_FFMPEG_AVC)
    struct SwsContext* yuv444_to_bgra;
#endif
    uint8_t unused;
};

#if defined(RDP_HAVE_ANY_AVC)
static int rdp_avc_mul_overflow_size(size_t a, size_t b, size_t* out)
{
    if (!out)
        return 1;
    if (a != 0 && b > ((size_t)-1) / a)
        return 1;
    *out = a * b;
    return 0;
}
#endif

#if defined(RDP_HAVE_ANY_AVC)
static librdp_status rdp_avc_frame_prepare(rdp_avc_frame* frame, uint32_t width, uint32_t height)
{
    size_t stride = 0;
    size_t length = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!frame || width == 0 || height == 0 || width > (uint32_t)INT_MAX / 4u ||
        height > (uint32_t)INT_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    stride = (size_t)width * 4u;
    if (rdp_avc_mul_overflow_size(stride, height, &length))
        return LIBRDP_STATUS_NO_MEMORY;
    status = rdp_buffer_reserve(&frame->pixels, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    frame->pixels.length = length;
    frame->width = width;
    frame->height = height;
    frame->stride = stride;
    return LIBRDP_STATUS_OK;
}
#endif

void rdp_avc_frame_init(rdp_avc_frame* frame)
{
    if (!frame)
        return;
    memset(frame, 0, sizeof(*frame));
    rdp_buffer_init(&frame->pixels);
}

void rdp_avc_frame_free(rdp_avc_frame* frame)
{
    if (!frame)
        return;
    rdp_buffer_free(&frame->pixels);
    frame->width = 0;
    frame->height = 0;
    frame->stride = 0;
}

#if defined(RDP_HAVE_FFMPEG_AVC)
static void rdp_avc_frame_move(rdp_avc_frame* dst, rdp_avc_frame* src)
{
    if (!dst || !src || dst == src)
        return;
    rdp_buffer_free(&dst->pixels);
    *dst = *src;
    src->pixels.data = NULL;
    src->pixels.length = 0;
    src->pixels.capacity = 0;
    src->width = 0;
    src->height = 0;
    src->stride = 0;
}
#endif

static uint8_t rdp_avc_clip_u8(int value)
{
    if (value < 0)
        return 0;
    if (value > 255)
        return 255;
    return (uint8_t)value;
}

#if defined(RDP_HAVE_ANY_AVC)
static void rdp_avc_yuv420_init(rdp_avc_yuv420* yuv)
{
    size_t i = 0;

    if (!yuv)
        return;
    memset(yuv, 0, sizeof(*yuv));
    for (i = 0; i < 3u; i++)
        rdp_buffer_init(&yuv->planes[i]);
}

static void rdp_avc_yuv420_free(rdp_avc_yuv420* yuv)
{
    size_t i = 0;

    if (!yuv)
        return;
    for (i = 0; i < 3u; i++)
        rdp_buffer_free(&yuv->planes[i]);
    memset(yuv, 0, sizeof(*yuv));
}

static void rdp_avc_yuv420_move(rdp_avc_yuv420* dst, rdp_avc_yuv420* src)
{
    size_t i = 0;

    if (!dst || !src || dst == src)
        return;
    rdp_avc_yuv420_free(dst);
    *dst = *src;
    for (i = 0; i < 3u; i++)
    {
        src->planes[i].data = NULL;
        src->planes[i].length = 0;
        src->planes[i].capacity = 0;
        src->stride[i] = 0;
    }
    src->width = 0;
    src->height = 0;
}

static void rdp_avc_yuv444_snapshot_init(rdp_avc_yuv444_snapshot* snapshot)
{
    size_t i = 0;

    if (!snapshot)
        return;
    memset(snapshot, 0, sizeof(*snapshot));
    for (i = 0; i < 3u; i++)
        rdp_buffer_init(&snapshot->planes[i]);
}

static void rdp_avc_yuv444_snapshot_free(rdp_avc_yuv444_snapshot* snapshot)
{
    size_t i = 0;

    if (!snapshot)
        return;
    for (i = 0; i < 3u; i++)
        rdp_buffer_free(&snapshot->planes[i]);
    memset(snapshot, 0, sizeof(*snapshot));
}

static librdp_status rdp_avc_yuv444_snapshot_capture(rdp_avc_decoder* decoder,
                                                     rdp_avc_yuv444_snapshot* snapshot)
{
    size_t i = 0;

    if (!decoder || !snapshot)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_avc_yuv444_snapshot_init(snapshot);
    snapshot->width = decoder->yuv444_width;
    snapshot->height = decoder->yuv444_height;
    snapshot->luma_valid = decoder->yuv444_luma_valid;
    snapshot->chroma_valid = decoder->yuv444_chroma_valid;
    for (i = 0; i < 3u; i++)
    {
        librdp_status status = rdp_buffer_reserve(&snapshot->planes[i], decoder->yuv444[i].length);

        if (status != LIBRDP_STATUS_OK)
        {
            rdp_avc_yuv444_snapshot_free(snapshot);
            return status;
        }
        if (decoder->yuv444[i].length > 0)
            memcpy(snapshot->planes[i].data, decoder->yuv444[i].data, decoder->yuv444[i].length);
        snapshot->planes[i].length = decoder->yuv444[i].length;
        snapshot->stride[i] = decoder->yuv444_stride[i];
    }
    snapshot->active = 1;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_avc_yuv444_snapshot_restore(rdp_avc_decoder* decoder,
                                                     const rdp_avc_yuv444_snapshot* snapshot)
{
    size_t i = 0;

    if (!decoder || !snapshot)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!snapshot->active)
        return LIBRDP_STATUS_OK;
    for (i = 0; i < 3u; i++)
    {
        librdp_status status = rdp_buffer_reserve(&decoder->yuv444[i], snapshot->planes[i].length);

        if (status != LIBRDP_STATUS_OK)
            return status;
        if (snapshot->planes[i].length > 0)
            memcpy(decoder->yuv444[i].data, snapshot->planes[i].data, snapshot->planes[i].length);
        decoder->yuv444[i].length = snapshot->planes[i].length;
        decoder->yuv444_stride[i] = snapshot->stride[i];
    }
    decoder->yuv444_width = snapshot->width;
    decoder->yuv444_height = snapshot->height;
    decoder->yuv444_luma_valid = snapshot->luma_valid;
    decoder->yuv444_chroma_valid = snapshot->chroma_valid;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_avc_yuv420_prepare(rdp_avc_yuv420* yuv, uint32_t width, uint32_t height)
{
    size_t y_length = 0;
    size_t c_width = 0;
    size_t c_height = 0;
    size_t c_length = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!yuv || width == 0 || height == 0 || width > (uint32_t)INT_MAX || height > (uint32_t)INT_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    yuv->stride[0] = width;
    yuv->stride[1] = ((size_t)width + 1u) / 2u;
    yuv->stride[2] = yuv->stride[1];
    c_width = yuv->stride[1];
    c_height = ((size_t)height + 1u) / 2u;
    if (rdp_avc_mul_overflow_size(width, height, &y_length) ||
        rdp_avc_mul_overflow_size(c_width, c_height, &c_length))
        return LIBRDP_STATUS_NO_MEMORY;
    status = rdp_buffer_reserve(&yuv->planes[0], y_length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_reserve(&yuv->planes[1], c_length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_reserve(&yuv->planes[2], c_length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    yuv->planes[0].length = y_length;
    yuv->planes[1].length = c_length;
    yuv->planes[2].length = c_length;
    yuv->width = width;
    yuv->height = height;
    return LIBRDP_STATUS_OK;
}
#endif

static librdp_status rdp_avc_parse_region(const rdp_graphics_avc420_metablock* meta,
                                          uint32_t index,
                                          rdp_graphics_rect16* rect)
{
    if (!meta || !rect || index >= meta->rect_count || meta->rects_len < ((size_t)index + 1u) * 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_graphics_parse_rect16(meta->rects + ((size_t)index * 8u), 8u, rect);
}

static librdp_status rdp_avc_validate_surface_rect(uint32_t surface_width,
                                                   uint32_t surface_height,
                                                   const rdp_graphics_rect16* rect)
{
    if (!rect || surface_width == 0 || surface_height == 0 ||
        rect->left >= rect->right || rect->top >= rect->bottom ||
        rect->right > surface_width || rect->bottom > surface_height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_avc_validate_metablock_regions(const rdp_graphics_avc420_metablock* meta,
                                                        uint32_t surface_width,
                                                        uint32_t surface_height)
{
    uint32_t i = 0;

    if (!meta || meta->rect_count == 0 ||
        meta->rects_len < (size_t)meta->rect_count * 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < meta->rect_count; i++)
    {
        rdp_graphics_rect16 rect;
        librdp_status status = rdp_avc_parse_region(meta, i, &rect);

        if (status == LIBRDP_STATUS_OK)
            status = rdp_avc_validate_surface_rect(surface_width, surface_height, &rect);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Reconstruct AVC444 chroma planes from the split auxiliary stream. The merge
 * path validates plane sizes and falls back predictably when chroma payloads
 * are absent or clipped.
 */
librdp_status rdp_avc_reconstruct_444_chroma(const rdp_avc_444_chroma_view* view)
{
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t padded_height = 0;
    uint32_t u_row = 0;
    uint32_t v_row = 0;
    uint32_t y = 0;
    uint32_t odd_column_count = 0;
    uint32_t first_odd_column = 0;
    uint32_t even_row_count = 0;

    if (!view || !view->aux_y || !view->aux_u || !view->aux_v || !view->dst_u || !view->dst_v ||
        view->aux_width == 0 || view->aux_height == 0 || view->dst_width == 0 || view->dst_height == 0 ||
        view->rect.left >= view->rect.right || view->rect.top >= view->rect.bottom ||
        view->rect.right > view->aux_width || view->rect.bottom > view->aux_height ||
        view->rect.right > view->dst_width || view->rect.bottom > view->dst_height ||
        view->aux_y_stride < view->aux_width || view->dst_u_stride < view->dst_width ||
        view->dst_v_stride < view->dst_width)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    width = (uint32_t)(view->rect.right - view->rect.left);
    height = (uint32_t)(view->rect.bottom - view->rect.top);
    padded_height = ((height + 15u) / 16u) * 16u;
    odd_column_count = (uint32_t)(view->rect.right / 2u - view->rect.left / 2u);
    first_odd_column = (view->rect.left & 1u) ? 0u : 1u;
    even_row_count = (height + 1u) / 2u;
    if (view->aux_u_stride < ((size_t)view->aux_width + 1u) / 2u ||
        view->aux_v_stride < ((size_t)view->aux_width + 1u) / 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    for (y = 0; y < padded_height; y++)
    {
        uint32_t dest_row = 0;
        uint32_t src_row = 0;
        uint8_t* dest = NULL;
        const uint8_t* src = NULL;

        if ((y % 16u) < 8u)
        {
            dest_row = view->rect.top + 2u * u_row + 1u;
            u_row++;
            if (dest_row >= view->rect.bottom)
                continue;
            dest = view->dst_u + ((size_t)dest_row * view->dst_u_stride) + view->rect.left;
        }
        else
        {
            dest_row = view->rect.top + 2u * v_row + 1u;
            v_row++;
            if (dest_row >= view->rect.bottom)
                continue;
            dest = view->dst_v + ((size_t)dest_row * view->dst_v_stride) + view->rect.left;
        }
        src_row = view->rect.top + y;
        if (src_row >= view->aux_height)
            src_row = view->aux_height - 1u;
        if (view->rect.left + width > view->aux_y_stride)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        src = view->aux_y + ((size_t)src_row * view->aux_y_stride) + view->rect.left;
        memcpy(dest, src, width);
    }

    for (y = 0; y < even_row_count; y++)
    {
        uint32_t dest_row = view->rect.top + 2u * y;
        const uint8_t* src_u = NULL;
        const uint8_t* src_v = NULL;
        uint8_t* dest_u = NULL;
        uint8_t* dest_v = NULL;
        uint32_t x = 0;

        if (dest_row >= view->rect.bottom)
            break;
        if ((size_t)(view->rect.top / 2u + y) >= (((size_t)view->aux_height + 1u) / 2u))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if ((size_t)(view->rect.left / 2u) + odd_column_count > view->aux_u_stride ||
            (size_t)(view->rect.left / 2u) + odd_column_count > view->aux_v_stride)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        src_u = view->aux_u + ((size_t)(view->rect.top / 2u + y) * view->aux_u_stride) +
                (view->rect.left / 2u);
        src_v = view->aux_v + ((size_t)(view->rect.top / 2u + y) * view->aux_v_stride) +
                (view->rect.left / 2u);
        dest_u = view->dst_u + ((size_t)dest_row * view->dst_u_stride) + view->rect.left;
        dest_v = view->dst_v + ((size_t)dest_row * view->dst_v_stride) + view->rect.left;
        for (x = 0; x < odd_column_count; x++)
        {
            uint32_t dest_col = first_odd_column + 2u * x;

            if (view->rect.left + dest_col >= view->rect.right)
                break;
            dest_u[dest_col] = src_u[x];
            dest_v[dest_col] = src_v[x];
        }
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Reconstruct AVC444v2 chroma planes from luma-aligned decoder output. Plane
 * dimensions and edge padding are handled here so callers receive a complete
 * BGRA-ready image.
 */
librdp_status rdp_avc_reconstruct_444v2_chroma(const rdp_avc_444v2_chroma_view* view)
{
    size_t half_source_width = 0;
    size_t quarter_source_width = 0;
    uint32_t y = 0;

    if (!view || !view->aux_y || !view->aux_u || !view->aux_v || !view->dst_u || !view->dst_v ||
        view->aux_width == 0 || view->aux_height == 0 || view->dst_width == 0 || view->dst_height == 0 ||
        view->rect.left >= view->rect.right || view->rect.top >= view->rect.bottom ||
        view->rect.right > view->aux_width || view->rect.bottom > view->aux_height ||
        view->rect.right > view->dst_width || view->rect.bottom > view->dst_height ||
        view->aux_y_stride < view->aux_width || view->dst_u_stride < view->dst_width ||
        view->dst_v_stride < view->dst_width)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    half_source_width = ((size_t)view->aux_width + 1u) / 2u;
    quarter_source_width = ((size_t)view->aux_width + 3u) / 4u;
    if (view->aux_u_stride < quarter_source_width * 2u ||
        view->aux_v_stride < quarter_source_width * 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    for (y = view->rect.top; y < view->rect.bottom; y++)
    {
        uint8_t* dst_u = NULL;
        uint8_t* dst_v = NULL;
        const uint8_t* src = NULL;
        uint32_t x = view->rect.left;

        dst_u = view->dst_u + ((size_t)y * view->dst_u_stride);
        dst_v = view->dst_v + ((size_t)y * view->dst_v_stride);
        src = view->aux_y + ((size_t)y * view->aux_y_stride);

        for (; x < view->rect.right; x++)
        {
            size_t src_u_col = (size_t)x / 2u;
            size_t src_v_col = src_u_col + half_source_width;

            if ((x & 1u) == 0)
                continue;
            if (src_u_col >= half_source_width || src_v_col >= view->aux_y_stride)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            dst_u[x] = src[src_u_col];
            dst_v[x] = src[src_v_col];
        }
    }

    for (y = view->rect.top; y < view->rect.bottom; y++)
    {
        size_t src_row = (size_t)y / 2u;
        uint8_t* dst_u = NULL;
        uint8_t* dst_v = NULL;
        uint32_t x = view->rect.left;

        if ((y & 1u) == 0)
            continue;
        if (src_row >= (((size_t)view->aux_height + 1u) / 2u))
            return LIBRDP_STATUS_PROTOCOL_ERROR;

        dst_u = view->dst_u + ((size_t)y * view->dst_u_stride);
        dst_v = view->dst_v + ((size_t)y * view->dst_v_stride);

        for (; x < view->rect.right; x++)
        {
            size_t src_col = (size_t)x / 4u;
            size_t src_pair_col = src_col + quarter_source_width;
            const uint8_t* src_plane = NULL;
            size_t src_stride = 0;

            if ((x & 1u) != 0)
                continue;
            if ((x & 3u) == 0)
            {
                src_plane = view->aux_u + src_row * view->aux_u_stride;
                src_stride = view->aux_u_stride;
            }
            else
            {
                src_plane = view->aux_v + src_row * view->aux_v_stride;
                src_stride = view->aux_v_stride;
            }
            if (src_col >= quarter_source_width || src_pair_col >= src_stride)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            dst_u[x] = src_plane[src_col];
            dst_v[x] = src_plane[src_pair_col];
        }
    }

    for (y = (view->rect.top + 1u) & ~1u; y + 1u < view->rect.bottom; y += 2u)
    {
        uint8_t* dst_u0 = view->dst_u + ((size_t)y * view->dst_u_stride);
        uint8_t* dst_v0 = view->dst_v + ((size_t)y * view->dst_v_stride);
        const uint8_t* dst_u1 = view->dst_u + (((size_t)y + 1u) * view->dst_u_stride);
        const uint8_t* dst_v1 = view->dst_v + (((size_t)y + 1u) * view->dst_v_stride);
        uint32_t x = (view->rect.left + 1u) & ~1u;

        for (; x + 1u < view->rect.right; x += 2u)
        {
            int u = 4 * (int)dst_u0[x] - (int)dst_u0[x + 1u] - (int)dst_u1[x] - (int)dst_u1[x + 1u];
            int v = 4 * (int)dst_v0[x] - (int)dst_v0[x + 1u] - (int)dst_v1[x] - (int)dst_v1[x + 1u];
            uint8_t ru = rdp_avc_clip_u8(u);
            uint8_t rv = rdp_avc_clip_u8(v);

            dst_u0[x] = ru;
            dst_v0[x] = rv;
        }
    }

    return LIBRDP_STATUS_OK;
}

#if defined(RDP_HAVE_ANY_AVC)

#if defined(RDP_HAVE_FFMPEG_AVC)
static void rdp_avc_h264_reset(rdp_avc_h264* h264)
{
    if (!h264)
        return;
    if (h264->context)
        avcodec_flush_buffers(h264->context);
    if (h264->packet)
        av_packet_unref(h264->packet);
    if (h264->frame)
        av_frame_unref(h264->frame);
}

static void rdp_avc_h264_free(rdp_avc_h264* h264)
{
    if (!h264)
        return;
    sws_freeContext(h264->to_bgra);
    sws_freeContext(h264->to_yuv420);
    h264->to_bgra = NULL;
    h264->to_yuv420 = NULL;
    av_frame_free(&h264->frame);
    av_packet_free(&h264->packet);
    avcodec_free_context(&h264->context);
}

static librdp_status rdp_avc_h264_open(rdp_avc_h264* h264)
{
    const AVCodec* codec = NULL;

    if (!h264)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (h264->context)
        return LIBRDP_STATUS_OK;

    codec = avcodec_find_decoder(AV_CODEC_ID_H264);
    if (!codec)
        return LIBRDP_STATUS_UNSUPPORTED;
    h264->context = avcodec_alloc_context3(codec);
    h264->packet = av_packet_alloc();
    h264->frame = av_frame_alloc();
    if (!h264->context || !h264->packet || !h264->frame)
        return LIBRDP_STATUS_NO_MEMORY;
    h264->context->thread_count = 1;
    if (avcodec_open2(h264->context, codec, NULL) < 0)
    {
        rdp_avc_h264_free(h264);
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_avc_h264_decode(rdp_avc_h264* h264, const uint8_t* data, size_t length)
{
    int rc = 0;
    int got = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!h264 || !data || length == 0 || length > (size_t)INT_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_avc_h264_open(h264);
    if (status != LIBRDP_STATUS_OK)
        return status;

    av_packet_unref(h264->packet);
    av_frame_unref(h264->frame);
    rc = av_new_packet(h264->packet, (int)length);
    if (rc < 0)
        return LIBRDP_STATUS_NO_MEMORY;
    memcpy(h264->packet->data, data, length);
    rc = avcodec_send_packet(h264->context, h264->packet);
    av_packet_unref(h264->packet);
    if (rc < 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    for (;;)
    {
        rc = avcodec_receive_frame(h264->context, h264->frame);
        if (rc == 0)
        {
            got = 1;
            break;
        }
        if (rc == AVERROR(EAGAIN) || rc == AVERROR_EOF)
            break;
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return got ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

static void rdp_avc_configure_sws_colorspace(struct SwsContext* context)
{
    const int* coefficients = NULL;

    if (!context)
        return;
    coefficients = sws_getCoefficients(SWS_CS_ITU709);
    if (!coefficients)
        return;
    (void)sws_setColorspaceDetails(context,
                                   coefficients,
                                   1,
                                   coefficients,
                                   1,
                                   0,
                                   1 << 16,
                                   1 << 16);
}

static librdp_status rdp_avc_frame_to_bgra(rdp_avc_h264* h264,
                                           uint32_t surface_width,
                                           uint32_t surface_height,
                                           rdp_avc_frame* frame)
{
    rdp_avc_frame converted;
    uint8_t* dst_data[4] = {0};
    int dst_stride[4] = {0};
    int rows = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_avc_frame_init(&converted);
    if (!h264 || !h264->frame || !frame || h264->frame->width <= 0 || h264->frame->height <= 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((uint32_t)h264->frame->width > surface_width || (uint32_t)h264->frame->height > surface_height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    h264->to_bgra = sws_getCachedContext(h264->to_bgra,
                                         h264->frame->width,
                                         h264->frame->height,
                                         (enum AVPixelFormat)h264->frame->format,
                                         h264->frame->width,
                                         h264->frame->height,
                                         AV_PIX_FMT_BGRA,
                                         SWS_FAST_BILINEAR,
                                         NULL,
                                         NULL,
                                         NULL);
    if (!h264->to_bgra)
        return LIBRDP_STATUS_UNSUPPORTED;
    rdp_avc_configure_sws_colorspace(h264->to_bgra);
    status = rdp_avc_frame_prepare(&converted, (uint32_t)h264->frame->width, (uint32_t)h264->frame->height);
    if (status != LIBRDP_STATUS_OK)
        return status;
    dst_data[0] = converted.pixels.data;
    dst_stride[0] = (int)converted.stride;
    rows = sws_scale(h264->to_bgra,
                     (const uint8_t* const*)h264->frame->data,
                     h264->frame->linesize,
                     0,
                     h264->frame->height,
                     dst_data,
                     dst_stride);
    if (rows == h264->frame->height)
        rdp_avc_frame_move(frame, &converted);
    else
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_avc_frame_free(&converted);
    return status;
}

static librdp_status rdp_avc_frame_to_yuv420(rdp_avc_h264* h264,
                                             uint32_t surface_width,
                                             uint32_t surface_height,
                                             rdp_avc_yuv420* yuv)
{
    uint8_t* dst_data[4] = {0};
    int dst_stride[4] = {0};
    int rows = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!h264 || !h264->frame || !yuv || h264->frame->width <= 0 || h264->frame->height <= 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((uint32_t)h264->frame->width > surface_width || (uint32_t)h264->frame->height > surface_height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_avc_yuv420_prepare(yuv, (uint32_t)h264->frame->width, (uint32_t)h264->frame->height);
    if (status != LIBRDP_STATUS_OK)
        return status;
    h264->to_yuv420 = sws_getCachedContext(h264->to_yuv420,
                                           h264->frame->width,
                                           h264->frame->height,
                                           (enum AVPixelFormat)h264->frame->format,
                                           h264->frame->width,
                                           h264->frame->height,
                                           AV_PIX_FMT_YUV420P,
                                           SWS_FAST_BILINEAR,
                                           NULL,
                                           NULL,
                                           NULL);
    if (!h264->to_yuv420)
        return LIBRDP_STATUS_UNSUPPORTED;
    rdp_avc_configure_sws_colorspace(h264->to_yuv420);
    dst_data[0] = yuv->planes[0].data;
    dst_data[1] = yuv->planes[1].data;
    dst_data[2] = yuv->planes[2].data;
    dst_stride[0] = (int)yuv->stride[0];
    dst_stride[1] = (int)yuv->stride[1];
    dst_stride[2] = (int)yuv->stride[2];
    rows = sws_scale(h264->to_yuv420,
                     (const uint8_t* const*)h264->frame->data,
                     h264->frame->linesize,
                     0,
                     h264->frame->height,
                     dst_data,
                     dst_stride);
    return rows == h264->frame->height ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}
#endif

#if defined(RDP_HAVE_OPENH264_AVC)
static void rdp_avc_openh264_free(rdp_avc_openh264* h264)
{
    if (!h264)
        return;
    if (h264->decoder)
    {
        (void)(*h264->decoder)->Uninitialize(h264->decoder);
        WelsDestroyDecoder(h264->decoder);
        h264->decoder = NULL;
    }
}

static void rdp_avc_openh264_reset(rdp_avc_openh264* h264)
{
    if (!h264 || !h264->decoder)
        return;
    rdp_avc_openh264_free(h264);
}

static librdp_status rdp_avc_openh264_open(rdp_avc_openh264* h264)
{
    SDecodingParam param;

    if (!h264)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (h264->decoder)
        return LIBRDP_STATUS_OK;
    memset(&param, 0, sizeof(param));
    param.eEcActiveIdc = ERROR_CON_DISABLE;
    param.sVideoProperty.size = sizeof(param.sVideoProperty);
    param.sVideoProperty.eVideoBsType = VIDEO_BITSTREAM_AVC;
    if (WelsCreateDecoder(&h264->decoder) != 0 || !h264->decoder)
    {
        h264->decoder = NULL;
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    if ((*h264->decoder)->Initialize(h264->decoder, &param) != 0)
    {
        rdp_avc_openh264_free(h264);
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_avc_openh264_copy_output(const SBufferInfo* info,
                                                  uint8_t* const planes[3],
                                                  rdp_avc_yuv420* yuv,
                                                  uint32_t surface_width,
                                                  uint32_t surface_height)
{
    int width = 0;
    int height = 0;
    int stride_y = 0;
    int stride_c = 0;
    uint32_t row = 0;
    size_t c_width = 0;
    size_t c_height = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!info || !planes || !yuv || info->iBufferStatus != 1 ||
        info->UsrData.sSystemBuffer.iFormat != videoFormatI420 || !planes[0] || !planes[1] || !planes[2])
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    width = info->UsrData.sSystemBuffer.iWidth;
    height = info->UsrData.sSystemBuffer.iHeight;
    stride_y = info->UsrData.sSystemBuffer.iStride[0];
    stride_c = info->UsrData.sSystemBuffer.iStride[1];
    if (width <= 0 || height <= 0 || stride_y < width || stride_c < (width + 1) / 2 ||
        (uint32_t)width > surface_width || (uint32_t)height > surface_height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_avc_yuv420_prepare(yuv, (uint32_t)width, (uint32_t)height);
    if (status != LIBRDP_STATUS_OK)
        return status;

    for (row = 0; row < (uint32_t)height; row++)
        memcpy(yuv->planes[0].data + ((size_t)row * yuv->stride[0]),
               planes[0] + ((size_t)row * (size_t)stride_y),
               (size_t)width);

    c_width = ((size_t)width + 1u) / 2u;
    c_height = ((size_t)height + 1u) / 2u;
    for (row = 0; row < c_height; row++)
    {
        memcpy(yuv->planes[1].data + ((size_t)row * yuv->stride[1]),
               planes[1] + ((size_t)row * (size_t)stride_c),
               c_width);
        memcpy(yuv->planes[2].data + ((size_t)row * yuv->stride[2]),
               planes[2] + ((size_t)row * (size_t)stride_c),
               c_width);
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_avc_openh264_decode_to_yuv420(rdp_avc_openh264* h264,
                                                       const uint8_t* data,
                                                       size_t length,
                                                       uint32_t surface_width,
                                                       uint32_t surface_height,
                                                       rdp_avc_yuv420* yuv)
{
    SBufferInfo info;
    uint8_t* planes[3] = {0};
    DECODING_STATE state = dsErrorFree;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!h264 || !data || length == 0 || length > (size_t)INT_MAX || !yuv)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_avc_openh264_open(h264);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(&info, 0, sizeof(info));
    state = (*h264->decoder)->DecodeFrameNoDelay(h264->decoder, data, (int)length, planes, &info);
    if ((state & (dsInvalidArgument | dsInitialOptExpected | dsOutOfMemory | dsDstBufNeedExpan)) != 0)
        return state == dsOutOfMemory ? LIBRDP_STATUS_NO_MEMORY : LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_avc_openh264_copy_output(&info, planes, yuv, surface_width, surface_height);
}
#endif

static librdp_status rdp_avc_ensure_yuv444(rdp_avc_decoder* decoder, uint32_t width, uint32_t height)
{
    size_t length = 0;
    size_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!decoder || width == 0 || height == 0 || width > (uint32_t)INT_MAX || height > (uint32_t)INT_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_avc_mul_overflow_size(width, height, &length))
        return LIBRDP_STATUS_NO_MEMORY;
    if (decoder->yuv444_width != width || decoder->yuv444_height != height)
    {
        decoder->yuv444_luma_valid = 0;
        decoder->yuv444_chroma_valid = 0;
        decoder->yuv444_width = width;
        decoder->yuv444_height = height;
        decoder->yuv444_stride[0] = width;
        decoder->yuv444_stride[1] = width;
        decoder->yuv444_stride[2] = width;
    }
    for (i = 0; i < 3u; i++)
    {
        status = rdp_buffer_reserve(&decoder->yuv444[i], length);
        if (status != LIBRDP_STATUS_OK)
            return status;
        decoder->yuv444[i].length = length;
    }
    if (!decoder->yuv444_luma_valid && !decoder->yuv444_chroma_valid)
    {
        memset(decoder->yuv444[0].data, 0, decoder->yuv444[0].length);
        memset(decoder->yuv444[1].data, 128, decoder->yuv444[1].length);
        memset(decoder->yuv444[2].data, 128, decoder->yuv444[2].length);
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_avc_validate_rect(const rdp_avc_yuv420* yuv,
                                           uint32_t surface_width,
                                           uint32_t surface_height,
                                           const rdp_graphics_rect16* rect)
{
    if (!yuv || !rect || rect->left >= rect->right || rect->top >= rect->bottom ||
        rect->right > surface_width || rect->bottom > surface_height ||
        rect->right > yuv->width || rect->bottom > yuv->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

/*
 * Apply decoded AVC luma data into the destination image while preserving
 * chroma state. Stride and rectangle checks keep partial tiles from
 * overwriting neighboring pixels.
 */
static librdp_status rdp_avc_apply_luma(rdp_avc_decoder* decoder,
                                        const rdp_avc_yuv420* yuv,
                                        const rdp_graphics_rect16* rect)
{
    uint32_t y = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t half_width = 0;
    uint32_t half_height = 0;

    if (!decoder || !yuv || !rect)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    width = (uint32_t)(rect->right - rect->left);
    height = (uint32_t)(rect->bottom - rect->top);
    half_width = (width + 1u) / 2u;
    half_height = (height + 1u) / 2u;

    for (y = rect->top; y < rect->bottom; y++)
    {
        uint8_t* dst_y = decoder->yuv444[0].data + ((size_t)y * decoder->yuv444_stride[0]) + rect->left;
        const uint8_t* src_y = yuv->planes[0].data + ((size_t)y * yuv->stride[0]) + rect->left;

        memcpy(dst_y, src_y, (size_t)(rect->right - rect->left));
    }

    for (y = 0; y < half_height; y++)
    {
        size_t src_row = (size_t)(rect->top / 2u + y);
        uint32_t dst_row0 = rect->top + 2u * y;
        uint32_t dst_row1 = dst_row0 + 1u;
        const uint8_t* src_u = NULL;
        const uint8_t* src_v = NULL;
        uint8_t* dst_u0 = NULL;
        uint8_t* dst_v0 = NULL;
        uint8_t* dst_u1 = NULL;
        uint8_t* dst_v1 = NULL;
        uint32_t x = 0;

        if (src_row >= (((size_t)yuv->height + 1u) / 2u) ||
            (size_t)(rect->left / 2u) + half_width > yuv->stride[1] ||
            (size_t)(rect->left / 2u) + half_width > yuv->stride[2])
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        src_u = yuv->planes[1].data + src_row * yuv->stride[1] + rect->left / 2u;
        src_v = yuv->planes[2].data + src_row * yuv->stride[2] + rect->left / 2u;
        dst_u0 = decoder->yuv444[1].data + ((size_t)dst_row0 * decoder->yuv444_stride[1]) + rect->left;
        dst_v0 = decoder->yuv444[2].data + ((size_t)dst_row0 * decoder->yuv444_stride[2]) + rect->left;
        if (dst_row1 < rect->bottom)
        {
            dst_u1 = decoder->yuv444[1].data + ((size_t)dst_row1 * decoder->yuv444_stride[1]) +
                     rect->left;
            dst_v1 = decoder->yuv444[2].data + ((size_t)dst_row1 * decoder->yuv444_stride[2]) +
                     rect->left;
        }
        for (x = 0; x < half_width; x++)
        {
            uint32_t dst_col0 = 2u * x;
            uint32_t dst_col1 = dst_col0 + 1u;

            if (rect->left + dst_col0 < rect->right)
            {
                dst_u0[dst_col0] = src_u[x];
                dst_v0[dst_col0] = src_v[x];
                if (dst_u1)
                {
                    dst_u1[dst_col0] = src_u[x];
                    dst_v1[dst_col0] = src_v[x];
                }
            }
            if (rect->left + dst_col1 < rect->right)
            {
                dst_u0[dst_col1] = src_u[x];
                dst_v0[dst_col1] = src_v[x];
                if (dst_u1)
                {
                    dst_u1[dst_col1] = src_u[x];
                    dst_v1[dst_col1] = src_v[x];
                }
            }
        }
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_avc_apply_chroma_v1(rdp_avc_decoder* decoder,
                                             const rdp_avc_yuv420* yuv,
                                             const rdp_graphics_rect16* rect)
{
    rdp_avc_444_chroma_view view;

    if (!decoder || !yuv || !rect || !decoder->yuv444_luma_valid)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&view, 0, sizeof(view));
    view.aux_y = yuv->planes[0].data;
    view.aux_y_stride = yuv->stride[0];
    view.aux_u = yuv->planes[1].data;
    view.aux_u_stride = yuv->stride[1];
    view.aux_v = yuv->planes[2].data;
    view.aux_v_stride = yuv->stride[2];
    view.aux_width = yuv->width;
    view.aux_height = yuv->height;
    view.rect = *rect;
    view.dst_u = decoder->yuv444[1].data;
    view.dst_u_stride = decoder->yuv444_stride[1];
    view.dst_v = decoder->yuv444[2].data;
    view.dst_v_stride = decoder->yuv444_stride[2];
    view.dst_width = decoder->yuv444_width;
    view.dst_height = decoder->yuv444_height;
    return rdp_avc_reconstruct_444_chroma(&view);
}

static librdp_status rdp_avc_apply_chroma_v2(rdp_avc_decoder* decoder,
                                             const rdp_avc_yuv420* yuv,
                                             const rdp_graphics_rect16* rect)
{
    rdp_avc_444v2_chroma_view view;

    if (!decoder || !yuv || !rect || !decoder->yuv444_luma_valid)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&view, 0, sizeof(view));
    view.aux_y = yuv->planes[0].data;
    view.aux_y_stride = yuv->stride[0];
    view.aux_u = yuv->planes[1].data;
    view.aux_u_stride = yuv->stride[1];
    view.aux_v = yuv->planes[2].data;
    view.aux_v_stride = yuv->stride[2];
    view.aux_width = yuv->width;
    view.aux_height = yuv->height;
    view.rect = *rect;
    view.dst_u = decoder->yuv444[1].data;
    view.dst_u_stride = decoder->yuv444_stride[1];
    view.dst_v = decoder->yuv444[2].data;
    view.dst_v_stride = decoder->yuv444_stride[2];
    view.dst_width = decoder->yuv444_width;
    view.dst_height = decoder->yuv444_height;
    return rdp_avc_reconstruct_444v2_chroma(&view);
}

static librdp_status rdp_avc_apply_regions_luma(rdp_avc_decoder* decoder,
                                                const rdp_avc_yuv420* yuv,
                                                uint32_t surface_width,
                                                uint32_t surface_height,
                                                const rdp_graphics_avc420_metablock* meta)
{
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    decoder->yuv444_luma_valid = 0;
    decoder->yuv444_chroma_valid = 0;
    for (i = 0; i < meta->rect_count; i++)
    {
        rdp_graphics_rect16 rect;

        status = rdp_avc_parse_region(meta, i, &rect);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_avc_validate_rect(yuv, surface_width, surface_height, &rect);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_avc_apply_luma(decoder, yuv, &rect);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    decoder->yuv444_luma_valid = 1;
    decoder->yuv444_chroma_valid = 1;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_avc_apply_regions_chroma(rdp_avc_decoder* decoder,
                                                  uint16_t codec_id,
                                                  const rdp_avc_yuv420* yuv,
                                                  uint32_t surface_width,
                                                  uint32_t surface_height,
                                                  const rdp_graphics_avc420_metablock* meta)
{
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    decoder->yuv444_chroma_valid = 0;
    for (i = 0; i < meta->rect_count; i++)
    {
        rdp_graphics_rect16 rect;

        status = rdp_avc_parse_region(meta, i, &rect);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_avc_validate_rect(yuv, surface_width, surface_height, &rect);
        if (status == LIBRDP_STATUS_OK && codec_id == RDP_GRAPHICS_CODECID_AVC444V2)
            status = rdp_avc_apply_chroma_v2(decoder, yuv, &rect);
        else if (status == LIBRDP_STATUS_OK)
            status = rdp_avc_apply_chroma_v1(decoder, yuv, &rect);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    decoder->yuv444_chroma_valid = 1;
    return LIBRDP_STATUS_OK;
}

static void rdp_avc_yuv_to_bgra_pixel(uint8_t y, uint8_t u, uint8_t v, uint8_t* dst)
{
    int yy = (int)y;
    int uu = (int)u - 128;
    int vv = (int)v - 128;

    dst[0] = rdp_avc_clip_u8(yy + ((475 * uu) >> 8));
    dst[1] = rdp_avc_clip_u8(yy - ((48 * uu + 120 * vv) >> 8));
    dst[2] = rdp_avc_clip_u8(yy + ((403 * vv) >> 8));
    dst[3] = 255;
}

static uint8_t rdp_avc_correct_444_chroma_sample(const uint8_t* plane,
                                                 size_t stride,
                                                 uint32_t width,
                                                 uint32_t height,
                                                 uint32_t row,
                                                 uint32_t col)
{
    int value = 0;

    if (!plane || (row & 1u) != 0 || (col & 1u) != 0 || row + 1u >= height || col + 1u >= width)
        return plane ? plane[(size_t)row * stride + col] : 128u;
    value = 4 * (int)plane[(size_t)row * stride + col] -
            (int)plane[(size_t)row * stride + col + 1u] -
            (int)plane[((size_t)row + 1u) * stride + col] -
            (int)plane[((size_t)row + 1u) * stride + col + 1u];
    return rdp_avc_clip_u8(value);
}

librdp_status rdp_avc_yuv444_planes_to_bgra(const uint8_t* y_plane,
                                            size_t y_stride,
                                            const uint8_t* u_plane,
                                            size_t u_stride,
                                            const uint8_t* v_plane,
                                            size_t v_stride,
                                            uint32_t width,
                                            uint32_t height,
                                            uint8_t avc444_correction,
                                            rdp_avc_frame* frame)
{
    uint32_t row = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!y_plane || !u_plane || !v_plane || !frame || width == 0 || height == 0 ||
        y_stride < width || u_stride < width || v_stride < width)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_avc_frame_prepare(frame, width, height);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (row = 0; row < height; row++)
    {
        uint32_t col = 0;
        const uint8_t* src_y = y_plane + ((size_t)row * y_stride);
        const uint8_t* src_u = u_plane + ((size_t)row * u_stride);
        const uint8_t* src_v = v_plane + ((size_t)row * v_stride);
        uint8_t* dst = frame->pixels.data + ((size_t)row * frame->stride);

        for (col = 0; col < width; col++)
        {
            uint8_t u = src_u[col];
            uint8_t v = src_v[col];

            if (avc444_correction)
            {
                u = rdp_avc_correct_444_chroma_sample(u_plane, u_stride, width, height, row, col);
                v = rdp_avc_correct_444_chroma_sample(v_plane, v_stride, width, height, row, col);
            }
            rdp_avc_yuv_to_bgra_pixel(src_y[col], u, v, dst + ((size_t)col * 4u));
        }
    }
    return LIBRDP_STATUS_OK;
}

#if defined(RDP_HAVE_OPENH264_AVC)
static librdp_status rdp_avc_yuv420_to_bgra(const rdp_avc_yuv420* yuv, rdp_avc_frame* frame)
{
    uint32_t row = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!yuv || !frame || !yuv->planes[0].data || !yuv->planes[1].data || !yuv->planes[2].data ||
        yuv->width == 0 || yuv->height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_avc_frame_prepare(frame, yuv->width, yuv->height);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (row = 0; row < yuv->height; row++)
    {
        uint32_t col = 0;
        const uint8_t* src_y = yuv->planes[0].data + ((size_t)row * yuv->stride[0]);
        const uint8_t* src_u = yuv->planes[1].data + (((size_t)row / 2u) * yuv->stride[1]);
        const uint8_t* src_v = yuv->planes[2].data + (((size_t)row / 2u) * yuv->stride[2]);
        uint8_t* dst = frame->pixels.data + ((size_t)row * frame->stride);

        for (col = 0; col < yuv->width; col++)
            rdp_avc_yuv_to_bgra_pixel(src_y[col], src_u[col / 2u], src_v[col / 2u], dst + ((size_t)col * 4u));
    }
    return LIBRDP_STATUS_OK;
}
#endif

static librdp_status rdp_avc_yuv444_to_bgra(rdp_avc_decoder* decoder, rdp_avc_frame* frame)
{
    if (!decoder || !frame || !decoder->yuv444_luma_valid || !decoder->yuv444_chroma_valid)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_avc_yuv444_planes_to_bgra(decoder->yuv444[0].data,
                                         decoder->yuv444_stride[0],
                                         decoder->yuv444[1].data,
                                         decoder->yuv444_stride[1],
                                         decoder->yuv444[2].data,
                                         decoder->yuv444_stride[2],
                                         decoder->yuv444_width,
                                         decoder->yuv444_height,
                                         1,
                                         frame);
}
#endif

rdp_avc_decoder* rdp_avc_decoder_new(void)
{
    rdp_avc_decoder* decoder = (rdp_avc_decoder*)calloc(1, sizeof(*decoder));
#if defined(RDP_HAVE_ANY_AVC)
    size_t i = 0;
#endif

    if (!decoder)
        return NULL;
#if defined(RDP_HAVE_ANY_AVC)
    rdp_avc_yuv420_init(&decoder->main_yuv);
    rdp_avc_yuv420_init(&decoder->aux_yuv);
    for (i = 0; i < 3u; i++)
        rdp_buffer_init(&decoder->yuv444[i]);
#endif
    return decoder;
}

void rdp_avc_decoder_reset(rdp_avc_decoder* decoder)
{
    if (!decoder)
        return;
#if defined(RDP_HAVE_FFMPEG_AVC)
    rdp_avc_h264_reset(&decoder->main_stream);
    rdp_avc_h264_reset(&decoder->aux_stream);
#endif
#if defined(RDP_HAVE_OPENH264_AVC)
    rdp_avc_openh264_reset(&decoder->openh264_main_stream);
    rdp_avc_openh264_reset(&decoder->openh264_aux_stream);
#endif
#if defined(RDP_HAVE_ANY_AVC)
    decoder->yuv444_luma_valid = 0;
    decoder->yuv444_chroma_valid = 0;
#endif
}

void rdp_avc_decoder_free(rdp_avc_decoder* decoder)
{
#if defined(RDP_HAVE_ANY_AVC)
    size_t i = 0;
#endif

    if (!decoder)
        return;
#if defined(RDP_HAVE_FFMPEG_AVC)
    rdp_avc_h264_free(&decoder->main_stream);
    rdp_avc_h264_free(&decoder->aux_stream);
#endif
#if defined(RDP_HAVE_OPENH264_AVC)
    rdp_avc_openh264_free(&decoder->openh264_main_stream);
    rdp_avc_openh264_free(&decoder->openh264_aux_stream);
#endif
#if defined(RDP_HAVE_ANY_AVC)
    rdp_avc_yuv420_free(&decoder->main_yuv);
    rdp_avc_yuv420_free(&decoder->aux_yuv);
    for (i = 0; i < 3u; i++)
        rdp_buffer_free(&decoder->yuv444[i]);
#endif
#if defined(RDP_HAVE_FFMPEG_AVC)
    sws_freeContext(decoder->yuv444_to_bgra);
#endif
    free(decoder);
}

#if defined(RDP_HAVE_ANY_AVC)

#if defined(RDP_HAVE_FFMPEG_AVC)
/*
 * Probes FFmpeg beyond library presence: the H.264 decoder must open and the
 * pixel converters used by AVC420 and AVC444 must be constructible. Capability
 * advertisement uses this probe so negotiation mirrors the runtime path.
 */
static uint32_t rdp_avc_ffmpeg_runtime_support(void)
{
    rdp_avc_h264 h264;
    struct SwsContext* to_bgra = NULL;
    struct SwsContext* to_yuv420 = NULL;
    uint32_t support = 0;

    memset(&h264, 0, sizeof(h264));
    if (rdp_avc_h264_open(&h264) != LIBRDP_STATUS_OK)
        return 0;
    to_bgra = sws_getContext(16,
                             16,
                             AV_PIX_FMT_YUV420P,
                             16,
                             16,
                             AV_PIX_FMT_BGRA,
                             SWS_FAST_BILINEAR,
                             NULL,
                             NULL,
                             NULL);
    to_yuv420 = sws_getContext(16,
                               16,
                               AV_PIX_FMT_YUV420P,
                               16,
                               16,
                               AV_PIX_FMT_YUV420P,
                               SWS_FAST_BILINEAR,
                               NULL,
                               NULL,
                               NULL);
    if (to_bgra)
        support |= RDP_GRAPHICS_AVC_SUPPORT_AVC420;
    if (to_bgra && to_yuv420)
        support |= RDP_GRAPHICS_AVC_SUPPORT_AVC444 |
                   RDP_GRAPHICS_AVC_SUPPORT_AVC444V2;
    sws_freeContext(to_bgra);
    sws_freeContext(to_yuv420);
    rdp_avc_h264_free(&h264);
    return support;
}
#endif

#if defined(RDP_HAVE_OPENH264_AVC)
/*
 * Verifies that the OpenH264 backend can instantiate and initialize a decoder.
 * Output conversion for advertised AVC modes uses librdp's internal YUV paths,
 * so decoder initialization is the backend-specific runtime gate.
 */
static uint32_t rdp_avc_openh264_runtime_support(void)
{
    rdp_avc_openh264 h264;
    uint32_t support = 0;

    memset(&h264, 0, sizeof(h264));
    if (rdp_avc_openh264_open(&h264) == LIBRDP_STATUS_OK)
        support = RDP_GRAPHICS_AVC_SUPPORT_ALL;
    rdp_avc_openh264_free(&h264);
    return support;
}
#endif

uint32_t rdp_avc_runtime_support(void)
{
    uint32_t support = 0;

#if defined(RDP_HAVE_FFMPEG_AVC)
    support |= rdp_avc_ffmpeg_runtime_support();
#endif
#if defined(RDP_HAVE_OPENH264_AVC)
    support |= rdp_avc_openh264_runtime_support();
#endif
    return support & RDP_GRAPHICS_AVC_SUPPORT_ALL;
}
#else
uint32_t rdp_avc_runtime_support(void)
{
    return 0;
}
#endif

#if defined(RDP_HAVE_ANY_AVC)
static librdp_status rdp_avc_decode_h264_to_yuv420(rdp_avc_decoder* decoder,
                                                   uint8_t aux,
                                                   const uint8_t* data,
                                                   size_t length,
                                                   uint32_t surface_width,
                                                   uint32_t surface_height,
                                                   rdp_avc_yuv420* yuv)
{
    rdp_avc_yuv420 decoded;
    librdp_status status = LIBRDP_STATUS_UNSUPPORTED;

    rdp_avc_yuv420_init(&decoded);
#if defined(RDP_HAVE_FFMPEG_AVC)
    rdp_avc_h264* ffmpeg = aux ? &decoder->aux_stream : &decoder->main_stream;

    status = rdp_avc_h264_decode(ffmpeg, data, length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_avc_frame_to_yuv420(ffmpeg, surface_width, surface_height, &decoded);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_avc_yuv420_move(yuv, &decoded);
        rdp_avc_yuv420_free(&decoded);
        return status;
    }
    rdp_avc_yuv420_free(&decoded);
    rdp_avc_yuv420_init(&decoded);
#endif
#if defined(RDP_HAVE_OPENH264_AVC)
    {
        rdp_avc_openh264* openh264 = aux ? &decoder->openh264_aux_stream : &decoder->openh264_main_stream;
        librdp_status fallback_status =
            rdp_avc_openh264_decode_to_yuv420(openh264, data, length, surface_width, surface_height, &decoded);

        if (fallback_status == LIBRDP_STATUS_OK)
        {
            rdp_avc_yuv420_move(yuv, &decoded);
            rdp_avc_yuv420_free(&decoded);
            return fallback_status;
        }
        status = fallback_status;
    }
#endif
    rdp_avc_yuv420_free(&decoded);
    return status;
}

static librdp_status rdp_avc_decode_h264_to_bgra(rdp_avc_decoder* decoder,
                                                 const uint8_t* data,
                                                 size_t length,
                                                 uint32_t surface_width,
                                                 uint32_t surface_height,
                                                 rdp_avc_frame* frame)
{
    librdp_status status = LIBRDP_STATUS_UNSUPPORTED;

#if defined(RDP_HAVE_FFMPEG_AVC)
    status = rdp_avc_h264_decode(&decoder->main_stream, data, length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_avc_frame_to_bgra(&decoder->main_stream, surface_width, surface_height, frame);
    if (status == LIBRDP_STATUS_OK)
        return status;
#endif
#if defined(RDP_HAVE_OPENH264_AVC)
    status = rdp_avc_openh264_decode_to_yuv420(&decoder->openh264_main_stream,
                                               data,
                                               length,
                                               surface_width,
                                               surface_height,
                                               &decoder->main_yuv);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_avc_yuv420_to_bgra(&decoder->main_yuv, frame);
#endif
    return status;
}

static librdp_status rdp_avc_decode_status_for_advertised_runtime(librdp_status status,
                                                                  uint32_t avc_support,
                                                                  uint32_t required_support)
{
    if (status == LIBRDP_STATUS_UNSUPPORTED && (avc_support & required_support) == required_support)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return status;
}
#endif

librdp_status rdp_avc_decode_420(rdp_avc_decoder* decoder,
                                 const rdp_graphics_avc420_stream* stream,
                                 uint32_t surface_width,
                                 uint32_t surface_height,
                                 rdp_avc_frame* frame)
{
    if (!decoder || !stream || !frame)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!stream->bitstream || stream->bitstream_len == 0 || surface_width == 0 || surface_height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_avc_validate_metablock_regions(&stream->meta, surface_width, surface_height) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
#if defined(RDP_HAVE_ANY_AVC)
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t avc_support = rdp_avc_runtime_support();

    if ((avc_support & RDP_GRAPHICS_AVC_SUPPORT_AVC420) == 0)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_INFO,
                              "client.graphics.avc420.decode.unavailable",
                              "backend=runtime codec=AVC420");
        return LIBRDP_STATUS_UNSUPPORTED;
    }

    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.graphics.avc420.decode.start",
                          "surface_width=%u surface_height=%u rect_count=%u payload_len=%u",
                          surface_width,
                          surface_height,
                          stream->meta.rect_count,
                          (unsigned)stream->bitstream_len);
    status = rdp_avc_decode_h264_to_bgra(decoder,
                                         stream->bitstream,
                                         stream->bitstream_len,
                                         surface_width,
                                         surface_height,
                                         frame);
    status = rdp_avc_decode_status_for_advertised_runtime(status,
                                                          avc_support,
                                                          RDP_GRAPHICS_AVC_SUPPORT_AVC420);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          status == LIBRDP_STATUS_OK ? RDP_TRACE_LEVEL_DEBUG : RDP_TRACE_LEVEL_INFO,
                          status == LIBRDP_STATUS_OK ? "client.graphics.avc420.decode.done" :
                                                        "client.graphics.avc420.decode.failed",
                          "status=%d frame_width=%u frame_height=%u stride=%u",
                          (int)status,
                          frame ? frame->width : 0u,
                          frame ? frame->height : 0u,
                          frame ? (unsigned)frame->stride : 0u);
    return status;
#else
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_INFO,
                          "client.graphics.avc420.decode.unavailable",
                          "backend=none codec=AVC420");
    return LIBRDP_STATUS_UNSUPPORTED;
#endif
}

/*
 * Decode an AVC444 tile using primary and auxiliary bitstreams. The routine
 * coordinates OpenH264 output, chroma reconstruction, and fallback handling
 * before exposing pixels to the graphics pipeline.
 */
librdp_status rdp_avc_decode_444(rdp_avc_decoder* decoder,
                                 uint16_t codec_id,
                                 const rdp_graphics_avc444_stream* stream,
                                 uint32_t surface_width,
                                 uint32_t surface_height,
                                 rdp_avc_frame* frame)
{
    if (!decoder || !stream || !frame)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (codec_id != RDP_GRAPHICS_CODECID_AVC444 && codec_id != RDP_GRAPHICS_CODECID_AVC444V2)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (surface_width == 0 || surface_height == 0 ||
        stream->lc == RDP_GRAPHICS_AVC444_LC_INVALID ||
        stream->lc > RDP_GRAPHICS_AVC444_LC_CHROMA ||
        !stream->has_stream1 ||
        !stream->stream1.bitstream ||
        stream->stream1.bitstream_len == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (stream->lc == RDP_GRAPHICS_AVC444_LC_BOTH &&
        (!stream->has_stream2 || !stream->stream2.bitstream || stream->stream2.bitstream_len == 0))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (stream->lc != RDP_GRAPHICS_AVC444_LC_BOTH && stream->has_stream2)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_avc_validate_metablock_regions(&stream->stream1.meta, surface_width, surface_height) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (stream->has_stream2 &&
        rdp_avc_validate_metablock_regions(&stream->stream2.meta, surface_width, surface_height) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
#if defined(RDP_HAVE_ANY_AVC)
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t avc_support = rdp_avc_runtime_support();
    uint32_t required_support = codec_id == RDP_GRAPHICS_CODECID_AVC444V2 ?
                                    RDP_GRAPHICS_AVC_SUPPORT_AVC444V2 :
                                    RDP_GRAPHICS_AVC_SUPPORT_AVC444;
    rdp_avc_yuv444_snapshot snapshot;

    if ((avc_support & required_support) == 0)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_INFO,
                              "client.graphics.avc444.decode.unavailable",
                              "backend=runtime codec_id=%u lc=%u",
                              codec_id,
                              stream->lc);
        return LIBRDP_STATUS_UNSUPPORTED;
    }

    rdp_avc_yuv444_snapshot_init(&snapshot);

    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.graphics.avc444.decode.start",
                          "codec_id=%u lc=%u surface_width=%u surface_height=%u stream1_len=%u stream2_len=%u",
                          codec_id,
                          stream->lc,
                          surface_width,
                          surface_height,
                          stream->has_stream1 ? (unsigned)stream->stream1.bitstream_len : 0u,
                          stream->has_stream2 ? (unsigned)stream->stream2.bitstream_len : 0u);
    status = rdp_avc_yuv444_snapshot_capture(decoder, &snapshot);
    if (status != LIBRDP_STATUS_OK)
        goto out;
    status = rdp_avc_ensure_yuv444(decoder, surface_width, surface_height);
    if (status != LIBRDP_STATUS_OK)
        goto out;
    if (stream->lc == RDP_GRAPHICS_AVC444_LC_CHROMA && !decoder->yuv444_luma_valid)
    {
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto out;
    }

    if (stream->lc == RDP_GRAPHICS_AVC444_LC_BOTH || stream->lc == RDP_GRAPHICS_AVC444_LC_LUMA)
    {
        status = rdp_avc_decode_h264_to_yuv420(decoder,
                                               0,
                                               stream->stream1.bitstream,
                                               stream->stream1.bitstream_len,
                                               surface_width,
                                               surface_height,
                                               &decoder->main_yuv);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_avc_apply_regions_luma(decoder,
                                                &decoder->main_yuv,
                                                surface_width,
                                                surface_height,
                                                &stream->stream1.meta);
    }
    if (status == LIBRDP_STATUS_OK && stream->lc == RDP_GRAPHICS_AVC444_LC_BOTH)
    {
        status = rdp_avc_decode_h264_to_yuv420(decoder,
                                               1,
                                               stream->stream2.bitstream,
                                               stream->stream2.bitstream_len,
                                               surface_width,
                                               surface_height,
                                               &decoder->aux_yuv);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_avc_apply_regions_chroma(decoder,
                                                  codec_id,
                                                  &decoder->aux_yuv,
                                                  surface_width,
                                                  surface_height,
                                                  &stream->stream2.meta);
    }
    else if (status == LIBRDP_STATUS_OK && stream->lc == RDP_GRAPHICS_AVC444_LC_CHROMA)
    {
        status = rdp_avc_decode_h264_to_yuv420(decoder,
                                               1,
                                               stream->stream1.bitstream,
                                               stream->stream1.bitstream_len,
                                               surface_width,
                                               surface_height,
                                               &decoder->aux_yuv);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_avc_apply_regions_chroma(decoder,
                                                  codec_id,
                                                  &decoder->aux_yuv,
                                                  surface_width,
                                                  surface_height,
                                                  &stream->stream1.meta);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_avc_yuv444_to_bgra(decoder, frame);
    status = rdp_avc_decode_status_for_advertised_runtime(status,
                                                          avc_support,
                                                          required_support);

out:
    if (status != LIBRDP_STATUS_OK)
    {
        librdp_status restore_status = rdp_avc_yuv444_snapshot_restore(decoder, &snapshot);

        if (restore_status != LIBRDP_STATUS_OK)
            status = restore_status;
    }
    rdp_avc_yuv444_snapshot_free(&snapshot);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          status == LIBRDP_STATUS_OK ? RDP_TRACE_LEVEL_DEBUG : RDP_TRACE_LEVEL_INFO,
                          status == LIBRDP_STATUS_OK ? "client.graphics.avc444.decode.done" :
                                                        "client.graphics.avc444.decode.failed",
                          "status=%d codec_id=%u lc=%u frame_width=%u frame_height=%u stride=%u luma_valid=%u chroma_valid=%u",
                          (int)status,
                          codec_id,
                          stream->lc,
                          frame ? frame->width : 0u,
                          frame ? frame->height : 0u,
                          frame ? (unsigned)frame->stride : 0u,
                          decoder->yuv444_luma_valid,
                          decoder->yuv444_chroma_valid);
    return status;
#else
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_INFO,
                          "client.graphics.avc444.decode.unavailable",
                          "backend=none codec_id=%u lc=%u",
                          codec_id,
                          stream->lc);
    return LIBRDP_STATUS_UNSUPPORTED;
#endif
}
